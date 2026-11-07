//! End-to-end tests for the egress refusal log (`network.log`).
//!
//! These tests boot a real sandbox with a deny-by-default policy, probe it from
//! the guest, and read the records back through the SDK's opt-in `Network` log
//! source. They assert what a launcher (agent-vm's refusal feed) actually
//! observes: one record per refused decision, live delivery over a follow
//! stream, the tenant revision in force, per-site flood control, and an admitted
//! flow that records nothing.
//!
//! These tests require KVM (or libkrun on macOS). The `#[msb_test]`
//! attribute marks them `#[ignore]`, so plain `cargo test --workspace`
//! skips them. Run them via:
//!
//!     cargo nextest run -p microsandbox --test network_refusal_e2e --run-ignored=only
//!
//! Set `MSB_TEST_ISOLATE_HOME=1` (CI does this) to give each test its
//! own `~/.microsandbox` so they can run in parallel without sharing
//! the sqlite db, image cache, or sandbox namespace.

use std::io;
use std::net::SocketAddr;
use std::time::Duration;

use microsandbox::NetworkPolicy;
use microsandbox::Sandbox;
use microsandbox::logs::{
    LogOptions, LogSource, NameSource, NetworkLogEvent, NetworkLogRecord, RefusalLayer, RefusalSite,
};
use microsandbox_network::policy::{
    Action, Destination, DestinationGroup, Direction, PortRange, Protocol, Rule,
};
use serde_json::Value;
use test_utils::msb_test;
use tokio::io::AsyncWriteExt;
use tokio::net::TcpListener;
use tokio::task::JoinHandle;
use tokio::time::Instant;

#[path = "support/refusal_log.rs"]
mod refusal_log;

use refusal_log::RefusalLog;

//--------------------------------------------------------------------------------------------------
// Constants
//--------------------------------------------------------------------------------------------------

const PYTHON_IMAGE: &str = "mirror.gcr.io/library/python:3.12-alpine";
/// Guest path of [`refusal_probe.py`](fixtures/refusal_probe.py).
const PROBE: &str = "/tmp/refusal_probe.py";
/// TEST-NET-3: no host routes it, so every flow to it here is a policy decision.
const UNROUTABLE_IP: &str = "203.0.113.10";
/// PORT 443 is not answered by the deny responder unless TLS interception is on for it, so a
/// refused connection is a reset the guest reports as `refused`.
const REFUSED_TCP_PORT: u16 = 443;
const REFUSED_UDP_PORT: u16 = 9999;
/// A name only the policy's synthetic NXDOMAIN answers.
const BLOCKED_NAME: &str = "blocked.example";
/// The flood stops when the test creates this file; the guest checks it as it sends.
const FLOOD_STOP: &str = "/tmp/refusal-flood-stop";
const FLOOD_SUMMARY: &str = "/tmp/refusal-flood-summary";
/// Only a backstop: the flood normally ends because [`FLOOD_STOP`] appears. A run that hits this
/// cap proves nothing about "while the flood is still running", so the test asserts it did not.
const FLOOD_MAX_SECONDS: u64 = 30;
/// AC2's bucket size and refill rate, restated so the bound is checked against the spec.
const BUCKET_CAPACITY: u64 = 256;
const BUCKET_REFILL_PER_SEC: u64 = 20;

//--------------------------------------------------------------------------------------------------
// Types
//--------------------------------------------------------------------------------------------------

/// Minimal HTTP server on IPv4 loopback, standing in for a host service the policy admits.
struct HostTcp {
    port: u16,
    task: JoinHandle<()>,
}

//--------------------------------------------------------------------------------------------------
// Methods
//--------------------------------------------------------------------------------------------------

impl HostTcp {
    async fn start() -> io::Result<Self> {
        let listener = TcpListener::bind(SocketAddr::from(([127, 0, 0, 1], 0))).await?;
        let port = listener.local_addr()?.port();
        let task = tokio::spawn(async move {
            loop {
                let Ok((mut stream, _)) = listener.accept().await else {
                    return;
                };
                tokio::spawn(async move {
                    let _ = stream
                        .write_all(
                            b"HTTP/1.1 200 OK\r\nContent-Length: 2\r\nConnection: close\r\n\r\nok",
                        )
                        .await;
                    let _ = stream.shutdown().await;
                });
            }
        });
        Ok(Self { port, task })
    }

    fn port(&self) -> u16 {
        self.port
    }
}

impl Drop for HostTcp {
    fn drop(&mut self) {
        self.task.abort();
    }
}

//--------------------------------------------------------------------------------------------------
// Helpers
//--------------------------------------------------------------------------------------------------

/// Deny every egress flow except TCP to the sandbox host on `host_port`.
///
/// DNS stays denied on purpose: a lookup the policy refuses must produce its own
/// `dns-query` record, and the admitted flow below reaches the host through its
/// `/etc/hosts` alias, so it needs no lookup at all.
fn deny_all_but_host_tcp(host_port: u16) -> NetworkPolicy {
    NetworkPolicy {
        default_egress: Action::Deny,
        default_ingress: Action::Allow,
        rules: vec![Rule {
            direction: Direction::Egress,
            destination: Destination::Group(DestinationGroup::Host),
            protocols: vec![Protocol::Tcp],
            ports: vec![PortRange::single(host_port)],
            action: Action::Allow,
        }],
    }
}

async fn create_sandbox(name: &str, policy: NetworkPolicy) -> Sandbox {
    let sandbox = Sandbox::builder(name)
        .image(PYTHON_IMAGE)
        .cpus(1)
        .memory(256)
        .replace()
        .network(|n| n.policy(policy))
        .create()
        .await
        .expect("create sandbox");
    sandbox
        .fs()
        .write(PROBE, include_str!("fixtures/refusal_probe.py"))
        .await
        .expect("upload refusal probe");
    sandbox
}

/// Run one probe in the guest and return its single-line answer.
async fn probe(sandbox: &Sandbox, arguments: &str) -> String {
    let out = sandbox
        .shell(format!("python3 {PROBE} {arguments}"))
        .await
        .expect("run refusal probe");
    assert!(
        out.status().success,
        "probe `{arguments}` failed: stdout {:?}, stderr: {:?}",
        out.stdout().unwrap_or_default(),
        out.stderr().unwrap_or_default()
    );
    out.stdout().expect("utf8 stdout").trim().to_owned()
}

/// The guest's gateway IPv4, which is also its only nameserver.
async fn gateway_ipv4(sandbox: &Sandbox) -> String {
    let out = sandbox
        .shell("awk '/^nameserver /{print $2; exit}' /etc/resolv.conf")
        .await
        .expect("read resolv.conf");
    out.stdout().expect("utf8").trim().to_owned()
}

/// Decode the `network` entries a `Network` read returned.
fn network_records(entries: &[microsandbox::logs::LogEntry]) -> Vec<NetworkLogRecord> {
    entries
        .iter()
        .map(|entry| {
            serde_json::from_slice::<NetworkLogRecord>(entry.data.as_ref()).unwrap_or_else(
                |error| {
                    panic!(
                        "a stored network line must be a record ({error}): {:?}",
                        String::from_utf8_lossy(entry.data.as_ref())
                    )
                },
            )
        })
        .collect()
}

/// Read every stored `network` record from the sandbox's log directory.
async fn stored_records(sandbox: &Sandbox) -> Vec<NetworkLogRecord> {
    network_records(
        &sandbox
            .logs(&LogOptions {
                sources: vec![LogSource::Network],
                ..Default::default()
            })
            .await
            .expect("read the network log"),
    )
}

/// The envelope every refusal line carries, checked on the record's own wire form.
///
/// The wire form is what a launcher reads, so the field names, the omitted
/// optional fields and the value spelling are asserted here rather than only
/// through the typed view.
fn refusal_wire(record: &NetworkLogRecord) -> Value {
    let wire = RefusalLog::wire(record);
    assert_eq!(wire["v"], 1, "format version: {wire}");
    assert_eq!(wire["s"], "network", "source tag: {wire}");
    assert_eq!(wire["event"], "refusal", "event discriminator: {wire}");
    let timestamp = wire["t"].as_str().expect("a timestamp string");
    assert!(
        timestamp.len() == 24 && timestamp.ends_with('Z') && timestamp.as_bytes()[10] == b'T',
        "expected RFC 3339 UTC with millisecond precision, got {timestamp:?}"
    );
    wire
}

/// Parse `sent:<n> elapsed:<seconds>`.
fn parse_flood_summary(summary: &str) -> (u64, f64) {
    let mut sent = None;
    let mut elapsed = None;
    for field in summary.split_whitespace() {
        if let Some(value) = field.strip_prefix("sent:") {
            sent = Some(value.parse().expect("a datagram count"));
        } else if let Some(value) = field.strip_prefix("elapsed:") {
            elapsed = Some(value.parse().expect("an elapsed time"));
        }
    }
    (
        sent.unwrap_or_else(|| panic!("no `sent:` in {summary:?}")),
        elapsed.unwrap_or_else(|| panic!("no `elapsed:` in {summary:?}")),
    )
}

//--------------------------------------------------------------------------------------------------
// Tests
//--------------------------------------------------------------------------------------------------

/// AC1 (end-to-end half), AC3 and AC9: every deny site the guest can reach
/// records one line with the R4 facts, the live stream opened before the probes
/// yields each record, the admitted flow records nothing, and a replace that
/// returns revision 2 is reported as revision 2.
#[msb_test]
async fn network_refusal_log_records_deny_sites_live() {
    let host = HostTcp::start().await.expect("host tcp fixture");
    let host_port = host.port();
    let name = "network-refusal-deny-sites";
    let policy = deny_all_but_host_tcp(host_port);
    let sandbox = create_sandbox(name, policy.clone()).await;

    // Opened before any probe: this is the launcher's shape — the file already
    // exists (the runtime creates it at boot), and the reader has to pick up
    // every record the probes below cause while it follows.
    let mut log = RefusalLog::open(&sandbox).await;
    let gateway = gateway_ipv4(&sandbox).await;

    // 1. A denied lookup: the forwarder answers NXDOMAIN and records the query.
    assert_eq!(
        probe(&sandbox, &format!("dns {BLOCKED_NAME}")).await,
        "nxdomain",
        "a denied name must not resolve"
    );
    let record = log
        .expect_refusal("the denied lookup", |refusal| {
            refusal.site == RefusalSite::DnsQuery
        })
        .await;
    let wire = refusal_wire(&record);
    let refusal = RefusalLog::refusal(&record);
    assert_eq!(refusal.site, RefusalSite::DnsQuery);
    assert_eq!(refusal.layer, RefusalLayer::Tenant);
    assert_eq!(refusal.dst_ip, Some(gateway.parse().expect("gateway ip")));
    assert_eq!(refusal.dst_port, Some(53));
    assert_eq!(refusal.name.as_deref(), Some(BLOCKED_NAME));
    assert_eq!(refusal.name_source, NameSource::DnsQuery);
    assert_eq!(refusal.revision, 1, "the launch policy is revision 1");
    assert_eq!(wire["site"], "dns-query");
    assert_eq!(wire["layer"], "tenant");
    assert_eq!(wire["protocol"], "udp");
    assert_eq!(wire["name_source"], "dns-query");

    // 2. A refused TCP SYN: only the address is known, so no name is recorded.
    assert_eq!(
        probe(&sandbox, &format!("tcp {UNROUTABLE_IP} {REFUSED_TCP_PORT}")).await,
        "refused"
    );
    let record = log
        .expect_refusal("the refused SYN", |refusal| {
            refusal.site == RefusalSite::TcpSyn && refusal.dst_port == Some(REFUSED_TCP_PORT)
        })
        .await;
    let wire = refusal_wire(&record);
    let refusal = RefusalLog::refusal(&record);
    assert_eq!(refusal.dst_ip, Some(UNROUTABLE_IP.parse().expect("ip")));
    assert_eq!(refusal.name_source, NameSource::Absent);
    assert_eq!(refusal.revision, 1, "the launch policy is revision 1");
    assert_eq!(refusal.name, None);
    assert_eq!(wire["site"], "tcp-syn");
    assert_eq!(wire["protocol"], "tcp");
    assert!(wire.get("name").is_none(), "no name: {wire}");

    // 3. A refused datagram, recorded after reassembly, so it carries the port.
    assert_eq!(
        probe(
            &sandbox,
            &format!("udp {UNROUTABLE_IP} {REFUSED_UDP_PORT} 1")
        )
        .await,
        "sent:1"
    );
    let record = log
        .expect_refusal("the refused datagram", |refusal| {
            refusal.site == RefusalSite::Udp && refusal.dst_port == Some(REFUSED_UDP_PORT)
        })
        .await;
    let wire = refusal_wire(&record);
    let refusal = RefusalLog::refusal(&record);
    assert_eq!(refusal.dst_ip, Some(UNROUTABLE_IP.parse().expect("ip")));
    assert_eq!(refusal.revision, 1, "the launch policy is revision 1");
    assert_eq!(wire["site"], "udp");
    assert_eq!(wire["protocol"], "udp");

    // 4. A refused echo to the gateway: ICMP has no port to record.
    let ping = sandbox
        .shell(format!("ping -c 1 -W 1 {gateway}"))
        .await
        .expect("ping the gateway");
    assert!(
        !ping.status().success,
        "a refused echo must not be answered; stdout {:?}",
        ping.stdout().unwrap_or_default()
    );
    let record = log
        .expect_refusal("the refused echo", |refusal| {
            refusal.site == RefusalSite::Icmp
        })
        .await;
    let wire = refusal_wire(&record);
    let refusal = RefusalLog::refusal(&record);
    assert_eq!(refusal.dst_ip, Some(gateway.parse().expect("gateway ip")));
    assert_eq!(refusal.dst_port, None);
    assert_eq!(refusal.revision, 1, "the launch policy is revision 1");
    assert_eq!(wire["site"], "icmp");
    assert_eq!(wire["protocol"], "icmpv4");
    assert!(wire.get("dst_port").is_none(), "no port: {wire}");

    // 5. The flow the policy admits is not recorded, at any site.
    assert_eq!(
        probe(
            &sandbox,
            &format!("tcp host.microsandbox.internal {host_port}")
        )
        .await,
        "ok",
        "the host rule must admit the allowed connection"
    );
    log.expect_no_refusal(
        "the admitted host connection",
        Duration::from_secs(1),
        |refusal| refusal.dst_port == Some(host_port),
    )
    .await;

    // 6. A replace that reports revision 2 is the revision the next refusal carries.
    assert_eq!(
        sandbox
            .update_network_policy(policy)
            .await
            .expect("replace the policy"),
        2,
        "the first replace returns revision 2"
    );
    assert_eq!(
        probe(&sandbox, &format!("tcp {UNROUTABLE_IP} {REFUSED_TCP_PORT}")).await,
        "refused"
    );
    let record = log
        .expect_refusal("the SYN refused after the replace", |refusal| {
            refusal.site == RefusalSite::TcpSyn
                && refusal.dst_port == Some(REFUSED_TCP_PORT)
                && refusal.revision == 2
        })
        .await;
    assert_eq!(
        RefusalLog::refusal(&record).revision,
        2,
        "a refusal decided after the replace reports the revision the replace returned"
    );

    // The records are in the file, not only in the live stream: a stopped
    // sandbox is read with no runtime to ask.
    drop(log);
    Sandbox::get(name)
        .await
        .expect("get")
        .stop()
        .await
        .expect("stop");
    let ruled_syns: Vec<(u16, u64)> = stored_records(&sandbox)
        .await
        .iter()
        .filter_map(|record| match &record.event {
            NetworkLogEvent::Refusal(refusal)
                if refusal.site == RefusalSite::TcpSyn
                    && refusal.dst_port == Some(REFUSED_TCP_PORT) =>
            {
                Some((refusal.dst_port.unwrap(), refusal.revision))
            }
            _ => None,
        })
        .collect();
    assert_eq!(
        ruled_syns,
        vec![(REFUSED_TCP_PORT, 1), (REFUSED_TCP_PORT, 2)],
        "the stored log must hold both denied SYNs, with the revision each was decided under"
    );
    let _ = Sandbox::remove(name).await;
}

/// AC2 (end-to-end half): a refused-UDP flood is rate limited per site, its
/// overflow is reported as a `suppressed` record, another site is still recorded
/// while it runs, and an exec started during it stays responsive.
#[msb_test]
async fn network_refusal_log_suppresses_a_flood_and_stays_responsive() {
    let name = "network-refusal-flood";
    let sandbox = create_sandbox(name, NetworkPolicy::none()).await;
    let mut log = RefusalLog::open(&sandbox).await;

    // The flood runs until this test creates the stop file, so every probe below
    // really happens while it is still going.
    let flood = sandbox
        .exec_detached(
            "python3",
            [
                PROBE.to_owned(),
                "udp-flood".to_owned(),
                UNROUTABLE_IP.to_owned(),
                REFUSED_UDP_PORT.to_string(),
                FLOOD_STOP.to_owned(),
                FLOOD_SUMMARY.to_owned(),
                FLOOD_MAX_SECONDS.to_string(),
            ],
        )
        .await
        .expect("start the flood");

    // The first flood refusal is the evidence that it is running: by the time the
    // record lands the guest has sent far more datagrams than this one.
    log.expect_refusal("the first flood refusal", |refusal| {
        refusal.site == RefusalSite::Udp
    })
    .await;

    // AC2: another site is unaffected while one floods.
    assert_eq!(
        probe(&sandbox, &format!("tcp {UNROUTABLE_IP} {REFUSED_TCP_PORT}")).await,
        "refused",
        "a probe during the flood must still be refused at its SYN"
    );
    let syn = log
        .expect_refusal("the SYN refused during the flood", |refusal| {
            refusal.site == RefusalSite::TcpSyn
        })
        .await;
    assert_eq!(RefusalLog::refusal(&syn).revision, 1);

    // AC2: the sandbox stays responsive while its poll loop drops the flood.
    let started = Instant::now();
    let exec = sandbox
        .exec("echo", ["ok"])
        .await
        .expect("exec during the flood");
    let exec_elapsed = started.elapsed();
    assert_eq!(exec.stdout().unwrap_or_default().trim(), "ok");
    assert!(
        exec_elapsed < Duration::from_secs(5),
        "an exec started during the flood took {exec_elapsed:?}"
    );

    // AC2: overflow is reported, at the flooding site only.
    let suppressed = log
        .expect_suppressed(RefusalSite::Udp, Duration::from_secs(3))
        .await;
    assert!(
        suppressed.count >= 1,
        "a suppressed record must count at least the refusals it hides: {suppressed:?}"
    );
    let other_sites: Vec<&RefusalSite> = log
        .records()
        .iter()
        .filter_map(|record| match &record.event {
            NetworkLogEvent::Suppressed(other) => Some(&other.site),
            _ => None,
        })
        .filter(|site| **site != RefusalSite::Udp)
        .collect();
    assert!(
        other_sites.is_empty(),
        "only the flooding site may be suppressed, saw {other_sites:?}"
    );

    // Stop the flood, then read the totals the guest wrote itself.
    sandbox
        .fs()
        .write(FLOOD_STOP, b"1")
        .await
        .expect("open the flood stop file");
    let exit = tokio::time::timeout(Duration::from_secs(FLOOD_MAX_SECONDS + 30), flood.wait())
        .await
        .expect("the flood must stop once its stop file exists")
        .expect("the flood job");
    assert!(exit.success, "the flood exited with code {}", exit.code);
    let summary = sandbox
        .fs()
        .read_to_string(FLOOD_SUMMARY)
        .await
        .expect("read the flood summary");
    let (sent, elapsed) = parse_flood_summary(&summary);
    assert!(
        sent >= 1000,
        "the flood only means something if it refused far more than one bucket: {summary}"
    );
    assert!(
        elapsed < FLOOD_MAX_SECONDS as f64,
        "the flood must have ended because the stop file appeared, not because its own time \
         budget ran out — otherwise the probes above may not have overlapped it: {summary}"
    );

    // A refusal decided after the flood is a barrier: the writer drains one queue
    // in order, so every refusal the flood caused has been counted when it lands.
    assert_eq!(
        probe(&sandbox, &format!("tcp {UNROUTABLE_IP} {REFUSED_TCP_PORT}")).await,
        "refused"
    );
    log.expect_refusal("the barrier SYN after the flood", |refusal| {
        refusal.site == RefusalSite::TcpSyn
    })
    .await;

    // The bound is AC2's own: a full bucket plus what refills over the interval the
    // guest was sending, plus one second of slack for the datagrams still in flight
    // when it stopped sending. `elapsed` is the guest's measurement of that interval.
    let udp = log.count_refusals(RefusalSite::Udp) as u64;
    let bound =
        BUCKET_CAPACITY + BUCKET_REFILL_PER_SEC * elapsed.ceil() as u64 + BUCKET_REFILL_PER_SEC;
    assert!(
        udp <= bound,
        "{udp} udp refusals were written for a {elapsed:.3}s flood, above the {bound} a \
         {BUCKET_CAPACITY}-token bucket refilling at {BUCKET_REFILL_PER_SEC}/s allows"
    );

    // A clean stop writes the counts still pending, so the file keeps the
    // evidence after the sandbox is gone. This run cannot tell a close-time
    // suppressed record from one a flush tick wrote during the flood; the
    // deterministic proof of the close path is the runtime writer's
    // `close_writes_pending_suppressed_counts`.
    Sandbox::get(name)
        .await
        .expect("get")
        .stop()
        .await
        .expect("stop");
    let stored_suppressed: Vec<u64> = stored_records(&sandbox)
        .await
        .iter()
        .filter_map(|record| match &record.event {
            NetworkLogEvent::Suppressed(suppressed) if suppressed.site == RefusalSite::Udp => {
                Some(suppressed.count)
            }
            _ => None,
        })
        .collect();
    assert!(
        !stored_suppressed.is_empty() && stored_suppressed.iter().all(|count| *count >= 1),
        "the stored log must keep at least one suppressed record for udp: {stored_suppressed:?}"
    );
    let _ = Sandbox::remove(name).await;
}

/// AC5 (the ordering half): the log is closed before the sandbox is published as stopped, so a
/// launcher that reads `Network` the instant it sees `Stopped` finds the counts a close-time write
/// produces.
///
/// The reader is a concurrent watcher, which is the observable a launcher really has: it polls the
/// status, and on the first `Stopped` it reads the log exactly once — no retry, no delay. The burst
/// runs one site past its bucket and the stop follows immediately, so the suppressed counts are
/// still pending when the runtime closes the log. Closing it after the status update leaves the
/// watcher reading a file the writer has not finished with.
#[msb_test]
async fn network_log_final_counts_are_readable_as_soon_as_the_sandbox_is_stopped() {
    let name = "network-refusal-stopped";
    let sandbox = create_sandbox(name, NetworkPolicy::none()).await;

    // Well past one bucket, and fast enough that the flush tick does not necessarily run before
    // the stop below.
    let burst: u64 = 600;
    let summary = probe(
        &sandbox,
        &format!("udp {UNROUTABLE_IP} {REFUSED_UDP_PORT} {burst}"),
    )
    .await;
    let sent: u64 = summary
        .strip_prefix("sent:")
        .and_then(|sent| sent.parse().ok())
        .unwrap_or_else(|| panic!("expected `sent:<n>`, got {summary:?}"));
    assert!(
        sent >= burst,
        "the guest must actually send the burst, got {summary:?}"
    );

    let watcher_sandbox = Sandbox::get(name).await.expect("get");
    let watcher = tokio::spawn(async move {
        let deadline = Instant::now() + Duration::from_secs(180);
        loop {
            let handle = watcher_sandbox.refresh().await.expect("read status");
            if handle.status_snapshot() == microsandbox::sandbox::SandboxStatus::Stopped {
                // The launcher's read: once, immediately, with no retry.
                let entries = handle
                    .logs(&LogOptions {
                        sources: vec![LogSource::Network],
                        ..Default::default()
                    })
                    .await
                    .expect("read the network log");
                return network_records(&entries);
            }
            assert!(
                Instant::now() < deadline,
                "the sandbox never reported stopped"
            );
            tokio::time::sleep(Duration::from_millis(2)).await;
        }
    });

    Sandbox::get(name)
        .await
        .expect("get")
        .stop()
        .await
        .expect("stop");
    let records = tokio::time::timeout(Duration::from_secs(180), watcher)
        .await
        .expect("the watcher must see the sandbox stop")
        .expect("the watcher task");

    let written = records
        .iter()
        .filter(|record| {
            matches!(
                &record.event,
                NetworkLogEvent::Refusal(refusal)
                    if refusal.site == RefusalSite::Udp
                        && refusal.dst_port == Some(REFUSED_UDP_PORT)
            )
        })
        .count() as u64;
    let suppressed: u64 = records
        .iter()
        .filter_map(|record| match &record.event {
            NetworkLogEvent::Suppressed(count) if count.site == RefusalSite::Udp => {
                Some(count.count)
            }
            _ => None,
        })
        .sum();

    assert!(
        written <= BUCKET_CAPACITY + BUCKET_REFILL_PER_SEC,
        "one bucket bounds the written refusals; wrote {written} for {sent} datagrams"
    );
    // Everything past the bucket (plus a second of refill slack) has to be accounted for by the
    // suppressed counts, and the numbers must be on disk at the instant the sandbox reads stopped.
    let accounted = written + suppressed;
    let slack = BUCKET_CAPACITY + 2 * BUCKET_REFILL_PER_SEC;
    assert!(
        accounted + slack >= sent,
        "the log a watcher reads at `Stopped` accounts for {accounted} of {sent} refused \
         datagrams with {slack} of slack: written {written}, suppressed {suppressed}"
    );
    assert!(
        suppressed >= 1,
        "a burst past the bucket must leave a suppressed count on disk"
    );

    let _ = Sandbox::remove(name).await;
}
