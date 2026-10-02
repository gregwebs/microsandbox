//! Integration test for a malformed HTTP/2 header block arriving from the guest.
//!
//! A domain egress rule installs the secrets/egress handler on plain TCP even
//! when no secret is configured, so an h2c prior-knowledge flight from the
//! guest reaches the HPACK decoder. A header block that is truncated (`ff`) used
//! to panic `httlib-hpack` inside the sandbox's `msb machine` process; release
//! and CI builds use `panic = "abort"`, so the sandbox died. The guard must
//! instead close the guest connection promptly, forward nothing upstream, and
//! leave the same VM running.
//!
//! These tests require KVM (or libkrun on macOS). The `#[msb_test]` attribute
//! marks them `#[ignore]`, so plain `cargo test` skips them. Run them via:
//!
//!     MSB_TEST_ISOLATE_HOME=1 cargo nextest run -p microsandbox \
//!         --test malformed_h2_headers --run-ignored=only
//!
//! `MSB_TEST_ISOLATE_HOME=1` gives the test its own `~/.microsandbox` (CI sets
//! this). Without it the helper is a no-op and the ambient `MSB_HOME`/`MSB_PATH`
//! are used.

use std::io;
use std::net::{Ipv4Addr, Ipv6Addr, SocketAddr};
use std::time::Duration;

use microsandbox::{NetworkPolicy, Sandbox};
use microsandbox_network::policy::{Action, Destination, Direction, PortRange, Protocol, Rule};
use test_utils::msb_test;
use tokio::io::AsyncReadExt;
use tokio::net::TcpListener;
use tokio::task::JoinHandle;

// Constants

/// Match the mirrored fixture used by the other SDK integration tests.
const ALPINE_IMAGE: &str = "mirror.gcr.io/library/alpine:latest";

/// Stable per-boot identifier. A restarted VM (new kernel boot) reports a new
/// value, so equal reads bracket the payload prove the VM never restarted.
const BOOT_ID_CMD: &str = "cat /proc/sys/kernel/random/boot_id";

/// Host the guest dials to reach the host-side sink through the proxy.
const HOST_ALIAS: &str = "host.microsandbox.internal";

/// The proxy must close the rejected connection well under the guest client's
/// own 15 s budget (`sleep 5` + `nc -w 10`). The guest reports its elapsed
/// seconds, so a regression that leaves the connection open fails on time.
const MAX_PAYLOAD_SECONDS: u64 = 12;

// Types

/// Host TCP listener that records every byte the proxy forwards to it.
///
/// It never answers, so the only traffic it can observe is what the handler
/// relayed from the guest.
struct HostSink {
    port: u16,
    handle: Option<SinkTask>,
}

/// What the sink observed: whether a connection was accepted and the bytes read.
struct SinkObservation {
    accepted: bool,
    bytes: Vec<u8>,
}

/// Reader task that reports what the sink saw.
type SinkTask = JoinHandle<io::Result<SinkObservation>>;

// Methods

impl HostSink {
    async fn start() -> io::Result<Self> {
        // Bind both families on the same port: `host.microsandbox.internal`
        // resolves to a host loopback address whose family depends on the host.
        let v4_listener = TcpListener::bind(SocketAddr::from((Ipv4Addr::LOCALHOST, 0))).await?;
        let port = v4_listener.local_addr()?.port();
        let v6_listener = TcpListener::bind(SocketAddr::from((Ipv6Addr::LOCALHOST, port))).await?;

        let handle = tokio::spawn(async move {
            let (mut stream, _) = tokio::select! {
                accept = v4_listener.accept() => accept?,
                accept = v6_listener.accept() => accept?,
            };

            let mut bytes = Vec::new();
            let mut chunk = [0u8; 4096];
            loop {
                match tokio::time::timeout(Duration::from_secs(10), stream.read(&mut chunk)).await {
                    Ok(Ok(0)) | Ok(Err(_)) | Err(_) => break,
                    Ok(Ok(n)) => bytes.extend_from_slice(&chunk[..n]),
                }
            }

            Ok::<SinkObservation, io::Error>(SinkObservation {
                accepted: true,
                bytes,
            })
        });

        Ok(Self {
            port,
            handle: Some(handle),
        })
    }

    fn port(&self) -> u16 {
        self.port
    }

    /// Wait (bounded) for the sink to observe the upstream connection.
    async fn observed(&mut self) -> SinkObservation {
        let handle = self.handle.take().expect("sink already consumed");
        match tokio::time::timeout(Duration::from_secs(10), handle).await {
            Ok(Ok(Ok(observation))) => observation,
            // No upstream connection, or the reader task failed: the proxy
            // forwarded nothing either way.
            _ => SinkObservation {
                accepted: false,
                bytes: Vec::new(),
            },
        }
    }
}

impl Drop for HostSink {
    fn drop(&mut self) {
        if let Some(handle) = self.handle.take() {
            handle.abort();
        }
    }
}

// Functions

/// Allow-by-default policy carrying one domain rule.
///
/// The rule itself never matches the sink (the sink is on an ephemeral port),
/// but its presence is what installs the secrets/egress handler on plain TCP,
/// which is exactly the production trigger for the malformed-header path.
fn policy_with_domain_rule() -> NetworkPolicy {
    let mut policy = NetworkPolicy::allow_all();
    policy.rules.push(Rule {
        direction: Direction::Egress,
        destination: Destination::Domain("example.com".parse().expect("valid domain")),
        protocols: vec![Protocol::Tcp],
        ports: vec![PortRange::single(80)],
        action: Action::Allow,
    });
    policy
}

/// `msb exec` restarts a stopped sandbox, so a working exec alone proves
/// nothing. This reads the guest's boot id, which only the same VM repeats.
async fn boot_id(sb: &Sandbox) -> String {
    let out = sb.shell(BOOT_ID_CMD).await.expect("read boot id");
    assert!(
        out.status().success,
        "boot id read failed: {}",
        out.stderr().unwrap_or_default()
    );
    out.stdout().unwrap_or_default().trim().to_string()
}

async fn teardown(sb: Sandbox, name: &str) {
    // Best-effort: a dropped proxy connection can break the agent pipe, so a
    // stop error here is cleanup noise, not a test failure.
    drop(sb);
    if let Ok(handle) = Sandbox::get(name).await {
        let _ = handle.stop().await;
    }
    let _ = Sandbox::remove(name).await;
}

// Tests

#[msb_test]
async fn truncated_h2_header_block_closes_the_connection_without_restarting_the_sandbox() {
    let mut sink = HostSink::start().await.expect("host sink");
    let port = sink.port();
    let name = "malformed-h2-header-block";

    let sb = Sandbox::builder(name)
        .image(ALPINE_IMAGE)
        .cpus(1)
        .memory(256)
        .replace()
        .network(|n| n.policy(policy_with_domain_rule()))
        .create()
        .await
        .expect("create sandbox");

    // Marker before the payload: same VM afterwards means the same boot id.
    let boot_before = boot_id(&sb).await;

    // h2c prior-knowledge preface, an empty SETTINGS frame, and one HEADERS
    // frame (stream 1, END_STREAM|END_HEADERS) whose HPACK block is the single
    // truncated byte `ff`. The producer holds stdin open for 5 s so BusyBox
    // `nc` stays around for a proxy close instead of exiting on stdin EOF; its
    // own idle budget is `-w 10`, i.e. 15 s for the pipeline.
    let payload = format!(
        "start=$(date +%s); \
         bytes=$( (printf 'PRI * HTTP/2.0\\r\\n\\r\\nSM\\r\\n\\r\\n\
         \\000\\000\\000\\004\\000\\000\\000\\000\\000\
         \\000\\000\\001\\001\\005\\000\\000\\000\\001\\377'; sleep 5) \
         | nc -w 10 {HOST_ALIAS} {port} | wc -c); \
         end=$(date +%s); \
         printf '%s %s' \"$((end - start))\" \"$bytes\""
    );
    let out = sb
        .shell_with(&payload, |exec| exec.timeout(Duration::from_secs(30)))
        .await
        .expect("payload exec");
    assert!(
        out.status().success,
        "payload exec failed: stdout={:?} stderr={:?}",
        out.stdout().unwrap_or_default(),
        out.stderr().unwrap_or_default()
    );

    let stdout = out.stdout().unwrap_or_default();
    let mut fields = stdout.split_whitespace();
    let elapsed_secs: u64 = fields
        .next()
        .and_then(|value| value.parse().ok())
        .unwrap_or_else(|| panic!("payload did not report elapsed seconds: {stdout:?}"));
    let response_bytes: u64 = fields
        .next()
        .and_then(|value| value.parse().ok())
        .unwrap_or_else(|| panic!("payload did not report response bytes: {stdout:?}"));

    assert_eq!(
        response_bytes, 0,
        "the proxy must close a rejected header block with no response bytes"
    );
    assert!(
        elapsed_secs < MAX_PAYLOAD_SECONDS,
        "the proxy did not close the malformed connection promptly: {elapsed_secs}s \
         (guest client budget is 15s)"
    );

    // The rejected first flight must not be relayed: the handler drops the whole
    // buffered flight when the HEADERS block fails to decode, so the upstream
    // sink sees the TCP connection but no bytes (matching the in-tree unit
    // tests for the h2c rejection path).
    let observation = sink.observed().await;
    assert!(
        observation.accepted,
        "the guest flight never reached the host sink, so the test did not \
         exercise the proxy path"
    );
    assert!(
        observation.bytes.is_empty(),
        "rejected h2 header block forwarded {} bytes upstream (accepted={}): {:02x?}",
        observation.bytes.len(),
        observation.accepted,
        observation.bytes
    );

    // Same VM still serving, same boot id: not a restart.
    let boot_after = boot_id(&sb).await;
    assert_eq!(
        boot_after, boot_before,
        "sandbox restarted: boot id changed from {boot_before:?} to {boot_after:?}"
    );
    let alive = sb
        .shell("echo still-alive")
        .await
        .expect("post-payload exec");
    assert!(
        alive.status().success,
        "post-payload exec failed; sandbox did not survive"
    );
    assert_eq!(alive.stdout().unwrap_or_default().trim(), "still-alive");

    teardown(sb, name).await;
}
