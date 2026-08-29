//! Integration coverage for the runtime auto-publish poll loop
//! (`microsandbox_runtime::auto_publish`) that exercises the *real*
//! agent.sock wire protocol and *real* TCP sockets, without booting a
//! guest VM.
//!
//! `auto_publish::run()` only needs a peer that speaks the relay's
//! handshake plus `FsRequest`/`FsResponse`/`FsData` and
//! `LoopbackForward(Cancel)` frames — it does not care whether that
//! peer is a real agentd relay backed by a microVM or a fake one. This
//! file stands up a `UnixListener` that plays that peer role (a "fake
//! guest"), lets the real `auto_publish::spawn()` task dial it, and
//! then drives the `TcpListener` handed back over `PortCommand::Add`
//! with a genuine `TcpStream::connect` — so every assertion below is
//! backed by a real accept/connect pair and real bytes on the wire,
//! not a mocked channel.
//!
//! This closes two gaps noted during manual verification of issue #8
//! ("port automatic guest-listener publishing"):
//!   - there was no test driving `auto_publish::run()`'s ADD / REMOVE
//!     / RECONCILE loop against a real socket pair (only the pure
//!     `collapse_listeners`/`IdCounter` helpers had unit coverage);
//!   - the IPv6 loopback / cross-family `loopback_target` path had no
//!     coverage of the *runtime* side constructing the
//!     `LoopbackForwardReq` over the real wire protocol (only
//!     `crates/agentd/lib/loopback.rs`'s `bridge_ipv6_dials_v6_loopback`
//!     covered the forwarder itself, in isolation).
//!
//! Manual end-to-end verification (real guest VM, real `msb`) was also
//! performed separately and is recorded in the issue's verification
//! notes; these tests are the durable, CI-runnable regression coverage
//! for the same code paths.

#![cfg(all(feature = "net", unix))]

use std::collections::{HashMap, HashSet};
use std::net::{IpAddr, Ipv4Addr, Ipv6Addr, SocketAddr};
use std::sync::{Arc, Mutex};
use std::time::Duration;

use microsandbox_network::config::AutoPublishConfig;
use microsandbox_network::publisher::PortCommand;
use microsandbox_protocol::codec::{read_message, write_message};
use microsandbox_protocol::fs::{FsData, FsOp, FsRequest, FsResponse, FsResponseData};
use microsandbox_protocol::message::{Message, MessageType};
use microsandbox_protocol::network::{
    LoopbackForwardCancelReq, LoopbackForwardReq, LoopbackForwardResp, PortEvent,
};
use microsandbox_runtime::auto_publish::{EventBroadcast, spawn};
use tokio::io::{AsyncReadExt, AsyncWriteExt, BufReader};
use tokio::net::{TcpStream, UnixListener};
use tokio::sync::mpsc;
use tokio::time::timeout;

//--------------------------------------------------------------------------------------------------
// Test fixtures: /proc/net/tcp{,6} line formatting
//--------------------------------------------------------------------------------------------------

/// Mutable "guest" state shared between the test and the fake relay
/// task: the current contents of `/proc/net/tcp{,6}`, plus a log of
/// every `LoopbackForward(Cancel)` request the fake relay received
/// (so tests can assert on the runtime's cross-family address choice
/// without a real agentd).
#[derive(Default)]
struct GuestState {
    tcp4: String,
    tcp6: String,
    loopback_requests: Vec<LoopbackForwardReq>,
    loopback_cancels: Vec<LoopbackForwardCancelReq>,
}

fn tcp4_header() -> String {
    "  sl  local_address rem_address   st\n".to_string()
}

fn tcp6_header() -> String {
    "  sl  local_address                         remote_address                        st\n"
        .to_string()
}

/// Format one `/proc/net/tcp` LISTEN row. Matches the real kernel's
/// byte-reversed-per-octet hex encoding (verified against a live
/// guest's `/proc/net/tcp` during manual testing: `127.0.0.1:5000` ->
/// `0100007F:1388`).
fn tcp4_listen_line(sl: u32, addr: Ipv4Addr, port: u16) -> String {
    let o = addr.octets();
    format!(
        " {sl}: {:02X}{:02X}{:02X}{:02X}:{port:04X} 00000000:0000 0A 00000000:00000000 00:00000000 00000000     0        0 42 1\n",
        o[3], o[2], o[1], o[0],
    )
}

/// Format one `/proc/net/tcp6` LISTEN row. Each 4-byte big-endian
/// chunk of the address is re-emitted as the little-endian hex of
/// that chunk — verified against a live guest's `/proc/net/tcp6`
/// during manual testing: `::1` -> `...00000000 01000000`.
fn tcp6_listen_line(sl: u32, addr: Ipv6Addr, port: u16) -> String {
    let octets = addr.octets();
    let mut addr_hex = String::new();
    for chunk in octets.chunks(4) {
        let word = u32::from_be_bytes([chunk[0], chunk[1], chunk[2], chunk[3]]);
        addr_hex.push_str(&format!("{:08X}", word.swap_bytes()));
    }
    format!(
        "   {sl}: {addr_hex}:{port:04X} 00000000000000000000000000000000:0000 0A 00000000:00000000 00:00000000 00000000     0        0 42 1\n",
    )
}

//--------------------------------------------------------------------------------------------------
// Fake relay: speaks the real agent.sock wire protocol, backed by `GuestState`
//--------------------------------------------------------------------------------------------------

/// Accept exactly one connection on `listener` and serve it as a fake
/// relay would: the `[id_min][id_max]` handshake + `Ready` frame that
/// `auto_publish::run()` expects, then `FsRequest` (open/read/close on
/// `/proc/net/tcp{,6}`) and `LoopbackForward(Cancel)` requests, with
/// responses drawn live from `state` on every request (so the test can
/// mutate `state` between poll ticks to simulate the guest's listen
/// set changing).
async fn run_fake_relay(listener: UnixListener, state: Arc<Mutex<GuestState>>) {
    let (stream, _) = match listener.accept().await {
        Ok(x) => x,
        Err(_) => return,
    };
    let (read_half, mut write_half) = stream.into_split();

    // Handshake: correlation-id window, then the Ready frame every
    // relay client receives before anything else (see `AgentRelay::run`
    // and `auto_publish::run`'s handshake comment).
    if write_half.write_all(&1u32.to_be_bytes()).await.is_err() {
        return;
    }
    if write_half
        .write_all(&1_000_000u32.to_be_bytes())
        .await
        .is_err()
    {
        return;
    }
    let ready = Message::new(MessageType::Ready, 0, Vec::new());
    if write_message(&mut write_half, &ready).await.is_err() {
        return;
    }

    let mut buf_read = BufReader::new(read_half);
    let mut handle_paths: HashMap<u64, String> = HashMap::new();
    let mut next_handle: u64 = 1;

    loop {
        let msg = match read_message(&mut buf_read).await {
            Ok(m) => m,
            Err(_) => return,
        };
        match msg.t {
            MessageType::FsRequest => {
                let req: FsRequest = match msg.payload() {
                    Ok(r) => r,
                    Err(_) => return,
                };
                match req.op {
                    FsOp::OpenFile { path, .. } => {
                        let handle = next_handle;
                        next_handle += 1;
                        handle_paths.insert(handle, path);
                        let resp = FsResponse {
                            ok: true,
                            error: None,
                            data: Some(FsResponseData::Handle(handle)),
                        };
                        let Ok(m) = Message::with_payload(MessageType::FsResponse, msg.id, &resp)
                        else {
                            return;
                        };
                        if write_message(&mut write_half, &m).await.is_err() {
                            return;
                        }
                    }
                    FsOp::Read { handle, .. } => {
                        let path = handle_paths.get(&handle).cloned().unwrap_or_default();
                        let content = {
                            let st = state.lock().unwrap();
                            if path.ends_with("tcp6") {
                                st.tcp6.clone()
                            } else {
                                st.tcp4.clone()
                            }
                        };
                        let data = FsData {
                            data: content.into_bytes(),
                        };
                        let Ok(m) = Message::with_payload(MessageType::FsData, msg.id, &data)
                        else {
                            return;
                        };
                        if write_message(&mut write_half, &m).await.is_err() {
                            return;
                        }
                        let resp = FsResponse {
                            ok: true,
                            error: None,
                            data: None,
                        };
                        let Ok(m) = Message::with_payload(MessageType::FsResponse, msg.id, &resp)
                        else {
                            return;
                        };
                        if write_message(&mut write_half, &m).await.is_err() {
                            return;
                        }
                    }
                    FsOp::CloseHandle { handle } => {
                        handle_paths.remove(&handle);
                        let resp = FsResponse {
                            ok: true,
                            error: None,
                            data: None,
                        };
                        let Ok(m) = Message::with_payload(MessageType::FsResponse, msg.id, &resp)
                        else {
                            return;
                        };
                        if write_message(&mut write_half, &m).await.is_err() {
                            return;
                        }
                    }
                    _ => return,
                }
            }
            MessageType::LoopbackForward => {
                let req: LoopbackForwardReq = match msg.payload() {
                    Ok(r) => r,
                    Err(_) => return,
                };
                state.lock().unwrap().loopback_requests.push(req);
                let resp = LoopbackForwardResp {
                    ok: true,
                    error: None,
                };
                let Ok(m) = Message::with_payload(MessageType::LoopbackForwardResp, msg.id, &resp)
                else {
                    return;
                };
                if write_message(&mut write_half, &m).await.is_err() {
                    return;
                }
            }
            MessageType::LoopbackForwardCancel => {
                let req: LoopbackForwardCancelReq = match msg.payload() {
                    Ok(r) => r,
                    Err(_) => return,
                };
                state.lock().unwrap().loopback_cancels.push(req);
                let resp = LoopbackForwardResp {
                    ok: true,
                    error: None,
                };
                let Ok(m) = Message::with_payload(MessageType::LoopbackForwardResp, msg.id, &resp)
                else {
                    return;
                };
                if write_message(&mut write_half, &m).await.is_err() {
                    return;
                }
            }
            _ => return,
        }
    }
}

/// [`EventBroadcast`] impl that forwards every [`PortEvent`] into a
/// channel the test can assert on.
struct TestBroadcast(mpsc::UnboundedSender<PortEvent>);

impl EventBroadcast for TestBroadcast {
    fn broadcast_port_event(&self, event: PortEvent) {
        let _ = self.0.send(event);
    }
}

/// Common harness: binds the fake relay's `UnixListener`, spawns the
/// real `auto_publish::spawn()` task against it, and returns the
/// handles a test needs to drive the scenario.
struct Harness {
    // Kept alive for the harness's lifetime; the fake relay's
    // `UnixListener` is bound inside this directory.
    _dir: tempfile::TempDir,
    state: Arc<Mutex<GuestState>>,
    port_rx: mpsc::UnboundedReceiver<PortCommand>,
    event_rx: mpsc::UnboundedReceiver<PortEvent>,
}

impl Harness {
    fn start(guest_ipv4: Option<Ipv4Addr>, guest_ipv6: Option<Ipv6Addr>) -> Self {
        Self::start_with_explicit(guest_ipv4, guest_ipv6, HashSet::new())
    }

    fn start_with_explicit(
        guest_ipv4: Option<Ipv4Addr>,
        guest_ipv6: Option<Ipv6Addr>,
        explicit_guest_ports: HashSet<u16>,
    ) -> Self {
        let dir = tempfile::tempdir().expect("tempdir");
        let sock_path = dir.path().join("agent.sock");
        let listener = UnixListener::bind(&sock_path).expect("bind fake agent.sock");

        let state = Arc::new(Mutex::new(GuestState {
            tcp4: tcp4_header(),
            tcp6: tcp6_header(),
            ..Default::default()
        }));
        tokio::spawn(run_fake_relay(listener, state.clone()));

        let (port_tx, port_rx) = mpsc::unbounded_channel::<PortCommand>();
        let (event_tx, event_rx) = mpsc::unbounded_channel::<PortEvent>();
        let broadcast: Arc<dyn EventBroadcast> = Arc::new(TestBroadcast(event_tx));

        let cfg = AutoPublishConfig {
            poll_interval_ms: 50,
            host_bind: IpAddr::V4(Ipv4Addr::LOCALHOST),
        };
        let rt_handle = tokio::runtime::Handle::current();
        spawn(
            &rt_handle,
            sock_path,
            cfg,
            port_tx,
            guest_ipv4,
            guest_ipv6,
            broadcast,
            explicit_guest_ports,
        );

        Self {
            _dir: dir,
            state,
            port_rx,
            event_rx,
        }
    }

    fn set_tcp4(&self, body: String) {
        self.state.lock().unwrap().tcp4 = body;
    }

    fn loopback_requests(&self) -> Vec<LoopbackForwardReq> {
        self.state.lock().unwrap().loopback_requests.clone()
    }

    fn loopback_cancels(&self) -> Vec<LoopbackForwardCancelReq> {
        self.state.lock().unwrap().loopback_cancels.clone()
    }

    async fn next_command(&mut self) -> PortCommand {
        timeout(Duration::from_secs(10), self.port_rx.recv())
            .await
            .expect("timed out waiting for PortCommand")
            .expect("port command channel closed")
    }

    async fn next_event(&mut self) -> PortEvent {
        timeout(Duration::from_secs(10), self.event_rx.recv())
            .await
            .expect("timed out waiting for PortEvent")
            .expect("port event channel closed")
    }
}

/// Connect a real `TcpStream` to `addr` and read exactly
/// `expected.len()` bytes, asserting they match. Proves the
/// `TcpListener` handed over `PortCommand::Add` is genuinely bound and
/// accepting — not just a value sitting in a channel.
async fn assert_connectable_and_serves(
    listener: tokio::net::TcpListener,
    addr: SocketAddr,
    expected: &'static [u8],
) {
    let server = tokio::spawn(async move {
        let (mut sock, _) = listener.accept().await.expect("accept");
        sock.write_all(expected).await.expect("write");
    });
    let mut client = timeout(Duration::from_secs(5), TcpStream::connect(addr))
        .await
        .expect("connect timed out")
        .expect("connect failed");
    let mut buf = vec![0u8; expected.len()];
    timeout(Duration::from_secs(5), client.read_exact(&mut buf))
        .await
        .expect("read timed out")
        .expect("read failed");
    assert_eq!(buf, expected);
    server.await.expect("server task panicked");
}

//--------------------------------------------------------------------------------------------------
// Tests
//--------------------------------------------------------------------------------------------------

/// IPv4 wildcard LISTEN -> host mirror -> real connect -> removal.
/// Exercises `run()`'s ADD and REMOVE passes end-to-end against a real
/// `TcpListener`/`TcpStream` pair.
#[tokio::test]
async fn wildcard_v4_listener_is_mirrored_and_torn_down() {
    let mut h = Harness::start(Some(Ipv4Addr::new(172, 16, 1, 2)), None);
    h.set_tcp4(format!(
        "{}{}",
        tcp4_header(),
        tcp4_listen_line(0, Ipv4Addr::UNSPECIFIED, 18_765)
    ));

    let cmd = h.next_command().await;
    let (listener, guest_port) = match cmd {
        PortCommand::Add {
            listener,
            guest_port,
            ..
        } => (listener, guest_port),
        other => panic!("expected PortCommand::Add, got {other:?}"),
    };
    assert_eq!(guest_port, 18_765);
    let addr = listener.local_addr().unwrap();
    assert_eq!(
        addr.port(),
        18_765,
        "wildcard mirror should reuse the guest port when free"
    );

    match h.next_event().await {
        PortEvent::Added {
            guest_port,
            host_port,
            ..
        } => {
            assert_eq!(guest_port, 18_765);
            assert_eq!(host_port, 18_765);
        }
        other => panic!("expected PortEvent::Added, got {other:?}"),
    }

    assert_connectable_and_serves(listener, addr, b"hello-wildcard").await;

    // Guest LISTEN disappears.
    h.set_tcp4(tcp4_header());

    match h.next_command().await {
        PortCommand::Remove { host_port, .. } => assert_eq!(host_port, 18_765),
        other => panic!("expected PortCommand::Remove, got {other:?}"),
    }
    match h.next_event().await {
        PortEvent::Removed {
            guest_port,
            host_port,
            ..
        } => {
            assert_eq!(guest_port, 18_765);
            assert_eq!(host_port, 18_765);
        }
        other => panic!("expected PortEvent::Removed, got {other:?}"),
    }
}

/// IPv6 wildcard LISTEN (`[::]:port`) is the fourth discovery/mapping
/// path alongside v4 wildcard, v4 loopback, and v6 loopback (all
/// covered by the other tests in this file) — smoltcp already reaches
/// it via the VLAN dial, so no `LoopbackForwardReq` should be sent.
#[tokio::test]
async fn wildcard_v6_listener_is_mirrored_without_a_forwarder() {
    let mut h = Harness::start(Some(Ipv4Addr::new(172, 16, 1, 2)), None);
    {
        let mut st = h.state.lock().unwrap();
        st.tcp6 = format!(
            "{}{}",
            tcp6_header(),
            tcp6_listen_line(0, Ipv6Addr::UNSPECIFIED, 18_772)
        );
    }

    let listener = match h.next_command().await {
        PortCommand::Add {
            listener,
            guest_port,
            ..
        } => {
            assert_eq!(guest_port, 18_772);
            listener
        }
        other => panic!("expected PortCommand::Add, got {other:?}"),
    };
    assert!(matches!(h.next_event().await, PortEvent::Added { .. }));
    assert!(
        h.loopback_requests().is_empty(),
        "a wildcard LISTEN must not trigger an agentd loopback forwarder"
    );

    let addr = listener.local_addr().unwrap();
    assert_connectable_and_serves(listener, addr, b"hello-v6-wildcard").await;

    {
        let mut st = h.state.lock().unwrap();
        st.tcp6 = tcp6_header();
    }
    assert!(matches!(h.next_command().await, PortCommand::Remove { .. }));
    assert!(matches!(h.next_event().await, PortEvent::Removed { .. }));
    assert!(
        h.loopback_cancels().is_empty(),
        "no forwarder was spawned for a wildcard LISTEN, so no cancel should be sent"
    );
}

/// A guest port flapping (present -> absent -> present across
/// consecutive poll ticks) must produce exactly Added, Removed, Added
/// — never two Adds without an intervening Remove (which would mean a
/// stale listener was left registered).
#[tokio::test]
async fn flapping_listener_produces_added_removed_added_with_no_stale_entry() {
    let mut h = Harness::start(Some(Ipv4Addr::new(172, 16, 1, 2)), None);

    h.set_tcp4(format!(
        "{}{}",
        tcp4_header(),
        tcp4_listen_line(0, Ipv4Addr::UNSPECIFIED, 18_766)
    ));
    let first_listener = match h.next_command().await {
        PortCommand::Add { listener, .. } => listener,
        other => panic!("expected PortCommand::Add, got {other:?}"),
    };
    assert!(matches!(h.next_event().await, PortEvent::Added { .. }));

    h.set_tcp4(tcp4_header());
    assert!(matches!(h.next_command().await, PortCommand::Remove { .. }));
    assert!(matches!(h.next_event().await, PortEvent::Removed { .. }));
    drop(first_listener);

    h.set_tcp4(format!(
        "{}{}",
        tcp4_header(),
        tcp4_listen_line(0, Ipv4Addr::UNSPECIFIED, 18_766)
    ));
    let second_listener = match h.next_command().await {
        PortCommand::Add {
            listener,
            guest_port,
            ..
        } => {
            assert_eq!(guest_port, 18_766);
            listener
        }
        other => panic!("expected second PortCommand::Add, got {other:?}"),
    };
    assert!(matches!(h.next_event().await, PortEvent::Added { .. }));

    let addr = second_listener.local_addr().unwrap();
    assert_connectable_and_serves(second_listener, addr, b"second-incarnation").await;
}

/// IPv4 loopback-only LISTEN (`127.0.0.1:port`) requires a
/// `LoopbackForwardReq` before the host mirror is created; tears the
/// forwarder down (via `LoopbackForwardCancelReq`) on removal.
#[tokio::test]
async fn loopback_v4_listener_requests_forwarder_before_mirroring() {
    let mut h = Harness::start(Some(Ipv4Addr::new(172, 16, 1, 2)), None);
    h.set_tcp4(format!(
        "{}{}",
        tcp4_header(),
        tcp4_listen_line(0, Ipv4Addr::LOCALHOST, 18_767)
    ));

    let listener = match h.next_command().await {
        PortCommand::Add {
            listener,
            guest_port,
            ..
        } => {
            assert_eq!(guest_port, 18_767);
            listener
        }
        other => panic!("expected PortCommand::Add, got {other:?}"),
    };
    assert!(matches!(h.next_event().await, PortEvent::Added { .. }));

    let reqs = h.loopback_requests();
    assert_eq!(reqs.len(), 1);
    assert_eq!(reqs[0].bind_addr, IpAddr::V4(Ipv4Addr::new(172, 16, 1, 2)));
    assert_eq!(reqs[0].port, 18_767);
    // Same-family loopback: no explicit override needed.
    assert!(
        reqs[0].loopback_target.is_none()
            || reqs[0].loopback_target == Some(IpAddr::V4(Ipv4Addr::LOCALHOST))
    );

    let addr = listener.local_addr().unwrap();
    assert_connectable_and_serves(listener, addr, b"hello-loopback").await;

    h.set_tcp4(tcp4_header());
    assert!(matches!(h.next_command().await, PortCommand::Remove { .. }));
    assert!(matches!(h.next_event().await, PortEvent::Removed { .. }));
    assert_eq!(h.loopback_cancels().len(), 1);
    assert_eq!(h.loopback_cancels()[0].port, 18_767);
}

/// IPv6 loopback-only LISTEN (`[::1]:port`) on a dual-stack sandbox:
/// smoltcp dials the guest's IPv4 VLAN address (preferred when both
/// are present), so the `LoopbackForwardReq` must bind on
/// `guest_ipv4` while dialing `[::1]` — the cross-family case flagged
/// as uncovered (only the isolated agentd forwarder unit test,
/// `bridge_ipv6_dials_v6_loopback`, exercised this family mismatch
/// before this test; this exercises the *runtime* side constructing
/// the request over the real wire protocol).
#[tokio::test]
async fn loopback_v6_listener_uses_cross_family_loopback_target() {
    let guest_v4 = Ipv4Addr::new(172, 16, 1, 2);
    let mut h = Harness::start(
        Some(guest_v4),
        Some(Ipv6Addr::new(0xfe80, 0, 0, 0, 0, 0, 0, 1)),
    );

    {
        let mut st = h.state.lock().unwrap();
        st.tcp6 = format!(
            "{}{}",
            tcp6_header(),
            tcp6_listen_line(0, Ipv6Addr::LOCALHOST, 18_768)
        );
    }

    let listener = match h.next_command().await {
        PortCommand::Add {
            listener,
            guest_port,
            ..
        } => {
            assert_eq!(guest_port, 18_768);
            listener
        }
        other => panic!("expected PortCommand::Add, got {other:?}"),
    };
    assert!(matches!(h.next_event().await, PortEvent::Added { .. }));

    let reqs = h.loopback_requests();
    assert_eq!(
        reqs.len(),
        1,
        "v6 loopback LISTEN must trigger exactly one LoopbackForwardReq"
    );
    assert_eq!(
        reqs[0].bind_addr,
        IpAddr::V4(guest_v4),
        "bind_addr must match smoltcp's v4-preferred dial address, not the v6 LISTEN's own family"
    );
    assert_eq!(
        reqs[0].loopback_target,
        Some(IpAddr::V6(Ipv6Addr::LOCALHOST)),
        "loopback_target must be set explicitly to [::1] since it differs from bind_addr's family"
    );
    assert_eq!(reqs[0].port, 18_768);

    let addr = listener.local_addr().unwrap();
    assert_connectable_and_serves(listener, addr, b"hello-v6-loopback").await;

    {
        let mut st = h.state.lock().unwrap();
        st.tcp6 = tcp6_header();
    }
    assert!(matches!(h.next_command().await, PortCommand::Remove { .. }));
    assert!(matches!(h.next_event().await, PortEvent::Removed { .. }));
    assert_eq!(h.loopback_cancels().len(), 1);
    assert_eq!(h.loopback_cancels()[0].port, 18_768);
}

/// When the preferred host port is already taken (simulated here by
/// binding it ourselves before the ADD pass runs), `bind_host_for`
/// must fall back to an OS-assigned ephemeral port rather than
/// failing the whole poll loop or losing track of other ports — and
/// the fallback listener must be genuinely connectable.
#[tokio::test]
async fn host_bind_collision_falls_back_to_ephemeral_port() {
    // Occupy the port auto-publish will prefer.
    let blocker = tokio::net::TcpListener::bind((Ipv4Addr::LOCALHOST, 18_769))
        .await
        .expect("bind blocker");

    let mut h = Harness::start(Some(Ipv4Addr::new(172, 16, 1, 2)), None);
    h.set_tcp4(format!(
        "{}{}",
        tcp4_header(),
        tcp4_listen_line(0, Ipv4Addr::UNSPECIFIED, 18_769)
    ));

    let (listener, host_port) = match h.next_command().await {
        PortCommand::Add {
            listener,
            guest_port,
            ..
        } => {
            assert_eq!(guest_port, 18_769);
            let port = listener.local_addr().unwrap().port();
            (listener, port)
        }
        other => panic!("expected PortCommand::Add, got {other:?}"),
    };
    assert_ne!(
        host_port, 18_769,
        "ephemeral fallback must pick a different port than the blocked preferred one"
    );

    match h.next_event().await {
        PortEvent::Added {
            guest_port,
            host_port: ev_port,
            ..
        } => {
            assert_eq!(guest_port, 18_769);
            assert_eq!(
                ev_port, host_port,
                "PortEvent::Added must report the actual (fallback) port"
            );
        }
        other => panic!("expected PortEvent::Added, got {other:?}"),
    }

    let addr = listener.local_addr().unwrap();
    assert_connectable_and_serves(listener, addr, b"hello-ephemeral").await;
    drop(blocker);
}

/// A guest port that is both explicitly published at boot
/// (`explicit_guest_ports`) and guest-LISTENing must never be mirrored
/// by auto-publish — the "explicit and automatic publishing coexist
/// without duplicate listeners" acceptance criterion (S1 in the code
/// review). No `PortCommand`/`PortEvent` should be emitted for it at
/// all.
#[tokio::test]
async fn explicitly_published_port_is_excluded_from_auto_publish() {
    let mut explicit = HashSet::new();
    explicit.insert(18_770u16);
    let mut h = Harness::start_with_explicit(Some(Ipv4Addr::new(172, 16, 1, 2)), None, explicit);

    // A second, non-explicit port alongside the excluded one, so we
    // can positively confirm the loop is still running and would
    // react to new listens — just not this one.
    h.set_tcp4(format!(
        "{}{}{}",
        tcp4_header(),
        tcp4_listen_line(0, Ipv4Addr::UNSPECIFIED, 18_770),
        tcp4_listen_line(1, Ipv4Addr::UNSPECIFIED, 18_771),
    ));

    // The only command that should arrive is for port 18_771.
    match h.next_command().await {
        PortCommand::Add { guest_port, .. } => assert_eq!(guest_port, 18_771),
        other => panic!("expected PortCommand::Add for the non-explicit port, got {other:?}"),
    }
    match h.next_event().await {
        PortEvent::Added { guest_port, .. } => assert_eq!(guest_port, 18_771),
        other => panic!("expected PortEvent::Added, got {other:?}"),
    }

    // Give the loop a few more ticks; nothing further must arrive for
    // 18_770.
    assert!(
        timeout(Duration::from_millis(300), h.port_rx.recv())
            .await
            .is_err(),
        "no PortCommand should ever be emitted for an explicitly-published port"
    );
}
