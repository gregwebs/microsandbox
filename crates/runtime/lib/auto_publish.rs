//! Runtime side of auto-publish.
//!
//! Spawns a tokio task that loop-polls the guest's
//! `/proc/net/tcp{,6}` via a loopback connection to the relay's
//! agent.sock, diffs the LISTEN set against currently-active host
//! listeners, and drives [`PortPublisher`](microsandbox_network::publisher::PortPublisher)
//! through [`PortCommand`]s.
//!
//! Why the loopback UDS instead of an in-process channel into the
//! relay: the relay already routes framed messages to/from agentd,
//! and giving it a "synthetic client" by opening a UDS to itself is
//! one extra socketpair-equivalent round-trip — far cheaper than
//! extending the relay's internal API to support host-local frame
//! injection. Frames go agentd → ring → relay → loopback UDS → us,
//! same path any SDK client would take.
//!
//! Unix-only: the loopback connection dials the relay's Unix domain
//! socket directly (`UnixStream::connect`), bypassing the
//! platform-abstracted client transport in `agent-client` (which
//! supports Windows named pipes for SDK clients). Porting this to a
//! named-pipe dial is tracked separately; until then, auto-publish is
//! unavailable on Windows and `vm.rs` never spawns this task there.

use std::collections::{BTreeMap, BTreeSet, HashMap, HashSet};
use std::net::{IpAddr, Ipv4Addr, Ipv6Addr, SocketAddr};
use std::path::PathBuf;
use std::sync::Arc;
use std::time::Duration;

use microsandbox_network::auto_publish::{
    ListenEntry, parse_listen_v4, parse_listen_v6, should_forward,
};
use microsandbox_network::config::AutoPublishConfig;
use microsandbox_network::publisher::PortCommand;
use microsandbox_protocol::codec::{read_message, write_message};
use microsandbox_protocol::fs::{
    FsData, FsOp, FsOpenOptions, FsRequest, FsResponse, FsResponseData,
};
use microsandbox_protocol::message::{Message, MessageType};
use microsandbox_protocol::network::{
    LoopbackForwardCancelReq, LoopbackForwardReq, LoopbackForwardResp, PortEvent,
};
use tokio::io::{AsyncReadExt, BufReader};
use tokio::net::{TcpListener, UnixStream};
use tokio::sync::mpsc::UnboundedSender;
use tokio::time::sleep;

//--------------------------------------------------------------------------------------------------
// Constants
//--------------------------------------------------------------------------------------------------

/// Initial supervisor restart delay. Short enough that a single
/// dropped frame restarts within a poll cycle; long enough to
/// avoid a hot loop when agent.sock is permanently gone.
const INITIAL_RESTART_BACKOFF: Duration = Duration::from_millis(100);

/// Ceiling on the supervisor's exponential backoff between
/// `run()` restarts.
const MAX_RESTART_BACKOFF: Duration = Duration::from_secs(30);

/// Reserved broadcast id (re-export of the protocol constant) that
/// the IdCounter must never emit — a request id colliding with the
/// PortEvent broadcast id would route the SDK's port_events
/// subscriber the FsResponse/LoopbackForwardResp body, which it
/// would then drop with `msg.t != PortEvent`.
const RESERVED_BROADCAST_ID: u32 = microsandbox_protocol::network::PORT_EVENT_BROADCAST_ID;

//--------------------------------------------------------------------------------------------------
// Types
//--------------------------------------------------------------------------------------------------

/// Abstraction so the runtime can plug its relay-side broadcast in
/// without the network crate (or this module) needing to import the
/// `AgentRelay` type directly. Implementations push the same
/// `PortEvent` frame to every connected SDK client.
pub trait EventBroadcast: Send + Sync {
    /// Push a [`PortEvent`] to every connected SDK client. The
    /// caller already constructed the framed `Message`; the impl
    /// just needs to forward the bytes.
    fn broadcast_port_event(&self, event: PortEvent);
}

/// Bookkeeping for one active mapping. Tracks the host side of
/// the forward (so we can emit a precise `Removed` event later)
/// plus the `WantedFamily` the mapping was created for so the
/// RECONCILE pass can detect bind-mode flips (and so a teardown
/// knows whether to issue a LoopbackForwardCancel).
struct ActiveMapping {
    host_bind: IpAddr,
    host_port: u16,
    /// The `WantedFamily` we wired up for. `WildcardAny` →
    /// no agentd forwarder was spawned; the other variants both
    /// imply a LoopbackForward was sent and must be cancelled on
    /// teardown.
    family: WantedFamily,
}

/// Monotonic id allocator clamped within the relay-assigned slot
/// range. Without the clamp a raw `wrapping_add(1)` could carry us
/// past `id_max` into a neighbouring slot's range, and the relay
/// would route our FsResponse / LoopbackForwardResp to the wrong
/// client. Mirrors the math in `AgentClient::next_id`, plus an
/// extra guard against landing on
/// [`microsandbox_protocol::network::PORT_EVENT_BROADCAST_ID`] —
/// for the highest relay slot, the raw slot range reaches
/// `u32::MAX`, which includes that broadcast id.
///
/// Constructor `assert!`s (not `debug_assert!`) so a degenerate
/// counter is loud in release. A single-id window would silently
/// reuse the same correlation id for every request — the SDK
/// reader_loop keys pending on id, so request N+1's reply tx
/// overwrites request N's, and request N blocks forever.
pub(crate) struct IdCounter {
    next: u32,
    min: u32,
    /// Exclusive upper bound. Always strictly less than
    /// `RESERVED_BROADCAST_ID + 1`, AND the constructor enforces
    /// `min + 2 <= max` so the window has at least two distinct ids.
    max: u32,
}

/// Per-port summary the diff loop consumes: does this port need
/// an in-guest forwarder (loopback-only) AND which IP family
/// owns the LISTEN. The family matters for the loopback case: a
/// `[::1]:port` LISTEN must trigger a v6 LoopbackForward (agentd
/// binds the guest's v6 NIC address and dials `[::1]`), otherwise
/// the bridge dials the wrong family and ECONNREFUSEs.
///
/// For a wildcard bind (`0.0.0.0` or `[::]`) the smoltcp publisher
/// reaches the guest service directly via the VLAN IP — family
/// here is irrelevant; the runtime uses `WantedFamily::Any`.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum WantedFamily {
    /// LISTEN bound on `127.0.0.1` only — need a v4 agentd
    /// forwarder bound to `guest_ipv4:port → 127.0.0.1:port`.
    LoopbackV4,
    /// LISTEN bound on `[::1]` only — need a v6 agentd forwarder
    /// bound to `[guest_ipv6]:port → [::1]:port`.
    LoopbackV6,
    /// Wildcard bind on either family — smoltcp dial works
    /// without an agentd forwarder.
    WildcardAny,
}

//--------------------------------------------------------------------------------------------------
// Methods
//--------------------------------------------------------------------------------------------------

impl IdCounter {
    pub(crate) fn new(min: u32, max: u32) -> Self {
        // Clamp away from the broadcast id even if the caller passed
        // a window that would include it. `RESERVED_BROADCAST_ID` is
        // u32::MAX - 1, so `max = RESERVED_BROADCAST_ID` excludes it
        // cleanly (the range is `[min, max)`).
        let max = max.min(RESERVED_BROADCAST_ID);
        // `assert!` not `debug_assert!` — a degenerate counter is a
        // silent infinite-collision bug in release builds.
        assert!(
            min < max,
            "IdCounter::new requires min ({min}) < max ({max}) after broadcast-id clamp"
        );
        assert!(
            max - min >= 2,
            "IdCounter::new requires a window of at least 2 ids; got [{min}, {max})"
        );
        Self {
            next: min,
            min,
            max,
        }
    }

    pub(crate) fn next(&mut self) -> u32 {
        let id = self.next;
        // `>=` so `max` itself is excluded — that boundary value
        // belongs to the next slot under `frame.id / ID_RANGE_STEP`.
        self.next = if self.next.saturating_add(1) >= self.max {
            self.min
        } else {
            self.next + 1
        };
        id
    }
}

impl WantedFamily {
    fn needs_loopback_forwarder(self) -> bool {
        !matches!(self, WantedFamily::WildcardAny)
    }
}

//--------------------------------------------------------------------------------------------------
// Functions
//--------------------------------------------------------------------------------------------------

/// Spawn the auto-publish background task on the supplied tokio
/// runtime handle.
///
/// Takes the handle explicitly rather than relying on the current
/// tokio context because the caller in `vm.rs` runs in the
/// synchronous startup path, not inside a tokio task.
///
/// `guest_ipv4` is the guest's eth0 IPv4 (or `None` for v6-only
/// sandboxes). Used as the bind address sent to agentd via
/// `LoopbackForwardReq` when a `127.0.0.1`-only LISTEN is
/// detected — agentd binds `guest_ipv4:port` inside the guest so
/// smoltcp's existing dial-to-VLAN-IP path lands on that
/// listener instead of failing against guest loopback.
///
/// `explicit_guest_ports` is the set of guest ports already covered by a
/// boot-time `--publish` listener (`NetworkConfig.ports`). Auto-publish
/// skips these: an explicit listener already owns
/// `host_bind:guest_port`, so mirroring the same guest LISTEN would hit
/// `bind_host_for`'s EADDRINUSE fallback and stand up a second, ephemeral
/// host listener for the same guest port — exactly the duplicate the
/// "explicit and automatic publishing coexist without duplicate
/// listeners" contract rules out.
#[allow(clippy::too_many_arguments)]
pub fn spawn(
    runtime: &tokio::runtime::Handle,
    agent_sock_path: PathBuf,
    cfg: AutoPublishConfig,
    port_handle: UnboundedSender<PortCommand>,
    guest_ipv4: Option<Ipv4Addr>,
    guest_ipv6: Option<Ipv6Addr>,
    event_broadcast: Arc<dyn EventBroadcast>,
    explicit_guest_ports: HashSet<u16>,
) {
    runtime.spawn(async move {
        // Supervisor: re-establish the loopback UDS connection
        // after stream-level errors so a transient hiccup (broken
        // pipe, partial frame, malformed reply) doesn't silently
        // disable auto-publish for the sandbox's lifetime.
        //
        // `active` is owned BY THE SUPERVISOR (not by run()) so
        // mappings survive across reconnects. If the supervisor
        // dropped its own `active`, the next run() would re-detect
        // every still-LISTENing guest port as "new" and send
        // PortCommand::Add — the matching host port is still owned
        // by a listener registered in the previous run, so bind_host_for
        // EADDRINUSEs and falls back to ephemeral. Result: each
        // reconnect would leak one orphan listener per active port.
        //
        // `port_handle.send(...)` failing — the PortPublisher / smoltcp
        // stack is gone — is the only sentinel for permanent shutdown;
        // `run()` returns Ok in that case and we don't restart.
        //
        // Backoff: exponential with cap. Without this, a permanently
        // unreachable agent.sock (relay shut down but supervisor not
        // yet aborted) would spin at fixed 1s burning CPU.
        let mut active: HashMap<u16, ActiveMapping> = HashMap::new();
        let mut backoff = INITIAL_RESTART_BACKOFF;
        loop {
            match run(
                &agent_sock_path,
                &cfg,
                &port_handle,
                guest_ipv4,
                guest_ipv6,
                &*event_broadcast,
                &mut active,
                &explicit_guest_ports,
            )
            .await
            {
                Ok(()) => {
                    tracing::debug!("auto-publish: clean shutdown");
                    return;
                }
                Err(e) => {
                    tracing::warn!(
                        ?e,
                        ?backoff,
                        "auto-publish: connection lost, reconnecting after backoff",
                    );
                    tokio::time::sleep(backoff).await;
                    backoff = (backoff * 2).min(MAX_RESTART_BACKOFF);
                }
            }
        }
    });
}

/// Distinguish stream-level errors (UDS dead — supervisor must
/// reconnect) from app-level errors (agentd returned `ok=false`,
/// CBOR decode failed, etc. — keep going on the existing stream).
fn is_stream_error(e: &std::io::Error) -> bool {
    use std::io::ErrorKind::*;
    matches!(
        e.kind(),
        BrokenPipe | UnexpectedEof | ConnectionReset | ConnectionAborted | NotConnected | WriteZero
    )
}

#[allow(clippy::too_many_arguments)]
async fn run(
    agent_sock_path: &PathBuf,
    cfg: &AutoPublishConfig,
    port_handle: &UnboundedSender<PortCommand>,
    guest_ipv4: Option<Ipv4Addr>,
    guest_ipv6: Option<Ipv6Addr>,
    broadcast: &dyn EventBroadcast,
    active: &mut HashMap<u16, ActiveMapping>,
    explicit_guest_ports: &HashSet<u16>,
) -> std::io::Result<()> {
    // Connect a loopback client to the relay and consume the handshake it
    // sends to every client before the Ready frame:
    //
    //   [id_start: u32 BE][id_end_exclusive: u32 BE][ready_frame_bytes...]
    //
    // (see `AgentRelay::run` in relay.rs). `[id_start, id_end_exclusive)` is
    // THIS client's assigned correlation-id slot. The ring reader demuxes
    // replies back to the originating slot via `frame.id /
    // AGENT_RELAY_ID_RANGE_STEP`, and the relay drops (and disconnects on) any
    // frame whose id falls outside the assigned range — so we must take the
    // window straight from the handshake rather than recomputing it from a
    // hardcoded step (which drifts whenever AGENT_RELAY_MAX_CLIENTS changes).
    let mut stream = connect_with_retry(agent_sock_path).await?;
    let mut range_buf = [0u8; 8];
    stream.read_exact(&mut range_buf).await?;
    let id_min = u32::from_be_bytes(range_buf[0..4].try_into().unwrap());
    let id_max = u32::from_be_bytes(range_buf[4..8].try_into().unwrap());
    let mut read_half_tmp = BufReader::new(&mut stream);
    // Consume the Ready frame.
    let ready = read_message(&mut read_half_tmp)
        .await
        .map_err(protocol_err)?;
    debug_assert_eq!(ready.t, MessageType::Ready);
    drop(read_half_tmp);

    let (mut read_half, mut write_half) = stream.into_split();
    let mut buf_read = BufReader::new(&mut read_half);

    let host_bind: IpAddr = cfg.host_bind;
    let poll = Duration::from_millis(cfg.poll_interval_ms);

    // ID counter confined to our assigned slot `[id_min, id_max)`. IdCounter
    // also clamps away from `PORT_EVENT_BROADCAST_ID` so we can't collide with
    // the SDK's port_events subscriber.
    let mut next_req_id: IdCounter = IdCounter::new(id_min, id_max);

    loop {
        sleep(poll).await;

        let tcp4 = match read_proc(
            "/proc/net/tcp",
            &mut next_req_id,
            &mut write_half,
            &mut buf_read,
        )
        .await
        {
            Ok(s) => s,
            // Stream-level errors → bubble up to the supervisor so
            // it reconnects. App-level errors (agentd refused the
            // FsRequest, transient procfs glitch, CBOR decode bug)
            // → log and try next poll on the same connection.
            Err(e) if is_stream_error(&e) => return Err(e),
            Err(e) => {
                tracing::debug!(?e, "auto-publish: read /proc/net/tcp failed (transient)");
                continue;
            }
        };
        let tcp6 = match read_proc(
            "/proc/net/tcp6",
            &mut next_req_id,
            &mut write_half,
            &mut buf_read,
        )
        .await
        {
            Ok(s) => s,
            Err(e) if is_stream_error(&e) => return Err(e),
            Err(e) => {
                tracing::debug!(?e, "auto-publish: read /proc/net/tcp6 failed (transient)");
                String::new()
            }
        };

        let listening: BTreeSet<ListenEntry> = parse_listen_v4(&tcp4)
            .into_iter()
            .chain(parse_listen_v6(&tcp6))
            .filter(|e| should_forward(*e))
            .collect();
        let mut wanted = collapse_listeners(&listening);
        exclude_explicit_ports(&mut wanted, explicit_guest_ports);

        // RECONCILE: ports present in BOTH active and wanted but
        // whose loopback flag flipped (e.g. dev-server restart
        // switched `--host 0.0.0.0` → `--host 127.0.0.1` or
        // vice-versa). Without re-evaluation, the latched
        // `has_loopback_forwarder` from the first detection would
        // either leave an agentd forwarder un-spawned (loopback
        // case → smoltcp dials a NIC address with no listener) or
        // leave one running pointlessly (wildcard case). Tear the
        // stale mapping down here so the ADD phase below
        // re-creates it with the correct state.
        let mutated: Vec<u16> = active
            .iter()
            .filter_map(|(port, mapping)| {
                wanted
                    .get(port)
                    .and_then(|wf| (mapping.family != *wf).then_some(*port))
            })
            .collect();
        for guest_port in mutated {
            if let Some(mapping) = active.remove(&guest_port) {
                tracing::info!(
                    guest_port,
                    host_port = mapping.host_port,
                    "auto-publish: bind mode changed; rebuilding mapping",
                );
                let _ = port_handle.send(PortCommand::Remove {
                    host_bind: mapping.host_bind,
                    host_port: mapping.host_port,
                });
                if mapping.family.needs_loopback_forwarder() {
                    let _ = send_loopback_cancel(
                        guest_port,
                        &mut next_req_id,
                        &mut write_half,
                        &mut buf_read,
                    )
                    .await;
                }
                broadcast.broadcast_port_event(PortEvent::Removed {
                    host_bind: mapping.host_bind,
                    host_port: mapping.host_port,
                    guest_port,
                });
            }
        }

        // ADD: ports newly listening that we haven't mirrored yet
        // (including ones torn down above by the RECONCILE pass).
        let new_ports: Vec<(u16, WantedFamily)> = wanted
            .iter()
            .filter(|(p, _)| !active.contains_key(p))
            .map(|(p, wf)| (*p, *wf))
            .collect();
        for (guest_port, family) in new_ports {
            // For loopback-only guest LISTENs we need agentd to
            // bring up an in-guest forwarder. Two addresses matter:
            //
            //   bind_addr     — must match the family smoltcp dials
            //                   (v4 if guest_ipv4 is set, else v6).
            //                   Otherwise smoltcp's dial lands at no
            //                   listener and clients ECONNREFUSE.
            //
            //   loopback_target — must match the LISTEN's family so
            //                     the bridge actually reaches the
            //                     guest service. A v6-only service
            //                     at [::1]:port can't be dialed via
            //                     127.0.0.1:port and vice versa.
            //
            // The two often coincide, but for a `[::1]` LISTEN on a
            // dual-stack sandbox they differ: bind on guest_ipv4
            // (where smoltcp goes) and dial [::1] (where the
            // service is).
            let smoltcp_dial_addr = guest_ipv4
                .map(IpAddr::V4)
                .or_else(|| guest_ipv6.map(IpAddr::V6));
            let loopback_target: IpAddr = match family {
                WantedFamily::LoopbackV4 => IpAddr::V4(Ipv4Addr::LOCALHOST),
                WantedFamily::LoopbackV6 => IpAddr::V6(Ipv6Addr::LOCALHOST),
                WantedFamily::WildcardAny => IpAddr::V4(Ipv4Addr::LOCALHOST),
            };
            let loopback_ok = if family.needs_loopback_forwarder() {
                match smoltcp_dial_addr {
                    Some(bind_addr) => match send_loopback_forward(
                        bind_addr,
                        Some(loopback_target),
                        guest_port,
                        &mut next_req_id,
                        &mut write_half,
                        &mut buf_read,
                    )
                    .await
                    {
                        Ok(()) => true,
                        Err(e) if is_stream_error(&e) => return Err(e),
                        Err(e) => {
                            tracing::warn!(
                                guest_port,
                                ?e,
                                "auto-publish: LoopbackForward request failed; skipping port",
                            );
                            false
                        }
                    },
                    None => {
                        tracing::debug!(
                            guest_port,
                            ?family,
                            "auto-publish: skipping loopback LISTEN — sandbox has no guest IP",
                        );
                        false
                    }
                }
            } else {
                true
            };
            if !loopback_ok {
                continue;
            }

            match bind_host_for(host_bind, guest_port).await {
                Ok((listener, addr)) => {
                    let key = (addr.ip(), addr.port());
                    if port_handle
                        .send(PortCommand::Add {
                            listener,
                            key,
                            guest_port,
                        })
                        .is_err()
                    {
                        // PortPublisher gone — sandbox shutting down.
                        return Ok(());
                    }
                    active.insert(
                        guest_port,
                        ActiveMapping {
                            host_bind: addr.ip(),
                            host_port: addr.port(),
                            family,
                        },
                    );
                    broadcast.broadcast_port_event(PortEvent::Added {
                        host_bind: addr.ip(),
                        host_port: addr.port(),
                        guest_port,
                    });
                    tracing::info!(
                        guest_port,
                        host_port = addr.port(),
                        ?family,
                        "auto-publish: mapping added",
                    );
                }
                Err(e) => {
                    tracing::warn!(guest_port, ?e, "auto-publish: bind failed");
                    // The loopback forwarder we asked agentd to
                    // spawn would now leak. Cancel it so we don't
                    // accumulate orphans across poll cycles.
                    if family.needs_loopback_forwarder() {
                        let _ = send_loopback_cancel(
                            guest_port,
                            &mut next_req_id,
                            &mut write_half,
                            &mut buf_read,
                        )
                        .await;
                    }
                }
            }
        }

        // REMOVE: previously-active ports that went away.
        let stale: Vec<u16> = active
            .keys()
            .copied()
            .filter(|p| !wanted.contains_key(p))
            .collect();
        for guest_port in stale {
            if let Some(mapping) = active.remove(&guest_port) {
                let _ = port_handle.send(PortCommand::Remove {
                    host_bind: mapping.host_bind,
                    host_port: mapping.host_port,
                });
                if mapping.family.needs_loopback_forwarder()
                    && let Err(e) = send_loopback_cancel(
                        guest_port,
                        &mut next_req_id,
                        &mut write_half,
                        &mut buf_read,
                    )
                    .await
                {
                    if is_stream_error(&e) {
                        return Err(e);
                    }
                    tracing::warn!(
                        guest_port,
                        ?e,
                        "auto-publish: LoopbackForwardCancel failed (forwarder may leak)",
                    );
                }
                broadcast.broadcast_port_event(PortEvent::Removed {
                    host_bind: mapping.host_bind,
                    host_port: mapping.host_port,
                    guest_port,
                });
                tracing::info!(
                    guest_port,
                    host_port = mapping.host_port,
                    "auto-publish: mapping removed",
                );
            }
        }
    }
}

/// Try to bind `(host_bind, guest_port)` first so the host port
/// mirrors the guest port (Lima-ish). If that's taken, fall back to
/// an OS-assigned ephemeral port.
async fn bind_host_for(
    host_bind: IpAddr,
    guest_port: u16,
) -> std::io::Result<(TcpListener, SocketAddr)> {
    let preferred = SocketAddr::new(host_bind, guest_port);
    if let Ok(l) = TcpListener::bind(preferred).await {
        let addr = l.local_addr()?;
        return Ok((l, addr));
    }
    let any = SocketAddr::new(host_bind, 0);
    let l = TcpListener::bind(any).await?;
    let addr = l.local_addr()?;
    Ok((l, addr))
}

async fn connect_with_retry(path: &PathBuf) -> std::io::Result<UnixStream> {
    // The agent.sock listener is up before the auto-publish task
    // spawns (vm.rs orders this), but guard against early-boot
    // races where the listener hasn't yet bound on a slow host.
    let mut backoff = Duration::from_millis(50);
    for _ in 0..20 {
        match UnixStream::connect(path).await {
            Ok(s) => return Ok(s),
            Err(_) => {
                sleep(backoff).await;
                backoff = (backoff * 2).min(Duration::from_millis(500));
            }
        }
    }
    UnixStream::connect(path).await
}

async fn read_proc(
    path: &str,
    next_req_id: &mut IdCounter,
    write_half: &mut tokio::net::unix::OwnedWriteHalf,
    read_half: &mut BufReader<&mut tokio::net::unix::OwnedReadHalf>,
) -> std::io::Result<String> {
    // Upstream's FS protocol is handle-based: open the file → read the whole
    // file by handle (streaming FsData chunks) → close. (The old one-shot
    // `FsOp::Read { path }` no longer exists.)
    let open_id = next_req_id.next();
    let open_req = FsRequest {
        op: FsOp::OpenFile {
            path: path.to_string(),
            options: FsOpenOptions {
                read: true,
                write: false,
                append: false,
                create: false,
                truncate: false,
                create_new: false,
                mode: None,
            },
        },
    };
    let msg = Message::with_payload(MessageType::FsRequest, open_id, &open_req).map_err(io_err)?;
    write_message(write_half, &msg)
        .await
        .map_err(protocol_err)?;
    let handle = loop {
        let msg = read_message(read_half).await.map_err(protocol_err)?;
        if msg.id != open_id {
            continue;
        }
        if msg.t == MessageType::FsResponse {
            let resp: FsResponse = msg.payload().map_err(io_err)?;
            if !resp.ok {
                return Err(std::io::Error::other(
                    resp.error.unwrap_or_else(|| "fs open failed".into()),
                ));
            }
            match resp.data {
                Some(FsResponseData::Handle(h)) => break h,
                _ => return Err(std::io::Error::other("fs open: no handle in response")),
            }
        }
    };

    let read_id = next_req_id.next();
    let read_req = FsRequest {
        op: FsOp::Read {
            handle,
            offset: 0,
            len: None,
        },
    };
    let msg = Message::with_payload(MessageType::FsRequest, read_id, &read_req).map_err(io_err)?;
    write_message(write_half, &msg)
        .await
        .map_err(protocol_err)?;

    let mut out = Vec::new();
    let mut read_err = None;
    loop {
        let msg = read_message(read_half).await.map_err(protocol_err)?;
        if msg.id != read_id {
            continue;
        }
        match msg.t {
            MessageType::FsData => {
                let chunk: FsData = msg.payload().map_err(io_err)?;
                out.extend_from_slice(&chunk.data);
            }
            MessageType::FsResponse => {
                let resp: FsResponse = msg.payload().map_err(io_err)?;
                if !resp.ok {
                    read_err = Some(resp.error.unwrap_or_else(|| "fs read failed".into()));
                }
                break;
            }
            _ => {}
        }
    }

    // Close the handle (best-effort) before returning.
    let close_id = next_req_id.next();
    let close_req = FsRequest {
        op: FsOp::CloseHandle { handle },
    };
    if let Ok(msg) = Message::with_payload(MessageType::FsRequest, close_id, &close_req) {
        let _ = write_message(write_half, &msg).await;
        loop {
            match read_message(read_half).await {
                Ok(m) if m.id == close_id && m.t == MessageType::FsResponse => break,
                Ok(_) => continue,
                Err(_) => break,
            }
        }
    }

    if let Some(e) = read_err {
        return Err(std::io::Error::other(e));
    }
    String::from_utf8(out).map_err(|e| std::io::Error::other(format!("utf-8: {e}")))
}

async fn send_loopback_forward(
    bind_addr: IpAddr,
    loopback_target: Option<IpAddr>,
    port: u16,
    next_req_id: &mut IdCounter,
    write_half: &mut tokio::net::unix::OwnedWriteHalf,
    read_half: &mut BufReader<&mut tokio::net::unix::OwnedReadHalf>,
) -> std::io::Result<()> {
    let req = LoopbackForwardReq {
        bind_addr,
        port,
        loopback_target,
    };
    send_loopback_req(
        MessageType::LoopbackForward,
        &req,
        next_req_id,
        write_half,
        read_half,
    )
    .await
}

async fn send_loopback_cancel(
    port: u16,
    next_req_id: &mut IdCounter,
    write_half: &mut tokio::net::unix::OwnedWriteHalf,
    read_half: &mut BufReader<&mut tokio::net::unix::OwnedReadHalf>,
) -> std::io::Result<()> {
    let req = LoopbackForwardCancelReq { port };
    send_loopback_req(
        MessageType::LoopbackForwardCancel,
        &req,
        next_req_id,
        write_half,
        read_half,
    )
    .await
}

async fn send_loopback_req<T: serde::Serialize>(
    msg_type: MessageType,
    payload: &T,
    next_req_id: &mut IdCounter,
    write_half: &mut tokio::net::unix::OwnedWriteHalf,
    read_half: &mut BufReader<&mut tokio::net::unix::OwnedReadHalf>,
) -> std::io::Result<()> {
    let id = next_req_id.next();
    let msg = Message::with_payload(msg_type, id, payload).map_err(io_err)?;
    write_message(write_half, &msg)
        .await
        .map_err(protocol_err)?;

    loop {
        let reply = read_message(read_half).await.map_err(protocol_err)?;
        if reply.id != id {
            continue;
        }
        if reply.t != MessageType::LoopbackForwardResp {
            return Err(std::io::Error::other(format!(
                "unexpected reply type for loopback req: {:?}",
                reply.t
            )));
        }
        let resp: LoopbackForwardResp = reply.payload().map_err(io_err)?;
        if !resp.ok {
            return Err(std::io::Error::other(
                resp.error
                    .unwrap_or_else(|| "agentd refused request".into()),
            ));
        }
        return Ok(());
    }
}

fn io_err<E: std::fmt::Display>(e: E) -> std::io::Error {
    std::io::Error::other(e.to_string())
}

/// Convert a [`microsandbox_protocol`] error into an `io::Error`
/// while preserving the underlying `ErrorKind` when one exists.
/// `io_err` flattens everything to `ErrorKind::Other`, which then
/// hides stream-level errors from [`is_stream_error`] — the
/// supervisor's reconnect path depends on us preserving
/// `BrokenPipe` / `UnexpectedEof` / friends.
fn protocol_err(e: microsandbox_protocol::ProtocolError) -> std::io::Error {
    use microsandbox_protocol::ProtocolError;
    match e {
        ProtocolError::Io(io) => io,
        ProtocolError::UnexpectedEof => std::io::Error::from(std::io::ErrorKind::UnexpectedEof),
        other => std::io::Error::other(other.to_string()),
    }
}

/// Collapse a set of LISTEN entries into a per-port [`WantedFamily`].
///
/// Rule: if ANY wildcard bind exists for the port, the port wants
/// `WildcardAny` regardless of how many loopback binds also exist
/// — smoltcp's dial-to-VLAN-IP path already reaches the wildcard
/// listener, so spawning a forwarder would be wasteful and cause
/// duplicate connections. Loopback-only ports become
/// `LoopbackV4`/`LoopbackV6` based on the LISTEN's address family.
/// A port with both v4 and v6 loopback binds (no wildcard) prefers
/// v4 — agentd serves the v4 NIC bind via the v4 forwarder, and
/// any client connecting via the host's v6 path still terminates
/// at the v4 listener after smoltcp's family resolution.
fn collapse_listeners(listening: &BTreeSet<ListenEntry>) -> BTreeMap<u16, WantedFamily> {
    let mut out = BTreeMap::new();
    for e in listening {
        let this = match e.addr {
            IpAddr::V4(a) if a.is_unspecified() => WantedFamily::WildcardAny,
            IpAddr::V6(a) if a.is_unspecified() => WantedFamily::WildcardAny,
            IpAddr::V4(a) if a.is_loopback() => WantedFamily::LoopbackV4,
            IpAddr::V6(a) if a.is_loopback() => WantedFamily::LoopbackV6,
            // Should not reach here because `should_forward` already
            // filters to wildcard|loopback only — be defensive.
            _ => continue,
        };
        out.entry(e.port)
            .and_modify(|prev| *prev = merge_wanted(*prev, this))
            .or_insert(this);
    }
    out
}

fn merge_wanted(a: WantedFamily, b: WantedFamily) -> WantedFamily {
    // Wildcard wins over loopback.
    if matches!(a, WantedFamily::WildcardAny) || matches!(b, WantedFamily::WildcardAny) {
        return WantedFamily::WildcardAny;
    }
    // Both loopback — prefer v4 if either is v4 (matches the doc
    // comment above on collapse_listeners).
    if matches!(a, WantedFamily::LoopbackV4) || matches!(b, WantedFamily::LoopbackV4) {
        return WantedFamily::LoopbackV4;
    }
    WantedFamily::LoopbackV6
}

/// Drop any guest port already covered by an explicit `--publish`
/// listener from the auto-publish `wanted` set.
///
/// Why here, before the RECONCILE/ADD/REMOVE passes: an explicit
/// listener already owns `host_bind:guest_port`, so letting
/// auto-publish treat that guest port as "wanted" would make
/// `bind_host_for` EADDRINUSE against the boot listener and fall
/// back to a second, ephemeral host listener forwarding to the same
/// guest port — the exact duplicate the "explicit and automatic
/// publishing coexist without duplicate listeners" contract rules
/// out.
fn exclude_explicit_ports(
    wanted: &mut BTreeMap<u16, WantedFamily>,
    explicit_guest_ports: &HashSet<u16>,
) {
    wanted.retain(|guest_port, _| !explicit_guest_ports.contains(guest_port));
}

//--------------------------------------------------------------------------------------------------
// Tests
//--------------------------------------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn collapse_marks_v4_loopback() {
        let mut s = BTreeSet::new();
        s.insert(ListenEntry {
            addr: IpAddr::V4(Ipv4Addr::LOCALHOST),
            port: 8080,
        });
        let out = collapse_listeners(&s);
        assert_eq!(out.get(&8080), Some(&WantedFamily::LoopbackV4));
    }

    #[test]
    fn collapse_marks_v6_loopback() {
        // Regression: previously is_loopback was a single bool and
        // the runtime always sent IpAddr::V4 to agentd, so a
        // `[::1]:port` LISTEN got bridged to 127.0.0.1:port and
        // ECONNREFUSED. With WantedFamily::LoopbackV6 the runtime
        // picks the v6 NIC bind address.
        let mut s = BTreeSet::new();
        s.insert(ListenEntry {
            addr: IpAddr::V6(Ipv6Addr::LOCALHOST),
            port: 8080,
        });
        let out = collapse_listeners(&s);
        assert_eq!(out.get(&8080), Some(&WantedFamily::LoopbackV6));
    }

    #[test]
    fn collapse_marks_wildcard_only() {
        let mut s = BTreeSet::new();
        s.insert(ListenEntry {
            addr: IpAddr::V4(Ipv4Addr::UNSPECIFIED),
            port: 8080,
        });
        let out = collapse_listeners(&s);
        assert_eq!(out.get(&8080), Some(&WantedFamily::WildcardAny));
    }

    #[test]
    fn collapse_wildcard_wins_when_both_present() {
        // Regression: an app that binds BOTH 127.0.0.1:80 and
        // 0.0.0.0:80 should NOT trigger an agentd forwarder — the
        // wildcard bind is already smoltcp-reachable.
        let mut s = BTreeSet::new();
        s.insert(ListenEntry {
            addr: IpAddr::V4(Ipv4Addr::LOCALHOST),
            port: 80,
        });
        s.insert(ListenEntry {
            addr: IpAddr::V4(Ipv4Addr::UNSPECIFIED),
            port: 80,
        });
        let out = collapse_listeners(&s);
        assert_eq!(
            out.get(&80),
            Some(&WantedFamily::WildcardAny),
            "wildcard must override loopback for the same port"
        );
    }

    #[test]
    fn collapse_v6_wildcard_wins_over_v4_loopback_on_same_port() {
        let mut s = BTreeSet::new();
        s.insert(ListenEntry {
            addr: IpAddr::V4(Ipv4Addr::LOCALHOST),
            port: 80,
        });
        s.insert(ListenEntry {
            addr: IpAddr::V6(Ipv6Addr::UNSPECIFIED),
            port: 80,
        });
        let out = collapse_listeners(&s);
        assert_eq!(out.get(&80), Some(&WantedFamily::WildcardAny));
    }

    #[test]
    fn collapse_both_loopback_families_prefer_v4() {
        // Dual-stack loopback bind on a port — pick V4 so agentd
        // installs a single forwarder on guest_ipv4:port and any
        // client (v4 or v6 via smoltcp) terminates there.
        let mut s = BTreeSet::new();
        s.insert(ListenEntry {
            addr: IpAddr::V4(Ipv4Addr::LOCALHOST),
            port: 80,
        });
        s.insert(ListenEntry {
            addr: IpAddr::V6(Ipv6Addr::LOCALHOST),
            port: 80,
        });
        let out = collapse_listeners(&s);
        assert_eq!(out.get(&80), Some(&WantedFamily::LoopbackV4));
    }

    #[test]
    fn collapse_independent_ports_keep_their_own_family() {
        let mut s = BTreeSet::new();
        s.insert(ListenEntry {
            addr: IpAddr::V4(Ipv4Addr::LOCALHOST),
            port: 7001,
        });
        s.insert(ListenEntry {
            addr: IpAddr::V4(Ipv4Addr::UNSPECIFIED),
            port: 7002,
        });
        s.insert(ListenEntry {
            addr: IpAddr::V6(Ipv6Addr::LOCALHOST),
            port: 7003,
        });
        let out = collapse_listeners(&s);
        assert_eq!(out.get(&7001), Some(&WantedFamily::LoopbackV4));
        assert_eq!(out.get(&7002), Some(&WantedFamily::WildcardAny));
        assert_eq!(out.get(&7003), Some(&WantedFamily::LoopbackV6));
    }

    #[test]
    fn exclude_explicit_ports_drops_only_the_explicitly_published_port() {
        let mut wanted = BTreeMap::new();
        wanted.insert(8000, WantedFamily::WildcardAny);
        wanted.insert(5000, WantedFamily::LoopbackV4);
        let explicit: HashSet<u16> = [8000].into_iter().collect();

        exclude_explicit_ports(&mut wanted, &explicit);

        assert_eq!(
            wanted.get(&8000),
            None,
            "guest port 8000 is covered by an explicit --publish listener \
             and must not also get an automatic one (duplicate-listener \
             coexistence criterion)"
        );
        assert_eq!(wanted.get(&5000), Some(&WantedFamily::LoopbackV4));
    }

    #[test]
    fn exclude_explicit_ports_is_a_noop_when_nothing_overlaps() {
        let mut wanted = BTreeMap::new();
        wanted.insert(9000, WantedFamily::WildcardAny);
        let explicit: HashSet<u16> = [1234].into_iter().collect();

        exclude_explicit_ports(&mut wanted, &explicit);

        assert_eq!(wanted.get(&9000), Some(&WantedFamily::WildcardAny));
    }

    /// Regression for the wrap bug: a u32 counter that does
    /// `wrapping_add(1)` would carry past id_max into a
    /// neighbouring slot's range. IdCounter must wrap to id_min
    /// instead.
    #[test]
    fn id_counter_wraps_at_max_back_to_min() {
        let mut c = IdCounter::new(100, 105);
        assert_eq!(c.next(), 100);
        assert_eq!(c.next(), 101);
        assert_eq!(c.next(), 102);
        assert_eq!(c.next(), 103);
        // saturating_add(1) >= max → wrap; 104 + 1 == 105 == max,
        // so the very next call wraps.
        assert_eq!(c.next(), 104);
        assert_eq!(c.next(), 100);
        assert_eq!(c.next(), 101);
    }

    /// Edge: counter near u32::MAX is clamped to skip the broadcast
    /// id. Previously a slot-15 client (id_offset ≈ 0xF000_0000)
    /// had id_max == u32::MAX, so next() could emit u32::MAX - 1 =
    /// PORT_EVENT_BROADCAST_ID — that reply would be routed to the
    /// SDK's port_events subscriber instead of back to us.
    #[test]
    fn id_counter_excludes_port_event_broadcast_id() {
        // Construct with a window whose nominal upper bound includes
        // the broadcast id; the constructor must clamp it out.
        let mut c = IdCounter::new(u32::MAX - 4, u32::MAX);
        // Drive the counter through its full range. Expected ids are
        // [MAX-4, MAX-3, MAX-2] — wrap before MAX-1 because the
        // constructor clamps max to MAX-1 (== PORT_EVENT_BROADCAST_ID).
        let mut seen = BTreeSet::new();
        for _ in 0..6 {
            seen.insert(c.next());
        }
        assert!(
            !seen.contains(&u32::MAX),
            "must not emit u32::MAX (out of any client's slot)"
        );
        assert!(
            !seen.contains(&u32::MAX.saturating_sub(1)),
            "must not emit PORT_EVENT_BROADCAST_ID = u32::MAX - 1"
        );
    }

    /// A degenerate single-id window must panic in release, not
    /// silently return the same id forever. Old code used
    /// `debug_assert!`, which optimised out in release builds and
    /// produced an infinite correlation-id collision.
    #[test]
    #[should_panic(expected = "window of at least 2 ids")]
    fn id_counter_rejects_single_id_window() {
        let _ = IdCounter::new(100, 101);
    }

    #[test]
    #[should_panic(expected = "requires min")]
    fn id_counter_rejects_inverted_window() {
        let _ = IdCounter::new(200, 100);
    }
}
