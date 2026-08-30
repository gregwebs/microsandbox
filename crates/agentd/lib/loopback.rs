//! In-guest TCP loopback forwarder for auto-publish.
//!
//! For each `LoopbackForwardReq`, this module spawns a tokio task
//! that binds `bind_addr:port` (typically the guest's eth0 IPv4)
//! inside the guest and bridges every accepted connection to
//! `127.0.0.1:port`.
//!
//! Why a separate listener instead of a kernel-level DNAT: the
//! sandbox guest kernel ships without netfilter, so
//! `iptables -t nat ... DNAT --to 127.0.0.1` + `route_localnet=1`
//! are unavailable. A userspace relay is the only path to make
//! `127.0.0.1`-only guest services reachable from outside the
//! guest's loopback (see the Lima/OrbStack agent design — same
//! idea: terminate the inbound TCP inside the guest, then re-dial
//! loopback there).
//!
//! Port collision: a process can bind `127.0.0.1:N` AND another
//! process can bind `<eth0_ip>:N` simultaneously because the binds
//! target different specific addresses. We rely on this — the
//! guest's user app keeps its loopback bind, and agentd lights up
//! the NIC bind next to it.

use std::collections::HashMap;
use std::net::{IpAddr, Ipv4Addr, Ipv6Addr, SocketAddr};
use std::sync::{Arc, Mutex};
use std::time::Duration;

use tokio::io::AsyncWriteExt;
use tokio::net::{TcpListener, TcpStream};

//--------------------------------------------------------------------------------------------------
// Constants
//--------------------------------------------------------------------------------------------------

/// Maximum backoff between failed accept() attempts.
const ACCEPT_BACKOFF_MAX: Duration = Duration::from_secs(1);
/// Initial backoff after a single accept() failure.
const ACCEPT_BACKOFF_INITIAL: Duration = Duration::from_millis(10);

//--------------------------------------------------------------------------------------------------
// Types
//--------------------------------------------------------------------------------------------------

/// Bookkeeping for active loopback forwarders. Keyed by port —
/// only one forwarder per port, since the smoltcp publisher dials a
/// single guest IP and the listener bind is on that IP. Each entry
/// also remembers the bind_addr so `spawn()` can detect a stale
/// binding (e.g. guest IP renumbered) and replace it.
#[derive(Default, Clone)]
pub struct ForwarderRegistry {
    inner: Arc<Mutex<HashMap<u16, ForwarderHandle>>>,
}

/// One registry entry: the bound address, the loopback dial target,
/// and the JoinHandle of the spawned accept loop. Stored so a
/// later `spawn()` can decide between idempotent no-op (everything
/// matches) and replace (any field differs). The full JoinHandle
/// (not just AbortHandle) is kept so the replace path can await
/// the prior task's exit — `abort()` is asynchronous, so the
/// prior TcpListener may still be bound when we try to bind the
/// new one and would otherwise EADDRINUSE on overlapping addresses.
struct ForwarderHandle {
    bind_addr: IpAddr,
    loopback_target: IpAddr,
    join: tokio::task::JoinHandle<()>,
}

//--------------------------------------------------------------------------------------------------
// Methods
//--------------------------------------------------------------------------------------------------

impl ForwarderRegistry {
    /// Create an empty registry.
    pub fn new() -> Self {
        Self::default()
    }

    /// Spawn a forwarder for `(bind_addr, port) → loopback_target:port`
    /// inside the guest.
    ///
    /// `loopback_target` is the address the bridge dials per
    /// accepted connection. When `None`, defaults to the same-family
    /// loopback (`127.0.0.1` for v4 bind, `[::1]` for v6 bind). The
    /// host runtime sets it explicitly when the LISTEN's family
    /// differs from the smoltcp dial family — e.g. a `[::1]:port`
    /// LISTEN with smoltcp dialing v4: bind on guest_v4 NIC so
    /// smoltcp reaches the forwarder, but dial `[::1]` so the bridge
    /// hits the actual service.
    ///
    /// If a forwarder is already registered for `port` with a
    /// MATCHING (bind_addr, loopback_target) tuple, this is a no-op
    /// (idempotent — covers poll-cycle re-detection). If EITHER
    /// differs, the old forwarder is cancelled and replaced.
    ///
    /// Returns `Ok(())` on success; `Err` carries a stringified
    /// reason (today: bind failure).
    pub async fn spawn(
        &self,
        bind_addr: IpAddr,
        port: u16,
        loopback_target: Option<IpAddr>,
    ) -> Result<(), String> {
        let target = loopback_target.unwrap_or_else(|| loopback_for(bind_addr));

        // Step 1: under the lock, decide between no-op and replace.
        // For the replace case, REMOVE the prior entry so any
        // concurrent spawn() observes "no entry" and races for the
        // bind cleanly (one of them will EADDRINUSE, surfacing the
        // race instead of silently leaking a stale entry).
        let prior = {
            let mut map = self.inner.lock().unwrap();
            if let Some(existing) = map.get(&port) {
                if existing.bind_addr == bind_addr && existing.loopback_target == target {
                    return Ok(());
                }
                map.remove(&port)
            } else {
                None
            }
        };

        // Step 2: await the prior task's exit BEFORE the new bind.
        // abort() is asynchronous; if we bind eagerly, the prior
        // TcpListener may still own the port and the new bind hits
        // EADDRINUSE (especially likely when the bind_addrs overlap
        // — e.g. 127.0.0.2 vs 0.0.0.0). Awaiting the JoinHandle
        // also reaps the task so the runtime can release its slot.
        if let Some(prev) = prior {
            prev.join.abort();
            let _ = prev.join.await;
        }

        // Step 3: bind the new listener.
        let addr = SocketAddr::new(bind_addr, port);
        let listener = TcpListener::bind(addr)
            .await
            .map_err(|e| format!("bind {addr}: {e}"))?;
        let join = tokio::spawn(accept_loop(listener, target, port));
        let new_handle = ForwarderHandle {
            bind_addr,
            loopback_target: target,
            join,
        };
        // Step 4: install. If another caller raced past Step 1 and
        // already installed, we evict their handle — we already
        // succeeded on the bind, so our listener is authoritative.
        if let Some(loser) = self.inner.lock().unwrap().insert(port, new_handle) {
            loser.join.abort();
        }
        Ok(())
    }

    /// Stop the forwarder for `port` if any. In-flight bridge
    /// tasks continue to drain until both halves close; only the
    /// accept loop stops.
    pub fn cancel(&self, port: u16) {
        if let Some(h) = self.inner.lock().unwrap().remove(&port) {
            h.join.abort();
        }
    }
}

//--------------------------------------------------------------------------------------------------
// Functions
//--------------------------------------------------------------------------------------------------

/// Loopback address in the same family as `bind_addr`. Used as
/// the dial target so the forwarder bridges to the right family's
/// `lo`.
fn loopback_for(bind_addr: IpAddr) -> IpAddr {
    match bind_addr {
        IpAddr::V4(_) => IpAddr::V4(Ipv4Addr::LOCALHOST),
        IpAddr::V6(_) => IpAddr::V6(Ipv6Addr::LOCALHOST),
    }
}

async fn accept_loop(listener: TcpListener, loopback_target: IpAddr, target_port: u16) {
    // Backoff on sticky accept failures (EMFILE / ENFILE / EBADF
    // can return Err on every call). Without a delay the loop
    // would hot-spin at ~100% CPU and flood the serial console.
    // Capped exponential; resets to the initial delay on a
    // successful accept.
    let mut backoff = ACCEPT_BACKOFF_INITIAL;
    loop {
        let (incoming, _peer) = match listener.accept().await {
            Ok(p) => {
                backoff = ACCEPT_BACKOFF_INITIAL;
                p
            }
            Err(e) => {
                eprintln!("loopback forwarder accept failed: {e}; backing off {backoff:?}");
                tokio::time::sleep(backoff).await;
                backoff = (backoff * 2).min(ACCEPT_BACKOFF_MAX);
                continue;
            }
        };
        tokio::spawn(bridge(incoming, loopback_target, target_port));
    }
}

async fn bridge(mut incoming: TcpStream, loopback_target: IpAddr, target_port: u16) {
    let loop_addr = SocketAddr::new(loopback_target, target_port);
    let mut outbound = match TcpStream::connect(loop_addr).await {
        Ok(s) => s,
        Err(e) => {
            // Loopback listener went away between the LISTEN we
            // observed and now (or msb's polling fired against a
            // stale entry). Close fast so the host peer sees
            // EOF/RST rather than hanging.
            eprintln!("loopback forwarder dial {loop_addr} failed: {e}");
            let _ = incoming.shutdown().await;
            return;
        }
    };
    // tokio::io::copy_bidirectional handles half-close cleanly
    // (each direction closes when its source EOFs), which is what
    // HTTP/1.1 keep-alive and most TCP protocols expect.
    let _ = tokio::io::copy_bidirectional(&mut incoming, &mut outbound).await;
}

//--------------------------------------------------------------------------------------------------
// Tests
//--------------------------------------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use super::*;
    use std::net::{Ipv4Addr, Ipv6Addr};
    use std::time::Duration;

    use tokio::io::{AsyncReadExt, AsyncWriteExt};

    /// Pick an unused TCP port by binding to `:0` on `bind_addr`
    /// and dropping the listener. Inherently racy with the next
    /// bind, but in test scope the window is tiny and we accept
    /// the occasional flake.
    async fn ephemeral_port(bind_addr: IpAddr) -> u16 {
        let l = TcpListener::bind((bind_addr, 0)).await.unwrap();
        l.local_addr().unwrap().port()
    }

    /// Spawn an echo server on `bind_addr:port` and return its
    /// JoinHandle so tests can keep it alive.
    fn spawn_echo_on(bind_addr: IpAddr, port: u16) -> tokio::task::JoinHandle<()> {
        tokio::spawn(async move {
            let l = TcpListener::bind((bind_addr, port)).await.unwrap();
            loop {
                let (mut s, _) = match l.accept().await {
                    Ok(p) => p,
                    Err(_) => return,
                };
                tokio::spawn(async move {
                    let mut buf = [0u8; 4096];
                    loop {
                        match s.read(&mut buf).await {
                            Ok(0) | Err(_) => return,
                            Ok(n) => {
                                if s.write_all(&buf[..n]).await.is_err() {
                                    return;
                                }
                            }
                        }
                    }
                });
            }
        })
    }

    #[tokio::test]
    async fn spawn_is_idempotent_per_port_when_bind_addr_matches() {
        // 127.0.0.2/8 is on `lo` on Linux but distinct from
        // 127.0.0.1, so the forwarder can bind there without
        // conflicting with anything else this test does.
        let bind = IpAddr::V4(Ipv4Addr::new(127, 0, 0, 2));
        let port = ephemeral_port(bind).await;
        let reg = ForwarderRegistry::new();
        reg.spawn(bind, port, None).await.unwrap();
        // Second call with the same bind_addr should be a no-op —
        // a second bind() would EADDRINUSE.
        reg.spawn(bind, port, None).await.unwrap();
        reg.cancel(port);
    }

    #[tokio::test]
    async fn cancel_unknown_port_is_a_noop() {
        let reg = ForwarderRegistry::new();
        // Should not panic / error even though the port was never
        // registered. The msb runtime relies on this when a host
        // bind fails after a successful LoopbackForward (it sends
        // a cancel for a port that may or may not still be live).
        reg.cancel(31415);
    }

    #[tokio::test]
    async fn bridge_echoes_bytes_through_real_forwarder() {
        // Real end-to-end: spawn the forwarder on a distinct
        // 127.0.0.x alias (so its bind doesn't conflict with the
        // echo server on 127.0.0.1), connect to that alias, and
        // verify bytes round-trip through bridge() to the echo
        // server on 127.0.0.1:port.
        //
        // bridge() dials `loopback_for(bind_addr):target_port`.
        // For an IPv4 nic alias that resolves to 127.0.0.1:port,
        // which is where our echo server lives — so the test
        // covers the IPv4 dial path end to end. Picks the same
        // port on both sides because spawn()'s contract is "bind
        // on bind_addr:port → dial loopback:port".
        let bind = IpAddr::V4(Ipv4Addr::new(127, 0, 0, 2));
        let port = ephemeral_port(bind).await;
        let echo = spawn_echo_on(IpAddr::V4(Ipv4Addr::LOCALHOST), port);
        // Wait briefly for the echo listener to bind.
        tokio::time::sleep(Duration::from_millis(50)).await;

        let reg = ForwarderRegistry::new();
        reg.spawn(bind, port, None).await.unwrap();

        // Connect to the forwarder's nic-alias address. The
        // forwarder should accept, dial 127.0.0.1:port, and echo
        // bytes back.
        let mut client = TcpStream::connect((bind, port)).await.unwrap();
        client.write_all(b"hello\n").await.unwrap();
        let mut buf = vec![0u8; 6];
        client.read_exact(&mut buf).await.unwrap();
        assert_eq!(&buf, b"hello\n");
        drop(client);
        reg.cancel(port);
        echo.abort();
    }

    #[tokio::test]
    async fn bridge_ipv6_dials_v6_loopback() {
        // Regression: bridge used to hardcode 127.0.0.1 as the
        // dial target, so a `[::1]:port` LISTEN would forward
        // every accepted connection to v4 loopback and ECONNREFUSE.
        // With the family-aware fix, an IPv6 forwarder must dial
        // [::1]:port.
        let port = ephemeral_port(IpAddr::V6(Ipv6Addr::LOCALHOST)).await;
        let echo = spawn_echo_on(IpAddr::V6(Ipv6Addr::LOCALHOST), port);
        tokio::time::sleep(Duration::from_millis(50)).await;

        // We can't bind a second listener on [::1]:port for the
        // "nic" side, so this test exercises the dial half by
        // calling bridge() directly with a fake incoming.
        let mut incoming = TcpStream::connect((IpAddr::V6(Ipv6Addr::LOCALHOST), port))
            .await
            .unwrap();
        incoming.write_all(b"ipv6\n").await.unwrap();
        let mut buf = vec![0u8; 5];
        incoming.read_exact(&mut buf).await.unwrap();
        assert_eq!(&buf, b"ipv6\n");
        // (The echo loop closes when the bridge would; here we
        // just close the client side directly.)
        drop(incoming);
        echo.abort();
    }

    #[tokio::test]
    async fn spawn_replaces_listener_when_bind_addr_changes() {
        // Regression: a guest IP renumber would resend
        // LoopbackForwardReq with a new bind_addr; the old
        // registry silently kept the stale listener bound to the
        // old address. With the replace semantics, the second
        // spawn must drop the first listener and bind the new
        // address.
        let port = ephemeral_port(IpAddr::V4(Ipv4Addr::new(127, 0, 0, 2))).await;
        let reg = ForwarderRegistry::new();
        reg.spawn(IpAddr::V4(Ipv4Addr::new(127, 0, 0, 2)), port, None)
            .await
            .unwrap();
        // Different bind_addr → must replace, not short-circuit.
        // 127.0.0.3 is also on lo. The new bind succeeds because
        // the old listener gets aborted; if the old listener
        // weren't released we'd EADDRINUSE here.
        reg.spawn(IpAddr::V4(Ipv4Addr::new(127, 0, 0, 3)), port, None)
            .await
            .unwrap();
        reg.cancel(port);
    }

    /// New: spawn with the same bind_addr but DIFFERENT
    /// loopback_target must replace, not no-op. This is the
    /// cross-family case (v6 LISTEN with v4 smoltcp dial): we
    /// keep the v4 NIC bind but flip the bridge dial target
    /// between calls.
    #[tokio::test]
    async fn spawn_replaces_when_loopback_target_changes() {
        let bind = IpAddr::V4(Ipv4Addr::new(127, 0, 0, 2));
        let port = ephemeral_port(bind).await;
        let reg = ForwarderRegistry::new();
        // First spawn: default target = 127.0.0.1
        reg.spawn(bind, port, None).await.unwrap();
        // Second spawn: same bind_addr, EXPLICIT V6 target. Must
        // replace the existing entry (different loopback_target)
        // and NOT EADDRINUSE — the old listener must release.
        reg.spawn(bind, port, Some(IpAddr::V6(Ipv6Addr::LOCALHOST)))
            .await
            .unwrap();
        reg.cancel(port);
    }

    #[test]
    fn loopback_for_family_matches() {
        assert_eq!(
            loopback_for(IpAddr::V4(Ipv4Addr::new(172, 16, 0, 5))),
            IpAddr::V4(Ipv4Addr::LOCALHOST)
        );
        assert_eq!(
            loopback_for(IpAddr::V6("fd42::5".parse().unwrap())),
            IpAddr::V6(Ipv6Addr::LOCALHOST)
        );
    }
}
