//! Channel-based TLS proxy task.
//!
//! Intercepts TLS connections by terminating the guest's TLS with a
//! generated per-domain certificate (MITM) and re-originating a TLS
//! connection to the real server. Bypass mode replays buffered bytes and
//! splices the connection without termination.

use std::borrow::Cow;
use std::io::{self, Read, Write};
use std::net::SocketAddr;
use std::sync::Arc;

use bytes::Bytes;
use rustls::pki_types::ServerName;
use tokio::io::{AsyncReadExt, AsyncWrite, AsyncWriteExt};
use tokio::net::TcpStream;
use tokio::sync::mpsc;

use super::sni;
use super::state::TlsState;
use crate::engine::http_deny::classify_http_request;
use crate::extensions::{
    AuthorizedRouteRequestStream, AuthorizedTlsRoute, NetworkExtensions, RequestAction,
};
use crate::netstack::shared::SharedState;
use crate::policy::{EgressEvaluation, HostnameSource, NetworkPolicy, Protocol};
use crate::proxy::ResolvedOutboundProxy;
use crate::secrets::config::SecretViolationAction;
use crate::secrets::handler::SecretsHandler;
use crate::tcp::{connection::ProxyConnectState, upstream::UpstreamTcpTarget};

//--------------------------------------------------------------------------------------------------
// Constants
//--------------------------------------------------------------------------------------------------

/// Max bytes to buffer while waiting for the ClientHello.
const CLIENT_HELLO_BUF_SIZE: usize = 16384;

/// Buffer size for bidirectional relay.
const RELAY_BUF_SIZE: usize = 16384;

//--------------------------------------------------------------------------------------------------
// Types
//--------------------------------------------------------------------------------------------------

/// Per-connection TLS proxy task and the state it owns.
pub(crate) struct TlsProxy {
    guest_dst: SocketAddr,
    connect_target: UpstreamTcpTarget,
    from_smoltcp: mpsc::Receiver<Bytes>,
    to_smoltcp: mpsc::Sender<Bytes>,
    shared: Arc<SharedState>,
    tls_state: Arc<TlsState>,
    network_policy: Arc<NetworkPolicy>,
    strict: bool,
    proxy_connect: Arc<ProxyConnectState>,
    extensions: NetworkExtensions,
    outbound_proxy: Option<Arc<ResolvedOutboundProxy>>,
    /// Pre-connected upstream; when `Some`, skips dialing `connect_target`.
    upstream_stream: Option<TcpStream>,
    /// Hostname from a CONNECT authority that must match the ClientHello SNI.
    expected_sni: Option<String>,
    /// `true` when the connection arrived via HTTP CONNECT; skips the DNS-cache pin check.
    via_connect: bool,
    /// ClientHello bytes already consumed from the guest stream.
    initial_buf: Vec<u8>,
}

//--------------------------------------------------------------------------------------------------
// Methods
//--------------------------------------------------------------------------------------------------

impl TlsProxy {
    /// Build a proxy for a newly established guest TLS connection.
    /// `upstream_stream` is reused when present; otherwise, dial after policy checks.
    /// Policy uses `guest_dst`; host connections use the resolved `connect_target`.
    #[allow(clippy::too_many_arguments)]
    pub(crate) fn new(
        upstream_stream: Option<TcpStream>,
        guest_dst: SocketAddr,
        connect_target: UpstreamTcpTarget,
        from_smoltcp: mpsc::Receiver<Bytes>,
        to_smoltcp: mpsc::Sender<Bytes>,
        shared: Arc<SharedState>,
        tls_state: Arc<TlsState>,
        network_policy: Arc<NetworkPolicy>,
        strict: bool,
        proxy_connect: Arc<ProxyConnectState>,
        extensions: NetworkExtensions,
        outbound_proxy: Option<Arc<ResolvedOutboundProxy>>,
    ) -> Self {
        Self {
            guest_dst,
            connect_target,
            from_smoltcp,
            to_smoltcp,
            shared,
            tls_state,
            network_policy,
            strict,
            proxy_connect,
            extensions,
            outbound_proxy,
            upstream_stream,
            expected_sni: None,
            via_connect: false,
            initial_buf: Vec::new(),
        }
    }

    /// Mark this proxy as an HTTP CONNECT handoff and optionally verify its hostname authority.
    ///
    /// An IP-literal authority still marks the transport as CONNECT, but has no
    /// hostname authority to verify: it therefore keeps the DNS-pin check the
    /// direct path uses rather than being trusted outright. This is why
    /// `via_connect` and the hostname-authority flag are separate — upstream's
    /// single flag conflated them.
    pub(crate) fn with_connect_authority(mut self, expected_sni: Option<String>) -> Self {
        self.via_connect = true;
        self.expected_sni = expected_sni;
        self
    }

    /// Seed the proxy with ClientHello bytes already read from the guest.
    pub(crate) fn with_initial_buf(mut self, initial_buf: Vec<u8>) -> Self {
        self.initial_buf = initial_buf;
        self
    }

    /// Run the TLS proxy task to completion.
    ///
    /// See [`crate::tcp::proxy::spawn_tcp_proxy`] for the `proxy_connect`
    /// contract.
    pub(crate) async fn run(self) {
        let guest_dst = self.guest_dst;
        let connect_dst = self.connect_target.primary();

        if let Err(error) = self.try_run().await {
            tracing::debug!(
                dst = %connect_dst,
                %guest_dst,
                %error,
                "TLS proxy task ended",
            );
        }
    }

    /// Drive the TLS proxy to completion, returning operational failures.
    pub(crate) async fn try_run(self) -> io::Result<()> {
        let Self {
            guest_dst,
            connect_target,
            mut from_smoltcp,
            to_smoltcp,
            shared,
            tls_state,
            network_policy,
            strict,
            proxy_connect,
            extensions,
            upstream_stream,
            outbound_proxy,
            expected_sni,
            via_connect,
            initial_buf,
        } = self;
        let connect_dst = connect_target.primary();
        // A hostname CONNECT authority is proven by the proxy against the
        // CONNECT request; an IP-literal authority is not (no hostname to
        // verify), so it keeps the existing DNS-pin check.
        let has_connect_hostname_authority = expected_sni.is_some();

        // Buffer a complete ClientHello. Timeout prevents a
        // slow/malicious guest from holding a proxy slot indefinitely.
        let sni_name = tokio::time::timeout(
            std::time::Duration::from_secs(10),
            read_client_hello(&mut from_smoltcp, initial_buf),
        )
        .await
        .map_err(|_| io::Error::new(io::ErrorKind::TimedOut, "ClientHello timed out"))?;
        let (sni_name, initial_buf) = sni_name?;

        // Without SNI, authenticate the original destination IP, never a cached
        // DNS name or the host-side address used for gateway forwarding.
        // Canonicalize so byte equality against rule destinations works.
        let has_sni = sni_name.is_some();
        let sni_name = sni_name.unwrap_or_else(|| guest_dst.ip().to_string());
        let sni_name = sni_name.trim_end_matches('.').to_ascii_lowercase();

        if let Some(expected) = expected_sni.as_deref()
            && !sni_name.eq_ignore_ascii_case(expected.trim_end_matches('.'))
        {
            tracing::debug!(
                sni = %sni_name,
                expected = %expected,
                dst = %connect_dst,
                "TLS SNI did not match CONNECT authority",
            );
            proxy_connect.mark_policy_denied();
            shared.proxy_wake.wake();
            return Ok(());
        }

        // Policy uses cached DNS evidence when the client supplied no hostname.
        // Certificate and secret identity remain bound to the destination IP.
        let hostname_source = if has_sni {
            HostnameSource::Sni(&sni_name)
        } else {
            HostnameSource::CacheOnly
        };
        let eval = network_policy.evaluate_egress_with_source(
            guest_dst,
            Protocol::Tcp,
            &shared,
            hostname_source,
        );
        if !matches!(eval, EgressEvaluation::Allow) {
            tracing::debug!(
                sni = %sni_name,
                dst = %guest_dst,
                "TLS egress denied by domain policy",
            );
            // Bypassed names cannot be answered in-tunnel (the guest expects
            // the real server's certificate); they still get a plain close.
            if !tls_state.should_bypass(&sni_name) {
                let denied = serve_tls_deny(
                    &sni_name,
                    initial_buf,
                    &mut from_smoltcp,
                    &to_smoltcp,
                    &shared,
                    &tls_state,
                )
                .await;
                if let Err(error) = denied {
                    tracing::debug!(sni = %sni_name, %error, "TLS deny response not delivered");
                }
            }
            proxy_connect.mark_policy_denied();
            shared.proxy_wake.wake();
            return Ok(());
        }

        let should_bypass = tls_state.should_bypass(&sni_name);
        if strict
            && should_bypass
            && network_policy.allows_egress_via_hostname(
                guest_dst,
                Protocol::Tcp,
                &shared,
                hostname_source,
            )
        {
            tracing::debug!(
                sni = %sni_name,
                dst = %guest_dst,
                "TLS bypass denied by strict hostname policy",
            );
            proxy_connect.mark_policy_denied();
            shared.proxy_wake.wake();
            return Ok(());
        }

        if should_bypass {
            tracing::debug!(sni = %sni_name, dst = %connect_dst, guest_dst = %guest_dst, "TLS bypass");
            bypass_relay(
                connect_target,
                initial_buf,
                from_smoltcp,
                to_smoltcp,
                shared,
                proxy_connect,
                upstream_stream,
                outbound_proxy,
            )
            .await
        } else {
            tracing::debug!(sni = %sni_name, dst = %connect_dst, guest_dst = %guest_dst, "TLS intercept");
            intercept_relay(
                guest_dst,
                connect_target,
                &sni_name,
                via_connect,
                has_connect_hostname_authority,
                initial_buf,
                from_smoltcp,
                to_smoltcp,
                shared,
                tls_state,
                proxy_connect,
                extensions,
                upstream_stream,
                outbound_proxy,
            )
            .await
        }
    }
}

//--------------------------------------------------------------------------------------------------
// Functions
//--------------------------------------------------------------------------------------------------

/// Answer a policy-denied HTTPS connection with `403 Forbidden`.
///
/// Terminates the guest's TLS with the intercept cert for `sni_name`, reads
/// the first request so the client is not mid-write when the close lands,
/// then writes the deny body and a `close_notify`. No upstream connection
/// is ever opened.
pub(crate) async fn serve_tls_deny(
    sni_name: &str,
    initial_buf: Vec<u8>,
    from_smoltcp: &mut mpsc::Receiver<Bytes>,
    to_smoltcp: &mpsc::Sender<Bytes>,
    shared: &SharedState,
    tls_state: &TlsState,
) -> io::Result<()> {
    if !shared.http_deny_response_enabled() {
        return Ok(());
    }

    let domain_cert = tls_state
        .get_or_generate_cert(sni_name)
        .map_err(|e| io::Error::new(io::ErrorKind::InvalidInput, e))?;
    let mut guest_tls = rustls::ServerConnection::new(domain_cert.server_config.clone())
        .map_err(io::Error::other)?;
    let mut tls_buf = Vec::with_capacity(RELAY_BUF_SIZE + 256);

    complete_guest_handshake(
        &mut guest_tls,
        initial_buf,
        from_smoltcp,
        to_smoltcp,
        shared,
        &mut tls_buf,
    )
    .await?;

    // Only HTTP/1.x can receive our HTTP/1.1 response. Buffer across TLS
    // records; EOF, malformed input, and timeout are not evidence of HTTP.
    let is_http = tokio::time::timeout(std::time::Duration::from_secs(2), async {
        let mut request = Vec::new();
        let mut scratch = [0u8; RELAY_BUF_SIZE];
        loop {
            match guest_tls.reader().read(&mut scratch) {
                Ok(0) => return false,
                Ok(n) => {
                    let remaining = RELAY_BUF_SIZE - request.len();
                    request.extend_from_slice(&scratch[..n.min(remaining)]);
                    if let Some(is_http) = classify_http_request(&request) {
                        return is_http;
                    }
                    if request.len() == RELAY_BUF_SIZE {
                        return false;
                    }
                    continue;
                }
                Err(ref error) if error.kind() == io::ErrorKind::WouldBlock => {}
                Err(_) => return false,
            }
            let Some(data) = from_smoltcp.recv().await else {
                return false;
            };
            let mut remaining = &data[..];
            while !remaining.is_empty() {
                if !matches!(guest_tls.read_tls(&mut remaining), Ok(n) if n > 0)
                    || guest_tls.process_new_packets().is_err()
                {
                    return false;
                }
            }
        }
    })
    .await
    .unwrap_or(false);
    if !is_http {
        return Ok(());
    }

    guest_tls
        .writer()
        .write_all(&shared.network_denial_response(sni_name))
        .map_err(io::Error::other)?;
    guest_tls.send_close_notify();
    flush_to_guest(&mut guest_tls, to_smoltcp, shared, &mut tls_buf).await
}

/// Feed the buffered ClientHello and drive the guest-facing handshake to
/// completion, bounded by a 10s timeout.
async fn complete_guest_handshake(
    guest_tls: &mut rustls::ServerConnection,
    initial_buf: Vec<u8>,
    from_smoltcp: &mut mpsc::Receiver<Bytes>,
    to_smoltcp: &mpsc::Sender<Bytes>,
    shared: &SharedState,
    tls_buf: &mut Vec<u8>,
) -> io::Result<()> {
    {
        let mut remaining = &initial_buf[..];
        while !remaining.is_empty() {
            guest_tls
                .read_tls(&mut remaining)
                .map_err(io::Error::other)?;
            guest_tls.process_new_packets().map_err(io::Error::other)?;
        }
    }

    // Send ServerHello etc. back to guest.
    flush_to_guest(guest_tls, to_smoltcp, shared, tls_buf).await?;

    tokio::time::timeout(std::time::Duration::from_secs(10), async {
        while guest_tls.is_handshaking() {
            let data = from_smoltcp
                .recv()
                .await
                .ok_or_else(|| io::Error::new(io::ErrorKind::UnexpectedEof, "channel closed"))?;
            let mut remaining = &data[..];
            while !remaining.is_empty() {
                guest_tls
                    .read_tls(&mut remaining)
                    .map_err(io::Error::other)?;
                guest_tls.process_new_packets().map_err(io::Error::other)?;
            }
            flush_to_guest(guest_tls, to_smoltcp, shared, tls_buf).await?;
        }
        Ok::<_, io::Error>(())
    })
    .await
    .map_err(|_| io::Error::new(io::ErrorKind::TimedOut, "TLS handshake timed out"))?
}

/// Bypass mode: plain TCP splice, no TLS termination.
#[allow(clippy::too_many_arguments)]
async fn bypass_relay(
    connect_target: UpstreamTcpTarget,
    initial_buf: Vec<u8>,
    mut from_smoltcp: mpsc::Receiver<Bytes>,
    to_smoltcp: mpsc::Sender<Bytes>,
    shared: Arc<SharedState>,
    proxy_connect: Arc<ProxyConnectState>,
    upstream_stream: Option<TcpStream>,
    outbound_proxy: Option<Arc<ResolvedOutboundProxy>>,
) -> io::Result<()> {
    let mut server = match upstream_stream {
        Some(stream) => stream,
        None => {
            connect_target
                .connect(&proxy_connect, &shared, outbound_proxy.as_deref())
                .await?
        }
    };
    server.write_all(&initial_buf).await?;

    let (mut server_rx, mut server_tx) = server.into_split();
    let mut buf = vec![0u8; RELAY_BUF_SIZE];

    let mut guest_eof = false;
    loop {
        tokio::select! {
            data = from_smoltcp.recv(), if !guest_eof => {
                match data {
                    Some(bytes) => server_tx.write_all(&bytes).await?,
                    // Guest half-closed (FIN): stop sending upstream but
                    // keep relaying server → guest until the server closes.
                    None => {
                        guest_eof = true;
                        if server_tx.shutdown().await.is_err() {
                            break;
                        }
                    }
                }
            }
            result = server_rx.read(&mut buf) => {
                match result {
                    Ok(0) => break,
                    Ok(n) => {
                        if to_smoltcp.send(Bytes::copy_from_slice(&buf[..n])).await.is_err() {
                            break;
                        }
                        shared.proxy_wake.wake();
                    }
                    Err(e) => return Err(e),
                }
            }
        }
    }

    Ok(())
}

/// Intercept mode: MITM with guest-facing rustls + server-facing tokio_rustls.
#[allow(clippy::too_many_arguments)]
pub(crate) async fn intercept_relay(
    guest_dst: SocketAddr,
    connect_target: UpstreamTcpTarget,
    sni_name: &str,
    via_connect: bool,
    has_connect_hostname_authority: bool,
    initial_buf: Vec<u8>,
    mut from_smoltcp: mpsc::Receiver<Bytes>,
    to_smoltcp: mpsc::Sender<Bytes>,
    shared: Arc<SharedState>,
    tls_state: Arc<TlsState>,
    proxy_connect: Arc<ProxyConnectState>,
    extensions: NetworkExtensions,
    upstream_stream: Option<TcpStream>,
    outbound_proxy: Option<Arc<ResolvedOutboundProxy>>,
) -> io::Result<()> {
    // Per-connection snapshot: live secret updates apply to later connections.
    let secrets = tls_state.secrets.load();
    let mut secrets_handler = if has_connect_hostname_authority {
        SecretsHandler::new_tls_intercepted_via_connect(&secrets, sni_name)
    } else {
        // Direct TLS, or a CONNECT to an IP-literal authority (no hostname to
        // verify): both retain the DNS-pin check.
        SecretsHandler::new_tls_intercepted(&secrets, sni_name, guest_dst.ip(), &shared)
    }
    .with_header_credentials(tls_state.header_credentials().to_vec())
    .with_guest_dst(guest_dst);
    let mut request_stream =
        open_authorized_request_stream(&extensions, guest_dst, sni_name, via_connect);

    // Get or generate per-domain certificate (includes cached ServerConfig).
    let domain_cert = tls_state
        .get_or_generate_cert(sni_name)
        .map_err(|e| io::Error::new(io::ErrorKind::InvalidInput, e))?;

    // Reuse cached ServerConfig — avoids cert chain clone + key clone + rebuild per connection.
    let mut guest_tls = rustls::ServerConnection::new(domain_cert.server_config.clone())
        .map_err(io::Error::other)?;

    // Reusable buffer for TLS output — avoids per-flush heap allocation.
    let mut tls_buf = Vec::with_capacity(RELAY_BUF_SIZE + 256);

    // Feed the buffered ClientHello and complete the guest-facing handshake
    // (bounded, to prevent resource exhaustion).
    complete_guest_handshake(
        &mut guest_tls,
        initial_buf,
        &mut from_smoltcp,
        &to_smoltcp,
        &shared,
        &mut tls_buf,
    )
    .await?;

    // Connect to real server with TLS.
    let server_stream = match upstream_stream {
        Some(stream) => stream,
        None => {
            connect_target
                .connect(&proxy_connect, &shared, outbound_proxy.as_deref())
                .await?
        }
    };
    let server_name = ServerName::try_from(sni_name.to_string())
        .map_err(|e| io::Error::new(io::ErrorKind::InvalidInput, e))?;
    let mut server_tls = tls_state
        .upstream_connector_for(sni_name)
        .connect(server_name, server_stream)
        .await
        .map_err(io::Error::other)?;

    // Phase 2: Bidirectional plaintext relay.
    let mut server_buf = vec![0u8; RELAY_BUF_SIZE];
    let mut plaintext_buf = vec![0u8; RELAY_BUF_SIZE];

    // Drain any application data already buffered during the TLS handshake.
    // In TLS 1.3, the client sends Finished + application data in the same
    // flight, so process_new_packets() during the handshake loop may have
    // already decrypted the first HTTP request into the plaintext buffer.
    match forward_plaintext(
        &mut guest_tls,
        &mut server_tls,
        &mut secrets_handler,
        request_stream.as_deref_mut(),
        &shared,
        &mut plaintext_buf,
        &to_smoltcp,
        &mut tls_buf,
        false,
    )
    .await
    {
        Ok(true) => return Ok(()),
        Ok(false) => {}
        Err(error) => {
            flush_to_guest(&mut guest_tls, &to_smoltcp, &shared, &mut tls_buf).await?;
            return Err(error);
        }
    }

    let mut upstream_response_started = false;
    let mut guest_eof = false;
    loop {
        tokio::select! {
            // Guest → server: receive encrypted, decrypt, forward plaintext.
            data = from_smoltcp.recv(), if !guest_eof => {
                let data = match data {
                    Some(d) => d,
                    // Guest half-closed (TCP FIN): propagate as a TLS
                    // close_notify + FIN upstream, but keep relaying
                    // server → guest until the server closes. (A TLS 1.3
                    // server may keep sending; a TLS 1.2 server responds
                    // with its own close_notify, ending the relay.)
                    None => {
                        guest_eof = true;
                        // EOF has no extension callback. Drop held request state
                        // before continuing the server-to-guest half of the relay.
                        request_stream = None;
                        if server_tls.shutdown().await.is_err() {
                            break;
                        }
                        continue;
                    }
                };
                // Feed all data to rustls.
                let mut remaining = &data[..];
                while !remaining.is_empty() {
                    guest_tls
                        .read_tls(&mut remaining)
                        .map_err(io::Error::other)?;
                    guest_tls
                        .process_new_packets()
                        .map_err(io::Error::other)?;
                    match forward_plaintext(
                        &mut guest_tls,
                        &mut server_tls,
                        &mut secrets_handler,
                        request_stream.as_deref_mut(),
                        &shared,
                        &mut plaintext_buf,
                        &to_smoltcp,
                        &mut tls_buf,
                        upstream_response_started,
                    )
                    .await
                    {
                        Ok(true) => return Ok(()),
                        Ok(false) => {}
                        Err(error) => {
                            flush_to_guest(&mut guest_tls, &to_smoltcp, &shared, &mut tls_buf)
                                .await?;
                            return Err(error);
                        }
                    }
                }
            }

            // Server → guest: read plaintext, encrypt, send via channel.
            result = server_tls.read(&mut server_buf) => {
                match result {
                    Ok(0) => break,
                    Ok(n) => {
                        upstream_response_started = true;
                        guest_tls
                            .writer()
                            .write_all(&server_buf[..n])
                            .map_err(io::Error::other)?;
                        flush_to_guest(&mut guest_tls, &to_smoltcp, &shared, &mut tls_buf).await?;
                    }
                    Err(e) => return Err(e),
                }
            }
        }
    }

    Ok(())
}

/// Read a ClientHello, preserving its bytes for the TLS relay.
/// A complete hello without SNI is distinct from malformed or incomplete TLS.
pub(crate) async fn read_client_hello(
    from_smoltcp: &mut mpsc::Receiver<Bytes>,
    seed: Vec<u8>,
) -> io::Result<(Option<String>, Vec<u8>)> {
    let mut initial_buf = seed;
    let mut acceptor = rustls::server::Acceptor::default();
    let mut consumed = 0;
    loop {
        if initial_buf.len() > CLIENT_HELLO_BUF_SIZE {
            return Err(io::Error::new(
                io::ErrorKind::InvalidData,
                "ClientHello too large",
            ));
        }

        // Bypass must remain usable for TLS clients rustls cannot terminate
        // (for example TLS 1.1 without signature_algorithms). Preserve the
        // existing wire-level SNI peek before asking rustls to validate TLS.
        if let Some(hello) = sni::parse_client_hello(&initial_buf) {
            // Match rustls: IP literals and invalid DNS names are absent SNI.
            let name = hello.server_name.filter(|name| {
                matches!(
                    ServerName::try_from(name.as_str()),
                    Ok(ServerName::DnsName(_))
                )
            });
            return Ok((name, initial_buf));
        }

        while consumed < initial_buf.len() {
            let read = acceptor.read_tls(&mut &initial_buf[consumed..])?;
            if read == 0 {
                return Err(io::Error::new(
                    io::ErrorKind::InvalidData,
                    "incomplete ClientHello",
                ));
            }
            consumed += read;
            match acceptor.accept() {
                Ok(Some(accepted)) => {
                    let name = accepted.client_hello().server_name().map(str::to_owned);
                    return Ok((name, initial_buf));
                }
                Ok(None) => {}
                Err((error, _)) => return Err(io::Error::new(io::ErrorKind::InvalidData, error)),
            }
        }
        let data = from_smoltcp
            .recv()
            .await
            .ok_or_else(|| io::Error::new(io::ErrorKind::UnexpectedEof, "channel closed"))?;
        initial_buf.extend_from_slice(&data);
    }
}

/// Read all available decrypted plaintext from the guest-facing TLS
/// connection and forward it to the upstream server, applying secret
/// substitution and, when a request extension is installed, the
/// post-substitution request action.
///
/// Returns `true` when the relay was terminated by a synthetic response
/// (the caller must stop relaying). The no-extension branch is byte-for-byte
/// the previous behavior: `request_stream.is_none()` forwards as before.
#[allow(clippy::too_many_arguments)]
async fn forward_plaintext(
    guest_tls: &mut rustls::ServerConnection,
    server_tls: &mut tokio_rustls::client::TlsStream<TcpStream>,
    secrets_handler: &mut SecretsHandler,
    mut request_stream: Option<&mut (dyn AuthorizedRouteRequestStream + '_)>,
    shared: &SharedState,
    buf: &mut [u8],
    to_smoltcp: &mpsc::Sender<Bytes>,
    tls_buf: &mut Vec<u8>,
    upstream_response_started: bool,
) -> io::Result<bool> {
    let mut wrote_plaintext = false;

    loop {
        let n = match guest_tls.reader().read(buf) {
            Ok(0) => break,
            Ok(n) => n,
            Err(ref e) if e.kind() == io::ErrorKind::WouldBlock => break,
            Err(e) => return Err(e),
        };

        // The default path (no request extension) is the existing direct
        // forwarding, unchanged.
        if request_stream.is_none() {
            if secrets_handler.is_empty() {
                server_tls.write_all(&buf[..n]).await?;
                wrote_plaintext = true;
                continue;
            }

            match secrets_handler.substitute(&buf[..n]) {
                Ok(data) => {
                    if !data.is_empty() {
                        server_tls.write_all(&data).await?;
                        wrote_plaintext = true;
                    }
                }
                Err(action) => {
                    // Stop upstream forwarding. Only answer before any upstream
                    // response bytes have reached the guest; the caller flushes
                    // the denial and close_notify before dropping the connection.
                    if matches!(action, SecretViolationAction::BlockAndTerminate) {
                        shared.trigger_termination();
                    } else if shared.secret_deny_response_enabled()
                        && !upstream_response_started
                        && let Some(response) =
                            secrets_handler.http1_violation_response(shared.secret_deny_message())
                    {
                        guest_tls.writer().write_all(&response)?;
                        guest_tls.send_close_notify();
                    }
                    return Err(io::Error::new(
                        io::ErrorKind::PermissionDenied,
                        "secret violation: request blocked by secret policy",
                    ));
                }
            }
            continue;
        }

        let substituted = match substitute_request_chunk(secrets_handler, &buf[..n]) {
            Ok(data) => data,
            Err(action) => {
                // Stop upstream forwarding. Only answer before any upstream
                // response bytes have reached the guest; the caller flushes
                // the denial and close_notify before dropping the connection.
                if matches!(action, SecretViolationAction::BlockAndTerminate) {
                    shared.trigger_termination();
                } else if shared.secret_deny_response_enabled()
                    && !upstream_response_started
                    && let Some(response) =
                        secrets_handler.http1_violation_response(shared.secret_deny_message())
                {
                    guest_tls.writer().write_all(&response)?;
                    guest_tls.send_close_notify();
                }
                return Err(io::Error::new(
                    io::ErrorKind::PermissionDenied,
                    "secret violation: request blocked by secret policy",
                ));
            }
        };
        if substituted.is_empty() {
            continue;
        }

        match dispatch_request_action(
            request_stream
                .as_deref_mut()
                .expect("request stream checked above"),
            substituted.as_ref(),
            server_tls,
        )
        .await?
        {
            RequestDispatch::Continue { wrote } => wrote_plaintext |= wrote,
            RequestDispatch::RespondAndClose(response) => {
                if wrote_plaintext {
                    server_tls.flush().await?;
                }
                send_synthetic_response(guest_tls, &response, to_smoltcp, shared, tls_buf).await?;
                return Ok(true);
            }
        }
    }

    // tokio-rustls buffers writes; flush each drained plaintext batch so
    // upstream servers waiting for the full request body can respond.
    if wrote_plaintext {
        server_tls.flush().await?;
    }

    Ok(false)
}

/// The local result of one applied request action.
enum RequestDispatch {
    /// Forwarding continues; `wrote` records whether upstream bytes were sent.
    Continue { wrote: bool },
    /// A synthetic response must be sent to the guest and the relay terminated.
    RespondAndClose(Vec<u8>),
}

fn open_authorized_request_stream(
    extensions: &NetworkExtensions,
    guest_destination: SocketAddr,
    server_name: &str,
    via_connect: bool,
) -> Option<Box<dyn AuthorizedRouteRequestStream>> {
    extensions.authorized_requests().and_then(|extension| {
        // Constructing route metadata copies the SNI. Keep the default-empty
        // path allocation-free until a host actually installs this extension.
        extension.open(&AuthorizedTlsRoute::new(
            guest_destination,
            server_name,
            via_connect,
        ))
    })
}

/// Substitute secrets in one chunk, borrowing when no handler is installed so
/// the zero-substitution path stays copy-free.
fn substitute_request_chunk<'a>(
    secrets_handler: &mut SecretsHandler,
    chunk: &'a [u8],
) -> Result<Cow<'a, [u8]>, SecretViolationAction> {
    if secrets_handler.is_empty() {
        Ok(Cow::Borrowed(chunk))
    } else {
        secrets_handler.substitute(chunk)
    }
}

async fn dispatch_request_action<W: AsyncWrite + Unpin>(
    request_stream: &mut dyn AuthorizedRouteRequestStream,
    chunk: &[u8],
    upstream: &mut W,
) -> io::Result<RequestDispatch> {
    match request_stream.process(chunk).await? {
        RequestAction::ForwardCurrent => {
            upstream.write_all(chunk).await?;
            Ok(RequestDispatch::Continue { wrote: true })
        }
        RequestAction::Hold => Ok(RequestDispatch::Continue { wrote: false }),
        RequestAction::ForwardOwned(bytes) => {
            if bytes.is_empty() {
                Ok(RequestDispatch::Continue { wrote: false })
            } else {
                upstream.write_all(&bytes).await?;
                Ok(RequestDispatch::Continue { wrote: true })
            }
        }
        RequestAction::RespondAndClose(response) => Ok(RequestDispatch::RespondAndClose(response)),
    }
}

/// Encrypt and enqueue a request-extension synthetic response for the guest.
async fn send_synthetic_response(
    guest_tls: &mut rustls::ServerConnection,
    response: &[u8],
    to_smoltcp: &mpsc::Sender<Bytes>,
    shared: &SharedState,
    tls_buf: &mut Vec<u8>,
) -> io::Result<()> {
    guest_tls
        .writer()
        .write_all(response)
        .map_err(io::Error::other)?;
    flush_to_guest(guest_tls, to_smoltcp, shared, tls_buf).await
}

/// Flush pending TLS output from the guest-facing rustls connection
/// to the smoltcp channel.
///
/// Reuses `buf` across calls to avoid per-flush heap allocation. The
/// buffer grows to steady-state capacity on the first call and stays there.
async fn flush_to_guest(
    guest_tls: &mut rustls::ServerConnection,
    to_smoltcp: &mpsc::Sender<Bytes>,
    shared: &SharedState,
    buf: &mut Vec<u8>,
) -> io::Result<()> {
    if guest_tls.wants_write() {
        buf.clear();
        guest_tls.write_tls(buf)?;
        if !buf.is_empty() {
            to_smoltcp
                .send(Bytes::copy_from_slice(buf))
                .await
                .map_err(|_| io::Error::new(io::ErrorKind::BrokenPipe, "channel closed"))?;
            shared.proxy_wake.wake();
        }
    }
    Ok(())
}
//--------------------------------------------------------------------------------------------------
// Tests
//--------------------------------------------------------------------------------------------------

#[cfg(test)]
// Some ported helper types are used only by tests not restored in this
// commit; keep them for the follow-up suite rather than dropping coverage.
#[allow(dead_code)]
mod tests {
    use std::collections::VecDeque;
    use std::io;
    use std::net::SocketAddr;
    use std::sync::atomic::{AtomicBool, AtomicUsize, Ordering};
    use std::sync::{Arc, Mutex};
    use std::time::Duration;

    use futures::future::BoxFuture;
    use microsandbox_types::{InterceptCaConfig, TlsConfig};
    use rustls::pki_types::{CertificateDer, PrivateKeyDer, PrivatePkcs8KeyDer};
    use tokio::io::{AsyncReadExt, AsyncWriteExt};
    use tokio::net::TcpListener;
    use tokio::sync::oneshot;
    use tokio_rustls::TlsAcceptor;

    use super::*;
    use crate::extensions::AuthorizedRouteRequestExtension;
    use crate::intercept::InterceptExtension;
    use crate::intercept::config::{InterceptConfig, InterceptRule};
    use crate::secrets::config::{HostPattern, SecretEntry, SecretSubstitution, SecretsConfig};
    use crate::secrets::credential::ResolvedHeaderCredential;
    use crate::secrets::handle::SecretsHandle;
    use crate::tls::state::TlsState;

    fn isolated_tls_state(mut config: TlsConfig, secrets: SecretsHandle) -> TlsState {
        static NEXT_CA: AtomicUsize = AtomicUsize::new(0);
        // Parallel fixtures must not load or overwrite a shared persisted CA pair. Create an
        // exclusive, disposable directory; an old directory or symlink is never reused.
        let directory = loop {
            let directory = std::env::temp_dir().join(format!(
                "msb-proxy-ca-{}-{}",
                std::process::id(),
                NEXT_CA.fetch_add(1, Ordering::Relaxed)
            ));
            match std::fs::create_dir(&directory) {
                Ok(()) => break directory,
                Err(error) if error.kind() == io::ErrorKind::AlreadyExists => continue,
                Err(error) => panic!("cannot create test CA directory: {error}"),
            }
        };
        let ca = crate::engine::tls::ca::CertAuthority::generate();
        let cert_path = directory.join("ca.crt");
        let key_path = directory.join("ca.key");
        std::fs::write(&cert_path, ca.cert_pem()).unwrap();
        std::fs::write(&key_path, ca.key_pem()).unwrap();
        config.intercept_ca.cert_path = Some(cert_path);
        config.intercept_ca.key_path = Some(key_path);
        let state = TlsState::new(config, secrets, false);
        // Construction reads both files synchronously and retains the CA material in memory.
        std::fs::remove_dir_all(directory).unwrap();
        state.unwrap()
    }

    async fn tls_denial_response(chunks: &[&[u8]], close_input: bool, enabled: bool) -> Vec<u8> {
        let state = isolated_tls_state(
            microsandbox_types::TlsConfig::default(),
            SecretsHandle::new(SecretsConfig::default()),
        );
        let mut roots = rustls::RootCertStore::empty();
        roots.add(state.intercept_ca.cert_der.clone()).unwrap();
        let config = rustls::ClientConfig::builder()
            .with_root_certificates(roots)
            .with_no_client_auth();
        let mut client = rustls::ClientConnection::new(
            Arc::new(config),
            ServerName::try_from("blocked.example").unwrap(),
        )
        .unwrap();
        let mut hello = Vec::new();
        client.write_tls(&mut hello).unwrap();
        let (from_tx, mut from_rx) = mpsc::channel(16);
        let (to_tx, mut to_rx) = mpsc::channel(16);
        let server = tokio::spawn(async move {
            let shared = SharedState::new(16);
            shared.set_http_config(microsandbox_types::HttpConfig {
                deny_response: enabled,
                deny_response_format: microsandbox_types::HttpDenyResponseFormat::Json,
                ..Default::default()
            });
            serve_tls_deny(
                "blocked.example",
                hello,
                &mut from_rx,
                &to_tx,
                &shared,
                &state,
            )
            .await
            .unwrap();
        });
        let mut sent = false;
        let mut sender = Some(from_tx);
        let mut response = Vec::new();
        while let Some(data) = to_rx.recv().await {
            assert!(
                enabled,
                "disabled responses must not complete a TLS handshake"
            );
            let mut remaining = &data[..];
            while !remaining.is_empty() {
                client.read_tls(&mut remaining).unwrap();
                client.process_new_packets().unwrap();
            }
            let mut wire = Vec::new();
            client.write_tls(&mut wire).unwrap();
            if !wire.is_empty() {
                sender
                    .as_ref()
                    .unwrap()
                    .send(Bytes::from(wire))
                    .await
                    .unwrap();
            }
            if !client.is_handshaking() && !sent {
                for chunk in chunks {
                    client.writer().write_all(chunk).unwrap();
                    let mut wire = Vec::new();
                    client.write_tls(&mut wire).unwrap();
                    sender
                        .as_ref()
                        .unwrap()
                        .send(Bytes::from(wire))
                        .await
                        .unwrap();
                }
                sent = true;
                if close_input {
                    sender.take();
                }
            }
            let mut plain = [0; 4096];
            loop {
                match client.reader().read(&mut plain) {
                    Ok(0) => break,
                    Ok(n) => response.extend_from_slice(&plain[..n]),
                    Err(error) if error.kind() == io::ErrorKind::WouldBlock => break,
                    Err(error) => panic!("unexpected TLS read error: {error}"),
                }
            }
        }
        server.await.unwrap();
        response
    }

    #[tokio::test]
    async fn tls_denial_is_silent_without_opt_in() {
        assert!(
            tls_denial_response(&[b"GET / HTTP/1.1\r\n\r\n"], true, false)
                .await
                .is_empty()
        );
    }

    #[tokio::test(start_paused = true)]
    async fn tls_denial_answers_fragmented_http1() {
        let response = tls_denial_response(
            &[
                b"\r",
                b"\nGE",
                b"T / HTTP/1.1\r",
                b"\nHost: blocked.example\r\n\r\n",
            ],
            true,
            true,
        )
        .await;
        assert!(response.starts_with(b"HTTP/1.1 403 Forbidden\r\n"));
        let text = std::str::from_utf8(&response).unwrap();
        let (_, body) = text.split_once("\r\n\r\n").unwrap();
        let error: serde_json::Value = serde_json::from_str(body).unwrap();
        assert_eq!(error["code"], "network_policy_denied");
        assert_eq!(error["domain"], "blocked.example");
        assert_eq!(error["message"], "Request blocked by network policy.");
    }

    #[tokio::test(start_paused = true)]
    async fn tls_denial_closes_non_http_and_incomplete_streams_silently() {
        for chunks in [
            vec![b"SSH-2.0-OpenSSH\r\n".as_slice()],
            vec![b"PRI * HTTP/2.0\r\n\r\nSM\r\n\r\n".as_slice()],
            vec![b"GE".as_slice()],
            vec![],
        ] {
            assert!(tls_denial_response(&chunks, true, true).await.is_empty());
        }
    }

    #[tokio::test(start_paused = true)]
    async fn tls_denial_does_not_answer_after_timeout() {
        assert!(
            tls_denial_response(&[b"GET /"], false, true)
                .await
                .is_empty()
        );
    }

    async fn accept_with_deadline(listener: TcpListener) -> io::Result<TcpStream> {
        tokio::time::timeout(Duration::from_secs(1), listener.accept())
            .await
            .map_err(|_| io::Error::new(io::ErrorKind::TimedOut, "fixture accept timed out"))?
            .map(|(stream, _)| stream)
    }

    fn test_tls_state(secrets: SecretsConfig) -> Arc<TlsState> {
        Arc::new(isolated_tls_state(
            TlsConfig {
                verify_upstream: false,
                ..Default::default()
            },
            SecretsHandle::new(secrets),
        ))
    }

    fn host_bound_secret_config() -> SecretsConfig {
        SecretsConfig {
            secrets: vec![SecretEntry {
                env_var: "API_KEY".into(),
                value: zeroize::Zeroizing::new("real-secret-value".into()),
                source: None,
                placeholder: "$MSB_KEY".into(),
                allowed_hosts: vec![HostPattern::Exact("example.com".into())],
                substitution: SecretSubstitution {
                    headers: true,
                    header_fields: Vec::new(),
                    query: false,
                    body: false,
                },
                passthrough_hosts: Vec::new(),
                violation_action: None,
                require_tls_identity: true,
            }],
            ..Default::default()
        }
    }

    fn test_tls_state_with_intercept(
        secrets: SecretsConfig,
        intercept_active: bool,
    ) -> Arc<TlsState> {
        test_tls_state_with_credentials(secrets, intercept_active, Vec::new())
    }

    fn test_tls_state_with_credentials(
        secrets: SecretsConfig,
        intercept_active: bool,
        credentials: Vec<ResolvedHeaderCredential>,
    ) -> Arc<TlsState> {
        let dir = tempfile::tempdir().unwrap();
        let ca = crate::engine::tls::ca::CertAuthority::generate();
        let cert_path = dir.path().join("ca.pem");
        let key_path = dir.path().join("ca.key");
        std::fs::write(&cert_path, ca.cert_pem()).unwrap();
        std::fs::write(&key_path, ca.key_pem()).unwrap();

        let config = TlsConfig {
            verify_upstream: false,
            intercept_ca: InterceptCaConfig {
                cert_path: Some(cert_path),
                key_path: Some(key_path),
            },
            ..Default::default()
        };
        Arc::new(
            TlsState::new(config, SecretsHandle::new(secrets), intercept_active)
                .unwrap()
                .with_header_credentials(credentials),
        )
    }

    /// A resolved header credential for the `example.com:443` fixture origin.
    fn example_header_credential(value: &str) -> ResolvedHeaderCredential {
        ResolvedHeaderCredential::from_definition(
            &microsandbox_types::DurableHeaderCredential {
                id: "example".into(),
                reference: "example-ref".into(),
                origin: microsandbox_types::HttpsOrigin {
                    host: "example.com".into(),
                    port: 443,
                },
                header: "x-api-key".into(),
                format: "%s".into(),
            },
            zeroize::Zeroizing::new(value.to_owned()),
        )
    }

    #[tokio::test]
    async fn client_hello_preserves_fragmented_records_with_and_without_sni() {
        for name in ["example.com", "192.0.2.1", "2001:db8::1"] {
            let _ = rustls::crypto::ring::default_provider().install_default();
            let config = rustls::ClientConfig::builder()
                .with_root_certificates(rustls::RootCertStore::empty())
                .with_no_client_auth();
            let mut client = rustls::ClientConnection::new(
                Arc::new(config),
                ServerName::try_from(name.to_owned()).unwrap(),
            )
            .unwrap();
            let mut hello = Vec::new();
            client.write_tls(&mut hello).unwrap();
            // Fragment the handshake over TLS records as well as channel messages.
            let mut wire = Vec::new();
            for fragment in hello[5..].chunks(31) {
                wire.extend_from_slice(&hello[..3]);
                wire.extend_from_slice(&(fragment.len() as u16).to_be_bytes());
                wire.extend_from_slice(fragment);
            }
            let (tx, mut rx) = mpsc::channel(wire.len());
            for fragment in wire.chunks(7) {
                tx.send(Bytes::copy_from_slice(fragment)).await.unwrap();
            }
            drop(tx);
            let (sni, buffered) = read_client_hello(&mut rx, Vec::new()).await.unwrap();
            assert_eq!(sni.as_deref(), (name == "example.com").then_some(name));
            assert_eq!(buffered, wire);
        }
    }

    #[tokio::test]
    async fn client_hello_rejects_invalid_and_truncated_tls() {
        for wire in [
            b"GET / HTTP/1.1\r\n\r\n".to_vec(),
            vec![0x16, 3, 1, 0, 10, 1],
        ] {
            let (tx, mut rx) = mpsc::channel(1);
            tx.send(Bytes::from(wire)).await.unwrap();
            drop(tx);
            assert!(read_client_hello(&mut rx, Vec::new()).await.is_err());
        }
    }

    #[tokio::test]
    async fn no_sni_policy_uses_cached_hostname_for_allow_and_deny() {
        let _ = rustls::crypto::ring::default_provider().install_default();
        for (allowed, strict) in [(true, false), (false, false), (true, true), (false, true)] {
            let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
            let upstream = listener.local_addr().unwrap();
            let shared = Arc::new(SharedState::new(8));
            shared.set_http_config(microsandbox_types::HttpConfig {
                deny_response: false,
                ..Default::default()
            });
            shared.cache_resolved_hostname(
                "example.com",
                crate::netstack::shared::ResolvedHostnameFamily::Ipv4,
                [upstream.ip()],
                Duration::from_secs(60),
            );
            let policy = if allowed {
                NetworkPolicy::none().allow_domain("example.com").unwrap()
            } else {
                NetworkPolicy::allow_all()
                    .deny_domain("example.com")
                    .unwrap()
            };
            let state = Arc::new(isolated_tls_state(
                TlsConfig {
                    bypass: vec![upstream.ip().to_string()],
                    ..Default::default()
                },
                SecretsHandle::new(SecretsConfig::default()),
            ));
            let config = rustls::ClientConfig::builder()
                .with_root_certificates(rustls::RootCertStore::empty())
                .with_no_client_auth();
            let mut client = rustls::ClientConnection::new(
                Arc::new(config),
                ServerName::IpAddress(upstream.ip().into()),
            )
            .unwrap();
            let mut hello = Vec::new();
            client.write_tls(&mut hello).unwrap();
            let received =
                run_bypass_probe(listener, state, shared, policy, strict, hello.clone()).await;
            assert_eq!(
                received,
                if allowed && !strict {
                    hello
                } else {
                    Vec::new()
                }
            );
        }
    }

    #[tokio::test]
    async fn no_sni_interception_allows_cached_domain_policy() {
        let check = async {
            let _ = rustls::crypto::ring::default_provider().install_default();
            let (address, request_rx, server) = spawn_upstream_request_sink().await;
            let shared = Arc::new(SharedState::new(8));
            shared.cache_resolved_hostname(
                "example.com",
                crate::netstack::shared::ResolvedHostnameFamily::Ipv4,
                [address.ip()],
                Duration::from_secs(60),
            );
            let state = test_tls_state(SecretsConfig::default());
            let mut roots = rustls::RootCertStore::empty();
            roots.add(state.intercept_ca.cert_der.clone()).unwrap();
            let config = rustls::ClientConfig::builder()
                .with_root_certificates(roots)
                .with_no_client_auth();
            let mut client = rustls::ClientConnection::new(
                Arc::new(config),
                ServerName::IpAddress(address.ip().into()),
            )
            .unwrap();
            let (from_tx, from_rx) = mpsc::channel(8);
            let (to_tx, mut to_rx) = mpsc::channel(8);
            let proxy = TlsProxy::new(
                None,
                address,
                UpstreamTcpTarget::direct(address),
                from_rx,
                to_tx,
                shared,
                state,
                Arc::new(NetworkPolicy::none().allow_domain("example.com").unwrap()),
                true,
                Arc::new(ProxyConnectState::new()),
                NetworkExtensions::default(),
                None,
            );
            let relay = tokio::spawn(proxy.try_run());
            send_client_tls_output(&mut client, &from_tx).await;
            complete_relay_handshake(&mut client, &from_tx, &mut to_rx).await;
            let request = b"GET / HTTP/1.1\r\nHost: 127.0.0.1\r\n\r\n";
            client.writer().write_all(request).unwrap();
            send_client_tls_output(&mut client, &from_tx).await;
            assert_eq!(request_rx.await.unwrap(), request);
            drop(from_tx);
            while to_rx.recv().await.is_some() {}
            relay.await.unwrap().unwrap();
            server.await.unwrap().unwrap();
        };
        tokio::time::timeout(Duration::from_secs(5), check)
            .await
            .unwrap();
    }

    #[tokio::test]
    async fn bypass_preserves_legacy_tls_without_signature_algorithms() {
        let _ = rustls::crypto::ring::default_provider().install_default();
        for (name, fragmented) in [
            (Some("example.com"), false),
            (None, false),
            (Some("example.com"), true),
            (None, true),
        ] {
            let mut hello = legacy_client_hello(name);
            if fragmented {
                let mut wire = Vec::new();
                for fragment in hello[5..].chunks(17) {
                    wire.extend_from_slice(&hello[..3]);
                    wire.extend_from_slice(&(fragment.len() as u16).to_be_bytes());
                    wire.extend_from_slice(fragment);
                }
                hello = wire;
            }
            let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
            let state = Arc::new(isolated_tls_state(
                TlsConfig {
                    bypass: vec![name.unwrap_or("127.0.0.1").into()],
                    ..Default::default()
                },
                SecretsHandle::new(SecretsConfig::default()),
            ));
            let received = run_bypass_probe(
                listener,
                state,
                Arc::new(SharedState::new(8)),
                NetworkPolicy::allow_all(),
                false,
                hello.clone(),
            )
            .await;
            assert_eq!(received, hello);
        }
    }

    #[tokio::test]
    async fn client_hello_treats_invalid_dns_names_as_absent() {
        for name in [
            "",
            "a..b",
            "-example.com",
            "example.123",
            "é.example",
            &"a".repeat(254),
        ] {
            let (tx, mut rx) = mpsc::channel(1);
            let hello = legacy_client_hello(Some(name));
            tx.send(Bytes::from(hello.clone())).await.unwrap();
            drop(tx);
            let (name, buffered) = read_client_hello(&mut rx, Vec::new()).await.unwrap();
            assert_eq!(name, None);
            assert_eq!(buffered, hello);
        }
    }

    #[tokio::test]
    async fn duplicate_sni_cannot_replace_the_policy_hostname() {
        let _ = rustls::crypto::ring::default_provider().install_default();
        let config = rustls::ClientConfig::builder()
            .with_root_certificates(rustls::RootCertStore::empty())
            .with_no_client_auth();
        let mut client = rustls::ClientConnection::new(
            Arc::new(config),
            ServerName::try_from("blocked.example").unwrap(),
        )
        .unwrap();
        let mut hello = Vec::new();
        client.write_tls(&mut hello).unwrap();
        // Skip record/handshake headers, version/random, session ID, ciphers,
        // and compression methods to find the extensions length.
        let mut extensions_offset = 9 + 34;
        extensions_offset += 1 + hello[extensions_offset] as usize;
        let length = u16::from_be_bytes([hello[extensions_offset], hello[extensions_offset + 1]]);
        extensions_offset += 2 + length as usize;
        extensions_offset += 1 + hello[extensions_offset] as usize;
        let other = legacy_client_hello(Some("allowed.example"));
        let mut sni_offset = extensions_offset + 2;
        while hello[sni_offset..sni_offset + 2] != [0, 0] {
            let size = u16::from_be_bytes([hello[sni_offset + 2], hello[sni_offset + 3]]);
            sni_offset += 4 + size as usize;
        }

        // Preserve the first policy hostname while rejecting malformed lists
        // and duplicate names, whether inside one extension or across two.
        for (same_extension, malformed) in
            [(false, false), (false, true), (true, false), (true, true)]
        {
            let mut wire = hello.clone();
            if same_extension {
                let old_length =
                    u16::from_be_bytes([wire[sni_offset + 2], wire[sni_offset + 3]]) as usize;
                let end = sni_offset + 4 + old_length;
                let mut entry = other[58..].to_vec();
                if malformed {
                    entry[1..3].copy_from_slice(&u16::MAX.to_be_bytes());
                }
                wire.splice(end..end, entry.iter().copied());
                let size = (old_length + entry.len()) as u16;
                wire[sni_offset + 2..sni_offset + 4].copy_from_slice(&size.to_be_bytes());
                wire[sni_offset + 4..sni_offset + 6].copy_from_slice(&(size - 2).to_be_bytes());
            } else {
                let second = wire.len();
                wire.extend_from_slice(&other[52..]);
                if malformed {
                    wire[second + 2..second + 4].copy_from_slice(&u16::MAX.to_be_bytes());
                }
            }
            let size = (wire.len() - 5) as u16;
            wire[3..5].copy_from_slice(&size.to_be_bytes());
            let size = (wire.len() - 9) as u32;
            wire[6..9].copy_from_slice(&size.to_be_bytes()[1..]);
            let size = (wire.len() - extensions_offset - 2) as u16;
            wire[extensions_offset..extensions_offset + 2].copy_from_slice(&size.to_be_bytes());
            assert_eq!(sni::extract_sni(&wire).as_deref(), Some("blocked.example"));
            let (tx, mut rx) = mpsc::channel(1);
            tx.send(Bytes::from(wire)).await.unwrap();
            drop(tx);
            assert!(
                read_client_hello(&mut rx, Vec::new()).await.is_err(),
                "same_extension={same_extension}, malformed={malformed}"
            );
        }
    }

    fn legacy_client_hello(name: Option<&str>) -> Vec<u8> {
        // TLS 1.1: RSA cipher and null compression, without signature_algorithms.
        let mut body = vec![3, 2];
        body.extend_from_slice(&[0; 32]);
        body.extend_from_slice(&[0, 0, 2, 0, 0x2f, 1, 0]);
        if let Some(name) = name {
            let name = name.as_bytes();
            body.extend_from_slice(&((name.len() + 9) as u16).to_be_bytes());
            body.extend_from_slice(&[0, 0]);
            body.extend_from_slice(&((name.len() + 5) as u16).to_be_bytes());
            body.extend_from_slice(&((name.len() + 3) as u16).to_be_bytes());
            body.push(0);
            body.extend_from_slice(&(name.len() as u16).to_be_bytes());
            body.extend_from_slice(name);
        }
        let mut hello = vec![0x16, 3, 2];
        hello.extend_from_slice(&((body.len() + 4) as u16).to_be_bytes());
        hello.push(1);
        hello.extend_from_slice(&(body.len() as u32).to_be_bytes()[1..]);
        hello.extend_from_slice(&body);
        hello
    }

    async fn run_bypass_probe(
        listener: TcpListener,
        state: Arc<TlsState>,
        shared: Arc<SharedState>,
        policy: NetworkPolicy,
        strict: bool,
        hello: Vec<u8>,
    ) -> Vec<u8> {
        let address = listener.local_addr().unwrap();
        let stream = TcpStream::connect(address).await.unwrap();
        let server = tokio::spawn(async move {
            let mut stream = accept_with_deadline(listener).await.unwrap();
            let mut received = Vec::new();
            stream.read_to_end(&mut received).await.unwrap();
            received
        });
        let (tx, rx) = mpsc::channel(hello.len());
        let (to_tx, _to_rx) = mpsc::channel(1);
        for fragment in hello.chunks(7) {
            tx.send(Bytes::copy_from_slice(fragment)).await.unwrap();
        }
        drop(tx);
        let proxy = TlsProxy::new(
            Some(stream),
            address,
            UpstreamTcpTarget::direct(address),
            rx,
            to_tx,
            shared,
            state,
            Arc::new(policy),
            strict,
            Arc::new(ProxyConnectState::new()),
            NetworkExtensions::default(),
            None,
        );
        tokio::time::timeout(Duration::from_secs(2), proxy.try_run())
            .await
            .unwrap()
            .unwrap();
        server.await.unwrap()
    }

    fn guest_client(tls_state: &TlsState) -> rustls::ClientConnection {
        let mut roots = rustls::RootCertStore::empty();
        roots.add(tls_state.intercept_ca.cert_der.clone()).unwrap();
        let config = rustls::ClientConfig::builder()
            .with_root_certificates(roots)
            .with_no_client_auth();
        rustls::ClientConnection::new(
            Arc::new(config),
            ServerName::try_from("example.com".to_owned()).unwrap(),
        )
        .unwrap()
    }

    fn upstream_server_config() -> Arc<rustls::ServerConfig> {
        let key_pair = rcgen::KeyPair::generate().unwrap();
        let params = rcgen::CertificateParams::new(vec!["example.com".to_owned()]).unwrap();
        let cert = params.self_signed(&key_pair).unwrap();
        let chain = vec![CertificateDer::from(cert.der().to_vec())];
        let key = PrivateKeyDer::Pkcs8(PrivatePkcs8KeyDer::from(key_pair.serialize_der()));
        Arc::new(
            rustls::ServerConfig::builder()
                .with_no_client_auth()
                .with_single_cert(chain, key)
                .unwrap(),
        )
    }

    async fn send_client_tls_output(
        client: &mut rustls::ClientConnection,
        to_relay: &mpsc::Sender<Bytes>,
    ) {
        while client.wants_write() {
            let mut encrypted = Vec::new();
            client.write_tls(&mut encrypted).unwrap();
            to_relay.send(Bytes::from(encrypted)).await.unwrap();
        }
    }

    async fn complete_relay_handshake(
        client: &mut rustls::ClientConnection,
        to_relay: &mpsc::Sender<Bytes>,
        from_relay: &mut mpsc::Receiver<Bytes>,
    ) {
        for _ in 0..8 {
            if !client.is_handshaking() {
                return;
            }
            let encrypted =
                tokio::time::timeout(std::time::Duration::from_secs(1), from_relay.recv())
                    .await
                    .expect("guest handshake record timed out")
                    .expect("relay closed during guest handshake");
            let mut input = encrypted.as_ref();
            client.read_tls(&mut input).unwrap();
            client.process_new_packets().unwrap();
            send_client_tls_output(client, to_relay).await;
        }
        assert!(
            !client.is_handshaking(),
            "guest TLS handshake did not finish"
        );
    }

    async fn read_connect_request(stream: &mut TcpStream) -> io::Result<String> {
        tokio::time::timeout(Duration::from_secs(1), async {
            let mut request = Vec::new();
            while !request.ends_with(b"\r\n\r\n") {
                let mut byte = [0_u8; 1];
                stream.read_exact(&mut byte).await?;
                request.push(byte[0]);
            }
            String::from_utf8(request)
                .map_err(|error| io::Error::new(io::ErrorKind::InvalidData, error))
        })
        .await
        .map_err(|_| io::Error::new(io::ErrorKind::TimedOut, "CONNECT request timed out"))?
    }

    async fn spawn_sink() -> (SocketAddr, tokio::task::JoinHandle<Vec<u8>>) {
        let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let address = listener.local_addr().unwrap();
        let sink = tokio::spawn(async move {
            let mut stream = accept_with_deadline(listener).await.unwrap();
            let mut received = Vec::new();
            stream.read_to_end(&mut received).await.unwrap();
            received
        });
        (address, sink)
    }
    fn guest_client_hello(tls_state: &TlsState) -> Bytes {
        let mut client = guest_client(tls_state);
        let mut hello = Vec::new();
        client.write_tls(&mut hello).unwrap();
        Bytes::from(hello)
    }

    async fn spawn_upstream_after_eof(
        response: &'static [u8],
    ) -> (
        SocketAddr,
        oneshot::Receiver<Vec<u8>>,
        oneshot::Sender<()>,
        tokio::task::JoinHandle<io::Result<()>>,
    ) {
        let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let address = listener.local_addr().unwrap();
        let (eof_tx, eof_rx) = oneshot::channel();
        let (release_tx, release_rx) = oneshot::channel();
        let server = tokio::spawn(async move {
            let stream = accept_with_deadline(listener).await?;
            let mut stream = TlsAcceptor::from(upstream_server_config())
                .accept(stream)
                .await?;
            let mut received = Vec::new();
            stream.read_to_end(&mut received).await?;
            let _ = eof_tx.send(received);
            let _ = release_rx.await;
            stream.write_all(response).await?;
            stream.shutdown().await
        });
        (address, eof_rx, release_tx, server)
    }
    struct ScriptedRequestStream {
        actions: VecDeque<RequestAction>,
    }

    struct RecordingRequestStream {
        seen: Arc<Mutex<Vec<Vec<u8>>>>,
    }

    impl AuthorizedRouteRequestStream for RecordingRequestStream {
        fn process<'a>(&'a mut self, chunk: &'a [u8]) -> BoxFuture<'a, io::Result<RequestAction>> {
            self.seen.lock().unwrap().push(chunk.to_vec());
            Box::pin(async { Ok(RequestAction::ForwardCurrent) })
        }
    }

    struct RecordingRequestExtension {
        routes: Mutex<Vec<AuthorizedTlsRoute>>,
        seen: Arc<Mutex<Vec<Vec<u8>>>>,
    }

    impl AuthorizedRouteRequestExtension for RecordingRequestExtension {
        fn open(
            &self,
            route: &AuthorizedTlsRoute,
        ) -> Option<Box<dyn AuthorizedRouteRequestStream>> {
            self.routes.lock().unwrap().push(route.clone());
            Some(Box::new(RecordingRequestStream {
                seen: self.seen.clone(),
            }))
        }
    }

    struct OrderedRequestExtension {
        order: Arc<Mutex<Vec<&'static str>>>,
    }

    impl AuthorizedRouteRequestExtension for OrderedRequestExtension {
        fn open(
            &self,
            _route: &AuthorizedTlsRoute,
        ) -> Option<Box<dyn AuthorizedRouteRequestStream>> {
            self.order.lock().unwrap().push("request factory");
            None
        }
    }

    struct UninterestedRequestExtension(AtomicUsize);

    impl AuthorizedRouteRequestExtension for UninterestedRequestExtension {
        fn open(
            &self,
            _route: &AuthorizedTlsRoute,
        ) -> Option<Box<dyn AuthorizedRouteRequestStream>> {
            self.0.fetch_add(1, std::sync::atomic::Ordering::Relaxed);
            None
        }
    }

    struct CountingRequestExtension(AtomicUsize);

    impl AuthorizedRouteRequestExtension for CountingRequestExtension {
        fn open(
            &self,
            _route: &AuthorizedTlsRoute,
        ) -> Option<Box<dyn AuthorizedRouteRequestStream>> {
            self.0.fetch_add(1, Ordering::Relaxed);
            None
        }
    }

    struct GatedRequestStream {
        started: Option<tokio::sync::oneshot::Sender<()>>,
        release: Option<tokio::sync::oneshot::Receiver<()>>,
    }

    impl AuthorizedRouteRequestStream for GatedRequestStream {
        fn process<'a>(&'a mut self, _chunk: &'a [u8]) -> BoxFuture<'a, io::Result<RequestAction>> {
            let started = self.started.take().expect("process called once");
            let release = self.release.take().expect("process called once");
            Box::pin(async move {
                let _ = started.send(());
                let _ = release.await;
                Ok(RequestAction::ForwardCurrent)
            })
        }
    }

    struct DropGuard(Arc<std::sync::atomic::AtomicBool>);

    impl Drop for DropGuard {
        fn drop(&mut self) {
            self.0.store(true, std::sync::atomic::Ordering::Release);
        }
    }

    struct BlockingRequestStream {
        started: Option<tokio::sync::oneshot::Sender<()>>,
        dropped: Arc<std::sync::atomic::AtomicBool>,
    }

    impl AuthorizedRouteRequestStream for BlockingRequestStream {
        fn process<'a>(&'a mut self, _chunk: &'a [u8]) -> BoxFuture<'a, io::Result<RequestAction>> {
            let started = self.started.take().expect("process called once");
            let guard = DropGuard(self.dropped.clone());
            Box::pin(async move {
                let _guard = guard;
                let _ = started.send(());
                std::future::pending::<io::Result<RequestAction>>().await
            })
        }
    }

    impl AuthorizedRouteRequestStream for ScriptedRequestStream {
        fn process<'a>(&'a mut self, _chunk: &'a [u8]) -> BoxFuture<'a, io::Result<RequestAction>> {
            let action = self.actions.pop_front().expect("script action");
            Box::pin(async move { Ok(action) })
        }
    }

    struct ScriptedRequestExtension {
        actions: Mutex<Option<VecDeque<RequestAction>>>,
    }

    impl AuthorizedRouteRequestExtension for ScriptedRequestExtension {
        fn open(
            &self,
            _route: &AuthorizedTlsRoute,
        ) -> Option<Box<dyn AuthorizedRouteRequestStream>> {
            self.actions
                .lock()
                .unwrap()
                .take()
                .map(|actions| Box::new(ScriptedRequestStream { actions }) as _)
        }
    }

    struct HoldingRequestExtension {
        processed: Option<oneshot::Sender<()>>,
        dropped: Arc<AtomicBool>,
    }

    struct HoldingRequestStream {
        processed: Option<oneshot::Sender<()>>,
        dropped: Arc<AtomicBool>,
    }

    impl Drop for HoldingRequestStream {
        fn drop(&mut self) {
            self.dropped.store(true, Ordering::Release);
        }
    }

    impl AuthorizedRouteRequestExtension for Mutex<HoldingRequestExtension> {
        fn open(
            &self,
            _route: &AuthorizedTlsRoute,
        ) -> Option<Box<dyn AuthorizedRouteRequestStream>> {
            let mut extension = self.lock().unwrap();
            Some(Box::new(HoldingRequestStream {
                processed: extension.processed.take(),
                dropped: extension.dropped.clone(),
            }))
        }
    }

    impl AuthorizedRouteRequestStream for HoldingRequestStream {
        fn process<'a>(&'a mut self, _chunk: &'a [u8]) -> BoxFuture<'a, io::Result<RequestAction>> {
            if let Some(processed) = self.processed.take() {
                let _ = processed.send(());
            }
            Box::pin(async { Ok(RequestAction::Hold) })
        }
    }

    struct BlockingRequestExtension {
        started: Option<oneshot::Sender<()>>,
        dropped: Arc<AtomicBool>,
    }

    impl AuthorizedRouteRequestExtension for Mutex<BlockingRequestExtension> {
        fn open(
            &self,
            _route: &AuthorizedTlsRoute,
        ) -> Option<Box<dyn AuthorizedRouteRequestStream>> {
            let mut extension = self.lock().unwrap();
            Some(Box::new(BlockingRequestStream {
                started: extension.started.take(),
                dropped: extension.dropped.clone(),
            }))
        }
    }

    async fn spawn_upstream_request_sink() -> (
        SocketAddr,
        oneshot::Receiver<Vec<u8>>,
        tokio::task::JoinHandle<io::Result<()>>,
    ) {
        let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let address = listener.local_addr().unwrap();
        let (request_tx, request_rx) = oneshot::channel();
        let server = tokio::spawn(async move {
            let stream = accept_with_deadline(listener).await?;
            let mut stream = TlsAcceptor::from(upstream_server_config())
                .accept(stream)
                .await?;
            let mut buf = [0; RELAY_BUF_SIZE];
            let request = match stream.read(&mut buf).await {
                Ok(read) => buf[..read].to_vec(),
                // Fail-closed relay outcomes drop the upstream connection without
                // reading queued-but-unsent bytes (e.g. TLS 1.3 session tickets the
                // server sends unsolicited right after the handshake). Depending on
                // scheduling, the kernel may report that abrupt drop as a reset
                // rather than a clean EOF; both mean "no request bytes arrived".
                Err(error)
                    if matches!(
                        error.kind(),
                        io::ErrorKind::UnexpectedEof | io::ErrorKind::ConnectionReset
                    ) =>
                {
                    Vec::new()
                }
                Err(error) => return Err(error),
            };
            let _ = request_tx.send(request);
            match stream.shutdown().await {
                Ok(()) => Ok(()),
                // Fail-closed relay outcomes may drop the upstream socket before
                // the fixture can send its TLS close notification.
                Err(error)
                    if matches!(
                        error.kind(),
                        io::ErrorKind::BrokenPipe | io::ErrorKind::ConnectionReset
                    ) =>
                {
                    Ok(())
                }
                Err(error) => Err(error),
            }
        });
        (address, request_rx, server)
    }

    #[tokio::test]
    async fn secret_denial_is_delivered_inside_the_existing_tls_connection() {
        let check = async {
            for (enabled, streamed, response_started) in [
                (true, false, false),
                (false, false, false),
                (true, true, false),
                (true, true, true),
            ] {
                let _ = rustls::crypto::ring::default_provider().install_default();
                let mut secrets = host_bound_secret_config();
                secrets.secrets[0].allowed_hosts = vec![HostPattern::Exact("github.com".into())];
                let tls_state = test_tls_state(secrets);
                let shared = Arc::new(SharedState::new(8));
                shared.set_http_config(microsandbox_types::HttpConfig {
                    deny_response: enabled,
                    deny_response_format: microsandbox_types::HttpDenyResponseFormat::Json,
                    ..Default::default()
                });
                let headers = b"POST / HTTP/1.1\r\nHost: example.com\r\nContent-Length: 8\r\n\r\n";
                let early_response = b"HTTP/1.1 200 OK\r\nContent-Length: 8\r\n\r\nhello";
                let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
                let upstream = listener.local_addr().unwrap();
                let (headers_tx, headers_rx) = oneshot::channel();
                let server = tokio::spawn(async move {
                    let stream = accept_with_deadline(listener).await.unwrap();
                    let mut stream = TlsAcceptor::from(upstream_server_config())
                        .accept(stream)
                        .await
                        .unwrap();
                    if streamed {
                        let mut received = vec![0; headers.len()];
                        stream.read_exact(&mut received).await.unwrap();
                        assert_eq!(received, headers);
                    }
                    let _ = headers_tx.send(());
                    if response_started {
                        stream.write_all(early_response).await.unwrap();
                        stream.flush().await.unwrap();
                    }
                    let mut rejected = Vec::new();
                    match stream.read_to_end(&mut rejected).await {
                        Ok(_) => {}
                        Err(error)
                            if matches!(
                                error.kind(),
                                io::ErrorKind::UnexpectedEof | io::ErrorKind::ConnectionReset
                            ) => {}
                        Err(error) => panic!("upstream read failed: {error}"),
                    }
                    assert!(
                        rejected.is_empty(),
                        "blocked TLS request bytes reached upstream"
                    );
                });
                let (from_tx, from_rx) = mpsc::channel(8);
                let (to_tx, mut to_rx) = mpsc::channel(8);
                let mut client = guest_client(&tls_state);
                send_client_tls_output(&mut client, &from_tx).await;
                let relay = tokio::spawn(intercept_relay(
                    "203.0.113.10:443".parse().unwrap(),
                    UpstreamTcpTarget::direct(upstream),
                    "example.com",
                    true,
                    true,
                    Vec::new(),
                    from_rx,
                    to_tx,
                    shared,
                    tls_state,
                    Arc::new(ProxyConnectState::new()),
                    NetworkExtensions::default(),
                    None,
                    None,
                ));
                if streamed {
                    complete_relay_handshake(&mut client, &from_tx, &mut to_rx).await;
                    // Fragment the headers across TLS records before delivering the body.
                    client.writer().write_all(&headers[..12]).unwrap();
                    send_client_tls_output(&mut client, &from_tx).await;
                    client.writer().write_all(&headers[12..]).unwrap();
                    send_client_tls_output(&mut client, &from_tx).await;
                    headers_rx.await.unwrap();
                    if response_started {
                        let mut received = Vec::new();
                        while received.len() < early_response.len() {
                            let bytes = to_rx.recv().await.unwrap();
                            client.read_tls(&mut bytes.as_ref()).unwrap();
                            client.process_new_packets().unwrap();
                            let mut buf = [0; 1024];
                            while let Ok(n) = client.reader().read(&mut buf) {
                                if n == 0 {
                                    break;
                                }
                                received.extend_from_slice(&buf[..n]);
                            }
                        }
                        assert_eq!(received, early_response);
                    }
                    client.writer().write_all(b"$MSB_KEY").unwrap();
                    send_client_tls_output(&mut client, &from_tx).await;
                } else {
                    // Coalesce the request with the guest's TLS Finished flight,
                    // exercising plaintext already buffered during the handshake.
                    while client.is_handshaking() {
                        let bytes = to_rx.recv().await.unwrap();
                        client.read_tls(&mut bytes.as_ref()).unwrap();
                        client.process_new_packets().unwrap();
                        if !client.is_handshaking() {
                            client.writer().write_all(headers).unwrap();
                            client.writer().write_all(b"$MSB_KEY").unwrap();
                        }
                        send_client_tls_output(&mut client, &from_tx).await;
                    }
                }
                let mut response = Vec::new();
                let mut clean_close = false;
                while let Some(bytes) = to_rx.recv().await {
                    client.read_tls(&mut bytes.as_ref()).unwrap();
                    clean_close |= client.process_new_packets().unwrap().peer_has_closed();
                    let mut buf = [0; 1024];
                    loop {
                        match client.reader().read(&mut buf) {
                            Ok(0) => break,
                            Ok(n) => response.extend_from_slice(&buf[..n]),
                            Err(error) if error.kind() == io::ErrorKind::WouldBlock => break,
                            Err(error) => panic!("denial TLS read failed: {error}"),
                        }
                    }
                }
                assert!(
                    relay.await.unwrap().is_err(),
                    "secret request must remain blocked"
                );
                server.await.unwrap();
                if enabled && !response_started {
                    assert!(
                        response.starts_with(b"HTTP/1.1 403 Forbidden\r\n"),
                        "{response:?}"
                    );
                    let body = String::from_utf8(response).unwrap();
                    let (_, json) = body.split_once("\r\n\r\n").unwrap();
                    let error: serde_json::Value = serde_json::from_str(json).unwrap();
                    assert_eq!(error["code"], "secret_policy_denied");
                    assert_eq!(error["domain"], "example.com");
                    assert!(!body.contains("real-secret-value") && !body.contains("$MSB_KEY"));
                    assert!(
                        clean_close,
                        "guest must receive TLS close_notify after the denial"
                    );
                } else {
                    assert!(
                        response.is_empty(),
                        "must not append a denial: {response:?}"
                    );
                }
            }
        };
        tokio::time::timeout(Duration::from_secs(10), check)
            .await
            .expect("TLS secret denial fixture timed out");
    }

    #[tokio::test]
    async fn intercept_relay_rejects_a_truncated_h2_header_block_without_forwarding() {
        let _ = rustls::crypto::ring::default_provider().install_default();
        // A non-empty secret makes the relay install the HTTP/2 secret handler;
        // a truncated HPACK representation must then fail the connection closed
        // instead of reaching httlib-hpack's out-of-bounds indexing.
        let tls_state = test_tls_state(host_bound_secret_config());
        let (upstream, upstream_request, server) = spawn_upstream_request_sink().await;
        let guest_destination: SocketAddr = "203.0.113.10:443".parse().unwrap();
        let (from_tx, from_rx) = mpsc::channel(4);
        let (to_tx, mut to_rx) = mpsc::channel(4);
        let mut client = guest_client(&tls_state);
        send_client_tls_output(&mut client, &from_tx).await;
        let relay = tokio::spawn(intercept_relay(
            guest_destination,
            UpstreamTcpTarget::direct(upstream),
            "example.com",
            true,
            true,
            Vec::new(),
            from_rx,
            to_tx,
            Arc::new(SharedState::new(4)),
            tls_state,
            Arc::new(ProxyConnectState::new()),
            NetworkExtensions::default(),
            None,
            None,
        ));

        complete_relay_handshake(&mut client, &from_tx, &mut to_rx).await;
        // h2 preface + empty SETTINGS + HEADERS(stream 1, END_HEADERS|END_STREAM)
        // whose entire header block is the truncated representation `ff`.
        let mut payload = b"PRI * HTTP/2.0\r\n\r\nSM\r\n\r\n".to_vec();
        payload.extend_from_slice(&[0, 0, 0, 0x04, 0x00, 0, 0, 0, 0]);
        payload.extend_from_slice(&[0, 0, 1, 0x01, 0x05, 0, 0, 0, 1, 0xff]);
        client.writer().write_all(&payload).unwrap();
        send_client_tls_output(&mut client, &from_tx).await;

        // The relay must fail closed on the malformed block...
        let result = tokio::time::timeout(Duration::from_secs(5), relay)
            .await
            .expect("relay did not close after a truncated header block")
            .unwrap();
        assert!(
            result.is_err(),
            "relay must close on a truncated header block"
        );
        drop(from_tx);
        // ...and the rejected flight must not reach the upstream at all.
        let received = tokio::time::timeout(Duration::from_secs(1), upstream_request)
            .await
            .expect("upstream sink did not finish")
            .expect("upstream sink task failed");
        assert!(
            received.is_empty(),
            "a rejected header flight must forward nothing upstream, got {received:02x?}"
        );
        server.await.unwrap().unwrap();
    }
    #[test]
    fn request_factory_can_bypass_unrelated_tls_routes() {
        let extension = Arc::new(UninterestedRequestExtension(
            std::sync::atomic::AtomicUsize::new(0),
        ));
        let stream = open_authorized_request_stream(
            &NetworkExtensions::new().with_authorized_requests(extension.clone()),
            "203.0.113.10:443".parse().unwrap(),
            "example.com",
            false,
        );

        assert!(stream.is_none());
        assert_eq!(extension.0.load(std::sync::atomic::Ordering::Relaxed), 1);
        assert!(
            open_authorized_request_stream(
                &NetworkExtensions::default(),
                "203.0.113.10:443".parse().unwrap(),
                "example.com",
                false,
            )
            .is_none()
        );
    }

    #[tokio::test]
    async fn intercept_relay_orders_route_factory_secret_substitution_and_upstream_flush() {
        let _ = rustls::crypto::ring::default_provider().install_default();
        let tls_state = test_tls_state(host_bound_secret_config());
        let (upstream, upstream_request, server) = spawn_upstream_request_sink().await;
        let guest_destination: SocketAddr = "203.0.113.10:443".parse().unwrap();
        let seen = Arc::new(Mutex::new(Vec::new()));
        let requests = Arc::new(RecordingRequestExtension {
            routes: Mutex::new(Vec::new()),
            seen: seen.clone(),
        });
        let (from_tx, from_rx) = mpsc::channel(4);
        let (to_tx, mut to_rx) = mpsc::channel(4);
        let mut client = guest_client(&tls_state);
        send_client_tls_output(&mut client, &from_tx).await;
        let relay = tokio::spawn(intercept_relay(
            guest_destination,
            UpstreamTcpTarget::direct(upstream),
            "example.com",
            true,
            true,
            Vec::new(),
            from_rx,
            to_tx,
            Arc::new(SharedState::new(4)),
            tls_state,
            Arc::new(ProxyConnectState::new()),
            NetworkExtensions::new().with_authorized_requests(requests.clone()),
            None,
            None,
        ));

        complete_relay_handshake(&mut client, &from_tx, &mut to_rx).await;
        client
            .writer()
            .write_all(
                b"GET / HTTP/1.1\r\nHost: example.com\r\nAuthorization: Bearer $MSB_KEY\r\n\r\n",
            )
            .unwrap();
        send_client_tls_output(&mut client, &from_tx).await;

        // The sink receives this before guest FIN, proving production relay
        // flushes the extension-approved plaintext upstream.
        let upstream_request =
            tokio::time::timeout(std::time::Duration::from_secs(1), upstream_request)
                .await
                .expect("upstream did not receive flushed request")
                .unwrap();
        assert!(
            upstream_request
                .windows(b"real-secret-value".len())
                .any(|w| w == b"real-secret-value")
        );
        assert!(
            !upstream_request
                .windows(b"$MSB_KEY".len())
                .any(|w| w == b"$MSB_KEY")
        );
        assert_eq!(
            seen.lock().unwrap().as_slice(),
            std::slice::from_ref(&upstream_request)
        );
        assert_eq!(
            requests.routes.lock().unwrap().as_slice(),
            &[AuthorizedTlsRoute::new(
                guest_destination,
                "example.com",
                true
            )]
        );
        drop(from_tx);
        relay.await.unwrap().unwrap();
        server.await.unwrap().unwrap();
    }

    fn github_style_intercept_config() -> InterceptConfig {
        InterceptConfig {
            rules: vec![InterceptRule {
                host: "example.com".into(),
                method: "GET".into(),
                path_prefix: "/allowed".into(),
                dispatch_on_headers: false,
            }],
            hook: Some(vec!["/bin/cat".to_string()]),
            max_request_bytes: 64 * 1024,
        }
    }

    #[tokio::test]
    async fn intercept_extension_refuses_unmatched_request_and_writes_nothing_upstream() {
        let _ = rustls::crypto::ring::default_provider().install_default();
        let tls_state = test_tls_state(SecretsConfig::default());
        let (upstream, upstream_request, server) = spawn_upstream_request_sink().await;
        let (from_tx, from_rx) = mpsc::channel(4);
        let (to_tx, mut to_rx) = mpsc::channel(4);
        let mut client = guest_client(&tls_state);
        send_client_tls_output(&mut client, &from_tx).await;
        let extensions = NetworkExtensions::new().with_authorized_requests(Arc::new(
            InterceptExtension::new(github_style_intercept_config()),
        ));
        let relay = tokio::spawn(intercept_relay(
            "203.0.113.10:443".parse().unwrap(),
            UpstreamTcpTarget::direct(upstream),
            "example.com",
            false,
            false,
            Vec::new(),
            from_rx,
            to_tx,
            Arc::new(SharedState::new(4)),
            tls_state,
            Arc::new(ProxyConnectState::new()),
            extensions,
            None,
            None,
        ));

        complete_relay_handshake(&mut client, &from_tx, &mut to_rx).await;
        // "/denied" matches no rule — the only configured rule is `GET
        // /allowed` — so this must be refused, not forwarded.
        client
            .writer()
            .write_all(b"GET /denied HTTP/1.1\r\nHost: example.com\r\n\r\n")
            .unwrap();
        send_client_tls_output(&mut client, &from_tx).await;

        let mut response = Vec::new();
        for _ in 0..4 {
            let encrypted = to_rx.recv().await.expect("relay closed before response");
            let mut input = encrypted.as_ref();
            client.read_tls(&mut input).unwrap();
            client.process_new_packets().unwrap();
            let mut buf = [0; RELAY_BUF_SIZE];
            match client.reader().read(&mut buf) {
                Ok(n) => response.extend_from_slice(&buf[..n]),
                Err(error) if error.kind() == io::ErrorKind::WouldBlock => {}
                Err(error) => panic!("failed to decrypt refusal response: {error}"),
            }
            if response.starts_with(b"HTTP/1.1 403") {
                break;
            }
        }
        assert!(
            response.starts_with(b"HTTP/1.1 403"),
            "expected a 403 refusal, got: {}",
            String::from_utf8_lossy(&response)
        );
        relay.await.unwrap().unwrap();
        assert_eq!(
            upstream_request.await.unwrap(),
            b"",
            "no bytes may reach upstream once a policed request is refused"
        );
        server.await.unwrap().unwrap();
    }

    #[tokio::test]
    async fn intercept_extension_forwards_matched_request_after_hook_approval() {
        let _ = rustls::crypto::ring::default_provider().install_default();
        let tls_state = test_tls_state(SecretsConfig::default());
        let (upstream, upstream_request, server) = spawn_upstream_request_sink().await;
        let (from_tx, from_rx) = mpsc::channel(4);
        let (to_tx, mut to_rx) = mpsc::channel(4);
        let mut client = guest_client(&tls_state);
        send_client_tls_output(&mut client, &from_tx).await;
        let extensions = NetworkExtensions::new().with_authorized_requests(Arc::new(
            InterceptExtension::new(github_style_intercept_config()),
        ));
        let relay = tokio::spawn(intercept_relay(
            "203.0.113.10:443".parse().unwrap(),
            UpstreamTcpTarget::direct(upstream),
            "example.com",
            false,
            false,
            Vec::new(),
            from_rx,
            to_tx,
            Arc::new(SharedState::new(4)),
            tls_state,
            Arc::new(ProxyConnectState::new()),
            extensions,
            None,
            None,
        ));

        complete_relay_handshake(&mut client, &from_tx, &mut to_rx).await;
        client
            .writer()
            .write_all(b"GET /allowed HTTP/1.1\r\nHost: example.com\r\nContent-Length: 0\r\n\r\n")
            .unwrap();
        send_client_tls_output(&mut client, &from_tx).await;

        let received = tokio::time::timeout(std::time::Duration::from_secs(1), upstream_request)
            .await
            .expect("upstream did not receive the approved request")
            .unwrap();
        assert!(
            String::from_utf8_lossy(&received).contains("GET /allowed"),
            "the hook-approved request must reach upstream: {}",
            String::from_utf8_lossy(&received)
        );

        drop(from_tx);
        relay.await.unwrap().unwrap();
        server.await.unwrap().unwrap();
    }

    #[tokio::test]
    async fn request_dispatch_observes_substituted_secret_bytes() {
        let mut handler = SecretsHandler::new_tls_intercepted_via_connect(
            &host_bound_secret_config(),
            "example.com",
        );
        let chunk =
            b"GET / HTTP/1.1\r\nHost: example.com\r\nAuthorization: Bearer $MSB_KEY\r\n\r\n";
        let substituted = substitute_request_chunk(&mut handler, chunk).unwrap();
        let seen = Arc::new(Mutex::new(Vec::new()));
        let mut request_stream = RecordingRequestStream { seen: seen.clone() };
        let (mut upstream, mut observed) = tokio::io::duplex(256);

        dispatch_request_action(&mut request_stream, &substituted, &mut upstream)
            .await
            .unwrap();
        let mut forwarded = vec![0; substituted.len()];
        observed.read_exact(&mut forwarded).await.unwrap();

        assert_eq!(seen.lock().unwrap().as_slice(), &[substituted.to_vec()]);
        assert!(
            seen.lock().unwrap()[0]
                .windows(b"real-secret-value".len())
                .any(|window| window == b"real-secret-value")
        );
        assert!(
            !seen.lock().unwrap()[0]
                .windows(b"$MSB_KEY".len())
                .any(|window| window == b"$MSB_KEY")
        );
    }

    /// The no-SNI fixtures dial an IP literal, so their ClientHello carries no
    /// server name and the proxy names the route after the destination IP.
    const NO_SNI_DESTINATION: &str = "203.0.113.10:443";

    /// The route name the proxy derives for that destination: the IP literal.
    const NO_SNI_ROUTE_NAME: &str = "203.0.113.10";

    fn no_sni_destination() -> SocketAddr {
        NO_SNI_DESTINATION.parse().unwrap()
    }

    /// A guest TLS client that sends no SNI: rustls omits the extension when
    /// the server name is an IP literal.
    fn no_sni_guest_client(tls_state: &TlsState) -> rustls::ClientConnection {
        let mut roots = rustls::RootCertStore::empty();
        roots.add(tls_state.intercept_ca.cert_der.clone()).unwrap();
        let config = rustls::ClientConfig::builder()
            .with_root_certificates(roots)
            .with_no_client_auth();
        rustls::ClientConnection::new(
            Arc::new(config),
            ServerName::IpAddress(no_sni_destination().ip().into()),
        )
        .unwrap()
    }

    fn contains(haystack: &[u8], needle: &[u8]) -> bool {
        haystack
            .windows(needle.len())
            .any(|window| window == needle)
    }

    /// What one intercepted no-SNI exchange left behind.
    struct NoSniOutcome {
        /// Plaintext the upstream sink read before the connection ended.
        upstream: Vec<u8>,
        /// Decrypted plaintext the guest received.
        guest: Vec<u8>,
        /// The relay's return value.
        relay: io::Result<()>,
    }

    /// Drive one intercepted, no-SNI request through [`TlsProxy`] to a loopback
    /// upstream sink. The `Host` header and the request bytes are the caller's;
    /// the TLS identity and the proxy's route name are both the destination IP.
    async fn run_no_sni_probe(
        tls_state: Arc<TlsState>,
        shared: Arc<SharedState>,
        extensions: NetworkExtensions,
        request: &'static [u8],
    ) -> NoSniOutcome {
        let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let upstream = listener.local_addr().unwrap();
        let sink = tokio::spawn(async move {
            let stream = match accept_with_deadline(listener).await {
                Ok(stream) => stream,
                Err(_) => return Vec::new(),
            };
            let mut stream = match TlsAcceptor::from(upstream_server_config())
                .accept(stream)
                .await
            {
                Ok(stream) => stream,
                // A blocked request drops the upstream socket during handshake.
                Err(_) => return Vec::new(),
            };
            let mut received = Vec::new();
            let mut buf = [0_u8; RELAY_BUF_SIZE];
            loop {
                match stream.read(&mut buf).await {
                    Ok(0) => break,
                    Ok(read) => received.extend_from_slice(&buf[..read]),
                    // A fail-closed relay resets the connection; either way no
                    // further request bytes arrive.
                    Err(_) => return received,
                }
            }
            let _ = stream.shutdown().await;
            received
        });

        let (from_tx, from_rx) = mpsc::channel(8);
        let (to_tx, mut to_rx) = mpsc::channel(8);
        let mut client = no_sni_guest_client(&tls_state);
        send_client_tls_output(&mut client, &from_tx).await;

        let proxy = TlsProxy::new(
            None,
            no_sni_destination(),
            UpstreamTcpTarget::direct(upstream),
            from_rx,
            to_tx,
            shared,
            tls_state,
            Arc::new(NetworkPolicy::allow_all()),
            false,
            Arc::new(ProxyConnectState::new()),
            extensions,
            None,
        );
        let relay = tokio::spawn(proxy.try_run());

        complete_relay_handshake(&mut client, &from_tx, &mut to_rx).await;
        client.writer().write_all(request).unwrap();
        send_client_tls_output(&mut client, &from_tx).await;
        // Let the relay consume the request and apply its secret policy.
        tokio::time::sleep(Duration::from_millis(250)).await;
        drop(from_tx);

        let mut guest = Vec::new();
        while let Some(bytes) = to_rx.recv().await {
            let mut input = bytes.as_ref();
            if client.read_tls(&mut input).is_err() || client.process_new_packets().is_err() {
                continue;
            }
            let mut plain = [0_u8; RELAY_BUF_SIZE];
            loop {
                match client.reader().read(&mut plain) {
                    Ok(0) => break,
                    Ok(read) => guest.extend_from_slice(&plain[..read]),
                    Err(_) => break,
                }
            }
        }

        let relay = relay.await.unwrap();
        let upstream = tokio::time::timeout(Duration::from_secs(5), sink)
            .await
            .expect("upstream sink did not finish")
            .unwrap();

        NoSniOutcome {
            upstream,
            guest,
            relay,
        }
    }

    /// D9 (a): an origin-scoped header credential is never injected on a route
    /// with no hostname authority, even when the DNS cache pins the credential's
    /// origin to the destination IP and the request asks for that host.
    #[tokio::test]
    async fn no_sni_route_never_receives_an_origin_scoped_header_credential() {
        let _ = rustls::crypto::ring::default_provider().install_default();
        let shared = Arc::new(SharedState::new(8));
        shared.cache_resolved_hostname(
            "api.example.com",
            crate::netstack::shared::ResolvedHostnameFamily::Ipv4,
            [no_sni_destination().ip()],
            Duration::from_secs(60),
        );
        let credential = ResolvedHeaderCredential::from_definition(
            &microsandbox_types::DurableHeaderCredential {
                id: "api".into(),
                reference: "api-ref".into(),
                origin: microsandbox_types::HttpsOrigin {
                    host: "api.example.com".into(),
                    port: 443,
                },
                header: "x-api-key".into(),
                format: "%s".into(),
            },
            zeroize::Zeroizing::new("header-credential-value".to_owned()),
        );
        let tls_state =
            test_tls_state_with_credentials(SecretsConfig::default(), false, vec![credential]);

        let outcome = run_no_sni_probe(
            tls_state,
            shared,
            NetworkExtensions::default(),
            b"GET / HTTP/1.1\r\nHost: 203.0.113.10\r\n\r\n",
        )
        .await;

        // No secret policy applies, so the request itself is forwarded.
        assert!(contains(&outcome.upstream, b"GET / HTTP/1.1"));
        assert!(
            !contains(&outcome.upstream, b"header-credential-value"),
            "an origin-scoped credential must not be injected without hostname authority: {:?}",
            String::from_utf8_lossy(&outcome.upstream)
        );
        assert!(!contains(&outcome.upstream, b"x-api-key"));
    }

    /// D9 (b): a host-bound secret placeholder is neither substituted nor
    /// forwarded on a no-SNI route. The request is blocked: the relay fails and
    /// nothing reaches upstream.
    #[tokio::test]
    async fn no_sni_route_blocks_a_host_bound_secret_placeholder() {
        let _ = rustls::crypto::ring::default_provider().install_default();
        let shared = Arc::new(SharedState::new(8));
        // Even a DNS pin for the secret's host grants no hostname authority.
        shared.cache_resolved_hostname(
            "example.com",
            crate::netstack::shared::ResolvedHostnameFamily::Ipv4,
            [no_sni_destination().ip()],
            Duration::from_secs(60),
        );
        let tls_state = test_tls_state(host_bound_secret_config());

        let outcome = run_no_sni_probe(
            tls_state,
            shared,
            NetworkExtensions::default(),
            b"GET / HTTP/1.1\r\nHost: 203.0.113.10\r\nAuthorization: Bearer $MSB_KEY\r\n\r\n",
        )
        .await;

        assert!(
            outcome.relay.is_err(),
            "a host-bound placeholder on a no-SNI route must fail the relay closed"
        );
        assert!(
            outcome.upstream.is_empty(),
            "no request bytes may reach upstream: {:?}",
            String::from_utf8_lossy(&outcome.upstream)
        );
        assert!(!contains(&outcome.guest, b"real-secret-value"));
    }

    /// D9 (c): an `InterceptConfig` rule naming a host does not police the
    /// IP-named route, so the hook never runs and the request is forwarded
    /// untouched.
    #[tokio::test]
    async fn no_sni_route_does_not_invoke_a_hostname_intercept_rule() {
        let _ = rustls::crypto::ring::default_provider().install_default();
        let directory = tempfile::tempdir().unwrap();
        let marker = directory.path().join("hook-ran");
        let config = InterceptConfig {
            rules: vec![InterceptRule {
                host: "example.com".into(),
                method: "GET".into(),
                path_prefix: "/".into(),
                dispatch_on_headers: true,
            }],
            hook: Some(vec![
                "/bin/sh".into(),
                "-c".into(),
                format!("printf ran >> {}; cat", marker.display()),
            ]),
            max_request_bytes: 64 * 1024,
        };
        let extensions = NetworkExtensions::new()
            .with_authorized_requests(Arc::new(InterceptExtension::new(config)));

        let outcome = run_no_sni_probe(
            test_tls_state(SecretsConfig::default()),
            Arc::new(SharedState::new(8)),
            extensions,
            b"GET /anything HTTP/1.1\r\nHost: 203.0.113.10\r\n\r\n",
        )
        .await;

        assert!(
            !marker.exists(),
            "a hostname rule must not police the IP-named route"
        );
        assert!(contains(&outcome.upstream, b"GET /anything HTTP/1.1"));
        assert!(!outcome.relay.is_err());
    }

    /// D9 (d): a wildcard secret (`HostPattern::Any`) is still eligible for
    /// placeholder substitution on the no-SNI, destination-IP route, because its
    /// policy names no hostname identity to verify.
    #[tokio::test]
    async fn no_sni_route_still_substitutes_a_wildcard_secret() {
        let _ = rustls::crypto::ring::default_provider().install_default();
        let mut secrets = host_bound_secret_config();
        secrets.secrets[0].allowed_hosts = vec![HostPattern::Any];

        let outcome = run_no_sni_probe(
            test_tls_state(secrets),
            Arc::new(SharedState::new(8)),
            NetworkExtensions::default(),
            b"GET / HTTP/1.1\r\nHost: 203.0.113.10\r\nAuthorization: Bearer $MSB_KEY\r\n\r\n",
        )
        .await;

        assert!(
            contains(&outcome.upstream, b"real-secret-value"),
            "a wildcard secret stays eligible for substitution: {:?}",
            String::from_utf8_lossy(&outcome.upstream)
        );
        assert!(!contains(&outcome.upstream, b"$MSB_KEY"));
    }

    /// D9 (e): an `InterceptRule` whose `host` is the destination IP literal
    /// does police the IP-named route, and the hook runs.
    #[tokio::test]
    async fn no_sni_route_matches_an_exact_ip_intercept_rule() {
        let _ = rustls::crypto::ring::default_provider().install_default();
        let directory = tempfile::tempdir().unwrap();
        let marker = directory.path().join("hook-ran");
        let config = InterceptConfig {
            rules: vec![InterceptRule {
                host: no_sni_destination().ip().to_string(),
                method: "GET".into(),
                path_prefix: "/allowed".into(),
                dispatch_on_headers: true,
            }],
            hook: Some(vec![
                "/bin/sh".into(),
                "-c".into(),
                format!("printf ran >> {}; cat", marker.display()),
            ]),
            max_request_bytes: 64 * 1024,
        };
        let extensions = NetworkExtensions::new()
            .with_authorized_requests(Arc::new(InterceptExtension::new(config)));

        let outcome = run_no_sni_probe(
            test_tls_state(SecretsConfig::default()),
            Arc::new(SharedState::new(8)),
            extensions,
            b"GET /allowed HTTP/1.1\r\nHost: 203.0.113.10\r\n\r\n",
        )
        .await;

        assert!(
            marker.exists(),
            "an exact-IP rule must police the IP-named route"
        );
        assert!(
            contains(&outcome.upstream, b"GET /allowed HTTP/1.1"),
            "the hook-approved request must reach upstream: {:?}",
            String::from_utf8_lossy(&outcome.upstream)
        );
    }

    /// The DNS-pin guarantee: a secret placeholder on a route with no hostname
    /// authority and no DNS pin for the destination is blocked, not substituted,
    /// and nothing reaches upstream.
    #[tokio::test]
    async fn no_sni_route_without_a_dns_pin_blocks_a_host_bound_placeholder() {
        let _ = rustls::crypto::ring::default_provider().install_default();
        let tls_state = test_tls_state(host_bound_secret_config());
        let (upstream, upstream_request, server) = spawn_upstream_request_sink().await;
        let (from_tx, from_rx) = mpsc::channel(8);
        let (to_tx, mut to_rx) = mpsc::channel(8);
        let mut client = no_sni_guest_client(&tls_state);
        send_client_tls_output(&mut client, &from_tx).await;

        let relay = tokio::spawn(intercept_relay(
            no_sni_destination(),
            UpstreamTcpTarget::direct(upstream),
            NO_SNI_ROUTE_NAME,
            false,
            false,
            Vec::new(),
            from_rx,
            to_tx,
            Arc::new(SharedState::new(8)),
            tls_state,
            Arc::new(ProxyConnectState::new()),
            NetworkExtensions::default(),
            None,
            None,
        ));

        complete_relay_handshake(&mut client, &from_tx, &mut to_rx).await;
        client
            .writer()
            .write_all(
                b"GET / HTTP/1.1\r\nHost: 203.0.113.10\r\nAuthorization: Bearer $MSB_KEY\r\n\r\n",
            )
            .unwrap();
        send_client_tls_output(&mut client, &from_tx).await;

        let result = tokio::time::timeout(Duration::from_secs(5), relay)
            .await
            .expect("relay did not close on the blocked placeholder")
            .unwrap();
        assert!(result.is_err(), "the relay must fail closed");
        drop(from_tx);

        let received = tokio::time::timeout(Duration::from_secs(5), upstream_request)
            .await
            .expect("upstream sink did not finish")
            .unwrap();
        assert!(
            received.is_empty(),
            "a blocked placeholder must not reach upstream: {received:02x?}"
        );
        server.await.unwrap().unwrap();
    }
}
