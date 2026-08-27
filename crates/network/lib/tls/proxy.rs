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
use crate::extensions::{
    AuthorizedRouteRequestStream, AuthorizedTlsRoute, NetworkExtensions, OutboundProtocol,
    RequestAction,
};
use crate::netstack::shared::SharedState;
use crate::policy::{EgressEvaluation, HostnameSource, NetworkPolicy, Protocol};
use crate::secrets::config::ViolationAction;
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
    proxy_connect: Arc<ProxyConnectState>,
    extensions: NetworkExtensions,
    /// Pre-connected upstream; when `Some`, skips dialing `connect_target`.
    upstream_stream: Option<TcpStream>,
    /// Hostname from a CONNECT authority that must match the ClientHello SNI.
    expected_sni: Option<String>,
    /// `true` when the connection arrived via HTTP CONNECT.
    via_connect: bool,
    /// ClientHello bytes already consumed from the guest stream.
    initial_buf: Vec<u8>,
}

/// Result of applying one request-extension action to the upstream relay.
enum RequestDispatch {
    Continue { wrote: bool },
    RespondAndClose(Vec<u8>),
}

//--------------------------------------------------------------------------------------------------
// Methods
//--------------------------------------------------------------------------------------------------

impl TlsProxy {
    /// Build a proxy for a newly established guest TLS connection.
    #[allow(clippy::too_many_arguments)]
    pub(crate) fn new(
        guest_dst: SocketAddr,
        connect_target: UpstreamTcpTarget,
        from_smoltcp: mpsc::Receiver<Bytes>,
        to_smoltcp: mpsc::Sender<Bytes>,
        shared: Arc<SharedState>,
        tls_state: Arc<TlsState>,
        network_policy: Arc<NetworkPolicy>,
        proxy_connect: Arc<ProxyConnectState>,
        extensions: NetworkExtensions,
    ) -> Self {
        Self {
            guest_dst,
            connect_target,
            from_smoltcp,
            to_smoltcp,
            shared,
            tls_state,
            network_policy,
            proxy_connect,
            extensions,
            upstream_stream: None,
            expected_sni: None,
            via_connect: false,
            initial_buf: Vec::new(),
        }
    }

    /// Reuse an already connected upstream stream.
    pub(crate) fn with_upstream(mut self, upstream_stream: TcpStream) -> Self {
        self.upstream_stream = Some(upstream_stream);
        self
    }

    /// Mark this proxy as an HTTP CONNECT handoff and optionally verify its hostname authority.
    ///
    /// An IP-literal authority still marks the transport as CONNECT, but has no
    /// hostname authority to verify.
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
            proxy_connect,
            extensions,
            upstream_stream,
            expected_sni,
            via_connect,
            initial_buf,
        } = self;
        let connect_dst = connect_target.primary();
        let has_connect_hostname_authority = expected_sni.is_some();

        // Buffer initial data to extract SNI from ClientHello. Timeout prevents a
        // slow/malicious guest from holding a proxy slot indefinitely.
        let sni_name = tokio::time::timeout(
            std::time::Duration::from_secs(10),
            extract_sni_from_channel(&mut from_smoltcp, initial_buf),
        )
        .await
        .map_err(|_| io::Error::new(io::ErrorKind::TimedOut, "SNI extraction timed out"))?;
        let (sni_name, initial_buf) = sni_name?;

        // Canonicalize so byte equality against rule destinations works.
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

        // Apply Domain / DomainSuffix rules against the SNI.
        let eval = network_policy.evaluate_egress_with_source(
            guest_dst,
            Protocol::Tcp,
            &shared,
            HostnameSource::Sni(&sni_name),
        );
        if !matches!(eval, EgressEvaluation::Allow) {
            tracing::debug!(
                sni = %sni_name,
                dst = %guest_dst,
                "TLS egress denied by domain policy",
            );
            proxy_connect.mark_policy_denied();
            shared.proxy_wake.wake();
            return Ok(());
        }

        if tls_state.should_bypass(&sni_name) {
            tracing::debug!(sni = %sni_name, dst = %connect_dst, guest_dst = %guest_dst, "TLS bypass");
            bypass_relay(
                guest_dst,
                connect_target,
                &sni_name,
                initial_buf,
                from_smoltcp,
                to_smoltcp,
                shared,
                proxy_connect,
                extensions,
                upstream_stream,
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
            )
            .await
        }
    }
}

//--------------------------------------------------------------------------------------------------
// Functions
//--------------------------------------------------------------------------------------------------

/// Bypass mode: plain TCP splice, no TLS termination.
#[allow(clippy::too_many_arguments)]
async fn bypass_relay(
    guest_dst: SocketAddr,
    connect_target: UpstreamTcpTarget,
    sni_name: &str,
    initial_buf: Vec<u8>,
    mut from_smoltcp: mpsc::Receiver<Bytes>,
    to_smoltcp: mpsc::Sender<Bytes>,
    shared: Arc<SharedState>,
    proxy_connect: Arc<ProxyConnectState>,
    extensions: NetworkExtensions,
    upstream_stream: Option<TcpStream>,
) -> io::Result<()> {
    let mut server = match upstream_stream {
        Some(s) => s,
        None => {
            connect_target
                .connect(
                    guest_dst,
                    Some(sni_name),
                    OutboundProtocol::Tls,
                    &extensions,
                    &proxy_connect,
                    &shared,
                )
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
) -> io::Result<()> {
    // Per-connection snapshot: live secret updates apply to later connections.
    let secrets = tls_state.secrets.load();
    let mut secrets_handler = if has_connect_hostname_authority {
        SecretsHandler::new_tls_intercepted_via_connect(&secrets, sni_name)
    } else {
        // IP-literal CONNECT authorities retain the existing DNS-pin check.
        SecretsHandler::new_tls_intercepted(&secrets, sni_name, guest_dst.ip(), &shared)
    }
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

    // Feed the buffered ClientHello.
    {
        let mut remaining = &initial_buf[..];
        while !remaining.is_empty() {
            guest_tls
                .read_tls(&mut remaining)
                .map_err(io::Error::other)?;
            guest_tls.process_new_packets().map_err(io::Error::other)?;
        }
    }

    // Reusable buffer for TLS output — avoids per-flush heap allocation.
    let mut tls_buf = Vec::with_capacity(RELAY_BUF_SIZE + 256);

    // Send ServerHello etc. back to guest.
    flush_to_guest(&mut guest_tls, &to_smoltcp, &shared, &mut tls_buf).await?;

    // Complete guest-facing TLS handshake with timeout to prevent resource exhaustion.
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
            flush_to_guest(&mut guest_tls, &to_smoltcp, &shared, &mut tls_buf).await?;
        }
        Ok::<_, io::Error>(())
    })
    .await
    .map_err(|_| io::Error::new(io::ErrorKind::TimedOut, "TLS handshake timed out"))??;

    // Connect to real server with TLS.
    let server_stream = match upstream_stream {
        Some(s) => s,
        None => {
            connect_target
                .connect(
                    guest_dst,
                    Some(sni_name),
                    OutboundProtocol::Tls,
                    &extensions,
                    &proxy_connect,
                    &shared,
                )
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
    if forward_plaintext(
        &mut guest_tls,
        &mut server_tls,
        &mut secrets_handler,
        request_stream.as_deref_mut(),
        &shared,
        &mut plaintext_buf,
        &to_smoltcp,
        &mut tls_buf,
    )
    .await?
    {
        return Ok(());
    }

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
                    if forward_plaintext(
                        &mut guest_tls,
                        &mut server_tls,
                        &mut secrets_handler,
                        request_stream.as_deref_mut(),
                        &shared,
                        &mut plaintext_buf,
                        &to_smoltcp,
                        &mut tls_buf,
                    )
                    .await?
                    {
                        return Ok(());
                    }
                }
            }

            // Server → guest: read plaintext, encrypt, send via channel.
            result = server_tls.read(&mut server_buf) => {
                match result {
                    Ok(0) => break,
                    Ok(n) => {
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

/// Buffer channel data until a complete ClientHello with SNI is received.
///
/// `seed` carries bytes already read from the channel before this call
/// (e.g. bytes trailing a CONNECT request). Pass an empty `Vec` when no
/// bytes have been pre-consumed.
pub(crate) async fn extract_sni_from_channel(
    from_smoltcp: &mut mpsc::Receiver<Bytes>,
    seed: Vec<u8>,
) -> io::Result<(String, Vec<u8>)> {
    let mut initial_buf = seed;
    initial_buf.reserve(CLIENT_HELLO_BUF_SIZE.saturating_sub(initial_buf.len()));
    loop {
        if let Some(name) = sni::extract_sni(&initial_buf) {
            return Ok((name, initial_buf));
        }
        if initial_buf.len() >= CLIENT_HELLO_BUF_SIZE {
            return Err(io::Error::new(
                io::ErrorKind::InvalidData,
                "ClientHello too large or no SNI found",
            ));
        }
        let data = from_smoltcp
            .recv()
            .await
            .ok_or_else(|| io::Error::new(io::ErrorKind::UnexpectedEof, "channel closed"))?;
        initial_buf.extend_from_slice(&data);

        if let Some(name) = sni::extract_sni(&initial_buf) {
            return Ok((name, initial_buf));
        }
        if initial_buf.len() >= CLIENT_HELLO_BUF_SIZE {
            return Err(io::Error::new(
                io::ErrorKind::InvalidData,
                "ClientHello too large or no SNI found",
            ));
        }
    }
}

/// Read all available decrypted plaintext from the guest-facing TLS
/// connection and forward it to the upstream server, applying secret
/// substitution when configured.
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
) -> io::Result<bool> {
    let mut wrote_plaintext = false;

    loop {
        let n = match guest_tls.reader().read(buf) {
            Ok(0) => break,
            Ok(n) => n,
            Err(ref e) if e.kind() == io::ErrorKind::WouldBlock => break,
            Err(e) => return Err(e),
        };

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
                    if matches!(action, ViolationAction::BlockAndTerminate) {
                        shared.trigger_termination();
                    }
                    return Err(io::Error::new(
                        io::ErrorKind::PermissionDenied,
                        "secret violation: placeholder sent to disallowed host",
                    ));
                }
            }
            continue;
        }

        let substituted = match substitute_request_chunk(secrets_handler, &buf[..n]) {
            Ok(data) => data,
            Err(action) => {
                if matches!(action, ViolationAction::BlockAndTerminate) {
                    shared.trigger_termination();
                }
                return Err(io::Error::new(
                    io::ErrorKind::PermissionDenied,
                    "secret violation: placeholder sent to disallowed host",
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

    if wrote_plaintext {
        server_tls.flush().await?;
    }

    Ok(false)
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

fn substitute_request_chunk<'a>(
    secrets_handler: &mut SecretsHandler,
    chunk: &'a [u8],
) -> Result<Cow<'a, [u8]>, ViolationAction> {
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
mod tests {
    use std::collections::VecDeque;
    use std::io;
    use std::net::SocketAddr;
    use std::sync::atomic::{AtomicBool, AtomicUsize, Ordering};
    use std::sync::{Arc, Mutex};

    use futures::future::BoxFuture;
    use microsandbox_types::{InterceptCaConfig, TlsConfig};
    use rustls::pki_types::{CertificateDer, PrivateKeyDer, PrivatePkcs8KeyDer};
    use tokio::io::{AsyncReadExt, AsyncWriteExt};
    use tokio::net::TcpListener;
    use tokio::sync::oneshot;
    use tokio_rustls::TlsAcceptor;

    use crate::extensions::{
        AuthorizedRouteRequestExtension, AuthorizedTcpRoute, OutboundConnectionExtension,
    };
    use crate::secrets::config::{HostPattern, SecretEntry, SecretInjection, SecretsConfig};
    use crate::secrets::handle::SecretsHandle;
    use crate::tcp::connection::ProxyConnectStatus;
    use crate::tls::state::TlsState;

    use super::*;

    type RecordedRoute = (SocketAddr, Option<String>, OutboundProtocol);

    struct DirectRecordingConnector {
        routes: Mutex<Vec<RecordedRoute>>,
    }

    impl OutboundConnectionExtension for DirectRecordingConnector {
        fn connect<'a>(
            &'a self,
            route: AuthorizedTcpRoute,
        ) -> BoxFuture<'a, io::Result<TcpStream>> {
            self.routes.lock().unwrap().push((
                route.guest_destination(),
                route.server_name().map(ToOwned::to_owned),
                route.protocol(),
            ));
            Box::pin(route.connect_direct())
        }
    }

    struct CountingConnector {
        calls: std::sync::atomic::AtomicUsize,
    }

    impl OutboundConnectionExtension for CountingConnector {
        fn connect<'a>(
            &'a self,
            _route: AuthorizedTcpRoute,
        ) -> BoxFuture<'a, io::Result<TcpStream>> {
            self.calls
                .fetch_add(1, std::sync::atomic::Ordering::Relaxed);
            Box::pin(async { Err(io::Error::other("unexpected connection extension call")) })
        }
    }

    async fn spawn_sink() -> (SocketAddr, tokio::task::JoinHandle<Vec<u8>>) {
        let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let address = listener.local_addr().unwrap();
        let sink = tokio::spawn(async move {
            let (mut stream, _) = listener.accept().await.unwrap();
            let mut received = Vec::new();
            stream.read_to_end(&mut received).await.unwrap();
            received
        });
        (address, sink)
    }

    fn test_tls_state(secrets: SecretsConfig) -> Arc<TlsState> {
        let dir = tempfile::tempdir().unwrap();
        let ca = crate::tls::ca::CertAuthority::generate();
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
        Arc::new(TlsState::new(config, SecretsHandle::new(secrets)).unwrap())
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

    fn guest_client_hello(tls_state: &TlsState) -> Bytes {
        let mut client = guest_client(tls_state);
        let mut hello = Vec::new();
        client.write_tls(&mut hello).unwrap();
        Bytes::from(hello)
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

    async fn spawn_upstream_request_sink() -> (
        SocketAddr,
        oneshot::Receiver<Vec<u8>>,
        tokio::task::JoinHandle<io::Result<()>>,
    ) {
        let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let address = listener.local_addr().unwrap();
        let (request_tx, request_rx) = oneshot::channel();
        let server = tokio::spawn(async move {
            let (stream, _) = listener.accept().await?;
            let mut stream = TlsAcceptor::from(upstream_server_config())
                .accept(stream)
                .await?;
            let mut buf = [0; RELAY_BUF_SIZE];
            let request = match stream.read(&mut buf).await {
                Ok(read) => buf[..read].to_vec(),
                Err(error) if error.kind() == io::ErrorKind::UnexpectedEof => Vec::new(),
                Err(error) => return Err(error),
            };
            let _ = request_tx.send(request);
            match stream.shutdown().await {
                Ok(()) => Ok(()),
                // Fail-closed relay outcomes may drop the upstream socket before
                // the fixture can send its TLS close notification.
                Err(error) if error.kind() == io::ErrorKind::BrokenPipe => Ok(()),
                Err(error) => Err(error),
            }
        });
        (address, request_rx, server)
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
            let (stream, _) = listener.accept().await?;
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

    struct OrderedConnector {
        order: Arc<Mutex<Vec<&'static str>>>,
    }

    impl OutboundConnectionExtension for OrderedConnector {
        fn connect<'a>(
            &'a self,
            route: AuthorizedTcpRoute,
        ) -> BoxFuture<'a, io::Result<TcpStream>> {
            self.order.lock().unwrap().push("outbound connector");
            Box::pin(route.connect_direct())
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

    fn host_bound_secret_config() -> SecretsConfig {
        SecretsConfig {
            secrets: vec![SecretEntry {
                env_var: "API_KEY".into(),
                value: zeroize::Zeroizing::new("real-secret-value".into()),
                source: None,
                placeholder: "$MSB_KEY".into(),
                allowed_hosts: vec![HostPattern::Exact("example.com".into())],
                injection: SecretInjection {
                    headers: true,
                    basic_auth: false,
                    query_params: false,
                    body: false,
                },
                on_violation: None,
                require_tls_identity: true,
            }],
            ..Default::default()
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

    struct BlockingConnector {
        started: Mutex<Option<oneshot::Sender<()>>>,
        dropped: Arc<AtomicBool>,
    }

    impl OutboundConnectionExtension for BlockingConnector {
        fn connect<'a>(
            &'a self,
            _route: AuthorizedTcpRoute,
        ) -> BoxFuture<'a, io::Result<TcpStream>> {
            let started = self.started.lock().unwrap().take();
            let guard = DropGuard(self.dropped.clone());
            Box::pin(async move {
                let _guard = guard;
                if let Some(started) = started {
                    let _ = started.send(());
                }
                std::future::pending::<io::Result<TcpStream>>().await
            })
        }
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
    async fn denied_tls_route_does_not_open_request_extension() {
        let _ = rustls::crypto::ring::default_provider().install_default();
        let tls_state = test_tls_state(SecretsConfig::default());
        let request_extension = Arc::new(CountingRequestExtension(AtomicUsize::new(0)));
        let shared = Arc::new(SharedState::new(4));
        shared.proxy_wake.drain();
        let proxy_connect = Arc::new(ProxyConnectState::new());
        let (from_tx, from_rx) = mpsc::channel(1);
        let (to_tx, _to_rx) = mpsc::channel(1);
        from_tx.send(guest_client_hello(&tls_state)).await.unwrap();
        drop(from_tx);

        TlsProxy::new(
            "203.0.113.10:443".parse().unwrap(),
            UpstreamTcpTarget::direct("127.0.0.1:9".parse().unwrap()),
            from_rx,
            to_tx,
            shared.clone(),
            tls_state,
            Arc::new(NetworkPolicy::none()),
            proxy_connect.clone(),
            NetworkExtensions::new().with_authorized_requests(request_extension.clone()),
        )
        .try_run()
        .await
        .unwrap();

        assert_eq!(request_extension.0.load(Ordering::Relaxed), 0);
        assert_eq!(proxy_connect.status(), ProxyConnectStatus::PolicyDenied);
        assert!(shared.proxy_wake.wait_timeout(std::time::Duration::ZERO));
    }

    #[tokio::test]
    async fn connect_sni_mismatch_does_not_open_request_extension() {
        let _ = rustls::crypto::ring::default_provider().install_default();
        let tls_state = test_tls_state(SecretsConfig::default());
        let request_extension = Arc::new(CountingRequestExtension(AtomicUsize::new(0)));
        let shared = Arc::new(SharedState::new(4));
        shared.proxy_wake.drain();
        let proxy_connect = Arc::new(ProxyConnectState::new());
        let (from_tx, from_rx) = mpsc::channel(1);
        let (to_tx, _to_rx) = mpsc::channel(1);
        from_tx.send(guest_client_hello(&tls_state)).await.unwrap();
        drop(from_tx);

        TlsProxy::new(
            "203.0.113.10:443".parse().unwrap(),
            UpstreamTcpTarget::direct("127.0.0.1:9".parse().unwrap()),
            from_rx,
            to_tx,
            shared.clone(),
            tls_state,
            Arc::new(NetworkPolicy::allow_all()),
            proxy_connect.clone(),
            NetworkExtensions::new().with_authorized_requests(request_extension.clone()),
        )
        .with_connect_authority(Some("different.example".to_owned()))
        .try_run()
        .await
        .unwrap();

        assert_eq!(request_extension.0.load(Ordering::Relaxed), 0);
        assert_eq!(proxy_connect.status(), ProxyConnectStatus::PolicyDenied);
        assert!(shared.proxy_wake.wait_timeout(std::time::Duration::ZERO));
    }

    #[tokio::test]
    async fn tls_bypass_uses_authorized_route_context() {
        let (target, sink) = spawn_sink().await;
        let connector = Arc::new(DirectRecordingConnector {
            routes: Mutex::new(Vec::new()),
        });
        let (from_tx, from_rx) = mpsc::channel(2);
        let (to_tx, _to_rx) = mpsc::channel(2);
        from_tx
            .send(Bytes::from_static(b"guest bytes"))
            .await
            .unwrap();
        drop(from_tx);

        bypass_relay(
            "203.0.113.10:443".parse().unwrap(),
            UpstreamTcpTarget::direct(target),
            "example.com",
            b"client hello".to_vec(),
            from_rx,
            to_tx,
            Arc::new(SharedState::new(4)),
            Arc::new(ProxyConnectState::new()),
            NetworkExtensions::new().with_outbound(connector.clone()),
            None,
        )
        .await
        .unwrap();

        assert_eq!(sink.await.unwrap(), b"client helloguest bytes");
        assert_eq!(
            connector.routes.lock().unwrap().as_slice(),
            &[(
                "203.0.113.10:443".parse().unwrap(),
                Some("example.com".to_owned()),
                OutboundProtocol::Tls,
            )]
        );
    }

    #[tokio::test]
    async fn preconnected_tls_bypass_skips_extension_and_propagates_guest_fin() {
        let (target, sink) = spawn_sink().await;
        let preconnected = TcpStream::connect(target).await.unwrap();
        let connector = Arc::new(CountingConnector {
            calls: std::sync::atomic::AtomicUsize::new(0),
        });
        let (from_tx, from_rx) = mpsc::channel(1);
        let (to_tx, _to_rx) = mpsc::channel(1);
        drop(from_tx);

        bypass_relay(
            target,
            UpstreamTcpTarget::direct(target),
            "example.com",
            b"client hello".to_vec(),
            from_rx,
            to_tx,
            Arc::new(SharedState::new(4)),
            Arc::new(ProxyConnectState::new()),
            NetworkExtensions::new().with_outbound(connector.clone()),
            Some(preconnected),
        )
        .await
        .unwrap();

        assert_eq!(sink.await.unwrap(), b"client hello");
        assert_eq!(
            connector.calls.load(std::sync::atomic::Ordering::Relaxed),
            0
        );
    }

    #[tokio::test]
    async fn intercept_relay_drops_held_request_state_when_guest_fin_arrives() {
        let _ = rustls::crypto::ring::default_provider().install_default();
        let tls_state = test_tls_state(SecretsConfig::default());
        let (upstream, upstream_eof, release_upstream, server) =
            spawn_upstream_after_eof(b"server response").await;
        let preconnected = TcpStream::connect(upstream).await.unwrap();
        let connector = Arc::new(CountingConnector {
            calls: std::sync::atomic::AtomicUsize::new(0),
        });
        let (from_tx, from_rx) = mpsc::channel(4);
        let (to_tx, mut to_rx) = mpsc::channel(4);
        let mut client = guest_client(&tls_state);
        send_client_tls_output(&mut client, &from_tx).await;

        let (processed_tx, processed_rx) = oneshot::channel();
        let dropped = Arc::new(AtomicBool::new(false));
        let request_extension = Arc::new(Mutex::new(HoldingRequestExtension {
            processed: Some(processed_tx),
            dropped: dropped.clone(),
        }));
        let mut relay = tokio::spawn(intercept_relay(
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
            NetworkExtensions::new()
                .with_outbound(connector.clone())
                .with_authorized_requests(request_extension),
            Some(preconnected),
        ));

        complete_relay_handshake(&mut client, &from_tx, &mut to_rx).await;
        client
            .writer()
            .write_all(b"GET / HTTP/1.1\r\nHost: example.com\r\n\r\n")
            .unwrap();
        assert!(
            client.wants_write(),
            "guest plaintext did not produce TLS output"
        );
        send_client_tls_output(&mut client, &from_tx).await;
        tokio::select! {
            processed = processed_rx => processed.unwrap(),
            result = &mut relay => panic!("relay ended before request dispatch: {result:?}"),
            _ = tokio::time::sleep(std::time::Duration::from_secs(2)) => {
                panic!("request adapter did not process guest plaintext")
            }
        }

        // FIN must discard adapter-owned held state before the server-to-guest
        // relay finishes. The upstream waits here to make that distinction observable.
        drop(from_tx);
        assert_eq!(
            tokio::time::timeout(std::time::Duration::from_secs(2), upstream_eof)
                .await
                .expect("upstream did not observe guest FIN")
                .unwrap(),
            b""
        );
        assert!(
            dropped.load(Ordering::Acquire),
            "guest FIN must drop held request state before server relay completes"
        );
        assert_eq!(connector.calls.load(Ordering::Relaxed), 0);

        release_upstream.send(()).unwrap();
        let mut response = Vec::new();
        for _ in 0..4 {
            let encrypted = tokio::time::timeout(std::time::Duration::from_secs(1), to_rx.recv())
                .await
                .expect("server response timed out")
                .expect("relay closed before server response");
            let mut input = encrypted.as_ref();
            client.read_tls(&mut input).unwrap();
            client.process_new_packets().unwrap();
            loop {
                let mut buf = [0; RELAY_BUF_SIZE];
                match client.reader().read(&mut buf) {
                    Ok(0) => break,
                    Ok(n) => response.extend_from_slice(&buf[..n]),
                    Err(ref error) if error.kind() == io::ErrorKind::WouldBlock => break,
                    Err(error) => panic!("failed to decrypt server response: {error}"),
                }
            }
            if response == b"server response" {
                break;
            }
        }
        assert_eq!(response, b"server response");

        relay.await.unwrap().unwrap();
        server.await.unwrap().unwrap();
    }

    #[tokio::test]
    async fn intercept_relay_orders_route_factory_secret_substitution_and_upstream_flush() {
        let _ = rustls::crypto::ring::default_provider().install_default();
        let tls_state = test_tls_state(host_bound_secret_config());
        let (upstream, upstream_request, server) = spawn_upstream_request_sink().await;
        let guest_destination: SocketAddr = "203.0.113.10:443".parse().unwrap();
        let connector = Arc::new(DirectRecordingConnector {
            routes: Mutex::new(Vec::new()),
        });
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
            NetworkExtensions::new()
                .with_outbound(connector.clone())
                .with_authorized_requests(requests.clone()),
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
        assert_eq!(
            connector.routes.lock().unwrap().as_slice(),
            &[(
                guest_destination,
                Some("example.com".to_owned()),
                OutboundProtocol::Tls,
            )]
        );

        drop(from_tx);
        relay.await.unwrap().unwrap();
        server.await.unwrap().unwrap();
    }

    #[tokio::test]
    async fn intercept_relay_sends_synthetic_response_and_terminates_without_upstream_request() {
        let _ = rustls::crypto::ring::default_provider().install_default();
        let tls_state = test_tls_state(SecretsConfig::default());
        let (upstream, upstream_request, server) = spawn_upstream_request_sink().await;
        let (from_tx, from_rx) = mpsc::channel(4);
        let (to_tx, mut to_rx) = mpsc::channel(4);
        let mut client = guest_client(&tls_state);
        send_client_tls_output(&mut client, &from_tx).await;
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
            NetworkExtensions::new().with_authorized_requests(Arc::new(ScriptedRequestExtension {
                actions: Mutex::new(Some(VecDeque::from([RequestAction::RespondAndClose(
                    b"synthetic response".to_vec(),
                )]))),
            })),
            None,
        ));

        complete_relay_handshake(&mut client, &from_tx, &mut to_rx).await;
        client
            .writer()
            .write_all(b"GET / HTTP/1.1\r\nHost: example.com\r\n\r\n")
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
                Err(error) => panic!("failed to decrypt synthetic response: {error}"),
            }
            if response == b"synthetic response" {
                break;
            }
        }
        assert_eq!(response, b"synthetic response");
        relay.await.unwrap().unwrap();
        assert_eq!(upstream_request.await.unwrap(), b"");
        server.await.unwrap().unwrap();
    }

    #[tokio::test]
    async fn intercept_relay_opens_request_factory_before_connecting_upstream() {
        let _ = rustls::crypto::ring::default_provider().install_default();
        let tls_state = test_tls_state(SecretsConfig::default());
        let (upstream, _request, server) = spawn_upstream_request_sink().await;
        let order = Arc::new(Mutex::new(Vec::new()));
        let (from_tx, from_rx) = mpsc::channel(4);
        let (to_tx, mut to_rx) = mpsc::channel(4);
        let mut client = guest_client(&tls_state);
        send_client_tls_output(&mut client, &from_tx).await;
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
            NetworkExtensions::new()
                .with_outbound(Arc::new(OrderedConnector {
                    order: order.clone(),
                }))
                .with_authorized_requests(Arc::new(OrderedRequestExtension {
                    order: order.clone(),
                })),
            None,
        ));

        complete_relay_handshake(&mut client, &from_tx, &mut to_rx).await;
        tokio::time::timeout(std::time::Duration::from_secs(1), async {
            loop {
                if order.lock().unwrap().len() == 2 {
                    return;
                }
                tokio::task::yield_now().await;
            }
        })
        .await
        .expect("factory and connector did not both run");
        assert_eq!(
            order.lock().unwrap().as_slice(),
            &["request factory", "outbound connector"]
        );
        relay.abort();
        server.abort();
    }

    #[tokio::test]
    async fn intercept_relay_rejects_secret_violations_before_request_dispatch() {
        let _ = rustls::crypto::ring::default_provider().install_default();
        let mut secrets = host_bound_secret_config();
        secrets.secrets[0].allowed_hosts = vec![HostPattern::Exact("denied.example".into())];
        let tls_state = test_tls_state(secrets);
        let (upstream, upstream_request, server) = spawn_upstream_request_sink().await;
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
            "203.0.113.10:443".parse().unwrap(),
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
            NetworkExtensions::new().with_authorized_requests(requests),
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

        let error = relay.await.unwrap().unwrap_err();
        assert_eq!(error.kind(), io::ErrorKind::PermissionDenied);
        assert!(seen.lock().unwrap().is_empty());
        assert_eq!(upstream_request.await.unwrap(), b"");
        server.await.unwrap().unwrap();
    }

    #[tokio::test]
    async fn intercept_relay_preserves_backpressure_and_drops_pending_request_work_on_abort() {
        let _ = rustls::crypto::ring::default_provider().install_default();
        let tls_state = test_tls_state(SecretsConfig::default());
        let (upstream, _request, server) = spawn_upstream_request_sink().await;
        let (started_tx, started_rx) = oneshot::channel();
        let dropped = Arc::new(AtomicBool::new(false));
        let requests = Arc::new(Mutex::new(BlockingRequestExtension {
            started: Some(started_tx),
            dropped: dropped.clone(),
        }));
        let (from_tx, from_rx) = mpsc::channel(1);
        let (to_tx, mut to_rx) = mpsc::channel(4);
        let mut client = guest_client(&tls_state);
        send_client_tls_output(&mut client, &from_tx).await;
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
            NetworkExtensions::new().with_authorized_requests(requests),
            None,
        ));

        complete_relay_handshake(&mut client, &from_tx, &mut to_rx).await;
        client
            .writer()
            .write_all(b"GET / HTTP/1.1\r\nHost: example.com\r\n\r\n")
            .unwrap();
        send_client_tls_output(&mut client, &from_tx).await;
        started_rx.await.unwrap();

        from_tx.send(Bytes::from_static(b"queued")).await.unwrap();
        assert!(
            tokio::time::timeout(
                std::time::Duration::from_millis(50),
                from_tx.send(Bytes::from_static(b"must remain backpressured")),
            )
            .await
            .is_err(),
            "a pending request future must leave the bounded receive channel full"
        );

        relay.abort();
        let _ = relay.await;
        assert!(dropped.load(Ordering::Acquire));
        server.abort();
    }

    #[tokio::test]
    async fn intercept_relay_drops_pending_outbound_connector_on_abort() {
        let _ = rustls::crypto::ring::default_provider().install_default();
        let tls_state = test_tls_state(SecretsConfig::default());
        let (started_tx, started_rx) = oneshot::channel();
        let dropped = Arc::new(AtomicBool::new(false));
        let connector = Arc::new(BlockingConnector {
            started: Mutex::new(Some(started_tx)),
            dropped: dropped.clone(),
        });
        let (from_tx, from_rx) = mpsc::channel(4);
        let (to_tx, mut to_rx) = mpsc::channel(4);
        let mut client = guest_client(&tls_state);
        send_client_tls_output(&mut client, &from_tx).await;
        let relay = tokio::spawn(intercept_relay(
            "203.0.113.10:443".parse().unwrap(),
            UpstreamTcpTarget::direct("127.0.0.1:9".parse().unwrap()),
            "example.com",
            false,
            false,
            Vec::new(),
            from_rx,
            to_tx,
            Arc::new(SharedState::new(4)),
            tls_state,
            Arc::new(ProxyConnectState::new()),
            NetworkExtensions::new().with_outbound(connector),
            None,
        ));

        complete_relay_handshake(&mut client, &from_tx, &mut to_rx).await;
        tokio::time::timeout(std::time::Duration::from_secs(1), started_rx)
            .await
            .expect("outbound connector did not start")
            .unwrap();
        relay.abort();
        let _ = relay.await;
        assert!(dropped.load(Ordering::Acquire));
    }

    fn complete_guest_tls_handshake(
        client: &mut rustls::ClientConnection,
        server: &mut rustls::ServerConnection,
    ) {
        while client.is_handshaking() || server.is_handshaking() {
            if client.wants_write() {
                let mut encrypted = Vec::new();
                client.write_tls(&mut encrypted).unwrap();
                let mut input = encrypted.as_slice();
                server.read_tls(&mut input).unwrap();
                server.process_new_packets().unwrap();
            }
            if server.wants_write() {
                let mut encrypted = Vec::new();
                server.write_tls(&mut encrypted).unwrap();
                let mut input = encrypted.as_slice();
                client.read_tls(&mut input).unwrap();
                client.process_new_packets().unwrap();
            }
        }
    }

    #[tokio::test]
    async fn synthetic_response_is_encrypted_for_the_guest_and_wakes_polling() {
        let _ = rustls::crypto::ring::default_provider().install_default();
        let ca = crate::tls::ca::CertAuthority::generate();
        let domain = crate::tls::certgen::generate_domain_cert("example.com", &ca, 24).unwrap();
        let mut roots = rustls::RootCertStore::empty();
        roots.add(ca.cert_der.clone()).unwrap();
        let client_config = rustls::ClientConfig::builder()
            .with_root_certificates(roots)
            .with_no_client_auth();
        let mut client = rustls::ClientConnection::new(
            Arc::new(client_config),
            ServerName::try_from("example.com".to_owned()).unwrap(),
        )
        .unwrap();
        let mut guest_tls = rustls::ServerConnection::new(domain.server_config).unwrap();
        complete_guest_tls_handshake(&mut client, &mut guest_tls);

        let shared = SharedState::new(4);
        shared.proxy_wake.drain();
        let (to_smoltcp, mut guest_rx) = mpsc::channel(1);
        send_synthetic_response(
            &mut guest_tls,
            b"synthetic response",
            &to_smoltcp,
            &shared,
            &mut Vec::new(),
        )
        .await
        .unwrap();

        let encrypted = guest_rx.recv().await.unwrap();
        let mut input = encrypted.as_ref();
        client.read_tls(&mut input).unwrap();
        client.process_new_packets().unwrap();
        let mut response = [0; b"synthetic response".len()];
        let read = client.reader().read(&mut response).unwrap();
        assert_eq!(&response[..read], b"synthetic response");
        assert!(shared.proxy_wake.wait_timeout(std::time::Duration::ZERO));
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

    #[test]
    fn buffered_secret_substitution_does_not_produce_a_request_chunk() {
        let mut handler = SecretsHandler::new_tls_intercepted_via_connect(
            &host_bound_secret_config(),
            "example.com",
        );

        assert!(
            substitute_request_chunk(&mut handler, b"GET / HTTP/1.1\r\nHost: example.")
                .unwrap()
                .is_empty()
        );
        assert!(
            !substitute_request_chunk(&mut handler, b"com\r\n\r\n")
                .unwrap()
                .is_empty()
        );
    }

    #[tokio::test]
    async fn pending_request_processing_preserves_channel_backpressure() {
        let (from_tx, mut from_rx) = mpsc::channel::<Bytes>(1);
        let (started_tx, started_rx) = tokio::sync::oneshot::channel();
        let (release_tx, release_rx) = tokio::sync::oneshot::channel();
        let mut stream = GatedRequestStream {
            started: Some(started_tx),
            release: Some(release_rx),
        };
        from_tx.send(Bytes::from_static(b"first")).await.unwrap();

        let worker = tokio::spawn(async move {
            let chunk = from_rx.recv().await.unwrap();
            let (mut upstream, _observed) = tokio::io::duplex(64);
            dispatch_request_action(&mut stream, &chunk, &mut upstream).await
        });
        started_rx.await.unwrap();

        from_tx.send(Bytes::from_static(b"second")).await.unwrap();
        assert!(
            tokio::time::timeout(
                std::time::Duration::from_millis(50),
                from_tx.send(Bytes::from_static(b"third")),
            )
            .await
            .is_err(),
            "the bounded receive channel must apply pressure while dispatch is pending"
        );

        release_tx.send(()).unwrap();
        assert!(matches!(
            worker.await.unwrap().unwrap(),
            RequestDispatch::Continue { wrote: true }
        ));
    }

    #[tokio::test]
    async fn aborting_request_dispatch_drops_its_in_flight_future() {
        let (started_tx, started_rx) = tokio::sync::oneshot::channel();
        let dropped = Arc::new(std::sync::atomic::AtomicBool::new(false));
        let mut stream = BlockingRequestStream {
            started: Some(started_tx),
            dropped: dropped.clone(),
        };
        let (mut upstream, _observed) = tokio::io::duplex(64);

        let task = tokio::spawn(async move {
            dispatch_request_action(&mut stream, b"request", &mut upstream).await
        });
        started_rx.await.unwrap();
        task.abort();
        let _ = task.await;

        assert!(dropped.load(std::sync::atomic::Ordering::Acquire));
    }

    #[tokio::test]
    async fn request_actions_hold_and_release_owned_bytes_in_order() {
        let (mut upstream, mut observed) = tokio::io::duplex(64);
        let mut stream = ScriptedRequestStream {
            actions: VecDeque::from([
                RequestAction::Hold,
                RequestAction::Hold,
                RequestAction::ForwardOwned(b"abc".to_vec()),
                RequestAction::ForwardCurrent,
            ]),
        };

        assert!(matches!(
            dispatch_request_action(&mut stream, b"a", &mut upstream)
                .await
                .unwrap(),
            RequestDispatch::Continue { wrote: false }
        ));
        assert!(matches!(
            dispatch_request_action(&mut stream, b"b", &mut upstream)
                .await
                .unwrap(),
            RequestDispatch::Continue { wrote: false }
        ));
        assert!(matches!(
            dispatch_request_action(&mut stream, b"c", &mut upstream)
                .await
                .unwrap(),
            RequestDispatch::Continue { wrote: true }
        ));
        assert!(matches!(
            dispatch_request_action(&mut stream, b"d", &mut upstream)
                .await
                .unwrap(),
            RequestDispatch::Continue { wrote: true }
        ));

        let mut bytes = [0; 4];
        observed.read_exact(&mut bytes).await.unwrap();
        assert_eq!(&bytes, b"abcd");
    }

    #[tokio::test]
    async fn request_response_action_never_writes_current_bytes_upstream() {
        let (mut upstream, mut observed) = tokio::io::duplex(64);
        let mut stream = ScriptedRequestStream {
            actions: VecDeque::from([RequestAction::RespondAndClose(b"response".to_vec())]),
        };

        let action = dispatch_request_action(&mut stream, b"secret", &mut upstream)
            .await
            .unwrap();

        assert!(
            matches!(action, RequestDispatch::RespondAndClose(response) if response == b"response")
        );
        let mut bytes = [0; 1];
        assert!(
            tokio::time::timeout(
                std::time::Duration::from_millis(50),
                observed.read(&mut bytes)
            )
            .await
            .is_err()
        );
    }
}
