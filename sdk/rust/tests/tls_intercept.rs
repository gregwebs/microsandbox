//! Integration tests for TLS interception.

use std::io;
use std::net::{Ipv4Addr, Ipv6Addr, SocketAddr};
use std::sync::Arc;
use std::time::Duration;

use microsandbox::sandbox::SecretSource;
use microsandbox::{NetworkPolicy, Sandbox};
use microsandbox_network::config::InterfaceOverrides;
use rcgen::CertificateParams;
use rustls::pki_types::{CertificateDer, PrivateKeyDer, PrivatePkcs8KeyDer};
use test_utils::msb_test;
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::{TcpListener, TcpStream, UdpSocket};
use tokio::task::JoinHandle;
use tokio_rustls::TlsAcceptor;

//--------------------------------------------------------------------------------------------------
// Constants
//--------------------------------------------------------------------------------------------------

const LARGE_POST_BODY_LEN: usize = 135_000; // 135 kb, above the old ~128 kib failure threshold.
const LARGE_SECRET_PAD_LEN: usize = 1024 * 1024; // 1 MiB on each side of the placeholder.
const CURL_IMAGE: &str = "mirror.gcr.io/curlimages/curl";
const REAL_SECRET: &[u8] = b"real-secret";
const IPV6_GUEST: &str = "fd42:6d73:62:ffff::2";
const IPV6_GATEWAY: &str = "fd42:6d73:62:ffff::1";

//--------------------------------------------------------------------------------------------------
// Types
//--------------------------------------------------------------------------------------------------

/// Minimal HTTPS server bound to `127.0.0.1` and `::1` on the same port.
struct HostHttps {
    port: u16,
    handle: Option<JoinHandle<io::Result<ReceivedRequest>>>,
}

/// Local DNS fixture supplies real cache evidence for the policy matrix.
struct HostDns {
    address: SocketAddr,
    task: Option<JoinHandle<io::Result<()>>>,
}

struct ReceivedRequest {
    peer: SocketAddr,
    headers: Vec<u8>,
    body: Vec<u8>,
}

//--------------------------------------------------------------------------------------------------
// Methods
//--------------------------------------------------------------------------------------------------

impl HostDns {
    async fn start() -> Self {
        let socket = UdpSocket::bind("127.0.0.1:0").await.unwrap();
        let address = socket.local_addr().unwrap();
        let task = tokio::spawn(async move {
            let mut buf = [0; 512];
            loop {
                let (length, peer) = socket.recv_from(&mut buf).await?;
                let query = &buf[..length];
                if query.len() < 12 || query[4..6] != [0, 1] {
                    continue;
                }
                let mut end = 12;
                loop {
                    match query.get(end).copied() {
                        Some(0) => {
                            end += 1;
                            break;
                        }
                        Some(length @ 1..=63) if end + 1 + length as usize <= query.len() => {
                            end += 1 + length as usize;
                        }
                        _ => {
                            end = query.len();
                            break;
                        }
                    }
                }
                let Some(question_type) = query.get(end..end + 4) else {
                    continue;
                };
                end += 4;
                let address = match question_type {
                    [0, 1, 0, 1] => vec![172, 30, 255, 1],
                    [0, 28, 0, 1] => IPV6_GATEWAY.parse::<Ipv6Addr>().unwrap().octets().to_vec(),
                    _ => Vec::new(),
                };
                let answer = !address.is_empty();
                let mut reply = vec![
                    query[0],
                    query[1],
                    0x81,
                    0x80,
                    0,
                    1,
                    0,
                    u8::from(answer),
                    0,
                    0,
                    0,
                    0,
                ];
                reply.extend_from_slice(&query[12..end]);
                if answer {
                    reply.extend_from_slice(&[0xc0, 0x0c]);
                    reply.extend_from_slice(question_type);
                    reply.extend_from_slice(&[0, 0, 0, 60]);
                    reply.extend_from_slice(&(address.len() as u16).to_be_bytes());
                    reply.extend_from_slice(&address);
                }
                socket.send_to(&reply, peer).await?;
            }
        });
        Self {
            address,
            task: Some(task),
        }
    }

    async fn assert_running(&mut self) {
        if self.task.as_ref().unwrap().is_finished() {
            self.task
                .take()
                .unwrap()
                .await
                .expect("DNS fixture task panicked")
                .expect("DNS fixture I/O failed");
            panic!("DNS fixture stopped unexpectedly");
        }
    }
}

impl HostHttps {
    async fn start() -> io::Result<Self> {
        Self::start_with_config(async { test_server_config() }).await
    }

    async fn start_with_config(
        config: impl std::future::Future<Output = Arc<rustls::ServerConfig>> + Send + 'static,
    ) -> io::Result<Self> {
        let _ = rustls::crypto::ring::default_provider().install_default();

        let v4_listener = TcpListener::bind(SocketAddr::from((Ipv4Addr::LOCALHOST, 0))).await?;
        let port = v4_listener.local_addr()?.port();
        let v6_listener = TcpListener::bind(SocketAddr::from((Ipv6Addr::LOCALHOST, port))).await?;

        let handle = tokio::spawn(async move {
            let acceptor = TlsAcceptor::from(config.await);
            let (stream, _) = tokio::select! {
                accept = v4_listener.accept() => accept?,
                accept = v6_listener.accept() => accept?,
            };
            let tls = acceptor.accept(stream).await?;
            handle_https_request(tls).await
        });

        Ok(Self {
            port,
            handle: Some(handle),
        })
    }

    fn port(&self) -> u16 {
        self.port
    }

    async fn received_request(&mut self) -> io::Result<ReceivedRequest> {
        // Keep ownership while awaiting so cancellation still lets Drop abort.
        let result = self
            .handle
            .as_mut()
            .expect("https fixture already consumed")
            .await
            .map_err(io::Error::other)?;
        self.handle.take();
        result
    }

    async fn received_body(&mut self) -> io::Result<Vec<u8>> {
        self.received_request().await.map(|request| request.body)
    }
}

impl Drop for HostDns {
    fn drop(&mut self) {
        if let Some(task) = self.task.take() {
            task.abort();
        }
    }
}

impl Drop for HostHttps {
    fn drop(&mut self) {
        if let Some(handle) = self.handle.take() {
            handle.abort();
        }
    }
}

/// HTTPS fixture that accepts and records several *sequential* connections on
/// the same port, so a test can assert on request N+1 after mutating host
/// state (e.g. rotating a file-backed secret) between requests N and N+1.
struct HostHttpsSequence {
    port: u16,
    bodies: tokio::sync::mpsc::Receiver<io::Result<Vec<u8>>>,
    handle: Option<JoinHandle<()>>,
}

impl HostHttpsSequence {
    /// Bind once and accept up to `count` connections in order.
    async fn start(count: usize) -> io::Result<Self> {
        let _ = rustls::crypto::ring::default_provider().install_default();

        let v4_listener = TcpListener::bind(SocketAddr::from((Ipv4Addr::LOCALHOST, 0))).await?;
        let port = v4_listener.local_addr()?.port();
        let v6_listener = TcpListener::bind(SocketAddr::from((Ipv6Addr::LOCALHOST, port))).await?;
        let acceptor = TlsAcceptor::from(test_server_config());
        let (tx, rx) = tokio::sync::mpsc::channel(count.max(1));

        let handle = tokio::spawn(async move {
            for _ in 0..count {
                let accepted = tokio::select! {
                    accept = v4_listener.accept() => accept,
                    accept = v6_listener.accept() => accept,
                };
                let result = async {
                    let (stream, _) = accepted?;
                    let tls = acceptor.accept(stream).await?;
                    handle_https_request(tls).await.map(|req| req.body)
                }
                .await;
                if tx.send(result).await.is_err() {
                    return;
                }
            }
        });

        Ok(Self {
            port,
            bodies: rx,
            handle: Some(handle),
        })
    }

    fn port(&self) -> u16 {
        self.port
    }

    /// Wait for the next connection's body, in accept order.
    async fn next_body(&mut self) -> io::Result<Vec<u8>> {
        self.bodies
            .recv()
            .await
            .ok_or_else(|| io::Error::other("sequence fixture closed with no more connections"))?
    }
}

impl Drop for HostHttpsSequence {
    fn drop(&mut self) {
        if let Some(handle) = self.handle.take() {
            handle.abort();
        }
    }
}

//--------------------------------------------------------------------------------------------------
// Functions
//--------------------------------------------------------------------------------------------------

/// Boot a curl sandbox with TLS interception enabled on the fixture port.
async fn spawn_curl_sandbox(name: &str, port: u16) -> Sandbox {
    Sandbox::builder(name)
        .image(CURL_IMAGE)
        .cpus(1)
        .memory(256)
        .user("0")
        .replace()
        .network(|n| {
            n.policy(NetworkPolicy::allow_all())
                .tls(|t| t.intercepted_ports(vec![port]).verify_upstream(false))
        })
        .create()
        .await
        .expect("create sandbox")
}

/// Boot a curl sandbox with one body-injected secret and TLS interception on the fixture port.
async fn spawn_secret_curl_sandbox(
    name: &str,
    port: u16,
    allowed_host: &str,
    deny_response: bool,
) -> Sandbox {
    let allowed_host = allowed_host.to_string();
    Sandbox::builder(name)
        .image(CURL_IMAGE)
        .cpus(1)
        .memory(256)
        .user("0")
        .replace()
        .secret(|s| {
            s.env("API_KEY")
                .value("real-secret")
                .allow(allowed_host)
                .substitute_in_body(true)
        })
        .network(|n| {
            n.policy(NetworkPolicy::allow_all())
                .http(|h| {
                    let h = if deny_response {
                        h
                    } else {
                        h.deny_response(false)
                    };
                    h.network_deny_message("network-only")
                        .secret_deny_message("Check secret access for {host}.")
                })
                .tls(|t| t.intercepted_ports(vec![port]).verify_upstream(false))
        })
        .create()
        .await
        .expect("create sandbox")
}

/// Boot a curl sandbox with one body-injected secret, TLS interception, and
/// fail-closed request interception on the fixture port: only `POST
/// /allowed` on the fixture host is policed by `hook_argv`. `POST`, not
/// `GET`, because every caller uploads a body via `curl --data-binary`,
/// which curl sends as a `POST` unless overridden.
async fn spawn_intercept_curl_sandbox(
    name: &str,
    port: u16,
    allowed_host: &str,
    hook_argv: Vec<String>,
) -> Sandbox {
    let allowed_host = allowed_host.to_string();
    Sandbox::builder(name)
        .image(CURL_IMAGE)
        .cpus(1)
        .memory(256)
        .user("0")
        .replace()
        .secret(|s| {
            s.env("API_KEY")
                .value("real-secret")
                .allow(allowed_host)
                .substitute_in_body(true)
        })
        .network(|n| {
            n.policy(NetworkPolicy::allow_all())
                .tls(|t| t.intercepted_ports(vec![port]).verify_upstream(false))
                .intercept(|i| {
                    i.hook(hook_argv)
                        .rule("host.microsandbox.internal", "POST", "/allowed")
                })
        })
        .create()
        .await
        .expect("create sandbox")
}

/// Boot a curl sandbox with `dispatch_on_headers` request interception on
/// the fixture port: the hook fires as soon as headers are buffered, and
/// the body then streams to upstream unbuffered — used to prove a body far
/// larger than `max_request_bytes` still reaches upstream (AC #1).
async fn spawn_streaming_intercept_curl_sandbox(name: &str, port: u16) -> Sandbox {
    Sandbox::builder(name)
        .image(CURL_IMAGE)
        .cpus(1)
        .memory(256)
        .user("0")
        .replace()
        .network(|n| {
            n.policy(NetworkPolicy::allow_all())
                .tls(|t| t.intercepted_ports(vec![port]).verify_upstream(false))
                .intercept(|i| {
                    i.hook(vec!["/bin/cat".to_string()])
                        .max_request_bytes(4096)
                        .streaming_rule("host.microsandbox.internal", "POST", "/upload")
                })
        })
        .create()
        .await
        .expect("create sandbox")
}

/// Boot a curl sandbox with one file-backed, body-injected secret and TLS
/// interception on the fixture port. `secret_path` is re-read by the network
/// engine on every eligible connection, so rotating the file on the host
/// takes effect on the sandbox's next request without a restart.
async fn spawn_file_secret_curl_sandbox(
    name: &str,
    port: u16,
    allowed_host: &str,
    secret_path: &std::path::Path,
) -> Sandbox {
    let allowed_host = allowed_host.to_string();
    let secret_path = secret_path.to_path_buf();
    Sandbox::builder(name)
        .image(CURL_IMAGE)
        .cpus(1)
        .memory(256)
        .user("0")
        .replace()
        .secret(|s| {
            s.env("API_KEY")
                .source(SecretSource::File { path: secret_path })
                .allow(allowed_host)
                .substitute_in_body(true)
        })
        .network(|n| {
            n.policy(NetworkPolicy::allow_all())
                .tls(|t| t.intercepted_ports(vec![port]).verify_upstream(false))
        })
        .create()
        .await
        .expect("create sandbox")
}

/// Stop the sandbox and remove it.
async fn teardown(sb: Sandbox, name: &str) {
    drop(sb);
    let handle = Sandbox::get(name).await.expect("get");
    handle.stop().await.expect("stop");
    let _ = Sandbox::remove(name).await;
}

async fn handle_https_request(
    mut stream: tokio_rustls::server::TlsStream<TcpStream>,
) -> io::Result<ReceivedRequest> {
    let peer = stream.get_ref().0.peer_addr()?;
    let mut request = Vec::new();
    let header_end = loop {
        let mut buf = [0; 8192];
        let n = stream.read(&mut buf).await?;
        if n == 0 {
            return Err(io::Error::new(
                io::ErrorKind::UnexpectedEof,
                "connection closed before headers",
            ));
        }
        request.extend_from_slice(&buf[..n]);
        if let Some(pos) = find_header_end(&request) {
            break pos;
        }
    };

    let body_start = header_end + 4;
    let headers = request[..header_end].to_vec();
    let body = if is_transfer_chunked(&headers)? {
        read_chunked_body(&mut stream, request[body_start..].to_vec()).await?
    } else {
        let content_length = parse_content_length(&headers)?;
        read_content_length_body(&mut stream, request[body_start..].to_vec(), content_length)
            .await?
    };

    stream
        .write_all(b"HTTP/1.1 200 OK\r\nContent-Length: 2\r\nConnection: close\r\n\r\nok")
        .await?;
    stream.shutdown().await?;

    Ok(ReceivedRequest {
        peer,
        headers,
        body,
    })
}

fn find_header_end(buf: &[u8]) -> Option<usize> {
    buf.windows(4).position(|window| window == b"\r\n\r\n")
}

fn parse_content_length(headers: &[u8]) -> io::Result<usize> {
    let headers =
        std::str::from_utf8(headers).map_err(|e| io::Error::new(io::ErrorKind::InvalidData, e))?;
    headers
        .lines()
        .find_map(|line| {
            let (name, value) = line.split_once(':')?;
            name.eq_ignore_ascii_case("content-length")
                .then(|| value.trim().parse::<usize>())
        })
        .transpose()
        .map_err(|e| io::Error::new(io::ErrorKind::InvalidData, e))?
        .ok_or_else(|| io::Error::new(io::ErrorKind::InvalidData, "missing content-length"))
}

fn is_transfer_chunked(headers: &[u8]) -> io::Result<bool> {
    let headers =
        std::str::from_utf8(headers).map_err(|e| io::Error::new(io::ErrorKind::InvalidData, e))?;
    Ok(headers.lines().any(|line| {
        let Some((name, value)) = line.split_once(':') else {
            return false;
        };
        name.eq_ignore_ascii_case("transfer-encoding")
            && value
                .split(',')
                .next_back()
                .is_some_and(|encoding| encoding.trim().eq_ignore_ascii_case("chunked"))
    }))
}

async fn read_content_length_body(
    stream: &mut tokio_rustls::server::TlsStream<TcpStream>,
    mut body: Vec<u8>,
    content_length: usize,
) -> io::Result<Vec<u8>> {
    while body.len() < content_length {
        read_more(stream, &mut body, "connection closed before body").await?;
    }
    body.truncate(content_length);
    Ok(body)
}

async fn read_chunked_body(
    stream: &mut tokio_rustls::server::TlsStream<TcpStream>,
    mut raw: Vec<u8>,
) -> io::Result<Vec<u8>> {
    let mut cursor = 0;
    let mut decoded = Vec::new();

    loop {
        let line_end = read_until_crlf(stream, &mut raw, cursor, "chunk size line").await?;
        let size = parse_chunk_size(&raw[cursor..line_end])?;
        cursor = line_end + 2;

        if size == 0 {
            loop {
                let trailer_end =
                    read_until_crlf(stream, &mut raw, cursor, "chunk trailer").await?;
                let empty = trailer_end == cursor;
                cursor = trailer_end + 2;
                if empty {
                    return Ok(decoded);
                }
            }
        }

        while raw.len() < cursor + size + 2 {
            read_more(stream, &mut raw, "connection closed before chunk data").await?;
        }
        decoded.extend_from_slice(&raw[cursor..cursor + size]);
        cursor += size;
        if raw.get(cursor..cursor + 2) != Some(b"\r\n") {
            return Err(io::Error::new(
                io::ErrorKind::InvalidData,
                "chunk data missing CRLF",
            ));
        }
        cursor += 2;
    }
}

async fn read_until_crlf(
    stream: &mut tokio_rustls::server::TlsStream<TcpStream>,
    raw: &mut Vec<u8>,
    start: usize,
    context: &str,
) -> io::Result<usize> {
    loop {
        if let Some(pos) = raw[start..].windows(2).position(|window| window == b"\r\n") {
            return Ok(start + pos);
        }
        read_more(stream, raw, context).await?;
    }
}

async fn read_more(
    stream: &mut tokio_rustls::server::TlsStream<TcpStream>,
    buf: &mut Vec<u8>,
    context: &str,
) -> io::Result<()> {
    let mut chunk = [0; 8192];
    let n = stream.read(&mut chunk).await?;
    if n == 0 {
        return Err(io::Error::new(io::ErrorKind::UnexpectedEof, context));
    }
    buf.extend_from_slice(&chunk[..n]);
    Ok(())
}

fn parse_chunk_size(line: &[u8]) -> io::Result<usize> {
    let size = line
        .split(|byte| *byte == b';')
        .next()
        .unwrap_or_default()
        .trim_ascii();
    let size =
        std::str::from_utf8(size).map_err(|e| io::Error::new(io::ErrorKind::InvalidData, e))?;
    usize::from_str_radix(size, 16).map_err(|e| io::Error::new(io::ErrorKind::InvalidData, e))
}

fn assert_large_secret_body(body: &[u8]) {
    assert_eq!(body.len(), LARGE_SECRET_PAD_LEN * 2 + REAL_SECRET.len());
    assert!(body[..LARGE_SECRET_PAD_LEN].iter().all(|b| *b == b'a'));
    assert_eq!(
        &body[LARGE_SECRET_PAD_LEN..LARGE_SECRET_PAD_LEN + REAL_SECRET.len()],
        REAL_SECRET,
    );
    assert!(
        body[LARGE_SECRET_PAD_LEN + REAL_SECRET.len()..]
            .iter()
            .all(|b| *b == b'b')
    );
}

fn test_server_config() -> Arc<rustls::ServerConfig> {
    test_server_config_and_certificate().0
}

fn test_server_config_and_certificate() -> (Arc<rustls::ServerConfig>, Vec<u8>) {
    let key_pair = rcgen::KeyPair::generate().expect("generate test key");
    let params = CertificateParams::new(vec!["host.microsandbox.internal".to_string()])
        .expect("test certificate params");
    let cert = params.self_signed(&key_pair).expect("self-sign test cert");
    let chain = vec![CertificateDer::from(cert.der().to_vec())];
    let key = PrivateKeyDer::Pkcs8(PrivatePkcs8KeyDer::from(key_pair.serialize_der()));

    let config = Arc::new(
        rustls::ServerConfig::builder()
            .with_no_client_auth()
            .with_single_cert(chain, key)
            .expect("test server config"),
    );
    (config, cert.der().to_vec())
}

//--------------------------------------------------------------------------------------------------
// Tests
//--------------------------------------------------------------------------------------------------

#[msb_test]
async fn tls_intercept_large_post_to_host_https_server() {
    let mut server = HostHttps::start().await.expect("https fixture");
    let port = server.port();
    let name = "tls-intercept-large-post";
    let sb = spawn_curl_sandbox(name, port).await;

    let out = sb
        .shell(format!(
            r#"set -eu
body=/tmp/large-post-body
head -c {LARGE_POST_BODY_LEN} /dev/zero | tr '\000' a > "$body"
curl -k --http1.1 -m 30 -sS -o /tmp/response \
  -w 'code=%{{http_code}} upload=%{{size_upload}} download=%{{size_download}}' \
  -H 'content-type: text/plain' \
  --data-binary @"$body" \
  https://host.microsandbox.internal:{port}/post
"#
        ))
        .await
        .expect("curl host https fixture");

    let stdout = out.stdout().expect("utf8 stdout");
    assert!(
        stdout.contains("code=200"),
        "expected curl to receive 200, stdout: {stdout}, stderr: {}",
        out.stderr().unwrap_or_default()
    );
    assert!(
        stdout.contains(&format!("upload={LARGE_POST_BODY_LEN}")),
        "expected curl to upload full body, stdout: {stdout}, stderr: {}",
        out.stderr().unwrap_or_default()
    );

    let received = server.received_body().await.expect("read fixture body");
    assert_eq!(received.len(), LARGE_POST_BODY_LEN);
    assert!(received.iter().all(|b| *b == b'a'));

    teardown(sb, name).await;
}

#[msb_test]
async fn tls_intercept_rejects_http_host_sni_mismatch() {
    let mut server = HostHttps::start().await.expect("https fixture");
    let port = server.port();
    let name = "tls-intercept-host-sni-mismatch";
    let sb = spawn_curl_sandbox(name, port).await;

    let out = sb
        .shell(format!(
            r#"set +e
curl -k --http1.1 -m 10 -sS -o /tmp/response \
  -w 'code=%{{http_code}}' \
  -H 'Host: target.example.test' \
  https://host.microsandbox.internal:{port}/fronted
status=$?
echo "status=$status"
"#
        ))
        .await
        .expect("curl host mismatch fixture");

    let stdout = out.stdout().expect("utf8 stdout");
    assert!(
        !stdout.contains("status=0"),
        "expected curl to fail, stdout: {stdout}, stderr: {}",
        out.stderr().unwrap_or_default()
    );

    let received = tokio::time::timeout(Duration::from_secs(5), server.received_body()).await;
    assert!(
        received.is_err() || received.expect("timeout checked").is_err(),
        "upstream fixture should not receive a valid HTTP request"
    );

    teardown(sb, name).await;
}

#[msb_test]
async fn tls_intercept_substitutes_secret_for_host_alias() {
    let mut server = HostHttps::start().await.expect("https fixture");
    let port = server.port();
    let name = "tls-intercept-secret-host-alias";
    let sb = spawn_secret_curl_sandbox(name, port, "host.microsandbox.internal", false).await;

    let out = sb
        .shell(format!(
            r#"set -eu
body=/tmp/secret-body
printf 'token=%s' "$API_KEY" > "$body"
curl -k --http1.1 -m 30 -sS -o /tmp/response \
  -w 'code=%{{http_code}} upload=%{{size_upload}}' \
  -H 'content-type: text/plain' \
  --data-binary @"$body" \
  https://host.microsandbox.internal:{port}/secret
"#
        ))
        .await
        .expect("curl secret host alias fixture");

    let stdout = out.stdout().expect("utf8 stdout");
    assert!(
        stdout.contains("code=200"),
        "expected curl to receive 200, stdout: {stdout}, stderr: {}",
        out.stderr().unwrap_or_default()
    );

    let received = server.received_body().await.expect("read fixture body");
    assert_eq!(received, b"token=real-secret");

    teardown(sb, name).await;
}

/// The upstream must receive the real header credential and an unchanged body,
/// regardless of body characters or how curl/TLS split the request into reads.
#[msb_test]
async fn tls_intercept_header_secret_preserves_every_byte_and_unicode_character() {
    let mut server = HostHttps::start().await.expect("https fixture");
    let port = server.port();
    let name = "tls-intercept-secret-alphabet";
    let sb = Sandbox::builder(name)
        .image(CURL_IMAGE)
        .cpus(1)
        .memory(256)
        .user("0")
        .replace()
        .secret(|s| {
            s.env("API_KEY")
                .value("real-secret")
                .allow("host.microsandbox.internal")
        })
        .network(|n| {
            n.policy(NetworkPolicy::allow_all())
                .tls(|t| t.intercepted_ports(vec![port]).verify_upstream(false))
        })
        .create()
        .await
        .expect("create sandbox");

    // Include encoding markers near the start to exercise a body coalesced
    // with the Authorization header, then every byte and every Unicode scalar.
    let mut body = br#"100% %20 \u0041 \\user"#.to_vec();
    body.extend(0..=u8::MAX);
    let alphabet: String = (0..=0x10ffff).filter_map(char::from_u32).collect();
    body.extend_from_slice(alphabet.as_bytes());
    sb.fs()
        .write("/tmp/alphabet-body", &body)
        .await
        .expect("write body");

    let out = sb
        .shell(format!(
            r#"set -eu
curl -k --http1.1 -m 30 -sS -o /tmp/response -w 'code=%{{http_code}}' \
  -H "Authorization: Bearer $API_KEY" -H 'Expect:' \
  -H 'Content-Type: application/octet-stream' \
  --data-binary @/tmp/alphabet-body \
  https://host.microsandbox.internal:{port}/alphabet
"#
        ))
        .await
        .expect("curl alphabet fixture");
    let received = tokio::time::timeout(Duration::from_secs(5), server.received_request()).await;
    // Clean up even when a regression causes the assertions below to fail.
    teardown(sb, name).await;

    assert!(
        out.stdout().unwrap_or_default().contains("code=200"),
        "request failed: {}",
        out.stderr().unwrap_or_default()
    );
    let received = received
        .expect("upstream timeout")
        .expect("upstream request");
    let headers = String::from_utf8(received.headers).expect("UTF-8 headers");
    let authorization = headers.lines().find_map(|line| {
        let (name, value) = line.split_once(':')?;
        name.eq_ignore_ascii_case("authorization")
            .then(|| value.trim())
    });
    assert_eq!(authorization, Some("Bearer real-secret"));
    assert_eq!(received.body.len(), body.len());
    assert!(received.body == body, "upstream body bytes changed");
}

#[msb_test]
async fn tls_intercept_substitutes_secret_in_chunked_body() {
    let mut server = HostHttps::start().await.expect("https fixture");
    let port = server.port();
    let name = "tls-intercept-secret-chunked-body";
    let sb = spawn_secret_curl_sandbox(name, port, "host.microsandbox.internal", false).await;

    let out = sb
        .shell(format!(
            r#"set -eu
body=/tmp/chunked-secret-body
printf 'prefix-%s-suffix' "$API_KEY" > "$body"
curl -k --http1.1 -m 30 -sS -o /tmp/response \
  -w 'code=%{{http_code}} upload=%{{size_upload}}' \
  -H 'content-type: text/plain' \
  -H 'Transfer-Encoding: chunked' \
  --data-binary @"$body" \
  https://host.microsandbox.internal:{port}/chunked-secret
"#
        ))
        .await
        .expect("curl chunked secret fixture");

    let stdout = out.stdout().expect("utf8 stdout");
    assert!(
        stdout.contains("code=200"),
        "expected curl to receive 200, stdout: {stdout}, stderr: {}",
        out.stderr().unwrap_or_default()
    );

    let received = server.received_request().await.expect("read fixture body");
    assert!(
        is_transfer_chunked(&received.headers).expect("headers are utf8"),
        "expected upstream fixture to receive a chunked request, headers: {}",
        String::from_utf8_lossy(&received.headers)
    );
    assert_eq!(received.body, b"prefix-real-secret-suffix");

    teardown(sb, name).await;
}

#[msb_test]
async fn tls_intercept_substitutes_secret_in_large_content_length_body() {
    let mut server = HostHttps::start().await.expect("https fixture");
    let port = server.port();
    let name = "tls-intercept-large-secret-cl";
    let sb = spawn_secret_curl_sandbox(name, port, "host.microsandbox.internal", false).await;

    let out = sb
        .shell(format!(
            r#"set -eu
body=/tmp/large-secret-cl-body
head -c {LARGE_SECRET_PAD_LEN} /dev/zero | tr '\000' a > "$body"
printf '%s' "$API_KEY" >> "$body"
head -c {LARGE_SECRET_PAD_LEN} /dev/zero | tr '\000' b >> "$body"
curl -k --http1.1 -m 60 -sS -o /tmp/response \
  -w 'code=%{{http_code}} upload=%{{size_upload}}' \
  -H 'content-type: text/plain' \
  --data-binary @"$body" \
  https://host.microsandbox.internal:{port}/large-secret-cl
"#
        ))
        .await
        .expect("curl large content-length secret fixture");

    let stdout = out.stdout().expect("utf8 stdout");
    assert!(
        stdout.contains("code=200"),
        "expected curl to receive 200, stdout: {stdout}, stderr: {}",
        out.stderr().unwrap_or_default()
    );

    let received = server.received_request().await.expect("read fixture body");
    assert!(
        !is_transfer_chunked(&received.headers).expect("headers are utf8"),
        "expected upstream fixture to receive a fixed-length request, headers: {}",
        String::from_utf8_lossy(&received.headers)
    );
    assert_large_secret_body(&received.body);

    teardown(sb, name).await;
}

#[msb_test]
async fn tls_intercept_substitutes_secret_in_large_chunked_body() {
    let mut server = HostHttps::start().await.expect("https fixture");
    let port = server.port();
    let name = "tls-intercept-large-secret-chunked";
    let sb = spawn_secret_curl_sandbox(name, port, "host.microsandbox.internal", false).await;

    let out = sb
        .shell(format!(
            r#"set -eu
body=/tmp/large-secret-chunked-body
head -c {LARGE_SECRET_PAD_LEN} /dev/zero | tr '\000' a > "$body"
printf '%s' "$API_KEY" >> "$body"
head -c {LARGE_SECRET_PAD_LEN} /dev/zero | tr '\000' b >> "$body"
curl -k --http1.1 -m 60 -sS -o /tmp/response \
  -w 'code=%{{http_code}} upload=%{{size_upload}}' \
  -H 'content-type: text/plain' \
  -H 'Transfer-Encoding: chunked' \
  --data-binary @"$body" \
  https://host.microsandbox.internal:{port}/large-secret-chunked
"#
        ))
        .await
        .expect("curl large chunked secret fixture");

    let stdout = out.stdout().expect("utf8 stdout");
    if !stdout.contains("code=200") {
        let server_status =
            tokio::time::timeout(Duration::from_secs(5), server.received_request()).await;
        let server_status = match server_status {
            Ok(Ok(request)) => format!(
                "server received headers={} body={}",
                request.headers.len(),
                request.body.len()
            ),
            Ok(Err(e)) => format!("server error: {e}"),
            Err(_) => "server timed out".to_string(),
        };
        panic!(
            "expected curl to receive 200, stdout: {stdout}, stderr: {}, {server_status}",
            out.stderr().unwrap_or_default()
        );
    }

    let received = server.received_request().await.expect("read fixture body");
    assert!(
        is_transfer_chunked(&received.headers).expect("headers are utf8"),
        "expected upstream fixture to receive a chunked request, headers: {}",
        String::from_utf8_lossy(&received.headers)
    );
    assert_large_secret_body(&received.body);

    teardown(sb, name).await;
}

#[msb_test]
async fn tls_intercept_denies_secret_without_dns_pin() {
    let mut server = HostHttps::start().await.expect("https fixture");
    let port = server.port();
    let name = "tls-intercept-secret-dns-pin";
    let sb = spawn_secret_curl_sandbox(name, port, "api.allowed.test", false).await;

    let out = sb
        .shell(format!(
            r#"set +e
host_ip="$(getent ahostsv4 host.microsandbox.internal | awk '{{print $1; exit}}')"
body=/tmp/secret-body
printf 'token=%s' "$API_KEY" > "$body"
curl -k --http1.1 -m 10 -sS -o /tmp/response \
  -w 'code=%{{http_code}}' \
  --resolve "api.allowed.test:{port}:$host_ip" \
  -H 'content-type: text/plain' \
  --data-binary @"$body" \
  https://api.allowed.test:{port}/secret
status=$?
echo "status=$status"
"#
        ))
        .await
        .expect("curl secret dns pin fixture");

    let stdout = out.stdout().expect("utf8 stdout");
    assert!(
        !stdout.contains("status=0"),
        "expected curl to fail without DNS pin, stdout: {stdout}, stderr: {}",
        out.stderr().unwrap_or_default()
    );

    let received = tokio::time::timeout(Duration::from_secs(5), server.received_body()).await;
    assert!(
        received.is_err() || received.expect("timeout checked").is_err(),
        "upstream fixture should not receive a valid HTTP request"
    );

    teardown(sb, name).await;
}

#[msb_test]
async fn file_backed_secret_substitutes_current_file_contents() {
    let dir = tempfile::tempdir().expect("tempdir");
    let secret_path = dir.path().join("token");
    std::fs::write(&secret_path, "file-secret-v1\n").expect("write fixture secret file");

    let mut server = HostHttps::start().await.expect("https fixture");
    let port = server.port();
    let name = "file-secret-substitutes";
    let sb = spawn_file_secret_curl_sandbox(name, port, "host.microsandbox.internal", &secret_path)
        .await;

    let out = sb
        .shell(format!(
            r#"set -eu
body=/tmp/secret-body
printf 'token=%s' "$API_KEY" > "$body"
curl -k --http1.1 -m 30 -sS -o /tmp/response \
  -w 'code=%{{http_code}} upload=%{{size_upload}}' \
  -H 'content-type: text/plain' \
  --data-binary @"$body" \
  https://host.microsandbox.internal:{port}/secret
"#
        ))
        .await
        .expect("curl file secret fixture");

    let stdout = out.stdout().expect("utf8 stdout");
    assert!(
        stdout.contains("code=200"),
        "expected curl to receive 200, stdout: {stdout}, stderr: {}",
        out.stderr().unwrap_or_default()
    );

    // The host received the file's current bytes (trailing newline trimmed).
    let received = server.received_body().await.expect("read fixture body");
    assert_eq!(received, b"token=file-secret-v1");

    // The durable sandbox config stores only the path; the credential bytes
    // never reach the database.
    let handle = Sandbox::get(name).await.expect("get sandbox handle");
    let config_json = handle.config_json();
    assert!(!config_json.contains("file-secret-v1"));
    assert!(config_json.contains(secret_path.to_str().unwrap()));

    teardown(sb, name).await;
}

#[msb_test]
async fn file_backed_secret_rotation_takes_effect_without_restart() {
    let dir = tempfile::tempdir().expect("tempdir");
    let secret_path = dir.path().join("token");
    std::fs::write(&secret_path, "rotate-v1\n").expect("write fixture secret file");

    let mut server = HostHttpsSequence::start(2).await.expect("https fixture");
    let port = server.port();
    let name = "file-secret-rotation";
    let sb = spawn_file_secret_curl_sandbox(name, port, "host.microsandbox.internal", &secret_path)
        .await;

    let curl = |path: &str| {
        format!(
            r#"set -eu
body=/tmp/secret-body
printf 'token=%s' "$API_KEY" > "$body"
curl -k --http1.1 -m 30 -sS -o /tmp/response \
  -w 'code=%{{http_code}}' \
  -H 'content-type: text/plain' \
  --data-binary @"$body" \
  https://host.microsandbox.internal:{port}/{path}
"#
        )
    };

    sb.shell(curl("first")).await.expect("first curl");
    let first = server.next_body().await.expect("read first fixture body");
    assert_eq!(first, b"token=rotate-v1");

    // Rotate by editing the file directly. No control-socket call, no restart.
    std::fs::write(&secret_path, "rotate-v2\n").expect("rewrite fixture secret file");

    sb.shell(curl("second")).await.expect("second curl");
    let second = server.next_body().await.expect("read second fixture body");
    assert_eq!(second, b"token=rotate-v2");

    teardown(sb, name).await;
}

#[msb_test]
async fn file_backed_secret_missing_file_blocks_request() {
    let dir = tempfile::tempdir().expect("tempdir");
    let secret_path = dir.path().join("does-not-exist");

    let mut server = HostHttps::start().await.expect("https fixture");
    let port = server.port();
    let name = "file-secret-missing";
    let sb = spawn_file_secret_curl_sandbox(name, port, "host.microsandbox.internal", &secret_path)
        .await;

    let out = sb
        .shell(format!(
            r#"set +e
body=/tmp/secret-body
printf 'token=%s' "$API_KEY" > "$body"
curl -k --http1.1 -m 10 -sS -o /tmp/response \
  -w 'code=%{{http_code}}' \
  -H 'content-type: text/plain' \
  --data-binary @"$body" \
  https://host.microsandbox.internal:{port}/secret
status=$?
echo "status=$status"
"#
        ))
        .await
        .expect("curl missing file secret fixture");

    let stdout = out.stdout().expect("utf8 stdout");
    assert!(
        !stdout.contains("status=0"),
        "expected curl to fail (placeholder blocked), stdout: {stdout}, stderr: {}",
        out.stderr().unwrap_or_default()
    );

    let received = tokio::time::timeout(Duration::from_secs(5), server.received_body()).await;
    assert!(
        received.is_err() || received.expect("timeout checked").is_err(),
        "upstream fixture should not receive a valid HTTP request when the secret file is missing"
    );

    teardown(sb, name).await;
}

/// AC "credentials are not exposed to unauthorized destinations": a policed
/// rule (`GET /allowed`) does not cover `/denied` on the same host. Even
/// though a secret is configured to allow that host, the mismatched request
/// must be refused with a synthesized 403 and the fixture upstream must
/// never see it — proving the secret's host allow-list alone is not enough
/// to move a credential once interception is policing that host.
#[msb_test]
async fn intercept_refuses_unpoliced_request_with_credentials() {
    let mut server = HostHttps::start().await.expect("https fixture");
    let port = server.port();
    let name = "intercept-refuses-unpoliced";
    let sb = spawn_intercept_curl_sandbox(
        name,
        port,
        "host.microsandbox.internal",
        vec!["/bin/cat".to_string()],
    )
    .await;

    let out = sb
        .shell(format!(
            r#"set +e
body=/tmp/secret-body
printf 'token=%s' "$API_KEY" > "$body"
curl -k --http1.1 -m 10 -sS -o /tmp/response \
  -w 'code=%{{http_code}}' \
  -H 'content-type: text/plain' \
  --data-binary @"$body" \
  https://host.microsandbox.internal:{port}/denied
status=$?
echo "status=$status"
"#
        ))
        .await
        .expect("curl denied path fixture");

    let stdout = out.stdout().expect("utf8 stdout");
    assert!(
        stdout.contains("code=403"),
        "expected the interceptor's synthesized 403, stdout: {stdout}, stderr: {}",
        out.stderr().unwrap_or_default()
    );

    let received = tokio::time::timeout(Duration::from_secs(5), server.received_body()).await;
    assert!(
        received.is_err() || received.expect("timeout checked").is_err(),
        "upstream fixture must never receive a request the interceptor refused"
    );

    teardown(sb, name).await;
}

/// The passthrough half: a matched rule whose hook approves (empty stdout)
/// must let the request reach upstream, still carrying the network
/// secret-substitution layer's real credential — proving interception and
/// secret substitution compose rather than one disabling the other.
#[msb_test]
async fn intercept_passthrough_forwards_after_hook_approval() {
    let mut server = HostHttps::start().await.expect("https fixture");
    let port = server.port();
    let name = "intercept-passthrough-approval";
    // Reads and discards stdin, writes nothing to stdout: the empty-stdout
    // passthrough shape from the hook contract.
    let sb = spawn_intercept_curl_sandbox(
        name,
        port,
        "host.microsandbox.internal",
        vec![
            "/bin/sh".to_string(),
            "-c".to_string(),
            "cat >/dev/null".to_string(),
        ],
    )
    .await;

    let out = sb
        .shell(format!(
            r#"set -eu
body=/tmp/secret-body
printf 'token=%s' "$API_KEY" > "$body"
curl -k --http1.1 -m 30 -sS -o /tmp/response \
  -w 'code=%{{http_code}} upload=%{{size_upload}}' \
  -H 'content-type: text/plain' \
  --data-binary @"$body" \
  https://host.microsandbox.internal:{port}/allowed
"#
        ))
        .await
        .expect("curl allowed path fixture");

    let stdout = out.stdout().expect("utf8 stdout");
    assert!(
        stdout.contains("code=200"),
        "expected the hook-approved request to reach upstream, stdout: {stdout}, stderr: {}",
        out.stderr().unwrap_or_default()
    );

    let received = server.received_body().await.expect("read fixture body");
    assert_eq!(received, b"token=real-secret");

    teardown(sb, name).await;
}

/// AC #3: a failed or bypassed request cannot disable interception for
/// later requests. The first connection sends an unmatched request and gets
/// refused; a second, independent connection to the same policed host is
/// still fully policed and a matching request still reaches the hook.
///
/// Uses [`HostHttpsSequence`], not the single-shot [`HostHttps`]: the relay
/// dials and TLS-handshakes the upstream fixture *before* the interceptor
/// has seen any plaintext (interception only inspects already-decrypted
/// bytes), so even a refused request consumes one upstream accept — it just
/// never writes any request bytes over it. A single-shot fixture would have
/// that first, byte-less connection consume its only accept and starve the
/// second, actually-approved connection.
#[msb_test]
async fn intercept_survives_multiple_requests_on_one_connection() {
    let mut server = HostHttpsSequence::start(2).await.expect("https fixture");
    let port = server.port();
    let name = "intercept-survives-multiple-requests";
    let sb = spawn_intercept_curl_sandbox(
        name,
        port,
        "host.microsandbox.internal",
        vec!["/bin/cat".to_string()],
    )
    .await;

    let out = sb
        .shell(format!(
            r#"set -eu
body=/tmp/secret-body
printf 'token=%s' "$API_KEY" > "$body"

# First connection: unmatched path, must be refused.
first=$(curl -k --http1.1 -m 10 -sS -o /dev/null -w '%{{http_code}}' \
  -H 'content-type: text/plain' --data-binary @"$body" \
  https://host.microsandbox.internal:{port}/denied || true)
echo "first=$first"

# Second, independent connection: matched path, must still be policed
# and forwarded — proves the first connection's refusal did not disable
# interception for this one.
second=$(curl -k --http1.1 -m 10 -sS -o /dev/null -w '%{{http_code}}' \
  -H 'content-type: text/plain' --data-binary @"$body" \
  https://host.microsandbox.internal:{port}/allowed)
echo "second=$second"
"#
        ))
        .await
        .expect("curl multi-connection fixture");

    let stdout = out.stdout().expect("utf8 stdout");
    assert!(
        stdout.contains("first=403"),
        "expected the first, unmatched connection to be refused, stdout: {stdout}, stderr: {}",
        out.stderr().unwrap_or_default()
    );
    assert!(
        stdout.contains("second=200"),
        "expected the second, matched connection to still be policed and forwarded, stdout: {stdout}, stderr: {}",
        out.stderr().unwrap_or_default()
    );

    // The refused first connection reaches the fixture's listener (the
    // relay dials upstream before it knows the outcome) but never sends
    // any request bytes over it before the relay drops the connection.
    let first_upstream = server.next_body().await;
    assert!(
        first_upstream.is_err(),
        "the refused connection must not deliver a well-formed request upstream"
    );

    let second_upstream = server.next_body().await.expect("read second fixture body");
    assert_eq!(second_upstream, b"token=real-secret");

    teardown(sb, name).await;
}

/// AC #1: a `dispatch_on_headers` rule's body streams to upstream unbuffered
/// even though it is far larger than `max_request_bytes` — the hook only
/// ever sees the (small) headers, never the body, so the byte cap that
/// protects the *buffered* fail-closed path does not apply to it.
#[msb_test]
async fn intercept_streaming_rule_forwards_large_body_without_buffering() {
    let mut server = HostHttps::start().await.expect("https fixture");
    let port = server.port();
    let name = "intercept-streaming-large-body";
    let sb = spawn_streaming_intercept_curl_sandbox(name, port).await;

    let out = sb
        .shell(format!(
            r#"set -eu
body=/tmp/large-upload-body
head -c {LARGE_POST_BODY_LEN} /dev/zero | tr '\000' a > "$body"
curl -k --http1.1 -m 30 -sS -o /tmp/response \
  -w 'code=%{{http_code}} upload=%{{size_upload}}' \
  -H 'content-type: application/octet-stream' \
  --data-binary @"$body" \
  https://host.microsandbox.internal:{port}/upload
"#
        ))
        .await
        .expect("curl streaming upload fixture");

    let stdout = out.stdout().expect("utf8 stdout");
    assert!(
        stdout.contains("code=200"),
        "expected the streaming rule to forward past its cap, not refuse with 413, stdout: {stdout}, stderr: {}",
        out.stderr().unwrap_or_default()
    );
    assert!(
        stdout.contains(&format!("upload={LARGE_POST_BODY_LEN}")),
        "expected curl to upload the full body, stdout: {stdout}, stderr: {}",
        out.stderr().unwrap_or_default()
    );

    let received = server.received_body().await.expect("read fixture body");
    assert_eq!(received.len(), LARGE_POST_BODY_LEN);
    assert!(received.iter().all(|b| *b == b'a'));

    teardown(sb, name).await;
}

// A real guest client must receive the complete JSON before the TLS proxy closes.
#[msb_test]
async fn tls_secret_denial_delivers_json_to_guest() {
    for version in ["1.0", "1.1"] {
        let mut server = HostHttps::start().await.expect("https fixture");
        let port = server.port();
        let name = "tls-secret-deny-json";
        let sb = spawn_secret_curl_sandbox(name, port, "api.allowed.test", true).await;

        let out = sb
            .shell(format!(
                r#"curl -k --http{version} -m 10 -sS -o /tmp/denial -w '%{{http_code}}\n' \
  -H "Authorization: Bearer $API_KEY" \
  https://host.microsandbox.internal:{port}/ && cat /tmp/denial"#
            ))
            .await
            .expect("curl denied secret");

        teardown(sb, name).await;
        let stdout = out.stdout().expect("utf8 stdout");
        let (code, body) = stdout.split_once('\n').expect("HTTP status and body");
        assert_eq!(
            code,
            "403",
            "stdout: {stdout}, stderr: {}",
            out.stderr().unwrap_or_default()
        );
        let error: serde_json::Value = serde_json::from_str(body).expect("complete JSON body");
        assert_eq!(
            error,
            serde_json::json!({
                "code": "secret_policy_denied",
                "message": "Check secret access for {host}.",
                "domain": "host.microsandbox.internal"
            })
        );
        let received = tokio::time::timeout(Duration::from_secs(5), server.received_request())
            .await
            .expect("upstream connection closes");
        assert!(received.is_err(), "rejected request reached upstream");
    }
}

fn probe_interface(ipv6: bool) -> InterfaceOverrides {
    InterfaceOverrides {
        ipv4_address: Some("172.30.255.2".parse().unwrap()),
        ipv6_address: ipv6.then(|| IPV6_GUEST.parse().unwrap()),
        ..Default::default()
    }
}

/// Adding an unrelated secret must not prevent HTTPS to a literal IP.
#[msb_test]
async fn tls_intercept_ip_destination_without_sni() {
    run_tls_intercept_ip_destination_without_sni(false).await;
}

#[msb_test]
async fn tls_intercept_ip_destination_without_sni_ipv6() {
    run_tls_intercept_ip_destination_without_sni(true).await;
}

async fn run_tls_intercept_ip_destination_without_sni(ipv6: bool) {
    for (trust_ca, matching_ip, send_secret) in [
        (true, true, false),
        (false, true, false),
        (true, false, false),
        (true, true, true),
    ] {
        let ca_key = rcgen::KeyPair::generate().unwrap();
        let mut ca_params = CertificateParams::default();
        ca_params.is_ca = rcgen::IsCa::Ca(rcgen::BasicConstraints::Unconstrained);
        ca_params.key_usages = vec![rcgen::KeyUsagePurpose::KeyCertSign];
        let ca = ca_params.clone().self_signed(&ca_key).unwrap();
        let ca_file = tempfile::NamedTempFile::new().unwrap();
        std::fs::write(ca_file.path(), ca.pem()).unwrap();
        let (config_tx, config_rx) = tokio::sync::oneshot::channel();
        let mut server = HostHttps::start_with_config(async { config_rx.await.unwrap() })
            .await
            .expect("https fixture");
        let port = server.port();
        let name = if ipv6 {
            "tls-intercept-ip-destination-v6"
        } else {
            "tls-intercept-ip-destination"
        };
        let sb = Sandbox::builder(name)
            .image(CURL_IMAGE)
            .cpus(1)
            .memory(256)
            .user("0")
            .replace()
            .secret(|s| {
                s.env("API_KEY")
                    .value("real-secret")
                    .allow("api.allowed.test")
            })
            .network(|n| {
                n.interface(probe_interface(ipv6))
                    .policy(NetworkPolicy::allow_all())
                    .tls(|t| {
                        let t = t.intercepted_ports(vec![port]).verify_upstream(true);
                        if trust_ca {
                            t.upstream_ca_cert(ca_file.path())
                        } else {
                            t
                        }
                    })
            })
            .create()
            .await
            .expect("create sandbox");
        let ip = if ipv6 { IPV6_GATEWAY } else { "172.30.255.1" };
        let authority = if ipv6 {
            format!("[{ip}]")
        } else {
            ip.to_string()
        };
        let identity = if matching_ip {
            ip.to_string()
        } else {
            if ipv6 { "2001:db8::1" } else { "192.0.2.1" }.to_string()
        };
        let key = rcgen::KeyPair::generate().unwrap();
        let issuer = rcgen::Issuer::from_params(&ca_params, &ca_key);
        let cert = CertificateParams::new(vec![identity])
            .unwrap()
            .signed_by(&key, &issuer)
            .unwrap();
        let config = rustls::ServerConfig::builder()
            .with_no_client_auth()
            .with_single_cert(
                vec![cert.der().clone(), ca.der().clone()],
                PrivateKeyDer::Pkcs8(PrivatePkcs8KeyDer::from(key.serialize_der())),
            )
            .unwrap();
        config_tx.send(Arc::new(config)).unwrap();
        let header = if send_secret {
            "-H \"Authorization: Bearer $API_KEY\""
        } else {
            ""
        };
        let out = sb
            .shell(format!(
                r#"curl --noproxy '*' -{family} -k --http1.1 -m 15 -sS -o /tmp/response -w '%{{http_code}}\n' --data 'probe' {header} https://{authority}:{port}/
"#,
                family = if ipv6 { 6 } else { 4 },
            ))
            .await
            .expect("curl IP destination");
        teardown(sb, name).await;
        let status = out.stdout().unwrap_or_default();
        if !trust_ca || !matching_ip {
            assert!(
                !out.status().success,
                "untrusted or mismatched upstream must be rejected"
            );
            assert_eq!(status.trim(), "000");
        } else {
            assert!(out.status().success, "{}", out.stderr().unwrap_or_default());
            assert_eq!(status.trim(), if send_secret { "403" } else { "200" });
        }
        let received =
            tokio::time::timeout(Duration::from_secs(2), server.received_request()).await;
        if trust_ca && matching_ip && !send_secret {
            let received = received
                .expect("upstream request")
                .expect("valid HTTP request");
            assert_eq!(received.peer.is_ipv6(), ipv6, "upstream address family");
            assert_eq!(received.body, b"probe");
        } else if let Ok(Ok(request)) = received {
            assert!(
                request.headers.is_empty(),
                "denied request reached upstream"
            );
        }
    }
}

/// Exercise the complete guest network stack with TLS records split independently
/// of TCP writes. Both SNI and destination-IP identities must retain their policy.
#[msb_test]
async fn tls_versions_fragmentation_and_policy_matrix() {
    run_tls_versions_fragmentation_and_policy_matrix(false).await;
}

#[msb_test]
async fn tls_versions_fragmentation_and_policy_matrix_ipv6() {
    run_tls_versions_fragmentation_and_policy_matrix(true).await;
}

async fn run_tls_versions_fragmentation_and_policy_matrix(ipv6: bool) {
    let _ = rustls::crypto::ring::default_provider().install_default();
    let mut dns = HostDns::start().await;
    for mode in ["intercept", "bypass", "domain-allow", "strict-bypass"] {
        for version in [12, 13] {
            for named in [false, true] {
                for fragmented in [false, true] {
                    let label = format!("{mode}/tls{version}/sni={named}/fragmented={fragmented}");
                    let (config, certificate) = test_server_config_and_certificate();
                    let mut server = HostHttps::start_with_config(async move { config })
                        .await
                        .unwrap();
                    let port = server.port();
                    let name = if ipv6 {
                        "tls-record-policy-matrix-v6"
                    } else {
                        "tls-record-policy-matrix"
                    };
                    let domain_policy = matches!(mode, "domain-allow" | "strict-bypass");
                    let bypass = matches!(mode, "bypass" | "strict-bypass");
                    let blocked = mode == "strict-bypass";
                    let policy = if domain_policy {
                        NetworkPolicy::none().allow_domain("probe.example").unwrap()
                    } else {
                        NetworkPolicy::allow_all()
                    };
                    let sb = Sandbox::builder(name)
                        .image("mirror.gcr.io/library/python:3.12-alpine")
                        .cpus(1)
                        .memory(256)
                        .replace()
                        .network(|n| {
                            n.dns(|d| d.nameservers([dns.address]).rebind_protection(false))
                                .policy(policy)
                                .strict(true)
                                .interface(probe_interface(ipv6))
                                .tls(|t| {
                                    let t = t.intercepted_ports(vec![port]).verify_upstream(false);
                                    if bypass {
                                        t.bypass("probe.example").bypass(if ipv6 {
                                            IPV6_GATEWAY
                                        } else {
                                            "172.30.255.1"
                                        })
                                    } else {
                                        t
                                    }
                                })
                        })
                        .create()
                        .await
                        .expect("create matrix sandbox");
                    sb.fs()
                        .write("/tmp/tls_probe.py", include_str!("fixtures/tls_probe.py"))
                        .await
                        .unwrap();
                    sb.fs()
                        .write("/tmp/upstream.der", certificate)
                        .await
                        .unwrap();
                    let out = sb
                        .shell(format!(
                            "python3 /tmp/tls_probe.py {port} {version} {} {} {} {} {}",
                            u8::from(named),
                            u8::from(fragmented),
                            u8::from(blocked),
                            u8::from(bypass),
                            u8::from(ipv6)
                        ))
                        .await
                        .unwrap();
                    teardown(sb, name).await;
                    dns.assert_running().await;
                    assert!(
                        out.status().success,
                        "{label}: {} {}",
                        out.stdout().unwrap_or_default(),
                        out.stderr().unwrap_or_default()
                    );
                    let received =
                        tokio::time::timeout(Duration::from_secs(2), server.received_request())
                            .await;
                    if blocked {
                        assert!(out.stdout().unwrap().starts_with("blocked"), "{label}");
                        assert!(
                            !matches!(received, Ok(Ok(_))),
                            "{label}: denied request reached upstream"
                        );
                    } else {
                        let received = received
                            .expect("fixture response deadline")
                            .expect("upstream HTTP request");
                        assert_eq!(
                            received.peer.is_ipv6(),
                            ipv6,
                            "{label}: upstream address family"
                        );
                        assert_eq!(received.body, b"probe", "{label}");
                    }
                }
            }
        }
    }
}

/// Raw guests must retain legacy bypass while malformed modern hellos never
/// deliver bytes to an upstream, even when the selected host is bypassed.
#[msb_test]
async fn tls_legacy_bypass_and_malformed_hello_matrix() {
    run_tls_legacy_bypass_and_malformed_hello_matrix(false).await;
}

#[msb_test]
async fn tls_legacy_bypass_and_malformed_hello_matrix_ipv6() {
    run_tls_legacy_bypass_and_malformed_hello_matrix(true).await;
}

async fn run_tls_legacy_bypass_and_malformed_hello_matrix(ipv6: bool) {
    for (kind, named) in [
        ("legacy", false),
        ("legacy", true),
        ("duplicate-extension", true),
        ("duplicate-name", true),
        ("truncated-name", true),
    ] {
        for fragmented in [false, true] {
            let label = format!("{kind}/sni={named}/fragmented={fragmented}");
            let listener = TcpListener::bind(if ipv6 { "[::1]:0" } else { "127.0.0.1:0" })
                .await
                .unwrap();
            let port = listener.local_addr().unwrap().port();
            let mut server = tokio::spawn(async move {
                let (mut stream, _) = listener.accept().await.unwrap();
                let mut received = Vec::new();
                let read = async {
                    let mut buf = [0; 16384];
                    loop {
                        let length = match stream.read(&mut buf).await {
                            Ok(0) => break,
                            Ok(length) => length,
                            Err(error) if error.kind() == io::ErrorKind::ConnectionReset => break,
                            Err(error) => panic!("fixture read: {error}"),
                        };
                        received.extend_from_slice(&buf[..length]);
                        if stream.write_all(&buf[..length]).await.is_err() {
                            break;
                        }
                    }
                };
                tokio::time::timeout(Duration::from_secs(8), read)
                    .await
                    .expect("raw fixture deadline");
                received
            });
            let name = if ipv6 {
                "tls-raw-hello-matrix-v6"
            } else {
                "tls-raw-hello-matrix"
            };
            let sb = Sandbox::builder(name)
                .image("mirror.gcr.io/library/python:3.12-alpine")
                .cpus(1)
                .memory(256)
                .replace()
                .network(|n| {
                    n.policy(NetworkPolicy::allow_all())
                        .interface(probe_interface(ipv6))
                        .tls(|t| {
                            t.intercepted_ports(vec![port])
                                .bypass("host.microsandbox.internal")
                                .bypass(if ipv6 { IPV6_GATEWAY } else { "172.30.255.1" })
                        })
                })
                .create()
                .await
                .expect("raw probe sandbox");
            sb.fs()
                .write(
                    "/tmp/tls_raw_probe.py",
                    include_str!("fixtures/tls_raw_probe.py"),
                )
                .await
                .unwrap();
            let out = sb
                .shell(format!(
                    "python3 /tmp/tls_raw_probe.py {port} {} {} {kind} {}",
                    u8::from(named),
                    u8::from(fragmented),
                    u8::from(ipv6)
                ))
                .await
                .unwrap();
            teardown(sb, name).await;
            let received = match tokio::time::timeout(Duration::from_secs(2), &mut server).await {
                Ok(result) => result.unwrap(),
                Err(_) => {
                    server.abort();
                    assert_ne!(kind, "legacy", "{label}: upstream never completed");
                    Vec::new()
                }
            };
            assert!(
                out.status().success,
                "{label}: {} {}",
                out.stdout().unwrap_or_default(),
                out.stderr().unwrap_or_default()
            );
            if kind == "legacy" {
                assert!(!received.is_empty(), "{label}: no upstream bytes");
                assert_eq!(
                    out.stdout().unwrap().trim(),
                    format!("forwarded {}", received.len()),
                    "{label}"
                );
            } else {
                assert!(
                    received.is_empty(),
                    "{label}: malformed TLS reached upstream"
                );
                assert_eq!(out.stdout().unwrap().trim(), "blocked", "{label}");
            }
        }
    }
}
