//! Real-VM end-to-end coverage for origin-scoped header credentials (#175).
//!
//! This exercises the whole shipped path on a real microVM: an embedding
//! application registers a per-launch [`CredentialResolver`], the runtime
//! resolves the credential reference in the host process, transports the value
//! on the private memory-backed launch-config fd, and the egress proxy *sets*
//! one named header on requests to exactly one HTTPS origin (host **and**
//! port) — while the guest never sees the value.
//!
//! Unlike the in-process TLS-handler/proxy unit tests, these assertions are
//! made against a real HTTPS upstream that records the bytes it actually
//! received, from a guest that really booted.
//!
//! # Running
//!
//! The suite boots a real VM (libkrun on macOS / KVM on Linux) and is marked
//! `#[ignore]`, so it must be selected explicitly. It also needs to be pointed
//! at the `msb` binary built from this branch and the matching `libkrunfw`,
//! because the SDK execs that binary and probes `msb __capabilities`:
//!
//! ```sh
//! cd vendor/microsandbox
//! # 1. Build + ad-hoc sign the runtime from this branch (macOS):
//! (cd .. && ./script/build/macos.sh --dev)      # -> build/msb-dev, target/macos-dev/
//! #    (or, inside the submodule: `just build-msb`)
//! # 2. Run this test against the freshly built binary:
//! MSB_PATH="$PWD/build/msb-dev" \
//! MSB_LIBKRUNFW_PATH="$PWD/build/libkrunfw.5.dylib" \
//!   cargo test -p microsandbox --test header_credential_e2e \
//!     -- --ignored --nocapture --test-threads=1
//! ```
//!
//! The image (`mirror.gcr.io/curlimages/curl`) must be pullable or already
//! cached. Bound the run externally as well (`perl -e 'alarm 600; exec @ARGV'`),
//! as CI does with nextest's `slow-timeout`; every wait below is also bounded
//! internally.

use std::io;
use std::net::{Ipv4Addr, Ipv6Addr, SocketAddr};
use std::sync::Arc;
use std::time::Duration;

use microsandbox::{CredentialResolveError, CredentialResolver, NetworkPolicy, Sandbox};
use rcgen::CertificateParams;
use rustls::pki_types::{CertificateDer, PrivateKeyDer, PrivatePkcs8KeyDer};
use test_utils::msb_test;
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::{TcpListener, TcpStream};
use tokio::sync::mpsc;
use tokio::task::JoinHandle;
use tokio_rustls::TlsAcceptor;
use zeroize::Zeroizing;

//--------------------------------------------------------------------------------------------------
// Constants
//--------------------------------------------------------------------------------------------------

const CURL_IMAGE: &str = "mirror.gcr.io/curlimages/curl";

/// The exact authorized origin host. The guest reaches this name through the
/// sandbox's host-alias DNS, and the runtime maps it to the host loopback.
const CREDENTIAL_HOST: &str = "host.microsandbox.internal";

/// A second hostname that resolves (via `curl --resolve`) to the same gateway
/// address, used to prove the credential is scoped to the exact host.
const WRONG_HOST: &str = "api.other.test";

/// Non-secret reference the test resolver understands.
const CREDENTIAL_REFERENCE: &str = "e2e/api-key";

/// The real value the resolver returns. Chosen to be a distinctive sentinel so
/// the "guest never sees it" assertions cannot pass by accident.
const REAL_VALUE: &str = "sk-e2e-175-sentinel-3f9a";

/// The one named header that is set (not substituted).
const HEADER: &str = "x-api-key";

/// Template with exactly one `%s`.
const FORMAT: &str = "Token %s";

/// Wall-clock ceiling for the create/boot task.
const CREATE_BUDGET: Duration = Duration::from_secs(180);

/// Wall-clock ceiling for one guest shell command.
const SHELL_BUDGET: Duration = Duration::from_secs(120);

/// Wall-clock ceiling for waiting on one recorded upstream request.
const UPSTREAM_BUDGET: Duration = Duration::from_secs(30);

//--------------------------------------------------------------------------------------------------
// Types
//--------------------------------------------------------------------------------------------------

/// Per-launch resolver holding the real value only in this (host) process.
struct FixedResolver;

/// One request as the real upstream observed it on the wire.
struct RecordedRequest {
    /// Raw request line plus header lines (no body).
    head: Vec<u8>,
    /// Request body bytes (empty for these GETs).
    body: Vec<u8>,
}

/// Real HTTPS upstream that records `capacity` sequential requests on one port.
struct HttpsFixture {
    port: u16,
    requests: mpsc::Receiver<io::Result<RecordedRequest>>,
    handle: Option<JoinHandle<()>>,
}

//--------------------------------------------------------------------------------------------------
// Methods
//--------------------------------------------------------------------------------------------------

impl CredentialResolver for FixedResolver {
    fn resolve(&self, reference: &str) -> Result<Zeroizing<String>, CredentialResolveError> {
        if reference == CREDENTIAL_REFERENCE {
            Ok(Zeroizing::new(REAL_VALUE.to_string()))
        } else {
            Err(CredentialResolveError::not_found())
        }
    }
}

impl RecordedRequest {
    /// All values of the named field, case-insensitively.
    fn header_values(&self, name: &str) -> Vec<String> {
        let text = String::from_utf8_lossy(&self.head);
        text.split("\r\n")
            .skip(1) // request line
            .filter_map(|line| {
                let (field, value) = line.split_once(':')?;
                field
                    .eq_ignore_ascii_case(name)
                    .then(|| value.trim().to_string())
            })
            .collect()
    }

    /// The raw request line.
    fn request_line(&self) -> String {
        String::from_utf8_lossy(&self.head)
            .lines()
            .next()
            .unwrap_or_default()
            .to_string()
    }
}

impl HttpsFixture {
    /// Bind loopback (v4 + v6) on a random port and serve `capacity`
    /// sequential TLS connections. `redirect_port`, when set, makes any request
    /// target beginning `/redirect` answer `302` to that port on
    /// [`CREDENTIAL_HOST`].
    async fn start(capacity: usize, redirect_port: Option<u16>) -> io::Result<Self> {
        let _ = rustls::crypto::ring::default_provider().install_default();

        let v4_listener = TcpListener::bind(SocketAddr::from((Ipv4Addr::LOCALHOST, 0))).await?;
        let port = v4_listener.local_addr()?.port();
        let v6_listener = TcpListener::bind(SocketAddr::from((Ipv6Addr::LOCALHOST, port))).await?;
        let acceptor = TlsAcceptor::from(test_server_config());
        let (tx, rx) = mpsc::channel(capacity.max(1));

        let handle = tokio::spawn(async move {
            for _ in 0..capacity {
                let accepted = tokio::select! {
                    accept = v4_listener.accept() => accept,
                    accept = v6_listener.accept() => accept,
                };
                let result = async {
                    let (stream, _) = accepted?;
                    let tls = acceptor.accept(stream).await?;
                    handle_https_request(tls, redirect_port).await
                }
                .await;
                if tx.send(result).await.is_err() {
                    return;
                }
            }
        });

        Ok(Self {
            port,
            requests: rx,
            handle: Some(handle),
        })
    }

    fn port(&self) -> u16 {
        self.port
    }

    /// Wait for the next recorded upstream request, in accept order.
    async fn next_request(&mut self) -> RecordedRequest {
        tokio::time::timeout(UPSTREAM_BUDGET, self.requests.recv())
            .await
            .expect("upstream fixture timed out waiting for a request")
            .expect("upstream fixture closed with no more connections")
            .expect("upstream fixture request failed")
    }
}

impl Drop for HttpsFixture {
    fn drop(&mut self) {
        if let Some(handle) = self.handle.take() {
            handle.abort();
        }
    }
}

//--------------------------------------------------------------------------------------------------
// Functions
//--------------------------------------------------------------------------------------------------

async fn handle_https_request(
    mut stream: tokio_rustls::server::TlsStream<TcpStream>,
    redirect_port: Option<u16>,
) -> io::Result<RecordedRequest> {
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
        if let Some(pos) = request.windows(4).position(|w| w == b"\r\n\r\n") {
            break pos;
        }
    };

    let head = request[..header_end].to_vec();
    let body = request[header_end + 4..].to_vec();

    let target = String::from_utf8_lossy(&head)
        .lines()
        .next()
        .and_then(|line| line.split_whitespace().nth(1))
        .unwrap_or_default()
        .to_string();

    if target.starts_with("/redirect")
        && let Some(port) = redirect_port
    {
        let response = format!(
            "HTTP/1.1 302 Found\r\nLocation: https://{CREDENTIAL_HOST}:{port}/after-redirect\r\nContent-Length: 0\r\nConnection: close\r\n\r\n"
        );
        stream.write_all(response.as_bytes()).await?;
    } else {
        stream
            .write_all(b"HTTP/1.1 200 OK\r\nContent-Length: 2\r\nConnection: close\r\n\r\nok")
            .await?;
    }
    stream.shutdown().await?;

    Ok(RecordedRequest { head, body })
}

fn test_server_config() -> Arc<rustls::ServerConfig> {
    let _ = rustls::crypto::ring::default_provider().install_default();
    let key_pair = rcgen::KeyPair::generate().expect("generate test key");
    let params =
        CertificateParams::new(vec![CREDENTIAL_HOST.to_string()]).expect("test certificate params");
    let cert = params.self_signed(&key_pair).expect("self-sign test cert");
    let chain = vec![CertificateDer::from(cert.der().to_vec())];
    let key = PrivateKeyDer::Pkcs8(PrivatePkcs8KeyDer::from(key_pair.serialize_der()));

    Arc::new(
        rustls::ServerConfig::builder()
            .with_no_client_auth()
            .with_single_cert(chain, key)
            .expect("test server config"),
    )
}

async fn teardown(sb: Sandbox, name: &str) {
    let _ = sb.stop().await;
    let _ = Sandbox::remove(name).await;
}

//--------------------------------------------------------------------------------------------------
// Tests
//--------------------------------------------------------------------------------------------------

/// End-to-end proof of the #175 primitive and its origin scoping on a real VM:
///
/// * the named header is **set** on the authorized origin even when the guest
///   sent no such header, and the guest's own value is **replaced** (not
///   duplicated) when it did;
/// * the real value never appears in the guest environment or guest-readable
///   filesystem, nor in the durable config the host persisted;
/// * the same host on a **different port**, and a **different host** on the
///   authorized port, both arrive at the real upstream **uninjected**;
/// * a `302` redirect to a non-authorized port is re-decided per request and
///   arrives uninjected.
#[msb_test]
async fn header_credential_is_set_only_for_the_exact_origin() {
    let _ = rustls::crypto::ring::default_provider().install_default();

    // The non-authorized port's upstream (wrong-port request, then the
    // redirect follow-up) is started first so its port can appear in the
    // authorized fixture's redirect target.
    let mut wrong_port_upstream = HttpsFixture::start(2, None)
        .await
        .expect("wrong-port upstream fixture");
    let wrong_port = wrong_port_upstream.port();

    // The authorized origin's upstream accepts: happy, replace, wrong-host,
    // redirect.
    let mut authorized_upstream = HttpsFixture::start(4, Some(wrong_port))
        .await
        .expect("authorized upstream fixture");
    let authorized_port = authorized_upstream.port();

    let name = "header-credential-e2e";

    let config = Sandbox::builder(name)
        .image(CURL_IMAGE)
        .cpus(1)
        .memory(256)
        .user("0")
        .replace()
        .network(|n| {
            n.policy(NetworkPolicy::allow_all())
                .tls(|t| {
                    t.intercepted_ports(vec![authorized_port, wrong_port])
                        .verify_upstream(false)
                })
                .header_credential(|c| {
                    c.id("e2e")
                        .reference(CREDENTIAL_REFERENCE)
                        .origin(CREDENTIAL_HOST, authorized_port)
                        .header(HEADER)
                        .format(FORMAT)
                })
        })
        .build()
        .await
        .expect("build sandbox config");

    // Nothing durable may carry the value.
    let durable_json = serde_json::to_string(&config).expect("serialize durable config");
    assert!(
        !durable_json.contains(REAL_VALUE),
        "durable SandboxConfig must never contain the resolved value"
    );
    assert!(
        durable_json.contains(CREDENTIAL_REFERENCE),
        "durable SandboxConfig must carry the non-secret reference"
    );

    let (mut progress, task) =
        Sandbox::create_with_pull_progress_and_resolver(config, Arc::new(FixedResolver));
    let drain = tokio::spawn(async move { while progress.recv().await.is_some() {} });
    let sb = tokio::time::timeout(CREATE_BUDGET, task)
        .await
        .expect("create timed out")
        .expect("create task panicked")
        .expect("create sandbox");
    let _ = drain.await;

    let script = format!(
        r#"set -u
host_ip="$(getent ahostsv4 {CREDENTIAL_HOST} | awk '{{print $1; exit}}')"
echo "host_ip=$host_ip"

curl -k --http1.1 -m 30 -sS -o /dev/null -w 'happy=%{{http_code}}\n' \
  -H 'x-echo: keep-me' \
  https://{CREDENTIAL_HOST}:{authorized_port}/happy

curl -k --http1.1 -m 30 -sS -o /dev/null -w 'replace=%{{http_code}}\n' \
  -H 'x-api-key: guest-supplied-bogus' \
  https://{CREDENTIAL_HOST}:{authorized_port}/replace

curl -k --http1.1 -m 30 -sS -o /dev/null -w 'wronghost=%{{http_code}}\n' \
  --resolve {WRONG_HOST}:{authorized_port}:$host_ip \
  https://{WRONG_HOST}:{authorized_port}/wronghost

curl -k --http1.1 -L -m 30 -sS -o /dev/null -w 'redirect=%{{http_code}}\n' \
  https://{CREDENTIAL_HOST}:{authorized_port}/redirect

curl -k --http1.1 -m 30 -sS -o /dev/null -w 'wrongport=%{{http_code}}\n' \
  https://{CREDENTIAL_HOST}:{wrong_port}/wrongport

echo '--- guest env ---'
env | grep -q '{REAL_VALUE}' && echo 'VALUE_IN_ENV' || echo 'NO_VALUE_IN_ENV'
tr '\0' '\n' < /proc/self/environ | grep -q '{REAL_VALUE}' && echo 'VALUE_IN_ENVIRON' || echo 'NO_VALUE_IN_ENVIRON'
echo "X_API_KEY=${{X_API_KEY:-<unset>}}"
found="$(grep -rIl '{REAL_VALUE}' /etc /root /tmp /home /usr /bin /sbin /lib /var 2>/dev/null | head -n 1)"
if [ -n "$found" ]; then echo "VALUE_FOUND_AT=$found"; else echo 'NO_VALUE_IN_FS'; fi
"#
    );

    let out = tokio::time::timeout(SHELL_BUDGET, sb.shell(script))
        .await
        .expect("guest shell timed out")
        .expect("guest shell failed");
    let stdout = out.stdout().unwrap_or_default();
    let stderr = out.stderr().unwrap_or_default();
    println!("--- guest script output ---\n{stdout}");
    if !stderr.is_empty() {
        println!("--- guest script stderr ---\n{stderr}");
    }

    for expected in [
        "happy=200",
        "replace=200",
        "wronghost=200",
        "redirect=200",
        "wrongport=200",
    ] {
        assert!(
            stdout.contains(expected),
            "expected {expected} in guest output\n--- guest stdout ---\n{stdout}\n--- guest stderr ---\n{stderr}\n--- ports (authorized, wrong) ---\n{}\n{}",
            authorized_port,
            wrong_port
        );
    }

    // The guest has no path to the value.
    assert!(
        stdout.contains("NO_VALUE_IN_ENV"),
        "guest environment must not contain the real value: {stdout}"
    );
    assert!(
        !stdout.contains(REAL_VALUE),
        "the real value must never appear in guest output: {stdout}"
    );
    assert!(
        stdout.contains("X_API_KEY=<unset>"),
        "the credential must not be exposed as an environment variable: {stdout}"
    );
    assert!(
        stdout.contains("NO_VALUE_IN_ENVIRON"),
        "the credential must not appear in the guest process environment: {stdout}"
    );
    assert!(
        stdout.contains("NO_VALUE_IN_FS"),
        "the credential must not be readable from the guest filesystem: {stdout}"
    );

    // The durable record the host persisted carries the reference, not the value.
    let handle = Sandbox::get(name).await.expect("get sandbox handle");
    let persisted = handle.config_json();
    assert!(
        !persisted.contains(REAL_VALUE),
        "persisted sandbox config must never contain the resolved value"
    );
    assert!(
        persisted.contains(CREDENTIAL_REFERENCE),
        "persisted sandbox config must carry the non-secret reference"
    );

    // 1. Happy path: the header is *set* although the guest sent none.
    let happy = authorized_upstream.next_request().await;
    println!(
        "--- authorized upstream /happy head ---\n{}",
        String::from_utf8_lossy(&happy.head)
    );
    assert_eq!(
        happy.request_line(),
        "GET /happy HTTP/1.1",
        "request line must be preserved"
    );
    assert_eq!(
        happy.header_values("x-api-key"),
        vec![format!("Token {REAL_VALUE}")],
        "authorized origin must receive exactly one injected field; head: {}",
        String::from_utf8_lossy(&happy.head)
    );
    assert_eq!(
        happy.header_values("x-echo"),
        vec!["keep-me".to_string()],
        "unrelated guest headers must be preserved"
    );
    assert!(
        happy.body.is_empty(),
        "injection must not invent a request body; got {} bytes",
        happy.body.len()
    );

    // 2. A guest-supplied value is replaced, not duplicated.
    let replace = authorized_upstream.next_request().await;
    assert_eq!(
        replace.header_values("x-api-key"),
        vec![format!("Token {REAL_VALUE}")],
        "a guest-supplied field must be removed and re-set exactly once; head: {}",
        String::from_utf8_lossy(&replace.head)
    );
    assert!(
        !String::from_utf8_lossy(&replace.head).contains("guest-supplied-bogus"),
        "the guest's own value must not survive; head: {}",
        String::from_utf8_lossy(&replace.head)
    );

    // 3. Wrong host on the authorized port: forwarded, uninjected.
    let wrong_host = authorized_upstream.next_request().await;
    println!(
        "--- authorized upstream /wronghost head ---\n{}",
        String::from_utf8_lossy(&wrong_host.head)
    );
    assert!(
        wrong_host.header_values("x-api-key").is_empty(),
        "a different host must receive no credential; head: {}",
        String::from_utf8_lossy(&wrong_host.head)
    );

    // 4. Redirect: the authorized origin's 302 is served, then the follow-up
    //    to a non-authorized port is re-decided and arrives uninjected.
    let redirect = authorized_upstream.next_request().await;
    assert_eq!(redirect.request_line(), "GET /redirect HTTP/1.1");
    let redirected = wrong_port_upstream.next_request().await;
    assert_eq!(
        redirected.request_line(),
        "GET /after-redirect HTTP/1.1",
        "the redirect must be followed to the non-authorized port"
    );
    assert!(
        redirected.header_values("x-api-key").is_empty(),
        "a redirect target on a non-authorized port must receive no credential; head: {}",
        String::from_utf8_lossy(&redirected.head)
    );

    // 5. Wrong port on the authorized host: forwarded, uninjected.
    let wrong_port_req = wrong_port_upstream.next_request().await;
    println!(
        "--- wrong-port upstream /wrongport head ---\n{}",
        String::from_utf8_lossy(&wrong_port_req.head)
    );
    assert!(
        wrong_port_req.header_values("x-api-key").is_empty(),
        "the same host on a different port must receive no credential; head: {}",
        String::from_utf8_lossy(&wrong_port_req.head)
    );

    teardown(sb, name).await;
}
