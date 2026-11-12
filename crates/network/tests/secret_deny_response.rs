//! Guest-visible secret denials and the boundaries where the proxy must close.

#![cfg(feature = "engine")]

use std::sync::Arc;
use std::sync::atomic::{AtomicBool, Ordering};
use std::time::Duration;

use bytes::Bytes;
use microsandbox_network::config::builder::SecretBuilder;
use microsandbox_network::conn::ProxyConnectState;
use microsandbox_network::policy::NetworkPolicy;
use microsandbox_network::secrets::config::{SecretViolationAction, SecretsConfig};
use microsandbox_network::shared::{ResolvedHostnameFamily, SharedState};
use microsandbox_network::tcp::proxy::spawn_tcp_proxy;
use microsandbox_types::HttpConfig;
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::TcpListener;
use tokio::sync::mpsc;

//--------------------------------------------------------------------------------------------------
// Functions
//--------------------------------------------------------------------------------------------------

/// One plain-HTTP guest connection towards a listener standing in for `api.example.com`.
///
/// Returns the upstream side, the guest→proxy sender and the proxy→guest receiver, so a test can
/// assert both what the guest read and what reached upstream.
async fn plain_http_connection(
    secrets: Arc<SecretsConfig>,
) -> (
    tokio::net::TcpStream,
    mpsc::Sender<Bytes>,
    mpsc::Receiver<Bytes>,
) {
    let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let addr = listener.local_addr().unwrap();
    let shared = Arc::new(SharedState::new(8));
    shared.set_http_config(HttpConfig {
        deny_response: true,
        deny_response_format: microsandbox_types::HttpDenyResponseFormat::Json,
        secret_deny_message: Some("Remedy.".into()),
        ..Default::default()
    });
    shared.cache_resolved_hostname(
        "api.example.com",
        ResolvedHostnameFamily::Ipv4,
        [addr.ip()],
        Duration::from_secs(60),
    );

    let (from_tx, from_rx) = mpsc::channel(8);
    let (to_tx, to_rx) = mpsc::channel(8);
    spawn_tcp_proxy(
        &tokio::runtime::Handle::current(),
        addr,
        addr,
        from_rx,
        to_tx,
        shared,
        Arc::new(NetworkPolicy::default()),
        secrets,
        None,
        false,
        Arc::new(ProxyConnectState::new()),
        None,
    );

    let (upstream, _) = listener.accept().await.unwrap();

    (upstream, from_tx, to_rx)
}

//--------------------------------------------------------------------------------------------------
// Tests
//--------------------------------------------------------------------------------------------------

#[tokio::test]
async fn secret_denials_answer_only_when_an_http_response_is_safe() {
    let check = async {
        for action in [
            SecretViolationAction::Block,
            SecretViolationAction::BlockAndLog,
            SecretViolationAction::BlockAndTerminate,
        ] {
            for (name, prefix, rejected, upstream_response, enabled, expect_response) in [
                (
                    "server-first response",
                    "",
                    "GET /$KEY HTTP/1.1\r\nHost: api.example.com\r\n\r\n",
                    "HTTP/1.1 100 Continue\r\n\r\n",
                    true,
                    false,
                ),
                (
                    "http1.0 body",
                    "",
                    "POST / HTTP/1.0\r\nHost: api.example.com\r\nContent-Length: 4\r\n\r\n$KEY",
                    "",
                    true,
                    true,
                ),
                (
                    "http1.0 response started",
                    "POST / HTTP/1.0\r\nHost: api.example.com\r\nContent-Length: 4\r\n\r\n",
                    "$KEY",
                    "HTTP/1.0 200 OK\r\nContent-Length: 8\r\n\r\nhello",
                    true,
                    false,
                ),
                (
                    "legacy text",
                    "",
                    "POST / HTTP/1.1\r\nHost: api.example.com\r\nContent-Length: 4\r\n\r\n$KEY",
                    "",
                    true,
                    false,
                ),
                (
                    "body",
                    "",
                    "POST / HTTP/1.1\r\nHost: api.example.com\r\nContent-Length: 4\r\n\r\n$KEY",
                    "",
                    true,
                    true,
                ),
                (
                    "disabled",
                    "",
                    "POST / HTTP/1.1\r\nHost: api.example.com\r\nContent-Length: 4\r\n\r\n$KEY",
                    "",
                    false,
                    false,
                ),
                (
                    "streamed body",
                    "POST / HTTP/1.1\r\nHost: api.example.com\r\nContent-Length: 4\r\n\r\n",
                    "$KEY",
                    "",
                    true,
                    true,
                ),
                (
                    "split placeholder",
                    "POST / HTTP/1.1\r\nHost: api.example.com\r\nContent-Length: 4\r\n\r\n$K",
                    "EY",
                    "",
                    true,
                    true,
                ),
                (
                    "malformed authority",
                    "",
                    "GET /$KEY HTTP/1.1\r\nHost: api.example.com\r\nHost: other.example.com\r\n\r\n",
                    "",
                    true,
                    false,
                ),
                (
                    "chunked body",
                    "POST / HTTP/1.1\r\nHost: api.example.com\r\nTransfer-Encoding: chunked\r\n\r\n",
                    "4\r\n$KEY\r\n0\r\n\r\n",
                    "",
                    true,
                    true,
                ),
                (
                    "response started",
                    "POST / HTTP/1.1\r\nHost: api.example.com\r\nContent-Length: 4\r\n\r\n",
                    "$KEY",
                    "HTTP/1.1 200 OK\r\nContent-Length: 8\r\n\r\nhello",
                    true,
                    false,
                ),
                (
                    "interim response",
                    "POST / HTTP/1.1\r\nHost: api.example.com\r\nContent-Length: 4\r\n\r\n",
                    "$KEY",
                    "HTTP/1.1 100 Continue\r\n\r\n",
                    true,
                    false,
                ),
                (
                    "pipelined",
                    "GET /first HTTP/1.1\r\nHost: api.example.com\r\n\r\n",
                    "GET /$KEY HTTP/1.1\r\nHost: api.example.com\r\n\r\n",
                    "",
                    true,
                    false,
                ),
                (
                    "coalesced pipeline",
                    "",
                    "GET /first HTTP/1.1\r\nHost: api.example.com\r\n\r\nGET /$KEY HTTP/1.1\r\nHost: api.example.com\r\n\r\n",
                    "",
                    true,
                    false,
                ),
                ("opaque", "", "EHLO $KEY\r\n", "", true, false),
                (
                    "http2",
                    "",
                    "PRI * HTTP/2.0\r\n\r\nSM\r\n\r\n\x00\x00\x00\x04\x00\x00\x00\x00\x00\x00\x00D\x01\x05\x00\x00\x00\x01\x00\x07:method\x03GET\x00\x07:scheme\x04http\x00\x05:path\x05/$KEY\x00\n:authority\x0fapi.example.com",
                    "",
                    true,
                    false,
                ),
                (
                    "get with leading blank line",
                    "",
                    "\r\nGET /$KEY HTTP/1.1\r\nHost: api.example.com\r\n\r\n",
                    "",
                    true,
                    true,
                ),
                (
                    "connect with leading blank line",
                    "",
                    "\r\nCONNECT api.example.com:443 HTTP/1.1\r\nHost: api.example.com\r\nAuthorization: $KEY\r\n\r\n",
                    "",
                    true,
                    false,
                ),
                (
                    "head with leading blank line",
                    "",
                    "\r\nHEAD /$KEY HTTP/1.1\r\nHost: api.example.com\r\n\r\n",
                    "",
                    true,
                    false,
                ),
                (
                    "head",
                    "",
                    "HEAD /$KEY HTTP/1.1\r\nHost: api.example.com\r\n\r\n",
                    "",
                    true,
                    false,
                ),
            ] {
                let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
                let addr = listener.local_addr().unwrap();
                let shared = Arc::new(SharedState::new(8));
                let secret_message = match name {
                    "body" => Some("Check secret policy for {host}."),
                    "http1.0 body" => Some(""),
                    _ => None,
                };
                shared.set_http_config(HttpConfig {
                    deny_response: enabled,
                    deny_response_format: if name == "legacy text" {
                        microsandbox_types::HttpDenyResponseFormat::Text
                    } else {
                        microsandbox_types::HttpDenyResponseFormat::Json
                    },
                    // Network allow-list advice must not replace the secret-specific explanation.
                    network_deny_message: Some("network-only message".into()),
                    secret_deny_message: secret_message.map(str::to_owned),
                    ..Default::default()
                });
                shared.cache_resolved_hostname(
                    "api.example.com",
                    ResolvedHostnameFamily::Ipv4,
                    [addr.ip()],
                    Duration::from_secs(60),
                );
                let terminated = Arc::new(AtomicBool::new(false));
                let termination_flag = terminated.clone();
                shared.set_termination_hook(Arc::new(move || {
                    termination_flag.store(true, Ordering::SeqCst);
                }));
                let secrets = SecretsConfig {
                    violation_action: action.clone(),
                    secrets: vec![
                        SecretBuilder::new()
                            .env("API_KEY")
                            .value("real-secret")
                            .placeholder("$KEY")
                            .allow("github.com")
                            // The secrets the rows below put in a body must refuse
                            // there to prove when a denial is safe to answer.
                            .substitute_in_body(true)
                            .build(),
                    ],
                    ..Default::default()
                };
                let (from_tx, from_rx) = mpsc::channel(8);
                let (to_tx, mut to_rx) = mpsc::channel(8);
                // A server-first case waits for upstream bytes before sending its request.
                if !prefix.is_empty() || upstream_response.is_empty() {
                    from_tx
                        .send(Bytes::from_static(
                            if prefix.is_empty() { rejected } else { prefix }.as_bytes(),
                        ))
                        .await
                        .unwrap();
                }
                spawn_tcp_proxy(
                    &tokio::runtime::Handle::current(),
                    addr,
                    addr,
                    from_rx,
                    to_tx,
                    shared,
                    Arc::new(NetworkPolicy::default()),
                    Arc::new(secrets),
                    None,
                    false,
                    Arc::new(ProxyConnectState::new()),
                    None,
                );
                let (mut upstream, _) = listener.accept().await.unwrap();
                if !prefix.is_empty() {
                    let mut forwarded = vec![0; prefix.len()];
                    upstream.read_exact(&mut forwarded).await.unwrap();
                    assert_eq!(forwarded, prefix.as_bytes(), "{name}");
                }
                if !upstream_response.is_empty() {
                    upstream
                        .write_all(upstream_response.as_bytes())
                        .await
                        .unwrap();
                    let mut received = Vec::new();
                    while received.len() < upstream_response.len() {
                        received.extend_from_slice(&to_rx.recv().await.unwrap());
                    }
                    assert_eq!(received, upstream_response.as_bytes(), "{name}");
                }
                if !prefix.is_empty() || !upstream_response.is_empty() {
                    from_tx
                        .send(Bytes::from_static(rejected.as_bytes()))
                        .await
                        .unwrap();
                }
                drop(from_tx);
                let mut blocked = Vec::new();
                upstream.read_to_end(&mut blocked).await.unwrap();
                assert!(blocked.is_empty(), "{name}: blocked bytes reached upstream");
                let mut response = Vec::new();
                while let Some(bytes) = to_rx.recv().await {
                    response.extend_from_slice(&bytes);
                }
                // Invalid authority is rejected before placeholder policy selects an action.
                assert_eq!(
                    terminated.load(Ordering::SeqCst),
                    action == SecretViolationAction::BlockAndTerminate
                        && name != "malformed authority",
                    "{name}"
                );
                if expect_response && action != SecretViolationAction::BlockAndTerminate {
                    assert!(
                        response.starts_with(b"HTTP/1.1 403 Forbidden\r\n"),
                        "{name}: {response:?}"
                    );
                    let text = String::from_utf8(response).unwrap();
                    let (headers, body) = text.split_once("\r\n\r\n").unwrap();
                    assert!(
                        headers
                            .lines()
                            .any(|line| line == "Content-Type: application/json")
                    );
                    let error: serde_json::Value = serde_json::from_str(body).unwrap();
                    assert_eq!(error["code"], "secret_policy_denied", "{name}");
                    assert_eq!(error["domain"], "api.example.com", "{name}");
                    assert_eq!(error["credential"], "API_KEY", "{name}");
                    assert_eq!(error["reason"], "host-not-covered", "{name}");

                    // The engine states one facts sentence; a configured message is a literal
                    // suffix after it, never a replacement and never interpolated.
                    let (location, phrase) = match name {
                        "get with leading blank line" => ("unknown", "the request line"),
                        _ => ("body", "the request body"),
                    };
                    assert_eq!(error["location"], location, "{name}");
                    let facts = format!(
                        "Blocked: API_KEY was sent in {phrase} to api.example.com; it is \
                         substituted only for github.com."
                    );
                    let expected_message = match name {
                        // The one row with a configured message: it is a literal suffix.
                        "body" => format!("{facts} Check secret policy for {{host}}."),
                        // No configured message, or an empty one: the facts alone.
                        _ => facts,
                    };
                    assert_eq!(error["message"], expected_message, "{name}");
                    let content_length: usize = headers
                        .lines()
                        .find_map(|line| line.strip_prefix("Content-Length: "))
                        .unwrap()
                        .parse()
                        .unwrap();
                    assert_eq!(content_length, body.len(), "{name}: complete JSON body");
                    assert!(
                        !text.contains("real-secret")
                            && !text.contains("$KEY")
                            && !text.contains("network-only message")
                    );
                } else {
                    assert!(
                        response.is_empty(),
                        "{name}: must not inject a response: {response:?}"
                    );
                }
            }
        }
    };
    tokio::time::timeout(Duration::from_secs(10), check)
        .await
        .expect("secret denial fixture timed out");
}

/// A file-backed secret whose value cannot be read is named as such in the guest's 403, and the
/// reported fix works: restoring the file makes the same request substitute.
#[tokio::test]
async fn file_backed_secret_denial_names_the_unreadable_credential() {
    let check = async {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("token");
        let secrets = || {
            Arc::new(SecretsConfig {
                violation_action: SecretViolationAction::Block,
                secrets: vec![
                    SecretBuilder::new()
                        .env("API_FILE_KEY")
                        .file(&path)
                        .placeholder("$KEY")
                        .allow("api.example.com")
                        .require_tls_identity(false)
                        .build(),
                ],
                ..Default::default()
            })
        };
        let request =
            b"GET / HTTP/1.1\r\nHost: api.example.com\r\nAuthorization: Bearer $KEY\r\n\r\n";

        // Nothing to read: the guest learns which credential failed, not which hosts allow it.
        let (mut upstream, from_tx, mut to_rx) = plain_http_connection(secrets()).await;
        from_tx.send(Bytes::from_static(request)).await.unwrap();
        let mut response = Vec::new();
        while let Some(bytes) = to_rx.recv().await {
            response.extend_from_slice(&bytes);
        }
        let text = String::from_utf8(response).unwrap();
        let (_, body) = text.split_once("\r\n\r\n").expect("a JSON 403");
        let error: serde_json::Value = serde_json::from_str(body).unwrap();
        assert_eq!(
            error,
            serde_json::json!({
                "code": "secret_policy_denied",
                "domain": "api.example.com",
                "credential": "API_FILE_KEY",
                "location": "header",
                "reason": "credential-unavailable",
                "message": "Blocked: API_FILE_KEY was sent in a request header to api.example.com, but the sandbox could not read its real value. Remedy.",
            })
        );
        assert!(!text.contains("tok-"));
        drop(from_tx);
        let mut blocked = Vec::new();
        upstream.read_to_end(&mut blocked).await.unwrap();
        assert!(blocked.is_empty(), "blocked bytes reached upstream");

        // The fix the message names: restore the file and the request is substituted.
        std::fs::write(&path, "tok-AAA\n").unwrap();
        let (mut upstream, from_tx, mut to_rx) = plain_http_connection(secrets()).await;
        from_tx.send(Bytes::from_static(request)).await.unwrap();
        let expected =
            b"GET / HTTP/1.1\r\nHost: api.example.com\r\nAuthorization: Bearer tok-AAA\r\n\r\n";
        let mut forwarded = vec![0; expected.len()];
        upstream.read_exact(&mut forwarded).await.unwrap();
        assert_eq!(forwarded, expected);
        drop(from_tx);
        drop(upstream);
        // No response within the window, or the guest side closed: either way the request was
        // not denied.
        if let Ok(Some(bytes)) =
            tokio::time::timeout(Duration::from_millis(250), to_rx.recv()).await
        {
            panic!("a substituted request must not be denied: {bytes:?}");
        }
    };
    tokio::time::timeout(Duration::from_secs(10), check)
        .await
        .expect("file-backed denial fixture timed out");
}
