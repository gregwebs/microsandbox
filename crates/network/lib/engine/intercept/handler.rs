//! Per-connection interceptor state machine.
//!
//! The proxy feeds each decrypted, post-secret-substitution plaintext chunk
//! to [`Interceptor::process_chunk`]. The handler tracks one of five states:
//!
//! - **Pristine.** Haven't seen any data yet. On first chunk, either latch to
//!   `Forwarding` (unpoliced SNI / inactive config) or start evaluating the
//!   request head (policed SNI).
//! - **Forwarding.** Terminal fast path: no rule can ever match this SNI, or
//!   interception is inactive. Pass every chunk through unchanged forever.
//! - **AwaitingHead.** Policed SNI, request line not yet complete. Holds
//!   bytes rather than latching to `Forwarding` — see
//!   [`Interceptor::process_first_chunk`] for why that latch is a bypass.
//! - **Buffering.** A rule matched the request line. Accumulate until the
//!   hook can be dispatched (full body, or immediately for
//!   `dispatch_on_headers` rules).
//! - **Disabled.** Terminal: the hook already ran (or the request was
//!   refused) for this connection. Further chunks forward unchanged, but see
//!   the load-bearing invariant on the `Disabled` arm of
//!   [`Interceptor::process_chunk`] for why that never actually happens on a
//!   policed connection.
//!
//! Per-connection state means a long-lived connection that opens with an
//! HTTP/1.1 keep-alive but ships an intercepted request first will not have
//! subsequent requests on the same connection inspected — the connection is
//! effectively single-request on a policed SNI. That's acceptable for the
//! OAuth-refresh / scoped-API-call use case these rules are for.

use std::process::Stdio;

use tokio::io::AsyncWriteExt;
use tokio::process::Command;

use super::config::{InterceptConfig, InterceptRule};

//--------------------------------------------------------------------------------------------------
// Constants
//--------------------------------------------------------------------------------------------------

/// Wall-clock cap on one hook invocation. The hook runs on the host, so an
/// unbounded one lets the guest pin a host core per connection.
const HOOK_TIMEOUT: std::time::Duration = std::time::Duration::from_secs(90);

//--------------------------------------------------------------------------------------------------
// Types
//--------------------------------------------------------------------------------------------------

/// What the proxy should do with the chunk it just fed in.
pub(crate) enum Verdict {
    /// Forward the chunk the caller already has — zero-copy hot path.
    Forward,
    /// We had previously held bytes (in `Buffering`) and now must flush them
    /// as a single upstream write so the request reaches the server
    /// reassembled. Includes the held bytes plus the current chunk.
    ForwardBuffered(Vec<u8>),
    /// Hold this chunk; the interceptor is still accumulating bytes and will
    /// decide what to do later. The caller must not forward this chunk.
    Hold,
    /// Send `response` back to the guest and close the connection.
    Intercept(Vec<u8>),
}

/// Per-connection interceptor state.
pub(crate) struct Interceptor {
    config: InterceptConfig,
    sni: String,
    state: State,
}

enum State {
    Pristine,
    Forwarding,
    Buffering {
        rule: InterceptRule,
        accumulated: Vec<u8>,
        /// Position of the first byte of the body (= index just past the
        /// `\r\n\r\n` boundary). `None` until we've seen the headers in full.
        body_start: Option<usize>,
        /// Total body size from `Content-Length`. `None` if we can't parse
        /// one (treat as zero, i.e. no body expected — covers GET requests;
        /// POST bodies these rules target are always Content-Length'd).
        content_length: Option<usize>,
    },
    /// Policed SNI, request head not yet complete. We cannot latch to
    /// `Forwarding` here (that is the bypass described on
    /// [`Interceptor::process_first_chunk`]), so hold until there is enough
    /// of the head to decide.
    AwaitingHead {
        accumulated: Vec<u8>,
    },
    /// Terminal: the hook already ran, or the request was refused, or the
    /// buffer cap was hit. Stop trying.
    Disabled,
}

//--------------------------------------------------------------------------------------------------
// Methods
//--------------------------------------------------------------------------------------------------

impl Interceptor {
    pub(crate) fn new(config: InterceptConfig, sni: &str) -> Self {
        Self {
            config,
            sni: sni.to_ascii_lowercase(),
            state: State::Pristine,
        }
    }

    /// Drive the state machine forward with the next plaintext chunk.
    pub(crate) async fn process_chunk(&mut self, chunk: &[u8]) -> std::io::Result<Verdict> {
        match &mut self.state {
            State::Pristine => self.process_first_chunk(chunk).await,
            // Load-bearing invariant: this arm is reachable in-process (see
            // the state's own doc), but never actually reached on a policed
            // connection. `Disabled` is only entered via `Verdict::Intercept`
            // (refusal or hook-synthesized response), and the seam's
            // `forward_plaintext` terminates the relay as soon as it sees
            // `RequestAction::RespondAndClose` — no further chunk is ever
            // fed to this `Interceptor` afterward. If a future change let
            // the relay keep reading after `RespondAndClose`, this arm would
            // become a per-connection credential bypass on keep-alive: the
            // secret layer runs upstream of the interceptor and would keep
            // substituting the real credential into chunks this arm waves
            // through. Guarded by
            // `tls::proxy::tests::intercept_extension_refuses_unmatched_request_and_writes_nothing_upstream`
            // in `tls/proxy.rs`.
            State::Forwarding | State::Disabled => Ok(Verdict::Forward),
            State::Buffering { .. } => self.process_buffer_chunk(chunk).await,
            State::AwaitingHead { accumulated } => {
                if accumulated.len() + chunk.len() > self.config.max_request_bytes {
                    self.state = State::Disabled;
                    return Ok(Verdict::Intercept(too_large_response(
                        self.config.max_request_bytes,
                    )));
                }
                accumulated.extend_from_slice(chunk);
                let buf = std::mem::take(accumulated);
                self.evaluate_head(buf).await
            }
        }
    }

    /// First chunk on a connection.
    ///
    /// The fast path — latch to `Forwarding` and stream everything unchanged
    /// — is only safe when no rule could ever match this SNI. On a
    /// **policed** SNI it is a complete bypass of whatever policy the hook
    /// enforces, because HTTP/1.1 carries many requests per connection and
    /// the latch is per connection: send one request the rules don't cover
    /// (an unlisted method such as `HEAD`, or a one-byte write that defers
    /// the request line to the next chunk) and every later request on that
    /// connection is forwarded without the hook ever running — while the
    /// secret layer still substitutes the real credential. Anything in the
    /// guest can do this deliberately.
    ///
    /// So: unpoliced SNI keeps the zero-copy fast path; policed SNI goes
    /// through [`Self::evaluate_head`], which never latches without either
    /// running the hook or forcing the connection closed after this one
    /// request.
    async fn process_first_chunk(&mut self, chunk: &[u8]) -> std::io::Result<Verdict> {
        if !self.config.is_active() {
            self.state = State::Forwarding;
            return Ok(Verdict::Forward);
        }

        if !self.sni_is_policed() {
            // No rule can ever match this host. Latching is safe and keeps
            // long-lived streaming connections (agent APIs) on the
            // zero-copy path.
            self.state = State::Forwarding;
            return Ok(Verdict::Forward);
        }

        self.evaluate_head(chunk.to_vec()).await
    }

    /// True iff any rule targets this connection's SNI.
    fn sni_is_policed(&self) -> bool {
        self.config
            .rules
            .iter()
            .any(|r| r.host.eq_ignore_ascii_case(&self.sni))
    }

    /// Decide what to do with a request head on a policed SNI, given
    /// everything buffered so far. Holds until the head is complete enough
    /// to decide; never latches to plain forwarding without first making
    /// the connection single-request.
    async fn evaluate_head(&mut self, buf: Vec<u8>) -> std::io::Result<Verdict> {
        let Some(eol) = find_subsequence(&buf, b"\r\n") else {
            // Not even a request line yet. Hold — latching here is the
            // one-byte-first bypass.
            self.state = State::AwaitingHead { accumulated: buf };
            return Ok(Verdict::Hold);
        };
        let request_line = std::str::from_utf8(&buf[..eol]).unwrap_or("");

        let Some((method, path)) = parse_request_line(request_line) else {
            // Not HTTP/1.x we can parse, on a host we are supposed to
            // police. Refuse rather than stream it through blind.
            tracing::warn!(
                sni = %self.sni,
                "interceptor: unparseable request line on a policed host; refusing",
            );
            self.state = State::Disabled;
            return Ok(Verdict::Intercept(bad_request_response()));
        };

        // RFC 7230 5.3.2 absolute-form (`GET https://host/path`) is a legal
        // request target, and its path does not start with `/` — so a
        // prefix rule of `/` matched nothing and the request escaped the
        // policy entirely. Normalise to origin-form before matching.
        let target = normalize_request_target(path);
        if let Some(rule) = self.find_matching_rule(method, target) {
            let rule = rule.clone();
            tracing::debug!(
                sni = %self.sni,
                method,
                path = %sanitize(path),
                "interceptor: rule matched, buffering request",
            );
            let (body_start, content_length) = match find_subsequence(&buf, b"\r\n\r\n") {
                Some(p) => {
                    let start = p + 4;
                    let cl = parse_content_length(&buf[..start]);
                    (Some(start), cl)
                }
                None => (None, None),
            };
            self.state = State::Buffering {
                rule,
                accumulated: buf,
                body_start,
                content_length,
            };
            return self.maybe_dispatch().await;
        }

        // No rule covers this request and the host is policed, so REFUSE it.
        // Forwarding is not an option: the secret layer runs before the
        // interceptor, so by this point the guest's placeholder has already
        // become the real credential. Letting an unpoliced request through
        // "just once per connection" is still one credentialed request the
        // hook never saw, and the guest can open a connection per request.
        //
        // What lands here after `normalize_request_target` has done its job
        // is a method no rule covers (callers register a fixed list) or a
        // request-target shape we don't recognise. A 403 is the honest
        // answer rather than a silent credentialed forward.
        tracing::warn!(
            sni = %self.sni,
            method,
            path = %sanitize(path),
            "interceptor: no rule matched on a policed host; refusing",
        );
        self.state = State::Disabled;
        Ok(Verdict::Intercept(unpoliced_request_response(method, path)))
    }

    async fn process_buffer_chunk(&mut self, chunk: &[u8]) -> std::io::Result<Verdict> {
        if let State::Buffering { accumulated, .. } = &mut self.state {
            if accumulated.len() + chunk.len() > self.config.max_request_bytes {
                tracing::warn!(
                    sni = %self.sni,
                    accumulated = accumulated.len(),
                    chunk = chunk.len(),
                    max = self.config.max_request_bytes,
                    "interceptor: request exceeded max_request_bytes; refusing",
                );
                // Fail CLOSED. A rule matched this request, so the hook owns
                // the decision about it — and we can no longer get one,
                // because we'd have to hand the hook a truncated body.
                // Forwarding the held bytes instead means the request
                // reaches upstream with the secret-substitution layer
                // swapping the guest's placeholder for the real credential
                // and no policy applied at all: a bypass anything in the
                // guest can trigger deliberately by padding a request past
                // the cap.
                //
                // Bodies this large are not the traffic these rules are for
                // (OAuth refreshes and scoped API calls are ~KB); streaming
                // uploads use `dispatch_on_headers` rules, which decide from
                // the request line and never buffer a body. Raise
                // `max_request_bytes` if a legitimate flow needs more room.
                self.state = State::Disabled;
                return Ok(Verdict::Intercept(too_large_response(
                    self.config.max_request_bytes,
                )));
            }
            accumulated.extend_from_slice(chunk);
        }
        self.maybe_dispatch().await
    }

    async fn maybe_dispatch(&mut self) -> std::io::Result<Verdict> {
        let (rule, accumulated, body_start, content_length) = match &mut self.state {
            State::Buffering {
                rule,
                accumulated,
                body_start,
                content_length,
            } => (rule, accumulated, body_start, content_length),
            _ => return Ok(Verdict::Hold),
        };

        // Lazy-parse headers once they arrive.
        if body_start.is_none() {
            match find_subsequence(accumulated, b"\r\n\r\n") {
                Some(p) => {
                    *body_start = Some(p + 4);
                    *content_length = parse_content_length(&accumulated[..p + 4]);
                }
                None => return Ok(Verdict::Hold),
            }
        }

        let bs = body_start.expect("body_start set above");
        let expected = content_length.unwrap_or(0);
        let body_have = accumulated.len().saturating_sub(bs);

        // `dispatch_on_headers` rules fire the hook the moment we've seen
        // the headers — we don't need the body to make a path-based
        // allow/deny decision and we can't always buffer it (large uploads
        // exceed `max_request_bytes` by far). Other rules wait for the full
        // body as before.
        let dispatch_now = rule.dispatch_on_headers || body_have >= expected;
        if !dispatch_now {
            return Ok(Verdict::Hold);
        }

        // Hand the buffered prefix (headers + whatever body we have so far)
        // to the hook. For dispatch_on_headers rules this is usually just
        // the headers; for full-body rules it's the complete request.
        let request = std::mem::take(accumulated);
        let rule_clone = rule.clone();
        let response = run_hook(
            self.config
                .hook
                .as_ref()
                .expect("is_active() guarantees hook is Some"),
            &self.sni,
            &rule_clone,
            &request,
        )
        .await?;

        // Move out of Buffering: subsequent chunks (if any) take the
        // Disabled path — see the load-bearing-invariant comment on
        // `process_chunk`'s `Disabled` arm for why that never actually
        // forwards a later request on this connection.
        self.state = State::Disabled;

        // Three hook stdout shapes are recognised:
        //
        // - **Empty bytes**: passthrough verbatim. Flush the prefix we held
        //   to upstream and let subsequent chunks continue.
        // - **Starts with `HTTP/`**: synthesized response (Intercept). The
        //   bytes are an HTTP/1.x response sent to the guest; connection
        //   closes.
        // - **Anything else**: passthrough with *modified bytes*. The hook
        //   returned a rewritten request (typically: headers altered, e.g.
        //   Authorization stripped). Forward THESE bytes to upstream
        //   instead of the original prefix; let subsequent chunks continue.
        //   The check is "starts with `HTTP/`" because synthesized HTTP
        //   responses always begin with the protocol version, while a
        //   modified request always begins with the method (GET, POST,
        //   etc.) — a request line never starts with `HTTP/` and a response
        //   line always does.
        let verdict = if response.is_empty() {
            Verdict::ForwardBuffered(request)
        } else if response.starts_with(b"HTTP/") {
            Verdict::Intercept(response)
        } else {
            Verdict::ForwardBuffered(response)
        };
        Ok(verdict)
    }

    fn find_matching_rule(&self, method: &str, path: &str) -> Option<&InterceptRule> {
        // Strip query string from path for prefix match.
        let path_no_query = path.split_once('?').map(|(p, _)| p).unwrap_or(path);
        self.config.rules.iter().find(|r| {
            r.host.eq_ignore_ascii_case(&self.sni)
                && r.method == method
                && path_no_query.starts_with(&r.path_prefix)
        })
    }
}

//--------------------------------------------------------------------------------------------------
// Functions
//--------------------------------------------------------------------------------------------------

/// Invoke the hook subprocess. Pass `request` bytes on stdin, return stdout
/// bytes. Hook environment carries `MSB_INTERCEPT_SNI`,
/// `MSB_INTERCEPT_HOST_RULE`, `MSB_INTERCEPT_METHOD`, and
/// `MSB_INTERCEPT_PATH_PREFIX` so the hook doesn't have to re-parse the
/// request line just to know which rule fired.
async fn run_hook(
    hook: &[String],
    sni: &str,
    rule: &InterceptRule,
    request: &[u8],
) -> std::io::Result<Vec<u8>> {
    let (cmd, args) = hook.split_first().ok_or_else(|| {
        std::io::Error::new(std::io::ErrorKind::InvalidInput, "intercept hook is empty")
    })?;
    let mut child = Command::new(cmd)
        .args(args)
        .env("MSB_INTERCEPT_SNI", sni)
        .env("MSB_INTERCEPT_HOST_RULE", &rule.host)
        .env("MSB_INTERCEPT_METHOD", &rule.method)
        .env("MSB_INTERCEPT_PATH_PREFIX", &rule.path_prefix)
        .stdin(Stdio::piped())
        .stdout(Stdio::piped())
        .stderr(Stdio::inherit())
        .spawn()?;

    if let Some(mut stdin) = child.stdin.take() {
        stdin.write_all(request).await?;
        stdin.shutdown().await.ok();
    }

    // Bound the hook. It runs on the HOST, outside the guest's CPU and
    // memory limits, so a request that makes the hook expensive is a
    // host-side DoS the sandbox does not otherwise contain.
    let output = match tokio::time::timeout(HOOK_TIMEOUT, child.wait_with_output()).await {
        Ok(res) => res?,
        Err(_) => {
            return Err(std::io::Error::new(
                std::io::ErrorKind::TimedOut,
                format!("intercept hook exceeded {HOOK_TIMEOUT:?}"),
            ));
        }
    };
    if !output.status.success() {
        return Err(std::io::Error::other(format!(
            "intercept hook exited with {}",
            output.status
        )));
    }
    Ok(output.stdout)
}

/// Normalise a request target to origin-form for rule matching.
///
/// `GET https://api.github.com/repos/x HTTP/1.1` is legal HTTP/1.1 (RFC 7230
/// 5.3.2) and has a target that does not begin with `/` — so a prefix rule
/// against the path would otherwise match nothing and the request would
/// escape the policy entirely. Asterisk-form (`OPTIONS *`) and anything else
/// unrecognised is returned unchanged and will simply not match.
fn normalize_request_target(target: &str) -> &str {
    for scheme in ["http://", "https://"] {
        if let Some(rest) = target
            .get(..scheme.len())
            .filter(|p| p.eq_ignore_ascii_case(scheme))
            .and_then(|_| target.get(scheme.len()..))
        {
            // Strip the authority; the path starts at the next `/`.
            return match rest.find('/') {
                Some(slash) => &rest[slash..],
                // `https://host` with no path is the origin itself.
                None => "/",
            };
        }
    }
    target
}

/// Synthesized `403` for a request on a policed host that no rule covers.
/// See the call site: forwarding it would send the real credential upstream
/// with no policy applied.
fn unpoliced_request_response(method: &str, path: &str) -> Vec<u8> {
    let body = format!(
        "{{\"message\":\"microsandbox: {} {} matches no intercept rule on this host; \
         refused rather than forwarded with credentials\"}}",
        sanitize(method),
        sanitize(path)
    );
    let head = format!(
        "HTTP/1.1 403 Forbidden\r\n\
         Content-Type: application/json\r\n\
         Content-Length: {}\r\n\
         Connection: close\r\n\
         \r\n",
        body.len()
    );
    let mut out = Vec::with_capacity(head.len() + body.len());
    out.extend_from_slice(head.as_bytes());
    out.extend_from_slice(body.as_bytes());
    out
}

/// Synthesized `400` for a request we cannot parse on a policed host.
fn bad_request_response() -> Vec<u8> {
    let body =
        b"{\"message\":\"microsandbox: unparseable HTTP request on an intercepted host; refused\"}";
    let head = format!(
        "HTTP/1.1 400 Bad Request\r\n\
         Content-Type: application/json\r\n\
         Content-Length: {}\r\n\
         Connection: close\r\n\
         \r\n",
        body.len()
    );
    let mut out = Vec::with_capacity(head.len() + body.len());
    out.extend_from_slice(head.as_bytes());
    out.extend_from_slice(body);
    out
}

/// Synthesized `413` for a matched request that outgrew `max_request_bytes`.
/// Sent to the guest in place of forwarding an unvetted request upstream —
/// see the call site for why this fails closed.
fn too_large_response(max: usize) -> Vec<u8> {
    let body = format!(
        "{{\"message\":\"microsandbox: request exceeds max_request_bytes ({max}); \
         refused rather than forwarded unfiltered\"}}"
    );
    let head = format!(
        "HTTP/1.1 413 Content Too Large\r\n\
         Content-Type: application/json\r\n\
         Content-Length: {}\r\n\
         Connection: close\r\n\
         \r\n",
        body.len()
    );
    let mut out = Vec::with_capacity(head.len() + body.len());
    out.extend_from_slice(head.as_bytes());
    out.extend_from_slice(body.as_bytes());
    out
}

fn parse_request_line(line: &str) -> Option<(&str, &str)> {
    let mut parts = line.split(' ');
    let method = parts.next()?;
    let path = parts.next()?;
    // Sanity-check the HTTP version slot so we don't intercept e.g. a
    // CONNECT preamble accidentally.
    let version = parts.next()?;
    if !version.starts_with("HTTP/") {
        return None;
    }
    Some((method, path))
}

fn parse_content_length(headers: &[u8]) -> Option<usize> {
    let s = std::str::from_utf8(headers).ok()?;
    // Skip the request line, then walk header lines until we find one whose
    // name matches case-insensitively. Lines without a `:` (the request
    // line, or the trailing empty line) are ignored.
    for line in s.split("\r\n").skip(1) {
        let Some((name, value)) = line.split_once(':') else {
            continue;
        };
        if name.eq_ignore_ascii_case("content-length") {
            return value.trim().parse().ok();
        }
    }
    None
}

fn find_subsequence(haystack: &[u8], needle: &[u8]) -> Option<usize> {
    haystack.windows(needle.len()).position(|w| w == needle)
}

fn sanitize(s: &str) -> String {
    s.chars()
        .take(80)
        .map(|c| if c.is_ascii_graphic() { c } else { '?' })
        .collect()
}

//--------------------------------------------------------------------------------------------------
// Tests
//--------------------------------------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use super::*;

    fn cfg(rules: Vec<InterceptRule>) -> InterceptConfig {
        cfg_with_hook(rules, vec!["/bin/cat".to_string()])
    }

    fn cfg_with_hook(rules: Vec<InterceptRule>, hook: Vec<String>) -> InterceptConfig {
        InterceptConfig {
            rules,
            hook: Some(hook),
            max_request_bytes: 64 * 1024,
        }
    }

    #[tokio::test]
    async fn forwards_when_no_rules() {
        let mut i = Interceptor::new(InterceptConfig::default(), "example.com");
        let v = i.process_chunk(b"GET / HTTP/1.1\r\n\r\n").await.unwrap();
        assert!(matches!(v, Verdict::Forward));
    }

    #[tokio::test]
    async fn forwards_when_no_rule_matches() {
        let mut i = Interceptor::new(
            cfg(vec![InterceptRule {
                host: "platform.claude.com".into(),
                method: "POST".into(),
                path_prefix: "/v1/oauth/token".into(),
                dispatch_on_headers: false,
            }]),
            "example.com",
        );
        let v = i
            .process_chunk(b"GET / HTTP/1.1\r\nHost: example.com\r\n\r\n")
            .await
            .unwrap();
        assert!(matches!(v, Verdict::Forward));
    }

    #[tokio::test]
    async fn dispatches_matching_request_with_no_body() {
        // /bin/cat echoes stdin, so the hook's stdout is the request itself.
        // Under the three-shape stdout contract that is the "modified
        // passthrough" verdict (stdout that doesn't start with `HTTP/` is a
        // rewritten *request*), not a synthesized response — good enough to
        // prove the state machine buffered the request and ran the hook on
        // it.
        let mut i = Interceptor::new(
            cfg(vec![InterceptRule {
                host: "platform.claude.com".into(),
                method: "POST".into(),
                path_prefix: "/v1/oauth/token".into(),
                dispatch_on_headers: false,
            }]),
            "platform.claude.com",
        );
        let v = i
            .process_chunk(
                b"POST /v1/oauth/token HTTP/1.1\r\nHost: platform.claude.com\r\nContent-Length: 0\r\n\r\n",
            )
            .await
            .unwrap();
        match v {
            Verdict::ForwardBuffered(req) => {
                assert!(String::from_utf8_lossy(&req).contains("POST /v1/oauth/token"));
            }
            _ => panic!("expected ForwardBuffered (hook echoed the request back)"),
        }
    }

    /// A matched request that outgrows the buffer must NOT reach upstream.
    /// Forwarding it (the old behaviour) let anything in the guest opt out
    /// of the hook's policy on demand — pad a request past the cap and it
    /// goes upstream unfiltered, with the secret layer still substituting
    /// the real credential for the guest's placeholder.
    #[tokio::test]
    async fn oversized_matched_request_is_refused_not_forwarded() {
        let mut i = Interceptor::new(
            InterceptConfig {
                rules: vec![InterceptRule {
                    host: "api.github.com".into(),
                    method: "POST".into(),
                    path_prefix: "/".into(),
                    dispatch_on_headers: false,
                }],
                hook: Some(vec!["/bin/cat".to_string()]),
                max_request_bytes: 1024,
            },
            "api.github.com",
        );
        let head =
            b"POST /graphql HTTP/1.1\r\nHost: api.github.com\r\nContent-Length: 100000\r\n\r\n";
        assert!(matches!(
            i.process_chunk(head).await.unwrap(),
            Verdict::Hold
        ));

        let v = i.process_chunk(&vec![b'a'; 4096]).await.unwrap();
        match v {
            Verdict::Intercept(resp) => {
                let s = String::from_utf8_lossy(&resp);
                assert!(s.starts_with("HTTP/1.1 413"), "expected 413, got: {s}");
            }
            Verdict::ForwardBuffered(_) | Verdict::Forward => {
                panic!("oversized matched request was forwarded upstream unfiltered")
            }
            Verdict::Hold => panic!("expected a refusal, got Hold"),
        }
        // The proxy closes the connection on `Intercept`, so the rest of the
        // oversized body never reaches the interceptor (and the request
        // head was never forwarded upstream).
    }

    /// The deny path: a hook whose stdout starts with `HTTP/` has
    /// synthesized a response, which goes back to the guest and closes the
    /// connection. This is what a repo allow-list rejection rides on, so it
    /// needs its own coverage — every other test here uses a hook that
    /// echoes the request back instead.
    #[tokio::test]
    async fn hook_synthesized_response_is_returned_to_the_guest() {
        let mut i = Interceptor::new(
            cfg_with_hook(
                vec![InterceptRule {
                    host: "api.github.com".into(),
                    method: "GET".into(),
                    path_prefix: "/".into(),
                    dispatch_on_headers: false,
                }],
                vec![
                    "/bin/sh".to_string(),
                    "-c".to_string(),
                    "printf 'HTTP/1.1 403 Forbidden\\r\\nContent-Length: 0\\r\\n\\r\\n'"
                        .to_string(),
                ],
            ),
            "api.github.com",
        );
        let v = i
            .process_chunk(b"GET /repos/victim/private HTTP/1.1\r\nHost: api.github.com\r\n\r\n")
            .await
            .unwrap();
        match v {
            Verdict::Intercept(resp) => {
                assert!(String::from_utf8_lossy(&resp).starts_with("HTTP/1.1 403"));
            }
            _ => panic!("expected Intercept for a hook-synthesized response"),
        }
    }

    /// A hook that exits non-zero must fail the connection closed, not
    /// forward the buffered request. This is the third leg of the hook
    /// stdout contract documented on `maybe_dispatch` (empty / `HTTP/`-
    /// prefixed / modified-passthrough all assume a *successful* hook run);
    /// prior to this test nothing exercised the `!output.status.success()`
    /// branch in `run_hook`, so a regression there (e.g. treating a crashed
    /// hook as an empty-stdout passthrough) would have gone unnoticed.
    #[tokio::test]
    async fn hook_exiting_nonzero_fails_closed_without_forwarding() {
        let mut i = Interceptor::new(
            cfg_with_hook(
                vec![InterceptRule {
                    host: "api.github.com".into(),
                    method: "GET".into(),
                    path_prefix: "/".into(),
                    dispatch_on_headers: false,
                }],
                vec![
                    "/bin/sh".to_string(),
                    "-c".to_string(),
                    // Drain stdin (so the interceptor's write doesn't block
                    // on a full pipe) then exit non-zero.
                    "cat >/dev/null; exit 7".to_string(),
                ],
            ),
            "api.github.com",
        );
        let result = i
            .process_chunk(b"GET /repos/victim/private HTTP/1.1\r\nHost: api.github.com\r\n\r\n")
            .await;
        assert!(
            result.is_err(),
            "a hook exiting non-zero must fail closed, not produce a Verdict"
        );
    }

    /// A hook that runs past [`HOOK_TIMEOUT`] must fail the connection
    /// closed rather than forward the buffered request or wait indefinitely.
    ///
    /// This genuinely waits out the real 90-second timeout (tokio's
    /// paused-clock + `time::advance` combination was tried and reliably
    /// hangs here, apparently because advancing virtual time does not
    /// unstick a `tokio::process::Child` future that is still waiting on a
    /// *real* OS process — the process driver does not appear to get
    /// re-polled by `advance()` the way plain timers do) so it is `#[ignore]`d
    /// like the repo's other real-time/real-process integration tests (see
    /// `#[msb_test]`'s auto-`#[ignore]` for real VM boots). Run explicitly
    /// with `cargo test -p microsandbox-network -- --ignored
    /// hook_exceeding_timeout_fails_closed_without_forwarding` when touching
    /// `run_hook`'s timeout handling.
    #[tokio::test]
    #[ignore = "waits out the real 90s HOOK_TIMEOUT; run explicitly with --ignored"]
    async fn hook_exceeding_timeout_fails_closed_without_forwarding() {
        let mut i = Interceptor::new(
            cfg_with_hook(
                vec![InterceptRule {
                    host: "api.github.com".into(),
                    method: "GET".into(),
                    path_prefix: "/".into(),
                    dispatch_on_headers: false,
                }],
                vec![
                    "/bin/sh".to_string(),
                    "-c".to_string(),
                    // A few seconds past HOOK_TIMEOUT: long enough to prove
                    // the timeout (not the hook finishing first) is what
                    // triggers the failure, short enough to keep this test's
                    // real wall-clock cost bounded.
                    format!(
                        "sleep {}",
                        (HOOK_TIMEOUT + std::time::Duration::from_secs(5)).as_secs()
                    ),
                ],
            ),
            "api.github.com",
        );
        let result = i
            .process_chunk(b"GET /repos/victim/private HTTP/1.1\r\nHost: api.github.com\r\n\r\n")
            .await;
        match result {
            Err(e) => assert_eq!(
                e.kind(),
                std::io::ErrorKind::TimedOut,
                "expected a TimedOut error, got: {e:?}"
            ),
            Ok(_) => panic!("a hook exceeding the timeout must fail closed, not produce a Verdict"),
        }
    }

    /// `dispatch_on_headers` rules decide from the request line and must
    /// never buffer the body — that is what keeps multi-MB uploads off the
    /// `max_request_bytes` path, and what the fail-closed overflow refusal
    /// relies on to not break them. Assert both halves: the hook fires as
    /// soon as the headers land, and the body that follows streams through
    /// even though it dwarfs the cap.
    #[tokio::test]
    async fn streaming_rule_dispatches_on_headers_and_streams_body_past_the_cap() {
        let mut i = Interceptor::new(
            InterceptConfig {
                rules: vec![InterceptRule {
                    host: "github.com".into(),
                    method: "POST".into(),
                    path_prefix: "/".into(),
                    dispatch_on_headers: true,
                }],
                hook: Some(vec!["/bin/cat".to_string()]),
                max_request_bytes: 1024,
            },
            "github.com",
        );
        // Headers only, declaring a body far over the cap.
        let head = b"POST /o/r.git/git-receive-pack HTTP/1.1\r\nHost: github.com\r\nContent-Length: 10000000\r\n\r\n";
        match i.process_chunk(head).await.unwrap() {
            Verdict::ForwardBuffered(req) => {
                assert!(String::from_utf8_lossy(&req).contains("git-receive-pack"));
            }
            _ => panic!("streaming rule should dispatch as soon as the headers are complete"),
        }
        // Pack data now streams: never buffered, so never refused.
        for _ in 0..4 {
            assert!(
                matches!(
                    i.process_chunk(&vec![b'p'; 32 * 1024]).await.unwrap(),
                    Verdict::Forward
                ),
                "pack data must stream through, not hit the request cap"
            );
        }
    }

    /// The per-connection latch was a complete bypass of whatever the hook
    /// enforces: HTTP/1.1 carries many requests per connection, so one
    /// request the rules don't cover used to disable the hook for every
    /// request after it — with the secret layer still swapping in the real
    /// credential.
    #[tokio::test]
    async fn unlisted_method_cannot_disable_the_hook_for_the_connection() {
        let mut i = Interceptor::new(
            cfg(vec![InterceptRule {
                host: "api.github.com".into(),
                // Only GET is policed, as a caller might register a fixed
                // method list.
                method: "GET".into(),
                path_prefix: "/".into(),
                dispatch_on_headers: false,
            }]),
            "api.github.com",
        );
        // A method no rule covers must not latch the connection open.
        match i
            .process_chunk(b"HEAD / HTTP/1.1\r\nHost: api.github.com\r\n\r\n")
            .await
            .unwrap()
        {
            Verdict::Intercept(resp) => {
                assert!(String::from_utf8_lossy(&resp).starts_with("HTTP/1.1 403"));
            }
            Verdict::Forward | Verdict::ForwardBuffered(_) => {
                panic!("unmatched request latched the connection open / was forwarded")
            }
            Verdict::Hold => panic!("expected a refusal"),
        }
    }

    #[tokio::test]
    async fn one_byte_first_write_cannot_disable_the_hook() {
        let mut i = Interceptor::new(
            cfg(vec![InterceptRule {
                host: "api.github.com".into(),
                method: "GET".into(),
                path_prefix: "/".into(),
                dispatch_on_headers: false,
            }]),
            "api.github.com",
        );
        // The guest controls TLS record boundaries, so it can defer the
        // request line past the first chunk. That used to latch.
        assert!(
            matches!(i.process_chunk(b"G").await.unwrap(), Verdict::Hold),
            "a partial request line must be held, not forwarded"
        );
        // The rest of the request arrives and is policed normally.
        let v = i
            .process_chunk(b"ET /repos/victim/private HTTP/1.1\r\nHost: api.github.com\r\n\r\n")
            .await
            .unwrap();
        assert!(
            matches!(v, Verdict::ForwardBuffered(_) | Verdict::Intercept(_)),
            "the reassembled request must reach the hook"
        );
    }

    /// RFC 7230 absolute-form is legal HTTP/1.1 and its target does not
    /// start with `/` — so a `/` prefix rule matched nothing and the
    /// request escaped policy entirely. Worse, the old unmatched branch
    /// *forwarded* it, and secret substitution runs before the interceptor,
    /// so it went upstream carrying the real credential.
    #[tokio::test]
    async fn absolute_form_request_target_is_still_policed() {
        let mut i = Interceptor::new(
            cfg(vec![InterceptRule {
                host: "api.github.com".into(),
                method: "GET".into(),
                path_prefix: "/".into(),
                dispatch_on_headers: false,
            }]),
            "api.github.com",
        );
        let v = i
            .process_chunk(
                b"GET https://api.github.com/repos/victim/private HTTP/1.1\r\nHost: api.github.com\r\n\r\n",
            )
            .await
            .unwrap();
        match v {
            // Normalised to origin-form, so the rule matches and the hook
            // (here /bin/cat) gets to rule on it.
            Verdict::ForwardBuffered(req) => {
                assert!(String::from_utf8_lossy(&req).contains("/repos/victim/private"));
            }
            _ => panic!("absolute-form request must reach the hook, not bypass it"),
        }
    }

    #[test]
    fn normalize_request_target_strips_scheme_and_authority() {
        assert_eq!(
            normalize_request_target("https://api.github.com/repos/a/b"),
            "/repos/a/b"
        );
        assert_eq!(
            normalize_request_target("HTTPS://api.github.com/x?y=1"),
            "/x?y=1"
        );
        assert_eq!(normalize_request_target("http://github.com"), "/");
        assert_eq!(normalize_request_target("/repos/a/b"), "/repos/a/b");
        assert_eq!(normalize_request_target("*"), "*");
    }

    /// A method no rule covers must be refused, not forwarded. The
    /// credential is already substituted by the time the interceptor sees
    /// the bytes, so "forward it just once per connection" is one
    /// credentialed request the hook never saw — and the guest can open a
    /// connection per request.
    #[tokio::test]
    async fn unmatched_method_on_a_policed_host_is_refused() {
        let mut i = Interceptor::new(
            cfg(vec![InterceptRule {
                host: "api.github.com".into(),
                method: "GET".into(),
                path_prefix: "/".into(),
                dispatch_on_headers: false,
            }]),
            "api.github.com",
        );
        match i
            .process_chunk(b"HEAD /repos/victim/private HTTP/1.1\r\nHost: api.github.com\r\n\r\n")
            .await
            .unwrap()
        {
            Verdict::Intercept(resp) => {
                assert!(String::from_utf8_lossy(&resp).starts_with("HTTP/1.1 403"));
            }
            Verdict::Forward | Verdict::ForwardBuffered(_) => {
                panic!("unmatched request on a policed host was forwarded with credentials")
            }
            Verdict::Hold => panic!("expected a refusal"),
        }
    }

    /// An unpoliced SNI keeps the zero-copy fast path — long-lived
    /// streaming connections to agent APIs must not start buffering.
    #[tokio::test]
    async fn unpoliced_sni_keeps_the_zero_copy_fast_path() {
        let mut i = Interceptor::new(
            cfg(vec![InterceptRule {
                host: "api.github.com".into(),
                method: "GET".into(),
                path_prefix: "/".into(),
                dispatch_on_headers: false,
            }]),
            "api.anthropic.com",
        );
        assert!(matches!(
            i.process_chunk(b"P").await.unwrap(),
            Verdict::Forward
        ));
        assert!(matches!(
            i.process_chunk(b"OST /v1/messages HTTP/1.1\r\n\r\n")
                .await
                .unwrap(),
            Verdict::Forward
        ));
    }

    #[tokio::test]
    async fn buffers_split_request_then_dispatches() {
        let mut i = Interceptor::new(
            cfg(vec![InterceptRule {
                host: "platform.claude.com".into(),
                method: "POST".into(),
                path_prefix: "/v1/oauth/token".into(),
                dispatch_on_headers: false,
            }]),
            "platform.claude.com",
        );
        let chunk1 = b"POST /v1/oauth/token HTTP/1.1\r\nHost: platform.claude.com\r\n";
        let chunk2 = b"Content-Length: 10\r\n\r\n";
        let chunk3 = b"0123456789";
        assert!(matches!(
            i.process_chunk(chunk1).await.unwrap(),
            Verdict::Hold
        ));
        assert!(matches!(
            i.process_chunk(chunk2).await.unwrap(),
            Verdict::Hold
        ));
        // Hook is /bin/cat, so stdout is the request → modified passthrough.
        // The body must have been reassembled across all three chunks
        // before the hook saw it.
        match i.process_chunk(chunk3).await.unwrap() {
            Verdict::ForwardBuffered(req) => {
                assert!(String::from_utf8_lossy(&req).ends_with("0123456789"));
            }
            _ => panic!("expected ForwardBuffered (hook echoed the request back)"),
        }
    }

    /// Documents the `Disabled` → `Forward` behavior described on
    /// `process_chunk`'s `Disabled` arm: once a refusal or hook dispatch has
    /// happened, a *hypothetical* further chunk on the same `Interceptor`
    /// would forward unchanged. This is only safe because the seam's relay
    /// never actually feeds another chunk after `Verdict::Intercept` — see
    /// `tls::proxy::tests::intercept_extension_refuses_unmatched_request_and_writes_nothing_upstream`
    /// in `tls/proxy.rs` for the integration-level half of this guarantee.
    #[tokio::test]
    async fn disabled_state_forwards_a_hypothetical_further_chunk() {
        let mut i = Interceptor::new(
            cfg(vec![InterceptRule {
                host: "api.github.com".into(),
                method: "GET".into(),
                path_prefix: "/".into(),
                dispatch_on_headers: false,
            }]),
            "api.github.com",
        );
        let refusal = i
            .process_chunk(b"HEAD / HTTP/1.1\r\nHost: api.github.com\r\n\r\n")
            .await
            .unwrap();
        assert!(matches!(refusal, Verdict::Intercept(_)));

        let after = i.process_chunk(b"anything").await.unwrap();
        assert!(
            matches!(after, Verdict::Forward),
            "Disabled forwards further chunks in-process; the relay must never supply one"
        );
    }
}
