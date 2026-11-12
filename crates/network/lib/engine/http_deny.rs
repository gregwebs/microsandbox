//! HTTP/HTTPS bodies returned to the guest when egress is denied.
//!
//! Policy still closes the upstream path. For HTTP and intercepted HTTPS the
//! proxy answers the guest with `403 Forbidden` so clients surface a readable
//! error instead of a bare connection reset.
//!
//! A secret-policy denial states the refused credential, where its placeholder was and why it was
//! refused, followed by the embedder's own message.

use std::sync::Arc;

use microsandbox_types::{PlaceholderLocation, SecretRefusalReason};
use serde_json::json;

use crate::secrets::config::HostPattern;

//--------------------------------------------------------------------------------------------------
// Constants
//--------------------------------------------------------------------------------------------------

/// Placeholder replaced with the blocked hostname in deny templates.
pub const HOST_PLACEHOLDER: &str = "{host}";

/// Default body shown to HTTP/HTTPS clients for a denied host.
pub const DEFAULT_HTTP_DENY_MESSAGE: &str = "\
This host is not allowed by the sandbox network policy config.\n\
\n\
Note to agent: `{host}` is not in the allowed-host list. \
Ask the user to add it to the sandbox network allow list.\n";

/// Default JSON network-denial message.
pub const NETWORK_JSON_DENY_MESSAGE: &str = "Request blocked by network policy.";

/// Hosts a host-not-covered sentence names before it counts the rest.
const LISTED_HOSTS: usize = 3;

//--------------------------------------------------------------------------------------------------
// Types
//--------------------------------------------------------------------------------------------------

/// Why a secret cannot serve a request on this connection, with what its sentence needs.
#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) enum SecretDenialCause {
    /// The destination is not among the hosts the secret is substituted for.
    HostNotCovered {
        /// Every host the placeholder is substituted for, over all its declarations, in
        /// configured order. Shared by the declarations of one placeholder on a connection.
        substituted_for: Arc<[HostPattern]>,
    },

    /// The secret's file-backed value could not be read.
    CredentialUnavailable,

    /// The destination's identity could not be bound to a host the secret serves.
    DestinationUnverified,
}

/// One refused placeholder, as the guest's 403 states it. Holds no secret value.
pub(crate) struct SecretDenial<'a> {
    /// Environment variable name of the refused secret, or `None` when the name itself carries a
    /// placeholder and so cannot be stated (R4).
    pub(crate) credential: Option<&'a str>,
    /// Where the placeholder was found.
    pub(crate) location: PlaceholderLocation,
    /// Why the secret could not serve the request.
    pub(crate) cause: &'a SecretDenialCause,
}

//--------------------------------------------------------------------------------------------------
// Methods
//--------------------------------------------------------------------------------------------------

impl SecretDenialCause {
    /// The reason this cause is reported as.
    pub(crate) fn reason(&self) -> SecretRefusalReason {
        match self {
            Self::HostNotCovered { .. } => SecretRefusalReason::HostNotCovered,
            Self::CredentialUnavailable => SecretRefusalReason::CredentialUnavailable,
            Self::DestinationUnverified => SecretRefusalReason::DestinationUnverified,
        }
    }
}

//--------------------------------------------------------------------------------------------------
// Functions
//--------------------------------------------------------------------------------------------------

/// Classify a denied first flight as HTTP/1.x, another protocol, or incomplete.
/// A method prefix alone is not enough to choose a response protocol.
pub(crate) fn classify_http_request(buf: &[u8]) -> Option<bool> {
    let mut line = buf;

    while let Some(rest) = line.strip_prefix(b"\r\n") {
        line = rest;
    }
    if line.is_empty() || line == b"\r" {
        return None;
    }
    if !line[0].is_ascii_alphabetic() {
        return Some(false);
    }

    let Some(end) = line.windows(2).position(|pair| pair == b"\r\n") else {
        return line
            .iter()
            .any(|byte| !byte.is_ascii() || (*byte < b' ' && *byte != b'\r'))
            .then_some(false);
    };

    let mut headers = [];
    let mut request = httparse::Request::new(&mut headers);
    let parsed = request.parse(&line[..end + 2]);
    let is_http1 = parsed.is_ok()
        && matches!(request.version, Some(0 | 1))
        && request.method.is_some()
        && request.path.is_some();

    Some(is_http1)
}

/// Render a deny-message template, substituting [`HOST_PLACEHOLDER`].
pub fn render_http_deny_message(template: &str, host: &str) -> String {
    let host = host.trim();
    let host = if host.is_empty() { "this host" } else { host };
    template.replace(HOST_PLACEHOLDER, host)
}

/// Build a close-delimited HTTP/1.1 403 response for `body`.
pub fn http_forbidden_response(body: &str) -> Vec<u8> {
    let body = body.as_bytes();
    let mut response = Vec::with_capacity(128 + body.len());
    response.extend_from_slice(b"HTTP/1.1 403 Forbidden\r\n");
    response.extend_from_slice(b"Content-Type: text/plain; charset=utf-8\r\n");
    response.extend_from_slice(b"Connection: close\r\n");
    response.extend_from_slice(b"Cache-Control: no-store\r\n");
    response.extend_from_slice(format!("Content-Length: {}\r\n\r\n", body.len()).as_bytes());
    response.extend_from_slice(body);
    response
}

/// Build an HTTP/1.1 403 with a stable network-policy code and JSON message and requested domain.
pub fn json_http_forbidden_response(message: &str, host: &str) -> Vec<u8> {
    let domain = (!host.is_empty()).then_some(host);

    json_forbidden_response(
        &json!({ "code": "network_policy_denied", "message": message, "domain": domain }),
    )
}

/// Build an HTTP/1.1 403 for a refused secret placeholder: the facts sentence, then `remedy`
/// when it is non-empty, and the value-free `credential`, `location` and `reason` fields.
pub(crate) fn secret_http_forbidden_response(
    denial: &SecretDenial<'_>,
    host: &str,
    remedy: Option<&str>,
) -> Vec<u8> {
    let message = secret_denial_message(denial, host, remedy);
    let domain = (!host.is_empty()).then_some(host);

    // Serialize as a map so `credential` is absent, not null, when it cannot be stated.
    let mut error = serde_json::Map::new();
    error.insert("code".into(), json!("secret_policy_denied"));
    error.insert("message".into(), json!(message));
    error.insert("domain".into(), json!(domain));
    if let Some(credential) = denial.credential {
        error.insert("credential".into(), json!(credential));
    }
    error.insert("location".into(), json!(denial.location));
    error.insert("reason".into(), json!(denial.cause.reason()));

    json_forbidden_response(&serde_json::Value::Object(error))
}

fn json_forbidden_response(error: &serde_json::Value) -> Vec<u8> {
    // Serialize custom messages so quotes, control characters and Unicode
    // remain message content rather than changing the error envelope.
    let json = error.to_string();
    let body = json.as_bytes();
    let mut response = Vec::with_capacity(128 + body.len());
    response.extend_from_slice(b"HTTP/1.1 403 Forbidden\r\n");
    response.extend_from_slice(b"Content-Type: application/json\r\n");
    response.extend_from_slice(b"Connection: close\r\n");
    response.extend_from_slice(b"Cache-Control: no-store\r\n");
    response.extend_from_slice(format!("Content-Length: {}\r\n\r\n", body.len()).as_bytes());
    response.extend_from_slice(body);
    response
}

/// The guest-visible `message`: one facts sentence, then the embedder's remedy verbatim.
fn secret_denial_message(denial: &SecretDenial<'_>, host: &str, remedy: Option<&str>) -> String {
    let host = if host.is_empty() { "this host" } else { host };
    let credential = denial.credential.unwrap_or("a credential");
    let location = denial.location.phrase();

    let mut message = match denial.cause {
        SecretDenialCause::HostNotCovered { substituted_for } => format!(
            "Blocked: {credential} was sent in {location} to {host}; it is substituted only for {}.",
            substituted_hosts(substituted_for)
        ),
        SecretDenialCause::CredentialUnavailable => format!(
            "Blocked: {credential} was sent in {location} to {host}, but the sandbox could not read its real value."
        ),
        SecretDenialCause::DestinationUnverified => format!(
            "Blocked: {credential} was sent in {location} to {host}, whose identity could not be verified."
        ),
    };

    // The remedy is the embedder's text: appended as configured, never interpolated.
    if let Some(remedy) = remedy.filter(|remedy| !remedy.is_empty()) {
        message.push(' ');
        message.push_str(remedy);
    }

    message
}

/// The hosts a secret is substituted for, as a short English list.
///
/// Repeats are already removed where the list is built, ASCII case-insensitively, so this only
/// renders.
fn substituted_hosts(patterns: &[HostPattern]) -> String {
    let hosts: Vec<&str> = patterns
        .iter()
        .map(|pattern| match pattern {
            HostPattern::Exact(host) | HostPattern::Wildcard(host) => host.as_str(),
            HostPattern::Any => "any host",
        })
        .collect();

    match hosts.as_slice() {
        // Unreachable for a validated config, which requires an allowed host.
        [] => "no host".to_owned(),
        [only] => (*only).to_owned(),
        [listed @ .., last] if hosts.len() <= LISTED_HOSTS => {
            format!("{} and {last}", listed.join(", "))
        }
        _ => format!(
            "{} and {} more",
            hosts[..LISTED_HOSTS].join(", "),
            hosts.len() - LISTED_HOSTS
        ),
    }
}

//--------------------------------------------------------------------------------------------------
// Tests
//--------------------------------------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use microsandbox_types::{PlaceholderLocation, SecretRefusalReason};

    use super::{
        HostPattern, SecretDenial, SecretDenialCause, classify_http_request,
        json_http_forbidden_response, secret_denial_message, secret_http_forbidden_response,
        substituted_hosts,
    };

    /// The value-free facts every fixture states, so a leak would be obvious.
    const CREDENTIAL: &str = "MSB_AGENT_VM_ANTHROPIC_UNUSED";
    const HOST: &str = "api.deepseek.com";

    fn host_not_covered(hosts: Vec<HostPattern>) -> SecretDenialCause {
        SecretDenialCause::HostNotCovered {
            substituted_for: hosts.into(),
        }
    }

    fn denial(cause: &SecretDenialCause) -> SecretDenial<'_> {
        SecretDenial {
            credential: Some(CREDENTIAL),
            location: PlaceholderLocation::Header,
            cause,
        }
    }

    fn body_of(response: &[u8]) -> serde_json::Value {
        let text = std::str::from_utf8(response).unwrap();
        let (headers, body) = text.split_once("\r\n\r\n").unwrap();
        let content_length: usize = headers
            .lines()
            .find_map(|line| line.strip_prefix("Content-Length: "))
            .unwrap()
            .parse()
            .unwrap();

        assert_eq!(content_length, body.len());
        serde_json::from_str(body).unwrap()
    }

    #[test]
    fn classification_requires_a_complete_http1_request_line() {
        for request in [
            b"GET / HTTP/1.1\r\n".as_slice(),
            b"QUERY / HTTP/1.0\r\n",
            b"\r\nGET / HTTP/1.1\r\n",
        ] {
            for end in 0..request.len() {
                assert_eq!(
                    classify_http_request(&request[..end]),
                    None,
                    "prefix: {:?}",
                    &request[..end]
                );
            }
            assert_eq!(classify_http_request(request), Some(true));
        }
        for request in [
            b"PRI * HTTP/2.0\r\n\r\nSM\r\n\r\n".as_slice(),
            b"SSH-2.0-OpenSSH\r\n",
            b"EHLO mail.example\r\n",
            b"GET file\r\n",
            b"GET / HTTP/3.0\r\n",
            b"\x16\x03\x01",
            b"\x00binary",
        ] {
            assert_eq!(
                classify_http_request(request),
                Some(false),
                "request: {request:?}"
            );
        }
    }

    #[test]
    fn network_denial_bytes_are_unchanged() {
        // The f8155130 output, byte for byte: an added envelope field or a reordered key would
        // change what every embedder's network denials read.
        assert_eq!(
            json_http_forbidden_response("nope", "example.com"),
            b"HTTP/1.1 403 Forbidden\r\nContent-Type: application/json\r\nConnection: close\r\nCache-Control: no-store\r\nContent-Length: 72\r\n\r\n{\"code\":\"network_policy_denied\",\"domain\":\"example.com\",\"message\":\"nope\"}"
                .to_vec()
        );
    }

    #[test]
    fn secret_denial_states_one_facts_sentence_per_reason() {
        for (cause, expected) in [
            (
                host_not_covered(vec![HostPattern::Exact("api.anthropic.com".into())]),
                "Blocked: MSB_AGENT_VM_ANTHROPIC_UNUSED was sent in a request header to api.deepseek.com; it is substituted only for api.anthropic.com.",
            ),
            (
                SecretDenialCause::CredentialUnavailable,
                "Blocked: MSB_AGENT_VM_ANTHROPIC_UNUSED was sent in a request header to api.deepseek.com, but the sandbox could not read its real value.",
            ),
            (
                SecretDenialCause::DestinationUnverified,
                "Blocked: MSB_AGENT_VM_ANTHROPIC_UNUSED was sent in a request header to api.deepseek.com, whose identity could not be verified.",
            ),
        ] {
            assert_eq!(secret_denial_message(&denial(&cause), HOST, None), expected);
        }
    }

    #[test]
    fn remedy_is_appended_verbatim() {
        let cause = host_not_covered(vec![HostPattern::Exact("api.anthropic.com".into())]);
        let facts = "Blocked: MSB_AGENT_VM_ANTHROPIC_UNUSED was sent in a request header to api.deepseek.com; it is substituted only for api.anthropic.com.";

        // A remedy is the embedder's text: appended after one space, never interpolated.
        assert_eq!(
            secret_denial_message(&denial(&cause), HOST, Some("Check {host}.")),
            format!("{facts} Check {{host}}.")
        );
        assert_eq!(
            secret_denial_message(&denial(&cause), HOST, Some("")),
            facts
        );
        assert_eq!(secret_denial_message(&denial(&cause), HOST, None), facts);

        // The ticket's worked example, with agent-vm's remedy in place.
        let remedy = "This is agent-vm credential policy: signing in again inside the sandbox will not fix it. Run `agent-vm access` outside the sandbox.";
        let hosts = vec![
            HostPattern::Exact("api.anthropic.com".into()),
            HostPattern::Exact("platform.claude.com".into()),
            HostPattern::Exact("mcp-proxy.anthropic.com".into()),
        ];
        let cause = host_not_covered(hosts);

        assert_eq!(
            secret_denial_message(&denial(&cause), HOST, Some(remedy)),
            format!(
                "Blocked: MSB_AGENT_VM_ANTHROPIC_UNUSED was sent in a request header to \
                 api.deepseek.com; it is substituted only for api.anthropic.com, \
                 platform.claude.com and mcp-proxy.anthropic.com. {remedy}"
            )
        );
    }

    #[test]
    fn substituted_hosts_names_three_then_counts_the_rest() {
        // Repeats are removed where the list is built, so this pins the grammar only.
        for (hosts, expected) in [
            (vec!["api.a.com"], "api.a.com"),
            (vec!["api.a.com", "*.b.com"], "api.a.com and *.b.com"),
            (vec!["x", "y", "z"], "x, y and z"),
            (vec!["w", "x", "y", "z"], "w, x, y and 1 more"),
            (vec!["w", "x", "y", "z", "v"], "w, x, y and 2 more"),
        ] {
            let patterns: Vec<HostPattern> = hosts
                .into_iter()
                .map(|host| {
                    if host.starts_with("*.") {
                        HostPattern::Wildcard(host.to_owned())
                    } else {
                        HostPattern::Exact(host.to_owned())
                    }
                })
                .collect();

            assert_eq!(substituted_hosts(&patterns), expected, "{patterns:?}");
        }

        assert_eq!(substituted_hosts(&[HostPattern::Any]), "any host");
    }

    #[test]
    fn every_location_reads_as_its_phrase_in_the_sentence() {
        let cause = SecretDenialCause::DestinationUnverified;

        for (location, phrase) in [
            (PlaceholderLocation::Header, "a request header"),
            (PlaceholderLocation::BasicAuth, "a Basic auth header"),
            (PlaceholderLocation::Trailer, "a request trailer"),
            (PlaceholderLocation::Query, "the query string"),
            (PlaceholderLocation::Unknown, "the request line"),
            (PlaceholderLocation::Body, "the request body"),
            (PlaceholderLocation::ChunkMetadata, "chunk metadata"),
        ] {
            let denial = SecretDenial {
                credential: Some(CREDENTIAL),
                location,
                cause: &cause,
            };

            assert_eq!(
                secret_denial_message(&denial, HOST, None),
                format!(
                    "Blocked: {CREDENTIAL} was sent in {phrase} to {HOST}, whose identity could not be verified."
                )
            );
        }
    }

    #[test]
    fn secret_forbidden_response_carries_value_free_fields() {
        let cause = host_not_covered(vec![HostPattern::Exact("api.anthropic.com".into())]);
        let response = secret_http_forbidden_response(&denial(&cause), HOST, None);
        let error = body_of(&response);

        let keys: Vec<&str> = error
            .as_object()
            .unwrap()
            .keys()
            .map(String::as_str)
            .collect();
        assert_eq!(
            keys,
            [
                "code",
                "credential",
                "domain",
                "location",
                "message",
                "reason"
            ]
        );
        assert_eq!(error["code"], "secret_policy_denied");
        assert_eq!(error["credential"], CREDENTIAL);
        assert_eq!(error["domain"], HOST);
        assert_eq!(error["location"], "header");
        assert_eq!(error["reason"], "host-not-covered");

        // No name: the sentence says `this host` and `domain` stays null.
        let no_name = secret_http_forbidden_response(
            &SecretDenial {
                credential: Some(CREDENTIAL),
                location: PlaceholderLocation::Header,
                cause: &SecretDenialCause::DestinationUnverified,
            },
            "",
            Some("Remedy."),
        );
        let error = body_of(&no_name);
        assert_eq!(error["domain"], serde_json::Value::Null);
        assert_eq!(
            error["message"],
            format!(
                "Blocked: {CREDENTIAL} was sent in a request header to this host, whose identity could not be verified. Remedy."
            )
        );

        // A remedy stays message content: quotes, a backslash, a control character and Unicode are
        // JSON-escaped by the serializer rather than changing the envelope.
        let awkward = "Use \"api.deepseek.com\": C:\\policy\n雪\t\u{0000}";
        let response = secret_http_forbidden_response(&denial(&cause), HOST, Some(awkward));
        let error = body_of(&response);
        assert_eq!(
            error["reason"],
            SecretRefusalReason::HostNotCovered.as_str()
        );
        assert!(error["message"].as_str().unwrap().ends_with(awkward));
    }

    #[test]
    fn forbidden_response_is_http11_with_a_json_error() {
        for (message, host, expected_domain) in [
            ("nope\n", "example.com", Some("example.com")),
            ("", "", None),
            (
                "blocked \"example.com\": use C:\\policy\n雪\t\u{0000}",
                "example.com",
                Some("example.com"),
            ),
        ] {
            let response = json_http_forbidden_response(message, host);
            let text = std::str::from_utf8(&response).unwrap();
            let (headers, body) = text.split_once("\r\n\r\n").unwrap();
            assert!(headers.starts_with("HTTP/1.1 403 Forbidden\r\n"));
            assert!(headers.contains("Content-Type: application/json\r\n"));
            assert!(headers.contains("Connection: close\r\n"));
            let error: serde_json::Value = serde_json::from_str(body).unwrap();
            assert_eq!(error["code"], "network_policy_denied");
            assert_eq!(error["message"], message);
            assert_eq!(error["domain"], serde_json::json!(expected_domain));
            let content_length: usize = headers
                .lines()
                .find_map(|line| line.strip_prefix("Content-Length: "))
                .unwrap()
                .parse()
                .unwrap();
            assert_eq!(content_length, body.len());
        }
    }
}
