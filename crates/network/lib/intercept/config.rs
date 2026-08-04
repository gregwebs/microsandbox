//! Serializable interceptor configuration.

use serde::{Deserialize, Serialize};

/// Configuration for the request-interceptor hook.
///
/// `rules` are checked against each new TLS-intercepted connection's
/// first decrypted plaintext bytes (the HTTP request line + Host /
/// :authority header). On a match the connection switches to "buffer
/// until the request body is fully received, then hand it to `hook`."
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct InterceptConfig {
    /// Routes to intercept. Empty disables the interceptor entirely.
    #[serde(default)]
    pub rules: Vec<InterceptRule>,

    /// Subprocess command + args to invoke for matched requests.
    /// `None` is equivalent to an empty `rules` list.
    #[serde(default)]
    pub hook: Option<Vec<String>>,

    /// Maximum bytes to buffer per intercepted request before giving
    /// up. Refresh-token requests are tiny (~1 KB); 64 KiB is a roomy
    /// ceiling and a hard backstop against a misbehaving client.
    #[serde(default = "default_max_request_bytes")]
    pub max_request_bytes: usize,
}

/// One match rule. All fields must match for the rule to fire.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct InterceptRule {
    /// SNI host. Exact match (case-insensitive).
    pub host: String,
    /// HTTP method. Exact match (case-sensitive — HTTP methods are
    /// uppercase per RFC 9110).
    pub method: String,
    /// Path prefix match. The path portion of the request line
    /// (no query string) must start with this string.
    pub path_prefix: String,
    /// If true, dispatch the hook as soon as the request **headers**
    /// are buffered — do NOT wait for the body. Used for path-based
    /// allow-list / deny-list decisions where the body is irrelevant
    /// (or too large to fit in `max_request_bytes`, e.g. git push
    /// pack data).
    ///
    /// The hook signals its decision via the **size** of its stdout:
    /// - **Empty stdout** (zero bytes): passthrough. The proxy
    ///   flushes the buffered prefix to the upstream server and
    ///   continues streaming subsequent chunks unchanged (still
    ///   subject to the network secret-substitution layer).
    /// - **Non-empty stdout**: same as the normal Intercept verdict
    ///   — the bytes are returned to the guest as the synthesized
    ///   HTTP response and the connection closes.
    ///
    /// Default `false` preserves the original semantics (wait for
    /// full body before invoking the hook).
    #[serde(default)]
    pub dispatch_on_headers: bool,
}

fn default_max_request_bytes() -> usize {
    64 * 1024
}

/// Hand-written so `max_request_bytes` matches the serde default.
/// `#[derive(Default)]` would zero it — serde's `default = "…"` only
/// fills the field when it is *missing* from the input, so a config
/// built through [`InterceptBuilder`](crate::builder::InterceptBuilder)
/// (which starts from `Default`) carried a 0 cap, and every request
/// large enough to span two chunks blew past it on the first one.
///
/// [`InterceptBuilder`]: crate::builder::InterceptBuilder
impl Default for InterceptConfig {
    fn default() -> Self {
        Self {
            rules: Vec::new(),
            hook: None,
            max_request_bytes: default_max_request_bytes(),
        }
    }
}

impl InterceptConfig {
    /// Active = at least one rule and a hook command.
    pub fn is_active(&self) -> bool {
        !self.rules.is_empty() && self.hook.is_some()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    /// The builder path starts from `Default`; if that leaves the cap
    /// at 0 every buffered request overflows immediately.
    #[test]
    fn default_cap_matches_serde_default() {
        assert_eq!(
            InterceptConfig::default().max_request_bytes,
            default_max_request_bytes()
        );
        let from_json: InterceptConfig = serde_json::from_str("{}").unwrap();
        assert_eq!(
            from_json.max_request_bytes,
            InterceptConfig::default().max_request_bytes
        );
        // A config that has been through a serialize/deserialize round
        // trip (as it is on the way to the sandbox) keeps the cap.
        let round_tripped: InterceptConfig =
            serde_json::from_value(serde_json::to_value(InterceptConfig::default()).unwrap())
                .unwrap();
        assert_eq!(round_tripped.max_request_bytes, default_max_request_bytes());
    }
}
