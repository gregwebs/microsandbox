//! Request-interceptor configuration types.
//!
//! The data types ([`InterceptConfig`], [`InterceptRule`]) and their
//! `is_active` rule live in the shared `microsandbox-types` crate so the
//! SDK, the CLI, and this engine all speak one contract. This module
//! re-exports them for engine-internal callers.

pub use microsandbox_types::{InterceptConfig, InterceptRule};

//--------------------------------------------------------------------------------------------------
// Tests
//--------------------------------------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use super::*;

    /// The builder path starts from `Default`; if that leaves the cap at 0,
    /// every buffered request overflows immediately. Ported from the fork's
    /// `intercept/config.rs` regression test.
    #[test]
    fn default_cap_matches_serde_default() {
        let default_cap = InterceptConfig::default().max_request_bytes;
        assert_ne!(default_cap, 0);

        let from_json: InterceptConfig = serde_json::from_str("{}").unwrap();
        assert_eq!(from_json.max_request_bytes, default_cap);

        // A config that has been through a serialize/deserialize round trip
        // (as it is on the way to the sandbox) keeps the cap.
        let round_tripped: InterceptConfig =
            serde_json::from_value(serde_json::to_value(InterceptConfig::default()).unwrap())
                .unwrap();
        assert_eq!(round_tripped.max_request_bytes, default_cap);
    }

    #[test]
    fn is_active_requires_both_rules_and_hook() {
        assert!(!InterceptConfig::default().is_active());

        let rule = InterceptRule {
            host: "api.github.com".into(),
            method: "GET".into(),
            path_prefix: "/".into(),
            dispatch_on_headers: false,
        };

        assert!(
            !InterceptConfig {
                rules: vec![rule.clone()],
                hook: None,
                ..InterceptConfig::default()
            }
            .is_active()
        );
        assert!(
            !InterceptConfig {
                rules: Vec::new(),
                hook: Some(vec!["/bin/cat".into()]),
                ..InterceptConfig::default()
            }
            .is_active()
        );
        assert!(
            InterceptConfig {
                rules: vec![rule],
                hook: Some(vec!["/bin/cat".into()]),
                ..InterceptConfig::default()
            }
            .is_active()
        );
    }
}
