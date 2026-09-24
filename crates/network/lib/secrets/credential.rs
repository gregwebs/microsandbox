//! Internal launch-wire header credentials.
//!
//! These carry resolved plaintext and exist only in memory. The SDK builds them
//! from the durable [`DurableHeaderCredential`] definitions at spawn time,
//! serializes them only onto the private launch-config fd, and the network
//! engine holds them for the sandbox's lifetime. They are never part of a
//! durable [`SecretsConfig`](microsandbox_types::SecretsConfig),
//! `SandboxConfig`, the sandbox database, argv, or a log line.

use std::fmt;

use microsandbox_types::{
    DurableHeaderCredential, MAX_HEADER_CREDENTIAL_VALUE_BYTES, SecretConfigError,
};
use serde::{Deserialize, Serialize};
use zeroize::Zeroizing;

//--------------------------------------------------------------------------------------------------
// Types
//--------------------------------------------------------------------------------------------------

/// A header credential whose value has been resolved for this launch.
///
/// Carried only on the private launch-config FD and held in engine memory. The
/// authorization metadata is duplicated from the durable definition so the
/// engine can decide eligibility without a second lookup; the `value` is the
/// only secret and is wiped on drop.
#[doc(hidden)]
#[derive(Clone, Serialize, Deserialize)]
pub struct ResolvedHeaderCredential {
    /// Non-secret diagnostic label (duplicated from the durable definition).
    pub id: String,
    /// Authorized origin host (duplicated from the durable definition).
    pub origin_host: String,
    /// Authorized origin port (duplicated from the durable definition).
    pub origin_port: u16,
    /// Lowercase header name to set.
    pub header: String,
    /// Value template with exactly one `%s`.
    pub format: String,
    /// The resolved plaintext, wiped on drop.
    pub value: Zeroizing<String>,
}

//--------------------------------------------------------------------------------------------------
// Methods
//--------------------------------------------------------------------------------------------------

impl ResolvedHeaderCredential {
    /// Build a resolved credential from a durable definition and a value.
    pub fn from_definition(def: &DurableHeaderCredential, value: Zeroizing<String>) -> Self {
        Self {
            id: def.id.clone(),
            origin_host: def.origin.host.clone(),
            origin_port: def.origin.port,
            header: def.header.clone(),
            format: def.format.clone(),
            value,
        }
    }

    /// Render the header value by replacing `%s` with the resolved secret.
    ///
    /// Returns `None` when the value or the rendered result is empty, unsafe
    /// (contains CR/LF/NUL or a non-printable byte), or exceeds the byte cap.
    /// A caller must fail closed (block the connection) on `None`.
    pub fn render(&self) -> Option<Zeroizing<String>> {
        if !is_safe_credential_value(self.value.as_str()) {
            return None;
        }
        let rendered = self.format.replacen("%s", self.value.as_str(), 1);
        if rendered.len() > MAX_HEADER_CREDENTIAL_VALUE_BYTES
            || !is_safe_credential_value(rendered.as_str())
        {
            return None;
        }
        Some(Zeroizing::new(rendered))
    }
}

// The credential value and the caller-controlled metadata must never reach a
// log line or an error message; print fixed labels only.
impl fmt::Debug for ResolvedHeaderCredential {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("ResolvedHeaderCredential")
            .field("id", &"[REDACTED]")
            .field("origin_host", &"[REDACTED]")
            .field("origin_port", &"[REDACTED]")
            .field("header", &"[REDACTED]")
            .field("format", &"[REDACTED]")
            .field("value", &"[REDACTED]")
            .finish()
    }
}

//--------------------------------------------------------------------------------------------------
// Functions
//--------------------------------------------------------------------------------------------------

/// Validate a resolved credential list against its durable definitions.
///
/// Enforces a 1:1 mapping (same order) and a non-empty, safe, bounded value.
/// This cannot be satisfied by an unresolved definition, so it is a
/// runtime-only check distinct from [`microsandbox_types::SecretsConfig::validate`].
pub fn validate_resolved_header_credentials(
    definitions: &[DurableHeaderCredential],
    resolved: &[ResolvedHeaderCredential],
) -> Result<(), SecretConfigError> {
    if definitions.len() != resolved.len() {
        return Err(SecretConfigError::CredentialResolutionMismatch);
    }
    for (index, (def, rule)) in definitions.iter().zip(resolved.iter()).enumerate() {
        if def.id != rule.id
            || def.origin.host != rule.origin_host
            || def.origin.port != rule.origin_port
            || def.header != rule.header
            || def.format != rule.format
        {
            return Err(SecretConfigError::CredentialResolutionMismatch);
        }
        if !is_safe_credential_value(rule.value.as_str()) {
            return Err(SecretConfigError::CredentialValueInvalid {
                credential_index: index,
            });
        }
    }
    Ok(())
}

/// Whether a value is a non-empty run of printable ASCII (0x20..=0x7E) within
/// the byte cap. Rejects CR/LF/NUL and every non-printable byte.
pub(crate) fn is_safe_credential_value(value: &str) -> bool {
    !value.is_empty()
        && value.len() <= MAX_HEADER_CREDENTIAL_VALUE_BYTES
        && value.bytes().all(|b| (0x20..=0x7e).contains(&b))
}

//--------------------------------------------------------------------------------------------------
// Tests
//--------------------------------------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use microsandbox_types::HttpsOrigin;

    use super::*;

    fn definition(format: &str) -> DurableHeaderCredential {
        DurableHeaderCredential {
            id: "anthropic".into(),
            reference: "anthropic-api-key".into(),
            origin: HttpsOrigin {
                host: "api.anthropic.com".into(),
                port: 443,
            },
            header: "x-api-key".into(),
            format: format.into(),
        }
    }

    #[test]
    fn render_substitutes_single_placeholder() {
        let rule = ResolvedHeaderCredential::from_definition(
            &definition("Token %s; v=100%"),
            Zeroizing::new("sk-secret".into()),
        );
        assert_eq!(rule.render().unwrap().as_str(), "Token sk-secret; v=100%");
    }

    #[test]
    fn render_rejects_unsafe_values() {
        for value in ["", "a\rb", "a\nb", "a\0b", "caf\u{e9}"] {
            let rule = ResolvedHeaderCredential::from_definition(
                &definition("%s"),
                Zeroizing::new(value.into()),
            );
            assert!(rule.render().is_none(), "accepted unsafe value {value:?}");
        }
    }

    #[test]
    fn debug_never_prints_value_or_metadata() {
        let rule = ResolvedHeaderCredential::from_definition(
            &definition("Token %s"),
            Zeroizing::new("SENTINEL-value".into()),
        );
        let rendered = format!("{rule:?}");
        assert!(!rendered.contains("SENTINEL"), "{rendered}");
        assert!(!rendered.contains("anthropic"), "{rendered}");
    }

    #[test]
    fn validate_resolved_requires_one_to_one_mapping() {
        let defs = vec![definition("%s")];
        assert_eq!(
            validate_resolved_header_credentials(&defs, &[]).unwrap_err(),
            SecretConfigError::CredentialResolutionMismatch
        );

        let good = vec![ResolvedHeaderCredential::from_definition(
            &defs[0],
            Zeroizing::new("sk".into()),
        )];
        assert!(validate_resolved_header_credentials(&defs, &good).is_ok());

        let empty = vec![ResolvedHeaderCredential::from_definition(
            &defs[0],
            Zeroizing::new(String::new()),
        )];
        assert_eq!(
            validate_resolved_header_credentials(&defs, &empty).unwrap_err(),
            SecretConfigError::CredentialValueInvalid {
                credential_index: 0
            }
        );
    }
}
