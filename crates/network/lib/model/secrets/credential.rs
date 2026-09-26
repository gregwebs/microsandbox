//! Internal launch-wire header credentials.
//!
//! These carry resolved plaintext and exist only in memory. The SDK builds them
//! from the durable [`DurableHeaderCredential`] definitions at spawn time,
//! serializes them only onto the private launch-config fd, and the network
//! engine holds them for the sandbox's lifetime. They are never part of a
//! durable [`SecretsConfig`](microsandbox_types::SecretsConfig),
//! `SandboxConfig`, the sandbox database, argv, or a log line.

use microsandbox_types::{
    DurableHeaderCredential, MAX_HEADER_CREDENTIAL_VALUE_BYTES, SecretConfigError, SecretString,
};
use serde::{Deserialize, Serialize};

//--------------------------------------------------------------------------------------------------
// Types
//--------------------------------------------------------------------------------------------------

/// Why a resolved header-credential value could not be rendered into a header.
///
/// Every variant is value-free: it never carries the resolved plaintext, a
/// prefix or suffix of it, or a hash of it, and it never carries its length.
/// The byte cap is the only size disclosed, because the rendered length (or the
/// value length) would leak how long the secret is. A caller must fail closed
/// (block the request) on any variant; it may log the non-secret credential
/// `id` alongside the error to make the diagnosis actionable.
#[derive(Debug, Clone, PartialEq, Eq, thiserror::Error)]
pub enum HeaderCredentialRenderError {
    /// The resolved value was empty.
    #[error("resolved header credential value is empty")]
    EmptyValue,

    /// The resolved value, or the rendered `format`+value result, contains a
    /// byte that cannot appear in an HTTP field value: CR, LF, NUL, or any
    /// other non-printable byte.
    #[error(
        "resolved header credential value contains an unsafe byte (CR, LF, NUL, or non-printable)"
    )]
    UnsafeValue,

    /// The rendered `format`+value result exceeds the supported byte cap.
    ///
    /// The observed length is deliberately not disclosed: the rendered length
    /// is a proxy for the secret's length, which is itself worth not leaking.
    #[error("rendered header credential value exceeds the maximum of {max_bytes} bytes")]
    RenderedTooLong {
        /// Maximum permitted rendered header-value length in bytes.
        max_bytes: usize,
    },
}

/// A header credential whose value has been resolved for this launch.
///
/// Carried only on the private launch-config FD and held in engine memory. The
/// authorization metadata is duplicated from the durable definition so the
/// engine can decide eligibility without a second lookup; the `value` is the
/// only secret and is wiped on drop. The `id`, `origin_host`, `origin_port`,
/// `header`, and `format` fields are persisted in cleartext in the durable
/// config (which is what makes them non-secret), so they print normally in
/// `Debug`; only [`SecretString`] redacts itself.
#[doc(hidden)]
#[derive(Clone, Serialize, Deserialize, Debug)]
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
    /// The resolved plaintext, wiped on drop and redacted by `SecretString`.
    pub value: SecretString,
}

//--------------------------------------------------------------------------------------------------
// Methods
//--------------------------------------------------------------------------------------------------

impl ResolvedHeaderCredential {
    /// Build a resolved credential from a durable definition and a value.
    pub fn from_definition(def: &DurableHeaderCredential, value: impl Into<SecretString>) -> Self {
        Self {
            id: def.id.clone(),
            origin_host: def.origin.host.clone(),
            origin_port: def.origin.port,
            header: def.header.clone(),
            format: def.format.clone(),
            value: value.into(),
        }
    }

    /// Render the header value by replacing `%s` with the resolved secret.
    ///
    /// Fails with a value-free [`HeaderCredentialRenderError`] when the value is
    /// empty, the value or the rendered result contains an unsafe byte (CR, LF,
    /// NUL, or any non-printable byte), or the rendered result exceeds the byte
    /// cap. A caller must fail closed (block the connection) on any error.
    pub fn render(&self) -> Result<SecretString, HeaderCredentialRenderError> {
        let value = self.value.expose_secret();
        if value.is_empty() {
            return Err(HeaderCredentialRenderError::EmptyValue);
        }
        if !is_printable_ascii(value) {
            return Err(HeaderCredentialRenderError::UnsafeValue);
        }
        let rendered = self.format.replacen("%s", value, 1);
        if rendered.len() > MAX_HEADER_CREDENTIAL_VALUE_BYTES {
            return Err(HeaderCredentialRenderError::RenderedTooLong {
                max_bytes: MAX_HEADER_CREDENTIAL_VALUE_BYTES,
            });
        }
        // The definition's `format` is validated before launch, but fail closed
        // here too rather than emit an unsafe rendered header value.
        if !is_printable_ascii(&rendered) {
            return Err(HeaderCredentialRenderError::UnsafeValue);
        }
        Ok(SecretString::new(rendered))
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
        if !is_safe_credential_value(rule.value.expose_secret()) {
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
        && is_printable_ascii(value)
}

/// Whether every byte is printable ASCII (0x20..=0x7E). Empty is vacuously
/// true; the emptiness check is the caller's responsibility.
fn is_printable_ascii(value: &str) -> bool {
    value.bytes().all(|b| (0x20..=0x7e).contains(&b))
}

//--------------------------------------------------------------------------------------------------
// Tests
//--------------------------------------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use microsandbox_types::HttpsOrigin;
    use zeroize::Zeroizing;

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
        assert_eq!(
            rule.render().unwrap().expose_secret(),
            "Token sk-secret; v=100%"
        );
    }

    #[test]
    fn render_rejects_empty_value_with_a_specific_error() {
        let rule = ResolvedHeaderCredential::from_definition(
            &definition("%s"),
            Zeroizing::new(String::new()),
        );
        assert_eq!(
            rule.render().unwrap_err(),
            HeaderCredentialRenderError::EmptyValue
        );
    }

    #[test]
    fn render_rejects_unsafe_values_with_a_specific_error() {
        for value in ["a\rb", "a\nb", "a\0b", "caf\u{e9}", "tab\there"] {
            let rule = ResolvedHeaderCredential::from_definition(
                &definition("%s"),
                Zeroizing::new(value.into()),
            );
            assert_eq!(
                rule.render().unwrap_err(),
                HeaderCredentialRenderError::UnsafeValue,
                "accepted unsafe value {value:?}"
            );
        }
    }

    #[test]
    fn render_rejects_over_long_result_without_disclosing_the_length() {
        let value = format!("SENTINEL{}", "a".repeat(MAX_HEADER_CREDENTIAL_VALUE_BYTES));
        let rule = ResolvedHeaderCredential::from_definition(
            &definition("Token %s"),
            Zeroizing::new(value),
        );
        let err = rule.render().unwrap_err();
        assert_eq!(
            err,
            HeaderCredentialRenderError::RenderedTooLong {
                max_bytes: MAX_HEADER_CREDENTIAL_VALUE_BYTES
            }
        );
        // The observed length and the value bytes must not leak through Debug
        // or Display. `max_bytes` (8192) is the cap and may appear; the
        // rendered length is one more digit and must not.
        let observed = MAX_HEADER_CREDENTIAL_VALUE_BYTES + "Token ".len() + "SENTINEL".len();
        let rendered = format!("{err} {err:?}");
        assert!(
            !rendered.contains(&observed.to_string()),
            "error disclosed the observed length: {rendered}"
        );
        assert!(
            !rendered.contains("SENTINEL"),
            "error leaked value bytes: {rendered}"
        );
    }

    #[test]
    fn render_rejects_unsafe_format_before_injection() {
        // A format with an embedded CR is rejected at definition validation, but
        // render must fail closed even if one slips through.
        let rule = ResolvedHeaderCredential {
            format: "%s\rX-Evil: 1".into(),
            ..ResolvedHeaderCredential::from_definition(
                &definition("%s"),
                Zeroizing::new("sk-secret".into()),
            )
        };
        assert_eq!(
            rule.render().unwrap_err(),
            HeaderCredentialRenderError::UnsafeValue
        );
    }

    /// The redaction is a property of `SecretString`, not of this struct: the
    /// value never prints, while the non-secret metadata (persisted in cleartext
    /// in the durable config) does, so an operator can tell which credential
    /// failed.
    #[test]
    fn debug_redacts_only_the_value() {
        let rule = ResolvedHeaderCredential::from_definition(
            &definition("Token %s"),
            Zeroizing::new("SENTINEL-value".into()),
        );
        let rendered = format!("{rule:?}");
        assert!(!rendered.contains("SENTINEL"), "{rendered}");
        assert!(rendered.contains("[REDACTED]"), "{rendered}");
        assert!(rendered.contains("anthropic"), "{rendered}");
        assert!(rendered.contains("api.anthropic.com"), "{rendered}");
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
