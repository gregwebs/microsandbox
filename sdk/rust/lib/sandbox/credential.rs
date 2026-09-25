//! Host-side resolution of origin-scoped header-credential values.
//!
//! A durable [`DurableHeaderCredential`](microsandbox_types::DurableHeaderCredential)
//! carries only a non-secret `reference`. The embedding application supplies a
//! [`CredentialResolver`] in its own process; the SDK calls it immediately
//! before the sandbox process is forked, and the resolved value travels only on
//! the private launch-config fd. It never enters the durable config, the
//! sandbox database, argv, or a log line.

use zeroize::Zeroizing;

//--------------------------------------------------------------------------------------------------
// Types
//--------------------------------------------------------------------------------------------------

/// Resolves a non-secret credential reference into its value in the caller's
/// own process.
///
/// Implementations run synchronously on the host immediately before `fork`, so
/// they may read an OS keychain or another host-local store. The returned value
/// is moved into the private launch config and dropped after the spawn.
pub trait CredentialResolver: Send + Sync {
    /// Resolve `reference` into the corresponding secret value.
    ///
    /// Only [`CredentialResolveError`] crosses this boundary; an implementation
    /// must not surface provider text that could contain secret material.
    fn resolve(&self, reference: &str) -> Result<Zeroizing<String>, CredentialResolveError>;
}

/// A closed error kind returned by a [`CredentialResolver`].
///
/// Deliberately opaque and `Copy`: the embedding application's own error type
/// may embed sensitive material, so only a fixed category is propagated. Errors
/// surface to callers as an index-only
/// [`HeaderCredentialError`](crate::HeaderCredentialError).
#[derive(Debug, Clone, Copy, PartialEq, Eq, thiserror::Error)]
pub enum CredentialResolveError {
    /// The reference is unknown to this resolver.
    #[error("credential reference was not found")]
    NotFound,
    /// The reference is not authorized for this launch.
    #[error("credential reference was not authorized for this launch")]
    NotAuthorized,
    /// The value could not be read for some other reason.
    #[error("credential could not be resolved")]
    Failed,
}

//--------------------------------------------------------------------------------------------------
// Methods
//--------------------------------------------------------------------------------------------------

impl CredentialResolveError {
    /// The reference is unknown to this resolver.
    pub fn not_found() -> Self {
        Self::NotFound
    }

    /// The reference is not authorized for this launch.
    pub fn not_authorized() -> Self {
        Self::NotAuthorized
    }

    /// The value could not be read for some other reason.
    pub fn failed() -> Self {
        Self::Failed
    }
}

//--------------------------------------------------------------------------------------------------
// Tests
//--------------------------------------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use super::*;

    struct FixedResolver;

    impl CredentialResolver for FixedResolver {
        fn resolve(&self, reference: &str) -> Result<Zeroizing<String>, CredentialResolveError> {
            match reference {
                "known" => Ok(Zeroizing::new("value".into())),
                _ => Err(CredentialResolveError::not_found()),
            }
        }
    }

    #[test]
    fn resolver_returns_value_and_closed_error() {
        let resolver = FixedResolver;
        assert_eq!(resolver.resolve("known").unwrap().as_str(), "value");
        assert_eq!(
            resolver.resolve("missing").unwrap_err(),
            CredentialResolveError::NotFound
        );
    }
}
