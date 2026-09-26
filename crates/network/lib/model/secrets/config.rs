//! Secret substitution configuration types.
//!
//! The data types ([`SecretsConfig`], [`SecretEntry`], [`HostPattern`],
//! [`SecretSubstitution`], [`SecretViolationAction`]) and their validation live in the
//! shared `microsandbox-types` crate so the cloud control plane, the SDKs, and
//! this engine all speak one contract.

pub use microsandbox_types::{
    DurableHeaderCredential, HostPattern, HttpsOrigin, MAX_HEADER_CREDENTIAL_FORMAT_BYTES,
    MAX_HEADER_CREDENTIAL_VALUE_BYTES, MAX_HEADER_CREDENTIALS, MAX_SECRET_FILE_BYTES,
    MAX_SECRET_PLACEHOLDER_BYTES, SecretConfigError, SecretEntry, SecretSource, SecretString,
    SecretSubstitution, SecretViolationAction, SecretsConfig,
};
