//! Shared explanations for network-policy diagnostics.

//--------------------------------------------------------------------------------------------------
// Constants
//--------------------------------------------------------------------------------------------------

/// Explanation and remedies for opaque traffic rejected by strict hostname policy.
pub(crate) const STRICT_HOSTNAME_DENIAL_GUIDANCE: &str = concat!(
    "the first matching allow rule targets a hostname, but request authority cannot be inspected; ",
    "default allow does not override this rule. ",
    "Configure TLS interception for the destination port without bypassing this host and trust its CA, ",
    "or explicitly opt out with --net-strict=false (network.strict: false)",
);
