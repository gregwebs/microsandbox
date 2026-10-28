//! Checked-session pieces both platform loops share: how a session's own
//! failure is composed with the failures of its epilogue.

use crate::MicrosandboxError;

//--------------------------------------------------------------------------------------------------
// Functions
//--------------------------------------------------------------------------------------------------

/// Compose a checked session's own failure with the failures of its epilogue.
///
/// The session's failure stays first and keeps its own text: a later teardown
/// step must never replace the reason the session failed. The composed value is
/// a terminal error, because a terminal session that cannot restore or flush has
/// failed as a session — the alternative (returning only the primary) would
/// report the guest's status while the caller's terminal is still in raw mode.
#[cfg(any(unix, windows))]
pub(super) fn checked_epilogue_error(
    primary: MicrosandboxError,
    later: impl IntoIterator<Item = (&'static str, MicrosandboxError)>,
) -> MicrosandboxError {
    let mut text = primary.to_string();
    for (stage, error) in later {
        text.push_str(&format!("; {stage}: {error}"));
    }
    MicrosandboxError::Terminal(text)
}
