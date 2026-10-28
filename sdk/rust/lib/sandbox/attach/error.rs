//! The typed failure of a checked attach session.
//!
//! A checked session reports *why* it ended without a guest exit status, and
//! keeps the failures of its own teardown (restoring the terminal or console,
//! delivering held guest output) beside the reason instead of folding them into
//! one string. Both the session and its callers match on [`AttachFailureKind`]
//! or ask [`AttachSessionError::terminal_restored`], so no test and no caller has
//! to parse text.
//!
//! These items are `pub(crate)`: the public result of an attach call is
//! unchanged. One conversion site (`From<CheckedFailure>` in `checked.rs`) turns
//! a failure into the SDK's public error.

use std::fmt;

use crate::MicrosandboxError;

//--------------------------------------------------------------------------------------------------
// Types
//--------------------------------------------------------------------------------------------------

/// A checked attach session that ended without a guest exit status.
///
/// It carries the kind of failure, a message describing it, and the failures of
/// the teardown steps that ran afterwards. `Display` renders the message and
/// then `; <stage>: <detail>` for each teardown failure, which is the text a
/// caller sees once the value reaches the SDK's public error.
#[derive(Debug, thiserror::Error)]
#[error("{message}{teardown}")]
pub(crate) struct AttachSessionError {
    kind: AttachFailureKind,
    message: String,
    teardown: TeardownFailures,
}

/// What ended a checked attach session without a guest exit status.
///
/// A spawn failure is not a variant: the guest never ran, so it stays
/// `MicrosandboxError::ExecFailed` for the caller to match.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum AttachFailureKind {
    /// The detach key sequence ended the session before the guest exited.
    Detached,
    /// The event channel closed, or a send to the guest failed, before an exit.
    ConnectionLost,
    /// A guest output, exit, failure or input-error payload could not be decoded.
    Protocol,
    /// The host terminal or console could not be set up, read or sized, or host
    /// input ended before the guest exited.
    HostTerminal,
    /// Guest output could not be written to the host.
    Output,
    /// The guest reported a stdin failure that does not mean "input closed".
    GuestInput,
    /// The stdin filter worker ended.
    StdinFilter,
    /// The guest exited, but the host terminal or console could not be restored.
    TerminalRestore,
}

/// A teardown step that failed after the session itself had ended.
///
/// The variant, not a string, decides the label, so no caller or test matches
/// on text to know which step failed.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum TeardownStage {
    /// Restoring the saved `termios` of the host terminal.
    #[cfg_attr(not(unix), allow(dead_code))]
    RestoreTerminal,
    /// Restoring the console modes of the host console.
    #[cfg_attr(not(windows), allow(dead_code))]
    RestoreConsole,
    /// Flushing the console's decoded output tail.
    #[cfg_attr(not(windows), allow(dead_code))]
    FlushConsoleOutput,
    /// Delivering guest output already held by a failed session.
    #[cfg_attr(not(test), allow(dead_code))]
    DeliverOutput,
}

/// The teardown failures of one session, in the order they happened.
#[derive(Debug, Default)]
struct TeardownFailures(Vec<TeardownFailure>);

/// One teardown failure and the step it happened in.
#[derive(Debug)]
struct TeardownFailure {
    stage: TeardownStage,
    detail: String,
}

//--------------------------------------------------------------------------------------------------
// Methods
//--------------------------------------------------------------------------------------------------

impl AttachSessionError {
    /// A session failure of `kind`, described by `message`.
    pub(crate) fn new(kind: AttachFailureKind, message: impl Into<String>) -> Self {
        Self {
            kind,
            message: message.into(),
            teardown: TeardownFailures::default(),
        }
    }

    /// The same failure, with one more failed teardown step recorded.
    pub(crate) fn with_teardown(mut self, stage: TeardownStage, detail: impl fmt::Display) -> Self {
        self.teardown.0.push(TeardownFailure {
            stage,
            detail: detail.to_string(),
        });
        self
    }

    /// Wrap a host-terminal or console failure reported as `MicrosandboxError`.
    ///
    /// The Windows console layer reports through `MicrosandboxError::Terminal`,
    /// so the text is taken from there; anything else keeps its own rendering.
    #[cfg_attr(not(windows), allow(dead_code))]
    pub(crate) fn host(kind: AttachFailureKind, error: MicrosandboxError) -> Self {
        let message = match error {
            MicrosandboxError::Terminal(text) => text,
            other => other.to_string(),
        };
        Self::new(kind, message)
    }

    /// What ended the session without a guest exit status.
    #[cfg_attr(not(test), allow(dead_code))]
    pub(crate) fn kind(&self) -> AttachFailureKind {
        self.kind
    }

    /// Whether the host terminal (or console) was restored.
    ///
    /// False when the failure *is* a restore failure, or when a restore step
    /// failed after another failure ended the session.
    #[cfg_attr(not(test), allow(dead_code))]
    pub(crate) fn terminal_restored(&self) -> bool {
        self.kind != AttachFailureKind::TerminalRestore
            && !self
                .teardown
                .0
                .iter()
                .any(|failure| failure.stage.restores_terminal())
    }
}

impl TeardownStage {
    /// The label this step is reported under.
    pub(crate) fn label(self) -> &'static str {
        match self {
            Self::RestoreTerminal => "restoring the host terminal",
            Self::RestoreConsole => "restoring the console",
            Self::FlushConsoleOutput => "flushing guest output",
            Self::DeliverOutput => "delivering guest output",
        }
    }

    /// Whether this step is what puts the host terminal back.
    pub(crate) fn restores_terminal(self) -> bool {
        matches!(self, Self::RestoreTerminal | Self::RestoreConsole)
    }
}

//--------------------------------------------------------------------------------------------------
// Trait Implementations
//--------------------------------------------------------------------------------------------------

impl fmt::Display for TeardownFailures {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        for failure in &self.0 {
            write!(f, "; {}: {}", failure.stage.label(), failure.detail)?;
        }
        Ok(())
    }
}

//--------------------------------------------------------------------------------------------------
// Tests
//--------------------------------------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn display_without_teardown_is_the_message() {
        let error = AttachSessionError::new(AttachFailureKind::ConnectionLost, "the relay closed");
        assert_eq!(error.to_string(), "the relay closed");
    }

    #[test]
    fn display_names_every_teardown_step_in_order() {
        let error = AttachSessionError::new(AttachFailureKind::ConnectionLost, "the relay closed")
            .with_teardown(TeardownStage::RestoreTerminal, "no tty")
            .with_teardown(TeardownStage::DeliverOutput, "no consumer");
        assert_eq!(
            error.to_string(),
            "the relay closed; restoring the host terminal: no tty; delivering guest output: \
             no consumer"
        );
    }

    #[test]
    fn the_kind_round_trips() {
        for kind in [
            AttachFailureKind::Detached,
            AttachFailureKind::ConnectionLost,
            AttachFailureKind::Protocol,
            AttachFailureKind::HostTerminal,
            AttachFailureKind::Output,
            AttachFailureKind::GuestInput,
            AttachFailureKind::StdinFilter,
            AttachFailureKind::TerminalRestore,
        ] {
            assert_eq!(AttachSessionError::new(kind, "text").kind(), kind);
        }
    }

    #[test]
    fn a_session_failure_alone_leaves_the_terminal_restored() {
        assert!(
            AttachSessionError::new(AttachFailureKind::ConnectionLost, "the relay closed")
                .terminal_restored()
        );
    }

    #[test]
    fn a_restore_failure_is_not_a_restored_terminal() {
        assert!(
            !AttachSessionError::new(AttachFailureKind::TerminalRestore, "no tty")
                .terminal_restored()
        );
        for stage in [
            TeardownStage::RestoreTerminal,
            TeardownStage::RestoreConsole,
        ] {
            let error = AttachSessionError::new(AttachFailureKind::ConnectionLost, "lost")
                .with_teardown(stage, "no tty");
            assert!(
                !error.terminal_restored(),
                "{stage:?} must count as an unrestored terminal"
            );
        }
    }

    #[test]
    fn a_delivery_failure_still_leaves_the_terminal_restored() {
        let error = AttachSessionError::new(AttachFailureKind::ConnectionLost, "lost")
            .with_teardown(TeardownStage::DeliverOutput, "no consumer");
        assert!(error.terminal_restored());
    }

    #[test]
    fn a_host_failure_keeps_its_own_text() {
        let error = AttachSessionError::host(
            AttachFailureKind::HostTerminal,
            MicrosandboxError::Terminal("restoring the console mode: stdin ok".to_string()),
        );
        assert_eq!(
            error.to_string(),
            "restoring the console mode: stdin ok",
            "the wrapper must not repeat the outer error prefix"
        );
    }

    #[test]
    fn every_teardown_stage_has_a_distinct_label() {
        let stages = [
            TeardownStage::RestoreTerminal,
            TeardownStage::RestoreConsole,
            TeardownStage::FlushConsoleOutput,
            TeardownStage::DeliverOutput,
        ];
        let mut labels: Vec<&str> = stages.iter().map(|stage| stage.label()).collect();
        labels.sort_unstable();
        labels.dedup();
        assert_eq!(labels.len(), stages.len());
    }
}
