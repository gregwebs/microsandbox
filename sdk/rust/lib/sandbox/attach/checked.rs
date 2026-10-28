//! Checked-session pieces both platform loops share: how one guest event is
//! classified, how a session's own failure is composed with the failures of its
//! epilogue, and which guest input failures mean "the guest closed its input".
//!
//! The platform modules keep only what actually differs: how host output reaches
//! a descriptor (a writer thread on Unix, the console on Windows) and how host
//! input is read.

use microsandbox_protocol::{
    exec::{ExecExited, ExecFailed, ExecStdinError, ExecStdout},
    message::{Message, MessageType},
};

use crate::MicrosandboxError;

use super::error::{AttachFailureKind, AttachSessionError, TeardownStage};

//--------------------------------------------------------------------------------------------------
// Constants
//--------------------------------------------------------------------------------------------------

/// The guest's `EPIPE`. agentd reports the errno it observed inside the
/// guest, so this is not the host's `libc::EPIPE`.
const GUEST_EPIPE: i32 = 32;
/// The guest's `EIO`, reported when the guest's PTY has no slave side left.
const GUEST_EIO: i32 = 5;

//--------------------------------------------------------------------------------------------------
// Types
//--------------------------------------------------------------------------------------------------

/// How a checked session ended. Only a definitive guest event ends one; a
/// transport observation never stands in for an exit.
#[derive(Debug)]
pub(super) enum CheckedEnd {
    /// The guest reported this exit status.
    Exited(i32),
    /// The guest could not spawn the command.
    Failed(ExecFailed),
}

/// How a checked session ended without an exit status, before it reaches a
/// caller.
///
/// The three cases exist because they become three different public results: a
/// spawn failure stays [`MicrosandboxError::ExecFailed`], a setup failure keeps
/// its own variant, and a session failure is the typed
/// [`AttachSessionError`].
#[derive(Debug)]
pub(super) enum CheckedFailure {
    /// The guest could not spawn the command.
    Spawn(ExecFailed),
    /// The session ended without a guest exit status.
    Session(AttachSessionError),
    /// Failed before the session existed; the error is passed through unchanged.
    Setup(MicrosandboxError),
}

/// One guest event, decoded.
///
/// Guest output is handed back rather than written here, so each platform keeps
/// its own sink: Unix stages it for its writer thread, Windows writes the
/// console.
#[derive(Debug)]
pub(super) enum CheckedEvent {
    /// Guest output, for the platform's own sink.
    Output(Vec<u8>),
    /// The guest ended the session.
    End(CheckedEnd),
    /// The guest closed its input; stop feeding it and wait for its exit.
    InputClosed,
    /// Nothing this session acts on.
    Ignored,
}

//--------------------------------------------------------------------------------------------------
// Functions
//--------------------------------------------------------------------------------------------------

/// Decode one guest message for a checked session.
///
/// Pure: nothing here awaits, so a session that is holding guest output cannot
/// be stopped from classifying the next event. The caller owns the output sink
/// and the decision to stop feeding input.
pub(super) fn classify_checked_message(
    message: Message,
) -> Result<CheckedEvent, AttachSessionError> {
    match message.t {
        MessageType::ExecStdout => {
            let frame: ExecStdout = message
                .payload()
                .map_err(|error| protocol_failure(format!("decoding guest output: {error}")))?;
            Ok(CheckedEvent::Output(frame.data))
        }
        MessageType::ExecExited => {
            let exited: ExecExited = message.payload().map_err(|error| {
                protocol_failure(format!("decoding the guest exit event: {error}"))
            })?;
            Ok(CheckedEvent::End(CheckedEnd::Exited(exited.code)))
        }
        MessageType::ExecFailed => {
            let failed: ExecFailed = message.payload().map_err(|error| {
                protocol_failure(format!("decoding the guest spawn failure: {error}"))
            })?;
            Ok(CheckedEvent::End(CheckedEnd::Failed(failed)))
        }
        MessageType::ExecStdinError => {
            let error: ExecStdinError = message.payload().map_err(|decode_error| {
                protocol_failure(format!("decoding a guest input failure: {decode_error}"))
            })?;
            if guest_closed_input(&error) {
                Ok(CheckedEvent::InputClosed)
            } else {
                Err(AttachSessionError::new(
                    AttachFailureKind::GuestInput,
                    format!(
                        "forwarding host terminal input failed in the guest: {}",
                        describe_stdin_error(&error)
                    ),
                ))
            }
        }
        _ => Ok(CheckedEvent::Ignored),
    }
}

/// Compose a session's own result with the failures of its epilogue.
///
/// The session's own failure stays first and keeps its own kind and text: a
/// later teardown step must never replace the reason the session ended. A run
/// whose only failure is a teardown step becomes an error too, because a
/// terminal session that could not restore or flush has failed as a session —
/// the alternative is to report the guest's status while the caller's terminal
/// is still in raw mode.
pub(super) fn finish_with_teardown(
    primary: Result<i32, CheckedFailure>,
    teardown: Vec<(TeardownStage, AttachSessionError)>,
    success_but_teardown_failed: &'static str,
) -> Result<i32, CheckedFailure> {
    let kind = teardown_kind(&teardown);
    match primary {
        Ok(code) if teardown.is_empty() => Ok(code),
        // The success message already names the one step that failed (for
        // example "the host terminal could not be restored"), so a single
        // teardown failure continues that sentence rather than repeating the
        // stage label.
        Ok(_) if teardown.len() == 1 => {
            let (_, error) = teardown.into_iter().next().expect("one teardown failure");
            Err(CheckedFailure::Session(AttachSessionError::new(
                kind,
                format!("{success_but_teardown_failed}: {error}"),
            )))
        }
        Ok(_) => Err(CheckedFailure::Session(collect_teardown(
            AttachSessionError::new(kind, success_but_teardown_failed),
            teardown,
        ))),
        // A failure that ended the session keeps its own kind; only the
        // teardown steps are added to it.
        Err(CheckedFailure::Session(error)) => {
            Err(CheckedFailure::Session(collect_teardown(error, teardown)))
        }
        // A spawn failure is the fact the caller needs, so it stays exactly
        // `ExecFailed` — unless the terminal or console did not come back,
        // which outranks it because the caller has to act on it first.
        Err(CheckedFailure::Spawn(failure)) if teardown.is_empty() => {
            Err(CheckedFailure::Spawn(failure))
        }
        Err(CheckedFailure::Spawn(failure)) => Err(CheckedFailure::Session(collect_teardown(
            AttachSessionError::new(kind, format!("exec failed: {}", failure.message)),
            teardown,
        ))),
        // A setup failure happens before the session exists, so it never has a
        // teardown: there is no terminal to put back yet.
        Err(CheckedFailure::Setup(error)) => Err(CheckedFailure::Setup(error)),
    }
}

/// A closed event channel is a lost session, never a completed one.
pub(super) fn closed_session() -> AttachSessionError {
    AttachSessionError::new(
        AttachFailureKind::ConnectionLost,
        "the agent connection closed before the guest reported its exit",
    )
}

//--------------------------------------------------------------------------------------------------
// Functions: Helpers
//--------------------------------------------------------------------------------------------------

/// A guest payload the session could not decode.
fn protocol_failure(text: impl Into<String>) -> AttachSessionError {
    AttachSessionError::new(AttachFailureKind::Protocol, text)
}

/// Append every failed teardown step to a session failure.
fn collect_teardown(
    error: AttachSessionError,
    teardown: Vec<(TeardownStage, AttachSessionError)>,
) -> AttachSessionError {
    teardown.into_iter().fold(error, |error, (stage, detail)| {
        error.with_teardown(stage, detail)
    })
}

/// The kind a run whose only failure was its teardown step reports.
///
/// An unrestored terminal outranks a lost console tail: the caller has to fix
/// the terminal before anything else matters.
fn teardown_kind(teardown: &[(TeardownStage, AttachSessionError)]) -> AttachFailureKind {
    if teardown.iter().any(|(stage, _)| stage.restores_terminal()) {
        AttachFailureKind::TerminalRestore
    } else {
        AttachFailureKind::Output
    }
}

/// Whether a guest stdin failure means the guest simply closed its input.
///
/// A checked session is always a PTY session, and agentd writes its input to the
/// PTY master. `EPIPE` means the guest closed its input. `EIO` means the PTY's
/// slave side has no opener left: the guest's terminal is gone because it is
/// exiting (Linux `n_tty_write`). Both stop feeding input; the guest's own exit
/// event still ends the session, so a keystroke that races an exit cannot turn a
/// real exit into a failure.
fn guest_closed_input(error: &ExecStdinError) -> bool {
    match (error.errno_name.as_deref(), error.errno) {
        (Some(name), _) => name == "EPIPE" || name == "EIO",
        (None, errno) => errno == Some(GUEST_EPIPE) || errno == Some(GUEST_EIO),
    }
}

/// A guest stdin failure, as its error name and message.
fn describe_stdin_error(error: &ExecStdinError) -> String {
    let errno = error
        .errno_name
        .clone()
        .or_else(|| error.errno.map(|errno| errno.to_string()))
        .unwrap_or_else(|| "no errno".to_string());
    format!("{errno}: {}", error.message)
}

//--------------------------------------------------------------------------------------------------
// Trait Implementations
//--------------------------------------------------------------------------------------------------

impl From<AttachSessionError> for CheckedFailure {
    fn from(error: AttachSessionError) -> Self {
        Self::Session(error)
    }
}

/// The one conversion out of the crate: every checked failure becomes the
/// public result a caller already knows how to match.
impl From<CheckedFailure> for MicrosandboxError {
    fn from(failure: CheckedFailure) -> Self {
        match failure {
            CheckedFailure::Spawn(failure) => MicrosandboxError::ExecFailed(failure),
            CheckedFailure::Setup(error) => error,
            CheckedFailure::Session(error) => MicrosandboxError::Terminal(error.to_string()),
        }
    }
}

//--------------------------------------------------------------------------------------------------
// Tests
//--------------------------------------------------------------------------------------------------

#[cfg(test)]
mod tests {
    //! Message classification and teardown composition, for both platforms.
    //!
    //! These run on every host, so the Windows event handling is exercised here
    //! even though only a Windows console can drive the loop itself.

    use microsandbox_protocol::exec::{ExecFailureKind, ExecStdinError};

    use super::*;

    fn exited_frame(id: u32, code: i32) -> Message {
        Message::with_payload(MessageType::ExecExited, id, &ExecExited { code })
            .expect("a guest exit frame")
    }

    fn failed_frame(id: u32) -> Message {
        let failure = ExecFailed {
            kind: ExecFailureKind::NotFound,
            errno: Some(2),
            errno_name: Some("ENOENT".to_string()),
            message: "no such file or directory".to_string(),
            stage: Some("execvp".to_string()),
        };
        Message::with_payload(MessageType::ExecFailed, id, &failure).expect("a spawn failure frame")
    }

    fn stdin_error_frame(id: u32, errno: Option<i32>, name: Option<&str>) -> Message {
        let error = ExecStdinError {
            errno,
            errno_name: name.map(str::to_string),
            message: "write failed".to_string(),
        };
        Message::with_payload(MessageType::ExecStdinError, id, &error)
            .expect("a guest input failure frame")
    }

    #[test]
    fn guest_output_is_handed_back_byte_for_byte() {
        let frame = ExecStdout {
            data: b"partial line".to_vec(),
        };
        let message =
            Message::with_payload(MessageType::ExecStdout, 7, &frame).expect("an output frame");

        match classify_checked_message(message).expect("guest output decodes") {
            CheckedEvent::Output(data) => assert_eq!(data, b"partial line"),
            other => panic!("guest output must be handed to the platform sink: {other:?}"),
        }
    }

    #[test]
    fn a_guest_exit_is_the_end_of_the_session() {
        match classify_checked_message(exited_frame(7, 3)).expect("a guest exit decodes") {
            CheckedEvent::End(CheckedEnd::Exited(3)) => {}
            other => panic!("a guest exit must end the session with its code: {other:?}"),
        }
    }

    #[test]
    fn a_negative_guest_exit_is_still_an_exit() {
        match classify_checked_message(exited_frame(7, -1)).expect("a guest exit decodes") {
            CheckedEvent::End(CheckedEnd::Exited(-1)) => {}
            other => panic!("the guest's own status must survive unchanged: {other:?}"),
        }
    }

    #[test]
    fn a_guest_spawn_failure_ends_the_session_as_a_failure() {
        match classify_checked_message(failed_frame(7)).expect("a spawn failure decodes") {
            CheckedEvent::End(CheckedEnd::Failed(failure)) => {
                assert_eq!(failure.kind, ExecFailureKind::NotFound)
            }
            other => panic!("a spawn failure must stay a spawn failure: {other:?}"),
        }
    }

    #[test]
    fn a_malformed_guest_exit_is_a_session_failure() {
        let failure =
            classify_checked_message(Message::new(MessageType::ExecExited, 7, vec![0xff]))
                .expect_err("a payload that is not an exit event cannot end the session");
        assert!(
            failure
                .to_string()
                .contains("decoding the guest exit event"),
            "the failure must say which event it could not read: {failure}"
        );
    }

    #[test]
    fn a_malformed_guest_output_is_a_session_failure() {
        let failure =
            classify_checked_message(Message::new(MessageType::ExecStdout, 7, vec![0xff]))
                .expect_err("a payload that is not output cannot be written");
        assert!(
            failure.to_string().contains("decoding guest output"),
            "the failure must name guest output: {failure}"
        );
    }

    #[test]
    fn a_guest_epipe_closes_input_without_failing_the_session() {
        for message in [
            stdin_error_frame(7, Some(32), Some("EPIPE")),
            stdin_error_frame(7, Some(32), None),
        ] {
            match classify_checked_message(message).expect("EPIPE is not a session failure") {
                CheckedEvent::InputClosed => {}
                other => panic!("EPIPE means the guest closed its input: {other:?}"),
            }
        }
    }

    #[test]
    fn a_guest_eio_closes_input_without_failing_the_session() {
        // The PTY's slave side has no opener left because the guest is exiting,
        // which is what a keystroke racing the exit sees. That is a closed
        // input, never a failed session.
        for message in [
            stdin_error_frame(7, Some(5), Some("EIO")),
            stdin_error_frame(7, Some(5), None),
        ] {
            match classify_checked_message(message).expect("EIO is not a session failure") {
                CheckedEvent::InputClosed => {}
                other => panic!("EIO means the guest's input is gone: {other:?}"),
            }
        }
    }

    #[test]
    fn another_guest_stdin_failure_ends_the_session() {
        let failure = classify_checked_message(stdin_error_frame(7, Some(9), Some("EBADF")))
            .expect_err("only a closed input is benign");
        assert_eq!(failure.kind(), AttachFailureKind::GuestInput);
        assert!(
            failure
                .to_string()
                .contains("forwarding host terminal input failed in the guest: EBADF"),
            "the failure must name the guest's errno: {failure}"
        );

        // An errno the session does not know to be a closed input, and no errno
        // at all, are failures too: only `EPIPE` and `EIO` are benign.
        for (errno, name) in [(Some(28), Some("ENOSPC")), (None, None)] {
            let failure = classify_checked_message(stdin_error_frame(7, errno, name))
                .expect_err("only a closed input is benign");
            assert_eq!(failure.kind(), AttachFailureKind::GuestInput);
        }
    }

    #[test]
    fn an_unknown_message_type_is_ignored() {
        let message = Message::new(MessageType::Ready, 7, Vec::new());
        match classify_checked_message(message).expect("an unrelated message is not a failure") {
            CheckedEvent::Ignored => {}
            other => panic!("an unrelated message must be ignored: {other:?}"),
        }
    }

    #[test]
    fn a_clean_session_with_no_teardown_failure_keeps_the_exit_status() {
        assert_eq!(
            finish_with_teardown(Ok(3), Vec::new(), SUCCESS_MESSAGE).expect("nothing failed"),
            3
        );
    }

    #[test]
    fn a_successful_session_with_one_restore_failure_is_an_unrestored_terminal() {
        let failure = finish_with_teardown(
            Ok(3),
            vec![(
                TeardownStage::RestoreTerminal,
                AttachSessionError::new(
                    AttachFailureKind::HostTerminal,
                    "restoring the host terminal: no tty",
                ),
            )],
            SUCCESS_MESSAGE,
        )
        .expect_err("a terminal that cannot be restored failed the session");
        let CheckedFailure::Session(error) = failure else {
            panic!("a restore failure is a session failure: {failure:?}");
        };
        assert_eq!(error.kind(), AttachFailureKind::TerminalRestore);
        assert!(!error.terminal_restored());
        assert_eq!(
            error.to_string(),
            format!("{SUCCESS_MESSAGE}: restoring the host terminal: no tty"),
            "a single teardown failure continues the success message"
        );
    }

    #[test]
    fn a_successful_session_with_a_flush_failure_reports_output() {
        let failure = finish_with_teardown(
            Ok(3),
            vec![(
                TeardownStage::FlushConsoleOutput,
                AttachSessionError::new(AttachFailureKind::Output, "console gone"),
            )],
            SUCCESS_MESSAGE,
        )
        .expect_err("a lost output tail failed the session");
        let CheckedFailure::Session(error) = failure else {
            panic!("a flush failure is a session failure: {failure:?}");
        };
        assert_eq!(error.kind(), AttachFailureKind::Output);
        assert!(error.terminal_restored());
    }

    #[test]
    fn a_successful_session_with_two_teardown_failures_names_both_stages() {
        let failure = finish_with_teardown(
            Ok(3),
            vec![
                (
                    TeardownStage::FlushConsoleOutput,
                    AttachSessionError::new(AttachFailureKind::Output, "console gone"),
                ),
                (
                    TeardownStage::RestoreConsole,
                    AttachSessionError::new(AttachFailureKind::HostTerminal, "no console"),
                ),
            ],
            SUCCESS_MESSAGE,
        )
        .expect_err("an unrestored console failed the session");
        let CheckedFailure::Session(error) = failure else {
            panic!("a teardown failure is a session failure: {failure:?}");
        };
        assert_eq!(
            error.kind(),
            AttachFailureKind::TerminalRestore,
            "an unrestored console outranks the lost output tail"
        );
        assert_eq!(
            error.to_string(),
            format!(
                "{SUCCESS_MESSAGE}; flushing guest output: console gone; restoring the \
                 console: no console"
            )
        );
    }

    #[test]
    fn a_spawn_failure_with_no_teardown_failure_stays_a_spawn_failure() {
        let failure = finish_with_teardown(
            Err(CheckedFailure::Spawn(spawn_failure())),
            Vec::new(),
            SUCCESS_MESSAGE,
        )
        .expect_err("a spawn failure stays a failure");
        assert!(
            matches!(failure, CheckedFailure::Spawn(_)),
            "a spawn failure must stay matchable, not become a session failure: {failure:?}"
        );
        assert!(
            matches!(
                MicrosandboxError::from(failure),
                MicrosandboxError::ExecFailed(_)
            ),
            "the public result of a spawn failure is unchanged"
        );
    }

    #[test]
    fn a_spawn_failure_with_an_unrestored_terminal_becomes_a_session_failure() {
        let failure = finish_with_teardown(
            Err(CheckedFailure::Spawn(spawn_failure())),
            vec![(
                TeardownStage::RestoreTerminal,
                AttachSessionError::new(AttachFailureKind::HostTerminal, "no tty"),
            )],
            SUCCESS_MESSAGE,
        )
        .expect_err("an unrestored terminal outranks the spawn failure");
        let CheckedFailure::Session(error) = failure else {
            panic!("an unrestored terminal is a session failure: {failure:?}");
        };
        assert_eq!(error.kind(), AttachFailureKind::TerminalRestore);
        assert_eq!(
            error.to_string(),
            "exec failed: bash: not found; restoring the host terminal: no tty"
        );
    }

    #[test]
    fn a_failed_session_with_teardown_failures_keeps_its_own_failure_first() {
        let failure = finish_with_teardown(
            Err(CheckedFailure::Session(AttachSessionError::new(
                AttachFailureKind::ConnectionLost,
                "the connection closed",
            ))),
            vec![
                (
                    TeardownStage::FlushConsoleOutput,
                    AttachSessionError::new(AttachFailureKind::Output, "first"),
                ),
                (
                    TeardownStage::RestoreConsole,
                    AttachSessionError::new(AttachFailureKind::HostTerminal, "second"),
                ),
            ],
            SUCCESS_MESSAGE,
        )
        .expect_err("a session failure stays a failure");
        let CheckedFailure::Session(error) = failure else {
            panic!("a session failure stays a session failure: {failure:?}");
        };
        assert_eq!(
            error.kind(),
            AttachFailureKind::ConnectionLost,
            "the reason the session ended must keep its kind"
        );
        assert!(!error.terminal_restored());
        assert_eq!(
            error.to_string(),
            "the connection closed; flushing guest output: first; restoring the console: second"
        );
    }

    #[test]
    fn the_public_conversion_keeps_a_spawn_failure_typed() {
        let failure = MicrosandboxError::from(CheckedFailure::Spawn(spawn_failure()));
        assert!(
            matches!(failure, MicrosandboxError::ExecFailed(_)),
            "a spawn failure must stay matchable: {failure}"
        );
    }

    #[test]
    fn the_public_conversion_passes_a_setup_error_through() {
        let failure = MicrosandboxError::from(CheckedFailure::Setup(
            MicrosandboxError::InvalidConfig("no such key".to_string()),
        ));
        assert!(
            matches!(failure, MicrosandboxError::InvalidConfig(_)),
            "a failure before the session existed keeps its own variant: {failure}"
        );
    }

    #[test]
    fn the_public_conversion_renders_a_session_failure_as_a_terminal_error() {
        let session = AttachSessionError::new(AttachFailureKind::Detached, "detached")
            .with_teardown(TeardownStage::DeliverOutput, "no consumer");
        let rendered = session.to_string();
        let failure = MicrosandboxError::from(CheckedFailure::Session(session));
        assert!(
            matches!(failure, MicrosandboxError::Terminal(_)),
            "a session failure is a terminal error for a caller outside the crate: {failure}"
        );
        assert_eq!(failure.to_string(), format!("terminal error: {rendered}"));
    }

    const SUCCESS_MESSAGE: &str =
        "the guest reported its exit but the console session did not finish cleanly";

    fn spawn_failure() -> ExecFailed {
        ExecFailed {
            kind: ExecFailureKind::NotFound,
            errno: None,
            errno_name: None,
            message: "bash: not found".to_string(),
            stage: None,
        }
    }
}
