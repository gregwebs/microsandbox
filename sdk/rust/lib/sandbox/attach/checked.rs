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

use crate::{MicrosandboxError, MicrosandboxResult};

//--------------------------------------------------------------------------------------------------
// Constants
//--------------------------------------------------------------------------------------------------

/// The guest's `EPIPE`. agentd reports the errno it observed inside the
/// guest, so this is not the host's `libc::EPIPE`.
const GUEST_EPIPE: i32 = 32;

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
pub(super) fn classify_checked_message(message: Message) -> MicrosandboxResult<CheckedEvent> {
    match message.t {
        MessageType::ExecStdout => {
            let frame: ExecStdout = message
                .payload()
                .map_err(|error| checked_failure(format!("decoding guest output: {error}")))?;
            Ok(CheckedEvent::Output(frame.data))
        }
        MessageType::ExecExited => {
            let exited: ExecExited = message.payload().map_err(|error| {
                checked_failure(format!("decoding the guest exit event: {error}"))
            })?;
            Ok(CheckedEvent::End(CheckedEnd::Exited(exited.code)))
        }
        MessageType::ExecFailed => {
            let failed: ExecFailed = message.payload().map_err(|error| {
                checked_failure(format!("decoding the guest spawn failure: {error}"))
            })?;
            Ok(CheckedEvent::End(CheckedEnd::Failed(failed)))
        }
        MessageType::ExecStdinError => {
            let error: ExecStdinError = message.payload().map_err(|error| {
                checked_failure(format!("decoding a guest input failure: {error}"))
            })?;
            if guest_closed_input(&error) {
                Ok(CheckedEvent::InputClosed)
            } else {
                Err(checked_failure(format!(
                    "forwarding host terminal input failed in the guest: {}",
                    describe_stdin_error(&error)
                )))
            }
        }
        _ => Ok(CheckedEvent::Ignored),
    }
}

/// Compose a session's own result with the failures of its epilogue.
///
/// The session's own failure stays first and keeps its own text: a later
/// teardown step must never replace the reason the session ended. A run whose
/// only failure is a teardown step becomes an error too, because a terminal
/// session that could not restore or flush has failed as a session — the
/// alternative is to report the guest's status while the caller's terminal is
/// still in raw mode.
pub(super) fn finish_with_teardown(
    primary: MicrosandboxResult<i32>,
    teardown: Vec<(&'static str, MicrosandboxError)>,
    success_but_teardown_failed: &'static str,
) -> MicrosandboxResult<i32> {
    match (primary, teardown.as_slice()) {
        (Ok(code), []) => Ok(code),
        // The success message already names the one step that failed (for
        // example "the host terminal could not be restored"), so a single
        // teardown failure continues that sentence rather than repeating the
        // stage.
        (Ok(_), [(_, error)]) => Err(checked_failure(format!(
            "{success_but_teardown_failed}: {error}"
        ))),
        (Ok(_), _) => Err(checked_epilogue_error(
            checked_failure(success_but_teardown_failed),
            teardown,
        )),
        (Err(primary), []) => Err(primary),
        (Err(primary), _) => Err(checked_epilogue_error(primary, teardown)),
    }
}

/// A checked-session failure, with the text its cause needs.
///
/// Every checked failure is a terminal-session failure: the caller's terminal
/// (or console) was part of the session, so an error is what the caller has to
/// act on. Only the legacy session keeps the old "no exit status means `Ok(-1)`"
/// convention.
pub(super) fn checked_failure(text: impl Into<String>) -> MicrosandboxError {
    MicrosandboxError::Terminal(text.into())
}

/// A closed event channel is a lost session, never a completed one.
pub(super) fn closed_session() -> MicrosandboxError {
    checked_failure("the agent connection closed before the guest reported its exit")
}

//--------------------------------------------------------------------------------------------------
// Functions: Helpers
//--------------------------------------------------------------------------------------------------

/// Compose a checked session's own failure with the failures of its epilogue.
fn checked_epilogue_error(
    primary: MicrosandboxError,
    later: impl IntoIterator<Item = (&'static str, MicrosandboxError)>,
) -> MicrosandboxError {
    let mut text = primary.to_string();
    for (stage, error) in later {
        text.push_str(&format!("; {stage}: {error}"));
    }
    MicrosandboxError::Terminal(text)
}

/// Whether a guest stdin failure means the guest simply closed its input.
fn guest_closed_input(error: &ExecStdinError) -> bool {
    match (error.errno_name.as_deref(), error.errno) {
        (Some(name), _) => name == "EPIPE",
        (None, errno) => errno == Some(GUEST_EPIPE),
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
    fn another_guest_stdin_failure_ends_the_session() {
        let failure = classify_checked_message(stdin_error_frame(7, Some(9), Some("EBADF")))
            .expect_err("only a closed input is benign");
        assert!(
            failure
                .to_string()
                .contains("forwarding host terminal input failed in the guest: EBADF"),
            "the failure must name the guest's errno: {failure}"
        );
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
    fn a_successful_session_with_one_teardown_failure_is_an_error() {
        let failure = finish_with_teardown(
            Ok(3),
            vec![("restoring the host terminal", terminal_error("no tty"))],
            SUCCESS_MESSAGE,
        )
        .expect_err("a terminal that cannot be restored failed the session");
        assert_eq!(
            failure.to_string(),
            format!("terminal error: {SUCCESS_MESSAGE}: terminal error: no tty")
        );
    }

    #[test]
    fn a_successful_session_with_two_teardown_failures_names_both_stages() {
        let failure = finish_with_teardown(
            Ok(3),
            vec![
                ("flushing guest output", terminal_error("console gone")),
                ("restoring the console", terminal_error("no console")),
            ],
            SUCCESS_MESSAGE,
        )
        .expect_err("an unrestored console failed the session");
        assert_eq!(
            failure.to_string(),
            format!(
                "terminal error: terminal error: {SUCCESS_MESSAGE}; flushing guest output: \
                 terminal error: console gone; restoring the console: terminal error: no console"
            )
        );
    }

    #[test]
    fn a_failed_session_with_no_teardown_failure_keeps_its_own_error() {
        let failure = finish_with_teardown(
            Err(MicrosandboxError::ExecFailed(ExecFailed {
                kind: ExecFailureKind::NotFound,
                errno: None,
                errno_name: None,
                message: "no such file".to_string(),
                stage: None,
            })),
            Vec::new(),
            SUCCESS_MESSAGE,
        )
        .expect_err("a spawn failure stays a failure");
        assert!(
            matches!(failure, MicrosandboxError::ExecFailed(_)),
            "a spawn failure must stay matchable, not become a terminal error: {failure}"
        );
    }

    #[test]
    fn a_failed_session_with_teardown_failures_keeps_its_own_failure_first() {
        let failure = finish_with_teardown(
            Err(terminal_error("the connection closed")),
            vec![
                ("flushing guest output", terminal_error("first")),
                ("restoring the console", terminal_error("second")),
            ],
            SUCCESS_MESSAGE,
        )
        .expect_err("a session failure stays a failure");
        assert_eq!(
            failure.to_string(),
            "terminal error: terminal error: the connection closed; flushing guest output: \
             terminal error: first; restoring the console: terminal error: second"
        );
    }

    const SUCCESS_MESSAGE: &str =
        "the guest reported its exit but the console session did not finish cleanly";

    fn terminal_error(text: &str) -> MicrosandboxError {
        MicrosandboxError::Terminal(text.to_string())
    }
}
