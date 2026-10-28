//!
//! Same two sessions as Unix, but the console is the terminal: output is
//! written inline (UTF-8 decoded to UTF-16 for `WriteConsoleW`), so there is
//! no standalone writer thread here. The checked session still reports rather
//! than swallows every failure, and it stops its event pump and attempts both
//! console restorations before returning.

use std::sync::Arc;

use microsandbox_protocol::{
    exec::{ExecExited, ExecResize, ExecStdin, ExecStdout},
    message::{Message, MessageType},
};

use crate::backend::Backend;
use crate::{
    MicrosandboxError, MicrosandboxResult,
    sandbox::{
        AttachOptionsBuilder, SandboxConfig, build_exec_request,
        terminal::{
            WindowsTerminalEvent, WindowsTerminalEventPump, WindowsTerminalGuard,
            current_terminal_size,
        },
    },
};

use super::checked::{
    CheckedEnd, CheckedEvent, CheckedFailure, classify_checked_message, closed_session,
    finish_with_teardown,
};
use super::error::{AttachFailureKind, AttachSessionError, TeardownStage};
use super::{
    AttachOptions, DetachKeys, FilteredStdin, InputRoute, STDIN_FILTER_TASK_ENDED, StdinFilter,
    recv_filtered, require_filtered, route_input,
};

//--------------------------------------------------------------------------------------------------
// Functions
//--------------------------------------------------------------------------------------------------

pub(crate) async fn attach(
    backend: &dyn Backend,
    name: &str,
    config: &SandboxConfig,
    cmd: String,
    opts_builder: AttachOptionsBuilder,
) -> MicrosandboxResult<i32> {
    let opts = opts_builder.build()?;
    let client = Arc::new(super::super::fs::agent::connect_agent(backend, name).await?);
    attach_connected(client, config, cmd, opts).await
}

/// Bridge an already-connected agent: production reaches it through
/// [`attach`], tests drive it directly.
pub(super) async fn attach_connected(
    client: Arc<crate::agent::AgentClient>,
    config: &SandboxConfig,
    cmd: String,
    opts: AttachOptions,
) -> MicrosandboxResult<i32> {
    let detach_keys = opts.resolved_detach_keys()?;
    if opts.checked_session {
        checked_session(client, config, cmd, opts, detach_keys)
            .await
            .map_err(MicrosandboxError::from)
    } else {
        legacy_session(client, config, cmd, opts, detach_keys).await
    }
}

async fn legacy_session(
    client: Arc<crate::agent::AgentClient>,
    config: &SandboxConfig,
    cmd: String,
    mut opts: AttachOptions,
    detach_keys: Option<DetachKeys>,
) -> MicrosandboxResult<i32> {
    // Taken before the option fields move, exactly as on Unix.
    let stdin_filter = opts.stdin_filter.take();
    let (cols, rows) = current_terminal_size().unwrap_or((80, 24));

    let req = build_exec_request(
        config,
        cmd,
        opts.args,
        opts.cwd,
        opts.user,
        &opts.env,
        &opts.rlimits,
        true,
        rows,
        cols,
    );
    let (id, mut rx) = client.stream(MessageType::ExecRequest, &req).await?;

    let mut terminal_guard = WindowsTerminalGuard::enter()?;
    let mut terminal_events = WindowsTerminalEventPump::spawn_for_guard(&terminal_guard)?;
    let mut exit_code: i32 = -1;
    let mut spawn_failure: Option<microsandbox_protocol::exec::ExecFailed> = None;
    let mut match_pos = 0usize;

    // Filtered on its own task: a filter that awaits the guest must not
    // stop this loop from draining guest output (see `StdinFilter`).
    let mut filtered_stdin = stdin_filter.map(FilteredStdin::spawn);

    loop {
        tokio::select! {
            Some(event) = terminal_events.recv() => {
                match event {
                    WindowsTerminalEvent::Input(data) => {
                        match route_input(
                            &data,
                            detach_keys.as_ref(),
                            &mut match_pos,
                            filtered_stdin.as_ref(),
                        ) {
                            InputRoute::Detach => break,
                            InputRoute::Filtered => {}
                            InputRoute::WorkerEnded => {
                                return Err(MicrosandboxError::Runtime(
                                    STDIN_FILTER_TASK_ENDED.into(),
                                ));
                            }
                            InputRoute::Forward => {
                                // The whole chunk, byte for byte: interception
                                // only decides whether the session ends here.
                                let payload = ExecStdin { data };
                                let _ = client.send(id, MessageType::ExecStdin, &payload).await;
                            }
                        }
                    }
                    WindowsTerminalEvent::Resize { cols, rows } => {
                        let payload = ExecResize { rows, cols };
                        let _ = client.send(id, MessageType::ExecResize, &payload).await;
                    }
                    WindowsTerminalEvent::Error(error) => {
                        return Err(MicrosandboxError::Terminal(error));
                    }
                }
            }

            // Disabled without a filter: preserve the original set of enabled branches.
            filtered = recv_filtered(&mut filtered_stdin), if filtered_stdin.is_some() => {
                let data = require_filtered(filtered)?;
                let payload = ExecStdin { data };
                let _ = client.send(id, MessageType::ExecStdin, &payload).await;
            }

            Some(msg) = rx.recv() => {
                let mut should_break = false;

                match msg.t {
                    MessageType::ExecStdout => {
                        if let Ok(out) = msg.payload::<ExecStdout>() {
                            terminal_guard.write_output(&out.data)?;
                        }
                    }
                    MessageType::ExecExited => {
                        if let Ok(exited) = msg.payload::<ExecExited>() {
                            exit_code = exited.code;
                        }
                        should_break = true;
                    }
                    MessageType::ExecFailed => {
                        if let Ok(failed) =
                            msg.payload::<microsandbox_protocol::exec::ExecFailed>()
                        {
                            spawn_failure = Some(failed);
                        }
                        should_break = true;
                    }
                    _ => {}
                }

                if !should_break {
                    while let Ok(next) = rx.try_recv() {
                        match next.t {
                            MessageType::ExecStdout => {
                                if let Ok(out) = next.payload::<ExecStdout>() {
                                    terminal_guard.write_output(&out.data)?;
                                }
                            }
                            MessageType::ExecExited => {
                                if let Ok(exited) = next.payload::<ExecExited>() {
                                    exit_code = exited.code;
                                }
                                should_break = true;
                                break;
                            }
                            MessageType::ExecFailed => {
                                if let Ok(failed) = next
                                    .payload::<microsandbox_protocol::exec::ExecFailed>()
                                {
                                    spawn_failure = Some(failed);
                                }
                                should_break = true;
                                break;
                            }
                            _ => {}
                        }
                    }
                }

                if should_break {
                    break;
                }
            }
        }
    }

    if let Some(failure) = spawn_failure {
        return Err(MicrosandboxError::ExecFailed(failure));
    }

    terminal_guard.finish_output()?;

    Ok(exit_code)
}

async fn checked_session(
    client: Arc<crate::agent::AgentClient>,
    config: &SandboxConfig,
    cmd: String,
    mut opts: AttachOptions,
    detach_keys: Option<DetachKeys>,
) -> Result<i32, CheckedFailure> {
    let stdin_filter = opts.stdin_filter.take();
    // A console with no readable size is not a session failure here: the
    // console API reports "no size" as an absence, not an error, so the
    // legacy fallback is the only information available and inventing an
    // error would fail a session the legacy path runs.
    let (cols, rows) = current_terminal_size().unwrap_or((80, 24));
    let req = build_exec_request(
        config,
        cmd,
        opts.args,
        opts.cwd,
        opts.user,
        &opts.env,
        &opts.rlimits,
        true,
        rows,
        cols,
    );
    let (id, mut rx) = client
        .stream(MessageType::ExecRequest, &req)
        .await
        .map_err(|error| CheckedFailure::Setup(error.into()))?;

    // Raw console mode begins only once the exec request exists, exactly as
    // on Unix.
    let mut terminal = WindowsTerminalGuard::enter()
        .map_err(|error| AttachSessionError::host(AttachFailureKind::HostTerminal, error))?;
    let mut events = WindowsTerminalEventPump::spawn_for_guard(&terminal)
        .map_err(|error| AttachSessionError::host(AttachFailureKind::HostTerminal, error))?;
    // The loop reports how the guest ended (or the failure that ended it
    // first); the conclusion below turns that into the public-shaped result.
    let primary = match checked_bridge(
        &client,
        id,
        &mut rx,
        &mut terminal,
        &mut events,
        detach_keys.as_ref(),
        stdin_filter,
    )
    .await
    {
        Ok(CheckedEnd::Exited(code)) => Ok(code),
        Ok(CheckedEnd::Failed(failure)) => Err(CheckedFailure::Spawn(failure)),
        Err(error) => Err(CheckedFailure::from(error)),
    };

    // One epilogue: stop the event pump, flush the decoded tail, restore.
    drop(events);
    let mut teardown = Vec::new();
    if let Err(error) = terminal.finish_output() {
        teardown.push((
            TeardownStage::FlushConsoleOutput,
            AttachSessionError::host(AttachFailureKind::Output, error),
        ));
    }
    if let Err(error) = terminal.restore_checked() {
        teardown.push((
            TeardownStage::RestoreConsole,
            AttachSessionError::host(AttachFailureKind::HostTerminal, error),
        ));
    }
    finish_with_teardown(
        primary,
        teardown,
        "the guest reported its exit but the console session did not finish cleanly",
    )
}

async fn checked_bridge(
    client: &Arc<crate::agent::AgentClient>,
    id: u32,
    rx: &mut tokio::sync::mpsc::Receiver<Message>,
    terminal: &mut WindowsTerminalGuard,
    events: &mut WindowsTerminalEventPump,
    detach_keys: Option<&DetachKeys>,
    stdin_filter: Option<Box<dyn StdinFilter>>,
) -> Result<CheckedEnd, AttachSessionError> {
    let mut match_pos = 0usize;
    let mut feeding_input = true;
    // Same task boundary as the legacy session and as Unix.
    let mut filtered_stdin = stdin_filter.map(FilteredStdin::spawn);

    let end = 'session: loop {
        tokio::select! {
            event = events.recv() => {
                // The console's event pump ends on console EOF or on its own
                // read error, never because the agent connection closed: say
                // what actually happened.
                let Some(event) = event else {
                    return Err(host_failure(
                        "host console input ended before the guest reported its exit",
                    ));
                };
                match event {
                    WindowsTerminalEvent::Input(data) => {
                        // Shared routing: a filter sees the same chunks, one at a
                        // time and in order, as it would without the checked
                        // session; only the failure conventions differ.
                        match route_input(
                            &data,
                            detach_keys,
                            &mut match_pos,
                            filtered_stdin.as_ref(),
                        ) {
                            InputRoute::Detach => {
                                return Err(AttachSessionError::new(
                                    AttachFailureKind::Detached,
                                    "the detach key sequence ended the session before the guest reported its exit",
                                ));
                            }
                            InputRoute::Filtered => {}
                            InputRoute::WorkerEnded => {
                                return Err(AttachSessionError::new(
                                    AttachFailureKind::StdinFilter,
                                    STDIN_FILTER_TASK_ENDED,
                                ));
                            }
                            InputRoute::Forward => {
                                if feeding_input {
                                    client
                                        .send(id, MessageType::ExecStdin, &ExecStdin { data })
                                        .await
                                        .map_err(|error| {
                                            connection_lost(format!(
                                                "forwarding console input: {error}"
                                            ))
                                        })?;
                                }
                            }
                        }
                    }
                    WindowsTerminalEvent::Resize { cols, rows } => {
                        client
                            .send(id, MessageType::ExecResize, &ExecResize { rows, cols })
                            .await
                            .map_err(|error| {
                                connection_lost(format!("sending a console resize: {error}"))
                            })?;
                    }
                    WindowsTerminalEvent::Error(error) => {
                        return Err(host_failure(format!("reading console input: {error}")));
                    }
                }
            }

            filtered = recv_filtered(&mut filtered_stdin), if feeding_input && filtered_stdin.is_some() => {
                let Some(data) = filtered else {
                    return Err(AttachSessionError::new(
                        AttachFailureKind::StdinFilter,
                        STDIN_FILTER_TASK_ENDED,
                    ));
                };
                client
                    .send(id, MessageType::ExecStdin, &ExecStdin { data })
                    .await
                    .map_err(|error| {
                        connection_lost(format!("forwarding console input: {error}"))
                    })?;
            }

            message = rx.recv() => {
                let Some(message) = message else {
                    return Err(closed_session());
                };
                if let Some(end) =
                    handle_checked_message(message, terminal, &mut feeding_input)?
                {
                    break 'session end;
                }
                let mut drained = None;
                while drained.is_none() {
                    match rx.try_recv() {
                        Ok(next) => {
                            drained =
                                handle_checked_message(next, terminal, &mut feeding_input)?;
                        }
                        Err(_) => break,
                    }
                }
                if let Some(end) = drained {
                    break 'session end;
                }
            }
        }
    };

    Ok(end)
}

//--------------------------------------------------------------------------------------------------
// Functions: Helpers
//--------------------------------------------------------------------------------------------------

/// One session event: `Some` ends the session, `None` continues it.
///
/// Decoding is shared with the Unix loop; the console is this platform's own
/// sink for guest output.
fn handle_checked_message(
    message: Message,
    terminal: &mut WindowsTerminalGuard,
    feeding_input: &mut bool,
) -> Result<Option<CheckedEnd>, AttachSessionError> {
    match classify_checked_message(message)? {
        CheckedEvent::Output(data) => {
            terminal
                .write_output(&data)
                .map_err(|error| AttachSessionError::host(AttachFailureKind::Output, error))?;
            Ok(None)
        }
        CheckedEvent::End(end) => Ok(Some(end)),
        CheckedEvent::InputClosed => {
            *feeding_input = false;
            Ok(None)
        }
        CheckedEvent::Ignored => Ok(None),
    }
}

/// A failure of the console itself: setup, reading input, or restoring it.
fn host_failure(text: impl Into<String>) -> AttachSessionError {
    AttachSessionError::new(AttachFailureKind::HostTerminal, text)
}

/// A send the transport refused: the session is lost even while the guest runs.
fn connection_lost(text: impl Into<String>) -> AttachSessionError {
    AttachSessionError::new(AttachFailureKind::ConnectionLost, text)
}
