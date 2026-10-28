//!
//! Same two sessions as Unix, but the console is the terminal: output is
//! written inline (UTF-8 decoded to UTF-16 for `WriteConsoleW`), so there is
//! no standalone writer thread here. The checked session still reports rather
//! than swallows every failure, and it stops its event pump and attempts both
//! console restorations before returning.
//!
//! Its loop lives in `windows_checked`, behind the two console seams, so the
//! same code can be driven by a test on a host that has no Windows console.

use std::sync::Arc;

use microsandbox_protocol::{
    exec::{ExecExited, ExecResize, ExecStdin, ExecStdout},
    message::MessageType,
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

use super::checked::CheckedFailure;
use super::error::{AttachFailureKind, AttachSessionError};
use super::windows_checked::{ConsoleEvent, ConsoleEvents, ConsoleSink, checked_bridge, conclude};
use super::{
    AttachOptions, DetachKeys, FilteredStdin, InputRoute, STDIN_FILTER_TASK_ENDED, recv_filtered,
    require_filtered, route_input,
};

//--------------------------------------------------------------------------------------------------
// Trait Implementations
//--------------------------------------------------------------------------------------------------

/// The console's event pump, as the checked loop's input seam.
impl ConsoleEvents for WindowsTerminalEventPump {
    async fn recv(&mut self) -> Option<ConsoleEvent> {
        WindowsTerminalEventPump::recv(self)
            .await
            .map(|event| match event {
                WindowsTerminalEvent::Input(data) => ConsoleEvent::Input(data),
                WindowsTerminalEvent::Resize { cols, rows } => ConsoleEvent::Resize { cols, rows },
                WindowsTerminalEvent::Error(error) => ConsoleEvent::Error(error),
            })
    }
}

/// The console, as the checked loop's output and teardown seam.
impl ConsoleSink for WindowsTerminalGuard {
    fn write_output(&mut self, data: &[u8]) -> MicrosandboxResult<()> {
        WindowsTerminalGuard::write_output(self, data)
    }

    fn finish_output(&mut self) -> MicrosandboxResult<()> {
        WindowsTerminalGuard::finish_output(self)
    }

    fn restore(&mut self) -> MicrosandboxResult<()> {
        self.restore_checked()
    }
}

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
    let primary = checked_bridge(
        &client,
        id,
        &mut rx,
        &mut terminal,
        &mut events,
        detach_keys.as_ref(),
        stdin_filter,
    )
    .await;

    // One epilogue: stop the event pump, flush the decoded tail, restore.
    drop(events);
    conclude(primary, &mut terminal)
}
