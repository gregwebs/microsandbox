//! Attach over an agent connection: bridge a host terminal to a guest PTY
//! exec session.
//!
//! One connection setup serves two deliberately different sessions. The
//! legacy session is the interactive `shell` behavior, whose completion
//! conventions (`Ok(-1)` when no exit event arrived) and best-effort I/O are
//! observable and must not change. The checked session is an opt-in for a
//! caller that owns the process's exit status: a direct command launch has to

use std::collections::VecDeque;
use std::os::fd::{AsRawFd, FromRawFd, OwnedFd, RawFd};
use std::sync::Arc;

use microsandbox_protocol::{
    exec::{ExecExited, ExecFailed, ExecResize, ExecStdin, ExecStdinError, ExecStdout},
    message::{Message, MessageType},
};
use tokio::io::AsyncWriteExt;
use tokio::io::unix::AsyncFd;

use crate::{
    MicrosandboxError, MicrosandboxResult,
    agent::AgentClient,
    sandbox::{
        AttachOptionsBuilder, SandboxConfig, build_exec_request, open_nonblocking_terminal_input,
        read_from_fd, terminal_path_for_fd,
    },
};

use super::checked::checked_epilogue_error;
use super::checked_output::{
    CHECKED_OUTPUT_CHUNK_BYTES, CHECKED_OUTPUT_MAX_PENDING_BYTES, CheckedOutput,
    stage_output_chunks,
};
use super::{
    AttachOptions, DetachKeys, FilteredStdin, InputRoute, STDIN_FILTER_TASK_ENDED, StdinFilter,
    recv_filtered, require_filtered, route_input,
};

//--------------------------------------------------------------------------------------------------
// Constants
//--------------------------------------------------------------------------------------------------

/// Most staged chunks one session may hold read but not yet queued.
///
/// Staging is what keeps failure observation live across a capacity wait, so
/// it is bounded like the writer's own queue rather than growing with a
/// flooding guest.
const CHECKED_STAGED_CHUNKS: usize = CHECKED_OUTPUT_MAX_PENDING_BYTES / CHECKED_OUTPUT_CHUNK_BYTES;
/// Host terminal read size: one `read(2)`, one `ExecStdin` frame.
const CHECKED_INPUT_CHUNK_BYTES: usize = 1024;
/// The guest's `EPIPE`. agentd reports the errno it observed inside the
/// guest, so this is not the host's `libc::EPIPE`.
const GUEST_EPIPE: i32 = 32;

//--------------------------------------------------------------------------------------------------
// Types
//--------------------------------------------------------------------------------------------------

/// How a checked session ended. Only a definitive guest event ends one; a
/// transport observation never stands in for an exit.
enum CheckedEnd {
    Exited(i32),
    Failed(ExecFailed),
}

/// The host terminal's saved attributes for one checked session.
///
/// Duplicates fd 0 for ownership of the snapshot only: raw mode is a
/// terminal attribute, so no file-status flag of the caller's shared
/// description changes. Restoration is explicit on every ordinary return and
/// still attempted from `Drop` for cancellation or panic; an observation is
/// reported, never assumed, because a disconnected device cannot be
/// guaranteed restorable.
struct CheckedRawTerminal {
    fd: OwnedFd,
    saved: libc::termios,
    active: bool,
}

//--------------------------------------------------------------------------------------------------
// Methods
//--------------------------------------------------------------------------------------------------

impl CheckedRawTerminal {
    fn enter(stdin_fd: RawFd) -> MicrosandboxResult<Self> {
        let fd = duplicate_cloexec(stdin_fd).map_err(|error| {
            checked_failure(format!(
                "duplicating the host terminal for raw mode: {error}"
            ))
        })?;
        let saved = tcgetattr(fd.as_raw_fd())
            .map_err(|error| checked_failure(format!("reading the host terminal: {error}")))?;
        let mut raw = saved;
        // SAFETY: `raw` is a valid, fully initialized `termios` that this
        // function owns; `cfmakeraw` only writes into it.
        unsafe { libc::cfmakeraw(&mut raw) };
        set_attributes(fd.as_raw_fd(), &raw)
            .map_err(|error| checked_failure(format!("entering raw mode: {error}")))?;
        Ok(Self {
            fd,
            saved,
            active: true,
        })
    }

    /// Idempotent per attempt: a successful restore clears `active` so the
    /// snapshot is never re-applied. A *failed* restore leaves `active` set
    /// on purpose, so `Drop` makes one more bounded attempt when the session
    /// is already on its way out; the first attempt's error is what the
    /// session reports, and the retry is silent.
    fn restore(&mut self) -> MicrosandboxResult<()> {
        if !self.active {
            return Ok(());
        }
        set_attributes(self.fd.as_raw_fd(), &self.saved)
            .map_err(|error| checked_failure(format!("restoring the host terminal: {error}")))?;
        self.active = false;
        Ok(())
    }
}

//--------------------------------------------------------------------------------------------------
// Trait Implementations
//--------------------------------------------------------------------------------------------------

impl Drop for CheckedRawTerminal {
    fn drop(&mut self) {
        let _ = self.restore();
    }
}

//--------------------------------------------------------------------------------------------------
// Functions
//--------------------------------------------------------------------------------------------------

pub(crate) async fn attach(
    backend: &dyn crate::backend::Backend,
    name: &str,
    config: &SandboxConfig,
    cmd: String,
    opts_builder: AttachOptionsBuilder,
) -> MicrosandboxResult<i32> {
    let opts = opts_builder.build()?;
    let client = Arc::new(super::super::fs::agent::connect_agent(backend, name).await?);
    attach_connected(client, config, cmd, opts).await
}

/// Bridge an already-connected agent.
///
/// Production reaches it through [`attach`]; tests drive it over an owned
/// fake relay, so neither needs a sandbox or a VM.
pub(super) async fn attach_connected(
    client: Arc<AgentClient>,
    config: &SandboxConfig,
    cmd: String,
    opts: AttachOptions,
) -> MicrosandboxResult<i32> {
    let detach_keys = opts.resolved_detach_keys()?;
    if opts.checked_session {
        checked_session(client, config, cmd, opts, detach_keys).await
    } else {
        legacy_session(client, config, cmd, opts, detach_keys).await
    }
}

/// The interactive session every existing caller gets.
async fn legacy_session(
    client: Arc<AgentClient>,
    config: &SandboxConfig,
    cmd: String,
    mut opts: AttachOptions,
    detach_keys: Option<DetachKeys>,
) -> MicrosandboxResult<i32> {
    // Taken before the option fields move: the filter is an owned trait
    // object, and the session below only needs the rest.
    let stdin_filter = opts.stdin_filter.take();
    let (cols, rows) = crossterm::terminal::size().unwrap_or((80, 24));

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

    crossterm::terminal::enable_raw_mode()
        .map_err(|e| crate::MicrosandboxError::Terminal(e.to_string()))?;
    let _raw_guard = scopeguard::guard((), |_| {
        let _ = crossterm::terminal::disable_raw_mode();
    });

    let tty_input_path = terminal_path_for_fd(std::io::stdin().as_raw_fd())
        .map_err(|e| crate::MicrosandboxError::Terminal(format!("resolve tty path: {e}")))?;
    let tty_input = open_nonblocking_terminal_input(&tty_input_path)
        .map_err(|e| crate::MicrosandboxError::Terminal(format!("open tty input: {e}")))?;
    let stdin_async = AsyncFd::new(tty_input)
        .map_err(|e| crate::MicrosandboxError::Terminal(format!("async tty input: {e}")))?;

    let mut stdout = tokio::io::stdout();
    let mut sigwinch =
        tokio::signal::unix::signal(tokio::signal::unix::SignalKind::window_change())
            .map_err(|e| crate::MicrosandboxError::Runtime(format!("sigwinch: {e}")))?;

    let mut exit_code: i32 = -1;
    let mut spawn_failure: Option<microsandbox_protocol::exec::ExecFailed> = None;
    let mut match_pos = 0usize;

    // Filtered on its own task: a filter that awaits the guest must not
    // stop this loop from draining guest output (see `StdinFilter`).
    let mut filtered_stdin = stdin_filter.map(FilteredStdin::spawn);

    loop {
        tokio::select! {
            result = stdin_async.readable() => {
                let mut guard = match result {
                    Ok(g) => g,
                    Err(_) => break,
                };

                let mut input_buf = [0u8; 1024];
                match guard.try_io(|inner| {
                    read_from_fd(inner.get_ref().as_raw_fd(), &mut input_buf)
                }) {
                    Ok(Ok(0)) => break,
                    Ok(Ok(n)) => {
                        let data = &input_buf[..n];

                        match route_input(
                            data,
                            detach_keys.as_ref(),
                            &mut match_pos,
                            filtered_stdin.as_ref(),
                        ) {
                            InputRoute::Detach => break,
                            InputRoute::Filtered => {}
                            InputRoute::WorkerEnded => {
                                return Err(crate::MicrosandboxError::Runtime(
                                    STDIN_FILTER_TASK_ENDED.into(),
                                ));
                            }
                            InputRoute::Forward => {
                                // The whole chunk, byte for byte: interception
                                // only decides whether the session ends here.
                                let payload = ExecStdin { data: data.to_vec() };
                                if client.send(id, MessageType::ExecStdin, &payload).await.is_err() {
                                    break;
                                }
                            }
                        }
                    }
                    Ok(Err(e)) if e.kind() == std::io::ErrorKind::Interrupted => continue,
                    Ok(Err(_)) => break,
                    Err(_would_block) => continue,
                }
            }

            // Disabled without a filter: preserve the original set of enabled branches.
            filtered = recv_filtered(&mut filtered_stdin), if filtered_stdin.is_some() => {
                let data = require_filtered(filtered)?;
                let payload = ExecStdin { data };
                if client.send(id, MessageType::ExecStdin, &payload).await.is_err() {
                    break;
                }
            }

            msg = rx.recv() => {
                let Some(msg) = msg else {
                    break;
                };

                let mut should_break = false;

                match msg.t {
                    MessageType::ExecStdout => {
                        if let Ok(out) = msg.payload::<ExecStdout>() {
                            let _ = stdout.write_all(&out.data).await;
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
                                    let _ = stdout.write_all(&out.data).await;
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

                let _ = stdout.flush().await;

                if should_break {
                    break;
                }
            }

            _ = sigwinch.recv() => {
                if let Ok((new_cols, new_rows)) = crossterm::terminal::size() {
                    let payload = ExecResize { rows: new_rows, cols: new_cols };
                    let _ = client.send(id, MessageType::ExecResize, &payload).await;
                }
            }
        }
    }

    if let Some(failure) = spawn_failure {
        return Err(crate::MicrosandboxError::ExecFailed(failure));
    }
    Ok(exit_code)
}

/// The checked session: every completion and I/O fact is either observed or
/// an error.
async fn checked_session(
    client: Arc<AgentClient>,
    config: &SandboxConfig,
    cmd: String,
    mut opts: AttachOptions,
    detach_keys: Option<DetachKeys>,
) -> MicrosandboxResult<i32> {
    // Held back from the exec request like the legacy session does, so the
    // filter is set up by the session that reads the terminal.
    let stdin_filter = opts.stdin_filter.take();
    // Geometry comes from stdin's terminal, which is the descriptor whose
    // input this session forwards; a redirected stdout must not select a
    // different size.
    let (cols, rows) = stdin_terminal_size()?;
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
    // Raw mode begins only here: everything above can fail without having
    // touched the host terminal, and the guard below owns restoration from
    // the first byte of host input.
    let mut raw = CheckedRawTerminal::enter(std::io::stdin().as_raw_fd())?;
    let primary = checked_bridge(&client, id, &mut rx, detach_keys.as_ref(), stdin_filter).await;
    finish_checked_session(&mut raw, primary)
}

async fn checked_bridge(
    client: &Arc<AgentClient>,
    id: u32,
    rx: &mut tokio::sync::mpsc::Receiver<Message>,
    detach_keys: Option<&DetachKeys>,
    stdin_filter: Option<Box<dyn StdinFilter>>,
) -> MicrosandboxResult<i32> {
    // A *new* description of the terminal, marked non-blocking, rather than
    // a dup of fd 0: `O_NONBLOCK` is a file-status flag shared by every
    // descriptor on one description, so duplicating fd 0 would leak it to
    // the caller.
    let tty_input_path = terminal_path_for_fd(std::io::stdin().as_raw_fd())
        .map_err(|error| checked_failure(format!("resolving the host tty path: {error}")))?;
    let tty_input = open_nonblocking_terminal_input(&tty_input_path)
        .map_err(|error| checked_failure(format!("opening the host tty: {error}")))?;
    let input = AsyncFd::new(tty_input)
        .map_err(|error| checked_failure(format!("registering the host tty: {error}")))?;
    let output = CheckedOutput::start(std::io::stdout().as_raw_fd())?;
    let mut sigwinch =
        tokio::signal::unix::signal(tokio::signal::unix::SignalKind::window_change())
            .map_err(|error| checked_failure(format!("watching terminal resizes: {error}")))?;

    let mut match_pos = 0usize;
    // A guest that stopped reading its stdin (`head`, an early exit) keeps
    // its session: only feeding stops, and its own exit event still ends it.
    let mut feeding_input = true;
    let mut input_buffer = [0u8; CHECKED_INPUT_CHUNK_BYTES];
    // Guest output read but not yet handed to the writer. Keeping it here
    // instead of awaiting capacity inside the message handler is what makes a
    // capacity wait interruptible: a closed guest channel or a dead writer
    // still ends the session while the host consumer is not draining.
    let mut pending: VecDeque<Vec<u8>> = VecDeque::new();
    // A filter runs on its own task here exactly as it does for a legacy
    // caller: `push` never blocks this loop, and its output is drained by the
    // arm below, in the order the filter produced it.
    let mut filtered_stdin = stdin_filter.map(FilteredStdin::spawn);

    let end = 'session: loop {
        let Some(chunk) = pending.pop_front() else {
            tokio::select! {
                ready = input.readable(), if feeding_input => {
                    let mut readiness = ready.map_err(|error| {
                        checked_failure(format!("waiting for host terminal input: {error}"))
                    })?;
                    let read = readiness.try_io(|inner| {
                        read_from_fd(inner.get_ref().as_raw_fd(), &mut input_buffer)
                    });
                    let count = match read {
                        Ok(Ok(count)) => count,
                        Ok(Err(error)) if error.kind() == std::io::ErrorKind::Interrupted => {
                            continue;
                        }
                        Ok(Err(error)) => {
                            return Err(checked_failure(format!("reading host terminal input: {error}")));
                        }
                        // Spurious readiness: nothing to read yet.
                        Err(_would_block) => continue,
                    };
                    drop(readiness);

                    if count == 0 {
                        return Err(checked_failure(
                            "host terminal input ended before the guest reported its exit",
                        ));
                    }

                    // Routing is shared with the legacy session, so a filter sees
                    // every chunk the same way and in the same order; only what a
                    // detach, an ended worker or a failed send *mean* is stricter
                    // here. The whole chunk, including any escape byte, reaches the
                    // guest unchanged when nothing detaches.
                    match route_input(
                        &input_buffer[..count],
                        detach_keys,
                        &mut match_pos,
                        filtered_stdin.as_ref(),
                    ) {
                        InputRoute::Detach => {
                            return Err(checked_failure(
                                "the detach key sequence ended the session before the guest reported its exit",
                            ));
                        }
                        InputRoute::Filtered => {}
                        InputRoute::WorkerEnded => {
                            return Err(checked_failure(STDIN_FILTER_TASK_ENDED));
                        }
                        InputRoute::Forward => {
                            client
                                .send(
                                    id,
                                    MessageType::ExecStdin,
                                    &ExecStdin {
                                        data: input_buffer[..count].to_vec(),
                                    },
                                )
                                .await
                                .map_err(|error| {
                                    checked_failure(format!(
                                        "forwarding host terminal input: {error}"
                                    ))
                                })?;
                        }
                    }
                }

                // Filtered bytes reach the guest only here, one produced chunk at
                // a time: the worker is the only thing that ever holds a chunk
                // back, so input order is preserved without this arm ever
                // overtaking the one above.
                filtered = recv_filtered(&mut filtered_stdin), if feeding_input && filtered_stdin.is_some() => {
                    let Some(data) = filtered else {
                        return Err(checked_failure(STDIN_FILTER_TASK_ENDED));
                    };
                    client
                        .send(id, MessageType::ExecStdin, &ExecStdin { data })
                        .await
                        .map_err(|error| {
                            checked_failure(format!("forwarding host terminal input: {error}"))
                        })?;
                }

                message = rx.recv() => {
                    let Some(message) = message else {
                        return Err(closed_session());
                    };
                    if let Some(end) =
                        handle_checked_message(message, &mut pending, &mut feeding_input)?
                    {
                        break 'session end;
                    }
                    // The drain loop must not diverge from the receive arm: a
                    // terminal event batched behind guest output is handled by
                    // exactly the same code.
                    let mut drained = None;
                    while drained.is_none() {
                        match rx.try_recv() {
                            Ok(next) => {
                                drained =
                                    handle_checked_message(next, &mut pending, &mut feeding_input)?;
                            }
                            // A disconnected channel is reported by the next
                            // receive as the closed session it is.
                            Err(_) => break,
                        }
                    }
                    if let Some(end) = drained {
                        break 'session end;
                    }
                }

                // The writer's own verdict, selectable without an enqueue or a
                // finish: an unwritable host descriptor ends the session even
                // while the guest sits at a prompt.
                failure = output.failure() => return Err(failure),

                _ = sigwinch.recv() => {
                    let (cols, rows) = stdin_terminal_size()?;
                    client
                        .send(id, MessageType::ExecResize, &ExecResize { rows, cols })
                        .await
                        .map_err(|error| {
                            checked_failure(format!("sending a terminal resize to the guest: {error}"))
                        })?;
                }
            }
            continue;
        };

        // One staged chunk waits for output capacity. Only session-ending
        // events may interrupt it: `enqueue_chunk` is cancel-safe for a single
        // chunk, and a chunk it did not take goes back to the front of the
        // queue so the byte stream keeps its order.
        let mut delivered = false;
        tokio::select! {
            result = output.enqueue_chunk(&chunk) => {
                result?;
                delivered = true;
            }
            message = rx.recv(), if pending.len() < CHECKED_STAGED_CHUNKS => {
                let Some(message) = message else {
                    return Err(closed_session());
                };
                if let Some(end) =
                    handle_checked_message(message, &mut pending, &mut feeding_input)?
                {
                    break 'session end;
                }
            }
            failure = output.failure() => return Err(failure),
        }
        if !delivered {
            pending.push_front(chunk);
        }
    };

    match end {
        CheckedEnd::Failed(failure) => Err(MicrosandboxError::ExecFailed(failure)),
        CheckedEnd::Exited(code) => {
            // A definitive exit is necessary but not sufficient: output read
            // before the exit event is delivered first, and the ordered finish
            // receipt then proves every earlier byte reached the host
            // descriptor before the terminal is restored.
            while let Some(chunk) = pending.pop_front() {
                output.enqueue_chunk(&chunk).await?;
            }
            output.finish().await?;
            Ok(code)
        }
    }
}

//--------------------------------------------------------------------------------------------------
// Functions: Helpers
//--------------------------------------------------------------------------------------------------

/// One session event: `Some` ends the session, `None` continues it.
///
/// Nothing here awaits: a handler that blocked on output capacity could not
/// receive a guest channel closing behind that output.
fn handle_checked_message(
    message: Message,
    pending: &mut VecDeque<Vec<u8>>,
    feeding_input: &mut bool,
) -> MicrosandboxResult<Option<CheckedEnd>> {
    match message.t {
        MessageType::ExecStdout => {
            let frame: ExecStdout = message.payload().map_err(|error| {
                checked_failure(format!("decoding guest terminal output: {error}"))
            })?;
            stage_output_chunks(frame.data, pending);
            Ok(None)
        }
        MessageType::ExecExited => {
            let exited: ExecExited = message.payload().map_err(|error| {
                checked_failure(format!("decoding the guest exit event: {error}"))
            })?;
            Ok(Some(CheckedEnd::Exited(exited.code)))
        }
        MessageType::ExecFailed => {
            let failed: ExecFailed = message.payload().map_err(|error| {
                checked_failure(format!("decoding the guest spawn failure: {error}"))
            })?;
            Ok(Some(CheckedEnd::Failed(failed)))
        }
        MessageType::ExecStdinError => {
            let error: ExecStdinError = message.payload().map_err(|error| {
                checked_failure(format!("decoding a terminal input failure: {error}"))
            })?;
            if guest_closed_input(&error) {
                *feeding_input = false;
                Ok(None)
            } else {
                Err(checked_failure(format!(
                    "forwarding host terminal input failed in the guest: {}",
                    describe_stdin_error(&error)
                )))
            }
        }
        _ => Ok(None),
    }
}

/// The one exit from a checked session, so no `?` above can skip restoration.
fn finish_checked_session(
    raw: &mut CheckedRawTerminal,
    primary: MicrosandboxResult<i32>,
) -> MicrosandboxResult<i32> {
    match (primary, raw.restore()) {
        (Ok(code), Ok(())) => Ok(code),
        (Ok(_), Err(restore)) => Err(checked_failure(format!(
            "the guest reported its exit but the host terminal could not be restored: {restore}"
        ))),
        (Err(primary), Ok(())) => Err(primary),
        (Err(primary), Err(restore)) => Err(checked_epilogue_error(
            primary,
            [("restoring the host terminal", restore)],
        )),
    }
}

pub(super) fn checked_failure(text: impl Into<String>) -> MicrosandboxError {
    MicrosandboxError::Terminal(text.into())
}

/// A closed event channel is a lost session, never a completed one.
fn closed_session() -> MicrosandboxError {
    checked_failure("the agent connection closed before the guest reported its exit")
}

fn guest_closed_input(error: &ExecStdinError) -> bool {
    match (error.errno_name.as_deref(), error.errno) {
        (Some(name), _) => name == "EPIPE",
        (None, errno) => errno == Some(GUEST_EPIPE),
    }
}

fn describe_stdin_error(error: &ExecStdinError) -> String {
    let errno = error
        .errno_name
        .clone()
        .or_else(|| error.errno.map(|errno| errno.to_string()))
        .unwrap_or_else(|| "no errno".to_string());
    format!("{errno}: {}", error.message)
}

/// Host stdin's window size as `(cols, rows)`.
///
/// Reads fd 0 with `TIOCGWINSZ` rather than `crossterm::terminal::size()`,
/// whose answer may come from a different terminal (stdout's) than the one
/// this session reads. Zero dimensions mean "no size reported" and take the
/// legacy fallback.
fn stdin_terminal_size() -> MicrosandboxResult<(u16, u16)> {
    let mut size: libc::winsize = unsafe { std::mem::zeroed() };
    let rc = unsafe { libc::ioctl(std::io::stdin().as_raw_fd(), libc::TIOCGWINSZ, &mut size) };
    if rc == -1 {
        return Err(checked_failure(format!(
            "reading the stdin terminal size: {}",
            std::io::Error::last_os_error()
        )));
    }
    Ok(normalized_terminal_size((size.ws_col, size.ws_row)))
}

fn normalized_terminal_size((cols, rows): (u16, u16)) -> (u16, u16) {
    if cols == 0 || rows == 0 {
        (80, 24)
    } else {
        (cols, rows)
    }
}

fn tcgetattr(fd: RawFd) -> std::io::Result<libc::termios> {
    loop {
        let mut attributes: libc::termios = unsafe { std::mem::zeroed() };
        let rc = unsafe { libc::tcgetattr(fd, &mut attributes) };
        if rc == 0 {
            return Ok(attributes);
        }
        let error = std::io::Error::last_os_error();
        if error.kind() != std::io::ErrorKind::Interrupted {
            return Err(error);
        }
    }
}

fn set_attributes(fd: RawFd, attributes: &libc::termios) -> std::io::Result<()> {
    loop {
        let rc = unsafe { libc::tcsetattr(fd, libc::TCSANOW, attributes) };
        if rc == 0 {
            return Ok(());
        }
        let error = std::io::Error::last_os_error();
        if error.kind() != std::io::ErrorKind::Interrupted {
            return Err(error);
        }
    }
}

/// A descriptor that the child would not inherit and that this code owns.
pub(super) fn duplicate_cloexec(fd: RawFd) -> std::io::Result<OwnedFd> {
    let duplicate = unsafe { libc::fcntl(fd, libc::F_DUPFD_CLOEXEC, 3) };
    if duplicate == -1 {
        return Err(std::io::Error::last_os_error());
    }
    Ok(unsafe { OwnedFd::from_raw_fd(duplicate) })
}
