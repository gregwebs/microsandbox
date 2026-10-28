//! Attach over an agent connection: bridge a host terminal to a guest PTY
//! exec session.
//!
//! One connection setup serves two deliberately different sessions. The
//! legacy session is the interactive `shell` behavior, whose completion
//! conventions (`Ok(-1)` when no exit event arrived) and best-effort I/O are
//! observable and must not change. The checked session is an opt-in for a
//! caller that owns the process's exit status: a direct command launch has to

use std::future::Future;
use std::os::fd::{AsRawFd, FromRawFd, OwnedFd, RawFd};
use std::pin::Pin;
use std::sync::Arc;

use microsandbox_protocol::{
    exec::{ExecExited, ExecResize, ExecStdin, ExecStdout},
    message::{Message, MessageType},
};
use serde::Serialize;
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

use super::checked::{
    CheckedEnd, CheckedEvent, checked_failure, classify_checked_message, closed_session,
    finish_with_teardown,
};
use super::checked_output::{CheckedOutput, Staging};
use super::{
    AttachOptions, DetachKeys, FilteredStdin, InputRoute, STDIN_FILTER_TASK_ENDED, StdinFilter,
    recv_filtered, require_filtered, route_input,
};

//--------------------------------------------------------------------------------------------------
// Constants
//--------------------------------------------------------------------------------------------------

/// Host terminal read size: one `read(2)`, one `ExecStdin` frame.
const CHECKED_INPUT_CHUNK_BYTES: usize = 1024;

//--------------------------------------------------------------------------------------------------
// Types
//--------------------------------------------------------------------------------------------------

/// A send to the guest that has started.
///
/// Owned across loop iterations and polled as its own arm, or dropped with the
/// session. Never restarted: `AgentClient::send` may already have queued its
/// frame before it starts awaiting the transport, so a second call for the same
/// bytes would duplicate them.
type GuestSend = Pin<Box<dyn Future<Output = MicrosandboxResult<()>> + Send>>;

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

/// What one checked session reads and writes.
///
/// `checked_bridge` opens it from the process's own terminal. Tests open it
/// from pipes they control, which is how a session can be held at the exact
/// boundary where it ends with output still in hand.
pub(super) struct CheckedIo {
    /// Host input on a non-blocking descriptor (a fresh tty description in
    /// production).
    pub(super) input: AsyncFd<std::fs::File>,
    /// The writer thread for guest output.
    pub(super) output: CheckedOutput,
    /// Host terminal resizes.
    pub(super) resizes: tokio::signal::unix::Signal,
}

/// One checked session, between its setup and its conclusion.
///
/// Kept apart from both so the end of the loop is observable on its own: a
/// caller (and a test) can see that the loop returned, and what guest output
/// it still holds, before anything is flushed.
pub(super) struct CheckedLoop<'a> {
    client: &'a Arc<AgentClient>,
    id: u32,
    rx: &'a mut tokio::sync::mpsc::Receiver<Message>,
    detach_keys: Option<&'a DetachKeys>,
    filtered_stdin: Option<FilteredStdin>,
    io: CheckedIo,
    /// Guest output read but not yet accepted by the writer.
    ///
    /// The loop only *offers* the head to the writer and removes it once the
    /// writer accepted it, so a capacity wait holds nothing back and every
    /// other arm stays live: a closed guest channel, a dead writer or the
    /// guest's own exit still ends the session while the host consumer is not
    /// draining. Its bound is by allocation, so a flooding guest cannot grow
    /// the session's memory with retained chunk headers.
    staging: Staging,
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

impl<'a> CheckedLoop<'a> {
    pub(super) fn new(
        client: &'a Arc<AgentClient>,
        id: u32,
        rx: &'a mut tokio::sync::mpsc::Receiver<Message>,
        detach_keys: Option<&'a DetachKeys>,
        stdin_filter: Option<Box<dyn StdinFilter>>,
        io: CheckedIo,
    ) -> Self {
        Self {
            client,
            id,
            rx,
            detach_keys,
            // A filter runs on its own task here exactly as it does for a
            // legacy caller: `push` never blocks this loop, and its output is
            // drained by the arm below, in the order the filter produced it.
            filtered_stdin: stdin_filter.map(FilteredStdin::spawn),
            io,
            staging: Staging::default(),
        }
    }

    /// The session loop: how the guest ended it, or the failure that ended it
    /// first.
    ///
    /// One `select!`, in which every arm whose guard allows it is live on every
    /// iteration. Nothing in a handler awaits: a host consumer that stopped
    /// draining must not stop the session from reading host input, forwarding a
    /// resize, receiving the guest's exit, or reporting the writer's failure.
    pub(super) async fn run(&mut self) -> MicrosandboxResult<CheckedEnd> {
        let mut match_pos = 0usize;
        // A guest that stopped reading its stdin (`head`, an early exit) keeps
        // its session: only feeding stops, and its own exit event still ends it.
        let mut feeding_input = true;
        let mut input_buffer = [0u8; CHECKED_INPUT_CHUNK_BYTES];
        // At most one send to the guest is in flight. A handler only *starts*
        // one; this loop polls it to completion. Holding host input until then
        // keeps keystrokes in read order and never restarts a frame that may
        // already be on its way.
        let mut outbound: Option<GuestSend> = None;

        let end = 'session: loop {
            tokio::select! {
                // The head chunk leaves staging only once the writer accepted
                // it, so the chunk a session ends with is still its own.
                result = enqueue_front(&self.io.output, &self.staging), if !self.staging.is_empty() => {
                    result?;
                    self.staging.pop_delivered();
                }

                // The in-flight send's verdict. A rejected send is a lost
                // session: the transport, not the guest, refused the frame.
                result = finish_send(&mut outbound), if outbound.is_some() => {
                    outbound = None;
                    result?;
                }

                ready = self.io.input.readable(), if feeding_input && outbound.is_none() => {
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
                        self.detach_keys,
                        &mut match_pos,
                        self.filtered_stdin.as_ref(),
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
                            outbound = Some(start_send(
                                self.client,
                                self.id,
                                MessageType::ExecStdin,
                                ExecStdin {
                                    data: input_buffer[..count].to_vec(),
                                },
                                "forwarding host terminal input",
                            ));
                        }
                    }
                }

                // Filtered bytes reach the guest only here, one produced chunk at
                // a time: the worker is the only thing that ever holds a chunk
                // back, so input order is preserved without this arm ever
                // overtaking the one above.
                filtered = recv_filtered(&mut self.filtered_stdin), if feeding_input && self.filtered_stdin.is_some() && outbound.is_none() => {
                    let Some(data) = filtered else {
                        return Err(checked_failure(STDIN_FILTER_TASK_ENDED));
                    };
                    outbound = Some(start_send(
                        self.client,
                        self.id,
                        MessageType::ExecStdin,
                        ExecStdin { data },
                        "forwarding host terminal input",
                    ));
                }

                // A SIGWINCH that arrives while a send is in flight is recorded
                // by the signal stream and forwarded once the send completes, so
                // the geometry the guest ends up with is the latest one.
                _ = self.io.resizes.recv(), if outbound.is_none() => {
                    let (cols, rows) = stdin_terminal_size()?;
                    outbound = Some(start_send(
                        self.client,
                        self.id,
                        MessageType::ExecResize,
                        ExecResize { rows, cols },
                        "sending a terminal resize to the guest",
                    ));
                }

                message = self.rx.recv(), if self.staging.has_room_for_frame() => {
                    let Some(message) = message else {
                        return Err(closed_session());
                    };
                    if let Some(end) =
                        handle_checked_message(message, &mut self.staging, &mut feeding_input)?
                    {
                        break 'session end;
                    }
                    // The drain loop must not diverge from the receive arm: a
                    // terminal event batched behind guest output is handled by
                    // exactly the same code, and it stops for the same reason.
                    let mut drained = None;
                    while drained.is_none() && self.staging.has_room_for_frame() {
                        match self.rx.try_recv() {
                            Ok(next) => {
                                drained = handle_checked_message(
                                    next,
                                    &mut self.staging,
                                    &mut feeding_input,
                                )?;
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
                failure = self.io.output.failure() => return Err(failure),
            }
        };

        Ok(end)
    }

    /// The session's result from the loop's.
    ///
    /// Exactly the epilogue the loop used to run inline: a guest exit delivers
    /// the staged output and awaits the ordered finish receipt, a spawn failure
    /// stays typed, and a failure that ended the loop is returned as it is.
    pub(super) async fn conclude(
        &mut self,
        end: MicrosandboxResult<CheckedEnd>,
    ) -> MicrosandboxResult<i32> {
        match end? {
            CheckedEnd::Failed(failure) => Err(MicrosandboxError::ExecFailed(failure)),
            CheckedEnd::Exited(code) => {
                // A definitive exit is necessary but not sufficient: output read
                // before the exit event is delivered first, and the ordered finish
                // receipt then proves every earlier byte reached the host
                // descriptor before the terminal is restored.
                while let Some(chunk) = self.staging.front() {
                    self.io.output.enqueue_chunk(chunk).await?;
                    self.staging.pop_delivered();
                }
                self.io.output.finish().await?;
                Ok(code)
            }
        }
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
    let resizes = tokio::signal::unix::signal(tokio::signal::unix::SignalKind::window_change())
        .map_err(|error| checked_failure(format!("watching terminal resizes: {error}")))?;

    let mut session = CheckedLoop::new(
        client,
        id,
        rx,
        detach_keys,
        stdin_filter,
        CheckedIo {
            input,
            output,
            resizes,
        },
    );
    let end = session.run().await;
    session.conclude(end).await
}

//--------------------------------------------------------------------------------------------------
// Functions: Helpers
//--------------------------------------------------------------------------------------------------

/// Start one send to the guest, with the context its failure is reported in.
///
/// Started, never awaited here: the loop owns it as a `GuestSend` and polls it
/// as its own arm, so an unresponsive transport cannot stop the session from
/// observing anything else.
fn start_send<T>(
    client: &Arc<AgentClient>,
    id: u32,
    t: MessageType,
    payload: T,
    context: &'static str,
) -> GuestSend
where
    T: Serialize + Send + Sync + 'static,
{
    let client = Arc::clone(client);
    Box::pin(async move {
        client
            .send(id, t, &payload)
            .await
            .map_err(|error| checked_failure(format!("{context}: {error}")))
    })
}

/// The in-flight send's result; never resolves when there is none.
///
/// `select!` evaluates every arm's future expression, so the absent case has to
/// be a future rather than an `unwrap` in the arm.
async fn finish_send(outbound: &mut Option<GuestSend>) -> MicrosandboxResult<()> {
    match outbound {
        Some(send) => send.await,
        None => std::future::pending().await,
    }
}

/// The writer's verdict on the head of staging; never resolves when it is empty.
async fn enqueue_front(output: &CheckedOutput, staging: &Staging) -> MicrosandboxResult<()> {
    match staging.front() {
        Some(chunk) => output.enqueue_chunk(chunk).await,
        None => std::future::pending().await,
    }
}

/// One session event: `Some` ends the session, `None` continues it.
///
/// Nothing here awaits: a handler that blocked on output capacity could not
/// receive a guest channel closing behind that output. Decoding is shared with
/// the Windows loop; only the sink for guest output is this platform's own.
fn handle_checked_message(
    message: Message,
    staging: &mut Staging,
    feeding_input: &mut bool,
) -> MicrosandboxResult<Option<CheckedEnd>> {
    match classify_checked_message(message)? {
        CheckedEvent::Output(data) => {
            staging.stage(data);
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

/// The one exit from a checked session, so no `?` above can skip restoration.
fn finish_checked_session(
    raw: &mut CheckedRawTerminal,
    primary: MicrosandboxResult<i32>,
) -> MicrosandboxResult<i32> {
    let teardown = raw
        .restore()
        .err()
        .map(|error| ("restoring the host terminal", error))
        .into_iter()
        .collect();
    finish_with_teardown(
        primary,
        teardown,
        "the guest reported its exit but the host terminal could not be restored",
    )
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

//--------------------------------------------------------------------------------------------------
// Tests
//--------------------------------------------------------------------------------------------------

#[cfg(test)]
mod tests {
    //! The checked loop as a unit, without a terminal or a VM.
    //!
    //! The test owns the pipes, the writer's queue and the event channel, so it
    //! can hold guest output at the exact boundary where a session ends and see
    //! what the loop still had in hand when it returned. Nothing here infers
    //! queue state from byte counts or sleeps: the writer is blocked by
    //! construction before the loop is polled.
    //!
    //! The fixture registers the process-wide `SIGWINCH` handler that every
    //! checked session installs; its default disposition is "ignore", so no
    //! other test changes behavior. Resize *forwarding* is covered by the PTY
    //! cases instead: this test's fd 0 is not a terminal.

    use std::future::Future;
    use std::io::{PipeReader, PipeWriter, Read, Write};
    use std::os::fd::{AsRawFd, OwnedFd};
    use std::pin::Pin;
    use std::sync::Arc;
    use std::time::Duration;

    use microsandbox_protocol::codec;
    use microsandbox_protocol::exec::{ExecExited, ExecStdin, ExecStdout};
    use microsandbox_protocol::message::{Message, MessageType};
    use tokio::io::{AsyncReadExt, DuplexStream};
    use tokio::sync::mpsc;

    use crate::agent::AgentClient;
    use crate::sandbox::SandboxConfig;

    use super::super::checked_output::{
        CHECKED_OUTPUT_CHUNK_BYTES, CHECKED_OUTPUT_MAX_PENDING_BYTES,
    };
    use super::*;

    /// A bounded wait: a session that never concludes fails the test instead of
    /// hanging the suite.
    async fn within<F: std::future::Future>(future: F) -> F::Output {
        tokio::time::timeout(Duration::from_secs(5), future)
            .await
            .expect("the checked loop did not make progress")
    }

    /// Which output pipe a fixture starts its writer on.
    #[derive(Clone, Copy)]
    enum OutputPipe {
        /// An empty pipe, read by whoever the test hands the read end to.
        Open,
        /// A pipe filled until a write would block, so the writer's first
        /// `write(2)` blocks and nothing it is given is ever released.
        Prefilled,
        /// A pipe whose read end is closed, so the writer's first write fails.
        Closed,
    }

    /// A checked loop over pipes and a relay this test owns.
    struct LoopFixture {
        client: Arc<AgentClient>,
        /// The relay's end of the agent connection; nothing reads it unless a
        /// test takes it.
        relay: Option<DuplexStream>,
        /// Guest events, injected straight into the loop's receiver.
        events: mpsc::Sender<Message>,
        rx: mpsc::Receiver<Message>,
        /// The connection's own decoded stream. Held open, never read: events
        /// are injected on `events` instead, and dropping this receiver would
        /// stop the connection's reader.
        client_rx: mpsc::Receiver<Message>,
        /// The exec request's correlation id.
        id: u32,
        /// Write end of the host-input pipe.
        keyboard: PipeWriter,
        /// Read end of the output pipe; `None` for [`OutputPipe::Closed`].
        screen: Option<PipeReader>,
        /// Bytes already in the output pipe when the writer started.
        prefill: Vec<u8>,
        /// The loop's own I/O, taken by the first session built from it.
        io: Option<CheckedIo>,
    }

    impl LoopFixture {
        /// The checked loop over this fixture's relay, events and I/O, with an
        /// optional stdin filter.
        fn session_with(&mut self, filter: Option<Box<dyn StdinFilter>>) -> CheckedLoop<'_> {
            let io = self.io.take().expect("the fixture's io");
            CheckedLoop::new(&self.client, self.id, &mut self.rx, None, filter, io)
        }

        /// The checked loop over this fixture's relay, events and I/O.
        fn session(&mut self) -> CheckedLoop<'_> {
            self.session_with(None)
        }

        /// Deliver one guest event, exactly as the relay would.
        async fn inject(&self, message: Message) {
            self.events
                .send(message)
                .await
                .expect("the loop's event channel");
        }
    }

    /// A loop over pipes the test owns and a relay it never has to answer.
    async fn fixture(output_pipe: OutputPipe, duplex_bytes: usize) -> LoopFixture {
        let (mut relay, client_stream) = tokio::io::duplex(duplex_bytes);
        super::super::pty_tests::relay_handshake(&mut relay).await;
        let client =
            AgentClient::connect_stream_with_timeout(client_stream, Duration::from_secs(10))
                .await
                .expect("the fixture relay handshake");
        let request = build_exec_request(
            &SandboxConfig::default(),
            "bash".to_string(),
            Vec::new(),
            None,
            None,
            &[],
            &[],
            true,
            24,
            80,
        );
        let (id, client_rx) = client
            .stream(MessageType::ExecRequest, &request)
            .await
            .expect("a stream id");
        // Consumed here, so a test that reads the relay sees only the frames the
        // session sends.
        microsandbox_protocol::codec::read_raw_frame(&mut relay)
            .await
            .expect("the exec request frame");

        let (keyboard_read, keyboard) = std::io::pipe().expect("an input pipe");
        set_nonblocking(keyboard_read.as_raw_fd()).expect("a non-blocking input pipe");
        let input = AsyncFd::new(std::fs::File::from(OwnedFd::from(keyboard_read)))
            .expect("register the input pipe");
        let resizes = tokio::signal::unix::signal(tokio::signal::unix::SignalKind::window_change())
            .expect("the SIGWINCH handler");

        let mut prefill = Vec::new();
        let (screen, output) = match output_pipe {
            OutputPipe::Open => {
                let (read_end, write_end) = std::io::pipe().expect("an output pipe");
                let output = CheckedOutput::start(write_end.as_raw_fd()).expect("start the writer");
                (Some(read_end), output)
            }
            OutputPipe::Prefilled => {
                let (read_end, write_end) = std::io::pipe().expect("an output pipe");
                set_nonblocking(write_end.as_raw_fd()).expect("a non-blocking output pipe");
                // Fill the pipe and the kernel buffer behind it with a pattern
                // the test can recognise, until a write would block.
                let block = vec![0xEEu8; 4096];
                while let Ok(written) = (&write_end).write(&block) {
                    prefill.extend_from_slice(&block[..written]);
                }
                // The flag lives on the shared open file description, and the
                // writer's duplicate would otherwise see `EAGAIN` as a failure.
                clear_nonblocking(write_end.as_raw_fd()).expect("a blocking output pipe");
                let output = CheckedOutput::start(write_end.as_raw_fd()).expect("start the writer");
                (Some(read_end), output)
            }
            OutputPipe::Closed => {
                let (read_end, write_end) = std::io::pipe().expect("an output pipe");
                drop(read_end);
                let output = CheckedOutput::start(write_end.as_raw_fd()).expect("start the writer");
                (None, output)
            }
        };

        let (events, rx) = mpsc::channel(16);

        LoopFixture {
            client: Arc::new(client),
            relay: Some(relay),
            events,
            rx,
            client_rx,
            id,
            keyboard,
            screen,
            prefill,
            io: Some(CheckedIo {
                input,
                output,
                resizes,
            }),
        }
    }

    /// Fill the writer's queue to its bound and return the bytes queued.
    ///
    /// The consumer never drains, so the writer's first `write(2)` blocks and a
    /// reservation is released only after a *whole* chunk is written: every
    /// chunk of the bound therefore stays reserved, and the next enqueue has to
    /// wait. That is what makes a blocked enqueue deterministic.
    async fn fill_queue(output: &CheckedOutput) -> Vec<u8> {
        let mut queued = Vec::new();
        let chunk = vec![b'q'; CHECKED_OUTPUT_CHUNK_BYTES];
        for _ in 0..CHECKED_OUTPUT_MAX_PENDING_BYTES / CHECKED_OUTPUT_CHUNK_BYTES {
            within(output.enqueue_chunk(&chunk))
                .await
                .expect("enqueue inside the bound");
            queued.extend_from_slice(&chunk);
        }
        let mut overflow = Box::pin(output.enqueue_chunk(&chunk));
        assert!(
            futures::poll!(&mut overflow).is_pending(),
            "the writer's queue accepted a chunk past its bound"
        );
        queued
    }

    /// Drain the output pipe to EOF on its own thread.
    fn read_screen(reader: PipeReader) -> std::thread::JoinHandle<Vec<u8>> {
        let mut screen = std::fs::File::from(OwnedFd::from(reader));
        std::thread::spawn(move || {
            let mut seen = Vec::new();
            screen
                .read_to_end(&mut seen)
                .expect("drain the output pipe");
            seen
        })
    }

    fn stdout(id: u32, data: &[u8]) -> Message {
        Message::with_payload(
            MessageType::ExecStdout,
            id,
            &ExecStdout {
                data: data.to_vec(),
            },
        )
        .expect("a guest output frame")
    }

    fn exited(id: u32, code: i32) -> Message {
        Message::with_payload(MessageType::ExecExited, id, &ExecExited { code })
            .expect("a guest exit frame")
    }

    /// Replaces every host chunk with `n` bytes of `b'z'`.
    ///
    /// Larger than the fixture's duplex buffer, so a send the loop starts can
    /// never complete until something reads the relay: it stays in flight for
    /// as long as the test needs it to.
    struct Expand(usize);

    impl StdinFilter for Expand {
        fn filter<'a>(
            &'a mut self,
            _data: &'a [u8],
        ) -> Pin<Box<dyn Future<Output = Vec<u8>> + Send + 'a>> {
            let expanded = vec![b'z'; self.0];
            Box::pin(async move { expanded })
        }
    }

    fn set_nonblocking(fd: RawFd) -> std::io::Result<()> {
        set_blocking(fd, false)
    }

    fn clear_nonblocking(fd: RawFd) -> std::io::Result<()> {
        set_blocking(fd, true)
    }

    fn set_blocking(fd: RawFd, blocking: bool) -> std::io::Result<()> {
        let current = unsafe { libc::fcntl(fd, libc::F_GETFL) };
        if current == -1 {
            return Err(std::io::Error::last_os_error());
        }
        let flags = if blocking {
            current & !libc::O_NONBLOCK
        } else {
            current | libc::O_NONBLOCK
        };
        if unsafe { libc::fcntl(fd, libc::F_SETFL, flags) } == -1 {
            return Err(std::io::Error::last_os_error());
        }
        Ok(())
    }

    #[tokio::test]
    async fn the_loop_returns_the_guest_exit_with_output_in_hand() {
        let mut fixture = fixture(OutputPipe::Open, 64 * 1024).await;
        let screen = read_screen(fixture.screen.take().expect("an output pipe"));
        let id = fixture.id;
        fixture.inject(stdout(id, b"abc")).await;
        fixture.inject(exited(id, 3)).await;

        let mut session = fixture.session();
        let end = within(session.run())
            .await
            .expect("a guest exit ends the loop");
        assert!(
            matches!(end, CheckedEnd::Exited(3)),
            "the loop must report the guest's own status"
        );
        assert_eq!(
            within(session.conclude(Ok(end)))
                .await
                .expect("the guest exit is the session's result"),
            3
        );
        assert_eq!(
            screen.join().expect("the screen thread"),
            b"abc",
            "guest output must reach the descriptor before the finish receipt"
        );
    }

    #[tokio::test]
    async fn a_closed_event_channel_is_a_failure() {
        let LoopFixture {
            client,
            events,
            mut rx,
            id,
            io,
            ..
        } = fixture(OutputPipe::Open, 64 * 1024).await;
        drop(events);

        let mut session = CheckedLoop::new(
            &client,
            id,
            &mut rx,
            None,
            None,
            io.expect("the fixture's io"),
        );
        let failure = within(session.run())
            .await
            .expect_err("a closed channel without an exit is not a completed session");
        assert!(
            failure
                .to_string()
                .contains("closed before the guest reported its exit"),
            "a closed channel must be reported as the lost session it is: {failure}"
        );
    }

    #[tokio::test]
    async fn exit_during_a_blocked_enqueue_keeps_the_staged_chunk() {
        let mut fixture = fixture(OutputPipe::Prefilled, 64 * 1024).await;
        // The writer's queue is full by construction from here on, so nothing
        // can be accepted until the test starts draining the screen.
        let queued = fill_queue(&fixture.io.as_ref().expect("the fixture's io").output).await;
        let prefill = fixture.prefill.clone();
        // Held, not drained: the loop must end while the consumer is stalled.
        let reader = fixture.screen.take().expect("an output pipe");

        let staged = [
            vec![0xA1u8; CHECKED_OUTPUT_CHUNK_BYTES],
            vec![0xA2u8; CHECKED_OUTPUT_CHUNK_BYTES],
            vec![0xA3u8; 100],
        ];
        // Injected before the loop is polled at all: `enqueue` cannot be ready
        // while the writer is blocked, so the receive arm is the only one that
        // can run, and the exit is what interrupts the capacity wait.
        fixture.inject(exited(fixture.id, 5)).await;

        let mut session = fixture.session();
        for chunk in &staged {
            session.staging.stage(chunk.clone());
        }

        let end = within(session.run())
            .await
            .expect("the exit event itself ends the loop");
        assert!(
            matches!(end, CheckedEnd::Exited(5)),
            "the loop must report the guest's own status"
        );
        assert_eq!(
            session.staging.chunks().collect::<Vec<_>>(),
            staged.iter().map(Vec::as_slice).collect::<Vec<_>>(),
            "a chunk taken for a capacity wait must be back at the head of staging"
        );

        // Only now may a consumer drain: nothing the loop did depended on it.
        let screen = read_screen(reader);
        assert_eq!(
            within(session.conclude(Ok(end)))
                .await
                .expect("the guest exit is the session's result"),
            5
        );
        let mut expected = prefill;
        expected.extend_from_slice(&queued);
        for chunk in &staged {
            expected.extend_from_slice(chunk);
        }
        drop(session);
        assert_eq!(
            screen.join().expect("the screen thread"),
            expected,
            "every byte the guest wrote must reach the descriptor, in order"
        );
    }

    /// Start a blocked send from the fixture's keyboard.
    ///
    /// Reading the frame's length prefix proves the loop *started* the send;
    /// the payload cannot fit in the duplex buffer and nothing reads it, so the
    /// send stays in flight until the loop drops it.
    async fn blocked_send(relay: &mut DuplexStream, keyboard: &PipeWriter) {
        let mut keyboard = keyboard;
        keyboard.write_all(b"z").expect("type at the terminal");
        let mut length = [0u8; 4];
        within(relay.read_exact(&mut length))
            .await
            .expect("the loop must forward host input");
        assert!(
            u32::from_be_bytes(length) as usize > 1024 * 1024,
            "the filtered chunk must be one frame larger than the duplex buffer"
        );
    }

    #[tokio::test]
    async fn an_exit_ends_the_session_while_a_guest_send_is_blocked() {
        let LoopFixture {
            client,
            relay,
            events,
            rx,
            // Held open: dropping it would stop the connection's reader.
            client_rx: _client_rx,
            id,
            keyboard,
            screen: _screen,
            prefill: _prefill,
            io,
        } = fixture(OutputPipe::Open, 64 * 1024).await;
        let mut relay = relay.expect("the fixture's relay");
        let mut rx = rx;
        let mut session = CheckedLoop::new(
            &client,
            id,
            &mut rx,
            None,
            Some(Box::new(Expand(1024 * 1024))),
            io.expect("the fixture's io"),
        );

        // The transport never accepts the frame, so the send cannot complete.
        let mut run = Box::pin(session.run());
        tokio::select! {
            result = blocked_send(&mut relay, &keyboard) => result,
            end = &mut run => panic!("the loop ended before the send was in flight: {end:?}"),
        }
        // Injected while that send is still in flight: the guest's own exit has
        // to end the session regardless of the send.
        events
            .send(exited(id, 4))
            .await
            .expect("the loop's event channel");

        let end = within(&mut run)
            .await
            .expect("the guest exit ends the session even with a send in flight");
        assert!(
            matches!(end, CheckedEnd::Exited(4)),
            "the loop must report the guest's own status"
        );
    }

    #[tokio::test]
    async fn an_output_failure_ends_the_session_while_a_guest_send_is_blocked() {
        let LoopFixture {
            client,
            relay,
            events,
            rx,
            client_rx: _client_rx,
            id,
            keyboard,
            screen: _screen,
            prefill: _prefill,
            io,
        } = fixture(OutputPipe::Closed, 64 * 1024).await;
        let mut relay = relay.expect("the fixture's relay");
        let mut rx = rx;
        let mut session = CheckedLoop::new(
            &client,
            id,
            &mut rx,
            None,
            Some(Box::new(Expand(1024 * 1024))),
            io.expect("the fixture's io"),
        );

        let mut run = Box::pin(session.run());
        tokio::select! {
            result = blocked_send(&mut relay, &keyboard) => result,
            end = &mut run => panic!("the loop ended before the send was in flight: {end:?}"),
        }
        // The writer's first write fails, and that verdict has to reach the
        // session while the send is still waiting for the transport.
        events
            .send(stdout(id, &[b'x'; 4096]))
            .await
            .expect("the loop's event channel");

        let failure = within(&mut run)
            .await
            .expect_err("an unwritable descriptor ends the session");
        assert!(
            failure.to_string().contains("writing guest output"),
            "the writer's own failure must be reported: {failure}"
        );
    }

    #[tokio::test]
    async fn input_is_forwarded_while_output_waits_for_capacity() {
        let fixture = fixture(OutputPipe::Prefilled, 64 * 1024).await;
        // The writer's queue and the pipe are both full, and the held screen
        // means no capacity can free for as long as the test runs.
        let io = fixture.io.as_ref().expect("the fixture's io");
        fill_queue(&io.output).await;

        let LoopFixture {
            client,
            relay,
            events: _events,
            rx,
            client_rx: _client_rx,
            id,
            keyboard,
            screen: _screen,
            prefill: _prefill,
            io,
        } = fixture;
        let mut relay = relay.expect("the fixture's relay");
        let mut rx = rx;
        let mut session = CheckedLoop::new(
            &client,
            id,
            &mut rx,
            None,
            None,
            io.expect("the fixture's io"),
        );
        for chunk in [
            vec![0xB1u8; CHECKED_OUTPUT_CHUNK_BYTES],
            vec![0xB2u8; CHECKED_OUTPUT_CHUNK_BYTES],
        ] {
            session.staging.stage(chunk);
        }

        let mut keyboard = keyboard;
        keyboard.write_all(&[0x03]).expect("type at the terminal");

        let message = within(async {
            tokio::select! {
                end = session.run() => {
                    panic!("the loop ended with output still waiting for capacity: {end:?}")
                }
                message = codec::read_message(&mut relay) => {
                    message.expect("a guest frame")
                }
            }
        })
        .await;

        assert_eq!(message.t, MessageType::ExecStdin);
        let frame: ExecStdin = message.payload().expect("a stdin payload");
        assert_eq!(
            frame.data,
            vec![0x03],
            "host input must reach the guest while output waits for capacity"
        );
    }
}
