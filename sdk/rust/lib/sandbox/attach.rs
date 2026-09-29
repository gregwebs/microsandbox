//! Interactive attach types for terminal bridging with sandboxes.

use std::{fmt, future::Future, panic::AssertUnwindSafe, pin::Pin};

use futures::FutureExt;
use microsandbox_types::EnvVar;
use tokio::sync::mpsc;
use tokio_util::task::AbortOnDropHandle;

use crate::MicrosandboxResult;

use super::exec::Rlimit;

//--------------------------------------------------------------------------------------------------
// Constants
//--------------------------------------------------------------------------------------------------

/// Filtered chunks the worker may produce ahead of the attach loop. When
/// the channel is full the worker waits, never the loop. Input towards the
/// worker is unbounded (see `FilteredStdin::push`).
const FILTERED_STDIN_CAPACITY: usize = 16;

/// Error reported when the stdin-filter worker has ended (an unwinding panic in
/// the filter, or its output channel closing). Single-sourced so the closed
/// output channel (`require_filtered`) and both attach loops' `WorkerEnded`
/// arms cannot drift from each other.
pub(crate) const STDIN_FILTER_TASK_ENDED: &str = "stdin filter task ended";

//--------------------------------------------------------------------------------------------------
// Types
//--------------------------------------------------------------------------------------------------

/// Options for attaching to a sandbox with an interactive session.
///
/// The host terminal is set to raw mode for the duration of the attach session.
/// The guest process runs in a PTY, enabling terminal features (colors, line
/// editing, Ctrl+C → SIGINT).
#[derive(Debug, Default)]
pub struct AttachOptions {
    /// Arguments.
    pub(crate) args: Vec<String>,

    /// Environment variables (merged with sandbox env).
    pub(crate) env: Vec<EnvVar>,

    /// Working directory (default: sandbox's workdir).
    pub(crate) cwd: Option<String>,

    /// Guest user override for the attached command.
    pub(crate) user: Option<String>,

    /// Detach key sequence (default: `"ctrl-]"`).
    ///
    /// Uses Docker-style syntax: `"ctrl-<char>"` for control keys,
    /// comma-separated for multi-key sequences (e.g., `"ctrl-p,ctrl-q"`).
    pub(crate) detach_keys: Option<String>,

    /// Resource limits.
    pub(crate) rlimits: Vec<Rlimit>,

    /// Transforms terminal input after the detach-key scan, before it is
    /// sent to the guest. `None` forwards input unchanged.
    pub(crate) stdin_filter: Option<Box<dyn StdinFilter>>,
}

/// Builder for `AttachOptions`.
#[derive(Default)]
pub struct AttachOptionsBuilder {
    options: AttachOptions,
}

/// Hook applied to each chunk of terminal input during an interactive
/// attach, after the detach-key scan and before the bytes are sent to the
/// guest.
///
/// The returned future resolves to the bytes to forward for this chunk. It
/// may be empty to drop the chunk, or longer or different to replace it.
/// Chunks are filtered one at a time, in input order, on a task separate
/// from the attach loop. The loop therefore remains able to keep draining
/// guest output while a filter awaits I/O, including requests to the same
/// sandbox such as `fs().write()`. This is the API guarantee of the task
/// boundary, not a claim that end-to-end relay liveness is verified on
/// every backend: only local combined-port relay behavior has been traced;
/// dual-port, cloud and Windows interactive filtering are unverified.
/// Later chunks wait until the current one is done.
///
/// Ordinary failures and timeouts inside `filter` are entirely caller-owned:
/// the trait returns `Vec<u8>`, not `Result`, and the SDK applies no timeout.
/// A filter that can fail should bound its own work (for example with
/// `tokio::time::timeout`) and return `data.to_vec()` to forward the original bytes.
/// An unwinding panic in `filter()` or its future ends the worker and the attach
/// session with `Runtime("stdin filter task ended")`; no raw input is forwarded.
/// The guest may keep running as it does after detach. With `panic = "abort"`,
/// no policy can intercept the process exit.
/// The detach sequence is matched on terminal input before the filter runs,
/// so it always works; emitted filter bytes are NOT scanned for detach keys
/// (an emitted `0x1d` goes to the guest). Input still queued or in
/// flight when the session ends is discarded; the filter is dropped
/// at its current await point.
pub trait StdinFilter: Send + 'static {
    /// Returns the bytes to forward for one chunk of terminal input.
    fn filter<'a>(
        &'a mut self,
        data: &'a [u8],
    ) -> Pin<Box<dyn Future<Output = Vec<u8>> + Send + 'a>>;
}

/// A [`StdinFilter`] running on its own task for one attach session.
///
/// Chunks come out in the order they were pushed. Dropping this aborts the
/// task and drops the filter.
pub(crate) struct FilteredStdin {
    input: mpsc::UnboundedSender<Vec<u8>>,
    output: mpsc::Receiver<Vec<u8>>,
    _task: AbortOnDropHandle<()>,
}

/// What the attach loop does with one chunk of terminal input.
#[derive(Debug, PartialEq, Eq)]
pub(crate) enum InputRoute {
    /// The chunk completed the detach sequence; end the session.
    Detach,
    /// No filter is set: send the chunk to the guest now, as before.
    Forward,
    /// The chunk was queued on the filter task.
    Filtered,
    /// The worker ended; fail explicitly rather than silently lose input.
    WorkerEnded,
}

/// Parsed detach key sequence.
///
/// Matches raw stdin bytes against the configured detach sequence.
pub(crate) struct DetachKeys {
    /// The byte sequence that triggers detach.
    sequence: Vec<u8>,
}

//--------------------------------------------------------------------------------------------------
// Methods
//--------------------------------------------------------------------------------------------------

impl AttachOptionsBuilder {
    /// Prepend arguments resolved by a higher-level execution helper.
    pub(crate) fn prepend_args(mut self, args: impl IntoIterator<Item = String>) -> Self {
        self.options.args.splice(0..0, args);
        self
    }

    /// Append a command-line argument to the attached command.
    pub fn arg(mut self, arg: impl Into<String>) -> Self {
        self.options.args.push(arg.into());
        self
    }

    /// Append multiple command-line arguments.
    pub fn args(mut self, args: impl IntoIterator<Item = impl Into<String>>) -> Self {
        self.options.args.extend(args.into_iter().map(Into::into));
        self
    }

    /// Override the working directory for the attached session.
    pub fn cwd(mut self, cwd: impl Into<String>) -> Self {
        self.options.cwd = Some(cwd.into());
        self
    }

    /// Override the guest user for the attached session.
    pub fn user(mut self, user: impl Into<String>) -> Self {
        self.options.user = Some(user.into());
        self
    }

    /// Set an environment variable for the attached session. Merged on
    /// top of sandbox-level env vars.
    pub fn env(mut self, key: impl Into<String>, value: impl Into<String>) -> Self {
        self.options.env.push(EnvVar::new(key, value));
        self
    }

    /// Set multiple environment variables for the attached session.
    pub fn envs(
        mut self,
        vars: impl IntoIterator<Item = (impl Into<String>, impl Into<String>)>,
    ) -> Self {
        self.options
            .env
            .extend(vars.into_iter().map(|(key, value)| EnvVar::new(key, value)));
        self
    }

    /// Key sequence to detach from the session without stopping it.
    /// Uses Docker-style syntax: `"ctrl-]"` (default), `"ctrl-p,ctrl-q"`,
    /// or a single character like `"q"`.
    pub fn detach_keys(mut self, keys: impl Into<String>) -> Self {
        self.options.detach_keys = Some(keys.into());
        self
    }

    /// Set a resource limit (soft = hard).
    pub fn rlimit(mut self, resource: super::exec::RlimitResource, limit: u64) -> Self {
        self.options.rlimits.push(Rlimit {
            resource,
            soft: limit,
            hard: limit,
        });
        self
    }

    /// Set a resource limit with different soft/hard values.
    pub fn rlimit_range(
        mut self,
        resource: super::exec::RlimitResource,
        soft: u64,
        hard: u64,
    ) -> Self {
        self.options.rlimits.push(Rlimit {
            resource,
            soft,
            hard,
        });
        self
    }

    /// Transform terminal input before it reaches the guest. See [`StdinFilter`].
    pub fn stdin_filter(mut self, filter: impl StdinFilter) -> Self {
        self.options.stdin_filter = Some(Box::new(filter));
        self
    }

    /// Finalize the options. Called automatically when using the closure form.
    ///
    /// Returns an error if any rlimit entry has `soft > hard`.
    pub fn build(self) -> MicrosandboxResult<AttachOptions> {
        super::exec::validate_rlimits(&self.options.rlimits)?;
        Ok(self.options)
    }
}

impl DetachKeys {
    /// Default detach key: Ctrl+] (0x1D).
    const DEFAULT: u8 = 0x1d;

    /// Parse a detach key specification string.
    ///
    /// Supports Docker-style syntax:
    /// - `"ctrl-]"` → `[0x1D]`
    /// - `"ctrl-a"` → `[0x01]`
    /// - `"ctrl-p,ctrl-q"` → `[0x10, 0x11]`
    pub fn parse(spec: &str) -> MicrosandboxResult<Self> {
        let mut sequence = Vec::new();
        for part in spec.split(',') {
            let part = part.trim();
            if let Some(ch) = part.strip_prefix("ctrl-") {
                let byte = match ch {
                    "]" => 0x1d,
                    "[" => 0x1b,
                    "\\" => 0x1c,
                    "^" => 0x1e,
                    "_" => 0x1f,
                    "@" => 0x00,
                    c if c.len() == 1 => {
                        let b = c.as_bytes()[0];
                        if b.is_ascii_lowercase() {
                            b - b'a' + 1
                        } else if b.is_ascii_uppercase() {
                            b - b'A' + 1
                        } else {
                            return Err(crate::MicrosandboxError::InvalidConfig(format!(
                                "invalid detach key: {part}"
                            )));
                        }
                    }
                    _ => {
                        return Err(crate::MicrosandboxError::InvalidConfig(format!(
                            "invalid detach key: {part}"
                        )));
                    }
                };
                sequence.push(byte);
            } else if part.len() == 1 {
                sequence.push(part.as_bytes()[0]);
            } else {
                return Err(crate::MicrosandboxError::InvalidConfig(format!(
                    "invalid detach key: {part}"
                )));
            }
        }

        if sequence.is_empty() {
            sequence.push(Self::DEFAULT);
        }

        Ok(Self { sequence })
    }

    /// Create the default detach keys (Ctrl+]).
    pub fn default_keys() -> Self {
        Self {
            sequence: vec![Self::DEFAULT],
        }
    }

    /// Returns the detach key sequence bytes.
    pub fn sequence(&self) -> &[u8] {
        &self.sequence
    }
}

impl FilteredStdin {
    /// Spawn `filter` on a new task. Must be called within a Tokio runtime.
    pub(crate) fn spawn(filter: Box<dyn StdinFilter>) -> Self {
        let (input, input_rx) = mpsc::unbounded_channel();
        let (output_tx, output) = mpsc::channel(FILTERED_STDIN_CAPACITY);
        let task =
            AbortOnDropHandle::new(tokio::spawn(run_stdin_filter(filter, input_rx, output_tx)));
        Self {
            input,
            output,
            _task: task,
        }
    }

    /// Queue a chunk for filtering. Returns false if the worker has stopped.
    /// Never waits: the attach loop must keep reading the terminal (for the detach keys) and draining guest output
    /// while a filter is busy.
    pub(crate) fn push(&self, chunk: Vec<u8>) -> bool {
        self.input.send(chunk).is_ok()
    }

    /// Next non-empty filtered chunk, or None if the worker ended. Cancel-safe for `select!`.
    pub(crate) async fn recv(&mut self) -> Option<Vec<u8>> {
        self.output.recv().await
    }
}

//--------------------------------------------------------------------------------------------------
// Trait Implementations
//--------------------------------------------------------------------------------------------------

impl fmt::Debug for dyn StdinFilter {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str("StdinFilter")
    }
}

//--------------------------------------------------------------------------------------------------
// Functions
//--------------------------------------------------------------------------------------------------

/// Scan `data` for the detach sequence. When it does not detach, route the
/// chunk to the filter if one is set. The scan always runs first, so a
/// filter never sees, and cannot delay, the detach keys.
pub(crate) fn route_input(
    data: &[u8],
    detach_seq: &[u8],
    match_pos: &mut usize,
    filter: Option<&FilteredStdin>,
) -> InputRoute {
    if input_contains_detach_sequence(data, detach_seq, match_pos) {
        return InputRoute::Detach;
    }
    match filter {
        Some(filter) => {
            if filter.push(data.to_vec()) {
                InputRoute::Filtered
            } else {
                InputRoute::WorkerEnded
            }
        }
        None => InputRoute::Forward,
    }
}

/// Resolves to the next filtered chunk, or never when no filter is set.
pub(crate) async fn recv_filtered(filter: &mut Option<FilteredStdin>) -> Option<Vec<u8>> {
    match filter {
        Some(filter) => filter.recv().await,
        None => std::future::pending().await,
    }
}

/// Shared failure handling for a filtered output channel that closes.
/// Used by both platform loops so the None path is independently unit-testable.
pub(crate) fn require_filtered(data: Option<Vec<u8>>) -> MicrosandboxResult<Vec<u8>> {
    data.ok_or_else(|| crate::MicrosandboxError::Runtime(STDIN_FILTER_TASK_ENDED.into()))
}

pub(crate) fn input_contains_detach_sequence(
    data: &[u8],
    detach_seq: &[u8],
    match_pos: &mut usize,
) -> bool {
    if detach_seq.is_empty() {
        return false;
    }

    for &byte in data {
        if byte == detach_seq[*match_pos] {
            *match_pos += 1;
            if *match_pos == detach_seq.len() {
                return true;
            }
        } else {
            *match_pos = 0;
            if byte == detach_seq[0] {
                *match_pos = 1;
            }
        }
    }

    false
}

/// Filter chunks one at a time, in order. An unwinding panic ends the worker;
/// the closed output channel makes the attach loop return
/// Runtime("stdin filter task ended") through `require_filtered(None)`.
/// A panicking Drop also closes the output channel when the worker dies.
async fn run_stdin_filter(
    mut filter: Box<dyn StdinFilter>,
    mut input: mpsc::UnboundedReceiver<Vec<u8>>,
    output: mpsc::Sender<Vec<u8>>,
) {
    while let Some(chunk) = input.recv().await {
        // The call is inside the async block: catch both a synchronous
        // `filter()` panic and a panic while polling its returned future.
        let filtered = AssertUnwindSafe(async { filter.filter(&chunk).await })
            .catch_unwind()
            .await;
        let out = match filtered {
            Ok(out) => out,
            Err(_) => return, // Drop output; the loop reports "stdin filter task ended".
        };
        if out.is_empty() {
            continue;
        }
        if output.send(out).await.is_err() {
            break;
        }
    }
}

//--------------------------------------------------------------------------------------------------
// Module: agent (backend-agnostic ops driven over an agent connection)
//--------------------------------------------------------------------------------------------------

#[cfg(unix)]
pub(crate) mod agent {
    //! Local attach impl: bridges the host TTY to a PTY exec session in the
    //! named sandbox. Owns the host terminal's raw mode for the duration.

    use std::os::fd::AsRawFd;
    use std::sync::Arc;

    use microsandbox_protocol::{
        exec::{ExecExited, ExecResize, ExecStdin, ExecStdout},
        message::MessageType,
    };
    use tokio::io::{AsyncWriteExt, unix::AsyncFd};

    use crate::{
        MicrosandboxResult,
        sandbox::{
            AttachOptionsBuilder, SandboxConfig, build_exec_request,
            open_nonblocking_terminal_input, read_from_fd, terminal_path_for_fd,
        },
    };

    use super::{
        DetachKeys, FilteredStdin, InputRoute, STDIN_FILTER_TASK_ENDED, recv_filtered,
        require_filtered, route_input,
    };

    pub(crate) async fn attach(
        backend: &dyn crate::backend::Backend,
        name: &str,
        config: &SandboxConfig,
        cmd: String,
        opts_builder: AttachOptionsBuilder,
    ) -> MicrosandboxResult<i32> {
        let mut opts = opts_builder.build()?;
        let stdin_filter = opts.stdin_filter.take();

        let client = Arc::new(super::super::fs::agent::connect_agent(backend, name).await?);

        let detach_keys = match &opts.detach_keys {
            Some(spec) => DetachKeys::parse(spec)?,
            None => DetachKeys::default_keys(),
        };

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
        let detach_seq = detach_keys.sequence();
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

                            match route_input(data, detach_seq, &mut match_pos, filtered_stdin.as_ref()) {
                                InputRoute::Detach => break,
                                InputRoute::Filtered => {}
                                InputRoute::WorkerEnded => {
                                    return Err(crate::MicrosandboxError::Runtime(
                                        STDIN_FILTER_TASK_ENDED.into(),
                                    ));
                                }
                                InputRoute::Forward => {
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
}

#[cfg(windows)]
pub(crate) mod agent {
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

    use super::{
        DetachKeys, FilteredStdin, InputRoute, STDIN_FILTER_TASK_ENDED, recv_filtered,
        require_filtered, route_input,
    };

    pub(crate) async fn attach(
        backend: &dyn Backend,
        name: &str,
        config: &SandboxConfig,
        cmd: String,
        opts_builder: AttachOptionsBuilder,
    ) -> MicrosandboxResult<i32> {
        let mut opts = opts_builder.build()?;
        let stdin_filter = opts.stdin_filter.take();

        let client = Arc::new(super::super::fs::agent::connect_agent(backend, name).await?);

        let detach_keys = match &opts.detach_keys {
            Some(spec) => DetachKeys::parse(spec)?,
            None => DetachKeys::default_keys(),
        };

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
        let detach_seq = detach_keys.sequence();
        let mut match_pos = 0usize;

        // Filtered on its own task: a filter that awaits the guest must not
        // stop this loop from draining guest output (see `StdinFilter`).
        let mut filtered_stdin = stdin_filter.map(FilteredStdin::spawn);

        loop {
            tokio::select! {
                Some(event) = terminal_events.recv() => {
                    match event {
                        WindowsTerminalEvent::Input(data) => {
                            match route_input(&data, detach_seq, &mut match_pos, filtered_stdin.as_ref()) {
                                InputRoute::Detach => break,
                                InputRoute::Filtered => {}
                                InputRoute::WorkerEnded => {
                                    return Err(MicrosandboxError::Runtime(
                                        STDIN_FILTER_TASK_ENDED.into(),
                                    ));
                                }
                                InputRoute::Forward => {
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
}

//--------------------------------------------------------------------------------------------------
// Tests
//--------------------------------------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use std::sync::{
        Arc, Mutex,
        atomic::{AtomicBool, Ordering},
    };

    use tokio::sync::oneshot;

    use super::*;

    #[test]
    fn test_detach_keys_default() {
        let keys = DetachKeys::default_keys();
        assert_eq!(keys.sequence(), &[0x1d]);
    }

    #[test]
    fn test_detach_keys_ctrl_bracket() {
        let keys = DetachKeys::parse("ctrl-]").unwrap();
        assert_eq!(keys.sequence(), &[0x1d]);
    }

    #[test]
    fn test_detach_keys_ctrl_letter() {
        let keys = DetachKeys::parse("ctrl-a").unwrap();
        assert_eq!(keys.sequence(), &[0x01]);

        let keys = DetachKeys::parse("ctrl-z").unwrap();
        assert_eq!(keys.sequence(), &[0x1a]);
    }

    #[test]
    fn test_detach_keys_multi_sequence() {
        let keys = DetachKeys::parse("ctrl-p,ctrl-q").unwrap();
        assert_eq!(keys.sequence(), &[0x10, 0x11]);
    }

    #[test]
    #[allow(clippy::byte_char_slices)] // intentional: comparing to a single-byte slice
    fn test_detach_keys_single_char() {
        let keys = DetachKeys::parse("q").unwrap();
        assert_eq!(keys.sequence(), b"q");
    }

    #[test]
    fn test_detach_keys_invalid() {
        assert!(DetachKeys::parse("ctrl-").is_err());
        assert!(DetachKeys::parse("ctrl-ab").is_err());
    }

    #[test]
    fn test_input_contains_detach_sequence_across_chunks() {
        let keys = DetachKeys::parse("ctrl-p,ctrl-q").unwrap();
        let mut match_pos = 0;

        assert!(!input_contains_detach_sequence(
            &[0x10],
            keys.sequence(),
            &mut match_pos
        ));
        assert_eq!(match_pos, 1);

        assert!(input_contains_detach_sequence(
            &[0x11],
            keys.sequence(),
            &mut match_pos
        ));
    }

    #[test]
    fn test_input_contains_detach_sequence_restarts_partial_match() {
        let keys = DetachKeys::parse("ctrl-p,ctrl-q").unwrap();
        let mut match_pos = 0;

        assert!(!input_contains_detach_sequence(
            &[0x10, 0x10],
            keys.sequence(),
            &mut match_pos
        ));
        assert_eq!(match_pos, 1);
    }

    // -- StdinFilter routing and pump tests ------------------------------------

    #[test]
    fn test_attach_options_default_has_no_stdin_filter() {
        let opts = AttachOptionsBuilder::default().build().unwrap();
        assert!(
            opts.stdin_filter.is_none(),
            "a default install must not add a filter task or copy"
        );

        let opts = AttachOptionsBuilder::default()
            .stdin_filter(Identity { seen: None })
            .build()
            .unwrap();
        assert!(opts.stdin_filter.is_some());
    }

    #[test]
    fn test_attach_options_debug_is_opaque() {
        let opts = AttachOptionsBuilder::default()
            .stdin_filter(Identity { seen: None })
            .build()
            .unwrap();
        assert!(
            format!("{opts:?}").contains("stdin_filter: Some(StdinFilter)"),
            "unexpected Debug output: {opts:?}"
        );
    }

    #[test]
    fn test_route_input_without_filter_forwards() {
        let keys = DetachKeys::default_keys();

        let mut match_pos = 0usize;
        assert_eq!(
            route_input(b"abc", keys.sequence(), &mut match_pos, None),
            InputRoute::Forward
        );
        assert_eq!(
            match_pos, 0,
            "plain input must not advance the detach match"
        );

        let mut match_pos = 0usize;
        assert_eq!(
            route_input(&[0x1d], keys.sequence(), &mut match_pos, None),
            InputRoute::Detach
        );

        // A multi-key sequence forwards the prefix (today's behavior) and
        // detaches on the completing key.
        let keys = DetachKeys::parse("ctrl-p,ctrl-q").unwrap();
        let mut match_pos = 0usize;
        assert_eq!(
            route_input(&[0x10], keys.sequence(), &mut match_pos, None),
            InputRoute::Forward
        );
        assert_eq!(match_pos, 1);
        assert_eq!(
            route_input(&[0x11], keys.sequence(), &mut match_pos, None),
            InputRoute::Detach
        );
    }

    #[tokio::test]
    async fn test_route_input_scans_detach_before_filter() {
        let seen = Arc::new(Mutex::new(Vec::new()));
        let mut filter = Some(FilteredStdin::spawn(Box::new(Identity {
            seen: Some(seen.clone()),
        })));

        // A chunk that completes the detach sequence never reaches the filter.
        let keys = DetachKeys::default_keys();
        let mut match_pos = 0usize;
        assert_eq!(
            route_input(b"ab\x1d", keys.sequence(), &mut match_pos, filter.as_ref()),
            InputRoute::Detach
        );

        // A partial detach match is filtered; the completing key still detaches.
        // One fresh match state covers the whole two-key sequence.
        let keys = DetachKeys::parse("ctrl-p,ctrl-q").unwrap();
        let mut match_pos = 0usize;
        assert_eq!(
            route_input(&[0x10], keys.sequence(), &mut match_pos, filter.as_ref()),
            InputRoute::Filtered
        );
        assert_eq!(match_pos, 1);
        assert_eq!(
            filter
                .as_mut()
                .unwrap()
                .recv()
                .await
                .expect("filtered chunk"),
            vec![0x10]
        );
        assert_eq!(
            *seen.lock().unwrap(),
            vec![vec![0x10u8]],
            "the detach chunk must not reach the filter"
        );

        assert_eq!(
            route_input(&[0x11], keys.sequence(), &mut match_pos, filter.as_ref()),
            InputRoute::Detach
        );

        // The completing detach key must detach without ever being enqueued on
        // the filter. Push a sentinel right after routing it: a regression that
        // pushed the detach chunk before returning `Detach` would make the
        // worker emit that chunk first, so `recv` would return it instead of
        // the sentinel. This is deterministic; it does not race with the
        // worker via `yield_now`.
        assert!(
            filter.as_ref().unwrap().push(b"z".to_vec()),
            "worker died during the sentinel push"
        );
        assert_eq!(
            filter
                .as_mut()
                .unwrap()
                .recv()
                .await
                .expect("sentinel output"),
            b"z",
            "a chunk enqueued on the detach path overtook the sentinel"
        );
        assert!(
            filter.as_mut().unwrap().recv().now_or_never().is_none(),
            "the completing detach chunk was enqueued on the filter"
        );
        assert_eq!(
            *seen.lock().unwrap(),
            vec![vec![0x10u8], b"z".to_vec()],
            "the filter saw a chunk it must never see"
        );
    }

    #[tokio::test]
    async fn test_filtered_stdin_transforms_chunk() {
        let mut stdin = FilteredStdin::spawn(Box::new(Recording {
            seen: Arc::new(Mutex::new(Vec::new())),
            map: |data: &[u8]| data.to_ascii_uppercase(),
        }));

        assert!(stdin.push(b"abc".to_vec()));
        assert_eq!(stdin.recv().await.expect("filtered output"), b"ABC");
    }

    #[tokio::test]
    async fn test_filtered_stdin_drops_and_emits_later() {
        const PASTE_START: &[u8] = b"\x1b[200~";
        const PASTE_END: &[u8] = b"\x1b[201~";

        let mut stdin = FilteredStdin::spawn(Box::new(PasteOnCtrlV { pending: false }));

        assert!(stdin.push(vec![0x16]));
        assert!(stdin.push(b"x".to_vec()));
        assert!(stdin.push(b"y".to_vec()));

        let mut expected = Vec::new();
        expected.extend_from_slice(PASTE_START);
        expected.extend_from_slice(b"/p.png");
        expected.extend_from_slice(PASTE_END);
        expected.extend_from_slice(b"x");

        assert_eq!(stdin.recv().await.expect("paste output"), expected);
        assert_eq!(stdin.recv().await.expect("chunk after the paste"), b"y");
    }

    #[tokio::test]
    async fn test_filtered_stdin_held_chunk_is_not_overtaken() {
        let (entered_tx, entered_rx) = oneshot::channel();
        let (release_tx, release_rx) = oneshot::channel();

        let mut stdin = FilteredStdin::spawn(Box::new(Gate {
            entered: Some(entered_tx),
            release: Some(release_rx),
            first_output: b"A".to_vec(),
        }));

        assert!(stdin.push(b"1".to_vec()));
        assert!(stdin.push(b"2".to_vec()));
        assert!(stdin.push(b"3".to_vec()));

        // The worker is provably holding chunk 1 here.
        entered_rx.await.expect("worker entered the filter");

        for _ in 0..8 {
            tokio::task::yield_now().await;
            assert!(
                stdin.recv().now_or_never().is_none(),
                "a later chunk overtook the held one"
            );
        }

        release_tx.send(()).expect("release the filter");
        assert_eq!(stdin.recv().await.expect("first output"), b"A");
        assert_eq!(stdin.recv().await.expect("second output"), b"2");
        assert_eq!(stdin.recv().await.expect("third output"), b"3");
    }

    #[tokio::test]
    async fn test_filtered_stdin_preserves_order_under_varied_latency() {
        for round in 0..100u64 {
            run_order_round(0x9e37_79b9_7f4a_7c15u64.wrapping_add(round)).await;
        }
    }

    #[tokio::test(flavor = "multi_thread", worker_threads = 2)]
    async fn test_filtered_stdin_preserves_order_under_varied_latency_multi_thread() {
        for round in 0..100u64 {
            run_order_round(0xbf58_476d_1ce4_e5b9u64.wrapping_add(round)).await;
        }
    }

    #[tokio::test]
    async fn test_filtered_stdin_push_never_waits() {
        const CHUNKS: usize = 10_000;

        let (entered_tx, entered_rx) = oneshot::channel();
        let (release_tx, release_rx) = oneshot::channel();

        let chunks: Vec<Vec<u8>> = (0..CHUNKS).map(|i| vec![(i % 251) as u8]).collect();

        // The first chunk is held until `release`; all 10 000 pushes below
        // must then still complete without waiting. A blocking push would
        // hang rather than fail an assertion, so the synchronous pushes run on
        // a dedicated blocking thread and the whole section is bounded by a
        // watchdog timeout: a bounded/awaited `push` trips the timeout instead
        // of hanging the test forever.
        let stdin = FilteredStdin::spawn(Box::new(Gate {
            entered: Some(entered_tx),
            release: Some(release_rx),
            first_output: chunks[0].clone(),
        }));

        assert!(stdin.push(chunks[0].clone()));
        entered_rx.await.expect("worker entered the filter");

        let queued: Vec<Vec<u8>> = chunks[1..].to_vec();
        let (pushed_tx, pushed_rx) = oneshot::channel();
        // A detached std thread (not `spawn_blocking`) so a genuinely blocked
        // push cannot keep the test process alive after the watchdog fires.
        std::thread::spawn(move || {
            for chunk in &queued {
                assert!(stdin.push(chunk.clone()), "worker died during push");
            }
            let _ = pushed_tx.send(stdin);
        });

        // `tokio::time::timeout` over a `oneshot` rather than a blocking
        // `recv_timeout`, so the current-thread runtime is not stalled while the
        // watchdog waits. A dropped sender (`Err`) means the push thread
        // panicked before it could hand the worker back.
        let mut stdin =
            match tokio::time::timeout(std::time::Duration::from_secs(30), pushed_rx).await {
                Ok(Ok(stdin)) => stdin,
                Ok(Err(_)) => panic!("the push thread panicked: the worker died during push"),
                Err(_) => panic!("push blocked: the input queue is bounded or push awaits"),
            };

        release_tx.send(()).expect("release the filter");

        let drained = tokio::time::timeout(std::time::Duration::from_secs(10), async {
            let mut out = Vec::with_capacity(CHUNKS);
            for _ in 0..CHUNKS {
                out.push(stdin.recv().await.expect("worker produced too few chunks"));
            }
            out
        })
        .await
        .expect("queued input was not drained in order");

        assert_eq!(
            drained, chunks,
            "filtered output order differs from push order"
        );
    }

    #[tokio::test]
    async fn test_select_loop_drains_output_while_filter_awaits_model() {
        const OUTPUT_ITEMS: usize = 64;

        // "Guest output" with the same capacity as the agent client's
        // per-correlation stream queue.
        let (guest_tx, mut guest_rx) = mpsc::channel::<usize>(2);
        let (response_tx, response_rx) = oneshot::channel::<()>();

        let relay = tokio::spawn(async move {
            for i in 0..OUTPUT_ITEMS {
                if guest_tx.send(i).await.is_err() {
                    break;
                }
            }
            let _ = response_tx.send(());
        });

        let mut filtered = Some(FilteredStdin::spawn(Box::new(AwaitResponse {
            release: Some(response_rx),
            output: b"A".to_vec(),
        })));
        assert!(filtered.as_ref().unwrap().push(vec![0x16]));

        let mut drained = 0usize;
        let mut got_filtered = false;
        let mut guest_done = false;

        let modeled = tokio::time::timeout(std::time::Duration::from_secs(10), async {
            while drained < OUTPUT_ITEMS || !got_filtered {
                tokio::select! {
                    // Stop selecting the guest stream once it is exhausted:
                    // `recv()` is then permanently ready with `None`, and
                    // letting it end the loop would race the still-pending
                    // filtered chunk.
                    item = guest_rx.recv(), if !guest_done => {
                        match item {
                            Some(_) => drained += 1,
                            None => guest_done = true,
                        }
                    }
                    filtered_out = recv_filtered(&mut filtered) => {
                        match filtered_out {
                            Some(data) => {
                                assert_eq!(data, b"A");
                                got_filtered = true;
                            }
                            // A closed filter channel still fails the
                            // `got_filtered` assertion below.
                            None => break,
                        }
                    }
                }
            }
        })
        .await;

        // Never wait forever for a relay parked on a full channel.
        relay.abort();
        let _ = relay.await;

        assert!(
            modeled.is_ok(),
            "the loop stalled while the filter awaited the guest"
        );
        assert_eq!(drained, OUTPUT_ITEMS, "guest output was not fully drained");
        assert!(got_filtered, "the filtered chunk never arrived");
    }

    #[tokio::test]
    async fn test_filtered_stdin_panic_policy() {
        // 1. Panic in the synchronous `filter()` call.
        // 2. Panic while polling the returned future.
        // 3. Panic while the filter's future is being dropped, after it
        //    completed: the worker still ends and its output still closes.
        let filters: Vec<Box<dyn StdinFilter>> = vec![
            Box::new(PanicSync),
            Box::new(PanicFuture),
            Box::new(PanicOnDropFilter),
        ];

        for filter in filters {
            let mut stdin = Some(FilteredStdin::spawn(filter));
            assert!(stdin.as_ref().unwrap().push(vec![b'x']));

            let output = recv_filtered(&mut stdin).await;
            assert!(output.is_none(), "a panicking filter must close its output");

            match require_filtered(output) {
                Err(crate::MicrosandboxError::Runtime(message)) => {
                    assert_eq!(message, "stdin filter task ended");
                }
                other => panic!("unexpected panic-policy result: {other:?}"),
            }
        }

        assert_eq!(require_filtered(Some(b"ok".to_vec())).unwrap(), b"ok");
    }

    /// The detach-scan path reports a dead worker explicitly: after a filter
    /// panic, routing further input yields `WorkerEnded` (never a silent drop).
    /// The output-channel seam surfaces `require_filtered(None)`, and both
    /// attach loops' `WorkerEnded` arms report the same
    /// [`STDIN_FILTER_TASK_ENDED`] constant, so the two seams have a single
    /// source of truth. The loop bodies themselves (a live TTY plus an agent
    /// connection) are not executed here.
    #[tokio::test]
    async fn test_route_input_reports_worker_ended_after_panic() {
        let keys = DetachKeys::default_keys();
        let mut stdin = Some(FilteredStdin::spawn(Box::new(PanicSync)));
        assert!(stdin.as_ref().unwrap().push(b"x".to_vec()));

        // Resolves only once the worker is gone (its output sender dropped).
        // Bounded: if the panic policy regresses and the worker stays alive,
        // this must fail rather than hang `cargo test` until the CI job times
        // out.
        let ended = tokio::time::timeout(
            std::time::Duration::from_secs(10),
            recv_filtered(&mut stdin),
        )
        .await
        .expect("the worker stayed alive after a filter panic");
        assert!(ended.is_none(), "a panicking filter must close its output");

        let mut match_pos = 0usize;
        assert_eq!(
            route_input(b"y", keys.sequence(), &mut match_pos, stdin.as_ref()),
            InputRoute::WorkerEnded,
            "input after the worker died must be reported, not silently lost"
        );

        // The output-channel path surfaces the identical message. The two
        // attach loops build it from `STDIN_FILTER_TASK_ENDED`, so asserting
        // the constant's value here also pins the loops' message; a loop-local
        // literal would be free to drift.
        assert_eq!(STDIN_FILTER_TASK_ENDED, "stdin filter task ended");
        match require_filtered(None) {
            Err(crate::MicrosandboxError::Runtime(message)) => {
                assert_eq!(message, STDIN_FILTER_TASK_ENDED);
            }
            other => panic!("unexpected error: {other:?}"),
        }
    }

    /// The filter survives builder calls made before or after it, in the
    /// consumer's order (`.args().cwd()` then `.stdin_filter(f)`). Both halves
    /// assert the full field set, so a setter that clobbers the fields set
    /// before it (the ordering that would break the consumer) is caught.
    #[test]
    fn test_stdin_filter_survives_further_builder_calls() {
        let opts = AttachOptionsBuilder::default()
            .stdin_filter(Identity { seen: None })
            .args(["-c".to_string()])
            .cwd("/tmp".to_string())
            .detach_keys("ctrl-q")
            .build()
            .unwrap();
        assert!(
            opts.stdin_filter.is_some(),
            "filter dropped by later setter"
        );
        assert_eq!(opts.args, vec!["-c".to_string()]);
        assert_eq!(opts.cwd.as_deref(), Some("/tmp"));
        assert_eq!(opts.detach_keys.as_deref(), Some("ctrl-q"));

        let opts = AttachOptionsBuilder::default()
            .args(["-c".to_string()])
            .cwd("/tmp".to_string())
            .detach_keys("ctrl-q")
            .stdin_filter(Identity { seen: None })
            .build()
            .unwrap();
        assert!(
            opts.stdin_filter.is_some(),
            "filter dropped by earlier setter"
        );
        assert_eq!(opts.args, vec!["-c".to_string()], "stdin_filter wiped args");
        assert_eq!(opts.cwd.as_deref(), Some("/tmp"), "stdin_filter wiped cwd");
        assert_eq!(
            opts.detach_keys.as_deref(),
            Some("ctrl-q"),
            "stdin_filter wiped detach_keys"
        );
    }

    #[tokio::test]
    async fn test_filtered_stdin_drop_aborts_filter() {
        let dropped = Arc::new(AtomicBool::new(false));
        let (entered_tx, entered_rx) = oneshot::channel();

        let stdin = FilteredStdin::spawn(Box::new(DropFlag {
            dropped: dropped.clone(),
            entered: Some(entered_tx),
        }));
        assert!(stdin.push(vec![b'x']));

        // The worker has provably polled its pending future before the drop.
        entered_rx.await.expect("worker entered the filter");
        drop(stdin);

        let seen = tokio::time::timeout(std::time::Duration::from_secs(5), async {
            while !dropped.load(Ordering::SeqCst) {
                tokio::task::yield_now().await;
            }
        })
        .await;

        assert!(
            seen.is_ok(),
            "dropping FilteredStdin did not abort the worker and drop the filter"
        );
    }

    // -- Test-only filters -----------------------------------------------------

    /// Minimal identity filter that can also record the chunks it sees.
    struct Identity {
        seen: Option<Arc<Mutex<Vec<Vec<u8>>>>>,
    }

    impl StdinFilter for Identity {
        fn filter<'a>(
            &'a mut self,
            data: &'a [u8],
        ) -> Pin<Box<dyn Future<Output = Vec<u8>> + Send + 'a>> {
            if let Some(seen) = self.seen.as_ref() {
                seen.lock().unwrap().push(data.to_vec());
            }
            let data = data.to_vec();
            Box::pin(async move { data })
        }
    }

    /// Records every chunk it sees and maps it through `map`.
    struct Recording {
        seen: Arc<Mutex<Vec<Vec<u8>>>>,
        map: fn(&[u8]) -> Vec<u8>,
    }

    impl StdinFilter for Recording {
        fn filter<'a>(
            &'a mut self,
            data: &'a [u8],
        ) -> Pin<Box<dyn Future<Output = Vec<u8>> + Send + 'a>> {
            self.seen.lock().unwrap().push(data.to_vec());
            let out = (self.map)(data);
            Box::pin(async move { out })
        }
    }

    /// Drops the first chunk it sees and prepends a paste to the next one.
    struct PasteOnCtrlV {
        pending: bool,
    }

    impl StdinFilter for PasteOnCtrlV {
        fn filter<'a>(
            &'a mut self,
            data: &'a [u8],
        ) -> Pin<Box<dyn Future<Output = Vec<u8>> + Send + 'a>> {
            if data == b"\x16" {
                self.pending = true;
                Box::pin(async { Vec::new() })
            } else if self.pending {
                self.pending = false;
                let mut out = Vec::new();
                out.extend_from_slice(b"\x1b[200~");
                out.extend_from_slice(b"/p.png");
                out.extend_from_slice(b"\x1b[201~");
                out.extend_from_slice(data);
                Box::pin(async move { out })
            } else {
                let data = data.to_vec();
                Box::pin(async move { data })
            }
        }
    }

    /// Holds the first chunk until `release` fires; identity on later chunks.
    struct Gate {
        entered: Option<oneshot::Sender<()>>,
        release: Option<oneshot::Receiver<()>>,
        first_output: Vec<u8>,
    }

    impl StdinFilter for Gate {
        fn filter<'a>(
            &'a mut self,
            data: &'a [u8],
        ) -> Pin<Box<dyn Future<Output = Vec<u8>> + Send + 'a>> {
            let entered = self.entered.take();
            let release = self.release.take();
            let first_output = self.first_output.clone();
            let data = data.to_vec();
            Box::pin(async move {
                match (entered, release) {
                    (Some(entered), Some(release)) => {
                        let _ = entered.send(());
                        let _ = release.await;
                        first_output
                    }
                    _ => data,
                }
            })
        }
    }

    /// Waits for a separate "guest response" before emitting its output.
    struct AwaitResponse {
        release: Option<oneshot::Receiver<()>>,
        output: Vec<u8>,
    }

    impl StdinFilter for AwaitResponse {
        fn filter<'a>(
            &'a mut self,
            _data: &'a [u8],
        ) -> Pin<Box<dyn Future<Output = Vec<u8>> + Send + 'a>> {
            let release = self.release.take();
            let output = self.output.clone();
            Box::pin(async move {
                if let Some(release) = release {
                    let _ = release.await;
                }
                output
            })
        }
    }

    /// Panics in the synchronous `filter()` call.
    struct PanicSync;

    impl StdinFilter for PanicSync {
        fn filter<'a>(
            &'a mut self,
            _data: &'a [u8],
        ) -> Pin<Box<dyn Future<Output = Vec<u8>> + Send + 'a>> {
            panic!("synchronous filter panic")
        }
    }

    /// Panics while polling the returned future.
    struct PanicFuture;

    impl StdinFilter for PanicFuture {
        fn filter<'a>(
            &'a mut self,
            _data: &'a [u8],
        ) -> Pin<Box<dyn Future<Output = Vec<u8>> + Send + 'a>> {
            Box::pin(async { panic!("filter future panic") })
        }
    }

    /// Completes normally, but panics when its future is dropped: whichever
    /// unwind path runs, the worker still dies and takes its output with it.
    struct PanicOnDropFuture {
        ready: bool,
    }

    impl Future for PanicOnDropFuture {
        type Output = Vec<u8>;

        fn poll(
            mut self: Pin<&mut Self>,
            _cx: &mut std::task::Context<'_>,
        ) -> std::task::Poll<Self::Output> {
            self.ready = true;
            std::task::Poll::Ready(Vec::new())
        }
    }

    impl Drop for PanicOnDropFuture {
        fn drop(&mut self) {
            if self.ready {
                panic!("filter future drop panic");
            }
        }
    }

    /// Returns [`PanicOnDropFuture`] for every chunk.
    struct PanicOnDropFilter;

    impl StdinFilter for PanicOnDropFilter {
        fn filter<'a>(
            &'a mut self,
            _data: &'a [u8],
        ) -> Pin<Box<dyn Future<Output = Vec<u8>> + Send + 'a>> {
            Box::pin(PanicOnDropFuture { ready: false })
        }
    }

    /// Signals `dropped` when the worker task drops it, and `entered` once its
    /// pending future is being polled.
    struct DropFlag {
        dropped: Arc<AtomicBool>,
        entered: Option<oneshot::Sender<()>>,
    }

    impl Drop for DropFlag {
        fn drop(&mut self) {
            self.dropped.store(true, Ordering::SeqCst);
        }
    }

    impl StdinFilter for DropFlag {
        fn filter<'a>(
            &'a mut self,
            _data: &'a [u8],
        ) -> Pin<Box<dyn Future<Output = Vec<u8>> + Send + 'a>> {
            let entered = self.entered.take();
            Box::pin(async move {
                if let Some(entered) = entered {
                    let _ = entered.send(());
                }
                std::future::pending().await
            })
        }
    }

    /// Deterministic mapping for the order tests: a chunk whose first byte is
    /// a multiple of five is dropped, the rest are uppercased.
    fn jitter_mapping(chunk: &[u8]) -> Option<Vec<u8>> {
        if chunk[0].is_multiple_of(5) {
            None
        } else {
            Some(chunk.to_ascii_uppercase())
        }
    }

    /// Applies [`jitter_mapping`] after a data-dependent number of yields, so
    /// chunk latencies vary, and records every chunk it sees.
    struct Jitter {
        seen: Arc<Mutex<Vec<Vec<u8>>>>,
    }

    impl StdinFilter for Jitter {
        fn filter<'a>(
            &'a mut self,
            data: &'a [u8],
        ) -> Pin<Box<dyn Future<Output = Vec<u8>> + Send + 'a>> {
            self.seen.lock().unwrap().push(data.to_vec());
            let yields = (data[0] % 8) as usize;
            let mapped = jitter_mapping(data).unwrap_or_default();
            Box::pin(async move {
                for _ in 0..yields {
                    tokio::task::yield_now().await;
                }
                mapped
            })
        }
    }

    fn xorshift(state: &mut u64) -> u64 {
        let mut x = *state;
        x ^= x << 13;
        x ^= x >> 7;
        x ^= x << 17;
        *state = x;
        x
    }

    /// One property round: random chunks with varying filter latency must come
    /// out in input order, mapped element by element with empties removed.
    async fn run_order_round(seed: u64) {
        let mut state = seed | 1;
        let chunk_count = (xorshift(&mut state) % 50) as usize;
        let mut chunks = Vec::with_capacity(chunk_count);
        for _ in 0..chunk_count {
            let len = (xorshift(&mut state) % 64 + 1) as usize;
            let mut chunk = Vec::with_capacity(len);
            for _ in 0..len {
                chunk.push((xorshift(&mut state) % 256) as u8);
            }
            chunks.push(chunk);
        }

        let seen = Arc::new(Mutex::new(Vec::new()));
        let mut stdin = FilteredStdin::spawn(Box::new(Jitter { seen: seen.clone() }));
        for chunk in &chunks {
            assert!(stdin.push(chunk.clone()), "worker died during push");
        }

        let expected: Vec<Vec<u8>> = chunks
            .iter()
            .filter_map(|chunk| jitter_mapping(chunk))
            .collect();
        let mut actual = Vec::with_capacity(expected.len());
        for _ in 0..expected.len() {
            // Bounded: a worker that stops emitting without dropping its
            // output sender (for example one that loses chunks) parks on an
            // empty input queue, so an unbounded `recv` would hang `cargo
            // test` rather than fail.
            let next = tokio::time::timeout(std::time::Duration::from_secs(10), stdin.recv())
                .await
                .expect("the worker stopped emitting but never closed its output channel");
            actual.push(next.expect("worker produced too few chunks"));
        }

        // Draining the outputs does not prove the worker has pulled the
        // trailing dropped chunks off the input queue yet, so give it a
        // bounded *time* to finish recording before asserting order. A fixed
        // number of yields is not enough: under `flavor = "multi_thread"` the
        // worker runs on another OS thread, and a worker starved of CPU makes
        // no progress while this task burns through a yield budget in
        // microseconds. The wait is only for the worker to finish; the order
        // assertions below stay exact.
        let recorded = tokio::time::timeout(std::time::Duration::from_secs(10), async {
            loop {
                let all_recorded = { seen.lock().unwrap().len() == chunks.len() };
                if all_recorded {
                    break;
                }
                tokio::task::yield_now().await;
                tokio::time::sleep(std::time::Duration::from_millis(1)).await;
            }
        })
        .await;

        assert!(
            recorded.is_ok(),
            "the worker did not record every pushed chunk before the deadline: saw {} of {}",
            seen.lock().unwrap().len(),
            chunks.len()
        );

        assert_eq!(
            actual, expected,
            "filtered output order differs from input order"
        );
        assert_eq!(
            *seen.lock().unwrap(),
            chunks,
            "the filter did not see the chunks in push order"
        );
    }
}
