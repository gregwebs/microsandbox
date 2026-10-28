//! Interactive attach types for terminal bridging with sandboxes.

use std::{fmt, future::Future, panic::AssertUnwindSafe, pin::Pin};

use futures::FutureExt;
use microsandbox_types::EnvVar;
use tokio::sync::mpsc;
use tokio_util::task::AbortOnDropHandle;

use crate::{MicrosandboxError, MicrosandboxResult};

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

    /// Interception is off for this session; see
    /// [`AttachOptionsBuilder::disable_detach_keys`]. Unset means "use the
    /// `detach_keys` sequence, or the default", not "no interception".
    pub(crate) detach_disabled: bool,

    /// Strict session completion; see [`AttachOptionsBuilder::checked_session`].
    pub(crate) checked_session: bool,

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
/// so it always works; a session with detach disabled
/// ([`AttachOptionsBuilder::disable_detach_keys`]) scans nothing, so every chunk
/// reaches the filter. Emitted filter bytes are NOT scanned for detach keys
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
    /// No filter is set: send the chunk to the guest now, as before, byte for
    /// byte: routing decides who maps the chunk, never what it contains.
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
    ///
    /// Setting a sequence also re-enables interception after
    /// [`disable_detach_keys`](Self::disable_detach_keys): the last setter wins.
    pub fn detach_keys(mut self, keys: impl Into<String>) -> Self {
        self.options.detach_keys = Some(keys.into());
        self.options.detach_disabled = false;
        self
    }

    /// Forward every host input byte, including the default `Ctrl-]`, to the
    /// guest instead of intercepting an escape sequence.
    ///
    /// For this builder only: the option is per session, so other attaches keep
    /// their default detach behavior. Leaving `detach_keys` unset is *not* a
    /// way to disable interception (unset means the default `Ctrl-]`), and an
    /// empty sequence is not a disable mechanism (it parses back to the default).
    ///
    /// Without the escape key a session ends only when the guest exits, so a
    /// caller that wants a detach must set its own `detach_keys` again (which
    /// re-enables interception). A [`stdin_filter`](Self::stdin_filter) is
    /// unaffected either way: it sees every chunk, `Ctrl-]` included, because it
    /// runs after the scan that interception would have performed.
    pub fn disable_detach_keys(mut self) -> Self {
        self.options.detach_disabled = true;
        self
    }

    /// Report every terminal-session failure instead of the legacy
    /// best-effort conventions.
    ///
    /// A legacy attach swallows host output write/flush errors, ignores
    /// `ExecStdinError`, and reports a missing guest exit as the status `-1`.
    /// That is the wrong contract for a caller that owns the process's exit
    /// status: it cannot tell "the guest exited with -1" from "no exit event
    /// ever arrived".
    ///
    /// With this opt-in (Unix and Windows):
    ///
    /// * the guest exit is decoded into an `i32` only when an exit event
    ///   arrives; a receivable `ExecExited { code: -1 }` is a real status, not
    ///   a sentinel;
    /// * malformed output/exit/failure payloads, host input read errors, every
    ///   input and resize send, output write/flush errors, a closed event
    ///   channel, and host input EOF before the guest exits are errors;
    /// * a guest `EPIPE` for stdin (reported by agentd, so the guest's errno) is
    ///   expected and stops feeding input while the session still waits for the
    ///   guest's exit; any other stdin error is an error;
    /// * the host terminal's raw state is restored explicitly on both the normal
    ///   and the error return, and a restoration failure is appended to the
    ///   session's own failure rather than hiding it (it is returned as a
    ///   terminal error when the session otherwise succeeded);
    /// * on Unix the guest's output is written by a dedicated thread over a
    ///   duplicated stdout descriptor. Guest backpressure waits for the consumer
    ///   (memory is bounded, bytes are never dropped); a genuinely unwritable
    ///   output descriptor or runtime loss is an error; and cancellation aborts
    ///   without joining that thread, so a write already in progress may reach
    ///   the descriptor or keep the descriptor until the process exits. There is
    ///   no Tokio blocking task, so dropping the Tokio runtime cannot block on
    ///   this writer.
    ///
    /// The defaults (neither setter called) keep every legacy behavior,
    /// including detach's `Ok(-1)` return and best-effort I/O.
    ///
    /// A [`stdin_filter`](Self::stdin_filter) composes with this option instead
    /// of being replaced by it: the filter keeps its own task, sees every chunk
    /// in input order after the detach scan, and returns the bytes that reach
    /// the guest, so a filter that swallows a chunk still swallows it. Only the
    /// session's conventions differ, which is the point of the opt-in: a detach,
    /// an ended filter worker and a failed send are errors here rather than
    /// `Ok(-1)`, a silent fallback or a dropped chunk. A caller that sets both
    /// therefore gets the filter it asked for; it never gets raw terminal input
    /// because the session happens to be checked.
    pub fn checked_session(mut self) -> Self {
        self.options.checked_session = true;
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
    ///
    /// Independent of [`checked_session`](Self::checked_session) and of
    /// [`disable_detach_keys`](Self::disable_detach_keys): both compose with a
    /// filter rather than replacing it.
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

impl AttachOptions {
    /// The escape sequence this session intercepts, or `None` when the builder
    /// disabled interception.
    ///
    /// Resolved before any option field is moved out of `opts`, so a bad
    /// user-supplied sequence fails before the session starts and before the
    /// host terminal is touched.
    fn resolved_detach_keys(&self) -> MicrosandboxResult<Option<DetachKeys>> {
        if self.detach_disabled {
            return Ok(None);
        }
        match self.detach_keys.as_deref() {
            Some(spec) => Ok(Some(DetachKeys::parse(spec)?)),
            None => Ok(Some(DetachKeys::default_keys())),
        }
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

/// Scan `data` for this session's detach sequence, then route the chunk to the
/// filter if one is set, and otherwise report it for direct forwarding.
///
/// The scan always runs first, so a filter never sees, and cannot delay, the
/// detach keys. `detach_keys` is `None` when the session disabled interception:
/// no scan runs at all (so no match state is kept) and every chunk reaches the
/// filter, or the guest, unchanged.
///
/// Both sessions route through this one function, so a filter cannot behave
/// differently because the caller also asked for a checked session.
pub(crate) fn route_input(
    data: &[u8],
    detach_keys: Option<&DetachKeys>,
    match_pos: &mut usize,
    filter: Option<&FilteredStdin>,
) -> InputRoute {
    let detaches = detach_keys
        .is_some_and(|keys| input_contains_detach_sequence(data, keys.sequence(), match_pos));
    if detaches {
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

/// Compose a checked session's own failure with the failures of its epilogue.
///
/// The session's failure stays first and keeps its own text: a later teardown
/// step must never replace the reason the session failed. The composed value is
/// a terminal error, because a terminal session that cannot restore or flush has
/// failed as a session — the alternative (returning only the primary) would
/// report the guest's status while the caller's terminal is still in raw mode.
#[cfg(any(unix, windows))]
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

//--------------------------------------------------------------------------------------------------
// Module: agent (backend-agnostic ops driven over an agent connection)
//--------------------------------------------------------------------------------------------------

#[cfg(unix)]
pub(crate) mod agent {
    //! Attach over an agent connection: bridge a host terminal to a guest PTY
    //! exec session.
    //!
    //! One connection setup serves two deliberately different sessions. The
    //! legacy session is the interactive `shell` behavior, whose completion
    //! conventions (`Ok(-1)` when no exit event arrived) and best-effort I/O are
    //! observable and must not change. The checked session is an opt-in for a
    //! caller that owns the process's exit status: a direct command launch has to
    //! distinguish a guest exit from a lost session (#400).

    use std::collections::VecDeque;
    use std::os::fd::{AsRawFd, FromRawFd, OwnedFd, RawFd};
    use std::sync::Arc;
    use std::sync::{Condvar, Mutex};

    use microsandbox_protocol::{
        exec::{ExecExited, ExecFailed, ExecResize, ExecStdin, ExecStdinError, ExecStdout},
        message::{Message, MessageType},
    };
    use tokio::io::AsyncWriteExt;
    use tokio::io::unix::AsyncFd;
    use tokio::sync::Notify;

    use crate::{
        MicrosandboxError, MicrosandboxResult,
        agent::AgentClient,
        sandbox::{
            AttachOptionsBuilder, SandboxConfig, build_exec_request,
            open_nonblocking_terminal_input, read_from_fd, terminal_path_for_fd,
        },
    };

    use super::{
        AttachOptions, DetachKeys, FilteredStdin, InputRoute, STDIN_FILTER_TASK_ENDED, StdinFilter,
        checked_epilogue_error, recv_filtered, require_filtered, route_input,
    };

    /// Outstanding bytes one checked session may have queued or in flight.
    ///
    /// Memory accounting only. A full queue waits for the consumer, so guest
    /// backpressure stalls the session exactly as a native write to a slow
    /// terminal would; it never fails and never drops output.
    pub(super) const CHECKED_OUTPUT_MAX_PENDING_BYTES: usize = 8 * 1024 * 1024;

    /// Largest queued frame. A guest frame is split so one reservation can never
    /// exceed the bound above.
    const CHECKED_OUTPUT_CHUNK_BYTES: usize = 64 * 1024;

    /// Most staged chunks one session may hold read but not yet queued.
    ///
    /// Staging is what keeps failure observation live across a capacity wait, so
    /// it is bounded like the writer's own queue rather than growing with a
    /// flooding guest.
    const CHECKED_STAGED_CHUNKS: usize =
        CHECKED_OUTPUT_MAX_PENDING_BYTES / CHECKED_OUTPUT_CHUNK_BYTES;

    /// Host terminal read size: one `read(2)`, one `ExecStdin` frame.
    const CHECKED_INPUT_CHUNK_BYTES: usize = 1024;

    /// The guest's `EPIPE`. agentd reports the errno it observed inside the
    /// guest, so this is not the host's `libc::EPIPE`.
    const GUEST_EPIPE: i32 = 32;

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
        let primary =
            checked_bridge(&client, id, &mut rx, detach_keys.as_ref(), stdin_filter).await;
        finish_checked_session(&mut raw, primary)
    }

    /// How a checked session ended. Only a definitive guest event ends one; a
    /// transport observation never stands in for an exit.
    enum CheckedEnd {
        Exited(i32),
        Failed(ExecFailed),
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

    fn checked_failure(text: impl Into<String>) -> MicrosandboxError {
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

        /// Idempotent: a session that already restored (or failed to) reports
        /// once and never re-applies a stale snapshot.
        fn restore(&mut self) -> MicrosandboxResult<()> {
            if !self.active {
                return Ok(());
            }
            set_attributes(self.fd.as_raw_fd(), &self.saved).map_err(|error| {
                checked_failure(format!("restoring the host terminal: {error}"))
            })?;
            self.active = false;
            Ok(())
        }
    }

    impl Drop for CheckedRawTerminal {
        fn drop(&mut self) {
            let _ = self.restore();
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
    fn duplicate_cloexec(fd: RawFd) -> std::io::Result<OwnedFd> {
        let duplicate = unsafe { libc::fcntl(fd, libc::F_DUPFD_CLOEXEC, 3) };
        if duplicate == -1 {
            return Err(std::io::Error::last_os_error());
        }
        Ok(unsafe { OwnedFd::from_raw_fd(duplicate) })
    }

    /// Split one guest output frame into the bounded chunks the writer accepts.
    fn stage_output_chunks(bytes: Vec<u8>, pending: &mut VecDeque<Vec<u8>>) {
        let mut remaining = bytes;
        while !remaining.is_empty() {
            let mut chunk = remaining;
            remaining = chunk.split_off(chunk.len().min(CHECKED_OUTPUT_CHUNK_BYTES));
            pending.push_back(chunk);
        }
    }

    /// One unit of the checked output queue.
    enum CheckedOutputItem {
        Data(Vec<u8>),
        /// Enqueued after every preceding frame; its receipt is the session's
        /// success barrier.
        Finish(tokio::sync::oneshot::Sender<()>),
    }

    #[derive(Default)]
    struct CheckedOutputQueueState {
        items: VecDeque<CheckedOutputItem>,
        /// Bytes enqueued but not yet accepted by the host descriptor,
        /// including an in-flight write.
        reserved: usize,
        aborted: bool,
        error: Option<String>,
    }

    /// The checked session's output path: an ordered queue plus the thread that
    /// owns the blocking writes.
    ///
    /// A dedicated thread, not `tokio::io::stdout()`. Dropping a Tokio stdout
    /// write future cannot cancel a blocking write it already dispatched, and
    /// `Runtime::drop` waits for blocking tasks — so a checked session that
    /// failed while its consumer stopped draining could not report the failure at
    /// all. This thread is independent of the runtime: cancellation abandons it
    /// (the launcher exits the process afterwards), and the runtime drops
    /// immediately.
    #[derive(Default)]
    struct CheckedOutputQueue {
        state: Mutex<CheckedOutputQueueState>,
        /// Wakes the writer when work arrives or the queue is closed.
        work: Condvar,
        /// Wakes capacity waiters after a write, a failure, or an abort.
        capacity: Notify,
        /// Wakes a session that is waiting only for the writer's verdict.
        ///
        /// Deliberately separate from `capacity`: a writer failure has to reach
        /// its session even when nothing is being enqueued, so it must not be
        /// routed through guest progress.
        failed: Notify,
    }

    impl CheckedOutputQueue {
        fn lock(&self) -> std::sync::MutexGuard<'_, CheckedOutputQueueState> {
            // Every mutation is a single field update under this lock, so a panic
            // elsewhere cannot leave the accounting inconsistent.
            self.state
                .lock()
                .unwrap_or_else(|poisoned| poisoned.into_inner())
        }

        fn failure(&self) -> Option<String> {
            self.lock().error.clone()
        }

        /// Stop the writer and release everything it has not written.
        ///
        /// The writer may be blocked in a write; it is never joined, and its
        /// in-flight prefix may already have reached the descriptor.
        fn abort(&self) {
            {
                let mut state = self.lock();
                state.aborted = true;
                state.items.clear();
                state.reserved = 0;
            }
            self.work.notify_all();
            self.capacity.notify_waiters();
        }

        fn fail(&self, message: String) {
            {
                let mut state = self.lock();
                if state.error.is_none() {
                    state.error = Some(message);
                }
                state.items.clear();
                state.reserved = 0;
            }
            self.work.notify_all();
            self.capacity.notify_waiters();
            self.failed.notify_waiters();
        }

        fn release(&self, bytes: usize) {
            {
                let mut state = self.lock();
                state.reserved = state.reserved.saturating_sub(bytes);
            }
            self.capacity.notify_waiters();
        }

        /// The writer's next item; `None` means it must stop.
        fn next(&self) -> Option<CheckedOutputItem> {
            let mut state = self.lock();
            loop {
                if state.aborted || state.error.is_some() {
                    return None;
                }
                if let Some(item) = state.items.pop_front() {
                    return Some(item);
                }
                state = self
                    .work
                    .wait(state)
                    .unwrap_or_else(|poisoned| poisoned.into_inner());
            }
        }

        /// The writer's own message when it failed, otherwise the caller's.
        fn failure_or(&self, fallback: &str) -> MicrosandboxError {
            checked_failure(self.failure().unwrap_or_else(|| fallback.to_string()))
        }
    }

    /// Owns the duplicated host stdout descriptor and every blocking write.
    fn run_checked_writer(queue: Arc<CheckedOutputQueue>, output: OwnedFd) {
        // The queue is re-read for each item instead of being held across the
        // syscall, so an abort can discard unwritten output while a write blocks.
        while let Some(item) = queue.next() {
            match item {
                CheckedOutputItem::Data(bytes) => {
                    let written = write_all_fd(output.as_raw_fd(), &bytes);
                    queue.release(bytes.len());
                    if let Err(error) = written {
                        // Closed pipe, full device: a session failure, never
                        // truncation reported as a guest success.
                        queue.fail(format!(
                            "writing guest output to the host terminal: {error}"
                        ));
                        return;
                    }
                }
                CheckedOutputItem::Finish(receipt) => {
                    // Every earlier frame was accepted by the descriptor; the
                    // wait may already have been abandoned by cancellation.
                    let _ = receipt.send(());
                    return;
                }
            }
        }
    }

    fn write_all_fd(fd: RawFd, mut bytes: &[u8]) -> std::io::Result<()> {
        while !bytes.is_empty() {
            let written = unsafe { libc::write(fd, bytes.as_ptr().cast(), bytes.len()) };
            if written < 0 {
                let error = std::io::Error::last_os_error();
                if error.kind() == std::io::ErrorKind::Interrupted {
                    continue;
                }
                return Err(error);
            }
            if written == 0 {
                return Err(std::io::Error::from(std::io::ErrorKind::WriteZero));
            }
            bytes = &bytes[written as usize..];
        }
        Ok(())
    }

    struct CheckedOutput {
        queue: Arc<CheckedOutputQueue>,
    }

    impl CheckedOutput {
        fn start(stdout_fd: RawFd) -> MicrosandboxResult<Self> {
            let output = duplicate_cloexec(stdout_fd).map_err(|error| {
                checked_failure(format!("duplicating the host terminal output: {error}"))
            })?;
            let queue = Arc::new(CheckedOutputQueue::default());
            let writer_queue = Arc::clone(&queue);
            std::thread::Builder::new()
                .name("agent-vm-terminal-output".into())
                .spawn(move || run_checked_writer(writer_queue, output))
                .map_err(|error| {
                    checked_failure(format!("starting the terminal output writer: {error}"))
                })?;
            Ok(Self { queue })
        }

        /// Reserve capacity for one staged chunk, then queue it.
        ///
        /// Cancel-safe: the only suspension point is `reserve`, which has queued
        /// nothing when it is dropped, and no await separates a successful
        /// reservation from the queue push. A cancelled call therefore leaves
        /// neither a reservation nor a partial frame, so the session can put the
        /// chunk back at the head of its staging queue.
        async fn enqueue_chunk(&self, bytes: &[u8]) -> MicrosandboxResult<()> {
            debug_assert!(bytes.len() <= CHECKED_OUTPUT_CHUNK_BYTES);
            self.reserve(bytes.len()).await?;
            {
                let mut state = self.queue.lock();
                state
                    .items
                    .push_back(CheckedOutputItem::Data(bytes.to_vec()));
            }
            self.queue.work.notify_one();
            Ok(())
        }

        /// The writer's own failure, as a future the session can select on.
        ///
        /// Waiting for capacity and waiting for the finish receipt both report a
        /// stored failure, but only when the session calls them; a guest that
        /// writes one frame and then waits for input would never call them again.
        /// The notification is registered before the state is read, so a failure
        /// that races the registration is observed rather than lost.
        async fn failure(&self) -> MicrosandboxError {
            loop {
                let signal = self.queue.failed.notified();
                tokio::pin!(signal);
                signal.as_mut().enable();
                if let Some(message) = self.queue.failure() {
                    return checked_failure(message);
                }
                signal.await;
            }
        }

        /// Wait until `bytes` more fit under the pending bound, then reserve them.
        async fn reserve(&self, bytes: usize) -> MicrosandboxResult<()> {
            debug_assert!(bytes <= CHECKED_OUTPUT_MAX_PENDING_BYTES);
            loop {
                // Registered before the accounting is read, so a release between
                // the check and the wait cannot be lost.
                let capacity = self.queue.capacity.notified();
                tokio::pin!(capacity);
                capacity.as_mut().enable();
                {
                    let mut state = self.queue.lock();
                    if let Some(error) = &state.error {
                        return Err(checked_failure(error.clone()));
                    }
                    if state.aborted {
                        return Err(checked_failure("the terminal output writer was aborted"));
                    }
                    if state.reserved + bytes <= CHECKED_OUTPUT_MAX_PENDING_BYTES {
                        state.reserved += bytes;
                        return Ok(());
                    }
                }
                capacity.await;
            }
        }

        /// Wait for the ordered finish receipt: every earlier byte has been
        /// accepted by the host descriptor (not flushed to stable storage).
        ///
        /// Cancellable, like every other await in the session; the queue's abort
        /// then discards whatever the writer has not written.
        async fn finish(&self) -> MicrosandboxResult<()> {
            let (receipt, receipt_wait) = tokio::sync::oneshot::channel();
            {
                let mut state = self.queue.lock();
                if let Some(error) = &state.error {
                    return Err(checked_failure(error.clone()));
                }
                if state.aborted {
                    return Err(checked_failure("the terminal output writer was aborted"));
                }
                state.items.push_back(CheckedOutputItem::Finish(receipt));
            }
            self.queue.work.notify_one();
            match receipt_wait.await {
                Ok(()) => Ok(()),
                Err(_) => Err(self
                    .queue
                    .failure_or("the terminal output writer stopped before confirming its writes")),
            }
        }
    }

    impl Drop for CheckedOutput {
        fn drop(&mut self) {
            self.queue.abort();
        }
    }

    #[cfg(test)]
    mod checked_output {
        //! The checked writer's own contracts, without a terminal or a VM:
        //! exact ordered bytes, capacity that waits instead of failing, a
        //! non-joining abort, and a worker failure that reaches its caller.

        use std::io::{Read, Seek, SeekFrom};
        use std::os::fd::AsRawFd;
        use std::sync::Arc;
        use std::time::Duration;

        use super::*;

        /// A bounded wait that fails the test instead of hanging the suite.
        async fn within<F: std::future::Future>(future: F) -> F::Output {
            tokio::time::timeout(Duration::from_secs(20), future)
                .await
                .expect("the checked writer did not make progress")
        }

        #[tokio::test]
        async fn every_queued_byte_reaches_the_descriptor_in_order() {
            let mut file = tempfile::tempfile().expect("a scratch output file");
            let output = CheckedOutput::start(file.as_raw_fd()).expect("start the writer");

            let mut expected = Vec::new();
            let frames: Vec<Vec<u8>> = vec![
                b"first\n".to_vec(),
                // Larger than one queued frame: it must be split, never dropped.
                (0..=255u8)
                    .cycle()
                    .take(2 * CHECKED_OUTPUT_CHUNK_BYTES + 7)
                    .collect(),
                b"tail\n".to_vec(),
            ];
            let mut pending = VecDeque::new();
            for frame in frames {
                expected.extend_from_slice(&frame);
                stage_output_chunks(frame, &mut pending);
            }
            // Staging is where a frame is split, so no reservation can exceed the
            // queue's chunk bound.
            assert!(
                pending
                    .iter()
                    .all(|chunk| !chunk.is_empty() && chunk.len() <= CHECKED_OUTPUT_CHUNK_BYTES),
                "a staged chunk exceeded the queue's chunk bound"
            );
            while let Some(chunk) = pending.pop_front() {
                within(output.enqueue_chunk(&chunk)).await.expect("enqueue");
            }
            within(output.finish()).await.expect("finish");

            // The writer holds a duplicate of this descriptor, so its offset is
            // this one's: rewind before reading the bytes back.
            file.seek(SeekFrom::Start(0)).expect("rewind");
            let mut actual = Vec::new();
            file.read_to_end(&mut actual).expect("read back");
            assert_eq!(actual, expected);
        }

        /// Enqueue frames until the queue refuses to accept another one, and say
        /// how many bytes are then queued.
        ///
        /// The pipe's own buffer absorbs a little, so the count is discovered
        /// rather than assumed; a queue that failed instead of waiting panics.
        async fn fill_until_blocked(output: &CheckedOutput) -> usize {
            let mut queued = 0usize;
            loop {
                // Slack for what the descriptor itself absorbed: the point is
                // that the queue eventually stops accepting frames.
                assert!(
                    queued <= CHECKED_OUTPUT_MAX_PENDING_BYTES + CHECKED_OUTPUT_CHUNK_BYTES * 8,
                    "the queue never reached its pending bound"
                );
                let frame = vec![b'x'; CHECKED_OUTPUT_CHUNK_BYTES];
                match tokio::time::timeout(Duration::from_millis(500), output.enqueue_chunk(&frame))
                    .await
                {
                    Ok(Ok(())) => queued += CHECKED_OUTPUT_CHUNK_BYTES,
                    Ok(Err(error)) => {
                        panic!("a full queue failed instead of waiting for the consumer: {error}")
                    }
                    Err(_) => return queued,
                }
            }
        }

        #[tokio::test]
        async fn a_full_queue_waits_for_the_consumer_instead_of_failing() {
            // A pipe whose consumer stops: the writer blocks in `write(2)`,
            // reservations reach the bound, and the next enqueue must wait rather
            // than fail or drop bytes.
            let (mut read_end, write_end) = std::io::pipe().expect("a pipe");
            let output = CheckedOutput::start(write_end.as_raw_fd()).expect("start the writer");
            drop(write_end);

            let queued = fill_until_blocked(&output).await;

            // The consumer resumes: everything already queued still arrives, and
            // the session can finish after it.
            let draining = std::thread::spawn(move || {
                let mut seen = vec![0u8; 64 * 1024];
                let mut drained = 0usize;
                while drained < queued {
                    let read = read_end.read(&mut seen).expect("drain the pipe");
                    assert!(read > 0, "the writer stopped before delivering every byte");
                    drained += read;
                }
            });
            // Waiting for capacity is not a failure: the barrier succeeds.
            within(output.finish()).await.expect("finish");
            draining.join().expect("drain thread");
        }

        #[tokio::test]
        async fn an_abort_releases_a_capacity_blocked_sender_and_never_joins_the_worker() {
            // The consumer never reads, so the writer stays blocked in `write(2)`
            // and the next sender waits for capacity.
            let (_read_end, write_end) = std::io::pipe().expect("a pipe");
            let output = CheckedOutput::start(write_end.as_raw_fd()).expect("start the writer");
            drop(write_end);

            fill_until_blocked(&output).await;

            let queue = Arc::clone(&output.queue);
            let blocked = tokio::spawn(async move {
                output
                    .enqueue_chunk(&[b'z'; CHECKED_OUTPUT_CHUNK_BYTES])
                    .await
            });
            tokio::time::sleep(Duration::from_millis(200)).await;
            assert!(
                !blocked.is_finished(),
                "the sender must be waiting capacity"
            );

            // Abort must return promptly (it never joins a blocked write) and must
            // release the waiting sender.
            queue.abort();
            let result = within(blocked)
                .await
                .expect("the blocked sender was released");
            assert!(
                result.is_err(),
                "a released sender reports the abort, never a silent success"
            );
        }

        #[tokio::test]
        async fn a_dead_descriptor_is_a_reported_failure() {
            // The read end of a pipe cannot be written, so the worker's first
            // write fails and that failure must reach the session.
            let (read_end, _write_end) = std::io::pipe().expect("a pipe");
            let output = CheckedOutput::start(read_end.as_raw_fd()).expect("start the writer");

            let mut failure = output.enqueue_chunk(b"lost\n").await.err();
            if failure.is_none() {
                failure = within(output.finish()).await.err();
            }
            assert!(
                failure.is_some(),
                "an unwritable descriptor must be reported"
            );
            assert!(output.enqueue_chunk(b"more\n").await.is_err());
        }

        #[tokio::test]
        async fn a_writer_failure_wakes_a_session_that_is_not_enqueueing() {
            // The session has one frame in flight and then waits for input, as a
            // live terminal session does while the guest sits at a prompt. The
            // writer's failure has to reach that wait on its own: nothing else
            // calls `enqueue_chunk` or `finish` again.
            let (read_end, write_end) = std::io::pipe().expect("a pipe");
            let output = CheckedOutput::start(write_end.as_raw_fd()).expect("start the writer");
            drop(write_end);
            drop(read_end);

            within(output.enqueue_chunk(b"one frame\n"))
                .await
                .expect("the queue accepts the frame");
            let failure = within(output.failure()).await;
            assert!(
                failure.to_string().contains("writing guest output"),
                "the session must see the output-specific failure: {failure}"
            );
        }

        #[tokio::test]
        async fn a_writer_failure_reaches_a_session_stuck_on_capacity() {
            // The consumer never reads, so the writer is blocked inside `write(2)`
            // and a staged chunk cannot be delivered. The consumer then disappears:
            // the session must learn that while it is still waiting for capacity,
            // not only if it ever calls `enqueue_chunk` or `finish` again.
            let (read_end, write_end) = std::io::pipe().expect("a pipe");
            let output = CheckedOutput::start(write_end.as_raw_fd()).expect("start the writer");
            drop(write_end);

            fill_until_blocked(&output).await;
            drop(read_end);

            let staged = vec![b'q'; CHECKED_OUTPUT_CHUNK_BYTES];
            let failure = tokio::select! {
                result = output.enqueue_chunk(&staged) => match result {
                    Ok(()) => panic!("the queue accepted a chunk past its bound"),
                    Err(error) => error,
                },
                failure = output.failure() => failure,
            };
            assert!(
                failure.to_string().contains("writing guest output"),
                "the capacity wait must report the writer's failure: {failure}"
            );
        }

        #[tokio::test]
        async fn an_idle_writer_aborts_without_waiting() {
            let file = tempfile::tempfile().expect("a scratch output file");
            let output = CheckedOutput::start(file.as_raw_fd()).expect("start the writer");
            // A shared queue handle stands in for the session that cancels.
            let queue = Arc::clone(&output.queue);
            within(output.enqueue_chunk(b"queued\n"))
                .await
                .expect("enqueue");

            let started = std::time::Instant::now();
            queue.abort();
            assert!(
                started.elapsed() < Duration::from_secs(1),
                "abort must not wait for the worker"
            );
            assert!(output.enqueue_chunk(b"after\n").await.is_err());
            assert!(within(output.finish()).await.is_err());
        }
    }
}

#[cfg(windows)]
pub(crate) mod agent {
    //! Attach over an agent connection on Windows.
    //!
    //! Same two sessions as Unix, but the console is the terminal: output is
    //! written inline (UTF-8 decoded to UTF-16 for `WriteConsoleW`), so there is
    //! no standalone writer thread here. The checked session still reports rather
    //! than swallows every failure, and it stops its event pump and attempts both
    //! console restorations before returning.

    use std::sync::Arc;

    use microsandbox_protocol::{
        exec::{ExecExited, ExecFailed, ExecResize, ExecStdin, ExecStdinError, ExecStdout},
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

    use super::{
        AttachOptions, DetachKeys, FilteredStdin, InputRoute, STDIN_FILTER_TASK_ENDED, StdinFilter,
        checked_epilogue_error, recv_filtered, require_filtered, route_input,
    };

    /// The guest's `EPIPE`, as agentd reports the errno it observed inside the
    /// guest.
    const GUEST_EPIPE: i32 = 32;

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
            checked_session(client, config, cmd, opts, detach_keys).await
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
    ) -> MicrosandboxResult<i32> {
        let stdin_filter = opts.stdin_filter.take();
        let (cols, rows) = current_terminal_size()
            .map_err(|error| checked_failure(format!("reading the console size: {error}")))?;
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

        // Raw console mode begins only once the exec request exists, exactly as
        // on Unix.
        let mut terminal = WindowsTerminalGuard::enter()?;
        let mut events = WindowsTerminalEventPump::spawn_for_guard(&terminal)?;
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
        let finish = terminal.finish_output();
        let restore = terminal.restore_checked();
        match primary {
            Ok(code) => {
                let mut later = Vec::new();
                if let Err(error) = finish {
                    later.push(("flushing guest output", error));
                }
                if let Err(error) = restore {
                    later.push(("restoring the console", error));
                }
                if later.is_empty() {
                    Ok(code)
                } else {
                    Err(checked_epilogue_error(
                        checked_failure(
                            "the guest reported its exit but the console session did not finish cleanly",
                        ),
                        later,
                    ))
                }
            }
            Err(primary) => {
                let mut later = Vec::new();
                if let Err(error) = finish {
                    later.push(("flushing guest output", error));
                }
                if let Err(error) = restore {
                    later.push(("restoring the console", error));
                }
                if later.is_empty() {
                    Err(primary)
                } else {
                    Err(checked_epilogue_error(primary, later))
                }
            }
        }
    }

    enum CheckedEnd {
        Exited(i32),
        Failed(ExecFailed),
    }

    async fn checked_bridge(
        client: &Arc<crate::agent::AgentClient>,
        id: u32,
        rx: &mut tokio::sync::mpsc::Receiver<Message>,
        terminal: &mut WindowsTerminalGuard,
        events: &mut WindowsTerminalEventPump,
        detach_keys: Option<&DetachKeys>,
        stdin_filter: Option<Box<dyn StdinFilter>>,
    ) -> MicrosandboxResult<i32> {
        let mut match_pos = 0usize;
        let mut feeding_input = true;
        // Same task boundary as the legacy session and as Unix.
        let mut filtered_stdin = stdin_filter.map(FilteredStdin::spawn);

        let end = 'session: loop {
            tokio::select! {
                event = events.recv() => {
                    let Some(event) = event else {
                        return Err(closed_session());
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
                                    return Err(checked_failure(
                                        "the detach key sequence ended the session before the guest reported its exit",
                                    ));
                                }
                                InputRoute::Filtered => {}
                                InputRoute::WorkerEnded => {
                                    return Err(checked_failure(STDIN_FILTER_TASK_ENDED));
                                }
                                InputRoute::Forward => {
                                    if feeding_input {
                                        client
                                            .send(id, MessageType::ExecStdin, &ExecStdin { data })
                                            .await
                                            .map_err(|error| {
                                                checked_failure(format!(
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
                                    checked_failure(format!("sending a console resize: {error}"))
                                })?;
                        }
                        WindowsTerminalEvent::Error(error) => {
                            return Err(checked_failure(format!("reading console input: {error}")));
                        }
                    }
                }

                filtered = recv_filtered(&mut filtered_stdin), if feeding_input && filtered_stdin.is_some() => {
                    let Some(data) = filtered else {
                        return Err(checked_failure(STDIN_FILTER_TASK_ENDED));
                    };
                    client
                        .send(id, MessageType::ExecStdin, &ExecStdin { data })
                        .await
                        .map_err(|error| {
                            checked_failure(format!("forwarding console input: {error}"))
                        })?;
                }

                message = rx.recv() => {
                    let Some(message) = message else {
                        return Err(closed_session());
                    };
                    if let Some(end) =
                        handle_checked_message(message, terminal, &mut feeding_input).await?
                    {
                        break 'session end;
                    }
                    let mut drained = None;
                    while drained.is_none() {
                        match rx.try_recv() {
                            Ok(next) => {
                                drained =
                                    handle_checked_message(next, terminal, &mut feeding_input).await?;
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

        match end {
            CheckedEnd::Failed(failure) => Err(MicrosandboxError::ExecFailed(failure)),
            CheckedEnd::Exited(code) => Ok(code),
        }
    }

    async fn handle_checked_message(
        message: Message,
        terminal: &mut WindowsTerminalGuard,
        feeding_input: &mut bool,
    ) -> MicrosandboxResult<Option<CheckedEnd>> {
        match message.t {
            MessageType::ExecStdout => {
                let frame: ExecStdout = message.payload().map_err(|error| {
                    checked_failure(format!("decoding guest console output: {error}"))
                })?;
                terminal.write_output(&frame.data)?;
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
                    checked_failure(format!("decoding a console input failure: {error}"))
                })?;
                if guest_closed_input(&error) {
                    *feeding_input = false;
                    Ok(None)
                } else {
                    Err(checked_failure(format!(
                        "forwarding console input failed in the guest: {}",
                        describe_stdin_error(&error)
                    )))
                }
            }
            _ => Ok(None),
        }
    }

    fn checked_failure(text: impl Into<String>) -> MicrosandboxError {
        MicrosandboxError::Terminal(text.into())
    }

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
}

//--------------------------------------------------------------------------------------------------
// Module: PTY tests (Unix)
//--------------------------------------------------------------------------------------------------

#[cfg(all(test, unix))]
mod pty_tests {
    //! Both sessions over a real host terminal and an owned fake relay.
    //!
    //! The bridge reads the process's own stdin and writes its own stdout, so
    //! every case runs in a child process whose fd 0 is a fresh PTY slave (see
    //! `checked_bridge_pty_case`). The parent never changes its own descriptors
    //! or signal dispositions: it allocates the terminal, keeps one slave open so
    //! the terminal cannot be revoked when the child exits, proves the child
    //! reached raw mode, then drives input/resize and compares the attributes it
    //! recorded before the spawn with the attributes after the child exits.

    use std::io::{Read, Write};
    use std::os::fd::{AsRawFd, RawFd};
    use std::path::{Path, PathBuf};
    use std::process::{Command, Stdio};
    use std::sync::Arc;
    use std::time::{Duration, Instant};

    use microsandbox_protocol::codec;
    use microsandbox_protocol::core::Ready;
    use microsandbox_protocol::exec::{
        ExecExited, ExecFailed, ExecFailureKind, ExecRequest, ExecResize, ExecStdin, ExecStdout,
    };
    use microsandbox_protocol::message::{Message, MessageType};
    use tokio::io::{AsyncWriteExt, DuplexStream};

    use crate::agent::AgentClient;

    use super::AttachOptionsBuilder;
    use super::agent;
    use crate::SandboxConfig;

    /// Where the child reads its case from and writes its receipts to.
    const CASE_DIR: &str = "MSB_ATTACH_PTY_DIR";
    const CASE_NAME: &str = "MSB_ATTACH_PTY_CASE";

    /// The full name the parent re-runs this binary with.
    const CHILD_TEST: &str = "sandbox::attach::pty_tests::checked_bridge_pty_case";

    /// Every wait in this harness is bounded: a stuck case must fail, not hang.
    const DEADLINE: Duration = Duration::from_secs(30);

    /// Input the parent types at the terminal for the input case.
    const CASE_INPUT: &[u8] = b"A\x1dB";

    /// Guest output for the input case, on two frames: under a PTY the guest's
    /// stdout and stderr arrive as one ordered stream.
    const CASE_OUTPUT: &[&[u8]] = &[b"guest-out\n", b"guest-err\n"];

    #[derive(Clone, Copy, Debug, PartialEq, Eq)]
    enum Case {
        /// Ctrl-] reaches the guest and the guest's own status comes back.
        Input,
        /// A host resize reaches the guest with stdin's geometry.
        Resize,
        /// A typed spawn failure stays typed and is not a status.
        Failed,
        /// A malformed terminal frame is an error, not a silent skip.
        Malformed,
        /// A closed event channel without an exit is an error.
        Closed,
        /// An unwritable output descriptor is an error the session reports on
        /// its own, while the relay is still alive.
        OutputFailure,
        /// A lost relay is still observed once output has filled the writer's
        /// bound.
        OutputBackpressure,
        /// Dropping the session future restores the terminal.
        Cancel,
    }

    impl Case {
        const ALL: [Case; 8] = [
            Case::Input,
            Case::Resize,
            Case::Failed,
            Case::Malformed,
            Case::Closed,
            Case::OutputFailure,
            Case::OutputBackpressure,
            Case::Cancel,
        ];

        fn name(self) -> &'static str {
            match self {
                Case::Input => "input",
                Case::Resize => "resize",
                Case::Failed => "failed",
                Case::Malformed => "malformed",
                Case::Closed => "closed",
                Case::OutputFailure => "output-failure",
                Case::OutputBackpressure => "output-backpressure",
                Case::Cancel => "cancel",
            }
        }

        fn parse(name: &str) -> Self {
            Self::ALL
                .into_iter()
                .find(|case| case.name() == name)
                .unwrap_or_else(|| panic!("unknown PTY case {name}"))
        }
    }

    //---------------------------------------------------------------------------------------------
    // Parent
    //---------------------------------------------------------------------------------------------

    #[test]
    fn checked_bridge_over_a_real_terminal() {
        for case in Case::ALL {
            let dir = tempfile::tempdir().expect("a scratch case directory");
            run_case(dir.path(), case);
        }
    }

    fn run_case(dir: &Path, case: Case) {
        let pty = nix::pty::openpty(None, None).expect("allocate a PTY");
        set_winsize(pty.slave.as_raw_fd(), 24, 80);
        let baseline = terminal_state(pty.slave.as_raw_fd());

        let child_slave = pty.slave.try_clone().expect("clone the slave");
        let mut command = Command::new(std::env::current_exe().expect("the test binary"));
        command
            .arg("--exact")
            .arg(CHILD_TEST)
            .arg("--test-threads=1")
            .env(CASE_DIR, dir)
            .env(CASE_NAME, case.name())
            .stdin(Stdio::from(child_slave))
            .stdout(Stdio::piped())
            .stderr(Stdio::piped());
        let mut child = command.spawn().expect("spawn the case child");

        // Both pipes are drained concurrently: a child that logs must never block
        // on a full pipe while the parent waits for its receipt.
        let mut child_stdout = child.stdout.take().expect("child stdout");
        let mut child_stderr = child.stderr.take().expect("child stderr");
        let drain_stdout = std::thread::spawn(move || {
            let mut sink = Vec::new();
            let _ = child_stdout.read_to_end(&mut sink);
        });
        let drain_stderr = std::thread::spawn(move || {
            let mut sink = Vec::new();
            let _ = child_stderr.read_to_end(&mut sink);
        });

        // A held-open case proves raw state before it drives input or a fault.
        wait_for(dir, "stage=raw");
        match case {
            Case::Input => {
                let mut master = std::fs::File::from(pty.master.try_clone().expect("clone master"));
                master.write_all(CASE_INPUT).expect("type at the terminal");
                master.flush().expect("flush the terminal input");
            }
            Case::Resize => {
                set_winsize(pty.slave.as_raw_fd(), 43, 119);
                // The launcher is not a session leader, so the signal goes to the
                // exact owned child rather than to a process group.
                nix::sys::signal::kill(
                    nix::unistd::Pid::from_raw(child.id() as i32),
                    nix::sys::signal::Signal::SIGWINCH,
                )
                .expect("send SIGWINCH");
            }
            Case::Failed
            | Case::Malformed
            | Case::Closed
            | Case::OutputFailure
            | Case::OutputBackpressure
            | Case::Cancel => {}
        }
        std::fs::write(dir.join("go"), b"go").expect("release the child");

        let receipt = wait_for_receipt(dir);
        // The output-failure case keeps its relay open on purpose: the session must
        // end on the writer's own failure, so the parent releases the relay only
        // after the child has already reported its outcome.
        if case == Case::OutputFailure {
            std::fs::write(dir.join("release"), b"release").expect("release the relay");
        }
        wait_for_exit(&mut child);

        // A terminal that is not restored is the defect this whole path exists to
        // prevent, so it is compared before anything else is asserted.
        let final_state = terminal_state(pty.slave.as_raw_fd());
        assert_eq!(
            final_state,
            baseline,
            "case {}: the host terminal attributes were not restored",
            case.name()
        );

        let outcome = receipt_value(&receipt, "outcome");
        match case {
            Case::Input => {
                assert_eq!(outcome, "ok:7", "case {}: {receipt}", case.name());
                let expected: Vec<u8> = CASE_OUTPUT.concat();
                assert_eq!(
                    receipt_value(&receipt, "stdout_hex"),
                    hex(&expected),
                    "case {}: merged guest output must arrive in order",
                    case.name()
                );
                let relay = wait_for_receipt_file(dir, "relay.receipt");
                assert_eq!(relay_value(&relay, "stdin_hex"), hex(CASE_INPUT));
                assert_eq!(relay_value(&relay, "request_tty"), "true");
                assert_eq!(relay_value(&relay, "request_rows"), "24");
                assert_eq!(relay_value(&relay, "request_cols"), "80");
                assert_eq!(relay_value(&relay, "request_cwd"), "/workspace/project");
                assert_eq!(relay_value(&relay, "request_user"), "1000:1000");
                assert!(
                    relay_value(&relay, "request_env").contains("PATH=/opt/agent-vm-bin"),
                    "the exec request must carry the effective PATH: {relay}"
                );
            }
            Case::Resize => {
                assert_eq!(outcome, "ok:0", "case {}: {receipt}", case.name());
                let relay = wait_for_receipt_file(dir, "relay.receipt");
                assert_eq!(
                    relay_value(&relay, "resize"),
                    "43x119",
                    "a resize must come from stdin's terminal"
                );
            }
            Case::Failed => {
                assert_eq!(
                    outcome,
                    "err:exec-failed",
                    "case {}: {receipt}",
                    case.name()
                );
            }
            Case::Malformed | Case::Closed => {
                assert!(
                    outcome.starts_with("err:terminal:"),
                    "case {}: a session failure must be reported: {receipt}",
                    case.name()
                );
            }
            Case::OutputFailure => {
                // The relay was still open when this session ended, so the failure
                // can only be the writer's own.
                assert!(
                    outcome.contains("writing guest output"),
                    "case {}: an unwritable descriptor must be reported as an output \
                     failure, not as any other terminal error: {receipt}",
                    case.name()
                );
            }
            Case::OutputBackpressure => {
                assert!(
                    outcome.contains("closed before the guest reported its exit"),
                    "case {}: a relay lost while output capacity was exhausted must be \
                     reported: {receipt}",
                    case.name()
                );
            }
            Case::Cancel => {
                assert_eq!(outcome, "cancelled", "case {}: {receipt}", case.name());
            }
        }
        drain_stdout.join().expect("drain child stdout");
        drain_stderr.join().expect("drain child stderr");
    }

    fn set_winsize(fd: RawFd, rows: u16, cols: u16) {
        let size = libc::winsize {
            ws_row: rows,
            ws_col: cols,
            ws_xpixel: 0,
            ws_ypixel: 0,
        };
        let rc = unsafe { libc::ioctl(fd, libc::TIOCSWINSZ, &size) };
        assert_ne!(
            rc,
            -1,
            "set the terminal size: {}",
            std::io::Error::last_os_error()
        );
    }

    /// The attribute facts a raw-mode session must leave exactly as it found
    /// them.
    ///
    /// Raw mode changes exactly these: canonical input, echo, signal generation,
    /// extended input processing, the input/output translations, the read-time
    /// protocol and the port parameters. Kernel bookkeeping bits (macOS `PENDIN`,
    /// which reflects *unread* input at the terminal) are not part of the
    /// session's contract and cannot be set through this interface, so comparing
    /// them would assert the fixture rather than the code.
    fn terminal_state(fd: RawFd) -> String {
        let mut attributes: libc::termios = unsafe { std::mem::zeroed() };
        let rc = unsafe { libc::tcgetattr(fd, &mut attributes) };
        assert_eq!(
            rc,
            0,
            "read the terminal: {}",
            std::io::Error::last_os_error()
        );
        let local = libc::ICANON | libc::ECHO | libc::ECHONL | libc::ISIG | libc::IEXTEN;
        let input = libc::IXON | libc::ICRNL | libc::BRKINT | libc::INPCK | libc::ISTRIP;
        format!(
            "lflag={} iflag={} oflag={} cflag={} vmin={} vtime={} ispeed={} ospeed={}",
            attributes.c_lflag & local,
            attributes.c_iflag & input,
            attributes.c_oflag & libc::OPOST,
            attributes.c_cflag,
            attributes.c_cc[libc::VMIN],
            attributes.c_cc[libc::VTIME],
            attributes.c_ispeed,
            attributes.c_ospeed
        )
    }

    fn hex(bytes: &[u8]) -> String {
        let mut text = String::with_capacity(bytes.len() * 2);
        for byte in bytes {
            text.push_str(&format!("{byte:02x}"));
        }
        text
    }

    /// Read a receipt file once it exists, within the case deadline.
    fn wait_for_receipt_file(dir: &Path, name: &str) -> String {
        let path = dir.join(name);
        let deadline = Instant::now() + DEADLINE;
        loop {
            if let Ok(text) = std::fs::read_to_string(&path) {
                return text;
            }
            assert!(
                Instant::now() < deadline,
                "{} was never written",
                path.display()
            );
            std::thread::sleep(Duration::from_millis(5));
        }
    }

    fn wait_for(dir: &Path, marker: &str) {
        let deadline = Instant::now() + DEADLINE;
        loop {
            let relay = std::fs::read_to_string(dir.join("relay.receipt")).unwrap_or_default();
            if relay.lines().any(|line| line == marker) {
                return;
            }
            // A child that failed before the barrier says why.
            if let Ok(receipt) = std::fs::read_to_string(dir.join("child.receipt")) {
                panic!("the child finished before reaching {marker}: {receipt}");
            }
            assert!(
                Instant::now() < deadline,
                "the child never reported {marker}"
            );
            std::thread::sleep(Duration::from_millis(5));
        }
    }

    fn wait_for_receipt(dir: &Path) -> String {
        wait_for_receipt_file(dir, "child.receipt")
    }

    fn wait_for_exit(child: &mut std::process::Child) {
        let deadline = Instant::now() + DEADLINE;
        loop {
            if child.try_wait().expect("query the child").is_some() {
                return;
            }
            assert!(Instant::now() < deadline, "the case child did not exit");
            std::thread::sleep(Duration::from_millis(5));
        }
    }

    /// `key=value` from a receipt, panicking with the whole receipt when absent.
    fn receipt_value(receipt: &str, key: &str) -> String {
        receipt_line(receipt, key).unwrap_or_else(|| panic!("no {key} in receipt:\n{receipt}"))
    }

    fn relay_value(relay: &str, key: &str) -> String {
        receipt_value(relay, key)
    }

    fn receipt_line(receipt: &str, key: &str) -> Option<String> {
        let prefix = format!("{key}=");
        receipt
            .lines()
            .find_map(|line| line.strip_prefix(&prefix).map(str::to_owned))
    }

    //---------------------------------------------------------------------------------------------
    // Child
    //---------------------------------------------------------------------------------------------

    /// One PTY case, in the child process the parent spawned.
    ///
    /// Without the token this is an ordinary passing test, so a normal suite run
    /// never allocates a terminal or touches a signal disposition.
    #[test]
    fn checked_bridge_pty_case() {
        let Ok(dir) = std::env::var(CASE_DIR) else {
            return;
        };
        let case = Case::parse(&std::env::var(CASE_NAME).expect("a case name"));
        let dir = PathBuf::from(dir);
        let outcome = run_bridge_case(&dir, case);
        let receipt = format!(
            "outcome={}\nstdout_hex={}\ntermios={}\n",
            outcome.describe(),
            hex(&capture_output(&dir)),
            terminal_state(std::io::stdin().as_raw_fd())
        );
        // Written aside and renamed: the parent polls for the receipt's
        // existence, and a reader that opened the file between create and write
        // would see a session with no outcome.
        let staged = dir.join("child.receipt.staged");
        std::fs::write(&staged, receipt).expect("stage the case receipt");
        std::fs::rename(&staged, dir.join("child.receipt")).expect("publish the case receipt");
    }

    fn capture_output(dir: &Path) -> Vec<u8> {
        std::fs::read(dir.join("output.bin")).unwrap_or_default()
    }

    enum Outcome {
        Exited(i32),
        Error(String),
        Cancelled,
    }

    impl Outcome {
        fn describe(&self) -> String {
            match self {
                Outcome::Exited(code) => format!("ok:{code}"),
                Outcome::Error(error) => format!("err:{error}"),
                Outcome::Cancelled => "cancelled".to_string(),
            }
        }
    }

    fn run_bridge_case(dir: &Path, case: Case) -> Outcome {
        // Guest output is captured on this file only: the checked writer
        // duplicates fd 1, so nothing libtest prints can be mistaken for a guest
        // byte. The output-failure case instead points fd 1 at a pipe whose read
        // end is already closed.
        // A held read end keeps an output pipe open but undrained, so the writer
        // blocks on capacity instead of failing on a closed descriptor.
        let mut held_read_end: Option<std::os::fd::OwnedFd> = None;
        let capture: std::os::fd::OwnedFd = match case {
            Case::OutputFailure => {
                let (read_end, write_end) = std::io::pipe().expect("an output pipe");
                drop(read_end);
                write_end.into()
            }
            Case::OutputBackpressure => {
                let (read_end, write_end) = std::io::pipe().expect("an output pipe");
                held_read_end = Some(read_end.into());
                write_end.into()
            }
            _ => std::fs::OpenOptions::new()
                .create(true)
                .write(true)
                .truncate(true)
                .open(dir.join("output.bin"))
                .expect("the output capture file")
                .into(),
        };
        let saved_stdout = unsafe { libc::dup(1) };
        assert!(saved_stdout >= 0, "duplicate stdout");
        assert_eq!(unsafe { libc::dup2(capture.as_raw_fd(), 1) }, 1);

        let runtime = tokio::runtime::Builder::new_current_thread()
            .enable_all()
            .build()
            .expect("a test runtime");
        let outcome = runtime.block_on(run_case_session(dir, case));
        // Dropping the runtime must not wait for the checked writer: it is a
        // plain thread, not a Tokio blocking task.
        drop(runtime);

        assert_eq!(unsafe { libc::dup2(saved_stdout, 1) }, 1);
        unsafe { libc::close(saved_stdout) };
        drop(held_read_end);
        drop(capture);
        outcome
    }

    async fn run_case_session(dir: &Path, case: Case) -> Outcome {
        let options = AttachOptionsBuilder::default()
            .args(["-c", "probe"])
            .cwd("/workspace/project")
            .user("1000:1000")
            .env("PATH", "/opt/agent-vm-bin")
            .disable_detach_keys()
            .checked_session()
            .build()
            .expect("session options");
        let config = SandboxConfig::default();

        let (client_io, server_io) = tokio::io::duplex(512 * 1024);
        let relay = tokio::spawn(fake_relay(server_io, dir.to_path_buf(), case));
        let client = match AgentClient::connect_stream_with_timeout(
            client_io,
            Duration::from_secs(10),
        )
        .await
        {
            Ok(client) => client,
            Err(error) => return Outcome::Error(format!("terminal:{error}")),
        };

        let bridge =
            agent::attach_connected(Arc::new(client), &config, "bash".to_string(), options);
        let outcome = match case {
            Case::Cancel => {
                // The relay stays open. The parent releases the case once raw
                // mode is observed, and this side then drops the session future,
                // which must restore the terminal without a guest exit.
                tokio::select! {
                    result = bridge => session_outcome(result),
                    _ = released_then_settle(dir) => Outcome::Cancelled,
                }
            }
            _ => session_outcome(bridge.await),
        };
        relay.abort();
        outcome
    }

    fn session_outcome(result: crate::MicrosandboxResult<i32>) -> Outcome {
        match result {
            Ok(code) => Outcome::Exited(code),
            Err(crate::MicrosandboxError::ExecFailed(_)) => Outcome::Error("exec-failed".into()),
            Err(error) => Outcome::Error(format!("terminal:{error}")),
        }
    }

    /// Wait for the parent's release, then let the session sit open briefly.
    async fn released_then_settle(dir: &Path) {
        wait_for_dir(dir, "go").await;
        tokio::time::sleep(Duration::from_millis(100)).await;
    }

    async fn wait_for_dir(dir: &Path, name: &str) {
        let deadline = Instant::now() + DEADLINE;
        while !dir.join(name).exists() {
            assert!(Instant::now() < deadline, "{name} was never released");
            tokio::time::sleep(Duration::from_millis(2)).await;
        }
    }

    async fn fake_relay(mut io: DuplexStream, dir: PathBuf, case: Case) {
        // Relay handshake, exactly as agentd's relay answers one.
        io.write_all(&1u32.to_be_bytes()).await.unwrap();
        io.write_all(&1024u32.to_be_bytes()).await.unwrap();
        let ready = Ready {
            boot_time_ns: 1,
            init_time_ns: 2,
            ready_time_ns: 3,
            agent_version: "attach-pty".to_string(),
            ..Default::default()
        };
        write(
            &mut io,
            Message::with_payload(MessageType::Ready, 0, &ready).unwrap(),
        )
        .await;

        let request = codec::read_raw_frame(&mut io)
            .await
            .expect("the exec request");
        let id = request.id;
        let message = codec::raw_frame_to_message(request).expect("decode the exec request");
        let exec: ExecRequest = message.payload().expect("an exec request payload");
        append(
            &dir,
            &[
                format!("request_cmd={}", exec.cmd),
                format!("request_tty={}", exec.tty),
                format!("request_rows={}", exec.rows),
                format!("request_cols={}", exec.cols),
                format!("request_cwd={}", exec.cwd.unwrap_or_default()),
                format!("request_user={}", exec.user.unwrap_or_default()),
                format!("request_env={}", exec.env.join(",")),
            ],
        );

        // Raw mode is the barrier the parent waits for before driving the case.
        announce_raw(&dir).await;

        match case {
            Case::Input => {
                let mut forwarded = Vec::new();
                while forwarded.len() < CASE_INPUT.len() {
                    match read(&mut io).await {
                        Some(message) if message.t == MessageType::ExecStdin => {
                            let frame: ExecStdin = message.payload().expect("stdin payload");
                            forwarded.extend_from_slice(&frame.data);
                        }
                        Some(_) => {}
                        None => break,
                    }
                }
                append(&dir, &[format!("stdin_hex={}", hex(&forwarded))]);
                for frame in CASE_OUTPUT {
                    write(
                        &mut io,
                        Message::with_payload(
                            MessageType::ExecStdout,
                            id,
                            &ExecStdout {
                                data: frame.to_vec(),
                            },
                        )
                        .unwrap(),
                    )
                    .await;
                }
                write(
                    &mut io,
                    Message::with_payload(MessageType::ExecExited, id, &ExecExited { code: 7 })
                        .unwrap(),
                )
                .await;
            }
            Case::Resize => {
                while let Some(message) = read(&mut io).await {
                    if message.t != MessageType::ExecResize {
                        continue;
                    }
                    let frame: ExecResize = message.payload().expect("resize payload");
                    append(&dir, &[format!("resize={}x{}", frame.rows, frame.cols)]);
                    write(
                        &mut io,
                        Message::with_payload(MessageType::ExecExited, id, &ExecExited { code: 0 })
                            .unwrap(),
                    )
                    .await;
                    break;
                }
            }
            Case::Failed => {
                let failure = ExecFailed {
                    kind: ExecFailureKind::NotFound,
                    errno: None,
                    errno_name: None,
                    stage: None,
                    message: "bash: not found".to_string(),
                };
                write(
                    &mut io,
                    Message::with_payload(MessageType::ExecFailed, id, &failure).unwrap(),
                )
                .await;
            }
            Case::Malformed => {
                // An exit event whose payload is not an exit: the session must
                // report the decode failure rather than treat it as an exit.
                write(
                    &mut io,
                    Message::with_payload(
                        MessageType::ExecExited,
                        id,
                        &ExecStdout {
                            data: b"not an exit".to_vec(),
                        },
                    )
                    .unwrap(),
                )
                .await;
            }
            Case::Closed => {
                write(
                    &mut io,
                    Message::with_payload(
                        MessageType::ExecStdout,
                        id,
                        &ExecStdout {
                            data: b"partial\n".to_vec(),
                        },
                    )
                    .unwrap(),
                )
                .await;
                // Losing the relay without an exit is not a completed session.
                drop(io);
            }
            Case::OutputFailure => {
                write(
                    &mut io,
                    Message::with_payload(
                        MessageType::ExecStdout,
                        id,
                        &ExecStdout {
                            data: vec![b'x'; 4096],
                        },
                    )
                    .unwrap(),
                )
                .await;
                append(&dir, &["stage=output-sent".to_string()]);
                // No exit and no closure: the unwritable descriptor alone has to end
                // the session. The parent releases this barrier only after the child
                // has reported its outcome.
                wait_for_dir(&dir, "release").await;
            }
            Case::OutputBackpressure => {
                // The host descriptor takes one pipe buffer and is then never read
                // again, so the writer blocks and the session's outstanding output
                // reaches its bound. The relay then closes with output still owed
                // and no exit event: capacity backpressure must not hide that.
                let frame = vec![b'x'; 256 * 1024];
                let frames = agent::CHECKED_OUTPUT_MAX_PENDING_BYTES / frame.len() + 2;
                for _ in 0..frames {
                    write(
                        &mut io,
                        Message::with_payload(
                            MessageType::ExecStdout,
                            id,
                            &ExecStdout {
                                data: frame.clone(),
                            },
                        )
                        .unwrap(),
                    )
                    .await;
                }
                append(&dir, &["stage=output-flooded".to_string()]);
                drop(io);
            }
            Case::Cancel => {
                // Keep the connection open while the parent releases the case.
                tokio::time::sleep(Duration::from_secs(2)).await;
            }
        }
    }

    async fn announce_raw(dir: &Path) {
        // The bridge sets raw mode on the terminal fd 0 refers to, so the
        // observation is an attribute read, not a marker the code prints.
        let deadline = Instant::now() + DEADLINE;
        while canonical(std::io::stdin().as_raw_fd()) {
            assert!(Instant::now() < deadline, "raw mode was never entered");
            tokio::time::sleep(Duration::from_millis(2)).await;
        }
        append(dir, &["stage=raw".to_string()]);
        wait_for_dir(dir, "go").await;
    }

    fn canonical(fd: RawFd) -> bool {
        let mut attributes: libc::termios = unsafe { std::mem::zeroed() };
        let rc = unsafe { libc::tcgetattr(fd, &mut attributes) };
        assert_eq!(
            rc,
            0,
            "read the terminal: {}",
            std::io::Error::last_os_error()
        );
        attributes.c_lflag & libc::ICANON != 0
    }

    async fn read(io: &mut DuplexStream) -> Option<Message> {
        match tokio::time::timeout(DEADLINE, codec::read_message(io)).await {
            Ok(Ok(message)) => Some(message),
            Ok(Err(_)) | Err(_) => None,
        }
    }

    async fn write(io: &mut DuplexStream, message: Message) {
        codec::write_message(io, &message)
            .await
            .expect("the relay writes a frame");
    }

    fn append(dir: &Path, lines: &[String]) {
        let mut file = std::fs::OpenOptions::new()
            .create(true)
            .append(true)
            .open(dir.join("relay.receipt"))
            .expect("the relay receipt");
        for line in lines {
            writeln!(file, "{line}").expect("write the relay receipt");
        }
        file.flush().expect("flush the relay receipt");
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
    fn the_default_builder_still_intercepts_ctrl_bracket() {
        let options = AttachOptionsBuilder::default().build().unwrap();
        let keys = options
            .resolved_detach_keys()
            .unwrap()
            .expect("an unset sequence means the default, not no interception");
        assert_eq!(keys.sequence(), &[0x1d]);
        assert!(!options.checked_session, "checked completion stays opt-in");
    }

    #[test]
    fn a_custom_sequence_is_unchanged_and_the_last_setter_wins() {
        let custom = AttachOptionsBuilder::default()
            .detach_keys("ctrl-p,ctrl-q")
            .build()
            .unwrap();
        assert_eq!(
            custom.resolved_detach_keys().unwrap().unwrap().sequence(),
            &[0x10, 0x11]
        );

        // disable then set: interception comes back with that sequence.
        let reenabled = AttachOptionsBuilder::default()
            .disable_detach_keys()
            .detach_keys("ctrl-a")
            .build()
            .unwrap();
        assert_eq!(
            reenabled
                .resolved_detach_keys()
                .unwrap()
                .unwrap()
                .sequence(),
            &[0x01]
        );

        // set then disable: interception is off for this session.
        let disabled = AttachOptionsBuilder::default()
            .detach_keys("ctrl-a")
            .disable_detach_keys()
            .build()
            .unwrap();
        assert!(disabled.resolved_detach_keys().unwrap().is_none());
    }

    #[test]
    fn disabling_interception_is_per_session() {
        let disabled = AttachOptionsBuilder::default()
            .disable_detach_keys()
            .build()
            .unwrap();
        assert!(disabled.resolved_detach_keys().unwrap().is_none());
        // A later default builder is unaffected: nothing global changed.
        let next = AttachOptionsBuilder::default().build().unwrap();
        assert_eq!(
            next.resolved_detach_keys().unwrap().unwrap().sequence(),
            &[0x1d]
        );
    }

    #[test]
    fn checked_completion_and_detach_disable_are_independent() {
        let checked_only = AttachOptionsBuilder::default()
            .checked_session()
            .build()
            .unwrap();
        assert!(checked_only.checked_session);
        assert_eq!(
            checked_only
                .resolved_detach_keys()
                .unwrap()
                .expect("checked alone does not disable interception")
                .sequence(),
            &[0x1d]
        );

        let disabled_only = AttachOptionsBuilder::default()
            .disable_detach_keys()
            .build()
            .unwrap();
        assert!(!disabled_only.checked_session);
        assert!(disabled_only.resolved_detach_keys().unwrap().is_none());
    }

    #[test]
    fn disabled_interception_forwards_a_whole_chunk_unchanged() {
        // Bytes around the escape byte, in one chunk: no interception, no split,
        // and the caller sends the chunk it passed in byte for byte.
        assert_eq!(
            route_input(b"A\x1dB", None, &mut 0, None),
            InputRoute::Forward
        );
        // Every byte value, including 0x1d and 0x00, is forwarded.
        let all: Vec<u8> = (0..=255u8).collect();
        assert_eq!(route_input(&all, None, &mut 0, None), InputRoute::Forward);
        // And a session that disabled interception keeps no match state at all.
        let mut match_pos = 0;
        for byte in &all {
            assert_eq!(
                route_input(&[*byte], None, &mut match_pos, None),
                InputRoute::Forward
            );
        }
        assert_eq!(match_pos, 0);
    }

    #[test]
    fn enabled_interception_still_detaches_and_never_rewrites_bytes() {
        let keys = DetachKeys::default_keys();
        let mut match_pos = 0;
        // A chunk containing the escape byte ends a legacy session; nothing of
        // it is forwarded, which is the pre-existing behavior.
        assert_eq!(
            route_input(b"A\x1dB", Some(&keys), &mut match_pos, None),
            InputRoute::Detach
        );

        // Without the sequence the whole chunk is forwarded unchanged.
        let mut match_pos = 0;
        assert_eq!(
            route_input(b"plain\n", Some(&keys), &mut match_pos, None),
            InputRoute::Forward
        );

        // A multi-byte custom sequence is matched across chunks.
        let keys = DetachKeys::parse("ctrl-p,ctrl-q").unwrap();
        let mut match_pos = 0;
        assert_eq!(
            route_input(&[0x10], Some(&keys), &mut match_pos, None),
            InputRoute::Forward
        );
        assert_eq!(
            route_input(&[0x11], Some(&keys), &mut match_pos, None),
            InputRoute::Detach
        );
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
            route_input(b"abc", Some(&keys), &mut match_pos, None),
            InputRoute::Forward
        );
        assert_eq!(
            match_pos, 0,
            "plain input must not advance the detach match"
        );

        let mut match_pos = 0usize;
        assert_eq!(
            route_input(&[0x1d], Some(&keys), &mut match_pos, None),
            InputRoute::Detach
        );

        // A multi-key sequence forwards the prefix (today's behavior) and
        // detaches on the completing key.
        let keys = DetachKeys::parse("ctrl-p,ctrl-q").unwrap();
        let mut match_pos = 0usize;
        assert_eq!(
            route_input(&[0x10], Some(&keys), &mut match_pos, None),
            InputRoute::Forward
        );
        assert_eq!(match_pos, 1);
        assert_eq!(
            route_input(&[0x11], Some(&keys), &mut match_pos, None),
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
            route_input(b"ab\x1d", Some(&keys), &mut match_pos, filter.as_ref()),
            InputRoute::Detach
        );

        // A partial detach match is filtered; the completing key still detaches.
        // One fresh match state covers the whole two-key sequence.
        let keys = DetachKeys::parse("ctrl-p,ctrl-q").unwrap();
        let mut match_pos = 0usize;
        assert_eq!(
            route_input(&[0x10], Some(&keys), &mut match_pos, filter.as_ref()),
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
            route_input(&[0x11], Some(&keys), &mut match_pos, filter.as_ref()),
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
            route_input(b"y", Some(&keys), &mut match_pos, stdin.as_ref()),
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
