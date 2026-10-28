//! Attach session options: the per-session builder and its resolved state.

use microsandbox_types::EnvVar;

use crate::MicrosandboxResult;
use crate::sandbox::exec::{Rlimit, RlimitResource, validate_rlimits};

use super::DetachKeys;

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
    /// their default detach behavior. Leaving `detach_keys` unset is *not* a way
    /// to disable interception (unset means the default `Ctrl-]`), and an empty
    /// sequence is not a disable mechanism either: `DetachKeys::parse` rejects an
    /// empty spec rather than falling back to the default.
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
    ///   and bytes are never dropped. The session holds at most 16 MiB of guest
    ///   output: up to 8 MiB read ahead and 8 MiB queued for the writer, measured
    ///   by allocation. The agent client buffers at most a few frames more per
    ///   stream, upstream of the session. A genuinely unwritable
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
    pub fn rlimit(mut self, resource: RlimitResource, limit: u64) -> Self {
        self.options.rlimits.push(Rlimit {
            resource,
            soft: limit,
            hard: limit,
        });
        self
    }

    /// Set a resource limit with different soft/hard values.
    pub fn rlimit_range(mut self, resource: RlimitResource, soft: u64, hard: u64) -> Self {
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
        validate_rlimits(&self.options.rlimits)?;
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
    pub(super) fn resolved_detach_keys(&self) -> MicrosandboxResult<Option<DetachKeys>> {
        if self.detach_disabled {
            return Ok(None);
        }
        match self.detach_keys.as_deref() {
            Some(spec) => Ok(Some(DetachKeys::parse(spec)?)),
            None => Ok(Some(DetachKeys::default_keys())),
        }
    }
}

//--------------------------------------------------------------------------------------------------
// Tests
//--------------------------------------------------------------------------------------------------

use super::*;

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
