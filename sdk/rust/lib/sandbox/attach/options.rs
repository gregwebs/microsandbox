//! Attach session options: the per-session builder and its resolved state.

use std::fmt;

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
#[derive(Default)]
pub struct AttachOptions {
    /// Arguments.
    pub(crate) args: Vec<String>,

    /// Environment variables (merged with sandbox env).
    pub(crate) env: Vec<EnvVar>,

    /// Working directory (default: sandbox's workdir).
    pub(crate) cwd: Option<String>,

    /// Guest user override for the attached command.
    pub(crate) user: Option<String>,

    /// How this session treats the detach key sequence; see
    /// [`AttachOptionsBuilder::detach_keys`] and
    /// [`AttachOptionsBuilder::disable_detach_keys`].
    pub(crate) detach: DetachPolicy,

    /// Strict session completion; see [`AttachOptionsBuilder::checked_session`].
    pub(crate) checked_session: bool,

    /// Resource limits.
    pub(crate) rlimits: Vec<Rlimit>,

    /// Transforms terminal input after the detach-key scan, before it is
    /// sent to the guest. `None` forwards input unchanged.
    pub(crate) stdin_filter: Option<Box<dyn StdinFilter>>,
}

/// How one attach session treats the detach key sequence.
///
/// One field, so "the last setter wins" is structural rather than something two
/// fields have to be kept in step about: a name, a custom sequence, or nothing
/// to intercept.
#[derive(Debug, Default)]
pub(crate) enum DetachPolicy {
    /// Intercept the default `Ctrl-]`.
    #[default]
    Default,
    /// Intercept this Docker-style sequence (parsed when the session starts).
    Custom(String),
    /// Intercept nothing; every byte reaches the guest.
    Disabled,
}

/// A [`DetachPolicy`] as the option surface renders it: a bare variant name.
struct DetachPolicyDebug<'a>(&'a DetachPolicy);

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
        self.options.detach = DetachPolicy::Custom(keys.into());
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
    /// re-enables interception). Pairs with
    /// [`checked_session`](Self::checked_session) for a command whose only end
    /// is its own exit. A [`stdin_filter`](Self::stdin_filter) is
    /// unaffected either way: it sees every chunk, `Ctrl-]` included, because it
    /// runs after the scan that interception would have performed.
    pub fn disable_detach_keys(mut self) -> Self {
        self.options.detach = DetachPolicy::Disabled;
        self
    }

    /// Report every terminal-session failure instead of the legacy
    /// best-effort conventions.
    ///
    /// Return `Ok` only for an exit status the guest reported; every other way
    /// the session can end is an error. That is the contract a caller needs when
    /// it owns the process's exit status: a legacy attach swallows host output
    /// write/flush errors, ignores `ExecStdinError`, and reports a missing guest
    /// exit as the status `-1`, so it cannot tell "the guest exited with -1"
    /// from "no exit event ever arrived".
    ///
    /// With this opt-in (Unix and Windows):
    ///
    /// * the guest exit is decoded into an `i32` only when an exit event
    ///   arrives; a receivable `ExecExited { code: -1 }` is a real status, not
    ///   a sentinel;
    /// * malformed output/exit/failure payloads, host input read errors, every
    ///   input and resize send, output write/flush errors, a closed event
    ///   channel, and host input EOF before the guest exits are errors;
    /// * a guest `EPIPE` or `EIO` for stdin (reported by agentd, so the guest's
    ///   errno) is expected and stops feeding input while the session still
    ///   waits for the guest's exit: the guest closed its input, or its PTY is
    ///   gone because it is exiting. Any other stdin error is an error;
    /// * **detach is an error here.** With detach keys enabled (the default, or
    ///   [`detach_keys`](Self::detach_keys)), typing the sequence ends the
    ///   session with an error and leaves the guest running. Use
    ///   [`disable_detach_keys`](Self::disable_detach_keys) for a session that
    ///   only the guest can end;
    /// * the host terminal's raw state is restored explicitly on both the normal
    ///   and the error return, and a restoration failure is appended to the
    ///   session's own failure rather than hiding it (it is returned as a
    ///   terminal error when the session otherwise succeeded);
    /// * after a failure, guest output the session already holds is still
    ///   delivered while the host descriptor accepts it. Delivery stops after
    ///   500 ms without progress or 5 s in total, so a stalled or crawling
    ///   consumer cannot delay the error and the terminal restore for ever;
    /// * on Unix the guest's output is written by a dedicated thread over a
    ///   duplicated stdout descriptor. Guest backpressure waits for the consumer
    ///   and bytes are never dropped. Retention inside the session is bounded by
    ///   two queues, each measured by allocation: up to 8 MiB of staged chunks
    ///   read ahead of the writer, plus up to 8 MiB queued for the writer or in
    ///   flight in it. That bound covers those two queues only: it excludes
    ///   transient allocations (decoding holds a frame beside its encoded
    ///   message, and staging copies a frame into chunks before dropping it) as
    ///   well as the agent client's own buffers upstream of the session. A
    ///   genuinely unwritable output descriptor or runtime loss is an error; and
    ///   cancellation aborts
    ///   without joining that thread, so a write already in progress may reach
    ///   the descriptor or keep the descriptor until the process exits. There is
    ///   no Tokio blocking task, so dropping the Tokio runtime cannot block on
    ///   this writer.
    ///
    /// What a session can observe about a lost relay:
    ///
    /// * a relay that rejects a send is reported on the next keystroke or
    ///   resize the transport refuses. After the guest closed its input,
    ///   keystrokes are deliberately not read, so only a resize can carry it;
    /// * a relay that closed without refusing a send is reported as soon as the
    ///   host accepts output again. While output is stalled and the session's
    ///   read-ahead is full, that loss is behind guest output the host has not
    ///   taken, and the session waits for the host exactly as a native writer
    ///   would;
    /// * dropping the session future restores the terminal but reports nothing.
    ///
    /// A spawn failure is
    /// [`MicrosandboxError::ExecFailed`](crate::MicrosandboxError::ExecFailed);
    /// every other failure is
    /// [`MicrosandboxError::Terminal`](crate::MicrosandboxError::Terminal) with a
    /// message that says what ended the session. The message text is diagnostic,
    /// not a stable interface.
    ///
    /// Rust SDK only.
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
        match &self.detach {
            DetachPolicy::Default => Ok(Some(DetachKeys::default_keys())),
            DetachPolicy::Custom(spec) => Ok(Some(DetachKeys::parse(spec)?)),
            DetachPolicy::Disabled => Ok(None),
        }
    }

    /// The detach sequence as the option surface shows it: `Some` only for a
    /// custom sequence, exactly as the field rendered before the policy was one
    /// value.
    fn debug_detach_keys(&self) -> Option<&str> {
        match &self.detach {
            DetachPolicy::Custom(spec) => Some(spec),
            DetachPolicy::Default | DetachPolicy::Disabled => None,
        }
    }
}

//--------------------------------------------------------------------------------------------------
// Trait Implementations
//--------------------------------------------------------------------------------------------------

/// `build()` is public and returns this type, so its rendering is observable
/// outside the crate even though the type cannot be named.
///
/// It renders the fields every builder had before this option set grew, in
/// their original order, so a builder written against an earlier release prints
/// exactly what it printed then. The new opt-ins appear only when they are set.
impl fmt::Debug for AttachOptions {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        let mut options = f.debug_struct("AttachOptions");
        options
            .field("args", &self.args)
            .field("env", &self.env)
            .field("cwd", &self.cwd)
            .field("user", &self.user)
            .field("detach_keys", &self.debug_detach_keys())
            .field("rlimits", &self.rlimits)
            .field("stdin_filter", &self.stdin_filter);
        if matches!(self.detach, DetachPolicy::Disabled) {
            options.field("detach", &DetachPolicyDebug(&self.detach));
        }
        if self.checked_session {
            options.field("checked_session", &true);
        }
        options.finish()
    }
}

impl fmt::Debug for DetachPolicyDebug<'_> {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self.0 {
            DetachPolicy::Default => f.write_str("Default"),
            DetachPolicy::Custom(spec) => write!(f, "Custom({spec:?})"),
            DetachPolicy::Disabled => f.write_str("Disabled"),
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

#[test]
fn detach_policy_is_one_field() {
    // The last setter wins by construction: one value, not a flag beside a
    // sequence that has to be kept in step with it.
    let disabled_last = AttachOptionsBuilder::default()
        .detach_keys("ctrl-a")
        .disable_detach_keys()
        .build()
        .unwrap();
    assert!(matches!(disabled_last.detach, DetachPolicy::Disabled));

    let custom_last = AttachOptionsBuilder::default()
        .disable_detach_keys()
        .detach_keys("ctrl-a")
        .build()
        .unwrap();
    assert!(matches!(
        &custom_last.detach,
        DetachPolicy::Custom(keys) if keys == "ctrl-a"
    ));
}

/// `build()` is public, so this rendering is part of the option surface even
/// though `AttachOptions` cannot be named outside the crate.
///
/// The two strings were captured from the release that predates this option
/// set's additions (`fd74d1a8`): a builder that could have been written then
/// must print exactly what it printed then.
#[test]
fn debug_output_matches_main_for_legacy_builders() {
    assert_eq!(
        format!("{:?}", AttachOptionsBuilder::default().build().unwrap()),
        "AttachOptions { args: [], env: [], cwd: None, user: None, detach_keys: None, rlimits: \
         [], stdin_filter: None }"
    );
    assert_eq!(
        format!(
            "{:?}",
            AttachOptionsBuilder::default()
                .detach_keys("ctrl-q")
                .args(["-c"])
                .build()
                .unwrap()
        ),
        "AttachOptions { args: [\"-c\"], env: [], cwd: None, user: None, detach_keys: \
         Some(\"ctrl-q\"), rlimits: [], stdin_filter: None }"
    );
}

#[test]
fn debug_output_shows_only_the_new_opt_ins_that_were_set() {
    let disabled = AttachOptionsBuilder::default()
        .disable_detach_keys()
        .build()
        .unwrap();
    assert!(
        format!("{disabled:?}").ends_with("detach: Disabled }"),
        "a disabled interception must be named: {disabled:?}"
    );

    let checked = AttachOptionsBuilder::default()
        .checked_session()
        .build()
        .unwrap();
    assert!(
        format!("{checked:?}").ends_with("checked_session: true }"),
        "a checked session must be named: {checked:?}"
    );

    // A custom sequence is the field every earlier release had, so it is not
    // repeated as a policy.
    let custom = AttachOptionsBuilder::default()
        .detach_keys("ctrl-q")
        .build()
        .unwrap();
    assert!(
        !format!("{custom:?}").contains("detach:"),
        "a custom sequence renders in its own field: {custom:?}"
    );
}
