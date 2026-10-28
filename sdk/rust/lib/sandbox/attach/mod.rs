//! Interactive attach: bridge a host terminal to a guest PTY exec session.
//!
//! One connection setup serves two deliberately different sessions. The legacy
//! session is the interactive `shell` behavior, whose completion conventions
//! (`Ok(-1)` when no exit event arrived) and best-effort I/O are observable and
//! must not change. The checked session is an opt-in for a caller that owns the
//! process's exit status and must distinguish a guest exit from a lost session.

#[cfg(any(unix, windows))]
mod checked;
#[cfg(unix)]
mod checked_output;
#[cfg(any(unix, windows))]
mod error;
mod input;
mod options;
#[cfg(all(test, unix))]
mod pty_tests;
#[cfg(unix)]
mod unix;
#[cfg(windows)]
mod windows;

//--------------------------------------------------------------------------------------------------
// Re-Exports
//--------------------------------------------------------------------------------------------------

pub use input::StdinFilter;
#[cfg(feature = "ssh")]
pub(crate) use input::input_contains_detach_sequence;
pub(crate) use input::{
    DetachKeys, FilteredStdin, InputRoute, STDIN_FILTER_TASK_ENDED, recv_filtered,
    require_filtered, route_input,
};
pub use options::{AttachOptions, AttachOptionsBuilder};
#[cfg(unix)]
pub(crate) use unix::attach;
#[cfg(windows)]
pub(crate) use windows::attach;
