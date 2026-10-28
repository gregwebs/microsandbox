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
use std::os::fd::{AsRawFd, OwnedFd, RawFd};
use std::path::{Path, PathBuf};
use std::process::{Command, Stdio};
use std::sync::Arc;
use std::sync::atomic::{AtomicBool, AtomicUsize, Ordering};
use std::time::{Duration, Instant};

use microsandbox_protocol::codec;
use microsandbox_protocol::core::Ready;
use microsandbox_protocol::exec::{
    ExecExited, ExecFailed, ExecFailureKind, ExecRequest, ExecResize, ExecStdin, ExecStdout,
};
use microsandbox_protocol::message::{Message, MessageType};
use tokio::io::{AsyncRead, AsyncWrite, AsyncWriteExt, DuplexStream};

use crate::agent::AgentClient;

use super::AttachOptionsBuilder;
use super::checked::CheckedFailure;
use super::unix;
use crate::SandboxConfig;

/// Where the child reads its case from and writes its receipts to.
const CASE_DIR: &str = "MSB_ATTACH_PTY_DIR";
const CASE_NAME: &str = "MSB_ATTACH_PTY_CASE";

/// The full name the parent re-runs this binary with.
const CHILD_TEST: &str = "sandbox::attach::pty_tests::checked_bridge_pty_case";

/// Every wait in this harness is bounded: a stuck case must fail, not hang.
const DEADLINE: Duration = Duration::from_secs(30);

/// Frames the output-flood cases send, at `FLOOD_FRAME_BYTES` each: 10 MiB,
/// more than the writer's queue and the session's read-ahead can hold together,
/// so the guest is always ahead of the host consumer.
const FLOOD_FRAMES: usize = 40;
const FLOOD_FRAME_BYTES: usize = 256 * 1024;

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
    /// A detach in a checked session is an error, and the terminal is still
    /// restored.
    CheckedDetach,
    /// The guest exits while the host is not draining output: no staged chunk
    /// may be lost on the way out.
    ExitDuringBackpressure,
    /// Host input and a resize still reach the guest while guest output is
    /// waiting for a consumer that has stopped.
    InputDuringBackpressure,
    /// Dropping the session future restores the terminal.
    Cancel,
    /// The *no-options* legacy session still detaches on Ctrl-] while the
    /// relay stays open, i.e. the default interception is intact.
    LegacyDetach,
    /// The no-options legacy session still reports `Ok(-1)` for a channel
    /// that closed without a guest exit.
    LegacyClosed,
    /// A filter set beside `checked_session()` is honoured, one chunk at a
    /// time and in input order: the guest sees the filter's tags, not raw
    /// input.
    Filtered,
    /// A filtered chunk that produces no bytes is swallowed rather than
    /// forwarded raw, and the session still completes.
    FilteredSwallow,
    /// The same filter without `checked_session()`: a checked session must not
    /// change what the filter sees.
    FilteredLegacy,
}

impl Case {
    const ALL: [Case; 16] = [
        Case::Input,
        Case::Resize,
        Case::Failed,
        Case::Malformed,
        Case::Closed,
        Case::OutputFailure,
        Case::OutputBackpressure,
        Case::CheckedDetach,
        Case::ExitDuringBackpressure,
        Case::InputDuringBackpressure,
        Case::Cancel,
        Case::LegacyDetach,
        Case::LegacyClosed,
        Case::Filtered,
        Case::FilteredSwallow,
        Case::FilteredLegacy,
    ];

    /// Whether this case drives the untouched default session instead of the
    /// checked one. The legacy conventions are the reason both exist.
    fn legacy(self) -> bool {
        matches!(self, Case::LegacyDetach | Case::LegacyClosed)
    }

    fn name(self) -> &'static str {
        match self {
            Case::Input => "input",
            Case::Resize => "resize",
            Case::Failed => "failed",
            Case::Malformed => "malformed",
            Case::Closed => "closed",
            Case::OutputFailure => "output-failure",
            Case::OutputBackpressure => "output-backpressure",
            Case::CheckedDetach => "checked-detach",
            Case::ExitDuringBackpressure => "exit-during-backpressure",
            Case::InputDuringBackpressure => "input-during-backpressure",
            Case::Cancel => "cancel",
            Case::LegacyDetach => "legacy-detach",
            Case::LegacyClosed => "legacy-closed",
            Case::Filtered => "filtered",
            Case::FilteredSwallow => "filtered-swallow",
            Case::FilteredLegacy => "filtered-legacy",
        }
    }

    fn parse(name: &str) -> Self {
        Self::ALL
            .into_iter()
            .find(|case| case.name() == name)
            .unwrap_or_else(|| panic!("unknown PTY case {name}"))
    }
}

// The parent: allocates the terminal, drives the case, compares attributes.

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
    let mut child = CaseChild::new(command.spawn().expect("spawn the case child"));

    // Both pipes are drained concurrently: a child that logs must never block
    // on a full pipe while the parent waits for its receipt.
    let mut child_stdout = child.get().stdout.take().expect("child stdout");
    let mut child_stderr = child.get().stderr.take().expect("child stderr");
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
            // The case child is not a session leader, so the signal goes to
            // the exact owned child rather than to a process group.
            nix::sys::signal::kill(
                nix::unistd::Pid::from_raw(child.id() as i32),
                nix::sys::signal::Signal::SIGWINCH,
            )
            .expect("send SIGWINCH");
        }
        Case::ExitDuringBackpressure => {
            // The relay floods output and then reports the guest's exit, all
            // while the host is not draining. Release the raw barrier first,
            // then wait for that exit to be sent, and only then start draining:
            // the session must end during a capacity wait.
            std::fs::write(dir.join("go"), b"go").expect("release the relay");
            wait_for(dir, "stage=exit-sent");
            std::fs::write(dir.join("drain"), b"drain").expect("drain the output");
        }
        Case::InputDuringBackpressure => {
            // The relay floods until the session cannot take another byte, and
            // only then is input typed: the host consumer is stalled for the
            // whole case, so output can never make room for the keystroke.
            std::fs::write(dir.join("go"), b"go").expect("release the relay");
            wait_for(dir, "stage=saturated");
            let mut master = std::fs::File::from(pty.master.try_clone().expect("clone master"));
            master.write_all(&[0x03]).expect("type at the terminal");
            master.flush().expect("flush the terminal input");
            set_winsize(pty.slave.as_raw_fd(), 50, 132);
            nix::sys::signal::kill(
                nix::unistd::Pid::from_raw(child.id() as i32),
                nix::sys::signal::Signal::SIGWINCH,
            )
            .expect("send SIGWINCH");
            wait_for_prefix(dir, "stage=input-seen");
            std::fs::write(dir.join("drain"), b"drain").expect("drain the output");
            std::fs::write(dir.join("finish"), b"finish").expect("finish the relay");
        }
        Case::LegacyDetach | Case::CheckedDetach => {
            // The detach sequence, typed at the terminal exactly as a user
            // types it. The relay stays open (see the relay below), so a status
            // of -1 here cannot be the closed channel's convention, and a
            // checked session's error cannot be a lost connection.
            let mut master = std::fs::File::from(pty.master.try_clone().expect("clone master"));
            master.write_all(b"\x1d").expect("type the detach sequence");
            master.flush().expect("flush the detach sequence");
        }
        Case::Filtered | Case::FilteredLegacy => {
            // Released before typing, unlike the input case: the relay has to
            // be reading frames for the parent to step one chunk at a time.
            std::fs::write(dir.join("go"), b"go").expect("release the relay");
            let mut master = std::fs::File::from(pty.master.try_clone().expect("clone master"));
            // Each chunk is typed only after the filter's tag for the previous
            // one reached the guest, so the frames are per chunk and ordered by
            // construction rather than by a sleep.
            for (typed, tag) in [
                (b'a', "stdin_frame=30"),
                (b'b', "stdin_frame=31"),
                (b'c', "stdin_frame=32"),
            ] {
                master.write_all(&[typed]).expect("type at the terminal");
                master.flush().expect("flush the terminal input");
                wait_for(dir, tag);
            }
        }
        Case::FilteredSwallow => {
            std::fs::write(dir.join("go"), b"go").expect("release the relay");
            let mut master = std::fs::File::from(pty.master.try_clone().expect("clone master"));
            // The first chunk produces no bytes at all; the filter only sees the
            // second one after it. Nothing may reach the guest for the first.
            master.write_all(b"a").expect("type the swallowed chunk");
            master.flush().expect("flush the swallowed chunk");
            std::thread::sleep(Duration::from_millis(200));
            master.write_all(b"b").expect("type the forwarded chunk");
            master.flush().expect("flush the forwarded chunk");
        }
        Case::Failed
        | Case::Malformed
        | Case::Closed
        | Case::OutputFailure
        | Case::OutputBackpressure
        | Case::Cancel
        | Case::LegacyClosed => {}
    }
    std::fs::write(dir.join("go"), b"go").expect("release the child");

    let receipt = wait_for_receipt(dir);
    // The output-failure case keeps its relay open on purpose: the session must
    // end on the writer's own failure, so the parent releases the relay only
    // after the child has already reported its outcome.
    if matches!(
        case,
        Case::OutputFailure | Case::LegacyDetach | Case::CheckedDetach
    ) {
        std::fs::write(dir.join("release"), b"release").expect("release the relay");
    }
    child.wait_within(DEADLINE);

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
                relay_value(&relay, "request_env").contains("PATH=/opt/attach-test-bin"),
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
        Case::Malformed => {
            assert!(
                outcome.starts_with("err:attach:Protocol:"),
                "case {}: a decode failure is a protocol failure: {receipt}",
                case.name()
            );
        }
        Case::Closed => {
            assert!(
                outcome.starts_with("err:attach:ConnectionLost:"),
                "case {}: a session failure must be reported: {receipt}",
                case.name()
            );
        }
        Case::OutputFailure => {
            // The relay was still open when this session ended, so the failure
            // can only be the writer's own.
            assert!(
                outcome.starts_with("err:attach:Output:"),
                "case {}: an unwritable descriptor must be reported as an output \
                 failure, not as any other failure: {receipt}",
                case.name()
            );
            assert!(
                outcome.contains("writing guest output"),
                "case {}: the writer's own failure must be named: {receipt}",
                case.name()
            );
        }
        Case::OutputBackpressure => {
            assert!(
                outcome.starts_with("err:attach:ConnectionLost:"),
                "case {}: a relay lost while output capacity was exhausted must be \
                 reported as a lost connection: {receipt}",
                case.name()
            );
            assert!(
                outcome.contains("closed before the guest reported its exit"),
                "case {}: a lost relay must say what was lost: {receipt}",
                case.name()
            );
        }
        Case::CheckedDetach => {
            // A checked session turns the detach sequence into an error and
            // leaves the guest running; the terminal must still be restored.
            assert!(
                outcome.starts_with("err:attach:Detached:"),
                "case {}: a detach in a checked session is an error: {receipt}",
                case.name()
            );
        }
        Case::ExitDuringBackpressure => {
            // A guest exit is a definitive end: every byte the guest wrote
            // before it must reach the descriptor, in order, even though the
            // host consumer was stalled throughout.
            assert_eq!(outcome, "ok:5", "case {}: {receipt}", case.name());
            assert_eq!(
                receipt_value(&receipt, "output_len"),
                (FLOOD_FRAMES * FLOOD_FRAME_BYTES).to_string(),
                "case {}: a guest exit during a capacity wait must not lose output: {receipt}",
                case.name()
            );
            assert_eq!(
                receipt_value(&receipt, "output_ok"),
                "true",
                "case {}: the output must arrive complete, in order and unaltered: {receipt}",
                case.name()
            );
        }
        Case::InputDuringBackpressure => {
            assert_eq!(outcome, "ok:0", "case {}: {receipt}", case.name());
            let relay = wait_for_receipt_file(dir, "relay.receipt");
            assert!(
                relay
                    .lines()
                    .any(|line| line == "stage=input-seen drained=false"),
                "case {}: input and a resize must reach the guest while the host is \
                 not draining output: {relay}",
                case.name()
            );
            assert_eq!(
                relay_value(&relay, "resize"),
                "50x132",
                "case {}: a resize must reach the guest under output backpressure",
                case.name()
            );
            assert!(
                stdin_frames(dir).iter().any(|frame| frame == "03"),
                "case {}: a keystroke must reach the guest under output backpressure",
                case.name()
            );
            assert_eq!(
                receipt_value(&receipt, "output_ok"),
                "true",
                "case {}: the output must arrive complete, in order and unaltered: {receipt}",
                case.name()
            );
        }
        Case::LegacyDetach | Case::LegacyClosed => {
            // The legacy conventions, unchanged by the checked session: a
            // detach and a closed channel both end with the -1 sentinel rather
            // than a guest status.
            assert_eq!(
                outcome,
                "ok:-1",
                "case {}: the legacy session must keep its Ok(-1) convention: {receipt}",
                case.name()
            );
        }
        Case::Cancel => {
            assert_eq!(outcome, "cancelled", "case {}: {receipt}", case.name());
        }
        Case::Filtered | Case::FilteredLegacy => {
            // Identical frames and status for both sessions: `checked_session`
            // changes what a failure means, never what the filter sees.
            assert_eq!(outcome, "ok:0", "case {}: {receipt}", case.name());
            assert_eq!(
                stdin_frames(dir),
                ["30", "31", "32"],
                "case {}: every chunk must reach the guest as exactly the filter's \
                 bytes, one frame at a time and in input order",
                case.name()
            );
        }
        Case::FilteredSwallow => {
            assert_eq!(outcome, "ok:0", "case {}: {receipt}", case.name());
            assert_eq!(
                stdin_frames(dir),
                ["62"],
                "case {}: the swallowed chunk must not be forwarded raw, and the \
                 session must still complete",
                case.name()
            );
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

/// Wait for a relay line that *starts with* `prefix`, e.g. a marker that carries
/// a value.
fn wait_for_prefix(dir: &Path, prefix: &str) {
    let deadline = Instant::now() + DEADLINE;
    loop {
        let relay = std::fs::read_to_string(dir.join("relay.receipt")).unwrap_or_default();
        if relay.lines().any(|line| line.starts_with(prefix)) {
            return;
        }
        // A child that failed before the barrier says why.
        if let Ok(receipt) = std::fs::read_to_string(dir.join("child.receipt")) {
            panic!("the child finished before reaching {prefix}: {receipt}");
        }
        assert!(
            Instant::now() < deadline,
            "the child never reported {prefix}"
        );
        std::thread::sleep(Duration::from_millis(5));
    }
}

fn wait_for_receipt(dir: &Path) -> String {
    wait_for_receipt_file(dir, "child.receipt")
}

/// Every `ExecStdin` frame the relay recorded, in arrival order.
fn stdin_frames(dir: &Path) -> Vec<String> {
    wait_for_receipt_file(dir, "relay.receipt")
        .lines()
        .filter_map(|line| line.strip_prefix("stdin_frame=").map(str::to_owned))
        .collect()
}

/// The case child, killed and reaped if this parent panics.
///
/// Every parent wait is bounded, but an assertion that panicked first used to
/// leave the child (and its fake relay) running for the rest of the suite.
struct CaseChild {
    child: Option<std::process::Child>,
}

impl CaseChild {
    fn new(child: std::process::Child) -> Self {
        Self { child: Some(child) }
    }

    fn id(&self) -> u32 {
        self.child.as_ref().expect("the child is still owned").id()
    }

    fn get(&mut self) -> &mut std::process::Child {
        self.child.as_mut().expect("the child is still owned")
    }

    /// Wait for the child under a parent-side deadline, then reap it.
    fn wait_within(&mut self, deadline: Duration) {
        let limit = Instant::now() + deadline;
        loop {
            let owned = self.child.as_mut().expect("the child is still owned");
            if owned.try_wait().expect("query the child").is_some() {
                self.child = None;
                return;
            }
            assert!(Instant::now() < limit, "the case child did not exit");
            std::thread::sleep(Duration::from_millis(5));
        }
    }
}

impl Drop for CaseChild {
    fn drop(&mut self) {
        if let Some(child) = self.child.as_mut() {
            let _ = child.kill();
            let _ = child.wait();
        }
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

// The child: one case behind its own token, in a process with a real PTY.

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
    let output = capture_output(&dir);
    // A flood's hex would be 20 MiB of receipt. Those cases compare the bytes
    // here and report a verdict instead.
    let stdout_hex = if output.len() <= 64 * 1024 {
        hex(&output)
    } else {
        String::new()
    };
    let output_ok = match output_matches(&dir, &output, case) {
        Some(ok) => ok.to_string(),
        None => "n/a".to_string(),
    };
    let receipt = format!(
        "outcome={}\nstdout_hex={}\noutput_len={}\noutput_ok={}\ntermios={}\n",
        outcome.describe(),
        stdout_hex,
        output.len(),
        output_ok,
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

/// Where a case's host stdout goes, and what has to happen to it once the
/// session has ended.
///
/// Guest output is captured here only: the checked writer duplicates fd 1, so
/// nothing libtest prints can be mistaken for a guest byte.
enum Capture {
    /// A file: the writer's bytes land there and the parent reads them back.
    File { fd: OwnedFd },
    /// A pipe whose read end is already closed, so the writer's first write
    /// fails.
    Closed { fd: OwnedFd },
    /// A pipe whose read end is held open but never drained, so the writer
    /// blocks once the pipe's own buffer is full.
    Held { fd: OwnedFd, held: OwnedFd },
    /// A pipe drained by this child once the parent writes `drain`: the session
    /// runs with an output consumer that is not consuming.
    Stalled {
        fd: OwnedFd,
        drain: std::thread::JoinHandle<()>,
    },
}

impl Capture {
    fn start(dir: &Path, case: Case) -> Self {
        match case {
            Case::OutputFailure => {
                let (read_end, write_end) = std::io::pipe().expect("an output pipe");
                drop(read_end);
                Self::Closed {
                    fd: write_end.into(),
                }
            }
            Case::OutputBackpressure => {
                let (read_end, write_end) = std::io::pipe().expect("an output pipe");
                Self::Held {
                    fd: write_end.into(),
                    held: read_end.into(),
                }
            }
            Case::ExitDuringBackpressure | Case::InputDuringBackpressure => {
                let (read_end, write_end) = std::io::pipe().expect("an output pipe");
                Self::Stalled {
                    fd: write_end.into(),
                    drain: spawn_drain(dir.to_path_buf(), read_end),
                }
            }
            _ => Self::File {
                fd: std::fs::OpenOptions::new()
                    .create(true)
                    .write(true)
                    .truncate(true)
                    .open(dir.join("output.bin"))
                    .expect("the output capture file")
                    .into(),
            },
        }
    }

    fn fd(&self) -> RawFd {
        let owned = match self {
            Self::File { fd }
            | Self::Closed { fd }
            | Self::Held { fd, .. }
            | Self::Stalled { fd, .. } => fd,
        };
        owned.as_raw_fd()
    }

    /// Close this child's last write end and wait for a drain thread to finish.
    ///
    /// The drain thread writes `output.bin`, so the receipt is only written
    /// after this returns.
    fn finish(self) {
        match self {
            Self::File { fd } | Self::Closed { fd } => drop(fd),
            Self::Held { fd, held } => {
                drop(fd);
                drop(held);
            }
            Self::Stalled { fd, drain } => {
                drop(fd);
                drain.join().expect("drain the captured output");
            }
        }
    }
}

/// Copy the output pipe to `output.bin`, but only once the parent says
/// `drain`.
///
/// Reading nothing until then is what keeps the writer blocked while the case
/// runs; reading everything afterwards is what proves the bytes were still
/// there.
fn spawn_drain(dir: PathBuf, reader: std::io::PipeReader) -> std::thread::JoinHandle<()> {
    std::thread::spawn(move || {
        let deadline = Instant::now() + DEADLINE;
        while !dir.join("drain").exists() {
            assert!(
                Instant::now() < deadline,
                "the parent never drained the output"
            );
            std::thread::sleep(Duration::from_millis(5));
        }
        let mut screen = std::fs::File::from(OwnedFd::from(reader));
        let mut captured =
            std::fs::File::create(dir.join("output.bin")).expect("the output capture file");
        let mut buffer = vec![0u8; 64 * 1024];
        loop {
            match screen.read(&mut buffer) {
                Ok(0) => break,
                Ok(read) => captured
                    .write_all(&buffer[..read])
                    .expect("write the captured output"),
                Err(error) => panic!("draining the output pipe: {error}"),
            }
        }
        captured.flush().expect("flush the captured output");
    })
}

fn run_bridge_case(dir: &Path, case: Case) -> Outcome {
    let capture = Capture::start(dir, case);
    let saved_stdout = unsafe { libc::dup(1) };
    assert!(saved_stdout >= 0, "duplicate stdout");
    assert_eq!(unsafe { libc::dup2(capture.fd(), 1) }, 1);

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
    capture.finish();
    outcome
}

/// One flood frame: a single byte value repeated.
///
/// Frame `i` uses `(i % 251)`, so a lost or reordered 64 KiB chunk changes the
/// content and not only the length.
fn flood_frame(index: usize) -> Vec<u8> {
    vec![(index % 251) as u8; FLOOD_FRAME_BYTES]
}

/// The bytes a flood of `frames` frames must produce, exactly.
fn flood_bytes(frames: usize) -> Vec<u8> {
    (0..frames).flat_map(flood_frame).collect()
}

/// Whether the captured output is exactly what the case's relay sent, for the
/// cases that know their own expectation.
fn output_matches(dir: &Path, output: &[u8], case: Case) -> Option<bool> {
    match case {
        Case::ExitDuringBackpressure => Some(output == flood_bytes(FLOOD_FRAMES)),
        // The relay floods until the session stops taking output, so the count
        // is only known from its own receipt.
        Case::InputDuringBackpressure => {
            let relay = std::fs::read_to_string(dir.join("relay.receipt")).ok()?;
            let frames: usize = receipt_line(&relay, "relay_frames")?.parse().ok()?;
            Some(frames > 0 && output == flood_bytes(frames))
        }
        _ => None,
    }
}

async fn run_case_session(dir: &Path, case: Case) -> Outcome {
    let builder = AttachOptionsBuilder::default()
        .args(["-c", "probe"])
        .cwd("/workspace/project")
        .user("1000:1000")
        .env("PATH", "/opt/attach-test-bin");
    // The legacy cases call neither opt-in, so this is exactly the session
    // every existing caller gets: default detach interception, best-effort
    // output and the -1 sentinel. The filter cases add `stdin_filter` on top
    // of the checked session, which is the composition under test.
    let options = match case {
        Case::Filtered => builder
            .disable_detach_keys()
            .checked_session()
            .stdin_filter(TagChunks::default()),
        Case::FilteredSwallow => builder
            .disable_detach_keys()
            .checked_session()
            .stdin_filter(SwallowA),
        Case::FilteredLegacy => builder
            .disable_detach_keys()
            .stdin_filter(TagChunks::default()),
        // A checked session with its detach keys left at the default: the
        // sequence must be reported, not silently forwarded or ignored.
        Case::CheckedDetach => builder.checked_session(),
        _ if case.legacy() => builder,
        _ => builder.disable_detach_keys().checked_session(),
    }
    .build()
    .expect("session options");
    let config = SandboxConfig::default();

    let (client_io, server_io) = tokio::io::duplex(512 * 1024);
    let relay = tokio::spawn(fake_relay(server_io, dir.to_path_buf(), case));
    let client =
        match AgentClient::connect_stream_with_timeout(client_io, Duration::from_secs(10)).await {
            Ok(client) => client,
            Err(error) => return Outcome::Error(format!("terminal:{error}")),
        };
    let client = Arc::new(client);

    // Most checked cases call the session directly, so the failure *kind* is
    // asserted instead of a rendered string. `Input` and `Resize` keep going
    // through `attach_connected`, so the dispatch and the crate-boundary
    // conversion stay covered end to end.
    let outcome = if case.legacy() || matches!(case, Case::Input | Case::Resize) {
        session_outcome(unix::attach_connected(client, &config, "bash".to_string(), options).await)
    } else {
        let detach_keys = options
            .resolved_detach_keys()
            .expect("the case's detach keys");
        let session =
            unix::checked_session(client, &config, "bash".to_string(), options, detach_keys);
        match case {
            Case::Cancel => {
                // The relay stays open. The parent releases the case once raw
                // mode is observed, and this side then drops the session
                // future, which must restore the terminal without a guest exit.
                tokio::select! {
                    result = session => checked_outcome(result),
                    _ = released_then_settle(dir) => Outcome::Cancelled,
                }
            }
            _ => checked_outcome(session.await),
        }
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

/// The outcome of a checked session, by failure kind rather than by text.
///
/// `attach:<kind>:<text>` is what the parent's assertions match: the kind is
/// the interface, the text is diagnostic.
fn checked_outcome(result: Result<i32, CheckedFailure>) -> Outcome {
    match result {
        Ok(code) => Outcome::Exited(code),
        Err(CheckedFailure::Spawn(_)) => Outcome::Error("exec-failed".into()),
        Err(CheckedFailure::Session(error)) => {
            Outcome::Error(format!("attach:{:?}:{error}", error.kind()))
        }
        Err(CheckedFailure::Setup(error)) => Outcome::Error(format!("setup:{error}")),
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

/// Answer the agent handshake on a fresh stream, exactly as agentd's relay
/// does: version, frame limit, then `Ready`.
///
/// Shared with the loop fixture in `unix.rs`, which needs an `AgentClient`
/// over a relay it owns.
pub(super) async fn relay_handshake(io: &mut DuplexStream) {
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
        io,
        Message::with_payload(MessageType::Ready, 0, &ready).unwrap(),
    )
    .await;
}

async fn fake_relay(mut io: DuplexStream, dir: PathBuf, case: Case) {
    relay_handshake(&mut io).await;

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
            let frames = super::checked_output::CHECKED_OUTPUT_MAX_PENDING_BYTES / frame.len() + 2;
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
        Case::ExitDuringBackpressure => {
            // Flood output and then report the guest's exit, all before the
            // host has consumed anything. The connection stays open: the exit,
            // not a lost relay, has to end this session, and every byte the
            // guest wrote before that exit still has to arrive.
            for index in 0..FLOOD_FRAMES {
                write(
                    &mut io,
                    Message::with_payload(
                        MessageType::ExecStdout,
                        id,
                        &ExecStdout {
                            data: flood_frame(index),
                        },
                    )
                    .unwrap(),
                )
                .await;
            }
            write(
                &mut io,
                Message::with_payload(MessageType::ExecExited, id, &ExecExited { code: 5 })
                    .unwrap(),
            )
            .await;
            append(&dir, &["stage=exit-sent".to_string()]);
        }
        Case::InputDuringBackpressure => input_during_backpressure(io, &dir, id).await,
        Case::Cancel => {
            // Keep the connection open while the parent releases the case.
            tokio::time::sleep(Duration::from_secs(2)).await;
        }
        Case::LegacyDetach | Case::CheckedDetach => {
            // No guest exit and no closure: only the typed detach sequence can
            // end this session, and the parent releases the relay only after
            // the child has reported how it ended.
            wait_for_dir(&dir, "release").await;
        }
        Case::Filtered | Case::FilteredLegacy => {
            // One frame per filtered chunk: a chunk queued behind a busy filter
            // may not overtake it, so the tags have to arrive in order.
            let mut seen = 0;
            while seen < 3 {
                let Some(message) = read(&mut io).await else {
                    break;
                };
                if message.t != MessageType::ExecStdin {
                    continue;
                }
                let frame: ExecStdin = message.payload().expect("stdin payload");
                append(&dir, &[format!("stdin_frame={}", hex(&frame.data))]);
                seen += 1;
            }
            write(
                &mut io,
                Message::with_payload(MessageType::ExecExited, id, &ExecExited { code: 0 })
                    .unwrap(),
            )
            .await;
        }
        Case::FilteredSwallow => {
            // The swallowed chunk produces no frame; the first frame the guest
            // sees must therefore come from the second chunk.
            while let Some(message) = read(&mut io).await {
                if message.t != MessageType::ExecStdin {
                    continue;
                }
                let frame: ExecStdin = message.payload().expect("stdin payload");
                append(&dir, &[format!("stdin_frame={}", hex(&frame.data))]);
                break;
            }
            write(
                &mut io,
                Message::with_payload(MessageType::ExecExited, id, &ExecExited { code: 0 })
                    .unwrap(),
            )
            .await;
        }
        Case::LegacyClosed => {
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
            // The legacy session treats a lost channel as the -1 sentinel.
            drop(io);
        }
    }
}

/// Flood guest output until the session stops taking any, then record what the
/// session forwarded while the host consumer was stalled, and let the guest
/// exit.
///
/// The harness assumes the session holds two bounds, so the flood has to keep
/// going until *no frame completes* rather than for a fixed count: only then is
/// the session's read-ahead necessarily full and its receive arm necessarily
/// off.
async fn input_during_backpressure(io: DuplexStream, dir: &Path, id: u32) {
    let (mut reader, mut writer) = tokio::io::split(io);
    let frames = Arc::new(AtomicUsize::new(0));
    let stop = Arc::new(AtomicBool::new(false));

    let producer = {
        let frames = Arc::clone(&frames);
        let stop = Arc::clone(&stop);
        tokio::spawn(async move {
            let mut index = 0usize;
            while !stop.load(Ordering::Relaxed) {
                let message = Message::with_payload(
                    MessageType::ExecStdout,
                    id,
                    &ExecStdout {
                        data: flood_frame(index),
                    },
                )
                .expect("a guest output frame");
                write(&mut writer, message).await;
                frames.fetch_add(1, Ordering::Relaxed);
                index += 1;
            }
            // The frame in progress when the parent said `finish` completes once
            // the session takes output again, which is what `drain` is for.
            writer
        })
    };

    // `stage=saturated` only times the parent's next step: it says no frame has
    // completed for a while, so the session is holding as much output as it can.
    tokio::spawn({
        let dir = dir.to_path_buf();
        let frames = Arc::clone(&frames);
        async move {
            while frames.load(Ordering::Relaxed) == 0 {
                tokio::time::sleep(Duration::from_millis(2)).await;
            }
            let mut last = frames.load(Ordering::Relaxed);
            loop {
                tokio::time::sleep(Duration::from_millis(50)).await;
                let now = frames.load(Ordering::Relaxed);
                if now == last {
                    append(&dir, &["stage=saturated".to_string()]);
                    return;
                }
                last = now;
            }
        }
    });

    let mut seen_stdin = false;
    let mut seen_resize = false;
    loop {
        tokio::select! {
            message = read(&mut reader) => {
                let Some(message) = message else { break };
                match message.t {
                    MessageType::ExecStdin => {
                        let frame: ExecStdin = message.payload().expect("stdin payload");
                        append(dir, &[format!("stdin_frame={}", hex(&frame.data))]);
                        seen_stdin |= frame.data.contains(&0x03);
                    }
                    MessageType::ExecResize => {
                        let frame: ExecResize = message.payload().expect("resize payload");
                        append(dir, &[format!("resize={}x{}", frame.rows, frame.cols)]);
                        seen_resize = true;
                    }
                    _ => {}
                }
                if seen_stdin && seen_resize {
                    // `drained` records whether the host consumer had started to
                    // take output by the time both forwards happened.
                    append(
                        dir,
                        &[format!(
                            "stage=input-seen drained={}",
                            dir.join("drain").exists()
                        )],
                    );
                    seen_stdin = false;
                    seen_resize = false;
                }
            }
            _ = wait_for_dir(dir, "finish") => break,
        }
    }

    stop.store(true, Ordering::Relaxed);
    let mut writer = producer.await.expect("the flood producer");
    let count = frames.load(Ordering::Relaxed);
    append(dir, &[format!("relay_frames={count}")]);
    write(
        &mut writer,
        Message::with_payload(MessageType::ExecExited, id, &ExecExited { code: 0 })
            .expect("a guest exit frame"),
    )
    .await;
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

async fn read<S>(io: &mut S) -> Option<Message>
where
    S: AsyncRead + Unpin,
{
    match tokio::time::timeout(DEADLINE, codec::read_message(io)).await {
        Ok(Ok(message)) => Some(message),
        Ok(Err(_)) | Err(_) => None,
    }
}

async fn write<S>(io: &mut S, message: Message)
where
    S: AsyncWrite + Unpin,
{
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

// The filters the two filter cases install.

/// Replaces each chunk with the next tag byte, slowly.
///
/// The delay is what makes an implementation that forwarded a raw chunk, or
/// that let a later chunk overtake a busy filter, visible in the relay's
/// frames rather than merely slow: no raw byte can appear, and no tag can be
/// duplicated or reordered.
#[derive(Default)]
struct TagChunks {
    next: u8,
}

impl super::StdinFilter for TagChunks {
    fn filter<'a>(
        &'a mut self,
        _data: &'a [u8],
    ) -> std::pin::Pin<Box<dyn std::future::Future<Output = Vec<u8>> + Send + 'a>> {
        let tag = b'0' + self.next;
        self.next += 1;
        Box::pin(async move {
            tokio::time::sleep(Duration::from_millis(150)).await;
            vec![tag]
        })
    }
}

/// Swallows every `a`, forwards the rest: a filter that emits nothing.
struct SwallowA;

impl super::StdinFilter for SwallowA {
    fn filter<'a>(
        &'a mut self,
        data: &'a [u8],
    ) -> std::pin::Pin<Box<dyn std::future::Future<Output = Vec<u8>> + Send + 'a>> {
        let out: Vec<u8> = data.iter().copied().filter(|byte| *byte != b'a').collect();
        Box::pin(async move { out })
    }
}
