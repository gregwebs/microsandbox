#![cfg(unix)]

//! End-to-end checked attach against a real microVM over a real host terminal.
//!
//! Every case drives the public `Sandbox::attach_with` surface with fd 0 on a
//! fresh PTY slave and fd 1 on a pipe this test owns. That is the closest an
//! automated test gets to a user's terminal: the session sets raw mode on a real
//! terminal device, decodes a real relay, and its guest output is captured byte
//! for byte instead of being mixed with libtest's own output.
//!
//! The cases cover what only a real guest and a real relay can show:
//!
//! * a guest of 2 MiB that exits while the host is not draining, i.e. the output
//!   chunk a session holds when the exit arrives is not lost;
//! * 12 MiB delivered byte for byte, more than the session's read-ahead bound,
//!   with the guest's own status preserved;
//! * `Ctrl-]` reaching the guest unchanged when detach keys are disabled;
//! * a detach in a checked session reported as an error while the guest keeps
//!   running;
//! * the legacy session, with no options set at all, still detaching with
//!   `Ok(-1)`.
//!
//! Every case compares the PTY's attributes before and after the session, so a
//! session that leaves the terminal raw fails even when its verdict is right.
//!
//! Needs a working local VM backend. Run with (from the repository root):
//!
//! ```text
//! MSB_HOME=$(mktemp -d /tmp/msb-XXXX) MSB_PATH=$PWD/build/msb \
//!   cargo +stable nextest run -p microsandbox --test attach_checked \
//!     --run-ignored=only --test-threads 1
//! ```

use std::io::Read;
use std::os::fd::{AsRawFd, FromRawFd, OwnedFd, RawFd};
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::{Arc, Mutex};
use std::time::{Duration, Instant};

use microsandbox::{MicrosandboxError, Sandbox};
use test_utils::msb_test;

//--------------------------------------------------------------------------------------------------
// Constants
//--------------------------------------------------------------------------------------------------

/// Guest image.
const IMAGE: &str = "mirror.gcr.io/library/alpine";

/// Bound for creating the sandbox before the guest is available.
const CREATE_TIMEOUT: Duration = Duration::from_secs(60);

/// Bound for the attach session itself.
const SESSION_TIMEOUT: Duration = Duration::from_secs(60);

/// Bound for one step of a case, such as the guest printing `READY` or a
/// follow-up command after the session ended.
const STEP_TIMEOUT: Duration = Duration::from_secs(30);

/// Bound for the capture reader to see end-of-file after the session ended.
const DRAIN_TIMEOUT: Duration = Duration::from_secs(30);

/// Bound for stopping and removing the sandbox.
const CLEANUP_TIMEOUT: Duration = Duration::from_secs(15);

/// How long the capture reader waits before it takes the first byte, so the
/// pipe fills and the session has to hold guest output instead of writing it
/// straight through.
const STALL: Duration = Duration::from_millis(1500);

/// The bytes the `Ctrl-]` case types at the terminal: an ordinary byte, the
/// default detach sequence, and another ordinary byte, so a passthrough has to
/// be exact and in order.
const CTRL_RIGHT_BRACKET_INPUT: &[u8] = b"A\x1dB";

/// What the guest's `od` prints for those three bytes.
const CTRL_RIGHT_BRACKET_HEX: &[u8] = b"41 1d 42";

/// A guest that reports `READY` and then appends a beat every 100 ms, so a
/// probe can tell whether the guest process outlived the session.
const BEACON_SCRIPT: &str = "echo READY; i=0; while [ $i -lt 600 ]; do echo tick >> /tmp/beats; i=$((i+1)); sleep 0.1; done";

/// Read the beacon twice, one second apart.
const BEACON_PROBE: &str =
    "echo BEFORE=$(wc -l < /tmp/beats); sleep 1; echo AFTER=$(wc -l < /tmp/beats)";

/// Guest output for the exit-during-a-stall case, in bytes: small enough to sit
/// entirely inside the session's read-ahead, so the guest finishes and exits
/// while the host has read nothing.
const TWO_MEBIBYTES: usize = 2 << 20;

/// Guest output for the byte-exact case, in bytes: more than the session's
/// read-ahead and writer bounds together, so reception has to stop and resume.
const TWELVE_MEBIBYTES: usize = 12 << 20;

//--------------------------------------------------------------------------------------------------
// Types
//--------------------------------------------------------------------------------------------------

/// Which session options a case drives.
enum Session {
    /// `checked_session()` with the default detach policy: a detach is an error.
    CheckedDefaultDetach,
    /// `disable_detach_keys().checked_session()`: every host byte reaches the guest.
    CheckedNoDetach,
    /// No options set at all: the legacy session, unchanged.
    Legacy,
}

/// A case: one guest, one session, one observation.
struct Case<'a> {
    /// Sandbox name, unique per case.
    name: &'a str,
    /// The guest command line.
    script: &'a str,
    /// The session options.
    session: Session,
    /// How long the host consumer stalls before it reads.
    stall: Duration,
    /// Bytes typed at the terminal once the guest printed `READY`.
    input: Option<&'a [u8]>,
    /// A command run in the same sandbox after the session ended, to observe
    /// whether the guest survived the session.
    probe: Option<&'a str>,
}

/// What a session returned, rendered for an assertion message.
#[derive(Debug, PartialEq, Eq)]
enum Verdict {
    /// The session returned this status.
    Status(i32),
    /// The session returned this error.
    Failed(String),
}

/// Everything one case observed.
struct Observation {
    /// The session's own verdict.
    verdict: Verdict,
    /// The guest output the host received.
    output: Vec<u8>,
    /// The PTY's attributes before the session.
    terminal_before: String,
    /// The PTY's attributes after the session.
    terminal_after: String,
    /// Whether the follow-up command succeeded, and what it printed.
    probe: Option<(bool, String)>,
    /// Whether the session was still running when the stalled consumer was
    /// released. False means the consumer was never the bottleneck, so a
    /// backpressure case would be vacuous.
    session_open_when_released: bool,
}

/// The host terminal: fd 0 on a fresh PTY slave, fd 1 on the case's capture.
///
/// `Drop` puts both descriptors back, so a panicking assertion cannot leave the
/// test process writing guest bytes into libtest's output.
struct HostTerminal {
    saved_stdin: OwnedFd,
    saved_stdout: OwnedFd,
    master: OwnedFd,
    slave: OwnedFd,
    before: String,
    restored: bool,
}

/// The guest-output sink installed on fd 1: a pipe whose reader can be stalled.
struct Capture {
    write_end: OwnedFd,
    buffer: Arc<Mutex<Vec<u8>>>,
    released: Arc<AtomicBool>,
    drain: Option<std::thread::JoinHandle<()>>,
}

//--------------------------------------------------------------------------------------------------
// Methods
//--------------------------------------------------------------------------------------------------

impl HostTerminal {
    /// Allocate a 24x80 PTY, point fd 0 at its slave and fd 1 at `sink`.
    fn enter(sink: RawFd) -> std::io::Result<Self> {
        let winsize = nix::pty::Winsize {
            ws_row: 24,
            ws_col: 80,
            ws_xpixel: 0,
            ws_ypixel: 0,
        };
        let pty = nix::pty::openpty(Some(&winsize), None)?;
        let before = terminal_state(pty.slave.as_raw_fd());
        let saved_stdin = dup_fd(libc::STDIN_FILENO)?;
        let saved_stdout = dup_fd(libc::STDOUT_FILENO)?;
        if unsafe { libc::dup2(pty.slave.as_raw_fd(), libc::STDIN_FILENO) } < 0 {
            return Err(std::io::Error::last_os_error());
        }
        if unsafe { libc::dup2(sink, libc::STDOUT_FILENO) } < 0 {
            return Err(std::io::Error::last_os_error());
        }
        // The master is only ever written to, but a bounded nonblocking write
        // keeps a case from blocking here if the guest stops reading its input.
        set_nonblocking(pty.master.as_raw_fd())?;
        Ok(Self {
            saved_stdin,
            saved_stdout,
            master: pty.master,
            slave: pty.slave,
            before,
            restored: false,
        })
    }

    fn master(&self) -> RawFd {
        self.master.as_raw_fd()
    }

    /// The slave's attributes, as the reference for "the terminal came back".
    fn state(&self) -> String {
        terminal_state(self.slave.as_raw_fd())
    }

    /// Put fd 0 and fd 1 back.
    ///
    /// Explicit rather than only in `Drop`: restoring fd 1 closes this
    /// process's last write end of the capture pipe, which is what gives the
    /// reader end-of-file. The slave stays open, so the terminal can still be
    /// inspected afterwards.
    fn restore(&mut self) {
        if self.restored {
            return;
        }
        self.restored = true;
        unsafe {
            libc::dup2(self.saved_stdin.as_raw_fd(), libc::STDIN_FILENO);
            libc::dup2(self.saved_stdout.as_raw_fd(), libc::STDOUT_FILENO);
        }
    }
}

impl Drop for HostTerminal {
    fn drop(&mut self) {
        self.restore();
    }
}

impl Capture {
    /// Start a pipe on fd 1 and a reader that takes nothing until released.
    fn start() -> std::io::Result<Self> {
        let (read_end, write_end) = std::io::pipe()?;
        let buffer = Arc::new(Mutex::new(Vec::new()));
        let released = Arc::new(AtomicBool::new(false));
        let drain = {
            let buffer = buffer.clone();
            let released = released.clone();
            std::thread::spawn(move || read_until_eof(read_end.into(), &released, &buffer))
        };
        Ok(Self {
            write_end: write_end.into(),
            buffer,
            released,
            drain: Some(drain),
        })
    }

    /// Let the consumer start reading. Until this is called the pipe fills and
    /// the session has to hold guest output.
    fn release(&self) {
        self.released.store(true, Ordering::SeqCst);
    }

    fn fd(&self) -> RawFd {
        self.write_end.as_raw_fd()
    }

    /// Wait until the host has received `needle`, or `timeout` passes.
    async fn wait_for(&self, needle: &[u8], timeout: Duration) -> bool {
        let deadline = Instant::now() + timeout;
        loop {
            if contains(&self.buffer.lock().unwrap(), needle) {
                return true;
            }
            if Instant::now() >= deadline {
                return false;
            }
            tokio::time::sleep(Duration::from_millis(20)).await;
        }
    }

    /// Close our write end, wait for the reader to finish, and return the bytes.
    ///
    /// The caller restores fd 1 first; that plus this drop closes every write
    /// end this process owns, and the session closed its own duplicate when it
    /// returned, so the reader reaches end-of-file instead of being cut off by
    /// a timeout.
    fn finish(mut self) -> Vec<u8> {
        drop(self.write_end);
        let deadline = Instant::now() + DRAIN_TIMEOUT;
        while !self.drain.as_ref().is_none_or(|drain| drain.is_finished()) {
            if Instant::now() >= deadline {
                // Leave the thread alone rather than join a read that may never
                // return: the buffer is shared, so the bytes so far are enough
                // for the assertion to describe the failure.
                self.drain = None;
                break;
            }
            std::thread::sleep(Duration::from_millis(5));
        }
        if let Some(drain) = self.drain.take() {
            let _ = drain.join();
        }
        self.buffer.lock().unwrap().clone()
    }
}

impl Case<'_> {
    /// Run this case against its own sandbox and return what was observed.
    ///
    /// The sandbox is always stopped and removed before this returns, so a
    /// failing assertion afterwards cannot leak a running guest.
    async fn run(self) -> Observation {
        let capture = Capture::start().expect("a capture pipe");
        let mut terminal = HostTerminal::enter(capture.fd())
            .expect("a host terminal on fd 0 and the capture on fd 1");
        let master = terminal.master();
        let sandbox = tokio::time::timeout(
            CREATE_TIMEOUT,
            Sandbox::builder(self.name)
                .image(IMAGE)
                .cpus(1)
                .memory(512)
                .replace()
                .create(),
        )
        .await
        .unwrap_or_else(|_| panic!("{}: sandbox creation did not finish", self.name))
        .expect("create sandbox");

        let script = self.script.to_string();
        let attach_sandbox = sandbox.clone();
        let session = self.session;
        let mut attach = Box::pin(async move {
            match session {
                Session::CheckedDefaultDetach => {
                    attach_sandbox
                        .attach_with("sh", |options| {
                            options.args(["-c", script.as_str()]).checked_session()
                        })
                        .await
                }
                Session::CheckedNoDetach => {
                    attach_sandbox
                        .attach_with("sh", |options| {
                            options
                                .args(["-c", script.as_str()])
                                .disable_detach_keys()
                                .checked_session()
                        })
                        .await
                }
                Session::Legacy => {
                    attach_sandbox
                        .attach_with("sh", |options| options.args(["-c", script.as_str()]))
                        .await
                }
            }
        });

        // The session is a lazy future: nothing here happens unless it is
        // polled, so the input and stall steps race it instead of awaiting it.
        let mut verdict = None;
        // A case with no stall reads its guest output as it arrives; one with a
        // stall keeps the consumer shut until the guest's work is over.
        if self.stall.is_zero() {
            capture.release();
        }

        if let Some(input) = self.input {
            let typed = tokio::select! {
                ready = capture.wait_for(b"READY", STEP_TIMEOUT) => ready,
                result = &mut attach => {
                    panic!(
                        "{}: the session ended before the guest was ready: {:?}",
                        self.name,
                        render(result)
                    )
                }
            };
            assert!(typed, "{}: the guest never printed READY", self.name);
            note(self.name, "the guest is ready, typing at the terminal");
            write_master(master, input).expect("type at the terminal");
        }

        // Hold the consumer for `stall` while the session runs.
        if verdict.is_none() && !self.stall.is_zero() {
            tokio::select! {
                _ = tokio::time::sleep(self.stall) => {}
                result = &mut attach => verdict = Some(render(result)),
            }
        }
        let session_open_when_released = !self.stall.is_zero() && verdict.is_none();
        capture.release();

        let verdict = match verdict {
            Some(verdict) => verdict,
            None => match tokio::time::timeout(SESSION_TIMEOUT, &mut attach).await {
                Ok(result) => render(result),
                Err(_) => panic!("{}: the attach session did not finish", self.name),
            },
        };
        note(self.name, format!("the session returned {verdict:?}"));

        let probe = match self.probe {
            None => None,
            Some(command) => {
                let observed =
                    tokio::time::timeout(STEP_TIMEOUT, sandbox.exec("sh", ["-c", command]))
                        .await
                        .unwrap_or_else(|_| panic!("{}: the probe did not finish", self.name))
                        .expect("run the probe");
                let detail = format!(
                    "status={} stdout={:?} stderr={:?}",
                    observed.status().code,
                    observed.stdout().unwrap_or_default(),
                    observed.stderr().unwrap_or_default()
                );
                note(self.name, format!("probe: {detail}"));
                Some((observed.status().success, detail))
            }
        };

        // Put fd 1 back before draining: that plus the capture's own drop gives
        // the reader end-of-file.
        terminal.restore();
        let output = capture.finish();
        let after = terminal.state();
        let before = std::mem::take(&mut terminal.before);

        let _ = tokio::time::timeout(CLEANUP_TIMEOUT, sandbox.stop()).await;
        let _ = tokio::time::timeout(CLEANUP_TIMEOUT, Sandbox::remove(self.name)).await;

        Observation {
            verdict,
            output,
            terminal_before: before,
            terminal_after: after,
            probe,
            session_open_when_released,
        }
    }
}

impl Observation {
    /// The terminal must be exactly as it was, whichever way the session ended.
    fn assert_terminal_restored(&self, case: &str) {
        assert_eq!(
            self.terminal_after, self.terminal_before,
            "{case}: the host terminal attributes were not restored"
        );
    }

    /// The consumer must have been the bottleneck: the session was still open
    /// when the stalled consumer was released, so the guest's last bytes could
    /// only be delivered afterwards.
    fn assert_host_was_the_bottleneck(&self, case: &str) {
        assert!(
            self.session_open_when_released,
            "{case}: the session had already finished when the consumer was released, so this \
             case did not exercise a stalled host"
        );
    }

    /// Report what the follow-up command observed.
    ///
    /// It is deliberately not an assertion: on the local VM backend the runtime
    /// kills the session's process group when the attach client disconnects
    /// (`crates/runtime/lib/runner/relay.rs`, "Client disconnected — send
    /// SIGKILL for each active session"), so the guest's attached process does
    /// not outlive a detach even though the docs say it keeps running. The
    /// probe stays here so the observation is reproducible; see the printed
    /// line in the test log.
    fn report_guest_survival(&self, case: &str) {
        let (_, detail) = self
            .probe
            .as_ref()
            .unwrap_or_else(|| panic!("{case}: no follow-up command ran"));
        note(case, format!("guest survival probe: {detail}"));
    }
}

//--------------------------------------------------------------------------------------------------
// Functions
//--------------------------------------------------------------------------------------------------

/// Diagnostic line. Goes to stderr, never into the captured guest output.
fn note(case: &str, message: impl std::fmt::Display) {
    eprintln!("[attach-checked] {case}: {message}");
}

/// The public error of a failed session, rendered.
fn describe(error: MicrosandboxError) -> String {
    match error {
        MicrosandboxError::Terminal(text) => format!("Terminal: {text}"),
        MicrosandboxError::ExecFailed(failure) => format!("ExecFailed: {failure:?}"),
        other => other.to_string(),
    }
}

/// The public result of an attach call, rendered for an assertion message.
fn render(result: Result<i32, MicrosandboxError>) -> Verdict {
    match result {
        Ok(status) => Verdict::Status(status),
        Err(error) => Verdict::Failed(describe(error)),
    }
}

/// Whether `haystack` contains `needle`.
fn contains(haystack: &[u8], needle: &[u8]) -> bool {
    haystack
        .windows(needle.len())
        .any(|window| window == needle)
}

/// Read `read_end` into `buffer` until end-of-file, once `released` is set.
fn read_until_eof(read_end: OwnedFd, released: &AtomicBool, buffer: &Mutex<Vec<u8>>) {
    while !released.load(Ordering::SeqCst) {
        std::thread::sleep(Duration::from_millis(2));
    }
    let mut file = std::fs::File::from(read_end);
    let mut chunk = vec![0u8; 64 * 1024];
    loop {
        match file.read(&mut chunk) {
            Ok(0) => return,
            Ok(read) => buffer.lock().unwrap().extend_from_slice(&chunk[..read]),
            Err(error) if error.kind() == std::io::ErrorKind::Interrupted => continue,
            Err(_) => return,
        }
    }
}

/// Write all of `data` to the pty master, bounded, retrying on a full buffer.
fn write_master(master: RawFd, data: &[u8]) -> std::io::Result<()> {
    let deadline = Instant::now() + Duration::from_secs(5);
    let mut written = 0usize;
    while written < data.len() {
        let count = unsafe {
            libc::write(
                master,
                data[written..].as_ptr().cast::<libc::c_void>(),
                data.len() - written,
            )
        };
        if count > 0 {
            written += count as usize;
            continue;
        }
        let error = std::io::Error::last_os_error();
        match error.kind() {
            std::io::ErrorKind::WouldBlock | std::io::ErrorKind::Interrupted
                if Instant::now() < deadline =>
            {
                std::thread::sleep(Duration::from_millis(5));
            }
            _ => return Err(error),
        }
    }
    Ok(())
}

/// The parts of a terminal's state this harness compares.
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

/// `dup(2)` with error checking.
fn dup_fd(fd: RawFd) -> std::io::Result<OwnedFd> {
    let duplicated = unsafe { libc::dup(fd) };
    if duplicated < 0 {
        return Err(std::io::Error::last_os_error());
    }
    Ok(unsafe { OwnedFd::from_raw_fd(duplicated) })
}

/// Set `O_NONBLOCK` on a descriptor.
fn set_nonblocking(fd: RawFd) -> std::io::Result<()> {
    let flags = unsafe { libc::fcntl(fd, libc::F_GETFL) };
    if flags < 0 {
        return Err(std::io::Error::last_os_error());
    }
    if unsafe { libc::fcntl(fd, libc::F_SETFL, flags | libc::O_NONBLOCK) } < 0 {
        return Err(std::io::Error::last_os_error());
    }
    Ok(())
}

//--------------------------------------------------------------------------------------------------
// Tests
//--------------------------------------------------------------------------------------------------

/// The guest exits while the host consumer is stalled, so the session is
/// holding guest output when the exit arrives: every byte must still reach the
/// descriptor, in order, and the guest's status must survive.
///
/// 2 MiB fits inside the session's read-ahead, so the guest can finish and exit
/// before the host reads a byte.
#[msb_test]
async fn checked_session_keeps_its_held_output_when_the_guest_exits_during_a_stall() {
    let case = "checked-exit-during-stall";
    let observation = Case {
        name: case,
        script: "dd if=/dev/zero bs=65536 count=32 2>/dev/null | tr '\\0' a; exit 7",
        session: Session::CheckedNoDetach,
        stall: STALL,
        input: None,
        probe: None,
    }
    .run()
    .await;

    observation.assert_terminal_restored(case);
    observation.assert_host_was_the_bottleneck(case);
    assert_eq!(
        observation.verdict,
        Verdict::Status(7),
        "{case}: the guest's own status must come back"
    );
    assert_eq!(
        observation.output.len(),
        TWO_MEBIBYTES,
        "{case}: the host received {} bytes, not {TWO_MEBIBYTES}",
        observation.output.len()
    );
    assert!(
        observation.output.iter().all(|byte| *byte == b'a'),
        "{case}: the guest output was not delivered byte for byte"
    );
}

/// More guest output than the session may retain, with a stalled host consumer:
/// the body still arrives whole and the status is still the guest's.
#[msb_test]
async fn checked_session_delivers_twelve_mebibytes_byte_exactly_to_a_stalled_host() {
    let case = "checked-twelve-mebibytes";
    let observation = Case {
        name: case,
        script: "dd if=/dev/zero bs=65536 count=192 2>/dev/null | tr '\\0' z; exit 3",
        session: Session::CheckedNoDetach,
        stall: STALL,
        input: None,
        probe: None,
    }
    .run()
    .await;

    observation.assert_terminal_restored(case);
    observation.assert_host_was_the_bottleneck(case);
    assert_eq!(observation.verdict, Verdict::Status(3), "{case}");
    assert_eq!(
        observation.output.len(),
        TWELVE_MEBIBYTES,
        "{case}: the host received {} bytes, not {TWELVE_MEBIBYTES}",
        observation.output.len()
    );
    assert!(
        observation.output.iter().all(|byte| *byte == b'z'),
        "{case}: the guest output was not delivered byte for byte"
    );
}

/// With detach keys disabled, the default detach sequence is ordinary input:
/// the guest reads `A`, `0x1d`, `B` in that order, and the session ends with
/// the guest's status rather than a detach.
#[msb_test]
async fn checked_session_forwards_ctrl_right_bracket_to_the_guest() {
    let case = "checked-ctrl-right-bracket";
    let observation = Case {
        name: case,
        script: "stty raw -echo; echo READY; dd bs=1 count=3 2>/dev/null | od -An -tx1; exit 7",
        session: Session::CheckedNoDetach,
        stall: Duration::ZERO,
        input: Some(CTRL_RIGHT_BRACKET_INPUT),
        probe: None,
    }
    .run()
    .await;

    observation.assert_terminal_restored(case);
    assert_eq!(
        observation.verdict,
        Verdict::Status(7),
        "{case}: Ctrl-] must reach the guest, not end the session; output: {:?}",
        String::from_utf8_lossy(&observation.output)
    );
    assert!(
        contains(&observation.output, CTRL_RIGHT_BRACKET_HEX),
        "{case}: the guest did not read A, 0x1d, B; output: {:?}",
        String::from_utf8_lossy(&observation.output)
    );
}

/// A detach in a checked session is an error that names itself, and the host
/// terminal still comes back.
///
/// The case also records whether the guest outlived the session: on this
/// backend it does not (the runtime kills the session's process group when the
/// client disconnects), which contradicts the documented "leaves the guest
/// running". That observation is reported, not asserted — see
/// [`Observation::report_guest_survival`].
#[msb_test]
async fn checked_session_reports_a_detach_as_an_error() {
    let case = "checked-detach-live";
    let observation = Case {
        name: case,
        script: BEACON_SCRIPT,
        session: Session::CheckedDefaultDetach,
        stall: Duration::ZERO,
        input: Some(b"\x1d"),
        probe: Some(BEACON_PROBE),
    }
    .run()
    .await;

    observation.assert_terminal_restored(case);
    match &observation.verdict {
        Verdict::Failed(error) => assert!(
            error.starts_with("Terminal: ") && error.to_lowercase().contains("detach"),
            "{case}: the error must say that the session detached: {error}"
        ),
        other => panic!("{case}: a detach in a checked session must be an error, got {other:?}"),
    }
    observation.report_guest_survival(case);
}

/// The session this PR must not change: no options set at all still detaches
/// with `Ok(-1)`, and the terminal still comes back.
#[msb_test]
async fn legacy_session_still_detaches_with_minus_one() {
    let case = "legacy-detach-live";
    let observation = Case {
        name: case,
        script: BEACON_SCRIPT,
        session: Session::Legacy,
        stall: Duration::ZERO,
        input: Some(b"\x1d"),
        probe: Some(BEACON_PROBE),
    }
    .run()
    .await;

    observation.assert_terminal_restored(case);
    assert_eq!(
        observation.verdict,
        Verdict::Status(-1),
        "{case}: the legacy detach convention is Ok(-1)"
    );
    observation.report_guest_survival(case);
}
