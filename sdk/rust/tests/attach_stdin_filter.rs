#![cfg(unix)]

//! End-to-end candidate fixture for the attach `StdinFilter` liveness guarantee.
//!
//! A guest floods its terminal with 64 MiB. While that flood is still in
//! flight, the filter holds one key and performs real (repeated) guest
//! filesystem writes; the harness requires that at least 8 MiB of guest output
//! arrived after the filter entered its held phase and within an 8 s clock, that
//! a substantial amount of further output advanced during the guest write
//! itself, and that the write completed before the key was released.
//!
//! This fixture is a *candidate*, not proof on its own: the pty byte counter is
//! an indirect observation of the attach loop's `rx.recv()` calls, not a direct
//! `rx.recv()` instrument. It only discriminates if an intentionally
//! inline-awaiting mutation of the unix loop is observed to fail while this
//! fixture passes; note that such a mutant parks before `flood_started`, so it
//! fails earlier, waiting for `FLOOD_START`, rather than at these assertions.
//!
//! The fixture needs a working local VM backend (Linux KVM in CI; a working
//! microVM and the `mirror.gcr.io/library/alpine` image locally). Its whole
//! session budget is kept below nextest's 180 s `terminate-after`
//! (`.config/nextest.toml`) so its own timeout and diagnostics win the race.
//!
//! Run with (from the repository root):
//!
//! ```text
//! JUST_UNSTABLE=1 RUSTUP_TOOLCHAIN=stable just build-agentd
//! JUST_UNSTABLE=1 RUSTUP_TOOLCHAIN=stable just build
//! MSB_HOME=$(mktemp -d /tmp/msb-XXXX) MSB_PATH=$PWD/build/msb \
//!   cargo +stable nextest run -p microsandbox --test attach_stdin_filter \
//!     --run-ignored=only --test-threads 1
//! ```

use std::{
    future::Future,
    os::fd::{AsRawFd, FromRawFd, OwnedFd, RawFd},
    panic::AssertUnwindSafe,
    pin::Pin,
    sync::{
        Arc, Mutex,
        atomic::{AtomicBool, AtomicU64, Ordering},
    },
    time::{Duration, Instant},
};

use futures::FutureExt;
use microsandbox::{Sandbox, sandbox::StdinFilter};
use test_utils::msb_test;
use tokio::sync::oneshot;

//--------------------------------------------------------------------------------------------------
// Constants
//--------------------------------------------------------------------------------------------------

/// Sandbox name for this fixture.
const SANDBOX_NAME: &str = "attach-stdin-filter";

/// Guest image.
const IMAGE: &str = "mirror.gcr.io/library/alpine";

/// Bytes the guest floods to its terminal.
const FLOOD_TOTAL: usize = 64 << 20;

/// Bytes the filter writes into the guest before releasing the key.
const PAYLOAD_LEN: usize = 4 << 20;

/// Path of the filter's guest-side write.
const PAYLOAD_PATH: &str = "/tmp/filter-payload";

/// Go-file the driver creates so the guest may start flooding.
const GO_FILE: &str = "/tmp/flood-go";

/// Guest output that must arrive while the filter is held, past the post-hold
/// baseline (taken when the filter enters its held phase).
const POST_HOLD_THRESHOLD: u64 = 8 << 20;

/// Clock bound on the held phase, independent of the byte counter. Reaching it
/// before the threshold must fail the test, not silently end the hold.
const HOLD_BUDGET: Duration = Duration::from_secs(8);

/// Minimum real time the filter spends in guest round trips while held, so the
/// write window is long enough to measure rather than hiding behind one write.
const WRITE_ROUND_TRIP_WINDOW: Duration = Duration::from_secs(2);

/// Minimum guest output that must advance over `[write_started, write_result]`.
const WRITE_WINDOW_MIN_BYTES: u64 = 2 << 20;

/// Bound for the whole concurrent attach session. Kept well below nextest's
/// 180 s `terminate-after` so this fixture's own timeout and diagnostics win.
const SESSION_TIMEOUT: Duration = Duration::from_secs(120);

/// Bound for stopping and removing the sandbox.
const CLEANUP_TIMEOUT: Duration = Duration::from_secs(30);

/// Bound for each individual driver step.
const STEP_TIMEOUT: Duration = Duration::from_secs(45);

/// Bound for the remaining side once the other side has finished. Together with
/// `SESSION_TIMEOUT` this keeps the whole session under nextest's kill limit.
const SESSION_TAIL_TIMEOUT: Duration = Duration::from_secs(60);

/// Kept master-output tail, enough to hold the final `GOT:` line.
const TAIL_LIMIT: usize = 16 << 10;

/// Largest partial line buffered while looking for a marker.
const LINE_LIMIT: usize = 4 << 10;

//--------------------------------------------------------------------------------------------------
// Types
//--------------------------------------------------------------------------------------------------

/// State shared between the master-reader thread and the async session.
#[derive(Default)]
struct ReaderShared {
    /// Bounded tail of everything read from the master.
    tail: Mutex<Vec<u8>>,
    /// Bytes observed after the flood marker was recognized.
    post_marker: AtomicU64,
    /// The guest's READY line was recognized.
    ready_seen: AtomicBool,
    /// The guest's FLOOD_START line was recognized.
    marker_seen: AtomicBool,
    /// The driver observed the filter's "entered" signal.
    entered: AtomicBool,
    /// The guest flooded before the filter entered.
    premature_marker: AtomicBool,
    /// The reader should stop.
    stop: AtomicBool,
    /// The reader thread has exited.
    reader_exited: AtomicBool,
}

/// Everything the harness observed, asserted only after cleanup.
struct Observation {
    attach: Result<i32, String>,
    driver_error: Option<String>,
    ready_seen: bool,
    marker_seen: bool,
    premature_marker: bool,
    post_hold_delta: u64,
    threshold_observed_before_release: bool,
    write_window_delta: u64,
    write_result: Option<Result<(), String>>,
    seen_chunks: Vec<Vec<u8>>,
    tail: String,
}

/// Owns the host pty and restores fds 0 and 1 on drop, including on unwind.
struct PtyStdioGuard {
    saved_stdin: OwnedFd,
    saved_stdout: OwnedFd,
    master: OwnedFd,
}

/// Gate senders handed to the filter, so the test controls its policy.
struct FilterGates {
    entered: Option<oneshot::Sender<()>>,
    flood_started: Option<oneshot::Receiver<()>>,
    hold_started: Option<oneshot::Sender<()>>,
    write_started: Option<oneshot::Sender<()>>,
    release: Option<oneshot::Receiver<()>>,
    write_result: Option<oneshot::Sender<Result<(), String>>>,
    second_chunk: Option<oneshot::Sender<()>>,
}

/// Test-only filter: swallows `Ctrl+V`, waits for the guest to flood, performs a
/// real guest filesystem round trip while the flood is still in flight, then
/// holds until released and emits the replacement byte.
struct BridgeFilter {
    sandbox: Sandbox,
    gates: FilterGates,
    seen: Arc<Mutex<Vec<Vec<u8>>>>,
}

/// Driver-side channel ends and handles.
struct DriverContext {
    started: Instant,
    sandbox: Sandbox,
    master: RawFd,
    shared: Arc<ReaderShared>,
    ready_rx: oneshot::Receiver<()>,
    marker_rx: oneshot::Receiver<()>,
    entered_rx: oneshot::Receiver<()>,
    flood_started_tx: oneshot::Sender<()>,
    hold_started_rx: oneshot::Receiver<()>,
    write_started_rx: oneshot::Receiver<()>,
    release_tx: oneshot::Sender<()>,
    second_chunk_rx: oneshot::Receiver<()>,
    write_result_rx: oneshot::Receiver<Result<(), String>>,
}

/// Driver outcome, separate from the attach result.
#[derive(Debug)]
struct DriverOutcome {
    threshold_observed_before_release: bool,
    post_hold_delta: u64,
    write_window_delta: u64,
    write_result: Option<Result<(), String>>,
}

//--------------------------------------------------------------------------------------------------
// Methods
//--------------------------------------------------------------------------------------------------

impl PtyStdioGuard {
    /// Allocate a 24x80 pty and make its slave this process's stdin and stdout.
    fn enter() -> std::io::Result<Self> {
        let winsize = nix::pty::Winsize {
            ws_row: 24,
            ws_col: 80,
            ws_xpixel: 0,
            ws_ypixel: 0,
        };

        // `nix::pty::openpty` already handles the platform difference in
        // `libc::openpty`'s `winp` pointer constness (mut on darwin, const on
        // linux), so the same call lints cleanly on both targets.
        let pty = nix::pty::openpty(Some(&winsize), None)?;
        let master = pty.master;
        let slave = pty.slave;

        // Set O_NONBLOCK before touching the global descriptors: a failure here
        // must not leave stdin/stdout redirected onto the pty.
        set_nonblocking(master.as_raw_fd())?;

        let saved_stdin = dup_fd(libc::STDIN_FILENO)?;
        let saved_stdout = dup_fd(libc::STDOUT_FILENO)?;

        // Build the guard before any redirection so that a partial `dup2`
        // failure below is rolled back by `Drop` on the error return.
        let guard = Self {
            saved_stdin,
            saved_stdout,
            master,
        };

        if unsafe { libc::dup2(slave.as_raw_fd(), libc::STDIN_FILENO) } < 0 {
            return Err(std::io::Error::last_os_error());
        }
        if unsafe { libc::dup2(slave.as_raw_fd(), libc::STDOUT_FILENO) } < 0 {
            return Err(std::io::Error::last_os_error());
        }

        Ok(guard)
    }

    /// The pty master. Reading and writing it reaches the attached terminal.
    fn master_fd(&self) -> RawFd {
        self.master.as_raw_fd()
    }
}

impl Drop for PtyStdioGuard {
    fn drop(&mut self) {
        unsafe {
            libc::dup2(self.saved_stdin.as_raw_fd(), libc::STDIN_FILENO);
            libc::dup2(self.saved_stdout.as_raw_fd(), libc::STDOUT_FILENO);
        }
    }
}

//--------------------------------------------------------------------------------------------------
// Trait Implementations
//--------------------------------------------------------------------------------------------------

impl StdinFilter for BridgeFilter {
    fn filter<'a>(
        &'a mut self,
        data: &'a [u8],
    ) -> Pin<Box<dyn Future<Output = Vec<u8>> + Send + 'a>> {
        // The guard is released before the future is created.
        self.seen.lock().unwrap().push(data.to_vec());

        if data == b"\x16" {
            let entered = self.gates.entered.take();
            let flood_started = self.gates.flood_started.take();
            let hold_started = self.gates.hold_started.take();
            let write_started = self.gates.write_started.take();
            let release = self.gates.release.take();
            let write_result = self.gates.write_result.take();
            let sandbox = self.sandbox.clone();

            Box::pin(async move {
                if let Some(entered) = entered {
                    let _ = entered.send(());
                }
                // The guest may only start flooding after the filter entered.
                if let Some(flood_started) = flood_started {
                    let _ = flood_started.await;
                }
                // Enter the held phase. The driver snapshots the guest output
                // count on this signal, so only output produced from here on is
                // counted toward the post-hold threshold.
                if let Some(hold_started) = hold_started {
                    let _ = hold_started.send(());
                }

                // Signal the driver immediately before the first guest write so
                // it can measure the write window from here, not from earlier
                // output.
                if let Some(write_started) = write_started {
                    let _ = write_started.send(());
                }

                // Real guest round trips *while the guest is still flooding*:
                // the attach loop must keep draining guest output while these
                // writes are in flight, and `A` is emitted only after they
                // resolve. Repeating the 4 MiB write keeps the window long
                // enough to measure instead of hiding it behind one round trip.
                let write_deadline = tokio::time::Instant::now() + WRITE_ROUND_TRIP_WINDOW;
                let mut outcome: Result<(), String> = Ok(());
                loop {
                    match sandbox
                        .fs()
                        .write(PAYLOAD_PATH, vec![b'p'; PAYLOAD_LEN])
                        .await
                    {
                        Ok(()) => {}
                        Err(error) => {
                            outcome = Err(error.to_string());
                            break;
                        }
                    }
                    if tokio::time::Instant::now() >= write_deadline {
                        break;
                    }
                }
                if let Some(write_result) = write_result {
                    let _ = write_result.send(outcome);
                }

                // Stay held until the driver has observed the guest output
                // advance; only then is `A` forwarded to the guest.
                if let Some(release) = release {
                    let _ = release.await;
                }

                b"A".to_vec()
            })
        } else {
            let second_chunk = self.gates.second_chunk.take();
            let out = data.to_vec();
            Box::pin(async move {
                if let Some(second_chunk) = second_chunk {
                    let _ = second_chunk.send(());
                }
                out
            })
        }
    }
}

//--------------------------------------------------------------------------------------------------
// Functions
//--------------------------------------------------------------------------------------------------

/// The guest program. It announces READY, waits for the driver's go-file so it
/// cannot start flooding before the filter entered, floods its terminal, then
/// reads one line and reports what it read plus the filter's written size.
fn guest_script() -> String {
    format!(
        "echo READY; while [ ! -e {GO_FILE} ]; do sleep 0.1; done; \
         echo FLOOD_START; yes flood | head -c {FLOOD_TOTAL}; \
         IFS= read -r line; echo \"GOT:$line:$(wc -c < {PAYLOAD_PATH})\""
    )
}

/// The guest's final line: the filter's `A` reached the guest before the
/// driver's queued `hi\r`, and the filter's write landed.
fn expected_marker() -> String {
    format!("GOT:Ahi:{PAYLOAD_LEN}")
}

/// Run the concurrent attach session and its driver under one future.
async fn run_session(
    sandbox: &Sandbox,
    master: RawFd,
    shared: &Arc<ReaderShared>,
    ready_rx: oneshot::Receiver<()>,
    marker_rx: oneshot::Receiver<()>,
) -> Observation {
    let (entered_tx, entered_rx) = oneshot::channel();
    let (flood_started_tx, flood_started_rx) = oneshot::channel();
    let (hold_started_tx, hold_started_rx) = oneshot::channel();
    let (write_started_tx, write_started_rx) = oneshot::channel();
    let (release_tx, release_rx) = oneshot::channel();
    let (second_chunk_tx, second_chunk_rx) = oneshot::channel();
    let (write_result_tx, write_result_rx) = oneshot::channel();

    let seen = Arc::new(Mutex::new(Vec::new()));
    let filter = BridgeFilter {
        sandbox: sandbox.clone(),
        gates: FilterGates {
            entered: Some(entered_tx),
            flood_started: Some(flood_started_rx),
            hold_started: Some(hold_started_tx),
            write_started: Some(write_started_tx),
            release: Some(release_rx),
            write_result: Some(write_result_tx),
            second_chunk: Some(second_chunk_tx),
        },
        seen: seen.clone(),
    };

    let script = guest_script();
    let attach_sandbox = sandbox.clone();
    let attach = async move {
        attach_sandbox
            .attach_with("sh", |options| {
                options.args(["-c", script.as_str()]).stdin_filter(filter)
            })
            .await
            .map_err(|error| error.to_string())
    };

    let started = Instant::now();
    let driver = drive(DriverContext {
        started,
        sandbox: sandbox.clone(),
        master,
        shared: shared.clone(),
        ready_rx,
        marker_rx,
        entered_rx,
        flood_started_tx,
        hold_started_rx,
        write_started_rx,
        release_tx,
        second_chunk_rx,
        write_result_rx,
    });

    // Poll both sides concurrently, but never keep waiting for one after the
    // other has failed: a failed driver leaves the guest in its go-file loop
    // forever, so the session must end on the driver's error instead of
    // hanging until the harness timeout.
    let mut attach = Box::pin(attach);
    let mut driver = Box::pin(driver);

    let progress_shared = shared.clone();
    let progress_started = started;
    let progress = tokio::spawn(async move {
        loop {
            tokio::time::sleep(Duration::from_secs(5)).await;
            note(format!(
                "{:?}: progress post_marker={} reader_exited={}",
                progress_started.elapsed(),
                post_marker(&progress_shared),
                progress_shared.reader_exited.load(Ordering::SeqCst),
            ));
        }
    });

    let (attach_result, driver_result) = tokio::select! {
        result = &mut attach => {
            note(format!(
                "{:?}: attach session ended on its own: {result:?}",
                started.elapsed()
            ));
            let driver_result = match tokio::time::timeout(SESSION_TAIL_TIMEOUT, &mut driver).await {
                Ok(result) => result,
                Err(_) => Err("driver did not finish after the attach session ended".to_string()),
            };
            (result, driver_result)
        }
        result = &mut driver => {
            note(format!("{:?}: driver finished first: {result:?}", started.elapsed()));
            let attach_result = match &result {
                Ok(_) => {
                    match tokio::time::timeout(SESSION_TAIL_TIMEOUT, &mut attach).await {
                        Ok(result) => result,
                        Err(_) => Err(
                            "attach session did not finish after the filter was released".to_string(),
                        ),
                    }
                }
                Err(_) => Err("attach session abandoned after a driver failure".to_string()),
            };
            (attach_result, result)
        }
    };

    progress.abort();
    let _ = progress.await;
    note(format!(
        "{:?}: session end: post_marker={} reader_exited={}",
        started.elapsed(),
        post_marker(shared),
        shared.reader_exited.load(Ordering::SeqCst),
    ));

    let seen_chunks = seen.lock().unwrap().clone();
    let tail = String::from_utf8_lossy(&shared.tail.lock().unwrap()).into_owned();

    let (
        driver_error,
        threshold_observed_before_release,
        post_hold_delta,
        write_window_delta,
        write_result,
    ) = match driver_result {
        Ok(outcome) => (
            None,
            outcome.threshold_observed_before_release,
            outcome.post_hold_delta,
            outcome.write_window_delta,
            outcome.write_result,
        ),
        Err(error) => (Some(error), false, 0, 0, None),
    };

    Observation {
        attach: attach_result,
        driver_error,
        ready_seen: shared.ready_seen.load(Ordering::SeqCst),
        marker_seen: shared.marker_seen.load(Ordering::SeqCst),
        premature_marker: shared.premature_marker.load(Ordering::SeqCst),
        post_hold_delta,
        threshold_observed_before_release,
        write_window_delta,
        write_result,
        seen_chunks,
        tail,
    }
}

/// Waits for READY, sends one `Ctrl+V`, releases the guest gate only after the
/// filter entered, and requires flood progress while the filter is held.
async fn drive(context: DriverContext) -> Result<DriverOutcome, String> {
    let DriverContext {
        started,
        sandbox,
        master,
        shared,
        ready_rx,
        marker_rx,
        entered_rx,
        flood_started_tx,
        hold_started_rx,
        write_started_rx,
        release_tx,
        second_chunk_rx,
        write_result_rx,
    } = context;

    step("READY", STEP_TIMEOUT, ready_rx)
        .await
        .map_err(|error| format!("waiting for the guest's READY marker: {error}"))?;
    note(format!("{:?}: guest READY", started.elapsed()));

    write_master(master, b"\x16").map_err(|error| format!("sending Ctrl+V: {error}"))?;

    step("filter entered", STEP_TIMEOUT, entered_rx)
        .await
        .map_err(|error| format!("waiting for the filter to enter: {error}"))?;
    shared.entered.store(true, Ordering::SeqCst);
    note(format!("{:?}: filter entered", started.elapsed()));

    // The guest may start flooding now that the filter has entered.
    sandbox
        .fs()
        .write(GO_FILE, b"go")
        .await
        .map_err(|error| format!("creating {GO_FILE}: {error}"))?;
    note(format!("{:?}: {GO_FILE} created", started.elapsed()));

    step("FLOOD_START", STEP_TIMEOUT, marker_rx)
        .await
        .map_err(|error| format!("waiting for the guest's flood marker: {error}"))?;
    note(format!("{:?}: guest FLOOD_START", started.elapsed()));

    // The guest is already flooding; this only unblocks the filter's held phase.
    let _ = flood_started_tx.send(());

    step("held phase", STEP_TIMEOUT, hold_started_rx)
        .await
        .map_err(|error| format!("waiting for the filter's held phase: {error}"))?;
    note(format!(
        "{:?}: filter held phase started",
        started.elapsed()
    ));

    // Every byte counted toward the threshold or the write window must arrive
    // after this snapshot: output produced before the filter entered its held
    // phase does not count as progress.
    let baseline = post_marker(&shared);

    // The held phase is bounded by a fixed clock, independent of the counter.
    // Reaching it without the threshold ends the hold and fails the test (the
    // assertion below), rather than waiting for the counter to stop.
    let hold_deadline = tokio::time::Instant::now() + HOLD_BUDGET;

    // The driver's second chunk must be written while the filter still holds
    // the first one, so it queues behind it and cannot overtake it.
    write_master(master, b"hi\r").map_err(|error| format!("sending the line: {error}"))?;

    // The guest filesystem round trip must complete while the guest is still
    // flooding and the attach loop is still draining output. Any output in the
    // measured window is an *indirect* pty observation that draining overlapped
    // the guest operation; the byte floor asserted by the test refuses to treat
    // a token increment as progress. The window is exactly
    // [write_started, write_result], measured from the signal the filter sends
    // immediately before its first guest write.
    step_until("filter write started", hold_deadline, write_started_rx)
        .await
        .map_err(|error| format!("waiting for the filter's guest write to start: {error}"))?;
    let write_start = post_marker(&shared);

    let write_result = step_until("filter write result", hold_deadline, write_result_rx)
        .await
        .map_err(|error| format!("waiting for the filter's guest write: {error}"))?;
    let write_window_delta = post_marker(&shared).saturating_sub(write_start);
    note(format!(
        "{:?}: guest write finished: {write_result:?} (write-window delta {write_window_delta})",
        started.elapsed()
    ));

    // Hold release until the guest output has advanced past the threshold: the
    // filter is parked on `release` here, so the attach loop is free to drain.
    let mut threshold_observed_before_release = false;
    while tokio::time::Instant::now() < hold_deadline {
        if post_marker(&shared).saturating_sub(baseline) >= POST_HOLD_THRESHOLD {
            threshold_observed_before_release = true;
            break;
        }
        tokio::time::sleep(Duration::from_millis(20)).await;
    }
    let post_hold_delta = post_marker(&shared).saturating_sub(baseline);
    note(format!(
        "{:?}: threshold observed before release: {threshold_observed_before_release} (delta {post_hold_delta})",
        started.elapsed()
    ));

    let _ = release_tx.send(());

    let _ = step("second filtered chunk", STEP_TIMEOUT, second_chunk_rx).await;
    note(format!(
        "{:?}: driver done: {write_result:?}",
        started.elapsed()
    ));

    Ok(DriverOutcome {
        threshold_observed_before_release,
        post_hold_delta,
        write_window_delta,
        write_result: Some(write_result),
    })
}

/// Await one driver step with its own timeout.
async fn step<T>(name: &str, limit: Duration, receiver: oneshot::Receiver<T>) -> Result<T, String> {
    match tokio::time::timeout(limit, receiver).await {
        Ok(Ok(value)) => Ok(value),
        Ok(Err(_)) => Err(format!("{name}: sender dropped")),
        Err(_) => Err(format!("{name}: timed out after {limit:?}")),
    }
}

/// Await one driver step, failing at an absolute deadline rather than a fixed
/// per-step limit. Used to bound the held phase by the hold budget.
async fn step_until<T>(
    name: &str,
    deadline: tokio::time::Instant,
    receiver: oneshot::Receiver<T>,
) -> Result<T, String> {
    match tokio::time::timeout_at(deadline, receiver).await {
        Ok(Ok(value)) => Ok(value),
        Ok(Err(_)) => Err(format!("{name}: sender dropped")),
        Err(_) => Err(format!("{name}: timed out at the hold deadline")),
    }
}

/// Byte count observed after the flood marker.
fn post_marker(shared: &Arc<ReaderShared>) -> u64 {
    shared.post_marker.load(Ordering::SeqCst)
}

/// Diagnostic line for this ignored fixture. Goes to stderr, never to the
/// attached pty that the fixture is observing.
fn note(message: impl std::fmt::Display) {
    eprintln!("[attach-stdin-filter] {message}");
}

/// Printable summary of the marker state and the master tail, for failures
/// that happen after the session future was dropped.
fn summarize(shared: &Arc<ReaderShared>) -> String {
    let tail = shared.tail.lock().unwrap().clone();
    let start = tail.len().saturating_sub(400);
    let excerpt: String = String::from_utf8_lossy(&tail[start..])
        .chars()
        .map(|character| {
            if character.is_control() && character != '\n' {
                '.'
            } else {
                character
            }
        })
        .collect::<String>()
        .replace('\n', "\\n");

    format!(
        "ready_seen={} marker_seen={} premature_marker={} post_marker={} tail={excerpt:?}",
        shared.ready_seen.load(Ordering::SeqCst),
        shared.marker_seen.load(Ordering::SeqCst),
        shared.premature_marker.load(Ordering::SeqCst),
        shared.post_marker.load(Ordering::SeqCst),
    )
}

/// Stop the sandbox and remove it, reporting rather than masking failures.
async fn cleanup(name: &str, sandbox: &Sandbox) -> Vec<String> {
    let mut errors = Vec::new();

    match tokio::time::timeout(CLEANUP_TIMEOUT, sandbox.stop()).await {
        Ok(Ok(())) => {}
        Ok(Err(error)) => errors.push(format!("stop: {error}")),
        Err(_) => errors.push("stop timed out".to_string()),
    }

    match tokio::time::timeout(CLEANUP_TIMEOUT, Sandbox::remove(name)).await {
        Ok(Ok(())) => {}
        Ok(Err(error)) => errors.push(format!("remove: {error}")),
        Err(_) => errors.push("remove timed out".to_string()),
    }

    errors
}

/// Drain the pty master on its own thread, recognizing the guest's markers.
fn start_reader(
    master: RawFd,
    shared: Arc<ReaderShared>,
    ready_tx: oneshot::Sender<()>,
    marker_tx: oneshot::Sender<()>,
) -> std::thread::JoinHandle<()> {
    std::thread::spawn(move || read_master(master, shared, ready_tx, marker_tx))
}

/// Incremental marker parser and post-marker byte counter.
///
/// Nothing is counted as flood progress before `FLOOD_START` is recognized;
/// bytes after its newline, including later bytes of the same read, are.
fn read_master(
    master: RawFd,
    shared: Arc<ReaderShared>,
    ready_tx: oneshot::Sender<()>,
    marker_tx: oneshot::Sender<()>,
) {
    struct ExitFlag(Arc<ReaderShared>);

    impl Drop for ExitFlag {
        fn drop(&mut self) {
            self.0.reader_exited.store(true, Ordering::SeqCst);
        }
    }

    let _exit_flag = ExitFlag(shared.clone());
    let mut ready_tx = Some(ready_tx);
    let mut marker_tx = Some(marker_tx);
    let mut line = Vec::new();
    // 0: waiting for READY, 1: waiting for FLOOD_START, 2: counting.
    let mut stage = 0u8;
    let mut buffer = vec![0u8; 8192];

    while !shared.stop.load(Ordering::SeqCst) {
        let mut pollfd = libc::pollfd {
            fd: master,
            events: libc::POLLIN,
            revents: 0,
        };
        let ready = unsafe { libc::poll(&mut pollfd, 1, 50) };
        if ready < 0 {
            if std::io::Error::last_os_error().kind() == std::io::ErrorKind::Interrupted {
                continue;
            }
            break;
        }
        if ready == 0 {
            continue;
        }

        let read = unsafe {
            libc::read(
                master,
                buffer.as_mut_ptr().cast::<libc::c_void>(),
                buffer.len(),
            )
        };
        if read < 0 {
            let error = std::io::Error::last_os_error();
            match error.kind() {
                std::io::ErrorKind::WouldBlock | std::io::ErrorKind::Interrupted => continue,
                _ => break,
            }
        }
        if read == 0 {
            break;
        }

        let data = &buffer[..read as usize];
        {
            let mut tail = shared.tail.lock().unwrap();
            tail.extend_from_slice(data);
            if tail.len() > TAIL_LIMIT {
                let excess = tail.len() - TAIL_LIMIT;
                tail.drain(..excess);
            }
        }

        let mut index = 0usize;
        while index < data.len() {
            if stage == 2 {
                shared
                    .post_marker
                    .fetch_add((data.len() - index) as u64, Ordering::SeqCst);
                break;
            }

            match data[index..].iter().position(|byte| *byte == b'\n') {
                Some(offset) => {
                    let end = index + offset + 1;
                    line.extend_from_slice(&data[index..end]);
                    index = end;

                    let matched = match stage {
                        0 => trim_cr(&line) == b"READY",
                        1 => trim_cr(&line) == b"FLOOD_START",
                        _ => false,
                    };
                    line.clear();

                    if matched && stage == 0 {
                        shared.ready_seen.store(true, Ordering::SeqCst);
                        if let Some(sender) = ready_tx.take() {
                            let _ = sender.send(());
                        }
                        stage = 1;
                    } else if matched && stage == 1 {
                        if !shared.entered.load(Ordering::SeqCst) {
                            shared.premature_marker.store(true, Ordering::SeqCst);
                        }
                        shared.marker_seen.store(true, Ordering::SeqCst);
                        if let Some(sender) = marker_tx.take() {
                            let _ = sender.send(());
                        }
                        stage = 2;
                    }
                }
                None => {
                    line.extend_from_slice(&data[index..]);
                    index = data.len();
                    if line.len() > LINE_LIMIT {
                        line.clear();
                    }
                }
            }
        }
    }
}

/// A marker line without its CRLF or LF.
fn trim_cr(line: &[u8]) -> &[u8] {
    let mut end = line.len();
    while end > 0 && (line[end - 1] == b'\n' || line[end - 1] == b'\r') {
        end -= 1;
    }
    &line[..end]
}

/// Write all of `data` to the pty master, bounded, tolerating a full input
/// queue instead of blocking the run loop forever.
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
            std::io::ErrorKind::WouldBlock | std::io::ErrorKind::Interrupted => {
                if Instant::now() >= deadline {
                    return Err(error);
                }
                std::thread::sleep(Duration::from_millis(5));
            }
            _ => return Err(error),
        }
    }

    Ok(())
}

/// `dup(2)` with error checking.
fn dup_fd(fd: RawFd) -> std::io::Result<OwnedFd> {
    let duplicated = unsafe { libc::dup(fd) };
    if duplicated < 0 {
        return Err(std::io::Error::last_os_error());
    }
    // Safe: dup returned a fresh descriptor.
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

#[msb_test]
async fn attach_filter_awaiting_guest_does_not_stall_output() {
    let guard = PtyStdioGuard::enter().expect("create the host pty for the attach fixture");

    let sandbox = Sandbox::builder(SANDBOX_NAME)
        .image(IMAGE)
        .cpus(1)
        .memory(512)
        .replace()
        .create()
        .await
        .expect("create sandbox");

    let master = guard.master_fd();
    let shared = Arc::new(ReaderShared::default());
    let (ready_tx, ready_rx) = oneshot::channel();
    let (marker_tx, marker_rx) = oneshot::channel();
    let reader = start_reader(master, shared.clone(), ready_tx, marker_tx);

    // Poll the attach session and the driver concurrently; the session timeout
    // bounds both. Unexpected assertion panics are held until after cleanup.
    let observed = AssertUnwindSafe(tokio::time::timeout(
        SESSION_TIMEOUT,
        run_session(&sandbox, master, &shared, ready_rx, marker_rx),
    ))
    .catch_unwind()
    .await;

    // The reader must never outlive the fixture: stop it, then join it off the
    // run loop so a blocked poll cannot hang the runtime.
    shared.stop.store(true, Ordering::SeqCst);
    let _ = tokio::task::spawn_blocking(move || reader.join()).await;

    drop(guard);

    let cleanup_errors = cleanup(SANDBOX_NAME, &sandbox).await;
    if !cleanup_errors.is_empty() {
        eprintln!("attach fixture cleanup errors: {cleanup_errors:?}");
    }

    let observation = match observed {
        Ok(Ok(observation)) => observation,
        Ok(Err(_elapsed)) => panic!(
            "attach session did not finish within {SESSION_TIMEOUT:?}; {}\ncleanup errors: {cleanup_errors:?}",
            summarize(&shared)
        ),
        Err(payload) => std::panic::resume_unwind(payload),
    };

    if let Some(error) = &observation.driver_error {
        panic!("driver failed: {error}; cleanup errors: {cleanup_errors:?}");
    }

    assert!(
        !observation.premature_marker,
        "the guest flooded before the filter entered"
    );
    assert!(observation.ready_seen, "the guest never printed READY");
    assert!(
        observation.marker_seen,
        "the guest never printed FLOOD_START; tail: {}",
        observation.tail
    );
    assert!(
        observation.threshold_observed_before_release,
        "only {} bytes of guest output arrived after the filter entered its held phase \
         and before the {HOLD_BUDGET:?} hold budget expired (needed \
         {POST_HOLD_THRESHOLD}); the attach loop did not keep draining while the \
         filter was held",
        observation.post_hold_delta
    );
    assert!(
        observation.write_window_delta >= WRITE_WINDOW_MIN_BYTES,
        "only {} bytes of guest output advanced over [write_started, write_result] \
         (needed {WRITE_WINDOW_MIN_BYTES}); the attach loop did not keep draining \
         through the filter's guest round trip (indirect pty observation, not a \
         direct `rx.recv()` instrument)",
        observation.write_window_delta
    );
    assert_eq!(
        observation.write_result,
        Some(Ok(())),
        "the filter's guest write did not succeed"
    );
    assert_eq!(
        observation.attach,
        Ok(0),
        "attach session did not exit cleanly; tail: {}",
        observation.tail
    );
    assert!(
        observation.tail.contains(&expected_marker()),
        "guest output did not confirm the ordering; tail: {}",
        observation.tail
    );
    assert_eq!(
        observation.seen_chunks,
        vec![vec![0x16u8], b"hi\r".to_vec()],
        "the filter did not see exactly the two expected chunks in order"
    );
}
