#![cfg(unix)]

//! Regression fixture for issue #53: an interactive attach session that has
//! already produced a terminal output burst must still deliver its trailing
//! output and return the guest's exit code.
//!
//! The burst is `yes flood | head -c N`, which only terminates if `yes` dies
//! from SIGPIPE once `head` exits. PTY sessions used to inherit agentd's
//! ignored SIGPIPE, so the pipeline never finished and the session hung.
//!
//! Needs a working local VM backend. Run with (from the repository root):
//!
//! ```text
//! MSB_PATH=$PWD/build/msb cargo nextest run -p microsandbox --test attach_burst \
//!   --run-ignored=only --test-threads 1
//! ```

use std::{
    os::fd::{AsRawFd, FromRawFd, OwnedFd, RawFd},
    sync::{
        Arc, Mutex,
        atomic::{AtomicBool, AtomicU64, Ordering},
    },
    time::{Duration, Instant},
};

use microsandbox::Sandbox;
use test_utils::msb_test;

//--------------------------------------------------------------------------------------------------
// Constants
//--------------------------------------------------------------------------------------------------

/// Guest image.
const IMAGE: &str = "mirror.gcr.io/library/alpine";

/// Bound for creating the sandbox before the guest is available.
///
/// Together with the other bounds this keeps the fixture's worst-case runtime
/// under nextest's 180 s `terminate-after`, so a slow boot fails here with a
/// named message instead of being killed by the harness.
const CREATE_TIMEOUT: Duration = Duration::from_secs(60);

/// Bound for the attach session after the input line was sent.
const SESSION_TIMEOUT: Duration = Duration::from_secs(20);

/// Bound for waiting on the guest's READY line and the burst.
const STEP_TIMEOUT: Duration = Duration::from_secs(30);

/// Bound for the reader to observe the trailing marker after attach returns.
const MARKER_TIMEOUT: Duration = Duration::from_secs(2);

/// Bound for stopping and removing the sandbox.
const CLEANUP_TIMEOUT: Duration = Duration::from_secs(15);

/// Kept master-output tail.
const TAIL_LIMIT: usize = 16 << 10;

//--------------------------------------------------------------------------------------------------
// Types
//--------------------------------------------------------------------------------------------------

/// State shared between the master-reader thread and the async session.
#[derive(Default)]
struct ReaderShared {
    /// Bounded tail of everything read from the master.
    tail: Mutex<Vec<u8>>,
    /// Total bytes read from the master.
    total: AtomicU64,
    /// The reader should stop.
    stop: AtomicBool,
}

/// Owns the host pty and restores fds 0 and 1 on drop, including on unwind.
struct PtyStdioGuard {
    saved_stdin: OwnedFd,
    saved_stdout: OwnedFd,
    master: OwnedFd,
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
        let pty = nix::pty::openpty(Some(&winsize), None)?;
        set_nonblocking(pty.master.as_raw_fd())?;

        let guard = Self {
            saved_stdin: dup_fd(libc::STDIN_FILENO)?,
            saved_stdout: dup_fd(libc::STDOUT_FILENO)?,
            master: pty.master,
        };
        if unsafe { libc::dup2(pty.slave.as_raw_fd(), libc::STDIN_FILENO) } < 0 {
            return Err(std::io::Error::last_os_error());
        }
        if unsafe { libc::dup2(pty.slave.as_raw_fd(), libc::STDOUT_FILENO) } < 0 {
            return Err(std::io::Error::last_os_error());
        }
        Ok(guard)
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
// Functions
//--------------------------------------------------------------------------------------------------

/// Attach, let the guest burst `burst` bytes, send one line, and require the
/// guest's `GOT:<line>` report plus a clean exit.
async fn run_burst_case(name: &str, burst: usize) {
    let guard = PtyStdioGuard::enter().expect("create the host pty");
    let sandbox = tokio::time::timeout(
        CREATE_TIMEOUT,
        Sandbox::builder(name)
            .image(IMAGE)
            .cpus(1)
            .memory(512)
            .replace()
            .create(),
    )
    .await
    .unwrap_or_else(|_| panic!("sandbox creation did not finish within {CREATE_TIMEOUT:?}"))
    .expect("create sandbox");

    let master = guard.master.as_raw_fd();
    let shared = Arc::new(ReaderShared::default());
    let reader = {
        let shared = shared.clone();
        std::thread::spawn(move || read_master(master, &shared))
    };

    let script = if burst == 0 {
        "echo READY; IFS= read -r line; echo \"GOT:$line\"".to_string()
    } else {
        format!("echo READY; yes flood | head -c {burst}; IFS= read -r line; echo \"GOT:$line\"")
    };
    let attach_sandbox = sandbox.clone();
    let mut attach = Box::pin(async move {
        attach_sandbox
            .attach_with("sh", |options| options.args(["-c", script.as_str()]))
            .await
            .map_err(|error| error.to_string())
    });

    let started = Instant::now();
    let driver = async {
        // Wait until `READY\r\n` and the whole burst reached the host. The
        // pty expands each `flood\n` (6 bytes) into `flood\r\n` (7 bytes).
        let expected = 7 + burst as u64 * 7 / 6;
        let deadline = Instant::now() + STEP_TIMEOUT;
        while shared.total.load(Ordering::SeqCst) < expected {
            if Instant::now() >= deadline {
                return Err(format!(
                    "burst did not arrive: total={}",
                    shared.total.load(Ordering::SeqCst)
                ));
            }
            tokio::time::sleep(Duration::from_millis(20)).await;
        }
        note(format!(
            "{:?}: burst received total={}",
            started.elapsed(),
            shared.total.load(Ordering::SeqCst)
        ));
        tokio::time::sleep(Duration::from_millis(500)).await;
        write_master(master, b"hi\r").map_err(|error| format!("sending the line: {error}"))?;
        note(format!("{:?}: line sent", started.elapsed()));
        Ok(())
    };

    let outcome: Result<i32, String> = tokio::select! {
        result = &mut attach => Err(format!("attach ended before the line was sent: {result:?}")),
        result = driver => match result {
            Err(error) => Err(error),
            Ok(()) => match tokio::time::timeout(SESSION_TIMEOUT, &mut attach).await {
                Ok(result) => result,
                Err(_) => Err(format!("attach session did not finish within {SESSION_TIMEOUT:?}")),
            },
        },
    };
    note(format!(
        "{:?}: outcome {outcome:?} total={}",
        started.elapsed(),
        shared.total.load(Ordering::SeqCst)
    ));

    // A successful attach can return before the reader thread has drained the
    // guest's trailing output from the pty. Give it a short bounded window to
    // see the marker before stopping the reader.
    if outcome.is_ok() {
        let deadline = Instant::now() + MARKER_TIMEOUT;
        loop {
            let seen = {
                let tail = shared.tail.lock().unwrap();
                String::from_utf8_lossy(&tail).contains("GOT:hi")
            };
            if seen || Instant::now() >= deadline {
                break;
            }
            tokio::time::sleep(Duration::from_millis(20)).await;
        }
    }

    shared.stop.store(true, Ordering::SeqCst);
    let _ = tokio::task::spawn_blocking(move || reader.join()).await;
    drop(guard);

    let _ = tokio::time::timeout(CLEANUP_TIMEOUT, sandbox.stop()).await;
    let _ = tokio::time::timeout(CLEANUP_TIMEOUT, Sandbox::remove(name)).await;

    let raw_tail = shared.tail.lock().unwrap();
    let tail = String::from_utf8_lossy(&raw_tail).into_owned();
    let excerpt_start = raw_tail.len().saturating_sub(200);
    let excerpt = String::from_utf8_lossy(&raw_tail[excerpt_start..]).into_owned();
    drop(raw_tail);
    assert_eq!(
        outcome,
        Ok(0),
        "attach did not exit cleanly; tail: {excerpt:?}"
    );
    assert!(
        tail.contains("GOT:hi"),
        "guest never echoed the line; tail: {excerpt:?}"
    );
}

/// Diagnostic line. Goes to stderr, never to the attached pty.
fn note(message: impl std::fmt::Display) {
    eprintln!("[attach-burst] {message}");
}

/// Drain the pty master on its own thread.
fn read_master(master: RawFd, shared: &Arc<ReaderShared>) {
    let mut buffer = vec![0u8; 8192];
    while !shared.stop.load(Ordering::SeqCst) {
        let mut pollfd = libc::pollfd {
            fd: master,
            events: libc::POLLIN,
            revents: 0,
        };
        let ready = unsafe { libc::poll(&mut pollfd, 1, 50) };
        if ready <= 0 {
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
            match std::io::Error::last_os_error().kind() {
                std::io::ErrorKind::WouldBlock | std::io::ErrorKind::Interrupted => continue,
                _ => break,
            }
        }
        if read == 0 {
            break;
        }
        let data = &buffer[..read as usize];
        shared.total.fetch_add(data.len() as u64, Ordering::SeqCst);
        let mut tail = shared.tail.lock().unwrap();
        tail.extend_from_slice(data);
        if tail.len() > TAIL_LIMIT {
            let excess = tail.len() - TAIL_LIMIT;
            tail.drain(..excess);
        }
    }
}

/// Write all of `data` to the pty master, bounded.
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

#[msb_test]
async fn attach_round_trip_without_burst() {
    run_burst_case("attach-burst-none", 0).await;
}

#[msb_test]
async fn attach_round_trip_after_burst() {
    run_burst_case("attach-burst-100k", 100_000).await;
}

#[msb_test]
async fn attach_round_trip_after_large_burst() {
    run_burst_case("attach-burst-2m", 2 << 20).await;
}
