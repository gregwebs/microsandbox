//! The checked session's output path: an ordered queue, a dedicated writer
//! thread that owns the blocking writes, and the staging between the guest's
//! frames and the writer.

use std::collections::VecDeque;
use std::os::fd::{AsRawFd, OwnedFd, RawFd};
use std::sync::{Arc, Condvar, Mutex};

use tokio::sync::Notify;

use crate::{MicrosandboxError, MicrosandboxResult};

use super::unix::{checked_failure, duplicate_cloexec};

//--------------------------------------------------------------------------------------------------
// Constants
//--------------------------------------------------------------------------------------------------

/// Outstanding bytes one checked session may have queued or in flight.
///
/// Memory accounting only. A full queue waits for the consumer, so guest
/// backpressure stalls the session exactly as a native write to a slow
/// terminal would; it never fails and never drops output.
pub(super) const CHECKED_OUTPUT_MAX_PENDING_BYTES: usize = 8 * 1024 * 1024;

/// Largest queued frame. A guest frame is split so one reservation can never
/// exceed the bound above.
pub(super) const CHECKED_OUTPUT_CHUNK_BYTES: usize = 64 * 1024;

//--------------------------------------------------------------------------------------------------
// Types
//--------------------------------------------------------------------------------------------------

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

pub(super) struct CheckedOutput {
    queue: Arc<CheckedOutputQueue>,
}

//--------------------------------------------------------------------------------------------------
// Methods
//--------------------------------------------------------------------------------------------------

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

impl CheckedOutput {
    pub(super) fn start(stdout_fd: RawFd) -> MicrosandboxResult<Self> {
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
    pub(super) async fn enqueue_chunk(&self, bytes: &[u8]) -> MicrosandboxResult<()> {
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
    pub(super) async fn failure(&self) -> MicrosandboxError {
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
    pub(super) async fn finish(&self) -> MicrosandboxResult<()> {
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

//--------------------------------------------------------------------------------------------------
// Trait Implementations
//--------------------------------------------------------------------------------------------------

impl Drop for CheckedOutput {
    fn drop(&mut self) {
        self.queue.abort();
    }
}

//--------------------------------------------------------------------------------------------------
// Functions
//--------------------------------------------------------------------------------------------------

/// Split one guest output frame into the bounded chunks the writer accepts.
pub(super) fn stage_output_chunks(bytes: Vec<u8>, pending: &mut VecDeque<Vec<u8>>) {
    let mut remaining = bytes;
    while !remaining.is_empty() {
        let mut chunk = remaining;
        remaining = chunk.split_off(chunk.len().min(CHECKED_OUTPUT_CHUNK_BYTES));
        pending.push_back(chunk);
    }
}

/// Owns the duplicated host stdout descriptor and every blocking write.
fn run_checked_writer(queue: Arc<CheckedOutputQueue>, output: OwnedFd) {
    // The queue is re-read for each item instead of being held across the
    // syscall, so an abort can discard unwritten output while a write blocks.
    while let Some(item) = queue.next() {
        match item {
            CheckedOutputItem::Data(bytes) => {
                match write_all_fd(output.as_raw_fd(), &bytes) {
                    // The frame left the queue, so a waiting reservist may
                    // take its place.
                    Ok(()) => queue.release(bytes.len()),
                    Err(error) => {
                        // Closed pipe, full device: a session failure, never
                        // truncation reported as a guest success. Recorded
                        // before any capacity is released, because a caller
                        // woken by a release must never find a dead queue that
                        // still accepts work; `fail` clears the accounting.
                        queue.fail(format!(
                            "writing guest output to the host terminal: {error}"
                        ));
                        return;
                    }
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

//--------------------------------------------------------------------------------------------------
// Tests
//--------------------------------------------------------------------------------------------------

#[cfg(test)]
mod tests {

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
