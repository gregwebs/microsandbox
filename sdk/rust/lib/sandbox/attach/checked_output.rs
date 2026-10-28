//! The checked session's output path: an ordered queue, a dedicated writer
//! thread that owns the blocking writes, and the staging between the guest's
//! frames and the writer.

use std::collections::VecDeque;
use std::os::fd::{AsRawFd, OwnedFd, RawFd};
use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::{Arc, Condvar, Mutex};
use std::time::Duration;

use tokio::sync::Notify;

use super::error::{AttachFailureKind, AttachSessionError};
use super::unix::duplicate_cloexec;

//--------------------------------------------------------------------------------------------------
// Constants
//--------------------------------------------------------------------------------------------------

/// Outstanding bytes one checked session may have queued or in flight.
///
/// Allocation accounting only, and one of the session's two bounds: the other
/// is [`CHECKED_STAGED_MAX_BYTES`] of read-ahead. A full queue waits for the
/// consumer, so guest backpressure stalls the session exactly as a native write
/// to a slow terminal would; it never fails and never drops output.
pub(super) const CHECKED_OUTPUT_MAX_PENDING_BYTES: usize = 8 * 1024 * 1024;

/// Largest queued frame. A guest frame is split so one reservation can never
/// exceed the bound above.
pub(super) const CHECKED_OUTPUT_CHUNK_BYTES: usize = 64 * 1024;

/// Allocation bound on guest output read ahead of the writer.
///
/// Together with [`CHECKED_OUTPUT_MAX_PENDING_BYTES`] this bounds what one
/// checked session holds: at most 8 MiB of chunks waiting for the writer and
/// 8 MiB queued for it, measured by allocation, not by length.
pub(super) const CHECKED_STAGED_MAX_BYTES: usize = 8 * 1024 * 1024;

/// Largest guest frame the session may receive.
///
/// A receive is allowed only while a frame this size still fits under
/// [`CHECKED_STAGED_MAX_BYTES`], so staging never has to drop or split a frame
/// it cannot hold. The frame is an upper bound for a control message's body;
/// the payload inside it is a few bytes smaller.
const GUEST_FRAME_MAX_BYTES: usize = microsandbox_protocol::codec::MAX_FRAME_SIZE as usize;

/// The most one `write(2)` hands the host descriptor at a time.
///
/// A blocking write returns only once it has taken *all* of what it was given,
/// so a whole 64 KiB chunk that a slow consumer drains over a second makes the
/// writer look stalled for that whole second. Bounding each syscall makes the
/// accepted-byte count track what the descriptor actually takes, which is what
/// the delivery policy below waits for. Bytes and their order are unchanged.
const CHECKED_WRITE_SLICE_BYTES: usize = 8 * 1024;

/// How long a failed session keeps offering output to a host descriptor that
/// accepts no bytes at all.
pub(super) const CHECKED_FAILURE_FLUSH_IDLE: Duration = Duration::from_millis(500);

/// The most a failed session spends delivering held output, however slowly the
/// host keeps accepting it: the error and the terminal restore must not wait on
/// a crawling consumer for ever.
pub(super) const CHECKED_FAILURE_FLUSH_LIMIT: Duration = Duration::from_secs(5);

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
/// (a caller that cancels is expected to exit or move on; the thread holds
/// only its own descriptor), and the runtime drops immediately.
#[derive(Default)]
struct CheckedOutputQueue {
    state: Mutex<CheckedOutputQueueState>,
    /// Bytes the host descriptor has accepted, counted per successful
    /// `write(2)`. Monotonic, and only ever compared, so a relaxed load is
    /// enough.
    accepted: AtomicU64,
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

/// What a failed session spends delivering output it still holds.
#[derive(Clone, Copy)]
pub(super) struct FlushPolicy {
    /// Give up after this long without a single accepted byte.
    pub(super) idle: Duration,
    /// Give up after this long in total, however steadily the host accepts.
    pub(super) limit: Duration,
}

/// Guest output read but not yet accepted by the writer, as writer-sized chunks.
///
/// Invariant: `held` is the sum of the chunks' *capacities* and stays at most
/// [`CHECKED_STAGED_MAX_BYTES`] as long as callers stage only while
/// [`has_room_for_frame`](Self::has_room_for_frame). Each chunk is an
/// exact-size copy, never a `split_off` head of its frame: a head keeps the
/// whole frame's allocation alive, which for a 4 MiB frame staged as 64 chunks
/// would retain about 130 MiB instead of 4 MiB.
#[derive(Default)]
pub(super) struct Staging {
    chunks: VecDeque<Vec<u8>>,
    held: usize,
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
    fn failure_or(&self, fallback: &str) -> AttachSessionError {
        output_failure(self.failure().unwrap_or_else(|| fallback.to_string()))
    }
}

impl CheckedOutput {
    pub(super) fn start(stdout_fd: RawFd) -> Result<Self, AttachSessionError> {
        let output = duplicate_cloexec(stdout_fd).map_err(|error| {
            output_failure(format!("duplicating the host terminal output: {error}"))
        })?;
        let queue = Arc::new(CheckedOutputQueue::default());
        let writer_queue = Arc::clone(&queue);
        std::thread::Builder::new()
            .name("msb-attach-output".into())
            .spawn(move || run_checked_writer(writer_queue, output))
            .map_err(|error| {
                output_failure(format!("starting the terminal output writer: {error}"))
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
    pub(super) async fn enqueue_chunk(&self, bytes: &[u8]) -> Result<(), AttachSessionError> {
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
    pub(super) async fn failure(&self) -> AttachSessionError {
        loop {
            let signal = self.queue.failed.notified();
            tokio::pin!(signal);
            signal.as_mut().enable();
            if let Some(message) = self.queue.failure() {
                return output_failure(message);
            }
            signal.await;
        }
    }

    /// Wait until `bytes` more fit under the pending bound, then reserve them.
    async fn reserve(&self, bytes: usize) -> Result<(), AttachSessionError> {
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
                    return Err(output_failure(error.clone()));
                }
                if state.aborted {
                    return Err(output_failure("the terminal output writer was aborted"));
                }
                if state.reserved + bytes <= CHECKED_OUTPUT_MAX_PENDING_BYTES {
                    state.reserved += bytes;
                    return Ok(());
                }
            }
            capacity.await;
        }
    }

    /// The bytes the host descriptor has accepted so far, ever.
    ///
    /// Monotonic: the delivery policy only compares two readings.
    pub(super) fn accepted(&self) -> u64 {
        self.queue.accepted.load(Ordering::Relaxed)
    }

    /// Wait for the ordered finish receipt: every earlier byte has been
    /// accepted by the host descriptor (not flushed to stable storage).
    ///
    /// Cancellable, like every other await in the session; the queue's abort
    /// then discards whatever the writer has not written.
    pub(super) async fn finish(&self) -> Result<(), AttachSessionError> {
        let (receipt, receipt_wait) = tokio::sync::oneshot::channel();
        {
            let mut state = self.queue.lock();
            if let Some(error) = &state.error {
                return Err(output_failure(error.clone()));
            }
            if state.aborted {
                return Err(output_failure("the terminal output writer was aborted"));
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

impl FlushPolicy {
    /// A session that has already failed still offers what it holds for this
    /// long, so the guest's last words are not lost with the session.
    pub(super) const AFTER_FAILURE: Self = Self {
        idle: CHECKED_FAILURE_FLUSH_IDLE,
        limit: CHECKED_FAILURE_FLUSH_LIMIT,
    };
}

impl Staging {
    /// Whether one largest-possible guest frame still fits under the bound.
    pub(super) fn has_room_for_frame(&self) -> bool {
        self.held + GUEST_FRAME_MAX_BYTES <= CHECKED_STAGED_MAX_BYTES
    }

    /// Split one guest output frame into writer-sized chunks and hold them.
    pub(super) fn stage(&mut self, frame: Vec<u8>) {
        for chunk in frame.chunks(CHECKED_OUTPUT_CHUNK_BYTES) {
            let chunk = chunk.to_vec();
            self.held += chunk.capacity();
            self.chunks.push_back(chunk);
        }
        // `frame` is dropped here, so its allocation is not retained.
    }

    /// The head chunk, which the writer is offered next.
    pub(super) fn front(&self) -> Option<&[u8]> {
        self.chunks.front().map(Vec::as_slice)
    }

    /// The head chunk left staging: the writer accepted it.
    pub(super) fn pop_delivered(&mut self) {
        if let Some(chunk) = self.chunks.pop_front() {
            self.held = self.held.saturating_sub(chunk.capacity());
        }
    }

    pub(super) fn is_empty(&self) -> bool {
        self.chunks.is_empty()
    }

    /// The staged chunks, for a test that asserts order and chunk boundaries.
    #[cfg(test)]
    pub(super) fn chunks(&self) -> impl Iterator<Item = &[u8]> {
        self.chunks.iter().map(Vec::as_slice)
    }

    /// Each staged chunk's allocation, for a test that checks the accounting.
    #[cfg(test)]
    pub(super) fn capacities(&self) -> impl Iterator<Item = usize> {
        self.chunks.iter().map(Vec::capacity)
    }

    /// Every held byte, counted by allocation.
    #[cfg(test)]
    pub(super) fn held(&self) -> usize {
        self.held
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

/// Owns the duplicated host stdout descriptor and every blocking write.
fn run_checked_writer(queue: Arc<CheckedOutputQueue>, output: OwnedFd) {
    // The queue is re-read for each item instead of being held across the
    // syscall, so an abort can discard unwritten output while a write blocks.
    while let Some(item) = queue.next() {
        match item {
            CheckedOutputItem::Data(bytes) => {
                match write_all_fd(output.as_raw_fd(), &bytes, &queue.accepted) {
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

/// Best-effort delivery once the session has already failed.
///
/// Everything still staged is offered to the writer, then the finish receipt is
/// awaited, while the host descriptor keeps accepting bytes: an `idle` interval
/// in which `write(2)` took nothing, or `limit` in total, ends the attempt. The
/// writer thread is still never joined, so cancellation is unaffected.
///
/// The error is the reason delivery was given up, for the caller to append to
/// the session's own failure: an unrestored terminal or a lost relay is what the
/// caller has to act on, and this is a note beside it.
pub(super) async fn deliver_after_failure(
    output: &CheckedOutput,
    staging: &mut Staging,
    policy: FlushPolicy,
) -> Result<(), String> {
    let delivery = async {
        while let Some(chunk) = staging.front() {
            output
                .enqueue_chunk(chunk)
                .await
                .map_err(|error| error.to_string())?;
            staging.pop_delivered();
        }
        output.finish().await.map_err(|error| error.to_string())
    };
    tokio::pin!(delivery);
    let deadline = tokio::time::Instant::now() + policy.limit;
    let mut seen = output.accepted();
    loop {
        tokio::select! {
            result = &mut delivery => return result,
            _ = tokio::time::sleep(policy.idle) => {
                let now = output.accepted();
                if now == seen {
                    return Err(format!(
                        "the host output accepted nothing for {:?}",
                        policy.idle
                    ));
                }
                seen = now;
            }
            _ = tokio::time::sleep_until(deadline) => {
                return Err(format!(
                    "the host output did not take the held guest output within {:?}",
                    policy.limit
                ));
            }
        }
    }
}

/// A failure of the host's output descriptor or of its writer.
fn output_failure(text: impl Into<String>) -> AttachSessionError {
    AttachSessionError::new(AttachFailureKind::Output, text)
}

/// Write `bytes`, at most [`CHECKED_WRITE_SLICE_BYTES`] per syscall, counting
/// what the descriptor accepted.
fn write_all_fd(fd: RawFd, mut bytes: &[u8], accepted: &AtomicU64) -> std::io::Result<()> {
    while !bytes.is_empty() {
        let slice = &bytes[..bytes.len().min(CHECKED_WRITE_SLICE_BYTES)];
        let written = unsafe { libc::write(fd, slice.as_ptr().cast(), slice.len()) };
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
        accepted.fetch_add(written as u64, Ordering::Relaxed);
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

    use std::io::{Read, Seek, SeekFrom, Write};
    use std::os::fd::{AsRawFd, OwnedFd, RawFd};
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
        let mut staging = Staging::default();
        for frame in frames {
            expected.extend_from_slice(&frame);
            staging.stage(frame);
        }
        // Staging is where a frame is split, so no reservation can exceed the
        // queue's chunk bound.
        assert!(
            staging
                .chunks()
                .all(|chunk| !chunk.is_empty() && chunk.len() <= CHECKED_OUTPUT_CHUNK_BYTES),
            "a staged chunk exceeded the queue's chunk bound"
        );
        while let Some(chunk) = staging.front() {
            within(output.enqueue_chunk(chunk)).await.expect("enqueue");
            staging.pop_delivered();
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
        let failure = failure.expect("an unwritable descriptor must be reported");
        assert_eq!(
            failure.kind(),
            AttachFailureKind::Output,
            "an unwritable descriptor is an output failure: {failure}"
        );
        let later = output
            .enqueue_chunk(b"more\n")
            .await
            .expect_err("the queue keeps refusing work after its writer failed");
        assert_eq!(later.kind(), AttachFailureKind::Output);
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
        assert_eq!(
            failure.kind(),
            AttachFailureKind::Output,
            "the session must see an output failure: {failure}"
        );
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
        assert_eq!(
            failure.kind(),
            AttachFailureKind::Output,
            "the capacity wait must report an output failure: {failure}"
        );
        assert!(
            failure.to_string().contains("writing guest output"),
            "the capacity wait must report the writer's failure: {failure}"
        );
    }

    #[test]
    fn staging_holds_exact_size_chunks() {
        let mut staging = Staging::default();
        staging.stage(vec![0x5A; GUEST_FRAME_MAX_BYTES]);

        assert!(!staging.is_empty());
        for chunk in staging.chunks() {
            assert!(!chunk.is_empty(), "an empty chunk would loop the writer");
            assert!(
                chunk.len() <= CHECKED_OUTPUT_CHUNK_BYTES,
                "a staged chunk held more bytes than the writer's own frame bound"
            );
        }
        for capacity in staging.capacities() {
            assert!(
                capacity <= CHECKED_OUTPUT_CHUNK_BYTES,
                "a staged chunk retained its frame's whole allocation"
            );
        }
        assert_eq!(
            staging.held(),
            staging.capacities().sum::<usize>(),
            "the accounting must be the sum of the allocations"
        );
        assert!(
            staging.held() <= GUEST_FRAME_MAX_BYTES,
            "one frame must cost one frame, not a retained header per chunk"
        );
        assert!(staging.held() <= CHECKED_STAGED_MAX_BYTES);
    }

    #[test]
    fn staging_never_exceeds_its_allocation_bound() {
        let mut staging = Staging::default();
        let frames = [
            vec![b'a'; GUEST_FRAME_MAX_BYTES],
            vec![b'b'; 1],
            vec![b'c'; CHECKED_OUTPUT_CHUNK_BYTES + 7],
            vec![b'd'; GUEST_FRAME_MAX_BYTES],
            vec![b'e'; 3 * CHECKED_OUTPUT_CHUNK_BYTES],
        ];
        let mut delivered = 0usize;
        for frame in frames {
            // Receive only while a largest frame still fits, exactly as the
            // session's receive arm does.
            while !staging.has_room_for_frame() {
                assert!(!staging.is_empty(), "staging can never make room again");
                staging.pop_delivered();
                delivered += 1;
                assert_eq!(
                    staging.held(),
                    staging.capacities().sum::<usize>(),
                    "the accounting must follow a delivery"
                );
            }
            staging.stage(frame);
            assert_eq!(
                staging.held(),
                staging.capacities().sum::<usize>(),
                "the accounting must follow the allocations"
            );
            assert!(
                staging.held() <= CHECKED_STAGED_MAX_BYTES,
                "staging grew past its allocation bound"
            );
        }
        assert!(
            delivered > 0,
            "the bound must have forced a delivery during this run"
        );
    }

    #[test]
    fn staging_reopens_after_delivery() {
        let mut staging = Staging::default();
        while staging.has_room_for_frame() {
            staging.stage(vec![b'q'; GUEST_FRAME_MAX_BYTES]);
        }
        assert!(
            !staging.has_room_for_frame(),
            "a full staging must stop the session receiving"
        );

        let mut delivered = 0usize;
        while !staging.has_room_for_frame() {
            assert!(!staging.is_empty(), "staging never made room again");
            staging.pop_delivered();
            delivered += 1;
        }
        assert!(delivered > 0);
        assert!(staging.held() + GUEST_FRAME_MAX_BYTES <= CHECKED_STAGED_MAX_BYTES);
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

    // -- Failing-session delivery (C12) ---------------------------------------

    /// Set or clear `O_NONBLOCK` on one descriptor.
    fn set_nonblocking(fd: RawFd, nonblocking: bool) -> std::io::Result<()> {
        let current = unsafe { libc::fcntl(fd, libc::F_GETFL) };
        if current == -1 {
            return Err(std::io::Error::last_os_error());
        }
        let flags = if nonblocking {
            current | libc::O_NONBLOCK
        } else {
            current & !libc::O_NONBLOCK
        };
        if unsafe { libc::fcntl(fd, libc::F_SETFL, flags) } == -1 {
            return Err(std::io::Error::last_os_error());
        }
        Ok(())
    }

    /// A pipe that already holds everything it can, with its write end left
    /// blocking.
    ///
    /// The writer's first `write(2)` therefore cannot complete until the reader
    /// drains, which is what makes "no progress" a property of the fixture
    /// rather than of the timing.
    fn prefilled_pipe() -> (OwnedFd, std::fs::File, Vec<u8>) {
        let (read_end, write_end) = std::io::pipe().expect("an output pipe");
        set_nonblocking(write_end.as_raw_fd(), true).expect("a non-blocking pipe");
        let block = vec![0xEEu8; 4096];
        let mut prefill = Vec::new();
        while let Ok(written) = (&write_end).write(&block) {
            prefill.extend_from_slice(&block[..written]);
        }
        // The flag lives on the shared open file description, so the writer's
        // duplicate would otherwise see `EAGAIN` as a write failure.
        set_nonblocking(write_end.as_raw_fd(), false).expect("a blocking pipe");
        (
            write_end.into(),
            std::fs::File::from(OwnedFd::from(read_end)),
            prefill,
        )
    }

    /// Read whatever the pipe offers, sleep, repeat, until EOF.
    ///
    /// A consumer that keeps taking bytes, but slowly: the delivery policy has
    /// to keep going while it does.
    fn slow_reader(
        mut reader: std::fs::File,
        slice: usize,
        interval: Duration,
    ) -> std::thread::JoinHandle<Vec<u8>> {
        std::thread::spawn(move || {
            let mut seen = Vec::new();
            let mut buffer = vec![0u8; slice];
            loop {
                match reader.read(&mut buffer) {
                    Ok(0) => break,
                    Ok(read) => {
                        seen.extend_from_slice(&buffer[..read]);
                        std::thread::sleep(interval);
                    }
                    Err(error) => panic!("draining the output pipe: {error}"),
                }
            }
            seen
        })
    }

    fn flush_policy(idle: Duration, limit: Duration) -> FlushPolicy {
        FlushPolicy { idle, limit }
    }

    #[tokio::test]
    async fn delivers_everything_to_a_live_consumer() {
        let mut file = tempfile::tempfile().expect("a scratch output file");
        let output = CheckedOutput::start(file.as_raw_fd()).expect("start the writer");
        let mut staging = Staging::default();
        let frames: Vec<Vec<u8>> = vec![
            vec![b'a'; 100 * 1024],
            b"b".to_vec(),
            vec![b'c'; CHECKED_OUTPUT_CHUNK_BYTES + 3],
        ];
        let mut expected = Vec::new();
        for frame in frames {
            expected.extend_from_slice(&frame);
            staging.stage(frame);
        }

        within(deliver_after_failure(
            &output,
            &mut staging,
            FlushPolicy::AFTER_FAILURE,
        ))
        .await
        .expect("a live consumer takes everything");
        assert!(staging.is_empty(), "delivered chunks leave staging");

        file.seek(SeekFrom::Start(0)).expect("rewind");
        let mut actual = Vec::new();
        file.read_to_end(&mut actual).expect("read back");
        assert_eq!(actual, expected);
    }

    #[tokio::test]
    async fn counts_partial_writes_as_progress() {
        // The consumer drains this pipe at about 160 KiB/s, so one 64 KiB
        // chunk-sized write takes roughly twice the idle window to complete.
        // Progress has to be measured in bytes the descriptor accepted, not in
        // whole chunks that finished, or a consumer that is plainly working is
        // reported as stalled.
        let (write_end, reader, prefill) = prefilled_pipe();
        let output = CheckedOutput::start(write_end.as_raw_fd()).expect("start the writer");
        drop(write_end);

        let mut staging = Staging::default();
        staging.stage(vec![b'x'; 2 * CHECKED_OUTPUT_CHUNK_BYTES]);
        let mut expected = prefill;
        expected.extend_from_slice(&vec![b'x'; 2 * CHECKED_OUTPUT_CHUNK_BYTES]);

        let screen = slow_reader(reader, 8 * 1024, Duration::from_millis(50));
        within(deliver_after_failure(
            &output,
            &mut staging,
            flush_policy(Duration::from_millis(400), Duration::from_secs(20)),
        ))
        .await
        .expect("a consumer that keeps accepting is not stalled");
        assert!(staging.is_empty());

        drop(output);
        assert_eq!(screen.join().expect("the screen thread"), expected);
    }

    #[tokio::test]
    async fn stops_at_its_total_limit() {
        // A consumer that is slow but always progressing: the idle window never
        // fires, so only the total limit can stop the attempt.
        let (write_end, reader, _prefill) = prefilled_pipe();
        let output = CheckedOutput::start(write_end.as_raw_fd()).expect("start the writer");
        drop(write_end);

        let mut staging = Staging::default();
        staging.stage(vec![b'y'; 8 * CHECKED_OUTPUT_CHUNK_BYTES]);
        let _screen = slow_reader(reader, 8 * 1024, Duration::from_millis(30));

        let started = std::time::Instant::now();
        let error = within(deliver_after_failure(
            &output,
            &mut staging,
            flush_policy(Duration::from_millis(400), Duration::from_secs(1)),
        ))
        .await
        .expect_err("a crawling consumer must not delay the error without limit");
        let elapsed = started.elapsed();
        assert!(
            error.contains("within 1s"),
            "the total limit must say what it was: {error}"
        );
        assert!(
            elapsed >= Duration::from_secs(1),
            "the limit must not fire early: {elapsed:?}"
        );
        assert!(
            elapsed < Duration::from_secs(3),
            "the limit must fire when it says it does: {elapsed:?}"
        );
    }

    #[tokio::test]
    async fn gives_up_on_a_stalled_consumer() {
        let (write_end, reader, _prefill) = prefilled_pipe();
        let output = CheckedOutput::start(write_end.as_raw_fd()).expect("start the writer");
        drop(write_end);

        let mut staging = Staging::default();
        staging.stage(vec![b'q'; CHECKED_OUTPUT_CHUNK_BYTES]);
        // Held, never read: the writer has nowhere to put the next byte.
        let _screen = reader;

        let started = std::time::Instant::now();
        let error = within(deliver_after_failure(
            &output,
            &mut staging,
            flush_policy(Duration::from_millis(100), Duration::from_secs(20)),
        ))
        .await
        .expect_err("a consumer that takes nothing must end the attempt");
        assert!(
            error.contains("accepted nothing"),
            "the idle window must say what it was: {error}"
        );
        assert!(
            started.elapsed() < Duration::from_secs(2),
            "a stalled consumer must not hold the error for long: {:?}",
            started.elapsed()
        );
        // The chunk left staging when the writer queued it; it is the writer's
        // `write(2)` that is stalled, not the handover.
        assert!(staging.is_empty());
    }

    #[tokio::test]
    async fn reports_a_dead_writer() {
        let (read_end, write_end) = std::io::pipe().expect("a pipe");
        drop(read_end);
        let output = CheckedOutput::start(write_end.as_raw_fd()).expect("start the writer");
        drop(write_end);

        let mut staging = Staging::default();
        staging.stage(b"lost\n".to_vec());

        let error = within(deliver_after_failure(
            &output,
            &mut staging,
            FlushPolicy::AFTER_FAILURE,
        ))
        .await
        .expect_err("an unwritable descriptor cannot be delivered to");
        assert!(
            error.contains("writing guest output"),
            "the writer's own failure must be named: {error}"
        );
    }
}
