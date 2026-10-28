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

/// Outstanding bytes one checked session may have queued for its writer or in
/// flight in it.
///
/// Allocation accounting only, and one of the session's two retained bounds: the
/// other is [`CHECKED_STAGED_MAX_BYTES`] of staged read-ahead. Together they say
/// what one session retains — up to 8 MiB of staged chunks plus up to 8 MiB here
/// — and nothing more: a decoded frame is a transient allocation held beside its
/// encoded message, staging copies a frame into chunks before dropping it, and
/// the agent client buffers its own frames upstream. A full queue waits for the
/// consumer, so guest backpressure stalls the session exactly as a native write
/// to a slow terminal would; it never fails and never drops output.
pub(super) const CHECKED_OUTPUT_MAX_PENDING_BYTES: usize = 8 * 1024 * 1024;

/// Largest queued frame. A guest frame is split so one reservation can never
/// exceed the bound above.
pub(super) const CHECKED_OUTPUT_CHUNK_BYTES: usize = 64 * 1024;

/// Allocation bound on guest output staged ahead of the writer.
///
/// One of the session's two retained bounds, both measured by allocation rather
/// than by length: this many bytes of staged chunks, and
/// [`CHECKED_OUTPUT_MAX_PENDING_BYTES`] queued for the writer or in flight in it.
/// Allocations outside those two queues — a frame being decoded beside its
/// encoded message, the chunk copies staging makes before dropping the frame, and
/// the agent client's own buffers — are not part of the bound.
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

/// How long the writer waits for a temporary write refusal before it looks at
/// the session again.
///
/// A non-blocking host descriptor (a caller whose stdout is a non-blocking pipe
/// or socket, whose open-file-description flags the writer's duplicate shares)
/// refuses a write with `EAGAIN` while it is full. That is pressure, not a lost
/// session, so the writer waits for the descriptor instead of failing. `poll(2)`
/// is the wait; the timeout exists because there is no portable primitive the
/// session thread could use to wake this plain thread out of it, so an abort is
/// noticed on the next recheck instead. Waiting, never spinning: each round
/// sleeps for this whole interval.
const CHECKED_WRITE_RECHECK: Duration = Duration::from_millis(50);

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

/// What one queued chunk's writes achieved.
enum ChunkWrite {
    /// The descriptor accepted every byte of the chunk.
    Written,
    /// The session ended first, so the rest of the chunk was deliberately not
    /// written.
    Stopped,
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
    /// Wakes the delivery policy for each write the descriptor accepted.
    ///
    /// At most one permit is stored, so a flood cannot queue notifications. The
    /// policy only needs to know *that* progress happened, because the time it
    /// is woken is the time it measures its idle deadline from.
    progress: Notify,
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

    /// Record bytes the descriptor accepted, and wake the delivery policy.
    fn record_accepted(&self, bytes: usize) {
        self.accepted.fetch_add(bytes as u64, Ordering::Relaxed);
        self.progress.notify_one();
    }

    /// Whether the writer has been told to stop: the session aborted, or the
    /// writer itself recorded a failure.
    fn stopped(&self) -> bool {
        let state = self.lock();
        state.aborted || state.error.is_some()
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
    /// Monotonic, so a test that watches for progress only compares readings.
    /// The delivery policy itself is woken by the writer rather than sampling
    /// this counter.
    #[cfg(test)]
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
                match write_all_fd(output.as_raw_fd(), &bytes, &queue) {
                    // The frame left the queue, so a waiting reservist may
                    // take its place.
                    Ok(ChunkWrite::Written) => queue.release(bytes.len()),
                    // The queue stopped mid-chunk (`abort` or a failure
                    // cleared it), so there is nothing left to release.
                    Ok(ChunkWrite::Stopped) => return,
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
/// measured from the *last byte the descriptor accepted*, or `limit` in total,
/// ends the attempt. The writer thread is still never joined, so cancellation is
/// unaffected.
///
/// The idle deadline is a real deadline, not a sample. The writer wakes this
/// future on every accepted write, so `idle` runs from the last progress rather
/// than from a periodic look at the accepted-byte counter: one accepted byte
/// just after delivery starts must not buy a second interval, which is exactly
/// what a "sample at `start + idle`, reset the timer if the counter moved" loop
/// does.
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
    let start = tokio::time::Instant::now();
    let limit = start + policy.limit;
    let mut last_progress = start;
    loop {
        // Registered before the deadline is read, so progress that lands
        // between the two is a wakeup and not a lost notification that would
        // lengthen the window past the policy.
        let progress = output.queue.progress.notified();
        tokio::pin!(progress);
        progress.as_mut().enable();
        let idle_deadline = last_progress + policy.idle;
        tokio::select! {
            result = &mut delivery => return result,
            // A write the descriptor accepted. Its own instant is the deadline
            // base, so progress delays the deadline by exactly one interval
            // from when it happened.
            _ = &mut progress => {
                last_progress = tokio::time::Instant::now();
            }
            _ = tokio::time::sleep_until(idle_deadline) => {
                return Err(format!(
                    "the host output accepted nothing for {:?}",
                    policy.idle
                ));
            }
            _ = tokio::time::sleep_until(limit) => {
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
fn write_all_fd(
    fd: RawFd,
    mut bytes: &[u8],
    queue: &CheckedOutputQueue,
) -> std::io::Result<ChunkWrite> {
    while !bytes.is_empty() {
        // The session may have ended since the previous slice: at most the
        // syscall already in flight may still complete, never the rest of the
        // chunk. Checking here (and not only at the chunk boundary) is what
        // keeps an abort to one 8 KiB slice, and it also gates the retry that
        // follows a writability wait, so a descriptor that becomes writable
        // just as the session ends writes nothing more.
        if queue.stopped() {
            return Ok(ChunkWrite::Stopped);
        }
        let slice = &bytes[..bytes.len().min(CHECKED_WRITE_SLICE_BYTES)];
        let written = unsafe { libc::write(fd, slice.as_ptr().cast(), slice.len()) };
        if written < 0 {
            let error = std::io::Error::last_os_error();
            match error.kind() {
                std::io::ErrorKind::Interrupted => continue,
                // The writer's duplicate shares stdout's file-status flags, so
                // a caller whose stdout is a non-blocking pipe or socket sees
                // `EAGAIN` whenever it is momentarily full. That is transport
                // pressure, not a lost session: wait for the descriptor and
                // retry the *same* bytes, which keeps their order and leaves
                // the caller's own flags alone (clearing `O_NONBLOCK` on the
                // shared description would change them for the caller too).
                std::io::ErrorKind::WouldBlock => {
                    if !wait_writable(fd, queue)? {
                        return Ok(ChunkWrite::Stopped);
                    }
                    continue;
                }
                // A closed pipe, a full device, a dead descriptor: a session
                // failure, never truncation reported as a guest success.
                _ => return Err(error),
            }
        }
        if written == 0 {
            return Err(std::io::Error::from(std::io::ErrorKind::WriteZero));
        }
        queue.record_accepted(written as usize);
        bytes = &bytes[written as usize..];
    }
    Ok(ChunkWrite::Written)
}

/// Wait until the descriptor can take bytes again, or the session stops.
///
/// `Ok(true)` means "try the write again"; `Ok(false)` means the session ended
/// while the writer was waiting and the rest of the chunk must not be written.
///
/// The wait is a bounded `poll(2)`, not a spin: the interval is
/// [`CHECKED_WRITE_RECHECK`], and every round re-reads the queue, so an abort
/// during the wait is observed within one interval. A readiness result that is
/// an error condition is handed back as ready on purpose: the next `write(2)`
/// reports the real errno (a closed pipe, a revoked descriptor) rather than
/// this function guessing at it.
fn wait_writable(fd: RawFd, queue: &CheckedOutputQueue) -> std::io::Result<bool> {
    loop {
        // Checked before sleeping, so an abort that has already happened is not
        // followed by another whole interval of waiting.
        if queue.stopped() {
            return Ok(false);
        }
        let mut descriptor = libc::pollfd {
            fd,
            events: libc::POLLOUT,
            revents: 0,
        };
        let timeout = CHECKED_WRITE_RECHECK.as_millis() as libc::c_int;
        let rc = unsafe { libc::poll(&mut descriptor, 1, timeout) };
        if rc < 0 {
            let error = std::io::Error::last_os_error();
            if error.kind() == std::io::ErrorKind::Interrupted {
                continue;
            }
            return Err(error);
        }
        if rc > 0 {
            return Ok(true);
        }
        // Timed out with nothing to report: recheck the session and wait again.
    }
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

    /// Wait until the descriptor has accepted exactly `bytes` bytes.
    ///
    /// The fixtures here are built so the room a test opens is the only room the
    /// writer ever gets, which makes the accepted count an exact, observable
    /// event rather than a sample of the clock. Only the waiting is bounded, so
    /// a writer that never gets there fails the test instead of hanging it.
    async fn wait_for_accepted(queue: &CheckedOutputQueue, bytes: u64) {
        let deadline = std::time::Instant::now() + Duration::from_secs(5);
        loop {
            let accepted = queue.accepted.load(Ordering::Relaxed);
            if accepted == bytes {
                return;
            }
            assert!(
                accepted < bytes,
                "the descriptor accepted more than the fixture made room for: \
                 {accepted} of {bytes} bytes"
            );
            assert!(
                std::time::Instant::now() < deadline,
                "the writer accepted {accepted} of {bytes} bytes"
            );
            tokio::time::sleep(Duration::from_millis(1)).await;
        }
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
    async fn one_late_byte_of_progress_does_not_buy_a_second_idle_window() {
        // A consumer that takes one bufferful and then stops: the descriptor
        // accepts bytes after delivery starts and nothing afterwards. The idle
        // deadline has to run from that last accepted byte, so the attempt ends
        // one interval later — not two, which is what sampling the accepted
        // counter once per interval produces.
        //
        // Both halves of the fixture are facts rather than guesses about
        // timing. The pipe is prefilled to capacity and then read exactly once,
        // so the room this test opens is the only room the writer ever gets and
        // the accepted count stops for good at that size; and the idle window is
        // an order of magnitude wider than the scheduling delay this test can be
        // exposed to, so the policy dominates the measurement instead of jitter.
        const IDLE: Duration = Duration::from_secs(1);
        let (write_end, reader, _prefill) = prefilled_pipe();
        let output = CheckedOutput::start(write_end.as_raw_fd()).expect("start the writer");
        drop(write_end);
        let queue = Arc::clone(&output.queue);

        let mut staging = Staging::default();
        staging.stage(vec![b'p'; 8 * CHECKED_OUTPUT_CHUNK_BYTES]);
        let policy = flush_policy(IDLE, Duration::from_secs(20));

        let delivery =
            tokio::spawn(async move { deliver_after_failure(&output, &mut staging, policy).await });

        // The writer fills the pipe and blocks. Open room for one more accepted
        // write a third of the way into the window: an implementation that
        // measured the window from the *start* of delivery instead would end two
        // thirds of a window from here, short of the lower bound below.
        tokio::time::sleep(IDLE / 3).await;
        let mut screen = reader;
        let mut buffer = vec![0u8; 8 * 1024];
        screen
            .read_exact(&mut buffer)
            .expect("the pipe's prefilled bytes");
        let opened = std::time::Instant::now();
        // Held open and never read again: no room follows the one just opened,
        // and closing it would turn the stalled consumer into a broken pipe.
        let _screen = screen;

        // Synchronise on the write that room allowed, instead of sleeping and
        // hoping it landed before the deadline. It is the last accepted byte
        // there is, and the assertion after the measurement proves the count
        // never moved again.
        wait_for_accepted(&queue, buffer.len() as u64).await;

        let error = within(delivery)
            .await
            .expect("the delivery task")
            .expect_err("a consumer that stops taking bytes ends the attempt");
        // Measured from the moment room appeared: no byte can be accepted
        // before it, and the wait above is what proves one was accepted after
        // it, so the policy's own last-progress instant is this one plus the
        // writer's wake-up.
        let since_last_byte = opened.elapsed();
        assert!(
            error.contains("accepted nothing"),
            "the idle window must say what it was: {error}"
        );
        assert!(
            since_last_byte >= IDLE * 3 / 4,
            "the attempt must not end before one idle interval without progress: \
             {since_last_byte:?}"
        );
        assert!(
            since_last_byte < IDLE * 3 / 2,
            "one idle interval after the last accepted byte, not two: {since_last_byte:?}"
        );
        assert_eq!(
            queue.accepted.load(Ordering::Relaxed),
            buffer.len() as u64,
            "nothing follows the last accepted byte: the pipe was not read again"
        );
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

    // -- A non-blocking host descriptor ---------------------------------------

    /// A pipe filled to its capacity with `0xEE` and left **non-blocking**, the
    /// way a caller whose own stdout is a non-blocking pipe or socket leaves it.
    ///
    /// The writer's duplicate shares the open file description, so it inherits
    /// `O_NONBLOCK`: its first `write(2)` sees `EAGAIN`, which is pressure and
    /// not a failure.
    fn saturated_nonblocking_pipe() -> (OwnedFd, std::fs::File, Vec<u8>) {
        let (read_end, write_end) = std::io::pipe().expect("an output pipe");
        set_nonblocking(write_end.as_raw_fd(), true).expect("a non-blocking pipe");
        let block = vec![0xEEu8; 4096];
        let mut prefill = Vec::new();
        while let Ok(written) = (&write_end).write(&block) {
            prefill.extend_from_slice(&block[..written]);
        }
        (
            write_end.into(),
            std::fs::File::from(OwnedFd::from(read_end)),
            prefill,
        )
    }

    /// Drain a descriptor to EOF on its own thread.
    fn read_to_end_on_thread(mut reader: std::fs::File) -> std::thread::JoinHandle<Vec<u8>> {
        std::thread::spawn(move || {
            let mut seen = Vec::new();
            reader
                .read_to_end(&mut seen)
                .expect("drain the output pipe");
            seen
        })
    }

    /// Read exactly `bytes` bytes on its own thread, then stop.
    ///
    /// For a fixture that keeps the caller's own write end open (to inspect its
    /// flags), so the pipe cannot reach EOF here and the count is what ends the
    /// read.
    fn read_exact_on_thread(
        mut reader: std::fs::File,
        bytes: usize,
    ) -> std::thread::JoinHandle<Vec<u8>> {
        std::thread::spawn(move || {
            let mut seen = vec![0u8; bytes];
            let mut filled = 0;
            while filled < bytes {
                match reader.read(&mut seen[filled..]) {
                    Ok(0) => panic!("the output pipe closed after {filled} of {bytes} bytes"),
                    Ok(read) => filled += read,
                    Err(error) => panic!("draining the output pipe: {error}"),
                }
            }
            seen
        })
    }

    /// Join a drain thread under a deadline.
    ///
    /// The pipe only reaches EOF once the writer dropped its duplicate, so a
    /// writer that never ended would otherwise hang the suite instead of failing
    /// it. The message says what was being waited for.
    fn drain_within(
        handle: std::thread::JoinHandle<Vec<u8>>,
        limit: Duration,
        what: &str,
    ) -> Vec<u8> {
        let (done, drained) = std::sync::mpsc::channel();
        std::thread::spawn(move || {
            let _ = done.send(handle.join().expect("the drain thread"));
        });
        drained.recv_timeout(limit).unwrap_or_else(|_| {
            panic!("the output pipe never reached EOF within {limit:?}: {what}")
        })
    }

    #[tokio::test]
    async fn temporary_pressure_on_a_nonblocking_descriptor_is_not_a_failure() {
        let (write_end, reader, prefill) = saturated_nonblocking_pipe();
        // Deliberately left non-blocking: the writer has to cope with the flags
        // it inherits instead of changing the caller's.
        let output = CheckedOutput::start(write_end.as_raw_fd()).expect("start the writer");
        let staged = b"guest output under pressure\n".to_vec();
        within(output.enqueue_chunk(&staged))
            .await
            .expect("a full descriptor is not a failure to enqueue");

        // The descriptor cannot take a byte, so a writer that mistook pressure
        // for a lost session would have reported it by now.
        let mut failure = Box::pin(output.failure());
        tokio::time::sleep(Duration::from_millis(300)).await;
        assert!(
            futures::poll!(&mut failure).is_pending(),
            "temporary pressure must never be reported as an output failure"
        );

        // The consumer resumes: the held bytes follow in order, and the session
        // can finish.
        let mut expected = prefill.clone();
        expected.extend_from_slice(&staged);
        let screen = read_exact_on_thread(reader, expected.len());
        within(output.finish())
            .await
            .expect("the writer delivers once the descriptor drains");
        assert_eq!(
            drain_within(screen, Duration::from_secs(10), "the writer did not finish"),
            expected,
            "every byte must arrive in order once the pressure clears"
        );

        let flags = unsafe { libc::fcntl(write_end.as_raw_fd(), libc::F_GETFL) };
        assert!(flags >= 0, "read the caller's own flags");
        assert!(
            flags & libc::O_NONBLOCK != 0,
            "the writer must leave the caller's O_NONBLOCK exactly as it found it"
        );
    }

    /// Whether every write end of a pipe is gone, without reading a byte.
    ///
    /// A pipe's read end reports `POLLHUP` as soon as its last write end is
    /// closed, even while unread bytes remain, so this observes the writer
    /// releasing its duplicate at a point where draining the pipe would be what
    /// let the writer finish instead.
    fn write_sides_closed(reader: RawFd, limit: Duration) -> bool {
        let deadline = std::time::Instant::now() + limit;
        let timeout = CHECKED_WRITE_RECHECK.as_millis() as libc::c_int;
        loop {
            let mut descriptor = libc::pollfd {
                fd: reader,
                events: libc::POLLIN,
                revents: 0,
            };
            let rc = unsafe { libc::poll(&mut descriptor, 1, timeout) };
            if rc > 0 && descriptor.revents & libc::POLLHUP != 0 {
                return true;
            }
            if std::time::Instant::now() >= deadline {
                return false;
            }
        }
    }

    #[tokio::test]
    async fn an_abort_between_write_slices_stops_the_rest_of_the_chunk() {
        // A blocking pipe that already holds everything it can: the writer's
        // first 8 KiB slice is blocked by construction, so one slice is in
        // flight and 56 KiB of the same chunk have not been started when the
        // session ends.
        let (write_end, reader, prefill) = prefilled_pipe();
        let output = CheckedOutput::start(write_end.as_raw_fd()).expect("start the writer");
        // Only the writer's duplicate may hold the write end, so the pipe's EOF
        // later proves that it released it.
        drop(write_end);
        let queue = Arc::clone(&output.queue);
        let chunk = vec![b'M'; CHECKED_OUTPUT_CHUNK_BYTES];
        within(output.enqueue_chunk(&chunk))
            .await
            .expect("enqueue one chunk");

        // The descriptor cannot accept a byte while nothing drains, so the
        // writer cannot have started a second slice.
        tokio::time::sleep(Duration::from_millis(200)).await;
        assert_eq!(
            output.accepted(),
            0,
            "the prefilled pipe cannot have accepted anything yet"
        );

        queue.abort();

        // Only now may the consumer drain: whatever arrived after the abort is
        // what the writer was still willing to write.
        let drained = drain_within(
            read_to_end_on_thread(reader),
            Duration::from_secs(10),
            "the aborted writer must release its duplicate",
        );
        assert!(
            drained.starts_with(&prefill),
            "the bytes already in the pipe must be untouched"
        );
        let after_abort = &drained[prefill.len()..];
        assert!(
            after_abort.len() <= CHECKED_WRITE_SLICE_BYTES,
            "an abort may complete only the slice already in flight, not the rest of the \
             chunk: {} bytes followed it",
            after_abort.len()
        );
        assert!(
            after_abort.iter().all(|byte| *byte == b'M'),
            "only the chunk the writer held may appear"
        );
    }

    #[tokio::test]
    async fn cancellation_during_a_writability_wait_stops_the_writer() {
        let (write_end, reader, prefill) = saturated_nonblocking_pipe();
        let output = CheckedOutput::start(write_end.as_raw_fd()).expect("start the writer");
        // Only the writer's duplicate may hold the write end from here on, so
        // draining to EOF proves that it released it.
        drop(write_end);
        let queue = Arc::clone(&output.queue);
        let staged = b"never written\n";
        within(output.enqueue_chunk(staged)).await.expect("enqueue");

        // Nothing can be accepted while the pipe stays full and undrained, so
        // the writer is waiting for writability, not failing.
        let mut failure = Box::pin(output.failure());
        tokio::time::sleep(Duration::from_millis(300)).await;
        assert!(
            futures::poll!(&mut failure).is_pending(),
            "the writer must wait for the descriptor rather than fail"
        );

        queue.abort();

        // The wait must end on the abort, not on the descriptor becoming
        // writable: the pipe is still full and nothing has drained it. `POLLHUP`
        // appears when the writer drops its duplicate, which is the only write
        // end left.
        assert!(
            write_sides_closed(reader.as_raw_fd(), Duration::from_secs(5)),
            "an aborted writability wait must end and release the writer's duplicate"
        );
        let drained = drain_within(
            read_to_end_on_thread(reader),
            Duration::from_secs(10),
            "the writer's duplicate must already be gone here",
        );
        assert!(
            drained.starts_with(&prefill),
            "the bytes already in the pipe must be untouched"
        );
        // The only bytes that may still arrive are a prefix of the chunk the
        // writer was holding when the abort happened, in order; nothing from
        // the queue behind it can appear.
        let extra = &drained[prefill.len()..];
        assert!(
            staged.starts_with(extra),
            "only bytes the writer already held may follow an abort: {:?}",
            String::from_utf8_lossy(extra)
        );
    }
}
