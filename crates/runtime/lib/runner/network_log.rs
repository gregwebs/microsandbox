//! Host-side writer for `network.log`: one JSON line per egress refusal the network engine
//! reports, rate-limited per decision site so a flood cannot fill the sandbox's disk.
//!
//! The engine hands every refused decision to [`NetworkLog`] as its
//! [`RefusalSink`], from the smoltcp poll thread and from proxy, DNS and secrets tasks, and
//! requires that call never to block. The sink therefore does no I/O: one lock over fixed-size
//! counters decides whether a refusal is written, and enqueues it without waiting. A single
//! writer thread owns the [`RotatingLog`] and turns queued records into lines.
//!
//! Flood control is per [`RefusalSite`]: a bucket of [`BUCKET_CAPACITY`] tokens refilled at
//! [`BUCKET_REFILL_PER_SEC`], and one suppressed count per site written at most once per
//! [`FLUSH_INTERVAL`] and once more when the log closes.

use std::{
    path::Path,
    sync::{
        Arc, Mutex, MutexGuard, PoisonError, TryLockError,
        mpsc::{Receiver, RecvTimeoutError, SyncSender, TrySendError, sync_channel},
    },
    thread,
    time::{Duration, Instant},
};

#[cfg(test)]
use std::sync::Barrier;

use chrono::{DateTime, Utc};
use microsandbox_network::refusal::RefusalSink;
use microsandbox_types::{
    LogSource, NETWORK_LOG_FORMAT_VERSION, NetworkLogEvent, NetworkLogRecord, NetworkRefusal,
    NetworkSuppressed, RefusalSite,
};

use crate::logging::RotatingLog;
use crate::{RuntimeError, RuntimeResult};

//--------------------------------------------------------------------------------------------------
// Constants
//--------------------------------------------------------------------------------------------------

/// `RotatingLog` prefix; the file is `network.log`.
const NETWORK_LOG_PREFIX: &str = "network";

/// Per-file rotation threshold (10 MiB), as for `exec.log`.
const NETWORK_LOG_MAX_BYTES: u64 = 10 * 1024 * 1024;

/// Tokens each site's bucket starts with and refills up to.
const BUCKET_CAPACITY: u32 = 256;

/// Tokens each site's bucket regains per second.
const BUCKET_REFILL_PER_SEC: u32 = 20;

/// Cost of one admitted refusal, in milli-tokens.
const TOKEN_MILLI: u64 = 1_000;

/// Admitted records waiting for the writer thread.
const QUEUE_CAPACITY: usize = 1024;

/// How often the writer reports suppressed counts.
const FLUSH_INTERVAL: Duration = Duration::from_secs(1);

/// Longest the exit observer waits for the writer to drain.
pub(crate) const NETWORK_LOG_CLOSE_TIMEOUT: Duration = Duration::from_millis(250);

//--------------------------------------------------------------------------------------------------
// Types
//--------------------------------------------------------------------------------------------------

/// Writes `network.log`. Shared with the network engine as its refusal sink.
pub(crate) struct NetworkLog {
    /// Producer-side state. One lock covers the closed flag, the buckets and the enqueue, so a
    /// record can never be enqueued after `close` has set the flag.
    state: Arc<Mutex<ProducerState>>,

    /// Admitted records, then the close handshake. Never waited on by a producer.
    queue: SyncSender<WriterMessage>,

    /// Test hook: a producer parks here while holding the producer lock, so a test can run
    /// `close` against a producer that is mid-admission.
    #[cfg(test)]
    admission_stall: Option<Arc<Stall>>,
}

/// What the producer lock protects.
struct ProducerState {
    /// Set by `close` under the lock; a refusal reported after it is ignored.
    closed: bool,

    /// Per-site tokens and suppressed counts.
    limiter: RefusalLimiter,

    /// Records this process handed to the writer. Test-only: the close-race test needs to know
    /// how many records were accepted, which a producer cannot observe otherwise.
    #[cfg(test)]
    enqueued_refusals: u64,
}

/// One message from a producer to the writer thread.
enum WriterMessage {
    /// One admitted refusal. It carries no timestamp: the writer stamps it, so `t` in the file
    /// is non-decreasing however producers interleave.
    Record {
        /// The refused decision's facts.
        refusal: NetworkRefusal,
    },

    /// Drain, write pending suppressed counts, and acknowledge.
    Close(SyncSender<()>),
}

/// Per-site token buckets and the refusals each site has not had written.
///
/// Fixed size: one slot per [`RefusalSite`], created full when the log opens, so no method takes
/// an allocation.
struct RefusalLimiter {
    /// Bucket ceiling in milli-tokens.
    capacity_milli: u64,

    /// Tokens each site regains per second.
    refill_per_sec: u32,

    /// One slot per site, indexed by [`RefusalSite::index`].
    sites: [SiteState; RefusalSite::COUNT],
}

/// One site's bucket and suppressed count.
#[derive(Clone, Copy)]
struct SiteState {
    /// Tokens left, in milli-tokens.
    tokens_milli: u64,

    /// When this bucket last gained tokens.
    refilled_at: Instant,

    /// Refusals at this site decided but not written.
    suppressed: u64,
}

/// Tunables; `Default` is the constants above.
///
/// Tests shrink them: a `refill_per_sec` of 0 disables refill, so a burst is deterministic, and a
/// short `flush_interval` reaches the suppressed tick without waiting a second.
struct Settings {
    /// Per-file rotation threshold.
    max_bytes: u64,

    /// Bucket ceiling in tokens.
    bucket_capacity: u32,

    /// Tokens each site regains per second.
    refill_per_sec: u32,

    /// Records the queue holds before producers start counting drops.
    queue_capacity: usize,

    /// How often the writer reports suppressed counts.
    flush_interval: Duration,

    /// Test hook: the writer thread waits for this lock before taking any message, so a test can
    /// fill the queue deterministically.
    #[cfg(test)]
    writer_gate: Option<Arc<Mutex<()>>>,

    /// Test hook: see [`NetworkLog::admission_stall`].
    #[cfg(test)]
    admission_stall: Option<Arc<Stall>>,
}

impl Default for Settings {
    fn default() -> Self {
        Self {
            max_bytes: NETWORK_LOG_MAX_BYTES,
            bucket_capacity: BUCKET_CAPACITY,
            refill_per_sec: BUCKET_REFILL_PER_SEC,
            queue_capacity: QUEUE_CAPACITY,
            flush_interval: FLUSH_INTERVAL,
            #[cfg(test)]
            writer_gate: None,
            #[cfg(test)]
            admission_stall: None,
        }
    }
}

/// Reports a write failure once at `warn`, then at `debug`.
///
/// A full disk would otherwise flood `runtime.log` with one warning per dropped record.
#[derive(Default)]
struct WriteFailures {
    /// Whether a failure has already been reported at `warn`.
    reported: bool,
}

impl WriteFailures {
    /// Report one failed write of a record line.
    fn note(&mut self, error: &RuntimeError) {
        if self.reported {
            tracing::debug!(error = %error, "network.log: write failed, dropping record");
        } else {
            self.reported = true;
            tracing::warn!(error = %error, "network.log: write failed, dropping record");
        }
    }
}

/// Two barriers that park a producer until the test releases it.
#[cfg(test)]
struct Stall {
    /// Arrived: the producer is where the test wants it.
    reached: Barrier,

    /// Released: the test lets the producer continue.
    released: Barrier,
}

#[cfg(test)]
impl Stall {
    /// A stall for one producer and one test thread.
    fn new() -> Self {
        Self {
            reached: Barrier::new(2),
            released: Barrier::new(2),
        }
    }

    /// Block until the test has seen this point and released it.
    fn park(&self) {
        self.reached.wait();
        self.released.wait();
    }
}

//--------------------------------------------------------------------------------------------------
// Methods
//--------------------------------------------------------------------------------------------------

impl NetworkLog {
    /// Create or append `<log_dir>/network.log` and start the writer thread.
    pub(crate) fn open(log_dir: &Path) -> RuntimeResult<Arc<Self>> {
        Self::open_with(log_dir, Settings::default())
    }

    /// Stop accepting records, drain the queue, write pending suppressed counts, and wait at most
    /// `timeout` for the writer.
    ///
    /// Idempotent. Best effort: on timeout a warning goes to `runtime.log` and queued records and
    /// pending counts may be lost, because teardown continues.
    ///
    /// The budget covers waiting for a producer, not just the drain: a producer that is stalled
    /// or preempted while holding the producer lock must not hold teardown open past `timeout`.
    pub(crate) fn close(&self, timeout: Duration) {
        let deadline = Instant::now() + timeout;
        {
            let Some(mut state) = self.lock_state_until(deadline) else {
                tracing::warn!(
                    "network.log: close timed out waiting for a producer; queued refusals and \
                     pending suppressed counts may be lost"
                );
                return;
            };
            if state.closed {
                return;
            }
            // Setting the flag in the same critical section as `record`'s check is what makes a
            // clean stop lossless: a producer either enqueued before the flag, so its record is
            // ahead of `Close` and drained, or sees the flag and returns.
            state.closed = true;
        }

        let (ack_tx, ack_rx) = sync_channel::<()>(1);
        let mut message = WriterMessage::Close(ack_tx);
        loop {
            match self.queue.try_send(message) {
                Ok(()) => break,
                Err(TrySendError::Full(returned)) => {
                    if Instant::now() >= deadline {
                        tracing::warn!(
                            "network.log: close timed out queuing the drain; queued refusals and \
                             pending suppressed counts may be lost"
                        );
                        return;
                    }
                    // The writer is draining, so space appears soon.
                    thread::sleep(Duration::from_millis(1));
                    message = returned;
                }
                Err(TrySendError::Disconnected(_)) => {
                    tracing::warn!(
                        "network.log: writer thread is gone; queued refusals and pending \
                         suppressed counts may be lost"
                    );
                    return;
                }
            }
        }

        let remaining = deadline.saturating_duration_since(Instant::now());
        if ack_rx.recv_timeout(remaining).is_err() {
            tracing::warn!(
                "network.log: close timed out; queued refusals and pending suppressed counts may \
                 be lost"
            );
        }
    }

    /// Create or append `<log_dir>/network.log` with `settings` and start the writer thread.
    fn open_with(log_dir: &Path, settings: Settings) -> RuntimeResult<Arc<Self>> {
        let log = RotatingLog::new(log_dir, NETWORK_LOG_PREFIX, settings.max_bytes)?;
        let now = Instant::now();
        let limiter = RefusalLimiter::new(settings.bucket_capacity, settings.refill_per_sec, now);
        let state = Arc::new(Mutex::new(ProducerState {
            closed: false,
            limiter,
            #[cfg(test)]
            enqueued_refusals: 0,
        }));
        let (queue, receiver) = sync_channel(settings.queue_capacity);

        #[cfg(test)]
        let admission_stall = settings.admission_stall.clone();

        let writer_state = Arc::clone(&state);
        thread::Builder::new()
            .name("msb-network-log".to_string())
            .spawn(move || run_writer(log, receiver, writer_state, settings))
            .map_err(|error| {
                RuntimeError::Custom(format!("spawn the network.log writer: {error}"))
            })?;

        Ok(Arc::new(Self {
            state,
            queue,
            #[cfg(test)]
            admission_stall,
        }))
    }

    /// Lock the producer state, recovering from a poisoned lock.
    ///
    /// The state is plain counters and flags, so it stays usable after a panic elsewhere.
    fn lock_state(&self) -> MutexGuard<'_, ProducerState> {
        self.state.lock().unwrap_or_else(PoisonError::into_inner)
    }

    /// Lock the producer state, giving up at `deadline`.
    ///
    /// Used only by [`NetworkLog::close`], whose budget must include a producer that is inside the
    /// critical section: blocking on the lock would let one stalled producer delay teardown for
    /// as long as it likes.
    fn lock_state_until(&self, deadline: Instant) -> Option<MutexGuard<'_, ProducerState>> {
        loop {
            match self.state.try_lock() {
                Ok(guard) => return Some(guard),
                Err(TryLockError::Poisoned(poisoned)) => return Some(poisoned.into_inner()),
                Err(TryLockError::WouldBlock) => {
                    if Instant::now() >= deadline {
                        return None;
                    }
                    thread::sleep(Duration::from_millis(1));
                }
            }
        }
    }
}

impl RefusalLimiter {
    /// Every site's bucket full at `now`.
    fn new(capacity: u32, refill_per_sec: u32, now: Instant) -> Self {
        let capacity_milli = u64::from(capacity) * TOKEN_MILLI;
        Self {
            capacity_milli,
            refill_per_sec,
            sites: [SiteState {
                tokens_milli: capacity_milli,
                refilled_at: now,
                suppressed: 0,
            }; RefusalSite::COUNT],
        }
    }

    /// Take a token for `site`, or count the refusal as suppressed.
    fn admit(&mut self, site: RefusalSite, now: Instant) -> bool {
        let capacity_milli = self.capacity_milli;
        let refill_per_sec = self.refill_per_sec;
        let state = &mut self.sites[site.index()];

        refill(state, capacity_milli, refill_per_sec, now);

        if state.tokens_milli >= TOKEN_MILLI {
            state.tokens_milli -= TOKEN_MILLI;
            return true;
        }

        state.suppressed += 1;
        false
    }

    /// Count an admitted refusal the queue could not take.
    fn note_dropped(&mut self, site: RefusalSite) {
        self.sites[site.index()].suppressed += 1;
    }

    /// Copy every site's suppressed count, indexed by [`RefusalSite::index`], and reset them to
    /// zero.
    ///
    /// Returns a fixed array, so the writer's snapshot under the lock never allocates.
    fn take_suppressed(&mut self) -> [u64; RefusalSite::COUNT] {
        let mut counts = [0_u64; RefusalSite::COUNT];
        for (index, state) in self.sites.iter_mut().enumerate() {
            counts[index] = std::mem::take(&mut state.suppressed);
        }
        counts
    }
}

//--------------------------------------------------------------------------------------------------
// Trait Implementations
//--------------------------------------------------------------------------------------------------

impl RefusalSink for NetworkLog {
    /// Take the site's token, so the engine only builds a record it will accept.
    fn admits(&self, site: RefusalSite) -> bool {
        let mut state = self.lock_state();

        if state.closed {
            return false;
        }

        if !state.limiter.admit(site, Instant::now()) {
            return false;
        }

        // Test hook: stand in for a stall inside the critical section.
        #[cfg(test)]
        if let Some(stall) = &self.admission_stall {
            stall.park();
        }

        true
    }

    fn record(&self, refusal: NetworkRefusal) {
        let site = refusal.site;
        let mut state = self.lock_state();

        // A refusal reported after `close` is ignored (R7). Its token was taken, so nothing is
        // counted: the stopped sandbox has no reader that could use the count.
        if state.closed {
            return;
        }

        // `try_send` never blocks and the bounded channel is preallocated, so this holds the lock
        // for no I/O and no allocation. A full queue costs the site one suppressed count.
        match self.queue.try_send(WriterMessage::Record { refusal }) {
            Ok(()) => {
                #[cfg(test)]
                {
                    state.enqueued_refusals += 1;
                }
            }
            Err(_) => state.limiter.note_dropped(site),
        }
    }
}

//--------------------------------------------------------------------------------------------------
// Functions
//--------------------------------------------------------------------------------------------------

/// Serve the queue until `close` acknowledges, writing one line per record.
fn run_writer(
    mut log: RotatingLog,
    queue: Receiver<WriterMessage>,
    state: Arc<Mutex<ProducerState>>,
    settings: Settings,
) {
    // Test hook: stay parked here until the test opens the gate.
    #[cfg(test)]
    let _gate = settings
        .writer_gate
        .as_ref()
        .map(|gate| gate.lock().unwrap_or_else(PoisonError::into_inner));

    let mut failures = WriteFailures::default();
    let mut next_flush = Instant::now() + settings.flush_interval;

    loop {
        let wait = next_flush.saturating_duration_since(Instant::now());
        match queue.recv_timeout(wait) {
            Ok(WriterMessage::Record { refusal }) => {
                write_event(
                    &mut log,
                    NetworkLogEvent::Refusal(refusal),
                    Utc::now(),
                    &mut failures,
                );
            }
            Ok(WriterMessage::Close(ack)) => {
                // Everything a producer enqueued precedes `Close`, but drain anyway: a record the
                // channel still holds must not be dropped by the shutdown path.
                drain(&mut log, &queue, &mut failures);
                write_suppressed(&mut log, &state, &mut failures);
                let _ = ack.send(());
                return;
            }
            Err(RecvTimeoutError::Timeout) => {}
            Err(RecvTimeoutError::Disconnected) => {
                // The log was dropped without a close: write what is left and stop.
                drain(&mut log, &queue, &mut failures);
                write_suppressed(&mut log, &state, &mut failures);
                return;
            }
        }

        if Instant::now() >= next_flush {
            write_suppressed(&mut log, &state, &mut failures);
            next_flush = Instant::now() + settings.flush_interval;
        }
    }
}

//--------------------------------------------------------------------------------------------------
// Functions: Helpers
//--------------------------------------------------------------------------------------------------

/// Add the tokens `state` earned since it last refilled, capped at `capacity_milli`.
///
/// Integer milli-tokens keep every boundary exact: the same instant always yields the same
/// decision, which is what makes the limiter tests deterministic.
fn refill(state: &mut SiteState, capacity_milli: u64, refill_per_sec: u32, now: Instant) {
    let elapsed_milli = now.saturating_duration_since(state.refilled_at).as_millis() as u64;
    if elapsed_milli == 0 {
        return;
    }

    // Advance by whole milliseconds rather than to `now`, so a sub-millisecond remainder is not
    // discarded and repeated calls cannot drift.
    state.refilled_at += Duration::from_millis(elapsed_milli);
    let gained = elapsed_milli * u64::from(refill_per_sec);
    state.tokens_milli = state
        .tokens_milli
        .saturating_add(gained)
        .min(capacity_milli);
}

/// Write every record still queued, oldest first.
fn drain(log: &mut RotatingLog, queue: &Receiver<WriterMessage>, failures: &mut WriteFailures) {
    while let Ok(message) = queue.try_recv() {
        if let WriterMessage::Record { refusal } = message {
            write_event(log, NetworkLogEvent::Refusal(refusal), Utc::now(), failures);
        }
    }
}

/// Write one `suppressed` record per site with a pending count, then reset the counts.
///
/// The counts are taken and zeroed under the lock; the lines are built and written outside it, so
/// the writer never appends an allocating snapshot while holding the producer lock.
fn write_suppressed(
    log: &mut RotatingLog,
    state: &Mutex<ProducerState>,
    failures: &mut WriteFailures,
) {
    let counts = {
        let mut guard = state.lock().unwrap_or_else(PoisonError::into_inner);
        guard.limiter.take_suppressed()
    };

    if counts.iter().all(|count| *count == 0) {
        return;
    }

    let at = Utc::now();
    for (index, count) in counts.into_iter().enumerate() {
        if count == 0 {
            continue;
        }
        let event = NetworkLogEvent::Suppressed(NetworkSuppressed {
            site: RefusalSite::ALL[index],
            count,
        });
        write_event(log, event, at, failures);
    }
}

/// Encode `event` and append it as exactly one line.
fn write_event(
    log: &mut RotatingLog,
    event: NetworkLogEvent,
    at: DateTime<Utc>,
    failures: &mut WriteFailures,
) {
    let Some(line) = encode(at, event) else {
        return;
    };

    // One `write` per line: `RotatingLog` rotates before a write that would exceed the cap, so a
    // line is never split across files.
    if let Err(error) = log.write(&line) {
        failures.note(&error);
    }
}

/// The record envelope plus the event, as one JSON line.
fn encode(at: DateTime<Utc>, event: NetworkLogEvent) -> Option<Vec<u8>> {
    let record = NetworkLogRecord {
        v: NETWORK_LOG_FORMAT_VERSION,
        t: at,
        s: LogSource::Network,
        event,
    };

    match serde_json::to_vec(&record) {
        Ok(mut line) => {
            line.push(b'\n');
            Some(line)
        }
        Err(error) => {
            tracing::warn!(error = %error, "network.log: record encoding failed, dropping");
            None
        }
    }
}

//--------------------------------------------------------------------------------------------------
// Tests
//--------------------------------------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use std::{
        net::Ipv4Addr,
        path::PathBuf,
        sync::atomic::{AtomicUsize, Ordering},
        time::Duration,
    };

    use microsandbox_types::{
        NameSource, PlaceholderLocation, Protocol, RefusalLayer, SecretRefusalReason,
    };

    use super::*;

    /// One refusal for `site`, with `revision` used as a sequence number.
    fn refusal(site: RefusalSite, revision: u64) -> NetworkRefusal {
        NetworkRefusal {
            site,
            layer: RefusalLayer::Tenant,
            protocol: Protocol::Tcp,
            dst_ip: Some(Ipv4Addr::new(203, 0, 113, 10).into()),
            dst_port: Some(443),
            name: Some("api.example.com".to_string()),
            name_source: NameSource::DnsCache,
            revision,
            credential: None,
            location: None,
            reason: None,
        }
    }

    /// Report one refusal the way the engine does: ask the sink to admit the site, then hand it
    /// the record only if it did.
    ///
    /// The trait is two-phase so a suppressed refusal never pays for name evidence; a test that
    /// called `record` directly would skip the limiter entirely.
    fn report(log: &NetworkLog, refusal: NetworkRefusal) {
        if log.admits(refusal.site) {
            log.record(refusal);
        }
    }

    /// Settings with refill disabled, so a burst is exactly deterministic.
    fn burst_settings(bucket_capacity: u32) -> Settings {
        Settings {
            bucket_capacity,
            refill_per_sec: 0,
            flush_interval: Duration::from_secs(3600),
            ..Default::default()
        }
    }

    /// Every line of `path`, parsed, requiring each line to be terminated.
    fn read_records_in(path: &Path) -> Vec<NetworkLogRecord> {
        let bytes = std::fs::read(path).unwrap();
        let text = std::str::from_utf8(&bytes).unwrap();
        assert!(
            text.is_empty() || text.ends_with('\n'),
            "{} must end with a newline, so no line is split",
            path.display()
        );
        text.lines()
            .map(|line| {
                serde_json::from_str::<NetworkLogRecord>(line)
                    .unwrap_or_else(|error| panic!("{line:?} must parse as a record: {error}"))
            })
            .collect()
    }

    /// Files that hold records, oldest first: `.4` through `.1`, then the live file.
    fn record_files(dir: &Path) -> Vec<PathBuf> {
        let mut files = Vec::new();
        for index in (1..=4).rev() {
            let path = dir.join(format!("{NETWORK_LOG_PREFIX}.log.{index}"));
            if path.exists() {
                files.push(path);
            }
        }

        let live = dir.join(format!("{NETWORK_LOG_PREFIX}.log"));
        if live.exists() {
            files.push(live);
        }

        files
    }

    /// Every record file's lines, oldest file first.
    fn read_records(dir: &Path) -> Vec<NetworkLogRecord> {
        record_files(dir)
            .iter()
            .flat_map(|path| read_records_in(path))
            .collect()
    }

    fn refusals(records: &[NetworkLogRecord]) -> Vec<&NetworkRefusal> {
        records
            .iter()
            .filter_map(|record| match &record.event {
                NetworkLogEvent::Refusal(refusal) => Some(refusal),
                _ => None,
            })
            .collect()
    }

    fn suppressions(records: &[NetworkLogRecord]) -> Vec<&NetworkSuppressed> {
        records
            .iter()
            .filter_map(|record| match &record.event {
                NetworkLogEvent::Suppressed(suppressed) => Some(suppressed),
                _ => None,
            })
            .collect()
    }

    #[test]
    fn fresh_site_admits_capacity_then_suppresses() {
        let t0 = Instant::now();
        let mut limiter = RefusalLimiter::new(4, 20, t0);

        for _ in 0..4 {
            assert!(limiter.admit(RefusalSite::Udp, t0));
        }
        assert!(!limiter.admit(RefusalSite::Udp, t0));

        let counts = limiter.take_suppressed();
        assert_eq!(counts[RefusalSite::Udp.index()], 1);
        assert_eq!(counts.iter().sum::<u64>(), 1);
    }

    #[test]
    fn refill_restores_one_token_per_50ms() {
        let t0 = Instant::now();
        let mut limiter = RefusalLimiter::new(4, 20, t0);
        for _ in 0..4 {
            assert!(limiter.admit(RefusalSite::TcpSyn, t0));
        }

        assert!(
            !limiter.admit(RefusalSite::TcpSyn, t0 + Duration::from_millis(49)),
            "49 ms is 980 milli-tokens, short of one token"
        );
        assert!(
            limiter.admit(RefusalSite::TcpSyn, t0 + Duration::from_millis(50)),
            "50 ms is one token at 20 tokens per second"
        );
        assert!(
            !limiter.admit(RefusalSite::TcpSyn, t0 + Duration::from_millis(50)),
            "the token was spent"
        );
    }

    #[test]
    fn refill_caps_at_capacity() {
        let t0 = Instant::now();
        let mut limiter = RefusalLimiter::new(4, 20, t0);
        for _ in 0..4 {
            assert!(limiter.admit(RefusalSite::Udp, t0));
        }

        let after_an_hour = t0 + Duration::from_secs(3600);
        for _ in 0..4 {
            assert!(limiter.admit(RefusalSite::Udp, after_an_hour));
        }
        assert!(!limiter.admit(RefusalSite::Udp, after_an_hour));
    }

    #[test]
    fn sites_are_independent() {
        let t0 = Instant::now();
        let mut limiter = RefusalLimiter::new(2, 0, t0);

        for _ in 0..2 {
            assert!(limiter.admit(RefusalSite::Udp, t0));
        }
        assert!(!limiter.admit(RefusalSite::Udp, t0));

        assert!(
            limiter.admit(RefusalSite::TcpSyn, t0),
            "one site's exhausted bucket must not suppress another site"
        );

        let counts = limiter.take_suppressed();
        assert_eq!(counts[RefusalSite::Udp.index()], 1);
        assert_eq!(counts[RefusalSite::TcpSyn.index()], 0);
    }

    #[test]
    fn take_suppressed_resets_and_orders_by_site() {
        let t0 = Instant::now();
        let mut limiter = RefusalLimiter::new(1, 0, t0);

        assert!(limiter.admit(RefusalSite::DnsQuery, t0));
        assert!(!limiter.admit(RefusalSite::DnsQuery, t0));
        assert!(!limiter.admit(RefusalSite::DnsQuery, t0));
        assert!(limiter.admit(RefusalSite::SecretViolation, t0));
        assert!(!limiter.admit(RefusalSite::SecretViolation, t0));

        let counts = limiter.take_suppressed();
        assert_eq!(counts[RefusalSite::DnsQuery.index()], 2);
        assert_eq!(counts[RefusalSite::SecretViolation.index()], 1);
        assert_eq!(counts.iter().sum::<u64>(), 3);

        assert!(
            limiter.take_suppressed().iter().all(|count| *count == 0),
            "a taken count must not be reported twice"
        );
    }

    #[test]
    fn note_dropped_counts_as_suppressed() {
        let t0 = Instant::now();
        let mut limiter = RefusalLimiter::new(1, 0, t0);

        limiter.note_dropped(RefusalSite::TcpHostname);
        limiter.note_dropped(RefusalSite::TcpHostname);

        let counts = limiter.take_suppressed();
        assert_eq!(counts[RefusalSite::TcpHostname.index()], 2);
        assert_eq!(counts.iter().sum::<u64>(), 2);
    }

    #[test]
    fn concurrent_admission_never_exceeds_capacity() {
        let t0 = Instant::now();
        let limiter = Mutex::new(RefusalLimiter::new(4, 0, t0));
        let admitted = AtomicUsize::new(0);
        let start = Barrier::new(9);

        std::thread::scope(|scope| {
            for _ in 0..8 {
                scope.spawn(|| {
                    start.wait();
                    for _ in 0..100 {
                        let allowed = limiter
                            .lock()
                            .unwrap()
                            .admit(RefusalSite::HttpAuthority, t0);
                        if allowed {
                            admitted.fetch_add(1, Ordering::Relaxed);
                        }
                    }
                });
            }
            start.wait();
        });

        assert_eq!(
            admitted.load(Ordering::Relaxed),
            4,
            "contended admission must not hand out more tokens than the bucket held"
        );
        assert_eq!(
            limiter.lock().unwrap().take_suppressed()[RefusalSite::HttpAuthority.index()],
            796
        );
    }

    #[test]
    fn writes_one_documented_line_per_admitted_refusal() {
        let dir = tempfile::tempdir().unwrap();
        let log = NetworkLog::open_with(dir.path(), burst_settings(8)).unwrap();

        report(&log, refusal(RefusalSite::TcpSyn, 1));
        report(&log, refusal(RefusalSite::DnsQuery, 2));
        report(&log, refusal(RefusalSite::Icmp, 3));
        log.close(Duration::from_secs(5));

        let records = read_records(dir.path());
        assert_eq!(records.len(), 3);
        assert_eq!(refusals(&records).len(), 3);
        assert!(suppressions(&records).is_empty());

        for record in &records {
            assert_eq!(record.v, NETWORK_LOG_FORMAT_VERSION);
            assert_eq!(record.s, LogSource::Network);
        }
        let sites: Vec<RefusalSite> = refusals(&records)
            .iter()
            .map(|refusal| refusal.site)
            .collect();
        assert_eq!(
            sites,
            [
                RefusalSite::TcpSyn,
                RefusalSite::DnsQuery,
                RefusalSite::Icmp
            ]
        );
        assert_eq!(refusals(&records)[0].revision, 1);
        assert_eq!(
            refusals(&records)[0].dst_ip,
            Some(Ipv4Addr::new(203, 0, 113, 10).into())
        );

        // Byte for byte the envelope and field order of the documented format, with the record's
        // own timestamp in place.
        let text = std::fs::read_to_string(dir.path().join("network.log")).unwrap();
        let first = text.lines().next().unwrap();
        let t = records[0]
            .t
            .to_rfc3339_opts(chrono::SecondsFormat::Millis, true);
        assert_eq!(
            first,
            format!(
                r#"{{"v":1,"t":"{t}","s":"network","event":"refusal","site":"tcp-syn","layer":"tenant","protocol":"tcp","dst_ip":"203.0.113.10","dst_port":443,"name":"api.example.com","name_source":"dns-cache","revision":1}}"#
            )
        );
    }

    /// The writer puts a `secret-violation` record on disk with its three fields in the
    /// documented order; a reader of the same line gets them back.
    #[test]
    fn writes_the_documented_secret_violation_line() {
        let dir = tempfile::tempdir().unwrap();
        let log = NetworkLog::open_with(dir.path(), burst_settings(8)).unwrap();

        report(
            &log,
            NetworkRefusal {
                site: RefusalSite::SecretViolation,
                layer: RefusalLayer::Tenant,
                protocol: Protocol::Tcp,
                dst_ip: Some(Ipv4Addr::new(203, 0, 113, 10).into()),
                dst_port: Some(443),
                name: Some("api.deepseek.com".to_owned()),
                name_source: NameSource::Sni,
                revision: 2,
                credential: Some("MSB_AGENT_VM_ANTHROPIC_UNUSED".to_owned()),
                location: Some(PlaceholderLocation::Header),
                reason: Some(SecretRefusalReason::HostNotCovered),
            },
        );
        log.close(Duration::from_secs(5));

        // Byte for byte the documented line, with the writer's own timestamp in place.
        let records = read_records(dir.path());
        assert_eq!(records.len(), 1);
        let t = records[0]
            .t
            .to_rfc3339_opts(chrono::SecondsFormat::Millis, true);
        let text = std::fs::read_to_string(dir.path().join("network.log")).unwrap();
        assert_eq!(
            text,
            format!(
                r#"{{"v":1,"t":"{t}","s":"network","event":"refusal","site":"secret-violation","layer":"tenant","protocol":"tcp","dst_ip":"203.0.113.10","dst_port":443,"name":"api.deepseek.com","name_source":"sni","revision":2,"credential":"MSB_AGENT_VM_ANTHROPIC_UNUSED","location":"header","reason":"host-not-covered"}}"#
            ) + "\n"
        );

        let refusal = refusals(&records)[0];
        assert_eq!(
            refusal.credential.as_deref(),
            Some("MSB_AGENT_VM_ANTHROPIC_UNUSED")
        );
        assert_eq!(refusal.location, Some(PlaceholderLocation::Header));
        assert_eq!(refusal.reason, Some(SecretRefusalReason::HostNotCovered));
    }

    #[test]
    fn burst_past_capacity_writes_capacity_then_one_suppressed_record() {
        let dir = tempfile::tempdir().unwrap();
        let log = NetworkLog::open_with(dir.path(), burst_settings(4)).unwrap();

        for revision in 0..10 {
            report(&log, refusal(RefusalSite::Udp, revision));
        }
        log.close(Duration::from_secs(5));

        let records = read_records(dir.path());
        assert_eq!(refusals(&records).len(), 4);
        let suppressed = suppressions(&records);
        assert_eq!(suppressed.len(), 1);
        assert_eq!(suppressed[0].site, RefusalSite::Udp);
        assert_eq!(suppressed[0].count, 6);

        let text = std::fs::read_to_string(dir.path().join("network.log")).unwrap();
        let last = text.lines().last().unwrap();
        let t = records
            .last()
            .unwrap()
            .t
            .to_rfc3339_opts(chrono::SecondsFormat::Millis, true);
        assert_eq!(
            last,
            format!(
                r#"{{"v":1,"t":"{t}","s":"network","event":"suppressed","site":"udp","count":6}}"#
            )
        );
    }

    #[test]
    fn close_writes_pending_suppressed_counts() {
        let dir = tempfile::tempdir().unwrap();
        // A one-hour tick: only `close` can report the pending count.
        let log = NetworkLog::open_with(dir.path(), burst_settings(1)).unwrap();

        report(&log, refusal(RefusalSite::Udp, 1));
        report(&log, refusal(RefusalSite::Udp, 2));
        report(&log, refusal(RefusalSite::Udp, 3));
        log.close(Duration::from_secs(5));

        let records = read_records(dir.path());
        assert_eq!(refusals(&records).len(), 1);
        let suppressed = suppressions(&records);
        assert_eq!(suppressed.len(), 1);
        assert_eq!(suppressed[0].site, RefusalSite::Udp);
        assert_eq!(suppressed[0].count, 2);
    }

    #[test]
    fn close_without_pending_writes_nothing_more() {
        let dir = tempfile::tempdir().unwrap();
        let log = NetworkLog::open_with(dir.path(), burst_settings(8)).unwrap();

        report(&log, refusal(RefusalSite::Udp, 1));
        report(&log, refusal(RefusalSite::Udp, 2));
        log.close(Duration::from_secs(5));
        log.close(Duration::from_secs(5));

        let records = read_records(dir.path());
        assert_eq!(records.len(), 2, "a zero count is never written");
        assert!(suppressions(&records).is_empty());
    }

    #[test]
    fn record_after_close_is_ignored() {
        let dir = tempfile::tempdir().unwrap();
        let log = NetworkLog::open_with(dir.path(), burst_settings(8)).unwrap();

        report(&log, refusal(RefusalSite::Udp, 1));
        log.close(Duration::from_secs(5));
        report(&log, refusal(RefusalSite::Udp, 2));

        assert_eq!(log.lock_state().enqueued_refusals, 1);
        let records = read_records(dir.path());
        assert_eq!(refusals(&records).len(), 1);
        assert_eq!(refusals(&records)[0].revision, 1);
        assert!(suppressions(&records).is_empty());
    }

    /// The sink is two-phase (`admits` then `record`) so a suppressed refusal never resolves name
    /// evidence. That makes the split a correctness boundary: the bucket must be charged in
    /// `admits` only, so one admitted refusal costs exactly one token and one written line.
    ///
    /// Detects the two plausible defects of a two-phase sink: a limiter charged in both phases
    /// (half the records written) and a limiter not charged at all (a flood defeats the bound).
    #[test]
    fn the_bucket_is_charged_exactly_once_per_admitted_refusal() {
        let dir = tempfile::tempdir().unwrap();
        let capacity = 4_u32;
        let log = NetworkLog::open_with(dir.path(), burst_settings(capacity)).unwrap();

        // Phase one: every admission under the bucket is granted, and the bucket is then empty.
        let mut admitted = 0;
        for revision in 0..capacity {
            assert!(log.admits(RefusalSite::Udp), "revision {revision} fits");
            admitted += 1;
        }
        assert!(
            !log.admits(RefusalSite::Udp),
            "the bucket must be empty after exactly `capacity` admissions"
        );
        assert_eq!(admitted, capacity);

        // Phase two cannot be what charges or releases the bucket: the next admission is refused
        // whether or not the admitted records have been handed over yet.
        for revision in 0..capacity {
            log.record(refusal(RefusalSite::Udp, u64::from(revision)));
        }
        assert!(
            !log.admits(RefusalSite::Udp),
            "`record` must neither refund nor re-charge a token"
        );

        log.close(Duration::from_secs(5));

        let records = read_records(dir.path());
        assert_eq!(
            refusals(&records).len(),
            capacity as usize,
            "one written line per token, no more"
        );
        let suppressed = suppressions(&records);
        assert_eq!(suppressed.len(), 1, "one suppressed record for the site");
        assert_eq!(
            suppressed[0].count, 2,
            "the two refused admissions -- the burst past the bucket and the post-`record` check -- \
             are suppressed, and nothing else is"
        );
    }

    /// A site that reported without asking for a token would bypass the flood bound, so `record`
    /// itself never consumes one: the deny-site contract is that `admits` is the only charge.
    #[test]
    fn a_record_without_an_admission_never_charges_the_bucket() {
        let dir = tempfile::tempdir().unwrap();
        let log = NetworkLog::open_with(dir.path(), burst_settings(2)).unwrap();

        // Two records delivered with no admission at all.
        log.record(refusal(RefusalSite::TcpSyn, 1));
        log.record(refusal(RefusalSite::TcpSyn, 2));

        // The bucket is untouched, so the site still admits its two tokens.
        assert!(log.admits(RefusalSite::TcpSyn));
        assert!(log.admits(RefusalSite::TcpSyn));
        assert!(!log.admits(RefusalSite::TcpSyn));
        log.record(refusal(RefusalSite::TcpSyn, 3));

        log.close(Duration::from_secs(5));

        let records = read_records(dir.path());
        assert_eq!(refusals(&records).len(), 3);
        assert_eq!(suppressions(&records).len(), 1);
        assert_eq!(suppressions(&records)[0].count, 1);
    }

    #[test]
    fn rotates_at_max_bytes_without_splitting_lines() {
        // Measure one line first: the rotation threshold is then expressed in lines, so the test
        // does not depend on the encoded size of a record.
        let probe_dir = tempfile::tempdir().unwrap();
        let probe = NetworkLog::open_with(probe_dir.path(), burst_settings(2)).unwrap();
        report(&probe, refusal(RefusalSite::Udp, 0));
        probe.close(Duration::from_secs(5));
        let line_bytes = std::fs::metadata(probe_dir.path().join("network.log"))
            .unwrap()
            .len();
        assert!(line_bytes > 100);

        let dir = tempfile::tempdir().unwrap();
        let settings = Settings {
            max_bytes: 2 * line_bytes + 10,
            ..burst_settings(16)
        };
        let log = NetworkLog::open_with(dir.path(), settings).unwrap();
        for revision in 0..8 {
            report(&log, refusal(RefusalSite::Udp, revision));
        }
        log.close(Duration::from_secs(5));

        let files = record_files(dir.path());
        assert!(files.len() >= 3, "rotated files must exist, got {files:?}");
        for path in &files {
            let size = std::fs::metadata(path).unwrap().len();
            assert!(
                size <= 2 * line_bytes + 10,
                "{} exceeded the cap",
                path.display()
            );
            // Reading asserts that every line parses and the file ends with a newline.
            read_records_in(path);
        }

        let revisions: Vec<u64> = read_records(dir.path())
            .iter()
            .map(|record| match &record.event {
                NetworkLogEvent::Refusal(refusal) => refusal.revision,
                _ => panic!("no suppression at capacity 16"),
            })
            .collect();
        assert_eq!(revisions, (0..8).collect::<Vec<u64>>());
    }

    #[test]
    fn appends_on_reopen() {
        let dir = tempfile::tempdir().unwrap();

        {
            let log = NetworkLog::open_with(dir.path(), burst_settings(8)).unwrap();
            report(&log, refusal(RefusalSite::Udp, 1));
            log.close(Duration::from_secs(5));
        }
        {
            let log = NetworkLog::open_with(dir.path(), burst_settings(8)).unwrap();
            report(&log, refusal(RefusalSite::TcpSyn, 2));
            log.close(Duration::from_secs(5));
        }

        let records = read_records(dir.path());
        assert_eq!(refusals(&records).len(), 2);
        assert_eq!(refusals(&records)[0].site, RefusalSite::Udp);
        assert_eq!(refusals(&records)[1].site, RefusalSite::TcpSyn);
    }

    #[test]
    fn concurrent_producers_write_whole_lines() {
        let dir = tempfile::tempdir().unwrap();
        let log = NetworkLog::open_with(dir.path(), burst_settings(256)).unwrap();
        let producers = 8;
        let per_producer = 25;

        std::thread::scope(|scope| {
            for producer in 0..producers {
                let log = Arc::clone(&log);
                scope.spawn(move || {
                    for index in 0..per_producer {
                        report(
                            &log,
                            refusal(RefusalSite::Udp, (producer * per_producer + index) as u64),
                        );
                    }
                });
            }
        });
        log.close(Duration::from_secs(5));

        let records = read_records(dir.path());
        assert_eq!(refusals(&records).len(), producers * per_producer);
        assert!(suppressions(&records).is_empty());

        // Every line parsed, and the revisions are a permutation: no line was torn or interleaved.
        let mut revisions: Vec<u64> = refusals(&records)
            .iter()
            .map(|refusal| refusal.revision)
            .collect();
        revisions.sort_unstable();
        assert_eq!(
            revisions,
            (0..(producers * per_producer) as u64).collect::<Vec<u64>>()
        );
    }

    #[test]
    fn full_queue_counts_drops_and_never_blocks() {
        let dir = tempfile::tempdir().unwrap();
        // Park the writer so nothing drains, then fill the one-slot queue.
        let gate = Arc::new(Mutex::new(()));
        let parked = gate.lock().unwrap();
        let settings = Settings {
            queue_capacity: 1,
            writer_gate: Some(Arc::clone(&gate)),
            ..burst_settings(256)
        };
        let log = NetworkLog::open_with(dir.path(), settings).unwrap();

        let started = Instant::now();
        for revision in 0..100 {
            report(&log, refusal(RefusalSite::Udp, revision));
        }
        let elapsed = started.elapsed();
        drop(parked);

        assert!(
            elapsed < Duration::from_secs(5),
            "record must not wait on the writer, took {elapsed:?}"
        );

        log.close(Duration::from_secs(5));

        let records = read_records(dir.path());
        assert_eq!(
            refusals(&records).len(),
            1,
            "only the queued record can be written"
        );
        let suppressed = suppressions(&records);
        assert_eq!(suppressed.len(), 1);
        assert_eq!(suppressed[0].count, 99);
    }

    #[test]
    fn suppressed_counts_are_written_on_the_flush_tick() {
        let dir = tempfile::tempdir().unwrap();
        let settings = Settings {
            flush_interval: Duration::from_millis(20),
            ..burst_settings(1)
        };
        let log = NetworkLog::open_with(dir.path(), settings).unwrap();

        // One refusal fits the bucket; the next two are pending suppressed counts.
        for revision in 0..3 {
            report(&log, refusal(RefusalSite::Udp, revision));
        }

        let deadline = Instant::now() + Duration::from_secs(5);
        let suppressed = loop {
            let records = read_records(dir.path());
            let suppressed = suppressions(&records);
            if !suppressed.is_empty() {
                break suppressed.len();
            }
            if Instant::now() >= deadline {
                panic!("the flush tick must write pending suppressed counts");
            }
            std::thread::sleep(Duration::from_millis(5));
        };
        assert_eq!(suppressed, 1);

        log.close(Duration::from_secs(5));

        // `close` reports only what the tick did not take.
        let records = read_records(dir.path());
        assert_eq!(refusals(&records).len(), 1);
        assert_eq!(
            suppressions(&records)
                .iter()
                .map(|suppressed| suppressed.count)
                .sum::<u64>(),
            2,
            "the two suppressed refusals are reported exactly once in total"
        );
    }

    #[test]
    fn close_racing_producers_never_loses_an_accepted_record() {
        // Every round releases four producers and `close` from one barrier. Whatever order the
        // runtime interleaves them in, a record the sink accepted must reach the file: `close`
        // sets the closed flag in the same critical section as the enqueue, so an accepted record
        // is always ahead of `Close` in the channel.
        let rounds = 50;
        let producers = 4;
        let per_producer = 20;
        let mut accepted_total = 0;

        for round in 0..rounds {
            let dir = tempfile::tempdir().unwrap();
            let log = NetworkLog::open_with(dir.path(), burst_settings(256)).unwrap();
            let start = Barrier::new(producers + 1);

            std::thread::scope(|scope| {
                for producer in 0..producers {
                    let log = Arc::clone(&log);
                    let start = &start;
                    scope.spawn(move || {
                        start.wait();
                        for index in 0..per_producer {
                            report(
                                &log,
                                refusal(RefusalSite::Udp, (producer * per_producer + index) as u64),
                            );
                        }
                    });
                }
                start.wait();
                log.close(Duration::from_secs(5));
            });

            let accepted = log.lock_state().enqueued_refusals;
            let records = read_records(dir.path());
            assert_eq!(
                refusals(&records).len() as u64,
                accepted,
                "round {round}: every accepted record must be written"
            );
            assert!(
                suppressions(&records).is_empty(),
                "round {round}: nothing was rate limited or dropped"
            );
            accepted_total += accepted;
        }

        assert!(
            accepted_total > 0,
            "the race must actually exercise the enqueue path"
        );
    }

    #[test]
    fn close_waits_for_a_stalled_producer_and_writes_its_record() {
        let dir = tempfile::tempdir().unwrap();
        let stall = Arc::new(Stall::new());
        let settings = Settings {
            admission_stall: Some(Arc::clone(&stall)),
            ..burst_settings(8)
        };
        let log = NetworkLog::open_with(dir.path(), settings).unwrap();

        // The producer holds the producer lock while parked, which is the window reviewer finding
        // #8 was about: a record that passed admission but has not been enqueued yet.
        let producer = {
            let log = Arc::clone(&log);
            std::thread::spawn(move || report(&log, refusal(RefusalSite::TcpSyn, 1)))
        };
        stall.reached.wait();

        // `close` must take the same lock, so it cannot drain-and-acknowledge while the producer
        // is still between its closed check and its enqueue.
        let closer = {
            let log = Arc::clone(&log);
            std::thread::spawn(move || log.close(Duration::from_secs(5)))
        };
        stall.released.wait();

        producer.join().unwrap();
        closer.join().unwrap();

        assert_eq!(log.lock_state().enqueued_refusals, 1);
        let records = read_records(dir.path());
        assert_eq!(
            refusals(&records).len(),
            1,
            "the record admitted before close must be written"
        );
        assert!(suppressions(&records).is_empty());
    }

    #[test]
    fn close_gives_up_on_a_producer_held_past_the_deadline() {
        let dir = tempfile::tempdir().unwrap();
        let stall = Arc::new(Stall::new());
        let settings = Settings {
            admission_stall: Some(Arc::clone(&stall)),
            ..burst_settings(8)
        };
        let log = NetworkLog::open_with(dir.path(), settings).unwrap();

        // A producer that is parked inside the critical section, i.e. holding the producer lock.
        let producer = {
            let log = Arc::clone(&log);
            std::thread::spawn(move || report(&log, refusal(RefusalSite::Udp, 1)))
        };
        stall.reached.wait();

        // Waiting for that lock is inside the budget: a stalled producer must not hold teardown
        // open for longer than `close` was given.
        let started = Instant::now();
        log.close(Duration::from_millis(50));
        let waited = started.elapsed();
        assert!(
            waited < Duration::from_secs(2),
            "close waited {waited:?} for a producer it was told to wait 50 ms for"
        );

        // The timed-out close did not close the log, so the producer's record still reaches the
        // writer, and a later close drains it.
        stall.released.wait();
        producer.join().unwrap();
        log.close(Duration::from_secs(5));

        let records = read_records(dir.path());
        assert_eq!(refusals(&records).len(), 1);
        assert!(suppressions(&records).is_empty());
    }

    /// A guest-supplied name cannot break a line: whatever it contains, the file holds exactly one
    /// JSON object per record and every name survives the round trip through the file.
    #[test]
    fn hostile_names_round_trip_through_the_file_as_one_line_each() {
        let dir = tempfile::tempdir().unwrap();
        let log = NetworkLog::open_with(dir.path(), burst_settings(16)).unwrap();

        let names = [
            "quote\"and\\slash.example",
            "new\nline.example",
            "carriage\rreturn.example",
            "line\u{2028}separator.example",
            "nul\u{0}byte.example",
            "snowman-\u{2603}.example",
            // 253 bytes in labels of at most 63: the longest a record may carry.
            &[
                "a".repeat(63),
                "b".repeat(63),
                "c".repeat(63),
                "d".repeat(61),
            ]
            .join("."),
        ];
        for (index, name) in names.iter().enumerate() {
            let mut refusal = refusal(RefusalSite::TcpHostname, index as u64);
            refusal.name = Some((*name).to_owned());
            report(&log, refusal);
        }
        log.close(Duration::from_secs(5));

        // One line per record, each parsing as a `NetworkLogRecord`, with the name intact.
        let bytes = std::fs::read(dir.path().join("network.log")).unwrap();
        let text = std::str::from_utf8(&bytes).unwrap();
        assert_eq!(
            text.lines().count(),
            names.len(),
            "a name must never split a line: {text:?}"
        );
        let records = read_records(dir.path());
        assert_eq!(records.len(), names.len());
        for (record, name) in records.iter().zip(names) {
            let NetworkLogEvent::Refusal(refusal) = &record.event else {
                panic!("expected only refusals");
            };
            assert_eq!(refusal.name.as_deref(), Some(name));
        }
    }

    #[test]
    fn timestamps_never_go_backwards_in_the_file() {
        let dir = tempfile::tempdir().unwrap();
        let producers = 8;
        let per_producer = 50;
        // Every record must be written, so the bucket covers the whole burst.
        let log = NetworkLog::open_with(
            dir.path(),
            burst_settings((producers * per_producer) as u32),
        )
        .unwrap();

        // The timestamp is taken by the writer, so interleaved producers cannot enqueue an
        // earlier stamp behind a later one.
        std::thread::scope(|scope| {
            for producer in 0..producers {
                let log = Arc::clone(&log);
                scope.spawn(move || {
                    for index in 0..per_producer {
                        report(
                            &log,
                            refusal(
                                RefusalSite::TcpSyn,
                                (producer * per_producer + index) as u64,
                            ),
                        );
                    }
                });
            }
        });
        log.close(Duration::from_secs(5));

        let records = read_records(dir.path());
        assert_eq!(refusals(&records).len(), producers * per_producer);
        let timestamps: Vec<_> = records.iter().map(|record| record.t).collect();
        assert!(
            timestamps.windows(2).all(|pair| pair[0] <= pair[1]),
            "the file's timestamps must be non-decreasing: {timestamps:?}"
        );
    }
    /// The two phases are not one atomic operation: a refusal the sink admitted just before
    /// `close` and delivered just after it is neither written nor counted.
    ///
    /// This is the boundary the spec draws ("a refusal reported after close is ignored"): the
    /// token was spent, the record was never queued, and a stopped sandbox has no reader for a
    /// suppressed count. The test pins it so the window is a known, tested loss and not an
    /// accident if `record`'s early return is ever moved.
    #[test]
    fn a_refusal_admitted_before_close_and_delivered_after_it_is_dropped() {
        let dir = tempfile::tempdir().unwrap();
        let log = NetworkLog::open_with(dir.path(), burst_settings(8)).unwrap();

        assert!(
            RefusalSink::admits(&*log, RefusalSite::Udp),
            "the bucket admits the first refusal"
        );
        // The close drains what was enqueued and writes the pending suppressed counts.
        log.close(Duration::from_secs(5));
        // The producer delivers the record it was admitted for, too late.
        log.record(refusal(RefusalSite::Udp, 1));

        let records = read_records(dir.path());
        assert!(
            records.is_empty(),
            "a record delivered after close is neither written nor counted: {records:?}"
        );
    }

    /// `record` charges nothing and is not idempotent, so the flood bound is a contract on the
    /// deny sites: exactly one `admits`/`record` pair per refused decision.
    ///
    /// The engine honours it in one place (`refusal::record` calls the pair once), and this test
    /// documents why the pair, not the sink alone, is what bounds the file: a site that delivered
    /// twice would write two lines for one token, and a site that asked twice would spend two
    /// tokens for one line.
    #[test]
    fn the_limiter_bounds_admissions_not_deliveries() {
        let dir = tempfile::tempdir().unwrap();
        let log = NetworkLog::open_with(dir.path(), burst_settings(2)).unwrap();

        // One token, two deliveries: both lines reach the file.
        assert!(RefusalSink::admits(&*log, RefusalSite::TcpSyn));
        log.record(refusal(RefusalSite::TcpSyn, 1));
        log.record(refusal(RefusalSite::TcpSyn, 2));

        // The second token is asked for, and delivered once.
        assert!(RefusalSink::admits(&*log, RefusalSite::TcpSyn));
        log.record(refusal(RefusalSite::TcpSyn, 3));
        assert!(
            !RefusalSink::admits(&*log, RefusalSite::TcpSyn),
            "the bucket holds two tokens, so a third admission finds none"
        );

        log.close(Duration::from_secs(5));

        let records = read_records(dir.path());
        assert_eq!(
            refusals(&records).len(),
            3,
            "every delivered record is written, whatever was admitted: {records:?}"
        );
        let suppressed = suppressions(&records);
        assert_eq!(suppressed.len(), 1);
        assert_eq!(
            suppressed[0].count, 1,
            "only the admission that found no token is suppressed"
        );
    }
}
