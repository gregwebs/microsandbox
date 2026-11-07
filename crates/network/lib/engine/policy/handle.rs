//! Live-swappable view of the tenant network policy.
//!
//! Readers take the current snapshot at each decision; a replace affects decisions made after it
//! returns. Holders of an earlier snapshot keep it, which is how open connections keep the
//! revision they were admitted under. The platform floor is never stored here.
//!
//! A [`PolicySnapshot`] is the only way a decision and the revision it reports can be guaranteed
//! to agree: the policy and its revision are read as one pair under the same lock.

use std::ops::Deref;
use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::{Arc, RwLock};

use crate::policy::NetworkPolicy;

//--------------------------------------------------------------------------------------------------
// Constants
//--------------------------------------------------------------------------------------------------

/// Revision of the launch-time policy in every runtime process.
pub const INITIAL_NETWORK_POLICY_REVISION: u64 = 1;

//--------------------------------------------------------------------------------------------------
// Types
//--------------------------------------------------------------------------------------------------

/// Shared handle to the tenant policy consumed by the network stack. Cloning is cheap.
#[derive(Clone)]
pub struct NetworkPolicyHandle {
    inner: Arc<Shared>,
}

struct Shared {
    current: RwLock<Arc<NetworkPolicy>>,
    /// Written only while `current` is write-locked, so a reader holding the read lock sees the
    /// revision that belongs to the policy it read.
    revision: AtomicU64,
    /// How many times a [`PolicyCursor`] took the read lock to refresh. Test-only: it exists so a
    /// test can tell a reused snapshot from a re-read one, which `Arc::ptr_eq` alone cannot.
    #[cfg(test)]
    refreshes: std::sync::atomic::AtomicUsize,
}

/// A tenant policy paired with the revision it was published under.
///
/// The pair is read under one lock, so a decision evaluated against this policy can always report
/// the revision it was actually decided under. Cloning is cheap: both fields are copied.
#[derive(Clone)]
pub struct PolicySnapshot {
    policy: Arc<NetworkPolicy>,
    revision: u64,
}

/// The policy revision counter cannot advance.
#[derive(Debug, Clone, Copy, PartialEq, Eq, thiserror::Error)]
#[error("network policy revision is exhausted")]
pub struct NetworkPolicyRevisionExhausted;

/// Hot-loop reader that re-reads the snapshot only after a replace.
pub(crate) struct PolicyCursor {
    handle: NetworkPolicyHandle,
    snapshot: PolicySnapshot,
}

//--------------------------------------------------------------------------------------------------
// Methods
//--------------------------------------------------------------------------------------------------

impl NetworkPolicyHandle {
    /// Create a handle over the launch policy at [`INITIAL_NETWORK_POLICY_REVISION`].
    pub fn new(policy: NetworkPolicy) -> Self {
        Self {
            inner: Arc::new(Shared {
                current: RwLock::new(Arc::new(policy)),
                revision: AtomicU64::new(INITIAL_NETWORK_POLICY_REVISION),
                #[cfg(test)]
                refreshes: std::sync::atomic::AtomicUsize::new(0),
            }),
        }
    }

    /// Load the current policy alone.
    ///
    /// `load()` and [`revision`](Self::revision) are separate reads: a replace between them
    /// yields an old policy with a new revision. Use [`snapshot`](Self::snapshot) wherever a
    /// decision and the revision it reports must agree.
    pub fn load(&self) -> Arc<NetworkPolicy> {
        self.inner
            .current
            .read()
            .expect("network policy lock poisoned")
            .clone()
    }

    /// Revision of the current policy.
    pub fn revision(&self) -> u64 {
        self.inner.revision.load(Ordering::Acquire)
    }

    /// Load the current policy and its revision as one pair, under the read lock.
    ///
    /// This is the only paired read: a decision evaluated against the returned policy reports
    /// the returned revision, whatever a concurrent replace does.
    pub fn snapshot(&self) -> PolicySnapshot {
        let current = self
            .inner
            .current
            .read()
            .expect("network policy lock poisoned");
        let policy = current.clone();
        // Read the revision while the read lock is held: `replace` publishes the pair under the
        // write lock, so this pair is internally consistent.
        let revision = self.inner.revision.load(Ordering::Relaxed);
        drop(current);

        PolicySnapshot { policy, revision }
    }

    /// Replace the whole tenant policy and return its new revision. On error nothing changes.
    ///
    /// The incoming snapshot is allocated before the lock is taken, and the displaced `Arc` is
    /// dropped after it is released, so the write critical section stays short.
    pub fn replace(&self, policy: NetworkPolicy) -> Result<u64, NetworkPolicyRevisionExhausted> {
        let next = Arc::new(policy);
        let mut current = self
            .inner
            .current
            .write()
            .expect("network policy lock poisoned");
        let revision = self
            .inner
            .revision
            .load(Ordering::Relaxed)
            .checked_add(1)
            .ok_or(NetworkPolicyRevisionExhausted)?;

        let displaced = std::mem::replace(&mut *current, next);
        self.inner.revision.store(revision, Ordering::Release);
        drop(current);
        drop(displaced);
        Ok(revision)
    }

    /// Snapshot for a hot loop that must not take the read lock per iteration.
    ///
    /// The cursor keeps the newest [`PolicySnapshot`], so a decision it makes and the revision
    /// it reports can never disagree.
    pub(crate) fn cursor(&self) -> PolicyCursor {
        PolicyCursor {
            handle: self.clone(),
            snapshot: self.snapshot(),
        }
    }

    #[cfg(test)]
    pub(crate) fn with_revision(policy: NetworkPolicy, revision: u64) -> Self {
        Self {
            inner: Arc::new(Shared {
                current: RwLock::new(Arc::new(policy)),
                revision: AtomicU64::new(revision),
                #[cfg(test)]
                refreshes: std::sync::atomic::AtomicUsize::new(0),
            }),
        }
    }
}

impl PolicySnapshot {
    /// Pair a policy this caller owns with the revision it was published under.
    ///
    /// This is for a caller that already holds both halves and is stating them, not for reading
    /// the live policy: a decision that must report the revision in force obtains its pair from
    /// [`NetworkPolicyHandle::snapshot`], which is the only read that guarantees the pair. Use
    /// this to build a [`FlowPolicy::Admitted`](crate::tcp::connection::FlowPolicy) for a flow
    /// the caller authorized itself, and in tests.
    pub fn new(policy: Arc<NetworkPolicy>, revision: u64) -> Self {
        Self { policy, revision }
    }

    /// A fixed policy at [`INITIAL_NETWORK_POLICY_REVISION`].
    ///
    /// See [`PolicySnapshot::new`] for when this is the right constructor.
    pub fn initial(policy: Arc<NetworkPolicy>) -> Self {
        Self::new(policy, INITIAL_NETWORK_POLICY_REVISION)
    }

    /// The policy.
    pub fn policy(&self) -> &Arc<NetworkPolicy> {
        &self.policy
    }

    /// The revision `policy` was published under.
    pub fn revision(&self) -> u64 {
        self.revision
    }
}

impl PolicyCursor {
    /// The newest snapshot; costs one atomic load when nothing changed.
    pub(crate) fn current(&mut self) -> &PolicySnapshot {
        if self.handle.inner.revision.load(Ordering::Acquire) != self.snapshot.revision {
            #[cfg(test)]
            self.handle.inner.refreshes.fetch_add(1, Ordering::Relaxed);
            // One locked pair read, so the refreshed policy and its revision belong together.
            self.snapshot = self.handle.snapshot();
        }
        &self.snapshot
    }
}

//--------------------------------------------------------------------------------------------------
// Trait Implementations
//--------------------------------------------------------------------------------------------------

impl Deref for PolicySnapshot {
    type Target = NetworkPolicy;

    fn deref(&self) -> &Self::Target {
        self.policy.as_ref()
    }
}

//--------------------------------------------------------------------------------------------------
// Tests
//--------------------------------------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use std::sync::Barrier;
    use std::sync::atomic::AtomicBool;
    use std::thread;
    use std::time::{Duration, Instant};

    use super::*;
    use crate::policy::{Action, Destination, Direction, Rule};

    /// A policy whose rule count encodes the revision it belongs to.
    fn policy_of_len(len: usize) -> NetworkPolicy {
        NetworkPolicy {
            default_egress: Action::Deny,
            default_ingress: Action::Allow,
            rules: (0..len)
                .map(|_| Rule {
                    direction: Direction::Any,
                    destination: Destination::Any,
                    protocols: Vec::new(),
                    ports: Vec::new(),
                    action: Action::Allow,
                })
                .collect(),
        }
    }

    #[test]
    fn initial_revision_is_one_and_replaces_advance_it() {
        let handle = NetworkPolicyHandle::new(policy_of_len(1));

        assert_eq!(handle.revision(), INITIAL_NETWORK_POLICY_REVISION);
        assert_eq!(handle.replace(policy_of_len(2)), Ok(2));
        assert_eq!(handle.replace(policy_of_len(3)), Ok(3));
        assert_eq!(handle.revision(), 3);
    }

    #[test]
    fn load_returns_the_new_policy_and_keeps_earlier_snapshots() {
        let handle = NetworkPolicyHandle::new(policy_of_len(1));
        let before = handle.load();

        handle.replace(policy_of_len(2)).unwrap();

        assert_eq!(before.rules.len(), 1, "a loaded snapshot is retained");
        assert_eq!(handle.load().rules.len(), 2);
    }

    #[test]
    fn snapshot_returns_the_new_policy_and_revision_after_a_replace() {
        let handle = NetworkPolicyHandle::new(policy_of_len(1));
        let before = handle.snapshot();

        handle.replace(policy_of_len(2)).unwrap();

        assert_eq!(before.rules.len(), 1, "an earlier snapshot is retained");
        assert_eq!(before.revision(), INITIAL_NETWORK_POLICY_REVISION);
        let after = handle.snapshot();
        assert_eq!(after.rules.len(), 2);
        assert_eq!(after.revision(), 2);
    }

    #[test]
    fn snapshot_pairs_a_policy_with_the_revision_it_reports() {
        let policy = Arc::new(policy_of_len(3));
        let snapshot = PolicySnapshot::new(Arc::clone(&policy), 7);

        assert!(Arc::ptr_eq(snapshot.policy(), &policy));
        assert_eq!(snapshot.revision(), 7);
        // `Deref` lets a caller keep using the policy where `&NetworkPolicy` is expected.
        assert_eq!(snapshot.rules.len(), 3);

        let initial = PolicySnapshot::initial(Arc::clone(&policy));
        assert_eq!(initial.revision(), INITIAL_NETWORK_POLICY_REVISION);
    }

    #[test]
    fn cursor_reads_the_new_policy_after_a_replace() {
        let handle = NetworkPolicyHandle::new(policy_of_len(1));
        let mut cursor = handle.cursor();
        assert_eq!(cursor.current().rules.len(), 1);
        assert_eq!(cursor.current().revision(), INITIAL_NETWORK_POLICY_REVISION);

        handle.replace(policy_of_len(2)).unwrap();

        assert_eq!(cursor.current().rules.len(), 2);
        assert_eq!(cursor.current().revision(), 2);
    }

    #[test]
    fn cursor_reuses_the_cached_snapshot_without_a_replace() {
        let handle = NetworkPolicyHandle::new(policy_of_len(1));
        let mut cursor = handle.cursor();
        let refreshes = || handle.inner.refreshes.load(Ordering::Relaxed);

        let before = refreshes();
        let first = cursor.current().policy() as *const Arc<NetworkPolicy>;
        for _ in 0..64 {
            assert_eq!(cursor.current().rules.len(), 1);
        }
        let second = cursor.current().policy() as *const Arc<NetworkPolicy>;

        assert_eq!(first, second);
        assert!(Arc::ptr_eq(cursor.snapshot.policy(), &handle.load()));
        // `ptr_eq` alone cannot see a `current()` that re-reads and re-wraps the same policy: the
        // refresh counter is what proves no read lock was taken.
        assert_eq!(
            refreshes(),
            before,
            "the cursor refreshed its snapshot with no replace"
        );
    }

    /// Release the readers on any exit, including a panic, so a failed assertion fails the test
    /// instead of leaving `thread::scope` waiting on readers that will never stop.
    struct ReleaseReaders<'a>(&'a AtomicBool);

    impl Drop for ReleaseReaders<'_> {
        fn drop(&mut self) {
            self.0.store(true, Ordering::Relaxed);
        }
    }

    /// What one reader saw. The writer watches `max_revision` so every reader reads while it is
    /// still publishing, and `saw_non_final` is what the final assertion reads.
    #[derive(Default)]
    struct Observation {
        max_revision: AtomicU64,
        saw_non_final: AtomicBool,
    }

    #[test]
    fn cursor_never_pairs_a_policy_with_the_wrong_revision() {
        const REPLACES: usize = 200;
        const FINAL_REVISION: u64 = REPLACES as u64 + 1;
        const READERS: usize = 4;
        /// Nothing here may spin forever if a reader is never scheduled.
        const OBSERVATION_DEADLINE: Duration = Duration::from_secs(10);

        let handle = NetworkPolicyHandle::new(policy_of_len(1));
        let done = Arc::new(AtomicBool::new(false));
        // Readers may not start until every thread is ready, so the writer cannot finish before
        // the first read.
        let ready = Arc::new(Barrier::new(READERS + 1));
        let observations: Vec<Arc<Observation>> = (0..READERS)
            .map(|_| Arc::new(Observation::default()))
            .collect();

        thread::scope(|scope| {
            for observation in &observations {
                let handle = handle.clone();
                let done = Arc::clone(&done);
                let ready = Arc::clone(&ready);
                let observation = Arc::clone(observation);
                scope.spawn(move || {
                    let mut cursor = handle.cursor();
                    let mut last_revision = 0;
                    ready.wait();
                    while !done.load(Ordering::Relaxed) {
                        // Pairs come from the cursor: the policy and the revision it reports must
                        // describe the same snapshot.
                        // One cursor read per iteration, so the policy and the revision come
                        // from the same snapshot.
                        let current = cursor.current();
                        let len = current.rules.len() as u64;
                        let revision = current.revision();
                        assert_eq!(len, revision, "cursor paired a stale policy");

                        // Monotonic across snapshots observed by one reader.
                        assert!(
                            revision >= last_revision,
                            "revision went backwards: {} then {}",
                            last_revision,
                            revision
                        );
                        last_revision = revision;

                        // Record what this read saw. A revision below the last one the writer
                        // publishes can only be observed while the writer is still publishing,
                        // so `saw_non_final` is the read/write overlap the test requires.
                        if revision < FINAL_REVISION {
                            observation.saw_non_final.store(true, Ordering::Relaxed);
                        }
                        observation
                            .max_revision
                            .fetch_max(revision, Ordering::Relaxed);

                        // `load()` is a separate call by design; its policy must be some snapshot
                        // the writer actually published.
                        let loaded = handle.load().rules.len();
                        assert!((1..=REPLACES + 1).contains(&loaded));
                    }
                });
            }

            let writer_handle = handle.clone();
            let observed_by = observations.clone();
            let writer_ready = Arc::clone(&ready);
            scope.spawn(move || {
                let _release = ReleaseReaders(&done);
                writer_ready.wait();
                assert_eq!(writer_handle.replace(policy_of_len(2)), Ok(2));
                // Hold the remaining replaces back until every reader has observed the first one.
                // Any read from here on therefore sees a revision the writer has not finished
                // publishing, whatever the scheduler does with 200 publishes.
                let deadline = Instant::now() + OBSERVATION_DEADLINE;
                while !observed_by
                    .iter()
                    .all(|observation| observation.max_revision.load(Ordering::Relaxed) >= 2)
                {
                    assert!(
                        Instant::now() < deadline,
                        "a reader never observed a replace while the writer was active"
                    );
                    std::thread::yield_now();
                }
                for revision in 3..=REPLACES + 1 {
                    assert_eq!(
                        writer_handle.replace(policy_of_len(revision)),
                        Ok(revision as u64)
                    );
                }
            });
        });

        let highest: Vec<u64> = observations
            .iter()
            .map(|observation| observation.max_revision.load(Ordering::Relaxed))
            .collect();
        assert!(
            observations
                .iter()
                .any(|observation| observation.saw_non_final.load(Ordering::Relaxed)),
            "no reader observed a non-final revision, so no read overlapped the writer: {highest:?}"
        );
    }

    /// The same read/write overlap as the cursor test, but through [`NetworkPolicyHandle::snapshot`]:
    /// a caller that takes one snapshot must never see one revision's policy paired with another
    /// revision's number, which is what a refusal record would report.
    #[test]
    fn snapshot_pairs_policy_and_revision_under_replaces() {
        const REPLACES: usize = 200;
        const FINAL_REVISION: u64 = REPLACES as u64 + 1;
        const READERS: usize = 4;
        /// Nothing here may spin forever if a reader is never scheduled.
        const OBSERVATION_DEADLINE: Duration = Duration::from_secs(10);

        let handle = NetworkPolicyHandle::new(policy_of_len(1));
        let done = Arc::new(AtomicBool::new(false));
        let ready = Arc::new(Barrier::new(READERS + 1));
        let observations: Vec<Arc<Observation>> = (0..READERS)
            .map(|_| Arc::new(Observation::default()))
            .collect();

        thread::scope(|scope| {
            for observation in &observations {
                let handle = handle.clone();
                let done = Arc::clone(&done);
                let ready = Arc::clone(&ready);
                let observation = Arc::clone(observation);
                scope.spawn(move || {
                    let mut last_revision = 0;
                    ready.wait();
                    while !done.load(Ordering::Relaxed) {
                        // One paired read, so the evaluated policy and the reported revision
                        // always describe the same publication.
                        let snapshot = handle.snapshot();
                        let len = snapshot.rules.len() as u64;
                        let revision = snapshot.revision();
                        assert_eq!(len, revision, "snapshot paired a stale policy");
                        assert!(
                            revision >= last_revision,
                            "revision went backwards: {} then {}",
                            last_revision,
                            revision
                        );
                        last_revision = revision;

                        if revision < FINAL_REVISION {
                            observation.saw_non_final.store(true, Ordering::Relaxed);
                        }
                        observation
                            .max_revision
                            .fetch_max(revision, Ordering::Relaxed);
                    }
                });
            }

            let writer_handle = handle.clone();
            let observed_by = observations.clone();
            let writer_ready = Arc::clone(&ready);
            scope.spawn(move || {
                let _release = ReleaseReaders(&done);
                writer_ready.wait();
                assert_eq!(writer_handle.replace(policy_of_len(2)), Ok(2));
                // Hold the remaining replaces back until every reader has observed the first one,
                // so the reads provably overlap the publishes.
                let deadline = Instant::now() + OBSERVATION_DEADLINE;
                while !observed_by
                    .iter()
                    .all(|observation| observation.max_revision.load(Ordering::Relaxed) >= 2)
                {
                    assert!(
                        Instant::now() < deadline,
                        "a reader never observed a replace while the writer was active"
                    );
                    std::thread::yield_now();
                }
                for revision in 3..=REPLACES + 1 {
                    assert_eq!(
                        writer_handle.replace(policy_of_len(revision)),
                        Ok(revision as u64)
                    );
                }
            });
        });

        let highest: Vec<u64> = observations
            .iter()
            .map(|observation| observation.max_revision.load(Ordering::Relaxed))
            .collect();
        assert!(
            observations
                .iter()
                .any(|observation| observation.saw_non_final.load(Ordering::Relaxed)),
            "no reader observed a non-final revision, so no read overlapped the writer: {highest:?}"
        );
    }

    #[test]
    fn exhausted_revision_leaves_the_policy_and_revision_in_place() {
        let handle = NetworkPolicyHandle::with_revision(policy_of_len(1), u64::MAX);

        assert_eq!(
            handle.replace(policy_of_len(2)),
            Err(NetworkPolicyRevisionExhausted)
        );
        assert_eq!(handle.revision(), u64::MAX);
        assert_eq!(handle.load().rules.len(), 1);
    }
}
