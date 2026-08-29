//! Host-side heartbeat reader for idle detection.
//!
//! The guest agent (agentd) writes `/.msb/heartbeat.json` every second.
//! On the host, this file appears in the sandbox runtime directory via the
//! virtiofs mount. The sandbox process reads it to detect idle sandboxes and,
//! separately, to detect an agentd that has stopped responding entirely.

use std::path::{Path, PathBuf};
use std::time::{Duration, Instant};

use serde::Deserialize;

//--------------------------------------------------------------------------------------------------
// Constants
//--------------------------------------------------------------------------------------------------

const HEARTBEAT_FILE: &str = "heartbeat.json";
const HEARTBEAT_TMP_FILE: &str = "heartbeat.tmp";

//--------------------------------------------------------------------------------------------------
// Types
//--------------------------------------------------------------------------------------------------

/// Reads heartbeat data from the host-side runtime directory.
pub struct HeartbeatReader {
    /// Path to the heartbeat.json file on the host.
    path: PathBuf,

    /// Host time when this reader was created.
    created_at: Instant,

    /// Last heartbeat content read successfully.
    last_heartbeat: Option<HeartbeatSnapshot>,

    /// Last heartbeat sequence observed.
    last_heartbeat_seq: Option<u64>,

    /// Host time when the heartbeat sequence last advanced.
    last_heartbeat_seen_at: Option<Instant>,

    /// Last activity sequence observed.
    last_activity_seq: Option<u64>,

    /// Host time when the activity sequence last advanced.
    last_activity_seen_at: Option<Instant>,

    /// Host time when heartbeat staleness first crossed the stale budget.
    ///
    /// `None` means the heartbeat is either fresh or has not yet been
    /// observed stale for a full budget window. Set on the first `check_at`
    /// call that finds `heartbeat_stale_for >= stale_heartbeat_timeout`, and
    /// cleared as soon as a fresh `heartbeat_seq` is observed.
    stale_confirmed_at: Option<Instant>,
}

/// Idle decision derived from the heartbeat stream.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum HeartbeatDecision {
    /// No heartbeat is available yet, but startup grace has not elapsed.
    PendingBoot(HeartbeatStatus),

    /// The sandbox is not idle.
    Active(HeartbeatStatus),

    /// The sandbox is idle.
    Idle(HeartbeatStatus),

    /// agentd stopped producing fresh heartbeat data: either no heartbeat
    /// ever arrived within `boot_grace`, or an established heartbeat has
    /// been stale for at least two `stale_heartbeat_timeout` windows.
    AgentUnresponsive(HeartbeatStatus),
}

/// Snapshot of host-observed heartbeat state used to make a decision.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct HeartbeatStatus {
    /// Last heartbeat sequence observed.
    pub heartbeat_seq: Option<u64>,

    /// Last activity sequence observed.
    pub activity_seq: Option<u64>,

    /// Number of currently active exec sessions.
    pub active_exec_sessions: u32,

    /// Number of currently active filesystem stream sessions.
    pub active_fs_streams: u32,

    /// Number of currently active TCP stream sessions.
    pub active_tcp_streams: u32,

    /// Host-observed age of the latest heartbeat sequence.
    pub heartbeat_stale_for: Option<Duration>,

    /// Host-observed age of the latest activity sequence.
    pub idle_for: Option<Duration>,
}

#[derive(Debug, Clone, Copy, Deserialize)]
struct HeartbeatSnapshot {
    heartbeat_seq: u64,
    activity_seq: u64,
    active_exec_sessions: u32,
    active_fs_streams: u32,
    active_tcp_streams: u32,
}

//--------------------------------------------------------------------------------------------------
// Methods
//--------------------------------------------------------------------------------------------------

impl HeartbeatReader {
    /// Create a new heartbeat reader for the given runtime directory.
    pub fn new(runtime_dir: &Path) -> Self {
        Self::new_at(runtime_dir, Instant::now())
    }

    fn new_at(runtime_dir: &Path, created_at: Instant) -> Self {
        Self {
            path: runtime_dir.join(HEARTBEAT_FILE),
            created_at,
            last_heartbeat: None,
            last_heartbeat_seq: None,
            last_heartbeat_seen_at: None,
            last_activity_seq: None,
            last_activity_seen_at: None,
            stale_confirmed_at: None,
        }
    }

    /// Read and parse the heartbeat file.
    ///
    /// Returns `None` if the file doesn't exist or can't be parsed
    /// (e.g., agentd hasn't started writing yet).
    fn read(&self) -> Option<HeartbeatSnapshot> {
        let content = std::fs::read(&self.path).ok()?;
        serde_json::from_slice(&content).ok()
    }

    /// Decide the sandbox's liveness state from host-observed heartbeat and
    /// activity sequence changes.
    ///
    /// `stale_heartbeat_timeout` is the budget a heartbeat may go without
    /// advancing before it is considered stale. A brief staleness (one
    /// budget window) does not by itself indicate a dead agent — virtiofs
    /// write latency or host load can pause `heartbeat_seq` for seconds
    /// while the guest is still healthy and (if applicable) mid-exec. Only
    /// once staleness has been continuously observed for a *second* budget
    /// window (i.e. confirmed, not just crossed) is the agent declared
    /// unresponsive. `boot_grace` is the analogous budget for a heartbeat
    /// that has never arrived at all.
    pub fn check(
        &mut self,
        idle_timeout: Option<Duration>,
        stale_heartbeat_timeout: Duration,
        boot_grace: Duration,
    ) -> HeartbeatDecision {
        self.check_at(
            Instant::now(),
            idle_timeout,
            stale_heartbeat_timeout,
            boot_grace,
        )
    }

    fn check_at(
        &mut self,
        now: Instant,
        idle_timeout: Option<Duration>,
        stale_heartbeat_timeout: Duration,
        boot_grace: Duration,
    ) -> HeartbeatDecision {
        if let Some(heartbeat) = self.read() {
            self.observe(heartbeat, now);
        }

        let status = self.status(now);

        // No heartbeat seen yet. A guest that never boots at all is
        // reclaimed by this monitor once `boot_grace` elapses; before that,
        // it's still starting up.
        let Some(heartbeat_stale_for) = status.heartbeat_stale_for else {
            if now.duration_since(self.created_at) >= boot_grace {
                return HeartbeatDecision::AgentUnresponsive(status);
            }
            return HeartbeatDecision::PendingBoot(status);
        };

        // Heartbeat has gone stale. Grace for one budget window (transient
        // hiccup); confirmed unresponsive only after a second window with no
        // fresh `heartbeat_seq` in between (`observe` clears
        // `stale_confirmed_at` the moment the sequence advances again).
        if heartbeat_stale_for >= stale_heartbeat_timeout {
            let stale_confirmed_at = *self.stale_confirmed_at.get_or_insert(now);
            if now.duration_since(stale_confirmed_at) >= stale_heartbeat_timeout {
                return HeartbeatDecision::AgentUnresponsive(status);
            }
            return HeartbeatDecision::Active(status);
        }

        self.stale_confirmed_at = None;

        // Active exec sessions are never idle.
        if status.active_exec_sessions > 0 {
            return HeartbeatDecision::Active(status);
        }

        match (idle_timeout, status.idle_for) {
            (Some(idle_timeout), Some(idle_for)) if idle_for >= idle_timeout => {
                HeartbeatDecision::Idle(status)
            }
            _ => HeartbeatDecision::Active(status),
        }
    }

    fn observe(&mut self, heartbeat: HeartbeatSnapshot, now: Instant) {
        if self.last_heartbeat_seq != Some(heartbeat.heartbeat_seq) {
            self.last_heartbeat_seq = Some(heartbeat.heartbeat_seq);
            self.last_heartbeat_seen_at = Some(now);
            self.stale_confirmed_at = None;
        }

        if self.last_activity_seq != Some(heartbeat.activity_seq) {
            self.last_activity_seq = Some(heartbeat.activity_seq);
            self.last_activity_seen_at = Some(now);
        }

        self.last_heartbeat = Some(heartbeat);
    }

    fn status(&self, now: Instant) -> HeartbeatStatus {
        let heartbeat = self.last_heartbeat.as_ref();

        HeartbeatStatus {
            heartbeat_seq: self.last_heartbeat_seq,
            activity_seq: self.last_activity_seq,
            active_exec_sessions: heartbeat.map_or(0, |hb| hb.active_exec_sessions),
            active_fs_streams: heartbeat.map_or(0, |hb| hb.active_fs_streams),
            active_tcp_streams: heartbeat.map_or(0, |hb| hb.active_tcp_streams),
            heartbeat_stale_for: self
                .last_heartbeat_seen_at
                .map(|seen_at| now.duration_since(seen_at)),
            idle_for: self
                .last_activity_seen_at
                .map(|seen_at| now.duration_since(seen_at)),
        }
    }
}

//--------------------------------------------------------------------------------------------------
// Functions
//--------------------------------------------------------------------------------------------------

/// Clear heartbeat files from a previous sandbox run.
pub fn clear_stale(runtime_dir: &Path) -> std::io::Result<()> {
    remove_file_if_exists(&runtime_dir.join(HEARTBEAT_FILE))?;
    remove_file_if_exists(&runtime_dir.join(HEARTBEAT_TMP_FILE))?;
    Ok(())
}

fn remove_file_if_exists(path: &Path) -> std::io::Result<()> {
    match std::fs::remove_file(path) {
        Ok(()) => Ok(()),
        Err(err) if err.kind() == std::io::ErrorKind::NotFound => Ok(()),
        Err(err) => Err(err),
    }
}

//--------------------------------------------------------------------------------------------------
// Tests
//--------------------------------------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use std::time::{Duration, Instant};

    use chrono::Utc;
    use microsandbox_protocol::heartbeat::{ActivityCounters, Heartbeat};

    use super::*;

    /// Production defaults used by `vm.rs`'s heartbeat monitor, mirrored here
    /// so the AC-level test below reads as "what actually ships" rather than
    /// arbitrary numbers.
    const STALE_HEARTBEAT_TIMEOUT: Duration = Duration::from_secs(5);

    #[test]
    fn clear_stale_removes_previous_run_heartbeat_files() {
        let dir = tempfile::tempdir().unwrap();
        let heartbeat_path = dir.path().join(HEARTBEAT_FILE);
        let tmp_path = dir.path().join(HEARTBEAT_TMP_FILE);

        write_heartbeat_file(&heartbeat_path, heartbeat(1, 1, 0));
        std::fs::write(&tmp_path, b"stale").unwrap();

        clear_stale(dir.path()).unwrap();

        assert!(!heartbeat_path.exists());
        assert!(!tmp_path.exists());

        let start = Instant::now();
        let mut reader = HeartbeatReader::new_at(dir.path(), start);
        assert!(matches!(
            reader.check_at(
                start + Duration::from_secs(1),
                Some(Duration::from_secs(60)),
                Duration::from_secs(5),
                Duration::from_secs(2),
            ),
            HeartbeatDecision::PendingBoot(_)
        ));
    }

    #[test]
    fn running_exec_prevents_idle_despite_stale_activity_sequence() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join(HEARTBEAT_FILE);
        let start = Instant::now();
        let mut reader = HeartbeatReader::new_at(dir.path(), start);

        write_heartbeat_file(&path, heartbeat(1, 1, 1));
        assert!(matches!(
            reader.check_at(
                start,
                Some(Duration::from_secs(60)),
                Duration::from_secs(5),
                Duration::ZERO,
            ),
            HeartbeatDecision::Active(_)
        ));

        write_heartbeat_file(&path, heartbeat(2, 1, 1));
        assert!(matches!(
            reader.check_at(
                start + Duration::from_secs(120),
                Some(Duration::from_secs(60)),
                Duration::from_secs(5),
                Duration::ZERO,
            ),
            HeartbeatDecision::Active(_)
        ));
    }

    #[test]
    fn no_exec_is_idle_when_activity_sequence_is_stale() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join(HEARTBEAT_FILE);
        let start = Instant::now();
        let mut reader = HeartbeatReader::new_at(dir.path(), start);

        write_heartbeat_file(&path, heartbeat(1, 1, 0));
        assert!(matches!(
            reader.check_at(
                start,
                Some(Duration::from_secs(60)),
                Duration::from_secs(5),
                Duration::ZERO,
            ),
            HeartbeatDecision::Active(_)
        ));

        write_heartbeat_file(&path, heartbeat(2, 1, 0));
        assert!(matches!(
            reader.check_at(
                start + Duration::from_secs(120),
                Some(Duration::from_secs(60)),
                Duration::from_secs(5),
                Duration::ZERO,
            ),
            HeartbeatDecision::Idle(_)
        ));
    }

    #[test]
    fn no_idle_timeout_keeps_fresh_inactive_sandbox_active() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join(HEARTBEAT_FILE);
        let start = Instant::now();
        let mut reader = HeartbeatReader::new_at(dir.path(), start);

        write_heartbeat_file(&path, heartbeat(1, 1, 0));
        assert!(matches!(
            reader.check_at(start, None, Duration::from_secs(5), Duration::ZERO,),
            HeartbeatDecision::Active(_)
        ));

        write_heartbeat_file(&path, heartbeat(2, 1, 0));
        assert!(matches!(
            reader.check_at(
                start + Duration::from_secs(120),
                None,
                Duration::from_secs(5),
                Duration::ZERO,
            ),
            HeartbeatDecision::Active(_)
        ));
    }

    #[test]
    fn stale_heartbeat_with_running_exec_is_unresponsive_not_active() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join(HEARTBEAT_FILE);
        let start = Instant::now();
        let mut reader = HeartbeatReader::new_at(dir.path(), start);

        write_heartbeat_file(&path, heartbeat(1, 1, 1));
        assert!(matches!(
            reader.check_at(
                start,
                Some(Duration::from_secs(60)),
                Duration::from_secs(5),
                Duration::ZERO,
            ),
            HeartbeatDecision::Active(_)
        ));

        assert!(matches!(
            reader.check_at(
                start + Duration::from_secs(6),
                Some(Duration::from_secs(60)),
                Duration::from_secs(5),
                Duration::ZERO,
            ),
            HeartbeatDecision::Active(_)
        ));

        assert!(matches!(
            reader.check_at(
                start + Duration::from_secs(12),
                Some(Duration::from_secs(60)),
                Duration::from_secs(5),
                Duration::ZERO,
            ),
            HeartbeatDecision::AgentUnresponsive(_)
        ));
    }

    #[test]
    fn missing_heartbeat_becomes_unresponsive_after_boot_grace() {
        let dir = tempfile::tempdir().unwrap();
        let start = Instant::now();
        let mut reader = HeartbeatReader::new_at(dir.path(), start);

        assert!(matches!(
            reader.check_at(
                start + Duration::from_secs(1),
                Some(Duration::from_secs(60)),
                Duration::from_secs(5),
                Duration::from_secs(2),
            ),
            HeartbeatDecision::PendingBoot(_)
        ));

        assert!(matches!(
            reader.check_at(
                start + Duration::from_secs(3),
                Some(Duration::from_secs(60)),
                Duration::from_secs(5),
                Duration::from_secs(2),
            ),
            HeartbeatDecision::AgentUnresponsive(_)
        ));
    }

    /// AC (#41): a brief heartbeat staleness must not kill an active exec
    /// session, but staleness that persists past the confirmed budget must
    /// still be caught. Uses the production `STALE_HEARTBEAT_TIMEOUT` (5s)
    /// so this test reads as the literal acceptance criterion rather than an
    /// arbitrary timing example: pause `heartbeat_seq` for `[S, 2S)` while an
    /// exec session is open — still `Active` (grace) — then let it pass `2S`
    /// with no fresh sequence in between — now `AgentUnresponsive`.
    #[test]
    fn brief_heartbeat_staleness_does_not_kill_active_session() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join(HEARTBEAT_FILE);
        let start = Instant::now();
        let mut reader = HeartbeatReader::new_at(dir.path(), start);
        let boot_grace = Duration::from_secs(180);

        // heartbeat_seq advances once, then the guest pauses writing it
        // entirely (e.g. virtiofs write latency under load) while an exec
        // session stays open the whole time.
        write_heartbeat_file(&path, heartbeat(1, 1, 1));
        assert!(matches!(
            reader.check_at(
                start,
                Some(Duration::from_secs(60)),
                STALE_HEARTBEAT_TIMEOUT,
                boot_grace,
            ),
            HeartbeatDecision::Active(_)
        ));

        // Still within the first stale-budget window: not yet stale.
        let just_inside_first_window = start + STALE_HEARTBEAT_TIMEOUT - Duration::from_millis(1);
        assert!(matches!(
            reader.check_at(
                just_inside_first_window,
                Some(Duration::from_secs(60)),
                STALE_HEARTBEAT_TIMEOUT,
                boot_grace,
            ),
            HeartbeatDecision::Active(_)
        ));

        // Stale for [S, 2S): grace — a busy agent under transient latency,
        // not a dead one.
        let mid_grace_window = start + STALE_HEARTBEAT_TIMEOUT + Duration::from_secs(1);
        assert!(matches!(
            reader.check_at(
                mid_grace_window,
                Some(Duration::from_secs(60)),
                STALE_HEARTBEAT_TIMEOUT,
                boot_grace,
            ),
            HeartbeatDecision::Active(_)
        ));

        // Stale for >= 2S with no fresh sequence in between: confirmed
        // unresponsive.
        let confirmed = start + STALE_HEARTBEAT_TIMEOUT * 2 + Duration::from_secs(1);
        assert!(matches!(
            reader.check_at(
                confirmed,
                Some(Duration::from_secs(60)),
                STALE_HEARTBEAT_TIMEOUT,
                boot_grace,
            ),
            HeartbeatDecision::AgentUnresponsive(_)
        ));
    }

    fn heartbeat(heartbeat_seq: u64, activity_seq: u64, active_exec_sessions: u32) -> Heartbeat {
        Heartbeat {
            heartbeat_seq,
            activity_seq,
            timestamp: Utc::now(),
            last_activity: Utc::now(),
            active_exec_sessions,
            active_fs_streams: 0,
            active_tcp_streams: 0,
            activity_counters: ActivityCounters::default(),
        }
    }

    fn write_heartbeat_file(path: &Path, heartbeat: Heartbeat) {
        std::fs::write(path, serde_json::to_vec(&heartbeat).unwrap()).unwrap();
    }
}
