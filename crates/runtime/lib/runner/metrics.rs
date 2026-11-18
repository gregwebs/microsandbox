//! Sandbox guest metrics sampling and shared-memory publication.
//!
//! Samples come from `msb_krun` VMM/device counters plus the runtime network
//! boundary counters. They are written into the process's reserved slot in the
//! shared-memory registry. The catalog database is not touched on the
//! per-sample path; lifecycle rows still flow through `DbWriteConnection`.

use std::num::NonZero;
#[cfg(unix)]
use std::os::unix::fs::MetadataExt;
#[cfg(windows)]
use std::os::windows::ffi::OsStrExt;
use std::path::Path;
use std::time::{Duration, Instant};

use microsandbox_metrics::{MetricsError, MetricsSlotWriter, SampleWrite};
#[cfg(windows)]
use windows_sys::Win32::{
    Foundation::{GetLastError, NO_ERROR},
    Storage::FileSystem::GetCompressedFileSizeW,
};

//--------------------------------------------------------------------------------------------------
// Constants
//--------------------------------------------------------------------------------------------------

/// Default sampling interval used when the caller does not configure one.
pub const DEFAULT_SAMPLE_INTERVAL: Duration = Duration::from_secs(1);

/// Minimum age after which protected upper filesystem samples are treated as stale.
const MIN_UPPER_FILESYSTEM_STALE_AFTER: Duration = Duration::from_secs(3);

/// Gross-stall backstop for counter/clock pairing of the cheap aggregate read,
/// as a fraction of the CPU window's wall time. Residency is sampled outside
/// this bracket, so a stall during its page walk is invisible to this guard.
/// This is not a tolerance calibrated to normal counter-read latency.
const MAX_PAIRING_SKEW_RATIO: f64 = 0.05;

//--------------------------------------------------------------------------------------------------
// Types
//--------------------------------------------------------------------------------------------------

/// Optional runtime-supplied network byte counters.
pub trait NetworkMetrics: Send + Sync {
    /// Bytes transmitted by the guest into the runtime.
    fn tx_bytes(&self) -> u64;

    /// Bytes received by the guest from the runtime.
    fn rx_bytes(&self) -> u64;
}

impl NetworkMetrics for () {
    fn tx_bytes(&self) -> u64 {
        0
    }

    fn rx_bytes(&self) -> u64 {
        0
    }
}

#[cfg(feature = "net")]
impl NetworkMetrics for microsandbox_network::network::MetricsHandle {
    fn tx_bytes(&self) -> u64 {
        microsandbox_network::network::MetricsHandle::tx_bytes(self)
    }

    fn rx_bytes(&self) -> u64 {
        microsandbox_network::network::MetricsHandle::rx_bytes(self)
    }
}

/// Inputs for [`run_metrics_sampler`].
pub struct MetricsSamplerSpec {
    /// Slot writer owning the sandbox's registry slot.
    pub writer: MetricsSlotWriter,
    /// Catalog sandbox id, used for diagnostics.
    pub sandbox_id: i32,
    /// Runtime process id, used for diagnostics.
    pub pid: u32,
    /// Sampling interval in milliseconds.
    pub interval_ms: NonZero<u64>,
    /// vCPU hotplug ceiling; CPU readings are clamped to `max_cpus * 100`.
    pub max_cpus: u8,
    /// VMM metrics source.
    pub krun_metrics: msb_krun::MetricsHandle,
    /// VM control for live memory size and pause-aware residency sampling.
    pub vm_control: msb_krun::VmControl,
    /// Optional runtime network byte counters.
    pub network_metrics: Option<Box<dyn NetworkMetrics>>,
    /// Host path of the writable upper image, when one exists.
    pub upper_host_path: Option<std::path::PathBuf>,
}

//--------------------------------------------------------------------------------------------------
// Functions
//--------------------------------------------------------------------------------------------------

/// Run the background metrics sampler until the sandbox process exits or
/// the slot is reclaimed.
pub async fn run_metrics_sampler(spec: MetricsSamplerSpec) {
    let MetricsSamplerSpec {
        writer,
        sandbox_id,
        pid,
        interval_ms,
        max_cpus,
        krun_metrics,
        vm_control,
        network_metrics,
        upper_host_path,
    } = spec;
    let interval = Duration::from_millis(interval_ms.get());
    let upper_stale_after = upper_filesystem_stale_after(interval);
    let mut previous = paired_snapshot(&krun_metrics, &vm_control).await;
    let upper_host_path = upper_host_path.as_deref();
    let mut last_cpu_percent: Option<f32> = None;

    match write_sample(
        &writer,
        None,
        &previous.metrics,
        vm_control.memory_state(),
        network_metrics.as_deref(),
        upper_host_path,
        upper_stale_after,
    ) {
        Ok(()) => {}
        Err(SampleWriteError::Generation) => {
            tracing::info!(
                sandbox_id,
                pid,
                "metrics slot reclaimed before first sample; stopping sampler"
            );
            return;
        }
        Err(SampleWriteError::Other(err)) => {
            tracing::warn!(sandbox_id, pid, error = %err, "failed to write initial sandbox metrics");
        }
    }

    loop {
        tokio::time::sleep(interval).await;

        let current = paired_snapshot(&krun_metrics, &vm_control).await;
        let wall_secs = current
            .at
            .checked_duration_since(previous.at)
            .map(|d| d.as_secs_f64())
            .unwrap_or(0.0);
        // Each window's error bound is half of each endpoint's read spread:
        // the true counter read lies somewhere inside its bracket.
        let pairing_skew_secs =
            (previous.uncertainty.as_secs_f64() + current.uncertainty.as_secs_f64()) / 2.0;
        let cpu_percent = if pairing_is_reliable(pairing_skew_secs, wall_secs) {
            let computed = clamp_cpu_percent(
                cpu_percent_from_vcpu_time(
                    current.metrics.cpu.vcpu_time_ns,
                    previous.metrics.cpu.vcpu_time_ns,
                    wall_secs,
                ),
                max_cpus,
            );
            if computed.is_some() {
                last_cpu_percent = computed;
            }
            computed
        } else {
            // The (counter, timestamp) pairing was disturbed — the sampler
            // was descheduled mid-read, so this window's ratio is garbage.
            // Carry the last trustworthy reading instead of publishing it.
            tracing::debug!(
                sandbox_id,
                pairing_skew_secs,
                wall_secs,
                "cpu sample window skewed by descheduling; reusing previous reading"
            );
            last_cpu_percent
        };

        match write_sample(
            &writer,
            cpu_percent,
            &current.metrics,
            vm_control.memory_state(),
            network_metrics.as_deref(),
            upper_host_path,
            upper_stale_after,
        ) {
            Ok(()) => {}
            Err(SampleWriteError::Generation) => {
                tracing::info!(sandbox_id, pid, "metrics slot reclaimed; stopping sampler");
                break;
            }
            Err(SampleWriteError::Other(err)) => {
                tracing::warn!(sandbox_id, pid, error = %err, "failed to write sandbox metrics");
            }
        }

        previous = current;
    }
}

/// A VMM metrics snapshot paired with the wall-clock moment it describes.
///
/// Cheap aggregate counters are bracketed by two `Instant` reads. `at` is
/// their bracket midpoint and `uncertainty` its width; host residency is
/// sampled separately afterward and is not covered by this CPU pairing
/// timestamp. Every cumulative counter in the sample comes from that cheap
/// read; residency and `sampled_at` follow it. Normally the width is
/// microseconds; when the host deschedules this thread mid-read (observed
/// during a concurrent VM boot) it grows to whatever the scheduler stole, and
/// the sample window it bounds must not be trusted for rate math — pairing a
/// multi-second counter delta with a one-second wall window is exactly how
/// a 2-vCPU sandbox once read 592% CPU.
struct PairedSnapshot {
    metrics: msb_krun::VmMetrics,
    at: Instant,
    uncertainty: Duration,
}

async fn paired_snapshot(
    krun_metrics: &msb_krun::MetricsHandle,
    vm_control: &msb_krun::VmControl,
) -> PairedSnapshot {
    // Use the completed VMM boundary, including checkpoint pauses. A transition
    // racing this observation may permit one final scan or defer one until the
    // next tick; it never blocks pause/resume or caches unrelated counters.
    let paused = matches!(
        vm_control.execution_state(),
        Some(msb_krun::VmExecutionState::Paused(_))
    );
    snapshot_off_worker(krun_metrics, paused).await
}

/// Takes the snapshot on the blocking pool: the residency scan can take hundreds of
/// milliseconds on a large guest, and the runtime's few workers carry the agent relays.
async fn snapshot_off_worker(
    krun_metrics: &msb_krun::MetricsHandle,
    paused: bool,
) -> PairedSnapshot {
    let krun_metrics = krun_metrics.clone();
    tokio::task::spawn_blocking(move || snapshot(&krun_metrics, paused))
        .await
        .expect("metrics snapshot task panicked")
}

fn snapshot(krun_metrics: &msb_krun::MetricsHandle, paused: bool) -> PairedSnapshot {
    let before = Instant::now();
    let mut metrics = krun_metrics.aggregate_snapshot_without_host_residency();
    let after = Instant::now();
    let uncertainty = after.saturating_duration_since(before);

    // Residency is a separate observation: its page walk must not inflate
    // the counter/clock pairing error used for CPU rate math.
    if !paused {
        metrics.memory.host_resident_bytes =
            krun_metrics.aggregate_snapshot().memory.host_resident_bytes;
    }

    PairedSnapshot {
        metrics,
        at: before + uncertainty / 2,
        uncertainty,
    }
}

/// Whether the counter/clock pairing error is small enough for the window's
/// vCPU-time-over-wall-time ratio to be meaningful.
fn pairing_is_reliable(pairing_skew_secs: f64, wall_secs: f64) -> bool {
    wall_secs > 0.0 && pairing_skew_secs <= wall_secs * MAX_PAIRING_SKEW_RATIO
}

enum SampleWriteError {
    Generation,
    Other(MetricsError),
}

fn write_sample(
    writer: &MetricsSlotWriter,
    cpu_percent: Option<f32>,
    krun: &msb_krun::VmMetrics,
    memory_state: Option<msb_krun::VmMemoryState>,
    network_metrics: Option<&dyn NetworkMetrics>,
    upper_host_path: Option<&Path>,
    upper_stale_after: Duration,
) -> Result<(), SampleWriteError> {
    let (rx, tx) = match network_metrics {
        Some(m) => (m.rx_bytes(), m.tx_bytes()),
        None => (0, 0),
    };
    let (upper_used_bytes, upper_free_bytes) =
        upper_filesystem_metrics(krun, upper_stale_after, chrono::Utc::now());
    let memory_limit_bytes = live_memory_limit_bytes(memory_state.as_ref());
    let sample = SampleWrite {
        sampled_at: chrono::Utc::now(),
        cpu_percent,
        vcpu_time_ns: krun.cpu.vcpu_time_ns,
        memory_bytes: live_memory_used_bytes(krun, memory_limit_bytes),
        memory_available_bytes: krun.memory.available_bytes,
        memory_host_resident_bytes: krun.memory.host_resident_bytes,
        memory_limit_bytes,
        disk_read_bytes: krun.block.read_bytes,
        disk_write_bytes: krun.block.write_bytes,
        net_rx_bytes: rx,
        net_tx_bytes: tx,
        upper_used_bytes,
        upper_free_bytes,
        upper_host_allocated_bytes: upper_host_allocated_bytes(upper_host_path),
    };
    match writer.write_sample(sample) {
        Ok(()) => Ok(()),
        Err(MetricsError::GenerationMismatch { .. }) => Err(SampleWriteError::Generation),
        Err(other) => Err(SampleWriteError::Other(other)),
    }
}

/// Guest memory currently usable by the VM, boot plus plugged.
fn live_memory_limit_bytes(state: Option<&msb_krun::VmMemoryState>) -> Option<u64> {
    state.map(|state| state.current_mib.saturating_mul(1024 * 1024))
}

/// Guest memory in use against the live limit. Unavailable while the guest's
/// available-memory statistic still exceeds a limit that just shrank.
fn live_memory_used_bytes(krun: &msb_krun::VmMetrics, limit_bytes: Option<u64>) -> Option<u64> {
    match (limit_bytes, krun.memory.available_bytes) {
        (Some(limit), Some(available)) => limit.checked_sub(available),
        _ => krun.memory.used_bytes,
    }
}

fn upper_host_allocated_bytes(path: Option<&Path>) -> Option<u64> {
    let path = path?;
    #[cfg(unix)]
    {
        let metadata = std::fs::metadata(path).ok()?;
        Some(metadata.blocks().saturating_mul(512))
    }
    #[cfg(windows)]
    {
        windows_allocated_file_bytes(path).ok()
    }
}

#[cfg(windows)]
fn windows_allocated_file_bytes(path: &Path) -> std::io::Result<u64> {
    let mut high = 0_u32;
    let path_wide = path
        .as_os_str()
        .encode_wide()
        .chain(std::iter::once(0))
        .collect::<Vec<_>>();
    let low = unsafe { GetCompressedFileSizeW(path_wide.as_ptr(), &mut high) };
    if low == u32::MAX {
        let error = unsafe { GetLastError() };
        if error != NO_ERROR {
            return Err(std::io::Error::from_raw_os_error(error as i32));
        }
    }

    Ok((u64::from(high) << 32) | u64::from(low))
}

fn upper_filesystem_metrics(
    krun: &msb_krun::VmMetrics,
    stale_after: Duration,
    now: chrono::DateTime<chrono::Utc>,
) -> (Option<u64>, Option<u64>) {
    let (Some(used), Some(free), Some(sampled_at_ms)) = (
        krun.filesystem.upper_used_bytes,
        krun.filesystem.upper_free_bytes,
        krun.filesystem.upper_sampled_at_unix_ms,
    ) else {
        return (None, None);
    };

    if upper_filesystem_sample_is_fresh(sampled_at_ms, stale_after, now) {
        (Some(used), Some(free))
    } else {
        (None, None)
    }
}

fn upper_filesystem_sample_is_fresh(
    sampled_at_ms: u64,
    stale_after: Duration,
    now: chrono::DateTime<chrono::Utc>,
) -> bool {
    let now_ms = now.timestamp_millis();
    if now_ms < 0 {
        return false;
    }
    let now_ms = now_ms as u64;
    sampled_at_ms >= now_ms || now_ms.saturating_sub(sampled_at_ms) <= duration_millis(stale_after)
}

fn upper_filesystem_stale_after(interval: Duration) -> Duration {
    let millis = interval
        .as_millis()
        .saturating_mul(3)
        .max(MIN_UPPER_FILESYSTEM_STALE_AFTER.as_millis())
        .min(u128::from(u64::MAX)) as u64;
    Duration::from_millis(millis)
}

fn duration_millis(duration: Duration) -> u64 {
    duration.as_millis().min(u128::from(u64::MAX)) as u64
}

fn cpu_percent_from_vcpu_time(
    current_ns: Option<u64>,
    previous_ns: Option<u64>,
    wall_secs: f64,
) -> Option<f32> {
    match (current_ns, previous_ns) {
        (Some(current_ns), Some(previous_ns)) if wall_secs > 0.0 => {
            let vcpu_delta_ns = current_ns.saturating_sub(previous_ns);
            Some((((vcpu_delta_ns as f64 / 1_000_000_000.0) / wall_secs) * 100.0) as f32)
        }
        _ => None,
    }
}

/// Clamp a CPU reading to the vCPU hotplug ceiling.
///
/// Skewed windows are already rejected by the pairing check; this is the
/// invariant backstop for anything that still slips through — more
/// vCPU-seconds per second than vCPUs exist is physically impossible, so
/// cap at `max_cpus * 100`.
fn clamp_cpu_percent(cpu_percent: Option<f32>, max_cpus: u8) -> Option<f32> {
    let ceiling = f32::from(max_cpus.max(1)) * 100.0;
    cpu_percent.map(|pct| pct.min(ceiling))
}

//--------------------------------------------------------------------------------------------------
// Tests
//--------------------------------------------------------------------------------------------------

#[cfg(test)]
mod tests {
    #[cfg(unix)]
    use std::ffi::CString;

    use std::sync::Arc;
    use std::sync::atomic::{AtomicBool, AtomicU64, Ordering};

    use super::*;
    use microsandbox_metrics::{ActivateSlot, LiveMetric, MetricsRegistry, ReserveSlot};
    use msb_krun_utils::metrics::MetricsWriter;

    fn unique_shm_name(tag: &str) -> String {
        let nanos = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap()
            .as_nanos();
        format!("/msb-rtm-{tag}-{}", nanos & 0xffff_ffff)
    }

    fn cleanup_shm(name: &str) {
        #[cfg(unix)]
        {
            let cname = CString::new(name).unwrap();
            unsafe {
                libc::shm_unlink(cname.as_ptr());
            }
        }

        #[cfg(not(unix))]
        let _ = name;
    }

    /// Cleanup guard for the sampler fixture: aborts the sampler task, stops
    /// and joins the vCPU injector, and unlinks the fixture's own
    /// shared-memory name on assertion failure as well as on success.
    struct SamplerFixture {
        sampler: Option<tokio::task::JoinHandle<()>>,
        stop: Arc<AtomicBool>,
        injector: Option<std::thread::JoinHandle<()>>,
        shm_name: String,
    }

    impl SamplerFixture {
        /// Success-path teardown: await sampler cancellation before the caller
        /// drops the registry, writer and VM handles.
        async fn shutdown(mut self) {
            if let Some(sampler) = self.sampler.take() {
                sampler.abort();
                let error = sampler
                    .await
                    .expect_err("metrics sampler should be cancelled, not finish");
                assert!(error.is_cancelled(), "metrics sampler failed: {error}");
            }
            self.stop.store(true, Ordering::SeqCst);
            if let Some(injector) = self.injector.take() {
                injector.join().expect("vcpu injector thread panicked");
            }
        }
    }

    impl Drop for SamplerFixture {
        fn drop(&mut self) {
            if let Some(sampler) = self.sampler.take() {
                sampler.abort();
            }
            self.stop.store(true, Ordering::SeqCst);
            if let Some(injector) = self.injector.take() {
                let _ = injector.join();
            }
            cleanup_shm(&self.shm_name);
        }
    }

    /// Poll the registry until the sampler publishes a strictly newer slot
    /// timestamp, returning that distinct publication. Bound each wait so a
    /// stalled sampler fails the test instead of hanging it.
    async fn next_publication(
        registry: &MetricsRegistry,
        previous_timestamp: chrono::DateTime<chrono::Utc>,
    ) -> LiveMetric {
        let wait = async {
            loop {
                let mut snapshot = registry.snapshot().unwrap();
                assert!(snapshot.len() <= 1, "fixture owns at most one slot");
                if let Some(row) = snapshot.pop() {
                    assert_eq!(row.sandbox_id, 654);
                    assert_eq!(row.run_id, 1);
                    assert_eq!(row.pid, std::process::id() as i32);
                    assert_eq!(row.name, "slow-cpu");
                    assert_eq!(row.memory_host_resident_bytes, Some(4096));
                    if row.timestamp > previous_timestamp {
                        return row;
                    }
                }
                tokio::time::sleep(Duration::from_millis(2)).await;
            }
        };
        tokio::time::timeout(Duration::from_millis(500), wait)
            .await
            .expect("metrics sampler did not publish a new slot within 500 ms")
    }

    #[test]
    fn cpu_percent_uses_vcpu_seconds_over_wall_seconds() {
        assert_eq!(
            cpu_percent_from_vcpu_time(Some(2_000_000_000), Some(1_000_000_000), 1.0),
            Some(100.0)
        );
        assert_eq!(
            cpu_percent_from_vcpu_time(Some(3_000_000_000), Some(1_000_000_000), 1.0),
            Some(200.0)
        );
        assert_eq!(
            cpu_percent_from_vcpu_time(Some(1_000_000_000), Some(2_000_000_000), 1.0),
            Some(0.0)
        );
        assert_eq!(cpu_percent_from_vcpu_time(None, Some(0), 1.0), None);
        assert_eq!(cpu_percent_from_vcpu_time(Some(0), Some(0), 0.0), None);
    }

    #[test]
    fn cpu_percent_is_clamped_to_the_vcpu_ceiling() {
        // A skewed counter window can report more vCPU-seconds per second
        // than vCPUs exist; the ceiling caps it.
        assert_eq!(clamp_cpu_percent(Some(592.0), 2), Some(200.0));
        assert_eq!(clamp_cpu_percent(Some(197.5), 2), Some(197.5));
        assert_eq!(clamp_cpu_percent(Some(150.0), 0), Some(100.0));
        assert_eq!(clamp_cpu_percent(None, 2), None);
    }

    #[test]
    fn pairing_gate_rejects_descheduled_windows() {
        // Normal operation: microsecond read spread against a 1s window.
        assert!(pairing_is_reliable(0.000_05, 1.0));
        // Right at the tolerance boundary.
        assert!(pairing_is_reliable(0.05, 1.0));
        // A deschedule mid-read (the 592%-on-2-vCPUs incident: ~2s stolen
        // between the counter read and its timestamp) must be rejected.
        assert!(!pairing_is_reliable(1.0, 1.0));
        assert!(!pairing_is_reliable(0.051, 1.0));
        // Degenerate window.
        assert!(!pairing_is_reliable(0.0, 0.0));
    }

    #[test]
    #[cfg(unix)]
    fn upper_host_allocated_bytes_uses_allocated_blocks() {
        let file = tempfile::NamedTempFile::new().unwrap();
        std::fs::write(file.path(), vec![1_u8; 8192]).unwrap();

        let metadata = std::fs::metadata(file.path()).unwrap();

        assert_eq!(
            upper_host_allocated_bytes(Some(file.path())),
            Some(metadata.blocks().saturating_mul(512))
        );
    }

    #[test]
    #[cfg(windows)]
    fn upper_host_allocated_bytes_uses_windows_allocation_size() {
        let file = tempfile::NamedTempFile::new().unwrap();
        std::fs::write(file.path(), vec![1_u8; 8192]).unwrap();

        assert!(upper_host_allocated_bytes(Some(file.path())).is_some_and(|bytes| bytes > 0));
    }

    #[test]
    fn upper_host_allocated_bytes_returns_none_without_path() {
        assert_eq!(upper_host_allocated_bytes(None), None);
    }

    #[test]
    fn write_sample_leaves_upper_filesystem_metrics_empty_when_unavailable() {
        let name = unique_shm_name("upper-empty");
        let registry = MetricsRegistry::open_or_create(&name, 1).unwrap();
        let reserved = registry
            .reserve(ReserveSlot {
                sandbox_id: 7,
                name: "upper-empty",
                memory_limit_bytes: 512 * 1024 * 1024,
            })
            .unwrap();
        let writer = registry
            .activate_writer(ActivateSlot {
                slot: reserved.slot,
                generation: reserved.generation,
                run_id: 9,
                pid: std::process::id() as i32,
                started_at: chrono::Utc::now(),
            })
            .unwrap();
        let krun = msb_krun::VmMetrics::default();

        assert!(
            write_sample(
                &writer,
                None,
                &krun,
                None,
                None,
                None,
                Duration::from_secs(3)
            )
            .is_ok()
        );

        let snapshot = registry.snapshot().unwrap();
        assert_eq!(snapshot.len(), 1);
        assert_eq!(snapshot[0].upper_used_bytes, None);
        assert_eq!(snapshot[0].upper_free_bytes, None);
        cleanup_shm(&name);
    }

    #[test]
    fn write_sample_clears_unavailable_residency_and_restores_it_after_resume() {
        let name = unique_shm_name("residency");
        let registry = MetricsRegistry::open_or_create(&name, 1).unwrap();
        let reserved = registry
            .reserve(ReserveSlot {
                sandbox_id: 10,
                name: "residency",
                memory_limit_bytes: 4096,
            })
            .unwrap();
        let writer = registry
            .activate_writer(ActivateSlot {
                slot: reserved.slot,
                generation: reserved.generation,
                run_id: 11,
                pid: std::process::id() as i32,
                started_at: chrono::Utc::now(),
            })
            .unwrap();
        let mut krun = msb_krun::VmMetrics::default();

        // The pause sample must clear validity, not retain the last value or
        // publish zero resident bytes. Subsequent running samples restore it.
        for residency in [Some(4096), None, None, Some(2048)] {
            krun.memory.host_resident_bytes = residency;
            assert!(
                write_sample(
                    &writer,
                    Some(0.0),
                    &krun,
                    None,
                    None,
                    None,
                    Duration::from_secs(3)
                )
                .is_ok()
            );
            assert_eq!(
                registry.snapshot().unwrap()[0].memory_host_resident_bytes,
                residency
            );
        }
        cleanup_shm(&name);
    }

    #[test]
    fn write_sample_publishes_upper_filesystem_metrics_from_krun() {
        let name = unique_shm_name("upper");
        let registry = MetricsRegistry::open_or_create(&name, 1).unwrap();
        let reserved = registry
            .reserve(ReserveSlot {
                sandbox_id: 8,
                name: "upper",
                memory_limit_bytes: 512 * 1024 * 1024,
            })
            .unwrap();
        let writer = registry
            .activate_writer(ActivateSlot {
                slot: reserved.slot,
                generation: reserved.generation,
                run_id: 10,
                pid: std::process::id() as i32,
                started_at: chrono::Utc::now(),
            })
            .unwrap();
        let now = chrono::Utc::now();
        let krun = msb_krun::VmMetrics {
            filesystem: msb_krun::FilesystemMetrics {
                upper_used_bytes: Some(53_248),
                upper_free_bytes: Some(450_527_232),
                upper_sampled_at_unix_ms: Some(now.timestamp_millis() as u64),
            },
            ..Default::default()
        };

        assert!(
            write_sample(
                &writer,
                None,
                &krun,
                None,
                None,
                None,
                Duration::from_secs(3)
            )
            .is_ok()
        );

        let snapshot = registry.snapshot().unwrap();
        assert_eq!(snapshot.len(), 1);
        assert_eq!(snapshot[0].upper_used_bytes, Some(53_248));
        assert_eq!(snapshot[0].upper_free_bytes, Some(450_527_232));
        cleanup_shm(&name);
    }

    fn memory_state_mib(boot: u64, target: u64, current: u64) -> msb_krun::VmMemoryState {
        msb_krun::VmMemoryState {
            boot_mib: boot,
            target_mib: target,
            current_mib: current,
            max_mib: 32_768,
        }
    }

    fn krun_memory(used: Option<u64>, available: Option<u64>) -> msb_krun::VmMetrics {
        msb_krun::VmMetrics {
            memory: msb_krun::MemoryMetrics {
                used_bytes: used,
                available_bytes: available,
                ..Default::default()
            },
            ..Default::default()
        }
    }

    #[test]
    fn live_memory_limit_follows_plugged_memory() {
        const GIB: u64 = 1024 * 1024 * 1024;

        assert_eq!(live_memory_limit_bytes(None), None);
        assert_eq!(
            live_memory_limit_bytes(Some(&memory_state_mib(8_192, 32_768, 16_384))),
            Some(16 * GIB)
        );
        assert_eq!(
            live_memory_limit_bytes(Some(&memory_state_mib(8_192, 8_192, 16_384))),
            Some(16 * GIB)
        );
        assert_eq!(
            live_memory_limit_bytes(Some(&memory_state_mib(8_192, 32_768, 32_768))),
            Some(32 * GIB)
        );
    }

    #[test]
    fn live_memory_used_bytes_uses_live_total() {
        const GIB: u64 = 1024 * 1024 * 1024;

        let krun = krun_memory(Some(6 * GIB), Some(2 * GIB));
        assert_eq!(
            live_memory_used_bytes(&krun, Some(32 * GIB)),
            Some(30 * GIB)
        );
        assert_eq!(live_memory_used_bytes(&krun, None), Some(6 * GIB));

        let krun = krun_memory(Some(0), Some(4 * GIB));
        assert_eq!(live_memory_used_bytes(&krun, Some(2 * GIB)), None);
    }

    #[test]
    fn write_sample_publishes_live_memory_limit() {
        let name = unique_shm_name("memlim");
        let registry = MetricsRegistry::open_or_create(&name, 1).unwrap();
        let reserved = registry
            .reserve(ReserveSlot {
                sandbox_id: 9,
                name: "memlim",
                memory_limit_bytes: 512 * 1024 * 1024,
            })
            .unwrap();
        let writer = registry
            .activate_writer(ActivateSlot {
                slot: reserved.slot,
                generation: reserved.generation,
                run_id: 11,
                pid: std::process::id() as i32,
                started_at: chrono::Utc::now(),
            })
            .unwrap();
        let krun = krun_memory(Some(256 * 1024 * 1024), Some(256 * 1024 * 1024));

        assert!(
            write_sample(
                &writer,
                None,
                &krun,
                Some(memory_state_mib(512, 1_024, 1_024)),
                None,
                None,
                Duration::from_secs(3),
            )
            .is_ok()
        );

        let snapshot = registry.snapshot().unwrap();
        assert_eq!(snapshot.len(), 1);
        assert_eq!(snapshot[0].memory_limit_bytes, 1_024 * 1024 * 1024);
        assert!(snapshot[0].memory_limit_live);
        assert_eq!(snapshot[0].memory_bytes, 768 * 1024 * 1024);
        assert!(snapshot[0].memory_bytes_reported);

        let krun = krun_memory(Some(0), Some(2_048 * 1024 * 1024));
        assert!(
            write_sample(
                &writer,
                None,
                &krun,
                Some(memory_state_mib(512, 512, 1_024)),
                None,
                None,
                Duration::from_secs(3),
            )
            .is_ok()
        );

        let snapshot = registry.snapshot().unwrap();
        assert_eq!(snapshot[0].memory_bytes, 0);
        assert!(!snapshot[0].memory_bytes_reported);
        assert_eq!(snapshot[0].memory_limit_bytes, 1_024 * 1024 * 1024);
        assert!(snapshot[0].memory_limit_live);

        // The limit remains usable even before guest memory statistics arrive.
        let krun = krun_memory(None, None);
        assert!(
            write_sample(
                &writer,
                None,
                &krun,
                Some(memory_state_mib(512, 2_048, 2_048)),
                None,
                None,
                Duration::from_secs(3),
            )
            .is_ok()
        );

        let snapshot = registry.snapshot().unwrap();
        assert!(!snapshot[0].memory_bytes_reported);
        assert_eq!(snapshot[0].memory_limit_bytes, 2_048 * 1024 * 1024);
        assert!(snapshot[0].memory_limit_live);
        cleanup_shm(&name);
    }

    #[test]
    fn upper_filesystem_metrics_returns_none_for_stale_samples() {
        let now = chrono::Utc::now();
        let stale_sample = (now - chrono::Duration::seconds(10)).timestamp_millis() as u64;
        let krun = msb_krun::VmMetrics {
            filesystem: msb_krun::FilesystemMetrics {
                upper_used_bytes: Some(53_248),
                upper_free_bytes: Some(450_527_232),
                upper_sampled_at_unix_ms: Some(stale_sample),
            },
            ..Default::default()
        };

        assert_eq!(
            upper_filesystem_metrics(&krun, Duration::from_secs(3), now),
            (None, None)
        );
    }

    #[test]
    fn upper_filesystem_stale_after_scales_with_sample_interval() {
        assert_eq!(
            upper_filesystem_stale_after(Duration::from_millis(250)),
            Duration::from_secs(3)
        );
        assert_eq!(
            upper_filesystem_stale_after(Duration::from_secs(10)),
            Duration::from_secs(30)
        );
    }

    /// A residency callback as slow as the sampler's own sleep must not widen
    /// the CPU pairing bracket, and a paused snapshot must skip it entirely.
    /// VM-free and deterministic in its inputs: only the host clock varies.
    ///
    /// The uncertainty assertion is red on the unfixed body (about 40 ms of
    /// bracket against the 1 ms bound). The counter-coherence assertion pins
    /// that every cumulative counter comes from the cheap read; the paused
    /// half is characterisation and passes either way.
    #[test]
    fn snapshot_excludes_slow_residency_from_pairing() {
        // One entry of vCPU time, added by the walk itself: a counter read
        // taken after the walk can see it, the cheap read before it cannot.
        const WALK_ADVANCE_NS: u64 = 1_000_000;

        let writer = MetricsWriter::default();
        let handle = writer.handle();
        writer.add_vcpu_time_ns(0);
        let count = Arc::new(AtomicU64::new(0));
        let callback_count = Arc::clone(&count);
        let callback_writer = writer.clone();
        writer.set_memory_host_resident_sampler(move || {
            callback_count.fetch_add(1, Ordering::SeqCst);
            callback_writer.add_vcpu_time_ns(WALK_ADVANCE_NS);
            std::thread::sleep(Duration::from_millis(40));
            Some(4096)
        });

        // Bracketed by cheap reads, so the walk's own advance is visible to the
        // after-read and to a full read, but not to the cheap read inside.
        let before = handle
            .aggregate_snapshot_without_host_residency()
            .cpu
            .vcpu_time_ns;
        let s = snapshot(&handle, false);
        let after = handle
            .aggregate_snapshot_without_host_residency()
            .cpu
            .vcpu_time_ns;

        assert!(
            s.uncertainty < Duration::from_millis(1),
            "CPU pairing uncertainty must exclude the 40 ms residency scan: {:?}",
            s.uncertainty,
        );
        assert_eq!(before, Some(0), "no vCPU time may precede the walk");
        assert_eq!(
            after,
            Some(WALK_ADVANCE_NS),
            "the residency walk must be the only vCPU time advance",
        );
        assert_eq!(
            s.metrics.cpu.vcpu_time_ns, before,
            "published vCPU time must be the cheap read ({before:?}) taken before \
             the residency walk, not the full read ({after:?}) taken by it",
        );
        assert_eq!(s.metrics.memory.host_resident_bytes, Some(4096));
        assert_eq!(count.load(Ordering::SeqCst), 1);

        let p = snapshot(&handle, true);
        assert_eq!(p.metrics.memory.host_resident_bytes, None);
        assert!(p.uncertainty < Duration::from_millis(1));
        assert_eq!(count.load(Ordering::SeqCst), 1);
    }

    /// End-to-end sampler path against the real registry: a residency callback
    /// costing as long as the sampler's sleep must still publish fresh CPU.
    ///
    /// Red on the unfixed sampler only while `SAMPLER_INTERVAL_MS <
    /// 19 * SLOW_RESIDENCY_MS` (the 40/40 pair here rejects every interval
    /// below 760 ms). The pairing guard rejects a window whose bracket skew
    /// exceeds `MAX_PAIRING_SKEW_RATIO` of it, and the unfixed body puts the
    /// scan inside the bracket, so rejection needs `scan > 0.05 * (interval +
    /// scan)`, i.e. `interval < 19 * scan`. Raise the interval towards the
    /// production 1 s and the unfixed sampler publishes fresh-looking rates:
    /// this test goes green on the bug.
    #[tokio::test(flavor = "multi_thread", worker_threads = 2)]
    async fn slow_residency_sampler_publishes_fresh_cpu_percent() {
        const SLOW_RESIDENCY_MS: u64 = 40;
        const SAMPLER_INTERVAL_MS: u64 = 40;
        const RATE_25: u64 = 250;
        const RATE_75: u64 = 750;
        const RATE_IDLE: u64 = 0;
        const PUBLICATIONS_PER_PHASE: usize = 8;
        const SETTLING_PUBLICATIONS: usize = 3;
        const FIRST_WINDOW_ROWS: usize = 3;

        let shm_name = unique_shm_name("slow-cpu");
        let mut fixture = SamplerFixture {
            sampler: None,
            stop: Arc::new(AtomicBool::new(false)),
            injector: None,
            shm_name: shm_name.clone(),
        };

        let registry = MetricsRegistry::open_or_create(&shm_name, 1).unwrap();
        let reserved = registry
            .reserve(ReserveSlot {
                sandbox_id: 654,
                name: "slow-cpu",
                memory_limit_bytes: 1024 * 1024 * 1024,
            })
            .unwrap();
        let slot_writer = registry
            .activate_writer(ActivateSlot {
                slot: reserved.slot,
                generation: reserved.generation,
                run_id: 1,
                pid: std::process::id() as i32,
                started_at: chrono::Utc::now(),
            })
            .unwrap();
        // Constructs the control handle without booting a VM: `build()` only
        // assembles resources, so `execution_state()` stays `None` (unpaused).
        let vm = msb_krun::VmBuilder::new().build().unwrap();

        let metrics_writer = MetricsWriter::default();
        metrics_writer.add_vcpu_time_ns(0);
        let residency_calls = Arc::new(AtomicU64::new(0));
        let residency_counter = Arc::clone(&residency_calls);
        metrics_writer.set_memory_host_resident_sampler(move || {
            residency_counter.fetch_add(1, Ordering::SeqCst);
            std::thread::sleep(Duration::from_millis(SLOW_RESIDENCY_MS));
            Some(4096)
        });

        let rate_permille = Arc::new(AtomicU64::new(RATE_25));
        fixture.injector = Some({
            let stop = Arc::clone(&fixture.stop);
            let rate_permille = Arc::clone(&rate_permille);
            let vcpu_writer = metrics_writer.clone();
            std::thread::spawn(move || {
                let mut carry = 0_u64;
                let mut last = Instant::now();
                while !stop.load(Ordering::SeqCst) {
                    let now = Instant::now();
                    let elapsed_ns = now.saturating_duration_since(last).as_nanos();
                    last = now;
                    let scaled = elapsed_ns * u128::from(rate_permille.load(Ordering::SeqCst))
                        + u128::from(carry);
                    vcpu_writer.add_vcpu_time_ns(u64::try_from(scaled / 1000).unwrap());
                    carry = u64::try_from(scaled % 1000).unwrap();
                    std::thread::sleep(Duration::from_millis(1));
                }
            })
        });

        fixture.sampler = Some(tokio::spawn(run_metrics_sampler(MetricsSamplerSpec {
            writer: slot_writer,
            sandbox_id: 654,
            pid: std::process::id(),
            interval_ms: NonZero::new(SAMPLER_INTERVAL_MS).unwrap(),
            max_cpus: 2,
            krun_metrics: metrics_writer.handle(),
            vm_control: vm.control_handle(),
            network_metrics: None,
            upper_host_path: None,
        })));

        // The initial publication deliberately carries no computed rate.
        let initial =
            next_publication(&registry, chrono::DateTime::<chrono::Utc>::UNIX_EPOCH).await;
        let mut previous_timestamp = initial.timestamp;
        // Phase 1's opening rows, each kept with the window it reports over.
        let mut first_window: Vec<(LiveMetric, f64)> = Vec::new();
        let mut publications = 1_usize;
        let mut phases: Vec<(f64, Vec<LiveMetric>)> = Vec::new();

        for (phase, (expected, permille)) in [(25.0, RATE_25), (75.0, RATE_75), (0.0, RATE_IDLE)]
            .into_iter()
            .enumerate()
        {
            rate_permille.store(permille, Ordering::SeqCst);
            let mut gathered = Vec::with_capacity(PUBLICATIONS_PER_PHASE);
            for index in 0..PUBLICATIONS_PER_PHASE {
                let row = next_publication(&registry, previous_timestamp).await;
                let window_ms = (row.timestamp - previous_timestamp)
                    .num_nanoseconds()
                    .unwrap() as f64
                    / 1_000_000.0;
                previous_timestamp = row.timestamp;
                publications += 1;
                if phase == 0 && index < FIRST_WINDOW_ROWS {
                    first_window.push((row.clone(), window_ms));
                }
                gathered.push(row);
            }
            gathered.drain(..SETTLING_PUBLICATIONS);
            phases.push((expected, gathered));
        }

        // Phase 1's opening rate windows: this is where a carried initial
        // `None` surfaces as a zero. Checked before the phase oracles so the
        // integration red diagnostic is stable.
        assert_eq!(
            first_window.len(),
            FIRST_WINDOW_ROWS,
            "phase 1 must publish {FIRST_WINDOW_ROWS} opening rate windows",
        );
        for (index, (row, window_ms)) in first_window.iter().enumerate() {
            // The budget below is only sound if the window it is derived from
            // really spans at least one sampler interval.
            assert!(
                *window_ms >= SAMPLER_INTERVAL_MS as f64,
                "phase 1 row {index} reports over {window_ms:.1} ms, less than one {SAMPLER_INTERVAL_MS} ms sampler interval; no lag budget can be derived from it",
            );
            // error ~= rate * lag / window, so at 25 % demand a 10 pp allowance
            // buys 0.10 * window / 0.25 of differential counter lag.
            let lag_budget_ms = (10.0 / 100.0) * window_ms / 0.25;
            assert!(
                (f64::from(row.cpu_percent) - 25.0).abs() <= 10.0,
                "phase 1 row {index} must carry a freshly computed rate: expected 25.0% +/-10 pp, got {}; 0.0 means no rate was published (an absent CPU value is encoded as 0.0), which is what a carried initial None looks like, not a computed zero; measured rate window={window_ms:.1} ms, derived differential-lag budget={lag_budget_ms:.1} ms (0.10 * window / 0.25 rate fraction)",
                row.cpu_percent,
            );
        }

        // Primary counter oracle: cumulative-counter agreement, which the
        // pairing guard does not affect. It re-derives the rate from the
        // counter the injector wrote, so it sees the counter path, not the
        // published rate. Only *variation* in the publication lag between the
        // two endpoints charges the budget below; a constant lag cancels in
        // the difference.
        for (expected, rows) in &phases {
            let a = &rows[0];
            let b = &rows[rows.len() - 1];
            let delta_ns = b.vcpu_time_ns.checked_sub(a.vcpu_time_ns).unwrap();
            let wall_ns = (b.timestamp - a.timestamp).num_nanoseconds().unwrap();
            assert!(wall_ns > 0);
            if *expected > 0.0 {
                assert!(
                    delta_ns > 0,
                    "phase {expected:.1}% must advance vcpu_time_ns"
                );
            }
            let derived = 100.0 * delta_ns as f64 / wall_ns as f64;
            let span_ms = wall_ns as f64 / 1_000_000.0;
            let cadence_ms = (SAMPLER_INTERVAL_MS + SLOW_RESIDENCY_MS) as f64;
            let lag_budget_ms = (10.0 / 100.0) * span_ms;
            let diagnosis = if span_ms < 3.0 * cadence_ms {
                "oracle too tight: the retained span covers fewer than three fixture cadences"
            } else {
                "sampler disagrees with injected demand, or the publication lag varied between the endpoints by more than this budget"
            };
            assert!(
                (derived - *expected).abs() <= 10.0,
                "{diagnosis}: expected {expected:.1}% +/-10 pp, got {derived:.1}%; measured retained span={span_ms:.1} ms ({:.1} fixture cadences of {cadence_ms:.0} ms); conservative differential-lag budget={lag_budget_ms:.1} ms (10/100 * span); only variation in the lag is charged to it, a constant lag cancels between endpoints",
                span_ms / cadence_ms,
            );
            // Secondary, phase-level freshness evidence: at least one retained
            // row, not every row, must reflect this phase's demand.
            assert!(
                rows.iter()
                    .any(|row| (f64::from(row.cpu_percent) - expected).abs() <= 10.0),
                "no retained CPU row matches phase demand {expected:.1}% +/-10 pp",
            );
        }

        // At least one residency callback per publication; the injector
        // advances the shared counter, so the callback count is a lower bound.
        // A sampler that scanned twice per tick also passes: this pins that the
        // scan has not stopped, not that it runs once.
        let callbacks = residency_calls.load(Ordering::SeqCst);
        assert!(
            callbacks >= publications as u64,
            "{publications} publications but {callbacks} residency callbacks",
        );

        fixture.shutdown().await;
    }

    /// Characterisation of the existing pause contract, not the #654
    /// regression: a paused snapshot omits residency without a callback.
    ///
    /// Both halves pass on the unfixed body, so this is not a red receipt. It
    /// fails once the `if !paused` check is dropped: the paused half then reads
    /// `Some(4096)` and the callback count reaches two.
    #[test]
    fn snapshot_skips_residency_when_paused() {
        let writer = MetricsWriter::default();
        let handle = writer.handle();
        let count = Arc::new(AtomicU64::new(0));
        let callback_count = Arc::clone(&count);
        writer.set_memory_host_resident_sampler(move || {
            callback_count.fetch_add(1, Ordering::SeqCst);
            Some(4096)
        });
        writer.add_vcpu_time_ns(42);

        let running = snapshot(&handle, false);
        assert_eq!(running.metrics.memory.host_resident_bytes, Some(4096));
        assert_eq!(count.load(Ordering::SeqCst), 1);

        writer.add_vcpu_time_ns(42);
        let paused = snapshot(&handle, true);
        assert_eq!(paused.metrics.memory.host_resident_bytes, None);
        assert_eq!(paused.metrics.cpu.vcpu_time_ns, Some(84));
        assert_eq!(count.load(Ordering::SeqCst), 1);
    }

    #[tokio::test]
    async fn residency_sampling_runs_off_the_async_executor_thread() {
        let (sampling_thread, sampled_thread) = std::sync::mpsc::channel();
        let writer = MetricsWriter::default();
        writer.set_memory_host_resident_sampler(move || {
            sampling_thread.send(std::thread::current().id()).unwrap();
            Some(0)
        });
        let krun_metrics = writer.handle();
        let executor_thread = std::thread::current().id();

        let snapshot = snapshot_off_worker(&krun_metrics, false).await;

        assert_ne!(sampled_thread.try_recv().unwrap(), executor_thread);
        assert_eq!(snapshot.metrics.memory.host_resident_bytes, Some(0));
    }
}
