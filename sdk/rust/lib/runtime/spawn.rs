//! Spawning the sandbox process.
//!
//! [`spawn_sandbox`] assembles CLI arguments from [`SandboxConfig`],
//! fork+execs `msb sandbox`, and reads the startup JSON to obtain the
//! sandbox process PID. The sandbox process runs the VMM and agent relay
//! internally.

#[cfg(windows)]
use std::fmt::Write as _;
#[cfg(unix)]
use std::os::fd::AsRawFd;
#[cfg(unix)]
use std::os::fd::{FromRawFd, OwnedFd};
#[cfg(unix)]
use std::os::unix::ffi::OsStrExt;
#[cfg(unix)]
use std::os::unix::fs::{DirBuilderExt, MetadataExt, PermissionsExt};
#[cfg(windows)]
use std::os::windows::fs::OpenOptionsExt;
#[cfg(windows)]
use std::os::windows::io::AsRawHandle;
use std::{
    collections::{BTreeMap, BTreeSet, HashMap},
    ffi::{OsStr, OsString},
    fs::File,
    io::{Seek, SeekFrom, Write as IoWrite},
    path::{Path, PathBuf},
    process::Stdio,
};

#[cfg(windows)]
use rand::Rng;
use rand::RngExt;
use sea_orm::{ColumnTrait, EntityTrait, QueryFilter, Set};
use serde::Deserialize;
use sha2::{Digest as Sha2Digest, Sha256};
use tempfile::TempDir;
#[cfg(windows)]
use tokio::net::windows::named_pipe::{NamedPipeServer, PipeMode, ServerOptions};
use tokio::{
    io::{AsyncBufRead, AsyncBufReadExt},
    process::Command,
};
#[cfg(windows)]
use windows_sys::Win32::Foundation::{
    GetHandleInformation, HANDLE, HANDLE_FLAG_INHERIT, INVALID_HANDLE_VALUE, SetHandleInformation,
};
#[cfg(windows)]
use windows_sys::Win32::System::Console::{
    GetStdHandle, STD_ERROR_HANDLE, STD_INPUT_HANDLE, STD_OUTPUT_HANDLE,
};
#[cfg(windows)]
use windows_sys::Win32::System::Pipes::GetNamedPipeServerProcessId;
#[cfg(windows)]
use windows_sys::Win32::System::Threading::{
    CREATE_BREAKAWAY_FROM_JOB, CREATE_NEW_PROCESS_GROUP, DETACHED_PROCESS,
};

#[cfg(any(target_os = "linux", target_os = "macos"))]
use microsandbox_filesystem::nofollow::{CleanupOutcome, CopyError, CopySourceError, StageError};
#[cfg(all(test, any(target_os = "linux", target_os = "macos")))]
use microsandbox_filesystem::nofollow::{CopyFaults, LinkFaults, StageOverrides};
use microsandbox_image::{Digest, GlobalCache};
use microsandbox_metrics::{MetricsRegistry, ReserveSlot, SlotReservation};
use microsandbox_protocol::{
    bootstrap::{
        BootstrapBlockRoot, BootstrapBlockRootUpper, BootstrapDirMount, BootstrapDiskMount,
        BootstrapEnvVar, BootstrapFileMount, BootstrapHandoffInit, BootstrapMountFlags,
        BootstrapSecurityProfile, BootstrapTmpfsMount, GuestBootstrap,
    },
    exec::ExecRlimit,
};
use microsandbox_runtime::launch::{LaunchConfig, Lifecycle};
use microsandbox_runtime::vm::{MetricsSlotHandoff, StartupCommand};
use microsandbox_types::{CommandResolutionError, SandboxLogLevel, resolve_default_command};
use microsandbox_utils::{DB_FILENAME, DB_SUBDIR};

#[cfg(not(target_os = "linux"))]
use crate::error::{Operation, UnsupportedReason};
use crate::runtime::handle::ProcessHandle;
#[cfg(windows)]
use crate::runtime::handle::WindowsJob;
use crate::{
    MicrosandboxError, MicrosandboxResult,
    backend::LocalBackend,
    config::{BlockWritebackConfig, RuntimeConfig},
    db::entity::volume as volume_entity,
    runtime::handle::MetricsReservationCleanup,
    sandbox::{
        DiskImageFormat, HostPermissions, MountOptions, NamedVolumeMode, RootfsSource,
        SandboxConfig, StatVirtualization, VolumeMount, validate_named_disk_mount_options,
    },
    volume::{
        VolumeConfig, VolumeKind, lock_volume_name, materialize_volume_path,
        validate_volume_config, validate_volume_name,
    },
};

//--------------------------------------------------------------------------------------------------
// Constants
//--------------------------------------------------------------------------------------------------

#[cfg(unix)]
static SIGCHLD_ALT_STACK_INIT: tokio::sync::OnceCell<()> = tokio::sync::OnceCell::const_new();

#[cfg(windows)]
const STARTUP_PIPE_HASH_HEX_LEN: usize = 32;
#[cfg(target_os = "linux")]
const AUTO_BLOCK_WRITEBACK_LIMIT_BYTES: u64 = 1536 * 1024 * 1024;
#[cfg(target_os = "linux")]
const AUTO_BLOCK_WRITEBACK_POOL_DIVISOR: u64 = 10;
#[cfg(target_os = "linux")]
const MIN_BLOCK_WRITEBACK_LIMIT_BYTES: u64 = 128 * 1024 * 1024;

//--------------------------------------------------------------------------------------------------
// Types
//--------------------------------------------------------------------------------------------------

/// JSON structure read from the sandbox process stdout on startup.
#[derive(Debug, Deserialize)]
struct StartupInfo {
    pid: u32,
}

#[derive(Clone)]
struct MetricsReservation {
    shm_name: String,
    slot: u32,
    generation: u64,
    registry: MetricsRegistry,
}

#[cfg(unix)]
struct Pipe {
    read_fd: OwnedFd,
    write_fd: OwnedFd,
}

#[cfg(windows)]
struct StartupPipe {
    name: OsString,
    server: NamedPipeServer,
}

#[cfg(windows)]
#[derive(Debug)]
struct HandleInheritState {
    handle: HANDLE,
    flags: u32,
}

#[cfg(windows)]
#[derive(Debug)]
struct StdioInheritGuard {
    states: Vec<HandleInheritState>,
}

/// Local storage metadata for a named volume mounted by a sandbox.
#[derive(Clone, Debug)]
struct ResolvedNamedVolume {
    kind: VolumeKind,
    path: PathBuf,
    format: Option<DiskImageFormat>,
    fstype: Option<String>,
    quota_mib: Option<u32>,
}

#[derive(Clone, Debug)]
struct DiskLockRequest {
    path: PathBuf,
    readonly: bool,
    label: String,
    volume_name: Option<String>,
}

/// Named volume row and path created for one sandbox create attempt.
#[derive(Debug)]
pub(crate) struct CreatedNamedVolume {
    pub(crate) id: i32,
    pub(crate) path: PathBuf,
}

/// Sandbox-create named volume preflight state.
#[derive(Debug)]
pub(crate) struct EnsuredNamedVolumes {
    created: Vec<CreatedNamedVolume>,
    _locks: Vec<File>,
}

/// How the sandbox process should behave relative to the creating process.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum SpawnMode {
    /// The creating process keeps the sandbox handle and agent bridge alive.
    Attached,

    /// The sandbox must survive after the creating process exits.
    Detached,
}

//--------------------------------------------------------------------------------------------------
// Methods
//--------------------------------------------------------------------------------------------------

impl EnsuredNamedVolumes {
    pub(crate) fn is_empty(&self) -> bool {
        self.created.is_empty()
    }
}

#[cfg(windows)]
impl StdioInheritGuard {
    fn new() -> MicrosandboxResult<Self> {
        let mut states = Vec::new();

        for std_handle in [STD_INPUT_HANDLE, STD_OUTPUT_HANDLE, STD_ERROR_HANDLE] {
            let handle = unsafe { GetStdHandle(std_handle) };
            if handle.is_null() || handle == INVALID_HANDLE_VALUE {
                continue;
            }
            if states
                .iter()
                .any(|state: &HandleInheritState| state.handle == handle)
            {
                continue;
            }

            let mut flags = 0u32;
            if unsafe { GetHandleInformation(handle, &mut flags) } == 0 {
                continue;
            }
            if flags & HANDLE_FLAG_INHERIT == 0 {
                continue;
            }

            // A redirected `msb create` can receive inheritable stdout/stderr
            // pipe handles from its own parent. Detached sandbox children must
            // not keep those pipes alive after the launcher exits.
            if unsafe { SetHandleInformation(handle, HANDLE_FLAG_INHERIT, 0) } == 0 {
                return Err(std::io::Error::last_os_error().into());
            }
            states.push(HandleInheritState { handle, flags });
        }

        Ok(Self { states })
    }
}

#[cfg(windows)]
impl Drop for StdioInheritGuard {
    fn drop(&mut self) {
        for state in self.states.iter().rev() {
            let inherit = state.flags & HANDLE_FLAG_INHERIT;
            if unsafe { SetHandleInformation(state.handle, HANDLE_FLAG_INHERIT, inherit) } == 0 {
                tracing::debug!(
                    error = %std::io::Error::last_os_error(),
                    "failed to restore stdio handle inheritance flag"
                );
            }
        }
    }
}

//--------------------------------------------------------------------------------------------------
// Functions
//--------------------------------------------------------------------------------------------------

/// Spawn the sandbox process for a sandbox.
///
/// Returns a [`ProcessHandle`] and the path to the agent relay socket.
///
/// The function:
/// 1. Resolves the `msb` binary path
/// 2. Creates sandbox directories (logs, runtime, scripts)
/// 3. Builds CLI arguments from the config
/// 4. Spawns the hidden `msb sandbox` process with `--agent-sock` for the relay
/// 5. Reads startup JSON from stdout to get child PIDs
pub async fn spawn_sandbox(
    local: &LocalBackend,
    config: &SandboxConfig,
    sandbox_id: i32,
    mode: SpawnMode,
    lifecycle_guard: Option<microsandbox_runtime::ipc::SandboxLifecycleGuard>,
) -> MicrosandboxResult<(ProcessHandle, PathBuf)> {
    // Reference-model secrets store only a host-side source reference in the
    // durable config; resolve the actual values now so they travel to the
    // sandbox process on the private launch-config fd without ever being
    // persisted.
    #[cfg(feature = "net")]
    let resolved_config = crate::sandbox::config::resolve_config_secret_sources(config)?;
    #[cfg(feature = "net")]
    let config = resolved_config.as_ref().unwrap_or(config);

    // libkrunfw is process-level (one dylib per process address space). The
    // resolver consults MSB_LIBKRUNFW_PATH env, then SDK_LIBKRUNFW_PATH static,
    // then config.paths.libkrunfw, then filesystem fallbacks.
    let global = local.config();
    let msb_path = global.resolve_msb_path()?;
    let libkrunfw_path = global.resolve_libkrunfw_path()?;
    #[cfg(windows)]
    crate::setup::verify_windows_host_prerequisites()?;
    tracing::debug!(
        msb = %msb_path.display(),
        libkrunfw = %libkrunfw_path.display(),
        sandbox = %config.spec.name,
        cpus = config.spec.resources.cpus,
        memory_mib = config.spec.resources.memory_mib,
        mode = ?mode,
        "spawn_sandbox: resolved paths"
    );

    let sandbox_dir = global.sandboxes_dir().join(&config.spec.name);
    let log_dir = sandbox_dir.join("logs");
    let runtime_dir = sandbox_dir.join("runtime");
    let scripts_dir = runtime_dir.join("scripts");
    let db_dir = global.home().join(DB_SUBDIR);
    let db_path = db_dir.join(DB_FILENAME);

    // Own the sandbox's runtime namespace before touching any deterministic
    // endpoint. The descriptor is duplicated into the child below and remains
    // locked there for the runtime's entire lifetime.
    #[cfg(unix)]
    let lifecycle_guard = match lifecycle_guard {
        Some(guard) => guard,
        None => {
            acquire_sandbox_lifecycle_guard(
                &global.run_dir(),
                &config.spec.name,
                std::time::Duration::from_secs(5),
            )
            .await?
        }
    };

    #[cfg(not(unix))]
    let _ = lifecycle_guard;

    // Lifecycle callers prove any previous owner dead before reaching spawn.
    // With ownership now serialized, remove exact leftovers from that prior
    // generation so compatibility-link publication cannot be masked by them.
    remove_sandbox_socket_artifacts_at(
        &global.run_dir(),
        &global.sandboxes_dir(),
        &config.spec.name,
    )?;

    // Create directories concurrently.
    tokio::try_join!(
        tokio::fs::create_dir_all(&log_dir),
        tokio::fs::create_dir_all(&scripts_dir),
    )?;

    // Stopped-safe preparation: a `--next-start` upper grow persists only the
    // desired size, so the file itself grows here, before any virtio device
    // attaches the image.
    prepare_oci_upper(config, &sandbox_dir).await?;

    // Write scripts to the runtime scripts directory.
    for (name, content) in &config.spec.runtime.scripts {
        // Prevent path traversal: only use the filename component.
        let safe_name = Path::new(name).file_name().ok_or_else(|| {
            crate::MicrosandboxError::InvalidConfig(format!("invalid script name: {name}"))
        })?;
        let script_path = scripts_dir.join(safe_name);
        tokio::fs::write(&script_path, content).await?;
        #[cfg(unix)]
        tokio::fs::set_permissions(&script_path, std::fs::Permissions::from_mode(0o755)).await?;
        #[cfg(windows)]
        microsandbox_filesystem::PassthroughFs::set_path_virtual_permissions(
            &runtime_dir,
            &script_path,
            0,
            0,
            0o755,
        )?;
    }

    // Compute the agent relay socket path from the backend being used for
    // this spawn, not from the ambient default backend.
    let agent_sock_path = resolve_sandbox_agent_socket_path_for(local, &config.spec.name)?;

    // The pipe name is derived from the sandbox NAME, so a leaked VM process
    // from an earlier run would keep serving it and silently receive the new
    // sandbox's agent traffic. Refuse to boot on top of a live server.
    #[cfg(windows)]
    ensure_agent_pipe_unclaimed(&agent_sock_path, &config.spec.name).await?;

    // Stage file bind mounts: each file gets its own isolated directory so
    // that virtio-fs (which requires directories) can share it without
    // exposing adjacent files on the host.
    let (staged_file_mounts, file_mounts_staging) = stage_file_mounts(config, &sandbox_dir).await?;
    let named_volumes = resolve_named_volumes(local, config).await?;
    let disk_locks = lock_disk_mounts(config, &named_volumes)?;
    let metrics_reservation = if config.effective_metrics_interval().is_some() {
        reserve_metrics_slot(local, config, sandbox_id)
    } else {
        None
    };
    #[cfg(unix)]
    let parent_watchdog = match mode {
        SpawnMode::Attached => match create_parent_watchdog_pipe() {
            Ok(pipe) => Some(pipe),
            Err(err) => {
                release_metrics_reservation(config, metrics_reservation.as_ref());
                return Err(err);
            }
        },
        SpawnMode::Detached => None,
    };

    #[cfg(windows)]
    let parent_watchdog: Option<()> = None;

    #[cfg(unix)]
    let startup_pipe = match mode {
        SpawnMode::Attached => None,
        SpawnMode::Detached => match create_startup_pipe() {
            Ok(pipe) => Some(pipe),
            Err(err) => {
                release_metrics_reservation(config, metrics_reservation.as_ref());
                return Err(err);
            }
        },
    };

    #[cfg(windows)]
    let startup_pipe = match mode {
        SpawnMode::Attached => None,
        SpawnMode::Detached => match create_startup_pipe(&config.spec.name, sandbox_id) {
            Ok(pipe) => Some(pipe),
            Err(err) => {
                release_metrics_reservation(config, metrics_reservation.as_ref());
                return Err(err);
            }
        },
    };

    #[cfg(windows)]
    let child_job = match mode {
        SpawnMode::Attached => match WindowsJob::new_kill_on_close() {
            Ok(job) => Some(job),
            Err(err) => {
                release_metrics_reservation(config, metrics_reservation.as_ref());
                return Err(crate::MicrosandboxError::Runtime(format!(
                    "failed to create Windows sandbox job: {err}"
                )));
            }
        },
        SpawnMode::Detached => None,
    };

    #[cfg(windows)]
    let startup_pipe_name = startup_pipe.as_ref().map(|pipe| pipe.name.as_os_str());

    // Split the config: `visible` stays on argv, the typed `LaunchConfig` is
    // delivered over the config fd (keeps the network-config blob and
    // secret-bearing env off `ps` / `/proc/<pid>/cmdline` — see issue #997).
    let (mut visible, mut launch) = sandbox_cli_args(
        local,
        config,
        sandbox_id,
        &db_path,
        global.database.connect_timeout_secs,
        &log_dir,
        &runtime_dir,
        &agent_sock_path,
        &libkrunfw_path,
        &staged_file_mounts,
        &named_volumes,
        metrics_reservation.as_ref(),
        parent_watchdog
            .as_ref()
            .map(|_| microsandbox_runtime::vm::PARENT_WATCH_FD),
        #[cfg(unix)]
        startup_pipe
            .as_ref()
            .map(|_| microsandbox_runtime::vm::STARTUP_FD),
        #[cfg(unix)]
        None,
        #[cfg(windows)]
        None,
        #[cfg(windows)]
        startup_pipe_name,
    );
    let (writeback_limit_bytes, writeback_pool_bytes) = block_writeback_policy(&global.runtime)?;
    tracing::debug!(
        per_disk_limit_bytes = ?writeback_limit_bytes,
        pool_bytes = ?writeback_pool_bytes,
        "resolved buffered writeback policy"
    );
    launch.block_writeback_limit_bytes = writeback_limit_bytes;
    launch.block_writeback_pool_bytes = writeback_pool_bytes;

    #[cfg(unix)]
    let config_file = match write_launch_config_fd(&launch) {
        Ok(file) => file,
        Err(err) => {
            release_metrics_reservation(config, metrics_reservation.as_ref());
            return Err(err);
        }
    };
    #[cfg(unix)]
    let config_raw_fd = config_file.as_raw_fd();
    #[cfg(unix)]
    {
        visible.push(OsString::from("--config-fd"));
        visible.push(OsString::from(
            microsandbox_runtime::vm::CONFIG_FD.to_string(),
        ));
        visible.push(OsString::from("--lifecycle-lock-fd"));
        visible.push(OsString::from(
            microsandbox_runtime::vm::LIFECYCLE_LOCK_FD.to_string(),
        ));
    }

    #[cfg(windows)]
    let _config_file = match write_launch_config_file(&launch, &runtime_dir) {
        Ok(file) => {
            visible.push(OsString::from("--config-file"));
            visible.push(file.path().as_os_str().to_os_string());
            file
        }
        Err(err) => {
            release_metrics_reservation(config, metrics_reservation.as_ref());
            return Err(err);
        }
    };

    // Build the command.
    let mut cmd = Command::new(&msb_path);
    #[cfg(windows)]
    if matches!(mode, SpawnMode::Detached) {
        let flags = DETACHED_PROCESS | CREATE_NEW_PROCESS_GROUP | CREATE_BREAKAWAY_FROM_JOB;
        cmd.creation_flags(flags);
    }
    cmd.args(visible);

    // Prevent the sandbox process from inheriting the parent's terminal on
    // stdin — the VMM's implicit console auto-detects terminals and sets raw
    // mode, which corrupts the parent's terminal output (\n without \r).
    cmd.stdin(Stdio::null());

    #[cfg(unix)]
    {
        let parent_watch_fd = parent_watchdog
            .as_ref()
            .map(|pipe| pipe.read_fd.as_raw_fd());
        let startup_write_fd = startup_pipe.as_ref().map(|pipe| pipe.write_fd.as_raw_fd());
        let lifecycle_lock_fd = lifecycle_guard.as_raw_fd();
        unsafe {
            cmd.pre_exec(move || {
                if startup_write_fd.is_some() {
                    detach_from_launcher_session()?;
                }

                let mut config_mapping =
                    InheritedFdMapping::new(config_raw_fd, microsandbox_runtime::vm::CONFIG_FD);
                let mut parent_watch_mapping = parent_watch_fd.map(|fd| {
                    InheritedFdMapping::new(fd, microsandbox_runtime::vm::PARENT_WATCH_FD)
                });
                let mut startup_mapping = startup_write_fd
                    .map(|fd| InheritedFdMapping::new(fd, microsandbox_runtime::vm::STARTUP_FD));
                let mut lifecycle_mapping = InheritedFdMapping::new(
                    lifecycle_lock_fd,
                    microsandbox_runtime::vm::LIFECYCLE_LOCK_FD,
                );

                // Parent runtimes such as Vitest or Go tests can have enough
                // open files that pipe/tempfile allocation lands on one of the
                // fixed inherited fd numbers. Move those sources away before
                // any dup2 call can overwrite a later source fd.
                let mut next_spare_fd = microsandbox_runtime::vm::LIFECYCLE_LOCK_FD + 1;
                move_reserved_source_fd(&mut config_mapping, &mut next_spare_fd)?;
                if let Some(mapping) = parent_watch_mapping.as_mut() {
                    move_reserved_source_fd(mapping, &mut next_spare_fd)?;
                }
                if let Some(mapping) = startup_mapping.as_mut() {
                    move_reserved_source_fd(mapping, &mut next_spare_fd)?;
                }
                move_reserved_source_fd(&mut lifecycle_mapping, &mut next_spare_fd)?;

                dup_inherited_fd(config_mapping.src, config_mapping.dst)?;
                if let Some(mapping) = parent_watch_mapping {
                    dup_inherited_fd(mapping.src, mapping.dst)?;
                }
                if let Some(mapping) = startup_mapping {
                    dup_inherited_fd(mapping.src, mapping.dst)?;
                }
                dup_inherited_fd(lifecycle_mapping.src, lifecycle_mapping.dst)?;

                Ok(())
            });
        }
    }

    // Capture stdout for attached startup JSON. Detached mode uses a
    // dedicated startup fd so stdio can be severed from the launcher.
    #[cfg(unix)]
    if startup_pipe.is_some() {
        cmd.stdout(Stdio::null());
        cmd.stderr(Stdio::null());
    } else {
        cmd.stdout(Stdio::piped());
        cmd.stderr(Stdio::inherit());
    }
    #[cfg(windows)]
    {
        let runtime_log = std::fs::OpenOptions::new()
            .create(true)
            .append(true)
            .open(log_dir.join("runtime.log"))?;

        if startup_pipe.is_some() {
            cmd.stdout(Stdio::null());
        } else {
            cmd.stdout(Stdio::piped());
        }
        cmd.stderr(Stdio::from(runtime_log));
    }

    ensure_sigchld_handler_uses_alt_stack_before_spawn().await?;

    // Spawn the sandbox process.
    let mut child = {
        #[cfg(windows)]
        let _stdio_inherit_guard = if matches!(mode, SpawnMode::Detached) {
            Some(StdioInheritGuard::new()?)
        } else {
            None
        };

        match cmd.spawn() {
            Ok(child) => child,
            Err(err) => {
                release_metrics_reservation(config, metrics_reservation.as_ref());
                return Err(err.into());
            }
        }
    };

    let _pid = match child.id() {
        Some(pid) => pid,
        None => {
            release_metrics_reservation(config, metrics_reservation.as_ref());
            return Err(crate::MicrosandboxError::Runtime(
                "sandbox process exited immediately".into(),
            ));
        }
    };
    tracing::debug!(pid = _pid, sandbox = %config.spec.name, "spawn_sandbox: process started");

    #[cfg(windows)]
    if let Some(job) = &child_job
        && let Err(err) = job.assign_pid(_pid)
    {
        let status = terminate_startup_process(&mut child).await;
        release_metrics_reservation(config, metrics_reservation.as_ref());
        return Err(crate::MicrosandboxError::Runtime(format!(
            "failed to assign sandbox process to Windows job (status: {status:?}): {err}"
        )));
    }

    let line = match tokio::time::timeout(
        std::time::Duration::from_secs(30),
        read_startup_line(&mut child, startup_pipe),
    )
    .await
    {
        Ok(Ok(line)) => line,
        Ok(Err(err)) => {
            terminate_startup_process(&mut child).await;
            release_metrics_reservation(config, metrics_reservation.as_ref());
            return Err(err);
        }
        Err(_) => {
            terminate_startup_process(&mut child).await;
            release_metrics_reservation(config, metrics_reservation.as_ref());
            return Err(crate::MicrosandboxError::Runtime(
                "sandbox startup timeout: no JSON received within 30 seconds".into(),
            ));
        }
    };

    let startup: StartupInfo = match serde_json::from_str(line.trim()) {
        Ok(info) => info,
        Err(_) => {
            let status = terminate_startup_process(&mut child).await;
            release_metrics_reservation(config, metrics_reservation.as_ref());
            tracing::debug!(
                raw_line = ?line,
                exit_status = ?status,
                "spawn_sandbox: failed to parse startup JSON"
            );
            return Err(crate::MicrosandboxError::Runtime(format!(
                "sandbox process exited ({status:?}) before sending startup info \
                 (line: {line:?}, check stderr above for details)"
            )));
        }
    };
    if startup.pid != _pid {
        let status = terminate_startup_process(&mut child).await;
        release_metrics_reservation(config, metrics_reservation.as_ref());
        return Err(crate::MicrosandboxError::Runtime(format!(
            "sandbox startup PID mismatch: spawned pid {_pid}, startup pid {} \
             (status: {status:?})",
            startup.pid
        )));
    }

    tracing::debug!(
        vm_pid = startup.pid,
        agent_sock = %agent_sock_path.display(),
        "spawn_sandbox: startup JSON received"
    );

    #[cfg(unix)]
    let handle = ProcessHandle::new(
        startup.pid,
        config.spec.name.clone(),
        child,
        file_mounts_staging,
        disk_locks,
        parent_watchdog.map(|pipe| pipe.write_fd),
        metrics_reservation.as_ref().map(|reservation| {
            MetricsReservationCleanup::new(
                reservation.shm_name.clone(),
                reservation.slot,
                reservation.generation,
                Some(reservation.registry.clone()),
            )
        }),
    );

    #[cfg(windows)]
    let handle = ProcessHandle::new(
        startup.pid,
        config.spec.name.clone(),
        child,
        file_mounts_staging,
        disk_locks,
        child_job,
        metrics_reservation.as_ref().map(|reservation| {
            MetricsReservationCleanup::new(
                reservation.shm_name.clone(),
                reservation.slot,
                reservation.generation,
                Some(reservation.registry.clone()),
            )
        }),
    );

    Ok((handle, agent_sock_path))
}

fn block_writeback_policy(
    config: &RuntimeConfig,
) -> MicrosandboxResult<(Option<u64>, Option<u64>)> {
    #[cfg(target_os = "linux")]
    {
        if matches!(config.block_writeback, BlockWritebackConfig::Off {}) {
            return Ok((None, None));
        }

        let derived_pool_bytes = match config.block_writeback {
            BlockWritebackConfig::Auto { pool_mib: None }
            | BlockWritebackConfig::Fixed { pool_mib: None, .. } => {
                Some(linux_auto_block_writeback_pool_bytes(
                    linux_meminfo_bytes("MemTotal:")?,
                    linux_meminfo_bytes("MemAvailable:")?,
                )?)
            }
            BlockWritebackConfig::Auto { pool_mib: Some(_) }
            | BlockWritebackConfig::Fixed {
                pool_mib: Some(_), ..
            }
            | BlockWritebackConfig::Off {} => None,
        };
        resolve_linux_block_writeback_policy(
            config.block_writeback,
            linux_meminfo_bytes("MemTotal:")?,
            derived_pool_bytes,
        )
    }

    #[cfg(not(target_os = "linux"))]
    {
        match config.block_writeback {
            BlockWritebackConfig::Auto { pool_mib: None } | BlockWritebackConfig::Off {} => {
                Ok((None, None))
            }
            BlockWritebackConfig::Auto { pool_mib: Some(_) }
            | BlockWritebackConfig::Fixed { .. } => Err(MicrosandboxError::Unsupported {
                op: Operation::SandboxCreate,
                reason: UnsupportedReason::NotAvailable(
                    "bounded buffered block writeback requires a Linux host".into(),
                ),
            }),
        }
    }
}

#[cfg(target_os = "linux")]
fn resolve_linux_block_writeback_policy(
    config: BlockWritebackConfig,
    total_memory_bytes: u64,
    derived_pool_bytes: Option<u64>,
) -> MicrosandboxResult<(Option<u64>, Option<u64>)> {
    let (limit_bytes, explicit_pool_mib) = match config {
        BlockWritebackConfig::Auto { pool_mib } => (AUTO_BLOCK_WRITEBACK_LIMIT_BYTES, pool_mib),
        BlockWritebackConfig::Off {} => return Ok((None, None)),
        BlockWritebackConfig::Fixed {
            per_disk_mib,
            pool_mib,
        } => {
            if per_disk_mib.get() < MIN_BLOCK_WRITEBACK_LIMIT_BYTES / (1024 * 1024) {
                return Err(MicrosandboxError::InvalidConfig(format!(
                    "runtime.block_writeback.per_disk_mib must be at least {} MiB",
                    MIN_BLOCK_WRITEBACK_LIMIT_BYTES / (1024 * 1024)
                )));
            }
            let limit_bytes = per_disk_mib.get().checked_mul(1024 * 1024).ok_or_else(|| {
                MicrosandboxError::InvalidConfig(
                    "runtime.block_writeback.per_disk_mib exceeds the supported byte range".into(),
                )
            })?;
            (limit_bytes, pool_mib)
        }
    };
    let explicit_pool_bytes = explicit_pool_mib
        .map(|mib| {
            mib.get().checked_mul(1024 * 1024).ok_or_else(|| {
                MicrosandboxError::InvalidConfig(
                    "runtime.block_writeback.pool_mib exceeds the supported byte range".into(),
                )
            })
        })
        .transpose()?;
    let pool_bytes = explicit_pool_bytes.or(derived_pool_bytes).ok_or_else(|| {
        MicrosandboxError::Runtime(
            "derived writeback pool is unavailable while resolving Linux auto policy".into(),
        )
    })?;
    if pool_bytes > total_memory_bytes {
        return Err(MicrosandboxError::InvalidConfig(format!(
            "writeback pool ({pool_bytes} bytes) exceeds physical host memory ({total_memory_bytes} bytes)"
        )));
    }

    Ok((Some(limit_bytes), Some(pool_bytes)))
}

#[cfg(target_os = "linux")]
fn auto_block_writeback_pool_bytes(
    total_memory_bytes: u64,
    available_memory_bytes: u64,
    dirty_background_bytes: u64,
    dirty_background_ratio: u64,
) -> MicrosandboxResult<u64> {
    if dirty_background_ratio > 100 {
        return Err(MicrosandboxError::InvalidConfig(format!(
            "host vm.dirty_background_ratio must not exceed 100, got {dirty_background_ratio}"
        )));
    }

    // Respect a stricter host dirty-background policy, but never treat a permissive sysctl as
    // permission for Microsandbox alone to reserve more than 10% of physical memory.
    let conservative_cap = total_memory_bytes / AUTO_BLOCK_WRITEBACK_POOL_DIVISOR;
    let kernel_background = if dirty_background_bytes != 0 {
        dirty_background_bytes
    } else {
        // Linux applies the ratio to free and reclaimable memory, explicitly not total physical
        // memory. MemAvailable is a deliberately conservative userspace estimate of that dynamic
        // pool after reserves, so it avoids admitting against RAM the host cannot currently spare.
        available_memory_bytes
            .checked_mul(dirty_background_ratio)
            .ok_or_else(|| {
                MicrosandboxError::Runtime(
                    "host dirty-background threshold calculation overflowed u64".into(),
                )
            })?
            / 100
    };
    // A zero background threshold is a valid host tuning. Preserve one byte of cooperative
    // credit so libkrun can clamp it to one host page and retain forward progress.
    Ok(conservative_cap.min(kernel_background).max(1))
}

#[cfg(target_os = "linux")]
fn linux_auto_block_writeback_pool_bytes(
    total_memory_bytes: u64,
    available_memory_bytes: u64,
) -> MicrosandboxResult<u64> {
    let dirty_background_bytes = linux_u64_file("/proc/sys/vm/dirty_background_bytes")?;
    let dirty_background_ratio = if dirty_background_bytes == 0 {
        linux_u64_file("/proc/sys/vm/dirty_background_ratio")?
    } else {
        0
    };
    auto_block_writeback_pool_bytes(
        total_memory_bytes,
        available_memory_bytes,
        dirty_background_bytes,
        dirty_background_ratio,
    )
}

#[cfg(target_os = "linux")]
fn linux_meminfo_bytes(field: &str) -> MicrosandboxResult<u64> {
    let meminfo = std::fs::read_to_string("/proc/meminfo").map_err(|error| {
        MicrosandboxError::Runtime(format!(
            "read /proc/meminfo for writeback pressure policy: {error}"
        ))
    })?;
    let value_kib = meminfo
        .lines()
        .find_map(|line| {
            let mut fields = line.split_whitespace();
            (fields.next() == Some(field))
                .then(|| fields.next()?.parse::<u64>().ok())
                .flatten()
        })
        .ok_or_else(|| {
            MicrosandboxError::Runtime(format!(
                "parse {field} from /proc/meminfo for writeback pressure policy"
            ))
        })?;
    value_kib.checked_mul(1024).ok_or_else(|| {
        MicrosandboxError::Runtime(format!("{field} byte conversion overflowed u64"))
    })
}

#[cfg(target_os = "linux")]
fn linux_u64_file(path: &str) -> MicrosandboxResult<u64> {
    let value = std::fs::read_to_string(path)
        .map_err(|error| MicrosandboxError::Runtime(format!("read {path}: {error}")))?;
    value.trim().parse::<u64>().map_err(|error| {
        MicrosandboxError::Runtime(format!("parse unsigned integer from {path}: {error}"))
    })
}

//--------------------------------------------------------------------------------------------------
// Functions: Helpers
//--------------------------------------------------------------------------------------------------

/// Grow the sandbox-owned OCI root disk before boot when its persisted target increased.
async fn prepare_oci_upper(config: &SandboxConfig, sandbox_dir: &Path) -> MicrosandboxResult<()> {
    let RootfsSource::Oci(oci) = &config.spec.image else {
        return Ok(());
    };
    match &oci.root_disk {
        Some(microsandbox_types::RootDisk::Flat { size_mib, .. }) => {
            let Some(desired_mib) = size_mib else {
                return Ok(());
            };
            let path = sandbox_dir.join(crate::sandbox::flat_rootfs::FLAT_ROOTFS_FILENAME);
            if !tokio::fs::try_exists(&path).await.unwrap_or(false) {
                return Ok(());
            }
            crate::sandbox::flat_rootfs::grow_private_flat_rootfs(path, *desired_mib).await
        }
        Some(microsandbox_types::RootDisk::Managed {
            size_mib: Some(desired_mib),
        }) => {
            let upper_path = sandbox_dir.join("upper.ext4");
            if !tokio::fs::try_exists(&upper_path).await.unwrap_or(false) {
                return Ok(());
            }
            crate::sandbox::upper::grow_upper_to_mib(upper_path, *desired_mib).await
        }
        _ => Ok(()),
    }
}

fn reserve_metrics_slot(
    local: &LocalBackend,
    config: &SandboxConfig,
    sandbox_id: i32,
) -> Option<MetricsReservation> {
    let shm_name = local.config().metrics_registry_shm_name();
    let capacity = local.config().metrics_registry_capacity();
    let registry = match MetricsRegistry::open_or_create(&shm_name, capacity) {
        Ok(registry) => registry,
        Err(err) => {
            tracing::warn!(error = %err, sandbox = %config.spec.name, "failed to open metrics registry");
            return None;
        }
    };
    let memory_limit_bytes = u64::from(config.spec.resources.memory_mib) * 1024 * 1024;
    match registry.reserve(ReserveSlot {
        sandbox_id,
        name: &config.spec.name,
        memory_limit_bytes,
    }) {
        Ok(SlotReservation { slot, generation }) => Some(MetricsReservation {
            shm_name,
            slot,
            generation,
            registry,
        }),
        Err(err) => {
            tracing::warn!(error = %err, sandbox = %config.spec.name, "failed to reserve metrics slot");
            None
        }
    }
}

#[cfg(unix)]
fn create_parent_watchdog_pipe() -> MicrosandboxResult<Pipe> {
    create_pipe()
}

#[cfg(unix)]
fn create_startup_pipe() -> MicrosandboxResult<Pipe> {
    create_pipe()
}

#[cfg(windows)]
fn create_startup_pipe(sandbox_name: &str, sandbox_id: i32) -> MicrosandboxResult<StartupPipe> {
    let pipe_name = startup_pipe_name(sandbox_name, sandbox_id);
    let server = ServerOptions::new()
        .first_pipe_instance(true)
        .pipe_mode(PipeMode::Byte)
        .create(&pipe_name)?;

    Ok(StartupPipe {
        name: OsString::from(pipe_name),
        server,
    })
}

#[cfg(windows)]
fn startup_pipe_name(sandbox_name: &str, sandbox_id: i32) -> String {
    let mut nonce = [0u8; 16];
    rand::rng().fill_bytes(&mut nonce);

    let mut hasher = Sha256::new();
    hasher.update(sandbox_name.as_bytes());
    hasher.update(b"\0");
    hasher.update(sandbox_id.to_le_bytes());
    hasher.update(nonce);
    let digest = hasher.finalize();

    let mut hash = String::with_capacity(STARTUP_PIPE_HASH_HEX_LEN);
    for byte in digest.iter().take(STARTUP_PIPE_HASH_HEX_LEN / 2) {
        let _ = write!(hash, "{byte:02x}");
    }

    format!(r"\\.\pipe\msb-startup-{sandbox_id}-{hash}")
}

#[cfg(unix)]
fn create_pipe() -> MicrosandboxResult<Pipe> {
    let mut fds = [0; 2];
    let rc = create_cloexec_pipe(&mut fds);
    if rc != 0 {
        return Err(std::io::Error::last_os_error().into());
    }

    let read_fd = unsafe { OwnedFd::from_raw_fd(fds[0]) };
    let write_fd = unsafe { OwnedFd::from_raw_fd(fds[1]) };

    #[cfg(not(target_os = "linux"))]
    {
        set_cloexec(&read_fd, true)?;
        set_cloexec(&write_fd, true)?;
    }

    Ok(Pipe { read_fd, write_fd })
}

/// Serialize the [`LaunchConfig`] as JSON into an anonymous temp file, rewound
/// to offset 0. The file is unlinked on creation, so there is no path to clean
/// up or race on; it is `dup2`'d onto
/// [`CONFIG_FD`](microsandbox_runtime::vm::CONFIG_FD) for the child to read.
#[cfg(unix)]
fn write_launch_config_fd(launch: &LaunchConfig) -> MicrosandboxResult<std::fs::File> {
    let mut file = tempfile::tempfile()?;
    let json = serde_json::to_vec(launch)
        .map_err(|e| crate::MicrosandboxError::Runtime(format!("serialize launch config: {e}")))?;
    file.write_all(&json)?;
    file.flush()?;
    file.seek(SeekFrom::Start(0))?;
    Ok(file)
}

/// Serialize the [`LaunchConfig`] as JSON to a short-lived named file for Windows.
///
/// Windows does not have the Unix anonymous-fd handoff used above, so the
/// launcher keeps the file handle alive until the child reports startup and
/// passes only the path on argv.
#[cfg(windows)]
fn write_launch_config_file(
    launch: &LaunchConfig,
    runtime_dir: &Path,
) -> MicrosandboxResult<tempfile::NamedTempFile> {
    let mut file = tempfile::NamedTempFile::new_in(runtime_dir)?;
    let json = serde_json::to_vec(launch)
        .map_err(|e| crate::MicrosandboxError::Runtime(format!("serialize launch config: {e}")))?;
    file.write_all(&json)?;
    file.flush()?;
    file.as_file_mut().seek(SeekFrom::Start(0))?;
    Ok(file)
}

#[cfg(unix)]
async fn read_startup_line(
    child: &mut tokio::process::Child,
    startup_pipe: Option<Pipe>,
) -> MicrosandboxResult<String> {
    let mut reader: Box<dyn AsyncBufRead + Send + Unpin> = match startup_pipe {
        Some(pipe) => {
            let Pipe { read_fd, write_fd } = pipe;
            drop(write_fd);
            Box::new(tokio::io::BufReader::new(tokio::fs::File::from_std(
                std::fs::File::from(read_fd),
            )))
        }
        None => {
            let stdout = child.stdout.take().ok_or_else(|| {
                crate::MicrosandboxError::Runtime("failed to capture sandbox stdout".into())
            })?;
            Box::new(tokio::io::BufReader::new(stdout))
        }
    };

    let mut line = String::new();
    reader.read_line(&mut line).await?;
    Ok(line)
}

#[cfg(windows)]
async fn read_startup_line(
    child: &mut tokio::process::Child,
    startup_pipe: Option<StartupPipe>,
) -> MicrosandboxResult<String> {
    let mut reader: Box<dyn AsyncBufRead + Send + Unpin> = match startup_pipe {
        Some(pipe) => {
            let server = pipe.server;
            server.connect().await?;
            Box::new(tokio::io::BufReader::new(server))
        }
        None => {
            let stdout = child.stdout.take().ok_or_else(|| {
                crate::MicrosandboxError::Runtime("failed to capture sandbox stdout".into())
            })?;
            Box::new(tokio::io::BufReader::new(stdout))
        }
    };

    let mut line = String::new();
    reader.read_line(&mut line).await?;
    Ok(line)
}

#[cfg(unix)]
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
struct InheritedFdMapping {
    src: i32,
    dst: i32,
}

#[cfg(unix)]
impl InheritedFdMapping {
    fn new(src: i32, dst: i32) -> Self {
        Self { src, dst }
    }
}

#[cfg(unix)]
fn move_reserved_source_fd(
    mapping: &mut InheritedFdMapping,
    next_spare_fd: &mut i32,
) -> std::io::Result<()> {
    if !inherited_fd_source_needs_spare(mapping.src, mapping.dst) {
        return Ok(());
    }

    let spare = unsafe { libc::fcntl(mapping.src, libc::F_DUPFD, *next_spare_fd) };
    if spare < 0 {
        return Err(std::io::Error::last_os_error());
    }

    mapping.src = spare;
    *next_spare_fd = spare.saturating_add(1);
    Ok(())
}

#[cfg(unix)]
fn inherited_fd_source_needs_spare(src: i32, dst: i32) -> bool {
    src != dst
        && matches!(
            src,
            microsandbox_runtime::vm::CONFIG_FD
                | microsandbox_runtime::vm::PARENT_WATCH_FD
                | microsandbox_runtime::vm::STARTUP_FD
                | microsandbox_runtime::vm::LIFECYCLE_LOCK_FD
        )
}

#[cfg(unix)]
fn dup_inherited_fd(src: i32, dst: i32) -> std::io::Result<()> {
    if unsafe { libc::dup2(src, dst) } < 0 {
        return Err(std::io::Error::last_os_error());
    }
    if src != dst && unsafe { libc::close(src) } < 0 {
        return Err(std::io::Error::last_os_error());
    }
    let flags = unsafe { libc::fcntl(dst, libc::F_GETFD) };
    if flags < 0 {
        return Err(std::io::Error::last_os_error());
    }
    if unsafe { libc::fcntl(dst, libc::F_SETFD, flags & !libc::FD_CLOEXEC) } < 0 {
        return Err(std::io::Error::last_os_error());
    }
    Ok(())
}

#[cfg(unix)]
fn detach_from_launcher_session() -> std::io::Result<()> {
    if unsafe { libc::setsid() } < 0 {
        return Err(std::io::Error::last_os_error());
    }

    let mut action: libc::sigaction = unsafe { std::mem::zeroed() };
    action.sa_sigaction = libc::SIG_IGN;
    if unsafe { libc::sigemptyset(&mut action.sa_mask) } < 0 {
        return Err(std::io::Error::last_os_error());
    }
    if unsafe { libc::sigaction(libc::SIGHUP, &action, std::ptr::null_mut()) } < 0 {
        return Err(std::io::Error::last_os_error());
    }
    Ok(())
}

#[cfg(target_os = "linux")]
fn create_cloexec_pipe(fds: &mut [i32; 2]) -> i32 {
    unsafe { libc::pipe2(fds.as_mut_ptr(), libc::O_CLOEXEC) }
}

#[cfg(all(unix, not(target_os = "linux")))]
fn create_cloexec_pipe(fds: &mut [i32; 2]) -> i32 {
    unsafe { libc::pipe(fds.as_mut_ptr()) }
}

#[cfg(all(unix, not(target_os = "linux")))]
fn set_cloexec(fd: &OwnedFd, enabled: bool) -> MicrosandboxResult<()> {
    let current = unsafe { libc::fcntl(fd.as_raw_fd(), libc::F_GETFD) };
    if current < 0 {
        return Err(std::io::Error::last_os_error().into());
    }

    let mut next = current;
    if enabled {
        next |= libc::FD_CLOEXEC;
    } else {
        next &= !libc::FD_CLOEXEC;
    }

    if unsafe { libc::fcntl(fd.as_raw_fd(), libc::F_SETFD, next) } < 0 {
        return Err(std::io::Error::last_os_error().into());
    }

    Ok(())
}

fn release_metrics_reservation(config: &SandboxConfig, reservation: Option<&MetricsReservation>) {
    let Some(reservation) = reservation else {
        return;
    };
    if let Err(err) = reservation
        .registry
        .release_reserved(reservation.slot, reservation.generation)
    {
        tracing::debug!(error = %err, sandbox = %config.spec.name, "release: metrics slot release failed");
    }
}

#[cfg(unix)]
async fn ensure_sigchld_handler_uses_alt_stack_before_spawn() -> MicrosandboxResult<()> {
    SIGCHLD_ALT_STACK_INIT
        .get_or_try_init(|| async {
            install_tokio_sigchld_handler()?;
            patch_sigchld_handler_uses_alt_stack();
            Ok::<(), MicrosandboxError>(())
        })
        .await?;
    Ok(())
}

#[cfg(not(unix))]
async fn ensure_sigchld_handler_uses_alt_stack_before_spawn() -> MicrosandboxResult<()> {
    Ok(())
}

#[cfg(unix)]
fn install_tokio_sigchld_handler() -> MicrosandboxResult<()> {
    let signal = tokio::signal::unix::signal(tokio::signal::unix::SignalKind::child())?;
    let _ = Box::leak(Box::new(signal));
    Ok(())
}

#[cfg(unix)]
fn patch_sigchld_handler_uses_alt_stack() {
    unsafe {
        let mut action = std::mem::MaybeUninit::<libc::sigaction>::uninit();
        if libc::sigaction(libc::SIGCHLD, std::ptr::null(), action.as_mut_ptr()) != 0 {
            return;
        }

        let mut action = action.assume_init();
        if action.sa_flags & libc::SA_ONSTACK != 0 {
            return;
        }

        action.sa_flags |= libc::SA_ONSTACK;
        let _ = libc::sigaction(libc::SIGCHLD, &action, std::ptr::null_mut());
    }
}

pub(crate) async fn ensure_named_volumes(
    local: &LocalBackend,
    config: &SandboxConfig,
) -> MicrosandboxResult<EnsuredNamedVolumes> {
    let locks = lock_named_volume_mounts(local, config)?;
    let mut created = Vec::new();

    if let Err(err) = ensure_named_volumes_inner(local, config, &mut created).await {
        rollback_created_named_volume_records(local, &created).await;
        return Err(err);
    }

    // Resolve every named mount while the volume locks are still held and
    // before the caller inserts the sandbox row. Existing disk-backed volumes
    // are only distinguishable through the catalog, so this is the earliest
    // point where virtiofs-only ownership can be rejected without leaving
    // durable sandbox state behind.
    if let Err(err) = resolve_named_volumes(local, config).await {
        rollback_created_named_volume_records(local, &created).await;
        return Err(err);
    }

    Ok(EnsuredNamedVolumes {
        created,
        _locks: locks,
    })
}

async fn ensure_named_volumes_inner(
    local: &LocalBackend,
    config: &SandboxConfig,
    created: &mut Vec<CreatedNamedVolume>,
) -> MicrosandboxResult<()> {
    for mount in &config.spec.mounts {
        let Some(create) = mount.named_create() else {
            continue;
        };

        validate_volume_name(create.name())?;
        let pools = local.db().await?;
        let existing = volume_entity::Entity::find()
            .filter(volume_entity::Column::Name.eq(create.name()))
            .one(pools.read())
            .await?;

        if let Some(existing) = existing {
            match create.mode() {
                NamedVolumeMode::Create => {
                    return Err(MicrosandboxError::VolumeAlreadyExists(
                        create.name().to_string(),
                    ));
                }
                NamedVolumeMode::EnsureExists => {
                    validate_existing_named_volume(create, &existing)?;
                    continue;
                }
                NamedVolumeMode::Existing => continue,
            }
        }

        if create.mode() == NamedVolumeMode::Existing {
            return Err(MicrosandboxError::VolumeNotFound(create.name().to_string()));
        }

        let volume_config = VolumeConfig {
            name: create.name().to_string(),
            kind: create.kind(),
            quota_mib: create.quota_mib(),
            capacity_mib: create.capacity_mib(),
            labels: create.labels().to_vec(),
        };
        validate_volume_config(&volume_config)?;

        let labels_json = if create.labels().is_empty() {
            None
        } else {
            Some(serde_json::to_string(create.labels())?)
        };
        let now = chrono::Utc::now().naive_utc();
        let capacity_bytes = volume_config
            .capacity_mib
            .map(|mib| i64::from(mib) * 1024 * 1024);
        let model = volume_entity::ActiveModel {
            name: Set(volume_config.name.clone()),
            kind: Set(volume_config.kind.as_str().to_string()),
            quota_mib: Set(volume_config.quota_mib.map(|value| value as i32)),
            size_bytes: Set(None),
            capacity_bytes: Set(capacity_bytes),
            disk_format: Set((volume_config.kind == VolumeKind::Disk).then(|| "raw".to_string())),
            disk_fstype: Set((volume_config.kind == VolumeKind::Disk).then(|| "ext4".to_string())),
            labels: Set(labels_json),
            created_at: Set(Some(now)),
            updated_at: Set(Some(now)),
            ..Default::default()
        };
        let inserted = volume_entity::Entity::insert(model)
            .exec(pools.write())
            .await?;
        let volume_id = inserted.last_insert_id;

        let path = local.volume_path(&volume_config.name);
        if let Err(err) = materialize_volume_path(&volume_config, &path).await {
            let _ = volume_entity::Entity::delete_by_id(volume_id)
                .exec(pools.write())
                .await;
            let _ = tokio::fs::remove_dir_all(&path).await;
            return Err(err);
        }
        created.push(CreatedNamedVolume {
            id: volume_id,
            path,
        });
    }

    Ok(())
}

pub(crate) async fn rollback_created_named_volumes(
    local: &LocalBackend,
    volumes: &EnsuredNamedVolumes,
) {
    rollback_created_named_volume_records(local, &volumes.created).await;
}

async fn rollback_created_named_volume_records(
    local: &LocalBackend,
    volumes: &[CreatedNamedVolume],
) {
    if volumes.is_empty() {
        return;
    }

    for volume in volumes {
        let _ = tokio::fs::remove_dir_all(&volume.path).await;
    }

    let ids = volumes.iter().map(|volume| volume.id).collect::<Vec<_>>();
    if let Ok(pools) = local.db().await {
        let _ = volume_entity::Entity::delete_many()
            .filter(volume_entity::Column::Id.is_in(ids))
            .exec(pools.write())
            .await;
    }
}

fn lock_named_volume_mounts(
    local: &LocalBackend,
    config: &SandboxConfig,
) -> MicrosandboxResult<Vec<File>> {
    let mut names = BTreeSet::new();
    for mount in &config.spec.mounts {
        if let VolumeMount::Named { name, .. } = mount {
            validate_volume_name(name)?;
            names.insert(name.clone());
        }
    }

    let mut locks = Vec::with_capacity(names.len());
    for name in names {
        locks.push(lock_volume_name(local, &name)?);
    }
    Ok(locks)
}

async fn resolve_named_volumes(
    local: &LocalBackend,
    config: &SandboxConfig,
) -> MicrosandboxResult<HashMap<String, ResolvedNamedVolume>> {
    let mut resolved: HashMap<String, ResolvedNamedVolume> = HashMap::new();

    for mount in &config.spec.mounts {
        let VolumeMount::Named {
            name,
            options,
            stat_virtualization,
            host_permissions,
            ..
        } = mount
        else {
            continue;
        };

        if let Some(volume) = resolved.get(name) {
            if volume.kind == VolumeKind::Disk {
                validate_named_disk_mount_options(
                    name,
                    *stat_virtualization,
                    *host_permissions,
                    options,
                )?;
            }
            continue;
        }

        let pools = local.db().await?;
        let model = volume_entity::Entity::find()
            .filter(volume_entity::Column::Name.eq(name))
            .one(pools.read())
            .await?
            .ok_or_else(|| MicrosandboxError::VolumeNotFound(name.clone()))?;

        let kind = VolumeKind::from_db_value(&model.kind);
        let path = local.volume_path(name);
        let volume = match kind {
            VolumeKind::Directory => ResolvedNamedVolume {
                kind,
                path,
                format: None,
                fstype: None,
                quota_mib: model.quota_mib.map(|value| value.max(0) as u32),
            },
            VolumeKind::Disk => {
                validate_named_disk_mount_options(
                    name,
                    *stat_virtualization,
                    *host_permissions,
                    options,
                )?;
                let format = model
                    .disk_format
                    .as_deref()
                    .unwrap_or("raw")
                    .parse::<DiskImageFormat>()
                    .map_err(|err| {
                        MicrosandboxError::InvalidConfig(format!(
                            "disk named volume {name:?} has invalid disk format: {err}"
                        ))
                    })?;

                ResolvedNamedVolume {
                    kind,
                    path: path.join("disk.raw"),
                    format: Some(format),
                    fstype: model.disk_fstype,
                    quota_mib: None,
                }
            }
        };

        resolved.insert(name.clone(), volume);
    }

    Ok(resolved)
}

fn validate_existing_named_volume(
    requested: &microsandbox_types::NamedVolumeCreate,
    existing: &volume_entity::Model,
) -> MicrosandboxResult<()> {
    let actual_kind = VolumeKind::from_db_value(&existing.kind);
    if requested.kind() != actual_kind {
        return Err(MicrosandboxError::InvalidConfig(format!(
            "named volume {:?} already exists as {}, but this sandbox requested {}",
            requested.name(),
            actual_kind.as_str(),
            requested.kind().as_str()
        )));
    }

    if let Some(requested_quota_mib) = requested.quota_mib()
        && existing.quota_mib != Some(requested_quota_mib as i32)
    {
        return Err(MicrosandboxError::InvalidConfig(format!(
            "named volume {:?} already exists with quota {:?} MiB, but this sandbox requested {} MiB",
            requested.name(),
            existing.quota_mib,
            requested_quota_mib
        )));
    }

    if let Some(requested_capacity_mib) = requested.capacity_mib() {
        let requested_capacity_bytes = i64::from(requested_capacity_mib) * 1024 * 1024;
        if existing.capacity_bytes != Some(requested_capacity_bytes) {
            return Err(MicrosandboxError::InvalidConfig(format!(
                "named volume {:?} already exists with capacity {:?} bytes, but this sandbox requested {} bytes",
                requested.name(),
                existing.capacity_bytes,
                requested_capacity_bytes
            )));
        }
    }

    validate_requested_named_volume_labels(requested, existing)?;

    Ok(())
}

fn validate_requested_named_volume_labels(
    requested: &microsandbox_types::NamedVolumeCreate,
    existing: &volume_entity::Model,
) -> MicrosandboxResult<()> {
    if requested.labels().is_empty() {
        return Ok(());
    }

    let existing_labels = existing
        .labels
        .as_deref()
        .map(serde_json::from_str::<Vec<(String, String)>>)
        .transpose()?
        .unwrap_or_default()
        .into_iter()
        .collect::<BTreeMap<_, _>>();

    for (key, requested_value) in requested.labels() {
        match existing_labels.get(key) {
            Some(existing_value) if existing_value == requested_value => {}
            Some(existing_value) => {
                return Err(MicrosandboxError::InvalidConfig(format!(
                    "named volume {:?} already exists with label {key:?}={existing_value:?}, but this sandbox requested {requested_value:?}",
                    requested.name()
                )));
            }
            None => {
                return Err(MicrosandboxError::InvalidConfig(format!(
                    "named volume {:?} already exists without requested label {key:?}",
                    requested.name()
                )));
            }
        }
    }

    Ok(())
}

fn lock_disk_mounts(
    config: &SandboxConfig,
    named_volumes: &HashMap<String, ResolvedNamedVolume>,
) -> MicrosandboxResult<Vec<File>> {
    let mut locks = Vec::new();
    let mut requests = Vec::new();

    if let RootfsSource::DiskImage { path, .. } = &config.spec.image {
        requests.push(DiskLockRequest {
            path: path.clone(),
            readonly: false,
            label: format!("disk image rootfs {}", path.display()),
            volume_name: None,
        });
    }

    for mount in &config.spec.mounts {
        match mount {
            VolumeMount::DiskImage { host, options, .. } => {
                requests.push(DiskLockRequest {
                    path: host.clone(),
                    readonly: options.readonly,
                    label: format!("disk image {}", host.display()),
                    volume_name: None,
                });
            }
            VolumeMount::Named { name, options, .. } => {
                if let Some(ResolvedNamedVolume {
                    kind: VolumeKind::Disk,
                    path,
                    ..
                }) = named_volumes.get(name)
                {
                    requests.push(DiskLockRequest {
                        path: path.clone(),
                        readonly: options.readonly,
                        label: format!("named disk volume {name:?}"),
                        volume_name: Some(name.clone()),
                    });
                }
            }
            _ => {}
        }
    }

    let mut seen = HashMap::new();
    for request in requests {
        let canonical = std::fs::canonicalize(&request.path).map_err(|err| {
            MicrosandboxError::InvalidConfig(format!(
                "disk image host path does not exist: {} ({err})",
                request.path.display()
            ))
        })?;
        if let Some(previous) = seen.insert(canonical.clone(), request.label.clone()) {
            return Err(MicrosandboxError::InvalidConfig(format!(
                "disk images cannot be attached more than once per sandbox: {} ({previous}; {})",
                canonical.display(),
                request.label
            )));
        }
        locks.push(lock_disk_image(
            &canonical,
            request.readonly,
            request.volume_name.as_deref(),
        )?);
    }

    Ok(locks)
}

fn lock_disk_image(
    path: &Path,
    readonly: bool,
    volume_name: Option<&str>,
) -> MicrosandboxResult<File> {
    #[cfg(unix)]
    {
        lock_disk_image_unix(path, readonly, volume_name)
    }

    #[cfg(windows)]
    {
        lock_disk_image_windows(path, readonly, volume_name)
    }
}

#[cfg(unix)]
fn lock_disk_image_unix(
    path: &Path,
    readonly: bool,
    volume_name: Option<&str>,
) -> MicrosandboxResult<File> {
    let file = if readonly {
        std::fs::OpenOptions::new().read(true).open(path)
    } else {
        std::fs::OpenOptions::new()
            .read(true)
            .write(true)
            .open(path)
    }
    .map_err(|err| {
        MicrosandboxError::InvalidConfig(format!("open disk image lock {}: {err}", path.display()))
    })?;

    let operation = if readonly {
        libc::LOCK_SH | libc::LOCK_NB
    } else {
        libc::LOCK_EX | libc::LOCK_NB
    };

    if unsafe { libc::flock(file.as_raw_fd(), operation) } != 0 {
        let err = std::io::Error::last_os_error();
        let message = if matches!(err.kind(), std::io::ErrorKind::WouldBlock) {
            match volume_name {
                Some(name) => {
                    format!("volume {name:?} is already attached with an incompatible disk mode")
                }
                None => format!(
                    "disk image {:?} is already attached with an incompatible disk mode",
                    path.display().to_string()
                ),
            }
        } else {
            format!("lock disk image {}: {err}", path.display())
        };
        return Err(MicrosandboxError::InvalidConfig(message));
    }

    clear_cloexec(file.as_raw_fd())?;
    Ok(file)
}

#[cfg(windows)]
fn lock_disk_image_windows(
    path: &Path,
    _readonly: bool,
    volume_name: Option<&str>,
) -> MicrosandboxResult<File> {
    let lock_path = windows_disk_lock_path(path)?;
    if let Some(parent) = lock_path.parent() {
        std::fs::create_dir_all(parent)?;
    }

    // Windows share modes are mandatory. Holding an exclusive handle on the
    // disk image itself would also block the child VMM from opening it, so use
    // a sidecar lock file while leaving the image handle-free until launch.
    let mut options = std::fs::OpenOptions::new();
    options
        .create(true)
        .read(true)
        .truncate(false)
        .write(true)
        .share_mode(0);

    options.open(&lock_path).map_err(|err| {
        let message = if is_windows_lock_conflict(&err) {
            match volume_name {
                Some(name) => {
                    format!("volume {name:?} is already attached with an incompatible disk mode")
                }
                None => format!(
                    "disk image {:?} is already attached with an incompatible disk mode",
                    path.display().to_string()
                ),
            }
        } else {
            format!("lock disk image {}: {err}", path.display())
        };
        MicrosandboxError::InvalidConfig(message)
    })
}

#[cfg(windows)]
fn windows_disk_lock_path(path: &Path) -> MicrosandboxResult<PathBuf> {
    let file_name = path.file_name().ok_or_else(|| {
        MicrosandboxError::InvalidConfig(format!(
            "disk image path has no file name: {}",
            path.display()
        ))
    })?;

    let mut lock_name = file_name.to_os_string();
    lock_name.push(".lock");
    Ok(path.with_file_name(lock_name))
}

#[cfg(windows)]
fn is_windows_lock_conflict(err: &std::io::Error) -> bool {
    matches!(
        err.kind(),
        std::io::ErrorKind::PermissionDenied | std::io::ErrorKind::WouldBlock
    ) || err.raw_os_error() == Some(32)
}

#[cfg(unix)]
fn clear_cloexec(fd: i32) -> MicrosandboxResult<()> {
    let flags = unsafe { libc::fcntl(fd, libc::F_GETFD) };
    if flags < 0 {
        return Err(std::io::Error::last_os_error().into());
    }
    if unsafe { libc::fcntl(fd, libc::F_SETFD, flags & !libc::FD_CLOEXEC) } < 0 {
        return Err(std::io::Error::last_os_error().into());
    }
    Ok(())
}

/// Return agent relay socket paths in preferred connection order.
pub(crate) fn sandbox_agent_socket_path_candidates(name: &str) -> Vec<PathBuf> {
    let (run_dir, sandboxes_dir) = crate::backend::default_backend()
        .as_local()
        .map(|local| (local.config().run_dir(), local.config().sandboxes_dir()))
        .unwrap_or_else(|| {
            let home = microsandbox_utils::resolve_home();
            (
                home.join(microsandbox_utils::RUN_SUBDIR),
                home.join(microsandbox_utils::SANDBOXES_SUBDIR),
            )
        });
    sandbox_agent_socket_path_candidates_with_roots(&run_dir, &sandboxes_dir, name)
}

pub(crate) fn sandbox_agent_socket_path_candidates_for(
    local: &LocalBackend,
    name: &str,
) -> Vec<PathBuf> {
    sandbox_agent_socket_path_candidates_with_roots(
        &local.config().run_dir(),
        &local.config().sandboxes_dir(),
        name,
    )
}

fn sandbox_agent_socket_path_candidates_with_roots(
    run_dir: &Path,
    sandboxes_dir: &Path,
    name: &str,
) -> Vec<PathBuf> {
    let primary = microsandbox_runtime::ipc::canonical_agent_endpoint(run_dir, name);

    // New clients prefer the canonical per-sandbox endpoint, then the flat
    // legacy path used by older runtimes, and finally the pre-hash in-sandbox
    // fallback retained for unusually deep homes. Windows named pipes did not
    // change layout, so the canonical endpoint is the only candidate there.
    #[cfg(unix)]
    let candidates = {
        let paths = microsandbox_runtime::ipc::sandbox_socket_paths(run_dir, name);
        vec![
            primary,
            paths.legacy_agent,
            in_sandbox_agent_socket_path(sandboxes_dir, name),
        ]
    };
    #[cfg(not(unix))]
    let candidates = {
        let _ = sandboxes_dir;
        vec![primary]
    };

    candidates
}

/// Pick the first explicit-backend socket path usable on this platform.
pub(crate) fn resolve_sandbox_agent_socket_path_for(
    local: &LocalBackend,
    name: &str,
) -> MicrosandboxResult<PathBuf> {
    #[cfg(unix)]
    let candidates = vec![microsandbox_runtime::ipc::canonical_agent_endpoint(
        &local.config().run_dir(),
        name,
    )];
    #[cfg(not(unix))]
    let candidates = sandbox_agent_socket_path_candidates_for(local, name);
    resolve_sandbox_agent_socket_path_from_candidates(candidates)
}

/// Pick the first socket path usable on this platform.
pub(crate) fn resolve_sandbox_agent_socket_path(name: &str) -> MicrosandboxResult<PathBuf> {
    let candidates = sandbox_agent_socket_path_candidates(name);

    #[cfg(unix)]
    if let Some(existing) = first_existing_socket_candidate(&candidates) {
        return Ok(existing);
    }

    resolve_sandbox_agent_socket_path_from_candidates(candidates)
}

#[cfg(unix)]
fn first_existing_socket_candidate(candidates: &[PathBuf]) -> Option<PathBuf> {
    candidates.iter().find(|path| path.exists()).cloned()
}

#[cfg(unix)]
fn resolve_sandbox_agent_socket_path_from_candidates(
    candidates: Vec<PathBuf>,
) -> MicrosandboxResult<PathBuf> {
    for path in &candidates {
        if microsandbox_runtime::ipc::validate_socket_pair(path).is_ok() {
            return Ok(path.clone());
        }
    }

    let shortest = candidates
        .iter()
        .flat_map(|path| {
            [
                path.as_os_str().as_bytes().len(),
                microsandbox_runtime::ipc::control_socket_path_for(path)
                    .as_os_str()
                    .as_bytes()
                    .len(),
            ]
        })
        .min()
        .unwrap_or(0);
    Err(crate::MicrosandboxError::InvalidConfig(format!(
        "sandbox runtime socket path is too long: shortest derived path is {shortest} bytes, \
         but Unix socket paths on this platform must be shorter than {} bytes; set \
         MSB_HOME to a shorter directory",
        unsafe { std::mem::zeroed::<libc::sockaddr_un>() }
            .sun_path
            .len()
    )))
}

#[cfg(not(unix))]
fn resolve_sandbox_agent_socket_path_from_candidates(
    candidates: Vec<PathBuf>,
) -> MicrosandboxResult<PathBuf> {
    // Named pipes have no `sun_path`-style length limit, so the primary
    // candidate is always usable.
    candidates.into_iter().next().ok_or_else(|| {
        crate::MicrosandboxError::InvalidConfig(
            "no agent relay socket candidates were derived".to_string(),
        )
    })
}

/// What a client-side open of the agent pipe name revealed.
#[cfg(windows)]
enum AgentPipeProbe {
    /// No server instance exists — the name is free to bind.
    Free,

    /// A live server holds the name. The serving PID is best-effort.
    Served { server_pid: Option<u32> },
}

/// Fail the spawn when another process already serves this sandbox's agent
/// pipe, naming the stale PID so the operator can terminate it.
///
/// Unix sockets are files the new runtime simply unlinks and rebinds; Windows
/// named pipes have no such steal path — the child's `first_pipe_instance`
/// bind would fail deep in boot, and agent clients would keep silently
/// reaching the stale server in the meantime.
#[cfg(windows)]
async fn ensure_agent_pipe_unclaimed(
    pipe_path: &Path,
    sandbox_name: &str,
) -> MicrosandboxResult<()> {
    // A just-stopped runtime closes its pipe within moments of its DB row
    // going terminal; retry briefly so stop→start (restart) flows don't trip
    // on ordinary teardown.
    const PROBE_ATTEMPTS: u32 = 10;
    const PROBE_INTERVAL: std::time::Duration = std::time::Duration::from_millis(200);

    let mut last_seen_pid = None;
    for attempt in 0..PROBE_ATTEMPTS {
        match probe_agent_pipe_server(pipe_path) {
            Ok(AgentPipeProbe::Free) => return Ok(()),
            Ok(AgentPipeProbe::Served { server_pid }) => last_seen_pid = server_pid,
            Err(err) => {
                // Unexpected probe failure must not block the spawn — if the
                // name really is taken, the child's first-instance bind fails
                // loudly on its own.
                tracing::debug!(
                    error = %err,
                    pipe = %pipe_path.display(),
                    "agent pipe probe failed; proceeding with spawn"
                );
                return Ok(());
            }
        }
        if attempt + 1 < PROBE_ATTEMPTS {
            tokio::time::sleep(PROBE_INTERVAL).await;
        }
    }

    let pid_note = match last_seen_pid {
        Some(pid) => format!(" (pid {pid})"),
        None => String::new(),
    };
    Err(crate::MicrosandboxError::Runtime(format!(
        "agent pipe {} for sandbox '{sandbox_name}' is already being served by a stale sandbox \
         process{pid_note}; terminate that process and retry",
        pipe_path.display()
    )))
}

#[cfg(windows)]
fn probe_agent_pipe_server(pipe_path: &Path) -> std::io::Result<AgentPipeProbe> {
    const ERROR_PIPE_BUSY: i32 = 231;

    match std::fs::OpenOptions::new()
        .read(true)
        .write(true)
        .open(pipe_path)
    {
        Ok(client) => {
            let mut pid = 0u32;
            let ok =
                unsafe { GetNamedPipeServerProcessId(client.as_raw_handle() as HANDLE, &mut pid) };
            Ok(AgentPipeProbe::Served {
                server_pid: (ok != 0).then_some(pid),
            })
        }
        Err(err) if err.kind() == std::io::ErrorKind::NotFound => Ok(AgentPipeProbe::Free),
        // Every instance being busy still proves a live server.
        Err(err) if err.raw_os_error() == Some(ERROR_PIPE_BUSY) => {
            Ok(AgentPipeProbe::Served { server_pid: None })
        }
        Err(err) => Err(err),
    }
}

// The legacy `<sandboxes>/<name>/runtime/agent.sock` fallback only exists for
// backward compatibility with the pre-hash Unix layout; Windows never shipped a
// different agent-pipe scheme, so this is Unix-only.
#[cfg(unix)]
fn in_sandbox_agent_socket_path(sandboxes_dir: &Path, name: &str) -> PathBuf {
    sandboxes_dir.join(name).join("runtime").join("agent.sock")
}

/// Remove every Unix runtime socket artifact deterministically owned by a sandbox.
pub(crate) fn remove_sandbox_socket_artifacts_for(
    local: &LocalBackend,
    name: &str,
) -> MicrosandboxResult<()> {
    remove_sandbox_socket_artifacts_at(
        &local.config().run_dir(),
        &local.config().sandboxes_dir(),
        name,
    )
}

/// Remove runtime socket artifacts using explicit storage roots.
pub(crate) fn remove_sandbox_socket_artifacts_at(
    run_dir: &Path,
    sandboxes_dir: &Path,
    name: &str,
) -> MicrosandboxResult<()> {
    let canonical_result =
        microsandbox_runtime::ipc::remove_sandbox_socket_artifacts(run_dir, name);

    #[cfg(unix)]
    let fallback_result = microsandbox_runtime::ipc::remove_socket_pair(
        &in_sandbox_agent_socket_path(sandboxes_dir, name),
    );

    #[cfg(not(unix))]
    let fallback_result: std::io::Result<()> = {
        let _ = sandboxes_dir;
        Ok(())
    };

    canonical_result.and(fallback_result)?;
    Ok(())
}

/// Wait until no runtime generation owns a sandbox's deterministic namespace.
pub(crate) async fn acquire_sandbox_lifecycle_guard(
    run_dir: &Path,
    name: &str,
    timeout: std::time::Duration,
) -> MicrosandboxResult<microsandbox_runtime::ipc::SandboxLifecycleGuard> {
    let started = std::time::Instant::now();
    loop {
        if let Some(guard) = microsandbox_runtime::ipc::try_acquire_lifecycle_guard(run_dir, name)?
        {
            return Ok(guard);
        }
        if started.elapsed() >= timeout {
            return Err(crate::MicrosandboxError::SandboxStillRunning(format!(
                "sandbox {name:?} runtime still owns its lifecycle lock"
            )));
        }
        tokio::time::sleep(std::time::Duration::from_millis(50)).await;
    }
}

async fn terminate_startup_process(
    child: &mut tokio::process::Child,
) -> Option<std::process::ExitStatus> {
    let _ = child.start_kill();
    child.wait().await.ok()
}

/// Test-only handoff that lets the executor-progress test hold a
/// `spawn_blocking` staging worker at the gated copy while it checks that the
/// current-thread runtime keeps running tasks. If the copy ran inline on the
/// runtime thread, the heartbeat would stall and the test would fail.
#[cfg(all(test, any(target_os = "linux", target_os = "macos")))]
mod copy_worker_gate {
    use std::sync::{Condvar, Mutex};

    /// Set while the blocking worker is held at the gate.
    static BLOCKED: Mutex<bool> = Mutex::new(false);
    /// Notified by the test to release the worker.
    static RELEASE: Condvar = Condvar::new();

    /// Called from the blocking worker: announce that it reached the gated copy,
    /// then wait until the test releases it.
    pub(super) fn wait() {
        let mut blocked = BLOCKED.lock().unwrap();
        *blocked = true;
        RELEASE.notify_all();
        while *blocked {
            blocked = RELEASE.wait(blocked).unwrap();
        }
    }

    /// True while a worker is held at the gate.
    pub(super) fn blocked() -> bool {
        *BLOCKED.lock().unwrap()
    }

    /// Release a held worker.
    pub(super) fn release() {
        *BLOCKED.lock().unwrap() = false;
        RELEASE.notify_all();
    }
}

/// Test seam for the file-mount staging destination decision. `Automatic` uses
/// the real filesystem identity; the forced variants override only the
/// equality result so the cross-device branches can be exercised without a
/// second filesystem. Setup (metadata) failures still surface as errors.
#[cfg(unix)]
#[derive(Clone, Copy)]
enum FileMountStagingMode {
    Automatic,
    #[cfg(test)]
    ForceDeviceMismatch,
    #[cfg(test)]
    ForceDeviceMismatchAndRejectSourceParentStage,
    /// Substitute this errno for the `linkat` result, to exercise the
    /// mode-dependent link-failure handling without a privileged fixture.
    #[cfg(test)]
    ForceLinkErrno(i32),
    /// Replace the source after fstatat classification, before linkat.
    #[cfg(test)]
    ForceLeafSwapBeforeLink,
    /// Force the pinned source-parent stage descriptor to observe `m`, so the
    /// D5 gate's skipped and applied branches are distinguishable on an
    /// ordinary filesystem.
    #[cfg(test)]
    ForceSourceParentStageMode(u32),
    /// Force the D5 parent-writability gate true on a parent that is not
    /// group/other-writable.
    #[cfg(test)]
    ForceSourceParentForeignWritable,
    /// Force the first sandbox-dir `linkat` to return `EXDEV`, so the writable
    /// source-parent retry is exercised deterministically.
    #[cfg(test)]
    ForceFirstLinkExdev,
    /// Simulate a hostile foreign-owned `0700` directory at the first anchor: the
    /// pinned descriptor is observed as owned by another uid, so the D5
    /// ownership check must reject it.
    #[cfg(test)]
    ForceSourceParentStageSwap,
    /// After the first anchor, rename the stage root and plant a same-name decoy;
    /// population must stay on the held descriptor.
    #[cfg(test)]
    ForceStageSwapAfterAnchor,
    /// Rename the resolved source parent and plant a decoy tree; `mkdirat`/`linkat`
    /// must stay under the held parent.
    #[cfg(test)]
    ForceAncestorRedirect,
    /// Force the staged-entry verification `fstatat` to fail with `EIO`.
    #[cfg(test)]
    ForceVerifyStatError,
    /// Force a post-link identity mismatch, then a cleanup `unlinkat` failure.
    #[cfg(test)]
    ForceVerificationUnlinkError,
    /// Force the lazy-copy source open to fail with `EACCES`.
    #[cfg(test)]
    ForceCopyOpenError,
    /// Force the lazy-copy source `fstat` to fail with `EIO`.
    #[cfg(test)]
    ForceCopyStatError,
    /// Report the lazy-copy source as no longer regular.
    #[cfg(test)]
    ForceCopyNonRegular,
    /// Report the lazy-copy source as an identity change.
    #[cfg(test)]
    ForceCopyChanged,
    /// Fail the second mount after the first has been staged, so the unwind
    /// contract is exercised deterministically.
    #[cfg(test)]
    FailSecondMount,
    /// Hold the blocking copy worker at a gate, so an executor-progress test can
    /// prove the copy runs off the runtime thread.
    #[cfg(test)]
    ForceCopyWorkerGate,
}

#[cfg(unix)]
impl FileMountStagingMode {
    #[cfg(any(target_os = "linux", target_os = "macos"))]
    fn forces_device_mismatch(self) -> bool {
        match self {
            FileMountStagingMode::Automatic => false,
            // The source-parent-stage overrides imply the writable cross-device
            // path, since they only apply to a source-parent stage. The copy
            // hooks imply the cross-device readonly path, which copies directly.
            #[cfg(test)]
            FileMountStagingMode::ForceDeviceMismatch
            | FileMountStagingMode::ForceDeviceMismatchAndRejectSourceParentStage
            | FileMountStagingMode::ForceSourceParentStageMode(_)
            | FileMountStagingMode::ForceSourceParentForeignWritable
            | FileMountStagingMode::ForceSourceParentStageSwap
            | FileMountStagingMode::ForceStageSwapAfterAnchor
            | FileMountStagingMode::ForceAncestorRedirect
            | FileMountStagingMode::ForceCopyOpenError
            | FileMountStagingMode::ForceCopyStatError
            | FileMountStagingMode::ForceCopyNonRegular
            | FileMountStagingMode::ForceCopyChanged
            | FileMountStagingMode::ForceCopyWorkerGate => true,
            #[cfg(test)]
            _ => false,
        }
    }
}

/// One bind mount that passed the file-mount gate, with its host path already
/// resolved to a no-follow parent descriptor plus leaf.
#[cfg(any(target_os = "linux", target_os = "macos"))]
#[derive(Debug)]
struct FileMountCandidate {
    /// The path as the user wrote it. Under `follow_root_symlinks` this differs
    /// from `source.path()`; error messages name this one.
    requested: PathBuf,
    /// The classified, no-follow source.
    source: microsandbox_filesystem::nofollow::NoFollowFile,
    /// The guest path the mount is published at.
    guest: String,
    /// Whether the mount is readonly.
    readonly: bool,
}

/// The guest-path map a staging call returns: guest path to
/// `(canonical stage directory, staged filename, tag)`.
#[cfg(any(target_os = "linux", target_os = "macos"))]
type StagedFileMounts = HashMap<String, (PathBuf, String, String)>;

/// One bind mount admitted by the file-mount gate, before resolution. Owns the
/// values the original `filter_map` produced and introduces no policy on
/// `is_file() == false` mounts.
#[cfg(any(target_os = "linux", target_os = "macos"))]
#[derive(Debug)]
struct SelectedFileMount {
    requested: PathBuf,
    guest: String,
    readonly: bool,
    follow_root_symlinks: bool,
}

/// A file-mount stage root this process owns for the sandbox process lifetime.
#[derive(Debug)]
pub(crate) enum FileMountStageOwner {
    /// A source-parent stage pinned by held descriptors.
    #[cfg(any(target_os = "linux", target_os = "macos"))]
    SourceParent(microsandbox_filesystem::nofollow::SourceParentStage),
    /// A `TempDir`-owned stage. Only constructed on non-Linux/macOS targets;
    /// retained on all platforms so the handle plumbing and its tests share one
    /// type.
    #[allow(dead_code)]
    Temp(TempDir),
}

impl FileMountStageOwner {
    /// Release ownership without deleting the stage, so the detached VM process
    /// can keep reading it.
    pub(crate) fn detach(self) {
        match self {
            #[cfg(any(target_os = "linux", target_os = "macos"))]
            Self::SourceParent(stage) => stage.keep(),
            Self::Temp(dir) => {
                let _ = dir.keep();
            }
        }
    }

    /// The stage root path, for diagnostics and tests.
    #[allow(dead_code)]
    pub(crate) fn path(&self) -> &Path {
        match self {
            #[cfg(any(target_os = "linux", target_os = "macos"))]
            Self::SourceParent(stage) => stage.path(),
            Self::Temp(dir) => dir.path(),
        }
    }
}

/// The requested/resolved paths and guest path a staging error names.
#[cfg(any(target_os = "linux", target_os = "macos"))]
struct MountContext<'a> {
    requested: &'a Path,
    resolved: &'a Path,
    guest: &'a str,
    readonly: bool,
}

#[cfg(any(target_os = "linux", target_os = "macos"))]
impl MountContext<'_> {
    fn host(&self) -> String {
        if self.requested == self.resolved {
            self.requested.display().to_string()
        } else {
            format!(
                "{} (resolved to {})",
                self.requested.display(),
                self.resolved.display()
            )
        }
    }
}

/// Stage every file bind mount for one sandbox and return the guest-path map
/// plus the stage roots the caller must retain.
///
/// `sandbox_dir` is the backend-specific directory of the sandbox being
/// started (`<home>/sandboxes/<name>`). The Unix implementation stages into
/// `<sandbox_dir>/file-mounts` and resets it on every spawn. Callers must own
/// the sandbox lifecycle namespace and have established that the previous
/// generation is dead before calling; the lifecycle guard covers this on Unix.
/// The non-Unix implementation preserves the legacy system-temp staging and
/// ignores `sandbox_dir`.
async fn stage_file_mounts(
    config: &SandboxConfig,
    sandbox_dir: &Path,
) -> MicrosandboxResult<(
    HashMap<String, (PathBuf, String, String)>,
    Vec<FileMountStageOwner>,
)> {
    #[cfg(unix)]
    {
        stage_file_mounts_with_mode(config, sandbox_dir, FileMountStagingMode::Automatic).await
    }
    #[cfg(not(unix))]
    {
        let _ = sandbox_dir; // No metadata, cleanup, creation or path validation here.
        stage_file_mounts_legacy(config).await
    }
}

/// Unix file-mount staging: choose the stage root per mount by filesystem
/// identity, before any tag directory is created.
///
/// Same-device mounts hard-link into the private sandbox-dir stage; a readonly
/// cross-device mount copies into it; a writable cross-device mount hard-links
/// in a source-parent stage beside its source so guest writes reach it.
#[cfg(any(target_os = "linux", target_os = "macos"))]
async fn stage_file_mounts_with_mode(
    config: &SandboxConfig,
    sandbox_dir: &Path,
    mode: FileMountStagingMode,
) -> MicrosandboxResult<(
    HashMap<String, (PathBuf, String, String)>,
    Vec<FileMountStageOwner>,
)> {
    stage_file_mounts_with_after_gate_hook(config, sandbox_dir, mode, || {}).await
}

/// [`stage_file_mounts_with_mode`] with a `cfg(test)` hook that runs after the
/// following-stat gate has admitted its mounts and before canonicalize/resolve.
///
/// Production passes a no-op. The hook exists so a test can revoke search or
/// break a live opt-in symlink *after* `host.is_file()` has already returned
/// true, which is the only way to reach the post-gate classification branches
/// through the real entry point rather than by calling the classifier directly.
#[cfg(any(target_os = "linux", target_os = "macos"))]
async fn stage_file_mounts_with_after_gate_hook<F>(
    config: &SandboxConfig,
    sandbox_dir: &Path,
    mode: FileMountStagingMode,
    after_gate: F,
) -> MicrosandboxResult<(
    HashMap<String, (PathBuf, String, String)>,
    Vec<FileMountStageOwner>,
)>
where
    F: FnOnce() + Send + 'static,
{
    let stage_root = sandbox_dir.join("file-mounts");

    // Reset the previous generation's stage before identifying this one, even
    // when this spawn has no file mounts, so a restart never mixes generations.
    clear_sandbox_file_mount_stage(&stage_root).await?;

    // Phase 1A: the original following-stat filter, collected completely in
    // original order. This expression is the one at `:2205` before this change
    // and must not be rewritten: the behaviour-preservation argument for every
    // `is_file() == false` mount rests on it. Writing it as an `fstatat`, a
    // `symlink_metadata`, or a reuse of the resolver's own result silently
    // widens the change to directories, fifos and unresolvable paths.
    let mut selected: Vec<SelectedFileMount> = Vec::new();
    for mount in &config.spec.mounts {
        if let VolumeMount::Bind {
            host,
            guest,
            options,
            follow_root_symlinks,
            ..
        } = mount
            && host.is_file()
        {
            selected.push(SelectedFileMount {
                requested: host.clone(),
                guest: guest.clone(),
                readonly: options.readonly,
                follow_root_symlinks: *follow_root_symlinks,
            });
        }
    }
    if selected.is_empty() {
        return Ok((HashMap::new(), Vec::new()));
    }

    let stage_root_owned = stage_root.clone();
    tokio::task::spawn_blocking(move || {
        // Production passes a no-op; tests inject the post-gate break here.
        after_gate();
        let candidates = classify_file_mounts(selected)?;
        if candidates.is_empty() {
            return Ok((HashMap::new(), Vec::new()));
        }
        stage_candidates(candidates, &stage_root_owned, mode)
    })
    .await
    .map_err(|join_error| {
        crate::MicrosandboxError::InvalidConfig(format!(
            "file mount staging task failed: {join_error}"
        ))
    })?
}

/// Unix file-mount staging for other Unix targets: the pre-existing
/// implementation, retained byte-for-byte.
#[cfg(all(unix, not(any(target_os = "linux", target_os = "macos"))))]
async fn stage_file_mounts_with_mode(
    config: &SandboxConfig,
    sandbox_dir: &Path,
    mode: FileMountStagingMode,
) -> MicrosandboxResult<(
    HashMap<String, (PathBuf, String, String)>,
    Vec<FileMountStageOwner>,
)> {
    let stage_root = sandbox_dir.join("file-mounts");

    // Reset the previous generation's stage before identifying this one, even
    // when this spawn has no file mounts, so a restart never mixes generations.
    clear_sandbox_file_mount_stage(&stage_root).await?;

    let file_mounts: Vec<_> = config
        .spec
        .mounts
        .iter()
        .filter_map(|m| match m {
            VolumeMount::Bind {
                host,
                guest,
                options,
                ..
            } if host.is_file() => Some((host, guest, options.readonly)),
            _ => None,
        })
        .collect();
    if file_mounts.is_empty() {
        return Ok((HashMap::new(), Vec::new()));
    }

    // Create the sandbox-dir stage privately (mode `0700`): it holds hard links
    // to possibly private source files. It is not a `TempDir`: it persists
    // beyond handle drop until the next spawn of this name or `rm`.
    let mut builder = std::fs::DirBuilder::new();
    builder.mode(0o700);
    match builder.create(&stage_root) {
        Ok(()) => {}
        Err(error) if error.kind() == std::io::ErrorKind::AlreadyExists => {}
        Err(error) => {
            return Err(crate::MicrosandboxError::InvalidConfig(format!(
                "failed to create file mount staging directory {}: {error}",
                stage_root.display()
            )));
        }
    }
    restrict_stage_root_to_owner(&stage_root).map_err(|error| {
        crate::MicrosandboxError::InvalidConfig(format!(
            "failed to restrict file mount staging {} to its owner: {error}",
            stage_root.display()
        ))
    })?;

    let stage_dev = file_mount_device_id(&stage_root).map_err(|error| {
        crate::MicrosandboxError::InvalidConfig(format!(
            "failed to stat file mount staging directory {}: {error}",
            stage_root.display()
        ))
    })?;

    let mut staging: Vec<TempDir> = Vec::new();
    let mut staged = HashMap::new();
    for (host, guest, readonly) in file_mounts {
        let id: u32 = rand::rng().random();
        let tag = format!("fm_{id:08x}");
        let filename_os = host.file_name().ok_or_else(|| {
            crate::MicrosandboxError::InvalidConfig(format!(
                "file mount has no filename: {}",
                host.display()
            ))
        })?;
        let filename = filename_os
            .to_str()
            .ok_or_else(|| {
                crate::MicrosandboxError::InvalidConfig(format!(
                    "file mount filename is not valid UTF-8: {}",
                    host.display()
                ))
            })?
            .to_owned();

        let source_dev = file_mount_device_id(host).map_err(|error| {
            crate::MicrosandboxError::InvalidConfig(format!(
                "failed to stat file mount source {}: {error}",
                host.display()
            ))
        })?;
        let same_device = match mode {
            FileMountStagingMode::Automatic => source_dev == stage_dev,
            #[cfg(test)]
            FileMountStagingMode::ForceDeviceMismatch
            | FileMountStagingMode::ForceDeviceMismatchAndRejectSourceParentStage => false,
        };

        let stage_dir = if same_device {
            // Same filesystem: hard link into the sandbox-dir stage. This keeps
            // inode identity, so even a readonly mount is the source file
            // rather than a snapshot.
            let dir = create_file_mount_stage_dir(&stage_root, &tag).await?;
            let target = dir.join(&filename);
            tokio::fs::hard_link(host, &target).await.map_err(|error| {
                crate::MicrosandboxError::InvalidConfig(format!(
                    "failed to hard link file mount {} to {}: {error}",
                    host.display(),
                    target.display()
                ))
            })?;
            dir
        } else if readonly {
            // Cross-device readonly: copy into the sandbox-dir stage. A hard
            // link cannot cross filesystems, and a readonly mount needs no
            // writeback, so an isolated copy is correct.
            let dir = create_file_mount_stage_dir(&stage_root, &tag).await?;
            let target = dir.join(&filename);
            tokio::fs::copy(host, &target).await.map_err(|error| {
                crate::MicrosandboxError::InvalidConfig(format!(
                    "failed to copy file mount {} to {}: {error}",
                    host.display(),
                    target.display()
                ))
            })?;
            dir
        } else {
            // Cross-device writable: preserve inode identity by hard-linking in
            // a stage beside the source, which must be on the source's own
            // filesystem. Copying would lose guest writes.
            //
            // `parent()` is `Some("")` for a bare relative path such as
            // `foo.txt`, which is not a directory to stage in.
            let parent = host
                .parent()
                .filter(|parent| !parent.as_os_str().is_empty())
                .ok_or_else(|| {
                    crate::MicrosandboxError::InvalidConfig(format!(
                        "file mount has no parent directory: {}",
                        host.display()
                    ))
                })?;
            let local = match mode {
                #[cfg(test)]
                FileMountStagingMode::ForceDeviceMismatchAndRejectSourceParentStage => {
                    Err(std::io::Error::new(
                        std::io::ErrorKind::PermissionDenied,
                        "forced unwritable source parent for file mount staging",
                    ))
                }
                _ => tempfile::Builder::new()
                    .prefix(".microsandbox-file-mount-")
                    .tempdir_in(parent),
            }
            .map_err(|error| {
                crate::MicrosandboxError::InvalidConfig(format!(
                    "cannot stage writable file mount {} across a filesystem boundary: the \
                     staging directory must live beside the source in {}, which must be \
                     writable so guest writes reach the host file: {error}",
                    host.display(),
                    parent.display()
                ))
            })?;
            // The stage root holds a hard link to a possibly private source
            // file, so keep it owner-only instead of inheriting the umask.
            restrict_stage_root_to_owner(local.path()).map_err(|error| {
                crate::MicrosandboxError::InvalidConfig(format!(
                    "failed to restrict file mount staging {} to its owner: {error}",
                    local.path().display()
                ))
            })?;
            let dir = create_file_mount_stage_dir(local.path(), &tag).await?;
            let target = dir.join(&filename);
            tokio::fs::hard_link(host, &target).await?;
            staging.push(local);
            dir
        };
        let file_mount_dir = tokio::fs::canonicalize(&stage_dir).await?;
        staged.insert(guest.clone(), (file_mount_dir, filename, tag));
    }
    let owners = staging.into_iter().map(FileMountStageOwner::Temp).collect();
    Ok((staged, owners))
}

/// Create the private `<tag>` directory for one file mount under `stage_root`
/// and return it. Naming the directory in the error lets a caller attribute a
/// creation failure to the mount being staged.
#[cfg(all(unix, not(any(target_os = "linux", target_os = "macos"))))]
async fn create_file_mount_stage_dir(stage_root: &Path, tag: &str) -> MicrosandboxResult<PathBuf> {
    let dir = stage_root.join(tag);
    tokio::fs::create_dir(&dir).await.map_err(|error| {
        crate::MicrosandboxError::InvalidConfig(format!(
            "failed to create file mount staging directory {}: {error}",
            dir.display()
        ))
    })?;
    Ok(dir)
}

//--------------------------------------------------------------------------------------------------
// Functions: Helpers (no-follow file-mount staging)
//--------------------------------------------------------------------------------------------------

/// Classify every bind mount in `config` into file-mount candidates, applying
/// the no-follow policy to exactly the mounts that are file mounts today.
///
/// **Stage A — the gate.** A `VolumeMount::Bind` reaches this function only when
/// the unchanged `host.is_file()` filter admitted it. Everything else keeps the
/// directory-bind path with no inspection and no rejection.
///
/// **Stage B — the policy.** `follow_root_symlinks` canonicalizes the path
/// first; then the path is resolved following no symlink in any component,
/// preserving `..` with the descriptor stack, and the leaf is classified through
/// the parent descriptor.
#[cfg(any(target_os = "linux", target_os = "macos"))]
fn classify_file_mounts(
    selected: Vec<SelectedFileMount>,
) -> MicrosandboxResult<Vec<FileMountCandidate>> {
    use microsandbox_filesystem::nofollow::{NoFollowError, NoFollowPath};

    let mut candidates = Vec::with_capacity(selected.len());
    for item in selected {
        let resolved = if item.follow_root_symlinks {
            std::fs::canonicalize(&item.requested).map_err(|error| {
                crate::MicrosandboxError::InvalidConfig(format!(
                    "file mount source {} has follow-root-symlinks set but could not be \
                     resolved: {error}.",
                    item.requested.display()
                ))
            })?
        } else {
            item.requested.clone()
        };
        let context = MountContext {
            requested: &item.requested,
            resolved: &resolved,
            guest: &item.guest,
            readonly: item.readonly,
        };
        let source = NoFollowPath::resolve(&resolved)
            .and_then(NoFollowPath::classify_regular)
            .map_err(|error| match error {
                NoFollowError::Symlink { component } => {
                    if item.follow_root_symlinks {
                        symlink_reappeared_error(&context, &component)
                    } else if component == resolved {
                        symlink_leaf_error(&context)
                    } else {
                        symlink_ancestor_error(&context, &component)
                    }
                }
                NoFollowError::NonRegular { .. } => {
                    crate::MicrosandboxError::InvalidConfig(format!(
                        "file mount source {} changed while it was being classified: it is no \
                         longer a regular file. Spawn refused.",
                        context.host()
                    ))
                }
                NoFollowError::Unresolved { component, source } => {
                    crate::MicrosandboxError::InvalidConfig(format!(
                        "file mount source {} cannot be resolved at {}: {source}.",
                        context.host(),
                        component.display()
                    ))
                }
                NoFollowError::Unsupported { path, reason } => {
                    crate::MicrosandboxError::InvalidConfig(format!(
                        "file mount source {} cannot be resolved: {reason}.",
                        path.display()
                    ))
                }
            })?;
        candidates.push(FileMountCandidate {
            requested: item.requested,
            source,
            guest: item.guest,
            readonly: item.readonly,
        });
    }
    Ok(candidates)
}

/// The shared tail of both symlink-refusal messages, so the two opt-in
/// spellings cannot drift apart.
#[cfg(any(target_os = "linux", target_os = "macos"))]
const FILE_MOUNT_SYMLINK_TAIL: &str = "mount paths are resolved following no symlink by default, \
     so a symlink cannot redirect the mount. Opt in with .follow_root_symlinks(true) in the SDK, or \
     the `follow-root-symlinks` option on a CLI mount";

#[cfg(any(target_os = "linux", target_os = "macos"))]
fn symlink_ancestor_error(
    context: &MountContext<'_>,
    component: &Path,
) -> crate::MicrosandboxError {
    crate::MicrosandboxError::InvalidConfig(format!(
        "file mount source {} resolves through a symlink at {}: {FILE_MOUNT_SYMLINK_TAIL} \
         (-v {}:{}:follow-root-symlinks).",
        context.host(),
        component.display(),
        context.requested.display(),
        context.guest
    ))
}

#[cfg(any(target_os = "linux", target_os = "macos"))]
fn symlink_leaf_error(context: &MountContext<'_>) -> crate::MicrosandboxError {
    crate::MicrosandboxError::InvalidConfig(format!(
        "file mount source {} is a symlink: {FILE_MOUNT_SYMLINK_TAIL} \
         (-v {}:{}:follow-root-symlinks).",
        context.host(),
        context.requested.display(),
        context.guest
    ))
}

#[cfg(any(target_os = "linux", target_os = "macos"))]
fn symlink_reappeared_error(
    context: &MountContext<'_>,
    component: &Path,
) -> crate::MicrosandboxError {
    crate::MicrosandboxError::InvalidConfig(format!(
        "file mount source {} changed while it was being resolved: a symlink appeared at {} after \
         the path was canonicalized. Spawn refused.",
        context.host(),
        component.display()
    ))
}

/// Create the private sandbox-dir stage root (`0700`), tolerating an existing
/// directory and resetting its mode.
#[cfg(any(target_os = "linux", target_os = "macos"))]
fn create_stage_root(stage_root: &Path) -> MicrosandboxResult<()> {
    let mut builder = std::fs::DirBuilder::new();
    builder.mode(0o700);
    match builder.create(stage_root) {
        Ok(()) => {}
        Err(error) if error.kind() == std::io::ErrorKind::AlreadyExists => {}
        Err(error) => {
            return Err(crate::MicrosandboxError::InvalidConfig(format!(
                "failed to create file mount staging directory {}: {error}",
                stage_root.display()
            )));
        }
    }
    restrict_stage_root_to_owner(stage_root).map_err(|error| {
        crate::MicrosandboxError::InvalidConfig(format!(
            "failed to restrict file mount staging {} to its owner: {error}",
            stage_root.display()
        ))
    })
}

/// Stage every candidate into the sandbox-dir or a source-parent stage.
///
/// On any error, every source-parent owner created so far is explicitly closed
/// before the error is returned, so a partially staged spawn does not leak
/// source-owned descriptors.
#[cfg(any(target_os = "linux", target_os = "macos"))]
fn stage_candidates(
    candidates: Vec<FileMountCandidate>,
    stage_root: &Path,
    mode: FileMountStagingMode,
) -> MicrosandboxResult<(StagedFileMounts, Vec<FileMountStageOwner>)> {
    use microsandbox_filesystem::nofollow::NoFollowDir;

    create_stage_root(stage_root)?;
    let stage_dev = file_mount_device_id(stage_root).map_err(|error| {
        crate::MicrosandboxError::InvalidConfig(format!(
            "failed to stat file mount staging directory {}: {error}",
            stage_root.display()
        ))
    })?;
    let stage_root_dir = NoFollowDir::open(stage_root).map_err(|error| {
        crate::MicrosandboxError::InvalidConfig(format!(
            "failed to open file mount staging directory {}: {error}",
            stage_root.display()
        ))
    })?;

    let mut owners: Vec<FileMountStageOwner> = Vec::new();
    let mut staged: HashMap<String, (PathBuf, String, String)> = HashMap::new();
    for (index, candidate) in candidates.iter().enumerate() {
        if let Err(error) = stage_one(
            index,
            candidate,
            &stage_root_dir,
            stage_dev,
            mode,
            &mut owners,
            &mut staged,
        ) {
            // Close every source-parent owner created so far, and report each
            // retained object/cause in the returned error, not only via tracing.
            let mut retained_cleanup: Vec<String> = Vec::new();
            for owner in owners.drain(..) {
                match owner {
                    FileMountStageOwner::SourceParent(stage) => {
                        if let Err(cleanup) = stage.close() {
                            tracing::warn!(
                                error = %cleanup,
                                "failed to clean up source-parent file-mount stage after a staging error"
                            );
                            retained_cleanup.push(cleanup.to_string());
                        }
                    }
                    FileMountStageOwner::Temp(dir) => drop(dir),
                }
            }
            // Earlier sandbox-dir entries are not removed by this unwind; they are
            // cleared by the next spawn, so name them rather than promising global
            // emptiness.
            if !staged.is_empty() {
                retained_cleanup.push(format!(
                    "Earlier sandbox-dir stages may remain under {}; they are cleared by the \
                     next spawn or rm.",
                    stage_root.display()
                ));
            }
            return Err(append_retained_cleanup(error, &retained_cleanup));
        }
    }
    Ok((staged, owners))
}

/// Append the cleanup failures/notes retained by the explicit unwind to the
/// returned error, so a caller never learns of a retained stage only from logs.
#[cfg(any(target_os = "linux", target_os = "macos"))]
fn append_retained_cleanup(
    error: crate::MicrosandboxError,
    retained: &[String],
) -> crate::MicrosandboxError {
    if retained.is_empty() {
        return error;
    }
    match error {
        crate::MicrosandboxError::InvalidConfig(message) => {
            crate::MicrosandboxError::InvalidConfig(format!(
                "{message} Retention notes: {}",
                retained.join(" ")
            ))
        }
        other => other,
    }
}

/// Stage one candidate and publish it into `staged`.
#[cfg(any(target_os = "linux", target_os = "macos"))]
#[allow(clippy::too_many_arguments)]
fn stage_one(
    index: usize,
    candidate: &FileMountCandidate,
    stage_root_dir: &microsandbox_filesystem::nofollow::NoFollowDir,
    stage_dev: u64,
    mode: FileMountStagingMode,
    owners: &mut Vec<FileMountStageOwner>,
    staged: &mut HashMap<String, (PathBuf, String, String)>,
) -> MicrosandboxResult<()> {
    // Fail the second mount after the first has already been staged, so the
    // unwind contract (first sandbox entry retained, first source-parent owner
    // closed) is exercised deterministically rather than by a filesystem race.
    #[cfg(test)]
    if index == 1 && matches!(mode, FileMountStagingMode::FailSecondMount) {
        return Err(crate::MicrosandboxError::InvalidConfig(format!(
            "failed to stage file mount {}: injected second-mount failure",
            candidate.requested.display()
        )));
    }
    let _ = index;
    let requested = &candidate.requested;
    let resolved = candidate.source.path();
    let context = MountContext {
        requested,
        resolved,
        guest: &candidate.guest,
        readonly: candidate.readonly,
    };
    let filename_os = requested.file_name().ok_or_else(|| {
        crate::MicrosandboxError::InvalidConfig(format!(
            "file mount has no filename: {}",
            requested.display()
        ))
    })?;
    let filename = filename_os
        .to_str()
        .ok_or_else(|| {
            crate::MicrosandboxError::InvalidConfig(format!(
                "file mount filename is not valid UTF-8: {}",
                requested.display()
            ))
        })?
        .to_owned();
    let id: u32 = rand::rng().random();
    let tag = format!("fm_{id:08x}");
    let source = &candidate.source;

    let same_device = if mode.forces_device_mismatch() {
        false
    } else {
        source.device() == stage_dev
    };

    if same_device {
        let tag_dir = stage_root_dir
            .create_subdir(OsStr::new(&tag), 0o700)
            .map_err(|error| sandbox_tag_creation_error(&context, error))?;
        match inject_link_result(source, &tag_dir, filename_os, mode, true) {
            Ok(()) => publish(
                staged,
                &context,
                &filename,
                &tag,
                tag_dir.path(),
                tag_dir.identity(),
                None,
            ),
            Err(StageError::SourceChanged { cleanup }) => {
                Err(source_changed_error(&context, tag_dir.path(), cleanup))
            }
            Err(StageError::Unverifiable {
                source: error,
                cleanup,
            }) => Err(unverifiable_error(&context, tag_dir.path(), error, cleanup)),
            Err(StageError::Link(_)) if context.readonly => {
                inject_copy_result(source, &tag_dir, filename_os, mode)
                    .map_err(|error| copy_error(&context, tag_dir.path(), error))?;
                publish(
                    staged,
                    &context,
                    &filename,
                    &tag,
                    tag_dir.path(),
                    tag_dir.identity(),
                    None,
                )
            }
            Err(StageError::Link(error)) if is_cross_device(&error) => {
                stage_root_dir
                    .remove_child(OsStr::new(&tag))
                    .map_err(|remove_error| {
                        crate::MicrosandboxError::InvalidConfig(format!(
                            "failed to remove empty sandbox file mount stage {}: {remove_error}",
                            tag_dir.path().display()
                        ))
                    })?;
                stage_beside_source(source, &context, &tag, filename_os, mode, owners, staged)
            }
            Err(StageError::Link(error)) => Err(link_error(&context, tag_dir.path(), error)),
        }
    } else if context.readonly {
        let tag_dir = stage_root_dir
            .create_subdir(OsStr::new(&tag), 0o700)
            .map_err(|error| sandbox_tag_creation_error(&context, error))?;
        // Test hook: hold the blocking worker here so an executor-progress test
        // can prove the copy runs off the runtime thread.
        #[cfg(test)]
        if matches!(mode, FileMountStagingMode::ForceCopyWorkerGate) {
            copy_worker_gate::wait();
        }
        inject_copy_result(source, &tag_dir, filename_os, mode)
            .map_err(|error| copy_error(&context, tag_dir.path(), error))?;
        publish(
            staged,
            &context,
            &filename,
            &tag,
            tag_dir.path(),
            tag_dir.identity(),
            None,
        )
    } else {
        stage_beside_source(source, &context, &tag, filename_os, mode, owners, staged)
    }
}

/// Stage a writable mount in a source-parent stage beside the resolved source
/// and link the leaf into its tag directory.
#[cfg(any(target_os = "linux", target_os = "macos"))]
#[allow(clippy::too_many_arguments)]
fn stage_beside_source(
    source: &microsandbox_filesystem::nofollow::NoFollowFile,
    context: &MountContext<'_>,
    tag: &str,
    filename_os: &OsStr,
    mode: FileMountStagingMode,
    owners: &mut Vec<FileMountStageOwner>,
    staged: &mut HashMap<String, (PathBuf, String, String)>,
) -> MicrosandboxResult<()> {
    // A bare relative source such as `foo.txt` has no parent directory to stage
    // in; this keeps the pre-existing requested-path eligibility error.
    let has_requested_parent = context
        .requested
        .parent()
        .is_some_and(|parent| !parent.as_os_str().is_empty());
    if !has_requested_parent {
        return Err(crate::MicrosandboxError::InvalidConfig(format!(
            "file mount has no parent directory: {}",
            context.requested.display()
        )));
    }
    #[cfg(test)]
    if matches!(
        mode,
        FileMountStagingMode::ForceDeviceMismatchAndRejectSourceParentStage
    ) {
        return Err(crate::MicrosandboxError::InvalidConfig(format!(
            "cannot stage writable file mount {} across a filesystem boundary: the staging \
             directory must live beside the source in {}, which must be writable so guest writes \
             reach the host file: forced unwritable source parent for file mount staging",
            context.host(),
            context
                .requested
                .parent()
                .map(|parent| parent.display().to_string())
                .unwrap_or_default()
        )));
    }

    let stage = create_stage_beside(source, mode)
        .map_err(|error| source_parent_stage_creation_error(context, error))?;
    owners.push(FileMountStageOwner::SourceParent(stage));
    let index = owners.len() - 1;
    let stage_ref = match &mut owners[index] {
        FileMountStageOwner::SourceParent(stage) => stage,
        FileMountStageOwner::Temp(_) => unreachable!("source-parent owner was just pushed"),
    };
    #[cfg(test)]
    let root_path = stage_ref.path().to_path_buf();
    stage_ref
        .create_tag(OsStr::new(tag))
        .map_err(|error| source_parent_stage_creation_error(context, error))?;
    // Test hook: after the root swap or ancestor redirect, complete the
    // replacement tree with the exact expected `fm_*` tag and a decoy leaf, so
    // `canonicalize` succeeds as a fixture precondition and the refusal is
    // attributable to the held-identity comparison rather than a missing path.
    #[cfg(test)]
    if matches!(
        mode,
        FileMountStagingMode::ForceStageSwapAfterAnchor
            | FileMountStagingMode::ForceAncestorRedirect
    ) {
        let decoy_tag = root_path.join(tag);
        if std::fs::create_dir_all(&decoy_tag).is_ok() {
            let _ = std::fs::write(decoy_tag.join(filename_os), b"decoy-leaf");
        }
    }
    let target = stage_ref.dir().path().to_path_buf();
    let tag_identity = stage_ref.dir().identity();
    let root_identity = stage_ref.identity();
    match inject_link_result(source, stage_ref.dir(), filename_os, mode, false) {
        Ok(()) => {
            stage_ref.set_leaf(filename_os);
            publish(
                staged,
                context,
                &filename_os.to_string_lossy(),
                tag,
                &target,
                tag_identity,
                Some(root_identity),
            )
        }
        Err(StageError::SourceChanged { cleanup }) => {
            Err(source_changed_error(context, &target, cleanup))
        }
        Err(StageError::Unverifiable {
            source: error,
            cleanup,
        }) => Err(unverifiable_error(context, &target, error, cleanup)),
        Err(StageError::Link(error)) => Err(link_error(context, &target, error)),
    }
}

/// Create a source-parent stage, honouring the test-mode overrides.
#[cfg(any(target_os = "linux", target_os = "macos"))]
fn create_stage_beside(
    source: &microsandbox_filesystem::nofollow::NoFollowFile,
    mode: FileMountStagingMode,
) -> Result<
    microsandbox_filesystem::nofollow::SourceParentStage,
    microsandbox_filesystem::nofollow::StageCreateError,
> {
    #[cfg(test)]
    match mode {
        FileMountStagingMode::ForceSourceParentStageMode(observed) => {
            return source.create_stage_beside_with_override(StageOverrides {
                mode: Some(observed),
                ..StageOverrides::default()
            });
        }
        FileMountStagingMode::ForceSourceParentForeignWritable => {
            return source.create_stage_beside_with_override(StageOverrides {
                force_foreign_writable: true,
                ..StageOverrides::default()
            });
        }
        FileMountStagingMode::ForceSourceParentStageSwap => {
            // A foreign-owned directory cannot be created without privilege, so
            // the pinned descriptor is observed as uid 0 while the real directory
            // stays caller-owned 0700. This drives exactly the ownership check a
            // real decoy would trip.
            return source.create_stage_beside_with_override(StageOverrides {
                uid: Some(0),
                force_foreign_writable: true,
                ..StageOverrides::default()
            });
        }
        FileMountStagingMode::ForceStageSwapAfterAnchor => {
            return source.create_stage_beside_with_override(StageOverrides {
                swap_after_anchor: true,
                ..StageOverrides::default()
            });
        }
        FileMountStagingMode::ForceAncestorRedirect => {
            return source.create_stage_beside_with_override(StageOverrides {
                redirect_ancestor: true,
                ..StageOverrides::default()
            });
        }
        _ => {}
    }
    let _ = mode;
    source.create_stage_beside()
}

/// Swap the classified source leaf in place, so the next `linkat` observes a
/// different inode than classification did.
#[cfg(all(test, any(target_os = "linux", target_os = "macos")))]
fn swap_source_leaf_for_test(source: &microsandbox_filesystem::nofollow::NoFollowFile) {
    if let Some(parent) = source.path().parent() {
        let decoy = parent.join(format!(".msb-decoy-{}", std::process::id()));
        if std::fs::write(&decoy, b"decoy").is_ok() {
            let _ = std::fs::rename(&decoy, source.path());
        }
    }
}

/// Link the classified source into `dir`, honouring the test-mode injections.
#[cfg(all(test, any(target_os = "linux", target_os = "macos")))]
fn inject_link_result(
    source: &microsandbox_filesystem::nofollow::NoFollowFile,
    dir: &microsandbox_filesystem::nofollow::NoFollowDir,
    name: &OsStr,
    mode: FileMountStagingMode,
    sandbox_first_attempt: bool,
) -> Result<(), StageError> {
    let mut faults = LinkFaults::default();
    match mode {
        FileMountStagingMode::ForceLinkErrno(errno) => {
            return Err(StageError::Link(std::io::Error::from_raw_os_error(errno)));
        }
        FileMountStagingMode::ForceFirstLinkExdev if sandbox_first_attempt => {
            return Err(StageError::Link(std::io::Error::from_raw_os_error(
                libc::EXDEV,
            )));
        }
        FileMountStagingMode::ForceLeafSwapBeforeLink => swap_source_leaf_for_test(source),
        FileMountStagingMode::ForceVerifyStatError => faults.verify_stat_errno = Some(libc::EIO),
        FileMountStagingMode::ForceVerificationUnlinkError => {
            swap_source_leaf_for_test(source);
            faults.unlink_errno = Some(libc::EACCES);
        }
        _ => {}
    }
    source.link_into_with_faults(dir, name, faults)
}

/// Link the classified source into `dir`.
#[cfg(all(not(test), any(target_os = "linux", target_os = "macos")))]
fn inject_link_result(
    source: &microsandbox_filesystem::nofollow::NoFollowFile,
    dir: &microsandbox_filesystem::nofollow::NoFollowDir,
    name: &OsStr,
    _mode: FileMountStagingMode,
    _sandbox_first_attempt: bool,
) -> Result<(), StageError> {
    source.link_into(dir, name)
}

/// Copy the classified source into `dir`, honouring the test-mode injections.
#[cfg(all(test, any(target_os = "linux", target_os = "macos")))]
fn inject_copy_result(
    source: &microsandbox_filesystem::nofollow::NoFollowFile,
    dir: &microsandbox_filesystem::nofollow::NoFollowDir,
    name: &OsStr,
    mode: FileMountStagingMode,
) -> Result<(), CopyError> {
    let faults = match mode {
        FileMountStagingMode::ForceCopyOpenError => CopyFaults {
            open_errno: Some(libc::EACCES),
            ..CopyFaults::default()
        },
        FileMountStagingMode::ForceCopyStatError => CopyFaults {
            stat_errno: Some(libc::EIO),
            ..CopyFaults::default()
        },
        FileMountStagingMode::ForceCopyNonRegular => CopyFaults {
            non_regular: true,
            ..CopyFaults::default()
        },
        FileMountStagingMode::ForceCopyChanged => CopyFaults {
            changed: true,
            ..CopyFaults::default()
        },
        _ => CopyFaults::default(),
    };
    source.copy_into_with_faults(dir, name, faults)
}

/// Copy the classified source into `dir`.
#[cfg(all(not(test), any(target_os = "linux", target_os = "macos")))]
fn inject_copy_result(
    source: &microsandbox_filesystem::nofollow::NoFollowFile,
    dir: &microsandbox_filesystem::nofollow::NoFollowDir,
    name: &OsStr,
    _mode: FileMountStagingMode,
) -> Result<(), CopyError> {
    source.copy_into(dir, name)
}

/// Stat a path's `(dev, ino)` identity, following symlinks.
#[cfg(any(target_os = "linux", target_os = "macos"))]
fn path_identity(path: &Path) -> std::io::Result<microsandbox_filesystem::nofollow::StageIdentity> {
    use std::os::unix::fs::MetadataExt;

    let meta = std::fs::metadata(path)?;
    Ok(microsandbox_filesystem::nofollow::StageIdentity {
        dev: meta.dev(),
        ino: meta.ino(),
    })
}

/// Canonicalize the tag directory, verify it still resolves to the pinned
/// tag/root descriptors, and insert the staged map tuple.
///
/// `canonicalize` alone is not an identity check: a complete replacement tree
/// containing the exact expected `fm_*` tag canonicalizes successfully. The
/// held `(dev, ino)` comparisons are what refuse a substituted stage. This is a
/// consistency check, not a closure of the later path-to-VMM window.
#[cfg(any(target_os = "linux", target_os = "macos"))]
fn publish(
    staged: &mut HashMap<String, (PathBuf, String, String)>,
    context: &MountContext<'_>,
    filename: &str,
    tag: &str,
    tag_path: &Path,
    held_tag: microsandbox_filesystem::nofollow::StageIdentity,
    held_root: Option<microsandbox_filesystem::nofollow::StageIdentity>,
) -> MicrosandboxResult<()> {
    let file_mount_dir = std::fs::canonicalize(tag_path).map_err(|error| {
        crate::MicrosandboxError::InvalidConfig(format!(
            "failed to canonicalize file mount staging {}: {error}",
            tag_path.display()
        ))
    })?;
    let found_tag = path_identity(&file_mount_dir).map_err(|error| {
        crate::MicrosandboxError::InvalidConfig(format!(
            "failed to stat canonical file mount staging {}: {error}",
            file_mount_dir.display()
        ))
    })?;
    if found_tag != held_tag {
        return Err(crate::MicrosandboxError::InvalidConfig(format!(
            "file mount staging {} no longer matches the pinned tag directory (expected dev={}, \
             ino={}; found dev={}, ino={}). Spawn refused.",
            tag_path.display(),
            held_tag.dev,
            held_tag.ino,
            found_tag.dev,
            found_tag.ino
        )));
    }
    if let Some(held_root) = held_root {
        let parent = file_mount_dir.parent().ok_or_else(|| {
            crate::MicrosandboxError::InvalidConfig(format!(
                "canonical file mount staging {} has no parent directory",
                file_mount_dir.display()
            ))
        })?;
        let found_root = path_identity(parent).map_err(|error| {
            crate::MicrosandboxError::InvalidConfig(format!(
                "failed to stat file mount staging root {}: {error}",
                parent.display()
            ))
        })?;
        if found_root != held_root {
            return Err(crate::MicrosandboxError::InvalidConfig(format!(
                "file mount staging root {} no longer matches the pinned stage root (expected \
                 dev={}, ino={}; found dev={}, ino={}). Spawn refused.",
                parent.display(),
                held_root.dev,
                held_root.ino,
                found_root.dev,
                found_root.ino
            )));
        }
    }
    staged.insert(
        context.guest.to_string(),
        (file_mount_dir, filename.to_string(), tag.to_string()),
    );
    Ok(())
}

/// Render the `[5c]` cleanup suffix for a staging error.
#[cfg(any(target_os = "linux", target_os = "macos"))]
fn cleanup_suffix(cleanup: CleanupOutcome) -> String {
    match cleanup {
        CleanupOutcome::Removed => " The attempted entry was removed.".to_string(),
        CleanupOutcome::Retained {
            target,
            source,
            stage,
            identity,
        } => {
            format!(
                " Could not remove {}: {source}. Stage retained at last-known path {} (dev={}, ino={}).",
                target.display(),
                stage.display(),
                identity.dev,
                identity.ino
            )
        }
    }
}

#[cfg(any(target_os = "linux", target_os = "macos"))]
fn source_changed_error(
    context: &MountContext<'_>,
    target: &Path,
    cleanup: CleanupOutcome,
) -> crate::MicrosandboxError {
    crate::MicrosandboxError::InvalidConfig(format!(
        "file mount source {} changed while it was being staged: the entry linked into {} does not \
         match the classified source identity or regular kind. Spawn refused.{}",
        context.host(),
        target.display(),
        cleanup_suffix(cleanup)
    ))
}

#[cfg(any(target_os = "linux", target_os = "macos"))]
fn unverifiable_error(
    context: &MountContext<'_>,
    target: &Path,
    error: std::io::Error,
    cleanup: CleanupOutcome,
) -> crate::MicrosandboxError {
    crate::MicrosandboxError::InvalidConfig(format!(
        "could not verify staged file mount {} at {}: {error}. Spawn refused.{}",
        context.host(),
        target.display(),
        cleanup_suffix(cleanup)
    ))
}

#[cfg(any(target_os = "linux", target_os = "macos"))]
fn link_error(
    context: &MountContext<'_>,
    target: &Path,
    error: std::io::Error,
) -> crate::MicrosandboxError {
    let base = format!(
        "failed to hard link file mount {} for guest path {} to {}: {error}. A writable file mount \
         must keep the host inode, so it cannot fall back to a copy.",
        context.host(),
        context.guest,
        target.display()
    );
    if error.raw_os_error() == Some(libc::EPERM) {
        crate::MicrosandboxError::InvalidConfig(format!(
            "{base} On Linux fs.protected_hardlinks=1 refuses a hard link to a file you neither own \
             nor can both read and write: mount it readonly, or change the file's ownership."
        ))
    } else {
        crate::MicrosandboxError::InvalidConfig(base)
    }
}

#[cfg(any(target_os = "linux", target_os = "macos"))]
fn copy_error(
    context: &MountContext<'_>,
    target: &Path,
    error: CopyError,
) -> crate::MicrosandboxError {
    match error {
        CopyError::Source(CopySourceError::NonRegular) => {
            crate::MicrosandboxError::InvalidConfig(format!(
                "file mount source {} is no longer regular when opened for copying. Spawn refused.",
                context.host()
            ))
        }
        CopyError::Source(CopySourceError::Changed) => {
            crate::MicrosandboxError::InvalidConfig(format!(
                "file mount source {} changed before copying: opened identity differs from \
                 classification. Spawn refused.",
                context.host()
            ))
        }
        CopyError::Source(CopySourceError::Open(error)) => {
            copy_operation_error(context, target, "open source for copy", error, None)
        }
        CopyError::Source(CopySourceError::Stat(error)) => {
            copy_operation_error(context, target, "fstat copy source", error, None)
        }
        CopyError::Operation {
            operation,
            source,
            cleanup,
        } => copy_operation_error(context, target, operation, source, cleanup),
    }
}

#[cfg(any(target_os = "linux", target_os = "macos"))]
fn copy_operation_error(
    context: &MountContext<'_>,
    target: &Path,
    operation: &str,
    error: std::io::Error,
    cleanup: Option<CleanupOutcome>,
) -> crate::MicrosandboxError {
    let mut message = format!(
        "failed to copy file mount {} for guest path {} to {}: {operation}: {error}. Spawn refused.",
        context.host(),
        context.guest,
        target.display()
    );
    if let Some(cleanup) = cleanup {
        message.push_str(&cleanup_suffix(cleanup));
    }
    crate::MicrosandboxError::InvalidConfig(message)
}

/// A tag-creation failure inside the sandbox-dir stage root.
///
/// This is the same-device hard-link path and the cross-device readonly copy
/// path; it is not a source-parent staging failure, so it must not claim to be
/// one.
#[cfg(any(target_os = "linux", target_os = "macos"))]
fn sandbox_tag_creation_error(
    context: &MountContext<'_>,
    error: microsandbox_filesystem::nofollow::StageCreateError,
) -> crate::MicrosandboxError {
    crate::MicrosandboxError::InvalidConfig(format!(
        "failed to create file mount staging directory for {}: {error}",
        context.host()
    ))
}

/// A source-parent stage creation or tag-acquisition failure.
#[cfg(any(target_os = "linux", target_os = "macos"))]
fn source_parent_stage_creation_error(
    context: &MountContext<'_>,
    error: microsandbox_filesystem::nofollow::StageCreateError,
) -> crate::MicrosandboxError {
    crate::MicrosandboxError::InvalidConfig(format!(
        "cannot stage writable file mount {} across a filesystem boundary: the staging directory \
         must live beside the source, which must be writable so guest writes reach the host file: \
         {error}",
        context.host()
    ))
}

#[cfg(any(target_os = "linux", target_os = "macos"))]
fn is_cross_device(error: &std::io::Error) -> bool {
    error.raw_os_error() == Some(libc::EXDEV) || error.kind() == std::io::ErrorKind::CrossesDevices
}

/// Legacy non-Unix file-mount staging: eager system-temp root, then link, then
/// `EXDEV` routing. Preserved unchanged for Windows and other non-Unix targets;
/// this is not new platform support and does not use the sandbox directory.
#[cfg(not(unix))]
async fn stage_file_mounts_legacy(
    config: &SandboxConfig,
) -> MicrosandboxResult<(
    HashMap<String, (PathBuf, String, String)>,
    Vec<FileMountStageOwner>,
)> {
    let file_mounts: Vec<_> = config
        .spec
        .mounts
        .iter()
        .filter_map(|m| match m {
            VolumeMount::Bind {
                host,
                guest,
                options,
                ..
            } if host.is_file() => Some((host, guest, options.readonly)),
            _ => None,
        })
        .collect();
    if file_mounts.is_empty() {
        return Ok((HashMap::new(), Vec::new()));
    }

    // The system staging root is created eagerly: the hard-link fast path needs a
    // directory in the system temp dir to link into, and readonly cross-device
    // mounts copy into it. A writable cross-device mount abandons its (empty)
    // system-temp directory and stages in a second root beside its source.
    let tempdir = tempfile::tempdir()?;
    let mut staging = vec![FileMountStageOwner::Temp(tempdir)];
    let mut staged = HashMap::new();
    for (host, guest, readonly) in file_mounts {
        let id: u32 = rand::rng().random();
        let tag = format!("fm_{id:08x}");
        let filename_os = host.file_name().ok_or_else(|| {
            crate::MicrosandboxError::InvalidConfig(format!(
                "file mount has no filename: {}",
                host.display()
            ))
        })?;
        let filename = filename_os
            .to_str()
            .ok_or_else(|| {
                crate::MicrosandboxError::InvalidConfig(format!(
                    "file mount filename is not valid UTF-8: {}",
                    host.display()
                ))
            })?
            .to_owned();

        let mut file_mount_dir = staging[0].path().join(&tag);
        tokio::fs::create_dir_all(&file_mount_dir).await?;
        let mut target = file_mount_dir.join(&filename);
        let initial_link = tokio::fs::hard_link(host, &target).await;
        match initial_link {
            Ok(()) => {}
            Err(e) if is_cross_device_link_error(&e) && readonly => {
                tokio::fs::copy(host, &target).await?;
            }
            Err(e) if is_cross_device_link_error(&e) => {
                // A writable mount must retain inode identity. Stage beside the
                // source instead of copying, otherwise guest writes are lost.
                //
                // `parent()` is `Some("")` for a bare relative path such as
                // `foo.txt`, which is not a directory to stage in.
                let parent = host
                    .parent()
                    .filter(|parent| !parent.as_os_str().is_empty())
                    .ok_or_else(|| {
                        crate::MicrosandboxError::InvalidConfig(format!(
                            "file mount has no parent directory: {}",
                            host.display()
                        ))
                    })?;
                let local = tempfile::Builder::new()
                    .prefix(".microsandbox-file-mount-")
                    .tempdir_in(parent)
                    .map_err(|error| {
                        crate::MicrosandboxError::InvalidConfig(format!(
                            "cannot stage writable file mount {} across a filesystem boundary: the \
                             staging directory must live beside the source in {}, which must be \
                             writable so guest writes reach the host file: {error}",
                            host.display(),
                            parent.display()
                        ))
                    })?;
                // The stage root holds a hard link to a possibly private source
                // file, so keep it owner-only instead of inheriting the umask.
                restrict_stage_root_to_owner(local.path()).map_err(|error| {
                    crate::MicrosandboxError::InvalidConfig(format!(
                        "failed to restrict file mount staging {} to its owner: {error}",
                        local.path().display()
                    ))
                })?;
                file_mount_dir = local.path().join(&tag);
                tokio::fs::create_dir(&file_mount_dir).await?;
                target = file_mount_dir.join(&filename);
                tokio::fs::hard_link(host, &target).await?;
                staging.push(FileMountStageOwner::Temp(local));
            }
            Err(e) => return Err(e.into()),
        }
        let file_mount_dir = tokio::fs::canonicalize(&file_mount_dir).await?;
        staged.insert(guest.clone(), (file_mount_dir, filename, tag));
    }
    Ok((staged, staging))
}

/// Remove the exact sandbox-dir file-mount stage before a spawn reuses it.
///
/// A missing root is normal. The root is inspected with `symlink_metadata` so a
/// preexisting symlink is removed rather than traversed. A real directory is
/// removed recursively; a symlink or a stray regular file at exactly this
/// runtime-owned path is removed (only the link or file itself, never a
/// target); any other artifact type is a fatal error rather than something
/// cleared.
#[cfg(unix)]
async fn clear_sandbox_file_mount_stage(stage_root: &Path) -> MicrosandboxResult<()> {
    let metadata = match tokio::fs::symlink_metadata(stage_root).await {
        Ok(metadata) => metadata,
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => return Ok(()),
        Err(error) => {
            return Err(crate::MicrosandboxError::InvalidConfig(format!(
                "failed to inspect file mount staging directory {}: {error}",
                stage_root.display()
            )));
        }
    };

    let file_type = metadata.file_type();
    if file_type.is_dir() {
        tokio::fs::remove_dir_all(stage_root)
            .await
            .map_err(|error| {
                crate::MicrosandboxError::InvalidConfig(format!(
                    "failed to clear file mount staging directory {}: {error}",
                    stage_root.display()
                ))
            })
    } else if file_type.is_symlink() || file_type.is_file() {
        tokio::fs::remove_file(stage_root).await.map_err(|error| {
            crate::MicrosandboxError::InvalidConfig(format!(
                "failed to clear file mount staging directory {}: {error}",
                stage_root.display()
            ))
        })
    } else {
        Err(crate::MicrosandboxError::InvalidConfig(format!(
            "refusing to clear unexpected file mount staging artifact at {}",
            stage_root.display()
        )))
    }
}

/// Return the filesystem device id holding `path`, following symlinks so the
/// identity is that of the resolved file.
///
/// On Linux/macOS this now has a single caller: the sandbox-dir stage root,
/// which microsandbox owns and creates itself. Per-mount device identity comes
/// from the classified source's held-parent `fstatat` (`NoFollowFile::device`),
/// never from this helper.
#[cfg(unix)]
fn file_mount_device_id(path: &Path) -> std::io::Result<u64> {
    Ok(std::fs::metadata(path)?.dev())
}

/// Restrict a staging root to its owner (mode `0700`).
///
/// A sandbox-dir or source-parent stage holds a hard link to a possibly private
/// source file, so it must not be listable or traversable by other local users
/// no matter what the process umask is.
#[cfg(unix)]
fn restrict_stage_root_to_owner(path: &Path) -> std::io::Result<()> {
    use std::os::unix::fs::PermissionsExt;

    std::fs::set_permissions(path, std::fs::Permissions::from_mode(0o700))
}

#[cfg(not(unix))]
fn restrict_stage_root_to_owner(_path: &Path) -> std::io::Result<()> {
    Ok(())
}

/// Return whether a host hard-link failed because the target is on another device.
#[cfg(not(unix))]
fn is_cross_device_link_error(error: &std::io::Error) -> bool {
    error.kind() == std::io::ErrorKind::CrossesDevices || is_platform_cross_device_link_error(error)
}

#[cfg(windows)]
fn is_platform_cross_device_link_error(error: &std::io::Error) -> bool {
    // CreateHardLinkW reports cross-volume links as ERROR_NOT_SAME_DEVICE.
    const ERROR_NOT_SAME_DEVICE: i32 = 17;

    error.raw_os_error() == Some(ERROR_NOT_SAME_DEVICE)
}

#[cfg(not(any(unix, windows)))]
fn is_platform_cross_device_link_error(_error: &std::io::Error) -> bool {
    false
}

/// Push a `--mount tag:host_path[:ro]` arg pair.
#[allow(clippy::too_many_arguments)]
fn push_dir_mount_arg(
    mounts: &mut Vec<String>,
    guest: &str,
    host_display: &impl std::fmt::Display,
    options: MountOptions,
    stat_virtualization: StatVirtualization,
    host_permissions: HostPermissions,
    follow_root_symlinks: bool,
    quota_mib: Option<u32>,
) {
    let tag = guest_mount_tag(guest);
    let mut arg = format!("{tag}:{host_display}");
    let mut opts = mount_option_tokens(options);
    append_policy_options(
        &mut opts,
        stat_virtualization,
        host_permissions,
        follow_root_symlinks,
        options.override_uid,
        options.override_gid,
    );
    if let Some(mib) = quota_mib {
        opts.push(format!("quota={mib}"));
    }
    append_option_block(&mut arg, opts);
    mounts.push(arg);
}

/// Collect a `fm_tag:file_mount_dir[:ro]` mount entry.
fn push_file_mount_arg(
    mounts: &mut Vec<String>,
    tag: &str,
    file_mount_dir: &Path,
    options: MountOptions,
    stat_virtualization: StatVirtualization,
    host_permissions: HostPermissions,
) {
    let mut arg = format!("{tag}:{}", file_mount_dir.display());
    let mut opts = mount_option_tokens(options);
    // The staging directory is canonicalized at creation, so it is symlink-free
    // and stays under the default no-follow root protection — no opt-out here.
    append_policy_options(
        &mut opts,
        stat_virtualization,
        host_permissions,
        false,
        options.override_uid,
        options.override_gid,
    );
    append_option_block(&mut arg, opts);
    mounts.push(arg);
}

/// Collect a `id:host_path:format[:ro]` disk entry.
fn push_disk_mount_arg(
    disks: &mut Vec<String>,
    id: &str,
    host_display: &impl std::fmt::Display,
    format: &DiskImageFormat,
    options: MountOptions,
) {
    let mut arg = format!("{id}:{host_display}:{}", format.as_str());
    if options.readonly {
        arg.push_str(":ro");
    }
    disks.push(arg);
}

fn mount_option_tokens(options: MountOptions) -> Vec<String> {
    let mut tokens = Vec::new();
    if options.readonly {
        tokens.push("ro".to_string());
    }
    if options.noexec {
        tokens.push("noexec".to_string());
    }
    if options.nosuid {
        tokens.push("nosuid".to_string());
    }
    if options.nodev {
        tokens.push("nodev".to_string());
    }
    tokens
}

fn bootstrap_mount_flags(options: MountOptions) -> BootstrapMountFlags {
    BootstrapMountFlags {
        readonly: options.readonly,
        noexec: options.noexec,
        nosuid: options.nosuid,
        nodev: options.nodev,
    }
}

fn append_policy_options(
    opts: &mut Vec<String>,
    stat_virtualization: StatVirtualization,
    host_permissions: HostPermissions,
    follow_root_symlinks: bool,
    override_uid: Option<u32>,
    override_gid: Option<u32>,
) {
    match stat_virtualization {
        StatVirtualization::Strict => {}
        StatVirtualization::Relaxed => opts.push("stat-virt=relaxed".to_string()),
        StatVirtualization::Off => opts.push("stat-virt=off".to_string()),
    }
    match host_permissions {
        HostPermissions::Private => {}
        HostPermissions::Mirror => opts.push("host-perms=mirror".to_string()),
    }
    // Presence token opts out of the protective default (no-follow root
    // resolution); its absence keeps the default protection on.
    if follow_root_symlinks {
        opts.push("follow-root-symlinks".to_string());
    }
    // Explicit guest owner for host files with no per-file override. This is a
    // host-side virtiofs presentation policy (like stat-virt/host-perms above):
    // it rides the `--mount` arg the VMM parses and must NOT leak into the guest
    // mount specs (`MSB_DIR_MOUNTS`/`MSB_FILE_MOUNTS`), where agentd would reject
    // `uid`/`gid` as unknown. The runtime requires the pair together; the SDK's
    // `owner()` setter always sets both.
    if let Some(uid) = override_uid {
        opts.push(format!("uid={uid}"));
    }
    if let Some(gid) = override_gid {
        opts.push(format!("gid={gid}"));
    }
}

fn append_option_block(spec: &mut String, opts: Vec<String>) {
    if opts.is_empty() {
        return;
    }
    spec.push(':');
    spec.push_str(&opts.join(","));
}

/// Derive a stable, collision-resistant identifier from a guest mount path.
///
/// Used for virtiofs tags and for virtio-blk `serial` fields (the block id
/// agentd resolves via `/dev/disk/by-id/virtio-<id>`). The naive `/` → `_`
/// mangling collides for adversarial inputs (`/var/log` and `/var_log` both
/// produce `var_log`), so we append a short sha256-derived suffix.
///
/// Output is at most 20 bytes — the kernel's virtio-blk serial length limit.
/// Layout: `<slug[..11]>_<8-hex>`. The slug-part is a debugging hint; the
/// 8-hex suffix is what actually disambiguates.
fn guest_mount_tag(guest_path: &str) -> String {
    use std::fmt::Write as _;

    const SLUG_MAX: usize = 11;
    const HASH_HEX_LEN: usize = 8;

    let slug: String = guest_path
        .replace('/', "_")
        .trim_start_matches('_')
        .chars()
        .take(SLUG_MAX)
        .collect();

    let mut hasher = Sha256::new();
    hasher.update(guest_path.as_bytes());
    let digest = hasher.finalize();

    // Total layout: optional `<slug>_` prefix + HASH_HEX_LEN hex chars.
    let mut out = String::with_capacity(slug.len() + 1 + HASH_HEX_LEN);
    if !slug.is_empty() {
        out.push_str(&slug);
        out.push('_');
    }
    for byte in digest.iter().take(HASH_HEX_LEN / 2) {
        // write! to a String can't fail.
        let _ = write!(out, "{byte:02x}");
    }
    out
}

/// Build the `msb sandbox` CLI args for a sandbox.
#[allow(clippy::too_many_arguments)]
fn sandbox_cli_args(
    local: &LocalBackend,
    config: &SandboxConfig,
    sandbox_id: i32,
    db_path: &Path,
    db_connect_timeout_secs: u64,
    log_dir: &Path,
    runtime_dir: &Path,
    agent_sock_path: &Path,
    libkrunfw_path: &Path,
    staged_file_mounts: &HashMap<String, (PathBuf, String, String)>,
    named_volumes: &HashMap<String, ResolvedNamedVolume>,
    metrics_reservation: Option<&MetricsReservation>,
    parent_watch_fd: Option<i32>,
    startup_fd: Option<i32>,
    startup_pipe: Option<&OsStr>,
) -> (Vec<OsString>, LaunchConfig) {
    // `visible` stays on the process argv: a small set of operator-readable
    // labels (name, id, sizing, fds) so the sandbox is identifiable in `ps`
    // and logs. Everything bulky, structured, or secret-bearing goes into the
    // typed `LaunchConfig`, delivered over the config fd. See issue #997.
    let mut visible = vec![OsString::from("sandbox")];

    if let Some(log_level) = config.spec.runtime.log_level {
        visible.push(OsString::from(sandbox_log_level_cli_flag(log_level)));
    }

    visible.push(OsString::from("--name"));
    visible.push(OsString::from(&config.spec.name));
    visible.push(OsString::from("--sandbox-id"));
    visible.push(OsString::from(sandbox_id.to_string()));
    if let Some(fd) = parent_watch_fd {
        visible.push(OsString::from("--parent-watch-fd"));
        visible.push(OsString::from(fd.to_string()));
    }
    if let Some(fd) = startup_fd {
        visible.push(OsString::from("--startup-fd"));
        visible.push(OsString::from(fd.to_string()));
    }
    if let Some(pipe) = startup_pipe {
        visible.push(OsString::from("--startup-pipe"));
        visible.push(pipe.to_os_string());
    }
    visible.push(OsString::from("--vcpus"));
    visible.push(OsString::from(config.spec.resources.cpus.to_string()));
    visible.push(OsString::from("--memory-mib"));
    visible.push(OsString::from(config.spec.resources.memory_mib.to_string()));
    if config.spec.resources.max_cpus > config.spec.resources.cpus {
        visible.push(OsString::from("--max-vcpus"));
        visible.push(OsString::from(config.spec.resources.max_cpus.to_string()));
    }
    if config.spec.resources.max_memory_mib > config.spec.resources.memory_mib {
        visible.push(OsString::from("--max-memory-mib"));
        visible.push(OsString::from(
            config.spec.resources.max_memory_mib.to_string(),
        ));
    }

    let mut launch = LaunchConfig {
        db_path: db_path.to_path_buf(),
        db_connect_timeout_secs,
        log_dir: log_dir.to_path_buf(),
        runtime_dir: runtime_dir.to_path_buf(),
        sandboxes_dir: local.sandboxes_dir(),
        run_dir: local.config().run_dir(),
        cpu_lease_dir: local.config().run_dir().join("cpu-leases"),
        writeback_lease_dir: local.config().run_dir().join("writeback-leases"),
        cpu_placement: config.spec.resources.cpu_placement,
        placement_profile_name: config.spec.resources.placement_profile.clone(),
        placement_profile: config
            .spec
            .resources
            .placement_profile
            .as_ref()
            .and_then(|name| local.config().runtime.placement_profiles.get(name))
            .copied(),
        agent_sock: agent_sock_path.to_path_buf(),
        libkrunfw_path: libkrunfw_path.to_path_buf(),
        thp: config.spec.resources.thp,
        startup: startup_command(config),
        lifecycle: Lifecycle {
            max_duration_secs: config.spec.lifecycle.max_duration_secs,
            idle_timeout_secs: config.spec.lifecycle.idle_timeout_secs,
        },
        vsock: config.spec.vsock.routes.clone(),
        #[cfg(feature = "net")]
        deployment_profile: config.spec.deployment_profile,
        bootstrap: GuestBootstrap {
            hostname: Some(
                config.spec.runtime.hostname.clone().unwrap_or_else(|| {
                    crate::sandbox::hostname_from_sandbox_name(&config.spec.name)
                }),
            ),
            rlimits: config
                .spec
                .rlimits
                .iter()
                .map(|rlimit| ExecRlimit {
                    resource: rlimit.resource.as_str().to_string(),
                    soft: rlimit.soft,
                    hard: rlimit.hard,
                })
                .collect(),
            user: config.spec.runtime.user.clone(),
            default_cwd: config.spec.runtime.workdir.clone(),
            default_env: config
                .spec
                .env
                .iter()
                .map(|var| BootstrapEnvVar {
                    key: var.key.clone(),
                    value: var.value.clone(),
                })
                .collect(),
            security_profile: match config.spec.security_profile {
                crate::sandbox::SecurityProfile::Default => BootstrapSecurityProfile::Default,
                crate::sandbox::SecurityProfile::Restricted => BootstrapSecurityProfile::Restricted,
            },
            handoff_init: config.spec.init.as_ref().map(|init| BootstrapHandoffInit {
                cmd: init.cmd.clone(),
                args: init.args.clone(),
                cwd: config.spec.runtime.workdir.clone(),
                env: init
                    .env
                    .iter()
                    .map(|(key, value)| BootstrapEnvVar {
                        key: key.clone(),
                        value: value.clone(),
                    })
                    .collect(),
            }),
            ..GuestBootstrap::default()
        },
        ..Default::default()
    };

    match config.effective_metrics_interval() {
        Some(ms) => launch.metrics.sample_interval_ms = ms.get(),
        None => launch.metrics.disabled = true,
    }
    if let Some(reservation) = metrics_reservation {
        launch.metrics.slot = Some(MetricsSlotHandoff {
            shm_name: reservation.shm_name.clone(),
            slot: reservation.slot,
            generation: reservation.generation,
        });
    }

    match &config.spec.image {
        RootfsSource::Bind {
            path,
            follow_root_symlinks,
        } => {
            launch.rootfs.path = Some(path.clone());
            launch.rootfs.follow_root_symlinks = *follow_root_symlinks;
        }
        RootfsSource::Oci(oci) => {
            if let Some(microsandbox_types::RootDisk::Flat { fstype, .. }) = &oci.root_disk {
                let sandbox_dir = local.sandboxes_dir().join(&config.spec.name);
                launch.rootfs.disk =
                    Some(sandbox_dir.join(crate::sandbox::flat_rootfs::FLAT_ROOTFS_FILENAME));
                launch.rootfs.disk_format = Some("raw".to_string());
                launch.bootstrap.block_root = Some(BootstrapBlockRoot::DiskImage {
                    device: "/dev/vda".to_string(),
                    fstype: Some(fstype.as_deref().unwrap_or("ext4").to_string()),
                });
            // Derive VMDK + upper paths from the stored manifest digest.
            } else if let Some(ref digest_str) = config.manifest_digest {
                let cache_dir = local.cache_dir();
                let cache = GlobalCache::new(&cache_dir).expect("cache init");
                let digest: Digest = digest_str.parse().expect("invalid manifest digest");
                let vmdk_path = cache.vmdk_path(&digest);

                // VMDK (fsmeta + layers) read-only.
                launch.rootfs.disk = Some(vmdk_path);
                launch.rootfs.disk_format = Some("vmdk".to_string());

                // Writable upper per root disk kind. Managed and disk-image
                // attach /dev/vdb; tmpfs attaches no upper device and the
                // guest assembles a RAM-backed upper itself.
                use microsandbox_types::RootDisk;
                let block_root = match &oci.root_disk {
                    None | Some(RootDisk::Managed { .. }) => {
                        let sandbox_dir = local.sandboxes_dir().join(&config.spec.name);
                        launch.rootfs.upper = Some(sandbox_dir.join("upper.ext4"));
                        BootstrapBlockRoot::OciErofs {
                            lower: "/dev/vda".to_string(),
                            upper: BootstrapBlockRootUpper::Device {
                                device: "/dev/vdb".to_string(),
                                fstype: "ext4".to_string(),
                            },
                        }
                    }
                    Some(RootDisk::Tmpfs { size_mib }) => BootstrapBlockRoot::OciErofs {
                        lower: "/dev/vda".to_string(),
                        upper: BootstrapBlockRootUpper::Tmpfs {
                            size_mib: *size_mib,
                        },
                    },
                    Some(RootDisk::DiskImage {
                        path,
                        format,
                        fstype,
                    }) => {
                        launch.rootfs.upper = Some(path.clone());
                        launch.rootfs.upper_format = Some(format.as_str().to_string());
                        BootstrapBlockRoot::OciErofs {
                            lower: "/dev/vda".to_string(),
                            upper: BootstrapBlockRootUpper::Device {
                                device: "/dev/vdb".to_string(),
                                fstype: fstype.as_deref().unwrap_or("ext4").to_string(),
                            },
                        }
                    }
                    Some(RootDisk::Flat { .. }) => {
                        unreachable!("flat root disks are handled before layered root assembly")
                    }
                };
                launch.bootstrap.block_root = Some(block_root);
            }
        }
        RootfsSource::DiskImage {
            path,
            format,
            fstype,
        } => {
            launch.rootfs.disk = Some(path.clone());
            launch.rootfs.disk_format = Some(format.as_str().to_string());

            launch.bootstrap.block_root = Some(BootstrapBlockRoot::DiskImage {
                device: "/dev/vda".to_string(),
                fstype: fstype.clone(),
            });
        }
    }

    // Process mounts: emit host-side device args and collect the matching
    // typed guest-side mount instructions for agentd.
    for mount in &config.spec.mounts {
        match mount {
            VolumeMount::Bind {
                host,
                guest,
                options,
                stat_virtualization,
                host_permissions,
                follow_root_symlinks,
                quota_mib,
            } => {
                if let Some((file_mount_dir, filename, tag)) = staged_file_mounts.get(guest) {
                    push_file_mount_arg(
                        &mut launch.mounts,
                        tag,
                        file_mount_dir,
                        *options,
                        *stat_virtualization,
                        *host_permissions,
                    );
                    launch.bootstrap.file_mounts.push(BootstrapFileMount {
                        tag: tag.clone(),
                        filename: filename.clone(),
                        guest_path: guest.clone(),
                        flags: bootstrap_mount_flags(*options),
                    });
                } else {
                    // A directory bind mount gets a protective guest-write
                    // quota: the caller's override, or the default.
                    let quota = quota_mib.unwrap_or(crate::sandbox::config::DEFAULT_BIND_QUOTA_MIB);
                    push_dir_mount_arg(
                        &mut launch.mounts,
                        guest,
                        &host.display(),
                        *options,
                        *stat_virtualization,
                        *host_permissions,
                        *follow_root_symlinks,
                        Some(quota),
                    );
                    launch.bootstrap.dir_mounts.push(BootstrapDirMount {
                        tag: guest_mount_tag(guest),
                        guest_path: guest.clone(),
                        flags: bootstrap_mount_flags(*options),
                    });
                }
            }
            VolumeMount::Named {
                name,
                guest,
                options,
                stat_virtualization,
                host_permissions,
                follow_root_symlinks,
                create: _,
            } => {
                let named_volume = named_volumes
                    .get(name)
                    .expect("resolve_named_volumes must resolve every named volume before render");
                match named_volume {
                    ResolvedNamedVolume {
                        kind: VolumeKind::Disk,
                        path,
                        format,
                        fstype,
                        ..
                    } => {
                        let format = format
                            .as_ref()
                            .expect("resolved disk named volumes must carry a disk format");
                        let id = guest_mount_tag(guest);
                        push_disk_mount_arg(
                            &mut launch.disks,
                            &id,
                            &path.display(),
                            format,
                            *options,
                        );
                        launch.bootstrap.disk_mounts.push(BootstrapDiskMount {
                            id,
                            guest_path: guest.clone(),
                            fstype: fstype.clone(),
                            flags: bootstrap_mount_flags(*options),
                        });
                    }
                    ResolvedNamedVolume {
                        path, quota_mib, ..
                    } => {
                        push_dir_mount_arg(
                            &mut launch.mounts,
                            guest,
                            &path.display(),
                            *options,
                            *stat_virtualization,
                            *host_permissions,
                            *follow_root_symlinks,
                            *quota_mib,
                        );
                        launch.bootstrap.dir_mounts.push(BootstrapDirMount {
                            tag: guest_mount_tag(guest),
                            guest_path: guest.clone(),
                            flags: bootstrap_mount_flags(*options),
                        });
                    }
                }
            }
            VolumeMount::Tmpfs {
                guest,
                size_mib,
                options,
            } => {
                launch.bootstrap.tmpfs_mounts.push(BootstrapTmpfsMount {
                    path: guest.clone(),
                    size_mib: *size_mib,
                    mode: None,
                    flags: bootstrap_mount_flags(*options),
                });
            }
            VolumeMount::DiskImage {
                host,
                guest,
                format,
                fstype,
                options,
            } => {
                let id = guest_mount_tag(guest);
                push_disk_mount_arg(&mut launch.disks, &id, &host.display(), format, *options);
                launch.bootstrap.disk_mounts.push(BootstrapDiskMount {
                    id,
                    guest_path: guest.clone(),
                    fstype: fstype.clone(),
                    flags: bootstrap_mount_flags(*options),
                });
            }
        }
    }

    // Network configuration travels as a typed value inside the JSON payload.
    #[cfg(feature = "net")]
    {
        launch.network = Some(
            config
                .local_network_config()
                .expect("sandbox network spec should decode to local network config"),
        );
        launch.sandbox_slot = sandbox_id as u64;
    }

    (visible, launch)
}

fn startup_command(config: &SandboxConfig) -> Option<StartupCommand> {
    let (cmd, cmd_args) = resolve_startup_command(config)?;
    Some(StartupCommand {
        cmd,
        args: cmd_args,
        env: config
            .spec
            .env
            .iter()
            .map(|var| format!("{}={}", var.key, var.value))
            .collect(),
        cwd: config.spec.runtime.workdir.clone(),
        user: config.spec.runtime.user.clone(),
    })
}

fn resolve_startup_command(config: &SandboxConfig) -> Option<(String, Vec<String>)> {
    if !config.should_launch_background_command() {
        return None;
    }

    match resolve_default_command(
        config.spec.runtime.entrypoint.as_deref(),
        config.spec.runtime.cmd.as_deref(),
        None,
    ) {
        Ok(command) => Some((command.program, command.args)),
        Err(CommandResolutionError::NoDefaultCommand) => None,
        Err(error) => {
            tracing::error!(%error, "invalid startup command reached runtime launch planning");
            None
        }
    }
}

fn sandbox_log_level_cli_flag(level: SandboxLogLevel) -> &'static str {
    match level {
        SandboxLogLevel::Error => "--error",
        SandboxLogLevel::Warn => "--warn",
        SandboxLogLevel::Info => "--info",
        SandboxLogLevel::Debug => "--debug",
        SandboxLogLevel::Trace => "--trace",
    }
}

//--------------------------------------------------------------------------------------------------
// Tests
//--------------------------------------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use std::collections::HashMap;
    use std::ffi::{OsStr, OsString};
    #[cfg(target_os = "linux")]
    use std::num::NonZero;
    #[cfg(unix)]
    use std::os::unix::fs::MetadataExt;
    use std::path::{Path, PathBuf};

    /// Fully-qualified name of the child-process probe used by the no-system-temp
    /// tests; passed to the test binary via `--exact`.
    #[cfg(unix)]
    const CHILD_PROBE_TEST: &str =
        "runtime::spawn::tests::stage_file_mounts_child_probe_stages_without_system_temp";

    use microsandbox_protocol::{
        bootstrap::{BootstrapBlockRoot, BootstrapEnvVar, BootstrapMountFlags},
        exec::ExecRlimit,
    };
    use microsandbox_types::HandoffInit;
    use sea_orm::{ActiveModelTrait, ColumnTrait, EntityTrait, QueryFilter, Set};
    use tempfile::tempdir;

    use microsandbox_runtime::launch::LaunchConfig;

    #[cfg(target_os = "linux")]
    use super::{
        AUTO_BLOCK_WRITEBACK_LIMIT_BYTES, MIN_BLOCK_WRITEBACK_LIMIT_BYTES,
        auto_block_writeback_pool_bytes, resolve_linux_block_writeback_policy,
    };
    use super::{block_writeback_policy, sandbox_cli_args};
    use crate::{
        LogLevel,
        backend::LocalBackend,
        config::{BlockWritebackConfig, RuntimeConfig},
        sandbox::{
            DiskImageFormat, HostPermissions, MountOptions, OciRootfsSource, RlimitResource,
            RootfsSource, SandboxBuilder, SandboxConfig, StatVirtualization, VolumeMount,
        },
        volume::VolumeKind,
    };

    #[test]
    #[cfg(unix)]
    fn test_inherited_fd_source_needs_spare_for_cross_reserved_fd() {
        assert!(super::inherited_fd_source_needs_spare(
            microsandbox_runtime::vm::CONFIG_FD,
            microsandbox_runtime::vm::PARENT_WATCH_FD,
        ));
        assert!(super::inherited_fd_source_needs_spare(
            microsandbox_runtime::vm::PARENT_WATCH_FD,
            microsandbox_runtime::vm::STARTUP_FD,
        ));
    }

    #[test]
    #[cfg(unix)]
    fn test_inherited_fd_source_keeps_own_reserved_fd_in_place() {
        assert!(!super::inherited_fd_source_needs_spare(
            microsandbox_runtime::vm::CONFIG_FD,
            microsandbox_runtime::vm::CONFIG_FD,
        ));
        assert!(!super::inherited_fd_source_needs_spare(
            microsandbox_runtime::vm::PARENT_WATCH_FD,
            microsandbox_runtime::vm::PARENT_WATCH_FD,
        ));
    }

    #[test]
    #[cfg(unix)]
    fn test_inherited_fd_source_leaves_ordinary_fd_in_place() {
        assert!(!super::inherited_fd_source_needs_spare(
            42,
            microsandbox_runtime::vm::CONFIG_FD,
        ));
    }

    #[cfg(unix)]
    #[tokio::test]
    async fn test_sigchld_handler_uses_alt_stack_after_prepare() {
        super::ensure_sigchld_handler_uses_alt_stack_before_spawn()
            .await
            .unwrap();

        unsafe {
            let mut action = std::mem::MaybeUninit::<libc::sigaction>::uninit();
            let rc = libc::sigaction(libc::SIGCHLD, std::ptr::null(), action.as_mut_ptr());
            assert_eq!(rc, 0, "failed to read SIGCHLD action");

            let action = action.assume_init();
            assert_ne!(
                action.sa_flags & libc::SA_ONSTACK,
                0,
                "SIGCHLD handler should run on the alternate signal stack"
            );
        }
    }

    //----------------------------------------------------------------------------------------------
    // Functions: Helpers
    //----------------------------------------------------------------------------------------------

    /// Build a `LocalBackend` for tests. Uses `lazy()` since these tests only
    /// exercise the pure-rendering `sandbox_cli_args` path — no DB / FS
    /// touches.
    fn test_local_backend() -> LocalBackend {
        LocalBackend::lazy()
    }

    /// Return the typed launch payload generated for a sandbox configuration.
    fn render_launch(config: &SandboxConfig) -> LaunchConfig {
        let local = test_local_backend();
        let (_, launch) = sandbox_cli_args(
            &local,
            config,
            42,
            Path::new("/tmp/msb.db"),
            30,
            Path::new("/tmp/logs"),
            Path::new("/tmp/runtime"),
            Path::new("/tmp/agent.sock"),
            Path::new("/tmp/libkrunfw.dylib"),
            &HashMap::new(),
            &HashMap::new(),
            None,
            None,
            None,
            None,
        );
        launch
    }

    /// Re-expand a [`LaunchConfig`] into the historical `--flag value` token
    /// stream so the token-based assertions below keep working. Mirrors the
    /// former producer output field-for-field.
    fn flatten_launch(launch: &LaunchConfig) -> Vec<String> {
        fn pair(out: &mut Vec<String>, flag: &str, val: String) {
            out.push(flag.to_string());
            out.push(val);
        }
        fn path(p: &Path) -> String {
            p.to_string_lossy().into_owned()
        }

        let mut out: Vec<String> = Vec::new();
        pair(&mut out, "--db-path", path(&launch.db_path));
        pair(
            &mut out,
            "--db-connect-timeout-secs",
            launch.db_connect_timeout_secs.to_string(),
        );
        pair(&mut out, "--log-dir", path(&launch.log_dir));
        pair(&mut out, "--runtime-dir", path(&launch.runtime_dir));
        pair(&mut out, "--sandboxes-dir", path(&launch.sandboxes_dir));
        pair(&mut out, "--agent-sock", path(&launch.agent_sock));
        if let Some(s) = &launch.startup {
            out.push(format!("--startup-cmd={}", s.cmd));
            for a in &s.args {
                out.push(format!("--startup-arg={a}"));
            }
            for e in &s.env {
                out.push(format!("--startup-env={e}"));
            }
            if let Some(c) = &s.cwd {
                out.push(format!("--startup-cwd={c}"));
            }
            if let Some(u) = &s.user {
                out.push(format!("--startup-user={u}"));
            }
        }
        if let Some(d) = launch.lifecycle.max_duration_secs {
            pair(&mut out, "--max-duration", d.to_string());
        }
        if let Some(i) = launch.lifecycle.idle_timeout_secs {
            pair(&mut out, "--idle-timeout", i.to_string());
        }
        pair(&mut out, "--libkrunfw-path", path(&launch.libkrunfw_path));
        if launch.metrics.disabled {
            out.push("--disable-metrics-sample".to_string());
        } else {
            pair(
                &mut out,
                "--metrics-sample-interval-ms",
                launch.metrics.sample_interval_ms.to_string(),
            );
        }
        if let Some(slot) = &launch.metrics.slot {
            pair(&mut out, "--metrics-shm-name", slot.shm_name.clone());
            pair(&mut out, "--metrics-slot", slot.slot.to_string());
            pair(
                &mut out,
                "--metrics-generation",
                slot.generation.to_string(),
            );
        }
        if let Some(p) = &launch.rootfs.path {
            pair(&mut out, "--rootfs-path", path(p));
        }
        if let Some(d) = &launch.rootfs.disk {
            pair(&mut out, "--rootfs-disk", path(d));
        }
        if let Some(f) = &launch.rootfs.disk_format {
            pair(&mut out, "--rootfs-disk-format", f.clone());
        }
        if let Some(u) = &launch.rootfs.upper {
            pair(&mut out, "--rootfs-blk", path(u));
        }
        for m in &launch.mounts {
            pair(&mut out, "--mount", m.clone());
        }
        for d in &launch.disks {
            pair(&mut out, "--disk", d.clone());
        }

        // Project typed bootstrap mount data into the former environment
        // spelling so long-standing rendering tests can keep checking the
        // exact mount semantics. This is a test-only view, not launch argv.
        fn mount_flags(flags: BootstrapMountFlags) -> Vec<&'static str> {
            let mut values = Vec::new();
            if flags.readonly {
                values.push("ro");
            }
            if flags.noexec {
                values.push("noexec");
            }
            if flags.nosuid {
                values.push("nosuid");
            }
            if flags.nodev {
                values.push("nodev");
            }
            values
        }
        fn with_options(mut base: String, options: Vec<String>) -> String {
            if !options.is_empty() {
                base.push(':');
                base.push_str(&options.join(","));
            }
            base
        }

        if let Some(BootstrapBlockRoot::DiskImage { device, fstype }) = &launch.bootstrap.block_root
        {
            let mut value = format!("kind=disk-image,device={device}");
            if let Some(fstype) = fstype {
                value.push_str(&format!(",fstype={fstype}"));
            }
            pair(&mut out, "--env", format!("MSB_BLOCK_ROOT={value}"));
        }
        if !launch.bootstrap.dir_mounts.is_empty() {
            let value = launch
                .bootstrap
                .dir_mounts
                .iter()
                .map(|mount| {
                    with_options(
                        format!("{}:{}", mount.tag, mount.guest_path),
                        mount_flags(mount.flags)
                            .into_iter()
                            .map(str::to_string)
                            .collect(),
                    )
                })
                .collect::<Vec<_>>()
                .join(";");
            pair(&mut out, "--env", format!("MSB_DIR_MOUNTS={value}"));
        }
        if !launch.bootstrap.file_mounts.is_empty() {
            let value = launch
                .bootstrap
                .file_mounts
                .iter()
                .map(|mount| {
                    with_options(
                        format!("{}:{}:{}", mount.tag, mount.filename, mount.guest_path),
                        mount_flags(mount.flags)
                            .into_iter()
                            .map(str::to_string)
                            .collect(),
                    )
                })
                .collect::<Vec<_>>()
                .join(";");
            pair(&mut out, "--env", format!("MSB_FILE_MOUNTS={value}"));
        }
        if !launch.bootstrap.disk_mounts.is_empty() {
            let value = launch
                .bootstrap
                .disk_mounts
                .iter()
                .map(|mount| {
                    let mut options = Vec::new();
                    if let Some(fstype) = &mount.fstype {
                        options.push(format!("fstype={fstype}"));
                    }
                    options.extend(mount_flags(mount.flags).into_iter().map(str::to_string));
                    with_options(format!("{}:{}", mount.id, mount.guest_path), options)
                })
                .collect::<Vec<_>>()
                .join(";");
            pair(&mut out, "--env", format!("MSB_DISK_MOUNTS={value}"));
        }
        if !launch.bootstrap.tmpfs_mounts.is_empty() {
            let value = launch
                .bootstrap
                .tmpfs_mounts
                .iter()
                .map(|mount| {
                    let mut options = Vec::new();
                    if let Some(size_mib) = mount.size_mib {
                        options.push(format!("size={size_mib}"));
                    }
                    if let Some(mode) = mount.mode {
                        options.push(format!("mode={mode:o}"));
                    }
                    options.extend(mount_flags(mount.flags).into_iter().map(str::to_string));
                    with_options(mount.path.clone(), options)
                })
                .collect::<Vec<_>>()
                .join(";");
            pair(&mut out, "--env", format!("MSB_TMPFS={value}"));
        }
        for variable in &launch.bootstrap.default_env {
            pair(
                &mut out,
                "--env",
                format!("{}={}", variable.key, variable.value),
            );
        }
        #[cfg(feature = "net")]
        if let Some(net) = &launch.network {
            pair(
                &mut out,
                "--network-config",
                serde_json::to_string(net).unwrap(),
            );
            pair(&mut out, "--sandbox-slot", launch.sandbox_slot.to_string());
        }
        if let Some(cwd) = &launch.bootstrap.default_cwd {
            pair(&mut out, "--workdir", cwd.clone());
        }
        out
    }

    /// Render the full arg set (visible argv + the flattened config payload)
    /// as strings. Tests assert on the union since both feed `msb sandbox`.
    fn render_args(config: &SandboxConfig) -> Vec<String> {
        render_args_with_named_volumes(config, &HashMap::new())
    }

    fn render_args_with_named_volumes(
        config: &SandboxConfig,
        named_volumes: &HashMap<String, super::ResolvedNamedVolume>,
    ) -> Vec<String> {
        let local = test_local_backend();
        let (visible, launch) = sandbox_cli_args(
            &local,
            config,
            42,
            Path::new("/tmp/msb.db"),
            30,
            Path::new("/tmp/logs"),
            Path::new("/tmp/runtime"),
            Path::new("/tmp/agent.sock"),
            Path::new("/tmp/libkrunfw.dylib"),
            &HashMap::new(),
            named_volumes,
            None,
            None,
            None,
            None,
        );
        visible
            .into_iter()
            .map(|arg| arg.to_string_lossy().into_owned())
            .chain(flatten_launch(&launch))
            .collect()
    }

    fn named_disk(path: impl Into<PathBuf>) -> super::ResolvedNamedVolume {
        super::ResolvedNamedVolume {
            kind: VolumeKind::Disk,
            path: path.into(),
            format: Some(DiskImageFormat::Raw),
            fstype: Some("ext4".to_string()),
            quota_mib: None,
        }
    }

    fn named_directory(
        path: impl Into<PathBuf>,
        quota_mib: Option<u32>,
    ) -> super::ResolvedNamedVolume {
        super::ResolvedNamedVolume {
            kind: VolumeKind::Directory,
            path: path.into(),
            format: None,
            fstype: None,
            quota_mib,
        }
    }

    fn named_volume_create(
        name: &str,
        kind: VolumeKind,
        quota_mib: Option<u32>,
        capacity_mib: Option<u32>,
        labels: Vec<(String, String)>,
    ) -> microsandbox_types::NamedVolumeCreate {
        microsandbox_types::NamedVolumeCreate {
            mode: crate::sandbox::NamedVolumeMode::EnsureExists,
            name: name.to_string(),
            kind,
            quota_mib,
            capacity_mib,
            labels,
        }
    }

    fn existing_volume_model(
        name: &str,
        kind: VolumeKind,
        quota_mib: Option<i32>,
        capacity_bytes: Option<i64>,
        labels: Option<Vec<(String, String)>>,
    ) -> super::volume_entity::Model {
        super::volume_entity::Model {
            id: 1,
            name: name.to_string(),
            kind: kind.as_str().to_string(),
            quota_mib,
            size_bytes: None,
            capacity_bytes,
            disk_format: (kind == VolumeKind::Disk).then(|| "raw".to_string()),
            disk_fstype: (kind == VolumeKind::Disk).then(|| "ext4".to_string()),
            labels: labels.map(|labels| serde_json::to_string(&labels).unwrap()),
            created_at: Some(chrono::Utc::now().naive_utc()),
            updated_at: Some(chrono::Utc::now().naive_utc()),
        }
    }

    /// Render only the `visible` argv (what shows up in `ps`).
    fn render_visible_args(config: &SandboxConfig) -> Vec<String> {
        let local = test_local_backend();
        let (visible, _piped) = sandbox_cli_args(
            &local,
            config,
            42,
            Path::new("/tmp/msb.db"),
            30,
            Path::new("/tmp/logs"),
            Path::new("/tmp/runtime"),
            Path::new("/tmp/agent.sock"),
            Path::new("/tmp/libkrunfw.dylib"),
            &HashMap::new(),
            &HashMap::new(),
            None,
            None,
            None,
            None,
        );
        visible
            .into_iter()
            .map(|arg| arg.to_string_lossy().into_owned())
            .collect()
    }

    fn render_args_with_file_mounts(
        config: &SandboxConfig,
        staged_file_mounts: &HashMap<String, (PathBuf, String, String)>,
    ) -> Vec<String> {
        let local = test_local_backend();
        let (visible, launch) = sandbox_cli_args(
            &local,
            config,
            42,
            Path::new("/tmp/msb.db"),
            30,
            Path::new("/tmp/logs"),
            Path::new("/tmp/runtime"),
            Path::new("/tmp/agent.sock"),
            Path::new("/tmp/libkrunfw.dylib"),
            staged_file_mounts,
            &HashMap::new(),
            None,
            None,
            None,
            None,
        );
        visible
            .into_iter()
            .map(|arg| arg.to_string_lossy().into_owned())
            .chain(flatten_launch(&launch))
            .collect()
    }

    #[tokio::test]
    async fn test_sandbox_cli_args_include_selected_log_level() {
        let config = SandboxBuilder::new("test")
            .image("/tmp/rootfs")
            .log_level(LogLevel::Debug)
            .build()
            .await
            .unwrap();

        let args = render_args(&config);

        assert!(args.iter().any(|arg| arg == "--debug"));
    }

    #[tokio::test]
    async fn test_sandbox_cli_args_are_silent_by_default() {
        let config = SandboxBuilder::new("test")
            .image("/tmp/rootfs")
            .build()
            .await
            .unwrap();

        let args = render_args(&config);

        assert!(!args.iter().any(|arg| {
            matches!(
                arg.as_str(),
                "--error" | "--warn" | "--info" | "--debug" | "--trace"
            )
        }));
    }

    #[tokio::test]
    async fn test_sandbox_cli_args_include_agent_sock_path() {
        let config = SandboxBuilder::new("test")
            .image("/tmp/rootfs")
            .build()
            .await
            .unwrap();

        let rendered = render_args(&config);

        assert!(
            rendered
                .windows(2)
                .any(|pair| pair == ["--agent-sock", "/tmp/agent.sock"])
        );
    }

    #[tokio::test]
    async fn test_sandbox_cli_args_include_startup_fd_when_supplied() {
        let config = SandboxBuilder::new("test")
            .image("/tmp/rootfs")
            .build()
            .await
            .unwrap();

        let local = test_local_backend();
        let (visible, _piped) = sandbox_cli_args(
            &local,
            &config,
            42,
            Path::new("/tmp/msb.db"),
            30,
            Path::new("/tmp/logs"),
            Path::new("/tmp/runtime"),
            Path::new("/tmp/agent.sock"),
            Path::new("/tmp/libkrunfw.dylib"),
            &HashMap::new(),
            &HashMap::new(),
            None,
            None,
            Some(microsandbox_runtime::vm::STARTUP_FD),
            None,
        );

        // The startup fd is an operator-visible label, so it stays on argv.
        assert!(visible.windows(2).any(|pair| pair
            == [
                OsString::from("--startup-fd"),
                OsString::from(microsandbox_runtime::vm::STARTUP_FD.to_string()),
            ]));
    }

    #[tokio::test]
    async fn test_sandbox_cli_args_include_detached_startup_command() {
        let config = SandboxBuilder::new("test")
            .image("/tmp/rootfs")
            .entrypoint(["/entrypoint"])
            .env("APP_ENV", "test")
            .workdir("/workspace")
            .user("nobody")
            .background_command(["/bin/sh", "-lc", "echo detached"])
            .build()
            .await
            .unwrap();

        let rendered = render_args(&config);

        assert!(rendered.contains(&"--startup-cmd=/entrypoint".to_string()));
        assert!(rendered.contains(&"--startup-arg=/bin/sh".to_string()));
        assert!(rendered.contains(&"--startup-arg=-lc".to_string()));
        assert!(rendered.contains(&"--startup-arg=echo detached".to_string()));
        assert!(rendered.contains(&"--startup-env=APP_ENV=test".to_string()));
        assert!(rendered.contains(&"--startup-cwd=/workspace".to_string()));
        assert!(rendered.contains(&"--startup-user=nobody".to_string()));
    }

    #[tokio::test]
    async fn test_sandbox_cli_args_include_detached_image_default_command() {
        let mut config = SandboxBuilder::new("test")
            .image("/tmp/rootfs")
            .entrypoint(["/entrypoint"])
            .build()
            .await
            .unwrap();
        config.spec.runtime.cmd = Some(vec!["bash".to_string()]);
        config.set_background_command(Vec::new());

        let rendered = render_args(&config);

        assert!(rendered.contains(&"--startup-cmd=/entrypoint".to_string()));
        assert!(rendered.contains(&"--startup-arg=bash".to_string()));
    }

    #[tokio::test]
    async fn test_sandbox_cli_args_include_startup_pipe_when_supplied() {
        let config = SandboxBuilder::new("test")
            .image("/tmp/rootfs")
            .build()
            .await
            .unwrap();
        let local = test_local_backend();
        let (visible, _launch) = sandbox_cli_args(
            &local,
            &config,
            42,
            Path::new("/tmp/msb.db"),
            30,
            Path::new("/tmp/logs"),
            Path::new("/tmp/runtime"),
            Path::new("/tmp/agent.sock"),
            Path::new("/tmp/libkrunfw.dylib"),
            &HashMap::new(),
            &HashMap::new(),
            None,
            None,
            None,
            Some(OsStr::new(r"\\.\pipe\msb-startup-test")),
        );

        assert!(visible.windows(2).any(|pair| pair
            == [
                OsString::from("--startup-pipe"),
                OsString::from(r"\\.\pipe\msb-startup-test"),
            ]));
    }

    #[tokio::test]
    async fn test_sandbox_cli_args_skip_startup_exec_when_init_owns_argv() {
        let mut config = SandboxBuilder::new("test")
            .image("/tmp/rootfs")
            .workdir("/opt/hermes")
            .background_command(["gateway", "run"])
            .build()
            .await
            .unwrap();
        config.spec.init = Some(HandoffInit {
            cmd: "/init".to_string(),
            args: vec![
                "/opt/hermes/docker/main-wrapper.sh".to_string(),
                "gateway".to_string(),
                "run".to_string(),
            ],
            env: Vec::new(),
        });
        config.clear_launch_intent();

        let launch = render_launch(&config);
        let handoff = launch.bootstrap.handoff_init.expect("handoff bootstrap");

        assert_eq!(handoff.cmd, "/init");
        assert_eq!(
            handoff.args,
            vec![
                "/opt/hermes/docker/main-wrapper.sh".to_string(),
                "gateway".to_string(),
                "run".to_string(),
            ]
        );
        assert_eq!(handoff.cwd.as_deref(), Some("/opt/hermes"));
        assert!(launch.startup.is_none());
    }

    #[tokio::test]
    async fn test_agent_socket_candidates_follow_explicit_local_backend_paths() {
        let temp = tempdir().unwrap();
        let home = temp.path().join("msb-home");
        let backend = LocalBackend::builder().home(&home).build().await.unwrap();

        let candidates =
            super::sandbox_agent_socket_path_candidates_for(&backend, "sdk-socket-test");

        #[cfg(unix)]
        {
            assert_eq!(candidates.len(), 3);
            assert!(candidates[0].starts_with(backend.config().run_dir().join("sandboxes")));
            assert_eq!(candidates[0].file_name().unwrap(), "agent.sock");
            assert!(candidates[1].starts_with(backend.config().run_dir().join("agent")));
            assert_eq!(
                candidates[2],
                backend
                    .config()
                    .sandboxes_dir()
                    .join("sdk-socket-test")
                    .join("runtime")
                    .join("agent.sock")
            );
        }
        #[cfg(windows)]
        {
            assert_eq!(candidates.len(), 1);
            assert!(
                candidates[0]
                    .to_string_lossy()
                    .starts_with(r"\\.\pipe\msb-agent-")
            );
        }
    }

    #[tokio::test]
    async fn test_agent_socket_resolution_uses_explicit_local_backend_paths() {
        // Root the backend home under a short directory so the derived AF_UNIX
        // socket path stays within the platform `sun_path` limit (104 bytes on
        // macOS). The default system temp dir on macOS lives under
        // `/var/folders/...`, long enough to overflow that limit and make
        // resolution fail spuriously. Windows uses named pipes (no length
        // limit), so the default temp dir is fine there.
        #[cfg(unix)]
        let temp = tempfile::Builder::new()
            .prefix("msb")
            .tempdir_in("/tmp")
            .unwrap();
        #[cfg(not(unix))]
        let temp = tempfile::Builder::new().prefix("msb").tempdir().unwrap();
        let home = temp.path().join("msb-home");
        let backend = LocalBackend::builder().home(&home).build().await.unwrap();

        let resolved =
            super::resolve_sandbox_agent_socket_path_for(&backend, "sdk-socket-test").unwrap();

        #[cfg(unix)]
        assert!(resolved.starts_with(backend.config().run_dir().join("sandboxes")));
        #[cfg(windows)]
        assert!(
            resolved
                .to_string_lossy()
                .starts_with(r"\\.\pipe\msb-agent-")
        );
    }

    #[test]
    #[cfg(unix)]
    fn test_new_client_selects_old_runtime_socket_when_canonical_is_absent() {
        let temp = tempfile::Builder::new()
            .prefix("msb-compat")
            .tempdir_in("/tmp")
            .unwrap();
        let run_dir = temp.path().join("run");
        let sandboxes_dir = temp.path().join("sandboxes");
        let paths = microsandbox_runtime::ipc::sandbox_socket_paths(&run_dir, "old-runtime");
        std::fs::create_dir_all(paths.legacy_agent.parent().unwrap()).unwrap();
        let _listener = std::os::unix::net::UnixListener::bind(&paths.legacy_agent).unwrap();

        let candidates = super::sandbox_agent_socket_path_candidates_with_roots(
            &run_dir,
            &sandboxes_dir,
            "old-runtime",
        );
        let selected = super::first_existing_socket_candidate(&candidates).unwrap();

        assert_eq!(selected, paths.legacy_agent);
        std::os::unix::net::UnixStream::connect(selected).unwrap();
    }

    #[tokio::test]
    async fn test_sandbox_bootstrap_includes_rlimits() {
        let config = SandboxBuilder::new("test")
            .image("/tmp/rootfs")
            .rlimit(RlimitResource::Nofile, 65_535)
            .build()
            .await
            .unwrap();

        let launch = render_launch(&config);

        assert_eq!(
            launch.bootstrap.rlimits,
            vec![ExecRlimit {
                resource: "nofile".to_string(),
                soft: 65_535,
                hard: 65_535,
            }]
        );
    }

    #[tokio::test]
    async fn test_visible_args_keep_labels_and_omit_bulk() {
        let config = SandboxBuilder::new("test")
            .image("/tmp/rootfs")
            .env("TOKEN", "secret")
            .build()
            .await
            .unwrap();

        let visible = render_visible_args(&config);
        let all = render_args(&config);

        // Operator-readable labels stay on argv.
        assert_eq!(visible.first().map(String::as_str), Some("sandbox"));
        assert!(visible.windows(2).any(|p| p == ["--name", "test"]));
        assert!(visible.iter().any(|a| a == "--vcpus"));
        assert!(visible.iter().any(|a| a == "--memory-mib"));

        // Bulk / secret-bearing flags never appear on argv...
        for flag in ["--env", "--db-path", "--log-dir", "--agent-sock"] {
            assert!(
                !visible.iter().any(|a| a == flag),
                "visible argv unexpectedly contains {flag}"
            );
        }
        assert!(!visible.iter().any(|a| a.contains("TOKEN=secret")));

        // ...but are present in the full (piped) arg set.
        assert!(all.iter().any(|a| a == "--db-path"));
        assert!(all.iter().any(|a| a.contains("TOKEN=secret")));
    }

    #[tokio::test]
    async fn test_bootstrap_preserves_quoted_environment_without_visible_argv_exposure() {
        let value = "{\"message\":\"hello\",\"unicode\":\"lambda λ\"}\nnext\tline=a=b";
        let config = SandboxBuilder::new("test")
            .image("/tmp/rootfs")
            .env("APP_CONFIG", value)
            .build()
            .await
            .unwrap();

        let launch = render_launch(&config);
        let visible = render_visible_args(&config);

        assert_eq!(
            launch.bootstrap.default_env,
            vec![BootstrapEnvVar {
                key: "APP_CONFIG".to_string(),
                value: value.to_string(),
            }]
        );
        assert!(
            visible
                .iter()
                .all(|arg| !arg.contains("APP_CONFIG") && !arg.contains(value)),
            "guest environment leaked into visible argv: {visible:?}"
        );
    }

    #[tokio::test]
    async fn test_sandbox_bootstrap_preserves_multiple_rlimits() {
        let config = SandboxBuilder::new("test")
            .image("/tmp/rootfs")
            .rlimit_range(RlimitResource::Nofile, 4096, 65_535)
            .rlimit(RlimitResource::Nproc, 1024)
            .build()
            .await
            .unwrap();

        let launch = render_launch(&config);

        assert_eq!(launch.bootstrap.rlimits.len(), 2);
        assert_eq!(launch.bootstrap.rlimits[0].resource, "nofile");
        assert_eq!(launch.bootstrap.rlimits[0].soft, 4096);
        assert_eq!(launch.bootstrap.rlimits[0].hard, 65_535);
        assert_eq!(launch.bootstrap.rlimits[1].resource, "nproc");
        assert_eq!(launch.bootstrap.rlimits[1].soft, 1024);
        assert_eq!(launch.bootstrap.rlimits[1].hard, 1024);
    }

    #[tokio::test]
    async fn test_sandbox_cli_args_emit_metrics_interval_flag() {
        let config = SandboxBuilder::new("test")
            .image("/tmp/rootfs")
            .metrics_sample_interval(std::time::Duration::from_millis(1000))
            .build()
            .await
            .unwrap();

        let rendered = render_args(&config);

        assert!(
            rendered
                .windows(2)
                .any(|pair| pair == ["--metrics-sample-interval-ms", "1000"]),
            "expected metrics interval flag in {rendered:?}"
        );
    }

    #[tokio::test]
    async fn test_sandbox_cli_args_include_custom_metrics_sample_interval() {
        let config = SandboxBuilder::new("test")
            .image("/tmp/rootfs")
            .metrics_sample_interval(std::time::Duration::from_millis(2500))
            .build()
            .await
            .unwrap();

        let rendered = render_args(&config);

        assert!(
            rendered
                .windows(2)
                .any(|pair| pair == ["--metrics-sample-interval-ms", "2500"]),
            "expected custom metrics interval flag in {rendered:?}"
        );
    }

    #[tokio::test]
    async fn test_sandbox_cli_args_disabled_metrics_emit_disable_flag() {
        let config = SandboxBuilder::new("test")
            .image("/tmp/rootfs")
            .metrics_sample_interval(std::time::Duration::ZERO)
            .build()
            .await
            .unwrap();

        let rendered = render_args(&config);

        assert!(
            rendered.iter().any(|arg| arg == "--disable-metrics-sample"),
            "expected `--disable-metrics-sample` flag; got {rendered:?}"
        );
        assert!(
            !rendered
                .iter()
                .any(|arg| arg == "--metrics-sample-interval-ms"),
            "should not also emit interval flag; got {rendered:?}"
        );
    }

    #[tokio::test]
    async fn test_sandbox_cli_args_disable_overrides_positive_interval() {
        let config = SandboxBuilder::new("test")
            .image("/tmp/rootfs")
            .metrics_sample_interval(std::time::Duration::from_millis(2500))
            .disable_metrics_sample()
            .build()
            .await
            .unwrap();

        let rendered = render_args(&config);

        assert!(
            rendered.iter().any(|arg| arg == "--disable-metrics-sample"),
            "expected disable flag to win over positive interval; got {rendered:?}"
        );
        assert!(
            !rendered
                .iter()
                .any(|arg| arg == "--metrics-sample-interval-ms"),
            "should not emit interval flag when disable is set; got {rendered:?}"
        );
    }

    #[tokio::test]
    async fn test_sandbox_cli_args_include_db_connect_timeout() {
        let config = SandboxBuilder::new("test")
            .image("/tmp/rootfs")
            .build()
            .await
            .unwrap();

        let rendered = render_args(&config);

        assert!(
            rendered
                .windows(2)
                .any(|pair| pair == ["--db-connect-timeout-secs", "30"])
        );
    }

    #[tokio::test]
    async fn test_sandbox_cli_args_use_passthrough_for_bind_rootfs() {
        let config = SandboxBuilder::new("test")
            .image("/tmp/rootfs")
            .build()
            .await
            .unwrap();

        let rendered = render_args(&config);
        assert!(rendered.contains(&"--rootfs-path".to_string()));
        assert!(rendered.contains(&"/tmp/rootfs".to_string()));
        assert!(!rendered.contains(&"--rootfs-lower".to_string()));
        assert!(!rendered.contains(&"--rootfs-upper".to_string()));
        assert!(!rendered.contains(&"--rootfs-staging".to_string()));
    }

    #[tokio::test]
    async fn test_sandbox_cli_args_oci_without_manifest_digest_emits_no_block_root() {
        let config = SandboxBuilder::new("test")
            .image("alpine")
            .build()
            .await
            .unwrap();
        assert!(matches!(config.spec.image, RootfsSource::Oci(_)));

        let rendered = render_args(&config);
        // Without a manifest_digest set, no block root args should be emitted.
        assert!(!rendered.contains(&"--rootfs-blk".to_string()));
        assert!(!rendered.contains(&"--rootfs-disk".to_string()));
        assert!(!rendered.iter().any(|a| a.starts_with("MSB_BLOCK_ROOT=")));
    }

    #[tokio::test]
    async fn test_sandbox_cli_args_flat_oci_attaches_one_raw_root_disk() {
        let config = SandboxBuilder::new("test")
            .image("alpine")
            .root_disk_with(|disk| disk.flat().size(8192u32))
            .build()
            .await
            .unwrap();

        let rendered = render_args(&config);
        assert!(rendered.contains(&"--rootfs-disk".to_string()));
        assert!(rendered.iter().any(|arg| arg.ends_with("/test/rootfs.raw")));
        assert!(rendered.contains(&"--rootfs-disk-format".to_string()));
        assert!(rendered.contains(&"raw".to_string()));
        assert!(
            rendered.contains(
                &"MSB_BLOCK_ROOT=kind=disk-image,device=/dev/vda,fstype=ext4".to_string()
            )
        );
        assert!(!rendered.contains(&"--rootfs-upper".to_string()));
        assert!(!rendered.contains(&"--rootfs-lower".to_string()));
    }

    #[tokio::test]
    async fn test_sandbox_cli_args_inject_tmpfs_env_var() {
        let config = SandboxBuilder::new("test")
            .image("/tmp/rootfs")
            .volume("/tmp", |m| m.tmpfs().size(256u32))
            .volume("/var/tmp", |m| m.tmpfs())
            .build()
            .await
            .unwrap();

        let rendered = render_args(&config);

        assert!(rendered.contains(&"MSB_TMPFS=/tmp:size=256;/var/tmp".to_string()));
    }

    #[tokio::test]
    async fn test_sandbox_cli_args_tmpfs_readonly_appends_ro() {
        let config = SandboxBuilder::new("test")
            .image("/tmp/rootfs")
            .volume("/seed", |m| m.tmpfs().size(64u32).readonly())
            .build()
            .await
            .unwrap();

        let rendered = render_args(&config);

        assert!(rendered.contains(&"MSB_TMPFS=/seed:size=64,ro".to_string()));
    }

    #[tokio::test]
    async fn test_sandbox_cli_args_apply_default_oci_tmpfs() {
        let mut config = SandboxConfig {
            spec: microsandbox_types::SandboxSpec {
                name: "test".into(),
                image: RootfsSource::Oci(OciRootfsSource {
                    reference: "alpine".into(),
                    root_disk: None,
                }),
                resources: microsandbox_types::SandboxResources {
                    memory_mib: 1024,
                    ..Default::default()
                },
                ..Default::default()
            },
            manifest_digest: Some(
                "sha256:aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa".into(),
            ),
            ..Default::default()
        };
        config.apply_runtime_defaults();

        let rendered = render_args(&config);

        assert!(rendered.contains(&"MSB_TMPFS=/tmp:size=256".to_string()));
    }

    #[tokio::test]
    async fn test_sandbox_cli_args_omit_tmpfs_env_var_when_no_tmpfs() {
        let config = SandboxBuilder::new("test")
            .image("/tmp/rootfs")
            .build()
            .await
            .unwrap();

        let rendered = render_args(&config);

        assert!(!rendered.iter().any(|a| a.starts_with("MSB_TMPFS=")));
    }

    #[tokio::test]
    async fn test_sandbox_cli_args_disk_image_with_fstype() {
        let config = SandboxBuilder::new("test")
            .image_with(|i| i.disk("/tmp/ubuntu.qcow2").fstype("ext4"))
            .build()
            .await
            .unwrap();

        assert!(matches!(config.spec.image, RootfsSource::DiskImage { .. }));

        let rendered = render_args(&config);

        assert!(rendered.contains(&"--rootfs-disk".to_string()));
        assert!(rendered.contains(&"/tmp/ubuntu.qcow2".to_string()));
        assert!(rendered.contains(&"--rootfs-disk-format".to_string()));
        assert!(rendered.contains(&"qcow2".to_string()));
        assert!(
            rendered.contains(
                &"MSB_BLOCK_ROOT=kind=disk-image,device=/dev/vda,fstype=ext4".to_string()
            )
        );

        // Should not contain bind or overlay args.
        assert!(!rendered.contains(&"--rootfs-path".to_string()));
        assert!(!rendered.contains(&"--rootfs-lower".to_string()));
        assert!(!rendered.contains(&"--rootfs-upper".to_string()));
        assert!(!rendered.contains(&"--rootfs-staging".to_string()));
    }

    #[tokio::test]
    async fn test_sandbox_cli_args_disk_image_without_fstype() {
        let config = SandboxBuilder::new("test")
            .image_with(|i| i.disk("/tmp/alpine.raw"))
            .build()
            .await
            .unwrap();

        assert!(matches!(config.spec.image, RootfsSource::DiskImage { .. }));

        let rendered = render_args(&config);

        assert!(rendered.contains(&"--rootfs-disk".to_string()));
        assert!(rendered.contains(&"/tmp/alpine.raw".to_string()));
        assert!(rendered.contains(&"--rootfs-disk-format".to_string()));
        assert!(rendered.contains(&"raw".to_string()));
        assert!(rendered.contains(&"MSB_BLOCK_ROOT=kind=disk-image,device=/dev/vda".to_string()));

        // Should not contain bind or overlay args.
        assert!(!rendered.contains(&"--rootfs-path".to_string()));
        assert!(!rendered.contains(&"--rootfs-lower".to_string()));
    }

    #[tokio::test]
    async fn test_sandbox_cli_args_file_mount_generates_correct_args() {
        let config = SandboxBuilder::new("test")
            .image("/tmp/rootfs")
            .volume("/guest/config.txt", |m| {
                m.bind("/host/config.txt").readonly().noexec()
            })
            .build()
            .await
            .unwrap();

        let mut staged_file_mounts = HashMap::new();
        staged_file_mounts.insert(
            "/guest/config.txt".to_string(),
            (
                PathBuf::from("/tmp/staging/fm_aabbccdd"),
                "config.txt".to_string(),
                "fm_aabbccdd".to_string(),
            ),
        );

        let rendered = render_args_with_file_mounts(&config, &staged_file_mounts);

        // File mount should use staging dir in --mount. The staging dir is
        // canonicalized at creation so it stays under the no-follow default;
        // the spec carries no opt-out token.
        assert!(rendered.windows(2).any(|pair| pair[0] == "--mount"
            && pair[1] == "fm_aabbccdd:/tmp/staging/fm_aabbccdd:ro,noexec"));
        // MSB_FILE_MOUNTS should contain the spec.
        assert!(rendered.contains(
            &"MSB_FILE_MOUNTS=fm_aabbccdd:config.txt:/guest/config.txt:ro,noexec".to_string()
        ));
        // MSB_DIR_MOUNTS should NOT contain the file mount.
        assert!(!rendered.iter().any(|a| a.starts_with("MSB_DIR_MOUNTS=")));
    }

    #[tokio::test]
    async fn test_sandbox_cli_args_mixed_file_and_dir_mounts() {
        let config = SandboxBuilder::new("test")
            .image("/tmp/rootfs")
            .volume("/data", |m| m.bind("/host/data"))
            .volume("/guest/file.txt", |m| m.bind("/host/file.txt"))
            .build()
            .await
            .unwrap();

        let mut staged_file_mounts = HashMap::new();
        staged_file_mounts.insert(
            "/guest/file.txt".to_string(),
            (
                PathBuf::from("/tmp/staging/fm_11223344"),
                "file.txt".to_string(),
                "fm_11223344".to_string(),
            ),
        );

        let rendered = render_args_with_file_mounts(&config, &staged_file_mounts);

        // Directory mount in MSB_DIR_MOUNTS.
        let data_tag = super::guest_mount_tag("/data");
        assert!(rendered.contains(&format!("MSB_DIR_MOUNTS={data_tag}:/data")));
        // File mount in MSB_FILE_MOUNTS.
        assert!(
            rendered.contains(&"MSB_FILE_MOUNTS=fm_11223344:file.txt:/guest/file.txt".to_string())
        );
    }

    #[tokio::test]
    async fn test_sandbox_cli_args_bind_mount_gets_default_quota() {
        let config = SandboxBuilder::new("test")
            .image("/tmp/rootfs")
            .volume("/data", |m| m.bind("/host/data"))
            .build()
            .await
            .unwrap();

        let rendered = render_args(&config);
        let data_tag = super::guest_mount_tag("/data");
        let expected = format!(
            "{data_tag}:/host/data:quota={}",
            crate::sandbox::config::DEFAULT_BIND_QUOTA_MIB
        );
        assert!(
            rendered
                .windows(2)
                .any(|pair| pair[0] == "--mount" && pair[1] == expected),
            "missing default-quota --mount arg in {rendered:?}"
        );
    }

    #[tokio::test]
    async fn test_sandbox_cli_args_bind_mount_protected_by_default() {
        // No opt-out: the rendered mount spec must NOT carry the token, so the
        // runtime applies the protective no-follow default.
        let config = SandboxBuilder::new("test")
            .image("/tmp/rootfs")
            .volume("/data", |m| m.bind("/host/data"))
            .build()
            .await
            .unwrap();
        let rendered = render_args(&config);
        let data_tag = super::guest_mount_tag("/data");
        let arg = rendered
            .windows(2)
            .find(|p| p[0] == "--mount" && p[1].starts_with(&format!("{data_tag}:/host/data")))
            .map(|p| p[1].clone())
            .unwrap_or_default();
        assert!(
            !arg.contains("follow-root-symlinks"),
            "protected mount must omit the opt-out token, got {arg:?}"
        );
    }

    #[tokio::test]
    async fn test_sandbox_cli_args_bind_mount_follow_root_symlinks_opt_out() {
        let config = SandboxBuilder::new("test")
            .image("/tmp/rootfs")
            .volume("/data", |m| m.bind("/host/data").follow_root_symlinks(true))
            .build()
            .await
            .unwrap();
        let rendered = render_args(&config);
        let data_tag = super::guest_mount_tag("/data");
        let arg = rendered
            .windows(2)
            .find(|p| p[0] == "--mount" && p[1].starts_with(&format!("{data_tag}:/host/data")))
            .map(|p| p[1].clone())
            .unwrap_or_default();
        assert!(
            arg.contains("follow-root-symlinks"),
            "opt-out mount must carry the token, got {arg:?}"
        );
    }

    #[tokio::test]
    async fn test_sandbox_cli_args_bind_mount_owner_host_only() {
        // An explicit owner is a host-side virtiofs presentation policy: it must
        // ride the `--mount` arg the VMM parses, and must NOT leak into the guest
        // `MSB_DIR_MOUNTS` spec (where agentd rejects `uid`/`gid` as unknown).
        let config = SandboxBuilder::new("test")
            .image("/tmp/rootfs")
            .volume("/data", |m| m.bind("/host/data").owner(1000, 1000))
            .build()
            .await
            .unwrap();
        let rendered = render_args(&config);
        let data_tag = super::guest_mount_tag("/data");

        let mount_arg = rendered
            .windows(2)
            .find(|p| p[0] == "--mount" && p[1].starts_with(&format!("{data_tag}:/host/data")))
            .map(|p| p[1].clone())
            .unwrap_or_default();
        assert!(
            mount_arg.contains("uid=1000") && mount_arg.contains("gid=1000"),
            "host --mount arg must carry the owner, got {mount_arg:?}"
        );

        let dir_mounts = rendered
            .iter()
            .find(|a| a.starts_with("MSB_DIR_MOUNTS="))
            .cloned()
            .unwrap_or_default();
        assert!(
            !dir_mounts.contains("uid=") && !dir_mounts.contains("gid="),
            "guest MSB_DIR_MOUNTS must not carry uid/gid, got {dir_mounts:?}"
        );
    }

    #[tokio::test]
    async fn test_sandbox_cli_args_bind_mount_quota_override() {
        let config = SandboxBuilder::new("test")
            .image("/tmp/rootfs")
            .volume("/data", |m| m.bind("/host/data").quota(2048u32))
            .build()
            .await
            .unwrap();

        let rendered = render_args(&config);
        let data_tag = super::guest_mount_tag("/data");
        let expected = format!("{data_tag}:/host/data:quota=2048");
        assert!(
            rendered
                .windows(2)
                .any(|pair| pair[0] == "--mount" && pair[1] == expected),
            "missing override-quota --mount arg in {rendered:?}"
        );
    }

    #[tokio::test]
    #[cfg(windows)]
    async fn test_sandbox_cli_args_windows_drive_bind_mount_preserves_drive_colon() {
        let config = SandboxBuilder::new("test")
            .image("/tmp/rootfs")
            .volume("/data", |m| {
                m.bind(r"C:\Users\Stephen\data")
                    .readonly()
                    .stat_virtualization(StatVirtualization::Relaxed)
                    .host_permissions(HostPermissions::Mirror)
            })
            .build()
            .await
            .unwrap();

        let rendered = render_args(&config);
        let data_tag = super::guest_mount_tag("/data");
        let expected = format!(
            r"{data_tag}:C:\Users\Stephen\data:ro,stat-virt=relaxed,host-perms=mirror,quota={}",
            crate::sandbox::config::DEFAULT_BIND_QUOTA_MIB
        );

        assert!(
            rendered
                .windows(2)
                .any(|pair| pair[0] == "--mount" && pair[1] == expected),
            "missing Windows drive bind --mount arg in {rendered:?}"
        );
        assert!(rendered.contains(&format!("MSB_DIR_MOUNTS={data_tag}:/data:ro")));
    }

    #[tokio::test]
    #[cfg(windows)]
    async fn test_sandbox_cli_args_windows_drive_file_mount_preserves_drive_colon() {
        let config = SandboxBuilder::new("test")
            .image("/tmp/rootfs")
            .volume("/guest/config.txt", |m| {
                m.bind(r"C:\Users\Stephen\config.txt").readonly()
            })
            .build()
            .await
            .unwrap();

        let mut staged_file_mounts = HashMap::new();
        staged_file_mounts.insert(
            "/guest/config.txt".to_string(),
            (
                PathBuf::from(r"C:\Users\Stephen\AppData\Local\Temp\msb\fm_deadbeef"),
                "config.txt".to_string(),
                "fm_deadbeef".to_string(),
            ),
        );

        let rendered = render_args_with_file_mounts(&config, &staged_file_mounts);

        assert!(rendered.windows(2).any(|pair| pair[0] == "--mount"
            && pair[1] == r"fm_deadbeef:C:\Users\Stephen\AppData\Local\Temp\msb\fm_deadbeef:ro"));
        assert!(
            rendered.contains(
                &"MSB_FILE_MOUNTS=fm_deadbeef:config.txt:/guest/config.txt:ro".to_string()
            )
        );
    }

    #[tokio::test]
    async fn test_sandbox_cli_args_named_disk_volume() {
        let config = SandboxBuilder::new("test")
            .image("/tmp/rootfs")
            .volume("/var/lib/docker", |m| {
                m.named_with("docker-data", |v| v.disk().size(2048u32).ensure_exists())
            })
            .build()
            .await
            .unwrap();

        let mut named_volumes = HashMap::new();
        let raw_path = PathBuf::from("/tmp/docker-data/disk.raw");
        named_volumes.insert("docker-data".to_string(), named_disk(&raw_path));

        let rendered = render_args_with_named_volumes(&config, &named_volumes);
        let tag = super::guest_mount_tag("/var/lib/docker");

        assert!(
            rendered.windows(2).any(|pair| pair[0] == "--disk"
                && pair[1] == format!("{tag}:{}:raw", raw_path.display()))
        );
        assert!(rendered.contains(&format!(
            "MSB_DISK_MOUNTS={tag}:/var/lib/docker:fstype=ext4"
        )));
        assert!(
            !rendered
                .iter()
                .any(|arg| arg.starts_with("MSB_DIR_MOUNTS=") && arg.contains("/var/lib/docker")),
            "named disk volume must not be routed through virtiofs: {rendered:?}"
        );
    }

    #[tokio::test]
    async fn test_sandbox_cli_args_named_directory_volume() {
        let config = SandboxBuilder::new("test")
            .image("/tmp/rootfs")
            .volume("/data", |m| {
                m.named_with("mydir", |v| v.quota(512u32).ensure_exists())
            })
            .build()
            .await
            .unwrap();

        let mut named_volumes = HashMap::new();
        named_volumes.insert(
            "mydir".to_string(),
            named_directory("/tmp/mydir", Some(512)),
        );

        let rendered = render_args_with_named_volumes(&config, &named_volumes);
        let tag = super::guest_mount_tag("/data");

        assert!(
            rendered.windows(2).any(
                |pair| pair[0] == "--mount" && pair[1] == format!("{tag}:/tmp/mydir:quota=512")
            )
        );
        assert!(rendered.contains(&format!("MSB_DIR_MOUNTS={tag}:/data")));
        assert!(
            !rendered.windows(2).any(|pair| pair[0] == "--disk"),
            "named directory volume must not emit --disk: {rendered:?}"
        );
        assert!(
            !rendered
                .iter()
                .any(|arg| arg.starts_with("MSB_DISK_MOUNTS=")),
            "named directory volume must not emit disk mount metadata: {rendered:?}"
        );
    }

    #[test]
    fn test_validate_existing_named_volume_rejects_quota_mismatch() {
        let requested =
            named_volume_create("mydir", VolumeKind::Directory, Some(1024), None, Vec::new());
        let existing = existing_volume_model("mydir", VolumeKind::Directory, Some(512), None, None);

        let err = super::validate_existing_named_volume(&requested, &existing).unwrap_err();

        assert!(err.to_string().contains("quota"), "got: {err}");
    }

    #[test]
    fn test_validate_existing_named_volume_rejects_capacity_mismatch() {
        let requested =
            named_volume_create("mydisk", VolumeKind::Disk, None, Some(2048), Vec::new());
        let existing_capacity_bytes = 1024_i64 * 1024 * 1024;
        let existing = existing_volume_model(
            "mydisk",
            VolumeKind::Disk,
            None,
            Some(existing_capacity_bytes),
            None,
        );

        let err = super::validate_existing_named_volume(&requested, &existing).unwrap_err();

        assert!(err.to_string().contains("capacity"), "got: {err}");
    }

    #[test]
    fn test_validate_existing_named_volume_rejects_requested_label_mismatch() {
        let requested = named_volume_create(
            "mydir",
            VolumeKind::Directory,
            None,
            None,
            vec![("env".to_string(), "prod".to_string())],
        );
        let existing = existing_volume_model(
            "mydir",
            VolumeKind::Directory,
            None,
            None,
            Some(vec![("env".to_string(), "dev".to_string())]),
        );

        let err = super::validate_existing_named_volume(&requested, &existing).unwrap_err();

        assert!(err.to_string().contains("label"), "got: {err}");
    }

    #[test]
    fn test_validate_existing_named_volume_allows_extra_existing_labels() {
        let requested = named_volume_create(
            "mydir",
            VolumeKind::Directory,
            None,
            None,
            vec![("env".to_string(), "prod".to_string())],
        );
        let existing = existing_volume_model(
            "mydir",
            VolumeKind::Directory,
            None,
            None,
            Some(vec![
                ("env".to_string(), "prod".to_string()),
                ("team".to_string(), "runtime".to_string()),
            ]),
        );

        super::validate_existing_named_volume(&requested, &existing).unwrap();
    }

    #[tokio::test]
    async fn test_ensure_named_volumes_rolls_back_db_row_on_provision_failure() {
        let temp = tempdir().unwrap();
        let home = temp.path().join("home");
        let volumes_dir = temp.path().join("volumes");
        std::fs::create_dir_all(&volumes_dir).unwrap();
        std::fs::write(volumes_dir.join("broken"), b"not a directory").unwrap();
        let local = LocalBackend::builder()
            .home(&home)
            .volumes_dir(&volumes_dir)
            .build()
            .await
            .unwrap();
        let config = SandboxBuilder::new("test")
            .image("/tmp/rootfs")
            .volume("/data", |m| m.named_with("broken", |v| v.ensure_exists()))
            .build()
            .await
            .unwrap();

        let err = super::ensure_named_volumes(&local, &config)
            .await
            .unwrap_err();

        assert!(err.to_string().contains("already exists"), "got: {err}");
        let pools = local.db().await.unwrap();
        let existing = super::volume_entity::Entity::find()
            .filter(super::volume_entity::Column::Name.eq("broken"))
            .one(pools.read())
            .await
            .unwrap();
        assert!(
            existing.is_none(),
            "failed sandbox-time provisioning must not leave a phantom volume row"
        );
    }

    #[tokio::test]
    async fn test_ensure_named_volumes_rolls_back_earlier_created_volumes_on_later_failure() {
        let temp = tempdir().unwrap();
        let home = temp.path().join("home");
        let volumes_dir = temp.path().join("volumes");
        let local = LocalBackend::builder()
            .home(&home)
            .volumes_dir(&volumes_dir)
            .build()
            .await
            .unwrap();
        let config = SandboxBuilder::new("test")
            .image("/tmp/rootfs")
            .volume("/ok", |m| {
                m.named_with("first-created", |v| v.ensure_exists())
            })
            .volume("/bad", |m| {
                m.named_with("bad-disk", |v| v.ensure_exists().disk())
            })
            .build()
            .await
            .unwrap();

        let err = super::ensure_named_volumes(&local, &config)
            .await
            .unwrap_err();

        assert!(
            err.to_string().contains("disk named volumes require"),
            "got: {err}"
        );
        assert!(!local.volume_path("first-created").exists());
        let pools = local.db().await.unwrap();
        let existing = super::volume_entity::Entity::find()
            .filter(super::volume_entity::Column::Name.eq("first-created"))
            .one(pools.read())
            .await
            .unwrap();
        assert!(
            existing.is_none(),
            "later sandbox-time provisioning failure must roll back earlier created volumes"
        );
    }

    #[tokio::test]
    async fn test_resolve_named_volumes_recovers_disk_metadata_from_store() {
        let temp = tempdir().unwrap();
        let local = LocalBackend::builder()
            .home(temp.path())
            .build()
            .await
            .unwrap();
        let pools = local.db().await.unwrap();
        super::volume_entity::ActiveModel {
            name: Set("mydata".to_string()),
            kind: Set(VolumeKind::Disk.as_str().to_string()),
            disk_format: Set(Some("raw".to_string())),
            disk_fstype: Set(Some("ext4".to_string())),
            created_at: Set(Some(chrono::Utc::now().naive_utc())),
            updated_at: Set(Some(chrono::Utc::now().naive_utc())),
            ..Default::default()
        }
        .insert(pools.write())
        .await
        .unwrap();

        let config = SandboxBuilder::new("test")
            .image("/tmp/rootfs")
            .volume("/data", |m| m.named("mydata"))
            .build()
            .await
            .unwrap();

        let resolved = super::resolve_named_volumes(&local, &config).await.unwrap();
        let volume = resolved.get("mydata").expect("volume should resolve");
        assert_eq!(volume.kind, VolumeKind::Disk);
        assert_eq!(volume.format, Some(DiskImageFormat::Raw));
        assert_eq!(volume.fstype.as_deref(), Some("ext4"));
        assert_eq!(volume.path, local.volume_path("mydata").join("disk.raw"));

        let rendered = render_args_with_named_volumes(&config, &resolved);
        let tag = super::guest_mount_tag("/data");
        assert!(
            rendered.windows(2).any(|pair| pair[0] == "--disk"
                && pair[1] == format!("{tag}:{}:raw", volume.path.display()))
        );
        assert!(rendered.contains(&format!("MSB_DISK_MOUNTS={tag}:/data:fstype=ext4")));

        let owned_config = SandboxBuilder::new("owned-test")
            .image("/tmp/rootfs")
            .volume("/data", |m| m.named("mydata").owner(1000, 1000))
            .build()
            .await
            .unwrap();
        let err = super::resolve_named_volumes(&local, &owned_config)
            .await
            .unwrap_err();
        assert!(
            err.to_string().contains("directory named volumes"),
            "got: {err}"
        );
    }

    #[tokio::test]
    async fn test_existing_named_volume_mode_does_not_validate_default_metadata() {
        let temp = tempdir().unwrap();
        let local = LocalBackend::builder()
            .home(temp.path())
            .build()
            .await
            .unwrap();
        let pools = local.db().await.unwrap();
        super::volume_entity::ActiveModel {
            name: Set("docker-data".to_string()),
            kind: Set(VolumeKind::Disk.as_str().to_string()),
            capacity_bytes: Set(Some(2048_i64 * 1024 * 1024)),
            disk_format: Set(Some("raw".to_string())),
            disk_fstype: Set(Some("ext4".to_string())),
            created_at: Set(Some(chrono::Utc::now().naive_utc())),
            updated_at: Set(Some(chrono::Utc::now().naive_utc())),
            ..Default::default()
        }
        .insert(pools.write())
        .await
        .unwrap();

        let mut config = SandboxBuilder::new("test")
            .image("/tmp/rootfs")
            .volume("/var/lib/docker", |m| m.named("docker-data"))
            .build()
            .await
            .unwrap();
        if let VolumeMount::Named { create, .. } = &mut config.spec.mounts[0] {
            // Directly deserialized configs can still carry an explicit
            // Existing create object even though the builder normalizes this
            // path to a plain named mount.
            *create = Some(microsandbox_types::NamedVolumeCreate {
                mode: crate::sandbox::NamedVolumeMode::Existing,
                name: "docker-data".to_string(),
                kind: VolumeKind::Directory,
                quota_mib: None,
                capacity_mib: None,
                labels: Vec::new(),
            });
        }

        let ensured = super::ensure_named_volumes(&local, &config).await.unwrap();
        assert!(ensured.is_empty());
    }

    #[tokio::test]
    async fn test_sandbox_cli_args_disk_image_volume() {
        // SandboxBuilder::validate canonicalizes disk hosts, so the file
        // must exist. Stage one in a tempdir.
        let dir = tempfile::tempdir().unwrap();
        let host = dir.path().join("data.qcow2");
        std::fs::write(&host, []).unwrap();

        let host_clone = host.clone();
        let config = SandboxBuilder::new("test")
            .image("/tmp/rootfs")
            .volume("/data", |m| {
                m.disk(host_clone)
                    .format(DiskImageFormat::Qcow2)
                    .fstype("ext4")
            })
            .build()
            .await
            .unwrap();

        let rendered = render_args(&config);

        // --disk arg present with correct layout.
        let data_tag = super::guest_mount_tag("/data");
        let expected_disk_arg = format!("{data_tag}:{}:qcow2", host.display());
        assert!(
            rendered
                .windows(2)
                .any(|pair| pair[0] == "--disk" && pair[1] == expected_disk_arg),
            "missing --disk arg in {rendered:?}"
        );

        // MSB_DISK_MOUNTS env entry carries the guest path and fstype.
        let expected_env = format!("MSB_DISK_MOUNTS={data_tag}:/data:fstype=ext4");
        assert!(rendered.contains(&expected_env));
    }

    #[tokio::test]
    async fn test_sandbox_cli_args_disk_image_readonly() {
        let dir = tempfile::tempdir().unwrap();
        let host = dir.path().join("seed.raw");
        std::fs::write(&host, []).unwrap();

        let host_clone = host.clone();
        let config = SandboxBuilder::new("test")
            .image("/tmp/rootfs")
            .volume("/seed", |m| m.disk(host_clone).readonly().noexec())
            .build()
            .await
            .unwrap();

        let rendered = render_args(&config);
        let tag = super::guest_mount_tag("/seed");

        assert!(rendered.windows(2).any(
            |pair| pair[0] == "--disk" && pair[1] == format!("{tag}:{}:raw:ro", host.display())
        ));
        assert!(rendered.contains(&format!("MSB_DISK_MOUNTS={tag}:/seed:ro,noexec")));
    }

    #[test]
    fn test_lock_disk_mounts_rejects_rootfs_and_mount_same_path() {
        let dir = tempfile::tempdir().unwrap();
        let disk = dir.path().join("root.raw");
        std::fs::write(&disk, b"disk").unwrap();

        let config = SandboxConfig {
            spec: microsandbox_types::SandboxSpec {
                image: RootfsSource::DiskImage {
                    path: disk.clone(),
                    format: DiskImageFormat::Raw,
                    fstype: None,
                },
                mounts: vec![VolumeMount::DiskImage {
                    host: disk,
                    guest: "/data".to_string(),
                    format: DiskImageFormat::Raw,
                    fstype: None,
                    options: MountOptions::default(),
                }],
                ..Default::default()
            },
            ..Default::default()
        };

        let err = super::lock_disk_mounts(&config, &HashMap::new()).unwrap_err();
        assert!(err.to_string().contains("more than once per sandbox"));
    }

    #[test]
    fn test_lock_disk_mounts_rejects_duplicate_named_disk_volume() {
        let dir = tempfile::tempdir().unwrap();
        let disk = dir.path().join("disk.raw");
        std::fs::write(&disk, b"disk").unwrap();

        let config = SandboxConfig {
            spec: microsandbox_types::SandboxSpec {
                mounts: vec![
                    VolumeMount::Named {
                        name: "data".to_string(),
                        guest: "/data-a".to_string(),
                        create: None,
                        options: MountOptions::default(),
                        stat_virtualization: StatVirtualization::Strict,
                        host_permissions: HostPermissions::Private,
                        follow_root_symlinks: false,
                    },
                    VolumeMount::Named {
                        name: "data".to_string(),
                        guest: "/data-b".to_string(),
                        create: None,
                        options: MountOptions::default(),
                        stat_virtualization: StatVirtualization::Strict,
                        host_permissions: HostPermissions::Private,
                        follow_root_symlinks: false,
                    },
                ],
                ..Default::default()
            },
            ..Default::default()
        };
        let mut named_volumes = HashMap::new();
        named_volumes.insert("data".to_string(), named_disk(disk));

        let err = super::lock_disk_mounts(&config, &named_volumes).unwrap_err();
        assert!(err.to_string().contains("more than once per sandbox"));
    }

    #[cfg(windows)]
    #[test]
    fn test_lock_disk_image_windows_uses_sidecar_lock() {
        let dir = tempfile::tempdir().unwrap();
        let disk = dir.path().join("disk.raw");
        std::fs::write(&disk, b"disk").unwrap();

        let _lock = super::lock_disk_image_windows(&disk, false, Some("data")).unwrap();
        let _disk_handle = std::fs::OpenOptions::new()
            .read(true)
            .write(true)
            .open(&disk)
            .unwrap();

        let lock_path = super::windows_disk_lock_path(&disk).unwrap();
        assert_eq!(lock_path.file_name().unwrap(), "disk.raw.lock");
        assert!(lock_path.exists());

        let err = super::lock_disk_image_windows(&disk, false, Some("data")).unwrap_err();
        assert!(err.to_string().contains("already attached"));
    }

    #[tokio::test]
    async fn test_guest_mount_tag_is_deterministic() {
        let a = super::guest_mount_tag("/data");
        let b = super::guest_mount_tag("/data");
        assert_eq!(a, b);
    }

    #[tokio::test]
    async fn test_guest_mount_tag_disambiguates_colliding_paths() {
        // The naive `/` → `_` mangling treats these as identical. The
        // slug+hash form must not.
        let a = super::guest_mount_tag("/var/log");
        let b = super::guest_mount_tag("/var_log");
        assert_ne!(a, b);
        assert!(a.starts_with("var_log_"));
        assert!(b.starts_with("var_log_"));
    }

    #[tokio::test]
    async fn test_guest_mount_tag_fits_virtio_blk_serial_limit() {
        // virtio-blk serial is capped at 20 bytes. Long guest paths must still fit.
        let long = "/a/very/deeply/nested/guest/mount/point/that/exceeds/the/slug/cap";
        let tag = super::guest_mount_tag(long);
        assert!(tag.len() <= 20, "tag {tag:?} exceeds 20 bytes");
    }

    #[tokio::test]
    async fn test_guest_mount_tag_slug_prefix_is_readable() {
        assert!(super::guest_mount_tag("/data").starts_with("data_"));
        assert!(super::guest_mount_tag("/var/log").starts_with("var_log_"));
    }

    //----------------------------------------------------------------------------------------------
    // Tests: Handoff init bootstrap construction
    //----------------------------------------------------------------------------------------------

    #[tokio::test]
    async fn test_handoff_init_bootstrap_contains_only_cmd_when_args_and_env_empty() {
        let config = SandboxBuilder::new("test")
            .image("/tmp/rootfs")
            .init("/lib/systemd/systemd")
            .build()
            .await
            .unwrap();

        let launch = render_launch(&config);
        let handoff = launch.bootstrap.handoff_init.expect("handoff bootstrap");

        assert_eq!(handoff.cmd, "/lib/systemd/systemd");
        assert!(handoff.args.is_empty());
        assert!(handoff.cwd.is_none());
        assert!(handoff.env.is_empty());
    }

    #[tokio::test]
    async fn test_handoff_init_bootstrap_contains_cwd_when_workdir_set() {
        let config = SandboxBuilder::new("test")
            .image("/tmp/rootfs")
            .init("/init")
            .workdir("/opt/hermes")
            .build()
            .await
            .unwrap();

        let launch = render_launch(&config);
        let handoff = launch.bootstrap.handoff_init.expect("handoff bootstrap");

        assert_eq!(handoff.cwd.as_deref(), Some("/opt/hermes"));
    }

    #[tokio::test]
    async fn test_handoff_init_bootstrap_preserves_argv() {
        let config = SandboxBuilder::new("test")
            .image("/tmp/rootfs")
            .init_with("/lib/systemd/systemd", |i| {
                i.args([
                    "--unit=multi-user.target",
                    "--log-level=warning",
                    "literal\x1funit-separator",
                ])
            })
            .build()
            .await
            .unwrap();

        let launch = render_launch(&config);
        let handoff = launch.bootstrap.handoff_init.expect("handoff bootstrap");

        assert_eq!(
            handoff.args,
            vec![
                "--unit=multi-user.target",
                "--log-level=warning",
                "literal\x1funit-separator"
            ]
        );
    }

    #[tokio::test]
    async fn test_handoff_init_bootstrap_preserves_environment() {
        let config = SandboxBuilder::new("test")
            .image("/tmp/rootfs")
            .init_with("/sbin/init", |i| {
                i.env("container", "microsandbox")
                    .env("LANG", "C.UTF-8")
                    .env("TOKEN", "a=b;c\x1fd")
            })
            .build()
            .await
            .unwrap();

        let launch = render_launch(&config);
        let handoff = launch.bootstrap.handoff_init.expect("handoff bootstrap");

        assert_eq!(
            handoff.env,
            vec![
                BootstrapEnvVar {
                    key: "container".to_string(),
                    value: "microsandbox".to_string(),
                },
                BootstrapEnvVar {
                    key: "LANG".to_string(),
                    value: "C.UTF-8".to_string(),
                },
                BootstrapEnvVar {
                    key: "TOKEN".to_string(),
                    value: "a=b;c\x1fd".to_string(),
                },
            ]
        );
    }

    #[tokio::test]
    async fn test_handoff_init_omitted_when_unset() {
        let config = SandboxBuilder::new("test")
            .image("/tmp/rootfs")
            .build()
            .await
            .unwrap();

        let launch = render_launch(&config);

        assert!(launch.bootstrap.handoff_init.is_none());
    }

    #[tokio::test]
    async fn test_handoff_init_unit_separator_in_arg_allowed() {
        let config = SandboxBuilder::new("test")
            .image("/tmp/rootfs")
            .init_with("/sbin/init", |i| i.args(["foo\x1fbar"]))
            .build()
            .await
            .unwrap();
        let launch = render_launch(&config);
        let handoff = launch.bootstrap.handoff_init.expect("handoff bootstrap");

        assert_eq!(handoff.args, vec!["foo\x1fbar"]);
    }

    #[tokio::test]
    async fn test_handoff_init_equals_in_env_key_rejected_at_build_time() {
        let err = SandboxBuilder::new("test")
            .image("/tmp/rootfs")
            .init_with("/sbin/init", |i| i.env("BAD=KEY", "v"))
            .build()
            .await
            .unwrap_err();
        assert!(format!("{err}").contains("must not contain '='"));
    }

    /// The checkout's cargo `target` directory, for staging fixtures.
    ///
    /// Fixtures under `target/` share the checkout's filesystem (never the
    /// ambient system temp, which may be tmpfs, so the cross-device tests keep
    /// comparing against the checkout), and `target/` is already gitignored via
    /// `**/target/`, so an interrupted or aborted run cannot leave untracked
    /// litter in the tracked tree. The workspace root is found from the runtime
    /// `CARGO_MANIFEST_DIR`; the compile-time path is only a fallback for a test
    /// binary run outside Cargo.
    #[cfg(unix)]
    fn staging_fixture_dir() -> PathBuf {
        let manifest_dir = std::env::var_os("CARGO_MANIFEST_DIR")
            .map(PathBuf::from)
            .unwrap_or_else(|| PathBuf::from(env!("CARGO_MANIFEST_DIR")));
        let workspace_root = manifest_dir
            .ancestors()
            .find(|dir| {
                std::fs::read_to_string(dir.join("Cargo.toml"))
                    .is_ok_and(|manifest| manifest.lines().any(|line| line.trim() == "[workspace]"))
            })
            .unwrap_or(manifest_dir.as_path());
        let target = workspace_root.join("target");
        std::fs::create_dir_all(&target).unwrap();
        target
    }

    /// A staging fixture root under the checkout's `target/`. Sandbox and source
    /// directories are its subdirectories, so they share one device.
    #[cfg(unix)]
    fn staging_fixture_root() -> tempfile::TempDir {
        tempfile::Builder::new()
            .prefix("msb-staging-fixture-")
            .tempdir_in(staging_fixture_dir())
            .unwrap()
    }

    /// Create a sandbox directory that a staging call owns, separate from the
    /// source directories, under one fixture root. Returns the root (kept alive
    /// for the test) and the sandbox directory path.
    #[cfg(unix)]
    fn staging_sandbox_dir() -> (tempfile::TempDir, PathBuf) {
        let root = staging_fixture_root();
        let sandbox = root.path().join("sandbox");
        std::fs::create_dir_all(&sandbox).unwrap();
        // Return the canonical sandbox path so it compares equal to the
        // canonicalized stage paths the staging code produces (macOS temp paths
        // under `/var` resolve to `/private/var`).
        let sandbox = std::fs::canonicalize(&sandbox).unwrap();
        (root, sandbox)
    }

    /// A source directory under a fixture root, sibling to the sandbox
    /// directory so the two share a device.
    #[cfg(unix)]
    fn same_device_source_dir(root: &Path) -> PathBuf {
        let sources = root.join("sources");
        std::fs::create_dir_all(&sources).unwrap();
        std::fs::canonicalize(&sources).unwrap()
    }

    async fn file_mounts_config(mounts: &[(&Path, &str, bool)]) -> SandboxConfig {
        let mut builder = SandboxBuilder::new("test").image("/tmp/rootfs");
        for (host, guest, readonly) in mounts {
            builder = builder.volume(*guest, |mount| {
                let mount = mount.bind(*host);
                if *readonly { mount.readonly() } else { mount }
            });
        }
        builder.build().await.unwrap()
    }

    async fn file_mount_config(host: &Path, guest: &str, readonly: bool) -> SandboxConfig {
        file_mounts_config(&[(host, guest, readonly)]).await
    }

    /// The canonical sandbox-dir stage path. Staged mount directories are
    /// canonicalized, so the expected root must be too (macOS temp paths under
    /// `/var` resolve to `/private/var`). The sandbox directory always exists by
    /// the time this is called.
    #[cfg(unix)]
    fn sandbox_stage_root(sandbox_dir: &Path) -> PathBuf {
        std::fs::canonicalize(sandbox_dir)
            .unwrap_or_else(|error| {
                panic!("sandbox dir {} missing: {error}", sandbox_dir.display())
            })
            .join("file-mounts")
    }

    /// A `msb`-named sandbox directory with a pre-staged marker and a source
    /// file inside the fixture root, for the Windows legacy-preservation tests.
    ///
    /// The source lives under the fixture's own `root` rather than the
    /// process-global system temp dir, so two tests in this binary get distinct
    /// source paths and cannot race; dropping `root` removes the source.
    #[cfg(windows)]
    fn windows_staging_fixture() -> (tempfile::TempDir, PathBuf, PathBuf) {
        let root = tempdir().unwrap();
        let sandbox = root.path().join("sandbox");
        let stage_root = sandbox.join("file-mounts");
        std::fs::create_dir_all(&stage_root).unwrap();
        std::fs::write(stage_root.join("stale-sentinel"), b"old").unwrap();
        let source = root.path().join("msb-staging-source.txt");
        std::fs::write(&source, b"source").unwrap();
        (root, sandbox, source)
    }

    /// The legacy classifier still recognizes the OS cross-device error and the
    /// portable `CrossesDevices` kind.
    #[cfg(windows)]
    #[test]
    fn windows_cross_device_link_classifier_matches_raw_17_and_kind() {
        assert!(super::is_cross_device_link_error(
            &std::io::Error::from_raw_os_error(17)
        ));
        assert!(super::is_cross_device_link_error(&std::io::Error::new(
            std::io::ErrorKind::CrossesDevices,
            "kind"
        )));
        assert!(!super::is_cross_device_link_error(
            &std::io::Error::from_raw_os_error(2)
        ));
        assert!(!super::is_cross_device_link_error(&std::io::Error::new(
            std::io::ErrorKind::PermissionDenied,
            "other"
        )));
    }

    /// The non-Unix dispatcher preserves the legacy behavior: it stages into a
    /// system-temp root, never under the sandbox directory, and leaves the
    /// sandbox directory (and any stale `file-mounts` content) untouched.
    #[cfg(windows)]
    #[tokio::test]
    async fn windows_dispatcher_stages_in_system_temp_and_ignores_sandbox_dir() {
        let (root, sandbox, source) = windows_staging_fixture();
        let config = file_mount_config(&source, "/guest/source.txt", false).await;

        let (staged, staging) = super::stage_file_mounts(&config, &sandbox).await.unwrap();
        let (mount_dir, filename, _) = staged.get("/guest/source.txt").unwrap();

        let system_temp = std::fs::canonicalize(std::env::temp_dir()).unwrap();
        assert!(
            mount_dir.starts_with(&system_temp),
            "the legacy path must stage in the system temp dir: {}",
            mount_dir.display()
        );
        assert!(
            !mount_dir.starts_with(sandbox.join("file-mounts")),
            "the legacy path must not use the sandbox directory"
        );
        assert!(
            sandbox.join("file-mounts").join("stale-sentinel").exists(),
            "the legacy path must not clear the sandbox directory"
        );
        assert_eq!(std::fs::metadata(&source).unwrap().len(), 6);
        assert_eq!(std::fs::read(mount_dir.join(filename)).unwrap(), b"source");
        assert_eq!(staging.len(), 1, "one system-temp root per staging call");
        drop(root);
    }

    /// Two legacy staging calls with the same sandbox argument return independent
    /// system-temp roots; dropping one leaves the other's files intact.
    #[cfg(windows)]
    #[tokio::test]
    async fn windows_legacy_staging_roots_are_independent() {
        let (root, sandbox, source) = windows_staging_fixture();
        let config = file_mount_config(&source, "/guest/source.txt", false).await;

        let (_, first_staging) = super::stage_file_mounts(&config, &sandbox).await.unwrap();
        let (_, second_staging) = super::stage_file_mounts(&config, &sandbox).await.unwrap();
        let first_root = first_staging[0].path().to_path_buf();
        let second_root = second_staging[0].path().to_path_buf();
        assert_ne!(first_root, second_root);

        drop(windows_probe_handle(first_staging, "windows-legacy-first"));
        assert!(
            !first_root.exists(),
            "dropping one token must remove only its own root"
        );
        assert!(second_root.exists());
        drop(windows_probe_handle(
            second_staging,
            "windows-legacy-second",
        ));
        assert!(!second_root.exists());
        drop(root);
    }

    #[tokio::test]
    #[cfg(unix)]
    async fn stage_file_mounts_hard_links_same_filesystem_source() {
        let (root, sandbox) = staging_sandbox_dir();
        let source = same_device_source_dir(root.path()).join("source.txt");
        std::fs::write(&source, b"source").unwrap();
        let config = file_mount_config(&source, "/guest/source.txt", false).await;

        let (staged, staging) = super::stage_file_mounts(&config, &sandbox).await.unwrap();
        let (mount_dir, filename, _) = staged.get("/guest/source.txt").unwrap();
        let staged_file = mount_dir.join(filename);

        assert!(
            staging.is_empty(),
            "a same-device mount stages in the sandbox directory, not a temporary root"
        );
        assert!(
            mount_dir.starts_with(sandbox_stage_root(&sandbox)),
            "same-device stage must be under the sandbox dir: {}",
            mount_dir.display()
        );
        assert_eq!(std::fs::read(&staged_file).unwrap(), b"source");
        assert_eq!(
            std::fs::metadata(&source).unwrap().ino(),
            std::fs::metadata(&staged_file).unwrap().ino(),
            "ordinary same-device file mounts must hard-link the source"
        );
    }

    /// A same-device stage is a live hard link, not a snapshot: a readonly mount
    /// reflects later source edits, and a write through a writable mount reaches
    /// the source. This is the host-side behavior the VM e2e depends on for the
    /// common single-filesystem layout.
    #[tokio::test]
    #[cfg(unix)]
    async fn stage_file_mounts_same_device_links_are_live() {
        let (root, sandbox) = staging_sandbox_dir();
        let sources = same_device_source_dir(root.path());

        // Readonly same device is a link, so editing the source after staging is
        // visible through the staged file (readonly is not a frozen copy).
        let readonly = sources.join("readonly.txt");
        std::fs::write(&readonly, b"before").unwrap();
        let config = file_mount_config(&readonly, "/guest/readonly.txt", true).await;
        let (staged, _) = super::stage_file_mounts(&config, &sandbox).await.unwrap();
        let (dir, name, _) = staged.get("/guest/readonly.txt").unwrap();
        std::fs::write(&readonly, b"after").unwrap();
        assert_eq!(
            std::fs::read(dir.join(name)).unwrap(),
            b"after",
            "a same-device readonly mount is a link, so later source edits are visible"
        );

        // Writable same device preserves inode identity, so a write through the
        // staged path reaches the source file.
        let writable = sources.join("writable.txt");
        std::fs::write(&writable, b"before").unwrap();
        let config = file_mount_config(&writable, "/guest/writable.txt", false).await;
        let (staged, _) = super::stage_file_mounts(&config, &sandbox).await.unwrap();
        let (dir, name, _) = staged.get("/guest/writable.txt").unwrap();
        std::fs::write(dir.join(name), b"guest write").unwrap();
        assert_eq!(
            std::fs::read(&writable).unwrap(),
            b"guest write",
            "a same-device writable mount writes through to the source"
        );
    }

    /// A same-device readonly mount is still a hard link (not a snapshot), and
    /// its stage survives the staging token being dropped: the sandbox-dir
    /// stage is not a `TempDir`.
    #[tokio::test]
    #[cfg(unix)]
    async fn stage_file_mounts_same_device_readonly_links_and_persists() {
        let (root, sandbox) = staging_sandbox_dir();
        let source = same_device_source_dir(root.path()).join("readonly.txt");
        std::fs::write(&source, b"before").unwrap();
        let config = file_mount_config(&source, "/guest/readonly.txt", true).await;

        let (staged, staging) = super::stage_file_mounts(&config, &sandbox).await.unwrap();
        let (mount_dir, filename, _) = staged.get("/guest/readonly.txt").unwrap();
        let staged_file = mount_dir.join(filename);

        assert!(staging.is_empty());
        assert!(mount_dir.starts_with(sandbox_stage_root(&sandbox)));
        assert_eq!(
            std::fs::metadata(&source).unwrap().ino(),
            std::fs::metadata(&staged_file).unwrap().ino(),
            "a same-device readonly mount is a link, not a snapshot"
        );

        let stage_root = sandbox_stage_root(&sandbox);
        drop(staging);
        assert!(
            mount_dir.exists() && stage_root.exists(),
            "the sandbox-dir stage must persist after the staging token is dropped: {}",
            stage_root.display()
        );
        assert_eq!(file_mode(&stage_root), 0o700);
    }

    #[tokio::test]
    #[cfg(unix)]
    async fn stage_file_mounts_forced_device_mismatch_copies_readonly_source() {
        let (root, sandbox) = staging_sandbox_dir();
        let source = same_device_source_dir(root.path()).join("readonly.txt");
        std::fs::write(&source, b"before").unwrap();
        let config = file_mount_config(&source, "/guest/readonly.txt", true).await;

        let (staged, staging) = super::stage_file_mounts_with_mode(
            &config,
            &sandbox,
            super::FileMountStagingMode::ForceDeviceMismatch,
        )
        .await
        .unwrap();
        let (mount_dir, filename, _) = staged.get("/guest/readonly.txt").unwrap();
        let staged_file = mount_dir.join(filename);
        std::fs::write(&source, b"after").unwrap();

        assert!(
            staging.is_empty(),
            "a readonly copy needs no temporary root"
        );
        assert!(
            mount_dir.starts_with(sandbox_stage_root(&sandbox)),
            "a readonly cross-device copy stays in the sandbox dir: {}",
            mount_dir.display()
        );
        assert_eq!(std::fs::read(&staged_file).unwrap(), b"before");
        assert_eq!(
            std::fs::metadata(&staged_file).unwrap().nlink(),
            1,
            "a readonly cross-device copy must not share the source inode"
        );
    }

    #[tokio::test]
    #[cfg(unix)]
    async fn stage_file_mounts_forced_device_mismatch_hard_links_writable_source_parent() {
        let (root, sandbox) = staging_sandbox_dir();
        let source_dir = same_device_source_dir(root.path());
        let source = source_dir.join("writable.txt");
        std::fs::write(&source, b"before").unwrap();
        let config = file_mount_config(&source, "/guest/writable.txt", false).await;

        let (staged, staging) = super::stage_file_mounts_with_mode(
            &config,
            &sandbox,
            super::FileMountStagingMode::ForceDeviceMismatch,
        )
        .await
        .unwrap();
        let (mount_dir, filename, _) = staged.get("/guest/writable.txt").unwrap();
        let staged_file = mount_dir.join(filename);
        std::fs::write(&staged_file, b"guest write").unwrap();

        assert_eq!(
            staging.len(),
            1,
            "one source-parent stage per writable cross-device mount"
        );
        assert!(
            mount_dir.starts_with(std::fs::canonicalize(&source_dir).unwrap()),
            "a writable cross-device stage must live beside its source"
        );
        assert!(
            !mount_dir.starts_with(sandbox_stage_root(&sandbox)),
            "a writable cross-device mount must not use the sandbox-dir stage"
        );
        assert_eq!(std::fs::read(&source).unwrap(), b"guest write");
        assert_eq!(
            std::fs::metadata(&source).unwrap().ino(),
            std::fs::metadata(&staged_file).unwrap().ino(),
            "writable cross-device staging must preserve writeback through a hard link"
        );
    }

    #[tokio::test]
    #[cfg(unix)]
    async fn stage_file_mounts_retains_every_writable_device_mismatch_staging_directory() {
        let (root, sandbox) = staging_sandbox_dir();
        let sources = same_device_source_dir(root.path());
        let first_parent = sources.join("first");
        let second_parent = sources.join("second");
        std::fs::create_dir_all(&first_parent).unwrap();
        std::fs::create_dir_all(&second_parent).unwrap();
        let first = first_parent.join("first.txt");
        let second = second_parent.join("second.txt");
        std::fs::write(&first, b"first").unwrap();
        std::fs::write(&second, b"second").unwrap();
        let config = file_mounts_config(&[
            (&first, "/guest/first.txt", false),
            (&second, "/guest/second.txt", false),
        ])
        .await;

        let (staged, staging) = super::stage_file_mounts_with_mode(
            &config,
            &sandbox,
            super::FileMountStagingMode::ForceDeviceMismatch,
        )
        .await
        .unwrap();

        assert_eq!(staging.len(), 2, "one source-parent stage per file");
        for (source, guest) in [(&first, "/guest/first.txt"), (&second, "/guest/second.txt")] {
            let (mount_dir, filename, _) = staged.get(guest).unwrap();
            let staged_file = mount_dir.join(filename);
            assert!(staged_file.exists());
            assert_eq!(
                std::fs::metadata(source).unwrap().ino(),
                std::fs::metadata(&staged_file).unwrap().ino()
            );
        }
        assert!(
            directory_entries(&sandbox_stage_root(&sandbox)).is_empty(),
            "a writable cross-device mount must create no tag in the sandbox-dir stage"
        );
    }

    #[tokio::test]
    #[cfg(unix)]
    async fn stage_file_mounts_forced_device_mismatch_fails_when_source_parent_is_unwritable() {
        let (root, sandbox) = staging_sandbox_dir();
        let source = same_device_source_dir(root.path()).join("source.txt");
        std::fs::write(&source, b"source").unwrap();
        let config = file_mount_config(&source, "/guest/source.txt", false).await;

        let rendered = super::stage_file_mounts_with_mode(
            &config,
            &sandbox,
            super::FileMountStagingMode::ForceDeviceMismatchAndRejectSourceParentStage,
        )
        .await
        .expect_err("writable cross-device staging must not fall back to a copy")
        .to_string();
        assert!(
            rendered.contains(&source.display().to_string()),
            "the error must name the mount that could not be staged: {rendered}"
        );
        assert!(
            rendered.contains("writable"),
            "the error must explain what the caller can change: {rendered}"
        );
    }

    /// A sole writable cross-device mount creates no `<tag>` directory under the
    /// sandbox-dir stage, and a stale sandbox-dir stage is cleared first.
    #[tokio::test]
    #[cfg(unix)]
    async fn stage_file_mounts_sole_writable_mismatch_leaves_no_sandbox_tag() {
        let (root, sandbox) = staging_sandbox_dir();
        let stage_root = sandbox_stage_root(&sandbox);
        std::fs::create_dir_all(&stage_root).unwrap();
        std::fs::write(stage_root.join("stale-sentinel"), b"old").unwrap();
        let source = same_device_source_dir(root.path()).join("writable.txt");
        std::fs::write(&source, b"before").unwrap();
        let config = file_mount_config(&source, "/guest/writable.txt", false).await;

        let (staged, staging) = super::stage_file_mounts_with_mode(
            &config,
            &sandbox,
            super::FileMountStagingMode::ForceDeviceMismatch,
        )
        .await
        .unwrap();
        let (mount_dir, filename, _) = staged.get("/guest/writable.txt").unwrap();
        std::fs::write(mount_dir.join(filename), b"guest").unwrap();

        assert_eq!(std::fs::read(&source).unwrap(), b"guest");
        assert_eq!(staging.len(), 1);
        assert!(
            !stage_root.join("stale-sentinel").exists(),
            "the previous sandbox-dir stage must be cleared"
        );
        assert!(
            directory_entries(&stage_root).is_empty(),
            "a sole writable cross-device mount must create no tag in the sandbox-dir stage: {:?}",
            directory_entries(&stage_root)
        );
    }

    /// Mixed same-device and cross-device mounts place each stage exactly where
    /// its device decision says, expose exactly the selected filename, and leave
    /// the source files' siblings unshared.
    #[tokio::test]
    #[cfg(unix)]
    async fn stage_file_mounts_places_each_mount_by_device_decision() {
        let (root, sandbox) = staging_sandbox_dir();
        let sources = same_device_source_dir(root.path());
        let same_device = sources.join("same.txt");
        let readonly_mismatch = sources.join("readonly.txt");
        let writable_mismatch = sources.join("writable.txt");
        std::fs::write(&same_device, b"same").unwrap();
        std::fs::write(&readonly_mismatch, b"ro").unwrap();
        std::fs::write(&writable_mismatch, b"rw").unwrap();
        std::fs::write(sources.join("sibling-sentinel"), b"private").unwrap();

        // Same-device mount routed by identity (Automatic).
        let same_config = file_mount_config(&same_device, "/guest/same.txt", false).await;
        let (staged, _) = super::stage_file_mounts(&same_config, &sandbox)
            .await
            .unwrap();
        let (same_dir, same_name, _) = staged.get("/guest/same.txt").unwrap();
        assert!(same_dir.starts_with(sandbox_stage_root(&sandbox)));
        assert_eq!(directory_entries(same_dir), vec![same_name.clone()]);

        // Forced-mismatch mounts: readonly copies into the sandbox dir, writable
        // stages beside its source.
        let mismatch_config = file_mounts_config(&[
            (&readonly_mismatch, "/guest/readonly.txt", true),
            (&writable_mismatch, "/guest/writable.txt", false),
        ])
        .await;
        let (staged, staging) = super::stage_file_mounts_with_mode(
            &mismatch_config,
            &sandbox,
            super::FileMountStagingMode::ForceDeviceMismatch,
        )
        .await
        .unwrap();
        assert_eq!(staging.len(), 1, "only the writable mismatch needs a root");
        let (ro_dir, ro_name, _) = staged.get("/guest/readonly.txt").unwrap();
        assert!(ro_dir.starts_with(sandbox_stage_root(&sandbox)));
        assert_eq!(directory_entries(ro_dir), vec![ro_name.clone()]);
        let (rw_dir, rw_name, _) = staged.get("/guest/writable.txt").unwrap();
        assert!(rw_dir.starts_with(std::fs::canonicalize(&sources).unwrap()));
        assert_eq!(directory_entries(rw_dir), vec![rw_name.clone()]);
    }

    /// Respawning the same sandbox name clears the previous sandbox-dir stage,
    /// including when the new spawn has no file mounts.
    #[tokio::test]
    #[cfg(unix)]
    async fn stage_file_mounts_respawn_clears_previous_sandbox_stage() {
        let (root, sandbox) = staging_sandbox_dir();
        let sources = same_device_source_dir(root.path());
        let first = sources.join("first.txt");
        std::fs::write(&first, b"first").unwrap();
        let config = file_mount_config(&first, "/guest/first.txt", false).await;
        let (staged, _) = super::stage_file_mounts(&config, &sandbox).await.unwrap();
        let (first_dir, _, _) = staged.get("/guest/first.txt").unwrap();
        assert!(first_dir.exists());

        let second = sources.join("second.txt");
        std::fs::write(&second, b"second").unwrap();
        let second_config = file_mount_config(&second, "/guest/second.txt", false).await;
        let (staged, _) = super::stage_file_mounts(&second_config, &sandbox)
            .await
            .unwrap();
        let (second_dir, second_name, _) = staged.get("/guest/second.txt").unwrap();
        assert!(
            !first_dir.exists(),
            "the previous generation's stage directory must be cleared"
        );
        assert_eq!(
            std::fs::read(second_dir.join(second_name)).unwrap(),
            b"second"
        );

        // A restart that drops all file mounts removes the root entirely.
        let directory = sources.join("adir");
        std::fs::create_dir_all(&directory).unwrap();
        let directory_config = file_mounts_config(&[(&directory, "/guest/dir", false)]).await;
        let (staged, staging) = super::stage_file_mounts(&directory_config, &sandbox)
            .await
            .unwrap();
        assert!(staged.is_empty());
        assert!(staging.is_empty());
        assert!(
            !sandbox_stage_root(&sandbox).exists(),
            "a spawn with no file mounts must clear and not recreate the sandbox-dir stage"
        );
    }

    /// The sandbox-dir stage root is owner-only (`0700`), holds only its tag
    /// directories, and a stale symlink root is removed rather than followed.
    #[tokio::test]
    #[cfg(unix)]
    async fn stage_file_mounts_sandbox_stage_root_is_private() {
        let (root, sandbox) = staging_sandbox_dir();
        let source = same_device_source_dir(root.path()).join("source.txt");
        std::fs::write(&source, b"source").unwrap();
        let config = file_mount_config(&source, "/guest/source.txt", false).await;

        let (staged, _) = super::stage_file_mounts(&config, &sandbox).await.unwrap();
        let (mount_dir, filename, tag) = staged.get("/guest/source.txt").unwrap();
        let stage_root = sandbox_stage_root(&sandbox);
        assert_eq!(
            file_mode(&stage_root),
            0o700,
            "stage root must not be world-accessible"
        );
        assert_eq!(directory_entries(&stage_root), vec![tag.clone()]);
        assert_eq!(directory_entries(mount_dir), vec![filename.clone()]);

        // A permissive stale root must be reset back to 0700 by the next spawn.
        set_mode(&stage_root, 0o777);
        let (_, _) = super::stage_file_mounts(&config, &sandbox).await.unwrap();
        assert_eq!(file_mode(&stage_root), 0o700);
    }

    /// A `file-mounts` root that is a symlink is removed as a link, leaving the
    /// directory it points at untouched.
    #[tokio::test]
    #[cfg(unix)]
    async fn stage_file_mounts_clear_removes_symlink_root_not_its_target() {
        let (root, sandbox) = staging_sandbox_dir();
        let outside = root.path().join("outside");
        std::fs::create_dir_all(&outside).unwrap();
        std::fs::write(outside.join("keep"), b"keep").unwrap();
        std::fs::create_dir_all(&sandbox).unwrap();
        std::os::unix::fs::symlink(&outside, sandbox_stage_root(&sandbox)).unwrap();

        let source = same_device_source_dir(root.path()).join("source.txt");
        std::fs::write(&source, b"source").unwrap();
        let config = file_mount_config(&source, "/guest/source.txt", false).await;
        let (_staged, _) = super::stage_file_mounts(&config, &sandbox).await.unwrap();

        assert!(
            outside.join("keep").exists(),
            "clearing must not follow a root symlink into its target"
        );
        let stage_root = sandbox_stage_root(&sandbox);
        assert!(
            stage_root.is_dir(),
            "a fresh private root replaces the symlink"
        );
        assert!(!stage_root.is_symlink());
    }

    /// An unexpected non-directory root artifact is a fatal error, before any
    /// staging happens.
    #[tokio::test]
    #[cfg(unix)]
    async fn stage_file_mounts_clear_rejects_unexpected_root_artifact() {
        let (root, sandbox) = staging_sandbox_dir();
        std::fs::create_dir_all(&sandbox).unwrap();
        // A fifo is neither a file, directory, nor symlink.
        let fifo = sandbox_stage_root(&sandbox);
        let status = std::process::Command::new("mkfifo")
            .arg(&fifo)
            .status()
            .unwrap();
        assert!(status.success());

        let source = same_device_source_dir(root.path()).join("source.txt");
        std::fs::write(&source, b"source").unwrap();
        let config = file_mount_config(&source, "/guest/source.txt", false).await;
        let result = super::stage_file_mounts(&config, &sandbox).await;
        assert!(
            result.is_err(),
            "an unexpected root artifact must be fatal, not cleared"
        );
    }

    /// A source directory on a filesystem other than the sandbox directory, if
    /// this host has a writable one.
    ///
    /// Cross-device staging is only reachable when the source and the
    /// sandbox-dir stage really differ in `st_dev`, so a host without a second
    /// filesystem cannot cover the branch. The situation is reported instead of
    /// silently passing, and CI overrides it:
    ///
    /// - `MSB_TEST_CROSS_DEVICE_DIR` names the directory to stage from (the macOS
    ///   job points it at the RAM disk it creates; Linux auto-discovers `/dev/shm`).
    /// - `MSB_TEST_REQUIRE_CROSS_DEVICE_TESTS` turns the missing-precondition case
    ///   into a failure, so a job that is supposed to run these tests cannot quietly
    ///   stop running them.
    #[cfg(unix)]
    fn cross_device_source_dir(sandbox_dir: &Path) -> Option<tempfile::TempDir> {
        // Required mode must not escape via an early `?` on setup inspection:
        // a sandbox directory that cannot be inspected is a hard error.
        let sandbox_dir = match std::fs::canonicalize(sandbox_dir) {
            Ok(dir) => dir,
            Err(error) => panic!(
                "cross-device tests could not inspect the sandbox directory {}: {error}",
                sandbox_dir.display()
            ),
        };
        let sandbox_dev = std::fs::metadata(&sandbox_dir)
            .unwrap_or_else(|error| {
                panic!(
                    "cross-device tests could not stat the sandbox directory {}: {error}",
                    sandbox_dir.display()
                )
            })
            .dev();
        let required = std::env::var_os("MSB_TEST_REQUIRE_CROSS_DEVICE_TESTS").is_some();

        let explicit = std::env::var_os("MSB_TEST_CROSS_DEVICE_DIR").map(PathBuf::from);
        let candidates: Vec<PathBuf> = match &explicit {
            Some(explicit) => vec![explicit.clone()],
            None => {
                let mut candidates: Vec<PathBuf> =
                    ["/dev/shm", "/run"].iter().map(PathBuf::from).collect();
                // macOS: any mounted volume (a RAM disk or a disk image both work).
                // Entries for the boot volume resolve to the same device and are
                // filtered out below.
                if let Ok(entries) = std::fs::read_dir("/Volumes") {
                    candidates.extend(entries.flatten().map(|entry| entry.path()));
                }
                candidates
            }
        };

        let mut rejected: Vec<String> = Vec::new();
        let found = candidates.iter().find_map(|candidate| {
            // Canonicalize first: on a distribution where `/dev/shm` is a
            // symlink to `/run/shm`, `tempdir_in` would return a path that
            // traverses a symlink and every cross-device file mount would now be
            // refused by the no-follow policy.
            let candidate = match std::fs::canonicalize(candidate) {
                Ok(candidate) => candidate,
                Err(error) => {
                    rejected.push(format!("{}: {error}", candidate.display()));
                    return None;
                }
            };
            let candidate_dev = match std::fs::metadata(&candidate) {
                Ok(metadata) => metadata.dev(),
                Err(error) => {
                    rejected.push(format!("{}: {error}", candidate.display()));
                    return None;
                }
            };
            if candidate_dev == sandbox_dev {
                rejected.push(format!(
                    "{}: same device as the sandbox ({sandbox_dev})",
                    candidate.display()
                ));
                return None;
            }
            match tempfile::Builder::new()
                .prefix("microsandbox-cross-device-")
                .tempdir_in(&candidate)
            {
                Ok(dir) => Some(dir),
                Err(error) => {
                    rejected.push(format!("{}: not writable: {error}", candidate.display()));
                    None
                }
            }
        });
        if let Some(dir) = &found {
            // Validate the allocated fixture's device too, not just the guessed path.
            let actual_dev = std::fs::metadata(dir.path()).unwrap().dev();
            assert_ne!(
                actual_dev,
                sandbox_dev,
                "allocated cross-device source fixture {} is on the sandbox's device {sandbox_dev}",
                dir.path().display()
            );
        }
        if found.is_none() {
            let message = format!(
                "cross-device staging tests need a writable directory on a filesystem other than \
                 the sandbox directory ({}, device {sandbox_dev}): none of {candidates:?} qualifies \
                 (rejected: {rejected:?})",
                sandbox_dir.display()
            );
            if required {
                panic!("MSB_TEST_REQUIRE_CROSS_DEVICE_TESTS is set but {message}");
            }
            eprintln!("SKIP: {message}");
        }
        found
    }

    #[cfg(unix)]
    fn file_mode(path: &Path) -> u32 {
        use std::os::unix::fs::PermissionsExt;

        std::fs::metadata(path).unwrap().permissions().mode() & 0o7777
    }

    #[cfg(unix)]
    fn running_as_root() -> bool {
        // SAFETY: `geteuid` has no preconditions and cannot fail.
        unsafe { libc::geteuid() == 0 }
    }

    #[cfg(unix)]
    fn set_mode(path: &Path, mode: u32) {
        use std::os::unix::fs::PermissionsExt;

        std::fs::set_permissions(path, std::fs::Permissions::from_mode(mode)).unwrap();
    }

    #[cfg(unix)]
    fn directory_entries(path: &Path) -> Vec<String> {
        let mut entries: Vec<String> = std::fs::read_dir(path)
            .unwrap()
            .map(|entry| entry.unwrap().file_name().to_string_lossy().into_owned())
            .collect();
        entries.sort();
        entries
    }

    #[cfg(unix)]
    fn assert_no_staging_residue(path: &Path) {
        let residue: Vec<String> = directory_entries(path)
            .into_iter()
            .filter(|entry| entry.starts_with(".microsandbox-file-mount-"))
            .collect();
        assert!(
            residue.is_empty(),
            "staging residue left in {}: {residue:?}",
            path.display()
        );
    }

    #[cfg(unix)]
    fn probe_handle(
        staging: Vec<super::FileMountStageOwner>,
        label: &str,
    ) -> crate::runtime::ProcessHandle {
        let child = tokio::process::Command::new("true").spawn().unwrap();
        let pid = child.id().unwrap();
        crate::runtime::ProcessHandle::new(
            pid,
            label.to_string(),
            child,
            staging,
            Vec::new(),
            None,
            None,
        )
    }

    /// Like [`probe_handle`], but with the non-Unix `ProcessHandle::new` shape:
    /// on Windows the parent-watchdog argument is replaced by a job-object one,
    /// so both it and the metrics reservation are supplied explicitly.
    #[cfg(windows)]
    fn windows_probe_handle(
        staging: Vec<super::FileMountStageOwner>,
        label: &str,
    ) -> crate::runtime::ProcessHandle {
        let child = tokio::process::Command::new("cmd")
            .arg("/C")
            .arg("exit 0")
            .spawn()
            .unwrap();
        let pid = child.id().unwrap();
        crate::runtime::ProcessHandle::new(
            pid,
            label.to_string(),
            child,
            staging,
            Vec::new(),
            None,
            None,
        )
    }

    /// The forced modes above override the equality decision; this drives the
    /// real cross-device branch with filesystems that genuinely differ in
    /// `st_dev`, which is the only check that validates the identity classifier
    /// against the OS instead of a hand-built decision.
    #[tokio::test]
    #[cfg(unix)]
    async fn stage_file_mounts_real_cross_device_keeps_writable_inode_identity() {
        let (root, sandbox) = staging_sandbox_dir();
        let Some(source_dir) = cross_device_source_dir(&sandbox) else {
            drop(root);
            return;
        };
        let source = source_dir.path().join("writable.txt");
        std::fs::write(&source, b"before").unwrap();
        assert_ne!(
            std::fs::metadata(&source).unwrap().dev(),
            std::fs::metadata(sandbox_stage_root(&sandbox))
                .map(|metadata| metadata.dev())
                .unwrap_or_else(|_| std::fs::metadata(&sandbox).unwrap().dev()),
            "the source must really be on a different device from the sandbox dir"
        );

        let config = file_mount_config(&source, "/guest/writable.txt", false).await;
        let (staged, staging) = super::stage_file_mounts(&config, &sandbox).await.unwrap();
        let (mount_dir, filename, _) = staged.get("/guest/writable.txt").unwrap();
        let staged_file = mount_dir.join(filename);

        assert_eq!(
            staging.len(),
            1,
            "one source-parent stage per writable mount"
        );
        assert_eq!(
            std::fs::metadata(&source).unwrap().dev(),
            std::fs::metadata(&staged_file).unwrap().dev(),
            "a writable cross-device stage must live on the source's filesystem"
        );
        assert_eq!(
            std::fs::metadata(&source).unwrap().ino(),
            std::fs::metadata(&staged_file).unwrap().ino(),
            "a writable cross-device mount must keep inode identity"
        );
        std::fs::write(&staged_file, b"guest write").unwrap();
        assert_eq!(std::fs::read(&source).unwrap(), b"guest write");

        // The stage survives until the handle that owns it goes away, and then it is
        // gone from the user's own directory.
        let stage_root = mount_dir.parent().unwrap().to_path_buf();
        assert!(stage_root.exists());
        drop(staging);
        assert!(
            !stage_root.exists(),
            "dropping the staging handle must remove {}",
            stage_root.display()
        );
        assert_no_staging_residue(source_dir.path());
    }

    /// A readonly cross-device mount must become an isolated copy under the
    /// sandbox directory: no link to the host source, frozen content.
    #[tokio::test]
    #[cfg(unix)]
    async fn stage_file_mounts_real_cross_device_copies_readonly_into_sandbox_stage() {
        let (root, sandbox) = staging_sandbox_dir();
        let Some(source_dir) = cross_device_source_dir(&sandbox) else {
            drop(root);
            return;
        };
        let source = source_dir.path().join("readonly.txt");
        std::fs::write(&source, b"before").unwrap();
        assert_ne!(
            std::fs::metadata(&source).unwrap().dev(),
            std::fs::metadata(&sandbox).unwrap().dev(),
            "the source must really be on a different device from the sandbox dir"
        );

        let config = file_mount_config(&source, "/guest/readonly.txt", true).await;
        let (staged, staging) = super::stage_file_mounts(&config, &sandbox).await.unwrap();
        let (mount_dir, filename, _) = staged.get("/guest/readonly.txt").unwrap();
        let staged_file = mount_dir.join(filename);

        assert!(
            staging.is_empty(),
            "a readonly copy needs no temporary root"
        );
        assert!(
            mount_dir.starts_with(sandbox_stage_root(&sandbox)),
            "readonly cross-device copies belong under the sandbox dir: {}",
            mount_dir.display()
        );
        std::fs::write(&source, b"after").unwrap();
        assert_eq!(std::fs::read(&staged_file).unwrap(), b"before");
        assert_eq!(
            std::fs::metadata(&staged_file).unwrap().nlink(),
            1,
            "the readonly copy must not share the source inode"
        );
        assert_no_staging_residue(source_dir.path());
    }

    /// A readonly mount and a writable mount of a second-device directory:
    /// exactly one source-parent stage, each with the right identity and
    /// placement.
    #[tokio::test]
    #[cfg(unix)]
    async fn stage_file_mounts_real_cross_device_mixes_readonly_and_writable() {
        let (root, sandbox) = staging_sandbox_dir();
        let Some(source_dir) = cross_device_source_dir(&sandbox) else {
            drop(root);
            return;
        };
        let writable = source_dir.path().join("writable.txt");
        let readonly = source_dir.path().join("readonly.txt");
        std::fs::write(&writable, b"w").unwrap();
        std::fs::write(&readonly, b"r").unwrap();
        let config = file_mounts_config(&[
            (&writable, "/guest/writable.txt", false),
            (&readonly, "/guest/readonly.txt", true),
        ])
        .await;

        let (staged, staging) = super::stage_file_mounts(&config, &sandbox).await.unwrap();
        assert_eq!(
            staging.len(),
            1,
            "only the writable cross-device mount needs a source-parent root"
        );

        let (writable_dir, writable_name, _) = staged.get("/guest/writable.txt").unwrap();
        let writable_staged = writable_dir.join(writable_name);
        std::fs::write(&writable_staged, b"guest").unwrap();
        assert_eq!(std::fs::read(&writable).unwrap(), b"guest");
        assert!(writable_dir.starts_with(std::fs::canonicalize(source_dir.path()).unwrap()));

        let (readonly_dir, readonly_name, _) = staged.get("/guest/readonly.txt").unwrap();
        let readonly_staged = readonly_dir.join(readonly_name);
        assert!(
            readonly_dir.starts_with(sandbox_stage_root(&sandbox)),
            "a readonly cross-device copy stays under the sandbox dir"
        );
        std::fs::write(&readonly, b"changed").unwrap();
        assert_eq!(std::fs::read(&readonly_staged).unwrap(), b"r");
        assert_ne!(
            std::fs::metadata(&readonly).unwrap().ino(),
            std::fs::metadata(&readonly_staged).unwrap().ino()
        );

        drop(staging);
        assert_no_staging_residue(source_dir.path());
    }

    /// The source-parent stage is created inside the user's own directory, so it
    /// must be owner-only (mode `0700`) and hold nothing but the mount's own
    /// directory. The sandbox-dir stage is likewise private.
    #[tokio::test]
    #[cfg(unix)]
    async fn stage_file_mounts_real_cross_device_stage_root_is_owner_only() {
        let (root, sandbox) = staging_sandbox_dir();
        let Some(source_dir) = cross_device_source_dir(&sandbox) else {
            drop(root);
            return;
        };
        // A same-device mount proves the sandbox-dir stage mode.
        let same = same_device_source_dir(root.path()).join("same.txt");
        std::fs::write(&same, b"same").unwrap();
        let same_config = file_mount_config(&same, "/guest/same.txt", false).await;
        let (_, _) = super::stage_file_mounts(&same_config, &sandbox)
            .await
            .unwrap();
        assert_eq!(file_mode(&sandbox_stage_root(&sandbox)), 0o700);

        let source = source_dir.path().join("writable.txt");
        std::fs::write(&source, b"before").unwrap();
        let config = file_mount_config(&source, "/guest/writable.txt", false).await;

        let (staged, _staging) = super::stage_file_mounts(&config, &sandbox).await.unwrap();
        let (mount_dir, filename, _) = staged.get("/guest/writable.txt").unwrap();
        let stage_root = mount_dir.parent().unwrap();

        assert_eq!(
            file_mode(stage_root),
            0o700,
            "the per-source stage must not be world-traversable"
        );
        assert_eq!(
            stage_root.parent().unwrap(),
            std::fs::canonicalize(source_dir.path()).unwrap(),
            "the stage must live beside the source"
        );
        assert!(
            stage_root
                .file_name()
                .unwrap()
                .to_string_lossy()
                .starts_with(".microsandbox-file-mount-"),
            "the stage name is user-visible: {}",
            stage_root.display()
        );
        let entries = directory_entries(stage_root);
        assert_eq!(
            entries,
            vec![
                mount_dir
                    .file_name()
                    .unwrap()
                    .to_string_lossy()
                    .into_owned()
            ],
            "the stage holds only its own mount directory"
        );
        assert_eq!(
            file_mode(&mount_dir.join(filename)),
            file_mode(&source),
            "the staged link must keep the source's mode"
        );
    }

    /// The source-parent stage can only be dropped while the VM runs, so an
    /// attached handle must drop it and a detached (`disarm`ed) handle must keep
    /// it for the VM that is still reading through it. The sandbox-dir stage is
    /// not owned by the handle and is unaffected either way.
    #[tokio::test]
    #[cfg(unix)]
    async fn stage_file_mounts_real_cross_device_stages_follow_the_handle_lifetime() {
        let (root, sandbox) = staging_sandbox_dir();
        let Some(source_dir) = cross_device_source_dir(&sandbox) else {
            drop(root);
            return;
        };
        let source = source_dir.path().join("writable.txt");
        std::fs::write(&source, b"before").unwrap();
        let config = file_mount_config(&source, "/guest/writable.txt", false).await;

        let (_, staging) = super::stage_file_mounts(&config, &sandbox).await.unwrap();
        drop(probe_handle(staging, "cross-device-attached"));
        assert_eq!(
            directory_entries(source_dir.path()),
            vec!["writable.txt".to_string()],
            "an attached VM must not leave a stage inside the source directory"
        );

        let (_, staging) = super::stage_file_mounts(&config, &sandbox).await.unwrap();
        let mut detached = probe_handle(staging, "cross-device-detached");
        detached.disarm();
        drop(detached);
        // Note: `disarm` keeps the stage for the detached VM, and nothing removes it
        // once that VM exits - a residue the SDK does not clean up today. This
        // asserts the current contract so a change to it is deliberate.
        assert!(
            directory_entries(source_dir.path())
                .iter()
                .any(|entry| entry.starts_with(".microsandbox-file-mount-")),
            "a detached VM must keep reading its stage"
        );
    }

    /// Staging failures must be actionable (the caller cannot tell which mount
    /// broke from a bare `io::Error`) and must not leave earlier source-parent
    /// stages behind.
    #[tokio::test]
    #[cfg(unix)]
    async fn stage_file_mounts_real_unwritable_source_parent_names_the_mount() {
        if running_as_root() {
            eprintln!("SKIP: as root, mode 0500 does not deny directory writes");
            return;
        }
        let (root, sandbox) = staging_sandbox_dir();
        let Some(source_dir) = cross_device_source_dir(&sandbox) else {
            drop(root);
            return;
        };
        let source = source_dir.path().join("writable.txt");
        std::fs::write(&source, b"before").unwrap();
        let config = file_mount_config(&source, "/guest/writable.txt", false).await;

        set_mode(source_dir.path(), 0o500);
        let result = super::stage_file_mounts(&config, &sandbox).await;
        // Restore first: a panic here would otherwise poison the TempDir cleanup.
        set_mode(source_dir.path(), 0o700);

        let rendered = result
            .expect_err("an unwritable source parent cannot stage a writable mount")
            .to_string();
        assert!(
            rendered.contains(&source.display().to_string()),
            "the error must name the mount that could not be staged: {rendered}"
        );
        assert!(
            rendered.contains("writable"),
            "the error must explain what the caller can change: {rendered}"
        );
        assert_no_staging_residue(source_dir.path());
    }

    /// A failure on a later mount must not leave the earlier mount's source-parent
    /// stage inside the user's directory. The sandbox-dir stage may retain private
    /// remnants until retry or `rm`.
    #[tokio::test]
    #[cfg(unix)]
    async fn stage_file_mounts_failure_on_a_later_mount_drops_earlier_stages() {
        if running_as_root() {
            eprintln!("SKIP: as root, mode 0500 does not deny directory writes");
            return;
        }
        let (root, sandbox) = staging_sandbox_dir();
        let Some(source_dir) = cross_device_source_dir(&sandbox) else {
            drop(root);
            return;
        };
        let staged_parent = source_dir.path().join("staged");
        let broken_parent = source_dir.path().join("broken");
        std::fs::create_dir(&staged_parent).unwrap();
        std::fs::create_dir(&broken_parent).unwrap();
        let first = staged_parent.join("first.txt");
        let second = broken_parent.join("second.txt");
        std::fs::write(&first, b"first").unwrap();
        std::fs::write(&second, b"second").unwrap();
        let config = file_mounts_config(&[
            (&first, "/guest/first.txt", false),
            (&second, "/guest/second.txt", false),
        ])
        .await;

        set_mode(&broken_parent, 0o500);
        let result = super::stage_file_mounts(&config, &sandbox).await;
        set_mode(&broken_parent, 0o700);

        assert!(
            result.is_err(),
            "the second mount cannot be staged, so the whole spawn must fail"
        );
        assert_no_staging_residue(&staged_parent);
    }

    /// Two mounts of one host file must not share a virtiofs tag or a stage
    /// directory, and both must still reach the same inode.
    #[tokio::test]
    #[cfg(unix)]
    async fn stage_file_mounts_stages_every_mount_of_the_same_source() {
        let (root, sandbox) = staging_sandbox_dir();
        let source = same_device_source_dir(root.path()).join("shared.txt");
        std::fs::write(&source, b"shared").unwrap();
        let config = file_mounts_config(&[
            (&source, "/guest/a.txt", false),
            (&source, "/guest/b.txt", false),
        ])
        .await;

        let (staged, staging) = super::stage_file_mounts(&config, &sandbox).await.unwrap();
        assert!(staging.is_empty());

        let (first_dir, first_name, _) = staged.get("/guest/a.txt").unwrap();
        let (second_dir, second_name, _) = staged.get("/guest/b.txt").unwrap();
        assert_ne!(first_dir, second_dir);
        for (dir, name) in [(first_dir, first_name), (second_dir, second_name)] {
            assert_eq!(
                std::fs::metadata(&source).unwrap().ino(),
                std::fs::metadata(dir.join(name)).unwrap().ino()
            );
        }
    }

    /// A config without file mounts must not create any staging root at all, and
    /// must leave an existing sandbox-dir stage cleared.
    #[tokio::test]
    async fn stage_file_mounts_creates_nothing_without_file_mounts() {
        let (root, sandbox) = {
            let root = tempdir().unwrap();
            let sandbox = root.path().join("sandbox");
            std::fs::create_dir_all(&sandbox).unwrap();
            (root, sandbox)
        };
        #[cfg(unix)]
        {
            let stage_root = sandbox_stage_root(&sandbox);
            std::fs::create_dir_all(&stage_root).unwrap();
            std::fs::write(stage_root.join("stale"), b"old").unwrap();
        }
        let directory = root.path().join("adir");
        std::fs::create_dir_all(&directory).unwrap();
        let config = file_mounts_config(&[(&directory, "/guest/directory", false)]).await;

        let (staged, staging) = super::stage_file_mounts(&config, &sandbox).await.unwrap();
        assert!(staged.is_empty());
        assert!(
            staging.is_empty(),
            "a directory mount is not a file mount and needs no staging root"
        );
        #[cfg(unix)]
        assert!(
            !sandbox_stage_root(&sandbox).exists(),
            "a config without file mounts must clear and not recreate the sandbox-dir stage"
        );
    }

    /// The child-process probe used by the no-system-temp tests below. It reads
    /// explicit fixture paths from env vars and never calls the process-wide
    /// `tempdir()`, so the parent can point `TMPDIR`/`TMP`/`TEMP` at a location
    /// that must stay unused (missing or empty).
    #[tokio::test]
    #[cfg(unix)]
    async fn stage_file_mounts_child_probe_stages_without_system_temp() {
        let (Ok(sandbox), Ok(source_same), Ok(source_readonly), Ok(source_writable)) = (
            std::env::var("MSB_TEST_STAGING_SANDBOX"),
            std::env::var("MSB_TEST_STAGING_SOURCE_SAME"),
            std::env::var("MSB_TEST_STAGING_SOURCE_READONLY"),
            std::env::var("MSB_TEST_STAGING_SOURCE_WRITABLE"),
        ) else {
            return; // Not invoked as the probe child.
        };
        let sandbox = PathBuf::from(sandbox);
        let sandbox = std::fs::canonicalize(&sandbox).unwrap();
        let stage_root = sandbox_stage_root(&sandbox);

        // Same device (real identity): the mount hard-links into the sandbox-dir
        // stage and owns no temporary root.
        let same_config =
            file_mount_config(Path::new(&source_same), "/guest/same.txt", false).await;
        let (staged, staging) = super::stage_file_mounts(&same_config, &sandbox)
            .await
            .expect("same-device staging must not depend on the system temp dir");
        let (dir, name, _) = staged.get("/guest/same.txt").unwrap();
        assert!(
            dir.starts_with(&stage_root),
            "same-device mount must stage in the sandbox dir: {}",
            dir.display()
        );
        assert_eq!(std::fs::read(dir.join(name)).unwrap(), b"content");
        assert!(staging.is_empty());

        // Cross-device (forced): the readonly mount copies into the sandbox-dir
        // stage; the writable mount hard-links beside its source.
        let mismatch_config = file_mounts_config(&[
            (Path::new(&source_readonly), "/guest/readonly.txt", true),
            (Path::new(&source_writable), "/guest/writable.txt", false),
        ])
        .await;
        let (staged, staging) = super::stage_file_mounts_with_mode(
            &mismatch_config,
            &sandbox,
            super::FileMountStagingMode::ForceDeviceMismatch,
        )
        .await
        .expect("cross-device staging must not depend on the system temp dir");
        let (dir, name, _) = staged.get("/guest/readonly.txt").unwrap();
        assert!(
            dir.starts_with(&stage_root),
            "readonly mismatch must stage in the sandbox dir: {}",
            dir.display()
        );
        assert_eq!(std::fs::read(dir.join(name)).unwrap(), b"content");
        let (dir, name, _) = staged.get("/guest/writable.txt").unwrap();
        assert!(
            !dir.starts_with(&stage_root),
            "a writable mismatch must not stage in the sandbox dir"
        );
        assert_eq!(std::fs::read(dir.join(name)).unwrap(), b"content");
        assert_eq!(staging.len(), 1, "only the writable mismatch owns a root");
        let _ = std::fs::remove_dir_all(&sandbox);
    }

    /// Staging must not depend on the system temp dir. A child process runs the
    /// probe above with `TMPDIR`/`TMP`/`TEMP` pointed at a missing path; the
    /// staging succeeds and the missing path stays missing.
    #[tokio::test]
    #[cfg(unix)]
    async fn stage_file_mounts_ignores_missing_system_temp_dir() {
        let (root, sandbox) = staging_sandbox_dir();
        let sources = same_device_source_dir(root.path());
        let source_same = sources.join("same.txt");
        let source_readonly = sources.join("readonly.txt");
        let source_writable = sources.join("writable.txt");
        for source in [&source_same, &source_readonly, &source_writable] {
            std::fs::write(source, b"content").unwrap();
        }
        let missing = root.path().join("no-such-temp-dir");

        let child = std::process::Command::new(std::env::current_exe().unwrap())
            .args(["--exact", CHILD_PROBE_TEST, "--nocapture"])
            .env("MSB_TEST_STAGING_SANDBOX", &sandbox)
            .env("MSB_TEST_STAGING_SOURCE_SAME", &source_same)
            .env("MSB_TEST_STAGING_SOURCE_READONLY", &source_readonly)
            .env("MSB_TEST_STAGING_SOURCE_WRITABLE", &source_writable)
            .env("TMPDIR", &missing)
            .env("TMP", &missing)
            .env("TEMP", &missing)
            .output()
            .unwrap();
        assert!(
            child.status.success(),
            "probe child failed: stdout={} stderr={}",
            String::from_utf8_lossy(&child.stdout),
            String::from_utf8_lossy(&child.stderr)
        );
        assert!(
            !missing.exists(),
            "staging must not create or probe the system temp dir: {}",
            missing.display()
        );
    }

    /// As above, but the system temp dir exists and is empty: staging must leave
    /// it empty instead of writing anything there.
    #[tokio::test]
    #[cfg(unix)]
    async fn stage_file_mounts_leaves_empty_system_temp_dir_empty() {
        let (root, sandbox) = staging_sandbox_dir();
        let sources = same_device_source_dir(root.path());
        let source_same = sources.join("same.txt");
        let source_readonly = sources.join("readonly.txt");
        let source_writable = sources.join("writable.txt");
        for source in [&source_same, &source_readonly, &source_writable] {
            std::fs::write(source, b"content").unwrap();
        }
        let sentinel_temp = root.path().join("empty-temp-dir");
        std::fs::create_dir_all(&sentinel_temp).unwrap();

        let child = std::process::Command::new(std::env::current_exe().unwrap())
            .args(["--exact", CHILD_PROBE_TEST, "--nocapture"])
            .env("MSB_TEST_STAGING_SANDBOX", &sandbox)
            .env("MSB_TEST_STAGING_SOURCE_SAME", &source_same)
            .env("MSB_TEST_STAGING_SOURCE_READONLY", &source_readonly)
            .env("MSB_TEST_STAGING_SOURCE_WRITABLE", &source_writable)
            .env("TMPDIR", &sentinel_temp)
            .env("TMP", &sentinel_temp)
            .env("TEMP", &sentinel_temp)
            .output()
            .unwrap();
        assert!(
            child.status.success(),
            "probe child failed: stdout={} stderr={}",
            String::from_utf8_lossy(&child.stdout),
            String::from_utf8_lossy(&child.stderr)
        );
        assert_eq!(
            directory_entries(&sentinel_temp),
            Vec::<String>::new(),
            "staging must leave the system temp dir empty"
        );
    }

    #[test]
    fn block_writeback_policy_resolves_by_platform() {
        #[cfg(target_os = "linux")]
        {
            let automatic = resolve_linux_block_writeback_policy(
                BlockWritebackConfig::Auto { pool_mib: None },
                64 * 1024 * 1024 * 1024,
                Some(6 * 1024 * 1024 * 1024),
            )
            .unwrap();
            assert_eq!(automatic.0, Some(AUTO_BLOCK_WRITEBACK_LIMIT_BYTES));
            assert_eq!(automatic.1, Some(6 * 1024 * 1024 * 1024));

            let constrained_pool = 512 * 1024 * 1024;
            assert_eq!(
                resolve_linux_block_writeback_policy(
                    BlockWritebackConfig::Auto { pool_mib: None },
                    64 * 1024 * 1024 * 1024,
                    Some(constrained_pool),
                )
                .unwrap(),
                (
                    Some(AUTO_BLOCK_WRITEBACK_LIMIT_BYTES),
                    Some(constrained_pool)
                )
            );

            assert_eq!(
                resolve_linux_block_writeback_policy(
                    BlockWritebackConfig::Auto { pool_mib: None },
                    64 * 1024 * 1024 * 1024,
                    Some(MIN_BLOCK_WRITEBACK_LIMIT_BYTES - 1),
                )
                .unwrap(),
                (
                    Some(AUTO_BLOCK_WRITEBACK_LIMIT_BYTES),
                    Some(MIN_BLOCK_WRITEBACK_LIMIT_BYTES - 1)
                )
            );
            assert_eq!(
                auto_block_writeback_pool_bytes(
                    64 * 1024 * 1024 * 1024,
                    60 * 1024 * 1024 * 1024,
                    0,
                    10,
                )
                .unwrap(),
                60 * 1024 * 1024 * 1024 / 10
            );
            assert_eq!(
                auto_block_writeback_pool_bytes(
                    64 * 1024 * 1024 * 1024,
                    60 * 1024 * 1024 * 1024,
                    2 * 1024 * 1024 * 1024,
                    50,
                )
                .unwrap(),
                2 * 1024 * 1024 * 1024
            );
            assert_eq!(
                auto_block_writeback_pool_bytes(
                    64 * 1024 * 1024 * 1024,
                    60 * 1024 * 1024 * 1024,
                    0,
                    20,
                )
                .unwrap(),
                64 * 1024 * 1024 * 1024 / 10
            );
            assert_eq!(
                auto_block_writeback_pool_bytes(
                    64 * 1024 * 1024 * 1024,
                    8 * 1024 * 1024 * 1024,
                    0,
                    10,
                )
                .unwrap(),
                8 * 1024 * 1024 * 1024 / 10
            );
            assert_eq!(
                auto_block_writeback_pool_bytes(
                    64 * 1024 * 1024 * 1024,
                    60 * 1024 * 1024 * 1024,
                    0,
                    0,
                )
                .unwrap(),
                1
            );
            assert!(
                auto_block_writeback_pool_bytes(
                    64 * 1024 * 1024 * 1024,
                    60 * 1024 * 1024 * 1024,
                    0,
                    101,
                )
                .unwrap_err()
                .to_string()
                .contains("must not exceed 100")
            );
        }
        // The portable default enables live pressure sharing on Linux and remains a no-op on
        // platforms where this host page-cache controller does not apply.
        let default_policy = block_writeback_policy(&RuntimeConfig::default()).unwrap();
        #[cfg(target_os = "linux")]
        {
            assert_eq!(default_policy.0, Some(AUTO_BLOCK_WRITEBACK_LIMIT_BYTES));
            assert!(default_policy.1.is_some_and(|pool_bytes| pool_bytes > 0));
        }
        #[cfg(not(target_os = "linux"))]
        assert_eq!(default_policy, (None, None));

        assert_eq!(
            block_writeback_policy(&RuntimeConfig {
                block_writeback: BlockWritebackConfig::Off {},
                ..Default::default()
            })
            .unwrap(),
            (None, None)
        );

        #[cfg(target_os = "linux")]
        {
            let fixed = resolve_linux_block_writeback_policy(
                BlockWritebackConfig::Fixed {
                    per_disk_mib: NonZero::new(1024).unwrap(),
                    pool_mib: None,
                },
                64 * 1024 * 1024 * 1024,
                Some(4 * 1024 * 1024 * 1024),
            )
            .unwrap();
            assert_eq!(fixed.0, Some(1024 * 1024 * 1024));
            assert_eq!(fixed.1, Some(4 * 1024 * 1024 * 1024));
            assert!(
                resolve_linux_block_writeback_policy(
                    BlockWritebackConfig::Fixed {
                        per_disk_mib: NonZero::new(127).unwrap(),
                        pool_mib: None,
                    },
                    64 * 1024 * 1024 * 1024,
                    Some(4 * 1024 * 1024 * 1024),
                )
                .unwrap_err()
                .to_string()
                .contains("at least 128 MiB")
            );

            assert_eq!(
                resolve_linux_block_writeback_policy(
                    BlockWritebackConfig::Auto {
                        pool_mib: NonZero::new(512),
                    },
                    64 * 1024 * 1024 * 1024,
                    None,
                )
                .unwrap(),
                (
                    Some(AUTO_BLOCK_WRITEBACK_LIMIT_BYTES),
                    Some(512 * 1024 * 1024)
                )
            );
            assert_eq!(
                resolve_linux_block_writeback_policy(
                    BlockWritebackConfig::Fixed {
                        per_disk_mib: NonZero::new(1024).unwrap(),
                        pool_mib: NonZero::new(512),
                    },
                    64 * 1024 * 1024 * 1024,
                    None,
                )
                .unwrap(),
                (Some(1024 * 1024 * 1024), Some(512 * 1024 * 1024))
            );
        }
    }

    //----------------------------------------------------------------------------------------------
    // issue #24: no-follow file binds
    //----------------------------------------------------------------------------------------------

    /// Like [`file_mount_config`], but opts in to following root symlinks.
    #[cfg(unix)]
    async fn file_mount_config_following(
        host: &Path,
        guest: &str,
        readonly: bool,
    ) -> SandboxConfig {
        let mut builder = SandboxBuilder::new("test").image("/tmp/rootfs");
        builder = builder.volume(guest, |mount| {
            let mount = mount.bind(host).follow_root_symlinks(true);
            if readonly { mount.readonly() } else { mount }
        });
        builder.build().await.unwrap()
    }

    #[cfg(unix)]
    fn symlink_fixture(root: &Path, name: &str) -> (PathBuf, PathBuf) {
        let sources = same_device_source_dir(root);
        let real = sources.join("real.txt");
        std::fs::write(&real, b"before").unwrap();
        let link = sources.join(name);
        std::os::unix::fs::symlink("real.txt", &link).unwrap();
        (real, link)
    }

    #[tokio::test]
    #[cfg(unix)]
    async fn stage_file_mounts_rejects_a_symlinked_leaf_by_default() {
        let (root, sandbox) = staging_sandbox_dir();
        let (_real, link) = symlink_fixture(root.path(), "link.txt");
        let config = file_mount_config(&link, "/guest/link.txt", false).await;

        let rendered = super::stage_file_mounts(&config, &sandbox)
            .await
            .expect_err("a symlinked file source is refused by default")
            .to_string();
        assert!(
            rendered.contains(&link.display().to_string()),
            "the error must name the source: {rendered}"
        );
        assert!(
            rendered.contains(".follow_root_symlinks(true)"),
            "{rendered}"
        );
        assert!(rendered.contains("follow-root-symlinks"), "{rendered}");
        assert!(
            !sandbox_stage_root(&sandbox).exists(),
            "a rejected mount must not create the sandbox-dir stage"
        );
    }

    #[tokio::test]
    #[cfg(unix)]
    async fn stage_file_mounts_rejects_a_symlinked_ancestor_by_default() {
        let (root, sandbox) = staging_sandbox_dir();
        let sources = same_device_source_dir(root.path());
        let real_dir = sources.join("realdir");
        std::fs::create_dir(&real_dir).unwrap();
        std::fs::write(real_dir.join("f.txt"), b"x").unwrap();
        let link_dir = sources.join("linkdir");
        std::os::unix::fs::symlink("realdir", &link_dir).unwrap();
        let host = link_dir.join("f.txt");
        let config = file_mount_config(&host, "/guest/f.txt", false).await;

        let rendered = super::stage_file_mounts(&config, &sandbox)
            .await
            .expect_err("a symlinked ancestor is refused by default")
            .to_string();
        assert!(
            rendered.contains(&link_dir.display().to_string()),
            "the error must name the ancestor: {rendered}"
        );
        assert!(rendered.contains("follow-root-symlinks"), "{rendered}");
    }

    #[tokio::test]
    #[cfg(unix)]
    async fn stage_file_mounts_follows_root_symlinks_when_opted_in() {
        let (root, sandbox) = staging_sandbox_dir();
        let (real, link) = symlink_fixture(root.path(), "link.txt");
        let config = file_mount_config_following(&link, "/guest/link.txt", false).await;

        let (staged, _) = super::stage_file_mounts(&config, &sandbox).await.unwrap();
        let (mount_dir, filename, _) = staged.get("/guest/link.txt").unwrap();
        assert_eq!(
            filename, "link.txt",
            "the staged basename remains the requested name"
        );
        assert_eq!(
            std::fs::metadata(&real).unwrap().ino(),
            std::fs::metadata(mount_dir.join(filename)).unwrap().ino()
        );
    }

    #[tokio::test]
    #[cfg(unix)]
    async fn stage_file_mounts_opt_in_writable_symlink_writes_through() {
        let (root, sandbox) = staging_sandbox_dir();
        let (real, link) = symlink_fixture(root.path(), "link.txt");
        let config = file_mount_config_following(&link, "/guest/link.txt", false).await;
        let (staged, _) = super::stage_file_mounts(&config, &sandbox).await.unwrap();
        let (mount_dir, filename, _) = staged.get("/guest/link.txt").unwrap();
        std::fs::write(mount_dir.join(filename), b"written through").unwrap();
        assert_eq!(std::fs::read(&real).unwrap(), b"written through");
    }

    #[tokio::test]
    #[cfg(unix)]
    async fn stage_file_mounts_opt_in_absolute_symlink_stages_the_host_target() {
        let (root, sandbox) = staging_sandbox_dir();
        let sources = same_device_source_dir(root.path());
        let real = sources.join("real.txt");
        std::fs::write(&real, b"absolute").unwrap();
        let link = sources.join("abs.txt");
        // An absolute symlink target: on Linux `link(2)` would stage the link
        // itself, and the guest would resolve it against the guest root.
        std::os::unix::fs::symlink(&real, &link).unwrap();
        let config = file_mount_config_following(&link, "/guest/abs.txt", false).await;
        let (staged, _) = super::stage_file_mounts(&config, &sandbox).await.unwrap();
        let (mount_dir, filename, _) = staged.get("/guest/abs.txt").unwrap();
        let staged_file = mount_dir.join(filename);
        assert_eq!(
            std::fs::metadata(&real).unwrap().ino(),
            std::fs::metadata(&staged_file).unwrap().ino()
        );
        assert!(
            !std::fs::symlink_metadata(&staged_file)
                .unwrap()
                .file_type()
                .is_symlink(),
            "the staged entry must be the target file, never a symlink"
        );
    }

    #[tokio::test]
    #[cfg(unix)]
    async fn stage_file_mounts_detects_a_source_swapped_during_staging() {
        let (root, sandbox) = staging_sandbox_dir();
        let source = same_device_source_dir(root.path()).join("source.txt");
        std::fs::write(&source, b"source").unwrap();
        let config = file_mount_config(&source, "/guest/source.txt", false).await;

        let rendered = super::stage_file_mounts_with_mode(
            &config,
            &sandbox,
            super::FileMountStagingMode::ForceLeafSwapBeforeLink,
        )
        .await
        .expect_err("a leaf swap must be detected")
        .to_string();
        assert!(
            rendered.contains(&source.display().to_string()),
            "the error must name the mount: {rendered}"
        );
        assert!(
            rendered.contains("changed while it was being staged"),
            "{rendered}"
        );
        assert_eq!(
            std::fs::metadata(&source).unwrap().nlink(),
            1,
            "the attempted entry is removed and the decoy is not linked twice"
        );
    }

    #[tokio::test]
    #[cfg(unix)]
    async fn stage_file_mounts_readonly_falls_back_to_a_copy_on_link_failure() {
        let (root, sandbox) = staging_sandbox_dir();
        let source = same_device_source_dir(root.path()).join("readonly.txt");
        std::fs::write(&source, b"payload").unwrap();
        set_mode(&source, 0o640);
        let config = file_mount_config(&source, "/guest/readonly.txt", true).await;

        let (staged, _) = super::stage_file_mounts_with_mode(
            &config,
            &sandbox,
            super::FileMountStagingMode::ForceLinkErrno(libc::EPERM),
        )
        .await
        .unwrap();
        let (mount_dir, filename, _) = staged.get("/guest/readonly.txt").unwrap();
        let staged_file = mount_dir.join(filename);
        assert_eq!(std::fs::read(&staged_file).unwrap(), b"payload");
        assert_eq!(std::fs::metadata(&staged_file).unwrap().nlink(), 1);
        assert_eq!(
            file_mode(&staged_file) & 0o7777,
            0o640,
            "the copy must preserve the source mode, not inherit the umask"
        );
    }

    #[tokio::test]
    #[cfg(unix)]
    async fn stage_file_mounts_readonly_fallback_copy_is_a_snapshot_not_a_live_link() {
        let (root, sandbox) = staging_sandbox_dir();
        let source = same_device_source_dir(root.path()).join("snapshot.txt");
        std::fs::write(&source, b"before").unwrap();
        let config = file_mount_config(&source, "/guest/snapshot.txt", true).await;
        let (staged, _) = super::stage_file_mounts_with_mode(
            &config,
            &sandbox,
            super::FileMountStagingMode::ForceLinkErrno(libc::EPERM),
        )
        .await
        .unwrap();
        let (mount_dir, filename, _) = staged.get("/guest/snapshot.txt").unwrap();
        // A linked (non-fallback) readonly mount is live; the fallback copy is
        // a snapshot, so later source edits are not visible.
        std::fs::write(&source, b"after").unwrap();
        assert_eq!(std::fs::read(mount_dir.join(filename)).unwrap(), b"before");
    }

    #[tokio::test]
    #[cfg(unix)]
    async fn stage_file_mounts_writable_link_failure_names_protected_hardlinks() {
        let (root, sandbox) = staging_sandbox_dir();
        let source = same_device_source_dir(root.path()).join("writable.txt");
        std::fs::write(&source, b"x").unwrap();
        let config = file_mount_config(&source, "/guest/writable.txt", false).await;

        let rendered = super::stage_file_mounts_with_mode(
            &config,
            &sandbox,
            super::FileMountStagingMode::ForceLinkErrno(libc::EPERM),
        )
        .await
        .expect_err("a writable link failure must not fall back to a copy")
        .to_string();
        assert!(
            rendered.contains(&source.display().to_string()),
            "{rendered}"
        );
        assert!(rendered.contains("/guest/writable.txt"), "{rendered}");
        assert!(rendered.contains("protected_hardlinks"), "{rendered}");
    }

    #[tokio::test]
    #[cfg(unix)]
    async fn stage_file_mounts_writable_link_failure_other_errno_omits_protected_hardlinks() {
        let (root, sandbox) = staging_sandbox_dir();
        let source = same_device_source_dir(root.path()).join("writable.txt");
        std::fs::write(&source, b"x").unwrap();
        let config = file_mount_config(&source, "/guest/writable.txt", false).await;

        let rendered = super::stage_file_mounts_with_mode(
            &config,
            &sandbox,
            super::FileMountStagingMode::ForceLinkErrno(libc::EACCES),
        )
        .await
        .expect_err("a writable link failure is an error")
        .to_string();
        assert!(
            rendered.contains(&source.display().to_string()),
            "{rendered}"
        );
        assert!(
            !rendered.contains("protected_hardlinks"),
            "a non-EPERM errno must not mention protected_hardlinks: {rendered}"
        );
    }

    #[tokio::test]
    #[cfg(unix)]
    async fn stage_file_mounts_missing_source_is_left_to_the_directory_bind() {
        let (_root, sandbox) = staging_sandbox_dir();
        let missing = PathBuf::from("/definitely/not/here/settings.toml");
        let config = file_mount_config(&missing, "/guest/settings.toml", false).await;
        let (staged, staging) = super::stage_file_mounts(&config, &sandbox).await.unwrap();
        assert!(staged.is_empty());
        assert!(staging.is_empty());
    }

    #[tokio::test]
    #[cfg(unix)]
    async fn stage_file_mounts_symlinked_directory_source_is_left_to_the_directory_bind() {
        let (root, sandbox) = staging_sandbox_dir();
        let sources = same_device_source_dir(root.path());
        let real_dir = sources.join("realdir");
        std::fs::create_dir(&real_dir).unwrap();
        let link_dir = sources.join("linkdir");
        std::os::unix::fs::symlink("realdir", &link_dir).unwrap();
        let config = file_mount_config(&link_dir, "/guest/dir", false).await;
        let (staged, staging) = super::stage_file_mounts(&config, &sandbox).await.unwrap();
        assert!(
            staged.is_empty(),
            "the SDK must not reject a symlinked directory"
        );
        assert!(staging.is_empty());
    }

    #[tokio::test]
    #[cfg(unix)]
    async fn stage_file_mounts_fifo_source_is_left_to_the_directory_bind() {
        let (root, sandbox) = staging_sandbox_dir();
        let sources = same_device_source_dir(root.path());
        let fifo = sources.join("pipe");
        let status = std::process::Command::new("mkfifo")
            .arg(&fifo)
            .status()
            .unwrap();
        assert!(status.success());
        let config = file_mount_config(&fifo, "/guest/pipe", false).await;
        let (staged, staging) = super::stage_file_mounts(&config, &sandbox)
            .await
            .expect("a fifo source must not error or hang");
        assert!(staged.is_empty());
        assert!(staging.is_empty());
    }

    #[tokio::test]
    #[cfg(unix)]
    async fn stage_file_mounts_symlinked_source_rejection_survives_no_other_mounts() {
        let (root, sandbox) = staging_sandbox_dir();
        let (_real, link) = symlink_fixture(root.path(), "only.txt");
        let config = file_mount_config(&link, "/guest/only.txt", false).await;
        assert!(super::stage_file_mounts(&config, &sandbox).await.is_err());
    }

    #[tokio::test]
    #[cfg(unix)]
    async fn stage_file_mounts_preserves_parent_dir_components() {
        let (root, sandbox) = staging_sandbox_dir();
        let sources = same_device_source_dir(root.path());
        let file = sources.join("f.txt");
        std::fs::write(&file, b"x").unwrap();
        let host = sources.join("..").join("sources").join("f.txt");
        let config = file_mount_config(&host, "/guest/f.txt", false).await;
        let (staged, _) = super::stage_file_mounts(&config, &sandbox).await.unwrap();
        let (mount_dir, filename, _) = staged.get("/guest/f.txt").unwrap();
        assert_eq!(
            std::fs::metadata(&file).unwrap().ino(),
            std::fs::metadata(mount_dir.join(filename)).unwrap().ino()
        );
        // A `..` after a missing component must not cancel lexically.
        let missing = sources.join("nope").join("..").join("f.txt");
        let config = file_mount_config(&missing, "/guest/f2.txt", false).await;
        let (staged, _) = super::stage_file_mounts(&config, &sandbox).await.unwrap();
        assert!(
            staged.is_empty(),
            "a missing component before `..` must fail the gate"
        );
    }

    #[tokio::test]
    #[cfg(unix)]
    async fn stage_file_mounts_preserves_search_only_ancestors() {
        let (root, sandbox) = staging_sandbox_dir();
        let sources = same_device_source_dir(root.path());
        let search_only = sources.join("search-only");
        std::fs::create_dir(&search_only).unwrap();
        let file = search_only.join("f.txt");
        std::fs::write(&file, b"search").unwrap();
        set_mode(&search_only, 0o111);
        // Prove the ancestor is genuinely not readable.
        assert!(microsandbox_filesystem::nofollow::NoFollowDir::open(&search_only).is_err());
        let config = file_mount_config(&file, "/guest/f.txt", false).await;
        let result = super::stage_file_mounts(&config, &sandbox).await;
        let (staged, _) = match result {
            Ok(value) => value,
            Err(error) => {
                set_mode(&search_only, 0o700);
                panic!("a search-only ancestor must stage successfully: {error}");
            }
        };
        let (mount_dir, filename, _) = staged.get("/guest/f.txt").unwrap();
        assert_eq!(
            std::fs::metadata(&file).unwrap().ino(),
            std::fs::metadata(mount_dir.join(filename)).unwrap().ino()
        );
        set_mode(&search_only, 0o700);
    }

    #[tokio::test]
    #[cfg(unix)]
    async fn stage_file_mounts_genuine_no_search_stays_directory_routing() {
        let (root, sandbox) = staging_sandbox_dir();
        let sources = same_device_source_dir(root.path());
        let denied = sources.join("denied");
        std::fs::create_dir(&denied).unwrap();
        let file = denied.join("f.txt");
        std::fs::write(&file, b"x").unwrap();
        set_mode(&denied, 0o600);
        let config = file_mount_config(&file, "/guest/f.txt", false).await;
        let result = super::stage_file_mounts(&config, &sandbox).await;
        set_mode(&denied, 0o700);
        let (staged, _) = result.unwrap();
        assert!(
            staged.is_empty(),
            "an unsearchable source fails the gate and keeps directory-bind routing"
        );
    }

    #[tokio::test]
    #[cfg(unix)]
    async fn stage_file_mounts_opt_in_cross_device_writable_stages_beside_resolved_file() {
        let (root, sandbox) = staging_sandbox_dir();
        let (real, link) = symlink_fixture(root.path(), "link.txt");
        let config = file_mount_config_following(&link, "/guest/link.txt", false).await;
        let (staged, staging) = super::stage_file_mounts_with_mode(
            &config,
            &sandbox,
            super::FileMountStagingMode::ForceDeviceMismatch,
        )
        .await
        .unwrap();
        let (mount_dir, filename, _) = staged.get("/guest/link.txt").unwrap();
        assert_eq!(staging.len(), 1);
        assert!(
            mount_dir.starts_with(std::fs::canonicalize(real.parent().unwrap()).unwrap()),
            "the source-parent stage must be beside the resolved file: {}",
            mount_dir.display()
        );
        assert_eq!(
            std::fs::metadata(&real).unwrap().ino(),
            std::fs::metadata(mount_dir.join(filename)).unwrap().ino()
        );
    }

    #[tokio::test]
    #[cfg(unix)]
    async fn stage_file_mounts_owned_unreadable_sources_remain_linkable() {
        let (root, sandbox) = staging_sandbox_dir();
        let source = same_device_source_dir(root.path()).join("owned.txt");
        std::fs::write(&source, b"x").unwrap();
        set_mode(&source, 0o200);
        // A read-only open must fail for a 0200 source.
        assert!(std::fs::File::open(&source).is_err());

        let config = file_mount_config(&source, "/guest/owned.txt", false).await;
        let (staged, _) = super::stage_file_mounts(&config, &sandbox).await.unwrap();
        let (mount_dir, filename, _) = staged.get("/guest/owned.txt").unwrap();
        assert!(file_mode(&source) & 0o7777 == 0o200);
        assert_eq!(
            std::fs::metadata(&source).unwrap().ino(),
            std::fs::metadata(mount_dir.join(filename)).unwrap().ino(),
            "an owned write-only source must still hard-link"
        );
        set_mode(&source, 0o600);
    }

    /// `#21`/`#24` — an owned `0000` or `0200` source must stage on the same
    /// device for both a readonly and a writable mount, keeping inode identity
    /// (no readable open is required).
    #[tokio::test]
    #[cfg(unix)]
    async fn stage_file_mounts_owned_mode_matrix_keeps_inode_identity() {
        for mode in [0o000, 0o200] {
            for readonly in [true, false] {
                let (root, sandbox) = staging_sandbox_dir();
                let source = same_device_source_dir(root.path())
                    .join(format!("owned-{mode:04o}-{readonly}.txt"));
                std::fs::write(&source, b"payload").unwrap();
                set_mode(&source, mode);
                let config = file_mount_config(&source, "/guest/owned.txt", readonly).await;
                let (staged, _) = super::stage_file_mounts(&config, &sandbox)
                    .await
                    .unwrap_or_else(|error| panic!("mode {mode:04o} readonly={readonly}: {error}"));
                let (mount_dir, filename, _) = staged.get("/guest/owned.txt").unwrap();
                assert_eq!(
                    std::fs::metadata(&source).unwrap().ino(),
                    std::fs::metadata(mount_dir.join(filename)).unwrap().ino(),
                    "mode {mode:04o} readonly={readonly} must hard-link, not copy"
                );
                set_mode(&source, 0o600);
            }
        }
    }

    #[tokio::test]
    #[cfg(unix)]
    async fn stage_file_mounts_writable_exdev_retries_beside_the_source_once() {
        let (root, sandbox) = staging_sandbox_dir();
        let sources = same_device_source_dir(root.path());
        let source = sources.join("writable.txt");
        std::fs::write(&source, b"before").unwrap();
        let config = file_mount_config(&source, "/guest/writable.txt", false).await;

        let (staged, staging) = super::stage_file_mounts_with_mode(
            &config,
            &sandbox,
            super::FileMountStagingMode::ForceFirstLinkExdev,
        )
        .await
        .unwrap();
        let (mount_dir, filename, _) = staged.get("/guest/writable.txt").unwrap();
        assert_eq!(staging.len(), 1, "the retry uses one source-parent stage");
        assert!(
            mount_dir.starts_with(std::fs::canonicalize(&sources).unwrap()),
            "the retry stages beside the source: {}",
            mount_dir.display()
        );
        std::fs::write(mount_dir.join(filename), b"guest").unwrap();
        assert_eq!(std::fs::read(&source).unwrap(), b"guest");
        assert!(
            directory_entries(&sandbox_stage_root(&sandbox)).is_empty(),
            "the abandoned empty sandbox tag must be withdrawn"
        );
    }

    #[tokio::test]
    #[cfg(unix)]
    async fn stage_file_mounts_parent_writability_gate_skipped_permits_staging() {
        let (root, sandbox) = staging_sandbox_dir();
        let sources = same_device_source_dir(root.path());
        let source = sources.join("source.txt");
        std::fs::write(&source, b"x").unwrap();
        set_mode(&sources, 0o700);
        let config = file_mount_config(&source, "/guest/source.txt", false).await;
        let (staged, staging) = super::stage_file_mounts_with_mode(
            &config,
            &sandbox,
            super::FileMountStagingMode::ForceSourceParentStageMode(0o755),
        )
        .await
        .expect("the gate is skipped on a non-foreign-writable parent");
        assert_eq!(staging.len(), 1);
        let (mount_dir, filename, _) = staged.get("/guest/source.txt").unwrap();
        assert_eq!(
            std::fs::metadata(&source).unwrap().ino(),
            std::fs::metadata(mount_dir.join(filename)).unwrap().ino()
        );
    }

    #[tokio::test]
    #[cfg(unix)]
    async fn stage_file_mounts_parent_writability_gate_applied_fails_closed() {
        let (root, sandbox) = staging_sandbox_dir();
        let sources = same_device_source_dir(root.path());
        let source = sources.join("source.txt");
        std::fs::write(&source, b"x").unwrap();
        set_mode(&sources, 0o777);
        let config = file_mount_config(&source, "/guest/source.txt", false).await;
        let result = super::stage_file_mounts_with_mode(
            &config,
            &sandbox,
            super::FileMountStagingMode::ForceSourceParentStageMode(0o755),
        )
        .await;
        set_mode(&sources, 0o700);
        let rendered = result
            .expect_err("the applied gate must fail closed on a synthesized non-0700 mode")
            .to_string();
        assert!(
            rendered.contains(&source.display().to_string()),
            "the error must name the mount: {rendered}"
        );
    }

    #[tokio::test]
    #[cfg(unix)]
    async fn stage_file_mounts_parent_writability_gate_forced_foreign_writable() {
        // Force the gate applied even though the caller-owned parent is not
        // group/other-writable; the pinned directory is a genuine `0700`, so the
        // strict check passes and staging succeeds.
        let (root, sandbox) = staging_sandbox_dir();
        let sources = same_device_source_dir(root.path());
        let source = sources.join("source.txt");
        std::fs::write(&source, b"x").unwrap();
        set_mode(&sources, 0o700);
        let config = file_mount_config(&source, "/guest/source.txt", false).await;
        let (staged, staging) = super::stage_file_mounts_with_mode(
            &config,
            &sandbox,
            super::FileMountStagingMode::ForceSourceParentForeignWritable,
        )
        .await
        .expect("a genuine 0700 pinned directory passes the applied gate");
        assert_eq!(staging.len(), 1);
        let (mount_dir, filename, _) = staged.get("/guest/source.txt").unwrap();
        assert_eq!(
            std::fs::metadata(&source).unwrap().ino(),
            std::fs::metadata(mount_dir.join(filename)).unwrap().ino()
        );
    }

    #[tokio::test]
    #[cfg(unix)]
    async fn stage_file_mounts_false_gate_clears_stale_stage_without_policy() {
        let (root, sandbox) = staging_sandbox_dir();
        let stage_root = sandbox_stage_root(&sandbox);
        std::fs::create_dir_all(&stage_root).unwrap();
        std::fs::write(stage_root.join("stale"), b"old").unwrap();
        let directory = same_device_source_dir(root.path()).join("adir");
        std::fs::create_dir(&directory).unwrap();
        let config = file_mount_config(&directory, "/guest/dir", false).await;
        let (staged, staging) = super::stage_file_mounts(&config, &sandbox).await.unwrap();
        assert!(staged.is_empty());
        assert!(staging.is_empty());
        assert!(
            !stage_root.exists(),
            "the stale stage is cleared even when no file mount is admitted"
        );
    }

    // Stage-B mappings tested directly against the classifier, bypassing the
    // following-stat gate so the post-gate branches are reachable.

    #[cfg(unix)]
    fn selected(host: &Path, guest: &str, follow: bool) -> super::SelectedFileMount {
        super::SelectedFileMount {
            requested: host.to_path_buf(),
            guest: guest.to_string(),
            readonly: false,
            follow_root_symlinks: follow,
        }
    }

    #[cfg(unix)]
    #[test]
    fn classify_file_mounts_reports_opt_in_canonicalize_failure() {
        let dir = staging_fixture_root();
        let link = dir.path().join("dangling.txt");
        std::os::unix::fs::symlink("missing-target", &link).unwrap();
        let error = super::classify_file_mounts(vec![selected(&link, "/guest/x", true)])
            .expect_err("a dangling opt-in source cannot be canonicalized")
            .to_string();
        assert!(
            error.contains("follow-root-symlinks set but could not be resolved"),
            "{error}"
        );
        assert!(error.contains(&link.display().to_string()), "{error}");
    }

    #[cfg(unix)]
    #[test]
    fn classify_file_mounts_reports_nonregular_leaf() {
        let dir = staging_fixture_root();
        let sub = dir.path().join("subdir");
        std::fs::create_dir(&sub).unwrap();
        let error = super::classify_file_mounts(vec![selected(&sub, "/guest/x", false)])
            .expect_err("a non-regular leaf is a post-gate change")
            .to_string();
        assert!(error.contains("no longer a regular file"), "{error}");
    }

    #[cfg(unix)]
    #[test]
    fn classify_file_mounts_reports_post_gate_permission_denial() {
        let dir = staging_fixture_root();
        let denied = dir.path().join("denied");
        std::fs::create_dir(&denied).unwrap();
        let file = denied.join("f.txt");
        std::fs::write(&file, b"x").unwrap();
        set_mode(&denied, 0o600);
        let result = super::classify_file_mounts(vec![selected(&file, "/guest/x", false)]);
        set_mode(&denied, 0o700);
        let error = result
            .expect_err("a post-gate revocation fails closed")
            .to_string();
        assert!(error.contains("cannot be resolved"), "{error}");
        assert!(error.contains(&denied.display().to_string()), "{error}");
    }
    /// The literal non-owner `0711` search-only regression, using the privileged
    /// CI fixture. Skips with a printed reason when `MSB_TEST_SEARCH_ONLY_DIR`
    /// is unset (local runs); in CI the fixture is required.
    #[tokio::test]
    #[cfg(unix)]
    async fn stage_file_mounts_preserves_literal_0711_search_only_ancestor() {
        let Some(root) = std::env::var_os("MSB_TEST_SEARCH_ONLY_DIR").map(PathBuf::from) else {
            eprintln!(
                "skipping literal-0711 search-only test: MSB_TEST_SEARCH_ONLY_DIR is not set \
                 (CI sets it)"
            );
            return;
        };
        let meta = std::fs::metadata(&root).expect("MSB_TEST_SEARCH_ONLY_DIR must exist");
        use std::os::unix::fs::PermissionsExt as _;
        let euid = unsafe { libc::geteuid() };
        assert_ne!(
            meta.uid(),
            euid,
            "the fixture root must be owned by another uid"
        );
        assert_eq!(
            meta.permissions().mode() & 0o7777,
            0o711,
            "the fixture root must be 0711"
        );
        assert!(
            std::fs::File::open(&root).is_err(),
            "an 0711 root must not be readable"
        );
        let source = root.join("source.txt");
        assert!(source.is_file(), "the fixture source must exist");

        let (_root_guard, sandbox) = staging_sandbox_dir();
        if std::fs::metadata(&source).unwrap().dev() != std::fs::metadata(&sandbox).unwrap().dev() {
            eprintln!(
                "partial literal-0711 coverage: source and sandbox are on different devices, so \
                 only the copy path is exercised"
            );
        }
        let config = file_mount_config(&source, "/guest/source.txt", true).await;
        let staged = super::stage_file_mounts(&config, &sandbox)
            .await
            .expect("a search-only 0711 ancestor must stage successfully")
            .0;
        let (mount_dir, filename, _) = staged.get("/guest/source.txt").unwrap();
        assert_eq!(
            std::fs::read(mount_dir.join(filename)).unwrap(),
            std::fs::read(&source).unwrap()
        );
    }

    //----------------------------------------------------------------------------------------------
    // issue #24: source-parent race, verification, cleanup, copy faults
    //----------------------------------------------------------------------------------------------

    /// `#[18(a)]` — the D5 gate applied, with the pinned source-parent
    /// descriptor observed as owned by another uid: the ownership check must
    /// reject it, leave the created directory untouched, and link nothing.
    #[tokio::test]
    #[cfg(unix)]
    async fn stage_file_mounts_source_parent_stage_rejects_a_foreign_owned_decoy() {
        let (root, sandbox) = staging_sandbox_dir();
        let sources = same_device_source_dir(root.path());
        let source = sources.join("source.txt");
        std::fs::write(&source, b"secret").unwrap();
        let config = file_mount_config(&source, "/guest/source.txt", false).await;

        let rendered = super::stage_file_mounts_with_mode(
            &config,
            &sandbox,
            super::FileMountStagingMode::ForceSourceParentStageSwap,
        )
        .await
        .expect_err("a foreign-owned pinned stage must be rejected")
        .to_string();
        assert!(
            rendered.contains(&source.display().to_string()),
            "the error must name the mount: {rendered}"
        );
        assert!(
            rendered.contains("owned by uid"),
            "the ownership check, not the mode check, must fire: {rendered}"
        );

        // The rejected directory is retained for the operator and untouched:
        // nothing was linked into it.
        let retained: Vec<String> = directory_entries(&sources)
            .into_iter()
            .filter(|entry| entry.starts_with(".microsandbox-file-mount-"))
            .collect();
        assert_eq!(
            retained.len(),
            1,
            "the created directory is retained, not adopted: {retained:?}"
        );
        assert!(
            directory_entries(&sources.join(&retained[0])).is_empty(),
            "no staged entry may reach a rejected decoy"
        );
        assert_eq!(std::fs::metadata(&source).unwrap().nlink(), 1);
    }

    /// `#[18(b)]` — the same-name stage-root replacement AFTER the first anchor.
    /// Population must stay on the held descriptor, so the decoy never receives
    /// the staged entry. The replacement tree contains the exact expected
    /// `fm_*` tag (plus a decoy leaf), so `canonicalize` succeeds and the
    /// refusal is attributable to the held-identity comparison (S1).
    #[tokio::test]
    #[cfg(unix)]
    async fn stage_file_mounts_stage_swap_after_anchor_does_not_reach_the_decoy() {
        let (root, sandbox) = staging_sandbox_dir();
        let sources = same_device_source_dir(root.path());
        let source = sources.join("source.txt");
        std::fs::write(&source, b"secret").unwrap();
        let config = file_mount_config(&source, "/guest/source.txt", false).await;

        let result = super::stage_file_mounts_with_mode(
            &config,
            &sandbox,
            super::FileMountStagingMode::ForceStageSwapAfterAnchor,
        )
        .await;

        // The hook renamed the real stage root to `<name>.msb-held` and planted
        // a decoy at the original name; the test hook completed the decoy tree
        // with the exact `fm_*` tag and a decoy leaf.
        let entries: Vec<PathBuf> = directory_entries(&sources)
            .into_iter()
            .map(|entry| sources.join(entry))
            .filter(|path| {
                path.file_name().is_some_and(|name| {
                    name.to_string_lossy()
                        .starts_with(".microsandbox-file-mount-")
                })
            })
            .collect();
        let decoy = entries
            .iter()
            .find(|path| path.join("decoy-sentinel").exists());
        let decoy = decoy.expect("the same-name decoy must exist");
        let decoy_tags: Vec<String> = directory_entries(decoy)
            .into_iter()
            .filter(|entry| entry.starts_with("fm_"))
            .collect();
        assert_eq!(
            decoy_tags.len(),
            1,
            "the replacement tree must contain the exact expected tag: {:?}",
            directory_entries(decoy)
        );
        assert_eq!(
            std::fs::read(decoy.join(&decoy_tags[0]).join("source.txt")).unwrap(),
            b"decoy-leaf",
            "no real population may reach the decoy"
        );
        let held = entries.iter().find(|path| path != &decoy);
        assert!(held.is_some(), "the held original root must also remain");

        let rendered = result
            .expect_err("publication must refuse rather than redirect population")
            .to_string();
        assert!(
            rendered.contains("no longer matches the pinned tag"),
            "the held-identity comparison, not canonicalize, must fire: {rendered}"
        );
        assert!(
            rendered.contains("Retention notes") && rendered.contains("replacement"),
            "the renamed original root must be reported as retained: {rendered}"
        );
    }

    /// `#[18(c)]` — the source parent is renamed and a decoy tree planted at its
    /// old name before `mkdirat`. Staging must stay under the held parent, so
    /// the decoy tree is untouched and the real (renamed) parent has no residue.
    /// The replacement tree contains the exact expected `fm_*` tag (plus a decoy
    /// leaf), so `canonicalize` succeeds and the refusal is attributable to the
    /// held-identity comparison (S1).
    #[tokio::test]
    #[cfg(unix)]
    async fn stage_file_mounts_ancestor_redirect_keeps_staging_under_the_held_parent() {
        let (root, sandbox) = staging_sandbox_dir();
        let sources = same_device_source_dir(root.path());
        let source = sources.join("source.txt");
        std::fs::write(&source, b"secret").unwrap();
        let source_ino = std::fs::metadata(&source).unwrap().ino();
        let config = file_mount_config(&source, "/guest/source.txt", false).await;

        let result = super::stage_file_mounts_with_mode(
            &config,
            &sandbox,
            super::FileMountStagingMode::ForceAncestorRedirect,
        )
        .await;

        let redirected = sources.with_file_name(format!(
            "{}.msb-redirected",
            sources.file_name().unwrap().to_string_lossy()
        ));
        // The decoy tree at the original parent name holds its own `decoy.txt`
        // plus the planted complete stage tree (with the expected `fm_*` tag).
        let entries = directory_entries(&sources);
        assert!(entries.contains(&"decoy.txt".to_string()), "{entries:?}");
        let decoy_root = entries
            .iter()
            .find(|entry| entry.starts_with(".microsandbox-file-mount-"))
            .map(|entry| sources.join(entry))
            .expect("the planted decoy stage root must exist");
        let decoy_tags: Vec<String> = directory_entries(&decoy_root)
            .into_iter()
            .filter(|entry| entry.starts_with("fm_"))
            .collect();
        assert_eq!(decoy_tags.len(), 1, "{:?}", directory_entries(&decoy_root));
        assert_eq!(
            std::fs::read(decoy_root.join(&decoy_tags[0]).join("source.txt")).unwrap(),
            b"decoy-leaf",
            "no real population may reach the decoy"
        );
        assert_eq!(
            std::fs::metadata(redirected.join("source.txt"))
                .unwrap()
                .ino(),
            source_ino,
            "the real source moved with the renamed held parent"
        );
        assert_no_staging_residue(&redirected);

        let rendered = result
            .expect_err("publication refuses on the redirected path")
            .to_string();
        assert!(
            rendered.contains("no longer matches the pinned tag"),
            "the held-identity comparison, not canonicalize, must fire: {rendered}"
        );
    }

    /// `#22` — a failed staged-entry verification is reported as unverifiable,
    /// not as a mismatch, and the attempted entry is removed.
    #[tokio::test]
    #[cfg(unix)]
    async fn stage_file_mounts_verification_failure_is_reported_distinctly() {
        let (root, sandbox) = staging_sandbox_dir();
        let source = same_device_source_dir(root.path()).join("source.txt");
        std::fs::write(&source, b"payload").unwrap();
        let config = file_mount_config(&source, "/guest/source.txt", false).await;

        let rendered = super::stage_file_mounts_with_mode(
            &config,
            &sandbox,
            super::FileMountStagingMode::ForceVerifyStatError,
        )
        .await
        .expect_err("a verification failure refuses the spawn")
        .to_string();
        assert!(
            rendered.contains("could not verify staged file mount"),
            "{rendered}"
        );
        assert!(
            rendered.contains(&source.display().to_string()),
            "{rendered}"
        );
        assert!(rendered.contains("was removed"), "{rendered}");
        assert!(
            !rendered.contains("changed while it was being staged"),
            "a verification error must not be reported as a mismatch: {rendered}"
        );
        assert_eq!(std::fs::metadata(&source).unwrap().nlink(), 1);
    }

    /// `#22` — a detected mismatch whose cleanup `unlinkat` fails reports the
    /// retained entry with the stage's last-known path and identity.
    #[tokio::test]
    #[cfg(unix)]
    async fn stage_file_mounts_retained_verification_failure_names_the_stage_identity() {
        let (root, sandbox) = staging_sandbox_dir();
        let source = same_device_source_dir(root.path()).join("source.txt");
        std::fs::write(&source, b"payload").unwrap();
        let config = file_mount_config(&source, "/guest/source.txt", false).await;

        let rendered = super::stage_file_mounts_with_mode(
            &config,
            &sandbox,
            super::FileMountStagingMode::ForceVerificationUnlinkError,
        )
        .await
        .expect_err("a retained entry still refuses the spawn")
        .to_string();
        assert!(
            rendered.contains("changed while it was being staged"),
            "{rendered}"
        );
        assert!(rendered.contains("Could not remove"), "{rendered}");
        assert!(
            rendered.contains("Stage retained at last-known path"),
            "the [5c] retained text must name the stage path: {rendered}"
        );
        assert!(
            rendered.contains("(dev=") && rendered.contains("ino="),
            "{rendered}"
        );

        // The failed cleanup left the attempted entry for the operator.
        let stage_root = sandbox_stage_root(&sandbox);
        let tags = directory_entries(&stage_root);
        assert_eq!(tags.len(), 1, "the attempted tag must remain: {tags:?}");
        assert_eq!(
            directory_entries(&stage_root.join(&tags[0])),
            vec!["source.txt".to_string()],
            "the attempted entry is retained"
        );
    }

    /// `#22` — a failure on the second mount keeps the first sandbox-dir stage
    /// (no global emptiness).
    #[tokio::test]
    #[cfg(unix)]
    async fn stage_file_mounts_second_mount_failure_keeps_the_first_sandbox_stage() {
        let (root, sandbox) = staging_sandbox_dir();
        let sources = same_device_source_dir(root.path());
        let first = sources.join("first.txt");
        let second = sources.join("second.txt");
        std::fs::write(&first, b"first").unwrap();
        std::fs::write(&second, b"second").unwrap();
        let config = file_mounts_config(&[
            (&first, "/guest/first.txt", false),
            (&second, "/guest/second.txt", false),
        ])
        .await;

        let rendered = super::stage_file_mounts_with_mode(
            &config,
            &sandbox,
            super::FileMountStagingMode::FailSecondMount,
        )
        .await
        .expect_err("the injected second-mount failure must fail the spawn")
        .to_string();
        assert!(
            rendered.contains(&second.display().to_string()),
            "{rendered}"
        );

        let stage_root = sandbox_stage_root(&sandbox);
        let tags = directory_entries(&stage_root);
        assert_eq!(
            tags.len(),
            1,
            "the first sandbox-dir mount must remain: {tags:?}"
        );
        assert_eq!(
            std::fs::metadata(stage_root.join(&tags[0]).join("first.txt"))
                .unwrap()
                .ino(),
            std::fs::metadata(&first).unwrap().ino()
        );
    }

    /// `#22` — a failure on the second mount explicitly closes the first
    /// source-parent owner, leaving no staging residue in the user's tree.
    #[tokio::test]
    #[cfg(unix)]
    async fn stage_file_mounts_second_mount_failure_closes_the_first_source_parent_stage() {
        if running_as_root() {
            eprintln!("SKIP: as root, mode 0500 does not deny directory writes");
            return;
        }
        let (root, sandbox) = staging_sandbox_dir();
        let sources = same_device_source_dir(root.path());
        let first = sources.join("first.txt");
        let broken = sources.join("broken");
        std::fs::create_dir(&broken).unwrap();
        let second = broken.join("second.txt");
        std::fs::write(&first, b"first").unwrap();
        std::fs::write(&second, b"second").unwrap();
        let config = file_mounts_config(&[
            (&first, "/guest/first.txt", false),
            (&second, "/guest/second.txt", false),
        ])
        .await;

        set_mode(&broken, 0o500);
        let result = super::stage_file_mounts_with_mode(
            &config,
            &sandbox,
            super::FileMountStagingMode::ForceDeviceMismatch,
        )
        .await;
        set_mode(&broken, 0o700);
        assert!(result.is_err(), "the second mount cannot be staged");
        assert_no_staging_residue(&sources);
    }

    /// `#26` — lazy-copy source failures map to the `[9]`/`[9a]`/`[9b]`
    /// families and never silently fall back to directory routing.
    #[tokio::test]
    #[cfg(unix)]
    async fn stage_file_mounts_copy_source_faults_map_to_copy_failures() {
        let (root, sandbox) = staging_sandbox_dir();
        let source = same_device_source_dir(root.path()).join("readonly.txt");
        std::fs::write(&source, b"payload").unwrap();
        let config = file_mount_config(&source, "/guest/readonly.txt", true).await;

        let cases = [
            (
                super::FileMountStagingMode::ForceCopyOpenError,
                "open source for copy",
            ),
            (
                super::FileMountStagingMode::ForceCopyStatError,
                "fstat copy source",
            ),
        ];
        for (mode, operation) in cases {
            let rendered = super::stage_file_mounts_with_mode(&config, &sandbox, mode)
                .await
                .expect_err("the copy source fault must refuse the spawn")
                .to_string();
            assert!(rendered.contains("failed to copy"), "{rendered}");
            assert!(rendered.contains(operation), "{rendered}");
            assert!(!rendered.contains("cannot stage writable"), "{rendered}");
        }

        let rendered = super::stage_file_mounts_with_mode(
            &config,
            &sandbox,
            super::FileMountStagingMode::ForceCopyNonRegular,
        )
        .await
        .expect_err("a non-regular copy source refuses the spawn")
        .to_string();
        assert!(
            rendered.contains("no longer regular when opened for copying"),
            "{rendered}"
        );

        let rendered = super::stage_file_mounts_with_mode(
            &config,
            &sandbox,
            super::FileMountStagingMode::ForceCopyChanged,
        )
        .await
        .expect_err("an identity change refuses the spawn")
        .to_string();
        assert!(rendered.contains("changed before copying"), "{rendered}");
    }

    /// `#25` — the copy runs on a blocking worker: the current-thread runtime
    /// keeps running other tasks while the worker is held at the copy gate.
    #[tokio::test]
    #[cfg(unix)]
    async fn stage_file_mounts_copy_runs_off_the_runtime_thread() {
        use std::sync::Arc;
        use std::sync::atomic::{AtomicBool, AtomicUsize, Ordering};

        let (root, sandbox) = staging_sandbox_dir();
        let source = same_device_source_dir(root.path()).join("readonly.txt");
        std::fs::write(&source, b"payload").unwrap();
        let config = file_mount_config(&source, "/guest/readonly.txt", true).await;

        let heartbeat = Arc::new(AtomicUsize::new(0));
        let stop = Arc::new(AtomicBool::new(false));
        {
            let heartbeat = heartbeat.clone();
            let stop = stop.clone();
            tokio::spawn(async move {
                while !stop.load(Ordering::Relaxed) {
                    heartbeat.fetch_add(1, Ordering::Relaxed);
                    tokio::time::sleep(std::time::Duration::from_millis(2)).await;
                }
            });
        }

        let staging = tokio::spawn(async move {
            super::stage_file_mounts_with_mode(
                &config,
                &sandbox,
                super::FileMountStagingMode::ForceCopyWorkerGate,
            )
            .await
        });

        // Wait until the blocking worker is held at the gate (bounded, so a
        // regression fails instead of hanging).
        let mut waited = 0u32;
        while !super::copy_worker_gate::blocked() {
            assert!(waited < 5_000, "the copy worker never reached the gate");
            waited += 1;
            tokio::time::sleep(std::time::Duration::from_millis(1)).await;
        }
        let before = heartbeat.load(Ordering::Relaxed);
        tokio::time::sleep(std::time::Duration::from_millis(50)).await;
        let after = heartbeat.load(Ordering::Relaxed);
        super::copy_worker_gate::release();

        let staged = staging.await.unwrap().unwrap().0;
        stop.store(true, Ordering::Relaxed);
        assert!(
            after > before,
            "the runtime must keep running tasks while the copy worker is held: {before} -> {after}"
        );
        let (dir, name, _) = staged.get("/guest/readonly.txt").unwrap();
        assert_eq!(std::fs::read(dir.join(name)).unwrap(), b"payload");
    }

    /// `#16` post-gate partner — search revoked after `host.is_file()` admitted
    /// the mount fails closed through the real entry point.
    #[tokio::test]
    #[cfg(unix)]
    async fn stage_file_mounts_after_gate_revocation_fails_closed() {
        let (root, sandbox) = staging_sandbox_dir();
        let sources = same_device_source_dir(root.path());
        let denied = sources.join("denied");
        std::fs::create_dir(&denied).unwrap();
        let file = denied.join("f.txt");
        std::fs::write(&file, b"x").unwrap();
        let config = file_mount_config(&file, "/guest/f.txt", false).await;

        let denied_for_hook = denied.clone();
        let result = super::stage_file_mounts_with_after_gate_hook(
            &config,
            &sandbox,
            super::FileMountStagingMode::Automatic,
            move || set_mode(&denied_for_hook, 0o600),
        )
        .await;
        set_mode(&denied, 0o700);

        let rendered = result
            .expect_err("a post-gate revocation must fail closed")
            .to_string();
        assert!(rendered.contains("cannot be resolved"), "{rendered}");
        assert!(
            rendered.contains(&denied.display().to_string()),
            "{rendered}"
        );
        assert!(
            !sandbox_stage_root(&sandbox).exists(),
            "classification precedes stage creation"
        );
    }

    /// `#17` — an opt-in canonicalize failure is an error, reached by breaking a
    /// live symlink *after* the gate returned true.
    #[tokio::test]
    #[cfg(unix)]
    async fn stage_file_mounts_opt_in_canonicalize_failure_is_an_error() {
        let (root, sandbox) = staging_sandbox_dir();
        let (real, link) = symlink_fixture(root.path(), "link.txt");
        let config = file_mount_config_following(&link, "/guest/link.txt", false).await;

        let real_for_hook = real.clone();
        let result = super::stage_file_mounts_with_after_gate_hook(
            &config,
            &sandbox,
            super::FileMountStagingMode::Automatic,
            move || {
                let _ = std::fs::remove_file(&real_for_hook);
            },
        )
        .await;

        let rendered = result
            .expect_err("a canonicalize failure under the opt-in is an error")
            .to_string();
        assert!(
            rendered.contains("follow-root-symlinks set but could not be resolved"),
            "{rendered}"
        );
        assert!(rendered.contains(&link.display().to_string()), "{rendered}");
    }

    /// `§6.3` — a real Linux `protected_hardlinks=1` fixture. Skips with a
    /// printed reason whenever a precondition is absent, never fails.
    #[tokio::test]
    #[cfg(target_os = "linux")]
    async fn stage_file_mounts_readonly_root_owned_source_on_protected_hardlinks() {
        use std::os::unix::fs::PermissionsExt as _;

        let protected = std::fs::read_to_string("/proc/sys/fs/protected_hardlinks")
            .map(|value| value.trim() == "1")
            .unwrap_or(false);
        if !protected {
            eprintln!("SKIP protected_hardlinks test: /proc/sys/fs/protected_hardlinks is not 1");
            return;
        }
        if running_as_root() {
            eprintln!("SKIP protected_hardlinks test: running as root");
            return;
        }
        let (root, sandbox) = staging_sandbox_dir();
        let sandbox_dev = std::fs::metadata(&sandbox).unwrap().dev();
        let mut tried: Vec<String> = Vec::new();
        let candidate = ["/etc/hosts", "/etc/os-release"].iter().find_map(|path| {
            let canonical = match std::fs::canonicalize(path) {
                Ok(path) => path,
                Err(error) => {
                    tried.push(format!("{path}: {error}"));
                    return None;
                }
            };
            let meta = match std::fs::metadata(&canonical) {
                Ok(meta) => meta,
                Err(error) => {
                    tried.push(format!("{path}: {error}"));
                    return None;
                }
            };
            if !meta.is_file()
                || meta.dev() != sandbox_dev
                || meta.uid() != 0
                || meta.permissions().mode() & 0o022 != 0
            {
                tried.push(format!(
                    "{path}: dev={} uid={} mode={:o}",
                    meta.dev(),
                    meta.uid(),
                    meta.permissions().mode() & 0o7777
                ));
                return None;
            }
            Some(canonical)
        });
        let Some(source) = candidate else {
            eprintln!(
                "SKIP protected_hardlinks test: no root-owned, not-group/other-writable file \
                 on the sandbox device (tried {tried:?})"
            );
            return;
        };

        // Prove a real hard link into the stage device is refused, accounting for
        // ACLs and capabilities.
        let probe_dir = root.path().join("protected-hardlinks-probe");
        std::fs::create_dir_all(&probe_dir).unwrap();
        let probe = probe_dir.join("probe");
        let refused = std::fs::hard_link(&source, &probe).is_err();
        let _ = std::fs::remove_dir_all(&probe_dir);
        if !refused {
            eprintln!(
                "SKIP protected_hardlinks test: a probe hard link to {} unexpectedly succeeded",
                source.display()
            );
            return;
        }
        let read_source = std::fs::read(&source).unwrap();

        // Readonly: the refused link falls back to an isolated copy.
        let config = file_mount_config(&source, "/guest/hosts", true).await;
        let (staged, _) = super::stage_file_mounts(&config, &sandbox)
            .await
            .expect("a readonly root-owned source must fall back to a copy");
        let (mount_dir, filename, _) = staged.get("/guest/hosts").unwrap();
        let staged_file = mount_dir.join(filename);
        assert_eq!(std::fs::read(&staged_file).unwrap(), read_source);
        assert_eq!(std::fs::metadata(&staged_file).unwrap().nlink(), 1);

        // Writable: the refused link is a hard error naming protected_hardlinks.
        let config = file_mount_config(&source, "/guest/hosts-rw", false).await;
        let rendered = super::stage_file_mounts(&config, &sandbox)
            .await
            .expect_err("a writable root-owned source cannot hard-link")
            .to_string();
        assert!(rendered.contains("protected_hardlinks"), "{rendered}");
    }

    /// S1 — publication refuses a replacement tree that contains the exact
    /// expected `fm_*` tag but no leaf, so `canonicalize` succeeds as a fixture
    /// precondition and only the held-identity comparison rejects it.
    #[test]
    #[cfg(unix)]
    fn publish_rejects_a_tag_only_replacement() {
        use microsandbox_filesystem::nofollow::NoFollowDir;

        let dir = staging_fixture_root();
        let held_root_path = dir.path().join("held-root");
        std::fs::create_dir(&held_root_path).unwrap();
        let held_root = NoFollowDir::open(&held_root_path).unwrap();
        let tag = held_root
            .create_subdir(std::ffi::OsStr::new("fm_00000001"), 0o700)
            .unwrap();
        let tag_identity = tag.identity();
        let root_identity = held_root.identity();

        // A replacement tree containing only the expected tag name (no leaf).
        let replacement = dir.path().join("replacement");
        std::fs::create_dir(&replacement).unwrap();
        std::fs::create_dir(replacement.join("fm_00000001")).unwrap();
        let replacement_tag = replacement.join("fm_00000001");
        assert!(
            std::fs::canonicalize(&replacement_tag).is_ok(),
            "the fixture precondition is that canonicalize succeeds"
        );

        let mut staged = std::collections::HashMap::new();
        let requested = dir.path().join("source.txt");
        let resolved = requested.clone();
        let context = super::MountContext {
            requested: &requested,
            resolved: &resolved,
            guest: "/guest/source.txt",
            readonly: false,
        };
        let error = super::publish(
            &mut staged,
            &context,
            "source.txt",
            "fm_00000001",
            &replacement_tag,
            tag_identity,
            Some(root_identity),
        )
        .expect_err("a tag-only replacement must be rejected by identity");
        assert!(staged.is_empty(), "nothing may be published");
        assert!(
            error
                .to_string()
                .contains("no longer matches the pinned tag"),
            "{error}"
        );
    }
}
