//! Pin caller-supplied host paths before a local sandbox is persisted or launched.

use std::path::{Path, PathBuf};

use microsandbox_types::{Patch, RootDisk, RootfsSource, VolumeMount};

use crate::{MicrosandboxError, MicrosandboxResult, SandboxConfig, snapshot::SnapshotReference};

#[cfg(test)]
mod tests;

//--------------------------------------------------------------------------------------------------
// Constants
//--------------------------------------------------------------------------------------------------

/// Prefix Windows `canonicalize` adds; it identifies nothing a reader needs.
const VERBATIM_PATH_PREFIX: &str = r"\\?\";

//--------------------------------------------------------------------------------------------------
// Functions
//--------------------------------------------------------------------------------------------------

/// Resolve local inputs once, before creation yields or saves its configuration.
///
/// Keep this at the local backend boundary: cloud paths belong to the remote host,
/// and callers can bypass `SandboxBuilder` by supplying a `SandboxConfig` directly.
/// Do not call this when reopening existing saved state: legacy relative paths keep
/// their previous interpretation and must not be rewritten during restart.
pub(crate) fn resolve_host_paths(config: &mut SandboxConfig) -> MicrosandboxResult<()> {
    // Restore sources are operation-only paths too. They can be consumed after
    // snapshot preparation or a background task has yielded.
    if !config.local_restore_paths_resolved {
        if let Some(reference) = &mut config.snapshot_reference {
            resolve_snapshot_reference(reference)?;
        }
        if let Some(path) = &mut config.snapshot_archive_source {
            *path = std::path::absolute(&*path)?;
        }
        if let Some(base) = &mut config.snapshot_base {
            let mut reference = SnapshotReference::auto(&*base);
            resolve_snapshot_reference(&mut reference)?;
            if let SnapshotReference::Auto(value) = reference {
                *base = value;
            }
        }
        config.local_restore_paths_resolved = true;
    }
    visit_host_paths(config, true, |path, label| {
        if !path.is_absolute() {
            // `absolute` anchors the path without following symlinks or requiring
            // the target to exist. Canonicalizing here would bypass bind mounts'
            // default refusal to follow symlinks in caller-supplied components.
            *path = std::path::absolute(&*path).map_err(|error| {
                MicrosandboxError::InvalidConfig(format!(
                    "cannot resolve {label} {}: {error}",
                    path.display()
                ))
            })?;
        }
        Ok(())
    })
}

/// Report a symlinked bind mount root now instead of when the sandbox boots.
///
/// The runtime opens a bind mount root without following symlinks in any
/// component, including the last, unless `follow_root_symlinks` is set. Mirror
/// that check so creation fails with an actionable error before the sandbox is
/// persisted. Call it after missing-resource admission: only roots that exist
/// and resolve to a directory are checked, so a vanished mount that a relaxed
/// restore marks unavailable is never rejected here. Missing paths, dangling
/// links and files (canonicalized by `SingleFileFs`) are left to the runtime,
/// which enforces the policy itself; this only explains it. A restored mount whose
/// captured transport is a file, or whose backing is optional under a relaxed
/// restore, is skipped for the same reason: the runtime tolerates or reclassifies it.
#[cfg(unix)]
pub(crate) fn check_bind_roots_do_not_follow_symlinks(
    config: &SandboxConfig,
) -> MicrosandboxResult<()> {
    for mount in &config.spec.mounts {
        let VolumeMount::Bind {
            host,
            guest,
            follow_root_symlinks: false,
            ..
        } = mount
        else {
            continue;
        };
        if let Some(restore) = &config.checkpoint_restore
            && restore.external_mounts.iter().any(|binding| {
                binding.mount.guest_path == *guest
                    && (binding.filename.is_some()
                        || (restore.external_mount_policy
                            == microsandbox_types::ExternalMountRestorePolicy::Relaxed
                            && !binding.require_backing))
            })
        {
            continue;
        }
        if !std::fs::metadata(host).is_ok_and(|metadata| metadata.is_dir()) {
            continue;
        }
        let mut current = PathBuf::new();
        for component in host.components() {
            current.push(component);
            if !std::fs::symlink_metadata(&current)
                .is_ok_and(|metadata| metadata.file_type().is_symlink())
            {
                continue;
            }
            let reached = if current == *host {
                "is a symlink".to_string()
            } else {
                format!("goes through symlink {}", current.display())
            };
            let resolved = std::fs::canonicalize(host)?;
            return Err(MicrosandboxError::InvalidConfig(format!(
                "bind mount host path {} {reached}; use the resolved path {} or add follow-root-symlinks",
                host.display(),
                resolved.display()
            )));
        }
    }
    Ok(())
}

#[cfg(not(unix))]
pub(crate) fn check_bind_roots_do_not_follow_symlinks(
    _config: &SandboxConfig,
) -> MicrosandboxResult<()> {
    Ok(())
}

/// Refuse a writable caller bind that would expose msb's sandbox state to a guest.
///
/// `<sandboxes_dir>/<name>` holds each sandbox's disks, volumes and `logs/`, where the runtime
/// appends that sandbox's own refusal records. A writable bind of any sandbox directory, of a path
/// inside one, or of the sandboxes directory itself would let one guest read or rewrite another
/// sandbox's state, including the records that describe its own refusals, so all of them are
/// refused. Only `VolumeMount::Bind` roots that are not read-only are measured; owned volumes,
/// named volumes and tmpfs mounts are msb-managed and never resolve there, and a writable bind of
/// an *ancestor* above the sandboxes directory (`MSB_HOME`, `$HOME`) stays allowed as a documented
/// exposure. Call this once `sandbox_dir` exists, immediately before the runtime process is
/// spawned, so the comparison has a file identity to compare against.
///
/// Resolution is for comparison only. The configured path and its symlink policy
/// are never rewritten: a symlink is followed here whether or not the mount opts
/// into `follow_root_symlinks`, because the runtime either follows it too or
/// refuses it at open, so this can only refuse earlier.
pub(crate) fn check_writable_binds_do_not_expose_sandbox_state(
    sandboxes_dir: &Path,
    sandbox_dir: &Path,
    mounts: &[VolumeMount],
) -> MicrosandboxResult<()> {
    for mount in mounts {
        let VolumeMount::Bind { host, options, .. } = mount else {
            continue;
        };
        if options.readonly {
            continue;
        }
        let resolved = resolve_bind_root_for_comparison(host)?;
        // A directory or a path inside it is caught by walking ancestors; a hard link to one of
        // this sandbox's log files resolves outside the directory, so those files are compared by
        // identity too.
        if !resolved_root_is_inside_sandboxes_dir(sandboxes_dir, &resolved)?
            && !resolved_root_aliases_a_log_file(sandbox_dir, &resolved)?
        {
            continue;
        }
        return Err(MicrosandboxError::InvalidConfig(format!(
            "bind mount host path {} exposes msb's sandbox state directory {} to the guest (it resolves to {}); the guest could read or rewrite a sandbox's logs. Mount it read-only or bind a path outside {}",
            host.display(),
            sandboxes_dir.display(),
            resolved_path_text(&resolved),
            sandboxes_dir.display()
        )));
    }
    Ok(())
}

/// Capture explicit builder inputs without turning omitted settings into overrides.
/// The temporary value only feeds the common path visitor; copy back path-bearing
/// fields that were present, retaining sparse layer and managed-policy semantics.
pub(crate) fn resolve_patch_paths(patch: &mut crate::SandboxConfigPatch) -> MicrosandboxResult<()> {
    let mut config = patch.clone().into_config();
    resolve_host_paths(&mut config)?;
    if patch.spec.image.is_some() {
        patch.spec.image = Some(config.spec.image);
    }
    if patch.spec.mounts.is_some() {
        patch.spec.mounts = Some(config.spec.mounts);
    }
    if patch.spec.patches.is_some() {
        patch.spec.patches = Some(config.spec.patches);
    }
    if let Some(tls) = &mut patch.spec.network.tls
        && let Some(resolved) = config.spec.network.tls
    {
        if tls.upstream_ca_cert.is_some() {
            tls.upstream_ca_cert = Some(resolved.upstream_ca_cert);
        }
        if tls.scoped_upstream_ca_cert.is_some() {
            tls.scoped_upstream_ca_cert = Some(resolved.scoped_upstream_ca_cert);
        }
        if tls.intercept_ca.is_some() {
            tls.intercept_ca = Some(resolved.intercept_ca);
        }
    }
    patch.snapshot_reference = config.snapshot_reference;
    patch.snapshot_archive_source = config.snapshot_archive_source;
    patch.snapshot_base = config.snapshot_base;
    patch.local_restore_paths_resolved = Some(true);
    Ok(())
}

/// Capture explicit paths and path-shaped selectors without rebasing names or IDs.
pub(crate) fn resolve_snapshot_reference(
    reference: &mut SnapshotReference,
) -> MicrosandboxResult<()> {
    let value = match reference {
        SnapshotReference::Path(value) => {
            if value.is_empty() {
                return Err(MicrosandboxError::InvalidConfig(
                    "snapshot path or name must not be empty".into(),
                ));
            }
            value
        }
        SnapshotReference::Auto(value)
            if super::snapshot::looks_like_path(value) || std::path::Path::new(value).is_file() =>
        {
            value
        }
        SnapshotReference::Auto(_) | SnapshotReference::Id(_) => return Ok(()),
    };
    *value = std::path::absolute(&*value)?.to_string_lossy().into_owned();
    Ok(())
}

/// Enumerate host inputs explicitly so guest paths and resource names stay untouched.
fn visit_host_paths(
    config: &mut SandboxConfig,
    include_patch_sources: bool,
    mut visit: impl FnMut(&mut PathBuf, &str) -> MicrosandboxResult<()>,
) -> MicrosandboxResult<()> {
    match &mut config.spec.image {
        RootfsSource::Bind { path, .. } => visit(path, "bind rootfs path")?,
        RootfsSource::DiskImage { path, .. } => visit(path, "root disk image path")?,
        RootfsSource::Oci(oci) => match &mut oci.root_disk {
            Some(RootDisk::DiskImage { path, .. }) => visit(path, "OCI root disk image path")?,
            Some(RootDisk::Managed { .. } | RootDisk::Tmpfs { .. } | RootDisk::Flat { .. })
            | None => {}
        },
    }

    for mount in &mut config.spec.mounts {
        match mount {
            VolumeMount::Bind { host, .. } => visit(host, "bind mount host path")?,
            VolumeMount::DiskImage { host, .. } => visit(host, "disk mount host path")?,
            VolumeMount::Owned { .. } | VolumeMount::Named { .. } | VolumeMount::Tmpfs { .. } => {}
        }
    }

    // Patch sources can be read after an image pull has yielded. They share the
    // creation directory even though patches are only applied during creation.
    if include_patch_sources {
        for patch in &mut config.spec.patches {
            match patch {
                Patch::CopyFile { src, .. } | Patch::CopyDir { src, .. } => {
                    visit(src, "patch source path")?;
                }
                Patch::Text { .. }
                | Patch::File { .. }
                | Patch::Symlink { .. }
                | Patch::Mkdir { .. }
                | Patch::Remove { .. }
                | Patch::Append { .. } => {}
            }
        }
    }

    // TLS files are reopened on every boot too. A different cwd must not select
    // a different trust store or interception identity for the same sandbox.
    if let Some(tls) = &mut config.spec.network.tls {
        for path in &mut tls.upstream_ca_cert {
            visit(path, "upstream CA certificate path")?;
        }
        for scoped in &mut tls.scoped_upstream_ca_cert {
            visit(&mut scoped.path, "scoped upstream CA certificate path")?;
        }
        if let Some(path) = &mut tls.intercept_ca.cert_path {
            visit(path, "interception CA certificate path")?;
        }
        if let Some(path) = &mut tls.intercept_ca.key_path {
            visit(path, "interception CA key path")?;
        }
    }
    Ok(())
}

/// Locate the host path a bind root would open, without rewriting the configured path.
///
/// The path is anchored the same way `resolve_host_paths` anchors it (no symlink is
/// followed and the target need not exist), then the deepest existing prefix is
/// canonicalized the way `check_bind_roots_do_not_follow_symlinks` names the resolved
/// path. A tail that does not exist yet cannot be a symlink, so the prefix decides
/// which location the runtime would open. `/` always exists, so this terminates.
fn resolve_bind_root_for_comparison(host: &Path) -> MicrosandboxResult<PathBuf> {
    let anchored = std::path::absolute(host).map_err(|error| {
        MicrosandboxError::InvalidConfig(format!(
            "cannot resolve bind mount host path {}: {error}",
            host.display()
        ))
    })?;
    for candidate in anchored.ancestors() {
        match std::fs::canonicalize(candidate) {
            Ok(resolved) => return Ok(resolved),
            Err(error) if is_absent(&error) => {}
            Err(error) => {
                return Err(MicrosandboxError::InvalidConfig(format!(
                    "cannot resolve bind mount host path {}: {error}",
                    candidate.display()
                )));
            }
        }
    }
    Err(MicrosandboxError::InvalidConfig(format!(
        "cannot resolve bind mount host path {}: no existing ancestor",
        host.display()
    )))
}

/// Render a resolved path for a message, without the verbatim prefix Windows adds.
fn resolved_path_text(resolved: &Path) -> String {
    let text = resolved.to_string_lossy();
    text.strip_prefix(VERBATIM_PATH_PREFIX)
        .unwrap_or(&text)
        .to_string()
}

/// Whether a canonicalization failure only means "this prefix does not exist yet".
fn is_absent(error: &std::io::Error) -> bool {
    matches!(
        error.kind(),
        std::io::ErrorKind::NotFound | std::io::ErrorKind::NotADirectory
    )
}

/// Whether a resolved bind root is the sandboxes directory or lies inside it.
///
/// File identity is compared instead of path text, so a case-insensitive volume
/// (default APFS) or a differently spelled alias of a sandbox directory is caught.
#[cfg(unix)]
fn resolved_root_is_inside_sandboxes_dir(
    sandboxes_dir: &Path,
    resolved: &Path,
) -> MicrosandboxResult<bool> {
    use std::os::unix::fs::MetadataExt;

    let sandboxes = std::fs::metadata(sandboxes_dir).map_err(|error| {
        MicrosandboxError::InvalidConfig(format!(
            "cannot inspect sandboxes directory {}: {error}",
            sandboxes_dir.display()
        ))
    })?;
    // A canonical prefix exists, so every ancestor of it exists too; a candidate
    // that vanished under a concurrent deletion cannot be the shared directory.
    for candidate in resolved.ancestors() {
        let Ok(metadata) = std::fs::metadata(candidate) else {
            break;
        };
        if metadata.dev() == sandboxes.dev() && metadata.ino() == sandboxes.ino() {
            return Ok(true);
        }
    }
    Ok(false)
}

/// Whether a resolved bind root is the sandboxes directory or lies inside it.
#[cfg(not(unix))]
fn resolved_root_is_inside_sandboxes_dir(
    sandboxes_dir: &Path,
    resolved: &Path,
) -> MicrosandboxResult<bool> {
    let sandboxes = std::fs::canonicalize(sandboxes_dir).map_err(|error| {
        MicrosandboxError::InvalidConfig(format!(
            "cannot inspect sandboxes directory {}: {error}",
            sandboxes_dir.display()
        ))
    })?;
    Ok(components_start_with(resolved, &sandboxes))
}

/// Whether a resolved bind root is one of the files the sandbox's log directory holds.
///
/// A hard link to `<sandbox_dir>/logs/network.log` created outside the sandbox keeps that
/// external pathname through canonicalization, so the ancestor comparison above cannot see it and
/// the guest could still overwrite the refusal feed. File identity is what the link shares.
///
/// Bounded: one `read_dir` and one stat per entry, and only when the bind root is an existing
/// file. Residual, documented exposure: a hard link to a log file created *after* this check is
/// not caught, and a writable bind of an ancestor above the sandboxes directory still exposes the
/// logs (S2, S5).
#[cfg(unix)]
fn resolved_root_aliases_a_log_file(
    sandbox_dir: &Path,
    resolved: &Path,
) -> MicrosandboxResult<bool> {
    use std::os::unix::fs::MetadataExt;

    // A bind root that does not exist yet, or is a directory, holds no file identity to match.
    let Ok(bound) = std::fs::metadata(resolved) else {
        return Ok(false);
    };
    if !bound.is_file() {
        return Ok(false);
    }

    // A sandbox whose log directory is not there yet has no log to protect.
    let Ok(logs) = std::fs::read_dir(sandbox_dir.join("logs")) else {
        return Ok(false);
    };
    for entry in logs.flatten() {
        // `DirEntry::metadata` does not follow a symlink, and a link is not a log file.
        let Ok(log) = entry.metadata() else {
            continue;
        };
        if log.is_file() && log.dev() == bound.dev() && log.ino() == bound.ino() {
            return Ok(true);
        }
    }
    Ok(false)
}

/// Whether a resolved bind root is one of the sandbox's log files.
///
/// Windows has no portable file identity to compare a bind root against (the same limitation the
/// canonical-path sidecar already has), so only the path comparison above applies there.
#[cfg(not(unix))]
fn resolved_root_aliases_a_log_file(
    _sandbox_dir: &Path,
    _resolved: &Path,
) -> MicrosandboxResult<bool> {
    Ok(false)
}

/// Compare two canonical paths component-wise, ASCII-case-insensitively.
#[cfg(not(unix))]
fn components_start_with(path: &Path, base: &Path) -> bool {
    let mut components = path.components();
    base.components().all(|expected| {
        components
            .next()
            .is_some_and(|actual| component_eq_ignore_ascii_case(&actual, &expected))
    })
}

/// Compare one path component the way a case-insensitive volume would.
#[cfg(not(unix))]
fn component_eq_ignore_ascii_case(
    left: &std::path::Component<'_>,
    right: &std::path::Component<'_>,
) -> bool {
    left.as_os_str()
        .to_string_lossy()
        .eq_ignore_ascii_case(&right.as_os_str().to_string_lossy())
}
