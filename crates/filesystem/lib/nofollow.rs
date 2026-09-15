//! No-follow host path resolution and fd-relative staging operations.
//!
//! This module resolves a host path to the descriptor of its parent directory
//! plus the leaf name, following no symlink in any component, and then offers
//! the small set of `*at`-relative primitives the SDK's file-mount staging
//! needs: classify the leaf, hard-link it into a directory, copy it into a
//! directory, and create an owned source-parent stage directory.
//!
//! The point of the module is the invariant that **a name a decision was made
//! about is never re-resolved from the filesystem root**: the parent directory
//! descriptor is held from resolution through classification and the final
//! `linkat`, so a link cannot be redirected into a different directory. It does
//! not pin the *leaf's* lifetime in that directory: a local user who can write to
//! the source's directory can still swap the leaf between the check and the link,
//! so `link_into` re-checks the linked entry's `(st_dev, st_ino)` and kind and
//! removes an entry that does not match the classified snapshot (D2 accepts the
//! absence of a leaf-lifetime pin). The sibling directory-root
//! policy lives in
//! [`PassthroughConfig::no_symlink_root`](crate::PassthroughConfig); both reject
//! symlink traversal, but this resolver returns a search-only parent plus leaf
//! with component diagnostics rather than a readable directory.
//!
//! `..` is supported through a checked descriptor stack: every real directory
//! is opened without following a symlink, `..` pops a pushed descriptor (or
//! opens the actual parent when the stack floor is the initial base), and no
//! component is ever cancelled lexically.
//!
//! The module is compiled only on Linux and macOS. Other Unix targets keep the
//! existing staging implementation.

use std::ffi::{CStr, CString, OsStr, OsString};
use std::fs::File;
use std::io::{self, Read};
use std::os::fd::{AsRawFd, FromRawFd, IntoRawFd, OwnedFd, RawFd};
use std::os::unix::ffi::OsStrExt;
use std::path::{Component, Path, PathBuf};

#[cfg(target_os = "linux")]
use crate::backends::shared::platform;

//--------------------------------------------------------------------------------------------------
// Types
//--------------------------------------------------------------------------------------------------

/// What a path's last component is, determined without following a symlink at
/// that component.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum LeafKind {
    /// A regular file.
    Regular,
    /// A directory.
    Directory,
    /// A symbolic link.
    Symlink,
    /// Anything else: fifo, socket, block or character device.
    Other,
}

/// Why a no-follow resolution refused a path.
///
/// The distinction between [`Self::Symlink`] and every other variant is the
/// policy decision a caller makes: a symlink is a refusal, an unsearchable or
/// missing component is merely "this is not resolvable here".
#[derive(Debug)]
pub enum NoFollowError {
    /// A component of the path is a symlink. `component` is the path prefix up
    /// to and including it, so the caller can name it in a user-facing error.
    Symlink {
        /// The path prefix up to and including the symlinked component.
        component: PathBuf,
    },
    /// Invalid input: no final filename, a non-Unix prefix, or interior NUL.
    /// Never returned for `..`.
    Unsupported {
        /// The rejected path.
        path: PathBuf,
        /// Why it was rejected.
        reason: &'static str,
    },
    /// A successful no-follow stat found a non-regular leaf.
    NonRegular {
        /// The path whose leaf was classified.
        path: PathBuf,
        /// The kind that was observed.
        kind: LeafKind,
    },
    /// Resolution stopped at `component` for any other OS reason.
    Unresolved {
        /// The path prefix up to and including the offending component.
        component: PathBuf,
        /// The underlying OS error.
        source: io::Error,
    },
}

/// An absolute or relative host path resolved to the descriptor of its parent
/// directory plus the leaf name, following no symlink in any component.
///
/// This is the file-granularity counterpart of the directory-root protection in
/// [`PassthroughConfig::no_symlink_root`](crate::PassthroughConfig); see
/// `open_root_no_symlink` in `backends::passthroughfs`.
#[derive(Debug)]
pub struct NoFollowPath {
    parent: SearchDir,
    leaf: CString,
    path: PathBuf,
}

/// A regular source classified through a held parent, without requiring read
/// access. Identity is a `fstatat` snapshot; only [`NoFollowFile::copy_into`]
/// lazily opens a readable leaf.
#[derive(Debug)]
pub struct NoFollowFile {
    parent: SearchDir,
    leaf: CString,
    path: PathBuf,
    dev: u64,
    ino: u64,
    mode: u32,
}

/// An open directory descriptor used as the anchor for `*at` operations, so a
/// name under it is never re-resolved from the filesystem root.
///
/// [`NoFollowDir::path`] is carried for error messages and for the value handed
/// to the VMM; it is never used to perform an operation this type offers.
#[derive(Debug)]
pub struct NoFollowDir {
    anchor: SearchDir,
    admin: File,
    path: PathBuf,
    /// The `(st_dev, st_ino)` observed when the descriptor was acquired. Stored
    /// once so [`NoFollowDir::identity`] never fabricates a value from a failed
    /// re-stat.
    identity: StageIdentity,
}

/// Device/inode pair of a held stage directory, for diagnostics and the record
/// handoff a later ticket can use.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct StageIdentity {
    /// The filesystem device id.
    pub dev: u64,
    /// The inode number.
    pub ino: u64,
}

/// Source-parent stage ownership; no recursive path-based deletion.
///
/// The root descriptor pins dev/ino until [`SourceParentStage::close`] or
/// [`SourceParentStage::keep`]. Population and cleanup use held descriptors.
#[derive(Debug)]
pub struct SourceParentStage {
    parent: SearchDir,
    root: NoFollowDir,
    tag: Option<NoFollowDir>,
    name: CString,
    identity: StageIdentity,
    leaf: Option<CString>,
    armed: bool,
}

/// Creation failure retains the actual operation/errno and any last-known
/// created root, so a caller never reports a bare failure for a directory it
/// may have created.
#[derive(Debug)]
pub struct StageCreateError {
    /// What the code was attempting when it failed.
    pub operation: &'static str,
    /// The underlying OS error.
    pub source: io::Error,
    /// The last-known locator and identity of a directory that may have been
    /// created but not acquired.
    pub retained: Option<(PathBuf, Option<StageIdentity>)>,
}

/// Explicit close failure records each retained root and its actual cleanup
/// cause.
#[derive(Debug)]
pub struct StageCleanupError {
    /// One entry per object the close could not remove.
    pub retained: Vec<(PathBuf, StageIdentity, io::Error)>,
}

/// Why staging a classified source into a [`NoFollowDir`] failed.
#[derive(Debug)]
pub enum StageError {
    /// `linkat` itself failed. The caller decides what to do by mount mode.
    Link(io::Error),
    /// A successfully observed identity/kind differs from the classified source.
    SourceChanged {
        /// What happened to the attempted entry.
        cleanup: CleanupOutcome,
    },
    /// No identity conclusion is possible: preserve the verification errno.
    Unverifiable {
        /// The verification error.
        source: io::Error,
        /// What happened to the attempted entry.
        cleanup: CleanupOutcome,
    },
}

/// Describes only the attempted entry, not every mount in the spawn.
#[derive(Debug)]
pub enum CleanupOutcome {
    /// The attempted entry was removed.
    Removed,
    /// The attempted entry could not be removed.
    Retained {
        /// The target that could not be removed.
        target: PathBuf,
        /// Why removal failed.
        source: io::Error,
        /// Last-known locator of the stage directory that retains the entry.
        stage: PathBuf,
        /// `(dev, ino)` of the stage directory that retains the entry, so an
        /// operator can find it again after a rename.
        identity: StageIdentity,
    },
}

/// Test-only overrides for [`NoFollowFile::create_stage_beside`].
///
/// Production always uses [`StageOverrides::default`]. The SDK's `cfg(test)`
/// hooks set one field to reach a branch a normal filesystem cannot produce: a
/// foreign-owned pinned descriptor, a post-anchor same-name swap, or a
/// redirected ancestor.
///
/// Only compiled under `cfg(any(test, feature = "test-internals"))`; it is not
/// part of the shipping API.
#[cfg(any(test, feature = "test-internals"))]
#[derive(Debug, Default, Clone, Copy)]
pub struct StageOverrides {
    /// Observe this mode for the pinned stage descriptor instead of its real
    /// `st_mode`.
    pub mode: Option<u32>,
    /// Observe this owner for the pinned stage descriptor instead of its real
    /// `st_uid`, simulating a foreign-owned decoy without needing privilege.
    pub uid: Option<libc::uid_t>,
    /// Force the D5 parent-writability gate true on a parent that is not
    /// group/other-writable.
    pub force_foreign_writable: bool,
    /// After the first anchor, rename the stage root and plant a same-name decoy
    /// directory. Population must stay on the held descriptor.
    pub swap_after_anchor: bool,
    /// Before `mkdirat`, rename the resolved source parent and plant a decoy tree
    /// at its old name. Staging must stay under the held parent.
    pub redirect_ancestor: bool,
}

/// Test-only fault injection for [`NoFollowFile::link_into`].
///
/// Production always uses [`LinkFaults::default`].
///
/// Only compiled under `cfg(any(test, feature = "test-internals"))`; it is not
/// part of the shipping API.
#[cfg(any(test, feature = "test-internals"))]
#[derive(Debug, Default, Clone, Copy)]
pub struct LinkFaults {
    /// Force the post-link verification `fstatat` to fail with this errno.
    pub verify_stat_errno: Option<i32>,
    /// Force the post-mismatch cleanup `unlinkat` to fail with this errno.
    pub unlink_errno: Option<i32>,
}

/// Test-only fault injection for [`NoFollowFile::copy_into`].
///
/// Production always uses [`CopyFaults::default`].
///
/// Only compiled under `cfg(any(test, feature = "test-internals"))`; it is not
/// part of the shipping API.
#[cfg(any(test, feature = "test-internals"))]
#[derive(Debug, Default, Clone, Copy)]
pub struct CopyFaults {
    /// Force the lazy source open to fail with this errno.
    pub open_errno: Option<i32>,
    /// Force the lazy source `fstat` to fail with this errno.
    pub stat_errno: Option<i32>,
    /// Report the opened source as no longer regular.
    pub non_regular: bool,
    /// Report the opened source as an identity change.
    pub changed: bool,
}

/// A lazy copy-source failure, with phase-2 mappings decided by the caller.
#[derive(Debug)]
pub enum CopySourceError {
    /// Opening the source for reading failed.
    Open(io::Error),
    /// `fstat` on the opened source failed.
    Stat(io::Error),
    /// The opened source no longer matches the classified identity.
    Changed,
    /// The opened source is no longer a regular file.
    NonRegular,
}

/// A copy failure, preserving copy-source errors and any destination cleanup
/// failure structurally.
#[derive(Debug)]
pub enum CopyError {
    /// The source could not be opened, stat'd or verified.
    Source(CopySourceError),
    /// A destination operation failed.
    Operation {
        /// What the code was attempting.
        operation: &'static str,
        /// The underlying OS error.
        source: io::Error,
        /// What happened to a destination entry this call created.
        cleanup: Option<CleanupOutcome>,
    },
}

/// Private owned descriptor for lookup, never for directory reads or `fchmod`.
///
/// Linux: `O_PATH`; Darwin: `O_SEARCH`; always
/// `O_DIRECTORY | O_NOFOLLOW | O_CLOEXEC`.
#[derive(Debug)]
struct SearchDir {
    fd: OwnedFd,
}

#[cfg(test)]
std::thread_local! {
    /// Counts entries into the portable component walk, so a parity test can
    /// assert the Linux fast path performs none on success.
    static PORTABLE_WALK_CALLS: std::cell::Cell<usize> = const { std::cell::Cell::new(0) };
}

#[cfg(any(test, feature = "test-internals"))]
std::thread_local! {
    /// When set, the next [`create_dir_umask_safe`] child skips its
    /// post-`mkdirat` open, so the "directory created but not acquired"
    /// reporting branch is reachable deterministically.
    static FAIL_OPEN_AFTER_MKDIR: std::cell::Cell<bool> = const { std::cell::Cell::new(false) };

    /// When set, cleanup renames the stage root and plants a same-name empty
    /// replacement *between* the identity check and the removal decision, so the
    /// check/unlink race is reachable deterministically.
    static SWAP_ROOT_BEFORE_REMOVAL: std::cell::Cell<bool> = const { std::cell::Cell::new(false) };
}

//--------------------------------------------------------------------------------------------------
// Constants
//--------------------------------------------------------------------------------------------------

#[cfg(target_os = "linux")]
const SEARCH_OPEN_FLAGS: i32 =
    libc::O_PATH | libc::O_DIRECTORY | libc::O_NOFOLLOW | libc::O_CLOEXEC;
#[cfg(target_os = "macos")]
const SEARCH_OPEN_FLAGS: i32 =
    libc::O_SEARCH | libc::O_DIRECTORY | libc::O_NOFOLLOW | libc::O_CLOEXEC;

const ADMIN_OPEN_FLAGS: i32 =
    libc::O_RDONLY | libc::O_DIRECTORY | libc::O_NOFOLLOW | libc::O_CLOEXEC;

/// How many random basenames to try before giving up on an existing decoy.
const STAGE_NAME_ATTEMPTS: usize = 32;

//--------------------------------------------------------------------------------------------------
// Methods
//--------------------------------------------------------------------------------------------------

impl NoFollowPath {
    /// Resolve `path`'s parent without following any component.
    ///
    /// An absolute path resolves from the real root, a relative one from the
    /// process working directory; in both cases the base is the only implicitly
    /// trusted object. `..` follows the descriptor-stack rules described in the
    /// module docs.
    pub fn resolve(path: &Path) -> Result<Self, NoFollowError> {
        let path_bytes = path.as_os_str().as_bytes();
        if path_bytes.contains(&0) {
            return Err(NoFollowError::Unsupported {
                path: path.to_path_buf(),
                reason: "path contains an interior NUL byte",
            });
        }

        let components: Vec<Component> = path.components().collect();
        for component in &components {
            if matches!(component, Component::Prefix(_)) {
                return Err(NoFollowError::Unsupported {
                    path: path.to_path_buf(),
                    reason: "non-Unix path prefix",
                });
            }
        }
        let Some(Component::Normal(leaf_os)) = components.last() else {
            return Err(NoFollowError::Unsupported {
                path: path.to_path_buf(),
                reason: "path has no final filename",
            });
        };
        let leaf = cstring(leaf_os).map_err(|_| NoFollowError::Unsupported {
            path: path.to_path_buf(),
            reason: "leaf name contains an interior NUL byte",
        })?;
        let parent_components = &components[..components.len() - 1];
        #[cfg(target_os = "linux")]
        let has_parent_dir = parent_components
            .iter()
            .any(|component| matches!(component, Component::ParentDir));

        let base = if path.is_absolute() {
            SearchDir::open_path(Path::new("/"))
        } else {
            SearchDir::open_path(Path::new("."))
        }
        .map_err(|source| NoFollowError::Unresolved {
            component: path.to_path_buf(),
            source,
        })?;

        // Linux fast path: one strict openat2 for a parent with no `..`.
        #[cfg(target_os = "linux")]
        if !has_parent_dir && platform::probe_openat2() {
            match open_parent_openat2(&base, parent_components, path) {
                Ok(Some(parent)) => {
                    return Ok(Self {
                        parent,
                        leaf,
                        path: path.to_path_buf(),
                    });
                }
                Ok(None) => {}
                Err(fast_error) => {
                    // A capable kernel refused the fast path. Re-walk from the
                    // same held base purely to name the failing component; a
                    // diagnostic success never turns the failed resolution into
                    // permission to stage.
                    return match walk_parent(&base, parent_components, &components, path) {
                        Ok(_) => Err(NoFollowError::Unresolved {
                            component: attempted_parent(path),
                            source: fast_error,
                        }),
                        Err(diagnostic) => Err(diagnostic),
                    };
                }
            }
        }

        let parent = walk_parent(&base, parent_components, &components, path)?;
        Ok(Self {
            parent,
            leaf,
            path: path.to_path_buf(),
        })
    }

    /// The path this handle was resolved from.
    pub fn path(&self) -> &Path {
        &self.path
    }

    /// The leaf name.
    pub fn leaf(&self) -> &OsStr {
        OsStr::from_bytes(self.leaf.to_bytes())
    }

    /// Classify the leaf with `fstatat(parent_fd, leaf, AT_SYMLINK_NOFOLLOW)`.
    pub fn leaf_kind(&self) -> Result<LeafKind, NoFollowError> {
        let stat =
            stat_at(self.parent.raw(), &self.leaf).map_err(|source| NoFollowError::Unresolved {
                component: self.path.clone(),
                source,
            })?;
        Ok(kind_from_mode(stat_mode(&stat)))
    }

    /// `fstatat(parent_fd, leaf, AT_SYMLINK_NOFOLLOW)`, retaining regular
    /// kind/dev/ino/full mode.
    ///
    /// This does not open the leaf for read: owned `0200` and `0000` sources
    /// remain linkable. A symlink leaf maps to [`NoFollowError::Symlink`], any
    /// other non-regular leaf to [`NoFollowError::NonRegular`].
    pub fn classify_regular(self) -> Result<NoFollowFile, NoFollowError> {
        let stat =
            stat_at(self.parent.raw(), &self.leaf).map_err(|source| NoFollowError::Unresolved {
                component: self.path.clone(),
                source,
            })?;
        let kind = kind_from_mode(stat_mode(&stat));
        match kind {
            LeafKind::Regular => Ok(NoFollowFile {
                parent: self.parent,
                leaf: self.leaf,
                path: self.path,
                dev: stat_dev(&stat),
                ino: stat_ino(&stat),
                mode: stat_mode(&stat),
            }),
            LeafKind::Symlink => Err(NoFollowError::Symlink {
                component: self.path,
            }),
            other => Err(NoFollowError::NonRegular {
                path: self.path,
                kind: other,
            }),
        }
    }
}

impl NoFollowFile {
    /// Resolved source path, for context and publication only, never leaf I/O.
    pub fn path(&self) -> &Path {
        &self.path
    }

    /// Resolved raw-byte leaf used by `linkat`.
    pub fn leaf(&self) -> &OsStr {
        OsStr::from_bytes(self.leaf.to_bytes())
    }

    /// `st_dev` of the classified source.
    pub fn device(&self) -> u64 {
        self.dev
    }

    /// `st_ino` of the classified source.
    pub fn inode(&self) -> u64 {
        self.ino
    }

    /// Full permission bits (`st_mode & 0o7777`) from classification.
    pub fn permissions(&self) -> u32 {
        self.mode & 0o7777
    }

    /// Whether the *held* parent directory is writable by a principal other
    /// than the caller.
    ///
    /// The stable invariant is **ownership**: only privilege can change a
    /// directory's `st_uid`, whereas its owner can `chmod` its mode at any time,
    /// so "not group/other-writable" does **not** by itself mean "no other
    /// principal can write". The predicate is therefore
    /// `parent.st_uid != geteuid() || (parent.st_mode & 0o022) != 0`, plus, on
    /// Darwin, a non-caller `ACL_TYPE_EXTENDED` grant that can create, rename or
    /// remove an entry **or** change the directory's own permissions/ownership.
    /// It reads the `st_uid`/`st_mode` (and ACL) of the retained parent
    /// descriptor, never a pathname, so a permission change during the window
    /// cannot defeat the decision: a foreign-owned parent always triggers the
    /// strict check regardless of its current mode. A permission-synthesizing
    /// mount that maps `uid=` to the mounter (the caller) reports the caller as
    /// owner and a `umask=022`-style parent as `0755`, so it is not
    /// group/other-writable, presents no extended ACL, and skips the gate as
    /// before. The sticky bit is not treated as mitigating.
    pub fn parent_is_foreign_writable(&self) -> io::Result<bool> {
        fd_is_foreign_writable(self.parent.raw())
    }

    /// `mkdirat` relative to the held parent; return descriptor-relative
    /// ownership.
    ///
    /// The D5 parent-writability gate is evaluated here from the held parent fd,
    /// and the pinned descriptor's ownership/mode/ACL validation runs only when
    /// it is true.
    pub fn create_stage_beside(&self) -> Result<SourceParentStage, StageCreateError> {
        self.create_stage_beside_impl(None, None, false, false, false)
    }

    /// Test seam for [`Self::create_stage_beside`]: override the observed
    /// mode/owner of the pinned stage descriptor, force the D5 gate, or plant a
    /// post-anchor swap or a redirected ancestor.
    ///
    /// Only compiled under `cfg(any(test, feature = "test-internals"))`; it is
    /// not part of the shipping API.
    #[cfg(any(test, feature = "test-internals"))]
    pub fn create_stage_beside_with_override(
        &self,
        overrides: StageOverrides,
    ) -> Result<SourceParentStage, StageCreateError> {
        self.create_stage_beside_impl(
            overrides.mode,
            overrides.uid,
            overrides.force_foreign_writable,
            overrides.swap_after_anchor,
            overrides.redirect_ancestor,
        )
    }

    /// [`Self::create_stage_beside`] with the test overrides plumbed as plain
    /// primitives, so the production entry point never names a gated seam type.
    fn create_stage_beside_impl(
        &self,
        override_mode: Option<u32>,
        override_uid: Option<libc::uid_t>,
        force_foreign_writable: bool,
        swap_after_anchor: bool,
        redirect_ancestor: bool,
    ) -> Result<SourceParentStage, StageCreateError> {
        let parent_path = self
            .path
            .parent()
            .map(Path::to_path_buf)
            .unwrap_or_else(|| PathBuf::from("."));

        // Test hook: redirect the resolved ancestor before any `mkdirat`, so the
        // stage must be created through the held parent descriptor rather than
        // the (now decoy) path.
        if redirect_ancestor {
            #[cfg(any(test, feature = "test-internals"))]
            redirect_ancestor_for_test(&parent_path);
        }

        let mut last_error: Option<io::Error> = None;
        // Evaluate the D5 gate once, from the *held* parent descriptor, before any
        // stage directory is created. Ownership is stable (only privilege can
        // change `st_uid`), so reading it here cannot be defeated by a permission
        // change during the creation window.
        let gate = force_foreign_writable || self.parent_is_foreign_writable().unwrap_or(true);
        for _ in 0..STAGE_NAME_ATTEMPTS {
            let name_os = random_stage_name();
            let name = cstring(&name_os).expect("generated stage name has no NUL");
            let child_path = parent_path.join(&name_os);
            let admin_fd = match create_dir_umask_safe(self.parent.raw(), &name, 0o700) {
                Ok(fd) => fd,
                Err(error) if error.source.raw_os_error() == Some(libc::EEXIST) => {
                    last_error = Some(error.source);
                    continue;
                }
                Err(error) => {
                    // A failure after `mkdirat` succeeded leaves a directory we
                    // could not acquire; report its locator rather than hiding it.
                    return Err(StageCreateError {
                        operation: "create source-parent stage directory",
                        source: error.source,
                        retained: error.created.then_some((child_path, None)),
                    });
                }
            };
            let stat = match fstat(admin_fd.as_raw_fd()) {
                Ok(stat) => stat,
                Err(error) => {
                    return Err(StageCreateError {
                        operation: "fstat new source-parent stage directory",
                        source: error,
                        retained: Some((child_path, None)),
                    });
                }
            };
            let observed_mode = override_mode.unwrap_or_else(|| stat_mode(&stat));
            if let Err(source) = validate_pinned_stage(
                admin_fd.as_raw_fd(),
                &stat,
                observed_mode,
                override_uid,
                gate,
            ) {
                return Err(StageCreateError {
                    operation: "validate pinned source-parent stage directory",
                    source,
                    retained: Some((child_path, Some(identity_from_stat(&stat)))),
                });
            }

            let admin = file_from_owned_fd(admin_fd);
            let root = match NoFollowDir::from_admin(admin, child_path.clone()) {
                Ok(root) => root,
                Err(source) => {
                    return Err(StageCreateError {
                        operation: "anchor new source-parent stage directory",
                        source,
                        retained: Some((child_path, Some(identity_from_stat(&stat)))),
                    });
                }
            };
            let identity = root.identity();
            let parent = self.parent.try_clone().map_err(|source| StageCreateError {
                operation: "retain source parent descriptor for stage cleanup",
                source,
                retained: Some((child_path.clone(), Some(identity))),
            })?;

            // Test hook: after the first anchor, swap the stage root by name and
            // plant a decoy. Population must continue through the held `root`
            // descriptor, so the decoy never receives the staged entry.
            if swap_after_anchor {
                #[cfg(any(test, feature = "test-internals"))]
                swap_stage_root_after_anchor_for_test(&child_path);
            }

            return Ok(SourceParentStage {
                parent,
                root,
                tag: None,
                name,
                identity,
                leaf: None,
                armed: true,
            });
        }

        Err(StageCreateError {
            operation: "create source-parent stage directory",
            source: last_error.unwrap_or_else(|| {
                io::Error::new(io::ErrorKind::AlreadyExists, "no unused stage name found")
            }),
            retained: None,
        })
    }

    /// Hard-link the classified source into `dir` as `name`.
    ///
    /// Uses `linkat(parent_fd, leaf, dir_fd, name, 0)`, then requires the staged
    /// entry's `(st_dev, st_ino)` and regular kind, read with
    /// `fstatat(dir_fd, name, AT_SYMLINK_NOFOLLOW)`, to equal the source
    /// snapshot. On mismatch or a failed stat it attempts `unlinkat` and returns
    /// the actual cleanup outcome; neither outcome implies removal succeeded.
    pub fn link_into(&self, dir: &NoFollowDir, name: &OsStr) -> Result<(), StageError> {
        self.link_into_impl(dir, name, None, None)
    }

    /// [`Self::link_into`] with test-only fault injection.
    ///
    /// Only compiled under `cfg(any(test, feature = "test-internals"))`; it is
    /// not part of the shipping API.
    #[cfg(any(test, feature = "test-internals"))]
    pub fn link_into_with_faults(
        &self,
        dir: &NoFollowDir,
        name: &OsStr,
        faults: LinkFaults,
    ) -> Result<(), StageError> {
        self.link_into_impl(dir, name, faults.verify_stat_errno, faults.unlink_errno)
    }

    /// [`Self::link_into`] with the test faults plumbed as plain primitives, so
    /// the production entry point never names a gated seam type.
    fn link_into_impl(
        &self,
        dir: &NoFollowDir,
        name: &OsStr,
        verify_stat_errno: Option<i32>,
        unlink_errno: Option<i32>,
    ) -> Result<(), StageError> {
        let name = cstring(name).map_err(StageError::Link)?;
        let ret = unsafe {
            libc::linkat(
                self.parent.raw(),
                self.leaf.as_ptr(),
                dir.anchor.raw(),
                name.as_ptr(),
                0,
            )
        };
        if ret < 0 {
            return Err(StageError::Link(io::Error::last_os_error()));
        }
        let verified = match verify_stat_errno {
            Some(errno) => Err(io::Error::from_raw_os_error(errno)),
            None => stat_at(dir.anchor.raw(), &name),
        };
        match verified {
            Err(source) => {
                let cleanup = cleanup_entry_with_unlink(dir, &name, unlink_errno);
                Err(StageError::Unverifiable { source, cleanup })
            }
            Ok(stat) => {
                let same = kind_from_mode(stat_mode(&stat)) == LeafKind::Regular
                    && stat_dev(&stat) == self.dev
                    && stat_ino(&stat) == self.ino;
                if same {
                    Ok(())
                } else {
                    let cleanup = cleanup_entry_with_unlink(dir, &name, unlink_errno);
                    Err(StageError::SourceChanged { cleanup })
                }
            }
        }
    }

    /// Lazily open the leaf, verify it, then copy it into `dir` as `name`.
    ///
    /// Opens the source `O_RDONLY|O_NOFOLLOW|O_NONBLOCK|O_CLOEXEC`, `fstat`s it,
    /// requires regular kind and the classified dev/ino, then copies that fd.
    /// The destination is created with `O_WRONLY|O_CREAT|O_EXCL|O_NOFOLLOW` at
    /// `0600` and `fchmod`ed to the full source mode **after** the write.
    pub fn copy_into(&self, dir: &NoFollowDir, name: &OsStr) -> Result<(), CopyError> {
        self.copy_into_impl(dir, name, None, None, false, false)
    }

    /// [`Self::copy_into`] with test-only fault injection.
    ///
    /// Only compiled under `cfg(any(test, feature = "test-internals"))`; it is
    /// not part of the shipping API.
    #[cfg(any(test, feature = "test-internals"))]
    pub fn copy_into_with_faults(
        &self,
        dir: &NoFollowDir,
        name: &OsStr,
        faults: CopyFaults,
    ) -> Result<(), CopyError> {
        self.copy_into_impl(
            dir,
            name,
            faults.open_errno,
            faults.stat_errno,
            faults.non_regular,
            faults.changed,
        )
    }

    /// [`Self::copy_into`] with the test faults plumbed as plain primitives, so
    /// the production entry point never names a gated seam type.
    fn copy_into_impl(
        &self,
        dir: &NoFollowDir,
        name: &OsStr,
        open_errno: Option<i32>,
        stat_errno: Option<i32>,
        non_regular: bool,
        changed: bool,
    ) -> Result<(), CopyError> {
        if let Some(errno) = open_errno {
            return Err(CopyError::Source(CopySourceError::Open(
                io::Error::from_raw_os_error(errno),
            )));
        }
        let src_fd = unsafe {
            libc::openat(
                self.parent.raw(),
                self.leaf.as_ptr(),
                libc::O_RDONLY | libc::O_NOFOLLOW | libc::O_NONBLOCK | libc::O_CLOEXEC,
            )
        };
        if src_fd < 0 {
            return Err(CopyError::Source(CopySourceError::Open(
                io::Error::last_os_error(),
            )));
        }
        let mut src = unsafe { File::from_raw_fd(src_fd) };
        let stat = match stat_errno {
            Some(errno) => Err(CopyError::Source(CopySourceError::Stat(
                io::Error::from_raw_os_error(errno),
            ))),
            None => fstat(src.as_raw_fd())
                .map_err(|error| CopyError::Source(CopySourceError::Stat(error))),
        }?;
        if non_regular {
            return Err(CopyError::Source(CopySourceError::NonRegular));
        }
        if changed {
            return Err(CopyError::Source(CopySourceError::Changed));
        }
        if kind_from_mode(stat_mode(&stat)) != LeafKind::Regular {
            return Err(CopyError::Source(CopySourceError::NonRegular));
        }
        if stat_dev(&stat) != self.dev || stat_ino(&stat) != self.ino {
            return Err(CopyError::Source(CopySourceError::Changed));
        }

        let name = cstring(name).map_err(|error| CopyError::Operation {
            operation: "resolve copy destination name",
            source: error,
            cleanup: None,
        })?;
        let dst_fd = unsafe {
            libc::openat(
                dir.anchor.raw(),
                name.as_ptr(),
                libc::O_WRONLY | libc::O_CREAT | libc::O_EXCL | libc::O_NOFOLLOW | libc::O_CLOEXEC,
                0o600,
            )
        };
        if dst_fd < 0 {
            return Err(CopyError::Operation {
                operation: "create copy destination",
                source: io::Error::last_os_error(),
                cleanup: None,
            });
        }
        let mut dst = unsafe { File::from_raw_fd(dst_fd) };
        if let Err(source) = io::copy(&mut src, &mut dst) {
            // Capture the real copy errno before cleanup can overwrite it.
            let cleanup = cleanup_entry(dir, &name);
            return Err(CopyError::Operation {
                operation: "copy file contents",
                source,
                cleanup: Some(cleanup),
            });
        }
        // `fchmod` the *same* destination descriptor. The `O_EXCL` destination was
        // created at `0600 & !umask`; a non-root caller under a restrictive umask
        // can write through the original fd but cannot reopen it (by name, for
        // read) to change its mode, and reopening the name would re-resolve it.
        let ret = unsafe { libc::fchmod(dst.as_raw_fd(), (self.mode & 0o7777) as libc::mode_t) };
        if ret < 0 {
            // Capture the real `fchmod` errno before cleanup can overwrite it.
            let source = io::Error::last_os_error();
            let cleanup = cleanup_entry(dir, &name);
            return Err(CopyError::Operation {
                operation: "set copy destination mode",
                source,
                cleanup: Some(cleanup),
            });
        }
        Ok(())
    }
}

impl NoFollowDir {
    /// Open a directory the caller already owns (its own state directory).
    pub fn open(path: &Path) -> io::Result<Self> {
        let c = cstring(path.as_os_str())?;
        let fd = unsafe { libc::open(c.as_ptr(), ADMIN_OPEN_FLAGS) };
        if fd < 0 {
            return Err(io::Error::last_os_error());
        }
        let admin = unsafe { File::from_raw_fd(fd) };
        Self::from_admin(admin, path.to_path_buf())
    }

    /// Build from an already-open administrative descriptor, deriving the
    /// search anchor from its `.` and requiring identical identities.
    fn from_admin(admin: File, path: PathBuf) -> io::Result<Self> {
        let dot = c".";
        let anchor_fd = unsafe { libc::openat(admin.as_raw_fd(), dot.as_ptr(), SEARCH_OPEN_FLAGS) };
        if anchor_fd < 0 {
            return Err(io::Error::last_os_error());
        }
        let anchor = SearchDir {
            fd: unsafe { OwnedFd::from_raw_fd(anchor_fd) },
        };
        let admin_stat = fstat(admin.as_raw_fd())?;
        let anchor_stat = fstat(anchor.raw())?;
        if admin_stat.st_dev != anchor_stat.st_dev || admin_stat.st_ino != anchor_stat.st_ino {
            return Err(io::Error::other(
                "administrative and search descriptors resolve to different directories",
            ));
        }
        Ok(Self {
            anchor,
            admin,
            path,
            identity: identity_from_stat(&admin_stat),
        })
    }

    /// The identity (dev/ino) observed when this directory's descriptor was
    /// acquired.
    ///
    /// The value is captured at construction, so it is always a real observed
    /// identity and never a fabricated `(0, 0)` placeholder.
    pub fn identity(&self) -> StageIdentity {
        self.identity
    }

    /// `mkdirat(dir_fd, name, mode)`, then acquire and pin the owned directory
    /// with a safe owner-masked-umask bootstrap.
    ///
    /// The D5 gate applies to `create_stage_beside`'s attacker-writable parent,
    /// not to a tag created inside an already-pinned caller-owned stage root.
    pub fn create_subdir(&self, name: &OsStr, mode: u32) -> Result<Self, StageCreateError> {
        let name = cstring(name).map_err(|source| StageCreateError {
            operation: "resolve subdirectory name",
            source,
            retained: None,
        })?;
        let child_path = self.path.join(OsStr::from_bytes(name.to_bytes()));
        let admin_fd = create_dir_umask_safe(self.anchor.raw(), &name, mode).map_err(|error| {
            StageCreateError {
                operation: "create stage subdirectory",
                source: error.source,
                retained: error.created.then_some((child_path.clone(), None)),
            }
        })?;
        let admin = file_from_owned_fd(admin_fd);
        let dir =
            Self::from_admin(admin, child_path.clone()).map_err(|source| StageCreateError {
                operation: "anchor stage subdirectory",
                source,
                retained: Some((child_path.clone(), None)),
            })?;
        // Only owned stage directories get a readable admin fd, and only they
        // are restricted; the search anchor is never fchmod'd (it fails on Linux
        // O_PATH with EBADF).
        dir.restrict_to_owner().map_err(|source| StageCreateError {
            operation: "restrict stage subdirectory to its owner",
            source,
            retained: Some((child_path, Some(dir.identity()))),
        })?;
        Ok(dir)
    }

    /// `fchmod` this directory's administrative fd to `0o700`.
    pub fn restrict_to_owner(&self) -> io::Result<()> {
        let ret = unsafe { libc::fchmod(self.admin.as_raw_fd(), 0o700 as libc::mode_t) };
        if ret < 0 {
            return Err(io::Error::last_os_error());
        }
        Ok(())
    }

    /// Remove an empty child directory by name, relative to the held anchor.
    ///
    /// Used to withdraw an empty `linkat` destination after a failed attempt;
    /// it is never recursive and fails on a non-empty directory.
    pub fn remove_child(&self, name: &OsStr) -> io::Result<()> {
        let name = cstring(name)?;
        let ret = unsafe { libc::unlinkat(self.anchor.raw(), name.as_ptr(), libc::AT_REMOVEDIR) };
        if ret < 0 {
            return Err(io::Error::last_os_error());
        }
        Ok(())
    }

    /// The path this descriptor was reached by. For messages and for the value
    /// handed to the VMM only.
    pub fn path(&self) -> &Path {
        &self.path
    }

    /// Raw search-anchor fd, internal to the module.
    fn anchor(&self) -> RawFd {
        self.anchor.raw()
    }
}

impl SourceParentStage {
    /// The stage tag directory (once created) or the stage root.
    pub fn dir(&self) -> &NoFollowDir {
        self.tag.as_ref().unwrap_or(&self.root)
    }

    /// The last-known locator of the stage root.
    pub fn path(&self) -> &Path {
        self.root.path()
    }

    /// The pinned identity of the stage root.
    pub fn identity(&self) -> StageIdentity {
        self.identity
    }

    /// Create the `<tag>` directory inside the stage root and pin it.
    pub fn create_tag(&mut self, tag: &OsStr) -> Result<(), StageCreateError> {
        let dir = self.root.create_subdir(tag, 0o700)?;
        self.tag = Some(dir);
        Ok(())
    }

    /// Record the leaf name linked into the tag directory, for cleanup.
    pub fn set_leaf(&mut self, leaf: &OsStr) {
        if let Ok(c) = cstring(leaf) {
            self.leaf = Some(c);
        }
    }

    /// Stop owning the stage: the directory is left in place.
    pub fn keep(mut self) {
        self.armed = false;
    }

    /// Remove the owned objects through held descriptors.
    ///
    /// Only recorded leaf names and the tag/root names are removed. The root
    /// name is removed only when its held-parent stat still matches the pinned
    /// identity **and** a read of the held parent descriptor shows no other
    /// principal could rename entries (mode, sticky, and, on Darwin, extended
    /// ACL rights). A same-name replacement, a renamed original, or a parent
    /// whose safety could not be determined is retained and reported rather
    /// than deleted. No recursive walk, and no unconditional claim that a
    /// replacement was preserved: conservative retention is normal possible
    /// behaviour, not a guarantee that an empty root is removed.
    pub fn close(mut self) -> Result<(), StageCleanupError> {
        let armed = self.armed;
        self.armed = false;
        if armed { self.cleanup_owned() } else { Ok(()) }
    }

    /// The descriptor-relative cleanup body, shared by [`Self::close`] and its
    /// `Drop` impl.
    ///
    /// Leaf removal and directory removal both go through held descriptors. A
    /// tag/root name is removed only when the directory it now names is still
    /// the pinned object and the held parent is not swappable by another
    /// principal. A same-name replacement is preserved and reported, as is a
    /// renamed original we can no longer unlink by its old name; a root whose
    /// parent is foreign-swappable — or whose safety could not be determined —
    /// is retained and reported instead of removed, because a stat match cannot
    /// be tied to the later `unlinkat`.
    fn cleanup_owned(&mut self) -> Result<(), StageCleanupError> {
        let mut retained = Vec::new();
        if let (Some(tag), Some(leaf)) = (&self.tag, &self.leaf) {
            // The held tag descriptor is unaffected by a same-name replacement,
            // so the leaf is always removed through it.
            let ret = unsafe { libc::unlinkat(tag.anchor(), leaf.as_ptr(), 0) };
            if ret < 0 {
                let error = io::Error::last_os_error();
                if error.raw_os_error() != Some(libc::ENOENT) {
                    retained.push((
                        tag.path().join(OsStr::from_bytes(leaf.to_bytes())),
                        tag.identity(),
                        error,
                    ));
                }
            }
        }
        if let Some(tag) = self.tag.take() {
            let name = tag_name(&tag, self.root.path());
            let identity = tag.identity();
            match stat_at(self.root.anchor(), &name) {
                Ok(stat) if stat_dev(&stat) == identity.dev && stat_ino(&stat) == identity.ino => {
                    let ret = unsafe {
                        libc::unlinkat(self.root.anchor(), name.as_ptr(), libc::AT_REMOVEDIR)
                    };
                    if ret < 0 {
                        let error = io::Error::last_os_error();
                        if error.raw_os_error() != Some(libc::ENOENT) {
                            retained.push((tag.path().to_path_buf(), identity, error));
                        }
                    }
                }
                Ok(_) => retained.push((
                    tag.path().to_path_buf(),
                    identity,
                    io::Error::other("tag name now names a replacement; not removing it"),
                )),
                Err(error) if error.raw_os_error() == Some(libc::ENOENT) => retained.push((
                    tag.path().to_path_buf(),
                    identity,
                    io::Error::other("tag directory was renamed away; retained, not removed"),
                )),
                Err(error) => retained.push((tag.path().to_path_buf(), identity, error)),
            }
        }
        // The root's name lives in the source parent. A stat match proves which
        // object was there, not which object `unlinkat` would remove a moment
        // later, so first ask whether another principal could swap it. The
        // decision reads the **held parent descriptor** so a Darwin extended ACL
        // is included; a stat or ACL read failure is not proof of safety, so it
        // is reported as an inability to determine rather than as an observed
        // permission fact.
        let parent_allows_swap = parent_allows_foreign_root_swap(self.parent.raw());
        match stat_at(self.parent.raw(), &self.name) {
            Ok(stat)
                if stat_dev(&stat) == self.identity.dev && stat_ino(&stat) == self.identity.ino =>
            {
                // Deterministic test hook: the swap lands here, in the real
                // window between the identity check and the removal decision.
                #[cfg(any(test, feature = "test-internals"))]
                swap_root_before_removal_for_test(&self.parent, self.root.path());

                match parent_allows_swap {
                    Ok(false) => {
                        let ret = unsafe {
                            libc::unlinkat(
                                self.parent.raw(),
                                self.name.as_ptr(),
                                libc::AT_REMOVEDIR,
                            )
                        };
                        if ret < 0 {
                            let error = io::Error::last_os_error();
                            if error.raw_os_error() != Some(libc::ENOENT) {
                                retained.push((
                                    self.root.path().to_path_buf(),
                                    self.identity,
                                    error,
                                ));
                            }
                        }
                    }
                    Ok(true) => {
                        // A foreign-swappable parent cannot tie the checked
                        // identity to the removal, so retain and report rather
                        // than risk deleting a same-name replacement.
                        retained.push((
                            self.root.path().to_path_buf(),
                            self.identity,
                            io::Error::other(
                                "source parent is writable by another principal; the stage root was retained because its identity cannot be tied to a removal",
                            ),
                        ));
                    }
                    Err(error) => {
                        // The safety of removal could not be determined (stat or
                        // ACL read failed); retain and say so rather than claim
                        // an observed permission fact.
                        retained.push((
                            self.root.path().to_path_buf(),
                            self.identity,
                            io::Error::other(format!(
                                "could not determine whether the source parent is writable by another principal; the stage root was retained rather than risk removing a replacement: {error}"
                            )),
                        ));
                    }
                }
            }
            Ok(_) => retained.push((
                self.root.path().to_path_buf(),
                self.identity,
                io::Error::other("stage root name now names a replacement; not removing it"),
            )),
            Err(error) if error.raw_os_error() == Some(libc::ENOENT) => retained.push((
                self.root.path().to_path_buf(),
                self.identity,
                io::Error::other("stage root was renamed away; retained, not removed"),
            )),
            Err(error) => retained.push((self.root.path().to_path_buf(), self.identity, error)),
        }
        if retained.is_empty() {
            Ok(())
        } else {
            Err(StageCleanupError { retained })
        }
    }
}

impl SearchDir {
    fn open_path(path: &Path) -> io::Result<Self> {
        let c = cstring(path.as_os_str())?;
        let fd = unsafe { libc::open(c.as_ptr(), SEARCH_OPEN_FLAGS) };
        if fd < 0 {
            return Err(io::Error::last_os_error());
        }
        Ok(Self {
            fd: unsafe { OwnedFd::from_raw_fd(fd) },
        })
    }

    fn open_at(&self, name: &CStr) -> io::Result<Self> {
        let fd = unsafe { libc::openat(self.fd.as_raw_fd(), name.as_ptr(), SEARCH_OPEN_FLAGS) };
        if fd < 0 {
            return Err(io::Error::last_os_error());
        }
        Ok(Self {
            fd: unsafe { OwnedFd::from_raw_fd(fd) },
        })
    }

    fn try_clone(&self) -> io::Result<Self> {
        let fd = unsafe { libc::fcntl(self.fd.as_raw_fd(), libc::F_DUPFD_CLOEXEC, 0) };
        if fd < 0 {
            return Err(io::Error::last_os_error());
        }
        Ok(Self {
            fd: unsafe { OwnedFd::from_raw_fd(fd) },
        })
    }

    /// Verify this directory can be searched by the caller.
    ///
    /// A descriptor-relative `fstatat(fd, ".")` performs the kernel's search
    /// check on `fd`; on Linux this is not implied by a successful `O_PATH`
    /// `openat`, which is why the walk calls this before a `..` pop.
    fn check_searchable(&self) -> io::Result<()> {
        stat_at(self.raw(), c".").map(|_| ())
    }

    fn raw(&self) -> RawFd {
        self.fd.as_raw_fd()
    }
}

//--------------------------------------------------------------------------------------------------
// Trait Implementations
//--------------------------------------------------------------------------------------------------

impl Drop for SourceParentStage {
    /// Best-effort cleanup of an armed stage. This is **normal possible**
    /// cleanup, not a guarantee of removal: a conservative decision (a
    /// foreign-swappable parent, an undeterminable parent, or a replaced or
    /// renamed root) retains the root and only logs the retention, so a stage
    /// can legitimately survive a drop. Callers that need the retention
    /// reported should call [`SourceParentStage::close`].
    fn drop(&mut self) {
        if self.armed {
            self.armed = false;
            if let Err(error) = self.cleanup_owned() {
                tracing::warn!(
                    %error,
                    path = %self.root.path().display(),
                    "failed to clean up a source-parent file-mount stage on drop"
                );
            }
        }
    }
}

impl std::fmt::Display for NoFollowError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            NoFollowError::Symlink { component } => write!(
                f,
                "path resolves through a symlink at {}",
                component.display()
            ),
            NoFollowError::Unsupported { path, reason } => {
                write!(f, "unsupported path {}: {reason}", path.display())
            }
            NoFollowError::NonRegular { path, kind } => {
                write!(
                    f,
                    "path {} is not a regular file ({kind:?})",
                    path.display()
                )
            }
            NoFollowError::Unresolved { component, source } => {
                write!(f, "cannot resolve {}: {source}", component.display())
            }
        }
    }
}

impl std::error::Error for NoFollowError {
    fn source(&self) -> Option<&(dyn std::error::Error + 'static)> {
        match self {
            NoFollowError::Unresolved { source, .. } => Some(source),
            _ => None,
        }
    }
}

impl From<NoFollowError> for io::Error {
    fn from(error: NoFollowError) -> Self {
        match error {
            NoFollowError::Unresolved { source, .. } => source,
            other => io::Error::new(io::ErrorKind::InvalidInput, other.to_string()),
        }
    }
}

impl std::fmt::Display for StageCreateError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "{}: {}", self.operation, self.source)?;
        if let Some((path, identity)) = &self.retained {
            write!(f, " (retained {})", path.display())?;
            if let Some(identity) = identity {
                write!(f, " (dev={}, ino={})", identity.dev, identity.ino)?;
            }
        }
        Ok(())
    }
}

impl std::error::Error for StageCreateError {
    fn source(&self) -> Option<&(dyn std::error::Error + 'static)> {
        Some(&self.source)
    }
}

impl std::fmt::Display for StageCleanupError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(
            f,
            "could not remove {} stage object(s)",
            self.retained.len()
        )?;
        for (path, identity, error) in &self.retained {
            write!(
                f,
                "; {} (dev={}, ino={}): {error}",
                path.display(),
                identity.dev,
                identity.ino
            )?;
        }
        Ok(())
    }
}

impl std::error::Error for StageCleanupError {}

impl std::fmt::Display for StageError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            StageError::Link(error) => write!(f, "link failed: {error}"),
            StageError::SourceChanged { cleanup } => {
                write!(f, "source changed during staging ({cleanup})")
            }
            StageError::Unverifiable { source, cleanup } => {
                write!(f, "could not verify staged entry: {source} ({cleanup})")
            }
        }
    }
}

impl std::error::Error for StageError {
    fn source(&self) -> Option<&(dyn std::error::Error + 'static)> {
        match self {
            StageError::Link(error) => Some(error),
            StageError::Unverifiable { source, .. } => Some(source),
            StageError::SourceChanged { .. } => None,
        }
    }
}

impl std::fmt::Display for CleanupOutcome {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            CleanupOutcome::Removed => write!(f, "attempted entry removed"),
            CleanupOutcome::Retained {
                target,
                source,
                stage,
                identity,
            } => {
                write!(
                    f,
                    "could not remove {}: {source}; stage retained at {} (dev={}, ino={})",
                    target.display(),
                    stage.display(),
                    identity.dev,
                    identity.ino
                )
            }
        }
    }
}

impl std::fmt::Display for CopySourceError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            CopySourceError::Open(error) => write!(f, "open source for copy: {error}"),
            CopySourceError::Stat(error) => write!(f, "fstat copy source: {error}"),
            CopySourceError::Changed => write!(f, "source identity differs from classification"),
            CopySourceError::NonRegular => write!(f, "source is no longer regular"),
        }
    }
}

impl std::error::Error for CopySourceError {
    fn source(&self) -> Option<&(dyn std::error::Error + 'static)> {
        match self {
            CopySourceError::Open(error) | CopySourceError::Stat(error) => Some(error),
            _ => None,
        }
    }
}

impl std::fmt::Display for CopyError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            CopyError::Source(error) => write!(f, "{error}"),
            CopyError::Operation {
                operation,
                source,
                cleanup,
            } => {
                write!(f, "{operation}: {source}")?;
                if let Some(cleanup) = cleanup {
                    write!(f, " ({cleanup})")?;
                }
                Ok(())
            }
        }
    }
}

impl std::error::Error for CopyError {
    fn source(&self) -> Option<&(dyn std::error::Error + 'static)> {
        match self {
            CopyError::Source(error) => Some(error),
            CopyError::Operation { source, .. } => Some(source),
        }
    }
}

//--------------------------------------------------------------------------------------------------
// Functions: Helpers
//--------------------------------------------------------------------------------------------------

/// The parent path a failed resolution was attempting, for diagnostics when the
/// fast path cannot name the failing component.
#[cfg(target_os = "linux")]
fn attempted_parent(path: &Path) -> PathBuf {
    path.parent().map(Path::to_path_buf).unwrap_or_default()
}

/// Open the parent of a `..`-free path with the strict Linux `openat2` call.
///
/// Returns `Ok(None)` when the syscall is unavailable (falling back to the
/// portable walk) and `Err` for any other fast-path failure.
#[cfg(target_os = "linux")]
fn open_parent_openat2(
    base: &SearchDir,
    parent_components: &[Component],
    path: &Path,
) -> io::Result<Option<SearchDir>> {
    let mut rel = PathBuf::new();
    for component in parent_components {
        match component {
            Component::Normal(name) => rel.push(name),
            Component::CurDir | Component::RootDir => {}
            Component::ParentDir | Component::Prefix(_) => return Ok(None),
        }
    }
    if rel.as_os_str().is_empty() {
        return Ok(Some(base.try_clone()?));
    }
    let rel_c = cstring(rel.as_os_str())
        .map_err(|_| io::Error::new(io::ErrorKind::InvalidInput, "path contains a NUL byte"))?;
    let fd =
        platform::open_beneath_strict(base.raw(), rel_c.as_ptr(), libc::O_PATH | libc::O_DIRECTORY);
    if fd < 0 {
        let error = io::Error::last_os_error();
        if error.raw_os_error() == Some(libc::ENOSYS) {
            return Ok(None);
        }
        return Err(error);
    }
    Ok(Some(SearchDir {
        fd: unsafe { OwnedFd::from_raw_fd(fd) },
    }))
}

/// The portable no-follow component walk, used as the functional fallback and
/// for component diagnostics after a failed fast path.
fn walk_parent(
    base: &SearchDir,
    parent_components: &[Component],
    all_components: &[Component],
    path: &Path,
) -> Result<SearchDir, NoFollowError> {
    #[cfg(test)]
    PORTABLE_WALK_CALLS.with(|calls| calls.set(calls.get() + 1));

    let mut stack: Vec<(SearchDir, bool)> = vec![(
        base.try_clone()
            .map_err(|source| NoFollowError::Unresolved {
                component: path.to_path_buf(),
                source,
            })?,
        false,
    )];

    for (index, component) in parent_components.iter().enumerate() {
        match component {
            Component::RootDir | Component::CurDir => {}
            Component::Prefix(_) => unreachable!("prefix rejected during validation"),
            Component::Normal(name) => {
                let name_c = cstring(name).map_err(|_| NoFollowError::Unsupported {
                    path: path.to_path_buf(),
                    reason: "component contains an interior NUL byte",
                })?;
                let parent = &stack.last().expect("stack is never empty").0;
                match parent.open_at(&name_c) {
                    Ok(dir) => stack.push((dir, true)),
                    Err(source) => {
                        return Err(classify_walk_error(
                            parent,
                            &name_c,
                            all_components,
                            index,
                            source,
                        ));
                    }
                }
            }
            Component::ParentDir => {
                let popable = stack.last().expect("stack is never empty").1;
                if popable {
                    // Popping a component skips the kernel's search check for the
                    // directory being left (`a/../file` must fail when `a` is not
                    // searchable). On Linux an `O_PATH` directory can be opened
                    // without search permission, so verify it explicitly before
                    // discarding it.
                    let dir = &stack.last().expect("stack is never empty").0;
                    if let Err(source) = dir.check_searchable() {
                        return Err(classify_walk_error(
                            dir,
                            c".",
                            all_components,
                            index,
                            source,
                        ));
                    }
                    stack.pop();
                } else {
                    let dotdot = c"..";
                    let parent = &stack.last().expect("stack is never empty").0;
                    match parent.open_at(dotdot) {
                        Ok(dir) => stack.push((dir, false)),
                        Err(source) => {
                            return Err(classify_walk_error(
                                parent,
                                dotdot,
                                all_components,
                                index,
                                source,
                            ));
                        }
                    }
                }
            }
        }
    }
    let (parent, _) = stack.pop().expect("stack is never empty");
    Ok(parent)
}

/// Map a failed component open to a symlink vs unresolvable error by stat'ing
/// the component with no-follow relative to its already-held parent.
fn classify_walk_error(
    parent: &SearchDir,
    name: &CStr,
    all_components: &[Component],
    index: usize,
    source: io::Error,
) -> NoFollowError {
    let component: PathBuf = all_components[..=index].iter().collect();
    match stat_at(parent.raw(), name) {
        Ok(stat) if kind_from_mode(stat_mode(&stat)) == LeafKind::Symlink => {
            NoFollowError::Symlink { component }
        }
        _ => NoFollowError::Unresolved { component, source },
    }
}

/// `fstatat(dirfd, name, AT_SYMLINK_NOFOLLOW)`.
fn stat_at(dirfd: RawFd, name: &CStr) -> io::Result<libc::stat> {
    let mut stat: libc::stat = unsafe { std::mem::zeroed() };
    let ret = unsafe { libc::fstatat(dirfd, name.as_ptr(), &mut stat, libc::AT_SYMLINK_NOFOLLOW) };
    if ret < 0 {
        return Err(io::Error::last_os_error());
    }
    Ok(stat)
}

/// `fstat(fd)`.
fn fstat(fd: RawFd) -> io::Result<libc::stat> {
    let mut stat: libc::stat = unsafe { std::mem::zeroed() };
    let ret = unsafe { libc::fstat(fd, &mut stat) };
    if ret < 0 {
        return Err(io::Error::last_os_error());
    }
    Ok(stat)
}

/// Extract the [`LeafKind`] from a raw `st_mode`.
fn kind_from_mode(mode: u32) -> LeafKind {
    let kind = mode & (libc::S_IFMT as u32);
    if kind == libc::S_IFREG as u32 {
        LeafKind::Regular
    } else if kind == libc::S_IFDIR as u32 {
        LeafKind::Directory
    } else if kind == libc::S_IFLNK as u32 {
        LeafKind::Symlink
    } else {
        LeafKind::Other
    }
}

#[allow(clippy::unnecessary_cast)]
fn stat_dev(stat: &libc::stat) -> u64 {
    stat.st_dev as u64
}

#[allow(clippy::unnecessary_cast)]
fn stat_ino(stat: &libc::stat) -> u64 {
    stat.st_ino as u64
}

#[allow(clippy::unnecessary_cast)]
fn stat_mode(stat: &libc::stat) -> u32 {
    stat.st_mode as u32
}

#[allow(clippy::unnecessary_cast)]
fn stat_uid(stat: &libc::stat) -> libc::uid_t {
    stat.st_uid
}

#[allow(clippy::unnecessary_cast, dead_code)]
fn stat_gid(stat: &libc::stat) -> libc::gid_t {
    stat.st_gid
}

/// D5 parent-writability predicate, read from a held directory descriptor.
///
/// Backing implementation for [`NoFollowFile::parent_is_foreign_writable`]. A
/// foreign-owner or group/other-writable parent triggers the strict check
/// regardless of its current mode; on Darwin a non-caller extended-ACL grant
/// that can add/rename entries or change the directory's own
/// permissions/ownership triggers it too. Cleanup uses the tighter
/// [`parent_allows_foreign_root_swap`] instead.
fn fd_is_foreign_writable(fd: RawFd) -> io::Result<bool> {
    let stat = fstat(fd)?;
    let euid = unsafe { libc::geteuid() };
    if stat_uid(&stat) != euid {
        return Ok(true);
    }
    if (stat_mode(&stat) & 0o022) != 0 {
        return Ok(true);
    }
    #[cfg(target_os = "macos")]
    {
        match acl_grants_foreign_write(fd, stat_uid(&stat)) {
            Ok(granted) => Ok(granted),
            Err(_) => Ok(true),
        }
    }
    #[cfg(not(target_os = "macos"))]
    {
        Ok(false)
    }
}

fn identity_from_stat(stat: &libc::stat) -> StageIdentity {
    StageIdentity {
        dev: stat_dev(stat),
        ino: stat_ino(stat),
    }
}

/// Whether a principal other than the caller could rename or replace the
/// caller's stage root between an identity check and its removal.
///
/// Cleanup cannot tie the identity it just observed to the object `unlinkat`
/// will remove, so when this is true the root is retained rather than deleted.
///
/// This predicate is deliberately **tighter** than the D5 gate
/// ([`fd_is_foreign_writable`]): the gate conservatively treats the sticky bit
/// as non-mitigating because applying the strict check is free, but the cost of
/// a false positive here is leaking a stage directory. In a sticky directory a
/// non-owner cannot rename the caller's freshly created entry, so the
/// check/unlink race is unreachable **unless** a Darwin extended ACL grants the
/// principal an overriding right: XNU's `vnode_authorize_delete` gives node
/// `DELETE` and parent `DELETE_CHILD` ACEs priority over the sticky restriction,
/// a same-parent `renameatx_np(RENAME_SWAP)` needs only `DELETE_CHILD` on the
/// parent, and a foreign governance grant can widen access after the check. The
/// sticky exception therefore applies only when the parent carries no foreign
/// ACL grant of a swap, delete, search, or governance right. Root is outside the
/// threat model: it can remove the entry regardless, so a root-owned parent is
/// only counted when it is group/other-writable without the sticky bit.
///
/// Read from the **held parent descriptor** so the ACL snapshot belongs to the
/// directory the removal will use. A failed `fstat` or ACL read is returned as
/// an error; the caller treats that as unsafe and retains.
fn parent_allows_foreign_root_swap(fd: RawFd) -> io::Result<bool> {
    let stat = fstat(fd)?;
    let euid = unsafe { libc::geteuid() };
    let owner = stat_uid(&stat);
    let mode = stat_mode(&stat) & 0o7777;
    let sticky = mode & 0o1000 != 0;
    // A foreign non-root owner can rename entries regardless of the mode (and
    // can clear a sticky bit it set itself).
    if owner != euid && owner != 0 {
        return Ok(true);
    }
    #[cfg(target_os = "macos")]
    {
        // A foreign ACL grant of a create/rename/delete/search or governance
        // right makes the parent swappable even when the mode says otherwise,
        // and overrides the sticky carve-out below. Fail closed on a read error.
        if acl_grants_foreign_swap(fd, owner)? {
            return Ok(true);
        }
    }
    // Group/other write without the sticky bit lets any other principal rename.
    Ok((mode & 0o022) != 0 && !sticky)
}

/// Validate the pinned stage descriptor when the D5 gate applies.
///
/// `observed_mode` and `observed_uid` let a test simulate a pinned descriptor on
/// a permission-synthesizing filesystem or a foreign-owned decoy without
/// changing the real directory; production passes the real stat values.
fn validate_pinned_stage(
    fd: RawFd,
    stat: &libc::stat,
    observed_mode: u32,
    observed_uid: Option<libc::uid_t>,
    gate: bool,
) -> io::Result<()> {
    if kind_from_mode(stat_mode(stat)) != LeafKind::Directory {
        return Err(io::Error::other("pinned stage path is not a directory"));
    }
    if !gate {
        return Ok(());
    }
    let euid = unsafe { libc::geteuid() };
    let uid = observed_uid.unwrap_or_else(|| stat_uid(stat));
    if uid != euid {
        return Err(io::Error::new(
            io::ErrorKind::PermissionDenied,
            format!("pinned stage directory owned by uid {uid}, expected effective uid {euid}"),
        ));
    }
    if (observed_mode & 0o7777) != 0o700 {
        return Err(io::Error::new(
            io::ErrorKind::PermissionDenied,
            format!(
                "pinned stage directory mode {:04o}, expected 0700",
                observed_mode & 0o7777
            ),
        ));
    }
    #[cfg(target_os = "macos")]
    {
        // Distinct from the parent-writability predicate: on the strict pinned
        // root, reject any non-owner granting entry (not only write grants), as
        // well as any entry that could let a principal change this directory's
        // own permissions or ownership. A per-entry ACL query failure is
        // reported as an error and handled fail-closed by the caller.
        match acl_has_foreign_grant(fd, stat_uid(stat)) {
            Ok(false) => {}
            Ok(true) => {
                return Err(io::Error::new(
                    io::ErrorKind::PermissionDenied,
                    "pinned stage directory carries a non-owner extended ACL grant",
                ));
            }
            Err(error) => {
                return Err(io::Error::new(
                    io::ErrorKind::PermissionDenied,
                    format!("could not validate the pinned stage directory ACL: {error}"),
                ));
            }
        }
    }
    Ok(())
}

/// Unlink an attempted entry from a stage directory and report the outcome.
fn cleanup_entry(dir: &NoFollowDir, name: &CStr) -> CleanupOutcome {
    cleanup_entry_with_unlink(dir, name, None)
}

/// Unlink an attempted entry, optionally forcing the `unlinkat` to fail with
/// `unlink_errno` so the retained-entry branch is reachable deterministically.
fn cleanup_entry_with_unlink(
    dir: &NoFollowDir,
    name: &CStr,
    unlink_errno: Option<i32>,
) -> CleanupOutcome {
    let error = match unlink_errno {
        Some(errno) => Some(io::Error::from_raw_os_error(errno)),
        None => {
            let ret = unsafe { libc::unlinkat(dir.anchor(), name.as_ptr(), 0) };
            if ret == 0 {
                None
            } else {
                Some(io::Error::last_os_error())
            }
        }
    };
    match error {
        None => CleanupOutcome::Removed,
        Some(source) => CleanupOutcome::Retained {
            target: dir.path().join(OsStr::from_bytes(name.to_bytes())),
            source,
            stage: dir.path().to_path_buf(),
            identity: dir.identity(),
        },
    }
}

/// The tag directory's own basename, for `unlinkat` through its parent.
fn tag_name(tag: &NoFollowDir, root: &Path) -> CString {
    let name = tag
        .path()
        .strip_prefix(root)
        .ok()
        .and_then(|relative| relative.file_name())
        .map(OsStr::to_os_string)
        .unwrap_or_else(|| OsString::from(""));
    cstring(&name).unwrap_or_else(|_| c"".to_owned())
}

fn cstring(value: &OsStr) -> io::Result<CString> {
    CString::new(value.as_bytes()).map_err(|_| {
        io::Error::new(
            io::ErrorKind::InvalidInput,
            "path component contains an interior NUL byte",
        )
    })
}

fn file_from_owned_fd(fd: OwnedFd) -> File {
    unsafe { File::from_raw_fd(fd.into_raw_fd()) }
}

/// Correctly aligned storage for a single ancillary control message.
///
/// A bare `[u8; N]` does not guarantee the alignment `cmsghdr` requires, so the
/// control buffer is a struct whose first field is a `cmsghdr`.
#[repr(C)]
struct ControlBuffer {
    cmsg: libc::cmsghdr,
    rest: [u8; 64],
}

impl ControlBuffer {
    fn zeroed() -> Self {
        Self {
            cmsg: unsafe { std::mem::zeroed() },
            rest: [0u8; 64],
        }
    }
}

/// A directory-creation failure that records whether the directory may have
/// been created before the failure, so the caller never reports a bare failure
/// for a directory it may be leaving behind.
#[derive(Debug)]
struct DirCreationError {
    source: io::Error,
    created: bool,
}

/// Create `name` under `parent_fd` at `mode`, in a forked child with `umask(077)`
/// so the owner bits survive any process umask, and return the opened
/// administrative descriptor over `SCM_RIGHTS`.
///
/// The child uses only async-signal-safe libc calls; all buffers are prepared
/// before the fork. A failure after `mkdirat` succeeded but before the descriptor
/// was acquired is reported with `created: true`.
fn create_dir_umask_safe(
    parent_fd: RawFd,
    name: &CStr,
    mode: u32,
) -> Result<OwnedFd, DirCreationError> {
    let mut sockets = [0i32; 2];
    if unsafe { libc::socketpair(libc::AF_UNIX, libc::SOCK_STREAM, 0, sockets.as_mut_ptr()) } < 0 {
        return Err(DirCreationError {
            source: io::Error::last_os_error(),
            created: false,
        });
    }
    let (parent_sock, child_sock) = (sockets[0], sockets[1]);
    set_cloexec_raw(parent_sock);
    set_cloexec_raw(child_sock);

    let pid = unsafe { libc::fork() };
    if pid < 0 {
        let error = io::Error::last_os_error();
        unsafe {
            libc::close(parent_sock);
            libc::close(child_sock);
        }
        return Err(DirCreationError {
            source: error,
            created: false,
        });
    }
    if pid == 0 {
        let wire;
        let fd_to_send;
        // Capture the test flag before the fork so the child reads a plain local
        // (the thread-local is inherited by the fork).
        #[cfg(any(test, feature = "test-internals"))]
        let fail_after_mkdir = FAIL_OPEN_AFTER_MKDIR.with(|flag| flag.get());
        #[cfg(not(any(test, feature = "test-internals")))]
        let fail_after_mkdir = false;
        unsafe {
            libc::close(parent_sock);
            libc::umask(0o077);
            let ret = libc::mkdirat(parent_fd, name.as_ptr(), mode as libc::mode_t);
            if ret < 0 {
                // mkdirat failed: nothing was created.
                wire = errno();
                fd_to_send = -1;
            } else if fail_after_mkdir {
                // Test injection: mkdirat succeeded, so the directory exists but
                // was not acquired. Encode with a negative status.
                wire = -libc::EACCES;
                fd_to_send = -1;
            } else {
                let fd = libc::openat(parent_fd, name.as_ptr(), ADMIN_OPEN_FLAGS);
                if fd < 0 {
                    // mkdirat succeeded, so the directory exists but was not
                    // acquired. Encode with a negative status.
                    wire = -errno();
                    fd_to_send = -1;
                } else {
                    let mut stat: libc::stat = std::mem::zeroed();
                    if libc::fstat(fd, &mut stat) < 0 {
                        wire = -errno();
                        fd_to_send = -1;
                        libc::close(fd);
                    } else {
                        wire = 0;
                        fd_to_send = fd;
                    }
                }
            }
            child_send(child_sock, fd_to_send, wire);
            libc::close(child_sock);
            libc::_exit(0);
        }
    }

    unsafe { libc::close(child_sock) };
    let received = parent_recv(parent_sock);
    unsafe { libc::close(parent_sock) };
    reap_child(pid);

    let (received_fd, wire) = match received {
        Ok(received) => received,
        // The child ran, so conservatively report that it may have created the
        // directory rather than hiding a possibly-retained one.
        Err(source) => {
            return Err(DirCreationError {
                source,
                created: true,
            });
        }
    };

    if wire != 0 {
        // A nonzero status carries no descriptor; `parent_recv` already
        // reclaimed any descriptor the kernel delivered on this message.
        return Err(DirCreationError {
            source: io::Error::from_raw_os_error(wire.unsigned_abs() as i32),
            created: wire < 0,
        });
    }
    let Some(fd) = received_fd else {
        return Err(DirCreationError {
            source: io::Error::other("creation child returned no descriptor"),
            created: true,
        });
    };
    set_cloexec_raw(fd.as_raw_fd());
    Ok(fd)
}

/// Reap `pid`, retrying `waitpid` across `EINTR` so a signal cannot leave the
/// creation child unreaped.
fn reap_child(pid: libc::pid_t) {
    let mut wait_status = 0;
    loop {
        let ret = unsafe { libc::waitpid(pid, &mut wait_status, 0) };
        if ret >= 0 {
            break;
        }
        if errno() != libc::EINTR {
            break;
        }
    }
}

/// Send a status word plus an optional descriptor over `sock` (child side).
fn child_send(sock: RawFd, fd_to_send: RawFd, status: i32) {
    // The child uses only async-signal-safe libc calls; all buffers are prepared
    // by the caller before the fork and no allocation happens here.
    unsafe {
        let status_bytes = status.to_ne_bytes();
        let mut iov = libc::iovec {
            iov_base: status_bytes.as_ptr() as *mut libc::c_void,
            iov_len: status_bytes.len(),
        };
        let mut control = ControlBuffer::zeroed();
        let mut msg: libc::msghdr = std::mem::zeroed();
        msg.msg_iov = &mut iov;
        msg.msg_iovlen = 1;
        msg.msg_control = std::ptr::null_mut();
        msg.msg_controllen = 0;
        if fd_to_send >= 0 {
            control.cmsg.cmsg_level = libc::SOL_SOCKET;
            control.cmsg.cmsg_type = libc::SCM_RIGHTS;
            control.cmsg.cmsg_len = libc::CMSG_LEN(std::mem::size_of::<RawFd>() as u32) as _;
            std::ptr::copy_nonoverlapping(
                &fd_to_send as *const RawFd as *const u8,
                libc::CMSG_DATA(&control.cmsg),
                std::mem::size_of::<RawFd>(),
            );
            msg.msg_control = (&mut control.cmsg as *mut libc::cmsghdr).cast();
            msg.msg_controllen = libc::CMSG_SPACE(std::mem::size_of::<RawFd>() as u32) as _;
        }
        loop {
            let ret = libc::sendmsg(sock, &msg, 0);
            if ret >= 0 {
                break;
            }
            if errno() != libc::EINTR {
                break;
            }
        }
    }
}

/// Receive a status word plus an optional descriptor over `sock` (parent side).
///
/// The status word and the control message are validated independently by
/// [`validate_recv_message`]. On success the message must match the protocol
/// exactly: status `0` carries exactly one descriptor, a nonzero status carries
/// none.
///
/// The trusted creation child ([`child_send`]) sends **at most one** descriptor,
/// which always fits the fixed control buffer, so normal traffic never truncates.
/// Only malformed excess traffic can overflow the buffer and set `MSG_CTRUNC`.
fn parent_recv(sock: RawFd) -> io::Result<(Option<OwnedFd>, i32)> {
    let mut status_bytes = [0u8; 4];
    let mut iov = libc::iovec {
        iov_base: status_bytes.as_mut_ptr() as *mut libc::c_void,
        iov_len: status_bytes.len(),
    };
    let mut control = ControlBuffer::zeroed();
    let mut msg: libc::msghdr = unsafe { std::mem::zeroed() };
    msg.msg_iov = &mut iov;
    msg.msg_iovlen = 1;
    msg.msg_control = (&mut control.cmsg as *mut libc::cmsghdr).cast();
    msg.msg_controllen = std::mem::size_of::<ControlBuffer>() as _;

    let received_len = loop {
        let ret = unsafe { libc::recvmsg(sock, &mut msg, 0) };
        if ret < 0 {
            let error = io::Error::last_os_error();
            if error.raw_os_error() == Some(libc::EINTR) {
                continue;
            }
            return Err(error);
        }
        break ret as usize;
    };

    validate_recv_message(&msg, received_len, status_bytes)
}

/// The descriptors and malformed-control flag parsed out of a received
/// `msghdr`'s control buffer.
struct ParsedControl {
    /// Every descriptor the kernel placed in the buffer, adopted as owned guards
    /// so a refusal drops (and closes) them.
    descriptors: Vec<OwnedFd>,
    /// A control message with an unexpected offset, level, type, or length.
    malformed: bool,
}

/// Parse the control buffer of `msg`, adopting each descriptor into an owned
/// guard **before** any status/length validation, so every refusal path reclaims
/// the descriptors the kernel installed.
///
/// The copy of each descriptor payload is bounded by the bytes actually present
/// in the buffer (`msg_controllen`) rather than the *declared* `cmsg_len`, which
/// a kernel-truncated copy keeps even though fewer bytes (and `MSG_CTRUNC`) are
/// present. This is a private seam so tests can exercise the truncation and
/// malformed-header refusal semantics with synthetic buffers, without
/// manufacturing the kernel's own unreported truncation descriptors.
fn parse_control_descriptors(msg: &libc::msghdr) -> ParsedControl {
    let mut descriptors: Vec<OwnedFd> = Vec::new();
    let mut malformed = false;
    if msg.msg_controllen > 0 {
        let control_base = msg.msg_control as usize;
        let mut cmsg = unsafe { libc::CMSG_FIRSTHDR(msg) };
        while !cmsg.is_null() {
            let cmsg_len = unsafe { (*cmsg).cmsg_len as usize };
            let level = unsafe { (*cmsg).cmsg_level };
            let kind = unsafe { (*cmsg).cmsg_type };
            let header = unsafe { libc::CMSG_LEN(0) as usize };
            let offset = (cmsg as usize).saturating_sub(control_base);
            if offset > msg.msg_controllen as usize
                || level != libc::SOL_SOCKET
                || kind != libc::SCM_RIGHTS
                || cmsg_len < header
            {
                malformed = true;
                break;
            }
            let declared_data = cmsg_len - header;
            let available_data = (msg.msg_controllen as usize - offset).saturating_sub(header);
            let data_len = declared_data.min(available_data);
            for index in 0..(data_len / std::mem::size_of::<RawFd>()) {
                let mut raw: RawFd = -1;
                unsafe {
                    std::ptr::copy_nonoverlapping(
                        libc::CMSG_DATA(cmsg).add(index * std::mem::size_of::<RawFd>()),
                        &mut raw as *mut RawFd as *mut u8,
                        std::mem::size_of::<RawFd>(),
                    );
                }
                if raw >= 0 {
                    descriptors.push(unsafe { OwnedFd::from_raw_fd(raw) });
                }
            }
            cmsg = next_cmsg(msg, cmsg);
        }
    }
    ParsedControl {
        descriptors,
        malformed,
    }
}

/// Validate one received creation-child message: a 4-byte status word and the
/// control buffer in `msg`.
///
/// The descriptors in `msg` are adopted into owned guards by
/// [`parse_control_descriptors`] before the status, truncation, and count checks,
/// so every refusal drops them and reclaims them. The kernel reports only the
/// descriptors that fit the control buffer, so a message we refuse must close
/// the reported ones itself; an unreported overflow is a malformed-sender
/// artifact that the trusted one-descriptor [`child_send`] cannot produce. On
/// success the message must match the protocol exactly: status `0` carries
/// exactly one descriptor, a nonzero status carries none.
fn validate_recv_message(
    msg: &libc::msghdr,
    received_len: usize,
    status_bytes: [u8; 4],
) -> io::Result<(Option<OwnedFd>, i32)> {
    let mut parsed = parse_control_descriptors(msg);
    if received_len != status_bytes.len() {
        return Err(io::Error::other("creation child sent a short status word"));
    }
    if msg.msg_flags & libc::MSG_CTRUNC != 0 {
        return Err(io::Error::other(
            "creation child ancillary data was truncated",
        ));
    }
    if parsed.malformed {
        return Err(io::Error::other(
            "creation child sent a malformed control message",
        ));
    }
    let status = i32::from_ne_bytes(status_bytes);
    // Exactly one descriptor on success (status `0`), none on failure; any other
    // count is a protocol violation.
    let expected = usize::from(status == 0);
    if parsed.descriptors.len() != expected {
        return Err(io::Error::other(
            "creation child sent an unexpected number of descriptors",
        ));
    }
    Ok((parsed.descriptors.pop(), status))
}

/// Control-message alignment: Darwin aligns to 4 (`__DARWIN_ALIGN32`), other
/// supported platforms to the native word size (`CMSG_ALIGN`).
#[cfg(target_os = "macos")]
const CMSG_ALIGNMENT: usize = 4;
#[cfg(not(target_os = "macos"))]
const CMSG_ALIGNMENT: usize = std::mem::size_of::<usize>();

fn cmsg_align(len: usize) -> usize {
    (len + CMSG_ALIGNMENT - 1) & !(CMSG_ALIGNMENT - 1)
}

/// The next control message after `cmsg`, or null at the end of the buffer.
///
/// `libc` exposes `CMSG_NXTHDR` on Darwin but not on Linux, so this mirrors the
/// macro with the platform's control-message alignment.
fn next_cmsg(msg: &libc::msghdr, cmsg: *const libc::cmsghdr) -> *mut libc::cmsghdr {
    let base = msg.msg_control as usize;
    let end = base + msg.msg_controllen as usize;
    let len = unsafe { (*cmsg).cmsg_len as usize };
    let next = (cmsg as usize).saturating_add(cmsg_align(len));
    if next.saturating_add(cmsg_align(std::mem::size_of::<libc::cmsghdr>())) > end {
        std::ptr::null_mut()
    } else {
        next as *mut libc::cmsghdr
    }
}

fn set_cloexec_raw(fd: RawFd) {
    unsafe { libc::fcntl(fd, libc::F_SETFD, libc::FD_CLOEXEC) };
}

fn errno() -> i32 {
    io::Error::last_os_error().raw_os_error().unwrap_or(0)
}

/// Generate a random `.microsandbox-file-mount-*` basename.
fn random_stage_name() -> OsString {
    let mut bytes = [0u8; 8];
    let mut filled = false;
    if let Ok(mut file) = File::open("/dev/urandom") {
        filled = file.read_exact(&mut bytes).is_ok();
    }
    if !filled {
        let nanos = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .map(|duration| duration.as_nanos())
            .unwrap_or(0);
        let pid = std::process::id() as u128;
        let mut seed = nanos ^ (pid << 64) ^ (bytes.as_ptr() as u128);
        for chunk in bytes.chunks_mut(8) {
            seed = seed
                .wrapping_mul(6364136223846793005)
                .wrapping_add(1442695040888963407);
            let value = seed.to_le_bytes();
            chunk.copy_from_slice(&value[..chunk.len()]);
        }
    }
    let mut name = OsString::from(".microsandbox-file-mount-");
    for byte in bytes {
        name.push(format!("{byte:02x}"));
    }
    name
}

/// Test helper for [`StageOverrides::redirect_ancestor`]: rename the resolved
/// source parent and plant a decoy tree at its old name, so a stage must stay on
/// the held parent descriptor rather than the now-replaced path.
#[cfg(any(test, feature = "test-internals"))]
fn redirect_ancestor_for_test(parent_path: &Path) {
    // Never rename `.` or a filesystem root, which would be destructive and is
    // not what this hook is for.
    if parent_path.as_os_str().is_empty() || parent_path == Path::new(".") {
        return;
    }
    let Some(name) = parent_path.file_name() else {
        return;
    };
    let renamed = parent_path.with_file_name(format!("{}.msb-redirected", name.to_string_lossy()));
    if std::fs::rename(parent_path, &renamed).is_ok() {
        let _ = std::fs::create_dir_all(parent_path);
        let _ = std::fs::write(parent_path.join("decoy.txt"), b"decoy");
    }
}

/// Test helper for [`StageOverrides::swap_after_anchor`]: rename a freshly
/// anchored stage root and plant a same-name decoy directory, so post-anchor
/// population must stay on the held root descriptor.
#[cfg(any(test, feature = "test-internals"))]
fn swap_stage_root_after_anchor_for_test(child_path: &Path) {
    let held = child_path.with_extension("msb-held");
    if std::fs::rename(child_path, &held).is_ok() {
        let _ = std::fs::create_dir(child_path);
        let _ = std::fs::write(child_path.join("decoy-sentinel"), b"decoy");
    }
}

/// Test helper: if [`SWAP_ROOT_BEFORE_REMOVAL`] is set, rename the stage root
/// through the *held* parent descriptor and plant a same-name empty replacement
/// between the identity check and the removal decision.
#[cfg(any(test, feature = "test-internals"))]
fn swap_root_before_removal_for_test(parent: &SearchDir, root_path: &Path) {
    if !SWAP_ROOT_BEFORE_REMOVAL.with(|flag| flag.get()) {
        return;
    }
    SWAP_ROOT_BEFORE_REMOVAL.with(|flag| flag.set(false));
    let Some(file_name) = root_path.file_name() else {
        return;
    };
    let name = match cstring(file_name) {
        Ok(name) => name,
        Err(_) => return,
    };
    let held_name = OsString::from(format!("{}.msb-swapped", file_name.to_string_lossy()));
    let held = match cstring(&held_name) {
        Ok(held) => held,
        Err(_) => return,
    };
    unsafe {
        let ret = libc::renameat(parent.raw(), name.as_ptr(), parent.raw(), held.as_ptr());
        if ret == 0 {
            libc::mkdirat(parent.raw(), name.as_ptr(), 0o700 as libc::mode_t);
        }
    }
}

/// One `ACL_TYPE_EXTENDED` `ALLOW` entry, resolved to whether its qualifier is
/// the caller and which permission bits it grants.
#[cfg(target_os = "macos")]
struct ForeignAclGrant {
    /// The entry's qualifier is **not** the object owner's uid GUID.
    ///
    /// A group is not an owner-only principal (for example the shared `staff`
    /// group contains other uids), so a grant whose qualifier is the owning gid
    /// is treated as foreign. This is deliberately conservative: the parent
    /// predicate then applies the strict check, and the pinned-root predicate
    /// rejects, and neither can be wrong in the unsafe direction because the
    /// stage we create is `0700`. On a filesystem with real permissions a
    /// false-positive gate costs nothing — validation only fails when the stage
    /// *we* created is not caller-private, and we created it `0700`.
    foreign: bool,
    /// The entry's permission mask.
    mask: u64,
}

/// Enumerate the `ALLOW` entries of a Darwin extended ACL.
///
/// Each entry's qualifier is compared against the caller's uid GUID
/// (`mbr_uid_to_uuid`); anything else is foreign. A documented no-ACL errno
/// (`ENOENT`) yields no entries. A failure to open the ACL, a per-entry
/// tag/mask/qualifier query failure, or an unexpected iteration failure is
/// returned as an error so the caller can fail closed rather than silently
/// accept.
///
/// `acl_get_entry(3)` documents `0` for success and `-1` for every error,
/// including `EINVAL` when `ACL_NEXT_ENTRY` is called past the last entry. A
/// valid ACL's first entry can only fail unexpectedly; advancing past the last
/// entry is the one documented exhaustion that is not an error.
#[cfg(target_os = "macos")]
fn acl_allow_grants(fd: RawFd, owner_uid: libc::uid_t) -> io::Result<Vec<ForeignAclGrant>> {
    use darwin_acl::*;
    let mut grants = Vec::new();
    let mut owner_uid_uuid = [0u8; 16];
    let uid_resolved = unsafe { mbr_uid_to_uuid(owner_uid, owner_uid_uuid.as_mut_ptr()) } == 0;
    unsafe {
        let acl = acl_get_fd_np(fd, ACL_TYPE_EXTENDED);
        if acl.is_null() {
            let error = io::Error::last_os_error();
            if error.raw_os_error() == Some(libc::ENOENT) {
                return Ok(grants);
            }
            return Err(error);
        }
        let mut entry: AclEntryT = std::ptr::null_mut();
        // The first entry of a valid ACL only fails unexpectedly, so any
        // nonzero result here (including `EINVAL`) is an error, never an empty
        // ACL.
        if acl_get_entry(acl, ACL_FIRST_ENTRY, &mut entry) != 0 {
            let error = io::Error::last_os_error();
            acl_free(acl);
            return Err(error);
        }
        loop {
            let mut tag: libc::c_uint = 0;
            if acl_get_tag_type(entry, &mut tag) != 0 {
                let error = io::Error::last_os_error();
                acl_free(acl);
                return Err(error);
            }
            let mut mask: AclPermsetMaskT = 0;
            if acl_get_permset_mask_np(entry, &mut mask) != 0 {
                let error = io::Error::last_os_error();
                acl_free(acl);
                return Err(error);
            }
            let qualifier = acl_get_qualifier(entry);
            if qualifier.is_null() {
                let error = io::Error::last_os_error();
                acl_free(acl);
                return Err(error);
            }
            let mut qualifier_uuid = [0u8; 16];
            std::ptr::copy_nonoverlapping(
                qualifier as *const u8,
                qualifier_uuid.as_mut_ptr(),
                qualifier_uuid.len(),
            );
            acl_free(qualifier);
            // Fail closed when the owner GUID could not be resolved: an entry
            // is then treated as foreign.
            let matches_uid = uid_resolved && qualifier_uuid == owner_uid_uuid;
            if tag == ACL_EXTENDED_ALLOW {
                grants.push(ForeignAclGrant {
                    foreign: !matches_uid,
                    mask,
                });
            }
            if acl_get_entry(acl, ACL_NEXT_ENTRY, &mut entry) == 0 {
                continue;
            }
            let error = io::Error::last_os_error();
            if error.raw_os_error() == Some(libc::EINVAL) {
                // Documented normal exhaustion: `ACL_NEXT_ENTRY` past the last
                // entry.
                break;
            }
            acl_free(acl);
            return Err(error);
        }
        acl_free(acl);
    }
    Ok(grants)
}

/// Parent-writability predicate: any grant whose qualifier is not the caller
/// that could let another principal create, rename or remove an entry here, or
/// later change the directory's own permissions/ownership to widen access.
///
/// The governance right matters even though it does not itself write an entry:
/// a foreign `writesecurity`/`chown` grant can widen the directory after the
/// gate check without changing ownership, so the gate must treat it as foreign.
#[cfg(target_os = "macos")]
fn acl_grants_foreign_write(fd: RawFd, owner_uid: libc::uid_t) -> io::Result<bool> {
    let grants = acl_allow_grants(fd, owner_uid)?;
    Ok(grants.iter().any(|grant| {
        grant.foreign
            && (grant.mask & (darwin_acl::ACL_WRITE_BITS | darwin_acl::ACL_GOVERNANCE_BITS)) != 0
    }))
}

/// Cleanup-swap predicate: any grant whose qualifier is not the caller that
/// could let another principal create, rename, delete, or search this directory,
/// or later change the directory's own permissions/ownership to widen access.
///
/// Stricter than [`acl_grants_foreign_write`]: it also counts a foreign
/// `search`/`execute` right, and it gates the sticky carve-out in
/// [`parent_allows_foreign_root_swap`] because XNU lets a parent `DELETE_CHILD`
/// ACE override a sticky deny.
#[cfg(target_os = "macos")]
fn acl_grants_foreign_swap(fd: RawFd, owner_uid: libc::uid_t) -> io::Result<bool> {
    let grants = acl_allow_grants(fd, owner_uid)?;
    Ok(grants.iter().any(|grant| {
        grant.foreign
            && (grant.mask & (darwin_acl::ACL_SWAP_BITS | darwin_acl::ACL_GOVERNANCE_BITS)) != 0
    }))
}

/// Pinned-stage-privacy predicate: reject **any** non-caller granting entry, and
/// any entry that grants a right to change the directory's own permissions or
/// ownership (which could widen access later). An owning-group grant is a
/// non-caller grant and is rejected.
#[cfg(target_os = "macos")]
fn acl_has_foreign_grant(fd: RawFd, owner_uid: libc::uid_t) -> io::Result<bool> {
    let grants = acl_allow_grants(fd, owner_uid)?;
    Ok(grants
        .iter()
        .any(|grant| grant.foreign || (grant.mask & darwin_acl::ACL_GOVERNANCE_BITS) != 0))
}

#[cfg(target_os = "macos")]
mod darwin_acl {
    pub(super) type AclT = *mut libc::c_void;
    pub(super) type AclEntryT = *mut libc::c_void;
    pub(super) type AclPermsetMaskT = u64;

    pub(super) const ACL_TYPE_EXTENDED: libc::c_uint = 0x0000_0100;
    pub(super) const ACL_FIRST_ENTRY: libc::c_int = 0;
    pub(super) const ACL_NEXT_ENTRY: libc::c_int = -1;
    pub(super) const ACL_EXTENDED_ALLOW: libc::c_uint = 1;
    /// Parent-writability bits: write-data, delete, append/add-file, and
    /// delete-child, so any grant that could let another principal create,
    /// rename or remove an entry counts.
    pub(super) const ACL_WRITE_BITS: u64 = (1 << 2) | (1 << 4) | (1 << 5) | (1 << 6);
    /// Swap/removal rights: the parent-write bits plus search/execute. A foreign
    /// grant of any of these can let another principal swap or remove an entry
    /// here, or traverse the directory to reach it.
    pub(super) const ACL_SWAP_BITS: u64 = ACL_WRITE_BITS | (1 << 3);
    /// Rights that let a principal change the object's own permissions or
    /// ownership (`ACL_WRITE_SECURITY`, `ACL_CHANGE_OWNER`).
    pub(super) const ACL_GOVERNANCE_BITS: u64 = (1 << 12) | (1 << 13);

    unsafe extern "C" {
        pub(super) fn acl_get_fd_np(fd: libc::c_int, type_: libc::c_uint) -> AclT;
        pub(super) fn acl_get_entry(
            acl: AclT,
            entry_id: libc::c_int,
            entry_p: *mut AclEntryT,
        ) -> libc::c_int;
        pub(super) fn acl_get_tag_type(entry: AclEntryT, tag: *mut libc::c_uint) -> libc::c_int;
        pub(super) fn acl_get_permset_mask_np(
            entry: AclEntryT,
            mask: *mut AclPermsetMaskT,
        ) -> libc::c_int;
        pub(super) fn acl_get_qualifier(entry: AclEntryT) -> *mut libc::c_void;
        pub(super) fn acl_free(obj: *mut libc::c_void) -> libc::c_int;
        pub(super) fn mbr_uid_to_uuid(id: libc::uid_t, uuid: *mut libc::c_uchar) -> libc::c_int;
    }
}

//--------------------------------------------------------------------------------------------------
// Tests
//--------------------------------------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use super::*;
    use std::os::unix::fs::{MetadataExt, PermissionsExt};

    fn fixture() -> tempfile::TempDir {
        // Fixtures live under the canonical system temp root so the fixture path
        // is not itself the thing under test (macOS `/var` -> `/private/var`).
        let base = std::fs::canonicalize(std::env::temp_dir()).unwrap();
        let dir = tempfile::Builder::new()
            .prefix("msb-nofollow-")
            .tempdir_in(base)
            .unwrap();
        // The process umask can be left at `0` by an earlier test (the
        // passthrough backend clears it), which would create the fixture
        // group/other-writable and change which cleanup branch a test exercises.
        // Pin the fixture to caller-private `0700`; tests that need a writable
        // parent set the mode explicitly.
        std::fs::set_permissions(dir.path(), std::fs::Permissions::from_mode(0o700)).unwrap();
        dir
    }

    #[test]
    fn resolve_opens_the_parent_of_a_plain_file() {
        let dir = fixture();
        let file = dir.path().join("plain.txt");
        std::fs::write(&file, b"x").unwrap();
        let path = NoFollowPath::resolve(&file).unwrap();
        assert_eq!(path.leaf(), OsStr::new("plain.txt"));
        assert_eq!(path.leaf_kind().unwrap(), LeafKind::Regular);
    }

    #[test]
    fn resolve_rejects_a_symlinked_leaf() {
        let dir = fixture();
        let real = dir.path().join("real.txt");
        std::fs::write(&real, b"x").unwrap();
        let link = dir.path().join("link.txt");
        std::os::unix::fs::symlink("real.txt", &link).unwrap();
        let path = NoFollowPath::resolve(&link).unwrap();
        assert_eq!(path.leaf_kind().unwrap(), LeafKind::Symlink);
        match path.classify_regular() {
            Err(NoFollowError::Symlink { component }) => assert_eq!(component, link),
            other => panic!("expected Symlink, got {other:?}"),
        }
    }

    #[test]
    fn resolve_rejects_a_symlinked_ancestor() {
        let dir = fixture();
        let real_dir = dir.path().join("realdir");
        std::fs::create_dir(&real_dir).unwrap();
        let file = real_dir.join("f.txt");
        std::fs::write(&file, b"x").unwrap();
        let link_dir = dir.path().join("linkdir");
        std::os::unix::fs::symlink("realdir", &link_dir).unwrap();
        match NoFollowPath::resolve(&link_dir.join("f.txt")) {
            Err(NoFollowError::Symlink { component }) => assert_eq!(component, link_dir),
            other => panic!("expected ancestor Symlink, got {other:?}"),
        }
    }

    #[test]
    fn resolve_and_stage_through_a_search_only_ancestor() {
        let dir = fixture();
        let ancestor = dir.path().join("only-search");
        std::fs::create_dir(&ancestor).unwrap();
        let source = ancestor.join("source.txt");
        std::fs::write(&source, b"search-only").unwrap();
        std::fs::set_permissions(&ancestor, std::fs::Permissions::from_mode(0o111)).unwrap();

        // Prove the ancestor is genuinely search-only: a readable open fails.
        let opened = NoFollowDir::open(&ancestor);
        assert!(
            opened.is_err(),
            "an 0111 directory must not be openable for read"
        );

        let file = NoFollowPath::resolve(&source)
            .unwrap()
            .classify_regular()
            .unwrap();
        let dest = dir.path().join("dest");
        std::fs::create_dir(&dest).unwrap();
        let dest_dir = NoFollowDir::open(&dest).unwrap();
        file.link_into(&dest_dir, OsStr::new("staged.txt")).unwrap();
        assert_eq!(
            std::fs::metadata(&source).unwrap().ino(),
            std::fs::metadata(dest.join("staged.txt")).unwrap().ino()
        );
        std::fs::set_permissions(&ancestor, std::fs::Permissions::from_mode(0o700)).unwrap();
    }

    #[test]
    fn resolve_reports_eacces_in_an_ancestor_as_unresolved() {
        let dir = fixture();
        let ancestor = dir.path().join("no-search");
        std::fs::create_dir(&ancestor).unwrap();
        let source = ancestor.join("source.txt");
        std::fs::write(&source, b"x").unwrap();
        std::fs::set_permissions(&ancestor, std::fs::Permissions::from_mode(0o600)).unwrap();
        // Classify while the denial is still in force. On Linux an `O_PATH` walk
        // can return the parent descriptor even without search permission, so the
        // denial may surface on `resolve` or on the leaf classification; both are
        // `Unresolved`/`EACCES`.
        let source_error = match NoFollowPath::resolve(&source) {
            Ok(path) => match path.leaf_kind() {
                Ok(kind) => panic!("a denied ancestor must not resolve, got {kind:?}"),
                Err(NoFollowError::Unresolved { source, .. }) => source,
                Err(other) => panic!("expected Unresolved/EACCES, got {other:?}"),
            },
            Err(NoFollowError::Unresolved { source, .. }) => source,
            Err(other) => panic!("expected Unresolved/EACCES, got {other:?}"),
        };
        std::fs::set_permissions(&ancestor, std::fs::Permissions::from_mode(0o700)).unwrap();
        assert_eq!(source_error.raw_os_error(), Some(libc::EACCES));
    }

    #[test]
    fn resolve_rejects_dotdot_through_an_unsearchable_directory() {
        // `a/../file` must not pop past an `a` that is present but unsearchable:
        // the kernel denies `a/..` and a descriptor-stack pop would skip that
        // check (S6). `resolve` is directly reachable here.
        let dir = fixture();
        let a = dir.path().join("a");
        std::fs::create_dir(&a).unwrap();
        let file = dir.path().join("file.txt");
        std::fs::write(&file, b"x").unwrap();
        let via = a.join("..").join("file.txt");
        std::fs::set_permissions(&a, std::fs::Permissions::from_mode(0o600)).unwrap();
        let result = NoFollowPath::resolve(&via);
        std::fs::set_permissions(&a, std::fs::Permissions::from_mode(0o700)).unwrap();
        match result {
            Err(NoFollowError::Unresolved { source, .. }) => {
                assert_eq!(source.raw_os_error(), Some(libc::EACCES));
            }
            other => panic!("expected Unresolved/EACCES for an unsearchable pop, got {other:?}"),
        }
    }

    #[test]
    fn create_stage_beside_skips_validation_when_the_parent_is_not_foreign_writable() {
        let dir = fixture();
        let source = dir.path().join("source.txt");
        std::fs::write(&source, b"x").unwrap();
        std::fs::set_permissions(dir.path(), std::fs::Permissions::from_mode(0o700)).unwrap();
        let file = NoFollowPath::resolve(&source)
            .unwrap()
            .classify_regular()
            .unwrap();
        assert!(!file.parent_is_foreign_writable().unwrap());
        // The pinned directory really is 0700; forcing the observed mode to 0755
        // must not matter because the gate is skipped.
        let stage = file
            .create_stage_beside_with_override(StageOverrides {
                mode: Some(0o755),
                ..StageOverrides::default()
            })
            .unwrap();
        assert_eq!(
            std::fs::metadata(stage.path())
                .unwrap()
                .permissions()
                .mode()
                & 0o7777,
            0o700
        );
        stage.keep();
    }

    #[test]
    fn create_stage_beside_fails_closed_when_the_gate_applies() {
        let dir = fixture();
        let source = dir.path().join("source.txt");
        std::fs::write(&source, b"x").unwrap();
        // A foreign-writable parent plus a synthesized non-0700 mode must fail.
        std::fs::set_permissions(dir.path(), std::fs::Permissions::from_mode(0o777)).unwrap();
        let file = NoFollowPath::resolve(&source)
            .unwrap()
            .classify_regular()
            .unwrap();
        assert!(file.parent_is_foreign_writable().unwrap());
        let result = file.create_stage_beside_with_override(StageOverrides {
            mode: Some(0o755),
            ..StageOverrides::default()
        });
        std::fs::set_permissions(dir.path(), std::fs::Permissions::from_mode(0o700)).unwrap();
        match result {
            Err(StageCreateError {
                operation,
                retained,
                ..
            }) => {
                assert!(operation.contains("validate pinned"));
                assert!(retained.is_some(), "the created directory must be reported");
            }
            Ok(_) => panic!("the strict check must fail closed"),
        }
    }

    #[test]
    fn source_parent_stage_drop_removes_the_stage() {
        let dir = fixture();
        let source = dir.path().join("source.txt");
        std::fs::write(&source, b"x").unwrap();
        let file = NoFollowPath::resolve(&source)
            .unwrap()
            .classify_regular()
            .unwrap();
        let stage = file.create_stage_beside().unwrap();
        let root = stage.path().to_path_buf();
        assert!(root.exists());
        drop(stage);
        assert!(!root.exists(), "dropping an armed stage must remove it");
        assert!(source.exists());
    }

    #[test]
    fn source_parent_stage_keep_leaves_the_stage() {
        let dir = fixture();
        let source = dir.path().join("source.txt");
        std::fs::write(&source, b"x").unwrap();
        let file = NoFollowPath::resolve(&source)
            .unwrap()
            .classify_regular()
            .unwrap();
        let stage = file.create_stage_beside().unwrap();
        let root = stage.path().to_path_buf();
        stage.keep();
        assert!(
            root.exists(),
            "keep() must preserve the stage for a detached VM"
        );
        std::fs::remove_dir_all(&root).ok();
    }

    #[test]
    fn source_parent_stage_creates_tag_links_and_closes() {
        let dir = fixture();
        let source = dir.path().join("source.txt");
        std::fs::write(&source, b"payload").unwrap();
        let file = NoFollowPath::resolve(&source)
            .unwrap()
            .classify_regular()
            .unwrap();
        let mut stage = file.create_stage_beside().unwrap();
        stage.create_tag(OsStr::new("fm_test")).unwrap();
        file.link_into(stage.dir(), OsStr::new("source.txt"))
            .unwrap();
        stage.set_leaf(OsStr::new("source.txt"));
        let staged = stage.dir().path().join("source.txt");
        assert_eq!(std::fs::read(&staged).unwrap(), b"payload");
        let root = stage.path().to_path_buf();
        stage.close().unwrap();
        assert!(!root.exists(), "close must remove the stage root");
        assert!(source.exists(), "the source must survive cleanup");
    }

    #[test]
    fn resolve_reports_a_missing_component_as_unresolved() {
        let dir = fixture();
        match NoFollowPath::resolve(&dir.path().join("missing").join("f.txt")) {
            Err(NoFollowError::Unresolved { source, .. }) => {
                assert_eq!(source.kind(), io::ErrorKind::NotFound);
            }
            other => panic!("expected Unresolved/NotFound, got {other:?}"),
        }
    }

    #[test]
    fn resolve_reports_enotdir_in_an_ancestor_as_unresolved() {
        let dir = fixture();
        let file = dir.path().join("regular.txt");
        std::fs::write(&file, b"x").unwrap();
        match NoFollowPath::resolve(&file.join("child")) {
            Err(NoFollowError::Unresolved { source, .. }) => {
                assert_eq!(source.raw_os_error(), Some(libc::ENOTDIR));
            }
            other => panic!("expected Unresolved/ENOTDIR, got {other:?}"),
        }
    }

    #[test]
    fn classify_regular_reports_identity_and_mode() {
        let dir = fixture();
        let file = dir.path().join("mode.txt");
        std::fs::write(&file, b"x").unwrap();
        std::fs::set_permissions(&file, std::fs::Permissions::from_mode(0o640)).unwrap();
        let resolved = NoFollowPath::resolve(&file)
            .unwrap()
            .classify_regular()
            .unwrap();
        let meta = std::fs::metadata(&file).unwrap();
        assert_eq!(resolved.device(), meta.dev());
        assert_eq!(resolved.inode(), meta.ino());
        assert_eq!(resolved.permissions(), 0o640);
    }

    #[test]
    fn classify_regular_refuses_directory_and_fifo_without_open() {
        let dir = fixture();
        let sub = dir.path().join("subdir");
        std::fs::create_dir(&sub).unwrap();
        match NoFollowPath::resolve(&sub).unwrap().classify_regular() {
            Err(NoFollowError::NonRegular {
                kind: LeafKind::Directory,
                ..
            }) => {}
            other => panic!("expected NonRegular/Directory, got {other:?}"),
        }
    }

    #[test]
    fn leaf_kind_classifies_directory_fifo_and_symlink() {
        let dir = fixture();
        let sub = dir.path().join("d");
        std::fs::create_dir(&sub).unwrap();
        assert_eq!(
            NoFollowPath::resolve(&sub).unwrap().leaf_kind().unwrap(),
            LeafKind::Directory
        );
        let fifo = dir.path().join("pipe");
        let c = cstring(fifo.as_os_str()).unwrap();
        let ret = unsafe { libc::mkfifo(c.as_ptr(), 0o600) };
        assert_eq!(ret, 0, "mkfifo failed");
        assert_eq!(
            NoFollowPath::resolve(&fifo).unwrap().leaf_kind().unwrap(),
            LeafKind::Other
        );
        let link = dir.path().join("l");
        std::os::unix::fs::symlink(&sub, &link).unwrap();
        assert_eq!(
            NoFollowPath::resolve(&link).unwrap().leaf_kind().unwrap(),
            LeafKind::Symlink
        );
    }

    #[test]
    fn link_into_preserves_inode_identity() {
        let dir = fixture();
        let source = dir.path().join("source.txt");
        std::fs::write(&source, b"content").unwrap();
        let dest = dir.path().join("dest");
        std::fs::create_dir(&dest).unwrap();
        let dest_dir = NoFollowDir::open(&dest).unwrap();
        let file = NoFollowPath::resolve(&source)
            .unwrap()
            .classify_regular()
            .unwrap();
        file.link_into(&dest_dir, OsStr::new("staged.txt")).unwrap();
        let staged = dest.join("staged.txt");
        let source_meta = std::fs::metadata(&source).unwrap();
        let staged_meta = std::fs::metadata(&staged).unwrap();
        assert_eq!(source_meta.ino(), staged_meta.ino());
        assert_eq!(staged_meta.nlink(), 2);
        assert_eq!(std::fs::read(&staged).unwrap(), b"content");
    }

    #[test]
    fn link_into_detects_a_leaf_swapped_after_open() {
        let dir = fixture();
        let source = dir.path().join("source.txt");
        std::fs::write(&source, b"original").unwrap();
        let decoy = dir.path().join("decoy.txt");
        std::fs::write(&decoy, b"decoy").unwrap();
        let file = NoFollowPath::resolve(&source)
            .unwrap()
            .classify_regular()
            .unwrap();
        // Swap the leaf after classification, before the link.
        std::fs::rename(&decoy, &source).unwrap();
        let dest = dir.path().join("dest");
        std::fs::create_dir(&dest).unwrap();
        let dest_dir = NoFollowDir::open(&dest).unwrap();
        match file.link_into(&dest_dir, OsStr::new("staged.txt")) {
            Err(StageError::SourceChanged {
                cleanup: CleanupOutcome::Removed,
            }) => {}
            other => panic!("expected SourceChanged/Removed, got {other:?}"),
        }
        assert!(!dest.join("staged.txt").exists());
        assert_eq!(std::fs::metadata(&source).unwrap().nlink(), 1);
    }

    #[test]
    fn link_into_surfaces_the_os_error() {
        let dir = fixture();
        let source = dir.path().join("source.txt");
        std::fs::write(&source, b"content").unwrap();
        let dest = dir.path().join("dest");
        std::fs::create_dir(&dest).unwrap();
        let file = NoFollowPath::resolve(&source)
            .unwrap()
            .classify_regular()
            .unwrap();
        let dest_dir = NoFollowDir::open(&dest).unwrap();
        dest_dir.restrict_to_owner().unwrap();
        // Make the destination non-writable for this process.
        std::fs::set_permissions(&dest, std::fs::Permissions::from_mode(0o500)).unwrap();
        let result = file.link_into(&dest_dir, OsStr::new("staged.txt"));
        std::fs::set_permissions(&dest, std::fs::Permissions::from_mode(0o700)).unwrap();
        match result {
            Err(StageError::Link(error)) => {
                assert_eq!(error.raw_os_error(), Some(libc::EACCES));
            }
            other => panic!("expected Link(EACCES), got {other:?}"),
        }
        let _ = dest_dir;
    }

    #[test]
    fn copy_into_creates_exclusively_with_the_source_mode() {
        let dir = fixture();
        let source = dir.path().join("source.txt");
        std::fs::write(&source, b"payload").unwrap();
        std::fs::set_permissions(&source, std::fs::Permissions::from_mode(0o640)).unwrap();
        let dest = dir.path().join("dest");
        std::fs::create_dir(&dest).unwrap();
        let dest_dir = NoFollowDir::open(&dest).unwrap();
        let file = NoFollowPath::resolve(&source)
            .unwrap()
            .classify_regular()
            .unwrap();
        file.copy_into(&dest_dir, OsStr::new("copy.txt")).unwrap();
        let copied = dest.join("copy.txt");
        assert_eq!(std::fs::read(&copied).unwrap(), b"payload");
        assert_eq!(std::fs::metadata(&copied).unwrap().nlink(), 1);
        assert_eq!(
            std::fs::metadata(&copied).unwrap().permissions().mode() & 0o7777,
            0o640
        );
        // Existing destination name is refused.
        match file.copy_into(&dest_dir, OsStr::new("copy.txt")) {
            Err(CopyError::Operation { source, .. }) => {
                assert_eq!(source.raw_os_error(), Some(libc::EEXIST));
            }
            other => panic!("expected AlreadyExists, got {other:?}"),
        }
    }

    #[test]
    fn copy_into_propagates_the_full_source_mode() {
        let dir = fixture();
        let source = dir.path().join("setuid.txt");
        std::fs::write(&source, b"x").unwrap();
        std::fs::set_permissions(&source, std::fs::Permissions::from_mode(0o4755)).unwrap();
        let dest = dir.path().join("dest");
        std::fs::create_dir(&dest).unwrap();
        let dest_dir = NoFollowDir::open(&dest).unwrap();
        let file = NoFollowPath::resolve(&source)
            .unwrap()
            .classify_regular()
            .unwrap();
        file.copy_into(&dest_dir, OsStr::new("c.txt")).unwrap();
        let mode = std::fs::metadata(dest.join("c.txt"))
            .unwrap()
            .permissions()
            .mode();
        assert_eq!(mode & 0o7777, 0o4755);
    }

    #[test]
    fn create_subdir_ignores_the_umask() {
        // Run under a distinct umask in an isolated subprocess: changing the
        // host umask in the shared test process would race parallel tests.
        for mask in ["000", "077", "777"] {
            let exe = std::env::current_exe().unwrap();
            let status = std::process::Command::new("/bin/sh")
                .arg("-c")
                .arg(
                    "umask \"$1\"; exec \"$0\" --exact nofollow::tests::create_subdir_umask_worker",
                )
                .arg(&exe)
                .arg(mask)
                .env("MSB_NOFOLLOW_UMASK_WORKER", mask)
                .status()
                .unwrap();
            assert!(status.success(), "worker failed under umask {mask}");
        }
    }

    #[test]
    fn create_subdir_umask_worker() {
        let Ok(mask) = std::env::var("MSB_NOFOLLOW_UMASK_WORKER") else {
            return;
        };
        let expected = u32::from_str_radix(mask.trim_start_matches('0'), 8).unwrap_or(0);
        let dir = fixture();
        // Under umask 0777 the fixture itself is created mode 0000; restore
        // owner access so the directory under test is reachable, then rely on
        // the fork child's own umask for the subdirectory mode.
        std::fs::set_permissions(dir.path(), std::fs::Permissions::from_mode(0o700)).unwrap();
        let root = NoFollowDir::open(dir.path()).unwrap();
        let sub = root.create_subdir(OsStr::new("tag"), 0o700).unwrap();
        assert_eq!(
            std::fs::metadata(sub.path()).unwrap().permissions().mode() & 0o7777,
            0o700,
            "umask {mask} must not narrow the stage directory mode"
        );
        // The fork child must not mutate the host process umask.
        let current = unsafe { libc::umask(0) } as u32;
        unsafe { libc::umask(current as libc::mode_t) };
        assert_eq!(current, expected, "host umask must be unchanged");
    }

    #[test]
    fn parent_foreign_writable_reads_the_held_parent_descriptor() {
        let dir = fixture();
        let file = dir.path().join("f.txt");
        std::fs::write(&file, b"x").unwrap();
        for (mode, expected) in [
            (0o700, false),
            (0o755, false),
            (0o770, true),
            (0o702, true),
            (0o777, true),
            (0o1777, true),
        ] {
            std::fs::set_permissions(dir.path(), std::fs::Permissions::from_mode(mode)).unwrap();
            let resolved = NoFollowPath::resolve(&file)
                .unwrap()
                .classify_regular()
                .unwrap();
            assert_eq!(
                resolved.parent_is_foreign_writable().unwrap(),
                expected,
                "mode {mode:04o}"
            );
        }
        std::fs::set_permissions(dir.path(), std::fs::Permissions::from_mode(0o700)).unwrap();
    }

    #[test]
    fn create_stage_beside_pins_created_directory() {
        let dir = fixture();
        let file = dir.path().join("f.txt");
        std::fs::write(&file, b"x").unwrap();
        let resolved = NoFollowPath::resolve(&file)
            .unwrap()
            .classify_regular()
            .unwrap();
        let stage = resolved.create_stage_beside().unwrap();
        assert_eq!(
            std::fs::metadata(stage.path())
                .unwrap()
                .permissions()
                .mode()
                & 0o7777,
            0o700
        );
        let identity = stage.identity();
        let stat = std::fs::metadata(stage.path()).unwrap();
        assert_eq!(stat.dev(), identity.dev);
        assert_eq!(stat.ino(), identity.ino);
        stage.keep();
    }

    #[test]
    fn resolve_accepts_parent_dir_components() {
        let dir = fixture();
        let sources = dir.path().join("sources");
        std::fs::create_dir(&sources).unwrap();
        let file = sources.join("f.txt");
        std::fs::write(&file, b"x").unwrap();
        let via_dotdot = sources.join("..").join("sources").join("f.txt");
        let resolved = NoFollowPath::resolve(&via_dotdot).unwrap();
        assert_eq!(resolved.leaf_kind().unwrap(), LeafKind::Regular);
        // A `..` after a missing component must not cancel lexically.
        let missing = dir
            .path()
            .join("nope")
            .join("..")
            .join("sources")
            .join("f.txt");
        assert!(matches!(
            NoFollowPath::resolve(&missing),
            Err(NoFollowError::Unresolved { .. })
        ));
    }

    #[test]
    fn create_stage_beside_rejects_a_foreign_owned_pinned_descriptor() {
        let dir = fixture();
        let source = dir.path().join("source.txt");
        std::fs::write(&source, b"x").unwrap();
        std::fs::set_permissions(dir.path(), std::fs::Permissions::from_mode(0o700)).unwrap();
        let file = NoFollowPath::resolve(&source)
            .unwrap()
            .classify_regular()
            .unwrap();
        // Observe a uid guaranteed to differ from the caller's effective uid, so
        // the ownership check (not the mode check) rejects the pinned descriptor.
        let foreign_uid = unsafe { libc::geteuid() }.wrapping_add(1);
        let result = file.create_stage_beside_with_override(StageOverrides {
            uid: Some(foreign_uid),
            force_foreign_writable: true,
            ..StageOverrides::default()
        });
        match result {
            Err(StageCreateError { operation, .. }) => {
                assert!(
                    operation.contains("validate pinned"),
                    "the pinned-descriptor validation must fire: {operation}"
                );
            }
            Ok(_) => panic!("a foreign-owned pinned descriptor must be rejected"),
        }
    }

    #[test]
    fn stage_verification_and_cleanup_errors_are_distinct() {
        let dir = fixture();
        let source = dir.path().join("source.txt");
        std::fs::write(&source, b"payload").unwrap();
        let dest = dir.path().join("dest");
        std::fs::create_dir(&dest).unwrap();
        let dest_dir = NoFollowDir::open(&dest).unwrap();
        let file = NoFollowPath::resolve(&source)
            .unwrap()
            .classify_regular()
            .unwrap();

        // (1) Verification stat fails with EIO; removal succeeds.
        match file.link_into_with_faults(
            &dest_dir,
            OsStr::new("a.txt"),
            LinkFaults {
                verify_stat_errno: Some(libc::EIO),
                unlink_errno: None,
            },
        ) {
            Err(StageError::Unverifiable {
                source,
                cleanup: CleanupOutcome::Removed,
            }) => assert_eq!(source.raw_os_error(), Some(libc::EIO)),
            other => panic!("expected Unverifiable/Removed, got {other:?}"),
        }
        assert!(!dest.join("a.txt").exists());

        // (2) A detected mismatch whose cleanup unlink fails with EACCES keeps
        // the attempted entry, reported with the stage path and identity.
        let decoy = dir.path().join("decoy.txt");
        std::fs::write(&decoy, b"decoy").unwrap();
        std::fs::rename(&decoy, &source).unwrap();
        match file.link_into_with_faults(
            &dest_dir,
            OsStr::new("b.txt"),
            LinkFaults {
                verify_stat_errno: None,
                unlink_errno: Some(libc::EACCES),
            },
        ) {
            Err(StageError::SourceChanged {
                cleanup:
                    CleanupOutcome::Retained {
                        source,
                        stage,
                        identity,
                        ..
                    },
            }) => {
                assert_eq!(source.raw_os_error(), Some(libc::EACCES));
                assert_eq!(stage, dest);
                assert_eq!(identity, dest_dir.identity());
            }
            other => panic!("expected SourceChanged/Retained, got {other:?}"),
        }
        assert!(
            dest.join("b.txt").exists(),
            "a failed cleanup must report the retained entry, never claim removal"
        );

        // (3) Verification stat EIO and cleanup unlink EACCES: the cause is the
        // verification error, and the entry is reported retained.
        match file.link_into_with_faults(
            &dest_dir,
            OsStr::new("c.txt"),
            LinkFaults {
                verify_stat_errno: Some(libc::EIO),
                unlink_errno: Some(libc::EACCES),
            },
        ) {
            Err(StageError::Unverifiable {
                source,
                cleanup: CleanupOutcome::Retained { .. },
            }) => assert_eq!(source.raw_os_error(), Some(libc::EIO)),
            other => panic!("expected Unverifiable/Retained, got {other:?}"),
        }
        assert!(dest.join("c.txt").exists());
    }

    #[test]
    fn copy_source_errors_are_phase2_errors() {
        let dir = fixture();
        let source = dir.path().join("source.txt");
        std::fs::write(&source, b"payload").unwrap();
        let dest = dir.path().join("dest");
        std::fs::create_dir(&dest).unwrap();
        let dest_dir = NoFollowDir::open(&dest).unwrap();
        let file = NoFollowPath::resolve(&source)
            .unwrap()
            .classify_regular()
            .unwrap();

        match file.copy_into_with_faults(
            &dest_dir,
            OsStr::new("o.txt"),
            CopyFaults {
                open_errno: Some(libc::EACCES),
                ..CopyFaults::default()
            },
        ) {
            Err(CopyError::Source(CopySourceError::Open(error))) => {
                assert_eq!(error.raw_os_error(), Some(libc::EACCES));
            }
            other => panic!("expected Source/Open, got {other:?}"),
        }
        match file.copy_into_with_faults(
            &dest_dir,
            OsStr::new("s.txt"),
            CopyFaults {
                stat_errno: Some(libc::EIO),
                ..CopyFaults::default()
            },
        ) {
            Err(CopyError::Source(CopySourceError::Stat(error))) => {
                assert_eq!(error.raw_os_error(), Some(libc::EIO));
            }
            other => panic!("expected Source/Stat, got {other:?}"),
        }
        match file.copy_into_with_faults(
            &dest_dir,
            OsStr::new("n.txt"),
            CopyFaults {
                non_regular: true,
                ..CopyFaults::default()
            },
        ) {
            Err(CopyError::Source(CopySourceError::NonRegular)) => {}
            other => panic!("expected Source/NonRegular, got {other:?}"),
        }
        match file.copy_into_with_faults(
            &dest_dir,
            OsStr::new("c.txt"),
            CopyFaults {
                changed: true,
                ..CopyFaults::default()
            },
        ) {
            Err(CopyError::Source(CopySourceError::Changed)) => {}
            other => panic!("expected Source/Changed, got {other:?}"),
        }
        // No copy destination may be created before the source is verified.
        for name in ["o.txt", "s.txt", "n.txt", "c.txt"] {
            assert!(!dest.join(name).exists(), "{name} must not exist");
        }
    }

    //----------------------------------------------------------------------------------------------
    // Independent-review follow-up: cleanup identity, worker robustness, umask copy, Darwin ACLs
    //----------------------------------------------------------------------------------------------

    #[test]
    fn close_reports_a_replaced_tag_and_preserves_the_replacement() {
        let dir = fixture();
        let source = dir.path().join("source.txt");
        std::fs::write(&source, b"payload").unwrap();
        let file = NoFollowPath::resolve(&source)
            .unwrap()
            .classify_regular()
            .unwrap();
        let mut stage = file.create_stage_beside().unwrap();
        stage.create_tag(OsStr::new("fm_test")).unwrap();
        let tag_path = stage.dir().path().to_path_buf();
        // Replace the tag by name; the held descriptor still points at the
        // original, so cleanup must not delete the replacement.
        let held = tag_path.with_extension("msb-held-tag");
        std::fs::rename(&tag_path, &held).unwrap();
        std::fs::create_dir(&tag_path).unwrap();
        let error = stage.close().expect_err("a replaced tag is retained");
        assert!(held.exists(), "the original tag directory must remain");
        assert!(
            tag_path.exists(),
            "the same-name replacement must not be removed"
        );
        assert!(error.to_string().contains("replacement"), "{error}");
    }

    #[test]
    fn close_reports_a_replaced_root_and_preserves_the_replacement() {
        let dir = fixture();
        let source = dir.path().join("source.txt");
        std::fs::write(&source, b"payload").unwrap();
        let file = NoFollowPath::resolve(&source)
            .unwrap()
            .classify_regular()
            .unwrap();
        let stage = file.create_stage_beside().unwrap();
        let root_path = stage.path().to_path_buf();
        let held = root_path.with_extension("msb-held-root");
        std::fs::rename(&root_path, &held).unwrap();
        std::fs::create_dir(&root_path).unwrap();
        let error = stage.close().expect_err("a replaced root is retained");
        assert!(held.exists(), "the original root directory must remain");
        assert!(
            root_path.exists(),
            "the same-name replacement must not be removed"
        );
        assert!(error.to_string().contains("replacement"), "{error}");
    }

    #[test]
    fn close_reports_a_renamed_root() {
        let dir = fixture();
        let source = dir.path().join("source.txt");
        std::fs::write(&source, b"payload").unwrap();
        let file = NoFollowPath::resolve(&source)
            .unwrap()
            .classify_regular()
            .unwrap();
        let stage = file.create_stage_beside().unwrap();
        let root_path = stage.path().to_path_buf();
        let held = root_path.with_extension("msb-held-root");
        std::fs::rename(&root_path, &held).unwrap();
        let error = stage
            .close()
            .expect_err("a renamed root is retained, not claimed removed");
        assert!(held.exists());
        assert!(error.to_string().contains("renamed away"), "{error}");
    }

    #[test]
    fn close_retains_the_root_when_a_swap_lands_between_the_check_and_removal() {
        // A group/other-writable non-sticky parent lets another principal rename
        // the stage root between the identity check and the `unlinkat`, so the
        // checked identity cannot be tied to the removal: cleanup must retain and
        // report rather than delete (a replacement, or the original, wrongly).
        let dir = fixture();
        std::fs::set_permissions(dir.path(), std::fs::Permissions::from_mode(0o777)).unwrap();
        let source = dir.path().join("source.txt");
        std::fs::write(&source, b"payload").unwrap();
        let file = NoFollowPath::resolve(&source)
            .unwrap()
            .classify_regular()
            .unwrap();
        let stage = file.create_stage_beside().unwrap();
        let root_path = stage.path().to_path_buf();
        let swapped = root_path.with_extension("msb-swapped");
        SWAP_ROOT_BEFORE_REMOVAL.with(|flag| flag.set(true));
        let error = stage
            .close()
            .expect_err("a root swap in the removal window must be retained");
        SWAP_ROOT_BEFORE_REMOVAL.with(|flag| flag.set(false));
        std::fs::set_permissions(dir.path(), std::fs::Permissions::from_mode(0o700)).unwrap();
        assert!(
            swapped.exists(),
            "the renamed original root must be retained"
        );
        assert!(
            root_path.exists(),
            "the same-name replacement must not be removed"
        );
        assert!(
            error.to_string().contains("cannot be tied to a removal"),
            "retention must be reported truthfully: {error}"
        );
        let _ = std::fs::remove_dir_all(&swapped);
        let _ = std::fs::remove_dir_all(&root_path);
    }

    #[test]
    fn close_removes_the_root_from_a_sticky_parent() {
        // A sticky parent blocks a non-owner from renaming the caller's fresh
        // entry, so the check/unlink race is unreachable and cleanup removes the
        // stage (it must not leak stages in a `/tmp`-style directory).
        let dir = fixture();
        std::fs::set_permissions(dir.path(), std::fs::Permissions::from_mode(0o1777)).unwrap();
        let source = dir.path().join("source.txt");
        std::fs::write(&source, b"payload").unwrap();
        let file = NoFollowPath::resolve(&source)
            .unwrap()
            .classify_regular()
            .unwrap();
        let stage = file.create_stage_beside().unwrap();
        let root_path = stage.path().to_path_buf();
        stage.close().expect("a sticky parent permits removal");
        std::fs::set_permissions(dir.path(), std::fs::Permissions::from_mode(0o700)).unwrap();
        assert!(
            !root_path.exists(),
            "the stage root must be removed from a sticky caller-owned parent"
        );
    }

    #[cfg(target_os = "macos")]
    #[test]
    fn close_retains_the_root_when_an_acl_only_0755_parent_permits_a_swap() {
        // A caller-owned, non-sticky `0755` parent has no mode write bits, so a
        // mode-only check calls removal safe. A foreign extended-ACL grant of the
        // parent-only swap rights (`delete_child,search`) — which need not be
        // inherited onto the private `0700` root — lets another principal perform
        // a same-parent `renameatx_np(RENAME_SWAP)` after the identity stat, so
        // cleanup must treat the ACL and retain.
        let dir = fixture();
        std::fs::set_permissions(dir.path(), std::fs::Permissions::from_mode(0o755)).unwrap();
        let source = dir.path().join("source.txt");
        std::fs::write(&source, b"payload").unwrap();
        let file = NoFollowPath::resolve(&source)
            .unwrap()
            .classify_regular()
            .unwrap();
        set_acl(dir.path(), "everyone allow delete_child,search");
        let stage = file.create_stage_beside().unwrap();
        let root_path = stage.path().to_path_buf();
        let swapped = root_path.with_extension("msb-swapped");
        SWAP_ROOT_BEFORE_REMOVAL.with(|flag| flag.set(true));
        let error = stage
            .close()
            .expect_err("a foreign ACL grant on the parent must retain the root");
        SWAP_ROOT_BEFORE_REMOVAL.with(|flag| flag.set(false));
        clear_acl(dir.path());
        std::fs::set_permissions(dir.path(), std::fs::Permissions::from_mode(0o700)).unwrap();
        assert!(
            root_path.exists(),
            "the same-name replacement must not be removed"
        );
        assert!(
            swapped.exists(),
            "the renamed original root must be retained under the decoy name"
        );
        assert!(
            error.to_string().contains("cannot be tied to a removal"),
            "retention must be reported truthfully: {error}"
        );
        let message = error.to_string();
        assert!(
            message.contains("dev=") && message.contains("ino="),
            "the retained original's identity must reach the caller: {message}"
        );
        let _ = std::fs::remove_dir_all(&swapped);
        let _ = std::fs::remove_dir_all(&root_path);
    }

    #[cfg(target_os = "macos")]
    #[test]
    fn close_retains_the_root_when_a_foreign_delete_child_acl_overrides_sticky() {
        // A sticky `1777` parent normally makes removal safe (a non-owner cannot
        // rename the caller's fresh entry). XNU's `vnode_authorize_delete` gives a
        // parent `DELETE_CHILD` ACE priority over the sticky deny, so a foreign
        // grant of it reopens the swap for a same-parent `RENAME_SWAP`; cleanup
        // must retain rather than treat the sticky bit as mitigating.
        let dir = fixture();
        std::fs::set_permissions(dir.path(), std::fs::Permissions::from_mode(0o1777)).unwrap();
        let source = dir.path().join("source.txt");
        std::fs::write(&source, b"payload").unwrap();
        let file = NoFollowPath::resolve(&source)
            .unwrap()
            .classify_regular()
            .unwrap();
        set_acl(dir.path(), "everyone allow delete_child");
        let stage = file.create_stage_beside().unwrap();
        let root_path = stage.path().to_path_buf();
        let swapped = root_path.with_extension("msb-swapped");
        SWAP_ROOT_BEFORE_REMOVAL.with(|flag| flag.set(true));
        let error = stage
            .close()
            .expect_err("a foreign DELETE_CHILD grant overrides the sticky carve-out");
        SWAP_ROOT_BEFORE_REMOVAL.with(|flag| flag.set(false));
        clear_acl(dir.path());
        std::fs::set_permissions(dir.path(), std::fs::Permissions::from_mode(0o700)).unwrap();
        assert!(
            root_path.exists(),
            "the same-name replacement must not be removed"
        );
        assert!(
            swapped.exists(),
            "the renamed original root must be retained under the decoy name"
        );
        assert!(
            error.to_string().contains("cannot be tied to a removal"),
            "retention must be reported truthfully: {error}"
        );
        let message = error.to_string();
        assert!(
            message.contains("dev=") && message.contains("ino="),
            "the retained original's identity must reach the caller: {message}"
        );
        let _ = std::fs::remove_dir_all(&swapped);
        let _ = std::fs::remove_dir_all(&root_path);
    }

    #[test]
    fn create_dir_reports_a_directory_left_by_a_post_mkdir_failure() {
        let dir = fixture();
        let source = dir.path().join("source.txt");
        std::fs::write(&source, b"x").unwrap();
        let file = NoFollowPath::resolve(&source)
            .unwrap()
            .classify_regular()
            .unwrap();
        FAIL_OPEN_AFTER_MKDIR.with(|flag| flag.set(true));
        let result = file.create_stage_beside();
        FAIL_OPEN_AFTER_MKDIR.with(|flag| flag.set(false));
        let error = result.expect_err("a post-mkdir acquisition failure is an error");
        let (path, identity) = error
            .retained
            .clone()
            .expect("the created-but-unacquired directory must be reported");
        assert!(
            identity.is_none(),
            "no identity is knowable before acquisition"
        );
        assert!(
            path.exists(),
            "the reported locator must be the real directory"
        );
        std::fs::remove_dir(&path).unwrap();
    }

    #[test]
    fn parent_is_foreign_writable_uses_ownership_not_only_mode() {
        if unsafe { libc::geteuid() } == 0 {
            eprintln!("skipping ownership test: running as root");
            return;
        }
        // A root-owned 0755 directory is not group/other-writable, but it is
        // owned by another principal, so the gate must fire on ownership alone.
        let candidate = ["/usr/bin/true", "/usr/bin/env"]
            .into_iter()
            .find_map(|path| {
                let parent = std::path::Path::new(path).parent()?;
                let meta = std::fs::metadata(path).ok()?;
                let parent_meta = std::fs::metadata(parent).ok()?;
                (meta.is_file()
                    && parent_meta.uid() == 0
                    && parent_meta.permissions().mode() & 0o7777 == 0o755)
                    .then_some(path)
            });
        let Some(path) = candidate else {
            eprintln!("skipping ownership test: no root-owned 0755 parent fixture found");
            return;
        };
        let file = NoFollowPath::resolve(std::path::Path::new(path))
            .unwrap()
            .classify_regular()
            .unwrap();
        assert!(
            file.parent_is_foreign_writable().unwrap(),
            "a foreign-owned 0755 parent must be treated as foreign-writable"
        );
    }

    #[test]
    fn control_buffer_is_aligned_for_a_cmsghdr() {
        assert!(
            std::mem::align_of::<ControlBuffer>() >= std::mem::align_of::<libc::cmsghdr>(),
            "the ancillary buffer must satisfy cmsghdr alignment"
        );
        assert!(
            std::mem::size_of::<ControlBuffer>() >= unsafe { libc::CMSG_SPACE(4) } as usize,
            "the ancillary buffer must hold one descriptor control message"
        );
    }

    fn socket_pair() -> (RawFd, RawFd) {
        let mut fds = [0i32; 2];
        let ret =
            unsafe { libc::socketpair(libc::AF_UNIX, libc::SOCK_STREAM, 0, fds.as_mut_ptr()) };
        assert_eq!(ret, 0, "socketpair failed");
        (fds[0], fds[1])
    }

    #[test]
    fn parent_recv_rejects_a_short_status_word() {
        let (a, b) = socket_pair();
        let written = unsafe { libc::write(b, b"x".as_ptr() as *const libc::c_void, 1) };
        assert_eq!(written, 1);
        let result = parent_recv(a);
        unsafe {
            libc::close(a);
            libc::close(b);
        }
        assert!(result.is_err(), "a one-byte status word must be rejected");
    }

    #[repr(C)]
    struct BigControl {
        cmsg: libc::cmsghdr,
        rest: [u8; 256],
    }

    /// Send `status` bytes plus zero or more descriptors as one `SCM_RIGHTS`
    /// control message.
    fn send_status_bytes_with_fds(sock: RawFd, status: &[u8], fds: &[RawFd]) {
        let mut iov = libc::iovec {
            iov_base: status.as_ptr() as *mut libc::c_void,
            iov_len: status.len(),
        };
        let mut control: BigControl = unsafe { std::mem::zeroed() };
        let mut msg: libc::msghdr = unsafe { std::mem::zeroed() };
        msg.msg_iov = &mut iov;
        msg.msg_iovlen = 1;
        if !fds.is_empty() {
            let byte_len = std::mem::size_of_val(fds);
            assert!(
                byte_len <= control.rest.len(),
                "test control buffer too small"
            );
            unsafe {
                control.cmsg.cmsg_len = libc::CMSG_LEN(byte_len as u32) as _;
                control.cmsg.cmsg_level = libc::SOL_SOCKET;
                control.cmsg.cmsg_type = libc::SCM_RIGHTS;
                std::ptr::copy_nonoverlapping(
                    fds.as_ptr() as *const u8,
                    libc::CMSG_DATA(&control.cmsg),
                    byte_len,
                );
            }
            msg.msg_control = (&mut control.cmsg as *mut libc::cmsghdr).cast();
            msg.msg_controllen = unsafe { libc::CMSG_SPACE(byte_len as u32) } as _;
        }
        let ret = unsafe { libc::sendmsg(sock, &msg, 0) };
        assert!(ret >= 0, "sendmsg failed: {}", io::Error::last_os_error());
    }

    /// Send a four-byte status word plus zero or more descriptors.
    fn send_status_with_fds(sock: RawFd, status: [u8; 4], fds: &[RawFd]) {
        send_status_bytes_with_fds(sock, &status, fds);
    }

    /// A synthetic received ancillary buffer, so parser-seam tests can model a
    /// kernel-truncated or malformed control message without sending (and thus
    /// installing) the kernel's own unreported excess descriptors.
    #[repr(C)]
    struct SyntheticControl {
        cmsg: libc::cmsghdr,
        data: [u8; 64],
    }

    /// Build a synthetic received `msghdr` over `control` holding the first
    /// `present_data` bytes of `fds` and declaring `declared_data` bytes of
    /// payload in `cmsg_len`. When `declared_data > present_data` the buffer
    /// models a kernel-truncated copy: the declared length is intact but fewer
    /// bytes are present.
    fn synthetic_control_msg(
        control: &mut SyntheticControl,
        fds: &[RawFd],
        declared_data: usize,
        present_data: usize,
        level: libc::c_int,
        kind: libc::c_int,
        flags: libc::c_int,
    ) -> libc::msghdr {
        let header = unsafe { libc::CMSG_LEN(0) } as usize;
        assert!(present_data <= control.data.len());
        assert!(present_data <= std::mem::size_of_val(fds));
        control.cmsg = unsafe { std::mem::zeroed() };
        control.cmsg.cmsg_len = (header + declared_data) as _;
        control.cmsg.cmsg_level = level;
        control.cmsg.cmsg_type = kind;
        unsafe {
            std::ptr::copy_nonoverlapping(
                fds.as_ptr() as *const u8,
                libc::CMSG_DATA(&control.cmsg),
                present_data,
            );
        }
        let mut msg: libc::msghdr = unsafe { std::mem::zeroed() };
        msg.msg_control = (&mut control.cmsg as *mut libc::cmsghdr).cast();
        msg.msg_controllen = (header + present_data) as _;
        msg.msg_flags = flags;
        msg
    }

    #[test]
    fn parent_recv_accepts_one_descriptor_for_a_success_status() {
        let (a, b) = socket_pair();
        let sent = unsafe { libc::open(c"/dev/null".as_ptr(), libc::O_RDONLY) };
        assert!(sent >= 0);
        send_status_with_fds(b, [0, 0, 0, 0], &[sent]);
        let result = parent_recv(a);
        unsafe {
            libc::close(sent);
            libc::close(a);
            libc::close(b);
        }
        let (fd, status) = result.expect("a one-descriptor success message is well formed");
        assert_eq!(status, 0);
        let fd = fd.expect("status 0 must deliver exactly one descriptor");
        let mut stat: libc::stat = unsafe { std::mem::zeroed() };
        assert_eq!(unsafe { libc::fstat(fd.as_raw_fd(), &mut stat) }, 0);
    }

    #[test]
    fn parent_recv_accepts_no_descriptor_for_a_failure_status() {
        let (a, b) = socket_pair();
        send_status_with_fds(b, libc::EACCES.to_ne_bytes(), &[]);
        let result = parent_recv(a);
        unsafe {
            libc::close(a);
            libc::close(b);
        }
        let (fd, status) = result.expect("a control-free failure status is well formed");
        assert!(
            fd.is_none(),
            "a failure status must not deliver a descriptor"
        );
        assert_eq!(status, libc::EACCES);
    }

    #[test]
    fn parent_recv_rejects_a_missing_descriptor() {
        let (a, b) = socket_pair();
        send_status_with_fds(b, [0, 0, 0, 0], &[]);
        let result = parent_recv(a);
        unsafe {
            libc::close(a);
            libc::close(b);
        }
        assert!(
            result.is_err(),
            "status 0 with no descriptor must be refused"
        );
    }

    #[test]
    fn parent_recv_rejects_extra_descriptors() {
        // The trusted creation child sends at most one descriptor, so a receiver
        // exchange sized for the bounded sender never truncates. Surplus but
        // **untruncated** rights (here two, which fit the buffer) must still be
        // refused; truncation refusal is covered by the parser seam.
        let (a, b) = socket_pair();
        let fds = [
            unsafe { libc::open(c"/dev/null".as_ptr(), libc::O_RDONLY) },
            unsafe { libc::open(c"/dev/null".as_ptr(), libc::O_RDONLY) },
        ];
        assert!(fds.iter().all(|fd| *fd >= 0));
        send_status_with_fds(b, [0, 0, 0, 0], &fds);
        let result = parent_recv(a);
        for fd in fds {
            unsafe { libc::close(fd) };
        }
        unsafe {
            libc::close(a);
            libc::close(b);
        }
        assert!(
            result.is_err(),
            "more than the expected descriptor must be refused"
        );
    }

    #[test]
    fn parent_recv_rejects_a_descriptor_on_a_failure_status() {
        let (a, b) = socket_pair();
        let sent = unsafe { libc::open(c"/dev/null".as_ptr(), libc::O_RDONLY) };
        assert!(sent >= 0);
        send_status_with_fds(b, libc::EACCES.to_ne_bytes(), &[sent]);
        let result = parent_recv(a);
        unsafe {
            libc::close(sent);
            libc::close(a);
            libc::close(b);
        }
        assert!(
            result.is_err(),
            "a descriptor on a failure status must be refused"
        );
    }

    #[test]
    fn parse_control_descriptors_rejects_a_malformed_control_message() {
        // A wrong `cmsg_level` must be flagged before the payload is
        // interpreted. The synthetic buffer holds no descriptor bytes, so no
        // kernel-backed descriptor is installed by this test.
        let mut control: SyntheticControl = unsafe { std::mem::zeroed() };
        let msg = synthetic_control_msg(
            &mut control,
            &[],
            0,
            0,
            /* level */ 0,
            libc::SCM_RIGHTS,
            0,
        );
        let parsed = parse_control_descriptors(&msg);
        assert!(
            parsed.malformed,
            "a wrong-level control message must be flagged malformed"
        );
        assert!(parsed.descriptors.is_empty());
    }

    #[test]
    fn parent_recv_rejects_surplus_untruncated_descriptors() {
        // The trusted creation child sends at most one descriptor, so a receiver
        // exchange sized for the bounded sender never truncates; surplus but
        // **untruncated** rights (here two, which fit the buffer) must still be
        // refused. Truncation refusal is covered by the parser seam.
        let (a, b) = socket_pair();
        let fds = [
            unsafe { libc::open(c"/dev/null".as_ptr(), libc::O_RDONLY) },
            unsafe { libc::open(c"/dev/null".as_ptr(), libc::O_RDONLY) },
        ];
        assert!(fds.iter().all(|fd| *fd >= 0));
        send_status_with_fds(b, [0, 0, 0, 0], &fds);
        let result = parent_recv(a);
        for fd in fds {
            unsafe { libc::close(fd) };
        }
        unsafe {
            libc::close(a);
            libc::close(b);
        }
        assert!(result.is_err(), "surplus descriptors must be refused");
    }

    #[test]
    fn parent_recv_reclaims_descriptors_on_every_rejection() {
        let exe = std::env::current_exe().unwrap();
        let status = std::process::Command::new(&exe)
            .arg("--exact")
            .arg("nofollow::tests::recv_rejection_fd_worker")
            .env("MSB_NOFOLLOW_RECV_FD_WORKER", "1")
            .status()
            .unwrap();
        assert!(
            status.success(),
            "the receive-rejection fd worker must succeed"
        );
    }

    #[test]
    fn recv_rejection_fd_worker() {
        if std::env::var_os("MSB_NOFOLLOW_RECV_FD_WORKER").is_none() {
            return;
        }
        let baseline = open_fd_count();

        // Real socket exchange: short status word **with** a descriptor. The
        // status is refused, but the already-installed descriptor must still be
        // reclaimed (this is the regression the previous short-status test, which
        // sent no rights, could not catch).
        {
            let (a, b) = socket_pair();
            let sent = unsafe { libc::open(c"/dev/null".as_ptr(), libc::O_RDONLY) };
            assert!(sent >= 0);
            send_status_bytes_with_fds(b, b"x", &[sent]);
            assert!(parent_recv(a).is_err());
            unsafe {
                libc::close(sent);
                libc::close(a);
                libc::close(b);
            }
        }
        assert_eq!(
            open_fd_count(),
            baseline,
            "short-status-with-rights receive leaked"
        );

        // Real socket exchange: success status with no descriptor.
        {
            let (a, b) = socket_pair();
            send_status_with_fds(b, [0, 0, 0, 0], &[]);
            assert!(parent_recv(a).is_err());
            unsafe {
                libc::close(a);
                libc::close(b);
            }
        }
        assert_eq!(
            open_fd_count(),
            baseline,
            "missing-descriptor receive leaked"
        );

        // Real socket exchange: success status with two descriptors; both must
        // be reclaimed.
        {
            let (a, b) = socket_pair();
            let extra = [
                unsafe { libc::open(c"/dev/null".as_ptr(), libc::O_RDONLY) },
                unsafe { libc::open(c"/dev/null".as_ptr(), libc::O_RDONLY) },
            ];
            send_status_with_fds(b, [0, 0, 0, 0], &extra);
            assert!(parent_recv(a).is_err());
            for fd in extra {
                unsafe { libc::close(fd) };
            }
            unsafe {
                libc::close(a);
                libc::close(b);
            }
        }
        assert_eq!(open_fd_count(), baseline, "extra-descriptor receive leaked");

        // Real socket exchange: failure status that still delivered a descriptor.
        {
            let (a, b) = socket_pair();
            let sent = unsafe { libc::open(c"/dev/null".as_ptr(), libc::O_RDONLY) };
            send_status_with_fds(b, libc::EACCES.to_ne_bytes(), &[sent]);
            assert!(parent_recv(a).is_err());
            unsafe {
                libc::close(sent);
                libc::close(a);
                libc::close(b);
            }
        }
        assert_eq!(
            open_fd_count(),
            baseline,
            "failure-status descriptor leaked"
        );

        // Parser seam: a truncated copy. The buffer declares two descriptors but
        // contains only one, exactly as the kernel leaves a copy when it sets
        // `MSG_CTRUNC`. The seam must adopt the one descriptor present and the
        // truncation check must refuse the message, closing it. The descriptor is
        // a real open descriptor so the count is exact; no unreported descriptor
        // is manufactured.
        {
            let fd = unsafe { libc::open(c"/dev/null".as_ptr(), libc::O_RDONLY) };
            assert!(fd >= 0);
            let one = std::mem::size_of::<RawFd>();
            let mut control: SyntheticControl = unsafe { std::mem::zeroed() };
            let msg = synthetic_control_msg(
                &mut control,
                &[fd],
                /* declared */ 2 * one,
                /* present */ one,
                libc::SOL_SOCKET,
                libc::SCM_RIGHTS,
                libc::MSG_CTRUNC,
            );
            assert!(
                validate_recv_message(&msg, 4, [0, 0, 0, 0]).is_err(),
                "a truncated control message must be refused"
            );
            assert_eq!(
                unsafe { libc::fcntl(fd, libc::F_GETFD) },
                -1,
                "the descriptor present in a truncated copy must be reclaimed"
            );
        }
        assert_eq!(open_fd_count(), baseline, "truncated-copy receive leaked");

        // Parser seam: a short status carrying a descriptor must still reclaim
        // it.
        {
            let fd = unsafe { libc::open(c"/dev/null".as_ptr(), libc::O_RDONLY) };
            assert!(fd >= 0);
            let one = std::mem::size_of::<RawFd>();
            let mut control: SyntheticControl = unsafe { std::mem::zeroed() };
            let msg = synthetic_control_msg(
                &mut control,
                &[fd],
                one,
                one,
                libc::SOL_SOCKET,
                libc::SCM_RIGHTS,
                0,
            );
            assert!(validate_recv_message(&msg, 1, [0, 0, 0, 0]).is_err());
            assert_eq!(unsafe { libc::fcntl(fd, libc::F_GETFD) }, -1);
        }
        assert_eq!(
            open_fd_count(),
            baseline,
            "parser-seam short-status receive leaked"
        );

        // Parser seam: a well-formed success carrying exactly one descriptor is
        // accepted and the returned guard owns it (dropped here).
        {
            let fd = unsafe { libc::open(c"/dev/null".as_ptr(), libc::O_RDONLY) };
            assert!(fd >= 0);
            let one = std::mem::size_of::<RawFd>();
            let mut control: SyntheticControl = unsafe { std::mem::zeroed() };
            let msg = synthetic_control_msg(
                &mut control,
                &[fd],
                one,
                one,
                libc::SOL_SOCKET,
                libc::SCM_RIGHTS,
                0,
            );
            let (owned, status) = validate_recv_message(&msg, 4, [0, 0, 0, 0])
                .expect("a one-descriptor success is well formed");
            assert_eq!(status, 0);
            assert!(owned.is_some());
            drop(owned);
        }
        assert_eq!(
            open_fd_count(),
            baseline,
            "parser-seam success receive leaked"
        );
    }

    #[test]
    fn copy_into_uses_the_original_destination_fd_under_a_restrictive_umask() {
        for mask in ["000", "077", "0400", "0777"] {
            let exe = std::env::current_exe().unwrap();
            let status = std::process::Command::new("/bin/sh")
                .arg("-c")
                .arg("umask \"$1\"; exec \"$0\" --exact nofollow::tests::copy_umask_worker")
                .arg(&exe)
                .arg(mask)
                .env("MSB_NOFOLLOW_COPY_UMASK", mask)
                .status()
                .unwrap();
            assert!(status.success(), "copy worker failed under umask {mask}");
        }
    }

    #[test]
    fn copy_umask_worker() {
        let Ok(mask) = std::env::var("MSB_NOFOLLOW_COPY_UMASK") else {
            return;
        };
        let dir = fixture();
        // The fixture itself may have been created under the restrictive umask;
        // restore owner access so the directory under test is reachable.
        std::fs::set_permissions(dir.path(), std::fs::Permissions::from_mode(0o700)).unwrap();
        let source = dir.path().join("source.txt");
        std::fs::write(&source, b"payload").unwrap();
        std::fs::set_permissions(&source, std::fs::Permissions::from_mode(0o640)).unwrap();
        let dest = dir.path().join("dest");
        std::fs::create_dir(&dest).unwrap();
        std::fs::set_permissions(&dest, std::fs::Permissions::from_mode(0o700)).unwrap();
        let dest_dir = NoFollowDir::open(&dest).unwrap();
        let file = NoFollowPath::resolve(&source)
            .unwrap()
            .classify_regular()
            .unwrap();
        // Under umask 0400/0777 the O_EXCL destination is created unreadable; the
        // copy must still succeed because fchmod uses the original descriptor.
        file.copy_into(&dest_dir, OsStr::new("copy.txt")).unwrap();
        let copied = dest.join("copy.txt");
        assert_eq!(std::fs::read(&copied).unwrap(), b"payload");
        assert_eq!(
            std::fs::metadata(&copied).unwrap().permissions().mode() & 0o7777,
            0o640,
            "umask {mask} must not change the propagated source mode"
        );
    }

    #[cfg(target_os = "macos")]
    fn set_acl(path: &Path, spec: &str) {
        let status = std::process::Command::new("chmod")
            .arg("+a")
            .arg(spec)
            .arg(path)
            .status()
            .unwrap();
        assert!(
            status.success(),
            "chmod +a {spec} {} failed",
            path.display()
        );
    }

    #[cfg(target_os = "macos")]
    fn clear_acl(path: &Path) {
        let _ = std::process::Command::new("chmod")
            .arg("-N")
            .arg(path)
            .status();
    }

    #[cfg(target_os = "macos")]
    fn current_name(flag: &str) -> String {
        let out = std::process::Command::new("id").arg(flag).output().unwrap();
        String::from_utf8_lossy(&out.stdout).trim().to_string()
    }

    #[cfg(target_os = "macos")]
    #[test]
    fn darwin_acl_predicates_distinguish_foreign_and_owner_grants() {
        use std::os::unix::fs::MetadataExt;

        let dir = fixture();
        let target = dir.path().join("acl-target");
        std::fs::create_dir(&target).unwrap();
        let stat = std::fs::metadata(&target).unwrap();
        let uid = stat.uid();
        let c = cstring(target.as_os_str()).unwrap();
        let fd = unsafe {
            libc::open(
                c.as_ptr(),
                libc::O_RDONLY | libc::O_DIRECTORY | libc::O_NOFOLLOW | libc::O_CLOEXEC,
            )
        };
        assert!(fd >= 0);

        // No ACL: neither predicate fires.
        assert!(!acl_grants_foreign_write(fd, uid).unwrap());
        assert!(!acl_has_foreign_grant(fd, uid).unwrap());

        // The caller's own uid read grant is not foreign.
        let user = current_name("-un");
        let group = current_name("-gn");
        set_acl(&target, &format!("user:{user} allow read"));
        assert!(!acl_grants_foreign_write(fd, uid).unwrap());
        assert!(!acl_has_foreign_grant(fd, uid).unwrap());
        clear_acl(&target);

        // An **owning-group** read grant is foreign: the group (`staff`, say) is
        // not an owner-only principal because it contains other uids. The
        // pinned-root predicate must reject it; a read grant alone does not trip
        // the parent-write predicate.
        set_acl(&target, &format!("group:{group} allow read"));
        assert!(!acl_grants_foreign_write(fd, uid).unwrap());
        assert!(
            acl_has_foreign_grant(fd, uid).unwrap(),
            "an owning-group grant is not owner-only and must be treated as foreign"
        );
        clear_acl(&target);

        // An owning-group write grant trips both predicates.
        set_acl(&target, &format!("group:{group} allow write"));
        assert!(acl_grants_foreign_write(fd, uid).unwrap());
        assert!(acl_has_foreign_grant(fd, uid).unwrap());
        clear_acl(&target);

        // Foreign read grant: not a write grant for the parent, but a non-caller
        // granting entry the strict pinned root must reject.
        set_acl(&target, "everyone allow read");
        assert!(!acl_grants_foreign_write(fd, uid).unwrap());
        assert!(acl_has_foreign_grant(fd, uid).unwrap());
        clear_acl(&target);

        // Foreign write grant: the parent predicate fires too.
        set_acl(&target, "group:everyone allow write");
        assert!(acl_grants_foreign_write(fd, uid).unwrap());
        assert!(acl_has_foreign_grant(fd, uid).unwrap());
        clear_acl(&target);

        // The caller's own governance right (change-owner): not foreign, but the
        // strict root must reject a right that can widen access later.
        set_acl(&target, &format!("user:{user} allow chown"));
        assert!(!acl_grants_foreign_write(fd, uid).unwrap());
        assert!(acl_has_foreign_grant(fd, uid).unwrap());
        clear_acl(&target);

        // A **foreign** governance right (`writesecurity`/`changeowner`) fires
        // the parent predicate: it can widen access after the gate check without
        // changing ownership.
        set_acl(&target, "everyone allow writesecurity");
        assert!(
            acl_grants_foreign_write(fd, uid).unwrap(),
            "a foreign writesecurity grant can widen access after the gate check"
        );
        assert!(acl_has_foreign_grant(fd, uid).unwrap());
        clear_acl(&target);

        unsafe { libc::close(fd) };

        // A grant inherited onto a child is foreign on the child descriptor too.
        let child = target.join("acl-child");
        set_acl(&target, "everyone allow read,directory_inherit");
        std::fs::create_dir(&child).unwrap();
        let child_stat = std::fs::metadata(&child).unwrap();
        let child_uid = child_stat.uid();
        let child_c = cstring(child.as_os_str()).unwrap();
        let child_fd = unsafe {
            libc::open(
                child_c.as_ptr(),
                libc::O_RDONLY | libc::O_DIRECTORY | libc::O_NOFOLLOW | libc::O_CLOEXEC,
            )
        };
        assert!(child_fd >= 0);
        assert!(
            acl_has_foreign_grant(child_fd, child_uid).unwrap(),
            "an inherited non-caller grant must be foreign on the child"
        );
        unsafe {
            libc::close(child_fd);
        }
        clear_acl(&target);
    }

    #[cfg(target_os = "macos")]
    #[test]
    fn parent_is_foreign_writable_sees_an_owning_group_acl_grant() {
        // A caller-owned 0755 parent is not group/other-writable, but an owning
        // group (which contains other uids) write grant makes it writable by
        // those users, so the gate must fire.
        let dir = fixture();
        let source = dir.path().join("acl-source.txt");
        std::fs::write(&source, b"x").unwrap();
        std::fs::set_permissions(dir.path(), std::fs::Permissions::from_mode(0o755)).unwrap();
        let file = NoFollowPath::resolve(&source)
            .unwrap()
            .classify_regular()
            .unwrap();
        assert!(
            !file.parent_is_foreign_writable().unwrap(),
            "a 0755 parent with no ACL is not foreign-writable"
        );
        let group = current_name("-gn");
        set_acl(dir.path(), &format!("group:{group} allow write"));
        let gated = file.parent_is_foreign_writable().unwrap();
        clear_acl(dir.path());
        std::fs::set_permissions(dir.path(), std::fs::Permissions::from_mode(0o700)).unwrap();
        assert!(
            gated,
            "an owning-group write grant must make the parent foreign-writable"
        );
    }

    #[test]
    fn create_and_close_do_not_leak_descriptors() {
        // Run in an isolated subprocess: counting process-wide descriptors from
        // the parallel test harness would race with other tests.
        let exe = std::env::current_exe().unwrap();
        let status = std::process::Command::new(&exe)
            .arg("--exact")
            .arg("nofollow::tests::fd_leak_worker")
            .env("MSB_NOFOLLOW_FD_WORKER", "1")
            .status()
            .unwrap();
        assert!(status.success(), "the descriptor-leak worker must succeed");
    }

    #[test]
    fn fd_leak_worker() {
        if std::env::var_os("MSB_NOFOLLOW_FD_WORKER").is_none() {
            return;
        }
        let dir = fixture();
        let source = dir.path().join("source.txt");
        std::fs::write(&source, b"x").unwrap();
        let file = NoFollowPath::resolve(&source)
            .unwrap()
            .classify_regular()
            .unwrap();
        // Warm up one-time allocations before sampling the descriptor count.
        for _ in 0..2 {
            file.create_stage_beside().unwrap().close().unwrap();
        }
        let before = open_fd_count();
        for _ in 0..20 {
            file.create_stage_beside().unwrap().close().unwrap();
        }
        let after = open_fd_count();
        assert_eq!(before, after, "create/close must not leak descriptors");
    }

    #[test]
    fn create_dir_umask_safe_sets_cloexec_on_the_received_descriptor() {
        let dir = fixture();
        let root = NoFollowDir::open(dir.path()).unwrap();
        let name = cstring(OsStr::new("sub")).unwrap();
        let fd = create_dir_umask_safe(root.anchor(), &name, 0o700).unwrap();
        let flags = unsafe { libc::fcntl(fd.as_raw_fd(), libc::F_GETFD) };
        assert!(flags >= 0);
        assert_eq!(flags & libc::FD_CLOEXEC, libc::FD_CLOEXEC);
        std::fs::remove_dir(dir.path().join("sub")).unwrap();
    }

    #[cfg(unix)]
    fn open_fd_count() -> usize {
        std::fs::read_dir("/dev/fd").unwrap().count()
    }

    #[test]
    fn create_stage_beside_succeeds_under_a_low_nofile_limit() {
        let exe = std::env::current_exe().unwrap();
        let status = std::process::Command::new(&exe)
            .arg("--exact")
            .arg("nofollow::tests::low_nofile_worker")
            .env("MSB_NOFOLLOW_LOW_NOFILE", "1")
            .status()
            .unwrap();
        assert!(status.success(), "the low-nofile worker must succeed");
    }

    #[test]
    fn low_nofile_worker() {
        if std::env::var_os("MSB_NOFOLLOW_LOW_NOFILE").is_none() {
            return;
        }
        let limit = libc::rlimit {
            rlim_cur: 64,
            rlim_max: 64,
        };
        assert_eq!(unsafe { libc::setrlimit(libc::RLIMIT_NOFILE, &limit) }, 0);
        let dir = fixture();
        let source = dir.path().join("source.txt");
        std::fs::write(&source, b"x").unwrap();
        let file = NoFollowPath::resolve(&source)
            .unwrap()
            .classify_regular()
            .unwrap();
        // Many create/close cycles under a tight descriptor budget must all
        // succeed and reclaim every descriptor and child.
        for _ in 0..50 {
            file.create_stage_beside().unwrap().close().unwrap();
        }
    }

    #[test]
    fn portable_walk_counter_advances_for_parent_dir_components() {
        let dir = fixture();
        let sub = dir.path().join("sub");
        std::fs::create_dir(&sub).unwrap();
        let file = sub.join("f.txt");
        std::fs::write(&file, b"x").unwrap();
        let via = sub.join("..").join("sub").join("f.txt");
        let before = PORTABLE_WALK_CALLS.with(|calls| calls.get());
        NoFollowPath::resolve(&via).unwrap();
        let after = PORTABLE_WALK_CALLS.with(|calls| calls.get());
        assert!(
            after > before,
            "a `..` parent must use the checked portable walk"
        );
    }

    #[cfg(target_os = "linux")]
    #[test]
    fn linux_fast_path_avoids_the_portable_walk() {
        if !platform::probe_openat2() {
            eprintln!("skipping fast-path parity test: openat2 is unavailable");
            return;
        }
        let dir = fixture();
        let sub = dir.path().join("sub");
        std::fs::create_dir(&sub).unwrap();
        let file = sub.join("f.txt");
        std::fs::write(&file, b"x").unwrap();
        let before = PORTABLE_WALK_CALLS.with(|calls| calls.get());
        NoFollowPath::resolve(&file).unwrap();
        let after = PORTABLE_WALK_CALLS.with(|calls| calls.get());
        assert_eq!(
            after, before,
            "a `..`-free parent must not use the portable walk on a capable kernel"
        );
    }
}
