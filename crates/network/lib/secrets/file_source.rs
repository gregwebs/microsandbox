//! Safe host-file reader for file-backed secrets.
//!
//! [`SecretSource::File`](microsandbox_types::SecretSource::File) secrets are
//! re-read on every eligible connection (see `new_inner` in
//! `crates/network/lib/secrets/handler.rs`) so a host process rotating the
//! credential file is picked up without restarting the sandbox. This module
//! is the deep, independently-tested primitive that performs that read
//! safely: it rejects symlinks, caps the size, and never lets a failure leak
//! partial file contents into a log or error message — only the path and a
//! failure kind.
//!
//! **Limitation:** rejecting symlinks (`O_NOFOLLOW` on Unix, a reparse-point
//! check on Windows) only guards the *final* path component; a symlink in an
//! *intermediate* directory is still followed. File secrets must point at an
//! operator-controlled directory tree (e.g. `/run/creds`), not one an
//! untrusted process can write into.

use std::fs::File;
use std::io::{self, Read};
use std::path::{Path, PathBuf};

use zeroize::Zeroizing;

use super::config::MAX_SECRET_FILE_BYTES;

#[cfg(unix)]
use std::os::unix::fs::OpenOptionsExt;
#[cfg(windows)]
use std::os::windows::fs::MetadataExt;

//--------------------------------------------------------------------------------------------------
// Constants
//--------------------------------------------------------------------------------------------------

/// `FILE_ATTRIBUTE_REPARSE_POINT` from the Win32 API. Duplicated here (rather
/// than pulling in `windows-sys` for one flag) to detect a symlink/junction
/// via `symlink_metadata` before opening the file.
#[cfg(windows)]
const FILE_ATTRIBUTE_REPARSE_POINT: u32 = 0x0000_0400;

//--------------------------------------------------------------------------------------------------
// Types
//--------------------------------------------------------------------------------------------------

/// Why a file-backed secret could not be resolved for this connection.
///
/// `Display` and [`kind_str`](Self::kind_str) name the path and failure kind
/// only; neither ever carries file contents.
#[derive(Debug, thiserror::Error)]
pub(crate) enum FileSecretError {
    /// No file exists at the configured path.
    #[error("secret file {path}: not found")]
    NotFound {
        /// Configured path (not secret; safe to display and log).
        path: PathBuf,
    },

    /// The final path component is a symlink. Rejected even when the link
    /// target is itself a valid, readable file — see the module docs.
    #[error("secret file {path}: refusing to follow a symlink")]
    Symlink {
        /// Configured path (not secret; safe to display and log).
        path: PathBuf,
    },

    /// The path resolves to something other than a regular file (directory,
    /// FIFO, device, ...).
    #[error("secret file {path}: not a regular file")]
    NotRegular {
        /// Configured path (not secret; safe to display and log).
        path: PathBuf,
    },

    /// The file exceeds [`MAX_SECRET_FILE_BYTES`].
    #[error("secret file {path}: exceeds the {MAX_SECRET_FILE_BYTES}-byte limit")]
    TooLarge {
        /// Configured path (not secret; safe to display and log).
        path: PathBuf,
    },

    /// The file content is not valid UTF-8 (the resolved secret `value` is a
    /// `String`).
    #[error("secret file {path}: not valid UTF-8")]
    NotUtf8 {
        /// Configured path (not secret; safe to display and log).
        path: PathBuf,
    },

    /// The file is empty, or contains only ASCII whitespace once trailing
    /// whitespace is trimmed. An empty credential is treated as a resolve
    /// failure rather than substituted as `""`.
    #[error("secret file {path}: empty after trimming trailing whitespace")]
    Empty {
        /// Configured path (not secret; safe to display and log).
        path: PathBuf,
    },

    /// Any other I/O failure (permission denied, etc.).
    #[error("secret file {path}: {source}")]
    Io {
        /// Configured path (not secret; safe to display and log).
        path: PathBuf,
        /// Underlying I/O error.
        #[source]
        source: io::Error,
    },
}

//--------------------------------------------------------------------------------------------------
// Methods
//--------------------------------------------------------------------------------------------------

impl FileSecretError {
    /// Stable short name for structured logs.
    pub(crate) fn kind_str(&self) -> &'static str {
        match self {
            Self::NotFound { .. } => "not_found",
            Self::Symlink { .. } => "symlink",
            Self::NotRegular { .. } => "not_regular",
            Self::TooLarge { .. } => "too_large",
            Self::NotUtf8 { .. } => "not_utf8",
            Self::Empty { .. } => "empty",
            Self::Io { .. } => "io",
        }
    }
}

//--------------------------------------------------------------------------------------------------
// Functions
//--------------------------------------------------------------------------------------------------

/// Read a file-backed secret's current value.
///
/// Opens `path` refusing to follow a symlink at the final component, checks
/// the file type and size on the resulting file descriptor (not the path —
/// this defeats a path swap between the open and the check), reads at most
/// `MAX_SECRET_FILE_BYTES + 1` bytes, requires valid UTF-8, and trims
/// trailing ASCII whitespace. An empty result after trimming is a failure,
/// not a valid empty credential.
pub(crate) fn read_file_secret(path: &Path) -> Result<Zeroizing<String>, FileSecretError> {
    let file = open_no_follow(path)?;

    let metadata = file.metadata().map_err(|source| FileSecretError::Io {
        path: path.to_path_buf(),
        source,
    })?;
    if !metadata.is_file() {
        return Err(FileSecretError::NotRegular {
            path: path.to_path_buf(),
        });
    }

    // Read into a zeroizing buffer so the raw credential bytes are wiped on
    // drop rather than lingering in freed heap. Validate UTF-8 by reference
    // (no owned intermediate `String`), so the only un-wiped copy that ever
    // exists is the trimmed value we return, itself wrapped in `Zeroizing`.
    let mut buf: Zeroizing<Vec<u8>> = Zeroizing::new(Vec::new());
    file.take(MAX_SECRET_FILE_BYTES as u64 + 1)
        .read_to_end(&mut buf)
        .map_err(|source| FileSecretError::Io {
            path: path.to_path_buf(),
            source,
        })?;
    if buf.len() > MAX_SECRET_FILE_BYTES {
        return Err(FileSecretError::TooLarge {
            path: path.to_path_buf(),
        });
    }

    let text = std::str::from_utf8(&buf).map_err(|_| FileSecretError::NotUtf8 {
        path: path.to_path_buf(),
    })?;
    let trimmed = text.trim_end_matches(|c: char| c.is_ascii_whitespace());
    if trimmed.is_empty() {
        return Err(FileSecretError::Empty {
            path: path.to_path_buf(),
        });
    }

    Ok(Zeroizing::new(trimmed.to_string()))
}

/// Open `path` for reading without following a symlink at the final
/// component.
///
/// Unix: `O_NOFOLLOW` makes the `open` syscall itself fail with `ELOOP` on a
/// symlink; `O_NONBLOCK` keeps a stray FIFO from blocking this call
/// indefinitely (the subsequent regular-file check rejects it). Windows has
/// no equivalent open flag, so a `symlink_metadata` reparse-point check runs
/// first; this leaves a narrow TOCTOU window on Windows only, documented in
/// the module docs.
fn open_no_follow(path: &Path) -> Result<File, FileSecretError> {
    #[cfg(windows)]
    {
        match std::fs::symlink_metadata(path) {
            Ok(metadata) => {
                if metadata.file_type().is_symlink()
                    || metadata.file_attributes() & FILE_ATTRIBUTE_REPARSE_POINT != 0
                {
                    return Err(FileSecretError::Symlink {
                        path: path.to_path_buf(),
                    });
                }
            }
            Err(source) if source.kind() == io::ErrorKind::NotFound => {
                return Err(FileSecretError::NotFound {
                    path: path.to_path_buf(),
                });
            }
            Err(source) => {
                return Err(FileSecretError::Io {
                    path: path.to_path_buf(),
                    source,
                });
            }
        }
    }

    let mut options = std::fs::OpenOptions::new();
    options.read(true);
    #[cfg(unix)]
    options.custom_flags(libc::O_NOFOLLOW | libc::O_CLOEXEC | libc::O_NONBLOCK);

    match options.open(path) {
        Ok(file) => Ok(file),
        Err(source) if source.kind() == io::ErrorKind::NotFound => Err(FileSecretError::NotFound {
            path: path.to_path_buf(),
        }),
        #[cfg(unix)]
        Err(source) if source.raw_os_error() == Some(libc::ELOOP) => {
            Err(FileSecretError::Symlink {
                path: path.to_path_buf(),
            })
        }
        Err(source) => Err(FileSecretError::Io {
            path: path.to_path_buf(),
            source,
        }),
    }
}

//--------------------------------------------------------------------------------------------------
// Tests
//--------------------------------------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use std::io::Write;

    use super::*;

    fn write_file(dir: &tempfile::TempDir, name: &str, contents: &[u8]) -> PathBuf {
        let path = dir.path().join(name);
        let mut file = File::create(&path).unwrap();
        file.write_all(contents).unwrap();
        path
    }

    #[test]
    fn reads_value_and_trims_trailing_whitespace() {
        let dir = tempfile::tempdir().unwrap();
        let path = write_file(&dir, "token", b"tok-AAA\n");

        let value = read_file_secret(&path).unwrap();

        assert_eq!(value.as_str(), "tok-AAA");
    }

    #[test]
    fn missing_file_fails_not_found() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("does-not-exist");

        let error = read_file_secret(&path).unwrap_err();

        assert_eq!(error.kind_str(), "not_found");
    }

    #[cfg(unix)]
    #[test]
    fn unreadable_file_fails_io() {
        use std::os::unix::fs::PermissionsExt;

        // Skip under root, where permission bits are ignored.
        if unsafe { libc::geteuid() } == 0 {
            return;
        }

        let dir = tempfile::tempdir().unwrap();
        let path = write_file(&dir, "token", b"tok-AAA\n");
        std::fs::set_permissions(&path, std::fs::Permissions::from_mode(0o000)).unwrap();

        let error = read_file_secret(&path).unwrap_err();

        assert_eq!(error.kind_str(), "io");

        // Restore permissions so the tempdir can clean itself up.
        std::fs::set_permissions(&path, std::fs::Permissions::from_mode(0o600)).unwrap();
    }

    #[cfg(unix)]
    #[test]
    fn symlink_to_valid_file_fails_closed() {
        let dir = tempfile::tempdir().unwrap();
        let target = write_file(&dir, "token", b"tok-AAA\n");
        let link = dir.path().join("token-link");
        std::os::unix::fs::symlink(&target, &link).unwrap();

        let error = read_file_secret(&link).unwrap_err();

        assert_eq!(error.kind_str(), "symlink");
    }

    #[test]
    fn oversized_file_fails_too_large() {
        let dir = tempfile::tempdir().unwrap();
        let oversized = vec![b'a'; MAX_SECRET_FILE_BYTES + 1];
        let path = write_file(&dir, "token", &oversized);

        let error = read_file_secret(&path).unwrap_err();

        assert_eq!(error.kind_str(), "too_large");
    }

    #[test]
    fn empty_file_fails_closed() {
        let dir = tempfile::tempdir().unwrap();
        let path = write_file(&dir, "token", b"");

        let error = read_file_secret(&path).unwrap_err();

        assert_eq!(error.kind_str(), "empty");
    }

    #[test]
    fn whitespace_only_file_fails_closed() {
        let dir = tempfile::tempdir().unwrap();
        let path = write_file(&dir, "token", b"   \n\t\n");

        let error = read_file_secret(&path).unwrap_err();

        assert_eq!(error.kind_str(), "empty");
    }

    #[test]
    fn directory_fails_not_regular() {
        let dir = tempfile::tempdir().unwrap();

        let error = read_file_secret(dir.path()).unwrap_err();

        assert_eq!(error.kind_str(), "not_regular");
    }

    #[cfg(unix)]
    #[test]
    fn fifo_fails_not_regular() {
        use std::ffi::CString;

        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("fifo");
        let c_path = CString::new(path.to_str().unwrap()).unwrap();
        let result = unsafe { libc::mkfifo(c_path.as_ptr(), 0o600) };
        assert_eq!(result, 0, "mkfifo failed: {}", io::Error::last_os_error());

        let error = read_file_secret(&path).unwrap_err();

        assert_eq!(error.kind_str(), "not_regular");
    }

    #[test]
    fn non_utf8_bytes_fail_closed() {
        let dir = tempfile::tempdir().unwrap();
        let path = write_file(&dir, "token", &[0xff, 0xfe, 0xfd]);

        let error = read_file_secret(&path).unwrap_err();

        assert_eq!(error.kind_str(), "not_utf8");
    }

    #[test]
    fn rotation_is_picked_up_on_next_read() {
        let dir = tempfile::tempdir().unwrap();
        let path = write_file(&dir, "token", b"tok-AAA\n");

        let first = read_file_secret(&path).unwrap();
        assert_eq!(first.as_str(), "tok-AAA");

        write_file(&dir, "token", b"tok-BBB\n");
        let second = read_file_secret(&path).unwrap();
        assert_eq!(second.as_str(), "tok-BBB");
    }
}
