//! End-to-end test for Unix file-mount staging: the stage lives in the sandbox
//! directory, is cleared on a same-name restart, and is removed with the sandbox
//! while the source survives.
//!
//! This test requires a signed, runnable `msb` and the host VM support (libkrun
//! on macOS, KVM on Linux). It is `#[ignore]`d by default, so the normal
//! workspace run does not exercise it. Run it with an explicit signed runtime:
//!
//! ```text
//! MSB_PATH=/path/to/build/msb \
//!   cargo test -p microsandbox --test file_mount_staging -- --ignored --nocapture --test-threads=1
//! ```
//!
//! It uses an explicit backend home (not the shared `test_utils` helper, which
//! overwrites `MSB_PATH` with the installed runtime). That home must contain the
//! chosen image or permit its pull, or the test reports the missing image. Point
//! `MSB_TEST_FILE_MOUNT_HOME` at a home that already holds the image (for example
//! one populated by `MSB_HOME=<home> msb pull <image>`), and override the image
//! with `MSB_TEST_FILE_MOUNT_IMAGE`.
#![cfg(unix)]

use std::os::unix::fs::{MetadataExt, PermissionsExt};
use std::path::{Path, PathBuf};
use std::sync::Arc;

use microsandbox::{
    Sandbox,
    backend::{Backend, LocalBackend},
    sandbox::SandboxBuilder,
};
use tempfile::TempDir;

const DEFAULT_IMAGE: &str = "debian:13-slim";
const NAME: &str = "file-mount-stage";

/// Image to boot. A pre-imported image under the chosen home (or one the
/// registry can serve) is required; override with `MSB_TEST_FILE_MOUNT_IMAGE`.
fn image() -> String {
    std::env::var("MSB_TEST_FILE_MOUNT_IMAGE").unwrap_or_else(|_| DEFAULT_IMAGE.to_string())
}

/// Home directory for the isolated backend. Defaults to a private temp dir; set
/// `MSB_TEST_FILE_MOUNT_HOME` to reuse one that already holds the image.
fn fixture_home(fallback: &Path) -> PathBuf {
    std::env::var_os("MSB_TEST_FILE_MOUNT_HOME")
        .map(PathBuf::from)
        .unwrap_or_else(|| fallback.to_path_buf())
}

async fn isolated_backend(home: &Path) -> Arc<dyn Backend> {
    Arc::new(LocalBackend::builder().home(home).build().await.unwrap())
}

fn sandbox_stage(sandbox_dir: &Path) -> PathBuf {
    sandbox_dir.join("file-mounts")
}

fn directory_entries(path: &Path) -> Vec<String> {
    let mut entries: Vec<String> = std::fs::read_dir(path)
        .map(|read| {
            read.map(|entry| entry.unwrap().file_name().to_string_lossy().into_owned())
                .collect()
        })
        .unwrap_or_default();
    entries.sort();
    entries
}

async fn assert_shell_ok(sandbox: &Sandbox, command: &str, expected: &str) {
    let output = sandbox.shell(command).await.expect("shell command");
    let stdout = output.stdout().unwrap_or_default();
    let stderr = output.stderr().unwrap_or_default();
    assert!(
        output.status().success,
        "shell `{command}` failed: stdout=`{stdout}` stderr=`{stderr}`"
    );
    assert_eq!(stdout.trim(), expected);
}

/// Boot a sandbox, write through a file mount, stop and restart the same
/// persisted name (clearing the old stage), then remove the sandbox and confirm
/// its whole directory is gone while the source survives.
#[tokio::test]
#[ignore = "requires a signed runtime + VM support; run with --ignored"]
async fn file_mount_stage_lives_in_sandbox_and_is_cleared_and_removed() {
    let fixture = TempDir::new().unwrap();
    let home = fixture_home(&fixture.path().join("home"));
    let sources = fixture.path().join("sources");
    std::fs::create_dir_all(&sources).unwrap();
    let source = sources.join("settings.toml");
    std::fs::write(&source, b"before\n").unwrap();

    let backend = isolated_backend(&home).await;
    // Standard local layout: `<home>/sandboxes/<name>`.
    let sandbox_dir = home.join("sandboxes").join(NAME);

    let outcome = microsandbox::with_backend(backend, {
        let source = source.clone();
        let sandbox_dir = sandbox_dir.clone();
        let sources = sources.clone();
        let image = image();
        run_e2e(image, source, sandbox_dir, sources)
    })
    .await;

    assert!(outcome.is_ok(), "e2e staging flow failed: {outcome:?}");
}

async fn run_e2e(
    image: String,
    source: PathBuf,
    sandbox_dir: PathBuf,
    sources: PathBuf,
) -> Result<(), String> {
    let build = || {
        SandboxBuilder::new(NAME)
            .image(image.clone())
            .cpus(1)
            .memory(256)
            .volume("/etc/app/settings.toml", |mount| mount.bind(&source))
    };

    let sandbox = build()
        .replace()
        .create()
        .await
        .map_err(|error| error.to_string())?;

    // Same-device mount (source and sandbox share a filesystem), so the stage
    // lives in the sandbox directory, holds exactly the mount's file plus its
    // tag, and is owner-only.
    if std::fs::metadata(&source).unwrap().dev() != std::fs::metadata(&sandbox_dir).unwrap().dev() {
        return Err("fixture must place the source on the sandbox's filesystem".into());
    }
    let stage_root = sandbox_stage(&sandbox_dir);
    let tags = directory_entries(&stage_root);
    assert_eq!(tags.len(), 1, "one tag directory expected: {tags:?}");
    let stage_dir = stage_root.join(&tags[0]);
    assert_eq!(
        directory_entries(&stage_dir),
        vec!["settings.toml".to_string()]
    );
    assert_eq!(
        std::fs::metadata(&stage_root).unwrap().permissions().mode() & 0o777,
        0o700
    );

    // The guest sees the file and a guest write reaches the host source.
    assert_shell_ok(&sandbox, "cat /etc/app/settings.toml", "before").await;
    assert_shell_ok(
        &sandbox,
        "printf 'guest write\n' > /etc/app/settings.toml",
        "",
    )
    .await;
    assert_eq!(
        std::fs::read_to_string(&source).unwrap(),
        "guest write\n",
        "the guest write must reach the host source through the stage"
    );

    // Stop, then start the same persisted name without replace/removal.
    sandbox
        .stop_and_wait()
        .await
        .map_err(|error| error.to_string())?;
    drop(sandbox);
    std::fs::write(&source, b"after restart\n").unwrap();
    let sentinel = stage_root.join("stale-sentinel");
    std::fs::write(&sentinel, b"stale").unwrap();

    let started = Sandbox::start(NAME)
        .await
        .map_err(|error| error.to_string())?;
    assert!(
        !sentinel.exists(),
        "restarting the same name must clear the previous stage"
    );
    assert_shell_ok(&started, "cat /etc/app/settings.toml", "after restart").await;

    // Remove via the SDK: the whole sandbox directory must go, the source and its
    // directory must survive.
    started
        .stop_and_wait()
        .await
        .map_err(|error| error.to_string())?;
    drop(started);
    Sandbox::remove(NAME)
        .await
        .map_err(|error| error.to_string())?;
    assert!(
        !sandbox_dir.exists(),
        "removal must delete the entire sandbox directory"
    );
    assert!(source.exists(), "removal must not touch the source file");
    assert!(sources.exists());
    Ok(())
}
