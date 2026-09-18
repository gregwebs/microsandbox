use std::path::{Path, PathBuf};
use std::time::SystemTime;

use microsandbox_utils::AGENTD_BINARY;
#[cfg(feature = "prebuilt")]
use microsandbox_utils::{PREBUILT_VERSION, agentd_download_url, http_client};

fn main() {
    println!("cargo:rerun-if-changed=build.rs");
    println!("cargo:rerun-if-changed=../utils/lib/lib.rs");
    // Invalidate the embedded agentd when its source changes.
    // This won't auto-rebuild agentd (that requires `just build-agentd`),
    // but it forces cargo to re-check that `build/agentd` is fresh.
    println!("cargo:rerun-if-changed=../agentd");
    println!("cargo:rerun-if-changed=../protocol");

    // `<workspace_root>/crates/filesystem` -> `<workspace_root>`. Taking ancestors
    // rather than joining `../..` keeps `..` out of the paths the build prints:
    // the messages below hand the reader commands to copy and run.
    let workspace_root = PathBuf::from(env!("CARGO_MANIFEST_DIR"))
        .parent()
        .and_then(Path::parent)
        .expect("CARGO_MANIFEST_DIR is <workspace_root>/crates/filesystem")
        .to_path_buf();
    let out_dir = PathBuf::from(std::env::var("OUT_DIR").unwrap());

    build_agentd(&workspace_root, &out_dir);
}

/// The guest agent's sources, present only when this build is inside a checkout.
///
/// A published crate carries neither directory. That is the difference between a
/// build that can rebuild the guest agent and one that can only consume a
/// released artifact.
struct GuestAgentdSources {
    agentd: PathBuf,
    protocol: PathBuf,
}

fn build_agentd(workspace_root: &Path, out_dir: &Path) {
    let local = workspace_root.join("build").join(AGENTD_BINARY);
    let sources = guest_agentd_sources(workspace_root);
    let dest = out_dir.join(AGENTD_BINARY);
    println!("cargo:rerun-if-changed={}", local.display());

    // `MSB_AGENTD_PATH` is the caller choosing this build's guest payload, so it
    // wins over the local artifact and the cache. Ignored without `prebuilt`,
    // where the local artifact is the only supported source.
    #[cfg(feature = "prebuilt")]
    {
        println!("cargo:rerun-if-env-changed=MSB_AGENTD_PATH");
        if let Some(staged) = std::env::var_os("MSB_AGENTD_PATH").map(PathBuf::from) {
            if !staged.is_file() {
                panic!(
                    "MSB_AGENTD_PATH does not point to an agentd file: {}",
                    staged.display()
                );
            }
            println!("cargo:rerun-if-changed={}", staged.display());
            println!(
                "cargo:warning=microsandbox: embedding the guest agent from \
                 MSB_AGENTD_PATH={}, not from build/{AGENTD_BINARY}",
                staged.display()
            );
            copy_agentd(&staged, &dest);
            return;
        }
    }

    if local.is_file() {
        ensure_local_agentd_is_current(&local, sources.as_ref());
        copy_agentd(&local, &dest);
        return;
    }

    if let Some(sources) = &sources {
        // A checkout can always rebuild the guest agent, so it must never
        // substitute a released artifact for a missing local one: the guest agent
        // is embedded in the host binary, so that would silently ship a payload
        // built from a different revision of this tree (upstream's, for a fork).
        panic!(
            "{}",
            missing_local_agentd_message(&local, workspace_root, sources)
        );
    }

    #[cfg(feature = "prebuilt")]
    {
        if dest.exists() {
            println!(
                "cargo:warning=microsandbox: this build has no guest agent source tree; \
                 reusing the {AGENTD_BINARY} staged in OUT_DIR by an earlier build of this \
                 target. Guest-side behaviour is whatever that artifact contains."
            );
            return;
        }

        let arch = std::env::var("CARGO_CFG_TARGET_ARCH").unwrap();
        let url = agentd_download_url(PREBUILT_VERSION, &arch);
        println!(
            "cargo:warning=microsandbox: this build has no guest agent source tree; \
             embedding the released {AGENTD_BINARY} for v{PREBUILT_VERSION} from {url}. \
             Guest-side behaviour is that release's, not any checkout's."
        );
        download_to(&url, &dest);
    }

    #[cfg(not(feature = "prebuilt"))]
    panic!(
        "no guest agent source tree and the `prebuilt` feature is off, so there is no \
         {AGENTD_BINARY} to embed.\n\
         Run `just build-agentd` to build one, or enable the `prebuilt` feature."
    );
}

/// The guest agent source tree, when this build sees one.
fn guest_agentd_sources(workspace_root: &Path) -> Option<GuestAgentdSources> {
    let agentd = workspace_root.join("crates/agentd");
    agentd.is_dir().then(|| GuestAgentdSources {
        agentd,
        protocol: workspace_root.join("crates/protocol"),
    })
}

fn missing_local_agentd_message(
    local: &Path,
    workspace_root: &Path,
    sources: &GuestAgentdSources,
) -> String {
    format!(
        r#"{AGENTD_BINARY} binary not found at `{}`.
This is a source checkout ({} exists), so it will not download a released guest
agent: that would embed a guest payload built from a different revision of this tree.
Build it from this workspace root, `{}`, either way:
    just build-agentd
or, without just and Docker (a Linux host with musl-tools):
    rustup target add x86_64-unknown-linux-musl
    cargo build --release --manifest-path crates/agentd/Cargo.toml --target x86_64-unknown-linux-musl
    cp target/x86_64-unknown-linux-musl/release/agentd build/{AGENTD_BINARY}
Or point MSB_AGENTD_PATH at an agentd binary that belongs to this build."#,
        local.display(),
        sources.agentd.display(),
        workspace_root.display()
    )
}

/// Fail when `build/agentd` is older than the guest sources it embeds.
///
/// The guest agent is compiled into the host binary, so a stale artifact silently
/// changes guest-side behaviour, and the protocol generation gate cannot detect a
/// change that does not introduce a message type. A warning is too easy to miss.
fn ensure_local_agentd_is_current(local: &Path, sources: Option<&GuestAgentdSources>) {
    let Some(sources) = sources else {
        return;
    };
    let Ok(built_at) = std::fs::metadata(local).and_then(|meta| meta.modified()) else {
        return;
    };
    let newest_source = newest_tree_mtime(&sources.agentd)
        .into_iter()
        .chain(newest_tree_mtime(&sources.protocol))
        .max();
    if let Some(newest_source) = newest_source
        && newest_source > built_at
    {
        panic!(
            "build/{AGENTD_BINARY} is older than crates/agentd or crates/protocol source.\n\
             Run `just build-agentd` to rebuild the guest agent binary."
        );
    }
}

fn copy_agentd(local: &Path, dest: &Path) {
    // Remove any previous copy first: fs::copy preserves a read-only source
    // mode, which would make the next overwrite fail with EACCES.
    match std::fs::remove_file(dest) {
        Ok(()) => {}
        Err(e) if e.kind() == std::io::ErrorKind::NotFound => {}
        Err(e) => panic!("failed to replace {}: {e}", dest.display()),
    }
    std::fs::copy(local, dest).expect("failed to copy agentd to OUT_DIR");
}

fn newest_tree_mtime(root: &Path) -> Option<SystemTime> {
    fn walk(path: &Path, newest: &mut Option<SystemTime>) {
        let entries = match std::fs::read_dir(path) {
            Ok(entries) => entries,
            Err(_) => return,
        };

        for entry in entries.flatten() {
            let entry_path = entry.path();
            let meta = match entry.metadata() {
                Ok(meta) => meta,
                Err(_) => continue,
            };

            if meta.is_dir() {
                walk(&entry_path, newest);
                continue;
            }

            let modified = match meta.modified() {
                Ok(modified) => modified,
                Err(_) => continue,
            };

            match newest {
                Some(current) if *current >= modified => {}
                _ => *newest = Some(modified),
            }
        }
    }

    let mut newest = None;
    walk(root, &mut newest);
    newest
}

#[cfg(feature = "prebuilt")]
fn download_to(url: &str, dest: &Path) {
    eprintln!("Downloading {url}");

    let part_path = {
        let mut s = dest.as_os_str().to_os_string();
        s.push(".part");
        PathBuf::from(s)
    };

    let response = http_client().get(url).call().unwrap_or_else(|e| {
        panic!("failed to download {url}: {e}");
    });

    let mut reader = response.into_body().into_reader();
    let mut file = std::fs::File::create(&part_path).unwrap_or_else(|e| {
        panic!("failed to create {}: {e}", part_path.display());
    });

    std::io::copy(&mut reader, &mut file).unwrap_or_else(|e| {
        panic!("failed to write {}: {e}", part_path.display());
    });

    std::fs::rename(&part_path, dest).unwrap_or_else(|e| {
        panic!(
            "failed to rename {} to {}: {e}",
            part_path.display(),
            dest.display()
        );
    });
}
