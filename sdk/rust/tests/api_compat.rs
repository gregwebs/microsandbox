#[test]
fn creation_futures_remain_small_for_concurrent_callers() {
    let future = microsandbox::Sandbox::builder("stack-probe").create();
    let detached = microsandbox::Sandbox::builder("stack-probe").create_detached();
    for bytes in [
        std::mem::size_of_val(&future),
        std::mem::size_of_val(&detached),
    ] {
        assert!(
            bytes < 16 * 1024,
            "create state must not inflate every caller's async stack: {bytes} bytes"
        );
    }
}

#[test]
#[cfg(feature = "local")]
fn rust_root_compat_exports_stay_available() {
    // Compile-time tripwire for public root exports restored after the
    // backend-routing refactor. The function items are not invoked.
    let _ = microsandbox::Image::get;
    let _ = microsandbox::Image::list;
    let _ = microsandbox::Image::inspect;
    let _ = microsandbox::Image::remove;
    let _ = microsandbox::Image::prune;
    let _ = microsandbox::all_sandbox_metrics;

    let _: Option<microsandbox::ImagePruneReport> = None;
    let _: Option<microsandbox::SandboxMetrics> = None;
}

#[test]
#[cfg(feature = "local")]
fn rust_config_and_runtime_setup_surface_stays_available() {
    let _ = microsandbox::setup::resolve_runtime;
    let _ = microsandbox::setup::install_runtime;
    let _ = microsandbox::setup::ensure_runtime;
    let _: Option<microsandbox::setup::ResolvedRuntime> = None;
    let _: Option<microsandbox::setup::InstallOptions> = None;
    let _ = microsandbox::config::config;
    let _ = microsandbox::config::resolve_msb_path;
    let _ = microsandbox::config::resolve_libkrunfw_path;
    let _ = microsandbox::config::GlobalConfig::resolve_msb_path;
    let _ = microsandbox::config::GlobalConfig::resolve_libkrunfw_path;

    #[allow(deprecated)]
    let _: Option<microsandbox::config::LocalConfig> = None;
}

#[cfg(feature = "ssh")]
#[test]
fn rust_ssh_compat_export_stays_available() {
    let _: Option<microsandbox::SandboxSshOps> = None;
}

#[test]
fn rust_identity_and_generated_patch_surface_is_backend_neutral() {
    use microsandbox::sandbox::{DestroyOptions, RestartOptions, SandboxHandle, SandboxId};

    let _: Option<SandboxId> = None;
    let _ = SandboxHandle::id;
    let _ = SandboxHandle::connect_or_start;
    let _ = SandboxHandle::wait_for_status;
    let _ = SandboxHandle::restart;
    let _ = SandboxHandle::destroy;
    let _ = (RestartOptions::default(), DestroyOptions::default());
    let _ = microsandbox::SandboxConfigPatch::new().spec(
        microsandbox::SandboxSpecPatch::new()
            .resources(microsandbox::SandboxResourcesPatch::new().cpus(2)),
    );
}

#[allow(dead_code)]
async fn rust_sandbox_fs_handle_api_stays_available(
    fs: &microsandbox::sandbox::SandboxFsOps<'_>,
    entry: microsandbox::sandbox::FsEntry,
    metadata: microsandbox::sandbox::FsMetadata,
) -> microsandbox::MicrosandboxResult<()> {
    use microsandbox::sandbox::{FsHandle, FsOpenOptions, FsSetAttrs};

    let _: Option<FsHandle> = None;
    let file = fs.open_file("/tmp/file", FsOpenOptions::default()).await?;
    let dir = fs.open_dir("/tmp").await?;

    let _ = fs.read_handle(file, 0, None).await?;
    let mut read_stream = fs.read_handle_stream(file, 0, Some(1)).await?;
    let _ = read_stream.recv().await?;

    fs.write_handle(file, 0, b"hello").await?;
    let write_stream = fs.write_handle_stream(file, 0, None).await?;
    write_stream.close().await?;

    let _ = fs.read_dir_handle(dir, None).await?;
    let _ = fs.read_dir(dir, None).await?;

    let _ = fs.stat_handle(file).await?;
    let _ = fs.fstat(file).await?;
    fs.set_stat_handle(file, FsSetAttrs::default()).await?;
    fs.fset_stat(file, FsSetAttrs::default()).await?;

    let _ = fs.real_path(".").await?;
    fs.remove_empty_dir("/tmp/empty").await?;
    fs.close_handle(file).await?;
    fs.close_handle(dir).await?;

    let _ = (entry.uid, entry.gid, entry.accessed);
    let _ = (metadata.uid, metadata.gid, metadata.accessed);

    Ok(())
}

/// Tripwire for the attach stdin-filter surface. The `impl` below is the exact
/// shape the downstream consumer uses, so this fails to compile if the
/// re-export, the trait signature, or the opaque future bound drifts.
#[test]
fn rust_attach_stdin_filter_surface_stays_available() {
    use std::future::Future;
    use std::pin::Pin;

    struct Upper;

    impl microsandbox::sandbox::StdinFilter for Upper {
        fn filter<'a>(
            &'a mut self,
            data: &'a [u8],
        ) -> Pin<Box<dyn Future<Output = Vec<u8>> + Send + 'a>> {
            let out = data.to_ascii_uppercase();
            Box::pin(async move { out })
        }
    }

    // The trait only needs `Send`; the boxed future must be `Send` too, but
    // the filter itself need not be `Sync`. `Cell<u8>` is `Send` but not
    // `Sync`, so this stops compiling if a `Sync` bound is added to the trait
    // or to `stdin_filter`.
    struct NotSyncFilter(std::cell::Cell<u8>);

    impl microsandbox::sandbox::StdinFilter for NotSyncFilter {
        fn filter<'a>(
            &'a mut self,
            data: &'a [u8],
        ) -> Pin<Box<dyn Future<Output = Vec<u8>> + Send + 'a>> {
            self.0.set(self.0.get().wrapping_add(1));
            let out = data.to_ascii_uppercase();
            Box::pin(async move { out })
        }
    }

    fn assert_send<T: Send>(_: &T) {}

    let options = microsandbox::sandbox::AttachOptionsBuilder::default()
        .stdin_filter(Upper)
        .build()
        .expect("attach options");
    assert_send(&options);

    // A non-`Sync`, `Send` filter is accepted by the builder and the trait.
    let _non_sync_options = microsandbox::sandbox::AttachOptionsBuilder::default()
        .stdin_filter(NotSyncFilter(std::cell::Cell::new(0)))
        .build()
        .expect("a Send but non-Sync filter must be accepted");

    let builder = microsandbox::sandbox::AttachOptionsBuilder::default().stdin_filter(Upper);
    let _: microsandbox::sandbox::AttachOptionsBuilder = builder.arg("-l");
}

/// A filter that awaits inside its returned future, as the downstream
/// consumer's does (it may push a file into the guest before letting a key
/// through).
#[allow(dead_code)]
struct AwaitingFilter;

impl microsandbox::sandbox::StdinFilter for AwaitingFilter {
    fn filter<'a>(
        &'a mut self,
        data: &'a [u8],
    ) -> std::pin::Pin<Box<dyn std::future::Future<Output = Vec<u8>> + Send + 'a>> {
        Box::pin(async move {
            tokio::task::yield_now().await;
            data.to_vec()
        })
    }
}

/// Compile-only: the exact attach call shape the downstream consumer uses, a
/// filter moved into the `FnOnce` `attach_with` closure beside `.args()` and
/// `.cwd()`. Never run. Fails to build if `attach_with` stops accepting an
/// `FnOnce`, if `stdin_filter` stops taking the filter by value, or if an
/// awaiting filter future cannot hold its borrow across an await.
#[allow(dead_code)]
async fn consumer_attach_shape(
    sandbox: microsandbox::sandbox::Sandbox,
    filter: Option<AwaitingFilter>,
) {
    let _ = sandbox
        .attach_with("bash", |a| {
            let a = a.args(vec!["-c".to_string()]).cwd("/".to_string());
            match filter {
                Some(f) => a.stdin_filter(f),
                None => a,
            }
        })
        .await;
}
