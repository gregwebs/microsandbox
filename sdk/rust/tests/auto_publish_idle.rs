//! Live auto-publish/idle regression. Requires a candidate runtime pair in
//! MSB_TEST_RUNTIME_DIR and registry access; run this target explicitly.

#![cfg(all(unix, feature = "local", feature = "net"))]

use std::time::Duration;

use microsandbox::{
    LocalBackend, Sandbox, backend::with_backend, sandbox::SandboxTerminationReason,
};

//--------------------------------------------------------------------------------------------------
// Tests
//--------------------------------------------------------------------------------------------------

// Live: needs a candidate `msb`/`agentd` pair in MSB_TEST_RUNTIME_DIR, HVF and
// network access, so it must not run in the default workspace suite.
#[ignore = "requires MSB_TEST_RUNTIME_DIR (candidate msb/agentd pair)"]
#[tokio::test]
async fn auto_publish_polls_do_not_keep_quiet_detached_jobs_alive_but_client_fs_does()
-> Result<(), Box<dyn std::error::Error>> {
    let home = tempfile::tempdir_in("/tmp")?;
    let backend = LocalBackend::builder()
        .config_path(home.path().join("config.json"))
        .home(home.path())
        .build()
        .await?;
    let runtime_dir = std::env::var_os("MSB_TEST_RUNTIME_DIR")
        .expect("MSB_TEST_RUNTIME_DIR must point to the candidate msb/agentd pair");
    microsandbox::setup::install_runtime(
        backend.config(),
        microsandbox::setup::InstallOptions {
            source: microsandbox::setup::InstallSource::Directory(runtime_dir.into()),
            ..Default::default()
        },
    )
    .await?;

    with_backend(backend, async {
        let sandbox = Sandbox::builder("auto-publish-idle")
            .image("alpine:3.20")
            .cpus(1)
            .memory(256)
            .ephemeral(false)
            .idle_timeout(5)
            .max_duration(90)
            .network(|network| {
                network
                    .auto_publish()
                    .http(|http| http.deny_response(false))
            })
            .create_detached()
            .await?;
        let result = async {
            let handle = Sandbox::get(sandbox.name()).await?;
            // A detached, quiet job is not an attachment and must not pin the VM.
            let _job = sandbox.exec_detached("sleep", ["60"]).await?;
            // Control: ordinary client filesystem reads reset idleness, even
            // while the runtime also issues its internal procfs polls.
            for _ in 0..8 {
                assert!(!sandbox.fs().read("/etc/os-release").await?.is_empty());
                tokio::time::sleep(Duration::from_secs(1)).await;
                assert!(handle.terminal_exit().await?.is_none());
            }
            // Now only auto-publish polls remain. They must not keep the quiet
            // job (or the VM) alive past the idle deadline.
            let exit = tokio::time::timeout(Duration::from_secs(25), async {
                loop {
                    if let Some(exit) = handle.terminal_exit().await? {
                        break Ok::<_, microsandbox::MicrosandboxError>(exit);
                    }
                    tokio::time::sleep(Duration::from_millis(250)).await;
                }
            })
            .await??;
            assert_eq!(exit.reason, Some(SandboxTerminationReason::IdleTimeout));
            Ok::<_, Box<dyn std::error::Error>>(())
        }
        .await;
        sandbox.destroy().await?;
        result
    })
    .await
}
