//! Live tenant network policy replacement over the existing host control endpoint.

use std::sync::Arc;

use microsandbox_control_client::ControlClientError;

use crate::backend::sandbox::SandboxIdentity;
use crate::error::{Operation, UnsupportedReason};
use crate::{MicrosandboxError, MicrosandboxResult};

use super::{NetworkPolicy, Sandbox};

//--------------------------------------------------------------------------------------------------
// Methods
//--------------------------------------------------------------------------------------------------

impl Sandbox {
    /// Replace this running sandbox's tenant network policy without a restart.
    ///
    /// Returns the new policy revision; the launch policy is revision 1. Decisions made after
    /// this returns — DNS queries, new flows, and new connections — use the new policy, while
    /// connections already admitted keep running under the policy they were admitted with. The
    /// platform floor is unaffected, and the persisted configuration is not changed, so a restart
    /// starts from the launch policy again.
    ///
    /// Local backend only. A runtime that cannot serve the operation reports
    /// [`MicrosandboxError::Unsupported`]: either it never advertised the capability, or the
    /// sandbox has no control endpoint at all. A runtime that accepts and refuses the policy
    /// reports [`MicrosandboxError::ControlClient`].
    pub async fn update_network_policy(&self, policy: NetworkPolicy) -> MicrosandboxResult<u64> {
        let operation = Operation::SandboxUpdateNetworkPolicy;
        let local = self
            .backend()
            .as_local()
            .ok_or_else(|| MicrosandboxError::local_only(operation))?;
        let SandboxIdentity::Local(expected_id) = self.identity() else {
            return Err(MicrosandboxError::local_only(operation));
        };

        let run = local.control_run_identity(self.name(), expected_id).await?;
        // An absent endpoint is the unsupported-feature signal, not an operational failure:
        // callers must be able to offer a next-launch grant instead of reporting a fault. Only
        // while the run selected above is still the current one, though: a runtime that exited or
        // was replaced between that selection and this lookup is the changed-runtime error, and
        // reporting it as unsupported would send the caller down the next-launch path for a
        // sandbox that is right now running something else.
        let Some(session) = local.control_session(self.name()).await? else {
            if local.control_run_identity(self.name(), expected_id).await? == run {
                return Err(MicrosandboxError::unsupported(
                    operation,
                    UnsupportedReason::NotAvailable(
                        "this running sandbox has no control endpoint: its runtime predates live \
                         configuration or has no mutable capacity"
                            .into(),
                    ),
                ));
            }
            return Err(MicrosandboxError::ControlClient(Arc::new(
                ControlClientError::RuntimeChanged,
            )));
        };
        if !session.matches_run(run) {
            return Err(MicrosandboxError::ControlClient(Arc::new(
                ControlClientError::RuntimeChanged,
            )));
        }

        // The engine and wire policy types share one serde contract, asserted in the network
        // crate; the runtime decodes the wire document exactly as it would at boot.
        let wire: microsandbox_types::NetworkPolicy =
            serde_json::from_value(serde_json::to_value(&policy)?)?;
        session.replace_network_policy(wire).await
    }
}

//--------------------------------------------------------------------------------------------------
// Tests
//--------------------------------------------------------------------------------------------------

#[cfg(all(test, unix))]
mod tests {
    use std::sync::Arc;
    use std::time::Duration;

    use microsandbox_control_client::ControlClientError;
    use microsandbox_network::policy::{
        Action, Destination, Direction, NetworkPolicy, PortRange, Protocol, Rule,
    };
    use sea_orm::{EntityTrait, Set};
    use tokio::io::{AsyncBufReadExt, AsyncWriteExt, BufReader};
    use tokio::net::UnixListener;

    use crate::MicrosandboxError;
    use crate::backend::{
        Backend, BackendKind, LocalBackend, SandboxBackend, SandboxLocalState, SnapshotBackend,
        VolumeBackend,
    };
    use crate::error::{Operation, UnsupportedReason};
    use crate::sandbox::{Sandbox, SandboxConfig, SandboxStatus};

    const WITHOUT_FLAG: &str = "{\"ok\":true,\"capabilities\":{\"cpu_resize\":true,\"memory_resize\":true,\"secrets_update\":true}}";
    const WITH_FLAG: &str = "{\"ok\":true,\"capabilities\":{\"cpu_resize\":true,\"memory_resize\":true,\"secrets_update\":true,\"network_policy_update\":true}}";

    /// A replacement of the shape `Sandbox::update_network_policy` accepts.
    fn replacement() -> NetworkPolicy {
        NetworkPolicy {
            default_egress: Action::Deny,
            default_ingress: Action::Deny,
            rules: vec![Rule {
                direction: Direction::Egress,
                destination: Destination::Domain("probe.example".parse().unwrap()),
                protocols: vec![Protocol::Tcp],
                ports: vec![PortRange {
                    start: 443,
                    end: 443,
                }],
                action: Action::Allow,
            }],
        }
    }

    async fn seed_run(local: &LocalBackend, name: &str) -> i32 {
        use crate::db::entity::{run, sandbox};
        let db = local.db().await.unwrap();
        let id = sandbox::Entity::insert(sandbox::ActiveModel {
            name: Set(name.into()),
            config: Set("{}".into()),
            status: Set(SandboxStatus::Running),
            ephemeral: Set(false),
            ..Default::default()
        })
        .exec(db.write())
        .await
        .unwrap()
        .last_insert_id;
        run::Entity::insert(run::ActiveModel {
            sandbox_id: Set(id),
            pid: Set(Some(std::process::id() as i32)),
            status: Set(run::RunStatus::Running),
            ..Default::default()
        })
        .exec(db.write())
        .await
        .unwrap();
        id
    }

    /// A backend whose home outlives the test, and the seeded live run.
    async fn local_backend(name: &str) -> (tempfile::TempDir, Arc<LocalBackend>, i32) {
        // macOS's per-user TMPDIR may already consume most of the Unix socket path limit.
        let home = tempfile::tempdir_in("/tmp").unwrap();
        let backend = Arc::new(
            crate::test_support::local_backend_builder(home.path())
                .build()
                .await
                .unwrap(),
        );
        let id = seed_run(&backend, name).await;
        (home, backend, id)
    }

    /// A `Sandbox` over `backend`. The retained agent client is never used by these tests.
    async fn sandbox(backend: Arc<dyn Backend>, name: &str, id: i32) -> Sandbox {
        let (client_io, mut server_io) = tokio::io::duplex(4096);
        let handshake = tokio::spawn(async move {
            use microsandbox_protocol::{
                codec,
                core::Ready,
                message::{Message, MessageType},
            };
            server_io.write_all(&1u32.to_be_bytes()).await.unwrap();
            server_io.write_all(&1024u32.to_be_bytes()).await.unwrap();
            codec::write_message(
                &mut server_io,
                &Message::with_payload(MessageType::Ready, 0, &Ready::default()).unwrap(),
            )
            .await
            .unwrap();
        });
        let client = crate::agent::AgentClient::connect_stream_with_timeout(
            client_io,
            Duration::from_secs(1),
        )
        .await
        .unwrap();
        handshake.await.unwrap();
        let mut config = SandboxConfig::default();
        config.spec.name = name.into();
        Sandbox::from_local(
            backend,
            SandboxLocalState {
                db_id: id,
                handle: None,
                client: Arc::new(client),
            },
            config,
        )
    }

    fn bind_control(local: &LocalBackend, name: &str) -> UnixListener {
        let agent = local
            .resolve_agent_socket_path(name)
            .expect("the test backend resolves an agent socket path");
        let path = microsandbox_runtime::control::control_socket_path_for(&agent);
        std::fs::create_dir_all(path.parent().unwrap()).unwrap();
        UnixListener::bind(path).unwrap()
    }

    /// Read one request line and write one reply line on the same stream.
    async fn exchange(listener: &UnixListener, reply: &'static str) -> String {
        let (stream, _) = listener.accept().await.unwrap();
        let mut stream = BufReader::new(stream);
        let mut line = String::new();
        stream.read_line(&mut line).await.unwrap();
        if !reply.is_empty() {
            stream.get_mut().write_all(reply.as_bytes()).await.unwrap();
            stream.get_mut().write_all(b"\n").await.unwrap();
        }
        line
    }

    fn assert_unsupported(error: MicrosandboxError) {
        assert!(
            matches!(
                error,
                MicrosandboxError::Unsupported {
                    op: Operation::SandboxUpdateNetworkPolicy,
                    reason: UnsupportedReason::NotAvailable(_),
                }
            ),
            "{error:?}"
        );
    }

    #[tokio::test]
    async fn absent_capability_is_unsupported_and_sends_no_operation() {
        let (_home, backend, id) = local_backend("source").await;
        let listener = bind_control(&backend, "source");
        let server = tokio::spawn(async move {
            assert_eq!(
                exchange(&listener, WITHOUT_FLAG).await,
                "{\"op\":\"capabilities\"}\n"
            );
            // AC7: no second connection, so no replacement bytes.
            tokio::time::timeout(Duration::from_millis(500), listener.accept())
                .await
                .is_err()
        });
        let error = sandbox(backend.clone(), "source", id)
            .await
            .update_network_policy(replacement())
            .await
            .unwrap_err();
        assert_unsupported(error);
        assert!(server.await.unwrap(), "an operation was sent");
    }

    /// A run that is replaced between the identity selection and the endpoint lookup is the
    /// changed-runtime error, not "this feature is unsupported".
    ///
    /// The selection and the revalidation are separate reads of the catalog, so the test races
    /// them: a second live run pid is swapped in and out until one attempt sees a different
    /// identity on the revalidation than on the selection. Without the revalidation every attempt
    /// reports `Unsupported`, which would send the caller down the next-launch path for a sandbox
    /// that is at that moment running something else.
    #[tokio::test]
    async fn a_run_that_changes_during_the_lookup_is_not_reported_as_unsupported() {
        use crate::db::entity::run;
        use sea_orm::{ActiveModelTrait, ColumnTrait, EntityTrait, QueryFilter};

        const ATTEMPTS: usize = 200;

        let (_home, backend, id) = local_backend("source").await;
        // A second live pid is enough to change the identity: `control_run_identity` reads the
        // same live run row twice and must see the same one both times.
        let mut other = std::process::Command::new("sleep")
            .arg("60")
            .spawn()
            .unwrap();
        let other_pid = other.id() as i32;
        let own_pid = std::process::id() as i32;
        let row = run::Entity::find()
            .filter(run::Column::SandboxId.eq(id))
            .one(backend.db().await.unwrap().read())
            .await
            .unwrap()
            .unwrap();

        let flipper = {
            let backend = Arc::clone(&backend);
            let row_id = row.id;
            tokio::spawn(async move {
                let mut pid = other_pid;
                loop {
                    let db = backend.db().await.unwrap();
                    let _ = run::ActiveModel {
                        id: Set(row_id),
                        pid: Set(Some(pid)),
                        ..Default::default()
                    }
                    .update(db.write())
                    .await;
                    pid = if pid == other_pid { own_pid } else { other_pid };
                    tokio::task::yield_now().await;
                }
            })
        };

        let sandbox = sandbox(backend.clone(), "source", id).await;
        let mut raced = None;
        for _ in 0..ATTEMPTS {
            match sandbox.update_network_policy(replacement()).await {
                Err(MicrosandboxError::ControlClient(error))
                    if matches!(&*error, ControlClientError::RuntimeChanged) =>
                {
                    raced = Some(());
                    break;
                }
                // A lookup that happened to see one identity is still the unsupported case.
                Err(error) => assert_unsupported(error),
                Ok(revision) => panic!("a sandbox with no control endpoint replaced: {revision}"),
            }
        }

        flipper.abort();
        let _ = other.kill();
        let _ = other.wait();
        assert!(
            raced.is_some(),
            "a run replaced between the selection and the lookup must be reported as changed"
        );
    }

    #[tokio::test]
    async fn a_sandbox_without_a_control_endpoint_is_unsupported_not_operational() {
        let (_home, backend, id) = local_backend("source").await;
        let error = sandbox(backend.clone(), "source", id)
            .await
            .update_network_policy(replacement())
            .await
            .unwrap_err();
        assert_unsupported(error);
    }

    #[tokio::test]
    async fn an_advertised_capability_sends_one_replacement_and_returns_its_revision() {
        let (_home, backend, id) = local_backend("source").await;
        let listener = bind_control(&backend, "source");
        let server = tokio::spawn(async move {
            assert_eq!(
                exchange(&listener, WITH_FLAG).await,
                "{\"op\":\"capabilities\"}\n"
            );
            let line = exchange(
                &listener,
                "{\"ok\":true,\"network_policy\":{\"revision\":7}}",
            )
            .await;
            // Exactly one operation: nothing else is admitted afterwards.
            assert!(
                tokio::time::timeout(Duration::from_millis(300), listener.accept())
                    .await
                    .is_err()
            );
            line
        });
        let revision = sandbox(backend.clone(), "source", id)
            .await
            .update_network_policy(replacement())
            .await
            .unwrap();
        assert_eq!(revision, 7);
        let request: serde_json::Value = serde_json::from_str(&server.await.unwrap()).unwrap();
        assert_eq!(request["op"], "network_policy_replace");
        assert_eq!(
            request["policy"],
            serde_json::to_value(replacement()).unwrap()
        );
    }

    #[tokio::test]
    async fn a_runtime_refusal_is_a_control_client_error_and_never_success() {
        let (_home, backend, id) = local_backend("source").await;
        let listener = bind_control(&backend, "source");
        let server = tokio::spawn(async move {
            assert_eq!(
                exchange(&listener, WITH_FLAG).await,
                "{\"op\":\"capabilities\"}\n"
            );
            exchange(
                &listener,
                "{\"ok\":false,\"error_code\":\"invalid_network_policy\",\"error\":\"refused\"}",
            )
            .await
        });
        let error = sandbox(backend.clone(), "source", id)
            .await
            .update_network_policy(replacement())
            .await
            .unwrap_err();
        let MicrosandboxError::ControlClient(error) = error else {
            panic!("wrong failure: {error:?}");
        };
        assert!(matches!(&*error, ControlClientError::LegacyRemote { .. }));
        assert_eq!(
            serde_json::from_str::<serde_json::Value>(&server.await.unwrap()).unwrap()["op"],
            "network_policy_replace"
        );
    }

    #[tokio::test]
    async fn a_success_reply_without_a_revision_is_never_reported_as_success() {
        let (_home, backend, id) = local_backend("source").await;
        let listener = bind_control(&backend, "source");
        let server = tokio::spawn(async move {
            assert_eq!(
                exchange(&listener, WITH_FLAG).await,
                "{\"op\":\"capabilities\"}\n"
            );
            exchange(&listener, "{\"ok\":true}").await
        });
        let error = sandbox(backend.clone(), "source", id)
            .await
            .update_network_policy(replacement())
            .await
            .unwrap_err();
        let MicrosandboxError::ControlClient(error) = error else {
            panic!("wrong failure: {error:?}");
        };
        assert!(matches!(
            &*error,
            ControlClientError::InvalidJsonResponse { .. }
        ));
        server.await.unwrap();
    }

    #[tokio::test]
    async fn a_non_local_backend_reports_the_operation_as_local_only() {
        struct Foreign;

        impl Backend for Foreign {
            fn kind(&self) -> BackendKind {
                BackendKind::Cloud
            }
            fn sandboxes(&self) -> &dyn SandboxBackend {
                unimplemented!("a foreign backend only tests local-only refusal")
            }
            fn volumes(&self) -> &dyn VolumeBackend {
                unimplemented!("a foreign backend only tests local-only refusal")
            }
            fn snapshots(&self) -> &dyn SnapshotBackend {
                unimplemented!("a foreign backend only tests local-only refusal")
            }
        }

        let error = sandbox(Arc::new(Foreign), "source", 1)
            .await
            .update_network_policy(replacement())
            .await
            .unwrap_err();
        assert!(
            matches!(
                error,
                MicrosandboxError::Unsupported {
                    op: Operation::SandboxUpdateNetworkPolicy,
                    reason: UnsupportedReason::LocalOnly,
                }
            ),
            "{error:?}"
        );
    }
}
