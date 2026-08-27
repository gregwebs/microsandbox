//! Host-side TCP destination selection and connection state reporting.

use std::io;
use std::net::SocketAddr;

use tokio::net::TcpStream;

use super::connection::ProxyConnectState;
use crate::extensions::{AuthorizedTcpRoute, NetworkExtensions, OutboundProtocol};
use crate::netstack::shared::SharedState;

//--------------------------------------------------------------------------------------------------
// Types
//--------------------------------------------------------------------------------------------------

/// Ordered host-side TCP destinations for one guest connection.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(crate) struct UpstreamTcpTarget {
    primary: SocketAddr,
    fallback: Option<SocketAddr>,
}

//--------------------------------------------------------------------------------------------------
// Methods
//--------------------------------------------------------------------------------------------------

impl UpstreamTcpTarget {
    /// Create a target with no address-family fallback.
    pub(crate) fn direct(primary: SocketAddr) -> Self {
        Self {
            primary,
            fallback: None,
        }
    }

    /// Create a target with an alternate address-family destination.
    pub(crate) fn with_fallback(primary: SocketAddr, fallback: SocketAddr) -> Self {
        Self {
            primary,
            fallback: Some(fallback),
        }
    }

    /// Return the first host-side address to dial.
    pub(crate) fn primary(self) -> SocketAddr {
        self.primary
    }

    /// Return the optional alternate host-side address.
    pub(crate) fn fallback(self) -> Option<SocketAddr> {
        self.fallback
    }

    /// Connect an already-authorized route and publish the final outcome.
    pub(crate) async fn connect(
        self,
        guest_destination: SocketAddr,
        server_name: Option<&str>,
        protocol: OutboundProtocol,
        extensions: &NetworkExtensions,
        proxy_connect: &ProxyConnectState,
        shared: &SharedState,
    ) -> io::Result<TcpStream> {
        let stream = match extensions.outbound() {
            Some(extension) => {
                extension
                    .connect(AuthorizedTcpRoute::new(
                        guest_destination,
                        self,
                        server_name,
                        protocol,
                    ))
                    .await
            }
            None => self.dial().await,
        };
        let stream = match stream {
            Ok(stream) => stream,
            Err(error) => {
                proxy_connect.mark_upstream_connect_failed();
                shared.proxy_wake.wake();

                return Err(error);
            }
        };

        proxy_connect.mark_connected();

        Ok(stream)
    }

    pub(crate) async fn dial(self) -> io::Result<TcpStream> {
        let primary_error = match TcpStream::connect(self.primary).await {
            Ok(stream) => return Ok(stream),
            Err(error) => error,
        };

        let Some(fallback) = self.fallback.filter(|_| fallback_eligible(&primary_error)) else {
            return Err(primary_error);
        };

        tracing::debug!(
            primary = %self.primary,
            fallback = %fallback,
            error = %primary_error,
            "primary host loopback connection failed; trying alternate address family"
        );

        TcpStream::connect(fallback)
            .await
            .map_err(|fallback_error| {
                let primary = self.primary;
                let message = format!(
                    "failed to connect to host loopback {primary} ({primary_error}); alternate \
                     {fallback} also failed ({fallback_error})"
                );

                io::Error::new(fallback_error.kind(), message)
            })
    }
}

//--------------------------------------------------------------------------------------------------
// Functions
//--------------------------------------------------------------------------------------------------

fn fallback_eligible(error: &io::Error) -> bool {
    matches!(
        error.kind(),
        io::ErrorKind::ConnectionRefused
            | io::ErrorKind::AddrNotAvailable
            | io::ErrorKind::NetworkUnreachable
    )
}

//--------------------------------------------------------------------------------------------------
// Tests
//--------------------------------------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use std::sync::{Arc, Mutex};

    use futures::future::BoxFuture;
    use tokio::net::TcpListener;

    use super::super::connection::ProxyConnectStatus;
    use super::*;
    use crate::extensions::{AuthorizedTcpRoute, OutboundConnectionExtension};

    type RecordedRoute = (
        SocketAddr,
        SocketAddr,
        Option<SocketAddr>,
        Option<String>,
        OutboundProtocol,
    );

    struct RecordingConnector {
        stream: Mutex<Option<TcpStream>>,
        routes: Mutex<Vec<RecordedRoute>>,
    }

    impl OutboundConnectionExtension for RecordingConnector {
        fn connect<'a>(
            &'a self,
            route: AuthorizedTcpRoute,
        ) -> BoxFuture<'a, io::Result<TcpStream>> {
            let route_data = (
                route.guest_destination(),
                route.primary_destination(),
                route.fallback_destination(),
                route.server_name().map(ToOwned::to_owned),
                route.protocol(),
            );
            self.routes.lock().unwrap().push(route_data);
            let stream = self.stream.lock().unwrap().take();
            Box::pin(async move {
                stream.ok_or_else(|| io::Error::other("fixture stream already used"))
            })
        }
    }

    struct FailingConnector;

    impl OutboundConnectionExtension for FailingConnector {
        fn connect<'a>(
            &'a self,
            _route: AuthorizedTcpRoute,
        ) -> BoxFuture<'a, io::Result<TcpStream>> {
            Box::pin(async { Err(io::Error::other("adapter failed")) })
        }
    }

    struct DirectConnector;

    impl OutboundConnectionExtension for DirectConnector {
        fn connect<'a>(
            &'a self,
            route: AuthorizedTcpRoute,
        ) -> BoxFuture<'a, io::Result<TcpStream>> {
            Box::pin(route.connect_direct())
        }
    }

    #[tokio::test]
    async fn connection_extension_receives_authorized_route_and_can_select_stream() {
        let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let target = listener.local_addr().unwrap();
        let fixture = TcpStream::connect(target).await.unwrap();
        let connector = Arc::new(RecordingConnector {
            stream: Mutex::new(Some(fixture)),
            routes: Mutex::new(Vec::new()),
        });
        let extensions = NetworkExtensions::new().with_outbound(connector.clone());
        let guest_destination: SocketAddr = "203.0.113.10:443".parse().unwrap();
        let proxy_connect = ProxyConnectState::new();
        let shared = SharedState::new(4);

        let stream = UpstreamTcpTarget::direct("127.0.0.1:9".parse().unwrap())
            .connect(
                guest_destination,
                Some("example.com"),
                OutboundProtocol::Tls,
                &extensions,
                &proxy_connect,
                &shared,
            )
            .await
            .unwrap();

        assert_eq!(stream.peer_addr().unwrap(), target);
        assert_eq!(proxy_connect.status(), ProxyConnectStatus::Connected);
        assert_eq!(
            connector.routes.lock().unwrap().as_slice(),
            &[(
                guest_destination,
                "127.0.0.1:9".parse().unwrap(),
                None,
                Some("example.com".to_owned()),
                OutboundProtocol::Tls,
            )]
        );
        let _accepted = listener.accept().await.unwrap();
    }

    #[tokio::test]
    async fn connection_extension_error_is_fail_closed_and_wakes_core_state() {
        let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let target = listener.local_addr().unwrap();
        let extensions = NetworkExtensions::new().with_outbound(Arc::new(FailingConnector));
        let proxy_connect = ProxyConnectState::new();
        let shared = SharedState::new(4);
        shared.proxy_wake.drain();

        let error = UpstreamTcpTarget::direct(target)
            .connect(
                target,
                None,
                OutboundProtocol::Tcp,
                &extensions,
                &proxy_connect,
                &shared,
            )
            .await
            .unwrap_err();

        assert_eq!(error.to_string(), "adapter failed");
        assert_eq!(
            proxy_connect.status(),
            ProxyConnectStatus::UpstreamConnectFailed
        );
        assert!(shared.proxy_wake.wait_timeout(std::time::Duration::ZERO));
        assert!(
            tokio::time::timeout(std::time::Duration::from_millis(50), listener.accept())
                .await
                .is_err()
        );
    }

    #[tokio::test]
    async fn connection_extension_can_delegate_primary_fallback_dial() {
        let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let port = listener.local_addr().unwrap().port();
        let fallback = SocketAddr::new("127.0.0.1".parse().unwrap(), port);
        let primary = SocketAddr::new("::1".parse().unwrap(), port);
        let extensions = NetworkExtensions::new().with_outbound(Arc::new(DirectConnector));
        let proxy_connect = ProxyConnectState::new();
        let shared = SharedState::new(4);

        let stream = UpstreamTcpTarget::with_fallback(primary, fallback)
            .connect(
                primary,
                None,
                OutboundProtocol::Tcp,
                &extensions,
                &proxy_connect,
                &shared,
            )
            .await
            .unwrap();

        assert_eq!(stream.peer_addr().unwrap(), fallback);
        assert_eq!(proxy_connect.status(), ProxyConnectStatus::Connected);
        let _accepted = listener.accept().await.unwrap();
    }

    #[tokio::test]
    async fn connect_falls_back_from_ipv6_to_ipv4_loopback() {
        let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let port = listener.local_addr().unwrap().port();
        let fallback = SocketAddr::new("127.0.0.1".parse().unwrap(), port);
        let primary = SocketAddr::new("::1".parse().unwrap(), port);
        let target = UpstreamTcpTarget::with_fallback(primary, fallback);
        let proxy_connect = ProxyConnectState::new();
        let shared = SharedState::new(4);

        let stream = target
            .connect(
                primary,
                None,
                OutboundProtocol::Tcp,
                &NetworkExtensions::default(),
                &proxy_connect,
                &shared,
            )
            .await
            .expect("IPv4 loopback fallback should connect");

        assert_eq!(stream.peer_addr().unwrap(), fallback);
        assert_eq!(proxy_connect.status(), ProxyConnectStatus::Connected);
        let _accepted = listener.accept().await.unwrap();
    }
}
