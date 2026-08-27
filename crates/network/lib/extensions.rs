//! Host-local extension points for already-authorized outbound network routes.
//!
//! Extensions are absent by default. They are not serialized configuration and
//! are only installed by the host through [`NetworkExtensions`]. A connection
//! extension is invoked after the platform and tenant policies authorize a
//! route; it must not treat rewritten host dial destinations as policy
//! identities. A request extension is invoked only for TLS-intercepted routes
//! after SNI, CONNECT-authority, and route policy checks, and sees bytes after
//! secret substitution. Route authorization does not authorize an HTTP
//! request.
//!
//! Extension futures are awaited inline. Core code does not detach work or add
//! queues, so the existing bounded channel backpressure is preserved. Dropping
//! a relay drops an in-flight extension future; adapters must be
//! cancellation-safe and enforce their own completion bounds. A guest FIN is
//! observed after an in-flight request future completes. There is no EOF
//! callback: held request state is dropped rather than implicitly forwarded.
//!
//! | Request result | Core behavior | Ownership |
//! | --- | --- | --- |
//! | [`RequestAction::ForwardCurrent`] | Writes the current chunk | The adapter retains no borrow |
//! | [`RequestAction::Hold`] | Writes nothing | The adapter retains any held bytes |
//! | [`RequestAction::ForwardOwned`] | Writes exactly the supplied bytes | The adapter releases all intended bytes |
//! | [`RequestAction::RespondAndClose`] | Sends a guest response and ends the relay | No held or current request bytes reach upstream |
//!
//! The outbound result is deliberately a concrete [`TcpStream`]. Adapters may
//! establish a raw tunnel before returning it, but arbitrary I/O wrappers and
//! TLS-to-proxy transports are outside this interface. Core owns the returned
//! stream lifecycle, status updates, wakeups, half-close, and TLS shutdown.
//!
//! Request adapters own HTTP byte and time limits: core supplies neither an
//! implicit framing limit nor a timeout that may release held bytes. Extensions
//! are trusted host code. The capability only gates core-owned authorized-route
//! setup; it cannot prevent an adapter from opening unrelated host sockets.

use std::io;
use std::net::SocketAddr;
use std::sync::Arc;

use futures::future::BoxFuture;
use tokio::net::TcpStream;

use crate::tcp::upstream::UpstreamTcpTarget;

//--------------------------------------------------------------------------------------------------
// Types
//--------------------------------------------------------------------------------------------------

/// Host-local outbound extensions. The default installs no extension objects.
#[derive(Clone, Default)]
pub struct NetworkExtensions {
    outbound: Option<Arc<dyn OutboundConnectionExtension>>,
    requests: Option<Arc<dyn AuthorizedRouteRequestExtension>>,
}

/// The wire protocol associated with an outbound connection.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum OutboundProtocol {
    /// A plain TCP relay.
    Tcp,
    /// A TLS bypass or TLS-intercepted relay.
    Tls,
}

/// An already policy-authorized TCP route and its one-shot direct dial capability.
///
/// `guest_destination` is the policy identity. `primary_destination` and
/// `fallback_destination` are host dial candidates and can be loopback
/// rewrites. Calling [`Self::connect_direct`] consumes the route, preserving
/// the existing primary/fallback behavior exactly once.
pub struct AuthorizedTcpRoute {
    guest_destination: SocketAddr,
    target: UpstreamTcpTarget,
    server_name: Option<String>,
    protocol: OutboundProtocol,
}

/// An already policy-authorized TLS route for post-substitution request handling.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct AuthorizedTlsRoute {
    guest_destination: SocketAddr,
    server_name: String,
    via_connect: bool,
}

/// The result of handling one post-substitution plaintext chunk.
pub enum RequestAction {
    /// Forward the supplied chunk without copying it.
    ForwardCurrent,
    /// Hold the supplied chunk. The extension owns any state needed to release it.
    Hold,
    /// Forward exactly these owned bytes.
    ForwardOwned(Vec<u8>),
    /// Send these bytes to the guest and terminate the relay.
    RespondAndClose(Vec<u8>),
}

/// Connects an already-authorized outbound route.
///
/// Returning an error is terminal: core marks the upstream connection as
/// failed and never retries the direct route. An adapter that does not
/// transform a route can delegate once with [`AuthorizedTcpRoute::connect_direct`].
pub trait OutboundConnectionExtension: Send + Sync {
    /// Establish the route's raw TCP stream, including any adapter setup.
    fn connect<'a>(&'a self, route: AuthorizedTcpRoute) -> BoxFuture<'a, io::Result<TcpStream>>;
}

/// Opens an optional per-authorized-TLS-route request stream.
///
/// Returning `None` preserves the existing direct forwarding path without
/// request buffering or virtual dispatch.
pub trait AuthorizedRouteRequestExtension: Send + Sync {
    /// Open a stream for this authorized TLS route, if the extension is interested.
    fn open(&self, route: &AuthorizedTlsRoute) -> Option<Box<dyn AuthorizedRouteRequestStream>>;
}

/// Stateful processing for post-substitution request chunks.
///
/// The adapter owns HTTP framing plus all HTTP byte and time limits. It is
/// trusted host code and may open unrelated sockets outside this capability;
/// core only guarantees that it supplies this stream after route authorization.
pub trait AuthorizedRouteRequestStream: Send {
    /// Process a non-empty plaintext chunk.
    ///
    /// `ForwardCurrent` does not permit retaining `chunk`; `Hold` requires the
    /// extension to retain any bytes it needs. On error, core closes the relay
    /// without forwarding held or current bytes.
    fn process<'a>(&'a mut self, chunk: &'a [u8]) -> BoxFuture<'a, io::Result<RequestAction>>;
}

//--------------------------------------------------------------------------------------------------
// Methods
//--------------------------------------------------------------------------------------------------

impl NetworkExtensions {
    /// Create an empty host-local extension set.
    pub fn new() -> Self {
        Self::default()
    }

    /// Return a set with an outbound connection extension installed.
    pub fn with_outbound(mut self, outbound: Arc<dyn OutboundConnectionExtension>) -> Self {
        self.outbound = Some(outbound);
        self
    }

    /// Return a set with an authorized-route request extension installed.
    pub fn with_authorized_requests(
        mut self,
        requests: Arc<dyn AuthorizedRouteRequestExtension>,
    ) -> Self {
        self.requests = Some(requests);
        self
    }

    pub(crate) fn outbound(&self) -> Option<Arc<dyn OutboundConnectionExtension>> {
        self.outbound.clone()
    }

    pub(crate) fn authorized_requests(&self) -> Option<Arc<dyn AuthorizedRouteRequestExtension>> {
        self.requests.clone()
    }
}

impl AuthorizedTcpRoute {
    pub(crate) fn new(
        guest_destination: SocketAddr,
        target: UpstreamTcpTarget,
        server_name: Option<&str>,
        protocol: OutboundProtocol,
    ) -> Self {
        Self {
            guest_destination,
            target,
            server_name: server_name.map(ToOwned::to_owned),
            protocol,
        }
    }

    /// Return the original guest destination used for policy evaluation.
    pub fn guest_destination(&self) -> SocketAddr {
        self.guest_destination
    }

    /// Return the first host-side destination to dial.
    pub fn primary_destination(&self) -> SocketAddr {
        self.target.primary()
    }

    /// Return the optional alternate host-side destination.
    pub fn fallback_destination(&self) -> Option<SocketAddr> {
        self.target.fallback()
    }

    /// Return the canonical SNI known for this route.
    pub fn server_name(&self) -> Option<&str> {
        self.server_name.as_deref()
    }

    /// Return the route protocol.
    pub fn protocol(&self) -> OutboundProtocol {
        self.protocol
    }

    /// Directly dial this route once using the core primary/fallback behavior.
    pub async fn connect_direct(self) -> io::Result<TcpStream> {
        self.target.dial().await
    }
}

impl AuthorizedTlsRoute {
    pub(crate) fn new(guest_destination: SocketAddr, server_name: &str, via_connect: bool) -> Self {
        Self {
            guest_destination,
            server_name: server_name.to_owned(),
            via_connect,
        }
    }

    /// Return the original guest destination used for policy evaluation.
    pub fn guest_destination(&self) -> SocketAddr {
        self.guest_destination
    }

    /// Return the canonical, policy-validated TLS server name.
    pub fn server_name(&self) -> &str {
        &self.server_name
    }

    /// Return whether the route was established via HTTP CONNECT.
    pub fn via_connect(&self) -> bool {
        self.via_connect
    }
}
