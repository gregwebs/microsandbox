//! Host-local extension points for already-authorized TLS routes.
//!
//! Extensions are absent by default. They are not serialized configuration and
//! are only installed by the host through [`NetworkExtensions`]. A request
//! extension is invoked only for TLS-intercepted routes after SNI,
//! CONNECT-authority, and route policy checks, and sees bytes after secret
//! substitution. Route authorization does not authorize an HTTP request.
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
//! Core owns the upstream stream lifecycle, status updates, wakeups,
//! half-close, and TLS shutdown; a request extension never receives it.
//!
//! Request adapters own HTTP byte and time limits: core supplies neither an
//! implicit framing limit nor a timeout that may release held bytes. Extensions
//! are trusted host code. The capability only gates core-owned authorized-route
//! setup; it cannot prevent an adapter from opening unrelated host sockets.

use std::io;
use std::net::SocketAddr;
use std::sync::Arc;

use futures::future::BoxFuture;

//--------------------------------------------------------------------------------------------------
// Types
//--------------------------------------------------------------------------------------------------

/// Host-local authorized-route extensions. The default installs no extension objects.
#[derive(Clone, Default)]
pub struct NetworkExtensions {
    requests: Option<Arc<dyn AuthorizedRouteRequestExtension>>,
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

    /// Return a set with an authorized-route request extension installed.
    pub fn with_authorized_requests(
        mut self,
        requests: Arc<dyn AuthorizedRouteRequestExtension>,
    ) -> Self {
        self.requests = Some(requests);
        self
    }

    pub(crate) fn authorized_requests(&self) -> Option<Arc<dyn AuthorizedRouteRequestExtension>> {
        self.requests.clone()
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
