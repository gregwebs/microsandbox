//! Adapter wiring [`Interceptor`] into the [`extensions`](crate::extensions) seam.
//!
//! [`InterceptExtension`] is the host-installed
//! [`AuthorizedRouteRequestExtension`] the engine builds from
//! [`InterceptConfig`] when it is active (see
//! [`crate::network::Network::new_with_profile_and_routes`]). It has no
//! state of its own beyond the config: each authorized TLS route gets a
//! fresh [`Interceptor`], so a bypassed or refused connection cannot affect
//! any other connection's policing.

use std::io;

use futures::future::BoxFuture;

use super::config::InterceptConfig;
use super::handler::{Interceptor, Verdict};
use crate::extensions::{
    AuthorizedRouteRequestExtension, AuthorizedRouteRequestStream, AuthorizedTlsRoute,
    RequestAction,
};

//--------------------------------------------------------------------------------------------------
// Types
//--------------------------------------------------------------------------------------------------

/// Host-installed request extension backed by [`InterceptConfig`].
pub struct InterceptExtension {
    config: InterceptConfig,
}

/// Per-connection stream adapter: translates [`Verdict`] into [`RequestAction`].
struct InterceptStream {
    inner: Interceptor,
}

//--------------------------------------------------------------------------------------------------
// Methods
//--------------------------------------------------------------------------------------------------

impl InterceptExtension {
    /// Build an extension from the resolved network configuration. Callers
    /// should only install this when [`InterceptConfig::is_active`] is true
    /// (see the engine startup call site); the extension itself does not
    /// gate on activity so that an inactive config never needs a special
    /// case in the trait object plumbing.
    pub fn new(config: InterceptConfig) -> Self {
        Self { config }
    }
}

//--------------------------------------------------------------------------------------------------
// Trait Implementations
//--------------------------------------------------------------------------------------------------

impl AuthorizedRouteRequestExtension for InterceptExtension {
    fn open(&self, route: &AuthorizedTlsRoute) -> Option<Box<dyn AuthorizedRouteRequestStream>> {
        // Open for every active-config TLS route, not just policed SNIs.
        // `Interceptor` itself decides policed-vs-unpoliced per SNI on the
        // first chunk (the zero-copy `Forwarding` fast path for unpoliced
        // hosts). Returning `None` here would route the connection through
        // the seam's direct-forwarding path instead, which for a policed
        // host is a bypass: the credential is already substituted by the
        // time bytes would reach that path.
        if !self.config.is_active() {
            return None;
        }
        Some(Box::new(InterceptStream {
            inner: Interceptor::new(self.config.clone(), route.server_name()),
        }))
    }
}

impl AuthorizedRouteRequestStream for InterceptStream {
    fn process<'a>(&'a mut self, chunk: &'a [u8]) -> BoxFuture<'a, io::Result<RequestAction>> {
        Box::pin(async move {
            Ok(match self.inner.process_chunk(chunk).await? {
                Verdict::Forward => RequestAction::ForwardCurrent,
                Verdict::Hold => RequestAction::Hold,
                Verdict::ForwardBuffered(bytes) => RequestAction::ForwardOwned(bytes),
                Verdict::Intercept(bytes) => RequestAction::RespondAndClose(bytes),
            })
        })
    }
}

//--------------------------------------------------------------------------------------------------
// Tests
//--------------------------------------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use std::net::{IpAddr, Ipv4Addr, SocketAddr};

    use super::*;
    use crate::intercept::config::InterceptRule;

    fn route(server_name: &str) -> AuthorizedTlsRoute {
        AuthorizedTlsRoute::new(
            SocketAddr::new(IpAddr::V4(Ipv4Addr::LOCALHOST), 443),
            server_name,
            false,
        )
    }

    fn active_config() -> InterceptConfig {
        InterceptConfig {
            rules: vec![InterceptRule {
                host: "api.github.com".into(),
                method: "GET".into(),
                path_prefix: "/".into(),
                dispatch_on_headers: false,
            }],
            hook: Some(vec!["/bin/cat".to_string()]),
            max_request_bytes: 64 * 1024,
        }
    }

    #[test]
    fn open_returns_none_when_config_is_inactive() {
        let extension = InterceptExtension::new(InterceptConfig::default());
        assert!(extension.open(&route("api.github.com")).is_none());
    }

    #[test]
    fn open_returns_some_for_every_active_config_route_including_unpoliced_sni() {
        let extension = InterceptExtension::new(active_config());
        assert!(extension.open(&route("api.github.com")).is_some());
        // Unpoliced SNI still gets a stream — the fast path lives inside
        // `Interceptor`, not in `open`. Returning `None` here would be a
        // bypass for any future policed host on the same extension.
        assert!(extension.open(&route("api.anthropic.com")).is_some());
    }

    /// `Verdict` → `RequestAction` mapping for all four variants.
    #[tokio::test]
    async fn process_maps_every_verdict_to_the_matching_request_action() {
        let extension = InterceptExtension::new(active_config());

        // Forward: unpoliced SNI zero-copy fast path.
        let mut unpoliced = extension.open(&route("api.anthropic.com")).unwrap();
        assert!(matches!(
            unpoliced.process(b"GET / HTTP/1.1\r\n\r\n").await.unwrap(),
            RequestAction::ForwardCurrent
        ));

        // Hold: partial request line on a policed SNI.
        let mut holding = extension.open(&route("api.github.com")).unwrap();
        assert!(matches!(
            holding.process(b"G").await.unwrap(),
            RequestAction::Hold
        ));

        // ForwardOwned: matched rule, hook (/bin/cat) echoes the request.
        let mut forwarding = extension.open(&route("api.github.com")).unwrap();
        assert!(matches!(
            forwarding
                .process(b"GET / HTTP/1.1\r\nHost: api.github.com\r\n\r\n")
                .await
                .unwrap(),
            RequestAction::ForwardOwned(_)
        ));

        // RespondAndClose: no rule matches (unlisted method) on a policed SNI.
        let mut refusing = extension.open(&route("api.github.com")).unwrap();
        assert!(matches!(
            refusing
                .process(b"HEAD / HTTP/1.1\r\nHost: api.github.com\r\n\r\n")
                .await
                .unwrap(),
            RequestAction::RespondAndClose(_)
        ));
    }

    /// Two connections through the same extension are independent: a
    /// bypassed/refused first connection must not affect the second. This
    /// is AC #3 ("a failed or bypassed request cannot disable interception
    /// for later requests") at the extension layer — `handler.rs` covers
    /// the same property within a single `Interceptor`.
    #[tokio::test]
    async fn each_connection_gets_an_independent_interceptor() {
        let extension = InterceptExtension::new(active_config());

        let mut first = extension.open(&route("api.github.com")).unwrap();
        let refusal = first
            .process(b"HEAD / HTTP/1.1\r\nHost: api.github.com\r\n\r\n")
            .await
            .unwrap();
        assert!(matches!(refusal, RequestAction::RespondAndClose(_)));

        let mut second = extension.open(&route("api.github.com")).unwrap();
        let policed = second
            .process(b"GET / HTTP/1.1\r\nHost: api.github.com\r\n\r\n")
            .await
            .unwrap();
        assert!(
            matches!(policed, RequestAction::ForwardOwned(_)),
            "a fresh connection must still be policed after an earlier one was refused"
        );
    }
}
