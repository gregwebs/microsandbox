//! Fail-closed request interception for TLS-intercepted routes.
//!
//! After secret substitution and before forwarding plaintext to the
//! upstream server, the [`extensions`](crate::extensions) seam can consult a
//! per-connection [`handler::Interceptor`]. If a configured
//! [`config::InterceptRule`] matches the request's SNI / method / path, the
//! interceptor buffers the request (headers, or headers + body — see
//! [`config::InterceptRule::dispatch_on_headers`]), spawns the configured
//! hook command with the request bytes on stdin, and uses the hook's stdout
//! to decide whether to forward, rewrite, or refuse the request. A request
//! on a policed SNI that matches no rule is refused, never forwarded — see
//! [`config::InterceptConfig::is_active`] and the module-level docs on
//! [`handler`].
//!
//! A representative use is OAuth-refresh interception: when an in-guest
//! agent's token-refresh request would otherwise reach the provider with a
//! placeholder refresh token substituted for the real one, the interceptor
//! traps it and the hook returns a synthesized response produced out-of-band
//! on the host.
//!
//! [`extension::InterceptExtension`] adapts [`handler::Interceptor`] to the
//! [`AuthorizedRouteRequestExtension`](crate::extensions::AuthorizedRouteRequestExtension)
//! seam; engine startup installs it when [`config::InterceptConfig::is_active`].

pub mod config;
mod extension;
mod handler;

//--------------------------------------------------------------------------------------------------
// Re-Exports
//--------------------------------------------------------------------------------------------------

pub use extension::InterceptExtension;
