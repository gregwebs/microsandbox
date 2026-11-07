//! Egress refusal reporting: the seam every refused egress decision is reported through.
//!
//! The engine cannot depend on the runtime that owns the log file, so a refused decision is handed
//! to a [`RefusalSink`] the host installs on the per-sandbox shared state. The one crate-internal
//! entry point, `record`, owns the rules every deny site shares: it returns before allocating when
//! no sink is installed, resolves `dns-cache` name evidence, normalizes names, and maps the
//! engine's protocol onto the wire contract. Sites state facts; this module decides how the facts
//! are recorded.

use std::net::IpAddr;

use microsandbox_types::{NameSource, NetworkRefusal, RefusalLayer, RefusalSite};

use crate::netstack::shared::SharedState;
use crate::policy::Protocol;

//--------------------------------------------------------------------------------------------------
// Constants
//--------------------------------------------------------------------------------------------------

/// Longest name a record carries; no valid DNS name is longer.
///
/// A longer name is reported as no evidence rather than truncated, because a truncated name could
/// read as a different, approvable domain.
const MAX_NAME_BYTES: usize = 253;

/// Longest one label of a name may be.
const MAX_LABEL_BYTES: usize = 63;

//--------------------------------------------------------------------------------------------------
// Types
//--------------------------------------------------------------------------------------------------

/// Receives one record per refused egress decision.
///
/// Called on the smoltcp poll thread and on proxy and DNS tasks. An implementation must not block
/// (no disk I/O, no waiting on a bounded queue) and may drop records.
pub trait RefusalSink: Send + Sync {
    /// Whether one more refusal at `site` should be recorded, taking its rate-limit token when it
    /// returns `true`.
    ///
    /// Reporting asks this *before* it resolves name evidence, so a refused datagram at a
    /// saturated site costs a lock and a counter rather than a DNS-index lookup and a name
    /// allocation. A sink that returns `false` also counts the refusal as suppressed; the record
    /// it admits is then delivered to [`record`](Self::record).
    fn admits(&self, site: RefusalSite) -> bool;

    /// Take the refusal record the sink admitted.
    ///
    /// Only a record whose site [`admits`](Self::admits) returned `true` for is delivered here, so
    /// a sink must not admit a second time: the two calls together are one decision, and the
    /// rate limiter is charged once, in `admits`.
    fn record(&self, refusal: NetworkRefusal);
}

/// The guest-supplied name a deny site holds.
#[derive(Clone, Copy, Debug)]
pub(crate) enum NameEvidence<'a> {
    /// A name from a TLS ClientHello.
    Sni(&'a str),
    /// An HTTP authority: a `Host` header, an HTTP/2 `:authority`, or a CONNECT target.
    HttpHost(&'a str),
    /// The name a DNS query asked for.
    DnsQuery(&'a str),
    /// The names the guest's own DNS answers bound to this address.
    CachedFor(IpAddr),
    /// No name evidence; the record carries no name.
    None,
}

/// One refused decision, as its deny site describes it.
pub(crate) struct Denial<'a> {
    /// The decision rule that refused.
    pub(crate) site: RefusalSite,
    /// Which configuration owned the refusal.
    pub(crate) layer: RefusalLayer,
    /// Transport of the refused attempt.
    pub(crate) protocol: Protocol,
    /// Destination address the guest used, when the site knows it.
    pub(crate) dst_ip: Option<IpAddr>,
    /// Destination port; absent for ICMP and for `dns-rebind`.
    pub(crate) dst_port: Option<u16>,
    /// The name evidence the site holds.
    pub(crate) name: NameEvidence<'a>,
    /// Revision of the tenant-policy snapshot the decision consulted.
    pub(crate) revision: u64,
}

//--------------------------------------------------------------------------------------------------
// Functions
//--------------------------------------------------------------------------------------------------

/// Report one refused decision.
///
/// Returns before any allocation, lock or lookup when no sink is installed, and returns before
/// resolving name evidence when the sink refuses the site's token.
pub(crate) fn record(shared: &SharedState, denial: Denial<'_>) {
    let Some(sink) = shared.refusal_sink() else {
        return;
    };
    // Admission first: evidence is only resolved for a refusal that will be written, so a
    // suppressed flood pays for neither the DNS index's lock nor a name allocation.
    if !sink.admits(denial.site) {
        return;
    }
    let (name, name_source) = evidence(shared, denial.name);

    sink.record(NetworkRefusal {
        site: denial.site,
        layer: denial.layer,
        protocol: wire_protocol(denial.protocol),
        dst_ip: denial.dst_ip,
        dst_port: denial.dst_port,
        name,
        name_source,
        revision: denial.revision,
    });
}

//--------------------------------------------------------------------------------------------------
// Functions: Helpers
//--------------------------------------------------------------------------------------------------

/// Map the engine's protocol onto the wire contract's.
fn wire_protocol(protocol: Protocol) -> microsandbox_types::Protocol {
    match protocol {
        Protocol::Tcp => microsandbox_types::Protocol::Tcp,
        Protocol::Udp => microsandbox_types::Protocol::Udp,
        Protocol::Icmpv4 => microsandbox_types::Protocol::Icmpv4,
        Protocol::Icmpv6 => microsandbox_types::Protocol::Icmpv6,
    }
}

/// Resolve a site's name evidence into the record's `(name, name_source)` pair.
///
/// A name is present if and only if the source is not `none`, so evidence that resolves to
/// nothing usable is reported as no evidence at all.
fn evidence(shared: &SharedState, name: NameEvidence<'_>) -> (Option<String>, NameSource) {
    let (name, name_source) = match name {
        NameEvidence::Sni(name) => (normalize_name(name), NameSource::Sni),
        NameEvidence::HttpHost(authority) => (normalize_authority(authority), NameSource::HttpHost),
        NameEvidence::DnsQuery(name) => (normalize_name(name), NameSource::DnsQuery),
        NameEvidence::CachedFor(addr) => (
            shared
                .resolved_hostname_for(addr)
                .and_then(|name| normalize_name(&name)),
            NameSource::DnsCache,
        ),
        NameEvidence::None => (None, NameSource::Absent),
    };

    match name {
        Some(name) => (Some(name), name_source),
        None => (None, NameSource::Absent),
    }
}

/// Normalize a name for the record: no trailing dot, ASCII-lowercase, never truncated.
///
/// Guest-supplied text is only a name if it *is* one. Anything that is not — an IP literal, a
/// scheme or path, whitespace or a control character, a malformed or over-long label — is
/// reported as no evidence at all, because a record's `name` is what an approval UI shows and a
/// mangled name could read as a different, approvable domain.
fn normalize_name(name: &str) -> Option<String> {
    // The length check comes before the lowercase allocation: a header value of many kilobytes
    // must be rejected without being copied.
    if name.len() > MAX_NAME_BYTES {
        return None;
    }

    let name = name.trim_end_matches('.');
    if !is_name(name) {
        return None;
    }
    Some(name.to_ascii_lowercase())
}

/// Whether `name` is a name a record may carry: dot-separated labels of ASCII letters, digits,
/// hyphens and underscores, and not an IP literal.
fn is_name(name: &str) -> bool {
    if name.is_empty() || name.parse::<IpAddr>().is_ok() {
        return false;
    }

    name.split('.').all(|label| {
        !label.is_empty()
            && label.len() <= MAX_LABEL_BYTES
            && label
                .bytes()
                .all(|byte| byte.is_ascii_alphanumeric() || byte == b'-' || byte == b'_')
    })
}

/// Normalize an HTTP authority into the hostname part a record may carry.
///
/// Reporting only: the policy path keeps its own deliberately lenient authority split, so a name
/// this rejects is still decided on exactly as before. Userinfo and one numeric port are removed;
/// anything else that is not a hostname — a scheme, a path, a non-numeric port, an IPv6 literal —
/// is no name evidence.
fn normalize_authority(authority: &str) -> Option<String> {
    let authority = authority.trim();

    // Userinfo is not the host: `user:pw@host:443` names `host`.
    let authority = match authority.rsplit_once('@') {
        Some((_, host)) => host,
        None => authority,
    };

    // A bracketed IPv6 literal is an address, not a name.
    if authority.starts_with('[') {
        return None;
    }

    let host = match authority.rsplit_once(':') {
        Some((host, port)) if !host.contains(':') && port.parse::<u16>().is_ok() => host,
        // A `:` that is not a port separator makes this unreadable as an authority.
        Some(_) => return None,
        None => authority,
    };

    normalize_name(host)
}

//--------------------------------------------------------------------------------------------------
// Tests
//--------------------------------------------------------------------------------------------------

#[cfg(test)]
pub(crate) mod test_support;

#[cfg(test)]
mod tests {
    use std::time::Duration;

    use super::test_support::{cache_name, recording_state};
    use super::*;

    const DST: &str = "203.0.113.10:443";
    const CACHED: &str = "198.51.100.7";

    fn denial(name: NameEvidence<'_>) -> Denial<'_> {
        let dst: std::net::SocketAddr = DST.parse().unwrap();
        Denial {
            site: RefusalSite::TcpSyn,
            layer: RefusalLayer::Tenant,
            protocol: Protocol::Tcp,
            dst_ip: Some(dst.ip()),
            dst_port: Some(dst.port()),
            name,
            revision: 2,
        }
    }

    #[test]
    fn record_without_a_sink_is_a_no_op() {
        let shared = SharedState::new(4);
        let cached: IpAddr = CACHED.parse().unwrap();
        cache_name(&shared, "cached.example", cached);

        // Every evidence kind, including one that would resolve through the DNS index: with no
        // sink installed the call must do nothing at all.
        for name in [
            NameEvidence::Sni("blocked.example"),
            NameEvidence::HttpHost("blocked.example:443"),
            NameEvidence::DnsQuery("blocked.example"),
            NameEvidence::CachedFor(cached),
            NameEvidence::None,
        ] {
            record(&shared, denial(name));
        }

        // Nothing was buffered for a sink that arrives later: reporting without a sink drops.
        let sink = super::test_support::CollectingSink::new();
        shared.set_refusal_sink(sink.clone());
        assert!(sink.take().is_empty());
    }

    #[test]
    fn record_reports_the_facts_the_deny_site_holds() {
        let (shared, sink) = recording_state(4);
        let cached: IpAddr = CACHED.parse().unwrap();
        cache_name(&shared, "cached.example", cached);

        record(
            &shared,
            Denial {
                site: RefusalSite::DnsRebind,
                layer: RefusalLayer::Platform,
                protocol: Protocol::Icmpv6,
                dst_ip: Some(cached),
                dst_port: None,
                name: NameEvidence::DnsQuery("Blocked.Example."),
                revision: 7,
            },
        );

        assert_eq!(
            sink.take(),
            vec![NetworkRefusal {
                site: RefusalSite::DnsRebind,
                layer: RefusalLayer::Platform,
                protocol: microsandbox_types::Protocol::Icmpv6,
                dst_ip: Some(cached),
                dst_port: None,
                name: Some("blocked.example".to_owned()),
                name_source: NameSource::DnsQuery,
                revision: 7,
            }]
        );
    }

    #[test]
    fn every_protocol_maps_onto_the_wire_contract() {
        for (engine, wire) in [
            (Protocol::Tcp, microsandbox_types::Protocol::Tcp),
            (Protocol::Udp, microsandbox_types::Protocol::Udp),
            (Protocol::Icmpv4, microsandbox_types::Protocol::Icmpv4),
            (Protocol::Icmpv6, microsandbox_types::Protocol::Icmpv6),
        ] {
            assert_eq!(wire_protocol(engine), wire);
        }
    }

    #[test]
    fn names_are_normalized_before_they_are_recorded() {
        let shared = SharedState::new(4);

        for (name, expected) in [
            (NameEvidence::Sni("Example.COM."), Some("example.com")),
            (
                NameEvidence::DnsQuery("Blocked.Example."),
                Some("blocked.example"),
            ),
            // A DNS service name is a name too.
            (
                NameEvidence::DnsQuery("_sip._tcp.Example."),
                Some("_sip._tcp.example"),
            ),
            // An http-host name is the hostname part of the authority.
            (
                NameEvidence::HttpHost("Blocked.Example.:8443"),
                Some("blocked.example"),
            ),
            // Userinfo is not part of the host.
            (
                NameEvidence::HttpHost("user:pw@blocked.example:443"),
                Some("blocked.example"),
            ),
            (
                NameEvidence::HttpHost("blocked.example@evil.test"),
                Some("evil.test"),
            ),
        ] {
            let (recorded, name_source) = evidence(&shared, name);
            assert_eq!(recorded.as_deref(), expected);
            assert_ne!(name_source, NameSource::Absent, "a name was recorded");
        }
    }

    /// A record's `name` is what an approval UI shows, so text that is not a name is reported as
    /// no evidence instead of being passed through.
    #[test]
    fn malformed_and_ip_literal_names_are_not_evidence() {
        let shared = SharedState::new(4);

        for name in [
            // An address is not a name, from either source.
            NameEvidence::Sni("203.0.113.10"),
            NameEvidence::DnsQuery("203.0.113.10"),
            NameEvidence::HttpHost("203.0.113.10"),
            NameEvidence::HttpHost("203.0.113.10:443"),
            NameEvidence::HttpHost("[2001:db8::1]:8080"),
            NameEvidence::Sni("2001:db8::1"),
            // A port that is not a number, a path, a scheme, an empty label.
            NameEvidence::HttpHost("evil.test:abc"),
            NameEvidence::HttpHost("evil.test/path"),
            NameEvidence::HttpHost("https://evil.test"),
            NameEvidence::HttpHost("evil..test"),
            NameEvidence::HttpHost("evil .test"),
            NameEvidence::HttpHost("e\u{0}vil.test"),
            NameEvidence::HttpHost("evil\ttest"),
            NameEvidence::Sni("evil.test/path"),
            NameEvidence::Sni("evil test"),
            NameEvidence::Sni("e\u{0}vil.test"),
            NameEvidence::Sni("evil\u{2028}.test"),
            // A label longer than DNS allows.
            NameEvidence::Sni(&"a".repeat(MAX_LABEL_BYTES + 1)),
        ] {
            let (recorded, name_source) = evidence(&shared, name);
            assert_eq!(recorded, None, "must not be recorded as a name: {name:?}");
            assert_eq!(name_source, NameSource::Absent, "{name:?}");
        }
    }

    #[test]
    fn unusable_names_are_recorded_as_no_evidence() {
        let shared = SharedState::new(4);
        let long = "a".repeat(MAX_NAME_BYTES + 1);
        // 253 bytes in dot-separated labels of at most 63: the longest name that still fits.
        let longest = [
            "a".repeat(63),
            "b".repeat(63),
            "c".repeat(63),
            "d".repeat(61),
        ]
        .join(".");

        for (name, expected) in [
            // Empty stays empty rather than becoming a name.
            (NameEvidence::Sni(""), None),
            (NameEvidence::Sni("."), None),
            (NameEvidence::DnsQuery(""), None),
            (NameEvidence::HttpHost(""), None),
            (NameEvidence::HttpHost("."), None),
            // An authority without a hostname has no name to report.
            (NameEvidence::HttpHost(":443"), None),
            // Never truncated: a longer name would read as a different domain.
            (NameEvidence::Sni(&long), None),
            (NameEvidence::DnsQuery(&long), None),
            (NameEvidence::HttpHost(&long), None),
            // No evidence at all.
            (NameEvidence::None, None),
            // The longest name that still fits, as labels DNS allows.
            (NameEvidence::Sni(&longest), Some(longest.as_str())),
        ] {
            let (recorded, name_source) = evidence(&shared, name);
            assert_eq!(recorded.as_deref(), expected);
            if expected.is_none() {
                assert_eq!(name_source, NameSource::Absent, "no name means no source");
            }
        }
    }

    #[test]
    fn cached_name_is_the_smallest_live_binding() {
        let (shared, sink) = recording_state(4);
        let addr: IpAddr = CACHED.parse().unwrap();
        // Three names for one address, cached out of order, so the choice cannot be insertion
        // order.
        cache_name(&shared, "zebra.example", addr);
        cache_name(&shared, "middle.example", addr);
        cache_name(&shared, "Apple.Example.", addr);

        record(&shared, denial(NameEvidence::CachedFor(addr)));

        let recorded = sink.take();
        assert_eq!(recorded.len(), 1);
        assert_eq!(recorded[0].name.as_deref(), Some("apple.example"));
        assert_eq!(recorded[0].name_source, NameSource::DnsCache);
    }

    #[test]
    fn address_without_a_live_binding_has_no_name_evidence() {
        let (shared, sink) = recording_state(4);
        let addr: IpAddr = CACHED.parse().unwrap();
        // A zero TTL is already expired, so the binding is not live.
        let ttl = Duration::from_secs(0);
        assert!(shared.cache_resolved_hostname(
            "cached.example",
            crate::netstack::shared::ResolvedHostnameFamily::Ipv4,
            [addr],
            ttl,
        ));

        record(&shared, denial(NameEvidence::CachedFor(addr)));

        let recorded = sink.take();
        assert_eq!(recorded.len(), 1);
        assert_eq!(recorded[0].name, None);
        assert_eq!(recorded[0].name_source, NameSource::Absent);
    }
}
