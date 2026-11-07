//! The `network.log` record: one JSON line per egress refusal, written by the runtime and read
//! through the SDK's `network` log source.
//!
//! Every line carries the envelope `v`, `t`, `s` and an `event` discriminator, followed by the
//! fields of that event. Guest-supplied names are JSON-escaped by the serializer, so a name can
//! never break a line.

use std::net::IpAddr;

use chrono::{DateTime, SecondsFormat, Utc};
use serde::{Deserialize, Deserializer, Serialize, Serializer};

use crate::{LogSource, Protocol};

//--------------------------------------------------------------------------------------------------
// Constants
//--------------------------------------------------------------------------------------------------

/// Format version written in every record's `v` field.
///
/// Additive optional fields keep this value; only an incompatible change increments it. A reader
/// skips a line whose `v` is greater than the version it knows.
pub const NETWORK_LOG_FORMAT_VERSION: u32 = 1;

//--------------------------------------------------------------------------------------------------
// Types
//--------------------------------------------------------------------------------------------------

/// One line of `network.log`.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct NetworkLogRecord {
    /// Format version; see [`NETWORK_LOG_FORMAT_VERSION`].
    pub v: u32,

    /// When the refusal was reported, or when a suppressed record was written: RFC 3339 UTC with
    /// millisecond precision and a `Z` suffix.
    #[serde(with = "rfc3339_millis")]
    pub t: DateTime<Utc>,

    /// Always [`LogSource::Network`].
    pub s: LogSource,

    /// What happened.
    #[serde(flatten)]
    pub event: NetworkLogEvent,
}

/// The two kinds of `network.log` record.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(tag = "event", rename_all = "kebab-case")]
#[non_exhaustive]
pub enum NetworkLogEvent {
    /// One refused egress decision.
    Refusal(NetworkRefusal),

    /// Refusals at one site that were decided but not written.
    Suppressed(NetworkSuppressed),
}

/// Facts about one refused egress decision.
///
/// Every name is guest-supplied; the record reports the name and where it came from, never
/// whether the name is approvable.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct NetworkRefusal {
    /// Where in the network engine the refusal was decided.
    pub site: RefusalSite,

    /// Which configuration owns the refusal.
    pub layer: RefusalLayer,

    /// Protocol of the refused traffic.
    pub protocol: Protocol,

    /// Destination address the guest used. Absent only for a DNS query whose addressed resolver
    /// the engine could not determine.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub dst_ip: Option<IpAddr>,

    /// Destination port. Absent for ICMP and for `dns-rebind`.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub dst_port: Option<u16>,

    /// Guest-supplied name evidence. Present if and only if `name_source` is not
    /// [`NameSource::Absent`].
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub name: Option<String>,

    /// Where [`NetworkRefusal::name`] came from.
    pub name_source: NameSource,

    /// Tenant policy revision in force for this decision.
    pub revision: u64,
}

/// A count of refusals at one site that were decided but not written.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct NetworkSuppressed {
    /// The site whose refusals were not written.
    pub site: RefusalSite,

    /// Refusals at `site` decided but not written since the previous suppressed record for
    /// `site` in that runtime process, or since it started.
    pub count: u64,
}

/// Where in the network engine a refusal was decided.
///
/// The string form is part of the wire contract: a value names one decision rule and is never
/// reused or renamed, and a new rule gets a new value at
/// [`NETWORK_LOG_FORMAT_VERSION`].
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash, Serialize, Deserialize)]
#[serde(rename_all = "kebab-case")]
#[non_exhaustive]
pub enum RefusalSite {
    /// A TCP SYN refused by a policy at admission.
    TcpSyn,

    /// A TCP connection to a DNS-over-TLS port refused because TLS interception is off.
    TcpDot,

    /// A TCP connection to an alternative DNS port refused.
    TcpAltDns,

    /// A TCP flow's hostname refused by a policy at the TCP proxy.
    TcpHostname,

    /// An opaque TLS flow refused because it has no hostname evidence under strict mode.
    TcpStrict,

    /// A flow that reached the TCP proxy as a denial and was closed as one.
    TcpProxyFailClosed,

    /// An HTTP CONNECT request refused by the strict-hostname rule.
    ConnectStrict,

    /// A TLS ClientHello's SNI refused by a policy.
    TlsSni,

    /// A TLS flow refused by the strict-hostname rule.
    TlsStrictBypass,

    /// A TLS ClientHello whose SNI does not match the CONNECT authority.
    TlsConnectMismatch,

    /// A UDP datagram refused by a policy.
    Udp,

    /// UDP to a TLS-intercepted port dropped because QUIC is blocked.
    UdpQuic,

    /// UDP to an alternative DNS port dropped.
    UdpAltDns,

    /// UDP to a DNS port dropped by the relay's defensive check.
    UdpDnsPort,

    /// An ICMP echo refused by a policy.
    Icmp,

    /// A DNS query refused by a policy.
    DnsQuery,

    /// A DNS query to a directly addressed resolver refused by a policy.
    DnsResolver,

    /// A DNS answer refused by rebind protection.
    DnsRebind,

    /// An HTTP request authority refused by a policy.
    HttpAuthority,

    /// An HTTP request authority that is not the connection's proven name.
    HttpAuthorityMismatch,

    /// An HTTP request authority with no parseable hostname.
    HttpAuthorityInvalid,

    /// An HTTP request whose authority count is not one.
    HttpAuthorityCount,

    /// An HTTP/2 header block over the header limits.
    HttpHeaderLimit,

    /// A secret violation refused by the secrets handler.
    SecretViolation,
}

/// Which configuration owns a refusal.
///
/// `#[non_exhaustive]`, like [`RefusalSite`] and [`NameSource`]: a consumer `match` must have a
/// wildcard arm, so a layer added later is wire-compatible instead of breaking every downstream
/// build.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "lowercase")]
#[non_exhaustive]
pub enum RefusalLayer {
    /// The sandbox's own network configuration, or a built-in engine rule that applies to every
    /// sandbox.
    Tenant,

    /// The deployment profile's fixed platform floor.
    Platform,
}

/// Where a refusal's name evidence came from.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "kebab-case")]
#[non_exhaustive]
pub enum NameSource {
    /// The SNI of a TLS ClientHello.
    Sni,

    /// An HTTP `Host` header, an HTTP/2 `:authority` or an HTTP CONNECT target.
    HttpHost,

    /// The name the guest queried over DNS.
    DnsQuery,

    /// A name the guest's own DNS answers bound to the destination address.
    DnsCache,

    /// No name evidence; the record carries no `name`.
    #[serde(rename = "none")]
    Absent,
}

//--------------------------------------------------------------------------------------------------
// Methods
//--------------------------------------------------------------------------------------------------

impl RefusalSite {
    /// Number of sites; the length of [`RefusalSite::ALL`].
    pub const COUNT: usize = 24;

    /// Every site, in declaration (and `Ord`) order.
    pub const ALL: [RefusalSite; Self::COUNT] = [
        RefusalSite::TcpSyn,
        RefusalSite::TcpDot,
        RefusalSite::TcpAltDns,
        RefusalSite::TcpHostname,
        RefusalSite::TcpStrict,
        RefusalSite::TcpProxyFailClosed,
        RefusalSite::ConnectStrict,
        RefusalSite::TlsSni,
        RefusalSite::TlsStrictBypass,
        RefusalSite::TlsConnectMismatch,
        RefusalSite::Udp,
        RefusalSite::UdpQuic,
        RefusalSite::UdpAltDns,
        RefusalSite::UdpDnsPort,
        RefusalSite::Icmp,
        RefusalSite::DnsQuery,
        RefusalSite::DnsResolver,
        RefusalSite::DnsRebind,
        RefusalSite::HttpAuthority,
        RefusalSite::HttpAuthorityMismatch,
        RefusalSite::HttpAuthorityInvalid,
        RefusalSite::HttpAuthorityCount,
        RefusalSite::HttpHeaderLimit,
        RefusalSite::SecretViolation,
    ];

    /// This site's position in [`RefusalSite::ALL`].
    ///
    /// An exhaustive `match`, so adding a variant without updating `ALL`/`COUNT` fails to
    /// compile. A fixed-size array indexed by this value lets the runtime keep one counter slot
    /// per site without allocating.
    pub const fn index(self) -> usize {
        match self {
            RefusalSite::TcpSyn => 0,
            RefusalSite::TcpDot => 1,
            RefusalSite::TcpAltDns => 2,
            RefusalSite::TcpHostname => 3,
            RefusalSite::TcpStrict => 4,
            RefusalSite::TcpProxyFailClosed => 5,
            RefusalSite::ConnectStrict => 6,
            RefusalSite::TlsSni => 7,
            RefusalSite::TlsStrictBypass => 8,
            RefusalSite::TlsConnectMismatch => 9,
            RefusalSite::Udp => 10,
            RefusalSite::UdpQuic => 11,
            RefusalSite::UdpAltDns => 12,
            RefusalSite::UdpDnsPort => 13,
            RefusalSite::Icmp => 14,
            RefusalSite::DnsQuery => 15,
            RefusalSite::DnsResolver => 16,
            RefusalSite::DnsRebind => 17,
            RefusalSite::HttpAuthority => 18,
            RefusalSite::HttpAuthorityMismatch => 19,
            RefusalSite::HttpAuthorityInvalid => 20,
            RefusalSite::HttpAuthorityCount => 21,
            RefusalSite::HttpHeaderLimit => 22,
            RefusalSite::SecretViolation => 23,
        }
    }
}

//--------------------------------------------------------------------------------------------------
// Functions: Helpers
//--------------------------------------------------------------------------------------------------

/// RFC 3339 UTC with millisecond precision and a `Z` suffix, as every record's `t` field.
mod rfc3339_millis {
    use super::*;

    pub(super) fn serialize<S: Serializer>(t: &DateTime<Utc>, s: S) -> Result<S::Ok, S::Error> {
        s.serialize_str(&t.to_rfc3339_opts(SecondsFormat::Millis, true))
    }

    pub(super) fn deserialize<'de, D: Deserializer<'de>>(d: D) -> Result<DateTime<Utc>, D::Error> {
        let raw = String::deserialize(d)?;
        DateTime::parse_from_rfc3339(&raw)
            .map(|t| t.with_timezone(&Utc))
            .map_err(serde::de::Error::custom)
    }
}

//--------------------------------------------------------------------------------------------------
// Tests
//--------------------------------------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use super::*;

    /// The four documented example lines from the specification, byte for byte.
    const TCP_SYN_LINE: &str = r#"{"v":1,"t":"2026-11-05T14:03:07.412Z","s":"network","event":"refusal","site":"tcp-syn","layer":"tenant","protocol":"tcp","dst_ip":"203.0.113.10","dst_port":443,"name":"api.example.com","name_source":"dns-cache","revision":2}"#;
    const DNS_QUERY_LINE: &str = r#"{"v":1,"t":"2026-11-05T14:03:07.398Z","s":"network","event":"refusal","site":"dns-query","layer":"tenant","protocol":"udp","dst_ip":"100.96.0.1","dst_port":53,"name":"blocked.example","name_source":"dns-query","revision":2}"#;
    const ICMP_LINE: &str = r#"{"v":1,"t":"2026-11-05T14:03:08.051Z","s":"network","event":"refusal","site":"icmp","layer":"platform","protocol":"icmpv4","dst_ip":"10.0.0.7","name_source":"none","revision":1}"#;
    const SUPPRESSED_LINE: &str = r#"{"v":1,"t":"2026-11-05T14:03:09.000Z","s":"network","event":"suppressed","site":"udp","count":4744}"#;

    fn tcp_syn() -> NetworkLogRecord {
        NetworkLogRecord {
            v: NETWORK_LOG_FORMAT_VERSION,
            t: "2026-11-05T14:03:07.412Z".parse().unwrap(),
            s: LogSource::Network,
            event: NetworkLogEvent::Refusal(NetworkRefusal {
                site: RefusalSite::TcpSyn,
                layer: RefusalLayer::Tenant,
                protocol: Protocol::Tcp,
                dst_ip: Some("203.0.113.10".parse().unwrap()),
                dst_port: Some(443),
                name: Some("api.example.com".to_string()),
                name_source: NameSource::DnsCache,
                revision: 2,
            }),
        }
    }

    fn dns_query() -> NetworkLogRecord {
        NetworkLogRecord {
            v: NETWORK_LOG_FORMAT_VERSION,
            t: "2026-11-05T14:03:07.398Z".parse().unwrap(),
            s: LogSource::Network,
            event: NetworkLogEvent::Refusal(NetworkRefusal {
                site: RefusalSite::DnsQuery,
                layer: RefusalLayer::Tenant,
                protocol: Protocol::Udp,
                dst_ip: Some("100.96.0.1".parse().unwrap()),
                dst_port: Some(53),
                name: Some("blocked.example".to_string()),
                name_source: NameSource::DnsQuery,
                revision: 2,
            }),
        }
    }

    #[test]
    fn refusal_record_serializes_to_the_documented_bytes() {
        assert_eq!(serde_json::to_string(&tcp_syn()).unwrap(), TCP_SYN_LINE);
        assert_eq!(serde_json::to_string(&dns_query()).unwrap(), DNS_QUERY_LINE);
        assert_eq!(
            serde_json::from_str::<NetworkLogRecord>(TCP_SYN_LINE).unwrap(),
            tcp_syn()
        );
        assert_eq!(
            serde_json::from_str::<NetworkLogRecord>(DNS_QUERY_LINE).unwrap(),
            dns_query()
        );
    }

    #[test]
    fn suppressed_record_serializes_to_the_documented_bytes() {
        let record = NetworkLogRecord {
            v: NETWORK_LOG_FORMAT_VERSION,
            t: "2026-11-05T14:03:09.000Z".parse().unwrap(),
            s: LogSource::Network,
            event: NetworkLogEvent::Suppressed(NetworkSuppressed {
                site: RefusalSite::Udp,
                count: 4744,
            }),
        };

        assert_eq!(serde_json::to_string(&record).unwrap(), SUPPRESSED_LINE);
        assert_eq!(
            serde_json::from_str::<NetworkLogRecord>(SUPPRESSED_LINE).unwrap(),
            record
        );
    }

    #[test]
    fn optional_fields_are_omitted_and_default_on_read() {
        let record = NetworkLogRecord {
            v: NETWORK_LOG_FORMAT_VERSION,
            t: "2026-11-05T14:03:08.051Z".parse().unwrap(),
            s: LogSource::Network,
            event: NetworkLogEvent::Refusal(NetworkRefusal {
                site: RefusalSite::Icmp,
                layer: RefusalLayer::Platform,
                protocol: Protocol::Icmpv4,
                dst_ip: Some("10.0.0.7".parse().unwrap()),
                dst_port: None,
                name: None,
                name_source: NameSource::Absent,
                revision: 1,
            }),
        };

        assert_eq!(serde_json::to_string(&record).unwrap(), ICMP_LINE);
        assert_eq!(
            serde_json::from_str::<NetworkLogRecord>(ICMP_LINE).unwrap(),
            record
        );
    }

    #[test]
    fn unknown_fields_are_ignored() {
        let line = TCP_SYN_LINE.replace(r#""revision":2"#, r#""revision":2,"future":1"#);
        let record: NetworkLogRecord = serde_json::from_str(&line).unwrap();

        assert_eq!(record, tcp_syn());
    }

    #[test]
    fn unknown_site_fails_to_deserialize() {
        let line = TCP_SYN_LINE.replace(r#""site":"tcp-syn""#, r#""site":"tcp-future""#);

        assert!(serde_json::from_str::<NetworkLogRecord>(&line).is_err());
    }

    #[test]
    fn unknown_event_fails_to_deserialize() {
        let line = TCP_SYN_LINE.replace(r#""event":"refusal""#, r#""event":"admired""#);

        assert!(serde_json::from_str::<NetworkLogRecord>(&line).is_err());
    }

    #[test]
    fn ipv6_destination_round_trips() {
        let mut record = tcp_syn();
        let NetworkLogEvent::Refusal(refusal) = &mut record.event else {
            unreachable!("tcp_syn is a refusal");
        };
        refusal.dst_ip = Some("2001:db8::1".parse().unwrap());
        refusal.dst_port = None;

        let line = serde_json::to_string(&record).unwrap();
        assert!(line.contains(r#""dst_ip":"2001:db8::1""#), "{line}");
        assert_eq!(
            serde_json::from_str::<NetworkLogRecord>(&line).unwrap(),
            record
        );
    }

    #[test]
    fn every_site_renders_its_documented_kebab_case_value() {
        let expected = [
            "tcp-syn",
            "tcp-dot",
            "tcp-alt-dns",
            "tcp-hostname",
            "tcp-strict",
            "tcp-proxy-fail-closed",
            "connect-strict",
            "tls-sni",
            "tls-strict-bypass",
            "tls-connect-mismatch",
            "udp",
            "udp-quic",
            "udp-alt-dns",
            "udp-dns-port",
            "icmp",
            "dns-query",
            "dns-resolver",
            "dns-rebind",
            "http-authority",
            "http-authority-mismatch",
            "http-authority-invalid",
            "http-authority-count",
            "http-header-limit",
            "secret-violation",
        ];

        assert_eq!(expected.len(), RefusalSite::COUNT);
        for (index, site) in RefusalSite::ALL.into_iter().enumerate() {
            assert_eq!(site.index(), index, "index of {site:?}");
            let rendered = serde_json::to_value(site).unwrap();
            assert_eq!(rendered, serde_json::json!(expected[index]));
            assert_eq!(
                serde_json::from_value::<RefusalSite>(rendered).unwrap(),
                site
            );
        }
    }

    #[test]
    fn sites_are_ordered_as_declared() {
        let mut sorted = RefusalSite::ALL;
        sorted.sort();

        assert_eq!(sorted, RefusalSite::ALL);
    }

    #[test]
    fn layer_and_name_source_render_their_documented_values() {
        assert_eq!(
            serde_json::to_value(RefusalLayer::Tenant).unwrap(),
            serde_json::json!("tenant")
        );
        assert_eq!(
            serde_json::to_value(RefusalLayer::Platform).unwrap(),
            serde_json::json!("platform")
        );
        for (source, expected) in [
            (NameSource::Sni, "sni"),
            (NameSource::HttpHost, "http-host"),
            (NameSource::DnsQuery, "dns-query"),
            (NameSource::DnsCache, "dns-cache"),
            (NameSource::Absent, "none"),
        ] {
            let rendered = serde_json::to_value(source).unwrap();
            assert_eq!(rendered, serde_json::json!(expected));
            assert_eq!(
                serde_json::from_value::<NameSource>(rendered).unwrap(),
                source
            );
        }
    }

    #[test]
    fn timestamps_are_millisecond_utc_with_z() {
        let record = NetworkLogRecord {
            v: NETWORK_LOG_FORMAT_VERSION,
            t: "2026-11-05T14:03:07.412999Z".parse().unwrap(),
            s: LogSource::Network,
            event: NetworkLogEvent::Suppressed(NetworkSuppressed {
                site: RefusalSite::Udp,
                count: 1,
            }),
        };

        let line = serde_json::to_string(&record).unwrap();
        assert!(line.contains(r#""t":"2026-11-05T14:03:07.412Z""#), "{line}");
    }

    #[test]
    fn source_field_is_the_network_tag() {
        let record: NetworkLogRecord = serde_json::from_str(TCP_SYN_LINE).unwrap();

        assert_eq!(record.s, LogSource::Network);
    }
}
