use std::io;
use std::net::{IpAddr, Ipv6Addr};
use std::time::Duration;

use base64::Engine as _;
use futures::future::BoxFuture;
use ipnetwork::IpNetwork;
use tokio::io::{AsyncReadExt as _, AsyncWriteExt as _};
use tokio::net::TcpStream;
use zeroize::Zeroizing;

use crate::extensions::{AuthorizedTcpRoute, OutboundConnectionExtension, OutboundProtocol};

//--------------------------------------------------------------------------------------------------
// Constants
//--------------------------------------------------------------------------------------------------

const CONNECT_TIMEOUT: Duration = Duration::from_secs(30);
const MAX_CONNECT_RESPONSE: usize = 16 * 1024;

//--------------------------------------------------------------------------------------------------
// Types
//--------------------------------------------------------------------------------------------------

#[derive(Clone)]
pub(crate) struct HostHttpProxyConnector {
    https: Option<ProxyEndpoint>,
    http: Option<ProxyEndpoint>,
    no_proxy: NoProxy,
}

#[derive(Clone)]
struct ProxyEndpoint {
    host: String,
    port: u16,
    authorization: Option<Zeroizing<String>>,
    display: String,
}

#[derive(Clone, Default)]
struct NoProxy {
    wildcard: bool,
    names: Vec<String>,
    networks: Vec<IpNetwork>,
}

#[derive(Default)]
struct EnvironmentValues {
    https_proxy: Option<String>,
    https_proxy_upper: Option<String>,
    http_proxy: Option<String>,
    http_proxy_upper: Option<String>,
    all_proxy: Option<String>,
    all_proxy_upper: Option<String>,
    no_proxy: Option<String>,
    no_proxy_upper: Option<String>,
}

//--------------------------------------------------------------------------------------------------
// Methods
//--------------------------------------------------------------------------------------------------

impl HostHttpProxyConnector {
    #[allow(dead_code)]
    pub(crate) fn from_env() -> Option<Self> {
        Self::from_values(EnvironmentValues::from_env())
    }

    fn from_values(values: EnvironmentValues) -> Option<Self> {
        let https = first_environment_value(values.https_proxy, values.https_proxy_upper);
        let http = first_environment_value(values.http_proxy, values.http_proxy_upper);
        let all = first_environment_value(values.all_proxy, values.all_proxy_upper);
        let no_proxy = first_environment_value(values.no_proxy, values.no_proxy_upper);
        let had_proxy_value = https.is_some() || http.is_some() || all.is_some();

        let https = https.as_deref().and_then(parse_endpoint);
        let http = http.as_deref().and_then(parse_endpoint);
        let all = all.as_deref().and_then(parse_endpoint);

        let connector = Self {
            https: https
                .clone()
                .or_else(|| all.clone())
                .or_else(|| http.clone()),
            http: http.or(all).or(https),
            no_proxy: NoProxy::parse(no_proxy.as_deref().unwrap_or("")),
        };

        if connector.https.is_none() && connector.http.is_none() {
            if had_proxy_value {
                tracing::warn!(
                    "ignoring unusable host HTTP proxy settings; guest egress will connect directly"
                );
            }
            return None;
        }

        Some(connector)
    }

    fn selected_endpoint(&self, protocol: OutboundProtocol) -> Option<&ProxyEndpoint> {
        match protocol {
            OutboundProtocol::Tcp => self.http.as_ref().or(self.https.as_ref()),
            OutboundProtocol::Tls => self.https.as_ref().or(self.http.as_ref()),
        }
    }

    pub(crate) fn endpoint_displays(&self) -> (Option<&str>, Option<&str>) {
        (
            self.https.as_ref().map(ProxyEndpoint::display),
            self.http.as_ref().map(ProxyEndpoint::display),
        )
    }

    pub(crate) fn has_no_proxy_rules(&self) -> bool {
        self.no_proxy.wildcard
            || !self.no_proxy.names.is_empty()
            || !self.no_proxy.networks.is_empty()
    }

    #[cfg(test)]
    pub(crate) fn from_url(url: &str) -> Option<Self> {
        let endpoint = parse_endpoint(url)?;
        Some(Self {
            https: Some(endpoint.clone()),
            http: Some(endpoint),
            no_proxy: NoProxy::default(),
        })
    }
}

impl ProxyEndpoint {
    fn display(&self) -> &str {
        &self.display
    }
}

impl NoProxy {
    fn parse(value: &str) -> Self {
        let mut no_proxy = Self::default();
        for token in value
            .split(|character: char| character == ',' || character.is_ascii_whitespace())
            .map(str::trim)
            .filter(|token| !token.is_empty())
        {
            if token == "*" {
                no_proxy.wildcard = true;
                continue;
            }

            let token = strip_no_proxy_port(token);
            if let Some(network) = parse_network(token) {
                no_proxy.networks.push(network);
                continue;
            }

            let name = token.trim_matches('.').to_ascii_lowercase();
            if !name.is_empty() {
                no_proxy.names.push(name);
            }
        }
        no_proxy
    }

    fn matches(&self, server_name: Option<&str>, guest_ip: IpAddr) -> bool {
        if self.wildcard {
            return true;
        }

        let guest_ip = normalize_ip(guest_ip);
        if self
            .networks
            .iter()
            .any(|network| network.contains(guest_ip))
        {
            return true;
        }

        let Some(server_name) = server_name else {
            return false;
        };
        let server_name = server_name.trim_end_matches('.').to_ascii_lowercase();
        self.names.iter().any(|name| {
            server_name == *name
                || server_name
                    .strip_suffix(name)
                    .is_some_and(|prefix| prefix.ends_with('.'))
        })
    }
}

impl EnvironmentValues {
    fn from_env() -> Self {
        Self {
            https_proxy: environment_value("https_proxy"),
            https_proxy_upper: environment_value("HTTPS_PROXY"),
            http_proxy: environment_value("http_proxy"),
            http_proxy_upper: environment_value("HTTP_PROXY"),
            all_proxy: environment_value("all_proxy"),
            all_proxy_upper: environment_value("ALL_PROXY"),
            no_proxy: environment_value("no_proxy"),
            no_proxy_upper: environment_value("NO_PROXY"),
        }
    }
}

//--------------------------------------------------------------------------------------------------
// Trait Implementations
//--------------------------------------------------------------------------------------------------

impl OutboundConnectionExtension for HostHttpProxyConnector {
    fn connect<'a>(&'a self, route: AuthorizedTcpRoute) -> BoxFuture<'a, io::Result<TcpStream>> {
        Box::pin(async move {
            let guest_destination = route.guest_destination();
            let primary_destination = route.primary_destination();
            let _fallback_destination = route.fallback_destination();
            let server_name = route.server_name().map(ToOwned::to_owned);
            let protocol = route.protocol();

            if self
                .no_proxy
                .matches(server_name.as_deref(), guest_destination.ip())
                || is_local_dial_address(primary_destination.ip())
            {
                return route.connect_direct().await;
            }

            let Some(endpoint) = self.selected_endpoint(protocol) else {
                return route.connect_direct().await;
            };
            let target_host = server_name.unwrap_or_else(|| guest_destination.ip().to_string());
            connect_via_proxy(endpoint, &target_host, guest_destination.port()).await
        })
    }
}

//--------------------------------------------------------------------------------------------------
// Functions
//--------------------------------------------------------------------------------------------------

fn first_environment_value(lowercase: Option<String>, uppercase: Option<String>) -> Option<String> {
    lowercase
        .and_then(trimmed_value)
        .or_else(|| uppercase.and_then(trimmed_value))
}

fn trimmed_value(value: String) -> Option<String> {
    let value = value.trim();
    (!value.is_empty()).then(|| value.to_owned())
}

fn environment_value(name: &str) -> Option<String> {
    std::env::var(name).ok()
}

fn parse_endpoint(raw: &str) -> Option<ProxyEndpoint> {
    let raw = raw.trim();
    let (scheme, remainder) = match raw.split_once("://") {
        Some((scheme, remainder)) => (Some(scheme), remainder),
        None => (None, raw),
    };
    if scheme.is_some_and(|scheme| !scheme.eq_ignore_ascii_case("http")) {
        return None;
    }

    let authority = remainder.split(['/', '?', '#']).next()?;
    let (userinfo, host_port) = authority
        .rsplit_once('@')
        .map_or((None, authority), |parts| (Some(parts.0), parts.1));
    let (host, port) = parse_host_port(host_port)?;
    let authorization = userinfo.map(basic_authorization);
    let display = format!("http://{}:{port}", display_host(&host));

    Some(ProxyEndpoint {
        host,
        port,
        authorization,
        display,
    })
}

fn parse_host_port(value: &str) -> Option<(String, u16)> {
    let value = value.trim();
    if value.is_empty() {
        return None;
    }

    if let Some(value) = value.strip_prefix('[') {
        let (host, suffix) = value.split_once(']')?;
        let host = host.parse::<Ipv6Addr>().ok()?.to_string();
        let port = match suffix {
            "" => 80,
            _ => suffix.strip_prefix(':')?.parse().ok()?,
        };
        return (port != 0).then_some((host, port));
    }

    if value.matches(':').count() > 1 {
        let host = value.parse::<Ipv6Addr>().ok()?.to_string();
        return Some((host, 80));
    }

    let (host, port) = match value.rsplit_once(':') {
        Some((host, port)) if !host.is_empty() => (host, port.parse().ok()?),
        Some(_) => return None,
        None => (value, 80),
    };
    if host
        .bytes()
        .any(|byte| byte.is_ascii_control() || byte.is_ascii_whitespace())
        || port == 0
    {
        return None;
    }

    Some((host.to_ascii_lowercase(), port))
}

fn basic_authorization(userinfo: &str) -> Zeroizing<String> {
    let (username, password) = userinfo.split_once(':').unwrap_or((userinfo, ""));
    let username = percent_encoding::percent_decode_str(username).decode_utf8_lossy();
    let password = percent_encoding::percent_decode_str(password).decode_utf8_lossy();
    let credentials = Zeroizing::new(format!("{username}:{password}"));
    let token =
        Zeroizing::new(base64::engine::general_purpose::STANDARD.encode(credentials.as_bytes()));
    let mut authorization = Zeroizing::new(String::from("Basic "));
    authorization.push_str(&token);
    authorization
}

fn strip_no_proxy_port(token: &str) -> &str {
    if let Some(bracketed) = token.strip_prefix('[') {
        if let Some((host, suffix)) = bracketed.split_once(']')
            && (suffix.is_empty() || suffix.strip_prefix(':').is_some())
        {
            return host;
        }
        return token;
    }

    match token.rsplit_once(':') {
        Some((host, port))
            if !host.contains(':') && port.bytes().all(|byte| byte.is_ascii_digit()) =>
        {
            host
        }
        _ => token,
    }
}

fn parse_network(token: &str) -> Option<IpNetwork> {
    let network = token.parse::<IpNetwork>().ok().or_else(|| {
        token.parse::<IpAddr>().ok().and_then(|ip| {
            let prefix = if ip.is_ipv4() { 32 } else { 128 };
            IpNetwork::new(ip, prefix).ok()
        })
    })?;
    normalize_network(network)
}

fn normalize_network(network: IpNetwork) -> Option<IpNetwork> {
    match network {
        IpNetwork::V4(_) => Some(network),
        IpNetwork::V6(network) => network
            .network()
            .to_ipv4_mapped()
            .and_then(|ip| {
                (network.prefix() >= 96)
                    .then(|| IpNetwork::new(IpAddr::V4(ip), network.prefix() - 96).ok())
                    .flatten()
            })
            .or(Some(IpNetwork::V6(network))),
    }
}

fn normalize_ip(ip: IpAddr) -> IpAddr {
    match ip {
        IpAddr::V6(ip) => ip
            .to_ipv4_mapped()
            .map(IpAddr::V4)
            .unwrap_or(IpAddr::V6(ip)),
        IpAddr::V4(_) => ip,
    }
}

fn is_local_dial_address(ip: IpAddr) -> bool {
    let ip = normalize_ip(ip);
    ip.is_loopback() || ip.is_unspecified() || is_link_local(ip)
}

fn is_link_local(ip: IpAddr) -> bool {
    match ip {
        IpAddr::V4(ip) => ip.is_link_local(),
        IpAddr::V6(ip) => (ip.segments()[0] & 0xffc0) == 0xfe80,
    }
}

async fn connect_via_proxy(
    endpoint: &ProxyEndpoint,
    target_host: &str,
    target_port: u16,
) -> io::Result<TcpStream> {
    connect_via_proxy_with_timeout(endpoint, target_host, target_port, CONNECT_TIMEOUT).await
}

async fn connect_via_proxy_with_timeout(
    endpoint: &ProxyEndpoint,
    target_host: &str,
    target_port: u16,
    timeout: Duration,
) -> io::Result<TcpStream> {
    if target_host
        .bytes()
        .any(|byte| byte.is_ascii_control() || byte.is_ascii_whitespace())
    {
        return Err(io::Error::new(
            io::ErrorKind::InvalidInput,
            "illegal character in CONNECT target host",
        ));
    }

    let authority = format_authority(target_host, target_port);
    let exchange = async {
        let mut stream = TcpStream::connect((endpoint.host.as_str(), endpoint.port)).await?;
        let request = build_connect_request(
            &authority,
            endpoint.authorization.as_deref().map(String::as_str),
        );
        stream.write_all(request.as_bytes()).await?;

        let status = read_connect_response(&mut stream).await?;
        if !(200..=299).contains(&status) {
            return Err(io::Error::other(format!(
                "proxy {} refused CONNECT to {authority}: HTTP {status}",
                endpoint.display()
            )));
        }
        Ok(stream)
    };

    match tokio::time::timeout(timeout, exchange).await {
        Ok(result) => result,
        Err(_) => Err(io::Error::new(
            io::ErrorKind::TimedOut,
            format!(
                "proxy {} CONNECT to {authority} timed out",
                endpoint.display()
            ),
        )),
    }
}

fn build_connect_request(authority: &str, authorization: Option<&str>) -> Zeroizing<String> {
    let authorization_length = authorization.map_or(0, |value| {
        "Proxy-Authorization: ".len() + value.len() + "\r\n".len()
    });
    let capacity = "CONNECT ".len()
        + authority.len()
        + " HTTP/1.1\r\nHost: ".len()
        + authority.len()
        + "\r\n".len()
        + authorization_length
        + "Proxy-Connection: keep-alive\r\n\r\n".len();
    let mut request = Zeroizing::new(String::with_capacity(capacity));

    request.push_str("CONNECT ");
    request.push_str(authority);
    request.push_str(" HTTP/1.1\r\nHost: ");
    request.push_str(authority);
    request.push_str("\r\n");
    if let Some(authorization) = authorization {
        request.push_str("Proxy-Authorization: ");
        request.push_str(authorization);
        request.push_str("\r\n");
    }
    request.push_str("Proxy-Connection: keep-alive\r\n\r\n");
    debug_assert_eq!(request.len(), capacity);

    request
}

async fn read_connect_response(stream: &mut TcpStream) -> io::Result<u16> {
    let mut response = Vec::with_capacity(128);
    let mut byte = [0_u8; 1];
    loop {
        let read = stream.read(&mut byte).await?;
        if read == 0 {
            return Err(io::Error::new(
                io::ErrorKind::UnexpectedEof,
                "proxy closed connection during CONNECT handshake",
            ));
        }
        response.push(byte[0]);
        if response.len() > MAX_CONNECT_RESPONSE {
            return Err(io::Error::new(
                io::ErrorKind::InvalidData,
                "proxy CONNECT response header too large",
            ));
        }
        if response.ends_with(b"\r\n\r\n") {
            return parse_status_line(&response);
        }
    }
}

fn parse_status_line(response: &[u8]) -> io::Result<u16> {
    let status_end = response
        .windows(2)
        .position(|bytes| bytes == b"\r\n")
        .ok_or_else(|| io::Error::new(io::ErrorKind::InvalidData, "missing proxy status line"))?;
    let line = &response[..status_end];
    if std::str::from_utf8(line).is_err() || line.iter().any(|byte| matches!(byte, b'\r' | b'\n')) {
        return Err(io::Error::new(
            io::ErrorKind::InvalidData,
            "malformed proxy CONNECT status line",
        ));
    }

    let status = line
        .strip_prefix(b"HTTP/1.0 ")
        .or_else(|| line.strip_prefix(b"HTTP/1.1 "))
        .filter(|status| {
            status.len() >= 4
                && status[..3].iter().all(|byte| byte.is_ascii_digit())
                && status[3] == b' '
                && status[4..]
                    .first()
                    .is_none_or(|byte| !byte.is_ascii_whitespace())
                && status[4..].iter().all(|byte| !byte.is_ascii_control())
        })
        .ok_or_else(|| {
            io::Error::new(
                io::ErrorKind::InvalidData,
                "malformed proxy CONNECT status line",
            )
        })?;

    Ok(u16::from(status[0] - b'0') * 100
        + u16::from(status[1] - b'0') * 10
        + u16::from(status[2] - b'0'))
}

fn format_authority(host: &str, port: u16) -> String {
    if host.parse::<Ipv6Addr>().is_ok() {
        format!("[{host}]:{port}")
    } else {
        format!("{host}:{port}")
    }
}

fn display_host(host: &str) -> String {
    if host.parse::<Ipv6Addr>().is_ok() {
        format!("[{host}]")
    } else {
        host.to_owned()
    }
}

//--------------------------------------------------------------------------------------------------
// Tests
//--------------------------------------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use std::net::SocketAddr;
    use std::time::Duration;

    use base64::Engine as _;
    use tokio::io::{AsyncReadExt as _, AsyncWriteExt as _};
    use tokio::net::TcpListener;
    use tokio::sync::oneshot;

    use super::*;
    use crate::tcp::upstream::UpstreamTcpTarget;

    fn values(
        https_proxy: Option<&str>,
        https_proxy_upper: Option<&str>,
        http_proxy: Option<&str>,
        http_proxy_upper: Option<&str>,
        all_proxy: Option<&str>,
        no_proxy: Option<&str>,
    ) -> EnvironmentValues {
        EnvironmentValues {
            https_proxy: https_proxy.map(ToOwned::to_owned),
            https_proxy_upper: https_proxy_upper.map(ToOwned::to_owned),
            http_proxy: http_proxy.map(ToOwned::to_owned),
            http_proxy_upper: http_proxy_upper.map(ToOwned::to_owned),
            all_proxy: all_proxy.map(ToOwned::to_owned),
            no_proxy: no_proxy.map(ToOwned::to_owned),
            ..EnvironmentValues::default()
        }
    }

    #[test]
    fn environment_selection_prefers_lowercase_and_uses_cross_protocol_fallback() {
        let connector = HostHttpProxyConnector::from_values(values(
            None,
            None,
            Some(" http://lower:443 "),
            Some("http://upper:9999"),
            None,
            None,
        ))
        .unwrap();

        assert_eq!(
            connector.http.as_ref().unwrap().display(),
            "http://lower:443"
        );
        assert_eq!(
            connector.https.as_ref().unwrap().display(),
            "http://lower:443"
        );
        assert_eq!(
            connector
                .selected_endpoint(OutboundProtocol::Tcp)
                .unwrap()
                .display(),
            "http://lower:443"
        );
        assert_eq!(
            connector
                .selected_endpoint(OutboundProtocol::Tls)
                .unwrap()
                .display(),
            "http://lower:443"
        );
    }

    #[test]
    fn environment_selection_uses_all_proxy_after_unsupported_specific_value() {
        let connector = HostHttpProxyConnector::from_values(values(
            Some("socks5://ignored:1080"),
            None,
            Some(""),
            None,
            Some("http://all-proxy:3128"),
            None,
        ))
        .unwrap();

        assert_eq!(
            connector.https.as_ref().unwrap().display(),
            "http://all-proxy:3128"
        );
        assert_eq!(
            connector.http.as_ref().unwrap().display(),
            "http://all-proxy:3128"
        );
    }

    #[test]
    fn unsupported_or_malformed_only_proxy_settings_leave_direct_routing_installed() {
        for proxy in [
            "socks5://proxy.example:1080",
            "http://:3128",
            "http://proxy:0",
        ] {
            let connector = HostHttpProxyConnector::from_values(values(
                Some(proxy),
                None,
                None,
                None,
                None,
                None,
            ));
            assert!(connector.is_none(), "accepted unusable proxy {proxy:?}");
        }
    }

    #[test]
    fn endpoint_parsing_normalizes_display_and_keeps_authorization_private() {
        let endpoint = parse_endpoint("http://a%20b:p%40ss@[2001:DB8::1]:3128/pac?x=1").unwrap();
        let token = base64::engine::general_purpose::STANDARD.encode("a b:p@ss");

        assert_eq!(endpoint.host, "2001:db8::1");
        assert_eq!(endpoint.display(), "http://[2001:db8::1]:3128");
        assert_eq!(
            endpoint.authorization.as_ref().map(|value| value.as_str()),
            Some(format!("Basic {token}").as_str())
        );
        assert!(!endpoint.display().contains("p@ss"));
        assert!(!endpoint.display().contains(&token));
        assert_eq!(
            parse_endpoint("fe80::1").unwrap().display(),
            "http://[fe80::1]:80"
        );
        assert!(
            parse_endpoint("http://proxy")
                .unwrap()
                .authorization
                .is_none()
        );
        assert_eq!(
            parse_endpoint("http://@proxy")
                .unwrap()
                .authorization
                .as_deref()
                .map(String::as_str),
            Some("Basic Og==")
        );
    }

    #[test]
    fn no_proxy_matches_names_networks_and_ipv4_mapped_addresses() {
        let no_proxy = NoProxy::parse(".example.com:443, 10.0.0.0/8 [::ffff:192.0.2.1]:80");

        assert!(no_proxy.matches(Some("API.Example.Com."), "203.0.113.8".parse().unwrap()));
        assert!(!no_proxy.matches(Some("notexample.com"), "203.0.113.8".parse().unwrap()));
        assert!(no_proxy.matches(None, "10.4.5.6".parse().unwrap()));
        assert!(no_proxy.matches(None, "::ffff:192.0.2.1".parse().unwrap()));
    }

    #[test]
    fn no_proxy_accepts_every_documented_rule_shape() {
        let cases = [
            ("*", Some("anything.test"), "203.0.113.1", true),
            ("example.test", Some("example.test"), "203.0.113.1", true),
            (
                "example.test",
                Some("api.example.test"),
                "203.0.113.1",
                true,
            ),
            (
                "example.test",
                Some("notexample.test"),
                "203.0.113.1",
                false,
            ),
            (
                ".Example.test.:443",
                Some("API.example.TEST."),
                "203.0.113.1",
                true,
            ),
            ("192.0.2.7", None, "192.0.2.7", true),
            ("192.0.2.7", None, "192.0.2.8", false),
            ("2001:db8::7", None, "2001:db8::7", true),
            ("2001:db8::7", None, "2001:db8::8", false),
            ("198.51.100.0/24", None, "198.51.100.8", true),
            ("198.51.100.0/24", None, "198.51.101.8", false),
            ("2001:db8:abcd::/48", None, "2001:db8:abcd::8", true),
            ("2001:db8:abcd::/48", None, "2001:db8:abce::8", false),
            ("::ffff:192.0.2.9", None, "192.0.2.9", true),
        ];

        for (rules, server_name, guest_ip, expected) in cases {
            assert_eq!(
                NoProxy::parse(rules).matches(server_name, guest_ip.parse().unwrap()),
                expected,
                "rules {rules:?}, server name {server_name:?}, guest IP {guest_ip}"
            );
        }

        let separators = NoProxy::parse("one.test,two.test\tthree.test\nfour.test");
        for name in ["one.test", "two.test", "three.test", "four.test"] {
            assert!(separators.matches(Some(name), "203.0.113.1".parse().unwrap()));
        }
    }

    #[test]
    fn connect_request_reserves_before_copying_authorization() {
        let authorization = format!("Basic {}", "a".repeat(32 * 1024));
        let request = build_connect_request("api.example.test:443", Some(&authorization));

        assert_eq!(request.len(), request.capacity());
        assert!(request.contains(&authorization));
    }

    #[test]
    fn status_line_requires_exact_http_1_x_framing_and_three_digit_status() {
        assert_eq!(
            parse_status_line(b"HTTP/1.1 200 Connected\r\n\r\n").unwrap(),
            200
        );
        assert_eq!(parse_status_line(b"HTTP/1.0 299 OK\r\n\r\n").unwrap(), 299);
        assert_eq!(parse_status_line(b"HTTP/1.1 204 \r\n\r\n").unwrap(), 204);

        for response in [
            b"HTTP/2 200 Connected\r\n\r\n".as_slice(),
            b"HTTP/1.1 20 Connected\r\n\r\n",
            b"HTTP/1.1 2000 Connected\r\n\r\n",
            b"HTTP/1.1 204\r\n\r\n",
            b"HTTP/1.1\t200 Connected\r\n\r\n",
            b"HTTP/1.1  200 Connected\r\n\r\n",
            b"HTTP/1.1 200\tConnected\r\n\r\n",
            b"HTTP/1.1 200  Connected\r\n\r\n",
            b"HTTP/1.1 200 O\0K\r\n\r\n",
            b"HTTP/1.1 200 O\tK\r\n\r\n",
            b"HTTP/1.1 200\nConnected\r\n\r\n",
            b"HTTP/1.1 200 Connected\n\r\n\r\n",
            b"HTTP/1.1 200 Connected\rnoise\r\n\r\n",
            b"HTTP/1.1 200 Connected\nnoise\r\n\r\n",
        ] {
            assert!(
                parse_status_line(response).is_err(),
                "accepted {response:?}"
            );
        }
    }

    #[tokio::test]
    async fn connector_sends_sni_authority_and_preserves_bytes_after_connect_headers() {
        let proxy = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let proxy_address = proxy.local_addr().unwrap();
        let (request_tx, request_rx) = oneshot::channel();
        let proxy_task = tokio::spawn(async move {
            let (mut stream, _) = proxy.accept().await.unwrap();
            let request = read_headers(&mut stream).await;
            request_tx.send(request).unwrap();
            stream
                .write_all(b"HTTP/1.1 201 Created\r\n\r\nresponse-before-client-write")
                .await
                .unwrap();
            let mut payload = [0_u8; 4];
            stream.read_exact(&mut payload).await.unwrap();
            assert_eq!(&payload, b"ping");
        });
        let connector = HostHttpProxyConnector::from_values(values(
            Some(&format!("http://user:pass@{proxy_address}")),
            None,
            None,
            None,
            None,
            None,
        ))
        .unwrap();
        let guest_destination: SocketAddr = "203.0.113.9:443".parse().unwrap();
        let route = AuthorizedTcpRoute::new(
            guest_destination,
            UpstreamTcpTarget::direct("198.51.100.2:443".parse().unwrap()),
            Some("api.example.test"),
            OutboundProtocol::Tls,
        );

        let mut tunnel = tokio::time::timeout(Duration::from_secs(1), connector.connect(route))
            .await
            .expect("CONNECT setup timed out")
            .unwrap();
        let request = tokio::time::timeout(Duration::from_secs(1), request_rx)
            .await
            .expect("proxy did not record CONNECT")
            .unwrap();
        let authorization = base64::engine::general_purpose::STANDARD.encode("user:pass");
        assert!(request.starts_with(
            "CONNECT api.example.test:443 HTTP/1.1\r\nHost: api.example.test:443\r\n"
        ));
        assert_eq!(
            request
                .matches(&format!("Proxy-Authorization: Basic {authorization}\r\n"))
                .count(),
            1
        );

        let mut response = vec![0_u8; "response-before-client-write".len()];
        tunnel.read_exact(&mut response).await.unwrap();
        assert_eq!(&response, b"response-before-client-write");
        tunnel.write_all(b"ping").await.unwrap();
        tokio::time::timeout(Duration::from_secs(1), proxy_task)
            .await
            .expect("proxy fixture did not finish")
            .unwrap();
    }

    #[tokio::test]
    async fn empty_proxy_userinfo_sends_basic_empty_credentials() {
        let proxy = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let connector =
            HostHttpProxyConnector::from_url(&format!("http://@{}", proxy.local_addr().unwrap()))
                .unwrap();
        let proxy_task = tokio::spawn(async move {
            let (mut stream, _) = proxy.accept().await.unwrap();
            let request = read_headers(&mut stream).await;
            assert_eq!(
                request
                    .matches("Proxy-Authorization: Basic Og==\r\n")
                    .count(),
                1
            );
            stream.write_all(b"HTTP/1.1 200 OK\r\n\r\n").await.unwrap();
        });
        let route = AuthorizedTcpRoute::new(
            "203.0.113.9:443".parse().unwrap(),
            UpstreamTcpTarget::direct("198.51.100.2:443".parse().unwrap()),
            Some("api.example.test"),
            OutboundProtocol::Tls,
        );

        let _tunnel = tokio::time::timeout(Duration::from_secs(1), connector.connect(route))
            .await
            .expect("CONNECT setup timed out")
            .unwrap();
        tokio::time::timeout(Duration::from_secs(1), proxy_task)
            .await
            .expect("proxy fixture did not finish")
            .unwrap();
    }

    #[tokio::test]
    async fn connector_sends_numeric_authority_for_tcp_route() {
        let proxy = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let proxy_address = proxy.local_addr().unwrap();
        let (request_tx, request_rx) = oneshot::channel();
        let proxy_task = tokio::spawn(async move {
            let (mut stream, _) = proxy.accept().await.unwrap();
            request_tx.send(read_headers(&mut stream).await).unwrap();
            stream
                .write_all(b"HTTP/1.1 200 Connected\r\n\r\n")
                .await
                .unwrap();
        });
        let connector = HostHttpProxyConnector::from_values(values(
            None,
            None,
            Some(&format!("http://{proxy_address}")),
            None,
            None,
            None,
        ))
        .unwrap();
        let guest_destination: SocketAddr = "203.0.113.9:80".parse().unwrap();
        let route = AuthorizedTcpRoute::new(
            guest_destination,
            UpstreamTcpTarget::direct("198.51.100.2:80".parse().unwrap()),
            None,
            OutboundProtocol::Tcp,
        );

        let _tunnel = tokio::time::timeout(Duration::from_secs(1), connector.connect(route))
            .await
            .expect("CONNECT setup timed out")
            .unwrap();
        assert!(
            tokio::time::timeout(Duration::from_secs(1), request_rx)
                .await
                .expect("proxy did not record CONNECT")
                .unwrap()
                .starts_with("CONNECT 203.0.113.9:80 HTTP/1.1\r\nHost: 203.0.113.9:80\r\n")
        );
        tokio::time::timeout(Duration::from_secs(1), proxy_task)
            .await
            .expect("proxy fixture did not finish")
            .unwrap();
    }

    #[tokio::test]
    async fn connector_rejects_injected_authority_before_dialing_proxy() {
        let proxy = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let endpoint = parse_endpoint(&format!("http://{}", proxy.local_addr().unwrap())).unwrap();

        let error = connect_via_proxy_with_timeout(
            &endpoint,
            "example.test\r\nProxy-Authorization: Basic injected",
            443,
            Duration::from_millis(50),
        )
        .await
        .unwrap_err();
        assert_eq!(error.kind(), io::ErrorKind::InvalidInput);
        assert!(
            tokio::time::timeout(Duration::from_millis(50), proxy.accept())
                .await
                .is_err()
        );
    }

    #[tokio::test]
    async fn connector_fails_closed_for_proxy_rejection_without_direct_fallback() {
        let proxy = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let direct = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let connector =
            HostHttpProxyConnector::from_url(&format!("http://{}", proxy.local_addr().unwrap()))
                .unwrap();
        let proxy_task = tokio::spawn(async move {
            let (mut stream, _) = proxy.accept().await.unwrap();
            let _ = read_headers(&mut stream).await;
            stream
                .write_all(b"HTTP/1.1 407 Proxy Authentication Required\r\n\r\n")
                .await
                .unwrap();
        });
        let route = AuthorizedTcpRoute::new(
            "203.0.113.9:443".parse().unwrap(),
            UpstreamTcpTarget::with_fallback(
                "198.51.100.2:443".parse().unwrap(),
                direct.local_addr().unwrap(),
            ),
            Some("api.example.test"),
            OutboundProtocol::Tls,
        );

        assert!(connector.connect(route).await.is_err());
        tokio::time::timeout(Duration::from_secs(1), proxy_task)
            .await
            .expect("proxy fixture did not finish")
            .unwrap();
        assert!(
            tokio::time::timeout(Duration::from_millis(100), direct.accept())
                .await
                .is_err(),
            "selected proxy rejection fell back to the direct origin"
        );
    }

    #[tokio::test]
    async fn connect_handshake_rejects_malformed_oversized_eof_and_stalled_responses() {
        let failures: Vec<(&str, Vec<u8>)> = vec![
            ("non-2xx", b"HTTP/1.1 503 Unavailable\r\n\r\n".to_vec()),
            ("malformed", b"HTTP/1.1\t200 OK\r\n\r\n".to_vec()),
            ("missing reason separator", b"HTTP/1.1 200\r\n\r\n".to_vec()),
            ("reason control", b"HTTP/1.1 200 O\0K\r\n\r\n".to_vec()),
            (
                "early newline",
                b"HTTP/1.1 200 OK\nignored\r\n\r\n".to_vec(),
            ),
            ("non-utf8", b"HTTP/1.1 200 \xff\r\n\r\n".to_vec()),
            ("oversized", vec![b'x'; MAX_CONNECT_RESPONSE + 1]),
            ("eof", Vec::new()),
        ];

        for (name, response) in failures {
            let proxy = TcpListener::bind("127.0.0.1:0").await.unwrap();
            let endpoint =
                parse_endpoint(&format!("http://{}", proxy.local_addr().unwrap())).unwrap();
            let fixture = tokio::spawn(async move {
                let (mut stream, _) = proxy.accept().await.unwrap();
                let _ = read_headers(&mut stream).await;
                if !response.is_empty() {
                    stream.write_all(&response).await.unwrap();
                }
            });

            assert!(
                connect_via_proxy_with_timeout(
                    &endpoint,
                    "example.test",
                    443,
                    Duration::from_secs(1),
                )
                .await
                .is_err(),
                "accepted {name} proxy response"
            );
            tokio::time::timeout(Duration::from_secs(1), fixture)
                .await
                .expect("{name} fixture did not finish")
                .unwrap();
        }

        let proxy = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let endpoint = parse_endpoint(&format!("http://{}", proxy.local_addr().unwrap())).unwrap();
        let (accepted_tx, accepted_rx) = oneshot::channel();
        let fixture = tokio::spawn(async move {
            let (mut stream, _) = proxy.accept().await.unwrap();
            let _ = read_headers(&mut stream).await;
            let _ = accepted_tx.send(());
            let mut byte = [0_u8; 1];
            let _ = stream.read(&mut byte).await;
        });
        let error = connect_via_proxy_with_timeout(
            &endpoint,
            "example.test",
            443,
            Duration::from_millis(40),
        )
        .await
        .unwrap_err();
        assert_eq!(error.kind(), io::ErrorKind::TimedOut);
        tokio::time::timeout(Duration::from_secs(1), accepted_rx)
            .await
            .expect("stalled proxy was not contacted")
            .unwrap();
        tokio::time::timeout(Duration::from_secs(1), fixture)
            .await
            .expect("stalled proxy fixture did not observe cleanup")
            .unwrap();
    }

    #[tokio::test]
    async fn aborting_connect_handshake_closes_proxy_socket() {
        let proxy = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let endpoint = parse_endpoint(&format!("http://{}", proxy.local_addr().unwrap())).unwrap();
        let (accepted_tx, accepted_rx) = oneshot::channel();
        let fixture = tokio::spawn(async move {
            let (mut stream, _) = proxy.accept().await.unwrap();
            let _ = read_headers(&mut stream).await;
            let _ = accepted_tx.send(());
            let mut byte = [0_u8; 1];
            assert_eq!(stream.read(&mut byte).await.unwrap(), 0);
        });
        let handshake = tokio::spawn(async move {
            connect_via_proxy_with_timeout(&endpoint, "example.test", 443, Duration::from_secs(5))
                .await
        });
        tokio::time::timeout(Duration::from_secs(1), accepted_rx)
            .await
            .expect("proxy did not receive CONNECT")
            .unwrap();
        handshake.abort();
        let _ = handshake.await;
        tokio::time::timeout(Duration::from_secs(1), fixture)
            .await
            .expect("aborted handshake left proxy socket open")
            .unwrap();
    }

    #[tokio::test]
    async fn no_proxy_and_local_targets_use_direct_route_without_proxy_contact() {
        let proxy = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let proxy_url = format!("http://{}", proxy.local_addr().unwrap());

        let non_local_primary = non_local_test_address().await;

        let name_direct = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let name_closed_port = TcpListener::bind(SocketAddr::new(non_local_primary, 0))
            .await
            .unwrap()
            .local_addr()
            .unwrap()
            .port();
        let connector = HostHttpProxyConnector::from_values(values(
            None,
            None,
            Some(&proxy_url),
            None,
            None,
            Some(".example.test"),
        ))
        .unwrap();
        let name_route = AuthorizedTcpRoute::new(
            "203.0.113.9:443".parse().unwrap(),
            UpstreamTcpTarget::with_fallback(
                SocketAddr::new(non_local_primary, name_closed_port),
                name_direct.local_addr().unwrap(),
            ),
            Some("api.example.test"),
            OutboundProtocol::Tls,
        );
        let name_tunnel =
            tokio::time::timeout(Duration::from_secs(1), connector.connect(name_route))
                .await
                .expect("hostname NO_PROXY direct setup timed out")
                .unwrap();
        assert_eq!(
            name_tunnel.peer_addr().unwrap(),
            name_direct.local_addr().unwrap()
        );
        drop(name_tunnel);
        tokio::time::timeout(Duration::from_secs(1), name_direct.accept())
            .await
            .expect("hostname NO_PROXY route did not use the direct target")
            .unwrap();

        let cidr_direct = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let cidr_closed_port = TcpListener::bind(SocketAddr::new(non_local_primary, 0))
            .await
            .unwrap()
            .local_addr()
            .unwrap()
            .port();
        let connector = HostHttpProxyConnector::from_values(values(
            None,
            None,
            Some(&proxy_url),
            None,
            None,
            Some("203.0.113.0/24"),
        ))
        .unwrap();
        let cidr_route = AuthorizedTcpRoute::new(
            "203.0.113.10:80".parse().unwrap(),
            UpstreamTcpTarget::with_fallback(
                SocketAddr::new(non_local_primary, cidr_closed_port),
                cidr_direct.local_addr().unwrap(),
            ),
            None,
            OutboundProtocol::Tcp,
        );
        let cidr_tunnel =
            tokio::time::timeout(Duration::from_secs(1), connector.connect(cidr_route))
                .await
                .expect("CIDR NO_PROXY direct setup timed out")
                .unwrap();
        assert_eq!(
            cidr_tunnel.peer_addr().unwrap(),
            cidr_direct.local_addr().unwrap()
        );
        drop(cidr_tunnel);
        tokio::time::timeout(Duration::from_secs(1), cidr_direct.accept())
            .await
            .expect("CIDR NO_PROXY route did not use the direct target")
            .unwrap();

        let fallback_direct = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let closed_port = TcpListener::bind("127.0.0.1:0")
            .await
            .unwrap()
            .local_addr()
            .unwrap()
            .port();
        let connector = HostHttpProxyConnector::from_url(&proxy_url).unwrap();
        let local_route = AuthorizedTcpRoute::new(
            "203.0.113.11:80".parse().unwrap(),
            UpstreamTcpTarget::with_fallback(
                format!("[::ffff:127.0.0.1]:{closed_port}").parse().unwrap(),
                fallback_direct.local_addr().unwrap(),
            ),
            None,
            OutboundProtocol::Tcp,
        );
        let local_tunnel = connector.connect(local_route).await.unwrap();
        assert_eq!(
            local_tunnel.peer_addr().unwrap(),
            fallback_direct.local_addr().unwrap()
        );
        drop(local_tunnel);
        tokio::time::timeout(Duration::from_secs(1), fallback_direct.accept())
            .await
            .expect("host-local direct route did not retain fallback behavior")
            .unwrap();

        assert!(
            tokio::time::timeout(Duration::from_millis(100), proxy.accept())
                .await
                .is_err(),
            "direct-route exclusion contacted the configured proxy"
        );
    }

    #[tokio::test]
    async fn proxy_credentials_are_redacted_and_never_enter_tunnel_payload() {
        let password = "diagnostic-secret";
        let token = base64::engine::general_purpose::STANDARD.encode(format!("user:{password}"));
        let rejecting_proxy = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let rejecting_endpoint = parse_endpoint(&format!(
            "http://user:{password}@{}",
            rejecting_proxy.local_addr().unwrap()
        ))
        .unwrap();
        let rejection = tokio::spawn(async move {
            let (mut stream, _) = rejecting_proxy.accept().await.unwrap();
            let _ = read_headers(&mut stream).await;
            stream
                .write_all(b"HTTP/1.1 407 Proxy Authentication Required\r\n\r\n")
                .await
                .unwrap();
        });
        let error = connect_via_proxy_with_timeout(
            &rejecting_endpoint,
            "api.example.test",
            443,
            Duration::from_secs(1),
        )
        .await
        .unwrap_err()
        .to_string();
        assert!(!error.contains(password));
        assert!(!error.contains(&token));
        tokio::time::timeout(Duration::from_secs(1), rejection)
            .await
            .expect("rejecting proxy fixture did not finish")
            .unwrap();

        let origin = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let origin_address = origin.local_addr().unwrap();
        let origin_task = tokio::spawn(async move {
            let (mut stream, _) = origin.accept().await.unwrap();
            let mut payload = Vec::new();
            stream.read_to_end(&mut payload).await.unwrap();
            payload
        });
        let proxy = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let connector = HostHttpProxyConnector::from_url(&format!(
            "http://user:{password}@{}",
            proxy.local_addr().unwrap()
        ))
        .unwrap();
        let proxy_task = tokio::spawn(async move {
            let (mut client, _) = proxy.accept().await.unwrap();
            let headers = read_headers(&mut client).await;
            assert_eq!(
                headers
                    .matches(&format!("Proxy-Authorization: Basic {token}\r\n"))
                    .count(),
                1
            );
            client.write_all(b"HTTP/1.1 200 OK\r\n\r\n").await.unwrap();
            let mut upstream = TcpStream::connect(origin_address).await.unwrap();
            tokio::io::copy_bidirectional(&mut client, &mut upstream)
                .await
                .unwrap();
        });
        let route = AuthorizedTcpRoute::new(
            "203.0.113.9:443".parse().unwrap(),
            UpstreamTcpTarget::direct("198.51.100.2:443".parse().unwrap()),
            Some("api.example.test"),
            OutboundProtocol::Tls,
        );
        let mut tunnel = connector.connect(route).await.unwrap();
        tunnel.write_all(b"origin payload").await.unwrap();
        tunnel.shutdown().await.unwrap();
        drop(tunnel);

        assert_eq!(
            tokio::time::timeout(Duration::from_secs(1), origin_task)
                .await
                .expect("origin fixture did not finish")
                .unwrap(),
            b"origin payload"
        );
        tokio::time::timeout(Duration::from_secs(1), proxy_task)
            .await
            .expect("tunnel proxy fixture did not finish")
            .unwrap();
    }

    #[tokio::test]
    async fn concurrent_tunnel_failure_does_not_poison_other_authorities() {
        const SUCCESSFUL_TUNNELS: usize = 4;
        const TUNNELS: usize = SUCCESSFUL_TUNNELS + 1;

        let proxy = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let proxy_address = proxy.local_addr().unwrap();
        let proxy_task = tokio::spawn(async move {
            let mut tunnels = Vec::new();
            for _ in 0..TUNNELS {
                let (mut stream, _) = proxy.accept().await.unwrap();
                tunnels.push(tokio::spawn(async move {
                    let headers = read_headers(&mut stream).await;
                    let authority = headers
                        .split_whitespace()
                        .nth(1)
                        .expect("CONNECT authority")
                        .to_owned();
                    if authority == "reject.example.test:443" {
                        stream
                            .write_all(b"HTTP/1.1 407 Proxy Authentication Required\r\n\r\n")
                            .await
                            .unwrap();
                        return;
                    }

                    let authority_name = authority.strip_suffix(":443").unwrap_or(&authority);
                    stream.write_all(b"HTTP/1.1 200 OK\r\n\r\n").await.unwrap();
                    let mut echoed = Vec::new();
                    let mut buffer = [0_u8; 64];
                    loop {
                        match stream.read(&mut buffer).await.unwrap() {
                            0 => {
                                let expected = (0..3)
                                    .map(|round| format!("payload-{authority_name}:{round}"))
                                    .collect::<String>();
                                assert_eq!(echoed, expected.as_bytes());
                                stream
                                    .write_all(format!("after-fin-{authority_name}").as_bytes())
                                    .await
                                    .unwrap();
                                stream.shutdown().await.unwrap();
                                return;
                            }
                            read => {
                                echoed.extend_from_slice(&buffer[..read]);
                                stream.write_all(&buffer[..read]).await.unwrap();
                            }
                        }
                    }
                }));
            }
            for tunnel in tunnels {
                tunnel.await.unwrap();
            }
        });
        let connector =
            HostHttpProxyConnector::from_url(&format!("http://{proxy_address}")).unwrap();
        let barrier = std::sync::Arc::new(tokio::sync::Barrier::new(TUNNELS));
        let mut clients = Vec::new();
        for index in 0..SUCCESSFUL_TUNNELS {
            let connector = connector.clone();
            let barrier = barrier.clone();
            clients.push(tokio::spawn(async move {
                let authority = format!("tunnel-{index}.example.test");
                barrier.wait().await;
                let route = AuthorizedTcpRoute::new(
                    format!("203.0.113.{}:443", index + 1).parse().unwrap(),
                    UpstreamTcpTarget::direct("198.51.100.1:443".parse().unwrap()),
                    Some(&authority),
                    OutboundProtocol::Tls,
                );
                let mut stream = connector.connect(route).await.unwrap();
                for round in 0..3 {
                    let payload = format!("payload-{authority}:{}", round);
                    stream.write_all(payload.as_bytes()).await.unwrap();
                    let mut echoed = vec![0; payload.len()];
                    stream.read_exact(&mut echoed).await.unwrap();
                    assert_eq!(echoed, payload.as_bytes());
                }
                stream.shutdown().await.unwrap();
                let after_fin = format!("after-fin-{authority}");
                let mut response = vec![0; after_fin.len()];
                stream.read_exact(&mut response).await.unwrap();
                assert_eq!(response, after_fin.as_bytes());
            }));
        }
        let rejected_connector = connector.clone();
        let rejected_barrier = barrier.clone();
        let rejected = tokio::spawn(async move {
            rejected_barrier.wait().await;
            let route = AuthorizedTcpRoute::new(
                "203.0.113.99:443".parse().unwrap(),
                UpstreamTcpTarget::direct("198.51.100.1:443".parse().unwrap()),
                Some("reject.example.test"),
                OutboundProtocol::Tls,
            );
            assert!(rejected_connector.connect(route).await.is_err());
        });

        tokio::time::timeout(Duration::from_secs(2), rejected)
            .await
            .expect("rejected tunnel hung")
            .unwrap();
        for client in clients {
            tokio::time::timeout(Duration::from_secs(2), client)
                .await
                .expect("concurrent tunnel hung")
                .unwrap();
        }
        tokio::time::timeout(Duration::from_secs(2), proxy_task)
            .await
            .expect("proxy tunnel cleanup hung")
            .unwrap();
    }

    async fn non_local_test_address() -> IpAddr {
        let socket = tokio::net::UdpSocket::bind("0.0.0.0:0").await.unwrap();
        socket.connect("192.0.2.1:80").await.unwrap();
        let address = socket.local_addr().unwrap().ip();
        assert!(
            !is_local_dial_address(address),
            "test route selected a host-local primary {address}"
        );
        address
    }

    async fn read_headers(stream: &mut TcpStream) -> String {
        tokio::time::timeout(Duration::from_secs(1), async {
            let mut headers = Vec::new();
            let mut byte = [0_u8; 1];
            loop {
                stream.read_exact(&mut byte).await.unwrap();
                headers.push(byte[0]);
                if headers.ends_with(b"\r\n\r\n") {
                    return String::from_utf8(headers).unwrap();
                }
            }
        })
        .await
        .expect("proxy request headers timed out")
    }
}
