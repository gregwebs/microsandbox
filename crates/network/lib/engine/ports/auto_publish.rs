//! Auto-publish: discover guest TCP LISTEN sockets and mirror each
//! one onto a host listener via [`PortPublisher`](crate::ports::publisher::PortPublisher).
//!
//! Stateless helpers (parser + diff) live here so the network crate
//! can keep its `/proc/net/tcp` knowledge co-located with the rest
//! of the smoltcp stack. The actual poll task — which reads
//! `/proc/net/tcp{,6}` over the agent.sock channel — is wired up by
//! the runtime crate in `runtime/lib/vm.rs`, because that's where
//! the agent client lives.
//!
//! Filter policy: both **wildcard** (`0.0.0.0` / `[::]`) and
//! **loopback** (`127.0.0.1` / `[::1]`) LISTEN binds are
//! auto-forwarded. Loopback works because agentd lights up an
//! in-guest forwarder (`eth0_ip:port → 127.0.0.1:port`) for each
//! loopback bind we observe — the smoltcp PortPublisher's
//! existing dial-to-guest-VLAN-IP path then lands on the agentd
//! listener and gets bridged into loopback inside the guest. The
//! runtime auto-publish loop in `runtime/lib/auto_publish.rs`
//! sends `LoopbackForwardReq` for each detected loopback port
//! before adding the host listener.

use std::collections::BTreeSet;
use std::net::{IpAddr, Ipv4Addr, Ipv6Addr};

//--------------------------------------------------------------------------------------------------
// Types
//--------------------------------------------------------------------------------------------------

/// One listening socket discovered via `/proc/net/tcp{,6}`.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub struct ListenEntry {
    /// Bound interface address.
    pub addr: IpAddr,
    /// Bound TCP port.
    pub port: u16,
}

//--------------------------------------------------------------------------------------------------
// Functions
//--------------------------------------------------------------------------------------------------

/// Parse the body of `/proc/net/tcp` (skipping the header row).
///
/// Returns only entries in TCP_LISTEN state (`st = 0A`). Malformed
/// rows are silently skipped — `/proc/net/tcp` writes are atomic
/// per-row, but the file as a whole can race with state transitions,
/// so a strict parse would yield false negatives.
pub fn parse_listen_v4(body: &str) -> BTreeSet<ListenEntry> {
    let mut out = BTreeSet::new();
    for line in body.lines().skip(1) {
        if let Some(entry) = parse_v4_line(line) {
            out.insert(entry);
        }
    }
    out
}

/// Like [`parse_listen_v4`] but for `/proc/net/tcp6`.
pub fn parse_listen_v6(body: &str) -> BTreeSet<ListenEntry> {
    let mut out = BTreeSet::new();
    for line in body.lines().skip(1) {
        if let Some(entry) = parse_v6_line(line) {
            out.insert(entry);
        }
    }
    out
}

/// Subset of LISTEN entries that auto-publish should mirror.
/// Wildcard *and* loopback both qualify — see the module-level
/// docs for the agentd-side loopback forwarder that makes the
/// loopback case work over smoltcp.
pub fn should_forward(entry: ListenEntry) -> bool {
    match entry.addr {
        IpAddr::V4(a) => a.is_unspecified() || a.is_loopback(),
        IpAddr::V6(a) => a.is_unspecified() || a.is_loopback(),
    }
}

/// True when this entry's address is a loopback bind that needs
/// an in-guest agentd forwarder before smoltcp can reach it.
pub fn needs_loopback_forwarder(entry: ListenEntry) -> bool {
    match entry.addr {
        IpAddr::V4(a) => a.is_loopback(),
        IpAddr::V6(a) => a.is_loopback(),
    }
}

//--------------------------------------------------------------------------------------------------
// Functions: Helpers
//--------------------------------------------------------------------------------------------------

fn parse_v4_line(line: &str) -> Option<ListenEntry> {
    let fields: Vec<&str> = line.split_whitespace().collect();
    // sl, local, remote, st, ...
    if fields.len() < 4 || fields[3] != "0A" {
        return None;
    }
    let (ip_hex, port_hex) = fields[1].split_once(':')?;
    if ip_hex.len() != 8 {
        return None;
    }
    let raw = u32::from_str_radix(ip_hex, 16).ok()?;
    // The kernel writes the IPv4 address as a single hex u32 in
    // native (little-endian on every supported arch) byte order:
    //   `0100007F` → bytes [01, 00, 00, 7F] in memory → `127.0.0.1`
    //   read with the most-significant byte last.
    let bytes = raw.to_be_bytes();
    let addr = IpAddr::V4(Ipv4Addr::new(bytes[3], bytes[2], bytes[1], bytes[0]));
    let port = u16::from_str_radix(port_hex, 16).ok()?;
    Some(ListenEntry { addr, port })
}

fn parse_v6_line(line: &str) -> Option<ListenEntry> {
    let fields: Vec<&str> = line.split_whitespace().collect();
    if fields.len() < 4 || fields[3] != "0A" {
        return None;
    }
    let (ip_hex, port_hex) = fields[1].split_once(':')?;
    if ip_hex.len() != 32 {
        return None;
    }
    // IPv6 is four little-endian u32 words concatenated; convert
    // each to its big-endian (network-order) byte sequence.
    let mut bytes = [0u8; 16];
    for i in 0..4 {
        let word = u32::from_str_radix(&ip_hex[i * 8..(i + 1) * 8], 16).ok()?;
        let be = word.to_be_bytes();
        bytes[i * 4] = be[3];
        bytes[i * 4 + 1] = be[2];
        bytes[i * 4 + 2] = be[1];
        bytes[i * 4 + 3] = be[0];
    }
    let addr = IpAddr::V6(Ipv6Addr::from(bytes));
    let port = u16::from_str_radix(port_hex, 16).ok()?;
    Some(ListenEntry { addr, port })
}

//--------------------------------------------------------------------------------------------------
// Tests
//--------------------------------------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use super::*;
    use std::net::{Ipv4Addr, Ipv6Addr};

    const SAMPLE_TCP4: &str = "  sl  local_address rem_address   st\n\
         0: 0100007F:2382 00000000:0000 0A 00000000:00000000 00:00000000 00000000     0        0 1089 1\n\
         1: 00000000:1F90 00000000:0000 0A 00000000:00000000 00:00000000 00000000     0        0 42 1\n\
         2: 0100007F:0050 0100007F:8000 01 00000000:00000000 00:00000000 00000000     0        0 99 1\n";

    #[test]
    fn parses_v4_loopback_and_wildcard() {
        let s = parse_listen_v4(SAMPLE_TCP4);
        assert!(s.contains(&ListenEntry {
            addr: IpAddr::V4(Ipv4Addr::LOCALHOST),
            port: 0x2382,
        }));
        assert!(s.contains(&ListenEntry {
            addr: IpAddr::V4(Ipv4Addr::UNSPECIFIED),
            port: 0x1F90,
        }));
    }

    #[test]
    fn skips_non_listen_states() {
        let s = parse_listen_v4(SAMPLE_TCP4);
        // st=01 (ESTABLISHED) for row 2 must not appear.
        assert!(!s.contains(&ListenEntry {
            addr: IpAddr::V4(Ipv4Addr::LOCALHOST),
            port: 0x0050,
        }));
    }

    #[test]
    fn parses_v6_unspecified() {
        let sample = "  sl  local_address                         remote_address                        st\n\
             0: 00000000000000000000000000000000:1F90 00000000000000000000000000000000:0000 0A 00000000:00000000 00:00000000 00000000     0        0 99 1\n";
        let s = parse_listen_v6(sample);
        assert!(s.contains(&ListenEntry {
            addr: IpAddr::V6(Ipv6Addr::UNSPECIFIED),
            port: 0x1F90,
        }));
    }

    #[test]
    fn parses_v6_loopback() {
        let sample = "  sl  local_address                         remote_address                        st\n\
             0: 00000000000000000000000001000000:1F90 00000000000000000000000000000000:0000 0A 00000000:00000000 00:00000000 00000000     0        0 99 1\n";
        let s = parse_listen_v6(sample);
        assert!(
            s.contains(&ListenEntry {
                addr: IpAddr::V6(Ipv6Addr::LOCALHOST),
                port: 0x1F90,
            }),
            "got {s:?}"
        );
    }

    #[test]
    fn empty_or_garbage_returns_empty_set() {
        assert!(parse_listen_v4("").is_empty());
        assert!(parse_listen_v4("garbage garbage garbage\n").is_empty());
    }

    #[test]
    fn should_forward_accepts_wildcard_and_loopback() {
        assert!(should_forward(ListenEntry {
            addr: IpAddr::V4(Ipv4Addr::UNSPECIFIED),
            port: 80,
        }));
        assert!(should_forward(ListenEntry {
            addr: IpAddr::V6(Ipv6Addr::UNSPECIFIED),
            port: 80,
        }));
        assert!(should_forward(ListenEntry {
            addr: IpAddr::V4(Ipv4Addr::LOCALHOST),
            port: 80,
        }));
        assert!(should_forward(ListenEntry {
            addr: IpAddr::V6(Ipv6Addr::LOCALHOST),
            port: 80,
        }));
    }

    #[test]
    fn should_forward_rejects_real_addresses() {
        assert!(!should_forward(ListenEntry {
            addr: IpAddr::V4(Ipv4Addr::new(172, 16, 0, 5)),
            port: 80,
        }));
    }

    #[test]
    fn needs_loopback_forwarder_only_for_loopback() {
        assert!(needs_loopback_forwarder(ListenEntry {
            addr: IpAddr::V4(Ipv4Addr::LOCALHOST),
            port: 80,
        }));
        assert!(needs_loopback_forwarder(ListenEntry {
            addr: IpAddr::V6(Ipv6Addr::LOCALHOST),
            port: 80,
        }));
        assert!(!needs_loopback_forwarder(ListenEntry {
            addr: IpAddr::V4(Ipv4Addr::UNSPECIFIED),
            port: 80,
        }));
    }
}
