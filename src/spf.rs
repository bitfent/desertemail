//! Inbound SPF evaluation (RFC 7208 core subset).
//! Mechanisms: ip4, ip6, a, mx, include, all; modifier redirect=.
//! DNS lookup cap of 10 (RFC). Injectable resolver for unit tests.

use std::net::{IpAddr, Ipv4Addr, Ipv6Addr};
use std::str::FromStr;

use crate::dns;

/// SPF check result (RFC 7208 §2.6).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum SpfResult {
    Pass,
    Fail,
    SoftFail,
    Neutral,
    None,
    TempError,
    PermError,
}

impl SpfResult {
    pub fn as_str(self) -> &'static str {
        match self {
            SpfResult::Pass => "pass",
            SpfResult::Fail => "fail",
            SpfResult::SoftFail => "softfail",
            SpfResult::Neutral => "neutral",
            SpfResult::None => "none",
            SpfResult::TempError => "temperror",
            SpfResult::PermError => "permerror",
        }
    }
}

/// Qualifier for a matching mechanism.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum Qual {
    Pass,     // +
    Fail,     // -
    SoftFail, // ~
    Neutral,  // ?
}

impl Qual {
    fn to_result(self) -> SpfResult {
        match self {
            Qual::Pass => SpfResult::Pass,
            Qual::Fail => SpfResult::Fail,
            Qual::SoftFail => SpfResult::SoftFail,
            Qual::Neutral => SpfResult::Neutral,
        }
    }
}

/// Trait for SPF DNS lookups (production uses real DNS; tests inject mocks).
pub trait SpfResolver {
    fn txt(&mut self, name: &str) -> Result<Vec<String>, SpfDnsErr>;
    fn a(&mut self, name: &str) -> Result<Vec<IpAddr>, SpfDnsErr>;
    fn mx(&mut self, name: &str) -> Result<Vec<String>, SpfDnsErr>;
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum SpfDnsErr {
    Temp,
    Perm,
}

/// Live DNS resolver (uses crate::dns).
pub struct LiveSpfResolver;

impl SpfResolver for LiveSpfResolver {
    fn txt(&mut self, name: &str) -> Result<Vec<String>, SpfDnsErr> {
        dns::resolve_txt(name).map_err(|_| SpfDnsErr::Temp)
    }
    fn a(&mut self, name: &str) -> Result<Vec<IpAddr>, SpfDnsErr> {
        let strs = dns::resolve_a(name).map_err(|_| SpfDnsErr::Temp)?;
        Ok(strs.iter().filter_map(|s| parse_ip_str(s)).collect())
    }
    fn mx(&mut self, name: &str) -> Result<Vec<String>, SpfDnsErr> {
        let mxs = dns::resolve_mx(name).map_err(|_| SpfDnsErr::Temp)?;
        Ok(mxs.into_iter().map(|m| m.exchange).collect())
    }
}

/// Parse IP string, stripping IPv6 brackets if present.
pub fn parse_ip_str(s: &str) -> Option<IpAddr> {
    let s = s.trim().trim_start_matches('[').trim_end_matches(']');
    IpAddr::from_str(s).ok()
}

/// Check SPF for `mail_from_domain` (or HELO domain if mail_from empty) against `client_ip`.
pub fn check_spf(client_ip: &str, helo: &str, mail_from_domain: &str) -> SpfResult {
    let mut res = LiveSpfResolver;
    check_spf_with(client_ip, helo, mail_from_domain, &mut res)
}

/// Injectable-resolver SPF check (for tests).
pub fn check_spf_with(
    client_ip: &str,
    helo: &str,
    mail_from_domain: &str,
    resolver: &mut dyn SpfResolver,
) -> SpfResult {
    let ip = match parse_ip_str(client_ip) {
        Some(ip) => ip,
        None => return SpfResult::PermError,
    };

    // RFC 7208: empty MAIL FROM → check HELO identity
    let domain = if mail_from_domain.is_empty() {
        helo.trim_end_matches('.').to_lowercase()
    } else {
        mail_from_domain.trim_end_matches('.').to_lowercase()
    };
    if domain.is_empty() {
        return SpfResult::None;
    }

    let mut lookups = 0usize;
    evaluate_domain(ip, &domain, resolver, &mut lookups, 0)
}

const MAX_DNS_LOOKUPS: usize = 10;
const MAX_INCLUDE_DEPTH: usize = 10;

fn evaluate_domain(
    ip: IpAddr,
    domain: &str,
    resolver: &mut dyn SpfResolver,
    lookups: &mut usize,
    depth: usize,
) -> SpfResult {
    if depth > MAX_INCLUDE_DEPTH {
        return SpfResult::PermError;
    }
    if *lookups >= MAX_DNS_LOOKUPS {
        return SpfResult::PermError;
    }

    *lookups += 1;
    let txts = match resolver.txt(domain) {
        Ok(t) => t,
        Err(SpfDnsErr::Temp) => return SpfResult::TempError,
        Err(SpfDnsErr::Perm) => return SpfResult::PermError,
    };

    let record = match find_spf_record(&txts) {
        Some(r) => r,
        None => return SpfResult::None,
    };

    evaluate_record(ip, domain, &record, resolver, lookups, depth)
}

/// Find first `v=spf1` record among TXT strings.
pub fn find_spf_record(txts: &[String]) -> Option<String> {
    for t in txts {
        let trimmed = t.trim();
        // v=spf1 must be at start (case-insensitive), version token
        let lower = trimmed.to_ascii_lowercase();
        if lower == "v=spf1" || lower.starts_with("v=spf1 ") || lower.starts_with("v=spf1\t") {
            return Some(trimmed.to_string());
        }
    }
    None
}

fn evaluate_record(
    ip: IpAddr,
    domain: &str,
    record: &str,
    resolver: &mut dyn SpfResolver,
    lookups: &mut usize,
    depth: usize,
) -> SpfResult {
    let terms: Vec<&str> = record.split_whitespace().collect();
    // skip v=spf1
    let mut redirect: Option<String> = None;

    for term in terms.iter().skip(1) {
        let term = *term;
        if term.is_empty() {
            continue;
        }

        // modifiers: redirect= / exp= (exp ignored)
        if let Some(rest) = term.strip_prefix("redirect=") {
            redirect = Some(rest.trim_end_matches('.').to_lowercase());
            continue;
        }
        if term.starts_with("exp=") {
            continue;
        }

        let (qual, mech) = parse_qualifier(term);

        match match_mechanism(ip, domain, mech, resolver, lookups) {
            MechMatch::Yes => return qual.to_result(),
            MechMatch::No => continue,
            MechMatch::TempError => return SpfResult::TempError,
            MechMatch::PermError => return SpfResult::PermError,
            MechMatch::Include(r) => {
                // include: uses the result of the included domain
                match r {
                    SpfResult::Pass => return qual.to_result(),
                    SpfResult::TempError => return SpfResult::TempError,
                    SpfResult::PermError => return SpfResult::PermError,
                    // Fail/SoftFail/Neutral/None of include → no match, continue
                    _ => continue,
                }
            }
        }
    }

    if let Some(redir) = redirect {
        if *lookups >= MAX_DNS_LOOKUPS {
            return SpfResult::PermError;
        }
        return evaluate_domain(ip, &redir, resolver, lookups, depth + 1);
    }

    // No mechanism matched and no redirect → Neutral
    SpfResult::Neutral
}

fn parse_qualifier(term: &str) -> (Qual, &str) {
    match term.as_bytes().first().copied() {
        Some(b'+') => (Qual::Pass, term.get(1..).unwrap_or("")),
        Some(b'-') => (Qual::Fail, term.get(1..).unwrap_or("")),
        Some(b'~') => (Qual::SoftFail, term.get(1..).unwrap_or("")),
        Some(b'?') => (Qual::Neutral, term.get(1..).unwrap_or("")),
        _ => (Qual::Pass, term),
    }
}

enum MechMatch {
    Yes,
    No,
    TempError,
    PermError,
    /// Result of an include: (only Pass means match with qualifier).
    Include(SpfResult),
}

fn match_mechanism(
    ip: IpAddr,
    domain: &str,
    mech: &str,
    resolver: &mut dyn SpfResolver,
    lookups: &mut usize,
) -> MechMatch {
    let lower = mech.to_ascii_lowercase();

    if lower == "all" {
        return MechMatch::Yes;
    }

    if let Some(rest) = strip_prefix_ci(mech, "ip4:") {
        return match_ip4(ip, rest);
    }
    if let Some(rest) = strip_prefix_ci(mech, "ip6:") {
        return match_ip6(ip, rest);
    }
    if lower == "a" || lower.starts_with("a:") || lower.starts_with("a/") {
        return match_a(ip, domain, mech, resolver, lookups);
    }
    if lower == "mx" || lower.starts_with("mx:") || lower.starts_with("mx/") {
        return match_mx(ip, domain, mech, resolver, lookups);
    }
    if let Some(rest) = strip_prefix_ci(mech, "include:") {
        let inc_dom = rest.trim_end_matches('.').to_lowercase();
        if inc_dom.is_empty() {
            return MechMatch::PermError;
        }
        if *lookups >= MAX_DNS_LOOKUPS {
            return MechMatch::PermError;
        }
        // include counts as a lookup inside evaluate_domain
        let r = evaluate_domain(ip, &inc_dom, resolver, lookups, 0);
        return MechMatch::Include(r);
    }
    // exists:, ptr: not implemented → treat as no-match (avoid blackholing on odd records).
    if lower.starts_with("exists:") || lower == "ptr" || lower.starts_with("ptr:") {
        return MechMatch::No;
    }
    // Unrecognized mechanism: skip (lenient vs RFC PermError) so misconfig doesn't
    // hard-fail legitimate senders.
    MechMatch::No
}

fn strip_prefix_ci<'a>(s: &'a str, prefix: &str) -> Option<&'a str> {
    if s.len() >= prefix.len() && s.get(..prefix.len())?.eq_ignore_ascii_case(prefix) {
        s.get(prefix.len()..)
    } else {
        None
    }
}

fn match_ip4(ip: IpAddr, spec: &str) -> MechMatch {
    let ip4 = match ip {
        IpAddr::V4(v) => v,
        IpAddr::V6(_) => return MechMatch::No,
    };
    let (addr_s, prefix) = split_cidr(spec, 32);
    let network = match Ipv4Addr::from_str(addr_s) {
        Ok(a) => a,
        Err(_) => return MechMatch::PermError,
    };
    let prefix = prefix.min(32);
    if ipv4_in_network(ip4, network, prefix) {
        MechMatch::Yes
    } else {
        MechMatch::No
    }
}

fn match_ip6(ip: IpAddr, spec: &str) -> MechMatch {
    let ip6 = match ip {
        IpAddr::V6(v) => v,
        IpAddr::V4(_) => return MechMatch::No,
    };
    let (addr_s, prefix) = split_cidr(spec, 128);
    let network = match Ipv6Addr::from_str(addr_s) {
        Ok(a) => a,
        Err(_) => return MechMatch::PermError,
    };
    let prefix = prefix.min(128);
    if ipv6_in_network(ip6, network, prefix) {
        MechMatch::Yes
    } else {
        MechMatch::No
    }
}

fn split_cidr(spec: &str, default_prefix: u8) -> (&str, u8) {
    if let Some(idx) = spec.find('/') {
        let addr = spec.get(..idx).unwrap_or(spec);
        let p = spec
            .get(idx + 1..)
            .and_then(|s| s.parse::<u8>().ok())
            .unwrap_or(default_prefix);
        (addr, p)
    } else {
        (spec, default_prefix)
    }
}

fn ipv4_in_network(ip: Ipv4Addr, network: Ipv4Addr, prefix: u8) -> bool {
    if prefix == 0 {
        return true;
    }
    let mask = if prefix >= 32 {
        u32::MAX
    } else {
        !((1u32 << (32 - prefix)) - 1)
    };
    (u32::from(ip) & mask) == (u32::from(network) & mask)
}

fn ipv6_in_network(ip: Ipv6Addr, network: Ipv6Addr, prefix: u8) -> bool {
    if prefix == 0 {
        return true;
    }
    let ip_bytes = ip.octets();
    let net_bytes = network.octets();
    let full_bytes = (prefix / 8) as usize;
    let rem_bits = prefix % 8;
    if full_bytes > 16 {
        return ip_bytes == net_bytes;
    }
    if ip_bytes.get(..full_bytes) != net_bytes.get(..full_bytes) {
        return false;
    }
    if rem_bits == 0 {
        return true;
    }
    let mask = 0xffu8 << (8 - rem_bits);
    let a = ip_bytes.get(full_bytes).copied().unwrap_or(0) & mask;
    let b = net_bytes.get(full_bytes).copied().unwrap_or(0) & mask;
    a == b
}

fn parse_dual_cidr(mech: &str, name_default: &str) -> (String, u8, u8) {
    // forms: a, a:domain, a/24, a:domain/24, a:domain/24//64, a//64
    let rest = if let Some(r) = strip_prefix_ci(mech, "a") {
        r
    } else if let Some(r) = strip_prefix_ci(mech, "mx") {
        r
    } else {
        ""
    };
    let rest = rest.trim_start_matches(':');
    if rest.is_empty() {
        return (name_default.to_string(), 32, 128);
    }
    // domain may contain : for IPv6-looking names — rare; keep simple
    // Split on / for dual-cidr
    let parts: Vec<&str> = rest.split('/').collect();
    let domain = if parts.first().map(|s| !s.is_empty()).unwrap_or(false) {
        parts[0].trim_end_matches('.').to_lowercase()
    } else {
        name_default.to_string()
    };
    let ip4_cidr = parts
        .get(1)
        .and_then(|s| if s.is_empty() { None } else { s.parse().ok() })
        .unwrap_or(32);
    // a:dom/24//64 → parts = ["dom", "24", "", "64"] after split? actually "dom/24//64".split('/') = ["dom","24","","64"]
    let ip6_cidr = if parts.len() >= 4 {
        parts.get(3).and_then(|s| s.parse().ok()).unwrap_or(128)
    } else if parts.len() == 3 && parts.get(1).map(|s| s.is_empty()).unwrap_or(false) {
        parts.get(2).and_then(|s| s.parse().ok()).unwrap_or(128)
    } else {
        128
    };
    (domain, ip4_cidr, ip6_cidr)
}

fn match_a(
    ip: IpAddr,
    domain: &str,
    mech: &str,
    resolver: &mut dyn SpfResolver,
    lookups: &mut usize,
) -> MechMatch {
    let (target, ip4_c, ip6_c) = parse_dual_cidr(mech, domain);
    if *lookups >= MAX_DNS_LOOKUPS {
        return MechMatch::PermError;
    }
    *lookups += 1;
    let addrs = match resolver.a(&target) {
        Ok(a) => a,
        Err(SpfDnsErr::Temp) => return MechMatch::TempError,
        Err(SpfDnsErr::Perm) => return MechMatch::PermError,
    };
    for addr in addrs {
        match (ip, addr) {
            (IpAddr::V4(client), IpAddr::V4(net)) => {
                if ipv4_in_network(client, net, ip4_c) {
                    return MechMatch::Yes;
                }
            }
            (IpAddr::V6(client), IpAddr::V6(net)) => {
                if ipv6_in_network(client, net, ip6_c) {
                    return MechMatch::Yes;
                }
            }
            _ => {}
        }
    }
    MechMatch::No
}

fn match_mx(
    ip: IpAddr,
    domain: &str,
    mech: &str,
    resolver: &mut dyn SpfResolver,
    lookups: &mut usize,
) -> MechMatch {
    let (target, ip4_c, ip6_c) = parse_dual_cidr(mech, domain);
    if *lookups >= MAX_DNS_LOOKUPS {
        return MechMatch::PermError;
    }
    *lookups += 1;
    let exchanges = match resolver.mx(&target) {
        Ok(m) => m,
        Err(SpfDnsErr::Temp) => return MechMatch::TempError,
        Err(SpfDnsErr::Perm) => return MechMatch::PermError,
    };
    // Each MX A/AAAA lookup counts; cap at 10 additional per RFC (use remaining budget)
    for ex in exchanges {
        if *lookups >= MAX_DNS_LOOKUPS {
            return MechMatch::PermError;
        }
        *lookups += 1;
        let addrs = match resolver.a(&ex) {
            Ok(a) => a,
            Err(SpfDnsErr::Temp) => return MechMatch::TempError,
            Err(SpfDnsErr::Perm) => continue,
        };
        for addr in addrs {
            match (ip, addr) {
                (IpAddr::V4(client), IpAddr::V4(net)) => {
                    if ipv4_in_network(client, net, ip4_c) {
                        return MechMatch::Yes;
                    }
                }
                (IpAddr::V6(client), IpAddr::V6(net)) => {
                    if ipv6_in_network(client, net, ip6_c) {
                        return MechMatch::Yes;
                    }
                }
                _ => {}
            }
        }
    }
    MechMatch::No
}

/// Format a Received-SPF header value (without the header name).
pub fn received_spf_header(
    result: SpfResult,
    client_ip: &str,
    helo: &str,
    mail_from: &str,
) -> String {
    let permitted = if matches!(result, SpfResult::Pass) {
        "permitted sender"
    } else {
        "not a permitted sender"
    };
    format!(
        "{} (desertemail: domain of {} designates {} as {}) client-ip={}; helo={}; envelope-from={}",
        result.as_str(),
        if mail_from.is_empty() { helo } else { mail_from },
        client_ip,
        permitted,
        client_ip,
        helo,
        mail_from,
    )
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::collections::HashMap;

    struct MockResolver {
        txt: HashMap<String, Vec<String>>,
        a: HashMap<String, Vec<IpAddr>>,
        mx: HashMap<String, Vec<String>>,
    }

    impl MockResolver {
        fn new() -> Self {
            Self {
                txt: HashMap::new(),
                a: HashMap::new(),
                mx: HashMap::new(),
            }
        }
    }

    impl SpfResolver for MockResolver {
        fn txt(&mut self, name: &str) -> Result<Vec<String>, SpfDnsErr> {
            Ok(self.txt.get(name).cloned().unwrap_or_default())
        }
        fn a(&mut self, name: &str) -> Result<Vec<IpAddr>, SpfDnsErr> {
            Ok(self.a.get(name).cloned().unwrap_or_default())
        }
        fn mx(&mut self, name: &str) -> Result<Vec<String>, SpfDnsErr> {
            Ok(self.mx.get(name).cloned().unwrap_or_default())
        }
    }

    #[test]
    fn find_spf_basic() {
        let txts = vec![
            "v=DMARC1; p=none".into(),
            "v=spf1 ip4:1.2.3.4 -all".into(),
        ];
        let r = find_spf_record(&txts).unwrap();
        assert!(r.contains("ip4:1.2.3.4"));
    }

    #[test]
    fn ip4_match_pass() {
        let mut mock = MockResolver::new();
        mock.txt.insert(
            "example.com".into(),
            vec!["v=spf1 ip4:192.0.2.1 -all".into()],
        );
        let r = check_spf_with("192.0.2.1", "mail.example.com", "example.com", &mut mock);
        assert_eq!(r, SpfResult::Pass);
    }

    #[test]
    fn ip4_no_match_fail_all() {
        let mut mock = MockResolver::new();
        mock.txt.insert(
            "example.com".into(),
            vec!["v=spf1 ip4:192.0.2.1 -all".into()],
        );
        let r = check_spf_with("198.51.100.1", "mail.example.com", "example.com", &mut mock);
        assert_eq!(r, SpfResult::Fail);
    }

    #[test]
    fn softfail_all() {
        let mut mock = MockResolver::new();
        mock.txt.insert(
            "example.com".into(),
            vec!["v=spf1 ~all".into()],
        );
        let r = check_spf_with("198.51.100.1", "x", "example.com", &mut mock);
        assert_eq!(r, SpfResult::SoftFail);
    }

    #[test]
    fn hard_fail_all() {
        let mut mock = MockResolver::new();
        mock.txt.insert(
            "example.com".into(),
            vec!["v=spf1 -all".into()],
        );
        let r = check_spf_with("198.51.100.1", "x", "example.com", &mut mock);
        assert_eq!(r, SpfResult::Fail);
    }

    #[test]
    fn include_recursion() {
        let mut mock = MockResolver::new();
        mock.txt.insert(
            "example.com".into(),
            vec!["v=spf1 include:_spf.example.com -all".into()],
        );
        mock.txt.insert(
            "_spf.example.com".into(),
            vec!["v=spf1 ip4:203.0.113.5 -all".into()],
        );
        let r = check_spf_with("203.0.113.5", "x", "example.com", &mut mock);
        assert_eq!(r, SpfResult::Pass);

        let r2 = check_spf_with("198.51.100.1", "x", "example.com", &mut mock);
        assert_eq!(r2, SpfResult::Fail);
    }

    #[test]
    fn cidr_match() {
        let mut mock = MockResolver::new();
        mock.txt.insert(
            "example.com".into(),
            vec!["v=spf1 ip4:192.0.2.0/24 -all".into()],
        );
        assert_eq!(
            check_spf_with("192.0.2.99", "x", "example.com", &mut mock),
            SpfResult::Pass
        );
        assert_eq!(
            check_spf_with("192.0.3.1", "x", "example.com", &mut mock),
            SpfResult::Fail
        );
    }

    #[test]
    fn no_record_none() {
        let mut mock = MockResolver::new();
        mock.txt
            .insert("example.com".into(), vec!["not-spf".into()]);
        assert_eq!(
            check_spf_with("1.2.3.4", "x", "example.com", &mut mock),
            SpfResult::None
        );
    }

    #[test]
    fn a_mechanism() {
        let mut mock = MockResolver::new();
        mock.txt
            .insert("example.com".into(), vec!["v=spf1 a -all".into()]);
        mock.a.insert(
            "example.com".into(),
            vec![IpAddr::V4(Ipv4Addr::new(192, 0, 2, 10))],
        );
        assert_eq!(
            check_spf_with("192.0.2.10", "x", "example.com", &mut mock),
            SpfResult::Pass
        );
    }
}
