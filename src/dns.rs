//! Minimal DNS client over UDP. Pure std.
//! On Unix, parses /etc/resolv.conf; otherwise (and as empty fallback) uses
//! 8.8.8.8:53 and 1.1.1.1:53. MX + A/AAAA with compression.

use std::io;
use std::net::{SocketAddr, UdpSocket};
use std::time::Duration;

use crate::util;

const DNS_TIMEOUT: Duration = Duration::from_secs(2);
const QTYPE_A: u16 = 1;
const QTYPE_NS: u16 = 2;
const QTYPE_CNAME: u16 = 5;
const QTYPE_PTR: u16 = 12;
const QTYPE_MX: u16 = 15;
const QTYPE_TXT: u16 = 16;
const QTYPE_AAAA: u16 = 28;
const QCLASS_IN: u16 = 1;

/// One MX record: preference (lower first) and exchange hostname.
#[derive(Debug, Clone)]
pub struct MxRecord {
    pub preference: u16,
    pub exchange: String,
}

/// Resolve MX for `domain`, sorted by preference ascending.
/// On empty MX answers, returns empty vec (caller may fall back to A/AAAA).
pub fn resolve_mx(domain: &str) -> io::Result<Vec<MxRecord>> {
    let domain = domain.trim_end_matches('.').to_lowercase();
    if domain.is_empty() {
        return Ok(Vec::new());
    }
    let answers = query(&domain, QTYPE_MX)?;
    let mut mxs = Vec::new();
    for ans in answers {
        if ans.rtype != QTYPE_MX {
            continue;
        }
        if ans.rdata.len() < 3 {
            continue;
        }
        let pref = u16::from_be_bytes([
            *ans.rdata.get(0).unwrap_or(&0),
            *ans.rdata.get(1).unwrap_or(&0),
        ]);
        // Exchange name is encoded starting at rdata[2]; may use compression
        // relative to the full message — we re-parse via stored message offset.
        if let Some(name) = ans.rdata_name {
            mxs.push(MxRecord {
                preference: pref,
                exchange: name.trim_end_matches('.').to_lowercase(),
            });
        }
    }
    mxs.sort_by_key(|m| m.preference);
    Ok(mxs)
}

/// Resolve A and AAAA addresses for `host`.
/// Returns parseable IP strings: dotted IPv4, and bracketed IPv6 for SocketAddr
/// (e.g. `[2001:db8::1]`). Callers that need `IpAddr` should strip brackets.
pub fn resolve_a(host: &str) -> io::Result<Vec<String>> {
    let host = host.trim_end_matches('.').to_lowercase();
    if host.is_empty() {
        return Ok(Vec::new());
    }

    let mut ips = Vec::new();

    // Prefer A records; also gather AAAA.
    if let Ok(answers) = query(&host, QTYPE_A) {
        for ans in answers {
            if ans.rtype == QTYPE_A && ans.rdata.len() == 4 {
                let a = *ans.rdata.get(0).unwrap_or(&0);
                let b = *ans.rdata.get(1).unwrap_or(&0);
                let c = *ans.rdata.get(2).unwrap_or(&0);
                let d = *ans.rdata.get(3).unwrap_or(&0);
                ips.push(format!("{}.{}.{}.{}", a, b, c, d));
            }
        }
    }
    if let Ok(answers) = query(&host, QTYPE_AAAA) {
        for ans in answers {
            if ans.rtype == QTYPE_AAAA && ans.rdata.len() == 16 {
                let mut parts = [0u16; 8];
                for i in 0..8 {
                    let hi = *ans.rdata.get(i * 2).unwrap_or(&0);
                    let lo = *ans.rdata.get(i * 2 + 1).unwrap_or(&0);
                    parts[i] = u16::from_be_bytes([hi, lo]);
                }
                // Bracketed so SocketAddr parse works; strip for IpAddr.
                ips.push(format!(
                    "[{:x}:{:x}:{:x}:{:x}:{:x}:{:x}:{:x}:{:x}]",
                    parts[0], parts[1], parts[2], parts[3], parts[4], parts[5], parts[6],
                    parts[7]
                ));
            }
        }
    }

    Ok(ips)
}

/// Resolve TXT records for `name` (QTYPE 16).
/// Character-strings within a single TXT RR are concatenated into one String;
/// each TXT RR becomes one entry.
pub fn resolve_txt(name: &str) -> io::Result<Vec<String>> {
    let name = name.trim_end_matches('.').to_lowercase();
    if name.is_empty() {
        return Ok(Vec::new());
    }
    let answers = query(&name, QTYPE_TXT)?;
    let mut out = Vec::new();
    for ans in answers {
        if ans.rtype != QTYPE_TXT {
            continue;
        }
        if let Some(s) = decode_txt_rdata(&ans.rdata) {
            out.push(s);
        }
    }
    Ok(out)
}

/// Reverse DNS (PTR) for an IP address string.
/// Accepts dotted IPv4, bare IPv6, or bracketed IPv6.
pub fn resolve_ptr(ip: &str) -> io::Result<Vec<String>> {
    let ptr_name = match ptr_name_for_ip(ip) {
        Some(n) => n,
        None => return Ok(Vec::new()),
    };
    let answers = query(&ptr_name, QTYPE_PTR)?;
    let mut out = Vec::new();
    for ans in answers {
        if ans.rtype != QTYPE_PTR {
            continue;
        }
        if let Some(name) = ans.rdata_name {
            out.push(name.trim_end_matches('.').to_lowercase());
        }
    }
    Ok(out)
}

/// Build the reverse-lookup name for an IP (`x.x.x.x.in-addr.arpa` / `ip6.arpa`).
pub fn ptr_name_for_ip(ip: &str) -> Option<String> {
    let ip = ip.trim().trim_start_matches('[').trim_end_matches(']');
    if ip.contains('.') && !ip.contains(':') {
        // IPv4
        let parts: Vec<&str> = ip.split('.').collect();
        if parts.len() != 4 {
            return None;
        }
        for p in &parts {
            if p.parse::<u8>().is_err() {
                return None;
            }
        }
        Some(format!(
            "{}.{}.{}.{}.in-addr.arpa",
            parts[3], parts[2], parts[1], parts[0]
        ))
    } else if ip.contains(':') {
        // Expand IPv6 to 32 nibbles
        let full = expand_ipv6(ip)?;
        let mut nibbles: Vec<char> = full.chars().filter(|c| *c != ':').collect();
        if nibbles.len() != 32 {
            return None;
        }
        nibbles.reverse();
        let labels: Vec<String> = nibbles.iter().map(|c| c.to_string()).collect();
        Some(format!("{}.ip6.arpa", labels.join(".")))
    } else {
        None
    }
}

/// Expand IPv6 to 8 groups of 4 hex digits joined by ':'.
fn expand_ipv6(ip: &str) -> Option<String> {
    let ip = ip.trim().trim_start_matches('[').trim_end_matches(']');
    let (left, right) = if let Some(idx) = ip.find("::") {
        let l = &ip[..idx];
        let r = &ip[idx + 2..];
        (l, r)
    } else {
        (ip, "")
    };
    let mut groups: Vec<String> = Vec::new();
    if !left.is_empty() {
        for g in left.split(':') {
            if g.is_empty() {
                return None;
            }
            let n = u16::from_str_radix(g, 16).ok()?;
            groups.push(format!("{:04x}", n));
        }
    }
    let mut right_groups: Vec<String> = Vec::new();
    if !right.is_empty() {
        for g in right.split(':') {
            if g.is_empty() {
                return None;
            }
            let n = u16::from_str_radix(g, 16).ok()?;
            right_groups.push(format!("{:04x}", n));
        }
    }
    if ip.contains("::") {
        let fill = 8usize.saturating_sub(groups.len() + right_groups.len());
        for _ in 0..fill {
            groups.push("0000".into());
        }
    }
    groups.extend(right_groups);
    if groups.len() != 8 {
        return None;
    }
    Some(groups.join(":"))
}

/// Decode TXT rdata: sequence of length-prefixed character-strings, concatenated.
fn decode_txt_rdata(rdata: &[u8]) -> Option<String> {
    if rdata.is_empty() {
        return Some(String::new());
    }
    let mut out = String::new();
    let mut i = 0usize;
    while i < rdata.len() {
        let len = *rdata.get(i)? as usize;
        i = i.saturating_add(1);
        if i.saturating_add(len) > rdata.len() {
            return None;
        }
        let chunk = rdata.get(i..i + len)?;
        out.push_str(&String::from_utf8_lossy(chunk));
        i = i.saturating_add(len);
    }
    Some(out)
}

/// Hosts to try for SMTP delivery of `domain`: MX exchanges sorted by pref,
/// or the domain itself if no MX (RFC 5321 implicit MX).
pub fn smtp_hosts_for_domain(domain: &str) -> io::Result<Vec<String>> {
    let mxs = resolve_mx(domain)?;
    if mxs.is_empty() {
        Ok(vec![domain.trim_end_matches('.').to_lowercase()])
    } else {
        Ok(mxs.into_iter().map(|m| m.exchange).collect())
    }
}

struct DnsAnswer {
    rtype: u16,
    rdata: Vec<u8>,
    /// For MX/NS/CNAME: decoded target name from rdata.
    rdata_name: Option<String>,
}

fn query(name: &str, qtype: u16) -> io::Result<Vec<DnsAnswer>> {
    let resolvers = system_resolvers();
    let mut last_err = io::Error::new(io::ErrorKind::Other, "no DNS resolvers");

    for resolver in &resolvers {
        match query_once(name, qtype, resolver, false) {
            Ok((answers, truncated)) => {
                if truncated {
                    // Retry once on TC bit; still return whatever we got if retry fails.
                    match query_once(name, qtype, resolver, true) {
                        Ok((a2, _)) => return Ok(a2),
                        Err(_) => return Ok(answers),
                    }
                }
                return Ok(answers);
            }
            Err(e) => last_err = e,
        }
    }
    Err(last_err)
}

fn query_once(
    name: &str,
    qtype: u16,
    resolver: &SocketAddr,
    _retry: bool,
) -> io::Result<(Vec<DnsAnswer>, bool)> {
    let id = (util::now_millis() as u16).wrapping_add(qtype);
    let packet = build_query(id, name, qtype)?;

    let sock = UdpSocket::bind("0.0.0.0:0")?;
    sock.set_read_timeout(Some(DNS_TIMEOUT))?;
    sock.set_write_timeout(Some(DNS_TIMEOUT))?;
    sock.send_to(&packet, resolver)?;

    let mut buf = [0u8; 2048];
    let (n, _) = sock.recv_from(&mut buf)?;
    if n < 12 {
        return Err(io::Error::new(io::ErrorKind::InvalidData, "DNS response too short"));
    }
    let resp = buf.get(..n).ok_or_else(|| {
        io::Error::new(io::ErrorKind::InvalidData, "DNS response slice OOB")
    })?;

    let resp_id = u16::from_be_bytes([
        *resp.get(0).unwrap_or(&0),
        *resp.get(1).unwrap_or(&0),
    ]);
    if resp_id != id {
        return Err(io::Error::new(io::ErrorKind::InvalidData, "DNS id mismatch"));
    }

    let flags = u16::from_be_bytes([
        *resp.get(2).unwrap_or(&0),
        *resp.get(3).unwrap_or(&0),
    ]);
    let truncated = (flags & 0x0200) != 0;
    let rcode = flags & 0x000F;
    if rcode != 0 {
        // NXDOMAIN / SERVFAIL etc. — return empty, not hard error for MX fallback.
        if rcode == 3 {
            return Ok((Vec::new(), truncated));
        }
        return Err(io::Error::new(
            io::ErrorKind::Other,
            format!("DNS rcode {}", rcode),
        ));
    }

    let qdcount = u16::from_be_bytes([
        *resp.get(4).unwrap_or(&0),
        *resp.get(5).unwrap_or(&0),
    ]) as usize;
    let ancount = u16::from_be_bytes([
        *resp.get(6).unwrap_or(&0),
        *resp.get(7).unwrap_or(&0),
    ]) as usize;

    let mut pos = 12usize;
    for _ in 0..qdcount {
        pos = skip_name(resp, pos)?;
        pos = pos.checked_add(4).ok_or_else(|| {
            io::Error::new(io::ErrorKind::InvalidData, "DNS qd overflow")
        })?;
    }

    let mut answers = Vec::new();
    for _ in 0..ancount {
        pos = skip_name(resp, pos)?;
        if pos.saturating_add(10) > resp.len() {
            break;
        }
        let rtype = u16::from_be_bytes([
            *resp.get(pos).unwrap_or(&0),
            *resp.get(pos + 1).unwrap_or(&0),
        ]);
        // class at pos+2..+4, ttl at +4..+8
        let rdlength = u16::from_be_bytes([
            *resp.get(pos + 8).unwrap_or(&0),
            *resp.get(pos + 9).unwrap_or(&0),
        ]) as usize;
        pos = pos.saturating_add(10);
        if pos.saturating_add(rdlength) > resp.len() {
            break;
        }
        let rdata = resp
            .get(pos..pos + rdlength)
            .unwrap_or(&[])
            .to_vec();
        let rdata_name = if rtype == QTYPE_MX && rdlength >= 3 {
            // preference (2) + name
            parse_name(resp, pos + 2).ok().map(|(n, _)| n)
        } else if rtype == QTYPE_PTR || rtype == QTYPE_CNAME || rtype == QTYPE_NS {
            // PTR / CNAME / NS — name is the whole rdata
            parse_name(resp, pos).ok().map(|(n, _)| n)
        } else {
            None
        };
        answers.push(DnsAnswer {
            rtype,
            rdata,
            rdata_name,
        });
        pos = pos.saturating_add(rdlength);
    }

    Ok((answers, truncated))
}

fn build_query(id: u16, name: &str, qtype: u16) -> io::Result<Vec<u8>> {
    let mut pkt = Vec::with_capacity(512);
    pkt.extend_from_slice(&id.to_be_bytes());
    // RD=1
    pkt.extend_from_slice(&0x0100u16.to_be_bytes());
    pkt.extend_from_slice(&1u16.to_be_bytes()); // QDCOUNT
    pkt.extend_from_slice(&0u16.to_be_bytes()); // ANCOUNT
    pkt.extend_from_slice(&0u16.to_be_bytes()); // NSCOUNT
    pkt.extend_from_slice(&0u16.to_be_bytes()); // ARCOUNT

    encode_name(&mut pkt, name)?;
    pkt.extend_from_slice(&qtype.to_be_bytes());
    pkt.extend_from_slice(&QCLASS_IN.to_be_bytes());
    Ok(pkt)
}

fn encode_name(buf: &mut Vec<u8>, name: &str) -> io::Result<()> {
    let name = name.trim_end_matches('.');
    if name.is_empty() {
        buf.push(0);
        return Ok(());
    }
    for label in name.split('.') {
        if label.is_empty() || label.len() > 63 {
            return Err(io::Error::new(io::ErrorKind::InvalidInput, "bad DNS label"));
        }
        buf.push(label.len() as u8);
        buf.extend_from_slice(label.as_bytes());
    }
    buf.push(0);
    Ok(())
}

/// Fuzz-visible: parse DNS names and walk answer sections without I/O.
pub fn fuzz_parse_response(resp: &[u8]) {
    if resp.len() < 12 {
        return;
    }
    let mut pos = 12usize;
    let qdcount = u16::from_be_bytes([
        *resp.get(4).unwrap_or(&0),
        *resp.get(5).unwrap_or(&0),
    ]) as usize;
    let ancount = u16::from_be_bytes([
        *resp.get(6).unwrap_or(&0),
        *resp.get(7).unwrap_or(&0),
    ]) as usize;
    for _ in 0..qdcount.min(64) {
        match skip_name(resp, pos) {
            Ok(p) => pos = p.saturating_add(4),
            Err(_) => return,
        }
        if pos > resp.len() {
            return;
        }
    }
    for _ in 0..ancount.min(64) {
        match skip_name(resp, pos) {
            Ok(p) => pos = p,
            Err(_) => return,
        }
        if pos.saturating_add(10) > resp.len() {
            return;
        }
        let rdlength = u16::from_be_bytes([
            *resp.get(pos + 8).unwrap_or(&0),
            *resp.get(pos + 9).unwrap_or(&0),
        ]) as usize;
        pos = pos.saturating_add(10).saturating_add(rdlength);
        let _ = parse_name(resp, 0);
    }
}

fn parse_name(msg: &[u8], mut pos: usize) -> io::Result<(String, usize)> {
    let mut labels = Vec::new();
    let mut jumped = false;
    let mut end_pos = pos;
    let mut hops = 0usize;

    loop {
        if pos >= msg.len() {
            return Err(io::Error::new(io::ErrorKind::InvalidData, "DNS name OOB"));
        }
        let len = *msg.get(pos).ok_or_else(|| {
            io::Error::new(io::ErrorKind::InvalidData, "DNS name OOB")
        })?;
        if len == 0 {
            if !jumped {
                end_pos = pos.saturating_add(1);
            }
            break;
        }
        if len & 0xC0 == 0xC0 {
            if pos + 1 >= msg.len() {
                return Err(io::Error::new(io::ErrorKind::InvalidData, "DNS ptr OOB"));
            }
            let b1 = *msg.get(pos + 1).ok_or_else(|| {
                io::Error::new(io::ErrorKind::InvalidData, "DNS ptr OOB")
            })?;
            let ptr = (((len as usize) & 0x3F) << 8) | (b1 as usize);
            if !jumped {
                end_pos = pos.saturating_add(2);
            }
            pos = ptr;
            jumped = true;
            hops += 1;
            if hops > 20 {
                return Err(io::Error::new(io::ErrorKind::InvalidData, "DNS ptr loop"));
            }
            continue;
        }
        if len & 0xC0 != 0 {
            return Err(io::Error::new(io::ErrorKind::InvalidData, "bad DNS label"));
        }
        let l = len as usize;
        pos = pos.saturating_add(1);
        if pos.saturating_add(l) > msg.len() {
            return Err(io::Error::new(io::ErrorKind::InvalidData, "DNS label OOB"));
        }
        let label = String::from_utf8_lossy(msg.get(pos..pos + l).unwrap_or(&[])).into_owned();
        labels.push(label);
        pos = pos.saturating_add(l);
        if !jumped {
            end_pos = pos;
        }
    }

    let name = if labels.is_empty() {
        ".".to_string()
    } else {
        labels.join(".")
    };
    Ok((name, end_pos))
}

fn skip_name(msg: &[u8], pos: usize) -> io::Result<usize> {
    parse_name(msg, pos).map(|(_, end)| end)
}

fn system_resolvers() -> Vec<SocketAddr> {
    let mut out = Vec::new();
    #[cfg(unix)]
    {
        if let Ok(content) = std::fs::read_to_string("/etc/resolv.conf") {
            for line in content.lines() {
                let line = line.trim();
                if line.is_empty() || line.starts_with('#') {
                    continue;
                }
                let mut parts = line.split_whitespace();
                if parts.next() != Some("nameserver") {
                    continue;
                }
                if let Some(ip) = parts.next() {
                    let addr = if ip.contains(':') && !ip.contains('.') {
                        // IPv6 bare
                        format!("[{}]:53", ip)
                    } else {
                        format!("{}:53", ip)
                    };
                    if let Ok(sa) = addr.parse::<SocketAddr>() {
                        out.push(sa);
                    }
                }
            }
        }
    }
    // Windows has no /etc/resolv.conf; also used when Unix resolv.conf is empty.
    if out.is_empty() {
        for s in ["8.8.8.8:53", "1.1.1.1:53"] {
            if let Ok(sa) = s.parse() {
                out.push(sa);
            }
        }
    }
    out
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn encode_simple_name() {
        let mut buf = Vec::new();
        encode_name(&mut buf, "example.com").unwrap();
        assert_eq!(
            buf,
            b"\x07example\x03com\x00".to_vec()
        );
    }

    #[test]
    fn parse_compressed_name() {
        // example.com + pointer back to start for second name
        let mut msg = Vec::new();
        msg.extend_from_slice(b"\x07example\x03com\x00");
        // pointer to offset 0
        msg.push(0xC0);
        msg.push(0x00);
        let (n, end) = parse_name(&msg, 0).unwrap();
        assert_eq!(n, "example.com");
        assert_eq!(end, 13);
        let (n2, end2) = parse_name(&msg, 13).unwrap();
        assert_eq!(n2, "example.com");
        assert_eq!(end2, 15);
    }

    #[test]
    fn decode_txt_concatenates_strings() {
        // "v=spf1" + " ~all"
        let rdata = b"\x06v=spf1\x05 ~all";
        assert_eq!(decode_txt_rdata(rdata).as_deref(), Some("v=spf1 ~all"));
    }

    #[test]
    fn ptr_name_ipv4() {
        assert_eq!(
            ptr_name_for_ip("1.2.3.4").as_deref(),
            Some("4.3.2.1.in-addr.arpa")
        );
    }

    #[test]
    fn ptr_name_ipv6() {
        let n = ptr_name_for_ip("2001:db8::1").unwrap();
        assert!(n.ends_with(".ip6.arpa"));
        assert!(n.starts_with("1.0.0.0."));
    }

    #[test]
    fn expand_ipv6_basic() {
        assert_eq!(
            expand_ipv6("2001:db8::1").as_deref(),
            Some("2001:0db8:0000:0000:0000:0000:0000:0001")
        );
    }
}
