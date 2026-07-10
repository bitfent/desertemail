//! Minimal DNS client over UDP. Pure std.
//! Parses /etc/resolv.conf (fallback 8.8.8.8:53). MX + A/AAAA with compression.

use std::io;
use std::net::{SocketAddr, UdpSocket};
use std::time::Duration;

use crate::util;

const DNS_TIMEOUT: Duration = Duration::from_secs(2);
const QTYPE_A: u16 = 1;
const QTYPE_AAAA: u16 = 28;
const QTYPE_MX: u16 = 15;
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
        let pref = u16::from_be_bytes([ans.rdata[0], ans.rdata[1]]);
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

/// Resolve A and AAAA addresses for `host`. Returns socket addrs on port 25 by default
/// when used for SMTP; here we return IP strings so the caller can pick the port.
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
                ips.push(format!(
                    "{}.{}.{}.{}",
                    ans.rdata[0], ans.rdata[1], ans.rdata[2], ans.rdata[3]
                ));
            }
        }
    }
    if let Ok(answers) = query(&host, QTYPE_AAAA) {
        for ans in answers {
            if ans.rtype == QTYPE_AAAA && ans.rdata.len() == 16 {
                let mut parts = [0u16; 8];
                for i in 0..8 {
                    parts[i] = u16::from_be_bytes([ans.rdata[i * 2], ans.rdata[i * 2 + 1]]);
                }
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
    let resp = &buf[..n];

    let resp_id = u16::from_be_bytes([resp[0], resp[1]]);
    if resp_id != id {
        return Err(io::Error::new(io::ErrorKind::InvalidData, "DNS id mismatch"));
    }

    let flags = u16::from_be_bytes([resp[2], resp[3]]);
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

    let qdcount = u16::from_be_bytes([resp[4], resp[5]]) as usize;
    let ancount = u16::from_be_bytes([resp[6], resp[7]]) as usize;

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
        if pos + 10 > resp.len() {
            break;
        }
        let rtype = u16::from_be_bytes([resp[pos], resp[pos + 1]]);
        // class at pos+2..+4, ttl at +4..+8
        let rdlength = u16::from_be_bytes([resp[pos + 8], resp[pos + 9]]) as usize;
        pos += 10;
        if pos + rdlength > resp.len() {
            break;
        }
        let rdata = resp[pos..pos + rdlength].to_vec();
        let rdata_name = if rtype == QTYPE_MX && rdlength >= 3 {
            // preference (2) + name
            parse_name(resp, pos + 2).ok().map(|(n, _)| n)
        } else if rtype == 5 || rtype == 2 {
            // CNAME / NS
            parse_name(resp, pos).ok().map(|(n, _)| n)
        } else {
            None
        };
        answers.push(DnsAnswer {
            rtype,
            rdata,
            rdata_name,
        });
        pos += rdlength;
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

fn parse_name(msg: &[u8], mut pos: usize) -> io::Result<(String, usize)> {
    let mut labels = Vec::new();
    let mut jumped = false;
    let mut end_pos = pos;
    let mut hops = 0usize;

    loop {
        if pos >= msg.len() {
            return Err(io::Error::new(io::ErrorKind::InvalidData, "DNS name OOB"));
        }
        let len = msg[pos];
        if len == 0 {
            if !jumped {
                end_pos = pos + 1;
            }
            break;
        }
        if len & 0xC0 == 0xC0 {
            if pos + 1 >= msg.len() {
                return Err(io::Error::new(io::ErrorKind::InvalidData, "DNS ptr OOB"));
            }
            let ptr = (((len as usize) & 0x3F) << 8) | (msg[pos + 1] as usize);
            if !jumped {
                end_pos = pos + 2;
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
        pos += 1;
        if pos + l > msg.len() {
            return Err(io::Error::new(io::ErrorKind::InvalidData, "DNS label OOB"));
        }
        let label = String::from_utf8_lossy(&msg[pos..pos + l]).into_owned();
        labels.push(label);
        pos += l;
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
    if out.is_empty() {
        if let Ok(sa) = "8.8.8.8:53".parse() {
            out.push(sa);
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
}
