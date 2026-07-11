//! Lightweight inbound spam scoring: greylisting, DNSBL/RBL, additive heuristics.
//! All checks are independently switchable; defaults are permissive (no rejection).

use std::collections::HashMap;
use std::fs;
use std::io::{self, Write};
use std::net::IpAddr;
use std::path::{Path, PathBuf};
use std::sync::Mutex;
use std::time::{Duration, Instant};

use crate::dkim::{DkimResult, DkimStatus};
use crate::dns;
use crate::spf::SpfResult;
use crate::util;

// ---------------------------------------------------------------------------
// Greylisting
// ---------------------------------------------------------------------------

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum GreylistDecision {
    /// First sight or still within delay — reply 451.
    Defer,
    /// Triplet known and delay elapsed — accept (and refresh whitelist).
    Accept,
}

/// Greylist key: (client /24, mail_from, first rcpt), all lowercased.
pub fn greylist_key(client_ip: &str, mail_from: &str, rcpt: &str) -> String {
    let net = ip_to_slash24(client_ip).unwrap_or_else(|| client_ip.to_string());
    format!(
        "{}|{}|{}",
        net,
        mail_from.trim().to_lowercase(),
        rcpt.trim().to_lowercase()
    )
}

fn ip_to_slash24(ip: &str) -> Option<String> {
    let ip = ip.trim().trim_start_matches('[').trim_end_matches(']');
    let addr: IpAddr = ip.parse().ok()?;
    match addr {
        IpAddr::V4(v4) => {
            let o = v4.octets();
            Some(format!("{}.{}.{}.0/24", o[0], o[1], o[2]))
        }
        IpAddr::V6(v6) => {
            // /48 coarse bucket for greylist
            let o = v6.octets();
            Some(format!(
                "{:02x}{:02x}:{:02x}{:02x}:{:02x}{:02x}::/48",
                o[0], o[1], o[2], o[3], o[4], o[5]
            ))
        }
    }
}

fn greylist_path(data_dir: &str, key: &str) -> PathBuf {
    let hash = util::base64_encode(&crate::crypto::sha256(key.as_bytes()));
    // filesystem-safe: strip + / =
    let safe: String = hash
        .chars()
        .map(|c| match c {
            '+' => '-',
            '/' => '_',
            '=' => 'A',
            o => o,
        })
        .take(40)
        .collect();
    Path::new(data_dir).join("greylist").join(safe)
}

/// Check greylist state with injectable clock (`now` = unix seconds).
///
/// - Unknown triplet → write first-seen, return Defer
/// - Seen but age < delay_secs → Defer
/// - Seen and age >= delay_secs and within whitelist TTL → Accept (refresh)
/// - Expired → treat as new (Defer)
pub fn greylist_check(
    data_dir: &str,
    client_ip: &str,
    mail_from: &str,
    rcpt: &str,
    delay_secs: u64,
    ttl_secs: u64,
    now: u64,
) -> GreylistDecision {
    let key = greylist_key(client_ip, mail_from, rcpt);
    let path = greylist_path(data_dir, &key);
    let _ = fs::create_dir_all(path.parent().unwrap_or(Path::new(".")));

    if let Ok(content) = fs::read_to_string(&path) {
        let parts: Vec<&str> = content.trim().split_whitespace().collect();
        // format: first_seen  last_ok(optional)  key
        if let Some(first_s) = parts.first() {
            if let Ok(first) = first_s.parse::<u64>() {
                let last_ok = parts
                    .get(1)
                    .and_then(|s| s.parse::<u64>().ok())
                    .unwrap_or(0);

                // Whitelisted triplet (last_ok set and still within TTL)
                if last_ok > 0 && now.saturating_sub(last_ok) <= ttl_secs {
                    let _ = write_greylist_entry(&path, first, now, &key);
                    return GreylistDecision::Accept;
                }

                // Still within initial observation window
                let age = now.saturating_sub(first);
                if age < delay_secs {
                    return GreylistDecision::Defer;
                }
                // Delay elapsed and not past absolute TTL from first sight
                if age <= ttl_secs.max(delay_secs) + 86_400 {
                    // Promote to whitelist
                    let _ = write_greylist_entry(&path, first, now, &key);
                    return GreylistDecision::Accept;
                }
                // Expired — fall through to new entry
            }
        }
    }

    // First sight
    let _ = write_greylist_entry(&path, now, 0, &key);
    GreylistDecision::Defer
}

fn write_greylist_entry(path: &Path, first: u64, last_ok: u64, key: &str) -> io::Result<()> {
    if let Some(parent) = path.parent() {
        fs::create_dir_all(parent)?;
    }
    let mut f = fs::File::create(path)?;
    writeln!(f, "{} {} {}", first, last_ok, key)?;
    Ok(())
}

/// Prune greylist files older than `max_age_secs` (by mtime / content first seen).
pub fn greylist_prune(data_dir: &str, max_age_secs: u64, now: u64) {
    let dir = Path::new(data_dir).join("greylist");
    let entries = match fs::read_dir(&dir) {
        Ok(e) => e,
        Err(_) => return,
    };
    for ent in entries.flatten() {
        let path = ent.path();
        if !path.is_file() {
            continue;
        }
        let mut drop = false;
        if let Ok(content) = fs::read_to_string(&path) {
            if let Some(first_s) = content.split_whitespace().next() {
                if let Ok(first) = first_s.parse::<u64>() {
                    if now.saturating_sub(first) > max_age_secs {
                        drop = true;
                    }
                }
            }
        }
        if drop {
            let _ = fs::remove_file(&path);
        }
    }
}

// ---------------------------------------------------------------------------
// DNSBL / RBL
// ---------------------------------------------------------------------------

/// Short-lived DNSBL result cache.
struct DnsblCache {
    map: HashMap<String, (bool, Instant)>,
}

static DNSBL_CACHE: Mutex<Option<DnsblCache>> = Mutex::new(None);
const DNSBL_CACHE_TTL: Duration = Duration::from_secs(300);

fn dnsbl_cache_get(key: &str) -> Option<bool> {
    let mut guard = DNSBL_CACHE.lock().ok()?;
    let cache = guard.get_or_insert_with(|| DnsblCache {
        map: HashMap::new(),
    });
    if let Some((hit, at)) = cache.map.get(key) {
        if at.elapsed() < DNSBL_CACHE_TTL {
            return Some(*hit);
        }
    }
    None
}

fn dnsbl_cache_set(key: &str, hit: bool) {
    if let Ok(mut guard) = DNSBL_CACHE.lock() {
        let cache = guard.get_or_insert_with(|| DnsblCache {
            map: HashMap::new(),
        });
        cache.map.insert(key.to_string(), (hit, Instant::now()));
        // bound size
        if cache.map.len() > 4096 {
            cache.map.clear();
        }
    }
}

/// Query one DNSBL zone for an IPv4 client. Returns true on A-record hit.
pub fn dnsbl_listed(client_ip: &str, zone: &str) -> bool {
    let ip = client_ip.trim().trim_start_matches('[').trim_end_matches(']');
    let parts: Vec<&str> = ip.split('.').collect();
    if parts.len() != 4 {
        return false; // only IPv4 DNSBLs in this basic impl
    }
    for p in &parts {
        if p.parse::<u8>().is_err() {
            return false;
        }
    }
    let qname = format!(
        "{}.{}.{}.{}.{}",
        parts[3], parts[2], parts[1], parts[0], zone
    );
    let cache_key = qname.clone();
    if let Some(hit) = dnsbl_cache_get(&cache_key) {
        return hit;
    }
    let hit = match dns::resolve_a(&qname) {
        Ok(ips) => !ips.is_empty(),
        Err(_) => false, // DNS failure → not listed (avoid false rejects)
    };
    dnsbl_cache_set(&cache_key, hit);
    hit
}

/// Count DNSBL hits across configured zones.
pub fn dnsbl_hit_count(client_ip: &str, zones: &[String]) -> usize {
    let mut n = 0;
    for z in zones {
        if z.is_empty() {
            continue;
        }
        if dnsbl_listed(client_ip, z) {
            n += 1;
        }
    }
    n
}

// ---------------------------------------------------------------------------
// Additive spam score
// ---------------------------------------------------------------------------

/// Score weights (documented heuristic — keep small).
pub const SCORE_RBL_HIT: i32 = 5;
pub const SCORE_SPF_FAIL: i32 = 3;
pub const SCORE_SPF_SOFTFAIL: i32 = 1;
pub const SCORE_DKIM_FAIL: i32 = 2;
pub const SCORE_DMARC_FAIL: i32 = 3;
pub const SCORE_NO_PTR: i32 = 1;
pub const SCORE_FCRDNS_MISMATCH: i32 = 2;
pub const SCORE_MISSING_DATE: i32 = 1;
pub const SCORE_MISSING_MSGID: i32 = 1;

#[derive(Debug, Clone)]
pub struct SpamScoreInput<'a> {
    pub client_ip: &'a str,
    pub helo: &'a str,
    pub spf: SpfResult,
    pub dkim: &'a [DkimResult],
    pub dmarc_pass: Option<bool>, // None = no record / not evaluated
    pub dmarc_record_found: bool,
    pub raw_message: &'a [u8],
    pub dnsbl_hits: usize,
    /// When true, perform PTR / FCrDNS lookups (costs DNS).
    pub check_ptr: bool,
}

#[derive(Debug, Clone)]
pub struct SpamScore {
    pub score: i32,
    pub reasons: Vec<String>,
}

/// Decide whether an accepted inbound message should land in the recipient's
/// Spam folder (`.Junk`) instead of the inbox root.
///
/// - `folder_threshold <= 0` disables auto-filing.
/// - Reject is handled earlier (`score >= reject_threshold`); this only runs for
///   messages that were accepted. If reject is enabled and score would reject,
///   returns false (caller should not deliver).
/// - Files when `score >= folder_threshold`.
pub fn should_file_to_junk(score: i32, folder_threshold: i32, reject_threshold: i32) -> bool {
    if folder_threshold <= 0 {
        return false;
    }
    if reject_threshold > 0 && score >= reject_threshold {
        return false;
    }
    score >= folder_threshold
}

impl SpamScore {
    pub fn compute(input: &SpamScoreInput<'_>) -> Self {
        let mut score = 0i32;
        let mut reasons = Vec::new();

        if input.dnsbl_hits > 0 {
            let add = SCORE_RBL_HIT.saturating_mul(input.dnsbl_hits as i32);
            score += add;
            reasons.push(format!("dnsbl_hits={} (+{})", input.dnsbl_hits, add));
        }

        match input.spf {
            SpfResult::Fail => {
                score += SCORE_SPF_FAIL;
                reasons.push(format!("spf=fail (+{})", SCORE_SPF_FAIL));
            }
            SpfResult::SoftFail => {
                score += SCORE_SPF_SOFTFAIL;
                reasons.push(format!("spf=softfail (+{})", SCORE_SPF_SOFTFAIL));
            }
            _ => {}
        }

        let dkim_failed = input.dkim.iter().any(|d| d.status == DkimStatus::Fail);
        let dkim_passed = input.dkim.iter().any(|d| d.status == DkimStatus::Pass);
        if dkim_failed && !dkim_passed {
            score += SCORE_DKIM_FAIL;
            reasons.push(format!("dkim=fail (+{})", SCORE_DKIM_FAIL));
        }

        if input.dmarc_record_found && input.dmarc_pass == Some(false) {
            score += SCORE_DMARC_FAIL;
            reasons.push(format!("dmarc=fail (+{})", SCORE_DMARC_FAIL));
        }

        if input.check_ptr {
            match check_fcrdns(input.client_ip, input.helo) {
                Fcrdns::NoPtr => {
                    score += SCORE_NO_PTR;
                    reasons.push(format!("no_ptr (+{})", SCORE_NO_PTR));
                }
                Fcrdns::Mismatch => {
                    score += SCORE_FCRDNS_MISMATCH;
                    reasons.push(format!("fcrdns_mismatch (+{})", SCORE_FCRDNS_MISMATCH));
                }
                Fcrdns::Ok | Fcrdns::Skipped => {}
            }
        }

        if !header_present(input.raw_message, "date") {
            score += SCORE_MISSING_DATE;
            reasons.push(format!("missing_date (+{})", SCORE_MISSING_DATE));
        }
        if !header_present(input.raw_message, "message-id") {
            score += SCORE_MISSING_MSGID;
            reasons.push(format!("missing_message_id (+{})", SCORE_MISSING_MSGID));
        }

        SpamScore { score, reasons }
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum Fcrdns {
    Ok,
    NoPtr,
    Mismatch,
    Skipped,
}

fn check_fcrdns(client_ip: &str, helo: &str) -> Fcrdns {
    let ptrs = match dns::resolve_ptr(client_ip) {
        Ok(p) if !p.is_empty() => p,
        Ok(_) => return Fcrdns::NoPtr,
        Err(_) => return Fcrdns::Skipped, // temp DNS — don't score
    };
    let helo_l = helo.trim_end_matches('.').to_lowercase();
    // Forward-confirm: any PTR that resolves back to client_ip, or matches HELO
    for p in &ptrs {
        let p_l = p.trim_end_matches('.').to_lowercase();
        if !helo_l.is_empty() && (p_l == helo_l || helo_l.ends_with(&format!(".{}", p_l))) {
            return Fcrdns::Ok;
        }
        if let Ok(ips) = dns::resolve_a(p) {
            for ip in ips {
                let plain = ip.trim_start_matches('[').trim_end_matches(']');
                let client = client_ip.trim().trim_start_matches('[').trim_end_matches(']');
                if plain == client {
                    return Fcrdns::Ok;
                }
            }
        }
    }
    Fcrdns::Mismatch
}

fn header_present(raw: &[u8], name: &str) -> bool {
    let header_end = raw
        .windows(4)
        .position(|w| w == b"\r\n\r\n")
        .or_else(|| raw.windows(2).position(|w| w == b"\n\n"))
        .unwrap_or(raw.len());
    let headers = raw.get(..header_end).unwrap_or(&[]);
    let name_bytes = name.as_bytes();
    for line in headers.split(|&b| b == b'\n') {
        let line = if line.last() == Some(&b'\r') {
            line.get(..line.len().saturating_sub(1)).unwrap_or(&[])
        } else {
            line
        };
        // skip continuations
        if line.first().map(|b| *b == b' ' || *b == b'\t').unwrap_or(false) {
            continue;
        }
        if let Some(colon) = line.iter().position(|&b| b == b':') {
            let n = line.get(..colon).unwrap_or(&[]);
            if n.eq_ignore_ascii_case(name_bytes) {
                return true;
            }
        }
    }
    false
}

/// Extract domain from a From: header in the raw message (best-effort).
pub fn from_header_domain(raw: &[u8]) -> String {
    let header_end = raw
        .windows(4)
        .position(|w| w == b"\r\n\r\n")
        .or_else(|| raw.windows(2).position(|w| w == b"\n\n"))
        .unwrap_or(raw.len());
    let headers = String::from_utf8_lossy(raw.get(..header_end).unwrap_or(&[]));
    let mut cur = String::new();
    let mut from_val = None;
    for line in headers.split('\n') {
        let line = line.strip_suffix('\r').unwrap_or(line);
        if line
            .bytes()
            .next()
            .map(|b| b == b' ' || b == b'\t')
            .unwrap_or(false)
            && !cur.is_empty()
        {
            cur.push(' ');
            cur.push_str(line.trim());
            continue;
        }
        if !cur.is_empty() {
            if cur.to_ascii_lowercase().starts_with("from:") {
                from_val = Some(cur.clone());
            }
        }
        cur = line.to_string();
    }
    if from_val.is_none() && cur.to_ascii_lowercase().starts_with("from:") {
        from_val = Some(cur);
    }
    let val = match from_val {
        Some(v) => v,
        None => return String::new(),
    };
    // extract email
    let after = val.splitn(2, ':').nth(1).unwrap_or("").trim();
    let addr = if let Some(start) = after.rfind('<') {
        if let Some(end) = after[start..].find('>') {
            after.get(start + 1..start + end).unwrap_or("").trim()
        } else {
            after
        }
    } else {
        after.split_whitespace().next().unwrap_or(after)
    };
    let (_l, d) = util::parse_email_addr(addr);
    d
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::dkim::{DkimResult, DkimStatus};
    use crate::spf::SpfResult;
    use std::time::{SystemTime, UNIX_EPOCH};

    fn now() -> u64 {
        SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .unwrap()
            .as_secs()
    }

    #[test]
    fn greylist_state_machine() {
        let dir = std::env::temp_dir().join(format!("de-gl-{}", now()));
        let _ = fs::remove_dir_all(&dir);
        fs::create_dir_all(&dir).unwrap();
        let data = dir.to_str().unwrap();

        let t0 = 1_700_000_000u64;
        // First sight → defer
        assert_eq!(
            greylist_check(data, "192.0.2.10", "a@b.com", "u@example.com", 60, 30 * 86400, t0),
            GreylistDecision::Defer
        );
        // Too soon → still defer
        assert_eq!(
            greylist_check(
                data,
                "192.0.2.10",
                "a@b.com",
                "u@example.com",
                60,
                30 * 86400,
                t0 + 30
            ),
            GreylistDecision::Defer
        );
        // After delay → accept
        assert_eq!(
            greylist_check(
                data,
                "192.0.2.10",
                "a@b.com",
                "u@example.com",
                60,
                30 * 86400,
                t0 + 61
            ),
            GreylistDecision::Accept
        );
        // Whitelisted → accept immediately
        assert_eq!(
            greylist_check(
                data,
                "192.0.2.10",
                "a@b.com",
                "u@example.com",
                60,
                30 * 86400,
                t0 + 100
            ),
            GreylistDecision::Accept
        );
        // Different /24 → new triplet
        assert_eq!(
            greylist_check(
                data,
                "198.51.100.1",
                "a@b.com",
                "u@example.com",
                60,
                30 * 86400,
                t0 + 100
            ),
            GreylistDecision::Defer
        );

        let _ = fs::remove_dir_all(&dir);
    }

    #[test]
    fn spam_score_thresholds() {
        let msg = b"From: x@y.com\r\nSubject: hi\r\n\r\nbody\r\n";
        let dkim_fail = vec![DkimResult {
            status: DkimStatus::Fail,
            domain: "y.com".into(),
            selector: "m".into(),
            detail: "x".into(),
        }];
        let input = SpamScoreInput {
            client_ip: "192.0.2.1",
            helo: "bad.example",
            spf: SpfResult::Fail,
            dkim: &dkim_fail,
            dmarc_pass: Some(false),
            dmarc_record_found: true,
            raw_message: msg,
            dnsbl_hits: 1,
            check_ptr: false,
        };
        let s = SpamScore::compute(&input);
        // rbl 5 + spf 3 + dkim 2 + dmarc 3 + missing date 1 + missing msgid 1 = 15
        assert_eq!(s.score, 15);
        assert!(s.score > 5);

        let clean = SpamScoreInput {
            client_ip: "192.0.2.1",
            helo: "ok",
            spf: SpfResult::Pass,
            dkim: &[],
            dmarc_pass: Some(true),
            dmarc_record_found: true,
            raw_message: b"From: a@b.c\r\nDate: x\r\nMessage-ID: <1>\r\n\r\nbody\r\n",
            dnsbl_hits: 0,
            check_ptr: false,
        };
        assert_eq!(SpamScore::compute(&clean).score, 0);
    }

    #[test]
    fn spam_folder_filing_decision() {
        // default-ish: folder=4, reject disabled
        assert!(!should_file_to_junk(0, 4, 0));
        assert!(!should_file_to_junk(3, 4, 0));
        assert!(should_file_to_junk(4, 4, 0));
        assert!(should_file_to_junk(10, 4, 0));
        // disabled
        assert!(!should_file_to_junk(99, 0, 0));
        assert!(!should_file_to_junk(99, -1, 0));
        // reject takes precedence (would not deliver)
        assert!(!should_file_to_junk(20, 4, 15));
        assert!(should_file_to_junk(10, 4, 15));
        // missing Date + Message-ID scores 2 — files when threshold is 1
        assert!(should_file_to_junk(2, 1, 0));
        assert!(!should_file_to_junk(2, 3, 0));
    }

    #[test]
    fn from_domain_extract() {
        let msg = b"From: Alice <alice@Example.COM>\r\n\r\nHi\r\n";
        assert_eq!(from_header_domain(msg), "example.com");
    }

    #[test]
    fn greylist_key_slash24() {
        let k1 = greylist_key("192.0.2.10", "a@b", "c@d");
        let k2 = greylist_key("192.0.2.99", "a@b", "c@d");
        assert_eq!(k1, k2);
        let k3 = greylist_key("192.0.3.10", "a@b", "c@d");
        assert_ne!(k1, k3);
    }
}
