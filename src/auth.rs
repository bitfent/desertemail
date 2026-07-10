//! AUTH PLAIN handling. Pure std + hand-rolled base64.

use crate::config::Config;
use crate::util;

pub fn decode_plain(b64: &str) -> Option<(String, String)> {
    let raw = util::base64_decode(b64.trim());
    if raw.is_empty() {
        return None;
    }
    let parts: Vec<&[u8]> = raw.split(|&b| b == 0).collect();
    if parts.len() >= 3 {
        let user = String::from_utf8_lossy(parts[1]).to_string();
        let pass = String::from_utf8_lossy(parts[2]).to_string();
        Some((user, pass))
    } else if parts.len() == 2 {
        let user = String::from_utf8_lossy(parts[0]).to_string();
        let pass = String::from_utf8_lossy(parts[1]).to_string();
        Some((user, pass))
    } else {
        None
    }
}

pub fn authenticate(cfg: &Config, user: &str, pass: &str) -> bool {
    cfg.check_password(user, pass)
}
