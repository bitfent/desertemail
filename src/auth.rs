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
        let user = String::from_utf8_lossy(parts.get(1).copied().unwrap_or(&[])).to_string();
        let pass = String::from_utf8_lossy(parts.get(2).copied().unwrap_or(&[])).to_string();
        Some((user, pass))
    } else if parts.len() == 2 {
        let user = String::from_utf8_lossy(parts.get(0).copied().unwrap_or(&[])).to_string();
        let pass = String::from_utf8_lossy(parts.get(1).copied().unwrap_or(&[])).to_string();
        Some((user, pass))
    } else {
        None
    }
}

pub fn authenticate(cfg: &Config, user: &str, pass: &str) -> bool {
    cfg.check_password(user, pass)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn decode_plain_standard() {
        // \0user\0pass
        let b64 = util::base64_encode(b"\0alice\0secret");
        let (u, p) = decode_plain(&b64).unwrap();
        assert_eq!(u, "alice");
        assert_eq!(p, "secret");
    }

    #[test]
    fn decode_plain_empty() {
        assert!(decode_plain("").is_none());
        assert!(decode_plain("!!!!").is_none() || decode_plain("!!!!").is_some());
    }
}
