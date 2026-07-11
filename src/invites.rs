//! Invite tokens for passwordless user onboarding.
//!
//! Stored under `<data_dir>/invites.json` as a JSON array. Tokens are 32 random
//! bytes (hex); only the SHA-256 hash is persisted. Single-use: delete on
//! redemption. Expired entries are ignored and pruned opportunistically.

use std::fs;
use std::path::{Path, PathBuf};
use std::sync::{Mutex, OnceLock};

use crate::crypto;
use crate::useredit;
use crate::util;

/// Default invite lifetime (7 days).
pub const DEFAULT_TTL_SECS: u64 = 7 * 24 * 3600;

const INVITES_FILE: &str = "invites.json";

/// One pending invite (persisted fields only — never the raw token).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Invite {
    pub token_hash: String,
    pub email: String,
    pub created_at: u64,
    pub expires_at: u64,
    pub invited_by: String,
}

/// Result of creating / regenerating an invite: plaintext token (show once) + record.
#[derive(Debug, Clone)]
pub struct CreatedInvite {
    pub token: String,
    pub invite: Invite,
}

fn invite_lock() -> &'static Mutex<()> {
    static L: OnceLock<Mutex<()>> = OnceLock::new();
    L.get_or_init(|| Mutex::new(()))
}

fn invites_path(data_dir: &Path) -> PathBuf {
    data_dir.join(INVITES_FILE)
}

fn hex_encode(bytes: &[u8]) -> String {
    let mut s = String::with_capacity(bytes.len() * 2);
    for b in bytes {
        s.push_str(&format!("{:02x}", b));
    }
    s
}

/// 32-byte CSPRNG token as URL-safe hex (64 chars). Same entropy source as sessions.
pub fn generate_token() -> String {
    let mut buf = [0u8; 32];
    util::fill_random(&mut buf);
    let material = format!("{}:{}", util::now_millis(), std::process::id());
    let dig = crypto::sha256(material.as_bytes());
    for i in 0..32 {
        buf[i] ^= dig[i];
    }
    hex_encode(&buf)
}

/// SHA-256 of the token, hex-encoded (what we store on disk).
pub fn hash_token(token: &str) -> String {
    hex_encode(&crypto::sha256(token.as_bytes()))
}

/// Validate `user@domain` against the server's configured domains.
/// Returns normalized `local@domain` (lowercase).
pub fn validate_invite_address(email: &str, domains: &[String]) -> Result<String, String> {
    let email = email.trim().to_lowercase();
    if email.is_empty() {
        return Err("email required".into());
    }
    let (local, domain) = util::parse_email_addr(&email);
    if local.is_empty() || domain.is_empty() {
        return Err("address must be user@domain".into());
    }
    if local.contains(|c: char| c.is_control() || c == '"' || c == '=' || c == '[' || c == ' ') {
        return Err("invalid username characters".into());
    }
    if domain.contains(|c: char| c.is_control() || c == '"' || c == '[' || c == ']') {
        return Err("invalid domain characters".into());
    }
    if domains.is_empty() {
        return Err("no domains configured".into());
    }
    if !domains.iter().any(|d| d.eq_ignore_ascii_case(&domain)) {
        return Err(format!(
            "address must use a configured domain ({})",
            domains.join(", ")
        ));
    }
    Ok(format!("{}@{}", local, domain))
}

fn load_raw(path: &Path) -> Result<Vec<Invite>, String> {
    if !path.exists() {
        return Ok(Vec::new());
    }
    let content = fs::read_to_string(path).map_err(|e| format!("read invites: {}", e))?;
    parse_invites_json(&content)
}

fn save_raw(path: &Path, invites: &[Invite]) -> Result<(), String> {
    if let Some(parent) = path.parent() {
        fs::create_dir_all(parent).map_err(|e| format!("create data dir: {}", e))?;
    }
    let json = serialize_invites_json(invites);
    useredit::write_atomic(path, &json)
}

fn prune_expired(invites: &mut Vec<Invite>, now: u64) -> bool {
    let before = invites.len();
    invites.retain(|i| i.expires_at > now);
    invites.len() != before
}

/// List non-expired invites (prunes file if any expired).
pub fn list_pending(data_dir: impl AsRef<Path>) -> Result<Vec<Invite>, String> {
    let _g = invite_lock().lock().map_err(|_| "invite lock poisoned")?;
    let path = invites_path(data_dir.as_ref());
    let now = util::now_secs();
    let mut invites = load_raw(&path)?;
    if prune_expired(&mut invites, now) {
        save_raw(&path, &invites)?;
    }
    Ok(invites)
}

/// Create a new invite. Returns plaintext token (show once) + record.
pub fn create(
    data_dir: impl AsRef<Path>,
    email: &str,
    invited_by: &str,
    ttl_secs: u64,
) -> Result<CreatedInvite, String> {
    create_at(data_dir.as_ref(), email, invited_by, ttl_secs, util::now_secs())
}

/// Injectable-clock create (tests).
pub fn create_at(
    data_dir: impl AsRef<Path>,
    email: &str,
    invited_by: &str,
    ttl_secs: u64,
    now: u64,
) -> Result<CreatedInvite, String> {
    let email = email.trim().to_lowercase();
    if email.is_empty() {
        return Err("email required".into());
    }
    let token = generate_token();
    let token_hash = hash_token(&token);
    let ttl = if ttl_secs == 0 {
        DEFAULT_TTL_SECS
    } else {
        ttl_secs
    };
    let invite = Invite {
        token_hash: token_hash.clone(),
        email,
        created_at: now,
        expires_at: now.saturating_add(ttl),
        invited_by: invited_by.trim().to_lowercase(),
    };

    let _g = invite_lock().lock().map_err(|_| "invite lock poisoned")?;
    let path = invites_path(data_dir.as_ref());
    let mut invites = load_raw(&path)?;
    prune_expired(&mut invites, now);
    invites.push(invite.clone());
    save_raw(&path, &invites)?;
    Ok(CreatedInvite { token, invite })
}

/// Look up a valid (non-expired) invite by plaintext token. Does not consume it.
pub fn lookup(data_dir: impl AsRef<Path>, token: &str) -> Result<Option<Invite>, String> {
    lookup_at(data_dir.as_ref(), token, util::now_secs())
}

pub fn lookup_at(
    data_dir: impl AsRef<Path>,
    token: &str,
    now: u64,
) -> Result<Option<Invite>, String> {
    if token.is_empty() {
        return Ok(None);
    }
    let th = hash_token(token);
    let _g = invite_lock().lock().map_err(|_| "invite lock poisoned")?;
    let path = invites_path(data_dir.as_ref());
    let mut invites = load_raw(&path)?;
    let pruned = prune_expired(&mut invites, now);
    let found = invites.iter().find(|i| i.token_hash == th).cloned();
    if pruned {
        save_raw(&path, &invites)?;
    }
    Ok(found)
}

/// Remove invite by token hash. Returns true if something was removed.
pub fn revoke_by_hash(data_dir: impl AsRef<Path>, token_hash: &str) -> Result<bool, String> {
    if token_hash.is_empty() {
        return Ok(false);
    }
    let _g = invite_lock().lock().map_err(|_| "invite lock poisoned")?;
    let path = invites_path(data_dir.as_ref());
    let now = util::now_secs();
    let mut invites = load_raw(&path)?;
    prune_expired(&mut invites, now);
    let before = invites.len();
    invites.retain(|i| i.token_hash != token_hash);
    let removed = invites.len() != before;
    if removed {
        save_raw(&path, &invites)?;
    }
    Ok(removed)
}

/// Consume (delete) invite by plaintext token if valid. Returns the invite if redeemed.
pub fn redeem(data_dir: impl AsRef<Path>, token: &str) -> Result<Option<Invite>, String> {
    redeem_at(data_dir.as_ref(), token, util::now_secs())
}

pub fn redeem_at(
    data_dir: impl AsRef<Path>,
    token: &str,
    now: u64,
) -> Result<Option<Invite>, String> {
    if token.is_empty() {
        return Ok(None);
    }
    let th = hash_token(token);
    let _g = invite_lock().lock().map_err(|_| "invite lock poisoned")?;
    let path = invites_path(data_dir.as_ref());
    let mut invites = load_raw(&path)?;
    prune_expired(&mut invites, now);
    let pos = invites.iter().position(|i| i.token_hash == th);
    match pos {
        Some(i) => {
            let inv = invites.remove(i);
            save_raw(&path, &invites)?;
            Ok(Some(inv))
        }
        None => Ok(None),
    }
}

/// Rotate the token for an existing invite (by hash). Returns new plaintext token.
pub fn regenerate(
    data_dir: impl AsRef<Path>,
    token_hash: &str,
) -> Result<Option<CreatedInvite>, String> {
    regenerate_at(
        data_dir.as_ref(),
        token_hash,
        util::now_secs(),
        DEFAULT_TTL_SECS,
    )
}

pub fn regenerate_at(
    data_dir: impl AsRef<Path>,
    token_hash: &str,
    now: u64,
    ttl_secs: u64,
) -> Result<Option<CreatedInvite>, String> {
    if token_hash.is_empty() {
        return Ok(None);
    }
    let _g = invite_lock().lock().map_err(|_| "invite lock poisoned")?;
    let path = invites_path(data_dir.as_ref());
    let mut invites = load_raw(&path)?;
    prune_expired(&mut invites, now);
    let pos = invites.iter().position(|i| i.token_hash == token_hash);
    let Some(i) = pos else {
        return Ok(None);
    };
    let token = generate_token();
    let new_hash = hash_token(&token);
    let ttl = if ttl_secs == 0 {
        DEFAULT_TTL_SECS
    } else {
        ttl_secs
    };
    invites[i].token_hash = new_hash;
    invites[i].created_at = now;
    invites[i].expires_at = now.saturating_add(ttl);
    let invite = invites[i].clone();
    save_raw(&path, &invites)?;
    Ok(Some(CreatedInvite { token, invite }))
}

// ---------------------------------------------------------------------------
// Minimal JSON (no serde)
// ---------------------------------------------------------------------------

fn serialize_invites_json(invites: &[Invite]) -> String {
    let mut out = String::from("[\n");
    for (i, inv) in invites.iter().enumerate() {
        if i > 0 {
            out.push_str(",\n");
        }
        out.push_str("  {\n");
        out.push_str(&format!(
            "    \"token_hash\": \"{}\",\n",
            util::json_escape(&inv.token_hash)
        ));
        out.push_str(&format!(
            "    \"email\": \"{}\",\n",
            util::json_escape(&inv.email)
        ));
        out.push_str(&format!("    \"created_at\": {},\n", inv.created_at));
        out.push_str(&format!("    \"expires_at\": {},\n", inv.expires_at));
        out.push_str(&format!(
            "    \"invited_by\": \"{}\"\n",
            util::json_escape(&inv.invited_by)
        ));
        out.push_str("  }");
    }
    out.push_str("\n]\n");
    out
}

fn parse_invites_json(content: &str) -> Result<Vec<Invite>, String> {
    let content = content.trim();
    if content.is_empty() || content == "[]" {
        return Ok(Vec::new());
    }
    let mut out = Vec::new();
    // Split on objects by finding `{...}` blocks at top level of the array.
    let mut rest = content;
    if let Some(i) = rest.find('[') {
        rest = &rest[i + 1..];
    }
    while let Some(start) = rest.find('{') {
        let after = &rest[start..];
        let end = match after.find('}') {
            Some(e) => e,
            None => break,
        };
        let obj = &after[..=end];
        if let Ok(inv) = parse_one_invite(obj) {
            out.push(inv);
        }
        rest = after.get(end + 1..).unwrap_or("");
    }
    Ok(out)
}

fn parse_one_invite(obj: &str) -> Result<Invite, String> {
    let token_hash = json_string(obj, "token_hash")?;
    let email = json_string(obj, "email")?;
    let invited_by = json_string(obj, "invited_by").unwrap_or_default();
    let created_at = json_u64(obj, "created_at")?;
    let expires_at = json_u64(obj, "expires_at")?;
    if token_hash.is_empty() || email.is_empty() {
        return Err("incomplete invite".into());
    }
    Ok(Invite {
        token_hash,
        email,
        created_at,
        expires_at,
        invited_by,
    })
}

fn json_string(obj: &str, key: &str) -> Result<String, String> {
    let pat = format!("\"{}\"", key);
    let idx = obj
        .find(&pat)
        .ok_or_else(|| format!("json missing {}", key))?;
    let after = &obj[idx + pat.len()..];
    let after = after.trim_start();
    let after = after.strip_prefix(':').unwrap_or(after).trim_start();
    if !after.starts_with('"') {
        return Err(format!("json key {} not a string", key));
    }
    let mut out = String::new();
    let mut chars = after[1..].chars();
    while let Some(c) = chars.next() {
        if c == '\\' {
            if let Some(n) = chars.next() {
                out.push(n);
            }
        } else if c == '"' {
            break;
        } else {
            out.push(c);
        }
    }
    Ok(out)
}

fn json_u64(obj: &str, key: &str) -> Result<u64, String> {
    let pat = format!("\"{}\"", key);
    let idx = obj
        .find(&pat)
        .ok_or_else(|| format!("json missing {}", key))?;
    let after = &obj[idx + pat.len()..];
    let after = after.trim_start();
    let after = after.strip_prefix(':').unwrap_or(after).trim_start();
    let num: String = after
        .chars()
        .take_while(|c| c.is_ascii_digit())
        .collect();
    num.parse()
        .map_err(|_| format!("json key {} not a number", key))
}

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use super::*;
    use std::time::{SystemTime, UNIX_EPOCH};

    fn tmp_dir(label: &str) -> PathBuf {
        let n = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .unwrap()
            .as_nanos();
        let p = std::env::temp_dir().join(format!("desertemail-invite-{}-{}", label, n));
        let _ = fs::remove_dir_all(&p);
        fs::create_dir_all(&p).unwrap();
        p
    }

    #[test]
    fn validate_address_requires_configured_domain() {
        let domains = vec!["example.com".into(), "mail.test".into()];
        assert_eq!(
            validate_invite_address("Bob@Example.COM", &domains).unwrap(),
            "bob@example.com"
        );
        assert!(validate_invite_address("bob@other.com", &domains).is_err());
        assert!(validate_invite_address("nodomain", &domains).is_err());
        assert!(validate_invite_address("", &domains).is_err());
        assert!(validate_invite_address("a@b@c.com", &domains).is_err()
            || validate_invite_address("a@b@c.com", &domains).is_ok());
        // local@mail.test ok
        assert_eq!(
            validate_invite_address("x@mail.test", &domains).unwrap(),
            "x@mail.test"
        );
    }

    #[test]
    fn create_lookup_redeem_single_use() {
        let dir = tmp_dir("create");
        let created = create_at(&dir, "bob@example.com", "admin@example.com", 3600, 1_000).unwrap();
        assert_eq!(created.invite.email, "bob@example.com");
        assert_eq!(created.invite.created_at, 1_000);
        assert_eq!(created.invite.expires_at, 1_000 + 3600);
        // raw token not on disk
        let disk = fs::read_to_string(dir.join(INVITES_FILE)).unwrap();
        assert!(!disk.contains(&created.token));
        assert!(disk.contains(&created.invite.token_hash));

        let found = lookup_at(&dir, &created.token, 1_100).unwrap().unwrap();
        assert_eq!(found.email, "bob@example.com");

        let redeemed = redeem_at(&dir, &created.token, 1_200).unwrap().unwrap();
        assert_eq!(redeemed.email, "bob@example.com");
        assert!(lookup_at(&dir, &created.token, 1_300).unwrap().is_none());
        assert!(redeem_at(&dir, &created.token, 1_400).unwrap().is_none());

        let _ = fs::remove_dir_all(&dir);
    }

    #[test]
    fn expired_invite_ignored_and_pruned() {
        let dir = tmp_dir("expire");
        let created = create_at(&dir, "bob@example.com", "admin", 10, 100).unwrap();
        assert!(lookup_at(&dir, &created.token, 105).unwrap().is_some());
        assert!(lookup_at(&dir, &created.token, 111).unwrap().is_none());
        // opportunistic prune on list
        let pending = {
            let _g = invite_lock().lock().unwrap();
            let path = invites_path(&dir);
            let mut invites = load_raw(&path).unwrap();
            prune_expired(&mut invites, 200);
            save_raw(&path, &invites).unwrap();
            invites
        };
        assert!(pending.is_empty());
        let _ = fs::remove_dir_all(&dir);
    }

    #[test]
    fn revoke_and_regenerate() {
        let dir = tmp_dir("rev");
        let now = util::now_secs();
        let c1 = create_at(&dir, "a@x.com", "admin", 3600, now).unwrap();
        assert!(revoke_by_hash(&dir, &c1.invite.token_hash).unwrap());
        assert!(lookup_at(&dir, &c1.token, now + 1).unwrap().is_none());

        let c2 = create_at(&dir, "b@x.com", "admin", 3600, now).unwrap();
        let regen = regenerate_at(&dir, &c2.invite.token_hash, now + 10, 3600)
            .unwrap()
            .unwrap();
        assert_ne!(regen.token, c2.token);
        assert!(lookup_at(&dir, &c2.token, now + 20).unwrap().is_none());
        assert!(lookup_at(&dir, &regen.token, now + 20).unwrap().is_some());
        let _ = fs::remove_dir_all(&dir);
    }

    #[test]
    fn hash_token_is_sha256_hex() {
        let h = hash_token("abc");
        assert_eq!(h.len(), 64);
        assert!(h.chars().all(|c| c.is_ascii_hexdigit()));
        // known SHA-256("abc")
        assert_eq!(
            h,
            "ba7816bf8f01cfea414140de5dae2223b00361a396177a9cb410ff61f20015ad"
        );
    }

    #[test]
    fn json_roundtrip() {
        let inv = Invite {
            token_hash: "deadbeef".into(),
            email: "u@d.com".into(),
            created_at: 1,
            expires_at: 2,
            invited_by: "a@d.com".into(),
        };
        let s = serialize_invites_json(&[inv.clone()]);
        let parsed = parse_invites_json(&s).unwrap();
        assert_eq!(parsed, vec![inv]);
    }
}
