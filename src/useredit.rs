//! Line-based editor for the `[users]` and `[quotas]` sections of config.toml.
//!
//! Rewrites only those section blocks (and inserts them if missing). All other
//! lines are preserved byte-for-byte (comments, formatting, unknown keys).
//! Documented behaviour: the `[users]` / `[quotas]` blocks are rewritten as a
//! contiguous sorted set of `"name" = "value"` lines; surrounding comments
//! outside those sections stay intact.

use std::collections::BTreeMap;
use std::fs;
use std::io::Write;
use std::path::Path;

use crate::passwd;

/// Parse a config string and return usernames from `[users]` (no passwords).
pub fn list_users(content: &str) -> Vec<String> {
    let (users, _) = parse_sections(content);
    users.into_keys().collect()
}

/// Add or update a user password hash in the `[users]` section.
/// `password` is plaintext; stored value is always a pbkdf2 hash.
pub fn add_user(content: &str, email: &str, password: &str) -> Result<String, String> {
    let email = normalize_user(email)?;
    if password.is_empty() {
        return Err("empty password".into());
    }
    let hash = passwd::hash_password(password);
    let (mut users, quotas) = parse_sections(content);
    users.insert(email, hash);
    Ok(rewrite_sections(content, &users, &quotas))
}

/// Set password for an existing user (or create if missing).
pub fn set_password(content: &str, email: &str, password: &str) -> Result<String, String> {
    add_user(content, email, password)
}

/// Remove a user from `[users]` (and optionally leave quotas alone).
pub fn remove_user(content: &str, email: &str) -> Result<String, String> {
    let email = normalize_user(email)?;
    let (mut users, mut quotas) = parse_sections(content);
    if users.remove(&email).is_none() {
        return Err(format!("user not found: {}", email));
    }
    quotas.remove(&email);
    Ok(rewrite_sections(content, &users, &quotas))
}

/// Set per-user quota in MiB (0 = remove override / unlimited for that key).
pub fn set_quota(content: &str, email: &str, mb: u64) -> Result<String, String> {
    let email = normalize_user(email)?;
    let (users, mut quotas) = parse_sections(content);
    if mb == 0 {
        quotas.remove(&email);
    } else {
        quotas.insert(email, mb);
    }
    Ok(rewrite_sections(content, &users, &quotas))
}

/// Write config atomically (temp file in same directory + rename).
pub fn write_atomic(path: &Path, content: &str) -> Result<(), String> {
    let parent = path.parent().unwrap_or_else(|| Path::new("."));
    let tmp_name = format!(
        ".{}.tmp.{}",
        path.file_name()
            .and_then(|s| s.to_str())
            .unwrap_or("config.toml"),
        std::process::id()
    );
    let tmp = parent.join(tmp_name);
    {
        let mut f = fs::File::create(&tmp).map_err(|e| format!("create temp: {}", e))?;
        f.write_all(content.as_bytes())
            .map_err(|e| format!("write temp: {}", e))?;
        f.sync_all().map_err(|e| format!("sync temp: {}", e))?;
    }
    fs::rename(&tmp, path).map_err(|e| {
        let _ = fs::remove_file(&tmp);
        format!("rename temp: {}", e)
    })?;
    Ok(())
}

/// Load config file, apply `edit`, write back atomically. Returns new content.
pub fn edit_file<F>(path: &Path, edit: F) -> Result<String, String>
where
    F: FnOnce(&str) -> Result<String, String>,
{
    let content = fs::read_to_string(path).map_err(|e| format!("read config: {}", e))?;
    let new = edit(&content)?;
    write_atomic(path, &new)?;
    Ok(new)
}

fn normalize_user(email: &str) -> Result<String, String> {
    let e = email.trim().to_lowercase();
    if e.is_empty() {
        return Err("empty username".into());
    }
    if e.contains(|c: char| c.is_control() || c == '"' || c == '=' || c == '[') {
        return Err("invalid username characters".into());
    }
    Ok(e)
}

/// Extract `[users]` and `[quotas]` maps from config text.
fn parse_sections(content: &str) -> (BTreeMap<String, String>, BTreeMap<String, u64>) {
    let mut users = BTreeMap::new();
    let mut quotas = BTreeMap::new();
    let mut section = String::new();

    for raw_line in content.lines() {
        let line = raw_line.trim();
        if line.is_empty() || line.starts_with('#') {
            continue;
        }
        if line.starts_with('[') && line.ends_with(']') && line.len() >= 2 {
            section = line[1..line.len() - 1].trim().to_lowercase();
            continue;
        }
        let eq = match line.find('=') {
            Some(i) => i,
            None => continue,
        };
        let mut key = line[..eq].trim().to_string();
        let mut val = line[eq + 1..].trim().to_string();
        if !val.starts_with("pbkdf2_sha256$") {
            if let Some(hash) = val.find('#') {
                val = val[..hash].trim().to_string();
            }
        }
        strip_quotes(&mut key);
        strip_quotes(&mut val);
        let key = key.to_lowercase();
        match section.as_str() {
            "users" => {
                users.insert(key, val);
            }
            "quotas" => {
                if let Ok(mb) = val.parse::<u64>() {
                    quotas.insert(key, mb);
                }
            }
            _ => {}
        }
    }
    (users, quotas)
}

fn strip_quotes(s: &mut String) {
    if (s.starts_with('"') && s.ends_with('"') && s.len() >= 2)
        || (s.starts_with('\'') && s.ends_with('\'') && s.len() >= 2)
    {
        *s = s[1..s.len() - 1].to_string();
    }
}

/// Rewrite content: drop old [users]/[quotas] bodies, append rewritten blocks.
fn rewrite_sections(
    content: &str,
    users: &BTreeMap<String, String>,
    quotas: &BTreeMap<String, u64>,
) -> String {
    let mut out = String::with_capacity(content.len() + 256);
    let mut section = String::new();
    let mut skipping = false;
    let mut had_users = false;
    let mut had_quotas = false;

    for raw_line in content.lines() {
        let trimmed = raw_line.trim();
        if trimmed.starts_with('[') && trimmed.ends_with(']') && trimmed.len() >= 2 {
            let name = trimmed[1..trimmed.len() - 1].trim().to_lowercase();
            if name == "users" || name == "quotas" {
                // Skip this section header and its body until next section.
                skipping = true;
                section = name;
                if section == "users" {
                    had_users = true;
                }
                if section == "quotas" {
                    had_quotas = true;
                }
                continue;
            } else {
                skipping = false;
                section.clear();
            }
        }
        if skipping {
            // Keep blank lines / comments that appear *before* any key in the
            // section only when they look like trailing file noise — simplest:
            // drop everything until next real section header (handled above).
            continue;
        }
        out.push_str(raw_line);
        out.push('\n');
    }

    // Always emit [users] block when we had one or have users to store.
    if had_users || !users.is_empty() {
        if !out.ends_with('\n') && !out.is_empty() {
            out.push('\n');
        }
        if !out.ends_with("\n\n") && !out.is_empty() {
            out.push('\n');
        }
        out.push_str("[users]\n");
        for (k, v) in users.iter() {
            out.push_str(&format!(
                "\"{}\" = \"{}\"\n",
                escape_toml_str(k),
                escape_toml_str(v)
            ));
        }
    }

    if had_quotas || !quotas.is_empty() {
        if !out.is_empty() && !out.ends_with('\n') {
            out.push('\n');
        }
        out.push_str("\n[quotas]\n");
        for (k, v) in quotas.iter() {
            out.push_str(&format!("\"{}\" = {}\n", escape_toml_str(k), v));
        }
    }

    let _ = (had_users, had_quotas);
    out
}

fn escape_toml_str(s: &str) -> String {
    s.replace('\\', "\\\\").replace('"', "\\\"")
}

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use super::*;
    use crate::passwd;

    // [users] is last (real configs put table sections at end). Keys after a
    // section header belong to that section under TOML rules.
    const SAMPLE: &str = r#"# top comment
domains = ["example.com"]
data_dir = "./data"
log_format = "text"
# keep me

[users]
"alice" = "alicepass"
"bob" = "bobpass"
"#;

    #[test]
    fn list_users_from_sample() {
        let names = list_users(SAMPLE);
        assert!(names.contains(&"alice".to_string()));
        assert!(names.contains(&"bob".to_string()));
        assert_eq!(names.len(), 2);
    }

    #[test]
    fn add_remove_list_roundtrip() {
        let added = add_user(SAMPLE, "carol@example.com", "secret").unwrap();
        // Unrelated lines preserved
        assert!(added.contains("domains = [\"example.com\"]"));
        assert!(added.contains("# top comment"));
        assert!(added.contains("data_dir = \"./data\""));
        assert!(added.contains("# keep me"));

        let names = list_users(&added);
        assert!(names.contains(&"carol@example.com".to_string()));
        assert!(names.contains(&"alice".to_string()));

        // Password is hashed
        let (users, _) = parse_sections(&added);
        let stored = users.get("carol@example.com").unwrap();
        assert!(passwd::is_hashed(stored));
        assert!(passwd::verify_password(stored, "secret"));

        let removed = remove_user(&added, "carol@example.com").unwrap();
        let names2 = list_users(&removed);
        assert!(!names2.contains(&"carol@example.com".to_string()));
        assert!(names2.contains(&"alice".to_string()));
        assert!(removed.contains("domains = [\"example.com\"]"));
    }

    #[test]
    fn update_existing_user() {
        let updated = add_user(SAMPLE, "alice", "newpass").unwrap();
        let (users, _) = parse_sections(&updated);
        let stored = users.get("alice").unwrap();
        assert!(passwd::verify_password(stored, "newpass"));
        assert!(!passwd::verify_password(stored, "alicepass"));
    }

    #[test]
    fn set_quota_block() {
        let with_q = set_quota(SAMPLE, "alice", 512).unwrap();
        assert!(with_q.contains("[quotas]"));
        assert!(with_q.contains("\"alice\" = 512"));
        let (_, quotas) = parse_sections(&with_q);
        assert_eq!(quotas.get("alice"), Some(&512));
        // zero removes
        let cleared = set_quota(&with_q, "alice", 0).unwrap();
        let (_, quotas2) = parse_sections(&cleared);
        assert!(!quotas2.contains_key("alice"));
    }

    #[test]
    fn remove_missing_errors() {
        assert!(remove_user(SAMPLE, "nobody").is_err());
    }

    #[test]
    fn empty_password_rejected() {
        assert!(add_user(SAMPLE, "x", "").is_err());
    }
}
