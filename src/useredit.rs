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
use std::path::{Path, PathBuf};

use crate::config::Config;
use crate::passwd;

/// Minimum length for any newly set password. Enforced centrally in
/// [`add_user`] so every path (web UI, admin, invites, CLI) shares the rule.
/// Length only — no composition requirements. Existing stored credentials are
/// unaffected; this applies only when a password is (re)set.
pub const MIN_PASSWORD_LEN: usize = 8;

/// Validate a password about to be set. Single source of the policy/message.
pub fn check_new_password(password: &str) -> Result<(), String> {
    if password.len() < MIN_PASSWORD_LEN {
        return Err(format!(
            "password must be at least {} characters",
            MIN_PASSWORD_LEN
        ));
    }
    Ok(())
}

/// Parse a config string and return usernames from `[users]` (no passwords).
pub fn list_users(content: &str) -> Vec<String> {
    let (users, _) = parse_sections(content);
    users.into_keys().collect()
}

/// Add a NEW user to the `[users]` section; errors if the user already exists
/// (so an add can never silently overwrite someone's password — use
/// [`set_password`] to reset). `password` is plaintext; stored value is always
/// a pbkdf2 hash.
pub fn add_user(content: &str, email: &str, password: &str) -> Result<String, String> {
    let email = normalize_user(email)?;
    check_new_password(password)?;
    let hash = passwd::hash_password(password);
    let (mut users, quotas) = parse_sections(content);
    if users.contains_key(&email) {
        return Err(format!("user already exists: {}", email));
    }
    users.insert(email, hash);
    Ok(rewrite_sections(content, &users, &quotas))
}

/// Set a new password for an EXISTING user; errors if the user is missing
/// (so a typo can't create a stray account — use [`add_user`] to create).
pub fn set_password(content: &str, email: &str, password: &str) -> Result<String, String> {
    let email = normalize_user(email)?;
    check_new_password(password)?;
    let (mut users, quotas) = parse_sections(content);
    if !users.contains_key(&email) {
        return Err(format!("user not found: {}", email));
    }
    users.insert(email, passwd::hash_password(password));
    Ok(rewrite_sections(content, &users, &quotas))
}

/// Rename a user: the `[users]` entry keeps its password hash, any `[quotas]`
/// entry follows, and top-level `admin_user` is updated if it pointed at the
/// old name. Errors if `old` is missing or `new` already exists. The caller
/// is responsible for moving the maildir (`data_dir/<old>` → `data_dir/<new>`).
pub fn rename_user(content: &str, old: &str, new: &str) -> Result<String, String> {
    let old = normalize_user(old)?;
    let new = normalize_user(new)?;
    if old == new {
        return Err("new address is the same as the old one".into());
    }
    let (mut users, mut quotas) = parse_sections(content);
    if users.contains_key(&new) {
        return Err(format!("user already exists: {}", new));
    }
    let hash = match users.remove(&old) {
        Some(h) => h,
        None => return Err(format!("user not found: {}", old)),
    };
    users.insert(new.clone(), hash);
    if let Some(q) = quotas.remove(&old) {
        quotas.insert(new.clone(), q);
    }
    let mut out = rewrite_sections(content, &users, &quotas);
    if top_level_string(&out, "admin_user")
        .map(|a| a.eq_ignore_ascii_case(&old))
        .unwrap_or(false)
    {
        out = set_top_level_string(&out, "admin_user", &new);
    }
    Ok(out)
}

/// Read a top-level `key = "value"` string (outside any [section]).
fn top_level_string(content: &str, key: &str) -> Option<String> {
    let key_l = key.to_lowercase();
    let mut in_section = false;
    for raw_line in content.lines() {
        let line = raw_line.trim();
        if line.starts_with('[') && line.ends_with(']') && line.len() >= 2 {
            in_section = true;
            continue;
        }
        if in_section || line.is_empty() || line.starts_with('#') {
            continue;
        }
        if let Some(eq) = line.find('=') {
            let k = line[..eq].trim().trim_matches('"').trim_matches('\'').to_lowercase();
            if k == key_l {
                let v = line[eq + 1..].trim().trim_matches('"').trim_matches('\'');
                return Some(v.to_string());
            }
        }
    }
    None
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

/// Complete first-run setup: add admin user, set `admin_user`, update primary domain.
///
/// Rewrites `[users]` via the normal helper, then updates top-level `admin_user` and
/// `domains` keys (preserving comments and other settings).
pub fn complete_setup(
    content: &str,
    username: &str,
    password: &str,
    domain: &str,
) -> Result<String, String> {
    let username = normalize_user(username)?;
    check_new_password(password)?;
    let domain = domain.trim().to_lowercase();
    if domain.is_empty() {
        return Err("domain required".into());
    }
    if domain.contains(|c: char| c.is_control() || c == '"' || c == '[' || c == ']') {
        return Err("invalid domain characters".into());
    }

    // Add user first (creates [users] section if needed).
    let mut out = add_user(content, &username, password)?;
    out = set_top_level_string(&out, "admin_user", &username);
    out = set_domains_primary(&out, &domain);
    Ok(out)
}

/// Set or replace a top-level string key (`key = "value"`). Preserves other lines.
pub fn set_top_level_string(content: &str, key: &str, value: &str) -> String {
    let key_l = key.to_lowercase();
    let mut out = String::with_capacity(content.len() + 64);
    let mut section = String::new();
    let mut replaced = false;
    let new_line = format!("{} = \"{}\"\n", key, escape_toml_str(value));

    for raw_line in content.lines() {
        let trimmed = raw_line.trim();
        if trimmed.starts_with('[') && trimmed.ends_with(']') && trimmed.len() >= 2 {
            // Insert before first table section if not yet written.
            if !replaced && section.is_empty() {
                if !out.ends_with('\n') && !out.is_empty() {
                    out.push('\n');
                }
                out.push_str(&new_line);
                replaced = true;
            }
            section = trimmed[1..trimmed.len() - 1].trim().to_lowercase();
            out.push_str(raw_line);
            out.push('\n');
            continue;
        }
        if section.is_empty() && !trimmed.is_empty() && !trimmed.starts_with('#') {
            if let Some(eq) = trimmed.find('=') {
                let k = trimmed[..eq].trim().trim_matches('"').trim_matches('\'').to_lowercase();
                if k == key_l {
                    out.push_str(&new_line);
                    replaced = true;
                    continue;
                }
            }
        }
        out.push_str(raw_line);
        out.push('\n');
    }
    if !replaced {
        if !out.ends_with('\n') && !out.is_empty() {
            out.push('\n');
        }
        out.push_str(&new_line);
    }
    out
}

/// Replace top-level `domains = [...]` with a single primary domain (or insert it).
pub fn set_domains_primary(content: &str, domain: &str) -> String {
    let mut out = String::with_capacity(content.len() + 64);
    let mut section = String::new();
    let mut replaced = false;
    let new_line = format!("domains = [\"{}\"]\n", escape_toml_str(domain));

    for raw_line in content.lines() {
        let trimmed = raw_line.trim();
        if trimmed.starts_with('[') && trimmed.ends_with(']') && trimmed.len() >= 2 {
            if !replaced && section.is_empty() {
                if !out.ends_with('\n') && !out.is_empty() {
                    out.push('\n');
                }
                out.push_str(&new_line);
                replaced = true;
            }
            section = trimmed[1..trimmed.len() - 1].trim().to_lowercase();
            out.push_str(raw_line);
            out.push('\n');
            continue;
        }
        if section.is_empty() && !trimmed.is_empty() && !trimmed.starts_with('#') {
            if let Some(eq) = trimmed.find('=') {
                let k = trimmed[..eq].trim().trim_matches('"').trim_matches('\'').to_lowercase();
                if k == "domains" {
                    out.push_str(&new_line);
                    replaced = true;
                    continue;
                }
            }
        }
        out.push_str(raw_line);
        out.push('\n');
    }
    if !replaced {
        if !out.ends_with('\n') && !out.is_empty() {
            out.push('\n');
        }
        out.push_str(&new_line);
    }
    out
}

/// Set `public_host` in config.toml.
pub fn set_public_host(content: &str, host: &str) -> Result<String, String> {
    let host = host.trim().trim_end_matches('.').to_lowercase();
    if host.contains(|c: char| c.is_control() || c == '"' || c == '[' || c == ']') {
        return Err("invalid public_host characters".into());
    }
    Ok(set_top_level_string(content, "public_host", &host))
}

/// Set primary domain (replaces `domains` array with a single entry).
pub fn set_primary_domain(content: &str, domain: &str) -> Result<String, String> {
    let domain = domain.trim().to_lowercase();
    if domain.is_empty() {
        return Err("domain required".into());
    }
    if domain.contains(|c: char| c.is_control() || c == '"' || c == '[' || c == ']') {
        return Err("invalid domain characters".into());
    }
    Ok(set_domains_primary(content, &domain))
}

/// Set `public_url` in config.toml (e.g. https://mail.example.com).
/// Empty string clears the override (back to auto-detection).
pub fn set_public_url(content: &str, url: &str) -> Result<String, String> {
    let url = url.trim().trim_end_matches('/').to_string();
    if url.contains(|c: char| c.is_control() || c == '"' || c == '[' || c == ']' || c == ' ') {
        return Err("invalid public_url characters".into());
    }
    if !url.is_empty() && !url.starts_with("http://") && !url.starts_with("https://") {
        return Err("public_url must start with http:// or https://".into());
    }
    Ok(set_top_level_string(content, "public_url", &url))
}

/// Set DKIM selector + key file paths in config.toml.
pub fn set_dkim_paths(content: &str, selector: &str, key_file: &str) -> Result<String, String> {
    let selector = selector.trim().to_lowercase();
    if selector.is_empty() {
        return Err("selector required".into());
    }
    if selector.contains(|c: char| !c.is_ascii_alphanumeric() && c != '-' && c != '_') {
        return Err("invalid selector characters".into());
    }
    let key_file = key_file.trim();
    if key_file.is_empty() {
        return Err("key file path required".into());
    }
    let mut out = set_top_level_string(content, "dkim_selector", &selector);
    out = set_top_level_string(&out, "dkim_key_file", key_file);
    Ok(out)
}

/// Set or replace a top-level boolean key (`key = true|false`).
pub fn set_top_level_bool(content: &str, key: &str, value: bool) -> String {
    let key_l = key.to_lowercase();
    let mut out = String::with_capacity(content.len() + 32);
    let mut section = String::new();
    let mut replaced = false;
    let new_line = format!("{} = {}\n", key, if value { "true" } else { "false" });

    for raw_line in content.lines() {
        let trimmed = raw_line.trim();
        if trimmed.starts_with('[') && trimmed.ends_with(']') && trimmed.len() >= 2 {
            if !replaced && section.is_empty() {
                if !out.ends_with('\n') && !out.is_empty() {
                    out.push('\n');
                }
                out.push_str(&new_line);
                replaced = true;
            }
            section = trimmed[1..trimmed.len() - 1].trim().to_lowercase();
            out.push_str(raw_line);
            out.push('\n');
            continue;
        }
        if section.is_empty() && !trimmed.is_empty() && !trimmed.starts_with('#') {
            if let Some(eq) = trimmed.find('=') {
                let k = trimmed[..eq]
                    .trim()
                    .trim_matches('"')
                    .trim_matches('\'')
                    .to_lowercase();
                if k == key_l {
                    out.push_str(&new_line);
                    replaced = true;
                    continue;
                }
            }
        }
        out.push_str(raw_line);
        out.push('\n');
    }
    if !replaced {
        if !out.ends_with('\n') && !out.is_empty() {
            out.push('\n');
        }
        out.push_str(&new_line);
    }
    out
}

/// Set top-level string-array key: `key = ["a", "b"]`.
pub fn set_top_level_string_list(content: &str, key: &str, values: &[&str]) -> String {
    let key_l = key.to_lowercase();
    let mut out = String::with_capacity(content.len() + 64);
    let mut section = String::new();
    let mut replaced = false;
    let items: Vec<String> = values
        .iter()
        .map(|v| format!("\"{}\"", escape_toml_str(v)))
        .collect();
    let new_line = format!("{} = [{}]\n", key, items.join(", "));

    for raw_line in content.lines() {
        let trimmed = raw_line.trim();
        if trimmed.starts_with('[') && trimmed.ends_with(']') && trimmed.len() >= 2 {
            if !replaced && section.is_empty() {
                if !out.ends_with('\n') && !out.is_empty() {
                    out.push('\n');
                }
                out.push_str(&new_line);
                replaced = true;
            }
            section = trimmed[1..trimmed.len() - 1].trim().to_lowercase();
            out.push_str(raw_line);
            out.push('\n');
            continue;
        }
        if section.is_empty() && !trimmed.is_empty() && !trimmed.starts_with('#') {
            if let Some(eq) = trimmed.find('=') {
                let k = trimmed[..eq]
                    .trim()
                    .trim_matches('"')
                    .trim_matches('\'')
                    .to_lowercase();
                if k == key_l {
                    out.push_str(&new_line);
                    replaced = true;
                    continue;
                }
            }
        }
        out.push_str(raw_line);
        out.push('\n');
    }
    if !replaced {
        if !out.ends_with('\n') && !out.is_empty() {
            out.push('\n');
        }
        out.push_str(&new_line);
    }
    out
}

/// Enable ACME in config.toml: `acme=true`, email, domains, and cert/key paths.
///
/// Also sets `web_tls_listen` when empty so a restart can bind HTTPS after issuance.
pub fn enable_acme(
    content: &str,
    email: &str,
    domain: &str,
    cert_file: &str,
    key_file: &str,
    web_tls_listen: &str,
) -> Result<String, String> {
    let email = email.trim();
    if email.is_empty() || !email.contains('@') {
        return Err("valid ACME contact email required".into());
    }
    if email.contains(|c: char| c.is_control() || c == '"' || c == '[' || c == ']') {
        return Err("invalid email characters".into());
    }
    let domain = domain.trim().trim_end_matches('.').to_lowercase();
    if domain.is_empty() {
        return Err("domain required".into());
    }
    if domain.contains(|c: char| c.is_control() || c == '"' || c == '[' || c == ']') {
        return Err("invalid domain characters".into());
    }
    let cert_file = cert_file.trim();
    let key_file = key_file.trim();
    if cert_file.is_empty() || key_file.is_empty() {
        return Err("tls cert and key paths required".into());
    }
    let mut out = set_top_level_bool(content, "acme", true);
    out = set_top_level_string(&out, "acme_email", email);
    out = set_top_level_string_list(&out, "acme_domains", &[domain.as_str()]);
    out = set_top_level_string(&out, "tls_cert_file", cert_file);
    out = set_top_level_string(&out, "tls_key_file", key_file);
    if !web_tls_listen.trim().is_empty() {
        // Only write web_tls_listen when provided (caller decides default).
        let current = content.lines().any(|l| {
            let t = l.trim();
            t.starts_with("web_tls_listen") && t.contains('=')
        });
        if !current {
            out = set_top_level_string(&out, "web_tls_listen", web_tls_listen.trim());
        } else {
            // Keep existing non-empty listen; if empty string on disk, set it.
            let empty_listen = content.lines().any(|l| {
                let t = l.trim();
                t.starts_with("web_tls_listen")
                    && (t.contains("\"\"") || t.ends_with("= ") || t.ends_with('='))
            });
            if empty_listen {
                out = set_top_level_string(&out, "web_tls_listen", web_tls_listen.trim());
            }
        }
    }
    Ok(out)
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

/// DKIM private-key path: existing config value, else `dkim.pem` next to config.toml.
pub fn dkim_key_path_for_config(cfg: &Config) -> Result<PathBuf, String> {
    if let Some(p) = cfg.dkim_key_file_path() {
        return Ok(PathBuf::from(p));
    }
    let config_path = cfg
        .config_path
        .as_ref()
        .ok_or_else(|| "config_path not set".to_string())?;
    let dir = config_path.parent().unwrap_or_else(|| Path::new("."));
    Ok(dir.join("dkim.pem"))
}

/// Default PEM paths next to config.toml for ACME-written certs.
pub fn default_tls_paths(cfg: &Config) -> (String, String) {
    let dir = cfg
        .config_path
        .as_ref()
        .and_then(|p| p.parent().map(|d| d.to_path_buf()))
        .unwrap_or_else(|| PathBuf::from("."));
    let cert = cfg
        .tls_cert_file
        .clone()
        .unwrap_or_else(|| dir.join("tls.crt").to_string_lossy().into_owned());
    let key = cfg
        .tls_key_file
        .clone()
        .unwrap_or_else(|| dir.join("tls.key").to_string_lossy().into_owned());
    (cert, key)
}

/// Normalize a pasted HTTPS domain (strip scheme/path/trailing dot, lowercase).
/// Rejects localhost, bare labels, and invalid characters.
pub fn normalize_https_domain(raw: &str) -> Result<String, String> {
    let domain = raw
        .trim()
        .trim_start_matches("https://")
        .trim_start_matches("http://")
        .split('/')
        .next()
        .unwrap_or("")
        .trim()
        .trim_end_matches('.')
        .to_lowercase();
    if domain.is_empty() {
        return Err("enter the domain you purchased".into());
    }
    if domain == "localhost"
        || !domain.contains('.')
        || domain.contains(|c: char| {
            c.is_control() || c == '"' || c == '[' || c == ']' || c == ' ' || c == ':'
        })
    {
        return Err("enter a real public domain name (e.g. mail.example.com)".into());
    }
    Ok(domain)
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
        let added = add_user(SAMPLE, "carol@example.com", "secret-pw").unwrap();
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
        assert!(passwd::verify_password(stored, "secret-pw"));

        let removed = remove_user(&added, "carol@example.com").unwrap();
        let names2 = list_users(&removed);
        assert!(!names2.contains(&"carol@example.com".to_string()));
        assert!(names2.contains(&"alice".to_string()));
        assert!(removed.contains("domains = [\"example.com\"]"));
    }

    #[test]
    fn update_existing_user() {
        let updated = set_password(SAMPLE, "alice", "newpass99").unwrap();
        let (users, _) = parse_sections(&updated);
        let stored = users.get("alice").unwrap();
        assert!(passwd::verify_password(stored, "newpass99"));
        assert!(!passwd::verify_password(stored, "alicepass"));
    }

    #[test]
    fn rename_user_carries_hash_quota_and_admin() {
        let base = r#"admin_user = "alice"
domains = ["example.com"]

[users]
"alice" = "pbkdf2_sha256$1000$dGVzdHNhbHQxMjM0NTY3OA==$CU3ECAVkv4TOapLOjKpPBf89f2vgg8O7y5H52xU+xE4="
"bob" = "bobpass"

[quotas]
"alice" = 512
"#;
        let out = rename_user(base, "alice", "alicia@example.com").unwrap();
        let (users, quotas) = parse_sections(&out);
        // Hash moved verbatim: the old password still verifies under the new name.
        assert!(!users.contains_key("alice"));
        assert!(passwd::verify_password(users.get("alicia@example.com").unwrap(), "s3cret!"));
        assert_eq!(quotas.get("alicia@example.com"), Some(&512));
        assert!(!quotas.contains_key("alice"));
        assert!(out.contains("admin_user = \"alicia@example.com\""));
        // Non-admin rename leaves admin_user alone.
        let out2 = rename_user(base, "bob", "robert").unwrap();
        assert!(out2.contains("admin_user = \"alice\""));

        assert!(rename_user(base, "nobody", "x@example.com").is_err());
        assert!(rename_user(base, "alice", "bob").is_err()); // target exists
        assert!(rename_user(base, "alice", "ALICE").is_err()); // same after normalize
    }

    #[test]
    fn add_refuses_existing_set_refuses_missing() {
        // add_user must never overwrite an existing credential.
        assert!(add_user(SAMPLE, "alice", "whatever123").is_err());
        // set_password must not create accounts from typos.
        assert!(set_password(SAMPLE, "nobody", "whatever123").is_err());
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

    #[test]
    fn short_password_rejected() {
        // 7 chars — one under the minimum. Applies to add and update alike.
        assert!(add_user(SAMPLE, "x", "seven77").is_err());
        assert!(set_password(SAMPLE, "alice", "seven77").is_err());
        assert!(add_user(SAMPLE, "x", "eight888").is_ok());
    }

    #[test]
    fn complete_setup_adds_admin_and_domain() {
        let base = r#"# gen
domains = ["localhost"]
data_dir = "./data"
web_listen = "0.0.0.0:8080"

[users]
"#;
        let out = complete_setup(base, "Admin", "password1", "mail.example.com").unwrap();
        assert!(out.contains("admin_user = \"admin\""));
        assert!(out.contains("domains = [\"mail.example.com\"]"));
        let names = list_users(&out);
        assert!(names.contains(&"admin".to_string()));
        let (users, _) = parse_sections(&out);
        let stored = users.get("admin").unwrap();
        assert!(passwd::verify_password(stored, "password1"));
        // short password rejected
        assert!(complete_setup(base, "a", "short", "x.com").is_err());
    }

    #[test]
    fn set_public_url_validates_and_writes() {
        let out = set_public_url(SAMPLE, "https://mail.example.com/").unwrap();
        assert!(out.contains("public_url = \"https://mail.example.com\""));
        assert!(out.contains("domains = [\"example.com\"]"));
        // Clearing is allowed
        let cleared = set_public_url(&out, "").unwrap();
        assert!(cleared.contains("public_url = \"\""));
        // Must be a URL
        assert!(set_public_url(SAMPLE, "mail.example.com").is_err());
        assert!(set_public_url(SAMPLE, "https://bad domain").is_err());
    }

    #[test]
    fn enable_acme_writes_keys_atomically() {
        let base = r#"# gen
domains = ["example.com"]
data_dir = "./data"
web_listen = "0.0.0.0:8080"
acme = false

[users]
"admin" = "x"
"#;
        let out = enable_acme(
            base,
            "admin@example.com",
            "mail.example.com",
            "/tmp/tls.crt",
            "/tmp/tls.key",
            "0.0.0.0:8443",
        )
        .unwrap();
        assert!(out.contains("acme = true"));
        assert!(out.contains("acme_email = \"admin@example.com\""));
        assert!(out.contains("acme_domains = [\"mail.example.com\"]"));
        assert!(out.contains("tls_cert_file = \"/tmp/tls.crt\""));
        assert!(out.contains("tls_key_file = \"/tmp/tls.key\""));
        assert!(out.contains("web_tls_listen = \"0.0.0.0:8443\""));
        assert!(enable_acme(base, "not-an-email", "x.com", "c", "k", "").is_err());
    }

    #[test]
    fn normalize_https_domain_strips_and_validates() {
        assert_eq!(
            normalize_https_domain("https://Mail.Example.com/path").unwrap(),
            "mail.example.com"
        );
        assert_eq!(
            normalize_https_domain("http://mail.example.com.").unwrap(),
            "mail.example.com"
        );
        assert_eq!(
            normalize_https_domain("  MAIL.EXAMPLE.COM  ").unwrap(),
            "mail.example.com"
        );
        assert!(normalize_https_domain("").is_err());
        assert!(normalize_https_domain("localhost").is_err());
        assert!(normalize_https_domain("nodot").is_err());
        assert!(normalize_https_domain("bad domain.com").is_err());
        assert!(normalize_https_domain("mail.example.com:443").is_err());
    }
}
