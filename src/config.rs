//! Hand-rolled config parser. Zero deps. Supports simple TOML-like syntax.

use std::collections::HashMap;
use std::fs;
use std::path::{Path, PathBuf};
use std::sync::{Arc, RwLock};

use crate::crypto::RsaKey;
use crate::passwd;
use crate::util;

/// Default max message size: 25 MiB.
pub const DEFAULT_MAX_MESSAGE_BYTES: u64 = 25 * 1024 * 1024;

#[derive(Debug, Clone)]
pub struct Config {
    /// Accepted domains (live-reloadable for first-run setup).
    pub domains: Arc<RwLock<Vec<String>>>,
    pub data_dir: String,
    pub smtp_listen: String,
    pub submission_listen: String,
    pub imap_listen: String,
    pub smarthost: Option<String>,
    pub smarthost_user: Option<String>,
    pub smarthost_pass: Option<String>,
    /// Accept mail for any local-part@our-domain (mailbox routing only; not auth).
    pub catch_all: bool,
    /// Password used only when `allow_default_password_auth = true` for unknown users.
    pub default_password: String,
    /// If true, unknown users may authenticate with `default_password`. Default false.
    pub allow_default_password_auth: bool,
    /// Live user map (username → password or pbkdf2 hash). Shared + reloadable.
    pub users: Arc<RwLock<HashMap<String, String>>>,
    /// DKIM selector (default "mail"). DNS: `<selector>._domainkey.<domain>`
    pub dkim_selector: String,
    /// Path to PEM RSA private key for DKIM (PKCS#1 or PKCS#8).
    pub dkim_key_file: Option<String>,
    /// Loaded at startup; None if missing/unparseable.
    pub dkim_key: Option<RsaKey>,
    /// HTTP webmail/admin listen address. Empty string disables the web UI.
    pub web_listen: String,
    /// Login name allowed to access /admin. None or empty disables admin page.
    /// Live-reloadable so first-run setup can enable admin without restart.
    pub admin_user: Arc<RwLock<Option<String>>>,
    /// Optional token allowing remote (non-loopback) first-run setup via
    /// `?setup_token=` / form field. Empty disables remote setup.
    pub setup_token: String,
    /// PEM certificate chain for TLS (STARTTLS + implicit listeners).
    pub tls_cert_file: Option<String>,
    /// PEM private key (PKCS#8 or RSA) for TLS.
    pub tls_key_file: Option<String>,
    /// Implicit SMTPS listen (submission-over-TLS). Empty = disabled.
    pub smtps_listen: String,
    /// Implicit IMAPS listen. Empty = disabled.
    pub imaps_listen: String,
    /// HTTPS webmail listen. Empty = disabled.
    pub web_tls_listen: String,
    /// If true, reject AUTH on plaintext SMTP (reply 538). Default false.
    pub require_tls_for_auth: bool,
    /// Failed auth attempts before lockout (default 10).
    pub auth_max_failures: u32,
    /// Sliding window for counting failures, seconds (default 300).
    pub auth_window_secs: u64,
    /// Lockout duration after threshold, seconds (default 900).
    pub auth_lockout_secs: u64,
    /// Max concurrent connections global (default 512).
    pub max_connections: usize,
    /// Max concurrent connections per client IP (default 20).
    pub max_connections_per_ip: usize,
    /// Socket idle read/write timeout, seconds (default 120).
    pub io_timeout_secs: u64,
    /// Max Received: headers on inbound DATA before 554 (default 30).
    pub max_received_hops: usize,
    /// Max recipients per authenticated user per rolling hour (default 200).
    pub outbound_max_rcpts_per_hour: u32,

    // --- Tier 2: inbound trust & deliverability (all off/permissive by default) ---
    /// When true: SPF hard-Fail + DMARC policy reject may yield 550. Default false.
    pub spf_enforce: bool,
    /// When true: honor DMARC p=reject (550) / p=quarantine (tag). Default false (annotate only).
    pub dmarc_enforce: bool,
    /// Enable greylisting on inbound. Default false.
    pub greylist: bool,
    /// Seconds a triplet must wait before accept (default 60).
    pub greylist_delay_secs: u64,
    /// Whitelist TTL after successful retry (default 30 days).
    pub greylist_ttl_secs: u64,
    /// DNSBL zones (e.g. zen.spamhaus.org). Default empty.
    pub dnsbls: Vec<String>,
    /// When true, a DNSBL hit alone causes 550. Default false.
    pub dnsbl_reject: bool,
    /// Score at/above which message is tagged X-Spam-Flag: YES (default 5).
    pub spam_score_tag: i32,
    /// Score at/above which message is rejected 550. 0 or negative = disabled (default 0).
    pub spam_score_reject: i32,
    /// Include PTR/FCrDNS in spam score (extra DNS). Default true when scoring runs.
    pub spam_check_ptr: bool,

    // --- Tier 3: protocol completeness, ACME, quotas, logging ---
    /// Default mailbox quota in MiB (0 = unlimited).
    pub default_quota_mb: u64,
    /// Per-user quota overrides in MiB (`[quotas]` section, key = username). Live-reloadable.
    pub quotas: Arc<RwLock<HashMap<String, u64>>>,
    /// Log format: "text" (default) or "json".
    pub log_format: String,
    /// Enable ACME (Let's Encrypt) auto-certificate. Default false.
    pub acme: bool,
    /// ACME account email (required when acme=true for registration).
    pub acme_email: String,
    /// ACME directory URL (default: Let's Encrypt production).
    pub acme_directory: String,
    /// Domains to request certs for (default = cfg.domains).
    pub acme_domains: Vec<String>,

    // --- Tier 4: ops ---
    /// Max accepted message size in bytes (SMTP DATA / IMAP APPEND). Default 25 MiB.
    pub max_message_bytes: u64,
    /// If non-empty, GET /metrics requires `Authorization: Bearer <token>` or `?token=`.
    pub metrics_token: String,
    /// Path of the config file this was loaded from (for in-place user edits).
    pub config_path: Option<PathBuf>,
}

impl Default for Config {
    fn default() -> Self {
        Self {
            domains: Arc::new(RwLock::new(vec!["localhost".into()])),
            data_dir: "./data".into(),
            smtp_listen: "0.0.0.0:2525".into(),
            submission_listen: "0.0.0.0:2587".into(),
            imap_listen: "0.0.0.0:2143".into(),
            smarthost: None,
            smarthost_user: None,
            smarthost_pass: None,
            catch_all: true,
            default_password: "changeme".into(),
            allow_default_password_auth: false,
            users: Arc::new(RwLock::new(HashMap::new())),
            dkim_selector: "mail".into(),
            dkim_key_file: None,
            dkim_key: None,
            web_listen: "0.0.0.0:8080".into(),
            admin_user: Arc::new(RwLock::new(None)),
            setup_token: String::new(),
            tls_cert_file: None,
            tls_key_file: None,
            smtps_listen: String::new(),
            imaps_listen: String::new(),
            web_tls_listen: String::new(),
            require_tls_for_auth: false,
            auth_max_failures: 10,
            auth_window_secs: 300,
            auth_lockout_secs: 900,
            max_connections: 512,
            max_connections_per_ip: 20,
            io_timeout_secs: 120,
            max_received_hops: 30,
            outbound_max_rcpts_per_hour: 200,
            spf_enforce: false,
            dmarc_enforce: false,
            greylist: false,
            greylist_delay_secs: 60,
            greylist_ttl_secs: 30 * 86400,
            dnsbls: Vec::new(),
            dnsbl_reject: false,
            spam_score_tag: 5,
            spam_score_reject: 0, // disabled
            spam_check_ptr: true,
            default_quota_mb: 0,
            quotas: Arc::new(RwLock::new(HashMap::new())),
            log_format: "text".into(),
            acme: false,
            acme_email: String::new(),
            acme_directory: "https://acme-v02.api.letsencrypt.org/directory".into(),
            acme_domains: Vec::new(),
            max_message_bytes: DEFAULT_MAX_MESSAGE_BYTES,
            metrics_token: String::new(),
            config_path: None,
        }
    }
}

impl Config {
    pub fn load(path: &Path) -> Result<Self, String> {
        let content = fs::read_to_string(path).map_err(|e| format!("read config: {}", e))?;
        let mut cfg = Self::parse(&content)?;
        cfg.config_path = Some(path.to_path_buf());
        Ok(cfg)
    }

    pub fn parse(content: &str) -> Result<Self, String> {
        let mut cfg = Config::default();
        let mut section = String::new();
        let mut users = HashMap::new();
        let mut quotas = HashMap::new();

        for (lineno, raw_line) in content.lines().enumerate() {
            let line = raw_line.trim();
            if line.is_empty() || line.starts_with('#') {
                continue;
            }
            if line.starts_with('[') && line.ends_with(']') && line.len() >= 2 {
                section = line
                    .get(1..line.len() - 1)
                    .unwrap_or("")
                    .trim()
                    .to_lowercase();
                continue;
            }

            let eq = match line.find('=') {
                Some(i) => i,
                None => return Err(format!("line {}: expected key = value", lineno + 1)),
            };
            let mut key = line.get(..eq).unwrap_or("").trim().to_lowercase();
            let mut val = line.get(eq + 1..).unwrap_or("").trim().to_string();

            if let Some(hash) = val.find('#') {
                // Only strip trailing comments when not inside a hash string that
                // uses $ (pbkdf2). Simple rule: strip # only if not after $ or if
                // the value looks like plain text with a space-hash comment.
                // Keep it simple: strip unquoted trailing # comments.
                if !val.starts_with("pbkdf2_sha256$") {
                    val = val.get(..hash).unwrap_or("").trim().to_string();
                }
            }

            if (key.starts_with('"') && key.ends_with('"') && key.len() >= 2)
                || (key.starts_with('\'') && key.ends_with('\'') && key.len() >= 2)
            {
                key = key.get(1..key.len() - 1).unwrap_or("").to_string();
            }
            if (val.starts_with('"') && val.ends_with('"') && val.len() >= 2)
                || (val.starts_with('\'') && val.ends_with('\'') && val.len() >= 2)
            {
                val = val.get(1..val.len() - 1).unwrap_or("").to_string();
            }

            match (section.as_str(), key.as_str()) {
                ("", "domains") => {
                    *cfg.domains.write().unwrap_or_else(|e| e.into_inner()) = parse_list(&val);
                }
                ("", "data_dir") => cfg.data_dir = val,
                ("", "smtp_listen") => cfg.smtp_listen = val,
                ("", "submission_listen") => cfg.submission_listen = val,
                ("", "imap_listen") => cfg.imap_listen = val,
                ("", "smarthost") => cfg.smarthost = Some(val),
                ("", "smarthost_user") => cfg.smarthost_user = Some(val),
                ("", "smarthost_pass") => cfg.smarthost_pass = Some(val),
                ("", "catch_all") => cfg.catch_all = parse_bool(&val),
                ("", "default_password") => cfg.default_password = val,
                ("", "allow_default_password_auth") => {
                    cfg.allow_default_password_auth = parse_bool(&val)
                }
                ("", "dkim_selector") => cfg.dkim_selector = val,
                ("", "dkim_key_file") => cfg.dkim_key_file = Some(val),
                ("", "web_listen") => cfg.web_listen = val,
                ("", "admin_user") => {
                    let v = if val.is_empty() {
                        None
                    } else {
                        Some(val.to_lowercase())
                    };
                    *cfg.admin_user.write().unwrap_or_else(|e| e.into_inner()) = v;
                }
                ("", "setup_token") => cfg.setup_token = val,
                ("", "tls_cert_file") => {
                    if val.is_empty() {
                        cfg.tls_cert_file = None;
                    } else {
                        cfg.tls_cert_file = Some(val);
                    }
                }
                ("", "tls_key_file") => {
                    if val.is_empty() {
                        cfg.tls_key_file = None;
                    } else {
                        cfg.tls_key_file = Some(val);
                    }
                }
                ("", "smtps_listen") => cfg.smtps_listen = val,
                ("", "imaps_listen") => cfg.imaps_listen = val,
                ("", "web_tls_listen") => cfg.web_tls_listen = val,
                ("", "require_tls_for_auth") => cfg.require_tls_for_auth = parse_bool(&val),
                ("", "auth_max_failures") => {
                    cfg.auth_max_failures = parse_u32(&val, cfg.auth_max_failures)
                }
                ("", "auth_window_secs") => {
                    cfg.auth_window_secs = parse_u64(&val, cfg.auth_window_secs)
                }
                ("", "auth_lockout_secs") => {
                    cfg.auth_lockout_secs = parse_u64(&val, cfg.auth_lockout_secs)
                }
                ("", "max_connections") => {
                    cfg.max_connections = parse_usize(&val, cfg.max_connections)
                }
                ("", "max_connections_per_ip") => {
                    cfg.max_connections_per_ip = parse_usize(&val, cfg.max_connections_per_ip)
                }
                ("", "io_timeout_secs") => {
                    cfg.io_timeout_secs = parse_u64(&val, cfg.io_timeout_secs)
                }
                ("", "max_received_hops") => {
                    cfg.max_received_hops = parse_usize(&val, cfg.max_received_hops)
                }
                ("", "outbound_max_rcpts_per_hour") => {
                    cfg.outbound_max_rcpts_per_hour =
                        parse_u32(&val, cfg.outbound_max_rcpts_per_hour)
                }
                ("", "spf_enforce") => cfg.spf_enforce = parse_bool(&val),
                ("", "dmarc_enforce") => cfg.dmarc_enforce = parse_bool(&val),
                ("", "greylist") => cfg.greylist = parse_bool(&val),
                ("", "greylist_delay_secs") => {
                    cfg.greylist_delay_secs = parse_u64(&val, cfg.greylist_delay_secs)
                }
                ("", "greylist_ttl_secs") => {
                    cfg.greylist_ttl_secs = parse_u64(&val, cfg.greylist_ttl_secs)
                }
                ("", "dnsbls") => cfg.dnsbls = parse_list(&val),
                ("", "dnsbl_reject") => cfg.dnsbl_reject = parse_bool(&val),
                ("", "spam_score_tag") => {
                    cfg.spam_score_tag = parse_i32(&val, cfg.spam_score_tag)
                }
                ("", "spam_score_reject") => {
                    cfg.spam_score_reject = parse_i32(&val, cfg.spam_score_reject)
                }
                ("", "spam_check_ptr") => cfg.spam_check_ptr = parse_bool(&val),
                ("", "default_quota_mb") => {
                    cfg.default_quota_mb = parse_u64(&val, cfg.default_quota_mb)
                }
                ("", "log_format") => cfg.log_format = val.to_lowercase(),
                ("", "acme") => cfg.acme = parse_bool(&val),
                ("", "acme_email") => cfg.acme_email = val,
                ("", "acme_directory") => cfg.acme_directory = val,
                ("", "acme_domains") => cfg.acme_domains = parse_list(&val),
                ("", "max_message_bytes") => {
                    cfg.max_message_bytes = parse_u64(&val, cfg.max_message_bytes);
                    if cfg.max_message_bytes == 0 {
                        cfg.max_message_bytes = DEFAULT_MAX_MESSAGE_BYTES;
                    }
                }
                ("", "metrics_token") => cfg.metrics_token = val,
                ("users", k) => {
                    users.insert(k.to_string(), val);
                }
                ("quotas", k) => {
                    let mb = parse_u64(&val, 0);
                    quotas.insert(k.to_string(), mb);
                }
                _ => {
                    if section.is_empty() {
                        util::log!("config: ignoring unknown key {}", key);
                    }
                }
            }
        }

        {
            let mut doms = cfg.domains.write().unwrap_or_else(|e| e.into_inner());
            *doms = doms.iter().map(|d| d.to_lowercase()).collect();
        }
        let mut new_users = HashMap::new();
        for (k, v) in users {
            new_users.insert(k.to_lowercase(), v);
        }
        let mut new_quotas = HashMap::new();
        for (k, v) in quotas {
            new_quotas.insert(k.to_lowercase(), v);
        }
        *cfg.users.write().unwrap_or_else(|e| e.into_inner()) = new_users;
        *cfg.quotas.write().unwrap_or_else(|e| e.into_inner()) = new_quotas;
        if cfg.acme_domains.is_empty() {
            cfg.acme_domains = cfg.domains_list();
        } else {
            cfg.acme_domains = cfg
                .acme_domains
                .into_iter()
                .map(|d| d.to_lowercase())
                .collect();
        }

        Ok(cfg)
    }

    /// Snapshot of configured domains (lowercase).
    pub fn domains_list(&self) -> Vec<String> {
        match self.domains.read() {
            Ok(g) => g.clone(),
            Err(e) => e.into_inner().clone(),
        }
    }

    /// First configured domain, or `"localhost"`.
    pub fn primary_domain(&self) -> String {
        self.domains_list()
            .into_iter()
            .next()
            .unwrap_or_else(|| "localhost".into())
    }

    /// Current admin username (if any).
    pub fn admin_user_name(&self) -> Option<String> {
        match self.admin_user.read() {
            Ok(g) => g.clone(),
            Err(e) => e.into_inner().clone(),
        }
    }

    /// True when no users are configured — first-run web setup is pending.
    pub fn setup_pending(&self) -> bool {
        self.user_names().is_empty()
    }

    /// Reload users + quotas (+ admin_user + domains) from `config_path` (live, no restart).
    pub fn reload_users_quotas(&self) -> Result<(), String> {
        let path = self
            .config_path
            .as_ref()
            .ok_or_else(|| "config_path not set".to_string())?;
        let content = fs::read_to_string(path).map_err(|e| format!("read config: {}", e))?;
        let fresh = Self::parse(&content)?;
        let users = fresh
            .users
            .read()
            .map_err(|_| "users lock poisoned".to_string())?
            .clone();
        let quotas = fresh
            .quotas
            .read()
            .map_err(|_| "quotas lock poisoned".to_string())?
            .clone();
        let domains = fresh.domains_list();
        let admin = fresh.admin_user_name();
        *self
            .users
            .write()
            .map_err(|_| "users lock poisoned".to_string())? = users;
        *self
            .quotas
            .write()
            .map_err(|_| "quotas lock poisoned".to_string())? = quotas;
        *self
            .domains
            .write()
            .map_err(|_| "domains lock poisoned".to_string())? = domains;
        *self
            .admin_user
            .write()
            .map_err(|_| "admin_user lock poisoned".to_string())? = admin;
        // setup_token is only needed while pending; clear live value after first user exists
        // by re-reading (token may still be on disk but is ignored once users exist).
        Ok(())
    }

    /// Sorted list of configured usernames (no passwords).
    pub fn user_names(&self) -> Vec<String> {
        let guard = match self.users.read() {
            Ok(g) => g,
            Err(e) => e.into_inner(),
        };
        let mut names: Vec<_> = guard.keys().cloned().collect();
        names.sort();
        names
    }

    /// Insert/update a user in the live map (does not persist).
    pub fn set_user_live(&self, user: &str, hash_or_pass: String) {
        let user = user.to_lowercase();
        if let Ok(mut g) = self.users.write() {
            g.insert(user, hash_or_pass);
        }
    }

    /// Remove a user from the live map (does not persist).
    pub fn remove_user_live(&self, user: &str) {
        let user = user.to_lowercase();
        if let Ok(mut g) = self.users.write() {
            g.remove(&user);
        }
    }

    /// Set live quota override in MiB (0 removes override).
    pub fn set_quota_live(&self, user: &str, mb: u64) {
        let user = user.to_lowercase();
        if let Ok(mut g) = self.quotas.write() {
            if mb == 0 {
                g.remove(&user);
            } else {
                g.insert(user, mb);
            }
        }
    }

    /// Quota for `user` in bytes (0 = unlimited).
    pub fn quota_bytes_for(&self, user: &str) -> u64 {
        let user = user.to_lowercase();
        let guard = match self.quotas.read() {
            Ok(g) => g,
            Err(e) => e.into_inner(),
        };
        let mb = guard.get(&user).copied().unwrap_or(self.default_quota_mb);
        mb.saturating_mul(1024 * 1024)
    }

    /// Log loud non-fatal security warnings about insecure config.
    pub fn audit(&self) {
        let users = match self.users.read() {
            Ok(g) => g,
            Err(e) => e.into_inner(),
        };
        for (user, stored) in users.iter() {
            if !passwd::is_hashed(stored) {
                util::log!(
                    "WARNING: user {} has a plaintext password in config; run `desertemail --hash-password` and replace it",
                    user
                );
            }
        }
        if self.allow_default_password_auth {
            util::log!(
                "WARNING: allow_default_password_auth=true — unknown users can authenticate with default_password"
            );
        }
        if self.default_password == "changeme" {
            util::log!(
                "WARNING: default_password is still \"changeme\" — change it (or leave allow_default_password_auth=false)"
            );
        }
        if self.catch_all && users.is_empty() {
            util::log!(
                "WARNING: catch_all=true with no [users] defined — mail is accepted but nobody can authenticate"
            );
        }
        if !passwd::is_hashed(&self.default_password)
            && self.allow_default_password_auth
            && !self.default_password.is_empty()
        {
            util::log!(
                "WARNING: default_password is stored as plaintext; run `desertemail --hash-password` and replace it"
            );
        }
    }

    pub fn resolve_mailbox(&self, addr: &str) -> Option<String> {
        let (local, domain) = util::parse_email_addr(addr);
        let users = match self.users.read() {
            Ok(g) => g,
            Err(e) => e.into_inner(),
        };
        if domain.is_empty() {
            if users.contains_key(&local) {
                return Some(local);
            }
            if self.catch_all {
                return Some(local);
            }
            return None;
        }
        if !self.is_our_domain(&domain) {
            return None;
        }
        let full = format!("{}@{}", local, domain);
        if users.contains_key(&full) {
            return Some(full);
        }
        if users.contains_key(&local) {
            return Some(local);
        }
        if self.catch_all {
            Some(local)
        } else {
            None
        }
    }

    /// Authenticate a user. Requires an explicit [users] entry unless
    /// `allow_default_password_auth` is true (then default_password may be used
    /// for unknown users). `catch_all` does NOT grant authentication.
    pub fn check_password(&self, user: &str, pass: &str) -> bool {
        let user = user.to_lowercase();
        let users = match self.users.read() {
            Ok(g) => g,
            Err(e) => e.into_inner(),
        };
        if let Some(stored) = users.get(&user) {
            return passwd::verify_password(stored, pass);
        }
        if self.allow_default_password_auth {
            return passwd::verify_password(&self.default_password, pass);
        }
        false
    }

    pub fn is_our_domain(&self, domain: &str) -> bool {
        let domain = domain.to_lowercase();
        self.domains_list().iter().any(|d| d == &domain)
    }
}

fn parse_list(s: &str) -> Vec<String> {
    let s = s.trim().trim_matches(|c| c == '[' || c == ']');
    s.split(|c| c == ',' || c == ' ')
        .map(|p| p.trim().trim_matches('"').trim_matches('\'').to_string())
        .filter(|p| !p.is_empty())
        .collect()
}

fn parse_bool(s: &str) -> bool {
    matches!(s.to_lowercase().as_str(), "true" | "1" | "yes" | "on")
}

fn parse_u32(s: &str, default: u32) -> u32 {
    s.parse().unwrap_or(default)
}

fn parse_u64(s: &str, default: u64) -> u64 {
    s.parse().unwrap_or(default)
}

fn parse_usize(s: &str, default: usize) -> usize {
    s.parse().unwrap_or(default)
}

fn parse_i32(s: &str, default: i32) -> i32 {
    s.parse().unwrap_or(default)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn check_password_requires_user_entry() {
        let mut cfg = Config::default();
        cfg.catch_all = true;
        cfg.allow_default_password_auth = false;
        cfg.default_password = "changeme".into();
        cfg.users
            .write()
            .unwrap()
            .insert("alice".into(), "alicepass".into());
        assert!(cfg.check_password("alice", "alicepass"));
        assert!(!cfg.check_password("alice", "wrong"));
        // Unknown user: rejected even with catch_all + default_password
        assert!(!cfg.check_password("bob", "changeme"));
    }

    #[test]
    fn allow_default_password_auth_opt_in() {
        let mut cfg = Config::default();
        cfg.allow_default_password_auth = true;
        cfg.default_password = "shared".into();
        assert!(cfg.check_password("anyone", "shared"));
        assert!(!cfg.check_password("anyone", "nope"));
    }

    #[test]
    fn hashed_password_in_config() {
        let cfg = Config::default();
        let hashed = passwd::hash_password("s3cret");
        cfg.users.write().unwrap().insert("alice".into(), hashed);
        assert!(cfg.check_password("alice", "s3cret"));
        assert!(!cfg.check_password("alice", "wrong"));
    }

    #[test]
    fn parse_new_keys() {
        let toml = r#"
domains = ["example.com"]
allow_default_password_auth = true
auth_max_failures = 5
auth_window_secs = 60
auth_lockout_secs = 120
max_connections = 100
max_connections_per_ip = 5
io_timeout_secs = 30
max_received_hops = 10
outbound_max_rcpts_per_hour = 50
spf_enforce = true
dmarc_enforce = true
greylist = true
greylist_delay_secs = 90
dnsbls = ["zen.spamhaus.org", "bl.spamcop.net"]
dnsbl_reject = false
spam_score_tag = 4
spam_score_reject = 20
default_quota_mb = 100
log_format = "json"
acme = true
acme_email = "admin@example.com"
acme_directory = "https://acme-staging-v02.api.letsencrypt.org/directory"
acme_domains = ["mail.example.com"]
max_message_bytes = 1048576
metrics_token = "secret"
[users]
"alice" = "pass"
[quotas]
"alice" = 512
"#;
        let cfg = Config::parse(toml).unwrap();
        assert!(cfg.allow_default_password_auth);
        assert_eq!(cfg.auth_max_failures, 5);
        assert_eq!(cfg.max_connections, 100);
        assert_eq!(cfg.max_received_hops, 10);
        assert_eq!(cfg.outbound_max_rcpts_per_hour, 50);
        assert!(cfg.spf_enforce);
        assert!(cfg.dmarc_enforce);
        assert!(cfg.greylist);
        assert_eq!(cfg.greylist_delay_secs, 90);
        assert_eq!(cfg.dnsbls.len(), 2);
        assert_eq!(cfg.spam_score_tag, 4);
        assert_eq!(cfg.spam_score_reject, 20);
        assert_eq!(cfg.default_quota_mb, 100);
        assert_eq!(cfg.log_format, "json");
        assert!(cfg.acme);
        assert_eq!(cfg.acme_email, "admin@example.com");
        assert_eq!(cfg.quota_bytes_for("alice"), 512 * 1024 * 1024);
        assert_eq!(cfg.quota_bytes_for("bob"), 100 * 1024 * 1024);
        assert_eq!(cfg.max_message_bytes, 1048576);
        assert_eq!(cfg.metrics_token, "secret");
        // defaults stay permissive when unset
        let def = Config::default();
        assert!(!def.spf_enforce);
        assert!(!def.dmarc_enforce);
        assert!(!def.greylist);
        assert_eq!(def.spam_score_reject, 0);
        assert_eq!(def.default_quota_mb, 0);
        assert!(!def.acme);
        assert_eq!(def.max_message_bytes, DEFAULT_MAX_MESSAGE_BYTES);
    }

    #[test]
    fn foreign_domain_not_resolved() {
        let cfg = Config::default();
        *cfg.domains.write().unwrap() = vec!["example.com".into()];
        // catch_all is true by default
        assert!(cfg.resolve_mailbox("a@example.com").is_some());
        assert!(cfg.resolve_mailbox("a@evil.com").is_none());
        assert!(!cfg.is_our_domain("evil.com"));
        assert!(cfg.is_our_domain("example.com"));
    }

    #[test]
    fn setup_pending_when_no_users() {
        let cfg = Config::default();
        assert!(cfg.setup_pending());
        cfg.users
            .write()
            .unwrap()
            .insert("admin".into(), "x".into());
        assert!(!cfg.setup_pending());
    }
}
