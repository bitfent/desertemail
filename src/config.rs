//! Hand-rolled config parser. Zero deps. Supports simple TOML-like syntax.

use std::collections::HashMap;
use std::fs;
use std::path::Path;

use crate::crypto::RsaKey;
use crate::util;

#[derive(Debug, Clone)]
pub struct Config {
    pub domains: Vec<String>,
    pub data_dir: String,
    pub smtp_listen: String,
    pub submission_listen: String,
    pub imap_listen: String,
    pub smarthost: Option<String>,
    pub smarthost_user: Option<String>,
    pub smarthost_pass: Option<String>,
    pub catch_all: bool,
    pub default_password: String,
    pub users: HashMap<String, String>,
    /// DKIM selector (default "mail"). DNS: `<selector>._domainkey.<domain>`
    pub dkim_selector: String,
    /// Path to PEM RSA private key for DKIM (PKCS#1 or PKCS#8).
    pub dkim_key_file: Option<String>,
    /// Loaded at startup; None if missing/unparseable.
    pub dkim_key: Option<RsaKey>,
    /// HTTP webmail/admin listen address. Empty string disables the web UI.
    pub web_listen: String,
    /// Login name allowed to access /admin. None or empty disables admin page.
    pub admin_user: Option<String>,
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
}

impl Default for Config {
    fn default() -> Self {
        Self {
            domains: vec!["localhost".into()],
            data_dir: "./data".into(),
            smtp_listen: "0.0.0.0:2525".into(),
            submission_listen: "0.0.0.0:2587".into(),
            imap_listen: "0.0.0.0:2143".into(),
            smarthost: None,
            smarthost_user: None,
            smarthost_pass: None,
            catch_all: true,
            default_password: "changeme".into(),
            users: HashMap::new(),
            dkim_selector: "mail".into(),
            dkim_key_file: None,
            dkim_key: None,
            web_listen: "0.0.0.0:8080".into(),
            admin_user: None,
            tls_cert_file: None,
            tls_key_file: None,
            smtps_listen: String::new(),
            imaps_listen: String::new(),
            web_tls_listen: String::new(),
            require_tls_for_auth: false,
        }
    }
}

impl Config {
    pub fn load(path: &Path) -> Result<Self, String> {
        let content = fs::read_to_string(path).map_err(|e| format!("read config: {}", e))?;
        Self::parse(&content)
    }

    pub fn parse(content: &str) -> Result<Self, String> {
        let mut cfg = Config::default();
        let mut section = String::new();

        for (lineno, raw_line) in content.lines().enumerate() {
            let line = raw_line.trim();
            if line.is_empty() || line.starts_with('#') {
                continue;
            }
            if line.starts_with('[') && line.ends_with(']') {
                section = line[1..line.len() - 1].trim().to_lowercase();
                continue;
            }

            let eq = match line.find('=') {
                Some(i) => i,
                None => return Err(format!("line {}: expected key = value", lineno + 1)),
            };
            let mut key = line[..eq].trim().to_lowercase();
            let mut val = line[eq + 1..].trim().to_string();

            if let Some(hash) = val.find('#') {
                val = val[..hash].trim().to_string();
            }

            if (key.starts_with('"') && key.ends_with('"'))
                || (key.starts_with('\'') && key.ends_with('\''))
            {
                key = key[1..key.len() - 1].to_string();
            }
            if (val.starts_with('"') && val.ends_with('"'))
                || (val.starts_with('\'') && val.ends_with('\''))
            {
                val = val[1..val.len() - 1].to_string();
            }

            match (section.as_str(), key.as_str()) {
                ("", "domains") => {
                    cfg.domains = parse_list(&val);
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
                ("", "dkim_selector") => cfg.dkim_selector = val,
                ("", "dkim_key_file") => cfg.dkim_key_file = Some(val),
                ("", "web_listen") => cfg.web_listen = val,
                ("", "admin_user") => {
                    if val.is_empty() {
                        cfg.admin_user = None;
                    } else {
                        cfg.admin_user = Some(val.to_lowercase());
                    }
                }
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
                ("users", k) => {
                    cfg.users.insert(k.to_string(), val);
                }
                _ => {
                    if section.is_empty() {
                        util::log!("config: ignoring unknown key {}", key);
                    }
                }
            }
        }

        cfg.domains = cfg.domains.into_iter().map(|d| d.to_lowercase()).collect();
        let mut new_users = HashMap::new();
        for (k, v) in cfg.users {
            new_users.insert(k.to_lowercase(), v);
        }
        cfg.users = new_users;

        Ok(cfg)
    }

    pub fn resolve_mailbox(&self, addr: &str) -> Option<String> {
        let (local, domain) = util::parse_email_addr(addr);
        if domain.is_empty() {
            if self.users.contains_key(&local) {
                return Some(local);
            }
            if self.catch_all {
                return Some(local);
            }
            return None;
        }
        if !self.domains.iter().any(|d| d == &domain) {
            return None;
        }
        let full = format!("{}@{}", local, domain);
        if self.users.contains_key(&full) {
            return Some(full);
        }
        if self.users.contains_key(&local) {
            return Some(local);
        }
        if self.catch_all {
            Some(local)
        } else {
            None
        }
    }

    pub fn check_password(&self, user: &str, pass: &str) -> bool {
        let user = user.to_lowercase();
        if let Some(stored) = self.users.get(&user) {
            return stored == pass;
        }
        if self.catch_all {
            return pass == self.default_password;
        }
        false
    }

    pub fn is_our_domain(&self, domain: &str) -> bool {
        self.domains.iter().any(|d| d == &domain.to_lowercase())
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
