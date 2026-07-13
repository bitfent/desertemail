//! Deployment readiness probe — actively checks DNS, ports, rDNS, and TLS
//! against the outside world. The installer configures the box; doctor verifies
//! mail will actually flow.
//!
//! Plain threads, small functions, no panics. Exit code = number of Fail blockers.

use std::env;
use std::fs::File;
use std::io::{self, BufReader, IsTerminal, Read};
use std::net::{IpAddr, SocketAddr, TcpStream, UdpSocket};
use std::path::Path;
use std::time::{Duration, SystemTime, UNIX_EPOCH};

use rustls_pemfile;

use crate::config::Config;
use crate::crypto;
use crate::dkim;
use crate::dns;
use crate::passwd;

const CONNECT_TIMEOUT: Duration = Duration::from_secs(3);
const BANNER_TIMEOUT: Duration = Duration::from_secs(3);

// ---------------------------------------------------------------------------
// Public API
// ---------------------------------------------------------------------------

/// CLI options for `desertemail doctor`.
#[derive(Debug, Clone, Default)]
pub struct DoctorOpts {
    /// Override domains to check (default: all cfg.domains).
    pub domains: Option<Vec<String>>,
    /// Public mail hostname (default: MX target, else first domain).
    pub host: Option<String>,
    /// Expected public IP override.
    pub public_ip: Option<String>,
    /// Machine-readable JSON array of checks.
    pub json: bool,
    /// DNS-only: skip TCP reachability probes.
    pub no_net: bool,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Status {
    Ok,
    Warn,
    Fail,
}

impl Status {
    fn as_str(self) -> &'static str {
        match self {
            Status::Ok => "ok",
            Status::Warn => "warn",
            Status::Fail => "fail",
        }
    }
}

#[derive(Debug, Clone)]
pub struct Check {
    pub name: String,
    pub status: Status,
    pub detail: String,
    pub fix: Option<String>,
}

impl Check {
    fn ok(name: impl Into<String>, detail: impl Into<String>) -> Self {
        Self {
            name: name.into(),
            status: Status::Ok,
            detail: detail.into(),
            fix: None,
        }
    }

    fn warn(name: impl Into<String>, detail: impl Into<String>, fix: impl Into<String>) -> Self {
        Self {
            name: name.into(),
            status: Status::Warn,
            detail: detail.into(),
            fix: Some(fix.into()),
        }
    }

    fn fail(name: impl Into<String>, detail: impl Into<String>, fix: impl Into<String>) -> Self {
        Self {
            name: name.into(),
            status: Status::Fail,
            detail: detail.into(),
            fix: Some(fix.into()),
        }
    }
}

/// Detect local egress IP (UDP connect trick). Used by the web DNS page.
pub fn detect_local_egress_ip() -> Option<String> {
    detect_egress_ip()
}

/// Resolve the mail host for DNS guidance: config `public_host`, else first domain.
pub fn mail_host_for_ui(cfg: &Config) -> String {
    let configured = cfg.public_host_name();
    if !configured.is_empty() {
        return configured;
    }
    let domains = cfg.domains_list();
    let opts = DoctorOpts::default();
    let host = resolve_host(cfg, &opts, &domains);
    // resolve_host follows the domain's currently-published MX. Freshly bought
    // domains often carry registrar parking MX (or leftover Google MX) pointing
    // at a foreign host — advising the user to publish records for someone
    // else's hostname would be wrong. Only trust MX targets inside our domains.
    let ours = domains
        .iter()
        .any(|d| host == *d || host.ends_with(&format!(".{}", d)));
    if ours {
        host
    } else {
        domains
            .first()
            .cloned()
            .unwrap_or_else(|| "localhost".into())
    }
}

/// Best-effort public IP for A-record guidance: this server's address, never a
/// third party's. Priority: router WAN IP (port-mapping discovery) > public
/// egress IP > what the mail host's A record already says.
pub fn suggest_public_ip(_cfg: &Config) -> Option<String> {
    if let Some(pa) = crate::portmap::current() {
        if let Some(ip) = pa.external_ip {
            if crate::portmap::is_public_ipv4(&ip) {
                return Some(ip);
            }
        }
    }
    if let Some(egress) = crate::portmap::local_egress_ip() {
        if crate::portmap::is_public_ipv4(&egress) {
            return Some(egress);
        }
    }
    // No trustworthy address (behind NAT without router discovery). Returning
    // the domain's currently-published A record would suggest someone else's
    // server — better to admit we don't know.
    None
}

/// DNS-only checks for the web UI (no TCP reachability probes). Short timeouts via dns module.
/// Runs domain checks concurrently with std threads.
pub fn run_dns_checks_ui(cfg: &Config, host: &str, public_ip: Option<&str>) -> Vec<Check> {
    ensure_dkim_key_loaded(cfg);
    let domains = cfg.domains_list();
    let selector = cfg.dkim_selector();
    let key = cfg.dkim_key_clone();
    let public_ip_owned = public_ip.map(|s| s.to_string());
    let host_owned = host.trim().trim_end_matches('.').to_lowercase();

    let mut handles = Vec::new();
    for domain in domains {
        let sel = selector.clone();
        let key_c = key.clone();
        let pip = public_ip_owned.clone();
        handles.push(std::thread::spawn(move || {
            let mut out = Vec::new();
            out.push(check_mx(&domain, pip.as_deref()));
            out.push(check_spf(&domain));
            out.push(check_dkim(
                &domain,
                &sel,
                key_c.as_ref(),
                |name| lookup_dkim_txt(name),
            ));
            out.push(check_dmarc(&domain));
            out
        }));
    }
    let host_for_a = host_owned.clone();
    let pip_a = public_ip_owned.clone();
    handles.push(std::thread::spawn(move || {
        vec![check_a_host(&host_for_a, pip_a.as_deref())]
    }));
    if let Some(ref ip) = public_ip_owned {
        let ip = ip.clone();
        let h = host_owned.clone();
        handles.push(std::thread::spawn(move || vec![check_rdns(&ip, &h)]));
    }

    let mut checks = Vec::new();
    for h in handles {
        match h.join() {
            Ok(part) => checks.extend(part),
            Err(_) => checks.push(Check::warn(
                "DNS check",
                "worker thread panicked",
                "Retry Check DNS",
            )),
        }
    }
    checks
}

/// Web-UI checks for serving HTTPS on a purchased domain: A/AAAA record for
/// the host, plus port 80 reachability (needed for the ACME HTTP-01 challenge).
pub fn run_https_checks_ui(cfg: &Config, host: &str) -> Vec<Check> {
    let host = host.trim().trim_end_matches('.').to_lowercase();
    let public_ip = suggest_public_ip(cfg);
    let mut checks = Vec::new();
    checks.push(check_a_host(&host, public_ip.as_deref()));
    // Probe port 80 at the address the domain actually resolves to (what
    // Let's Encrypt will contact), falling back to the detected public IP.
    let probe_ip = dns::resolve_a(&host)
        .ok()
        .and_then(|ips| first_v4(&ips))
        .or(public_ip);
    match probe_ip {
        Some(ip) => {
            checks.push(check_port_80(&ip, true));
            checks.push(check_http01_selfcheck(&host, &ip));
        }
        None => checks.push(Check::warn(
            "port 80 (ACME HTTP-01)",
            "no address to probe — publish the A record first",
            format!(
                "Create an A record for {} pointing at this server's public IP",
                host
            ),
        )),
    }
    checks
}

/// The decisive HTTPS-readiness probe: publish a one-off token on our own
/// ACME challenge path, then fetch it via the domain's public address — the
/// same round-trip Let's Encrypt will make. Passing proves the A record,
/// routing, and port forwarding all reach *this* server (a parked or foreign
/// domain answers on port 80 too, but can't serve our token).
fn check_http01_selfcheck(host: &str, ip: &str) -> Check {
    let name = "domain reaches this server";
    let mut buf = [0u8; 16];
    crate::util::fill_random(&mut buf);
    let token: String = buf.iter().map(|b| format!("{:02x}", b)).collect();
    let token = format!("selfcheck-{}", token);
    let expected = format!("desertemail-{}", token);
    crate::acme::set_http01(&token, &expected);
    let result = http01_fetch(ip, host, &token);
    crate::acme::clear_http01(&token);
    match result {
        Some(body) if body.trim() == expected => Check::ok(
            name,
            format!("{} → {} answers with this server's token", host, ip),
        ),
        Some(_) => Check::fail(
            name,
            format!(
                "{} (via {}) answered on port 80, but with someone else's content — \
                 the domain does not point at this server yet",
                host, ip
            ),
            format!(
                "Set the A record for {} to this server's public IP and remove any \
                 parking/forwarding at your domain provider, then wait for DNS to update",
                host
            ),
        ),
        None => Check::fail(
            name,
            format!(
                "could not fetch a test file from http://{}/ (via {})",
                host, ip
            ),
            "Make sure the A record points at this server and external port 80 is \
             forwarded to it"
                .to_string(),
        ),
    }
}

/// Minimal HTTP/1.1 GET of our ACME challenge path via an explicit IP with a
/// Host header (mirrors what Let's Encrypt does). Returns the response body.
fn http01_fetch(ip: &str, host: &str, token: &str) -> Option<String> {
    use std::io::Write;
    let addr = socket_addr(ip, 80).ok()?;
    let mut stream = TcpStream::connect_timeout(&addr, CONNECT_TIMEOUT).ok()?;
    let _ = stream.set_read_timeout(Some(CONNECT_TIMEOUT));
    let _ = stream.set_write_timeout(Some(CONNECT_TIMEOUT));
    let req = format!(
        "GET /.well-known/acme-challenge/{} HTTP/1.1\r\nHost: {}\r\n\
         Connection: close\r\nUser-Agent: desertemail-selfcheck\r\n\r\n",
        token, host
    );
    stream.write_all(req.as_bytes()).ok()?;
    let mut raw = Vec::new();
    let _ = stream.take(64 * 1024).read_to_end(&mut raw);
    let text = String::from_utf8_lossy(&raw);
    let body = text.split("\r\n\r\n").nth(1).unwrap_or("");
    Some(body.to_string())
}

/// Run all readiness checks. Returns the number of Fail blockers (exit code).
pub fn run(cfg: &Config, opts: &DoctorOpts) -> i32 {
    let cfg = cfg.clone();
    ensure_dkim_key_loaded(&cfg);

    let domains = resolve_domains(&cfg, opts);
    let host = resolve_host(&cfg, opts, &domains);
    let (expected_public_ip, egress_ip, ip_notes) = detect_ips(opts, &host, &domains);

    let mut checks: Vec<Check> = Vec::new();

    // --- Config ---
    checks.extend(check_config_sanity(&cfg));

    // --- DNS (per domain + host) ---
    let dkim_selector = cfg.dkim_selector();
    let dkim_key = cfg.dkim_key_clone();
    for domain in &domains {
        checks.push(check_mx(domain, expected_public_ip.as_deref()));
        checks.push(check_spf(domain));
        checks.push(check_dkim(
            domain,
            &dkim_selector,
            dkim_key.as_ref(),
            |name| lookup_dkim_txt(name),
        ));
        checks.push(check_dmarc(domain));
    }
    checks.push(check_a_host(&host, expected_public_ip.as_deref()));
    if let Some(ref ip) = expected_public_ip {
        checks.push(check_rdns(ip, &host));
    } else {
        checks.push(Check::warn(
            "rDNS / FCrDNS",
            "public IP unknown — cannot check PTR",
            "Pass --public-ip <ip> or publish an A record for the mail host",
        ));
    }

    // IP detection info (informational, never Fail)
    checks.push(ip_info_check(
        expected_public_ip.as_deref(),
        egress_ip.as_deref(),
        &ip_notes,
    ));

    // --- Network ---
    if !opts.no_net {
        checks.push(check_outbound_25());
        if let Some(ref ip) = expected_public_ip {
            checks.push(check_inbound_port(ip, 25, "inbound SMTP :25", b"220"));
            checks.push(check_inbound_port(ip, 587, "inbound submission :587", b"220"));
            checks.push(check_inbound_port(ip, 143, "inbound IMAP :143", b"*"));
            if cfg.acme || (cfg.tls_cert_file.is_none() || cfg.tls_key_file.is_none()) {
                checks.push(check_port_80(ip, cfg.acme));
            }
        } else {
            checks.push(Check::warn(
                "inbound ports",
                "skipped — public IP unknown",
                "Pass --public-ip <ip> so doctor can probe :25/:587/:143",
            ));
        }
    } else {
        checks.push(Check::ok(
            "network probes",
            "skipped (--no-net)",
        ));
    }

    // --- TLS ---
    checks.push(check_tls_cert(&cfg, &host, &domains));

    // Output
    if opts.json {
        print_json(&checks);
    } else {
        print_human(&checks, &host, expected_public_ip.as_deref(), egress_ip.as_deref());
    }

    let blockers = checks.iter().filter(|c| c.status == Status::Fail).count();
    blockers as i32
}

// ---------------------------------------------------------------------------
// Setup helpers
// ---------------------------------------------------------------------------

fn ensure_dkim_key_loaded(cfg: &Config) {
    if cfg.dkim_key_clone().is_some() {
        return;
    }
    if let Some(key_path) = cfg.dkim_key_file_path() {
        if let Ok(key) = crypto::RsaKey::from_pem_file(Path::new(&key_path)) {
            cfg.set_dkim_live(&cfg.dkim_selector(), Some(key_path), Some(key));
        }
    }
}

fn resolve_domains(cfg: &Config, opts: &DoctorOpts) -> Vec<String> {
    if let Some(ref ds) = opts.domains {
        return ds
            .iter()
            .map(|d| d.trim().trim_end_matches('.').to_lowercase())
            .filter(|d| !d.is_empty())
            .collect();
    }
    cfg.domains_list()
        .iter()
        .map(|d| d.trim().trim_end_matches('.').to_lowercase())
        .filter(|d| !d.is_empty())
        .collect()
}

/// Host = --host, else top MX exchange of first domain, else first domain.
fn resolve_host(cfg: &Config, opts: &DoctorOpts, domains: &[String]) -> String {
    if let Some(ref h) = opts.host {
        return h.trim().trim_end_matches('.').to_lowercase();
    }
    if let Some(domain) = domains.first() {
        if let Ok(mxs) = dns::resolve_mx(domain) {
            if let Some(top) = mxs.first() {
                if !top.exchange.is_empty() {
                    return top.exchange.clone();
                }
            }
        }
        return domain.clone();
    }
    let d = cfg.primary_domain();
    if d.is_empty() {
        "localhost".into()
    } else {
        d
    }
}

/// Returns (expected_public_ip, egress_ip, notes).
fn detect_ips(
    opts: &DoctorOpts,
    host: &str,
    domains: &[String],
) -> (Option<String>, Option<String>, Vec<String>) {
    let mut notes = Vec::new();
    let egress = detect_egress_ip();

    // Priority: --public-ip > A of host > A of MX target of first domain
    let mut from_dns: Option<String> = None;
    if let Ok(ips) = dns::resolve_a(host) {
        if let Some(ip) = first_v4(&ips) {
            from_dns = Some(ip);
            notes.push(format!("A({}) = {}", host, from_dns.as_ref().unwrap()));
        }
    }
    if from_dns.is_none() {
        if let Some(domain) = domains.first() {
            if let Ok(mxs) = dns::resolve_mx(domain) {
                if let Some(top) = mxs.first() {
                    if let Ok(ips) = dns::resolve_a(&top.exchange) {
                        if let Some(ip) = first_v4(&ips) {
                            from_dns = Some(ip);
                            notes.push(format!(
                                "A(MX {}) = {}",
                                top.exchange,
                                from_dns.as_ref().unwrap()
                            ));
                        }
                    }
                }
            }
        }
    }

    let expected = if let Some(ref flag) = opts.public_ip {
        let ip = flag.trim().to_string();
        notes.push(format!("--public-ip = {}", ip));
        Some(ip)
    } else {
        from_dns
    };

    if let (Some(ref exp), Some(ref eg)) = (&expected, &egress) {
        if exp != eg && !is_private_ip(eg) {
            notes.push(format!(
                "expected public IP ({}) differs from egress IP ({}) — NAT/port-forwarding may be in play",
                exp, eg
            ));
        } else if exp != eg {
            notes.push(format!(
                "expected public IP ({}) differs from local egress ({}) — likely behind NAT",
                exp, eg
            ));
        }
    }

    (expected, egress, notes)
}

fn first_v4(ips: &[String]) -> Option<String> {
    ips.iter()
        .find(|s| !s.starts_with('[') && s.parse::<std::net::Ipv4Addr>().is_ok())
        .cloned()
}

/// UDP-connect trick: bind, connect to 8.8.8.8:53 without sending, read local_addr.
fn detect_egress_ip() -> Option<String> {
    let sock = UdpSocket::bind("0.0.0.0:0").ok()?;
    sock.connect("8.8.8.8:53").ok()?;
    let local = sock.local_addr().ok()?;
    Some(local.ip().to_string())
}

fn is_private_ip(ip: &str) -> bool {
    match ip.parse::<IpAddr>() {
        Ok(IpAddr::V4(v4)) => {
            v4.is_private() || v4.is_loopback() || v4.is_link_local() || v4.is_unspecified()
        }
        Ok(IpAddr::V6(v6)) => v6.is_loopback() || v6.is_unspecified(),
        Err(_) => false,
    }
}

fn ip_info_check(
    expected: Option<&str>,
    egress: Option<&str>,
    notes: &[String],
) -> Check {
    let detail = match (expected, egress) {
        (Some(e), Some(g)) if e == g => {
            format!("public IP {} (matches egress); {}", e, notes.join("; "))
        }
        (Some(e), Some(g)) => {
            format!(
                "expected public IP {}; detected egress {}; {}",
                e,
                g,
                notes.join("; ")
            )
        }
        (Some(e), None) => format!("expected public IP {}; egress unknown; {}", e, notes.join("; ")),
        (None, Some(g)) => format!("public IP unknown; egress {}; {}", g, notes.join("; ")),
        (None, None) => "public IP and egress unknown".into(),
    };
    // Informational — never Fail.
    if expected.is_some() {
        Check::ok("IP detection", detail)
    } else {
        Check::warn(
            "IP detection",
            detail,
            "Pass --public-ip <ip> or publish A/MX so doctor can compare PTR and inbound ports",
        )
    }
}

// ---------------------------------------------------------------------------
// 1. Config sanity
// ---------------------------------------------------------------------------

fn check_config_sanity(cfg: &Config) -> Vec<Check> {
    let mut out = Vec::new();

    let domains = cfg.domains_list();
    if domains.is_empty() {
        out.push(Check::fail(
            "config domains",
            "domains list is empty",
            "Set domains = [\"your.domain\"] in config.toml",
        ));
    } else {
        out.push(Check::ok(
            "config domains",
            format!("{} domain(s): {}", domains.len(), domains.join(", ")),
        ));
    }

    // Plaintext vs hashed passwords
    let users = match cfg.users.read() {
        Ok(g) => g,
        Err(e) => e.into_inner(),
    };
    let mut plaintext: Vec<String> = Vec::new();
    let mut hashed_n = 0usize;
    for (user, stored) in users.iter() {
        if passwd::is_hashed(stored) {
            hashed_n += 1;
        } else {
            plaintext.push(user.clone());
        }
    }
    if !plaintext.is_empty() {
        out.push(Check::warn(
            "config passwords",
            format!(
                "{} user(s) with plaintext password: {}; {} hashed",
                plaintext.len(),
                plaintext.join(", "),
                hashed_n
            ),
            "Run `desertemail --hash-password` and replace plaintext values in [users]",
        ));
    } else if users.is_empty() {
        out.push(Check::warn(
            "config passwords",
            "no [users] defined",
            "Add users with `desertemail user add <email>` or a [users] section",
        ));
    } else {
        out.push(Check::ok(
            "config passwords",
            format!("{} user(s), all hashed", hashed_n),
        ));
    }

    if cfg.default_password == "changeme" {
        if cfg.allow_default_password_auth {
            out.push(Check::fail(
                "config default_password",
                "default_password is still \"changeme\" and allow_default_password_auth=true",
                "Change default_password (prefer hashed) or set allow_default_password_auth=false",
            ));
        } else {
            out.push(Check::warn(
                "config default_password",
                "default_password is still \"changeme\" (harmless while allow_default_password_auth=false)",
                "Change default_password for defense in depth, or leave allow_default_password_auth=false",
            ));
        }
    } else if cfg.allow_default_password_auth {
        out.push(Check::warn(
            "config default_password_auth",
            "allow_default_password_auth=true — unknown users can authenticate with default_password",
            "Set allow_default_password_auth=false unless you intentionally want a shared password",
        ));
    } else {
        out.push(Check::ok(
            "config default_password",
            "default_password not the factory default; allow_default_password_auth=false",
        ));
    }

    if !cfg.require_tls_for_auth {
        out.push(Check::warn(
            "config require_tls_for_auth",
            "require_tls_for_auth=false — AUTH allowed on plaintext",
            "Set require_tls_for_auth=true for public internet deployments (and enable TLS)",
        ));
    } else {
        out.push(Check::ok(
            "config require_tls_for_auth",
            "AUTH requires TLS",
        ));
    }

    out
}

// ---------------------------------------------------------------------------
// 2. MX
// ---------------------------------------------------------------------------

fn check_mx(domain: &str, public_ip: Option<&str>) -> Check {
    let name = format!("MX {}", domain);
    let mxs = match dns::resolve_mx(domain) {
        Ok(m) => m,
        Err(e) => {
            return Check::fail(
                name,
                format!("DNS error: {}", e),
                format!("Publish an MX record for {} pointing at your mail host", domain),
            );
        }
    };
    if mxs.is_empty() {
        return Check::fail(
            name,
            "no MX records",
            format!(
                "Add MX: {} → mail.{} (or your hostname) at your DNS provider",
                domain, domain
            ),
        );
    }
    let top = &mxs[0];
    let summary: Vec<String> = mxs
        .iter()
        .take(5)
        .map(|m| format!("{}:{}", m.preference, m.exchange))
        .collect();
    let detail_base = format!("top={} pref={}; records=[{}]", top.exchange, top.preference, summary.join(", "));

    if let Some(want) = public_ip {
        match dns::resolve_a(&top.exchange) {
            Ok(ips) if ips.is_empty() => Check::warn(
                name,
                format!("{}; A({}) empty", detail_base, top.exchange),
                format!(
                    "Publish an A record for {} = {}",
                    top.exchange, want
                ),
            ),
            Ok(ips) => {
                let bare: Vec<String> = ips
                    .iter()
                    .map(|s| s.trim_start_matches('[').trim_end_matches(']').to_string())
                    .collect();
                if bare.iter().any(|ip| ip == want) {
                    Check::ok(name, format!("{}; A includes {}", detail_base, want))
                } else {
                    Check::warn(
                        name,
                        format!(
                            "{}; A({})={:?} does not include public IP {}",
                            detail_base, top.exchange, bare, want
                        ),
                        format!(
                            "Point MX exchange {} A record to {}, or update --public-ip",
                            top.exchange, want
                        ),
                    )
                }
            }
            Err(e) => Check::warn(
                name,
                format!("{}; A({}) error: {}", detail_base, top.exchange, e),
                format!("Ensure {} has an A record = {}", top.exchange, want),
            ),
        }
    } else {
        Check::ok(name, detail_base)
    }
}

// ---------------------------------------------------------------------------
// 3. A/AAAA of mail host
// ---------------------------------------------------------------------------

fn check_a_host(host: &str, public_ip: Option<&str>) -> Check {
    let name = format!("A/AAAA {}", host);
    let ips = match dns::resolve_a(host) {
        Ok(i) => i,
        Err(e) => {
            return Check::fail(
                name,
                format!("DNS error: {}", e),
                format!("Publish A (and optionally AAAA) for {}", host),
            );
        }
    };
    if ips.is_empty() {
        return Check::fail(
            name,
            "no A/AAAA records",
            format!("Publish A record: {} → your public IP", host),
        );
    }
    let bare: Vec<String> = ips
        .iter()
        .map(|s| s.trim_start_matches('[').trim_end_matches(']').to_string())
        .collect();
    if let Some(want) = public_ip {
        if bare.iter().any(|ip| ip == want) {
            Check::ok(name, format!("addresses={:?} (includes {})", bare, want))
        } else {
            Check::warn(
                name,
                format!("addresses={:?}; missing expected public IP {}", bare, want),
                format!("Set A record for {} to {}", host, want),
            )
        }
    } else {
        Check::ok(name, format!("addresses={:?}", bare))
    }
}

// ---------------------------------------------------------------------------
// 4. SPF
// ---------------------------------------------------------------------------

fn check_spf(domain: &str) -> Check {
    let name = format!("SPF {}", domain);
    let txts = match dns::resolve_txt(domain) {
        Ok(t) => t,
        Err(e) => {
            return Check::fail(
                name,
                format!("DNS error: {}", e),
                format!("Publish a TXT SPF record on {}", domain),
            );
        }
    };
    let spf: Vec<&String> = txts
        .iter()
        .filter(|t| {
            let s = t.trim();
            s.to_lowercase().starts_with("v=spf1")
        })
        .collect();

    if spf.is_empty() {
        return Check::fail(
            name,
            "no v=spf1 TXT record",
            format!(
                "Publish TXT on {}: v=spf1 mx a ip4:<your-ip> -all  (or ~all while testing)",
                domain
            ),
        );
    }
    if spf.len() > 1 {
        return Check::fail(
            name,
            format!("multiple SPF records ({}) — RFC 7208 §3.2 violation", spf.len()),
            format!(
                "Keep exactly one v=spf1 TXT on {}; merge mechanisms into a single record",
                domain
            ),
        );
    }
    let record = spf[0].as_str();
    let lower = record.to_lowercase();

    // Mechanisms that can authorize this server (or redirect to a full policy).
    let mechanisms_ok = lower.split_whitespace().any(|tok| {
        let t = tok.trim_start_matches(['+', '-', '~', '?']);
        t == "mx"
            || t == "a"
            || t.starts_with("mx:")
            || t.starts_with("a:")
            || t.starts_with("ip4:")
            || t.starts_with("ip6:")
            || t.starts_with("include:")
            || t.starts_with("redirect=")
    });

    let policy = if lower.contains("redirect=") {
        "via redirect"
    } else if lower.contains("-all") {
        "-all (hard fail)"
    } else if lower.contains("~all") {
        "~all (soft fail)"
    } else if lower.contains("?all") {
        "?all (neutral)"
    } else if lower.contains("+all") {
        "+all (pass all — insecure)"
    } else {
        "no explicit all"
    };

    if !mechanisms_ok {
        return Check::warn(
            name,
            format!(
                "found `{}` (policy {}); no mx/a/ip4/ip6/include/redirect — may not authorize this server",
                record, policy
            ),
            "Include mx, a, or ip4:<public-ip> so receivers accept mail from this host; policy: prefer -all after testing".to_string(),
        );
    }

    Check::ok(
        name,
        format!("{} (policy {})", record, policy),
    )
}

// ---------------------------------------------------------------------------
// 5. DKIM (injectable lookup for tests)
// ---------------------------------------------------------------------------

/// Prefer a TXT that looks like DKIM (v=DKIM1 or has p=); else first TXT.
fn lookup_dkim_txt(name: &str) -> Option<String> {
    let txts = dns::resolve_txt(name).ok()?;
    if txts.is_empty() {
        return None;
    }
    txts.iter()
        .find(|t| {
            let l = t.to_lowercase();
            l.contains("v=dkim1") || l.split(';').any(|p| p.trim().starts_with("p="))
        })
        .cloned()
        .or_else(|| txts.into_iter().next())
}

/// Compare local DKIM public key against DNS TXT at `selector._domainkey.domain`.
///
/// `txt_lookup` returns the published TXT string (or None if missing).
/// Exposed for unit tests with a fake lookup.
pub fn check_dkim(
    domain: &str,
    selector: &str,
    key: Option<&crypto::RsaKey>,
    txt_lookup: impl Fn(&str) -> Option<String>,
) -> Check {
    let name = format!("DKIM {} (s={})", domain, selector);
    let dns_name = format!("{}._domainkey.{}", selector, domain);

    let key = match key {
        Some(k) => k,
        None => {
            return Check::warn(
                name,
                "no local DKIM key configured",
                "Generate: openssl genrsa -out dkim.pem 2048; set dkim_key_file + dkim_selector; publish with desertemail --dkim-dns <domain>",
            );
        }
    };

    let expected = dkim::dns_txt_record(key);
    let expected_p = extract_dkim_p(&expected);

    let published = match txt_lookup(&dns_name) {
        Some(t) => t,
        None => {
            return Check::fail(
                name,
                format!("no TXT at {}", dns_name),
                format!(
                    "Publish TXT at {}:\n  {}",
                    dns_name, expected
                ),
            );
        }
    };

    // DNS may return concatenated multi-string TXT; also handle quoted fragments.
    let published_flat = published.replace('\"', "").replace(' ', "");
    // Better: extract p= without removing all spaces from the whole record
    let published_p = extract_dkim_p(&published);

    match (&expected_p, &published_p) {
        (Some(want), Some(got)) if want == got => Check::ok(
            name,
            format!("p= matches at {}", dns_name),
        ),
        (Some(want), Some(got)) => Check::fail(
            name,
            format!(
                "p= mismatch at {} (published p= length {}, expected length {})",
                dns_name,
                got.len(),
                want.len()
            ),
            format!(
                "Update TXT at {} to exactly:\n  {}",
                dns_name, expected
            ),
        ),
        (Some(_), None) => {
            // Published TXT exists but no p= — try substring match of full record
            if published.contains(expected_p.as_deref().unwrap_or(""))
                || published_flat.contains(expected_p.as_deref().unwrap_or(""))
            {
                Check::ok(name, format!("p= found in TXT at {}", dns_name))
            } else {
                Check::fail(
                    name,
                    format!("TXT at {} has no p= tag: {}", dns_name, truncate(&published, 120)),
                    format!(
                        "Publish TXT at {}:\n  {}",
                        dns_name, expected
                    ),
                )
            }
        }
        (None, _) => Check::fail(
            name,
            "local key produced no p= value",
            "Regenerate DKIM key: openssl genrsa -out dkim.pem 2048",
        ),
    }
}

fn extract_dkim_p(txt: &str) -> Option<String> {
    // Parse tag=value; pairs (DKIM-style). Spaces around ; are allowed.
    let mut p = None;
    for part in txt.split(';') {
        let part = part.trim();
        if part.is_empty() {
            continue;
        }
        let mut kv = part.splitn(2, '=');
        let k = kv.next()?.trim();
        let v = kv.next().unwrap_or("").trim();
        if k.eq_ignore_ascii_case("p") {
            // p= may be split across quoted strings; strip whitespace inside
            let cleaned: String = v.chars().filter(|c| !c.is_whitespace() && *c != '"').collect();
            p = Some(cleaned);
        }
    }
    p
}

fn truncate(s: &str, max: usize) -> String {
    if s.len() <= max {
        s.to_string()
    } else {
        format!("{}…", &s[..max])
    }
}

// ---------------------------------------------------------------------------
// 6. DMARC
// ---------------------------------------------------------------------------

fn check_dmarc(domain: &str) -> Check {
    let name = format!("DMARC {}", domain);
    let dmarc_name = format!("_dmarc.{}", domain);
    let txts = match dns::resolve_txt(&dmarc_name) {
        Ok(t) => t,
        Err(e) => {
            return Check::warn(
                name,
                format!("DNS error: {}", e),
                format!(
                    "Publish TXT at {}: v=DMARC1; p=none; rua=mailto:dmarc@{}",
                    dmarc_name, domain
                ),
            );
        }
    };
    let dmarc: Vec<&String> = txts
        .iter()
        .filter(|t| t.trim().to_lowercase().starts_with("v=dmarc1"))
        .collect();
    if dmarc.is_empty() {
        return Check::warn(
            name,
            format!("no v=DMARC1 TXT at {}", dmarc_name),
            format!(
                "Publish TXT at {}: v=DMARC1; p=none; rua=mailto:dmarc@{}  (start with p=none, then quarantine/reject)",
                dmarc_name, domain
            ),
        );
    }
    let record = dmarc[0].as_str();
    let policy = extract_tag(record, "p").unwrap_or_else(|| "?".into());
    Check::ok(
        name,
        format!("{} (p={})", record, policy),
    )
}

fn extract_tag(record: &str, tag: &str) -> Option<String> {
    for part in record.split(';') {
        let part = part.trim();
        let mut kv = part.splitn(2, '=');
        let k = kv.next()?.trim();
        let v = kv.next()?.trim();
        if k.eq_ignore_ascii_case(tag) {
            return Some(v.to_string());
        }
    }
    None
}

// ---------------------------------------------------------------------------
// 7. rDNS / FCrDNS
// ---------------------------------------------------------------------------

fn check_rdns(public_ip: &str, host: &str) -> Check {
    let name = "rDNS / FCrDNS".to_string();
    let ptrs = match dns::resolve_ptr(public_ip) {
        Ok(p) => p,
        Err(e) => {
            return Check::fail(
                name,
                format!("PTR lookup error for {}: {}", public_ip, e),
                format!(
                    "Set reverse DNS (PTR) for {} → {} in your hosting provider's control panel (not your domain DNS)",
                    public_ip, host
                ),
            );
        }
    };
    if ptrs.is_empty() {
        return Check::fail(
            name,
            format!("no PTR for {}", public_ip),
            format!(
                "Set reverse DNS (PTR) for {} → {} in your hosting provider's control panel (DigitalOcean/Hetzner/AWS/etc. — not your domain registrar)",
                public_ip, host
            ),
        );
    }

    let host_l = host.trim_end_matches('.').to_lowercase();
    let mut fcrdns_ok = false;
    let mut host_match = false;
    for ptr in &ptrs {
        let ptr_l = ptr.trim_end_matches('.').to_lowercase();
        if ptr_l == host_l {
            host_match = true;
        }
        if let Ok(ips) = dns::resolve_a(ptr) {
            for ip in ips {
                let bare = ip.trim_start_matches('[').trim_end_matches(']');
                if bare == public_ip {
                    fcrdns_ok = true;
                }
            }
        }
    }

    let detail = format!("PTR={:?}; FCrDNS={}; matches host={} ", ptrs, fcrdns_ok, host_match);

    if fcrdns_ok && host_match {
        Check::ok(name, detail)
    } else if fcrdns_ok {
        Check::warn(
            name,
            format!("{}— PTR does not match mail host `{}`", detail, host),
            format!(
                "In your hosting provider's control panel, set PTR for {} to {} (FCrDNS already OK)",
                public_ip, host
            ),
        )
    } else if !ptrs.is_empty() {
        Check::warn(
            name,
            format!("{}— PTR exists but does not forward-confirm to {}", detail, public_ip),
            format!(
                "In your hosting provider's control panel, set PTR for {} → a name whose A record is {}",
                public_ip, public_ip
            ),
        )
    } else {
        Check::fail(
            name,
            detail,
            format!(
                "Set reverse DNS (PTR) for {} → {} in your hosting provider's control panel",
                public_ip, host
            ),
        )
    }
}

// ---------------------------------------------------------------------------
// 8–10. Network probes
// ---------------------------------------------------------------------------

fn check_outbound_25() -> Check {
    let name = "outbound port 25".to_string();
    // Small set of well-known domains; try gmail first.
    let probe_domains = ["gmail.com", "outlook.com"];
    let mut last_err = String::from("no MX targets tried");

    for domain in &probe_domains {
        let hosts = match dns::smtp_hosts_for_domain(domain) {
            Ok(h) if !h.is_empty() => h,
            Ok(_) => continue,
            Err(e) => {
                last_err = format!("MX {}: {}", domain, e);
                continue;
            }
        };
        for host in hosts.iter().take(3) {
            let ips = match dns::resolve_a(host) {
                Ok(i) if !i.is_empty() => i,
                Ok(_) => continue,
                Err(e) => {
                    last_err = format!("A {}: {}", host, e);
                    continue;
                }
            };
            for ip in ips.iter().take(2) {
                let bare = ip.trim_start_matches('[').trim_end_matches(']');
                match connect_and_banner(bare, 25, b"220") {
                    Ok(banner) => {
                        return Check::ok(
                            name,
                            format!(
                                "connected to {}:25 (via {}), banner: {}",
                                bare,
                                host,
                                truncate(&banner, 60)
                            ),
                        );
                    }
                    Err(e) => {
                        last_err = format!("{}:25 — {}", bare, e);
                    }
                }
            }
        }
    }

    Check::fail(
        name,
        format!("cannot reach remote MX on :25 ({})", last_err),
        "outbound 25 blocked (common on VPS/residential) — configure a smarthost (smarthost = \"smtp.provider:587\")",
    )
}

fn check_inbound_port(public_ip: &str, port: u16, label: &str, expect_prefix: &[u8]) -> Check {
    match connect_and_banner(public_ip, port, expect_prefix) {
        Ok(banner) => Check::ok(
            label.to_string(),
            format!(
                "{}:{} greeting: {}",
                public_ip,
                port,
                truncate(&banner, 60)
            ),
        ),
        Err(e) => Check::warn(
            label.to_string(),
            format!(
                "cannot reach {}:{} ({}) — NAT hairpin may cause false negatives if doctor runs on the same host",
                public_ip, port, e
            ),
            format!(
                "Ensure desertemail listens on 0.0.0.0:{} (or firewall-forwards to it) and confirm with an external port checker (e.g. mxtoolbox, portchecker.co)",
                port
            ),
        ),
    }
}

fn check_port_80(public_ip: &str, acme: bool) -> Check {
    let addr = match socket_addr(public_ip, 80) {
        Ok(a) => a,
        Err(e) => {
            return Check::warn(
                "port 80 (ACME HTTP-01)",
                format!("bad address: {}", e),
                "Pass a valid --public-ip",
            );
        }
    };
    match TcpStream::connect_timeout(&addr, CONNECT_TIMEOUT) {
        Ok(_) => Check::ok(
            "port 80 (ACME HTTP-01)",
            format!(
                "{}:80 reachable{}",
                public_ip,
                if acme { " (acme=true)" } else { "" }
            ),
        ),
        Err(e) => Check::warn(
            "port 80 (ACME HTTP-01)",
            format!("{}:80 not reachable ({})", public_ip, e),
            if acme {
                "ACME HTTP-01 needs port 80 open to the public IP (web_listen or redirect); open firewall/security-group for :80".to_string()
            } else {
                "Port 80 closed — fine without ACME; set acme=true + open :80, or provide tls_cert_file/tls_key_file".to_string()
            },
        ),
    }
}

fn socket_addr(ip: &str, port: u16) -> io::Result<SocketAddr> {
    let ip = ip.trim().trim_start_matches('[').trim_end_matches(']');
    let s = format!("{}:{}", ip, port);
    s.parse()
        .map_err(|e| io::Error::new(io::ErrorKind::InvalidInput, format!("{}: {}", s, e)))
}

fn connect_and_banner(ip: &str, port: u16, expect_prefix: &[u8]) -> Result<String, String> {
    let addr = socket_addr(ip, port).map_err(|e| e.to_string())?;
    let mut stream =
        TcpStream::connect_timeout(&addr, CONNECT_TIMEOUT).map_err(|e| e.to_string())?;
    let _ = stream.set_read_timeout(Some(BANNER_TIMEOUT));
    let _ = stream.set_write_timeout(Some(BANNER_TIMEOUT));
    let mut buf = [0u8; 512];
    let n = stream.read(&mut buf).map_err(|e| e.to_string())?;
    if n == 0 {
        return Err("empty banner".into());
    }
    if !buf[..n].starts_with(expect_prefix) {
        let preview = String::from_utf8_lossy(&buf[..n.min(80)]);
        return Err(format!(
            "unexpected banner (wanted {:?}): {}",
            String::from_utf8_lossy(expect_prefix),
            preview.trim()
        ));
    }
    Ok(String::from_utf8_lossy(&buf[..n]).trim().to_string())
}

// ---------------------------------------------------------------------------
// 11. TLS cert
// ---------------------------------------------------------------------------

fn check_tls_cert(cfg: &Config, host: &str, domains: &[String]) -> Check {
    let name = "TLS certificate".to_string();

    let cert_path = match cfg.tls_cert_file.as_ref() {
        Some(p) => p,
        None => {
            if cfg.acme {
                return Check::warn(
                    name,
                    "no tls_cert_file yet; acme=true will obtain one",
                    "Ensure port 80 is reachable for HTTP-01; cert will auto-renew via ACME",
                );
            }
            return Check::warn(
                name,
                "plaintext only — fine for LAN, not for public internet",
                "Set tls_cert_file + tls_key_file, or acme=true",
            );
        }
    };

    let leaf = match load_leaf_cert_der(cert_path) {
        Ok(d) => d,
        Err(e) => {
            return Check::fail(
                name,
                format!("cannot load {}: {}", cert_path, e),
                "Fix tls_cert_file path or regenerate the certificate",
            );
        }
    };

    let meta = match parse_cert_meta(&leaf) {
        Ok(m) => m,
        Err(e) => {
            return Check::warn(
                name,
                format!("loaded {} but could not parse leaf: {}", cert_path, e),
                "Ensure the file is a PEM X.509 certificate",
            );
        }
    };

    let now = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map(|d| d.as_secs() as i64)
        .unwrap_or(0);
    let not_after = meta.not_after_unix;
    let days_left = (not_after - now) / 86400;

    if days_left < 0 {
        return Check::fail(
            name,
            format!(
                "EXPIRED {} days ago (notAfter unix={})",
                -days_left, not_after
            ),
            if cfg.acme {
                "ACME should renew automatically — check acme logs and port 80; or replace tls_cert_file".to_string()
            } else {
                "Replace tls_cert_file with a new certificate (or enable acme=true)".to_string()
            },
        );
    }

    let mut names_to_cover: Vec<String> = vec![host.to_lowercase()];
    for d in domains {
        names_to_cover.push(d.to_lowercase());
    }
    names_to_cover.sort();
    names_to_cover.dedup();

    let covered = names_to_cover
        .iter()
        .filter(|n| name_matches_cert(n, &meta))
        .count();
    let host_ok = name_matches_cert(host, &meta);

    let sans = if meta.sans.is_empty() {
        meta.cn.clone().unwrap_or_else(|| "(no SAN/CN)".into())
    } else {
        meta.sans.join(", ")
    };

    let mut detail = format!(
        "notAfter in {}d; CN/SAN: {}; host `{}` covered={}",
        days_left, sans, host, host_ok
    );
    if cfg.acme {
        detail.push_str("; acme=true (auto-renew)");
    }

    if days_left < 15 {
        return Check::warn(
            name,
            detail,
            if cfg.acme {
                "Certificate expires in <15 days — ACME should renew soon; verify port 80 and acme worker".to_string()
            } else {
                "Renew the certificate soon (or enable acme=true)".to_string()
            },
        );
    }

    if !host_ok {
        return Check::warn(
            name,
            format!(
                "{}; covered {}/{} configured names",
                detail,
                covered,
                names_to_cover.len()
            ),
            format!(
                "Issue a cert with SAN covering `{}` (and your domains)",
                host
            ),
        );
    }

    Check::ok(name, detail)
}

fn load_leaf_cert_der(path: &str) -> Result<Vec<u8>, String> {
    let f = File::open(path).map_err(|e| format!("open: {}", e))?;
    let mut reader = BufReader::new(f);
    let certs: Result<Vec<_>, _> = rustls_pemfile::certs(&mut reader).collect();
    let certs = certs.map_err(|e| format!("parse PEM: {}", e))?;
    let leaf = certs
        .into_iter()
        .next()
        .ok_or_else(|| "no certificates in file".to_string())?;
    Ok(leaf.as_ref().to_vec())
}

struct CertMeta {
    not_after_unix: i64,
    cn: Option<String>,
    sans: Vec<String>,
}

fn name_matches_cert(name: &str, meta: &CertMeta) -> bool {
    let name = name.trim_end_matches('.').to_lowercase();
    if let Some(ref cn) = meta.cn {
        if dns_name_match(&name, cn) {
            return true;
        }
    }
    meta.sans.iter().any(|s| dns_name_match(&name, s))
}

fn dns_name_match(name: &str, pattern: &str) -> bool {
    let name = name.trim_end_matches('.').to_lowercase();
    let pattern = pattern.trim_end_matches('.').to_lowercase();
    if let Some(rest) = pattern.strip_prefix("*.") {
        // Wildcard: *.example.com matches foo.example.com, not example.com
        if let Some(idx) = name.find('.') {
            return &name[idx + 1..] == rest;
        }
        return false;
    }
    name == pattern
}

/// Minimal X.509 leaf parse: notAfter + CN + dNSName SANs. Defensive DER walk.
fn parse_cert_meta(der: &[u8]) -> Result<CertMeta, String> {
    // Certificate ::= SEQUENCE { tbs, sigAlg, sig }
    let (cert_seq, _) = der_expect_seq(der, 0)?;
    let (tbs, _) = der_expect_seq(der, cert_seq.content_start)?;

    // TBSCertificate fields
    let mut off = tbs.content_start;
    let end = tbs.content_start + tbs.length;

    // optional version [0]
    if off < end && der.get(off) == Some(&0xA0) {
        let (_v, next) = der_skip(der, off)?;
        off = next;
    }
    // serialNumber
    let (_serial, next) = der_skip(der, off)?;
    off = next;
    // signature AlgorithmIdentifier
    let (_alg, next) = der_skip(der, off)?;
    off = next;
    // issuer Name
    let (_issuer, next) = der_skip(der, off)?;
    off = next;
    // validity SEQUENCE { notBefore, notAfter }
    let (validity, next) = der_expect_seq(der, off)?;
    off = next;
    let (nb_tlv, after_nb) = der_read_tlv(der, validity.content_start)?;
    let (_na_tlv, _) = der_read_tlv(der, after_nb)?;
    // notAfter is second Time in validity
    let na_start = after_nb;
    let (na_tlv, _) = der_read_tlv(der, na_start)?;
    let not_after_unix = parse_x509_time(der, &na_tlv)?;
    let _ = nb_tlv; // silence unused

    // subject Name
    let (subject, next) = der_expect_seq(der, off)?;
    off = next;
    let cn = extract_cn_from_name(der, &subject);

    // subjectPublicKeyInfo
    let (_spki, next) = der_skip(der, off)?;
    off = next;

    // optional issuerUniqueID [1], subjectUniqueID [2], extensions [3]
    let mut sans = Vec::new();
    while off < end {
        let tag = *der.get(off).ok_or("truncated DER")?;
        if tag == 0xA3 {
            // extensions [3] EXPLICIT Extensions
            let (ext_wrap, next) = der_read_tlv(der, off)?;
            off = next;
            let (ext_seq, _) = der_expect_seq(der, ext_wrap.content_start)?;
            sans = extract_sans(der, &ext_seq)?;
        } else {
            let (_t, next) = der_skip(der, off)?;
            off = next;
        }
    }

    Ok(CertMeta {
        not_after_unix,
        cn,
        sans,
    })
}

struct DerTlv {
    tag: u8,
    length: usize,
    content_start: usize,
    /// offset after this TLV
    #[allow(dead_code)]
    end: usize,
}

fn der_read_tlv(data: &[u8], off: usize) -> Result<(DerTlv, usize), String> {
    let tag = *data.get(off).ok_or("DER: truncated tag")?;
    let mut i = off + 1;
    let first_len = *data.get(i).ok_or("DER: truncated length")? as usize;
    i += 1;
    let length = if first_len < 0x80 {
        first_len
    } else {
        let n = first_len & 0x7f;
        if n == 0 || n > 4 {
            return Err("DER: unsupported length form".into());
        }
        let mut len = 0usize;
        for _ in 0..n {
            len = (len << 8) | (*data.get(i).ok_or("DER: truncated long length")? as usize);
            i += 1;
        }
        len
    };
    let content_start = i;
    let end = content_start
        .checked_add(length)
        .ok_or("DER: length overflow")?;
    if end > data.len() {
        return Err("DER: content past end".into());
    }
    Ok((
        DerTlv {
            tag,
            length,
            content_start,
            end,
        },
        end,
    ))
}

fn der_skip(data: &[u8], off: usize) -> Result<(DerTlv, usize), String> {
    der_read_tlv(data, off)
}

fn der_expect_seq(data: &[u8], off: usize) -> Result<(DerTlv, usize), String> {
    let (tlv, next) = der_read_tlv(data, off)?;
    if tlv.tag != 0x30 {
        return Err(format!("DER: expected SEQUENCE, got tag 0x{:02x}", tlv.tag));
    }
    Ok((tlv, next))
}

fn parse_x509_time(data: &[u8], tlv: &DerTlv) -> Result<i64, String> {
    let s = std::str::from_utf8(&data[tlv.content_start..tlv.content_start + tlv.length])
        .map_err(|_| "DER: time not UTF-8")?;
    // UTCTime YYMMDDHHMMSSZ  or GeneralizedTime YYYYMMDDHHMMSSZ
    let (year, rest) = if tlv.tag == 0x17 {
        // UTCTime
        if s.len() < 13 {
            return Err("DER: short UTCTime".into());
        }
        let yy: i32 = s[0..2].parse().map_err(|_| "UTCTime year")?;
        let year = if yy >= 50 { 1900 + yy } else { 2000 + yy };
        (year, &s[2..])
    } else if tlv.tag == 0x18 {
        if s.len() < 15 {
            return Err("DER: short GeneralizedTime".into());
        }
        let year: i32 = s[0..4].parse().map_err(|_| "GenTime year")?;
        (year, &s[4..])
    } else {
        return Err(format!("DER: not a Time tag 0x{:02x}", tlv.tag));
    };
    if rest.len() < 11 {
        return Err("DER: short time remainder".into());
    }
    let month: u32 = rest[0..2].parse().map_err(|_| "month")?;
    let day: u32 = rest[2..4].parse().map_err(|_| "day")?;
    let hour: u32 = rest[4..6].parse().map_err(|_| "hour")?;
    let min: u32 = rest[6..8].parse().map_err(|_| "min")?;
    let sec: u32 = rest[8..10].parse().map_err(|_| "sec")?;
    civil_to_unix(year, month, day, hour, min, sec)
}

fn civil_to_unix(year: i32, month: u32, day: u32, hour: u32, min: u32, sec: u32) -> Result<i64, String> {
    // Algorithm from civil_from_days / days_from_civil (Howard Hinnant), UTC.
    if !(1..=12).contains(&month) || day == 0 || day > 31 {
        return Err("invalid date".into());
    }
    let y = if month <= 2 { year - 1 } else { year };
    let era = if y >= 0 { y } else { y - 399 } / 400;
    let yoe = (y - era * 400) as u32;
    let mp = if month > 2 { month - 3 } else { month + 9 };
    let doy = (153 * mp + 2) / 5 + day - 1;
    let doe = yoe * 365 + yoe / 4 - yoe / 100 + doy;
    let days = (era as i64) * 146097 + doe as i64 - 719468;
    Ok(days * 86400 + (hour as i64) * 3600 + (min as i64) * 60 + sec as i64)
}

fn extract_cn_from_name(data: &[u8], name_seq: &DerTlv) -> Option<String> {
    // Name ::= SEQUENCE OF RelativeDistinguishedName
    // RDN ::= SET OF AttributeTypeAndValue
    // ATV ::= SEQUENCE { OID, value }
    let mut off = name_seq.content_start;
    let end = name_seq.content_start + name_seq.length;
    let cn_oid: &[u8] = &[0x55, 0x04, 0x03]; // 2.5.4.3
    while off < end {
        let (rdn, next) = der_read_tlv(data, off).ok()?;
        off = next;
        // RDN is SET (0x31) or sometimes SEQUENCE
        let mut roff = rdn.content_start;
        let rend = rdn.content_start + rdn.length;
        while roff < rend {
            let (atv, rnext) = der_read_tlv(data, roff).ok()?;
            roff = rnext;
            if atv.tag != 0x30 {
                continue;
            }
            let (oid_tlv, after_oid) = der_read_tlv(data, atv.content_start).ok()?;
            if oid_tlv.tag != 0x06 {
                continue;
            }
            let oid = &data[oid_tlv.content_start..oid_tlv.content_start + oid_tlv.length];
            if oid == cn_oid {
                let (val, _) = der_read_tlv(data, after_oid).ok()?;
                let s = String::from_utf8_lossy(
                    &data[val.content_start..val.content_start + val.length],
                )
                .to_string();
                return Some(s);
            }
        }
    }
    None
}

fn extract_sans(data: &[u8], ext_seq: &DerTlv) -> Result<Vec<String>, String> {
    // Extensions ::= SEQUENCE OF Extension
    // Extension ::= SEQUENCE { extnID OID, critical BOOLEAN OPTIONAL, extnValue OCTET STRING }
    let san_oid: &[u8] = &[0x55, 0x1d, 0x11]; // 2.5.29.17
    let mut sans = Vec::new();
    let mut off = ext_seq.content_start;
    let end = ext_seq.content_start + ext_seq.length;
    while off < end {
        let (ext, next) = der_expect_seq(data, off)?;
        off = next;
        let (oid_tlv, mut eoff) = der_read_tlv(data, ext.content_start)?;
        if oid_tlv.tag != 0x06 {
            continue;
        }
        let oid = &data[oid_tlv.content_start..oid_tlv.content_start + oid_tlv.length];
        // optional critical BOOLEAN
        if eoff < ext.content_start + ext.length {
            if data.get(eoff) == Some(&0x01) {
                let (_b, n) = der_skip(data, eoff)?;
                eoff = n;
            }
        }
        let (val, _) = der_read_tlv(data, eoff)?;
        if val.tag != 0x04 {
            continue; // OCTET STRING
        }
        if oid != san_oid {
            continue;
        }
        // extnValue is OCTET STRING wrapping GeneralNames SEQUENCE
        let (gn_seq, _) = der_expect_seq(data, val.content_start)?;
        let mut goff = gn_seq.content_start;
        let gend = gn_seq.content_start + gn_seq.length;
        while goff < gend {
            let (gn, gnext) = der_read_tlv(data, goff)?;
            goff = gnext;
            // dNSName [2] IA5String = context-specific primitive tag 0x82
            if gn.tag == 0x82 {
                let s = String::from_utf8_lossy(
                    &data[gn.content_start..gn.content_start + gn.length],
                )
                .to_string();
                sans.push(s);
            }
        }
    }
    Ok(sans)
}

// ---------------------------------------------------------------------------
// Output
// ---------------------------------------------------------------------------

fn use_color() -> bool {
    if env::var_os("NO_COLOR").is_some() {
        return false;
    }
    io::stdout().is_terminal()
}

fn print_human(checks: &[Check], host: &str, public_ip: Option<&str>, egress: Option<&str>) {
    let color = use_color();
    println!("DesertEmail doctor — deployment readiness");
    println!(
        "  host={}  public_ip={}  egress={}",
        host,
        public_ip.unwrap_or("?"),
        egress.unwrap_or("?")
    );
    println!();

    let mut last_group = "";
    for c in checks {
        let group = group_for(&c.name);
        if group != last_group {
            println!("── {} ──", group);
            last_group = group;
        }
        let glyph = match c.status {
            Status::Ok => {
                if color {
                    "\x1b[32m✓\x1b[0m"
                } else {
                    "ok"
                }
            }
            Status::Warn => {
                if color {
                    "\x1b[33m⚠\x1b[0m"
                } else {
                    "warn"
                }
            }
            Status::Fail => {
                if color {
                    "\x1b[31m✗\x1b[0m"
                } else {
                    "FAIL"
                }
            }
        };
        println!("  {} {} — {}", glyph, c.name, c.detail);
        if let Some(ref fix) = c.fix {
            if c.status != Status::Ok {
                for line in fix.lines() {
                    println!("      → fix: {}", line);
                }
            }
        }
    }

    let blockers = checks.iter().filter(|c| c.status == Status::Fail).count();
    let warnings = checks.iter().filter(|c| c.status == Status::Warn).count();
    println!();
    println!("VERDICT: {} blocker(s), {} warning(s)", blockers, warnings);
    if blockers > 0 {
        println!("Not ready: fix the red items");
    } else if warnings > 0 {
        println!("Ready to deliver (with warnings — review yellow items)");
    } else {
        println!("Ready to deliver");
    }
}

fn group_for(name: &str) -> &'static str {
    if name.starts_with("config") {
        "Config"
    } else if name.starts_with("MX")
        || name.starts_with("A/")
        || name.starts_with("SPF")
        || name.starts_with("DKIM")
        || name.starts_with("DMARC")
        || name.starts_with("rDNS")
        || name.starts_with("IP ")
    {
        "DNS"
    } else if name.starts_with("outbound")
        || name.starts_with("inbound")
        || name.starts_with("port 80")
        || name.starts_with("network")
    {
        "Network"
    } else if name.starts_with("TLS") {
        "TLS"
    } else {
        "Other"
    }
}

fn print_json(checks: &[Check]) {
    // Minimal JSON without extra crates
    print!("[");
    for (i, c) in checks.iter().enumerate() {
        if i > 0 {
            print!(",");
        }
        print!("{{\"name\":");
        print_json_str(&c.name);
        print!(",\"status\":\"{}\",\"detail\":", c.status.as_str());
        print_json_str(&c.detail);
        print!(",\"fix\":");
        match &c.fix {
            Some(f) => print_json_str(f),
            None => print!("null"),
        }
        print!("}}");
    }
    println!("]");
}

fn print_json_str(s: &str) {
    print!("\"");
    for ch in s.chars() {
        match ch {
            '"' => print!("\\\""),
            '\\' => print!("\\\\"),
            '\n' => print!("\\n"),
            '\r' => print!("\\r"),
            '\t' => print!("\\t"),
            c if (c as u32) < 0x20 => print!("\\u{:04x}", c as u32),
            c => print!("{}", c),
        }
    }
    print!("\"");
}

// ---------------------------------------------------------------------------
// Unit tests
// ---------------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use super::*;
    use crate::crypto::RsaKey;

    fn test_key() -> RsaKey {
        // Small key for speed in tests — generate once per test invocation.
        RsaKey::generate(1024).expect("generate test key")
    }

    #[test]
    fn dkim_match_ok_when_published_equals_expected() {
        let key = test_key();
        let expected = dkim::dns_txt_record(&key);
        let domain = "example.com";
        let selector = "mail";
        let dns_name = format!("{}._domainkey.{}", selector, domain);
        let expected_clone = expected.clone();
        let check = check_dkim(domain, selector, Some(&key), |name| {
            if name == dns_name {
                Some(expected_clone.clone())
            } else {
                None
            }
        });
        assert_eq!(check.status, Status::Ok, "detail={}", check.detail);
    }

    #[test]
    fn dkim_fail_when_p_mismatches() {
        let key = test_key();
        let expected = dkim::dns_txt_record(&key);
        let domain = "example.com";
        let selector = "mail";
        let wrong = "v=DKIM1; k=rsa; p=AAAAWRONGKEYMATERIALBBBB";
        let check = check_dkim(domain, selector, Some(&key), |_name| Some(wrong.into()));
        assert_eq!(check.status, Status::Fail, "detail={}", check.detail);
        let fix = check.fix.expect("fix string");
        assert!(
            fix.contains(&expected) || fix.contains("p="),
            "fix should print the exact record to publish: {}",
            fix
        );
        // Ensure expected p= is in the fix
        let exp_p = extract_dkim_p(&expected).unwrap();
        assert!(
            fix.contains(&exp_p),
            "fix must include expected p= value"
        );
    }

    #[test]
    fn dkim_fail_when_missing() {
        let key = test_key();
        let expected = dkim::dns_txt_record(&key);
        let check = check_dkim("example.com", "mail", Some(&key), |_name| None);
        assert_eq!(check.status, Status::Fail);
        let fix = check.fix.unwrap();
        assert!(fix.contains(&expected));
    }

    #[test]
    fn dkim_warn_when_no_key() {
        let check = check_dkim("example.com", "mail", None, |_| None);
        assert_eq!(check.status, Status::Warn);
    }

    #[test]
    fn dkim_dns_txt_matches_extract_p() {
        let key = test_key();
        let txt = dkim::dns_txt_record(&key);
        assert!(txt.starts_with("v=DKIM1; k=rsa; p="));
        let p = extract_dkim_p(&txt).expect("p=");
        assert!(!p.is_empty());
        // Re-extract from the same string after "publishing" with spaces
        let published = format!("v=DKIM1; k=rsa; p={}", p);
        assert_eq!(extract_dkim_p(&published).as_deref(), Some(p.as_str()));
    }

    #[test]
    fn extract_dkim_p_handles_whitespace_in_p() {
        let p = extract_dkim_p("v=DKIM1; k=rsa; p=AB CD\nEF").unwrap();
        assert_eq!(p, "ABCDEF");
    }

    #[test]
    fn config_sanity_flags_plaintext_and_changeme() {
        let mut cfg = Config::default();
        *cfg.domains.write().unwrap() = vec!["example.com".into()];
        cfg.default_password = "changeme".into();
        cfg.allow_default_password_auth = false;
        cfg.require_tls_for_auth = false;
        cfg.users
            .write()
            .unwrap()
            .insert("alice".into(), "plaintext-secret".into());
        let checks = check_config_sanity(&cfg);
        assert!(
            checks.iter().any(|c| c.name.contains("password") && c.status == Status::Warn),
            "expected plaintext password warn: {:?}",
            checks
        );
        assert!(
            checks
                .iter()
                .any(|c| c.name.contains("default_password") && c.status == Status::Warn),
            "expected changeme warn: {:?}",
            checks
        );
        assert!(
            checks
                .iter()
                .any(|c| c.name.contains("require_tls") && c.status == Status::Warn),
            "expected require_tls warn: {:?}",
            checks
        );
    }

    #[test]
    fn dns_name_match_wildcard() {
        assert!(dns_name_match("mail.example.com", "*.example.com"));
        assert!(!dns_name_match("example.com", "*.example.com"));
        assert!(dns_name_match("mail.example.com", "mail.example.com"));
    }
}
