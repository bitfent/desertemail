//! ACME v2 (RFC 8555) client for automatic TLS certificates (Let's Encrypt).
//!
//! Uses rustls client TLS + our RSA (RS256 JWS) + hand-rolled HTTP/1.1.
//! HTTP-01 challenges are served via the webmail server (`web` module shared map).
//!
//! Live issuance requires a public domain with port 80 reachable. Unit tests cover
//! JWS construction and CSR DER encoding only.
//!
//! Staging directory (recommended for first tests):
//!   acme_directory = "https://acme-staging-v02.api.letsencrypt.org/directory"

use std::collections::HashMap;
use std::fs;
use std::io::{BufRead, BufReader, Read, Write};
use std::net::TcpStream;
use std::path::{Path, PathBuf};
use std::sync::{Arc, Mutex, OnceLock};
use std::thread;
use std::time::Duration;

use crate::config::Config;
use crate::crypto::{self, RsaKey};
use crate::tls;
use crate::util;

/// Pending HTTP-01 tokens: token → key authorization string.
fn http01_tokens() -> &'static Mutex<HashMap<String, String>> {
    static M: OnceLock<Mutex<HashMap<String, String>>> = OnceLock::new();
    M.get_or_init(|| Mutex::new(HashMap::new()))
}

/// Register a challenge response for the web server to serve.
pub fn set_http01(token: &str, key_auth: &str) {
    if let Ok(mut m) = http01_tokens().lock() {
        m.insert(token.to_string(), key_auth.to_string());
    }
}

pub fn clear_http01(token: &str) {
    if let Ok(mut m) = http01_tokens().lock() {
        m.remove(token);
    }
}

/// Look up key authorization for `/.well-known/acme-challenge/<token>`.
pub fn get_http01(token: &str) -> Option<String> {
    http01_tokens().lock().ok()?.get(token).cloned()
}

/// Spawn background ACME issuance/renewal if `cfg.acme` is true.
/// Does not block startup. Re-checks every 12 hours; renews when cert expires in <30 days.
pub fn start_background(cfg: Arc<Config>) {
    if !cfg.acme {
        return;
    }
    thread::spawn(move || {
        // Small delay so listeners (esp. web :80) are up.
        thread::sleep(Duration::from_secs(2));
        loop {
            if crate::shutdown::is_shutdown() {
                break;
            }
            match ensure_certificate(&cfg) {
                Ok(msg) => util::log!("ACME: {}", msg),
                Err(e) => util::log_error!("ACME: issuance/renewal failed: {}", e),
            }
            // Sleep 12h in small chunks so we notice shutdown.
            for _ in 0..12 * 60 {
                if crate::shutdown::is_shutdown() {
                    return;
                }
                thread::sleep(Duration::from_secs(60));
            }
        }
    });
}

/// Run issuance if cert missing or expiring within 30 days.
pub fn ensure_certificate(cfg: &Config) -> Result<String, String> {
    let cert_path = cfg
        .tls_cert_file
        .as_ref()
        .ok_or("acme=true requires tls_cert_file")?;
    let key_path = cfg
        .tls_key_file
        .as_ref()
        .ok_or("acme=true requires tls_key_file")?;
    let domains = if cfg.acme_domains.is_empty() {
        cfg.domains_list()
    } else {
        cfg.acme_domains.clone()
    };
    if domains.is_empty() {
        return Err("no acme_domains / domains configured".into());
    }
    if cfg.acme_email.is_empty() {
        return Err("acme_email is required when acme=true".into());
    }

    if !needs_renewal(cert_path, 30) {
        return Ok(format!("certificate {} still valid (>30d)", cert_path));
    }

    util::log!(
        "ACME: obtaining certificate for {:?} via {}",
        domains,
        cfg.acme_directory
    );
    issue(cfg, &domains, cert_path, key_path)?;
    Ok(format!("certificate written to {}", cert_path))
}

fn needs_renewal(cert_path: &str, days: u64) -> bool {
    let path = Path::new(cert_path);
    if !path.exists() {
        return true;
    }
    // Parse notAfter from PEM via openssl if available; else renew if file older than 60d.
    if let Some(expiry) = cert_not_after_secs(path) {
        let now = util::now_secs();
        return expiry < now.saturating_add(days * 86400);
    }
    // Fallback: renew if mtime older than 60 days
    if let Ok(md) = fs::metadata(path) {
        if let Ok(modif) = md.modified() {
            if let Ok(age) = modif.elapsed() {
                return age.as_secs() > 60 * 86400;
            }
        }
    }
    true
}

fn cert_not_after_secs(path: &Path) -> Option<u64> {
    // openssl x509 -enddate -noout -in cert
    let out = std::process::Command::new("openssl")
        .args(["x509", "-enddate", "-noout", "-in"])
        .arg(path)
        .output()
        .ok()?;
    if !out.status.success() {
        return None;
    }
    let s = String::from_utf8_lossy(&out.stdout);
    // notAfter=Mar 15 12:00:00 2025 GMT
    let line = s.lines().next()?;
    let date = line.strip_prefix("notAfter=")?;
    parse_openssl_date(date)
}

fn parse_openssl_date(s: &str) -> Option<u64> {
    // Mon DD HH:MM:SS YYYY GMT
    let parts: Vec<&str> = s.split_whitespace().collect();
    if parts.len() < 5 {
        return None;
    }
    let mon = match parts[0] {
        "Jan" => 1,
        "Feb" => 2,
        "Mar" => 3,
        "Apr" => 4,
        "May" => 5,
        "Jun" => 6,
        "Jul" => 7,
        "Aug" => 8,
        "Sep" => 9,
        "Oct" => 10,
        "Nov" => 11,
        "Dec" => 12,
        _ => return None,
    };
    let day: u32 = parts[1].parse().ok()?;
    let time: Vec<&str> = parts[2].split(':').collect();
    if time.len() != 3 {
        return None;
    }
    let h: u64 = time[0].parse().ok()?;
    let mi: u64 = time[1].parse().ok()?;
    let sec: u64 = time[2].parse().ok()?;
    let year: i32 = parts[3].parse().ok()?;
    let days = util::days_from_civil(year, mon, day);
    if days < 0 {
        return None;
    }
    Some((days as u64) * 86400 + h * 3600 + mi * 60 + sec)
}

fn issue(cfg: &Config, domains: &[String], cert_path: &str, key_path: &str) -> Result<(), String> {
    let account_dir = PathBuf::from(&cfg.data_dir).join("acme");
    fs::create_dir_all(&account_dir).map_err(|e| format!("acme dir: {}", e))?;
    let account_key_path = account_dir.join("account.key");

    let account_key = if account_key_path.exists() {
        RsaKey::from_pem_file(&account_key_path)?
    } else {
        util::log!("ACME: generating account RSA key (may take a moment)...");
        let k = RsaKey::generate(2048)?;
        fs::write(&account_key_path, k.to_pem_pkcs1()).map_err(|e| e.to_string())?;
        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt;
            let _ = fs::set_permissions(&account_key_path, fs::Permissions::from_mode(0o600));
        }
        k
    };

    let dir_url = cfg.acme_directory.trim_end_matches('/').to_string();
    let directory = http_get_json(&dir_url)?;
    let new_nonce = json_str(&directory, "newNonce")?;
    let new_account = json_str(&directory, "newAccount")?;
    let new_order = json_str(&directory, "newOrder")?;

    let mut nonce = fetch_nonce(&new_nonce)?;

    // newAccount
    let contact = format!("mailto:{}", cfg.acme_email);
    let payload = format!(
        "{{\"termsOfServiceAgreed\":true,\"contact\":[\"{}\"]}}",
        util::json_escape(&contact)
    );
    let (acct_resp, acct_headers, new_nonce_h) = jws_post(
        &new_account,
        &payload,
        &account_key,
        None,
        &nonce,
        true, // jwk in protected
    )?;
    nonce = new_nonce_h.unwrap_or(nonce);
    let account_url = acct_headers
        .get("location")
        .cloned()
        .or_else(|| json_str(&acct_resp, "url").ok())
        .ok_or("ACME: no account Location")?;
    util::log!("ACME: account {}", account_url);

    // newOrder
    let mut idents = String::from("[");
    for (i, d) in domains.iter().enumerate() {
        if i > 0 {
            idents.push(',');
        }
        idents.push_str(&format!(
            "{{\"type\":\"dns\",\"value\":\"{}\"}}",
            util::json_escape(d)
        ));
    }
    idents.push(']');
    let order_payload = format!("{{\"identifiers\":{}}}", idents);
    let (order_body, order_headers, new_nonce_h) = jws_post(
        &new_order,
        &order_payload,
        &account_key,
        Some(&account_url),
        &nonce,
        false,
    )?;
    nonce = new_nonce_h.unwrap_or(nonce);
    let order_url = order_headers
        .get("location")
        .cloned()
        .ok_or("ACME: no order Location")?;

    // Authorizations
    let authz_urls = json_str_array(&order_body, "authorizations")?;
    for authz_url in &authz_urls {
        let (authz, _, nn) = jws_post(
            authz_url,
            "",
            &account_key,
            Some(&account_url),
            &nonce,
            false,
        )?;
        // POST-as-GET uses empty payload → ""
        nonce = nn.unwrap_or(nonce);

        // Find http-01 challenge
        let challenges = extract_challenges(&authz)?;
        let http01 = challenges
            .iter()
            .find(|c| c.0 == "http-01")
            .ok_or("ACME: no http-01 challenge")?;
        let (ctype, token, chall_url) = http01;
        let _ = ctype;
        let thumb = jwk_thumbprint(&account_key)?;
        let key_auth = format!("{}.{}", token, thumb);
        set_http01(token, &key_auth);
        util::log!(
            "ACME: HTTP-01 ready at /.well-known/acme-challenge/{}",
            token
        );

        // Notify ACME to validate
        let (chal_resp, _, nn) = jws_post(
            chall_url,
            "{}",
            &account_key,
            Some(&account_url),
            &nonce,
            false,
        )?;
        nonce = nn.unwrap_or(nonce);
        let _ = chal_resp;

        // Poll challenge / authz until valid
        for _ in 0..60 {
            thread::sleep(Duration::from_secs(2));
            if crate::shutdown::is_shutdown() {
                clear_http01(token);
                return Err("shutdown during ACME".into());
            }
            let (a2, _, nn) = jws_post(
                authz_url,
                "",
                &account_key,
                Some(&account_url),
                &nonce,
                false,
            )?;
            nonce = nn.unwrap_or(nonce);
            let status = json_str(&a2, "status").unwrap_or_default();
            if status == "valid" {
                break;
            }
            if status == "invalid" {
                clear_http01(token);
                return Err(format!("ACME: authorization invalid: {}", a2));
            }
        }
        clear_http01(token);
    }

    // Finalize
    let finalize = json_str(&order_body, "finalize")?;
    util::log!("ACME: generating leaf key + CSR...");
    let leaf_key = RsaKey::generate(2048)?;
    let cn = domains[0].clone();
    let csr_der = leaf_key.build_csr_der(&cn, domains)?;
    let csr_b64 = util::base64url_encode(&csr_der);
    let fin_payload = format!("{{\"csr\":\"{}\"}}", csr_b64);
    let (fin_body, _, nn) = jws_post(
        &finalize,
        &fin_payload,
        &account_key,
        Some(&account_url),
        &nonce,
        false,
    )?;
    nonce = nn.unwrap_or(nonce);

    // Poll order for certificate URL
    let mut cert_url = json_str(&fin_body, "certificate").ok();
    for _ in 0..60 {
        if cert_url.is_some() {
            break;
        }
        thread::sleep(Duration::from_secs(2));
        let (ob, _, nn) = jws_post(
            &order_url,
            "",
            &account_key,
            Some(&account_url),
            &nonce,
            false,
        )?;
        nonce = nn.unwrap_or(nonce);
        let st = json_str(&ob, "status").unwrap_or_default();
        if st == "valid" {
            cert_url = json_str(&ob, "certificate").ok();
            break;
        }
        if st == "invalid" {
            return Err(format!("ACME: order invalid: {}", ob));
        }
    }
    let cert_url = cert_url.ok_or("ACME: no certificate URL")?;

    // Download certificate (POST-as-GET)
    let (cert_pem, _, _) = jws_post_raw(
        &cert_url,
        "",
        &account_key,
        Some(&account_url),
        &nonce,
        false,
    )?;
    // cert_pem should be PEM chain text
    let cert_text = if cert_pem.starts_with("-----") {
        cert_pem
    } else {
        // might be binary — unlikely for LE
        String::from_utf8_lossy(cert_pem.as_bytes()).into_owned()
    };

    if let Some(parent) = Path::new(cert_path).parent() {
        let _ = fs::create_dir_all(parent);
    }
    if let Some(parent) = Path::new(key_path).parent() {
        let _ = fs::create_dir_all(parent);
    }
    fs::write(cert_path, cert_text.as_bytes()).map_err(|e| format!("write cert: {}", e))?;
    fs::write(key_path, leaf_key.to_pem_pkcs1()).map_err(|e| format!("write key: {}", e))?;
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        let _ = fs::set_permissions(key_path, fs::Permissions::from_mode(0o600));
    }
    util::log!("ACME: wrote cert {} and key {}", cert_path, key_path);
    Ok(())
}

// ---------------------------------------------------------------------------
// JWS RS256
// ---------------------------------------------------------------------------

/// Build JWS protected header + signing input pieces (for tests).
pub fn jws_signing_input(protected_b64: &str, payload_b64: &str) -> String {
    format!("{}.{}", protected_b64, payload_b64)
}

/// Construct flattened JWS JSON body for ACME.
pub fn build_jws(
    key: &RsaKey,
    url: &str,
    nonce: &str,
    payload: &str,
    kid: Option<&str>,
    use_jwk: bool,
) -> Result<String, String> {
    let protected = if use_jwk {
        let jwk = rsa_jwk(key)?;
        format!(
            "{{\"alg\":\"RS256\",\"jwk\":{},\"nonce\":\"{}\",\"url\":\"{}\"}}",
            jwk,
            util::json_escape(nonce),
            util::json_escape(url)
        )
    } else {
        let kid = kid.ok_or("kid required when not using jwk")?;
        format!(
            "{{\"alg\":\"RS256\",\"kid\":\"{}\",\"nonce\":\"{}\",\"url\":\"{}\"}}",
            util::json_escape(kid),
            util::json_escape(nonce),
            util::json_escape(url)
        )
    };
    let protected_b64 = util::base64url_encode(protected.as_bytes());
    // Empty payload for POST-as-GET is empty string → base64url of empty = empty
    let payload_b64 = if payload.is_empty() {
        String::new()
    } else {
        util::base64url_encode(payload.as_bytes())
    };
    let input = jws_signing_input(&protected_b64, &payload_b64);
    let sig = key.sign_sha256(input.as_bytes())?;
    let sig_b64 = util::base64url_encode(&sig);
    Ok(format!(
        "{{\"protected\":\"{}\",\"payload\":\"{}\",\"signature\":\"{}\"}}",
        protected_b64, payload_b64, sig_b64
    ))
}

fn rsa_jwk(key: &RsaKey) -> Result<String, String> {
    let n = util::base64url_encode(&key.n.to_be_bytes());
    let e = util::base64url_encode(&key.e.to_be_bytes());
    Ok(format!(
        "{{\"kty\":\"RSA\",\"n\":\"{}\",\"e\":\"{}\"}}",
        n, e
    ))
}

/// JWK thumbprint (RFC 7638) over required members sorted: e, kty, n.
pub fn jwk_thumbprint(key: &RsaKey) -> Result<String, String> {
    let n = util::base64url_encode(&key.n.to_be_bytes());
    let e = util::base64url_encode(&key.e.to_be_bytes());
    let canon = format!(
        "{{\"e\":\"{}\",\"kty\":\"RSA\",\"n\":\"{}\"}}",
        e, n
    );
    let hash = crypto::sha256(canon.as_bytes());
    Ok(util::base64url_encode(&hash))
}

// ---------------------------------------------------------------------------
// Minimal HTTPS client
// ---------------------------------------------------------------------------

fn parse_url(url: &str) -> Result<(String, String, String), String> {
    let url = url.trim();
    let rest = url
        .strip_prefix("https://")
        .ok_or("ACME only supports https URLs")?;
    let (hostport, path) = match rest.find('/') {
        Some(i) => (&rest[..i], &rest[i..]),
        None => (rest, "/"),
    };
    let host = hostport
        .split(':')
        .next()
        .unwrap_or(hostport)
        .to_string();
    Ok((host, hostport.to_string(), path.to_string()))
}

fn http_get_json(url: &str) -> Result<String, String> {
    let (body, _, _) = http_exchange("GET", url, None, &[])?;
    Ok(body)
}

fn fetch_nonce(new_nonce_url: &str) -> Result<String, String> {
    let (_, headers, _) = http_exchange("HEAD", new_nonce_url, None, &[])?;
    headers
        .get("replay-nonce")
        .cloned()
        .ok_or_else(|| "no Replay-Nonce on newNonce".into())
}

fn jws_post(
    url: &str,
    payload: &str,
    key: &RsaKey,
    kid: Option<&str>,
    nonce: &str,
    use_jwk: bool,
) -> Result<(String, HashMap<String, String>, Option<String>), String> {
    let (body, headers, _) = jws_post_raw(url, payload, key, kid, nonce, use_jwk)?;
    let nn = headers.get("replay-nonce").cloned();
    Ok((body, headers, nn))
}

fn jws_post_raw(
    url: &str,
    payload: &str,
    key: &RsaKey,
    kid: Option<&str>,
    nonce: &str,
    use_jwk: bool,
) -> Result<(String, HashMap<String, String>, Option<String>), String> {
    let body = build_jws(key, url, nonce, payload, kid, use_jwk)?;
    let (resp_body, headers, _) = http_exchange(
        "POST",
        url,
        Some(body.as_bytes()),
        &[("Content-Type", "application/jose+json")],
    )?;
    let nn = headers.get("replay-nonce").cloned();
    Ok((resp_body, headers, nn))
}

fn http_exchange(
    method: &str,
    url: &str,
    body: Option<&[u8]>,
    extra_headers: &[(&str, &str)],
) -> Result<(String, HashMap<String, String>, u16), String> {
    let (host, hostport, path) = parse_url(url)?;
    let port: u16 = if hostport.contains(':') {
        hostport
            .rsplit(':')
            .next()
            .and_then(|p| p.parse().ok())
            .unwrap_or(443)
    } else {
        443
    };
    let addr = format!("{}:{}", host, port);
    use std::net::ToSocketAddrs;
    let sock = addr
        .to_socket_addrs()
        .map_err(|e| format!("resolve {}: {}", addr, e))?
        .next()
        .ok_or_else(|| format!("resolve {}", addr))?;
    let stream = TcpStream::connect_timeout(&sock, Duration::from_secs(30))
        .map_err(|e| format!("connect {}: {}", addr, e))?;
    let _ = stream.set_read_timeout(Some(Duration::from_secs(60)));
    let _ = stream.set_write_timeout(Some(Duration::from_secs(60)));
    let mut tls = tls::connect_tls(stream, &host).map_err(|e| format!("TLS: {}", e))?;

    let mut req = format!(
        "{} {} HTTP/1.1\r\nHost: {}\r\nUser-Agent: desertemail-acme/0.1\r\nConnection: close\r\n",
        method, path, host
    );
    if let Some(b) = body {
        req.push_str(&format!("Content-Length: {}\r\n", b.len()));
    } else if method == "POST" {
        req.push_str("Content-Length: 0\r\n");
    }
    for (k, v) in extra_headers {
        req.push_str(&format!("{}: {}\r\n", k, v));
    }
    req.push_str("\r\n");
    tls.write_all(req.as_bytes())
        .map_err(|e| format!("write: {}", e))?;
    if let Some(b) = body {
        tls.write_all(b).map_err(|e| format!("write body: {}", e))?;
    }
    tls.flush().map_err(|e| e.to_string())?;

    let mut reader = BufReader::new(tls);
    let status_line = util::read_line(&mut reader)
        .map_err(|e| e.to_string())?
        .ok_or("EOF status")?;
    let status: u16 = status_line
        .split_whitespace()
        .nth(1)
        .and_then(|s| s.parse().ok())
        .unwrap_or(0);

    let mut headers = HashMap::new();
    let mut content_length: Option<usize> = None;
    let mut chunked = false;
    loop {
        let line = util::read_line(&mut reader)
            .map_err(|e| e.to_string())?
            .ok_or("EOF headers")?;
        if line.is_empty() {
            break;
        }
        if let Some(colon) = line.find(':') {
            let k = line[..colon].trim().to_ascii_lowercase();
            let v = line[colon + 1..].trim().to_string();
            if k == "content-length" {
                content_length = v.parse().ok();
            }
            if k == "transfer-encoding" && v.to_ascii_lowercase().contains("chunked") {
                chunked = true;
            }
            headers.insert(k, v);
        }
    }

    // Cap ACME HTTP bodies (hostile / misconfigured directory).
    const MAX_ACME_BODY: usize = 2 * 1024 * 1024;
    let resp_body = if chunked {
        read_chunked_capped(&mut reader, MAX_ACME_BODY)?
    } else if let Some(n) = content_length {
        if n > MAX_ACME_BODY {
            return Err(format!("ACME response too large: {} bytes", n));
        }
        let mut buf = vec![0u8; n];
        if n > 0 {
            reader.read_exact(&mut buf).map_err(|e| e.to_string())?;
        }
        String::from_utf8_lossy(&buf).into_owned()
    } else {
        let mut buf = Vec::new();
        // Bound read without content-length.
        let mut chunk = [0u8; 8192];
        loop {
            let n = reader.read(&mut chunk).map_err(|e| e.to_string())?;
            if n == 0 {
                break;
            }
            if buf.len().saturating_add(n) > MAX_ACME_BODY {
                return Err("ACME response too large".into());
            }
            buf.extend_from_slice(&chunk[..n]);
        }
        String::from_utf8_lossy(&buf).into_owned()
    };

    if status >= 400 {
        return Err(format!(
            "HTTP {} from {}: {}",
            status,
            url,
            resp_body.chars().take(500).collect::<String>()
        ));
    }
    Ok((resp_body, headers, status))
}

fn read_chunked_capped<R: BufRead>(reader: &mut R, max: usize) -> Result<String, String> {
    let mut out = Vec::new();
    loop {
        let line = util::read_line(reader)
            .map_err(|e| e.to_string())?
            .ok_or("EOF chunk size")?;
        let size_hex = line.split(';').next().unwrap_or("0").trim();
        // Cap hex length to avoid huge usize parses on hostile input.
        if size_hex.len() > 8 {
            return Err("chunk size too large".into());
        }
        let size = usize::from_str_radix(size_hex, 16).map_err(|e| e.to_string())?;
        if size == 0 {
            // trailers
            loop {
                let t = util::read_line(reader)
                    .map_err(|e| e.to_string())?
                    .unwrap_or_default();
                if t.is_empty() {
                    break;
                }
            }
            break;
        }
        if out.len().saturating_add(size) > max {
            return Err("chunked body too large".into());
        }
        let mut buf = vec![0u8; size];
        reader.read_exact(&mut buf).map_err(|e| e.to_string())?;
        out.extend_from_slice(&buf);
        // CRLF after chunk
        let mut crlf = [0u8; 2];
        let _ = reader.read_exact(&mut crlf);
    }
    Ok(String::from_utf8_lossy(&out).into_owned())
}

// ---------------------------------------------------------------------------
// Tiny JSON helpers (no serde)
// ---------------------------------------------------------------------------

fn json_str(obj: &str, key: &str) -> Result<String, String> {
    // naive: find "key" : "value"
    let pat = format!("\"{}\"", key);
    let idx = obj.find(&pat).ok_or_else(|| format!("json missing {}", key))?;
    let after = &obj[idx + pat.len()..];
    let after = after.trim_start();
    let after = after.strip_prefix(':').unwrap_or(after).trim_start();
    if after.starts_with('"') {
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
    } else {
        Err(format!("json key {} not a string", key))
    }
}

fn json_str_array(obj: &str, key: &str) -> Result<Vec<String>, String> {
    let pat = format!("\"{}\"", key);
    let idx = obj.find(&pat).ok_or_else(|| format!("json missing {}", key))?;
    let after = &obj[idx + pat.len()..];
    let after = after.trim_start().strip_prefix(':').unwrap_or(after).trim_start();
    let start = after.find('[').ok_or("expected array")?;
    let mut depth = 0i32;
    let mut end = start;
    for (i, c) in after[start..].char_indices() {
        match c {
            '[' => depth += 1,
            ']' => {
                depth -= 1;
                if depth == 0 {
                    end = start + i;
                    break;
                }
            }
            _ => {}
        }
    }
    let arr = &after[start + 1..end];
    let mut out = Vec::new();
    let mut cur = String::new();
    let mut in_str = false;
    let mut chars = arr.chars().peekable();
    while let Some(c) = chars.next() {
        if in_str {
            if c == '\\' {
                if let Some(n) = chars.next() {
                    cur.push(n);
                }
            } else if c == '"' {
                in_str = false;
                out.push(cur);
                cur = String::new();
            } else {
                cur.push(c);
            }
        } else if c == '"' {
            in_str = true;
        }
    }
    Ok(out)
}

fn extract_challenges(authz: &str) -> Result<Vec<(String, String, String)>, String> {
    // Return list of (type, token, url)
    let mut out = Vec::new();
    let mut rest = authz;
    while let Some(idx) = rest.find("\"type\"") {
        rest = &rest[idx..];
        let ty = json_str(rest, "type").unwrap_or_default();
        let token = json_str(rest, "token").unwrap_or_default();
        let url = json_str(rest, "url").unwrap_or_default();
        if !ty.is_empty() && !token.is_empty() && !url.is_empty() {
            out.push((ty, token, url));
        }
        rest = rest.get(6..).unwrap_or("");
    }
    if out.is_empty() {
        return Err("no challenges found".into());
    }
    Ok(out)
}

#[cfg(test)]
mod tests {
    use super::*;

    // Use the same embedded test key as crypto tests (via PEM parse).
    const TEST_RSA_PEM: &str = "-----BEGIN RSA PRIVATE KEY-----\n\
MIICXQIBAAKBgQC+v+fwXgsS/AxQtvt+4WdkVebBKKRN79O/TH1gAQla79A5zjna\n\
LksqG/EuaVgRNo+fcxkuJd/xoPWP60vAZAZiojVk5g3BOYp3Qnl7d4W58QZPX9KU\n\
te+A4kO+HzZCZ9v/+MCOo/KwrHyEpWwrUJQCseWpmZgjF09f4s3QpnHq8wIDAQAB\n\
AoGBALtGQFo+ipLWAOVR8XLtrAvXRpmH5GBcQMFFQKZ7/gpY/k9yiFwMLWGnU1Ak\n\
vwEPV0zNvQAQ0WAyjkUBVzsJOTXz/nO2PeiR/eaIryuXnYxPkUb4PZ6/zFECPR2V\n\
/wg3YcbVrtCnmUKB62hluNOUArLGK3CUGmd3sCSLjJb4Iis5AkEA777lUJ4on28N\n\
kEIZ/Sd/BtKWsIZOd6l7ocp88dYbbqxGBCb7ZqUYywEmpMNazxy6BJcNGjhQsn/o\n\
DfmfHE33nQJBAMuunmhjCkbza81ylBJbYbbmDTGa79UrJjiPP9oWZg7BPuGYXD2V\n\
/y+5ETezFhLTaDNYB6QjKSHvNH9Zt0GOj88CQAtenjlohryo45fHyru6t8d3DTZp\n\
6Ca8nuRZWfuOD9b7zIY94wZHJhnagB6oNRJFZnz5POHVcd5FOpgPEoChIfECQGgz\n\
lWbiBEf4EJayn34ksgDYALf4A+qSgKM+5fO0sdGqm3jecZIwQrUvgNd2DzziWtSp\n\
nH8kXc62iaz9QPuQ65ECQQDZb9u4AHdPi9d5IINOMgN5mZ1TbDYH/z4s7QHeKGmK\n\
QnKcg6jvEzpc5zxAT1oYERfocK0XNetovfMnrwnC2Tqe\n\
-----END RSA PRIVATE KEY-----\n";

    #[test]
    fn base64url_and_jws_structure() {
        let key = RsaKey::from_pem(TEST_RSA_PEM).unwrap();
        let jws = build_jws(
            &key,
            "https://example.com/acme/new-acct",
            "nonce123",
            "{\"termsOfServiceAgreed\":true}",
            None,
            true,
        )
        .unwrap();
        assert!(jws.contains("\"protected\""));
        assert!(jws.contains("\"payload\""));
        assert!(jws.contains("\"signature\""));
        // protected is base64url of JSON with alg RS256
        let prot_b64 = jws
            .split("\"protected\":\"")
            .nth(1)
            .unwrap()
            .split('"')
            .next()
            .unwrap();
        let prot = String::from_utf8(util::base64url_decode(prot_b64)).unwrap();
        assert!(prot.contains("RS256"));
        assert!(prot.contains("nonce123"));

        let payload_b64 = jws
            .split("\"payload\":\"")
            .nth(1)
            .unwrap()
            .split('"')
            .next()
            .unwrap();
        let input = jws_signing_input(prot_b64, payload_b64);
        assert!(input.contains('.'));
        // Verify signature
        let sig_b64 = jws
            .split("\"signature\":\"")
            .nth(1)
            .unwrap()
            .split('"')
            .next()
            .unwrap();
        let sig = util::base64url_decode(sig_b64);
        assert!(key.verify_sha256(input.as_bytes(), &sig));
    }

    #[test]
    fn jwk_thumbprint_stable() {
        let key = RsaKey::from_pem(TEST_RSA_PEM).unwrap();
        let t1 = jwk_thumbprint(&key).unwrap();
        let t2 = jwk_thumbprint(&key).unwrap();
        assert_eq!(t1, t2);
        assert!(!t1.contains('+') && !t1.contains('/'));
    }

    #[test]
    fn csr_der_structure_and_openssl() {
        let key = RsaKey::from_pem(TEST_RSA_PEM).unwrap();
        let csr = key
            .build_csr_der("mail.example.com", &["mail.example.com".into()])
            .unwrap();
        assert_eq!(csr[0], 0x30); // SEQUENCE
        assert!(csr.len() > 100);

        // openssl verify when present (required for real CSR sanity)
        let tmp = std::env::temp_dir().join(format!("de_csr_{}.der", std::process::id()));
        fs::write(&tmp, &csr).unwrap();
        let openssl = std::process::Command::new("openssl")
            .args(["req", "-in"])
            .arg(&tmp)
            .args(["-inform", "DER", "-verify", "-noout"])
            .output();
        let _ = fs::remove_file(&tmp);
        if let Ok(out) = openssl {
            if out.status.code() == Some(127)
                || String::from_utf8_lossy(&out.stderr).contains("not found")
            {
                // openssl binary missing — structure check above is enough
                return;
            }
            let stderr = String::from_utf8_lossy(&out.stderr);
            let stdout = String::from_utf8_lossy(&out.stdout);
            let ok = out.status.success()
                || stderr.contains("verify OK")
                || stdout.contains("verify OK");
            assert!(
                ok,
                "openssl req -verify failed: status={:?} stderr={} stdout={}",
                out.status.code(),
                stderr,
                stdout
            );
        }
    }
}
