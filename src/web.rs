//! Minimal HTTP/1.1 webmail + admin UI. Pure std, thread-per-connection.
//! Optional HTTPS via web_tls_listen when TLS cert/key are configured.

use std::collections::HashMap;
use std::io::{self, BufRead, BufReader, Write};
use std::net::TcpListener;
use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::{Mutex, OnceLock};
use std::sync::Arc;
use std::thread;

use rustls::ServerConfig;

use crate::acme;
use crate::auth;
use crate::config::Config;
use crate::crypto;
use crate::limits;
use crate::metrics;
use crate::queue;
use crate::ratelimit;
use crate::storage::Maildir;
use crate::tls::{self, Conn};
use crate::useredit;
use crate::util;

// ---------------------------------------------------------------------------
// Session store
// ---------------------------------------------------------------------------

fn sessions() -> &'static Mutex<HashMap<String, String>> {
    static S: OnceLock<Mutex<HashMap<String, String>>> = OnceLock::new();
    S.get_or_init(|| Mutex::new(HashMap::new()))
}

/// 32 bytes from the OS CSPRNG (via util::fill_random). Timestamp/PID alone
/// would be guessable; fill_random prefers /dev/urandom.
fn os_random_seed() -> [u8; 32] {
    let mut buf = [0u8; 32];
    util::fill_random(&mut buf);
    // Fold in sha256(time+pid) so a weak fill_random fallback is strengthened
    // the same way the previous web.rs path did.
    let material = format!("{}:{}", util::now_millis(), std::process::id());
    let dig = crypto::sha256(material.as_bytes());
    for i in 0..32 {
        buf[i] ^= dig[i];
    }
    buf
}

fn session_seed() -> &'static [u8; 32] {
    static SEED: OnceLock<[u8; 32]> = OnceLock::new();
    SEED.get_or_init(os_random_seed)
}

fn make_session_token(username: &str) -> String {
    static COUNTER: AtomicU64 = AtomicU64::new(0);
    let n = COUNTER.fetch_add(1, Ordering::SeqCst);
    let mut material = Vec::new();
    material.extend_from_slice(session_seed());
    material.extend_from_slice(username.as_bytes());
    material.extend_from_slice(&util::now_millis().to_be_bytes());
    material.extend_from_slice(&n.to_be_bytes());
    hex_encode(&crypto::sha256(&material))
}

fn hex_encode(bytes: &[u8]) -> String {
    let mut s = String::with_capacity(bytes.len() * 2);
    for b in bytes {
        s.push_str(&format!("{:02x}", b));
    }
    s
}

fn session_user(token: Option<&str>) -> Option<String> {
    let token = token?;
    sessions().lock().ok()?.get(token).cloned()
}

fn set_session(token: &str, user: &str) {
    if let Ok(mut map) = sessions().lock() {
        map.insert(token.to_string(), user.to_string());
    }
}

fn clear_session(token: Option<&str>) {
    if let Some(t) = token {
        if let Ok(mut map) = sessions().lock() {
            map.remove(t);
        }
    }
}

// ---------------------------------------------------------------------------
// HTTP primitives
// ---------------------------------------------------------------------------

struct Request {
    method: String,
    path: String,
    query: HashMap<String, String>,
    headers: HashMap<String, String>,
    body: Vec<u8>,
}

/// Fuzz-visible HTTP request parser entry (from raw bytes).
pub fn fuzz_parse_http(data: &[u8]) {
    use std::io::Cursor;
    let mut reader = BufReader::new(Cursor::new(data));
    let _ = parse_request(&mut reader);
    // Also exercise URL/MIME helpers on the same bytes as text.
    let s = String::from_utf8_lossy(data);
    let _ = percent_decode(&s);
    let _ = parse_urlencoded(&s);
    let _ = split_path_query(&s);
    let _ = mime_boundary(&s);
}

fn parse_request(reader: &mut impl BufRead) -> io::Result<Option<Request>> {
    let first = match util::read_line(reader)? {
        Some(l) => l,
        None => return Ok(None),
    };
    if first.is_empty() {
        return Ok(None);
    }
    let mut parts = first.split_whitespace();
    let method = parts.next().unwrap_or("GET").to_uppercase();
    let target = parts.next().unwrap_or("/").to_string();
    let (path, query) = split_path_query(&target);

    let mut headers = HashMap::new();
    loop {
        let line = match util::read_line(reader)? {
            Some(l) => l,
            None => break,
        };
        if line.is_empty() {
            break;
        }
        if let Some(colon) = line.find(':') {
            let key = line.get(..colon).unwrap_or("").trim().to_lowercase();
            let val = line.get(colon + 1..).unwrap_or("").trim().to_string();
            headers.insert(key, val);
        }
    }

    // Cap body size: reject oversize with empty body (caller gets no form fields).
    // Prefer checked parse; cap at 1 MiB for form posts (mail send is small).
    const MAX_HTTP_BODY: usize = 1024 * 1024;
    let mut content_len = 0usize;
    if let Some(cl) = headers.get("content-length") {
        // Reject non-numeric / huge digit strings without panic.
        if cl.len() <= 12 && cl.bytes().all(|b| b.is_ascii_digit()) {
            if let Ok(n) = cl.parse::<u64>() {
                if n <= MAX_HTTP_BODY as u64 {
                    content_len = n as usize;
                } else {
                    // Drain a limited amount then stop — do not allocate the claimed size.
                    let mut drain = [0u8; 8192];
                    let mut left = n.min(MAX_HTTP_BODY as u64 * 2);
                    while left > 0 {
                        let chunk = drain.len().min(left as usize);
                        match reader.read(&mut drain[..chunk]) {
                            Ok(0) => break,
                            Ok(r) => left = left.saturating_sub(r as u64),
                            Err(_) => break,
                        }
                    }
                    return Ok(Some(Request {
                        method,
                        path,
                        query,
                        headers,
                        body: Vec::new(),
                    }));
                }
            }
        }
    }
    let mut body = vec![0u8; content_len];
    if content_len > 0 {
        reader.read_exact(&mut body)?;
    }

    Ok(Some(Request {
        method,
        path,
        query,
        headers,
        body,
    }))
}

fn split_path_query(target: &str) -> (String, HashMap<String, String>) {
    if let Some(q) = target.find('?') {
        let path = target.get(..q).unwrap_or(target).to_string();
        let qs = target.get(q + 1..).unwrap_or("");
        (path, parse_urlencoded(qs))
    } else {
        (target.to_string(), HashMap::new())
    }
}

/// Percent-decode a URL-encoded string (`+` → space, `%HH` → byte).
pub fn percent_decode(s: &str) -> String {
    let bytes = s.as_bytes();
    let mut out = Vec::with_capacity(bytes.len());
    let mut i = 0;
    while i < bytes.len() {
        if bytes.get(i) == Some(&b'%') && i + 2 < bytes.len() {
            if let (Some(hi), Some(lo)) = (
                bytes.get(i + 1).and_then(|b| from_hex(*b)),
                bytes.get(i + 2).and_then(|b| from_hex(*b)),
            ) {
                out.push((hi << 4) | lo);
                i += 3;
                continue;
            }
        }
        match bytes.get(i) {
            Some(&b'+') => out.push(b' '),
            Some(&b) => out.push(b),
            None => break,
        }
        i += 1;
    }
    String::from_utf8_lossy(&out).into_owned()
}

fn from_hex(b: u8) -> Option<u8> {
    match b {
        b'0'..=b'9' => Some(b - b'0'),
        b'a'..=b'f' => Some(b - b'a' + 10),
        b'A'..=b'F' => Some(b - b'A' + 10),
        _ => None,
    }
}

fn parse_urlencoded(s: &str) -> HashMap<String, String> {
    let mut map = HashMap::new();
    for pair in s.split('&') {
        if pair.is_empty() {
            continue;
        }
        if let Some(eq) = pair.find('=') {
            let k = percent_decode(pair.get(..eq).unwrap_or(""));
            let v = percent_decode(pair.get(eq + 1..).unwrap_or(""));
            map.insert(k, v);
        } else {
            map.insert(percent_decode(pair), String::new());
        }
    }
    map
}

fn form_body(req: &Request) -> HashMap<String, String> {
    let ct = req
        .headers
        .get("content-type")
        .map(|s| s.as_str())
        .unwrap_or("");
    if ct.to_lowercase().contains("application/x-www-form-urlencoded")
        || req.method == "POST"
    {
        let s = String::from_utf8_lossy(&req.body);
        return parse_urlencoded(s.trim());
    }
    HashMap::new()
}

fn cookie_value(req: &Request, name: &str) -> Option<String> {
    let cookie = req.headers.get("cookie")?;
    for part in cookie.split(';') {
        let part = part.trim();
        if let Some(eq) = part.find('=') {
            if part.get(..eq).unwrap_or("").trim() == name {
                return Some(part.get(eq + 1..).unwrap_or("").trim().to_string());
            }
        }
    }
    None
}

/// HTML-escape user-controlled data.
pub fn esc(s: &str) -> String {
    let mut out = String::with_capacity(s.len());
    for c in s.chars() {
        match c {
            '&' => out.push_str("&amp;"),
            '<' => out.push_str("&lt;"),
            '>' => out.push_str("&gt;"),
            '"' => out.push_str("&quot;"),
            '\'' => out.push_str("&#39;"),
            _ => out.push(c),
        }
    }
    out
}

struct Response {
    status: u16,
    reason: &'static str,
    headers: Vec<(String, String)>,
    body: Vec<u8>,
}

impl Response {
    fn html(status: u16, reason: &'static str, body: String) -> Self {
        let bytes = body.into_bytes();
        Self {
            status,
            reason,
            headers: vec![
                ("Content-Type".into(), "text/html; charset=utf-8".into()),
                ("Content-Length".into(), bytes.len().to_string()),
                ("Connection".into(), "close".into()),
            ],
            body: bytes,
        }
    }

    fn plain(status: u16, body: &str) -> Self {
        let reason = match status {
            200 => "OK",
            401 => "Unauthorized",
            403 => "Forbidden",
            404 => "Not Found",
            _ => "OK",
        };
        let bytes = body.as_bytes().to_vec();
        Self {
            status,
            reason,
            headers: vec![
                ("Content-Type".into(), "text/plain; charset=utf-8".into()),
                ("Content-Length".into(), bytes.len().to_string()),
                ("Connection".into(), "close".into()),
            ],
            body: bytes,
        }
    }

    fn prometheus(status: u16, body: &str) -> Self {
        let bytes = body.as_bytes().to_vec();
        Self {
            status,
            reason: "OK",
            headers: vec![
                (
                    "Content-Type".into(),
                    "text/plain; version=0.0.4; charset=utf-8".into(),
                ),
                ("Content-Length".into(), bytes.len().to_string()),
                ("Connection".into(), "close".into()),
            ],
            body: bytes,
        }
    }

    fn redirect(location: &str) -> Self {
        Self {
            status: 302,
            reason: "Found",
            headers: vec![
                ("Location".into(), location.to_string()),
                ("Content-Length".into(), "0".into()),
                ("Connection".into(), "close".into()),
            ],
            body: Vec::new(),
        }
    }

    fn with_cookie(mut self, cookie: &str) -> Self {
        self.headers
            .push(("Set-Cookie".into(), cookie.to_string()));
        self
    }

    fn write_to(self, stream: &mut impl Write) -> io::Result<()> {
        write!(
            stream,
            "HTTP/1.1 {} {}\r\n",
            self.status, self.reason
        )?;
        for (k, v) in &self.headers {
            write!(stream, "{}: {}\r\n", k, v)?;
        }
        write!(stream, "\r\n")?;
        if !self.body.is_empty() {
            stream.write_all(&self.body)?;
        }
        stream.flush()?;
        Ok(())
    }
}

fn session_cookie(token: &str, secure: bool) -> String {
    if secure {
        format!(
            "session={}; HttpOnly; Path=/; SameSite=Lax; Secure",
            token
        )
    } else {
        format!("session={}; HttpOnly; Path=/; SameSite=Lax", token)
    }
}

fn clear_session_cookie(secure: bool) -> String {
    if secure {
        "session=; HttpOnly; Path=/; SameSite=Lax; Secure; Max-Age=0".into()
    } else {
        "session=; HttpOnly; Path=/; SameSite=Lax; Max-Age=0".into()
    }
}

// ---------------------------------------------------------------------------
// Server
// ---------------------------------------------------------------------------

/// Start plaintext HTTP webmail if `web_listen` is non-empty.
pub fn start(cfg: Arc<Config>) {
    let addr = cfg.web_listen.clone();
    if addr.is_empty() {
        util::log!("web: disabled (web_listen empty)");
        return;
    }
    start_listener(cfg, addr, None, false);
}

/// Start HTTPS webmail on `web_tls_listen` when TLS is configured.
pub fn start_tls(cfg: Arc<Config>, tls_cfg: Arc<ServerConfig>) {
    let addr = cfg.web_tls_listen.clone();
    if addr.is_empty() {
        return;
    }
    start_listener(cfg, addr, Some(tls_cfg), true);
}

fn start_listener(
    cfg: Arc<Config>,
    addr: String,
    tls_cfg: Option<Arc<ServerConfig>>,
    secure: bool,
) {
    thread::spawn(move || {
        let listener = match TcpListener::bind(&addr) {
            Ok(l) => l,
            Err(e) => {
                util::log!(
                    "web{}: FATAL cannot bind {}: {}",
                    if secure { "s" } else { "" },
                    addr,
                    e
                );
                return;
            }
        };
        util::log!(
            "web{}: listening on {}",
            if secure { "s" } else { "" },
            addr
        );
        let _ = listener.set_nonblocking(true);
        loop {
            if crate::shutdown::is_shutdown() {
                util::log!("web: shutting down");
                break;
            }
            match listener.accept() {
                Ok((stream, _)) => {
                    let _ = stream.set_nonblocking(false);
                    let ip = limits::peer_ip_from_stream(&stream);
                    let guard = match limits::try_acquire(&ip) {
                        Some(g) => g,
                        None => {
                            limits::apply_timeouts(&stream);
                            let mut s = stream;
                            let body = b"503 Service Unavailable\r\n";
                            let _ = write!(
                                s,
                                "HTTP/1.1 503 Service Unavailable\r\nContent-Length: {}\r\nConnection: close\r\n\r\n",
                                body.len()
                            );
                            let _ = s.write_all(body);
                            let _ = s.flush();
                            continue;
                        }
                    };
                    limits::apply_timeouts(&stream);
                    let cfg = Arc::clone(&cfg);
                    let tls_cfg = tls_cfg.clone();
                    thread::spawn(move || {
                        let _guard = guard;
                        if let Err(e) = handle_connection(stream, &cfg, tls_cfg, secure) {
                            util::log!("web: connection error: {}", e);
                        }
                    });
                }
                Err(ref e) if e.kind() == io::ErrorKind::WouldBlock => {
                    thread::sleep(std::time::Duration::from_millis(200));
                }
                Err(e) => {
                    if crate::shutdown::is_shutdown() {
                        break;
                    }
                    util::log!("web: accept error: {}", e);
                    thread::sleep(std::time::Duration::from_millis(200));
                }
            }
        }
    });
}

fn handle_connection(
    stream: std::net::TcpStream,
    cfg: &Config,
    tls_cfg: Option<Arc<ServerConfig>>,
    secure: bool,
) -> io::Result<()> {
    limits::apply_timeouts(&stream);
    let timeout = std::time::Duration::from_secs(limits::io_timeout_secs());

    let conn = if secure {
        let tc = tls_cfg.as_ref().ok_or_else(|| {
            io::Error::new(io::ErrorKind::Other, "HTTPS without TLS config")
        })?;
        let c = tls::accept_tls(stream, tc)?;
        c.set_timeouts(timeout);
        c
    } else {
        let c = Conn::Plain(stream);
        c.set_timeouts(timeout);
        c
    };

    let peer = conn.peer_addr_string();
    let peer_ip = limits::ip_key(&peer);
    let mut reader = BufReader::new(conn);

    let req = match parse_request(&mut reader)? {
        Some(r) => r,
        None => return Ok(()),
    };
    util::log!(
        "web{}: {} {} {}",
        if secure { "s" } else { "" },
        peer,
        req.method,
        req.path
    );

    let resp = route(cfg, &req, secure, &peer_ip);
    resp.write_to(reader.get_mut())
}

fn route(cfg: &Config, req: &Request, secure: bool, peer_ip: &str) -> Response {
    let token = cookie_value(req, "session");
    let user = session_user(token.as_deref());

    // Liveness probe (no auth).
    if req.method == "GET" && req.path == "/healthz" {
        return Response::plain(200, "ok");
    }

    // Prometheus metrics (no auth, or gated by metrics_token).
    if req.method == "GET" && req.path == "/metrics" {
        if !metrics_authorized(cfg, req) {
            return Response::plain(401, "unauthorized");
        }
        let snap = metrics::snapshot(&cfg.data_dir);
        let body = metrics::format_prometheus(&snap);
        return Response::prometheus(200, &body);
    }

    // ACME HTTP-01 challenge (no auth) — required for Let's Encrypt when acme=true.
    // Must be reachable on port 80 (or a reverse-proxy path to this server).
    if req.method == "GET" && req.path.starts_with("/.well-known/acme-challenge/") {
        let token = req
            .path
            .strip_prefix("/.well-known/acme-challenge/")
            .unwrap_or("");
        if let Some(key_auth) = acme::get_http01(token) {
            return Response::plain(200, &key_auth);
        }
        return Response::plain(404, "not found");
    }

    match (req.method.as_str(), req.path.as_str()) {
        ("GET", "/login") => page_login(None, 200),
        ("POST", "/login") => handle_login(cfg, req, secure, peer_ip),
        ("GET", "/logout") => {
            clear_session(token.as_deref());
            Response::redirect("/login").with_cookie(&clear_session_cookie(secure))
        }
        _ => {
            let user = match user {
                Some(u) => u,
                None => return Response::redirect("/login"),
            };
            match (req.method.as_str(), req.path.as_str()) {
                ("GET", "/") => page_inbox(cfg, &user),
                ("GET", "/msg") => page_message(cfg, &user, req),
                ("GET", "/compose") => page_compose_for(&user, None, None),
                ("POST", "/send") => handle_send(cfg, &user, req),
                ("GET", "/sent") => page_sent(cfg, &user),
                ("GET", "/admin") => page_admin(cfg, &user, None),
                ("POST", "/admin") => handle_admin_post(cfg, &user, req),
                ("POST", "/admin/user/add") => handle_admin_user_add(cfg, &user, req),
                ("POST", "/admin/user/remove") => handle_admin_user_remove(cfg, &user, req),
                ("POST", "/admin/user/quota") => handle_admin_user_quota(cfg, &user, req),
                ("POST", "/admin/queue/delete") => handle_queue_delete(cfg, &user, req),
                _ => Response::html(404, "Not Found", page_shell("Not Found", &user, "<p>404</p>")),
            }
        }
    }
}

fn metrics_authorized(cfg: &Config, req: &Request) -> bool {
    if cfg.metrics_token.is_empty() {
        return true;
    }
    if let Some(q) = req.query.get("token") {
        if q == &cfg.metrics_token {
            return true;
        }
    }
    if let Some(auth) = req.headers.get("authorization") {
        let prefix = "Bearer ";
        if let Some(rest) = auth.strip_prefix(prefix) {
            if rest == cfg.metrics_token {
                return true;
            }
        }
        // Also accept raw token.
        if auth == &cfg.metrics_token {
            return true;
        }
    }
    false
}

/// Same-origin check for state-changing POSTs (CSRF-ish).
/// When Origin or Referer is present, require it to match Host.
fn same_origin_ok(req: &Request) -> bool {
    let host = match req.headers.get("host") {
        Some(h) if !h.is_empty() => h.as_str(),
        _ => return true, // no Host — cannot verify; allow (local/test)
    };
    if let Some(origin) = req.headers.get("origin") {
        return origin_matches_host(origin, host);
    }
    if let Some(referer) = req.headers.get("referer") {
        return origin_matches_host(referer, host);
    }
    // Neither header present — older clients / curl; allow (session cookie still required).
    true
}

fn origin_matches_host(origin_or_referer: &str, host: &str) -> bool {
    // origin: "https://mail.example.com" or "http://127.0.0.1:8080"
    // referer: same + path
    let s = origin_or_referer.trim();
    let after_scheme = if let Some(rest) = s.strip_prefix("https://") {
        rest
    } else if let Some(rest) = s.strip_prefix("http://") {
        rest
    } else {
        return false;
    };
    let authority = after_scheme
        .split(['/', '?', '#'])
        .next()
        .unwrap_or("");
    // Compare case-insensitively; Host may omit default port.
    authority.eq_ignore_ascii_case(host)
        || authority
            .split(':')
            .next()
            .unwrap_or("")
            .eq_ignore_ascii_case(host.split(':').next().unwrap_or(""))
}

// ---------------------------------------------------------------------------
// HTML helpers
// ---------------------------------------------------------------------------

const STYLE: &str = "\
body{font-family:system-ui,sans-serif;max-width:900px;margin:1.5rem auto;padding:0 1rem;color:#222}\
a{color:#06c}nav a{margin-right:1rem}\
table{border-collapse:collapse;width:100%}th,td{border-bottom:1px solid #ddd;padding:.4rem .5rem;text-align:left}\
tr.unread td{font-weight:600}\
pre{background:#f6f6f6;padding:.75rem;overflow:auto;white-space:pre-wrap;word-break:break-word}\
.msg-body{white-space:pre-wrap;word-break:break-word;border:1px solid #eee;padding:.75rem}\
form label{display:block;margin:.5rem 0 .2rem}input[type=text],input[type=password],textarea{width:100%;box-sizing:border-box;padding:.4rem}\
textarea{min-height:12rem}button,.btn{padding:.4rem .8rem;cursor:pointer}\
.err{color:#a00}.ok{color:#060}h1{font-size:1.4rem}";

fn page_shell(title: &str, user: &str, body: &str) -> String {
    let nav = if user.is_empty() {
        String::new()
    } else {
        format!(
            "<nav><a href=\"/\">Inbox</a><a href=\"/compose\">Compose</a>\
             <a href=\"/sent\">Sent</a><a href=\"/admin\">Admin</a>\
             <a href=\"/logout\">Logout</a> \
             <span style=\"float:right;color:#666\">{}</span></nav><hr>",
            esc(user)
        )
    };
    format!(
        "<!DOCTYPE html><html><head><meta charset=\"utf-8\"><title>{}</title>\
         <style>{}</style></head><body>{}{}</body></html>",
        esc(title),
        STYLE,
        nav,
        body
    )
}

fn page_login(error: Option<&str>, status: u16) -> Response {
    let err = error
        .map(|e| format!("<p class=\"err\">{}</p>", esc(e)))
        .unwrap_or_default();
    let body = format!(
        "<h1>Login</h1>{}<form method=\"post\" action=\"/login\">\
         <label>Username</label><input type=\"text\" name=\"username\" autofocus required>\
         <label>Password</label><input type=\"password\" name=\"password\" required>\
         <p><button type=\"submit\">Sign in</button></p></form>",
        err
    );
    let reason = if status == 429 {
        "Too Many Requests"
    } else {
        "OK"
    };
    Response::html(status, reason, page_shell("Login", "", &body))
}

fn handle_login(cfg: &Config, req: &Request, secure: bool, peer_ip: &str) -> Response {
    if !ratelimit::check_allowed(peer_ip) {
        return page_login(Some("Too many failed attempts, try later"), 429);
    }
    let form = form_body(req);
    let username = form.get("username").map(|s| s.trim()).unwrap_or("");
    let password = form.get("password").map(|s| s.as_str()).unwrap_or("");
    if username.is_empty() {
        return page_login(Some("Username required"), 200);
    }
    if !auth::authenticate(cfg, username, password) {
        ratelimit::record_failure(peer_ip);
        metrics::inc_auth_failure();
        util::log_event!(
            "warn",
            "web login failed",
            "event" => "auth_fail",
            "ip" => peer_ip,
            "user" => username,
            "proto" => "web",
            "result" => "fail"
        );
        return page_login(Some("Invalid username or password"), 200);
    }
    ratelimit::record_success(peer_ip);
    metrics::inc_auth_success();
    let user = username.to_lowercase();
    let token = make_session_token(&user);
    set_session(&token, &user);
    Response::redirect("/").with_cookie(&session_cookie(&token, secure))
}

fn mailbox_name(cfg: &Config, user: &str) -> String {
    cfg.resolve_mailbox(user)
        .unwrap_or_else(|| user.to_string())
}

fn user_from_addr(cfg: &Config, user: &str) -> String {
    if user.contains('@') {
        user.to_string()
    } else {
        let domain = cfg
            .domains
            .first()
            .map(|s| s.as_str())
            .unwrap_or("localhost");
        format!("{}@{}", user, domain)
    }
}

// ---------------------------------------------------------------------------
// Inbox / Sent
// ---------------------------------------------------------------------------

fn page_inbox(cfg: &Config, user: &str) -> Response {
    list_folder_page(cfg, user, "Inbox", false)
}

fn page_sent(cfg: &Config, user: &str) -> Response {
    list_folder_page(cfg, user, "Sent", true)
}

fn list_folder_page(cfg: &Config, user: &str, title: &str, sent: bool) -> Response {
    let mb = mailbox_name(cfg, user);
    let path = if sent {
        format!("{}/.Sent", mb)
    } else {
        mb.clone()
    };
    let md = match Maildir::open(&cfg.data_dir, &path) {
        Ok(m) => m,
        Err(e) => {
            let body = format!("<h1>{}</h1><p class=\"err\">Cannot open mailbox: {}</p>", esc(title), esc(&e.to_string()));
            return Response::html(500, "Error", page_shell(title, user, &body));
        }
    };
    let mut msgs = match md.list_messages() {
        Ok(m) => m,
        Err(e) => {
            let body = format!("<h1>{}</h1><p class=\"err\">List failed: {}</p>", esc(title), esc(&e.to_string()));
            return Response::html(500, "Error", page_shell(title, user, &body));
        }
    };
    // Newest first (filenames start with unix timestamp).
    msgs.reverse();

    let mut rows = String::new();
    if msgs.is_empty() {
        rows.push_str("<tr><td colspan=\"4\">No messages</td></tr>");
    } else {
        for m in &msgs {
            let raw = md.read_message(&m.path).unwrap_or_default();
            let headers = extract_headers(&raw);
            let subject = headers.get("subject").map(|s| s.as_str()).unwrap_or("(no subject)");
            let from = headers.get("from").map(|s| s.as_str()).unwrap_or("");
            let date = headers.get("date").map(|s| s.as_str()).unwrap_or("");
            let unread = m.in_new || !m.flags.contains('S');
            let cls = if unread { " class=\"unread\"" } else { "" };
            let status = if unread { "unread" } else { "read" };
            let link = if sent {
                format!("/msg?id={}&folder=sent", m.uid)
            } else {
                format!("/msg?id={}", m.uid)
            };
            rows.push_str(&format!(
                "<tr{}><td><a href=\"{}\">{}</a></td><td>{}</td><td>{}</td><td>{}</td></tr>",
                cls,
                link,
                esc(subject),
                esc(from),
                esc(date),
                status
            ));
        }
    }

    let body = format!(
        "<h1>{}</h1><table><thead><tr><th>Subject</th><th>From</th><th>Date</th><th>Status</th></tr></thead>\
         <tbody>{}</tbody></table>",
        esc(title),
        rows
    );
    Response::html(200, "OK", page_shell(title, user, &body))
}

// ---------------------------------------------------------------------------
// Message view
// ---------------------------------------------------------------------------

fn page_message(cfg: &Config, user: &str, req: &Request) -> Response {
    let id: u32 = match req.query.get("id").and_then(|s| s.parse().ok()) {
        Some(n) => n,
        None => {
            return Response::html(
                400,
                "Bad Request",
                page_shell("Message", user, "<p class=\"err\">Missing id</p>"),
            );
        }
    };
    let folder_sent = req.query.get("folder").map(|s| s.as_str()) == Some("sent");
    let show_raw = req.query.get("raw").map(|s| s.as_str()) == Some("1");

    let mb = mailbox_name(cfg, user);
    let path = if folder_sent {
        format!("{}/.Sent", mb)
    } else {
        mb
    };
    let md = match Maildir::open(&cfg.data_dir, &path) {
        Ok(m) => m,
        Err(e) => {
            return Response::html(
                500,
                "Error",
                page_shell(
                    "Message",
                    user,
                    &format!("<p class=\"err\">{}</p>", esc(&e.to_string())),
                ),
            );
        }
    };
    let msgs = match md.list_messages() {
        Ok(m) => m,
        Err(e) => {
            return Response::html(
                500,
                "Error",
                page_shell(
                    "Message",
                    user,
                    &format!("<p class=\"err\">{}</p>", esc(&e.to_string())),
                ),
            );
        }
    };
    let meta = match msgs.iter().find(|m| m.uid == id) {
        Some(m) => m.clone(),
        None => {
            return Response::html(
                404,
                "Not Found",
                page_shell("Message", user, "<p class=\"err\">Message not found</p>"),
            );
        }
    };
    let raw = match md.read_message(&meta.path) {
        Ok(r) => r,
        Err(e) => {
            return Response::html(
                500,
                "Error",
                page_shell(
                    "Message",
                    user,
                    &format!("<p class=\"err\">{}</p>", esc(&e.to_string())),
                ),
            );
        }
    };
    // Mark seen (inbox only makes sense; still safe for sent).
    let _ = md.mark_seen(&meta);

    let headers = extract_headers(&raw);
    let from = headers.get("from").map(|s| s.as_str()).unwrap_or("");
    let to = headers.get("to").map(|s| s.as_str()).unwrap_or("");
    let subject = headers.get("subject").map(|s| s.as_str()).unwrap_or("(no subject)");
    let date = headers.get("date").map(|s| s.as_str()).unwrap_or("");

    let text_body = extract_text_body(&raw, &headers);
    let folder_q = if folder_sent { "&folder=sent" } else { "" };

    let raw_section = if show_raw {
        format!(
            "<h2>Raw source</h2><pre>{}</pre>\
             <p><a href=\"/msg?id={}{}\">Hide raw</a></p>",
            esc(&String::from_utf8_lossy(&raw)),
            id,
            folder_q
        )
    } else {
        format!(
            "<p><a href=\"/msg?id={}&raw=1{}\">Show raw source</a></p>",
            id, folder_q
        )
    };

    let back = if folder_sent { "/sent" } else { "/" };
    let body = format!(
        "<p><a href=\"{}\">&larr; Back</a></p>\
         <h1>{}</h1>\
         <p><strong>From:</strong> {}<br>\
         <strong>To:</strong> {}<br>\
         <strong>Date:</strong> {}</p>\
         <div class=\"msg-body\">{}</div>\
         {}",
        back,
        esc(subject),
        esc(from),
        esc(to),
        esc(date),
        esc(&text_body),
        raw_section
    );
    Response::html(200, "OK", page_shell(subject, user, &body))
}

fn extract_headers(raw: &[u8]) -> HashMap<String, String> {
    let text = String::from_utf8_lossy(raw);
    let mut map = HashMap::new();
    let mut current_key = String::new();
    let mut current_val = String::new();

    for line in text.lines() {
        if line.is_empty() {
            break;
        }
        if line.starts_with(' ') || line.starts_with('\t') {
            if !current_key.is_empty() {
                current_val.push(' ');
                current_val.push_str(line.trim());
            }
            continue;
        }
        if !current_key.is_empty() {
            map.insert(current_key.clone(), current_val.clone());
        }
        if let Some(colon) = line.find(':') {
            current_key = line.get(..colon).unwrap_or("").trim().to_lowercase();
            current_val = line.get(colon + 1..).unwrap_or("").trim().to_string();
        } else {
            current_key.clear();
            current_val.clear();
        }
    }
    if !current_key.is_empty() {
        map.insert(current_key, current_val);
    }
    map
}

fn header_block_end(raw: &[u8]) -> usize {
    if let Some(p) = raw.windows(4).position(|w| w == b"\r\n\r\n") {
        return p.saturating_add(4);
    }
    if let Some(p) = raw.windows(2).position(|w| w == b"\n\n") {
        return p.saturating_add(2);
    }
    raw.len()
}

/// Minimal MIME: if multipart, return first text/plain part body; else whole body.
fn extract_text_body(raw: &[u8], headers: &HashMap<String, String>) -> String {
    let body_start = header_block_end(raw).min(raw.len());
    let body = raw.get(body_start..).unwrap_or(&[]);
    let ct = headers
        .get("content-type")
        .map(|s| s.as_str())
        .unwrap_or("text/plain");
    let ct_lower = ct.to_lowercase();

    if ct_lower.contains("multipart/") {
        if let Some(boundary) = mime_boundary(ct) {
            if let Some(part) = first_text_plain_part(body, &boundary) {
                return part;
            }
        }
    }

    // Single-part: optional quoted-printable/base64 left as-is (display raw-ish text).
    String::from_utf8_lossy(body).into_owned()
}

fn mime_boundary(content_type: &str) -> Option<String> {
    // boundary=foo or boundary="foo"
    let lower = content_type.to_lowercase();
    let idx = lower.find("boundary=")?;
    let rest = content_type.get(idx + 9..)?.trim();
    let rest = rest.trim_start_matches('"');
    let end = rest
        .find(|c: char| c == '"' || c == ';' || c.is_whitespace())
        .unwrap_or(rest.len());
    let b = rest.get(..end).unwrap_or("").trim().trim_matches('"');
    if b.is_empty() {
        None
    } else {
        Some(b.to_string())
    }
}

fn first_text_plain_part(body: &[u8], boundary: &str) -> Option<String> {
    let delim = format!("--{}", boundary);
    let text = String::from_utf8_lossy(body);
    let mut parts = text.split(&delim);
    // skip preamble
    let _ = parts.next();
    for part in parts {
        let part = part.trim_start_matches("\r\n").trim_start_matches('\n');
        if part.starts_with("--") {
            break; // epilogue / close
        }
        let (phdr, pbody) = split_mime_part(part);
        let ct = phdr
            .get("content-type")
            .map(|s| s.to_lowercase())
            .unwrap_or_else(|| "text/plain".into());
        if ct.starts_with("text/plain") {
            return Some(pbody.trim_end_matches("--").trim().to_string());
        }
    }
    None
}

fn split_mime_part(part: &str) -> (HashMap<String, String>, String) {
    let mut headers = HashMap::new();
    let mut lines = part.lines();
    let mut body_lines = Vec::new();
    let mut in_body = false;
    let mut cur_k = String::new();
    let mut cur_v = String::new();
    for line in lines.by_ref() {
        if !in_body {
            if line.is_empty() {
                if !cur_k.is_empty() {
                    headers.insert(cur_k.clone(), cur_v.clone());
                }
                in_body = true;
                continue;
            }
            if line.starts_with(' ') || line.starts_with('\t') {
                if !cur_k.is_empty() {
                    cur_v.push(' ');
                    cur_v.push_str(line.trim());
                }
                continue;
            }
            if !cur_k.is_empty() {
                headers.insert(cur_k.clone(), cur_v.clone());
            }
            if let Some(colon) = line.find(':') {
                cur_k = line.get(..colon).unwrap_or("").trim().to_lowercase();
                cur_v = line.get(colon + 1..).unwrap_or("").trim().to_string();
            }
        } else {
            body_lines.push(line);
        }
    }
    if !in_body && !cur_k.is_empty() {
        headers.insert(cur_k, cur_v);
    }
    (headers, body_lines.join("\n"))
}

// ---------------------------------------------------------------------------
// Compose / Send
// ---------------------------------------------------------------------------

fn page_compose_for(user: &str, error: Option<&str>, notice: Option<&str>) -> Response {
    let err = error
        .map(|e| format!("<p class=\"err\">{}</p>", esc(e)))
        .unwrap_or_default();
    let ok = notice
        .map(|e| format!("<p class=\"ok\">{}</p>", esc(e)))
        .unwrap_or_default();
    let body = format!(
        "<h1>Compose</h1>{}{}<form method=\"post\" action=\"/send\">\
         <label>To</label><input type=\"text\" name=\"to\" required>\
         <label>Subject</label><input type=\"text\" name=\"subject\">\
         <label>Body</label><textarea name=\"body\"></textarea>\
         <p><button type=\"submit\">Send</button></p></form>",
        err, ok
    );
    Response::html(200, "OK", page_shell("Compose", user, &body))
}

fn handle_send(cfg: &Config, user: &str, req: &Request) -> Response {
    let form = form_body(req);
    let to = form.get("to").map(|s| s.trim()).unwrap_or("");
    let subject = form.get("subject").map(|s| s.as_str()).unwrap_or("");
    let body_text = form.get("body").map(|s| s.as_str()).unwrap_or("");

    if to.is_empty() {
        return page_compose_for(user, Some("To is required"), None);
    }

    let from = user_from_addr(cfg, user);
    let recipients = parse_address_list(to);
    if recipients.is_empty() {
        return page_compose_for(user, Some("No valid recipients"), None);
    }

    let raw = build_rfc5322_message(&from, to, subject, body_text, cfg);
    match deliver_like_submission(cfg, user, &from, &recipients, &raw) {
        Ok(_) => page_compose_for(user, None, Some("Message sent.")),
        Err(e) => page_compose_for(user, Some(&e), None),
    }
}

fn parse_address_list(s: &str) -> Vec<String> {
    let mut out = Vec::new();
    for part in s.split(',') {
        let part = part.trim();
        if part.is_empty() {
            continue;
        }
        let addr = if let Some(start) = part.find('<') {
            if let Some(rel_end) = part.get(start..).and_then(|s| s.find('>')) {
                part.get(start + 1..start + rel_end)
                    .unwrap_or("")
                    .trim()
                    .to_string()
            } else {
                part.to_string()
            }
        } else {
            part.to_string()
        };
        if !addr.is_empty() {
            out.push(addr);
        }
    }
    out
}

fn build_rfc5322_message(
    from: &str,
    to_header: &str,
    subject: &str,
    body: &str,
    cfg: &Config,
) -> Vec<u8> {
    let domain = cfg
        .domains
        .first()
        .map(|s| s.as_str())
        .unwrap_or("localhost");
    let date = util::rfc2822_date(util::now_secs());
    let msg_id = format!(
        "<{}.{}@{}>",
        util::now_millis(),
        std::process::id(),
        domain
    );
    // Ensure body lines use CRLF; keep content as provided.
    let mut body_crlf = String::new();
    for line in body.split('\n') {
        let line = line.trim_end_matches('\r');
        body_crlf.push_str(line);
        body_crlf.push_str("\r\n");
    }
    let msg = format!(
        "From: {}\r\n\
         To: {}\r\n\
         Subject: {}\r\n\
         Date: {}\r\n\
         Message-ID: {}\r\n\
         MIME-Version: 1.0\r\n\
         Content-Type: text/plain; charset=utf-8\r\n\
         \r\n\
         {}",
        sanitize_header_value(from),
        sanitize_header_value(to_header),
        sanitize_header_value(subject),
        date,
        msg_id,
        body_crlf
    );
    msg.into_bytes()
}

/// Strip CR/LF and other control chars from a value interpolated into a
/// message header — a crafted POST could otherwise inject extra headers
/// (e.g. `subject=x%0d%0aBcc:...`) into the outbound message.
fn sanitize_header_value(s: &str) -> String {
    s.chars()
        .filter(|c| !c.is_control() || *c == '\t')
        .collect()
}

/// Same behavior as smtp.rs deliver_mail for authenticated submission:
/// local Maildir + remote enqueue + copy to sender .Sent.
fn deliver_like_submission(
    cfg: &Config,
    auth_user: &str,
    from: &str,
    rcpts: &[String],
    raw: &[u8],
) -> Result<(), String> {
    // Sent folder
    if let Some(mb) = cfg.resolve_mailbox(auth_user) {
        let md = Maildir::open(&cfg.data_dir, &format!("{}/.Sent", mb))
            .map_err(|e| e.to_string())?;
        md.deliver(raw, from).map_err(|e| e.to_string())?;
    }

    let mut remote: Vec<String> = Vec::new();
    let mut count = 0usize;
    for r in rcpts {
        if let Some(mb) = cfg.resolve_mailbox(r) {
            let md = Maildir::open(&cfg.data_dir, &mb).map_err(|e| e.to_string())?;
            md.deliver(raw, from).map_err(|e| e.to_string())?;
            count += 1;
        } else {
            remote.push(r.clone());
        }
    }
    if !remote.is_empty() {
        let id = queue::enqueue(&cfg.data_dir, from, &remote, raw).map_err(|e| e.to_string())?;
        util::log!(
            "web: send from {} to {:?}: enqueued as {}",
            from,
            remote,
            id
        );
        count += remote.len();
    }
    if count == 0 {
        return Err("no recipients accepted".into());
    }
    Ok(())
}


// ---------------------------------------------------------------------------
// Admin
// ---------------------------------------------------------------------------

fn is_admin(cfg: &Config, user: &str) -> bool {
    match &cfg.admin_user {
        Some(a) if !a.is_empty() => a.eq_ignore_ascii_case(user),
        _ => false,
    }
}

fn page_admin(cfg: &Config, user: &str, flash: Option<&str>) -> Response {
    if !is_admin(cfg, user) {
        let body = if cfg.admin_user.as_ref().map(|s| s.is_empty()).unwrap_or(true) {
            "<h1>Admin</h1><p class=\"err\">Admin page is disabled (admin_user not set).</p>"
                .to_string()
        } else {
            "<h1>Admin</h1><p class=\"err\">Access denied.</p>".to_string()
        };
        return Response::html(403, "Forbidden", page_shell("Admin", user, &body));
    }

    let domains: String = cfg
        .domains
        .iter()
        .map(|d| format!("<li>{}</li>", esc(d)))
        .collect();

    let names = cfg.user_names();
    let mut users_html = String::new();
    for n in &names {
        users_html.push_str(&format!(
            "<li>{} \
             <form method=\"post\" action=\"/admin/user/remove\" style=\"display:inline\">\
             <input type=\"hidden\" name=\"email\" value=\"{}\">\
             <button type=\"submit\">remove</button></form></li>",
            esc(n),
            esc(n)
        ));
    }
    if users_html.is_empty() {
        users_html.push_str("<li><em>(none configured)</em></li>");
    }

    let queue_rows = match queue::list_queue(&cfg.data_dir) {
        Ok(msgs) => {
            if msgs.is_empty() {
                "<tr><td colspan=\"6\">Queue empty</td></tr>".to_string()
            } else {
                let mut rows = String::new();
                for m in msgs {
                    rows.push_str(&format!(
                        "<tr><td>{}</td><td>{}</td><td>{}</td><td>{}</td><td>{}</td>\
                         <td><form method=\"post\" action=\"/admin/queue/delete\" style=\"display:inline\">\
                         <input type=\"hidden\" name=\"id\" value=\"{}\">\
                         <button type=\"submit\">delete</button></form></td></tr>",
                        esc(&m.id),
                        esc(&m.sender),
                        esc(&m.recipients.join(", ")),
                        m.retry_count,
                        m.next_attempt,
                        esc(&m.id)
                    ));
                }
                rows
            }
        }
        Err(e) => format!(
            "<tr><td colspan=\"6\" class=\"err\">{}</td></tr>",
            esc(&e.to_string())
        ),
    };

    let flash_html = flash
        .map(|f| {
            if f.starts_with("error:") {
                format!("<p class=\"err\">{}</p>", esc(f))
            } else {
                format!("<p class=\"ok\">{}</p>", esc(f))
            }
        })
        .unwrap_or_default();

    let body = format!(
        "<h1>Admin</h1>{}<h2>Domains</h2><ul>{}</ul>\
         <h2>Users</h2><ul>{}</ul>\
         <h3>Add user</h3>\
         <form method=\"post\" action=\"/admin/user/add\">\
         <label>Email / username</label><input type=\"text\" name=\"email\" required>\
         <label>Password</label><input type=\"password\" name=\"password\" required>\
         <p><button type=\"submit\">Add user</button></p></form>\
         <h3>Set quota (MiB)</h3>\
         <form method=\"post\" action=\"/admin/user/quota\">\
         <label>Username</label><input type=\"text\" name=\"email\" required>\
         <label>Quota MiB (0 = remove override)</label>\
         <input type=\"text\" name=\"quota_mb\" value=\"512\">\
         <p><button type=\"submit\">Set quota</button></p></form>\
         <h2>Outbound queue</h2>\
         <table><thead><tr><th>ID</th><th>Sender</th><th>Recipients</th>\
         <th>Retries</th><th>Next attempt</th><th></th></tr></thead>\
         <tbody>{}</tbody></table>\
         <p style=\"color:#666;font-size:.9rem\">Ops: <code>/healthz</code> · <code>/metrics</code></p>",
        flash_html, domains, users_html, queue_rows
    );
    Response::html(200, "OK", page_shell("Admin", user, &body))
}

fn handle_admin_post(cfg: &Config, user: &str, _req: &Request) -> Response {
    page_admin(cfg, user, None)
}

fn config_path_for_edit(cfg: &Config) -> Result<&std::path::Path, String> {
    cfg.config_path
        .as_deref()
        .ok_or_else(|| "config_path not set; cannot persist user changes".into())
}

fn persist_and_reload<F>(cfg: &Config, edit: F) -> Result<(), String>
where
    F: FnOnce(&str) -> Result<String, String>,
{
    let path = config_path_for_edit(cfg)?;
    useredit::edit_file(path, edit)?;
    cfg.reload_users_quotas()?;
    Ok(())
}

fn handle_admin_user_add(cfg: &Config, user: &str, req: &Request) -> Response {
    if !is_admin(cfg, user) {
        return page_admin(cfg, user, Some("error: access denied"));
    }
    if !same_origin_ok(req) {
        return page_admin(cfg, user, Some("error: cross-origin request blocked"));
    }
    let form = form_body(req);
    let email = form.get("email").map(|s| s.trim()).unwrap_or("");
    let password = form.get("password").map(|s| s.as_str()).unwrap_or("");
    if email.is_empty() || password.is_empty() {
        return page_admin(cfg, user, Some("error: email and password required"));
    }
    let email_owned = email.to_string();
    let password_owned = password.to_string();
    match persist_and_reload(cfg, |c| useredit::add_user(c, &email_owned, &password_owned)) {
        Ok(()) => page_admin(
            cfg,
            user,
            Some(&format!("User {} added (live; no restart needed).", email_owned)),
        ),
        Err(e) => page_admin(cfg, user, Some(&format!("error: {}", e))),
    }
}

fn handle_admin_user_remove(cfg: &Config, user: &str, req: &Request) -> Response {
    if !is_admin(cfg, user) {
        return page_admin(cfg, user, Some("error: access denied"));
    }
    if !same_origin_ok(req) {
        return page_admin(cfg, user, Some("error: cross-origin request blocked"));
    }
    let form = form_body(req);
    let email = form.get("email").map(|s| s.trim()).unwrap_or("");
    if email.is_empty() {
        return page_admin(cfg, user, Some("error: email required"));
    }
    if email.eq_ignore_ascii_case(user) {
        return page_admin(cfg, user, Some("error: cannot remove the logged-in admin"));
    }
    let email_owned = email.to_string();
    match persist_and_reload(cfg, |c| useredit::remove_user(c, &email_owned)) {
        Ok(()) => page_admin(
            cfg,
            user,
            Some(&format!("User {} removed.", email_owned)),
        ),
        Err(e) => page_admin(cfg, user, Some(&format!("error: {}", e))),
    }
}

fn handle_admin_user_quota(cfg: &Config, user: &str, req: &Request) -> Response {
    if !is_admin(cfg, user) {
        return page_admin(cfg, user, Some("error: access denied"));
    }
    if !same_origin_ok(req) {
        return page_admin(cfg, user, Some("error: cross-origin request blocked"));
    }
    let form = form_body(req);
    let email = form.get("email").map(|s| s.trim()).unwrap_or("");
    let mb_s = form.get("quota_mb").map(|s| s.trim()).unwrap_or("0");
    if email.is_empty() {
        return page_admin(cfg, user, Some("error: email required"));
    }
    let mb: u64 = mb_s.parse().unwrap_or(0);
    let email_owned = email.to_string();
    match persist_and_reload(cfg, |c| useredit::set_quota(c, &email_owned, mb)) {
        Ok(()) => {
            cfg.set_quota_live(&email_owned, mb);
            page_admin(
                cfg,
                user,
                Some(&format!("Quota for {} set to {} MiB.", email_owned, mb)),
            )
        }
        Err(e) => page_admin(cfg, user, Some(&format!("error: {}", e))),
    }
}

fn handle_queue_delete(cfg: &Config, user: &str, req: &Request) -> Response {
    if !is_admin(cfg, user) {
        return page_admin(cfg, user, None);
    }
    if !same_origin_ok(req) {
        return page_admin(cfg, user, Some("error: cross-origin request blocked"));
    }
    let form = form_body(req);
    let id = form.get("id").map(|s| s.as_str()).unwrap_or("");
    match queue::delete_queued(&cfg.data_dir, id) {
        Ok(true) => page_admin(cfg, user, Some("Queue entry deleted.")),
        Ok(false) => page_admin(cfg, user, Some("Queue entry not found.")),
        Err(e) => page_admin(cfg, user, Some(&format!("Delete failed: {}", e))),
    }
}

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn percent_decode_basic() {
        assert_eq!(percent_decode("hello"), "hello");
        assert_eq!(percent_decode("a+b"), "a b");
        assert_eq!(percent_decode("a%20b"), "a b");
        assert_eq!(percent_decode("%41%42"), "AB");
        assert_eq!(percent_decode("name%3Dval"), "name=val");
        assert_eq!(percent_decode("%2Fpath%2F"), "/path/");
        assert_eq!(percent_decode("100%25"), "100%");
        // invalid percent sequences left as-is-ish: %ZZ keeps % and continues
        assert_eq!(percent_decode("%ZZ"), "%ZZ");
        assert_eq!(percent_decode("end%"), "end%");
    }

    #[test]
    fn percent_decode_form_pair() {
        let map = parse_urlencoded("user=alice%40ex.com&pass=p%2Bss+word");
        assert_eq!(map.get("user").map(|s| s.as_str()), Some("alice@ex.com"));
        assert_eq!(map.get("pass").map(|s| s.as_str()), Some("p+ss word"));
    }

    #[test]
    fn esc_html() {
        assert_eq!(esc("plain"), "plain");
        assert_eq!(esc("<script>"), "&lt;script&gt;");
        assert_eq!(esc("a&b"), "a&amp;b");
        assert_eq!(esc("\"q\""), "&quot;q&quot;");
        assert_eq!(esc("it's"), "it&#39;s");
        assert_eq!(
            esc("<img src=x onerror=alert(1)>"),
            "&lt;img src=x onerror=alert(1)&gt;"
        );
    }

    #[test]
    fn same_origin_checks() {
        assert!(origin_matches_host("http://127.0.0.1:8080", "127.0.0.1:8080"));
        assert!(origin_matches_host(
            "https://mail.example.com/admin",
            "mail.example.com"
        ));
        assert!(!origin_matches_host("https://evil.com", "mail.example.com"));
    }
}
