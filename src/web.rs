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

    // First-run setup: empty [users] → everything goes to /setup (except healthz/metrics/acme).
    let pending = cfg.setup_pending();
    if pending {
        return match (req.method.as_str(), req.path.as_str()) {
            ("GET", "/setup") => page_setup(cfg, req, peer_ip, None, 200),
            ("POST", "/setup") => handle_setup(cfg, req, secure, peer_ip),
            _ => Response::redirect("/setup"),
        };
    }
    // Setup already done — /setup permanently redirects to login.
    if req.path == "/setup" {
        return Response::redirect("/login");
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

/// Loopback peer for first-run setup (127.0.0.1 / ::1 / IPv4-mapped ::ffff:127.0.0.1).
fn is_loopback_peer(ip: &str) -> bool {
    let ip = ip.trim();
    ip == "127.0.0.1"
        || ip == "::1"
        || ip == "localhost"
        || ip == "0:0:0:0:0:0:0:1"
        || ip == "::ffff:127.0.0.1"
        || ip.eq_ignore_ascii_case("::ffff:127.0.0.1")
}

/// Setup is allowed from loopback, or with a matching `setup_token` (query or form).
fn setup_access_ok(cfg: &Config, req: &Request, peer_ip: &str, form_token: Option<&str>) -> bool {
    if is_loopback_peer(peer_ip) {
        return true;
    }
    if cfg.setup_token.is_empty() {
        return false;
    }
    if let Some(t) = form_token {
        if t == cfg.setup_token {
            return true;
        }
    }
    if let Some(t) = req.query.get("setup_token") {
        if t == &cfg.setup_token {
            return true;
        }
    }
    false
}

fn page_setup_remote_blocked(cfg: &Config) -> Response {
    let token_hint = if cfg.setup_token.is_empty() {
        "<p class=\"muted\">No <code>setup_token</code> is configured. Open this page from the \
         machine itself (127.0.0.1), or add <code>setup_token = \"...\"</code> to config.toml and \
         open <code>/setup?setup_token=...</code>.</p>"
            .to_string()
    } else {
        "<p class=\"muted\">Add <code>?setup_token=...</code> to the URL (same value as \
         <code>setup_token</code> in config.toml), or open from the machine itself.</p>"
            .to_string()
    };
    let body = format!(
        "<div class=\"login-wrap\"><div class=\"pix-panel login-card\">\
         <div class=\"login-brand\">{}<span>DESERTEMAIL</span></div>\
         <h1>Setup from this machine</h1>\
         <p>First-run setup is only open on the local machine by default, so nobody else on the \
         network can claim your server.</p>{}\
         <p class=\"muted\">Open <code>http://127.0.0.1:8080/setup</code> in a browser on this host.</p>\
         </div></div>",
        CACTUS_SVG, token_hint
    );
    Response::html(403, "Forbidden", page_shell("Setup", "", &body))
}

fn page_setup(
    cfg: &Config,
    req: &Request,
    peer_ip: &str,
    error: Option<&str>,
    status: u16,
) -> Response {
    if !setup_access_ok(cfg, req, peer_ip, None) {
        return page_setup_remote_blocked(cfg);
    }
    let err = error
        .map(|e| format!("<p class=\"err\">{}</p>", esc(e)))
        .unwrap_or_default();
    let domain_prefill = cfg.primary_domain();
    let token_field = if !cfg.setup_token.is_empty() && !is_loopback_peer(peer_ip) {
        let pre = req
            .query
            .get("setup_token")
            .map(|s| s.as_str())
            .unwrap_or("");
        format!(
            "<input type=\"hidden\" name=\"setup_token\" value=\"{}\">",
            esc(pre)
        )
    } else {
        String::new()
    };
    let body = format!(
        "<div class=\"login-wrap\"><div class=\"pix-panel login-card\" style=\"max-width:26rem\">\
         <div class=\"login-brand\">{}<span>DESERTEMAIL</span></div>\
         <h1>Welcome to DesertEmail</h1>\
         <p class=\"muted\" style=\"text-align:center;margin-top:-.35rem\">Create your admin account — one-time setup.</p>\
         {}\
         <form method=\"post\" action=\"/setup\" autocomplete=\"on\">\
         {}\
         <label>Username</label>\
         <input type=\"text\" name=\"username\" value=\"admin\" autofocus required autocomplete=\"username\">\
         <label>Password <span class=\"muted\">(at least 8 characters)</span></label>\
         <input type=\"password\" name=\"password\" id=\"setup-pass\" required minlength=\"8\" autocomplete=\"new-password\">\
         <label>Confirm password</label>\
         <input type=\"password\" name=\"password2\" id=\"setup-pass2\" required minlength=\"8\" autocomplete=\"new-password\">\
         <p class=\"muted\" style=\"margin:.35rem 0 0\">\
         <label style=\"display:inline;font-weight:500;text-transform:none;letter-spacing:0\">\
         <input type=\"checkbox\" id=\"setup-show\" style=\"width:auto;display:inline;margin-right:.35rem\" \
         onchange=\"var p=document.getElementById('setup-pass'),q=document.getElementById('setup-pass2');\
         var t=this.checked?'text':'password';p.type=t;q.type=t;\">Show passwords</label></p>\
         <label>Primary domain</label>\
         <input type=\"text\" name=\"domain\" value=\"{}\" required autocomplete=\"off\">\
         <p class=\"muted\">Used for your email addresses (e.g. admin@domain). You can change DNS later.</p>\
         <p><button type=\"submit\">Create admin account</button></p></form></div></div>",
        CACTUS_SVG,
        err,
        token_field,
        esc(&domain_prefill)
    );
    let reason = if status == 429 {
        "Too Many Requests"
    } else if status == 403 {
        "Forbidden"
    } else {
        "OK"
    };
    Response::html(status, reason, page_shell("Setup", "", &body))
}

fn handle_setup(cfg: &Config, req: &Request, secure: bool, peer_ip: &str) -> Response {
    if !ratelimit::check_allowed(peer_ip) {
        return page_setup(
            cfg,
            req,
            peer_ip,
            Some("Too many attempts, try later"),
            429,
        );
    }
    let form = form_body(req);
    let form_token = form.get("setup_token").map(|s| s.as_str());
    if !setup_access_ok(cfg, req, peer_ip, form_token) {
        ratelimit::record_failure(peer_ip);
        return page_setup_remote_blocked(cfg);
    }
    if !same_origin_ok(req) {
        return page_setup(
            cfg,
            req,
            peer_ip,
            Some("Cross-origin request blocked"),
            200,
        );
    }
    // Re-check: race with another setup POST.
    if !cfg.setup_pending() {
        return Response::redirect("/login");
    }
    let username = form.get("username").map(|s| s.trim()).unwrap_or("");
    let password = form.get("password").map(|s| s.as_str()).unwrap_or("");
    let password2 = form.get("password2").map(|s| s.as_str()).unwrap_or("");
    let domain = form.get("domain").map(|s| s.trim()).unwrap_or("");
    if username.is_empty() {
        return page_setup(cfg, req, peer_ip, Some("Username required"), 200);
    }
    if password.len() < 8 {
        return page_setup(
            cfg,
            req,
            peer_ip,
            Some("Password must be at least 8 characters"),
            200,
        );
    }
    if password != password2 {
        return page_setup(cfg, req, peer_ip, Some("Passwords do not match"), 200);
    }
    if domain.is_empty() {
        return page_setup(cfg, req, peer_ip, Some("Domain required"), 200);
    }
    let user_owned = username.to_string();
    let pass_owned = password.to_string();
    let domain_owned = domain.to_string();
    match persist_and_reload(cfg, |c| {
        useredit::complete_setup(c, &user_owned, &pass_owned, &domain_owned)
    }) {
        Ok(()) => {
            ratelimit::record_success(peer_ip);
            let user = user_owned.to_lowercase();
            let token = make_session_token(&user);
            set_session(&token, &user);
            util::log_event!(
                "info",
                "first-run setup complete",
                "event" => "setup_complete",
                "user" => user.as_str(),
                "domain" => domain_owned.as_str()
            );
            Response::redirect("/").with_cookie(&session_cookie(&token, secure))
        }
        Err(e) => {
            ratelimit::record_failure(peer_ip);
            page_setup(cfg, req, peer_ip, Some(&e), 200)
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

/// Pixel cactus favicon (same data-URI as site/index.html).
const FAVICON_LINK: &str = "<link rel=\"icon\" href=\"data:image/svg+xml,%3Csvg%20xmlns='http://www.w3.org/2000/svg'%20viewBox='0%200%2012%2016'%20shape-rendering='crispEdges'%3E%3Crect%20x='6'%20y='0'%20width='1'%20height='1'%20fill='%23E8850C'/%3E%3Crect%20x='5'%20y='1'%20width='3'%20height='15'%20fill='%23E8850C'/%3E%3Crect%20x='5'%20y='1'%20width='1'%20height='15'%20fill='%23FFB03A'/%3E%3Crect%20x='7'%20y='1'%20width='1'%20height='15'%20fill='%23B35E00'/%3E%3Crect%20x='1'%20y='4'%20width='2'%20height='5'%20fill='%23E8850C'/%3E%3Crect%20x='1'%20y='4'%20width='1'%20height='5'%20fill='%23FFB03A'/%3E%3Crect%20x='3'%20y='7'%20width='2'%20height='2'%20fill='%23E8850C'/%3E%3Crect%20x='3'%20y='8'%20width='2'%20height='1'%20fill='%23B35E00'/%3E%3Crect%20x='9'%20y='5'%20width='2'%20height='6'%20fill='%23E8850C'/%3E%3Crect%20x='10'%20y='5'%20width='1'%20height='6'%20fill='%23B35E00'/%3E%3Crect%20x='9'%20y='5'%20width='1'%20height='1'%20fill='%23FFB03A'/%3E%3Crect%20x='8'%20y='9'%20width='1'%20height='2'%20fill='%23E8850C'/%3E%3C/svg%3E\">";

/// Inline cactus SVG for nav brand / login card (same pixel art as site).
const CACTUS_SVG: &str = "<svg class=\"nav-logo\" viewBox=\"0 0 12 16\" shape-rendering=\"crispEdges\" role=\"img\" aria-hidden=\"true\">\
<rect x=\"6\" y=\"0\" width=\"1\" height=\"1\" fill=\"#E8850C\"/>\
<rect x=\"5\" y=\"1\" width=\"3\" height=\"15\" fill=\"#E8850C\"/>\
<rect x=\"5\" y=\"1\" width=\"1\" height=\"15\" fill=\"#FFB03A\"/>\
<rect x=\"7\" y=\"1\" width=\"1\" height=\"15\" fill=\"#B35E00\"/>\
<rect x=\"1\" y=\"4\" width=\"2\" height=\"5\" fill=\"#E8850C\"/>\
<rect x=\"1\" y=\"4\" width=\"1\" height=\"5\" fill=\"#FFB03A\"/>\
<rect x=\"3\" y=\"7\" width=\"2\" height=\"2\" fill=\"#E8850C\"/>\
<rect x=\"3\" y=\"8\" width=\"2\" height=\"1\" fill=\"#B35E00\"/>\
<rect x=\"9\" y=\"5\" width=\"2\" height=\"6\" fill=\"#E8850C\"/>\
<rect x=\"10\" y=\"5\" width=\"1\" height=\"6\" fill=\"#B35E00\"/>\
<rect x=\"9\" y=\"5\" width=\"1\" height=\"1\" fill=\"#FFB03A\"/>\
<rect x=\"8\" y=\"9\" width=\"1\" height=\"2\" fill=\"#E8850C\"/></svg>";

const STYLE: &str = r#"
:root{
  --bg:#f5e3c0;--panel:#fdf3dd;--ink:#3a2410;--muted:#7a5c38;
  --accent:#e8850c;--accent-dark:#b35e00;--accent-light:#ffb03a;
  --border:#3a2410;--code-bg:#2a1a08;--code-ink:#ffd591;
  --nav-h:56px;
}
@media (prefers-color-scheme: dark){
  :root{
    --bg:#17110a;--panel:#211809;--ink:#f2e3c8;--muted:#b99a6e;
    --accent:#e8850c;--accent-dark:#B35E00;--accent-light:#ffb03a;
    --border:#e8850c;--code-bg:#0d0904;--code-ink:#ffd591;
  }
}
*{box-sizing:border-box}
html{-webkit-text-size-adjust:100%}
body{
  margin:0;background:var(--bg);color:var(--ink);
  font-family:"Courier New",Courier,ui-monospace,monospace;
  font-size:16px;line-height:1.55;image-rendering:pixelated;
  overflow-x:clip;
}
.wrap{max-width:900px;margin:0 auto;padding:1.25rem 1rem 3rem}
a{color:var(--accent-dark);text-decoration:none;border-bottom:2px solid var(--accent);font-weight:700}
@media (prefers-color-scheme: dark){a{color:var(--accent-light)}}
a:hover{background:var(--accent);color:#2a1a08}
h1,h2,h3{
  font-family:"Courier New",Courier,ui-monospace,monospace;
  font-weight:700;text-transform:uppercase;letter-spacing:.12em;line-height:1.3;
}
h1{font-size:1.35rem;margin:.4rem 0 .8rem;text-shadow:2px 2px 0 var(--accent-dark)}
h2{font-size:1.05rem;margin:1.4rem 0 .7rem;color:var(--accent)}
h2::before{content:"▶ ";color:var(--accent-dark)}
h3{font-size:.95rem;margin:1.1rem 0 .5rem;color:var(--accent)}
h3::before{content:"▶ ";color:var(--accent-dark)}
p{margin:.5rem 0}
ul{list-style:none;padding:0;margin:.4rem 0}
ul li{margin:.35rem 0;padding-left:.1rem}
ul li::before{content:"■ ";color:var(--accent)}
code{background:var(--code-bg);color:var(--code-ink);padding:.1rem .35rem;font-size:.9em}
.err{color:#b00000;font-weight:700}
.ok{color:#2d6a1e;font-weight:700}
@media (prefers-color-scheme: dark){
  .err{color:#ff8a80}.ok{color:#81c784}
}

/* --- sticky 8-bit navbar --- */
.site-nav{
  position:sticky;top:0;z-index:100;
  background:var(--panel);
  border-bottom:4px solid var(--border);
  box-shadow:0 4px 0 0 var(--accent-dark);
}
.site-nav-inner{
  max-width:900px;margin:0 auto;padding:0 1rem;
  min-height:var(--nav-h);display:flex;align-items:center;gap:.75rem;flex-wrap:wrap;
}
.nav-brand{
  display:flex;align-items:center;gap:.5rem;
  font-weight:700;text-transform:uppercase;letter-spacing:.12em;font-size:.85rem;
  color:var(--ink);border-bottom:none;text-decoration:none;
}
.nav-brand:hover{background:transparent;color:var(--ink)}
.nav-logo{width:22px;height:29px;flex:none;display:block}
.nav-user{color:var(--muted);font-size:.78rem;margin-left:.25rem;letter-spacing:0;text-transform:none;font-weight:600}
.nav-links{
  display:flex;align-items:center;gap:.15rem 1rem;margin-left:auto;
  list-style:none;padding:0;margin-top:0;margin-bottom:0;
}
.nav-links li{margin:0}
.nav-links li::before{content:none}
.nav-links a{
  display:inline-flex;align-items:center;min-height:44px;padding:.2rem .15rem;
  font-weight:700;text-transform:uppercase;letter-spacing:.08em;font-size:.78rem;
  color:var(--ink);border-bottom:3px solid transparent;text-decoration:none;
}
.nav-links a:hover{background:transparent;color:var(--accent-dark);border-bottom-color:var(--accent)}
@media (prefers-color-scheme: dark){
  .nav-links a:hover{color:var(--accent-light)}
}
.nav-toggle{
  display:none;margin-left:auto;font-family:inherit;font-weight:700;font-size:1.25rem;line-height:1;
  color:var(--ink);background:var(--panel);border:4px solid var(--border);
  box-shadow:3px 3px 0 0 var(--accent-dark);width:44px;height:44px;padding:0;cursor:pointer;
}
.nav-toggle:hover{background:var(--accent-light);color:#2a1a08}
.nav-toggle:active{transform:translate(2px,2px);box-shadow:none}
@media (max-width:640px){
  .nav-toggle{display:inline-flex;align-items:center;justify-content:center}
  .nav-links{
    display:none;flex-direction:column;align-items:stretch;width:100%;
    margin-left:0;margin-bottom:.6rem;background:var(--panel);
    border:4px solid var(--border);box-shadow:4px 4px 0 0 var(--accent-dark);padding:.35rem 0;
  }
  .site-nav.is-open .nav-links{display:flex}
  .nav-links a{min-height:44px;padding:.55rem 1rem;border-bottom:none;width:100%}
  .nav-links a:hover{background:var(--accent);color:#2a1a08}
  .nav-user{display:block;padding:.35rem 1rem;color:var(--muted);font-size:.85rem}
}

/* --- 8-bit panels / buttons / forms --- */
.pix-panel{
  background:var(--panel);border:4px solid var(--border);
  box-shadow:6px 6px 0 0 var(--accent-dark);padding:1.1rem 1.15rem 1.25rem;margin:1.1rem 0;
}
button,.btn,input[type=submit]{
  font-family:inherit;font-weight:700;text-transform:uppercase;letter-spacing:.08em;font-size:.9rem;
  color:#2a1a08;background:var(--accent);border:4px solid var(--border);
  box-shadow:4px 4px 0 0 var(--accent-dark);padding:.55rem 1.1rem;cursor:pointer;
  min-height:44px;display:inline-flex;align-items:center;justify-content:center;
}
button:hover,.btn:hover,input[type=submit]:hover{background:var(--accent-light)}
button:active,.btn:active,input[type=submit]:active{transform:translate(4px,4px);box-shadow:none}
button.btn-primary{font-size:1rem;padding:.7rem 1.5rem;min-width:8rem}
form label{display:block;margin:.65rem 0 .25rem;font-weight:700;text-transform:uppercase;letter-spacing:.06em;font-size:.85rem;color:var(--muted)}
input[type=text],input[type=password],textarea{
  width:100%;box-sizing:border-box;font-family:inherit;font-size:16px;line-height:1.4;
  color:var(--ink);background:var(--bg);border:4px solid var(--border);
  padding:.55rem .65rem;box-shadow:3px 3px 0 0 var(--accent-dark);
}
textarea{min-height:12rem;resize:vertical}
input:focus,textarea:focus{outline:2px solid var(--accent);outline-offset:1px}

/* --- tables (desktop chrome) --- */
table{border-collapse:collapse;width:100%;background:var(--panel)}
th,td{border-bottom:2px solid var(--border);padding:.55rem .6rem;text-align:left;vertical-align:top}
th{
  background:var(--accent);color:#2a1a08;text-transform:uppercase;letter-spacing:.08em;
  font-size:.8rem;border-bottom:4px solid var(--border);
}
.table-scroll{overflow-x:auto;-webkit-overflow-scrolling:touch;margin:.5rem 0}

/* --- message list: table → stacked cards on phone --- */
.msg-list{border:4px solid var(--border);box-shadow:6px 6px 0 0 var(--accent-dark)}
.msg-list th{border-bottom:4px solid var(--border)}
.msg-list td{border-bottom:2px solid var(--border)}
.msg-list tr.msg-row:last-child td{border-bottom:none}
.msg-list tr.unread td{font-weight:700}
.msg-list tr.unread .msg-subject::before{content:"■ ";color:var(--accent)}
.msg-list .msg-subject a{
  display:block;min-height:44px;padding:.35rem 0;border-bottom:none;
  color:var(--ink);font-weight:inherit;
}
.msg-list .msg-subject a:hover{background:var(--accent-light);color:#2a1a08}
.msg-list .msg-from,.msg-list .msg-date{color:var(--muted);font-size:.92rem;font-weight:500}
.msg-list .msg-status{font-size:.8rem;text-transform:uppercase;letter-spacing:.06em;color:var(--muted)}
.msg-list tr.unread .msg-status{color:var(--accent-dark);font-weight:700}
.msg-list tr.empty td{color:var(--muted);padding:1rem;text-align:center}
@media (max-width:640px){
  .msg-list,.msg-list thead,.msg-list tbody,.msg-list th,.msg-list td,.msg-list tr{display:block;width:100%}
  .msg-list{border:none;box-shadow:none;background:transparent}
  .msg-list thead{display:none}
  .msg-list tr.msg-row{
    display:block;background:var(--panel);border:4px solid var(--border);
    box-shadow:5px 5px 0 0 var(--accent-dark);margin:0 0 .85rem;padding:.15rem 0;
  }
  .msg-list tr.msg-row td{border:none;padding:.15rem .9rem}
  .msg-list tr.msg-row .msg-subject{padding-top:.65rem}
  .msg-list tr.msg-row .msg-subject a{min-height:44px;padding:.4rem 0;font-size:1.02rem}
  .msg-list tr.msg-row .msg-from,.msg-list tr.msg-row .msg-date{
    display:inline;padding:0 .15rem .2rem 0;font-size:.88rem;
  }
  .msg-list tr.msg-row .msg-from::after{content:" · "}
  .msg-list tr.msg-row .msg-status{padding-bottom:.65rem;font-size:.75rem}
  .msg-list tr.empty{
    background:var(--panel);border:4px solid var(--border);
    box-shadow:5px 5px 0 0 var(--accent-dark);padding:.5rem 0;
  }
}

/* --- message view: readable body, themed chrome --- */
.back-link{margin:0 0 .75rem}
.back-link a{display:inline-flex;align-items:center;min-height:44px}
.msg-headers p{margin:.35rem 0;color:var(--muted);font-size:.95rem}
.msg-headers strong{color:var(--ink);text-transform:uppercase;letter-spacing:.05em;font-size:.82rem}
.msg-headers h1{
  text-transform:none;letter-spacing:0;font-size:1.2rem;text-shadow:none;
  margin:0 0 .75rem;line-height:1.35;word-break:break-word;
}
.msg-body{
  white-space:pre-wrap;word-break:break-word;
  font-size:1rem;line-height:1.65;color:var(--ink);
  text-transform:none;letter-spacing:0;font-weight:400;
}
pre,.code,pre.code{
  background:var(--code-bg);color:var(--code-ink);border:4px solid var(--border);
  padding:.85rem 1rem;overflow:auto;white-space:pre-wrap;word-break:break-word;
  font-family:"Courier New",Courier,ui-monospace,monospace;font-size:.9rem;line-height:1.45;
  box-shadow:4px 4px 0 0 var(--accent-dark);
}
.raw-toggle{margin:1rem 0}
.raw-toggle a{display:inline-flex;align-items:center;min-height:44px}

/* --- login card --- */
.login-wrap{display:flex;justify-content:center;padding:1.5rem 0 2rem}
.login-card{max-width:22rem;width:100%;margin:0}
.login-brand{
  display:flex;align-items:center;justify-content:center;gap:.55rem;
  margin:0 0 1rem;font-weight:700;text-transform:uppercase;letter-spacing:.14em;font-size:.9rem;
}
.login-brand .nav-logo{width:28px;height:37px}
.login-card h1{text-align:center}
.login-card button{width:100%;margin-top:.85rem}

/* --- compose --- */
.compose-panel button[type=submit]{margin-top:.5rem;width:100%;max-width:16rem}
@media (max-width:640px){
  .compose-panel button[type=submit]{max-width:none}
  .pix-panel{box-shadow:5px 5px 0 0 var(--accent-dark);padding:1rem}
  h1{font-size:1.15rem}
  .wrap{padding:1rem .75rem 2.5rem}
}

/* --- admin queue cards on narrow --- */
.queue-list tr form{margin:0}
@media (max-width:640px){
  .queue-list,.queue-list thead,.queue-list tbody,.queue-list th,.queue-list td,.queue-list tr{display:block;width:100%}
  .queue-list{border:none;box-shadow:none;background:transparent}
  .queue-list thead{display:none}
  .queue-list tr{
    background:var(--panel);border:4px solid var(--border);
    box-shadow:5px 5px 0 0 var(--accent-dark);margin:0 0 .85rem;padding:.5rem .75rem;
  }
  .queue-list td{border:none;padding:.2rem 0;word-break:break-word}
  .queue-list td::before{
    content:attr(data-label);display:block;font-weight:700;text-transform:uppercase;
    letter-spacing:.06em;font-size:.72rem;color:var(--muted);margin-bottom:.1rem;
  }
  .queue-list td:last-child::before{content:none}
  .admin-ops{font-size:.85rem;color:var(--muted)}
}

.user-row form{display:inline}
.user-row button{min-height:36px;padding:.35rem .7rem;font-size:.8rem;margin-left:.35rem}
"#;

fn page_shell(title: &str, user: &str, body: &str) -> String {
    let nav = if user.is_empty() {
        format!(
            "<nav class=\"site-nav\" id=\"site-nav\" aria-label=\"Site\">\
             <div class=\"site-nav-inner\">\
             <a class=\"nav-brand\" href=\"/login\">{}<span>DESERTEMAIL</span></a>\
             </div></nav>",
            CACTUS_SVG
        )
    } else {
        format!(
            "<nav class=\"site-nav\" id=\"site-nav\" aria-label=\"Site\">\
             <div class=\"site-nav-inner\">\
             <a class=\"nav-brand\" href=\"/\">{}<span>DESERTEMAIL</span></a>\
             <button type=\"button\" class=\"nav-toggle\" id=\"nav-toggle\" \
             aria-expanded=\"false\" aria-controls=\"nav-menu\" aria-label=\"Open menu\">☰</button>\
             <ul class=\"nav-links\" id=\"nav-menu\">\
             <li><a href=\"/\">Inbox</a></li>\
             <li><a href=\"/compose\">Compose</a></li>\
             <li><a href=\"/sent\">Sent</a></li>\
             <li><a href=\"/admin\">Admin</a></li>\
             <li><a href=\"/logout\">Logout</a></li>\
             <li class=\"nav-user\">{}</li>\
             </ul></div></nav>",
            CACTUS_SVG,
            esc(user)
        )
    };
    let script = if user.is_empty() {
        String::new()
    } else {
        "<script>(function(){var n=document.getElementById(\"site-nav\"),t=document.getElementById(\"nav-toggle\");\
         if(t&&n){t.addEventListener(\"click\",function(){var o=!n.classList.contains(\"is-open\");\
         n.classList.toggle(\"is-open\",o);t.setAttribute(\"aria-expanded\",o?\"true\":\"false\");\
         t.setAttribute(\"aria-label\",o?\"Close menu\":\"Open menu\")})}})();</script>"
            .to_string()
    };
    format!(
        "<!DOCTYPE html><html lang=\"en\"><head><meta charset=\"utf-8\">\
         <meta name=\"viewport\" content=\"width=device-width, initial-scale=1\">\
         <title>{}</title>{}<style>{}</style></head><body>{}<div class=\"wrap\">{}</div>{}</body></html>",
        esc(title),
        FAVICON_LINK,
        STYLE,
        nav,
        body,
        script
    )
}

fn page_login(error: Option<&str>, status: u16) -> Response {
    let err = error
        .map(|e| format!("<p class=\"err\">{}</p>", esc(e)))
        .unwrap_or_default();
    let body = format!(
        "<div class=\"login-wrap\"><div class=\"pix-panel login-card\">\
         <div class=\"login-brand\">{}<span>DESERTEMAIL</span></div>\
         <h1>Login</h1>\
         <p class=\"muted\" style=\"text-align:center;margin-top:-.35rem;font-size:.85rem\">\
         Credentials were chosen during setup</p>\
         {}<form method=\"post\" action=\"/login\">\
         <label>Username</label><input type=\"text\" name=\"username\" autofocus required autocomplete=\"username\">\
         <label>Password</label><input type=\"password\" name=\"password\" required autocomplete=\"current-password\">\
         <p><button type=\"submit\">Sign in</button></p></form></div></div>",
        CACTUS_SVG,
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
        format!("{}@{}", user, cfg.primary_domain())
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
        rows.push_str("<tr class=\"empty\"><td colspan=\"4\">No messages</td></tr>");
    } else {
        for m in &msgs {
            let raw = md.read_message(&m.path).unwrap_or_default();
            let headers = extract_headers(&raw);
            let subject = headers.get("subject").map(|s| s.as_str()).unwrap_or("(no subject)");
            let from = headers.get("from").map(|s| s.as_str()).unwrap_or("");
            let date = headers.get("date").map(|s| s.as_str()).unwrap_or("");
            let unread = m.in_new || !m.flags.contains('S');
            let cls = if unread {
                " class=\"msg-row unread\""
            } else {
                " class=\"msg-row\""
            };
            let status = if unread { "unread" } else { "read" };
            let link = if sent {
                format!("/msg?id={}&folder=sent", m.uid)
            } else {
                format!("/msg?id={}", m.uid)
            };
            rows.push_str(&format!(
                "<tr{}><td class=\"msg-subject\"><a href=\"{}\">{}</a></td>\
                 <td class=\"msg-from\">{}</td><td class=\"msg-date\">{}</td>\
                 <td class=\"msg-status\">{}</td></tr>",
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
        "<h1>{}</h1><table class=\"msg-list\"><thead><tr>\
         <th>Subject</th><th>From</th><th>Date</th><th>Status</th></tr></thead>\
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
            "<div class=\"raw-toggle\"><h2>Raw source</h2>\
             <pre class=\"code\">{}</pre>\
             <p><a href=\"/msg?id={}{}\">Hide raw</a></p></div>",
            esc(&String::from_utf8_lossy(&raw)),
            id,
            folder_q
        )
    } else {
        format!(
            "<p class=\"raw-toggle\"><a href=\"/msg?id={}&raw=1{}\">Show raw source</a></p>",
            id, folder_q
        )
    };

    let back = if folder_sent { "/sent" } else { "/" };
    let body = format!(
        "<p class=\"back-link\"><a href=\"{}\">&larr; Back</a></p>\
         <div class=\"pix-panel msg-headers\">\
         <h1>{}</h1>\
         <p><strong>From:</strong> {}</p>\
         <p><strong>To:</strong> {}</p>\
         <p><strong>Date:</strong> {}</p>\
         </div>\
         <div class=\"pix-panel msg-body\">{}</div>\
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
        "<div class=\"pix-panel compose-panel\"><h1>Compose</h1>{}{}\
         <form method=\"post\" action=\"/send\">\
         <label>To</label><input type=\"text\" name=\"to\" required autocomplete=\"email\">\
         <label>Subject</label><input type=\"text\" name=\"subject\">\
         <label>Body</label><textarea name=\"body\"></textarea>\
         <p><button type=\"submit\" class=\"btn-primary\">Send</button></p></form></div>",
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
    let domain = cfg.primary_domain();
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
    match cfg.admin_user_name() {
        Some(a) if !a.is_empty() => a.eq_ignore_ascii_case(user),
        _ => false,
    }
}

fn page_admin(cfg: &Config, user: &str, flash: Option<&str>) -> Response {
    if !is_admin(cfg, user) {
        let body = if cfg
            .admin_user_name()
            .map(|s| s.is_empty())
            .unwrap_or(true)
        {
            "<h1>Admin</h1><p class=\"err\">Admin page is disabled (admin_user not set).</p>"
                .to_string()
        } else {
            "<h1>Admin</h1><p class=\"err\">Access denied.</p>".to_string()
        };
        return Response::html(403, "Forbidden", page_shell("Admin", user, &body));
    }

    let domains: String = cfg
        .domains_list()
        .iter()
        .map(|d| format!("<li>{}</li>", esc(d)))
        .collect();

    let names = cfg.user_names();
    let mut users_html = String::new();
    for n in &names {
        users_html.push_str(&format!(
            "<li class=\"user-row\">{} \
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
                "<tr class=\"empty\"><td colspan=\"6\">Queue empty</td></tr>".to_string()
            } else {
                let mut rows = String::new();
                for m in msgs {
                    rows.push_str(&format!(
                        "<tr>\
                         <td data-label=\"ID\">{}</td>\
                         <td data-label=\"Sender\">{}</td>\
                         <td data-label=\"Recipients\">{}</td>\
                         <td data-label=\"Retries\">{}</td>\
                         <td data-label=\"Next attempt\">{}</td>\
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
        "<h1>Admin</h1>{}\
         <div class=\"pix-panel\"><h2>Domains</h2><ul>{}</ul></div>\
         <div class=\"pix-panel\"><h2>Users</h2><ul>{}</ul>\
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
         <p><button type=\"submit\">Set quota</button></p></form></div>\
         <div class=\"pix-panel\"><h2>Outbound queue</h2>\
         <div class=\"table-scroll\">\
         <table class=\"queue-list\"><thead><tr><th>ID</th><th>Sender</th><th>Recipients</th>\
         <th>Retries</th><th>Next attempt</th><th></th></tr></thead>\
         <tbody>{}</tbody></table></div></div>\
         <p class=\"admin-ops\">Ops: <code>/healthz</code> · <code>/metrics</code></p>",
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

    #[test]
    fn loopback_peer_detection() {
        assert!(is_loopback_peer("127.0.0.1"));
        assert!(is_loopback_peer("::1"));
        assert!(is_loopback_peer("::ffff:127.0.0.1"));
        assert!(!is_loopback_peer("192.168.1.1"));
        assert!(!is_loopback_peer("10.0.0.2"));
    }
}
