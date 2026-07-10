//! Minimal HTTP/1.1 webmail + admin UI. Pure std, thread-per-connection.

use std::collections::HashMap;
use std::io::{self, BufRead, BufReader, Write};
use std::net::{TcpListener, TcpStream};
use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::{Mutex, OnceLock};
use std::sync::Arc;
use std::thread;

use crate::auth;
use crate::config::Config;
use crate::crypto;
use crate::queue;
use crate::storage::Maildir;
use crate::util;

// ---------------------------------------------------------------------------
// Session store
// ---------------------------------------------------------------------------

fn sessions() -> &'static Mutex<HashMap<String, String>> {
    static S: OnceLock<Mutex<HashMap<String, String>>> = OnceLock::new();
    S.get_or_init(|| Mutex::new(HashMap::new()))
}

/// 32 bytes from the OS CSPRNG. Timestamp/PID would be guessable, letting an
/// attacker who knows the rough login time brute-force session tokens.
fn os_random_seed() -> [u8; 32] {
    #[cfg(unix)]
    {
        use std::io::Read;
        let mut buf = [0u8; 32];
        if let Ok(mut f) = std::fs::File::open("/dev/urandom") {
            if f.read_exact(&mut buf).is_ok() {
                return buf;
            }
        }
    }
    #[cfg(windows)]
    {
        // BCryptGenRandom via system bcrypt.dll (no external crates).
        #[link(name = "bcrypt")]
        extern "system" {
            fn BCryptGenRandom(
                h_algorithm: *mut core::ffi::c_void,
                pb_buffer: *mut u8,
                cb_buffer: u32,
                dw_flags: u32,
            ) -> i32; // NTSTATUS
        }
        const BCRYPT_USE_SYSTEM_PREFERRED_RNG: u32 = 0x0000_0002;
        let mut buf = [0u8; 32];
        // STATUS_SUCCESS == 0
        let status = unsafe {
            BCryptGenRandom(
                core::ptr::null_mut(),
                buf.as_mut_ptr(),
                buf.len() as u32,
                BCRYPT_USE_SYSTEM_PREFERRED_RNG,
            )
        };
        if status == 0 {
            return buf;
        }
    }
    // Last-resort fallback (CSPRNG unavailable): hash time + pid.
    let material = format!("{}:{}", util::now_millis(), std::process::id());
    crypto::sha256(material.as_bytes())
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
            let key = line[..colon].trim().to_lowercase();
            let val = line[colon + 1..].trim().to_string();
            headers.insert(key, val);
        }
    }

    let mut content_len = 0usize;
    if let Some(cl) = headers.get("content-length") {
        content_len = cl.parse().unwrap_or(0);
    }
    // Cap body size to avoid unbounded allocation (16 MiB).
    if content_len > 16 * 1024 * 1024 {
        content_len = 0;
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
        (target[..q].to_string(), parse_urlencoded(&target[q + 1..]))
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
        if bytes[i] == b'%' && i + 2 < bytes.len() {
            if let (Some(hi), Some(lo)) = (from_hex(bytes[i + 1]), from_hex(bytes[i + 2])) {
                out.push((hi << 4) | lo);
                i += 3;
                continue;
            }
        }
        if bytes[i] == b'+' {
            out.push(b' ');
        } else {
            out.push(bytes[i]);
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
            let k = percent_decode(&pair[..eq]);
            let v = percent_decode(&pair[eq + 1..]);
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
            if part[..eq].trim() == name {
                return Some(part[eq + 1..].trim().to_string());
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

    fn write_to(self, stream: &mut TcpStream) -> io::Result<()> {
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

// ---------------------------------------------------------------------------
// Server
// ---------------------------------------------------------------------------

pub fn start(cfg: Arc<Config>) {
    let addr = cfg.web_listen.clone();
    if addr.is_empty() {
        util::log!("web: disabled (web_listen empty)");
        return;
    }
    thread::spawn(move || {
        let listener = match TcpListener::bind(&addr) {
            Ok(l) => l,
            Err(e) => {
                util::log!("web: FATAL cannot bind {}: {}", addr, e);
                return;
            }
        };
        util::log!("web: listening on {}", addr);
        for conn in listener.incoming() {
            match conn {
                Ok(stream) => {
                    let cfg = Arc::clone(&cfg);
                    thread::spawn(move || {
                        if let Err(e) = handle_connection(stream, &cfg) {
                            util::log!("web: connection error: {}", e);
                        }
                    });
                }
                Err(e) => util::log!("web: accept error: {}", e),
            }
        }
    });
}

fn handle_connection(stream: TcpStream, cfg: &Config) -> io::Result<()> {
    let _ = stream.set_read_timeout(Some(std::time::Duration::from_secs(30)));
    let _ = stream.set_write_timeout(Some(std::time::Duration::from_secs(30)));
    let peer = stream
        .peer_addr()
        .map(|a| a.to_string())
        .unwrap_or_else(|_| "?".into());
    let mut reader = BufReader::new(stream.try_clone()?);
    let mut writer = stream;

    let req = match parse_request(&mut reader)? {
        Some(r) => r,
        None => return Ok(()),
    };
    util::log!("web: {} {} {}", peer, req.method, req.path);

    let resp = route(cfg, &req);
    resp.write_to(&mut writer)
}

fn route(cfg: &Config, req: &Request) -> Response {
    let token = cookie_value(req, "session");
    let user = session_user(token.as_deref());

    match (req.method.as_str(), req.path.as_str()) {
        ("GET", "/login") => page_login(None),
        ("POST", "/login") => handle_login(cfg, req),
        ("GET", "/logout") => {
            clear_session(token.as_deref());
            Response::redirect("/login")
                .with_cookie("session=; HttpOnly; Path=/; SameSite=Lax; Max-Age=0")
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
                ("GET", "/admin") | ("POST", "/admin") => page_admin(cfg, &user, None),
                ("POST", "/admin/queue/delete") => handle_queue_delete(cfg, &user, req),
                _ => Response::html(404, "Not Found", page_shell("Not Found", &user, "<p>404</p>")),
            }
        }
    }
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

fn page_login(error: Option<&str>) -> Response {
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
    Response::html(200, "OK", page_shell("Login", "", &body))
}

fn handle_login(cfg: &Config, req: &Request) -> Response {
    let form = form_body(req);
    let username = form.get("username").map(|s| s.trim()).unwrap_or("");
    let password = form.get("password").map(|s| s.as_str()).unwrap_or("");
    if username.is_empty() {
        return page_login(Some("Username required"));
    }
    if !auth::authenticate(cfg, username, password) {
        return page_login(Some("Invalid username or password"));
    }
    let user = username.to_lowercase();
    let token = make_session_token(&user);
    set_session(&token, &user);
    Response::redirect("/").with_cookie(&format!(
        "session={}; HttpOnly; Path=/; SameSite=Lax",
        token
    ))
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
            current_key = line[..colon].trim().to_lowercase();
            current_val = line[colon + 1..].trim().to_string();
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
        return p + 4;
    }
    if let Some(p) = raw.windows(2).position(|w| w == b"\n\n") {
        return p + 2;
    }
    raw.len()
}

/// Minimal MIME: if multipart, return first text/plain part body; else whole body.
fn extract_text_body(raw: &[u8], headers: &HashMap<String, String>) -> String {
    let body_start = header_block_end(raw);
    let body = &raw[body_start..];
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
    let rest = content_type[idx + 9..].trim();
    let rest = rest.trim_start_matches('"');
    let end = rest
        .find(|c: char| c == '"' || c == ';' || c.is_whitespace())
        .unwrap_or(rest.len());
    let b = rest[..end].trim().trim_matches('"');
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
                cur_k = line[..colon].trim().to_lowercase();
                cur_v = line[colon + 1..].trim().to_string();
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
            if let Some(end) = part[start..].find('>') {
                part[start + 1..start + end].trim().to_string()
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

    let mut users_html = String::new();
    let mut names: Vec<_> = cfg.users.keys().cloned().collect();
    names.sort();
    for n in names {
        users_html.push_str(&format!("<li>{}</li>", esc(&n)));
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
        .map(|f| format!("<p class=\"ok\">{}</p>", esc(f)))
        .unwrap_or_default();

    let body = format!(
        "<h1>Admin</h1>{}<h2>Domains</h2><ul>{}</ul>\
         <h2>Users</h2><ul>{}</ul>\
         <h2>Outbound queue</h2>\
         <table><thead><tr><th>ID</th><th>Sender</th><th>Recipients</th>\
         <th>Retries</th><th>Next attempt</th><th></th></tr></thead>\
         <tbody>{}</tbody></table>",
        flash_html, domains, users_html, queue_rows
    );
    Response::html(200, "OK", page_shell("Admin", user, &body))
}

fn handle_queue_delete(cfg: &Config, user: &str, req: &Request) -> Response {
    if !is_admin(cfg, user) {
        return page_admin(cfg, user, None);
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
}
