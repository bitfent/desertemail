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
use crate::invites;
use crate::limits;
use crate::metrics;
use crate::passwd;
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
// CSRF (synchronizer token derived from session — no extra server state)
// ---------------------------------------------------------------------------

/// Per-session CSRF token: SHA-256(session_seed || "csrf:" || session_token).
/// Stable for the life of the session; regenerates when the session cookie changes.
fn csrf_token_for(session_token: &str) -> String {
    let mut material = Vec::with_capacity(32 + 5 + session_token.len());
    material.extend_from_slice(session_seed());
    material.extend_from_slice(b"csrf:");
    material.extend_from_slice(session_token.as_bytes());
    hex_encode(&crypto::sha256(&material))
}

/// Hidden input for authenticated mutating forms.
fn csrf_field(session_token: &str) -> String {
    if session_token.is_empty() {
        return String::new();
    }
    format!(
        "<input type=\"hidden\" name=\"csrf\" value=\"{}\">",
        esc(&csrf_token_for(session_token))
    )
}

/// Extract `csrf` form field from urlencoded or multipart body.
fn form_csrf_token(req: &Request) -> Option<String> {
    let ct = req
        .headers
        .get("content-type")
        .map(|s| s.as_str())
        .unwrap_or("");
    if ct.to_lowercase().contains("multipart/form-data") {
        let (fields, _) = parse_multipart_form(req);
        return fields.get("csrf").cloned();
    }
    form_body(req).get("csrf").cloned()
}

/// Primary CSRF check for authenticated POSTs (session cookie + form token).
fn csrf_ok(req: &Request) -> bool {
    let sess = match cookie_value(req, "session") {
        Some(t) if !t.is_empty() => t,
        _ => return false,
    };
    let expected = csrf_token_for(&sess);
    match form_csrf_token(req) {
        Some(provided) => passwd::ct_eq_str(&provided, &expected),
        None => false,
    }
}

fn csrf_fail_page(user: &str) -> Response {
    let body = "<h1>Form expired</h1>\
         <p>Please go back and try again. This can happen if you left a page open too long \
         or submitted a form from another site.</p>\
         <p><a href=\"/\">Return to inbox</a></p>";
    Response::html(
        403,
        "Forbidden",
        page_shell_app("Form expired", user, "", 0, None, body),
    )
}

/// Origin + synchronizer-token check for every authenticated mutating POST.
fn require_auth_post(req: &Request, user: &str) -> Option<Response> {
    if !same_origin_ok(req) || !csrf_ok(req) {
        Some(csrf_fail_page(user))
    } else {
        None
    }
}

/// Inject `csrf` hidden fields into every POST form in an HTML fragment.
fn inject_csrf_into_forms(html: &str, session_token: &str) -> String {
    if session_token.is_empty() || html.is_empty() {
        return html.to_string();
    }
    let field = csrf_field(session_token);
    if field.is_empty() {
        return html.to_string();
    }
    let mut out = String::with_capacity(html.len() + field.len() * 8);
    let mut rest = html;
    while let Some(idx) = rest.find("<form") {
        out.push_str(&rest[..idx]);
        let after = &rest[idx..];
        if let Some(end) = after.find('>') {
            let open = &after[..=end];
            let open_l = open.to_ascii_lowercase();
            out.push_str(open);
            // Only mutating forms (method=post). Forms without method default to GET.
            if open_l.contains("method=\"post\"") || open_l.contains("method='post'") {
                // Avoid double-injection if already present right after open tag.
                let tail = &after[end + 1..];
                if !tail.trim_start().starts_with(&field)
                    && !tail
                        .get(..200)
                        .unwrap_or(tail)
                        .contains("name=\"csrf\"")
                {
                    out.push_str(&field);
                }
            }
            rest = &after[end + 1..];
        } else {
            out.push_str(after);
            rest = "";
        }
    }
    out.push_str(rest);
    out
}

// ---------------------------------------------------------------------------
// TLS UX: warning banner, proxy-aware HTTPS detection, redirect + HSTS
// ---------------------------------------------------------------------------

/// True once `start_tls` has successfully bound the HTTPS web listener.
fn web_tls_listener_active() -> &'static std::sync::atomic::AtomicBool {
    static A: OnceLock<std::sync::atomic::AtomicBool> = OnceLock::new();
    A.get_or_init(|| std::sync::atomic::AtomicBool::new(false))
}

fn mark_web_tls_listener_active() {
    web_tls_listener_active().store(true, std::sync::atomic::Ordering::SeqCst);
}

/// Decision matrix for TLS UX (unit-tested).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum TlsUxAction {
    /// Serve as-is (loopback plaintext escape hatch, or already secure).
    None,
    /// Show cleartext warning banner (non-loopback HTTP, no trusted HTTPS signal).
    WarnCleartext,
    /// 301 redirect to https:// equivalent (TLS listener active, non-loopback HTTP).
    RedirectHttps,
}

/// Pure decision function: peer loopback × tls-active × trust_proxy × X-Forwarded-Proto.
fn tls_ux_decision(
    peer_loopback: bool,
    connection_secure: bool,
    tls_listener_active: bool,
    trust_proxy_headers: bool,
    x_forwarded_proto: Option<&str>,
) -> TlsUxAction {
    let behind_tls = connection_is_https(connection_secure, trust_proxy_headers, x_forwarded_proto);
    if behind_tls {
        return TlsUxAction::None;
    }
    if peer_loopback {
        return TlsUxAction::None;
    }
    if tls_listener_active {
        return TlsUxAction::RedirectHttps;
    }
    TlsUxAction::WarnCleartext
}

/// Direct TLS listener, or (when trust_proxy_headers) X-Forwarded-Proto: https.
fn connection_is_https(
    connection_secure: bool,
    trust_proxy_headers: bool,
    x_forwarded_proto: Option<&str>,
) -> bool {
    if connection_secure {
        return true;
    }
    if !trust_proxy_headers {
        return false;
    }
    let Some(proto) = x_forwarded_proto else {
        return false;
    };
    // First value if comma-separated chain.
    let first = proto.split(',').next().unwrap_or("").trim();
    first.eq_ignore_ascii_case("https")
}

fn request_x_forwarded_proto(req: &Request) -> Option<&str> {
    req.headers.get("x-forwarded-proto").map(|s| s.as_str())
}

fn should_add_hsts(connection_secure: bool) -> bool {
    connection_secure
}

/// Build https:// Location for HTTP→HTTPS redirect (preserve host/path/query; tls port when ≠443).
fn https_redirect_location(req: &Request, cfg: &Config) -> String {
    let host_hdr = req
        .headers
        .get("host")
        .map(|s| s.as_str())
        .filter(|h| !h.is_empty())
        .unwrap_or("localhost");
    // Strip any existing port from Host; re-attach TLS port when non-443.
    let hostname = host_hdr.split(':').next().unwrap_or(host_hdr);
    let tls_port: Option<u16> = cfg
        .web_tls_listen
        .rsplit(':')
        .next()
        .and_then(|p| p.parse().ok());
    let authority = match tls_port {
        Some(443) | None => hostname.to_string(),
        Some(p) => format!("{}:{}", hostname, p),
    };
    let path = if req.path.is_empty() {
        "/"
    } else {
        req.path.as_str()
    };
    // Reconstruct query string from parsed map (order not critical for redirect).
    let mut qparts: Vec<String> = req
        .query
        .iter()
        .map(|(k, v)| {
            if v.is_empty() {
                urlencode_component(k)
            } else {
                format!("{}={}", urlencode_component(k), urlencode_component(v))
            }
        })
        .collect();
    qparts.sort();
    let query = if qparts.is_empty() {
        String::new()
    } else {
        format!("?{}", qparts.join("&"))
    };
    format!("https://{}{}{}", authority, path, query)
}

// Per-request context for page renderers (thread-per-connection server).
thread_local! {
    static REQ_SESSION: std::cell::RefCell<String> = std::cell::RefCell::new(String::new());
    static REQ_TLS_WARN: std::cell::Cell<bool> = std::cell::Cell::new(false);
}

fn with_request_render_ctx<R>(session: &str, tls_warn: bool, f: impl FnOnce() -> R) -> R {
    REQ_SESSION.with(|c| *c.borrow_mut() = session.to_string());
    REQ_TLS_WARN.with(|c| c.set(tls_warn));
    let r = f();
    REQ_SESSION.with(|c| c.borrow_mut().clear());
    REQ_TLS_WARN.with(|c| c.set(false));
    r
}

fn current_session_token() -> String {
    REQ_SESSION.with(|c| c.borrow().clone())
}

fn current_tls_warn() -> bool {
    REQ_TLS_WARN.with(|c| c.get())
}

fn tls_warning_banner_html() -> String {
    if !current_tls_warn() {
        return String::new();
    }
    "<div class=\"banner tls-warn\" role=\"alert\">\
     <a class=\"dismiss\" href=\"?dismiss_tls_warn=1\">dismiss</a>\
     Connection is not encrypted — enable TLS in \
     <a href=\"/dns\">Security settings</a>.\
     </div>"
        .to_string()
}

fn tls_warn_dismissed(req: &Request) -> bool {
    cookie_value(req, "dismiss_tls_warn").as_deref() == Some("1")
        || req.query.get("dismiss_tls_warn").map(|s| s.as_str()) == Some("1")
}

fn maybe_dismiss_tls_cookie(req: &Request, mut resp: Response) -> Response {
    if req.query.get("dismiss_tls_warn").map(|s| s.as_str()) == Some("1") {
        resp = resp.with_cookie("dismiss_tls_warn=1; Path=/; SameSite=Lax; Max-Age=86400");
    }
    resp
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

/// Fuzz-visible MIME message walker entry: full message bytes (headers +
/// body). Exercises the multipart walker, transfer decoding, HTML stripping
/// and attachment extraction.
pub fn fuzz_parse_mime(data: &[u8]) {
    let parsed = parse_mime_message(data);
    let _ = parsed.text.len();
    let _ = parsed.attachments.len();
}

/// Fuzz-visible multipart/form-data parser entry. First line of `data` is
/// used as the boundary, the rest as the request body.
pub fn fuzz_multipart_form(data: &[u8]) {
    let split = data.iter().position(|&b| b == b'\n').unwrap_or(data.len());
    let boundary = String::from_utf8_lossy(&data[..split]).into_owned();
    let body = data.get(split + 1..).unwrap_or(&[]).to_vec();
    let mut headers = HashMap::new();
    headers.insert(
        "content-type".to_string(),
        format!("multipart/form-data; boundary={}", boundary),
    );
    let req = Request {
        method: "POST".into(),
        path: "/send".into(),
        query: HashMap::new(),
        headers,
        body,
    };
    let (fields, files) = parse_multipart_form(&req);
    let _ = fields.len();
    let _ = files.len();
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

    // Cap header count: unbounded header lines would let a client grow the
    // map (and consume parse time) indefinitely.
    const MAX_HEADER_LINES: usize = 200;
    let mut headers = HashMap::new();
    let mut header_lines = 0usize;
    loop {
        let line = match util::read_line(reader)? {
            Some(l) => l,
            None => break,
        };
        if line.is_empty() {
            break;
        }
        header_lines += 1;
        if header_lines > MAX_HEADER_LINES {
            return Err(io::Error::new(
                io::ErrorKind::InvalidData,
                "too many request headers",
            ));
        }
        if let Some(colon) = line.find(':') {
            let key = line.get(..colon).unwrap_or("").trim().to_lowercase();
            let val = line.get(colon + 1..).unwrap_or("").trim().to_string();
            headers.insert(key, val);
        }
    }

    // Cap body size: reject oversize with empty body (caller gets no form fields).
    // ~15 MiB allows compose with attachments (Gmail-like upload).
    const MAX_HTTP_BODY: usize = 15 * 1024 * 1024;
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
    let ct_lower = ct.to_lowercase();
    if ct_lower.contains("multipart/form-data") {
        let (fields, _files) = parse_multipart_form(req);
        return fields;
    }
    if ct_lower.contains("application/x-www-form-urlencoded") || req.method == "POST" {
        let s = String::from_utf8_lossy(&req.body);
        return parse_urlencoded(s.trim());
    }
    HashMap::new()
}

/// Uploaded file part from multipart/form-data.
struct FormFile {
    field: String,
    filename: String,
    content_type: String,
    data: Vec<u8>,
}

/// Parse multipart/form-data into text fields + file parts.
/// Total body already capped by the request parser (~15 MiB).
fn parse_multipart_form(req: &Request) -> (HashMap<String, String>, Vec<FormFile>) {
    let mut fields = HashMap::new();
    let mut files = Vec::new();
    let ct = req
        .headers
        .get("content-type")
        .map(|s| s.as_str())
        .unwrap_or("");
    let boundary = match multipart_form_boundary(ct) {
        Some(b) => b,
        None => return (fields, files),
    };
    let delim = format!("--{}", boundary);
    let body = &req.body;
    // Split on boundary markers in bytes.
    let delim_bytes = delim.as_bytes();
    let mut parts: Vec<&[u8]> = Vec::new();
    let mut start = 0usize;
    while start < body.len() {
        if let Some(rel) = find_bytes(&body[start..], delim_bytes) {
            if start > 0 {
                // previous chunk ends just before this delimiter
            }
            let abs = start + rel;
            if abs > start {
                // material between previous and this delim is a part (with leading CRLF)
            }
            // Advance past delimiter
            let after = abs + delim_bytes.len();
            // Closing -- 
            if body.get(after..after + 2) == Some(b"--") {
                break;
            }
            // Skip optional CRLF after boundary
            let mut content_start = after;
            if body.get(content_start..content_start + 2) == Some(b"\r\n") {
                content_start += 2;
            } else if body.get(content_start..content_start + 1) == Some(b"\n") {
                content_start += 1;
            }
            // Find next boundary
            if let Some(rel2) = find_bytes(&body[content_start..], delim_bytes) {
                let mut end = content_start + rel2;
                // strip trailing CRLF before next boundary
                if end >= 2 && &body[end - 2..end] == b"\r\n" {
                    end -= 2;
                } else if end >= 1 && body[end - 1] == b'\n' {
                    end -= 1;
                }
                parts.push(&body[content_start..end]);
                start = content_start + rel2;
            } else {
                break;
            }
        } else {
            break;
        }
    }
    for part in parts {
        if part.is_empty() {
            continue;
        }
        let (hdrs, data) = split_mime_part_bytes(part);
        let cd = hdrs
            .get("content-disposition")
            .map(|s| s.as_str())
            .unwrap_or("");
        let name = content_disposition_param(cd, "name").unwrap_or_default();
        if name.is_empty() {
            continue;
        }
        if let Some(filename) = content_disposition_param(cd, "filename") {
            let ctyp = hdrs
                .get("content-type")
                .cloned()
                .unwrap_or_else(|| "application/octet-stream".into());
            files.push(FormFile {
                field: name,
                filename,
                content_type: ctyp,
                data: data.to_vec(),
            });
        } else {
            let text = String::from_utf8_lossy(data).into_owned();
            fields.insert(name, text);
        }
    }
    (fields, files)
}

fn multipart_form_boundary(content_type: &str) -> Option<String> {
    mime_boundary(content_type)
}

fn find_bytes(hay: &[u8], needle: &[u8]) -> Option<usize> {
    if needle.is_empty() || hay.len() < needle.len() {
        return None;
    }
    hay.windows(needle.len()).position(|w| w == needle)
}

fn content_disposition_param(cd: &str, key: &str) -> Option<String> {
    // name="foo" or filename="bar.txt"
    let key_eq = format!("{}=", key);
    let lower = cd.to_lowercase();
    let key_l = key_eq.to_lowercase();
    let idx = lower.find(&key_l)?;
    let rest = cd.get(idx + key_eq.len()..)?.trim();
    if let Some(stripped) = rest.strip_prefix('"') {
        let end = stripped.find('"')?;
        Some(stripped[..end].to_string())
    } else {
        let end = rest
            .find(|c: char| c == ';' || c.is_whitespace())
            .unwrap_or(rest.len());
        Some(rest[..end].trim().to_string())
    }
}

/// Split a MIME part into headers map + body bytes (raw, no transfer decode).
fn split_mime_part_bytes(part: &[u8]) -> (HashMap<String, String>, &[u8]) {
    let mut headers = HashMap::new();
    let sep = if let Some(p) = find_bytes(part, b"\r\n\r\n") {
        (p, 4)
    } else if let Some(p) = find_bytes(part, b"\n\n") {
        (p, 2)
    } else {
        return (headers, part);
    };
    let header_block = String::from_utf8_lossy(&part[..sep.0]);
    let mut cur_k = String::new();
    let mut cur_v = String::new();
    for line in header_block.lines() {
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
        } else {
            cur_k.clear();
            cur_v.clear();
        }
    }
    if !cur_k.is_empty() {
        headers.insert(cur_k, cur_v);
    }
    let body_start = sep.0 + sep.1;
    (headers, part.get(body_start..).unwrap_or(&[]))
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

    fn redirect_permanent(location: &str) -> Self {
        Self {
            status: 301,
            reason: "Moved Permanently",
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

    fn with_header(mut self, name: &str, value: &str) -> Self {
        self.headers.push((name.into(), value.into()));
        self
    }

    /// Binary download (attachments). Always sets nosniff + attachment disposition.
    fn attachment(filename: &str, data: Vec<u8>) -> Self {
        let safe_name = filename
            .chars()
            .map(|c| {
                if c.is_ascii_alphanumeric() || c == '.' || c == '-' || c == '_' {
                    c
                } else {
                    '_'
                }
            })
            .collect::<String>();
        let safe_name = if safe_name.is_empty() {
            "attachment".into()
        } else {
            safe_name
        };
        Self {
            status: 200,
            reason: "OK",
            headers: vec![
                ("Content-Type".into(), "application/octet-stream".into()),
                (
                    "Content-Disposition".into(),
                    format!("attachment; filename=\"{}\"", safe_name),
                ),
                ("X-Content-Type-Options".into(), "nosniff".into()),
                ("Content-Length".into(), data.len().to_string()),
                ("Connection".into(), "close".into()),
            ],
            body: data,
        }
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
        if secure {
            mark_web_tls_listener_active();
        }
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

    let mut resp = route(cfg, &req, secure, &peer_ip);
    if should_add_hsts(secure) {
        resp = resp.with_header("Strict-Transport-Security", "max-age=15552000");
    }
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
    // Never HTTP→HTTPS redirect this path (Let's Encrypt validates over plain HTTP).
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

    // HTTP→HTTPS redirect when the TLS web listener is active (non-loopback only).
    let xfp = request_x_forwarded_proto(req);
    let tls_active = web_tls_listener_active().load(std::sync::atomic::Ordering::SeqCst);
    let ux = tls_ux_decision(
        is_loopback_peer(peer_ip),
        secure,
        tls_active,
        cfg.trust_proxy_headers,
        xfp,
    );
    if ux == TlsUxAction::RedirectHttps {
        return Response::redirect_permanent(&https_redirect_location(req, cfg));
    }
    let show_tls_warn = ux == TlsUxAction::WarnCleartext && !tls_warn_dismissed(req);
    let sess = token.as_deref().unwrap_or("");

    with_request_render_ctx(sess, show_tls_warn, || {
    let resp = route_inner(cfg, req, secure, peer_ip, token.as_deref(), user);
    maybe_dismiss_tls_cookie(req, resp)
    })
}

fn route_inner(
    cfg: &Config,
    req: &Request,
    secure: bool,
    peer_ip: &str,
    token: Option<&str>,
    user: Option<String>,
) -> Response {
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
        ("GET", "/invite") => page_invite(cfg, req, None, 200),
        ("POST", "/invite") => handle_invite_redeem(cfg, req, secure, peer_ip),
        ("GET", "/logout") => {
            clear_session(token);
            Response::redirect("/login").with_cookie(&clear_session_cookie(secure))
        }
        _ => {
            let user = match user {
                Some(u) => u,
                None => return Response::redirect("/login"),
            };
            match (req.method.as_str(), req.path.as_str()) {
                ("GET", "/") | ("GET", "/inbox") => page_inbox(cfg, &user, req),
                ("GET", "/starred") => page_folder(cfg, &user, "starred", req),
                ("GET", "/sent") => page_folder(cfg, &user, "sent", req),
                ("GET", "/drafts") => page_folder(cfg, &user, "drafts", req),
                ("GET", "/spam") => page_folder(cfg, &user, "spam", req),
                ("GET", "/trash") => page_folder(cfg, &user, "trash", req),
                ("GET", "/search") => page_search(cfg, &user, req),
                ("GET", "/msg") => page_message(cfg, &user, req),
                ("GET", "/msg/attachment") => handle_attachment(cfg, &user, req),
                ("GET", "/compose") => page_compose(cfg, &user, req, None, None),
                ("POST", "/send") => handle_send(cfg, &user, req),
                ("POST", "/draft") => handle_save_draft(cfg, &user, req),
                ("POST", "/msg/star") => handle_star(cfg, &user, req),
                ("POST", "/msg/bulk") => handle_bulk(cfg, &user, req),
                ("POST", "/trash/empty") => handle_empty_trash(cfg, &user, req),
                ("POST", "/spam/empty") => handle_empty_spam(cfg, &user, req),
                ("GET", "/dns") => page_dns(cfg, &user, None, None),
                ("POST", "/dns/check") => handle_dns_check(cfg, &user, req, peer_ip),
                ("POST", "/dns/dkim/generate") => handle_dns_dkim_generate(cfg, &user, req),
                ("POST", "/dns/settings") => handle_dns_settings(cfg, &user, req),
                ("POST", "/dns/acme/enable") => handle_dns_acme_enable(cfg, &user, req),
                ("GET", "/admin") => page_admin(cfg, &user, None, None),
                ("GET", "/admin/backup") => handle_admin_backup(cfg, &user),
                ("POST", "/admin") => handle_admin_post(cfg, &user, req),
                ("POST", "/admin/user/add") => handle_admin_user_add(cfg, &user, req),
                ("POST", "/admin/user/remove") => handle_admin_user_remove(cfg, &user, req),
                ("POST", "/admin/user/quota") => handle_admin_user_quota(cfg, &user, req),
                ("POST", "/admin/invite") => handle_admin_invite(cfg, &user, req, secure),
                ("POST", "/admin/invite/revoke") => handle_admin_invite_revoke(cfg, &user, req),
                ("POST", "/admin/invite/regenerate") => {
                    handle_admin_invite_regenerate(cfg, &user, req, secure)
                }
                ("POST", "/admin/queue/delete") => handle_queue_delete(cfg, &user, req),
                _ => Response::html(
                    404,
                    "Not Found",
                    page_shell_app("Not Found", &user, "", count_inbox_unread(cfg, &user), None, "<p>404</p>"),
                ),
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
        if passwd::ct_eq_str(t, &cfg.setup_token) {
            return true;
        }
    }
    if let Some(t) = req.query.get("setup_token") {
        if passwd::ct_eq_str(t, &cfg.setup_token) {
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
         <p class=\"muted\">After DNS, enable TLS on the DNS page (Security) so passwords are never sent in cleartext.</p>\
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
            // Real domains → DNS getting-started; localhost → inbox with banner.
            let dest = if domain_owned.eq_ignore_ascii_case("localhost") {
                "/?localhost_banner=1"
            } else {
                "/dns"
            };
            Response::redirect(dest).with_cookie(&session_cookie(&token, secure))
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
        if passwd::ct_eq_str(q, &cfg.metrics_token) {
            return true;
        }
    }
    if let Some(auth) = req.headers.get("authorization") {
        let prefix = "Bearer ";
        if let Some(rest) = auth.strip_prefix(prefix) {
            if passwd::ct_eq_str(rest, &cfg.metrics_token) {
                return true;
            }
        }
        // Also accept raw token.
        if passwd::ct_eq_str(auth, &cfg.metrics_token) {
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
  --nav-h:52px;--sidebar-w:220px;
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
.warn{color:#9a6b00;font-weight:700}
.muted{color:var(--muted)}
@media (prefers-color-scheme: dark){
  .err{color:#ff8a80}.ok{color:#81c784}.warn{color:#ffd54f}
}
.banner{
  background:var(--panel);border:4px solid var(--border);
  box-shadow:4px 4px 0 0 var(--accent-dark);padding:.75rem 1rem;margin:0 0 1rem;
}
.banner.tls-warn{
  border-color:#b00000;background:#fde8e8;color:#3a2410;
  box-shadow:4px 4px 0 0 #7a0000;
}
@media (prefers-color-scheme: dark){
  .banner.tls-warn{background:#3a1515;color:#ffc9c9;border-color:#ff8a80}
}
.banner a.dismiss{float:right;border-bottom:none;font-size:.85rem}
.dns-table{width:100%;border-collapse:collapse;font-size:.88rem}
.dns-table th,.dns-table td{
  border:2px solid var(--border);padding:.45rem .55rem;text-align:left;vertical-align:top;
  word-break:break-word;
}
.dns-table th{background:var(--code-bg);color:var(--code-ink);text-transform:uppercase;font-size:.72rem;letter-spacing:.06em}
.dns-table code,.dns-val{font-size:.82rem;word-break:break-all}
.dns-status{font-weight:700;white-space:nowrap}
.dns-status.ok{color:#2d6a1e}
.dns-status.fail{color:#b00000}
.dns-status.warn{color:#9a6b00}
@media (prefers-color-scheme: dark){
  .dns-status.ok{color:#81c784}.dns-status.fail{color:#ff8a80}.dns-status.warn{color:#ffd54f}
}
button.copy-btn,button.btn-secondary,.btn-ghost{
  min-height:36px;padding:.3rem .65rem;font-size:.78rem;margin:.15rem .15rem .15rem 0;
  background:var(--panel);color:var(--ink);border:3px solid var(--border);
  box-shadow:2px 2px 0 0 var(--accent-dark);cursor:pointer;font-family:inherit;font-weight:700;
  text-transform:uppercase;letter-spacing:.04em;display:inline-flex;align-items:center;justify-content:center;
  text-decoration:none;
}
button.copy-btn:hover,button.btn-secondary:hover,.btn-ghost:hover{background:var(--accent);color:#2a1a08}
.inline-form{display:inline}

/* --- app shell: fixed sidebar + main --- */
.app-shell{display:flex;min-height:100vh;align-items:stretch}
.app-sidebar{
  width:var(--sidebar-w);flex:none;background:var(--panel);
  border-right:4px solid var(--border);box-shadow:4px 0 0 0 var(--accent-dark);
  display:flex;flex-direction:column;padding:.85rem .7rem 1rem;
  position:sticky;top:0;height:100vh;overflow-y:auto;z-index:50;
}
.app-brand{
  display:flex;align-items:center;gap:.45rem;
  font-weight:700;text-transform:uppercase;letter-spacing:.12em;font-size:.78rem;
  color:var(--ink);border-bottom:none;text-decoration:none;margin:0 0 .85rem;padding:.15rem .2rem;
}
.app-brand:hover{background:transparent;color:var(--ink)}
.nav-logo{width:22px;height:29px;flex:none;display:block}
.btn-compose{
  display:flex;align-items:center;justify-content:center;width:100%;
  font-family:inherit;font-weight:700;text-transform:uppercase;letter-spacing:.1em;font-size:.9rem;
  color:#2a1a08;background:var(--accent);border:4px solid var(--border);
  box-shadow:4px 4px 0 0 var(--accent-dark);padding:.65rem .5rem;cursor:pointer;
  min-height:48px;text-decoration:none;margin:0 0 .9rem;
}
.btn-compose:hover{background:var(--accent-light);color:#2a1a08}
.btn-compose:active{transform:translate(3px,3px);box-shadow:1px 1px 0 0 var(--accent-dark)}
.side-nav{list-style:none;padding:0;margin:0;flex:1}
.side-nav li{margin:0;padding:0}
.side-nav li::before{content:none}
.side-nav a{
  display:flex;align-items:center;justify-content:space-between;gap:.4rem;
  min-height:40px;padding:.35rem .55rem;margin:0 0 .2rem;
  font-weight:700;text-transform:uppercase;letter-spacing:.06em;font-size:.78rem;
  color:var(--ink);border:3px solid transparent;text-decoration:none;border-bottom:none;
}
.side-nav a:hover{background:var(--accent-light);color:#2a1a08;border-color:var(--border)}
.side-nav a.active{
  background:var(--accent);color:#2a1a08;border-color:var(--border);
  box-shadow:3px 3px 0 0 var(--accent-dark);
}
.side-nav .badge{
  background:var(--code-bg);color:var(--code-ink);font-size:.7rem;padding:.1rem .4rem;
  border:2px solid var(--border);min-width:1.4rem;text-align:center;letter-spacing:0;
}
.side-nav a.active .badge{background:#2a1a08;color:var(--accent-light)}
.side-divider{
  border:0;border-top:3px solid var(--border);margin:.55rem 0;height:0;
}
.side-foot{margin-top:auto;padding-top:.5rem}
.side-user{
  display:block;font-size:.72rem;color:var(--muted);word-break:break-all;
  text-transform:none;letter-spacing:0;font-weight:600;padding:.35rem .4rem 0;
}
.side-hint{font-size:.7rem;color:var(--muted);padding:.35rem .4rem;letter-spacing:0;text-transform:none}
.app-main{flex:1;min-width:0;display:flex;flex-direction:column}
.app-topbar{
  display:flex;align-items:center;gap:.65rem;flex-wrap:wrap;
  padding:.65rem 1rem;background:var(--panel);
  border-bottom:4px solid var(--border);box-shadow:0 3px 0 0 var(--accent-dark);
  position:sticky;top:0;z-index:40;
}
.app-topbar h1{
  font-size:1rem;margin:0;text-shadow:none;flex:none;order:2;
}
.topbar-search{flex:1;min-width:10rem;order:3}
.topbar-search form{display:flex;gap:.4rem;align-items:center}
.topbar-search input[type=text],.topbar-search input[type=search]{
  width:100%;min-height:40px;box-shadow:2px 2px 0 0 var(--accent-dark);padding:.4rem .55rem;font-size:15px;
}
.topbar-search button{min-height:40px;padding:.35rem .75rem;font-size:.78rem}
.menu-toggle{
  display:none;order:1;font-family:inherit;font-weight:700;font-size:1.25rem;line-height:1;
  color:var(--ink);background:var(--panel);border:4px solid var(--border);
  box-shadow:3px 3px 0 0 var(--accent-dark);width:44px;height:44px;padding:0;cursor:pointer;
}
.menu-toggle:hover{background:var(--accent-light);color:#2a1a08}
.menu-toggle:active{transform:translate(2px,2px);box-shadow:none}
.app-content{padding:1rem 1.15rem 2.5rem;max-width:1100px;width:100%}
.sidebar-backdrop{
  display:none;position:fixed;inset:0;background:rgba(58,36,16,.35);z-index:45;
}
body.sidebar-open .sidebar-backdrop{display:block}
body.sidebar-open{overflow:hidden;touch-action:none}
@media (max-width:800px){
  .app-sidebar{
    position:fixed;left:0;top:0;transform:translateX(-105%);
    transition:transform .15s steps(3);box-shadow:6px 0 0 0 var(--accent-dark);
    z-index:50;width:min(var(--sidebar-w),86vw);
  }
  body.sidebar-open .app-sidebar{transform:translateX(0)}
  .menu-toggle{display:inline-flex;align-items:center;justify-content:center}
  .app-content{padding:.85rem .75rem 2rem;max-width:100%;overflow-x:clip}
  .app-topbar{padding:.55rem .65rem}
  .app-topbar h1{font-size:.92rem}
  .bulk-bar{gap:.3rem;padding:.35rem .4rem;flex-wrap:nowrap}
  .bulk-bar button{min-height:40px;padding:.25rem .45rem;font-size:.7rem}
  .bulk-bar .lbl-full{display:none}
  .bulk-bar .lbl-short{display:inline}
  .bulk-bar .pager{gap:.4rem;font-size:.75rem;flex:none}
  .bulk-bar .pager .range{display:none}
  .pix-panel{padding:.9rem .85rem;margin:.85rem 0}
}
@media (max-width:380px){
  .bulk-bar{flex-wrap:wrap}
}

/* legacy top nav (login/setup only) */
.site-nav{
  position:sticky;top:0;z-index:100;background:var(--panel);
  border-bottom:4px solid var(--border);box-shadow:0 4px 0 0 var(--accent-dark);
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
button:focus-visible,.btn:focus-visible,input[type=submit]:focus-visible,a:focus-visible,input:focus-visible,textarea:focus-visible,.star-btn:focus-visible{
  outline:3px solid var(--accent);outline-offset:2px;
}
button.btn-primary{font-size:1rem;padding:.7rem 1.5rem;min-width:8rem}
button.btn-danger{background:#c44;color:#fff}
button.btn-danger:hover{background:#e66}
form label{display:block;margin:.65rem 0 .25rem;font-weight:700;text-transform:uppercase;letter-spacing:.06em;font-size:.85rem;color:var(--muted)}
input[type=text],input[type=password],input[type=search],input[type=file],textarea{
  width:100%;box-sizing:border-box;font-family:inherit;font-size:16px;line-height:1.4;
  color:var(--ink);background:var(--bg);border:4px solid var(--border);
  padding:.55rem .65rem;box-shadow:3px 3px 0 0 var(--accent-dark);
}
textarea{min-height:12rem;resize:vertical}
input:focus,textarea:focus{outline:2px solid var(--accent);outline-offset:1px}

/* bulk toolbar */
.bulk-bar{
  display:flex;flex-wrap:wrap;align-items:center;gap:.4rem;margin:0 0 .65rem;
  padding:.45rem .55rem;background:var(--panel);border:3px solid var(--border);
  box-shadow:3px 3px 0 0 var(--accent-dark);
}
.bulk-bar button{min-height:40px;padding:.3rem .7rem;font-size:.75rem}
.bulk-bar .lbl-short{display:none}
.bulk-bar .pager{margin-left:auto;font-size:.82rem;color:var(--muted);display:flex;gap:.65rem;align-items:center;flex-wrap:nowrap}
.bulk-bar .pager a{border-bottom:none;min-height:auto;font-size:.82rem}
.bulk-bar .pager .range{white-space:nowrap}

/* --- message list (card rows; no horizontal scroll) --- */
table{border-collapse:collapse;width:100%;background:var(--panel);max-width:100%}
th,td{border-bottom:2px solid var(--border);padding:.55rem .6rem;text-align:left;vertical-align:top}
th{
  background:var(--accent);color:#2a1a08;text-transform:uppercase;letter-spacing:.08em;
  font-size:.8rem;border-bottom:4px solid var(--border);
}
.table-scroll{overflow-x:auto;-webkit-overflow-scrolling:touch;margin:.5rem 0;max-width:100%}
.msg-list-wrap{margin:.5rem 0;max-width:100%;overflow:hidden}
.msg-list{
  border:4px solid var(--border);box-shadow:6px 6px 0 0 var(--accent-dark);
  width:100%;max-width:100%;background:var(--panel);display:flex;flex-direction:column;
}
.msg-row{
  display:grid;
  grid-template-columns:44px minmax(0,1fr) auto 44px;
  grid-template-areas:
    "check from date star"
    "check subj subj star";
  column-gap:.2rem;row-gap:.05rem;
  align-items:center;
  padding:.35rem .4rem;
  border-bottom:2px solid var(--border);
  cursor:pointer;min-width:0;max-width:100%;
}
.msg-row:last-child{border-bottom:none}
.msg-row:hover{background:var(--accent-light)}
.msg-row.unread{box-shadow:inset 4px 0 0 0 var(--accent)}
.msg-row.unread .msg-from{font-weight:700}
.msg-row.focused{outline:2px solid var(--accent);outline-offset:-2px}
.msg-row .col-check{
  grid-area:check;
  display:flex;align-items:center;justify-content:center;
  min-width:44px;min-height:44px;margin:0;padding:0;cursor:pointer;
}
.msg-row .col-check input{
  width:1.15rem;height:1.15rem;margin:0;box-shadow:none;
  border:2px solid var(--border);min-height:auto;accent-color:var(--accent);
}
.msg-row .col-star{
  grid-area:star;
  display:flex;align-items:center;justify-content:center;
  min-width:44px;min-height:44px;
}
.msg-row .star-btn{
  border:none;background:transparent;box-shadow:none;
  min-width:44px;min-height:44px;padding:0;
  font-size:1.25rem;color:var(--muted);cursor:pointer;transform:none;
  display:inline-flex;align-items:center;justify-content:center;
}
.msg-row .star-btn:hover,.msg-row .star-btn:active{background:transparent;transform:none;box-shadow:none;color:var(--accent)}
.msg-row .star-btn.on{color:var(--accent)}
.msg-row .msg-from{
  grid-area:from;min-width:0;overflow:hidden;text-overflow:ellipsis;white-space:nowrap;
  font-size:.9rem;
}
.msg-row .msg-date{
  grid-area:date;
  white-space:nowrap;color:var(--muted);font-size:.78rem;font-weight:600;
  justify-self:end;
}
.msg-row.unread .msg-date{color:var(--ink)}
.msg-row .msg-line2{
  grid-area:subj;display:flex;align-items:baseline;gap:.35rem;min-width:0;overflow:hidden;
}
.msg-row .msg-subject{
  border-bottom:none;color:var(--ink);font-weight:inherit;
  white-space:nowrap;overflow:hidden;text-overflow:ellipsis;min-width:0;max-width:100%;
  min-height:auto;padding:0;flex:0 1 auto;
}
.msg-row .msg-subject:hover{background:transparent;color:var(--ink)}
.msg-row .msg-snippet{
  color:var(--muted);font-weight:400;font-size:.85rem;
  white-space:nowrap;overflow:hidden;text-overflow:ellipsis;min-width:0;flex:1 1 0;
}
.msg-row.empty{
  display:block;color:var(--muted);padding:1rem;text-align:center;cursor:default;
  border-bottom:none;
}
.msg-row.empty:hover{background:transparent}
/* desktop: checkbox | from | subject+snippet | date | star */
@media (min-width:801px){
  .msg-row{
    grid-template-columns:44px minmax(0,12rem) minmax(0,1fr) 5.5rem 44px;
    grid-template-areas:"check from subj date star";
    padding:.4rem .5rem;
  }
  .msg-row .msg-from{font-size:.9rem}
  .msg-row .msg-date{font-size:.82rem}
}

/* --- message view --- */
.back-link{margin:0 0 .75rem}
.back-link a{display:inline-flex;align-items:center;min-height:44px}
.msg-headers p{margin:.35rem 0;color:var(--muted);font-size:.95rem}
.msg-headers strong{color:var(--ink);text-transform:uppercase;letter-spacing:.05em;font-size:.82rem}
.msg-headers h1{
  text-transform:none;letter-spacing:0;font-size:1.2rem;text-shadow:none;
  margin:0 0 .75rem;line-height:1.35;word-break:break-word;
}
.msg-actions{display:flex;flex-wrap:wrap;gap:.5rem;margin:.75rem 0;align-items:center}
.msg-actions form{display:inline;margin:0}
.msg-actions button,.msg-actions a.btn-ghost{
  min-height:40px;font-size:.78rem;padding:.35rem .75rem;margin:0;
}
.msg-body{
  white-space:pre-wrap;word-break:break-word;
  font-size:1rem;line-height:1.65;color:var(--ink);
  text-transform:none;letter-spacing:0;font-weight:400;
}
.attach-list{list-style:none;padding:0;margin:.5rem 0}
.attach-list li{margin:.3rem 0;padding:0}
.attach-list li::before{content:"■ ";color:var(--accent)}
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
.compose-panel .compose-actions{display:flex;flex-wrap:wrap;gap:.5rem;margin-top:.75rem}
.compose-panel .compose-actions button{margin-top:0;width:auto;max-width:none}
.compose-cc-row{display:none}
.compose-cc-row.is-open{display:block}
@media (max-width:640px){
  .compose-panel .compose-actions{flex-direction:column}
  .compose-panel .compose-actions button{width:100%;max-width:100%}
  .pix-panel{box-shadow:5px 5px 0 0 var(--accent-dark);padding:1rem}
  h1{font-size:1.15rem}
  .wrap{padding:1rem .75rem 2.5rem}
  .msg-actions{gap:.4rem}
  .msg-actions button,.msg-actions a.btn-ghost{flex:1 1 auto;min-width:calc(50% - .3rem)}
}
@media (max-width:360px){
  .msg-actions button,.msg-actions a.btn-ghost{min-width:100%}
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

/// Active sidebar folder key for highlighting: inbox|starred|sent|drafts|spam|trash|dns|admin|compose|"".
fn page_shell(title: &str, user: &str, body: &str) -> String {
    page_shell_nav(title, user, "", body)
}

fn page_shell_nav(title: &str, user: &str, active: &str, body: &str) -> String {
    if user.is_empty() {
        let nav = format!(
            "<nav class=\"site-nav\" id=\"site-nav\" aria-label=\"Site\">\
             <div class=\"site-nav-inner\">\
             <a class=\"nav-brand\" href=\"/login\">{}<span>DESERTEMAIL</span></a>\
             </div></nav>",
            CACTUS_SVG
        );
        let warn = tls_warning_banner_html();
        return format!(
            "<!DOCTYPE html><html lang=\"en\"><head><meta charset=\"utf-8\">\
             <meta name=\"viewport\" content=\"width=device-width, initial-scale=1\">\
             <title>{}</title>{}<style>{}</style></head><body>{}<div class=\"wrap\">{}{}</div></body></html>",
            esc(title),
            FAVICON_LINK,
            STYLE,
            nav,
            warn,
            body
        );
    }

    let unread = 0u32; // filled by callers via page_shell_app when needed
    page_shell_app(title, user, active, unread, None, body)
}

fn page_shell_app(
    title: &str,
    user: &str,
    active: &str,
    inbox_unread: u32,
    search_folder: Option<&str>,
    body: &str,
) -> String {
    let badge = if inbox_unread > 0 {
        format!("<span class=\"badge\">{}</span>", inbox_unread.min(999))
    } else {
        String::new()
    };
    let act = |key: &str| if active == key { " active" } else { "" };
    let admin_link = if active == "admin" || active == "dns" || true {
        // Admin link always shown; page itself enforces access.
        format!(
            "<li><a class=\"{}\" href=\"/admin\">Admin</a></li>",
            act("admin").trim()
        )
    } else {
        String::new()
    };
    // Always show Admin; page_admin shows denied if not admin. DNS too for all? currently admin-only.
    let folder_q = search_folder.unwrap_or("inbox");
    let sidebar = format!(
        "<aside class=\"app-sidebar\" id=\"app-sidebar\" aria-label=\"Mailbox\">\
         <a class=\"app-brand\" href=\"/\">{}\
         <span>DESERTEMAIL</span></a>\
         <a class=\"btn-compose\" href=\"/compose\">✉ Compose</a>\
         <ul class=\"side-nav\">\
         <li><a class=\"{}\" href=\"/\">Inbox{}</a></li>\
         <li><a class=\"{}\" href=\"/starred\">Starred</a></li>\
         <li><a class=\"{}\" href=\"/sent\">Sent</a></li>\
         <li><a class=\"{}\" href=\"/drafts\">Drafts</a></li>\
         <li><a class=\"{}\" href=\"/spam\">Spam</a></li>\
         <li><a class=\"{}\" href=\"/trash\">Trash</a></li>\
         </ul>\
         <hr class=\"side-divider\">\
         <ul class=\"side-nav\">\
         <li><a class=\"{}\" href=\"/dns\">DNS</a></li>\
         {}\
         <li><a href=\"/logout\">Logout</a></li>\
         </ul>\
         <div class=\"side-foot\">\
         <span class=\"side-user\">{}</span>\
         <div class=\"side-hint\" title=\"Keyboard shortcuts\">? shortcuts: c compose · / search · j/k · x select · e delete</div>\
         </div></aside>\
         <div class=\"sidebar-backdrop\" id=\"sidebar-backdrop\" hidden></div>",
        CACTUS_SVG,
        act("inbox"),
        badge,
        act("starred"),
        act("sent"),
        act("drafts"),
        act("spam"),
        act("trash"),
        act("dns"),
        format!(
            "<li><a class=\"{}\" href=\"/admin\">Admin</a></li>",
            act("admin")
        ),
        esc(user)
    );
    let _ = admin_link;
    let topbar = format!(
        "<header class=\"app-topbar\">\
         <button type=\"button\" class=\"menu-toggle\" id=\"menu-toggle\" \
         aria-expanded=\"false\" aria-controls=\"app-sidebar\" aria-label=\"Open menu\">☰</button>\
         <h1>{}</h1>\
         <div class=\"topbar-search\">\
         <form method=\"get\" action=\"/search\" role=\"search\">\
         <input type=\"hidden\" name=\"folder\" value=\"{}\">\
         <input type=\"search\" name=\"q\" id=\"search-box\" placeholder=\"Search mail\" \
         aria-label=\"Search mail\" autocomplete=\"off\">\
         <button type=\"submit\">Search</button>\
         </form></div></header>",
        esc(title),
        esc(folder_q)
    );
    let script = r##"<script>(function(){
var b=document.body,t=document.getElementById("menu-toggle"),s=document.getElementById("app-sidebar"),
bd=document.getElementById("sidebar-backdrop");
function setOpen(o){b.classList.toggle("sidebar-open",o);if(t){t.setAttribute("aria-expanded",o?"true":"false");
t.setAttribute("aria-label",o?"Close menu":"Open menu")}if(bd)bd.hidden=!o;
try{document.documentElement.style.overflow=o?"hidden":""}catch(e){}}
if(t)t.addEventListener("click",function(){setOpen(!b.classList.contains("sidebar-open"))});
if(bd)bd.addEventListener("click",function(){setOpen(false)});
/* keyboard shortcuts */
var focusIdx=-1;
function rows(){return Array.prototype.slice.call(document.querySelectorAll(".msg-row[data-id]"))}
function setFocus(i){var r=rows();if(!r.length)return;r.forEach(function(x){x.classList.remove("focused")});
if(i<0)i=0;if(i>=r.length)i=r.length-1;focusIdx=i;r[i].classList.add("focused");r[i].scrollIntoView({block:"nearest"})}
document.addEventListener("keydown",function(e){
var tag=(e.target&&e.target.tagName||"").toLowerCase();
if(tag==="input"||tag==="textarea"||tag==="select"||(e.target&&e.target.isContentEditable)){
if(e.key==="Escape"){e.target.blur();return}return}
if(e.key==="Escape"&&b.classList.contains("sidebar-open")){setOpen(false);e.preventDefault();return}
if(e.key==="c"){location.href="/compose";e.preventDefault()}
else if(e.key==="/"){var sb=document.getElementById("search-box");if(sb){sb.focus();e.preventDefault()}}
else if(e.key==="j"){setFocus(focusIdx<0?0:focusIdx+1);e.preventDefault()}
else if(e.key==="k"){setFocus(focusIdx<0?0:focusIdx-1);e.preventDefault()}
else if(e.key==="Enter"&&focusIdx>=0){var r=rows()[focusIdx];if(r){var href=r.getAttribute("data-href");if(href)location.href=href;e.preventDefault()}}
else if(e.key==="x"&&focusIdx>=0){var r=rows()[focusIdx];if(r){var c=r.querySelector("input[type=checkbox]");if(c)c.checked=!c.checked;e.preventDefault()}}
else if((e.key==="e"||e.key==="#")&&focusIdx>=0){var r=rows()[focusIdx];if(r){var c=r.querySelector("input[type=checkbox]");if(c)c.checked=true;
var f=document.getElementById("bulk-form");var act=f&&f.querySelector("button[name=action][value=delete]");
if(act){act.click()}e.preventDefault()}}
else if(e.key==="?"){alert("Shortcuts:\nc compose\n/ search\nj/k move\nEnter open\nx select\ne or # delete")}
});
/* row click opens message unless interactive target */
document.querySelectorAll(".msg-row[data-href]").forEach(function(row){
row.addEventListener("click",function(ev){
var t=ev.target;if(t.closest("input,button,form,a,label"))return;
location.href=row.getAttribute("data-href");
})});
})();</script>"##;
    let sess = current_session_token();
    let body = inject_csrf_into_forms(body, &sess);
    let warn = tls_warning_banner_html();
    let content = if warn.is_empty() {
        body
    } else {
        format!("{}{}", warn, body)
    };
    format!(
        "<!DOCTYPE html><html lang=\"en\"><head><meta charset=\"utf-8\">\
         <meta name=\"viewport\" content=\"width=device-width, initial-scale=1\">\
         <title>{} · DesertEmail</title>{}<style>{}</style></head>\
         <body><div class=\"app-shell\">{}<div class=\"app-main\">{}<div class=\"app-content\">{}</div></div></div>{}</body></html>",
        esc(title),
        FAVICON_LINK,
        STYLE,
        sidebar,
        topbar,
        content,
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
// Folders / list / search
// ---------------------------------------------------------------------------

const PAGE_SIZE: usize = 50;
const SEARCH_SCAN_CAP: usize = 500;

fn count_inbox_unread(cfg: &Config, user: &str) -> u32 {
    let mb = mailbox_name(cfg, user);
    let md = match Maildir::open(&cfg.data_dir, &mb) {
        Ok(m) => m,
        Err(_) => return 0,
    };
    match md.list_messages() {
        Ok(msgs) => msgs
            .iter()
            .filter(|m| m.in_new || !m.flags.contains('S'))
            .count() as u32,
        Err(_) => 0,
    }
}

/// Map folder key → maildir path relative to data_dir (None for virtual Starred).
fn folder_maildir_rel(mb: &str, folder: &str) -> Option<String> {
    match folder {
        "" | "inbox" => Some(mb.to_string()),
        "sent" => Some(format!("{}/.Sent", mb)),
        "drafts" => Some(format!("{}/.Drafts", mb)),
        "spam" => Some(format!("{}/.Junk", mb)),
        "trash" => Some(format!("{}/.Trash", mb)),
        "starred" => None,
        _ => Some(mb.to_string()),
    }
}

fn folder_list_path(folder: &str) -> &'static str {
    match folder {
        "starred" => "/starred",
        "sent" => "/sent",
        "drafts" => "/drafts",
        "spam" => "/spam",
        "trash" => "/trash",
        _ => "/",
    }
}

fn folder_title(folder: &str) -> &'static str {
    match folder {
        "starred" => "Starred",
        "sent" => "Sent",
        "drafts" => "Drafts",
        "spam" => "Spam",
        "trash" => "Trash",
        _ => "Inbox",
    }
}

fn page_inbox(cfg: &Config, user: &str, req: &Request) -> Response {
    let dismissed = cookie_value(req, "dismiss_localhost").as_deref() == Some("1")
        || req.query.get("dismiss_localhost").map(|s| s.as_str()) == Some("1");
    let banner = if req.query.get("localhost_banner").map(|s| s.as_str()) == Some("1") && !dismissed
    {
        Some(
            "<div class=\"banner\" id=\"localhost-banner\">\
             <a class=\"dismiss\" href=\"/?dismiss_localhost=1\">dismiss</a>\
             Using <strong>localhost</strong> — set a real domain in \
             <a href=\"/dns\">DNS settings</a> to receive internet mail.\
             </div>",
        )
    } else {
        None
    };
    let mut resp = list_folder_page(cfg, user, "inbox", req, banner);
    if req.query.get("dismiss_localhost").map(|s| s.as_str()) == Some("1") {
        resp = resp.with_cookie("dismiss_localhost=1; Path=/; SameSite=Lax; Max-Age=31536000");
    }
    resp
}

fn page_folder(cfg: &Config, user: &str, folder: &str, req: &Request) -> Response {
    list_folder_page(cfg, user, folder, req, None)
}

fn page_search(cfg: &Config, user: &str, req: &Request) -> Response {
    list_folder_page(cfg, user, "search", req, None)
}

fn list_folder_page(
    cfg: &Config,
    user: &str,
    folder_key: &str,
    req: &Request,
    banner: Option<&str>,
) -> Response {
    let is_search = folder_key == "search";
    let folder = if is_search {
        req.query
            .get("folder")
            .map(|s| s.as_str())
            .filter(|s| !s.is_empty())
            .unwrap_or("inbox")
    } else {
        folder_key
    };
    let q = req
        .query
        .get("q")
        .map(|s| s.as_str())
        .unwrap_or("")
        .trim()
        .to_string();
    let offset: usize = req
        .query
        .get("offset")
        .and_then(|s| s.parse().ok())
        .unwrap_or(0);
    let mb = mailbox_name(cfg, user);
    let title = if is_search {
        "Search"
    } else {
        folder_title(folder)
    };
    let active = if is_search { folder } else { folder_key };

    // Collect messages: for starred, scan inbox for \Flagged; else open folder maildir.
    let (msgs_with_raw, scan_note): (Vec<(crate::storage::MessageMeta, Vec<u8>, String)>, String) =
        if folder == "starred" {
            let md = match Maildir::open(&cfg.data_dir, &mb) {
                Ok(m) => m,
                Err(e) => {
                    let body = format!(
                        "<h1>Starred</h1><p class=\"err\">Cannot open mailbox: {}</p>",
                        esc(&e.to_string())
                    );
                    return Response::html(
                        500,
                        "Error",
                        page_shell_app(
                            "Starred",
                            user,
                            "starred",
                            count_inbox_unread(cfg, user),
                            Some("inbox"),
                            &body,
                        ),
                    );
                }
            };
            let mut msgs = md.list_messages().unwrap_or_default();
            msgs.reverse();
            let mut out = Vec::new();
            for m in msgs {
                if m.flags.contains('F') {
                    let raw = md.read_message(&m.path).unwrap_or_default();
                    out.push((m, raw, "inbox".to_string()));
                }
            }
            (out, String::new())
        } else {
            let rel = folder_maildir_rel(&mb, folder).unwrap_or_else(|| mb.clone());
            let md = match Maildir::open(&cfg.data_dir, &rel) {
                Ok(m) => m,
                Err(e) => {
                    let body = format!(
                        "<h1>{}</h1><p class=\"err\">Cannot open mailbox: {}</p>",
                        esc(title),
                        esc(&e.to_string())
                    );
                    return Response::html(
                        500,
                        "Error",
                        page_shell_app(
                            title,
                            user,
                            active,
                            count_inbox_unread(cfg, user),
                            Some(folder),
                            &body,
                        ),
                    );
                }
            };
            let mut msgs = md.list_messages().unwrap_or_default();
            msgs.reverse();
            let mut note = String::new();
            if is_search && !q.is_empty() && msgs.len() > SEARCH_SCAN_CAP {
                msgs.truncate(SEARCH_SCAN_CAP);
                note = format!("searched last {}", SEARCH_SCAN_CAP);
            } else if is_search && !q.is_empty() {
                note = format!("searched last {}", msgs.len());
            }
            let mut out = Vec::new();
            for m in msgs {
                let raw = md.read_message(&m.path).unwrap_or_default();
                out.push((m, raw, folder.to_string()));
            }
            (out, note)
        };

    let mut filtered = msgs_with_raw;
    if is_search && !q.is_empty() {
        let q_lower = q.to_lowercase();
        filtered.retain(|(_m, raw, _)| message_matches_query(raw, &q_lower));
    }

    let total = filtered.len();
    let start = offset.min(total);
    let end = (start + PAGE_SIZE).min(total);
    let page = &filtered[start..end];

    let mut rows = String::new();
    if page.is_empty() {
        rows.push_str("<div class=\"msg-row empty\">No messages</div>");
    } else {
        for (m, raw, src_folder) in page {
            let headers = extract_headers(raw);
            let subject = headers
                .get("subject")
                .map(|s| s.as_str())
                .unwrap_or("(no subject)");
            let from = if src_folder == "sent" || src_folder == "drafts" {
                headers.get("to").map(|s| s.as_str()).unwrap_or("")
            } else {
                headers.get("from").map(|s| s.as_str()).unwrap_or("")
            };
            let date_hdr = headers.get("date").map(|s| s.as_str()).unwrap_or("");
            let date_disp = format_relative_date(date_hdr, util::now_secs());
            let text = extract_text_body(raw, &headers);
            let snip = snippet_from_body(&text, 80);
            let unread = m.in_new || !m.flags.contains('S');
            let starred = m.flags.contains('F');
            let cls = if unread {
                "msg-row unread"
            } else {
                "msg-row"
            };
            let link = if src_folder == "drafts" {
                format!("/compose?draft={}", m.uid)
            } else {
                format!("/msg?id={}&folder={}", m.uid, esc(src_folder))
            };
            let star_char = if starred { "★" } else { "☆" };
            let star_cls = if starred { "star-btn on" } else { "star-btn" };
            rows.push_str(&format!(
                "<div class=\"{cls}\" data-id=\"{uid}\" data-href=\"{link}\" role=\"row\">\
                 <label class=\"col-check\" onclick=\"event.stopPropagation()\">\
                 <input type=\"checkbox\" name=\"id\" value=\"{uid}\" form=\"bulk-form\" \
                 aria-label=\"Select message\"></label>\
                 <span class=\"msg-from\">{from}</span>\
                 <span class=\"msg-date\">{date}</span>\
                 <div class=\"msg-line2\"><a class=\"msg-subject\" href=\"{link}\">{subj}</a>\
                 <span class=\"msg-snippet\">{snip}</span></div>\
                 <div class=\"col-star\" onclick=\"event.stopPropagation()\">\
                 <form method=\"post\" action=\"/msg/star\" class=\"inline-form\">\
                 <input type=\"hidden\" name=\"id\" value=\"{uid}\">\
                 <input type=\"hidden\" name=\"folder\" value=\"{folder}\">\
                 <input type=\"hidden\" name=\"redirect\" value=\"{redir}\">\
                 <button type=\"submit\" class=\"{star_cls}\" title=\"Star\" \
                 aria-label=\"Star\">{star}</button></form></div></div>",
                cls = cls,
                uid = m.uid,
                link = link,
                folder = esc(src_folder),
                redir = esc(&format!("{}{}", folder_list_path(if is_search { "inbox" } else { folder }),
                    if is_search && !q.is_empty() {
                        format!("?q={}&folder={}&offset={}", urlencode_component(&q), folder, offset)
                    } else if offset > 0 {
                        format!("?offset={}", offset)
                    } else {
                        String::new()
                    })),
                star_cls = star_cls,
                star = star_char,
                from = esc(from),
                subj = esc(subject),
                snip = esc(&snip),
                date = esc(&date_disp),
            ));
        }
    }

    let list_base = if is_search {
        format!(
            "/search?q={}&folder={}",
            urlencode_component(&q),
            urlencode_component(folder)
        )
    } else {
        folder_list_path(folder).to_string()
    };
    let sep = if list_base.contains('?') { "&" } else { "?" };
    let newer = if offset > 0 {
        let no = offset.saturating_sub(PAGE_SIZE);
        format!(
            "<a href=\"{}{}offset={}\">‹ newer</a>",
            list_base, sep, no
        )
    } else {
        "<span>‹ newer</span>".into()
    };
    let older = if end < total {
        format!(
            "<a href=\"{}{}offset={}\">older ›</a>",
            list_base, sep, end
        )
    } else {
        "<span>older ›</span>".into()
    };
    let range = if total == 0 {
        "0 of 0".into()
    } else {
        format!("{}–{} of {}", start + 1, end, total)
    };

    let trash_empty_btn = if folder == "trash" {
        "<form method=\"post\" action=\"/trash/empty\" class=\"inline-form\" style=\"margin:.5rem 0\" \
         onsubmit=\"return confirm('Empty trash permanently?');\">\
         <button type=\"submit\" class=\"btn-danger\">Empty trash</button></form>"
            .to_string()
    } else if folder == "spam" {
        "<form method=\"post\" action=\"/spam/empty\" class=\"inline-form\" style=\"margin:.5rem 0\" \
         onsubmit=\"return confirm('Empty spam permanently?');\">\
         <button type=\"submit\" class=\"btn-danger\">Empty spam</button></form>"
            .to_string()
    } else {
        String::new()
    };

    let delete_label = if folder == "trash" || folder == "spam" {
        "Delete forever"
    } else {
        "Delete"
    };
    let delete_short = if folder == "trash" || folder == "spam" {
        "Forever"
    } else {
        "Del"
    };

    // Spam / Not spam bulk buttons depending on folder.
    let spam_bulk_btn = if folder == "spam" {
        "<button type=\"submit\" name=\"action\" value=\"notspam\" class=\"btn-secondary\">\
         <span class=\"lbl-full\">Not spam</span><span class=\"lbl-short\">Not spam</span></button>"
            .to_string()
    } else if folder == "inbox" || folder == "starred" || is_search {
        "<button type=\"submit\" name=\"action\" value=\"spam\" class=\"btn-secondary\">\
         <span class=\"lbl-full\">Spam</span><span class=\"lbl-short\">Spam</span></button>"
            .to_string()
    } else {
        String::new()
    };

    let search_note = if !scan_note.is_empty() {
        format!("<p class=\"muted\">{}</p>", esc(&scan_note))
    } else {
        String::new()
    };
    let q_note = if is_search && !q.is_empty() {
        format!("<p>Results for <strong>{}</strong></p>", esc(&q))
    } else {
        String::new()
    };

    let banner_html = banner.unwrap_or("");
    let body = format!(
        "{banner}\
         {q_note}{search_note}\
         {trash_empty}\
         <form method=\"post\" action=\"/msg/bulk\" id=\"bulk-form\">\
         <input type=\"hidden\" name=\"folder\" value=\"{folder}\">\
         <input type=\"hidden\" name=\"redirect\" value=\"{redir}\">\
         <div class=\"bulk-bar\">\
         <button type=\"submit\" name=\"action\" value=\"delete\">\
         <span class=\"lbl-full\">{del}</span><span class=\"lbl-short\">{del_short}</span></button>\
         {spam_btn}\
         <button type=\"submit\" name=\"action\" value=\"read\" class=\"btn-secondary\">\
         <span class=\"lbl-full\">Mark read</span><span class=\"lbl-short\">Read</span></button>\
         <button type=\"submit\" name=\"action\" value=\"unread\" class=\"btn-secondary\">\
         <span class=\"lbl-full\">Mark unread</span><span class=\"lbl-short\">Unread</span></button>\
         <div class=\"pager\"><span class=\"range\">{range}</span>{newer}{older}</div>\
         </div>\
         <div class=\"msg-list-wrap\"><div class=\"msg-list\" role=\"list\">{rows}</div></div></form>",
        banner = banner_html,
        q_note = q_note,
        search_note = search_note,
        trash_empty = trash_empty_btn,
        folder = esc(folder),
        redir = esc(&if is_search {
            format!(
                "/search?q={}&folder={}&offset={}",
                urlencode_component(&q),
                folder,
                offset
            )
        } else if offset > 0 {
            format!("{}?offset={}", folder_list_path(folder), offset)
        } else {
            folder_list_path(folder).to_string()
        }),
        del = delete_label,
        del_short = delete_short,
        spam_btn = spam_bulk_btn,
        range = range,
        newer = newer,
        older = older,
        rows = rows,
    );

    Response::html(
        200,
        "OK",
        page_shell_app(
            title,
            user,
            active,
            count_inbox_unread(cfg, user),
            Some(folder),
            &body,
        ),
    )
}

fn message_matches_query(raw: &[u8], q_lower: &str) -> bool {
    let headers = extract_headers(raw);
    for key in ["from", "to", "cc", "subject"] {
        if let Some(v) = headers.get(key) {
            if v.to_lowercase().contains(q_lower) {
                return true;
            }
        }
    }
    let body = extract_text_body(raw, &headers);
    body.to_lowercase().contains(q_lower)
}

fn urlencode_component(s: &str) -> String {
    let mut out = String::new();
    for b in s.bytes() {
        match b {
            b'A'..=b'Z' | b'a'..=b'z' | b'0'..=b'9' | b'-' | b'_' | b'.' | b'~' => {
                out.push(b as char)
            }
            b' ' => out.push('+'),
            _ => out.push_str(&format!("%{:02X}", b)),
        }
    }
    out
}

/// First ~`max` chars of body as a single-line snippet.
pub fn snippet_from_body(body: &str, max: usize) -> String {
    let flat: String = body
        .chars()
        .map(|c| if c.is_whitespace() { ' ' } else { c })
        .collect();
    let flat = flat.split_whitespace().collect::<Vec<_>>().join(" ");
    if flat.chars().count() <= max {
        flat
    } else {
        let s: String = flat.chars().take(max.saturating_sub(1)).collect();
        format!("{}…", s.trim_end())
    }
}

/// Gmail-style relative date: same day → HH:MM, same year → "Mon D", else YYYY-MM-DD.
pub fn format_relative_date(date_hdr: &str, now_secs: u64) -> String {
    let secs = parse_rfc2822_approx(date_hdr).unwrap_or(now_secs);
    let (ny, nm, nd, _) = civil_date(now_secs);
    let (y, m, d, hm) = civil_date(secs);
    if y == ny && m == nm && d == nd {
        hm
    } else if y == ny {
        format!("{} {}", month_abbr(m), d)
    } else {
        format!("{:04}-{:02}-{:02}", y, m, d)
    }
}

fn month_abbr(m: u32) -> &'static str {
    match m {
        1 => "Jan",
        2 => "Feb",
        3 => "Mar",
        4 => "Apr",
        5 => "May",
        6 => "Jun",
        7 => "Jul",
        8 => "Aug",
        9 => "Sep",
        10 => "Oct",
        11 => "Nov",
        12 => "Dec",
        _ => "???",
    }
}

/// Approximate civil (Y,M,D, "HH:MM") from unix seconds (UTC).
fn civil_date(secs: u64) -> (i32, u32, u32, String) {
    let days = (secs / 86400) as i64;
    let tod = secs % 86400;
    let hh = tod / 3600;
    let mm = (tod % 3600) / 60;
    let (y, m, d) = civil_from_days(days);
    (y, m, d, format!("{:02}:{:02}", hh, mm))
}

fn civil_from_days(days: i64) -> (i32, u32, u32) {
    // Howard Hinnant civil_from_days algorithm (UTC).
    let z = days + 719468;
    let era = if z >= 0 { z } else { z - 146096 } / 146097;
    let doe = (z - era * 146097) as u64;
    let yoe = (doe - doe / 1460 + doe / 36524 - doe / 146096) / 365;
    let y = (yoe as i64) + era * 400;
    let doy = doe - (365 * yoe + yoe / 4 - yoe / 100);
    let mp = (5 * doy + 2) / 153;
    let d = doy - (153 * mp + 2) / 5 + 1;
    let m = if mp < 10 { mp + 3 } else { mp - 9 };
    let y = if m <= 2 { y + 1 } else { y };
    (y as i32, m as u32, d as u32)
}

/// Best-effort parse of common Date: header forms → unix secs.
fn parse_rfc2822_approx(s: &str) -> Option<u64> {
    let s = s.trim();
    if s.is_empty() {
        return None;
    }
    // Try "Day, DD Mon YYYY HH:MM:SS ±ZZZZ" or without day name.
    let parts: Vec<&str> = s.split_whitespace().collect();
    // Find month token
    let months = [
        "jan", "feb", "mar", "apr", "may", "jun", "jul", "aug", "sep", "oct", "nov", "dec",
    ];
    let mut di = 0usize;
    while di + 3 < parts.len() {
        let mon = parts[di + 1].to_ascii_lowercase();
        if months.iter().any(|m| mon.starts_with(m)) {
            break;
        }
        // maybe "DD Mon YYYY"
        let mon0 = parts[di].to_ascii_lowercase();
        if months.iter().any(|m| mon0.starts_with(m)) && di > 0 {
            di -= 1;
            break;
        }
        di += 1;
    }
    if di + 3 >= parts.len() {
        return None;
    }
    let day: u32 = parts[di].trim_end_matches(',').parse().ok()?;
    let mon_s = parts[di + 1].to_ascii_lowercase();
    let month = months.iter().position(|m| mon_s.starts_with(m))? as u32 + 1;
    let year: i32 = parts[di + 2].parse().ok()?;
    let time = parts.get(di + 3).copied().unwrap_or("0:0:0");
    let mut tp = time.split(':');
    let hh: u64 = tp.next()?.parse().ok()?;
    let mm: u64 = tp.next().unwrap_or("0").parse().ok()?;
    let ss: u64 = tp
        .next()
        .unwrap_or("0")
        .trim_end_matches('Z')
        .parse()
        .unwrap_or(0);
    let days = days_from_civil(year, month, day)?;
    Some(days as u64 * 86400 + hh * 3600 + mm * 60 + ss)
}

fn days_from_civil(y: i32, m: u32, d: u32) -> Option<i64> {
    if m < 1 || m > 12 || d < 1 || d > 31 {
        return None;
    }
    let y = y as i64;
    let m = m as i64;
    let d = d as i64;
    let y = if m <= 2 { y - 1 } else { y };
    let era = if y >= 0 { y } else { y - 399 } / 400;
    let yoe = y - era * 400;
    let doy = (153 * (if m > 2 { m - 3 } else { m + 9 }) + 2) / 5 + d - 1;
    let doe = yoe * 365 + yoe / 4 - yoe / 100 + doy;
    Some(era * 146097 + doe - 719468)
}

// ---------------------------------------------------------------------------
// Message actions (star / bulk / trash)
// ---------------------------------------------------------------------------

fn find_message_in_folder(
    cfg: &Config,
    user: &str,
    folder: &str,
    id: u32,
) -> Result<(Maildir, crate::storage::MessageMeta), String> {
    let mb = mailbox_name(cfg, user);
    let folder = if folder == "starred" { "inbox" } else { folder };
    let rel = folder_maildir_rel(&mb, folder).unwrap_or(mb);
    let md = Maildir::open(&cfg.data_dir, &rel).map_err(|e| e.to_string())?;
    let msgs = md.list_messages().map_err(|e| e.to_string())?;
    let meta = msgs
        .into_iter()
        .find(|m| m.uid == id)
        .ok_or_else(|| "message not found".to_string())?;
    Ok((md, meta))
}

fn handle_star(cfg: &Config, user: &str, req: &Request) -> Response {
    if let Some(r) = require_auth_post(req, user) {
        return r;
    }
    let form = form_body(req);
    let id: u32 = form.get("id").and_then(|s| s.parse().ok()).unwrap_or(0);
    let folder = form.get("folder").map(|s| s.as_str()).unwrap_or("inbox");
    let redirect = form
        .get("redirect")
        .map(|s| s.as_str())
        .filter(|s| s.starts_with('/'))
        .unwrap_or_else(|| folder_list_path(folder));
    if id == 0 {
        return Response::redirect(redirect);
    }
    if let Ok((md, meta)) = find_message_in_folder(cfg, user, folder, id) {
        let mode = if meta.flags.contains('F') {
            "-FLAGS"
        } else {
            "+FLAGS"
        };
        let _ = md.store_flags(&meta, mode, &["\\Flagged".into()]);
    }
    Response::redirect(redirect)
}

fn handle_bulk(cfg: &Config, user: &str, req: &Request) -> Response {
    if let Some(r) = require_auth_post(req, user) {
        return r;
    }
    let form = form_body(req);
    let action = form.get("action").map(|s| s.as_str()).unwrap_or("");
    let folder = form.get("folder").map(|s| s.as_str()).unwrap_or("inbox");
    let redirect = form
        .get("redirect")
        .map(|s| s.as_str())
        .filter(|s| s.starts_with('/'))
        .unwrap_or_else(|| folder_list_path(folder));
    // Collect all id values — parse_urlencoded only keeps last duplicate key.
    // Re-parse body for repeated id=
    let ids = collect_form_ids(req);
    let mb = mailbox_name(cfg, user);
    let src_folder = if folder == "starred" { "inbox" } else { folder };
    let rel = folder_maildir_rel(&mb, src_folder).unwrap_or(mb.clone());
    let md = match Maildir::open(&cfg.data_dir, &rel) {
        Ok(m) => m,
        Err(_) => return Response::redirect(redirect),
    };
    let msgs = md.list_messages().unwrap_or_default();
    for id in ids {
        let meta = match msgs.iter().find(|m| m.uid == id) {
            Some(m) => m.clone(),
            None => continue,
        };
        match action {
            "read" => {
                let _ = md.store_flags(&meta, "+FLAGS", &["\\Seen".into()]);
            }
            "unread" => {
                // Remove Seen; if in new, already unread.
                let _ = md.store_flags(&meta, "-FLAGS", &["\\Seen".into()]);
            }
            "delete" => {
                if src_folder == "trash" || src_folder == "spam" {
                    let _ = md.expunge(&meta);
                } else {
                    let trash = match Maildir::open(&cfg.data_dir, &format!("{}/.Trash", mb)) {
                        Ok(t) => t,
                        Err(_) => continue,
                    };
                    let _ = md.move_to(&meta, &trash);
                }
            }
            "spam" => {
                if src_folder != "spam" {
                    let junk = match Maildir::open(&cfg.data_dir, &format!("{}/.Junk", mb)) {
                        Ok(t) => t,
                        Err(_) => continue,
                    };
                    let _ = md.move_to(&meta, &junk);
                }
            }
            "notspam" => {
                if src_folder == "spam" {
                    let inbox = match Maildir::open(&cfg.data_dir, &mb) {
                        Ok(t) => t,
                        Err(_) => continue,
                    };
                    let _ = md.move_to(&meta, &inbox);
                }
            }
            _ => {}
        }
    }
    Response::redirect(redirect)
}

fn collect_form_ids(req: &Request) -> Vec<u32> {
    let ct = req
        .headers
        .get("content-type")
        .map(|s| s.as_str())
        .unwrap_or("");
    let mut ids = Vec::new();
    if ct.to_lowercase().contains("multipart/form-data") {
        let (fields, _) = parse_multipart_form(req);
        // only last id — also scan raw
        let _ = fields;
    }
    let s = String::from_utf8_lossy(&req.body);
    for pair in s.split('&') {
        let pair = pair.trim();
        if let Some(rest) = pair.strip_prefix("id=") {
            let v = percent_decode(rest);
            if let Ok(n) = v.parse::<u32>() {
                ids.push(n);
            }
        }
    }
    // Also single id from form map
    if ids.is_empty() {
        let form = form_body(req);
        if let Some(v) = form.get("id") {
            if let Ok(n) = v.parse::<u32>() {
                ids.push(n);
            }
        }
    }
    ids
}

fn handle_empty_trash(cfg: &Config, user: &str, req: &Request) -> Response {
    if let Some(r) = require_auth_post(req, user) {
        return r;
    }
    let mb = mailbox_name(cfg, user);
    if let Ok(md) = Maildir::open(&cfg.data_dir, &format!("{}/.Trash", mb)) {
        if let Ok(msgs) = md.list_messages() {
            for m in msgs {
                let _ = md.expunge(&m);
            }
        }
    }
    Response::redirect("/trash")
}

fn handle_empty_spam(cfg: &Config, user: &str, req: &Request) -> Response {
    if let Some(r) = require_auth_post(req, user) {
        return r;
    }
    let mb = mailbox_name(cfg, user);
    if let Ok(md) = Maildir::open(&cfg.data_dir, &format!("{}/.Junk", mb)) {
        if let Ok(msgs) = md.list_messages() {
            for m in msgs {
                let _ = md.expunge(&m);
            }
        }
    }
    Response::redirect("/spam")
}

// ---------------------------------------------------------------------------
// DNS / Getting started
// ---------------------------------------------------------------------------

/// One DNS record the operator should publish.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct DnsRecordAdvice {
    pub rtype: &'static str,
    pub name: String,
    pub value: String,
    pub kind: &'static str,
}

/// Build the expected DNS records for a domain (pure; unit-tested).
pub fn build_dns_records(
    domain: &str,
    mailhost: &str,
    public_ip: Option<&str>,
    selector: &str,
    dkim_txt: Option<&str>,
) -> Vec<DnsRecordAdvice> {
    let domain = domain.trim().trim_end_matches('.').to_lowercase();
    let mailhost = mailhost.trim().trim_end_matches('.').to_lowercase();
    let selector = if selector.trim().is_empty() {
        "mail".to_string()
    } else {
        selector.trim().to_lowercase()
    };
    let mut out = Vec::new();
    out.push(DnsRecordAdvice {
        rtype: "MX",
        name: format!("{}.", domain),
        value: format!("10 {}.", mailhost),
        kind: "mx",
    });
    let a_val = public_ip
        .map(|s| s.trim().to_string())
        .filter(|s| !s.is_empty())
        .unwrap_or_else(|| "YOUR_PUBLIC_IP".into());
    out.push(DnsRecordAdvice {
        rtype: "A",
        name: format!("{}.", mailhost),
        value: a_val,
        kind: "a",
    });
    out.push(DnsRecordAdvice {
        rtype: "TXT",
        name: format!("{}.", domain),
        value: "v=spf1 mx ~all".into(),
        kind: "spf",
    });
    let dkim_name = format!("{}._domainkey.{}.", selector, domain);
    let dkim_val = dkim_txt
        .map(|s| s.to_string())
        .unwrap_or_else(|| "(generate a DKIM key below)".into());
    out.push(DnsRecordAdvice {
        rtype: "TXT",
        name: dkim_name,
        value: dkim_val,
        kind: "dkim",
    });
    out.push(DnsRecordAdvice {
        rtype: "TXT",
        name: format!("_dmarc.{}.", domain),
        value: format!("v=DMARC1; p=none; rua=mailto:admin@{}", domain),
        kind: "dmarc",
    });
    out
}

fn page_dns(
    cfg: &Config,
    user: &str,
    flash: Option<&str>,
    checks: Option<&[crate::doctor::Check]>,
) -> Response {
    if !is_admin(cfg, user) {
        let body = "<h1>DNS</h1><p class=\"err\">Access denied — admin only. \
                    Ask your server admin to publish DNS records.</p>";
        return Response::html(
            403,
            "Forbidden",
            page_shell_app(
                "DNS",
                user,
                "dns",
                count_inbox_unread(cfg, user),
                None,
                body,
            ),
        );
    }

    let domains = cfg.domains_list();
    let primary = cfg.primary_domain();
    let mailhost = crate::doctor::mail_host_for_ui(cfg);
    let public_ip = crate::doctor::suggest_public_ip(cfg);
    let selector = cfg.dkim_selector();
    let dkim_key = cfg.dkim_key_clone();
    let dkim_txt = dkim_key.as_ref().map(|k| crate::dkim::dns_txt_record(k));
    let has_dkim = dkim_key.is_some();

    let flash_html = flash
        .map(|f| {
            if f.starts_with("error:") {
                format!("<p class=\"err\">{}</p>", esc(f.trim_start_matches("error:")))
            } else {
                format!("<p class=\"ok\">{}</p>", esc(f))
            }
        })
        .unwrap_or_default();

    let ip_hint = match &public_ip {
        Some(ip) => format!("Detected address (egress/A): <code>{}</code>", esc(ip)),
        None => "Could not detect your public IP — fill in the real address from your VPS/router \
                 when publishing the A record."
            .to_string(),
    };

    let mut rows = String::new();
    for domain in &domains {
        let records = build_dns_records(
            domain,
            &mailhost,
            public_ip.as_deref(),
            &selector,
            dkim_txt.as_deref(),
        );
        for rec in &records {
            let status_cell = match checks {
                Some(cs) => dns_status_for(cs, rec, domain),
                None => "<span class=\"muted\">—</span>".to_string(),
            };
            let copy_payload = format!("{} {} {}", rec.rtype, rec.name, rec.value);
            rows.push_str(&format!(
                "<tr>\
                 <td data-label=\"Domain\">{}</td>\
                 <td data-label=\"Type\"><strong>{}</strong></td>\
                 <td data-label=\"Name\"><code>{}</code></td>\
                 <td data-label=\"Value\"><code class=\"dns-val\">{}</code></td>\
                 <td data-label=\"Status\">{}</td>\
                 <td><button type=\"button\" class=\"copy-btn\" data-copy=\"{}\">Copy</button></td>\
                 </tr>",
                esc(domain),
                esc(rec.rtype),
                esc(&rec.name),
                esc(&rec.value),
                status_cell,
                esc(&copy_payload)
            ));
        }
    }
    if rows.is_empty() {
        rows.push_str(
            "<tr class=\"empty\"><td colspan=\"6\">No domains configured — add one below.</td></tr>",
        );
    }

    let dkim_panel = if has_dkim {
        let path = cfg
            .dkim_key_file_path()
            .unwrap_or_else(|| "(in memory)".into());
        format!(
            "<p class=\"ok\">DKIM key loaded (selector <code>{}</code>, file <code>{}</code>).</p>\
             <form method=\"post\" action=\"/dns/dkim/generate\" class=\"inline-form\" \
             onsubmit=\"return confirm('Regenerate DKIM key? You must re-publish the TXT record.');\">\
             <input type=\"hidden\" name=\"confirm\" value=\"1\">\
             <button type=\"submit\" class=\"btn-secondary\">Regenerate DKIM key</button></form>",
            esc(&selector),
            esc(&path)
        )
    } else {
        "<p class=\"warn\">No DKIM key yet — generate one so outbound mail can be signed.</p>\
         <form method=\"post\" action=\"/dns/dkim/generate\">\
         <button type=\"submit\">Generate DKIM key</button></form>"
            .to_string()
    };

    let tls_panel = tls_security_panel_html(cfg, &mailhost);

    let body = format!(
        "<h1>DNS</h1>{}\
         <p>Add these records at your DNS provider (Cloudflare, Namecheap, Route&nbsp;53, …). \
         Then click <strong>Check DNS</strong>. Propagation can take minutes to hours.</p>\
         <p class=\"muted\">{}</p>\
         <div class=\"pix-panel\">\
         <h2>Records to publish</h2>\
         <div class=\"table-scroll\">\
         <table class=\"dns-table\"><thead><tr>\
         <th>Domain</th><th>Type</th><th>Name</th><th>Value</th><th>Check</th><th></th>\
         </tr></thead><tbody>{}</tbody></table></div>\
         <form method=\"post\" action=\"/dns/check\" style=\"margin-top:1rem\">\
         <button type=\"submit\">Check DNS</button></form>\
         </div>\
         <div class=\"pix-panel\"><h2>DKIM key</h2>{}</div>\
         <div class=\"pix-panel\"><h2>Security / TLS</h2>{}</div>\
         <div class=\"pix-panel\"><h2>Mail host &amp; domain</h2>\
         <form method=\"post\" action=\"/dns/settings\">\
         <label>Public mail hostname (MX target)</label>\
         <input type=\"text\" name=\"public_host\" value=\"{}\" \
         placeholder=\"mail.example.com\" autocomplete=\"off\">\
         <label>Primary domain</label>\
         <input type=\"text\" name=\"domain\" value=\"{}\" required autocomplete=\"off\">\
         <p class=\"muted\">Changing the domain updates <code>domains</code> in config (live). \
         User accounts on the old domain keep working if you still accept that domain.</p>\
         <p><button type=\"submit\">Save settings</button></p></form>\
         <p class=\"muted\">Also see <a href=\"/admin\">Admin</a> for users and queue.</p>\
         </div>\
         <script>(function(){{\
         document.querySelectorAll('button.copy-btn').forEach(function(b){{\
           b.addEventListener('click',function(){{\
             var t=b.getAttribute('data-copy')||'';\
             if(navigator.clipboard&&navigator.clipboard.writeText){{\
               navigator.clipboard.writeText(t).then(function(){{b.textContent='Copied';\
               setTimeout(function(){{b.textContent='Copy'}},1200)}});\
             }} else {{\
               var a=document.createElement('textarea');a.value=t;document.body.appendChild(a);\
               a.select();try{{document.execCommand('copy');b.textContent='Copied'}}catch(e){{}}\
               document.body.removeChild(a);\
               setTimeout(function(){{b.textContent='Copy'}},1200);\
             }}\
           }});\
         }});\
         }})();</script>",
        flash_html,
        ip_hint,
        rows,
        dkim_panel,
        tls_panel,
        esc(&mailhost),
        esc(&primary)
    );
    Response::html(
        200,
        "OK",
        page_shell_app(
            "DNS",
            user,
            "dns",
            count_inbox_unread(cfg, user),
            None,
            &body,
        ),
    )
}

fn dns_status_for(
    checks: &[crate::doctor::Check],
    rec: &DnsRecordAdvice,
    domain: &str,
) -> String {
    use crate::doctor::Status;
    let needle = match rec.kind {
        "mx" => format!("MX {}", domain),
        "a" => format!("A/AAAA {}", rec.name.trim_end_matches('.')),
        "spf" => format!("SPF {}", domain),
        "dkim" => format!("DKIM {}", domain),
        "dmarc" => format!("DMARC {}", domain),
        _ => String::new(),
    };
    let found = checks.iter().find(|c| {
        c.name == needle
            || (rec.kind == "dkim" && c.name.starts_with(&format!("DKIM {}", domain)))
            || (rec.kind == "a" && c.name.starts_with("A/AAAA "))
    });
    match found {
        Some(c) => {
            let cls = match c.status {
                Status::Ok => "ok",
                Status::Warn => "warn",
                Status::Fail => "fail",
            };
            let label = match c.status {
                Status::Ok => "OK",
                Status::Warn => "WARN",
                Status::Fail => "FAIL",
            };
            format!(
                "<span class=\"dns-status {}\">{}</span><br><span class=\"muted\">{}</span>",
                cls,
                label,
                esc(&truncate_str(&c.detail, 160))
            )
        }
        None => "<span class=\"muted\">—</span>".to_string(),
    }
}

fn truncate_str(s: &str, max: usize) -> String {
    if s.len() <= max {
        s.to_string()
    } else {
        format!("{}…", &s[..max])
    }
}

fn handle_dns_check(cfg: &Config, user: &str, req: &Request, peer_ip: &str) -> Response {
    if !is_admin(cfg, user) {
        return page_dns(cfg, user, Some("error: access denied"), None);
    }
    if let Some(r) = require_auth_post(req, user) {
        return r;
    }
    if !ratelimit::check_allowed(peer_ip) {
        return page_dns(
            cfg,
            user,
            Some("error: too many requests — wait a moment and retry"),
            None,
        );
    }
    // Light rate limit: count DNS check as a "failure" slot to throttle automated abuse.
    ratelimit::record_failure(peer_ip);

    let host = crate::doctor::mail_host_for_ui(cfg);
    let public_ip = crate::doctor::suggest_public_ip(cfg);
    let checks = crate::doctor::run_dns_checks_ui(cfg, &host, public_ip.as_deref());
    page_dns(
        cfg,
        user,
        Some("DNS check complete (failures are normal until records propagate)."),
        Some(&checks),
    )
}

fn handle_dns_dkim_generate(cfg: &Config, user: &str, req: &Request) -> Response {
    if !is_admin(cfg, user) {
        return page_dns(cfg, user, Some("error: access denied"), None);
    }
    if let Some(r) = require_auth_post(req, user) {
        return r;
    }
    let form = form_body(req);
    let confirm = form.get("confirm").map(|s| s.as_str()) == Some("1");
    let existing_path = cfg.dkim_key_file_path();
    let key_already = cfg.dkim_key_clone().is_some()
        || existing_path
            .as_ref()
            .map(|p| std::path::Path::new(p).is_file())
            .unwrap_or(false);
    if key_already && !confirm {
        return page_dns(
            cfg,
            user,
            Some("error: DKIM key already exists — use Regenerate (requires confirm)"),
            None,
        );
    }

    let key = match crypto::RsaKey::generate(2048) {
        Ok(k) => k,
        Err(e) => {
            return page_dns(
                cfg,
                user,
                Some(&format!("error: key generation failed: {}", e)),
                None,
            );
        }
    };
    let pem = key.to_pem_pkcs1();
    let key_path = match dkim_key_path_for_config(cfg) {
        Ok(p) => p,
        Err(e) => return page_dns(cfg, user, Some(&format!("error: {}", e)), None),
    };
    if let Some(parent) = key_path.parent() {
        if let Err(e) = std::fs::create_dir_all(parent) {
            return page_dns(
                cfg,
                user,
                Some(&format!("error: cannot create key dir: {}", e)),
                None,
            );
        }
    }
    if let Err(e) = std::fs::write(&key_path, pem.as_bytes()) {
        return page_dns(
            cfg,
            user,
            Some(&format!("error: cannot write key: {}", e)),
            None,
        );
    }
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        let _ = std::fs::set_permissions(&key_path, std::fs::Permissions::from_mode(0o600));
    }

    let path_str = key_path.to_string_lossy().to_string();
    let selector = {
        let s = cfg.dkim_selector();
        if s.is_empty() {
            "mail".into()
        } else {
            s
        }
    };
    let sel = selector.clone();
    let path_for_edit = path_str.clone();
    match persist_and_reload(cfg, |c| useredit::set_dkim_paths(c, &sel, &path_for_edit)) {
        Ok(()) => {
            // reload_users_quotas already reloads the key; ensure live even if path differs.
            cfg.set_dkim_live(&selector, Some(path_str.clone()), Some(key));
            page_dns(
                cfg,
                user,
                Some(&format!(
                    "DKIM key written to {} (selector {}). Publish the TXT record below.",
                    path_str, selector
                )),
                None,
            )
        }
        Err(e) => page_dns(cfg, user, Some(&format!("error: {}", e)), None),
    }
}

fn dkim_key_path_for_config(cfg: &Config) -> Result<std::path::PathBuf, String> {
    // Prefer existing path; else $config_dir/dkim.pem (installer PREFIX convention).
    if let Some(p) = cfg.dkim_key_file_path() {
        return Ok(std::path::PathBuf::from(p));
    }
    let config_path = cfg
        .config_path
        .as_ref()
        .ok_or_else(|| "config_path not set".to_string())?;
    let dir = config_path
        .parent()
        .unwrap_or_else(|| std::path::Path::new("."));
    Ok(dir.join("dkim.pem"))
}

/// Default PEM paths next to config.toml for ACME-written certs.
fn default_tls_paths(cfg: &Config) -> (String, String) {
    let dir = cfg
        .config_path
        .as_ref()
        .and_then(|p| p.parent().map(|d| d.to_path_buf()))
        .unwrap_or_else(|| std::path::PathBuf::from("."));
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

/// Live + on-disk snapshot of ACME / TLS state for the Security panel.
fn tls_state_from_disk(cfg: &Config) -> (bool, String, Vec<String>, Option<String>, Option<String>) {
    // Prefer re-reading config so UI reflects post-enable writes without restart.
    if let Some(path) = cfg.config_path.as_ref() {
        if let Ok(fresh) = Config::load(path) {
            return (
                fresh.acme,
                fresh.acme_email,
                fresh.acme_domains,
                fresh.tls_cert_file,
                fresh.tls_key_file,
            );
        }
    }
    (
        cfg.acme,
        cfg.acme_email.clone(),
        cfg.acme_domains.clone(),
        cfg.tls_cert_file.clone(),
        cfg.tls_key_file.clone(),
    )
}

fn tls_security_panel_html(cfg: &Config, mailhost: &str) -> String {
    let (acme_on, acme_email, acme_domains, cert_path, _key_path) = tls_state_from_disk(cfg);
    let cert_exists = cert_path
        .as_ref()
        .map(|p| std::path::Path::new(p).is_file())
        .unwrap_or(false);
    let expiry = cert_path
        .as_ref()
        .filter(|_| cert_exists)
        .and_then(|p| acme::cert_expiry_label(p));
    let tls_listen_active =
        web_tls_listener_active().load(std::sync::atomic::Ordering::SeqCst);
    let state_line = if acme_on && cert_exists {
        let exp = expiry
            .as_ref()
            .map(|e| format!(" (expires {})", esc(e)))
            .unwrap_or_default();
        format!(
            "<p class=\"ok\">ACME active — certificate at <code>{}</code>{}.</p>",
            esc(cert_path.as_deref().unwrap_or("")),
            exp
        )
    } else if acme_on {
        "<p class=\"warn\">ACME enabled in config — waiting for certificate issuance \
         (HTTP-01 needs your domain’s A/AAAA pointing here and port <strong>80</strong> \
         reachable for <code>/.well-known/acme-challenge/</code>).</p>"
            .to_string()
    } else if cert_exists {
        let exp = expiry
            .as_ref()
            .map(|e| format!(" (expires {})", esc(e)))
            .unwrap_or_default();
        format!(
            "<p class=\"ok\">TLS certificate file present: <code>{}</code>{}.</p>",
            esc(cert_path.as_deref().unwrap_or("")),
            exp
        )
    } else {
        "<p class=\"warn\">No TLS — webmail is plain HTTP. Enable ACME below or set \
         <code>tls_cert_file</code> / <code>tls_key_file</code> in config.</p>"
            .to_string()
    };
    let listener_line = if tls_listen_active {
        format!(
            "<p class=\"ok\">HTTPS listener active on <code>{}</code>.</p>",
            esc(&cfg.web_tls_listen)
        )
    } else if !cfg.web_tls_listen.is_empty() {
        format!(
            "<p class=\"muted\">Configured <code>web_tls_listen = {}</code> but HTTPS is not \
             bound yet (needs cert + restart after first issuance).</p>",
            esc(&cfg.web_tls_listen)
        )
    } else {
        "<p class=\"muted\">No <code>web_tls_listen</code> yet — enabling ACME will set \
         <code>0.0.0.0:8443</code> (restart after the cert arrives to serve HTTPS).</p>"
            .to_string()
    };
    let domains_disp = if acme_domains.is_empty() {
        mailhost.to_string()
    } else {
        acme_domains.join(", ")
    };
    let email_prefill = if acme_email.is_empty() {
        cfg.admin_user_name().unwrap_or_default()
    } else {
        acme_email
    };
    let form = if acme_on {
        format!(
            "<p class=\"muted\">ACME domains: <code>{}</code> · contact <code>{}</code>. \
             Background renewal runs every 12h when &lt;30 days remain.</p>",
            esc(&domains_disp),
            esc(&email_prefill)
        )
    } else {
        format!(
            "<p>One-click Let’s Encrypt (ACME HTTP-01). Requirements:</p>\
             <ul>\
             <li>A/AAAA for <code>{}</code> pointing at this host</li>\
             <li>Port <strong>80</strong> reachable from the internet (challenge path \
             <code>/.well-known/acme-challenge/…</code> on <code>web_listen</code>)</li>\
             <li>After the cert is written, <strong>restart desertemail</strong> so the \
             HTTPS listener loads it (and binds <code>web_tls_listen</code>)</li>\
             </ul>\
             <form method=\"post\" action=\"/dns/acme/enable\">\
             <label>Contact email (Let’s Encrypt account)</label>\
             <input type=\"email\" name=\"email\" value=\"{}\" required autocomplete=\"email\">\
             <p class=\"muted\">Certificate domain: <code>{}</code> (mail host). \
             Writes <code>acme=true</code>, <code>acme_email</code>, \
             <code>acme_domains</code>, and default cert paths atomically.</p>\
             <p><button type=\"submit\">Enable ACME / Let’s Encrypt</button></p></form>",
            esc(mailhost),
            esc(&email_prefill),
            esc(mailhost)
        )
    };
    format!("{}{}{}", state_line, listener_line, form)
}

fn handle_dns_acme_enable(cfg: &Config, user: &str, req: &Request) -> Response {
    if !is_admin(cfg, user) {
        return page_dns(cfg, user, Some("error: access denied"), None);
    }
    if let Some(r) = require_auth_post(req, user) {
        return r;
    }
    let form = form_body(req);
    let email = form.get("email").map(|s| s.trim()).unwrap_or("");
    if email.is_empty() {
        return page_dns(cfg, user, Some("error: contact email required"), None);
    }
    let mailhost = crate::doctor::mail_host_for_ui(cfg);
    let domain = mailhost.trim().trim_end_matches('.').to_lowercase();
    if domain.is_empty() || domain == "localhost" {
        return page_dns(
            cfg,
            user,
            Some("error: set a real public mail hostname before enabling ACME"),
            None,
        );
    }
    let (cert_path, key_path) = default_tls_paths(cfg);
    let web_tls = if cfg.web_tls_listen.is_empty() {
        "0.0.0.0:8443"
    } else {
        ""
    };
    let email_owned = email.to_string();
    let domain_owned = domain.clone();
    let cert_owned = cert_path.clone();
    let key_owned = key_path.clone();
    let web_tls_owned = web_tls.to_string();
    match persist_and_reload(cfg, |c| {
        useredit::enable_acme(
            c,
            &email_owned,
            &domain_owned,
            &cert_owned,
            &key_owned,
            &web_tls_owned,
        )
    }) {
        Ok(()) => {
            // On-demand ACME: snapshot with written paths and start issuance thread.
            let mut snap = if let Some(path) = cfg.config_path.as_ref() {
                Config::load(path).unwrap_or_else(|_| cfg.clone())
            } else {
                cfg.clone()
            };
            snap.acme = true;
            snap.acme_email = email_owned.clone();
            snap.acme_domains = vec![domain_owned.clone()];
            snap.tls_cert_file = Some(cert_path.clone());
            snap.tls_key_file = Some(key_path.clone());
            snap.data_dir = cfg.data_dir.clone();
            snap.config_path = cfg.config_path.clone();
            acme::start_background(std::sync::Arc::new(snap));
            page_dns(
                cfg,
                user,
                Some(
                    "ACME enabled — certificate request started in the background. \
                     Ensure port 80 and DNS A/AAAA are ready. Restart desertemail after \
                     the cert is written so HTTPS (web_tls_listen) can load it.",
                ),
                None,
            )
        }
        Err(e) => page_dns(cfg, user, Some(&format!("error: {}", e)), None),
    }
}

fn handle_dns_settings(cfg: &Config, user: &str, req: &Request) -> Response {
    if !is_admin(cfg, user) {
        return page_dns(cfg, user, Some("error: access denied"), None);
    }
    if let Some(r) = require_auth_post(req, user) {
        return r;
    }
    let form = form_body(req);
    let public_host = form
        .get("public_host")
        .map(|s| s.trim())
        .unwrap_or("")
        .to_string();
    let domain = form
        .get("domain")
        .map(|s| s.trim())
        .unwrap_or("")
        .to_string();
    if domain.is_empty() {
        return page_dns(cfg, user, Some("error: domain required"), None);
    }
    let ph = public_host.clone();
    let dom = domain.clone();
    match persist_and_reload(cfg, |c| {
        let mut out = useredit::set_primary_domain(c, &dom)?;
        out = useredit::set_public_host(&out, &ph)?;
        Ok(out)
    }) {
        Ok(()) => {
            cfg.set_public_host_live(&public_host);
            page_dns(
                cfg,
                user,
                Some(&format!(
                    "Saved domain={} public_host={}.",
                    domain,
                    if public_host.is_empty() {
                        "(auto)"
                    } else {
                        public_host.as_str()
                    }
                )),
                None,
            )
        }
        Err(e) => page_dns(cfg, user, Some(&format!("error: {}", e)), None),
    }
}

// ---------------------------------------------------------------------------
// Message view + MIME
// ---------------------------------------------------------------------------

fn page_message(cfg: &Config, user: &str, req: &Request) -> Response {
    let id: u32 = match req.query.get("id").and_then(|s| s.parse().ok()) {
        Some(n) => n,
        None => {
            return Response::html(
                400,
                "Bad Request",
                page_shell_app(
                    "Message",
                    user,
                    "inbox",
                    count_inbox_unread(cfg, user),
                    None,
                    "<p class=\"err\">Missing id</p>",
                ),
            );
        }
    };
    let folder = req
        .query
        .get("folder")
        .map(|s| s.as_str())
        .filter(|s| !s.is_empty())
        .unwrap_or("inbox");
    let show_raw = req.query.get("raw").map(|s| s.as_str()) == Some("1");

    let (md, meta) = match find_message_in_folder(cfg, user, folder, id) {
        Ok(x) => x,
        Err(e) => {
            return Response::html(
                404,
                "Not Found",
                page_shell_app(
                    "Message",
                    user,
                    folder,
                    count_inbox_unread(cfg, user),
                    Some(folder),
                    &format!("<p class=\"err\">{}</p>", esc(&e)),
                ),
            );
        }
    };
    let raw = match md.read_message(&meta.path) {
        Ok(r) => r,
        Err(e) => {
            return Response::html(
                500,
                "Error",
                page_shell_app(
                    "Message",
                    user,
                    folder,
                    count_inbox_unread(cfg, user),
                    Some(folder),
                    &format!("<p class=\"err\">{}</p>", esc(&e.to_string())),
                ),
            );
        }
    };
    let _ = md.mark_seen(&meta);
    // re-read meta after mark_seen for flag state
    let starred = meta.flags.contains('F');

    let headers = extract_headers(&raw);
    let from = headers.get("from").map(|s| s.as_str()).unwrap_or("");
    let to = headers.get("to").map(|s| s.as_str()).unwrap_or("");
    let cc = headers.get("cc").map(|s| s.as_str()).unwrap_or("");
    let subject = headers
        .get("subject")
        .map(|s| s.as_str())
        .unwrap_or("(no subject)");
    let date = headers.get("date").map(|s| s.as_str()).unwrap_or("");
    let message_id = headers.get("message-id").map(|s| s.as_str()).unwrap_or("");
    let references = headers.get("references").map(|s| s.as_str()).unwrap_or("");

    let parsed = parse_mime_message(&raw);
    let text_body = parsed.text.clone();
    let html_note = if parsed.was_html {
        "<p class=\"muted\"><em>HTML message shown as text</em></p>"
    } else {
        ""
    };

    let mut attach_html = String::new();
    if !parsed.attachments.is_empty() {
        attach_html.push_str("<div class=\"pix-panel\"><h2>Attachments</h2><ul class=\"attach-list\">");
        for (i, a) in parsed.attachments.iter().enumerate() {
            attach_html.push_str(&format!(
                "<li><a href=\"/msg/attachment?id={}&folder={}&part={}\">{}</a> \
                 <span class=\"muted\">({} · {})</span></li>",
                id,
                esc(folder),
                i,
                esc(&a.filename),
                esc(&a.content_type),
                format_size(a.data.len() as u64)
            ));
        }
        attach_html.push_str("</ul></div>");
    }

    let folder_q = format!("&folder={}", urlencode_component(folder));
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

    let back = folder_list_path(folder);
    let star_label = if starred { "Unstar" } else { "Star" };
    let cc_row = if cc.is_empty() {
        String::new()
    } else {
        format!("<p><strong>Cc:</strong> {}</p>", esc(cc))
    };

    // Prefill helpers for reply/forward links
    let reply_to = extract_reply_address(from);
    let reply_all_cc = {
        let mut addrs = Vec::new();
        for a in parse_address_list(to) {
            if !a.eq_ignore_ascii_case(user) && !a.eq_ignore_ascii_case(&user_from_addr(cfg, user)) {
                addrs.push(a);
            }
        }
        for a in parse_address_list(cc) {
            if !a.eq_ignore_ascii_case(user) && !a.eq_ignore_ascii_case(&user_from_addr(cfg, user)) {
                addrs.push(a);
            }
        }
        addrs.join(", ")
    };
    let re_subj = if subject.to_lowercase().starts_with("re:") {
        subject.to_string()
    } else {
        format!("Re: {}", subject)
    };
    let fwd_subj = if subject.to_lowercase().starts_with("fwd:")
        || subject.to_lowercase().starts_with("fw:")
    {
        subject.to_string()
    } else {
        format!("Fwd: {}", subject)
    };
    let quoted = format!(
        "\n\nOn {} {} wrote:\n{}",
        date,
        from,
        text_body
            .lines()
            .map(|l| format!("> {}", l))
            .collect::<Vec<_>>()
            .join("\n")
    );
    let fwd_body = format!(
        "\n\n---------- Forwarded message ----------\nFrom: {}\nDate: {}\nSubject: {}\nTo: {}\n\n{}",
        from, date, subject, to, text_body
    );

    let spam_action = if folder == "spam" {
        format!(
            "<form method=\"post\" action=\"/msg/bulk\">\
             <input type=\"hidden\" name=\"folder\" value=\"spam\">\
             <input type=\"hidden\" name=\"id\" value=\"{id}\">\
             <input type=\"hidden\" name=\"redirect\" value=\"/\">\
             <button type=\"submit\" name=\"action\" value=\"notspam\" class=\"btn-secondary\">Not spam</button></form>",
            id = id
        )
    } else if folder == "inbox" || folder == "starred" {
        format!(
            "<form method=\"post\" action=\"/msg/bulk\">\
             <input type=\"hidden\" name=\"folder\" value=\"{folder}\">\
             <input type=\"hidden\" name=\"id\" value=\"{id}\">\
             <input type=\"hidden\" name=\"redirect\" value=\"{back}\">\
             <button type=\"submit\" name=\"action\" value=\"spam\" class=\"btn-secondary\">Spam</button></form>",
            folder = esc(folder),
            id = id,
            back = back
        )
    } else {
        String::new()
    };
    let delete_label = if folder == "trash" || folder == "spam" {
        "Delete forever"
    } else {
        "Delete"
    };

    let body = format!(
        "<p class=\"back-link\"><a href=\"{back}\">&larr; Back to {title}</a></p>\
         <div class=\"pix-panel msg-headers\">\
         <h1>{subj}</h1>\
         <p><strong>From:</strong> {from}</p>\
         <p><strong>To:</strong> {to}</p>\
         {cc_row}\
         <p><strong>Date:</strong> {date}</p>\
         <div class=\"msg-actions\">\
         <a class=\"btn-ghost\" href=\"/compose?mode=reply&to={rto}&subject={rsubj}&in_reply_to={mid}&references={refs}&body={qbody}\">Reply</a>\
         <a class=\"btn-ghost\" href=\"/compose?mode=replyall&to={rto}&cc={rall}&subject={rsubj}&in_reply_to={mid}&references={refs}&body={qbody}\">Reply all</a>\
         <a class=\"btn-ghost\" href=\"/compose?mode=forward&subject={fsubj}&body={fbody}\">Forward</a>\
         {spam_action}\
         <form method=\"post\" action=\"/msg/bulk\">\
         <input type=\"hidden\" name=\"folder\" value=\"{folder}\">\
         <input type=\"hidden\" name=\"id\" value=\"{id}\">\
         <input type=\"hidden\" name=\"redirect\" value=\"{back}\">\
         <button type=\"submit\" name=\"action\" value=\"delete\">{del}</button></form>\
         <form method=\"post\" action=\"/msg/bulk\">\
         <input type=\"hidden\" name=\"folder\" value=\"{folder}\">\
         <input type=\"hidden\" name=\"id\" value=\"{id}\">\
         <input type=\"hidden\" name=\"redirect\" value=\"/msg?id={id}&folder={folder}\">\
         <button type=\"submit\" name=\"action\" value=\"unread\" class=\"btn-secondary\">Mark unread</button></form>\
         <form method=\"post\" action=\"/msg/star\">\
         <input type=\"hidden\" name=\"id\" value=\"{id}\">\
         <input type=\"hidden\" name=\"folder\" value=\"{folder}\">\
         <input type=\"hidden\" name=\"redirect\" value=\"/msg?id={id}&folder={folder}\">\
         <button type=\"submit\" class=\"btn-secondary\">{star}</button></form>\
         </div></div>\
         {html_note}\
         <div class=\"pix-panel msg-body\">{body}</div>\
         {attach}\
         {raw}",
        back = back,
        title = esc(folder_title(folder)),
        subj = esc(subject),
        from = esc(from),
        to = esc(to),
        cc_row = cc_row,
        date = esc(date),
        rto = urlencode_component(&reply_to),
        rsubj = urlencode_component(&re_subj),
        mid = urlencode_component(message_id),
        refs = urlencode_component(&if references.is_empty() {
            message_id.to_string()
        } else if message_id.is_empty() {
            references.to_string()
        } else {
            format!("{} {}", references, message_id)
        }),
        qbody = urlencode_component(&quoted),
        rall = urlencode_component(&reply_all_cc),
        fsubj = urlencode_component(&fwd_subj),
        fbody = urlencode_component(&fwd_body),
        folder = esc(folder),
        id = id,
        star = star_label,
        spam_action = spam_action,
        del = delete_label,
        html_note = html_note,
        body = esc(&text_body),
        attach = attach_html,
        raw = raw_section,
    );
    Response::html(
        200,
        "OK",
        page_shell_app(
            subject,
            user,
            folder,
            count_inbox_unread(cfg, user),
            Some(folder),
            &body,
        ),
    )
}

fn extract_reply_address(from: &str) -> String {
    let list = parse_address_list(from);
    list.into_iter().next().unwrap_or_else(|| from.to_string())
}

fn format_size(n: u64) -> String {
    if n < 1024 {
        format!("{} B", n)
    } else if n < 1024 * 1024 {
        format!("{:.1} KB", n as f64 / 1024.0)
    } else {
        format!("{:.1} MB", n as f64 / (1024.0 * 1024.0))
    }
}

fn handle_attachment(cfg: &Config, user: &str, req: &Request) -> Response {
    let id: u32 = match req.query.get("id").and_then(|s| s.parse().ok()) {
        Some(n) => n,
        None => return Response::plain(400, "missing id"),
    };
    let folder = req
        .query
        .get("folder")
        .map(|s| s.as_str())
        .unwrap_or("inbox");
    let part: usize = req
        .query
        .get("part")
        .and_then(|s| s.parse().ok())
        .unwrap_or(0);
    let (md, meta) = match find_message_in_folder(cfg, user, folder, id) {
        Ok(x) => x,
        Err(_) => return Response::plain(404, "not found"),
    };
    let raw = match md.read_message(&meta.path) {
        Ok(r) => r,
        Err(_) => return Response::plain(500, "read error"),
    };
    let parsed = parse_mime_message(&raw);
    match parsed.attachments.get(part) {
        Some(a) => Response::attachment(&a.filename, a.data.clone()),
        None => Response::plain(404, "part not found"),
    }
}

#[derive(Debug, Clone)]
pub struct MimeAttachment {
    pub filename: String,
    pub content_type: String,
    pub data: Vec<u8>,
}

#[derive(Debug, Clone)]
pub struct ParsedMime {
    pub text: String,
    pub was_html: bool,
    pub attachments: Vec<MimeAttachment>,
}

/// Maximum multipart nesting depth. A hostile message can nest multiparts
/// arbitrarily deep; since release builds use `panic = "abort"`, an unbounded
/// recursive walk that overflows the stack would take down the whole server.
/// Beyond this depth we stop recursing and treat the part as opaque.
const MAX_MIME_DEPTH: usize = 16;
/// Maximum number of parts processed within a single multipart body. Guards
/// against a body split into a pathological number of tiny parts.
const MAX_MIME_PARTS: usize = 1000;

/// Walk MIME tree: prefer text/plain, fall back to stripped HTML; list attachments;
/// decode base64 / quoted-printable transfer encodings.
pub fn parse_mime_message(raw: &[u8]) -> ParsedMime {
    let headers = extract_headers(raw);
    let body_start = header_block_end(raw).min(raw.len());
    let body = raw.get(body_start..).unwrap_or(&[]);
    let ct = headers
        .get("content-type")
        .map(|s| s.as_str())
        .unwrap_or("text/plain");
    let te = headers
        .get("content-transfer-encoding")
        .map(|s| s.as_str())
        .unwrap_or("");
    walk_mime_part(ct, te, body, 0)
}

fn walk_mime_part(content_type: &str, transfer_enc: &str, body: &[u8], depth: usize) -> ParsedMime {
    let ct_lower = content_type.to_lowercase();
    if ct_lower.contains("multipart/") && depth < MAX_MIME_DEPTH {
        if let Some(boundary) = mime_boundary(content_type) {
            return walk_multipart(
                body,
                &boundary,
                ct_lower.contains("multipart/alternative"),
                depth,
            );
        }
    }
    let decoded = decode_transfer(body, transfer_enc);
    if ct_lower.starts_with("text/plain") {
        return ParsedMime {
            text: String::from_utf8_lossy(&decoded).into_owned(),
            was_html: false,
            attachments: Vec::new(),
        };
    }
    if ct_lower.starts_with("text/html") {
        let html = String::from_utf8_lossy(&decoded);
        return ParsedMime {
            text: strip_html_to_text(&html),
            was_html: true,
            attachments: Vec::new(),
        };
    }
    // Non-text single part → treat as attachment
    let filename = content_type_name(content_type).unwrap_or_else(|| "attachment".into());
    ParsedMime {
        text: String::new(),
        was_html: false,
        attachments: vec![MimeAttachment {
            filename,
            content_type: content_type
                .split(';')
                .next()
                .unwrap_or("application/octet-stream")
                .trim()
                .to_string(),
            data: decoded,
        }],
    }
}

fn walk_multipart(body: &[u8], boundary: &str, _is_alt: bool, depth: usize) -> ParsedMime {
    let delim = format!("--{}", boundary);
    let text = String::from_utf8_lossy(body);
    let mut parts = text.split(&delim);
    let _ = parts.next(); // preamble
    let mut plain: Option<String> = None;
    let mut html: Option<String> = None;
    let mut attachments = Vec::new();
    let mut nested = Vec::new();
    let mut seen = 0usize;
    for part in parts {
        seen += 1;
        if seen > MAX_MIME_PARTS {
            break;
        }
        let part = part.trim_start_matches("\r\n").trim_start_matches('\n');
        if part.starts_with("--") || part.trim().is_empty() {
            break;
        }
        let part_bytes = part.as_bytes();
        // Use string split path for headers (part is UTF-8 lossy already)
        let (phdr, pbody_str) = split_mime_part(part);
        let ct = phdr
            .get("content-type")
            .map(|s| s.as_str())
            .unwrap_or("text/plain");
        let te = phdr
            .get("content-transfer-encoding")
            .map(|s| s.as_str())
            .unwrap_or("");
        let cd = phdr
            .get("content-disposition")
            .map(|s| s.as_str())
            .unwrap_or("");
        let ct_lower = ct.to_lowercase();
        // Nested multipart — bounded by MAX_MIME_DEPTH. Past the limit the part
        // is left to fall through and be handled as an opaque (attachment) body
        // rather than recursed into.
        if ct_lower.contains("multipart/") && depth + 1 < MAX_MIME_DEPTH {
            let sub = walk_mime_part(ct, te, pbody_str.as_bytes(), depth + 1);
            nested.push(sub);
            continue;
        }
        let is_attach = cd.to_lowercase().contains("attachment")
            || content_disposition_param(cd, "filename").is_some()
            || (!ct_lower.starts_with("text/") && !ct_lower.contains("multipart/"));
        let decoded = decode_transfer(pbody_str.as_bytes(), te);
        if is_attach && !ct_lower.starts_with("text/plain") && !ct_lower.starts_with("text/html")
            || (cd.to_lowercase().contains("attachment")
                && content_disposition_param(cd, "filename").is_some())
        {
            let fname = content_disposition_param(cd, "filename")
                .or_else(|| content_type_name(ct))
                .unwrap_or_else(|| "attachment".into());
            attachments.push(MimeAttachment {
                filename: fname,
                content_type: ct
                    .split(';')
                    .next()
                    .unwrap_or("application/octet-stream")
                    .trim()
                    .to_string(),
                data: decoded,
            });
            continue;
        }
        if ct_lower.starts_with("text/plain") {
            plain = Some(String::from_utf8_lossy(&decoded).into_owned());
        } else if ct_lower.starts_with("text/html") {
            html = Some(String::from_utf8_lossy(&decoded).into_owned());
        } else {
            let fname = content_disposition_param(cd, "filename")
                .or_else(|| content_type_name(ct))
                .unwrap_or_else(|| "attachment".into());
            attachments.push(MimeAttachment {
                filename: fname,
                content_type: ct
                    .split(';')
                    .next()
                    .unwrap_or("application/octet-stream")
                    .trim()
                    .to_string(),
                data: decoded,
            });
        }
        let _ = part_bytes;
    }
    // Merge nested
    for n in nested {
        if plain.is_none() && !n.text.is_empty() && !n.was_html {
            plain = Some(n.text.clone());
        } else if html.is_none() && n.was_html {
            html = Some(n.text.clone());
        } else if plain.is_none() && !n.text.is_empty() {
            plain = Some(n.text.clone());
        }
        attachments.extend(n.attachments);
    }
    if let Some(t) = plain {
        ParsedMime {
            text: t,
            was_html: false,
            attachments,
        }
    } else if let Some(h) = html {
        ParsedMime {
            text: strip_html_to_text(&h),
            was_html: true,
            attachments,
        }
    } else {
        ParsedMime {
            text: String::new(),
            was_html: false,
            attachments,
        }
    }
}

fn content_type_name(ct: &str) -> Option<String> {
    let lower = ct.to_lowercase();
    let idx = lower.find("name=")?;
    let rest = ct.get(idx + 5..)?.trim().trim_start_matches('"');
    let end = rest
        .find(|c: char| c == '"' || c == ';')
        .unwrap_or(rest.len());
    let n = rest.get(..end)?.trim().trim_matches('"');
    if n.is_empty() {
        None
    } else {
        Some(n.to_string())
    }
}

pub fn decode_transfer(data: &[u8], encoding: &str) -> Vec<u8> {
    let enc = encoding.trim().to_ascii_lowercase();
    if enc == "base64" {
        let s: String = String::from_utf8_lossy(data)
            .chars()
            .filter(|c| !c.is_whitespace())
            .collect();
        util::base64_decode(&s)
    } else if enc == "quoted-printable" {
        decode_quoted_printable(data)
    } else {
        data.to_vec()
    }
}

pub fn decode_quoted_printable(data: &[u8]) -> Vec<u8> {
    let mut out = Vec::with_capacity(data.len());
    let mut i = 0;
    while i < data.len() {
        if data[i] == b'=' {
            if i + 1 < data.len() && (data[i + 1] == b'\r' || data[i + 1] == b'\n') {
                // soft line break
                i += 1;
                if i < data.len() && data[i] == b'\r' {
                    i += 1;
                }
                if i < data.len() && data[i] == b'\n' {
                    i += 1;
                }
                continue;
            }
            if i + 2 < data.len() {
                if let (Some(hi), Some(lo)) = (from_hex(data[i + 1]), from_hex(data[i + 2])) {
                    out.push((hi << 4) | lo);
                    i += 3;
                    continue;
                }
            }
            out.push(data[i]);
            i += 1;
        } else {
            out.push(data[i]);
            i += 1;
        }
    }
    out
}

/// Strip HTML tags to plain text (no script execution / no HTML rendering).
pub fn strip_html_to_text(html: &str) -> String {
    let mut out = String::new();
    let mut in_tag = false;
    let mut in_entity = false;
    let mut entity = String::new();
    let lower = html.to_lowercase();
    // crude skip of script/style blocks
    let chars: Vec<char> = html.chars().collect();
    let mut ci = 0;
    while ci < chars.len() {
        let c = chars[ci];
        if !in_tag && c == '<' {
            // check for script/style
            let rest: String = chars[ci..].iter().take(20).collect::<String>().to_lowercase();
            if rest.starts_with("<script") {
                if let Some(end) = lower[html_char_byte_index(html, ci)..].find("</script>") {
                    let skip_to = html_char_byte_index(html, ci) + end + 9;
                    ci = html_byte_to_char_index(html, skip_to);
                    continue;
                }
            }
            if rest.starts_with("<style") {
                if let Some(end) = lower[html_char_byte_index(html, ci)..].find("</style>") {
                    let skip_to = html_char_byte_index(html, ci) + end + 8;
                    ci = html_byte_to_char_index(html, skip_to);
                    continue;
                }
            }
            in_tag = true;
            // block-level → newline
            if rest.starts_with("<br")
                || rest.starts_with("<p")
                || rest.starts_with("<div")
                || rest.starts_with("<tr")
                || rest.starts_with("<li")
                || rest.starts_with("</p")
                || rest.starts_with("</div")
                || rest.starts_with("</tr")
                || rest.starts_with("</h")
            {
                if !out.ends_with('\n') {
                    out.push('\n');
                }
            }
            ci += 1;
            continue;
        }
        if in_tag {
            if c == '>' {
                in_tag = false;
            }
            ci += 1;
            continue;
        }
        if c == '&' {
            in_entity = true;
            entity.clear();
            ci += 1;
            continue;
        }
        if in_entity {
            if c == ';' || entity.len() > 10 {
                out.push_str(&decode_html_entity(&entity));
                in_entity = false;
                if c != ';' {
                    out.push(c);
                }
            } else {
                entity.push(c);
            }
            ci += 1;
            continue;
        }
        out.push(c);
        ci += 1;
    }
    out
}

fn html_char_byte_index(s: &str, char_idx: usize) -> usize {
    s.chars().take(char_idx).map(|c| c.len_utf8()).sum()
}

fn html_byte_to_char_index(s: &str, byte_idx: usize) -> usize {
    s[..byte_idx.min(s.len())].chars().count()
}

fn decode_html_entity(e: &str) -> String {
    match e {
        "amp" => "&".into(),
        "lt" => "<".into(),
        "gt" => ">".into(),
        "quot" => "\"".into(),
        "apos" | "#39" => "'".into(),
        "nbsp" => " ".into(),
        _ => {
            if let Some(num) = e.strip_prefix('#') {
                if let Some(hex) = num.strip_prefix('x').or_else(|| num.strip_prefix('X')) {
                    if let Ok(n) = u32::from_str_radix(hex, 16) {
                        if let Some(ch) = char::from_u32(n) {
                            return ch.to_string();
                        }
                    }
                } else if let Ok(n) = num.parse::<u32>() {
                    if let Some(ch) = char::from_u32(n) {
                        return ch.to_string();
                    }
                }
            }
            format!("&{};", e)
        }
    }
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

/// Prefer text/plain from multipart; fall back to stripped HTML.
fn extract_text_body(raw: &[u8], _headers: &HashMap<String, String>) -> String {
    parse_mime_message(raw).text
}

fn mime_boundary(content_type: &str) -> Option<String> {
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
// Compose / Send / Drafts
// ---------------------------------------------------------------------------

fn page_compose(
    cfg: &Config,
    user: &str,
    req: &Request,
    error: Option<&str>,
    notice: Option<&str>,
) -> Response {
    let err = error
        .map(|e| format!("<p class=\"err\">{}</p>", esc(e)))
        .unwrap_or_default();
    let ok = notice
        .map(|e| format!("<p class=\"ok\">{}</p>", esc(e)))
        .unwrap_or_default();

    // Prefill from query or draft id
    let mut to = req.query.get("to").cloned().unwrap_or_default();
    let mut cc = req.query.get("cc").cloned().unwrap_or_default();
    let mut bcc = req.query.get("bcc").cloned().unwrap_or_default();
    let mut subject = req.query.get("subject").cloned().unwrap_or_default();
    let mut body_text = req.query.get("body").cloned().unwrap_or_default();
    let mut in_reply_to = req.query.get("in_reply_to").cloned().unwrap_or_default();
    let mut references = req.query.get("references").cloned().unwrap_or_default();
    let mut draft_id = String::new();

    if let Some(did) = req.query.get("draft") {
        if let Ok(id) = did.parse::<u32>() {
            if let Ok((md, meta)) = find_message_in_folder(cfg, user, "drafts", id) {
                if let Ok(raw) = md.read_message(&meta.path) {
                    let headers = extract_headers(&raw);
                    to = headers.get("to").cloned().unwrap_or_default();
                    cc = headers.get("cc").cloned().unwrap_or_default();
                    bcc = headers.get("bcc").cloned().unwrap_or_default();
                    subject = headers.get("subject").cloned().unwrap_or_default();
                    body_text = extract_text_body(&raw, &headers);
                    in_reply_to = headers.get("in-reply-to").cloned().unwrap_or_default();
                    references = headers.get("references").cloned().unwrap_or_default();
                    draft_id = id.to_string();
                }
            }
        }
    }

    let show_cc = !cc.is_empty() || !bcc.is_empty();
    let cc_class = if show_cc {
        "compose-cc-row is-open"
    } else {
        "compose-cc-row"
    };

    let body = format!(
        "<div class=\"pix-panel compose-panel\"><h1>Compose</h1>{err}{ok}\
         <form method=\"post\" action=\"/send\" enctype=\"multipart/form-data\">\
         <input type=\"hidden\" name=\"in_reply_to\" value=\"{irt}\">\
         <input type=\"hidden\" name=\"references\" value=\"{refs}\">\
         <input type=\"hidden\" name=\"draft_id\" value=\"{did}\">\
         <label>To</label><input type=\"text\" name=\"to\" value=\"{to}\" required autocomplete=\"email\">\
         <p><button type=\"button\" class=\"btn-secondary\" id=\"cc-toggle\" onclick=\"\
         var r=document.getElementById('cc-rows');r.classList.toggle('is-open');\
         \">Cc/Bcc</button></p>\
         <div id=\"cc-rows\" class=\"{cc_class}\">\
         <label>Cc</label><input type=\"text\" name=\"cc\" value=\"{cc}\" autocomplete=\"email\">\
         <label>Bcc</label><input type=\"text\" name=\"bcc\" value=\"{bcc}\" autocomplete=\"email\">\
         </div>\
         <label>Subject</label><input type=\"text\" name=\"subject\" value=\"{subj}\">\
         <label>Body</label><textarea name=\"body\">{body}</textarea>\
         <label>Attachments</label><input type=\"file\" name=\"file\" multiple>\
         <div class=\"compose-actions\">\
         <button type=\"submit\" class=\"btn-primary\" name=\"action\" value=\"send\">Send</button>\
         <button type=\"submit\" class=\"btn-secondary\" formaction=\"/draft\" name=\"action\" value=\"draft\">Save draft</button>\
         </div></form></div>",
        err = err,
        ok = ok,
        irt = esc(&in_reply_to),
        refs = esc(&references),
        did = esc(&draft_id),
        to = esc(&to),
        cc = esc(&cc),
        bcc = esc(&bcc),
        cc_class = cc_class,
        subj = esc(&subject),
        body = esc(&body_text),
    );
    Response::html(
        200,
        "OK",
        page_shell_app(
            "Compose",
            user,
            "compose",
            count_inbox_unread(cfg, user),
            None,
            &body,
        ),
    )
}

fn handle_send(cfg: &Config, user: &str, req: &Request) -> Response {
    if let Some(r) = require_auth_post(req, user) {
        return r;
    }
    let (form, files) = if req
        .headers
        .get("content-type")
        .map(|s| s.to_lowercase().contains("multipart/form-data"))
        .unwrap_or(false)
    {
        parse_multipart_form(req)
    } else {
        (form_body(req), Vec::new())
    };
    let to = form.get("to").map(|s| s.trim()).unwrap_or("");
    let cc = form.get("cc").map(|s| s.trim()).unwrap_or("");
    let bcc = form.get("bcc").map(|s| s.trim()).unwrap_or("");
    let subject = form.get("subject").map(|s| s.as_str()).unwrap_or("");
    let body_text = form.get("body").map(|s| s.as_str()).unwrap_or("");
    let in_reply_to = form.get("in_reply_to").map(|s| s.as_str()).unwrap_or("");
    let references = form.get("references").map(|s| s.as_str()).unwrap_or("");
    let draft_id = form.get("draft_id").map(|s| s.as_str()).unwrap_or("");

    if to.is_empty() {
        return page_compose(cfg, user, req, Some("To is required"), None);
    }

    let from = user_from_addr(cfg, user);
    let mut recipients = parse_address_list(to);
    recipients.extend(parse_address_list(cc));
    recipients.extend(parse_address_list(bcc));
    if recipients.is_empty() {
        return page_compose(cfg, user, req, Some("No valid recipients"), None);
    }

    let attach: Vec<(String, String, Vec<u8>)> = files
        .into_iter()
        .filter(|f| f.field == "file" && !f.data.is_empty())
        .map(|f| {
            (
                f.filename,
                if f.content_type.is_empty() {
                    "application/octet-stream".into()
                } else {
                    f.content_type
                },
                f.data,
            )
        })
        .collect();

    let raw = build_rfc5322_message(
        &from,
        to,
        cc,
        bcc,
        subject,
        body_text,
        in_reply_to,
        references,
        &attach,
        cfg,
    );
    match deliver_like_submission(cfg, user, &from, &recipients, &raw) {
        Ok(_) => {
            // Remove draft if sending from one
            if let Ok(id) = draft_id.parse::<u32>() {
                if let Ok((md, meta)) = find_message_in_folder(cfg, user, "drafts", id) {
                    let _ = md.expunge(&meta);
                }
            }
            page_compose(cfg, user, req, None, Some("Message sent."))
        }
        Err(e) => page_compose(cfg, user, req, Some(&e), None),
    }
}

fn handle_save_draft(cfg: &Config, user: &str, req: &Request) -> Response {
    if let Some(r) = require_auth_post(req, user) {
        return r;
    }
    let (form, files) = if req
        .headers
        .get("content-type")
        .map(|s| s.to_lowercase().contains("multipart/form-data"))
        .unwrap_or(false)
    {
        parse_multipart_form(req)
    } else {
        (form_body(req), Vec::new())
    };
    let to = form.get("to").map(|s| s.as_str()).unwrap_or("");
    let cc = form.get("cc").map(|s| s.as_str()).unwrap_or("");
    let bcc = form.get("bcc").map(|s| s.as_str()).unwrap_or("");
    let subject = form.get("subject").map(|s| s.as_str()).unwrap_or("");
    let body_text = form.get("body").map(|s| s.as_str()).unwrap_or("");
    let in_reply_to = form.get("in_reply_to").map(|s| s.as_str()).unwrap_or("");
    let references = form.get("references").map(|s| s.as_str()).unwrap_or("");
    let draft_id = form.get("draft_id").map(|s| s.as_str()).unwrap_or("");

    let from = user_from_addr(cfg, user);
    let attach: Vec<(String, String, Vec<u8>)> = files
        .into_iter()
        .filter(|f| f.field == "file" && !f.data.is_empty())
        .map(|f| (f.filename, f.content_type, f.data))
        .collect();
    let raw = build_rfc5322_message(
        &from, to, cc, bcc, subject, body_text, in_reply_to, references, &attach, cfg,
    );

    let mb = mailbox_name(cfg, user);
    match Maildir::open(&cfg.data_dir, &format!("{}/.Drafts", mb)) {
        Ok(md) => {
            // Replace previous draft if editing
            if let Ok(id) = draft_id.parse::<u32>() {
                if let Ok(msgs) = md.list_messages() {
                    if let Some(meta) = msgs.iter().find(|m| m.uid == id) {
                        let _ = md.expunge(meta);
                    }
                }
            }
            match md.append_raw(&raw, "DS") {
                Ok(_) => {
                    // Redirect to drafts list
                    Response::redirect("/drafts")
                }
                Err(e) => page_compose(cfg, user, req, Some(&e.to_string()), None),
            }
        }
        Err(e) => page_compose(cfg, user, req, Some(&e.to_string()), None),
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
    cc_header: &str,
    bcc_header: &str,
    subject: &str,
    body: &str,
    in_reply_to: &str,
    references: &str,
    attachments: &[(String, String, Vec<u8>)],
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
    let mut body_crlf = String::new();
    for line in body.split('\n') {
        let line = line.trim_end_matches('\r');
        body_crlf.push_str(line);
        body_crlf.push_str("\r\n");
    }

    let mut headers = format!(
        "From: {}\r\n\
         To: {}\r\n",
        sanitize_header_value(from),
        sanitize_header_value(to_header),
    );
    if !cc_header.trim().is_empty() {
        headers.push_str(&format!(
            "Cc: {}\r\n",
            sanitize_header_value(cc_header)
        ));
    }
    // Bcc is not written into the message body for privacy when sending, but for
    // drafts we keep it so the compose form can restore it.
    if !bcc_header.trim().is_empty() && attachments.is_empty() {
        // still omit from outbound - only include if draft (caller can pass later)
        let _ = bcc_header;
    }
    headers.push_str(&format!(
        "Subject: {}\r\n\
         Date: {}\r\n\
         Message-ID: {}\r\n",
        sanitize_header_value(subject),
        date,
        msg_id
    ));
    if !in_reply_to.trim().is_empty() {
        headers.push_str(&format!(
            "In-Reply-To: {}\r\n",
            sanitize_header_value(in_reply_to)
        ));
    }
    if !references.trim().is_empty() {
        headers.push_str(&format!(
            "References: {}\r\n",
            sanitize_header_value(references)
        ));
    }
    headers.push_str("MIME-Version: 1.0\r\n");

    if attachments.is_empty() {
        headers.push_str("Content-Type: text/plain; charset=utf-8\r\n\r\n");
        let mut msg = headers.into_bytes();
        msg.extend_from_slice(body_crlf.as_bytes());
        return msg;
    }

    let boundary = format!("de_{}_{}", util::now_millis(), std::process::id());
    headers.push_str(&format!(
        "Content-Type: multipart/mixed; boundary=\"{}\"\r\n\r\n",
        boundary
    ));
    let mut msg = headers.into_bytes();
    msg.extend_from_slice(
        format!(
            "--{}\r\nContent-Type: text/plain; charset=utf-8\r\nContent-Transfer-Encoding: 8bit\r\n\r\n{}\r\n",
            boundary, body_crlf
        )
        .as_bytes(),
    );
    for (fname, ctype, data) in attachments {
        let safe_name = sanitize_header_value(fname).replace('"', "_");
        let safe_ct = sanitize_header_value(ctype);
        let b64 = util::base64_encode(data);
        // fold base64 at 76 chars
        let mut folded = String::new();
        for (i, c) in b64.chars().enumerate() {
            if i > 0 && i % 76 == 0 {
                folded.push_str("\r\n");
            }
            folded.push(c);
        }
        msg.extend_from_slice(
            format!(
                "--{}\r\nContent-Type: {}; name=\"{}\"\r\n\
                 Content-Transfer-Encoding: base64\r\n\
                 Content-Disposition: attachment; filename=\"{}\"\r\n\r\n{}\r\n",
                boundary, safe_ct, safe_name, safe_name, folded
            )
            .as_bytes(),
        );
    }
    msg.extend_from_slice(format!("--{}--\r\n", boundary).as_bytes());
    msg
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

/// `flash` is plain text (escaped). `extra_html` is trusted server-built HTML
/// (e.g. invite link with copy button) rendered after the flash.
fn page_admin(
    cfg: &Config,
    user: &str,
    flash: Option<&str>,
    extra_html: Option<&str>,
) -> Response {
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
        return Response::html(
            403,
            "Forbidden",
            page_shell_app(
                "Admin",
                user,
                "admin",
                count_inbox_unread(cfg, user),
                None,
                &body,
            ),
        );
    }

    let domain_list = cfg.domains_list();
    let primary = cfg.primary_domain();
    let domains: String = domain_list
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

    let pending = invites::list_pending(&cfg.data_dir).unwrap_or_default();
    let mut invite_rows = String::new();
    if pending.is_empty() {
        invite_rows.push_str(
            "<tr class=\"empty\"><td colspan=\"4\">No pending invites</td></tr>",
        );
    } else {
        for inv in &pending {
            invite_rows.push_str(&format!(
                "<tr>\
                 <td data-label=\"Address\">{}</td>\
                 <td data-label=\"Created\">{}</td>\
                 <td data-label=\"Expires\">{}</td>\
                 <td>\
                 <form method=\"post\" action=\"/admin/invite/regenerate\" style=\"display:inline\">\
                 <input type=\"hidden\" name=\"token_hash\" value=\"{}\">\
                 <button type=\"submit\" class=\"btn-secondary\">Resend / regenerate</button></form> \
                 <form method=\"post\" action=\"/admin/invite/revoke\" style=\"display:inline\">\
                 <input type=\"hidden\" name=\"token_hash\" value=\"{}\">\
                 <button type=\"submit\">Revoke</button></form>\
                 </td></tr>",
                esc(&inv.email),
                esc(&fmt_unix_date(inv.created_at)),
                esc(&fmt_unix_date(inv.expires_at)),
                esc(&inv.token_hash),
                esc(&inv.token_hash)
            ));
        }
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
    let extra = extra_html.unwrap_or("");

    let body = format!(
        "<h1>Admin</h1>{}{}\
         <div class=\"pix-panel\"><h2>Domains</h2><ul>{}</ul>\
         <p class=\"muted\"><a href=\"/dns\">DNS setup &amp; checks →</a></p></div>\
         <div class=\"pix-panel\"><h2>Users</h2><ul>{}</ul>\
         <h3>Add user</h3>\
         <form method=\"post\" action=\"/admin/user/add\">\
         <label>Email / username</label><input type=\"text\" name=\"email\" required>\
         <label>Password</label><input type=\"password\" name=\"password\" required>\
         <p><button type=\"submit\">Add user</button></p></form>\
         <h3>Invite user</h3>\
         <p class=\"muted\">Create an account without choosing their password. They open a \
         one-time link and set it themselves. Optional: email the link to an address they \
         already read — <strong>not</strong> their new mailbox (they cannot log in yet).</p>\
         <form method=\"post\" action=\"/admin/invite\">\
         <label>Address</label>\
         <input type=\"text\" name=\"email\" required placeholder=\"user@{}\" autocomplete=\"off\">\
         <p class=\"muted\">Must be <code>user@</code> one of your configured domains \
         (primary: <code>{}</code>).</p>\
         <label>Send invite to (external email, optional)</label>\
         <input type=\"email\" name=\"send_to\" placeholder=\"them@gmail.com\" autocomplete=\"off\">\
         <p><button type=\"submit\">Create invite</button></p></form>\
         <h3>Pending invites</h3>\
         <div class=\"table-scroll\">\
         <table class=\"queue-list\"><thead><tr><th>Address</th><th>Created</th>\
         <th>Expires</th><th></th></tr></thead><tbody>{}</tbody></table></div>\
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
         <div class=\"pix-panel\"><h2>Backup &amp; migrate</h2>\
         <p>One click downloads a single <strong>ustar</strong> archive with \
         <code>config.toml</code>, TLS/DKIM keys (if configured), and the full \
         <code>data_dir</code> (maildirs including Spam/Trash/Sent/Drafts, queue, \
         invites, greylist). Maildir <code>tmp/</code> dirs are skipped. In-memory \
         downloads are capped at ~512&nbsp;MiB — for huge mailboxes use \
         <code>deploy/backup.sh</code> instead.</p>\
         <p><a class=\"btn btn-primary\" href=\"/admin/backup\" style=\"display:inline-flex;text-decoration:none;border-bottom:none\">\
         Download backup</a></p>\
         <p class=\"muted\">Restore on a new host:</p>\
         <pre class=\"code\">desertemail --restore desertemail-backup-….tar --config /path/to/config.toml</pre>\
         <p class=\"muted\">Then start with <code>desertemail --config /path/to/config.toml</code>. \
         The restore command rewrites <code>data_dir</code> next to the new config when needed.</p></div>\
         <p class=\"admin-ops\">Ops: <code>/healthz</code> · <code>/metrics</code></p>\
         <script>(function(){{\
         document.querySelectorAll('button.copy-btn').forEach(function(b){{\
           b.addEventListener('click',function(){{\
             var t=b.getAttribute('data-copy')||'';\
             if(navigator.clipboard&&navigator.clipboard.writeText){{\
               navigator.clipboard.writeText(t).then(function(){{b.textContent='Copied';\
               setTimeout(function(){{b.textContent='Copy'}},1200)}});\
             }} else {{\
               var a=document.createElement('textarea');a.value=t;document.body.appendChild(a);\
               a.select();try{{document.execCommand('copy');b.textContent='Copied'}}catch(e){{}}\
               document.body.removeChild(a);\
               setTimeout(function(){{b.textContent='Copy'}},1200);\
             }}\
           }});\
         }});\
         }})();</script>",
        flash_html,
        extra,
        domains,
        users_html,
        esc(&primary),
        esc(&primary),
        invite_rows,
        queue_rows
    );
    Response::html(
        200,
        "OK",
        page_shell_app(
            "Admin",
            user,
            "admin",
            count_inbox_unread(cfg, user),
            None,
            &body,
        ),
    )
}

fn fmt_unix_date(secs: u64) -> String {
    let days = (secs / 86400) as i64;
    let (y, m, d) = util::civil_from_days(days);
    format!("{:04}-{:02}-{:02}", y, m, d)
}

/// Base URL for invite links: `public_host` when set, else request Host.
fn invite_url_base(cfg: &Config, req: &Request, secure: bool) -> String {
    let ph = cfg.public_host_name();
    if !ph.is_empty() {
        let host = ph.trim().trim_end_matches('.');
        if host.starts_with("http://") || host.starts_with("https://") {
            return host.trim_end_matches('/').to_string();
        }
        let scheme = if secure || !cfg.web_tls_listen.is_empty() {
            "https"
        } else {
            "http"
        };
        let port = web_listen_port(cfg, secure);
        if !host.contains(':') {
            if let Some(p) = port {
                if (scheme == "https" && p != 443) || (scheme == "http" && p != 80) {
                    return format!("{}://{}:{}", scheme, host, p);
                }
            }
        }
        return format!("{}://{}", scheme, host);
    }
    let host = req
        .headers
        .get("host")
        .map(|s| s.as_str())
        .filter(|h| !h.is_empty())
        .unwrap_or("127.0.0.1:8080");
    let scheme = if secure { "https" } else { "http" };
    format!("{}://{}", scheme, host)
}

fn web_listen_port(cfg: &Config, secure: bool) -> Option<u16> {
    let listen = if secure && !cfg.web_tls_listen.is_empty() {
        cfg.web_tls_listen.as_str()
    } else if !cfg.web_listen.is_empty() {
        cfg.web_listen.as_str()
    } else if !cfg.web_tls_listen.is_empty() {
        cfg.web_tls_listen.as_str()
    } else {
        return None;
    };
    listen.rsplit(':').next().and_then(|p| p.parse().ok())
}

fn build_invite_url(cfg: &Config, req: &Request, secure: bool, token: &str) -> String {
    format!(
        "{}/invite?token={}",
        invite_url_base(cfg, req, secure),
        token
    )
}

fn invite_link_flash_html(url: &str, note: &str) -> String {
    format!(
        "<div class=\"pix-panel\" style=\"margin-bottom:1rem\">\
         <p class=\"ok\">{}</p>\
         <p>Invite link (copy now — it cannot be shown again from the table):</p>\
         <p><code style=\"word-break:break-all;user-select:all\">{}</code> \
         <button type=\"button\" class=\"copy-btn\" data-copy=\"{}\">Copy</button></p>\
         </div>",
        esc(note),
        esc(url),
        esc(url)
    )
}

fn user_already_exists(cfg: &Config, email: &str) -> bool {
    let email_l = email.to_lowercase();
    let (local, _) = util::parse_email_addr(&email_l);
    cfg.user_names().iter().any(|n| {
        let n = n.to_lowercase();
        n == email_l || n == local
    })
}

fn handle_admin_post(cfg: &Config, user: &str, _req: &Request) -> Response {
    page_admin(cfg, user, None, None)
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
        return page_admin(cfg, user, Some("error: access denied"), None);
    }
    if let Some(r) = require_auth_post(req, user) {
        return r;
    }
    let form = form_body(req);
    let email = form.get("email").map(|s| s.trim()).unwrap_or("");
    let password = form.get("password").map(|s| s.as_str()).unwrap_or("");
    if email.is_empty() || password.is_empty() {
        return page_admin(cfg, user, Some("error: email and password required"), None);
    }
    let email_owned = email.to_string();
    let password_owned = password.to_string();
    match persist_and_reload(cfg, |c| useredit::add_user(c, &email_owned, &password_owned)) {
        Ok(()) => page_admin(
            cfg,
            user,
            Some(&format!("User {} added (live; no restart needed).", email_owned)),
            None,
        ),
        Err(e) => page_admin(cfg, user, Some(&format!("error: {}", e)), None),
    }
}

fn handle_admin_user_remove(cfg: &Config, user: &str, req: &Request) -> Response {
    if !is_admin(cfg, user) {
        return page_admin(cfg, user, Some("error: access denied"), None);
    }
    if let Some(r) = require_auth_post(req, user) {
        return r;
    }
    let form = form_body(req);
    let email = form.get("email").map(|s| s.trim()).unwrap_or("");
    if email.is_empty() {
        return page_admin(cfg, user, Some("error: email required"), None);
    }
    if email.eq_ignore_ascii_case(user) {
        return page_admin(cfg, user, Some("error: cannot remove the logged-in admin"), None);
    }
    let email_owned = email.to_string();
    match persist_and_reload(cfg, |c| useredit::remove_user(c, &email_owned)) {
        Ok(()) => page_admin(
            cfg,
            user,
            Some(&format!("User {} removed.", email_owned)),
            None,
        ),
        Err(e) => page_admin(cfg, user, Some(&format!("error: {}", e)), None),
    }
}

fn handle_admin_user_quota(cfg: &Config, user: &str, req: &Request) -> Response {
    if !is_admin(cfg, user) {
        return page_admin(cfg, user, Some("error: access denied"), None);
    }
    if let Some(r) = require_auth_post(req, user) {
        return r;
    }
    let form = form_body(req);
    let email = form.get("email").map(|s| s.trim()).unwrap_or("");
    let mb_s = form.get("quota_mb").map(|s| s.trim()).unwrap_or("0");
    if email.is_empty() {
        return page_admin(cfg, user, Some("error: email required"), None);
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
                None,
            )
        }
        Err(e) => page_admin(cfg, user, Some(&format!("error: {}", e)), None),
    }
}

/// Soft cap for in-memory backup builds (~512 MiB).
const BACKUP_MAX_BYTES: u64 = 512 * 1024 * 1024;

fn handle_admin_backup(cfg: &Config, user: &str) -> Response {
    if !is_admin(cfg, user) {
        return Response::html(
            403,
            "Forbidden",
            page_shell_app(
                "Admin",
                user,
                "admin",
                count_inbox_unread(cfg, user),
                None,
                "<h1>Admin</h1><p class=\"err\">Access denied.</p>",
            ),
        );
    }
    let config_path = match cfg.config_path.as_ref() {
        Some(p) => p.clone(),
        None => {
            return page_admin(
                cfg,
                user,
                Some("error: config_path not set; cannot build backup"),
                None,
            );
        }
    };
    let data_dir = std::path::PathBuf::from(&cfg.data_dir);
    // Rough size guard before reading everything into memory.
    let approx = dir_size_approx(&data_dir).unwrap_or(0)
        + std::fs::metadata(&config_path)
            .map(|m| m.len())
            .unwrap_or(0);
    if approx > BACKUP_MAX_BYTES {
        return page_admin(
            cfg,
            user,
            Some(&format!(
                "error: mailbox data is about {} MiB — too large for in-browser download \
                 (limit {} MiB). Use deploy/backup.sh for large installs.",
                approx / (1024 * 1024),
                BACKUP_MAX_BYTES / (1024 * 1024)
            )),
            None,
        );
    }

    let dkim = cfg
        .dkim_key_file_path()
        .map(std::path::PathBuf::from);
    let tls_cert = cfg.tls_cert_file.as_ref().map(std::path::PathBuf::from);
    let tls_key = cfg.tls_key_file.as_ref().map(std::path::PathBuf::from);

    let layout = crate::tarball::backup_layout(
        &config_path,
        &data_dir,
        dkim.as_deref(),
        tls_cert.as_deref(),
        tls_key.as_deref(),
    );
    let tar = match crate::tarball::build_tar(&layout, |path, reason| {
        util::log!("backup skip {}: {}", path, reason);
    }) {
        Ok(t) => t,
        Err(e) => {
            return page_admin(
                cfg,
                user,
                Some(&format!("error: backup failed: {}", e)),
                None,
            );
        }
    };
    if tar.len() as u64 > BACKUP_MAX_BYTES {
        return page_admin(
            cfg,
            user,
            Some("error: backup archive exceeded 512 MiB; use deploy/backup.sh"),
            None,
        );
    }

    let domain = cfg.primary_domain();
    let domain_safe: String = domain
        .chars()
        .map(|c| {
            if c.is_ascii_alphanumeric() || c == '-' || c == '_' {
                c
            } else {
                '_'
            }
        })
        .collect();
    let stamp = backup_timestamp();
    let filename = format!("desertemail-backup-{}-{}.tar", domain_safe, stamp);
    Response::attachment(&filename, tar)
}

fn backup_timestamp() -> String {
    let secs = util::now_secs();
    let days = (secs / 86400) as i64;
    let tod = secs % 86400;
    let hh = tod / 3600;
    let mm = (tod % 3600) / 60;
    // Reuse civil date from message list helpers
    let z = days + 719468;
    let era = if z >= 0 { z } else { z - 146096 } / 146097;
    let doe = (z - era * 146097) as u64;
    let yoe = (doe - doe / 1460 + doe / 36524 - doe / 146096) / 365;
    let y = (yoe as i64) + era * 400;
    let doy = doe - (365 * yoe + yoe / 4 - yoe / 100);
    let mp = (5 * doy + 2) / 153;
    let d = doy - (153 * mp + 2) / 5 + 1;
    let m = if mp < 10 { mp + 3 } else { mp - 9 };
    let y = if m <= 2 { y + 1 } else { y };
    format!("{:04}{:02}{:02}-{:02}{:02}", y, m, d, hh, mm)
}

fn dir_size_approx(path: &std::path::Path) -> std::io::Result<u64> {
    if !path.exists() {
        return Ok(0);
    }
    if path.is_file() {
        return Ok(std::fs::metadata(path)?.len());
    }
    let mut total = 0u64;
    let mut stack = vec![path.to_path_buf()];
    while let Some(dir) = stack.pop() {
        let rd = match std::fs::read_dir(&dir) {
            Ok(r) => r,
            Err(_) => continue,
        };
        for ent in rd.flatten() {
            let p = ent.path();
            let name = ent.file_name();
            if name == "tmp" {
                continue;
            }
            let ft = match ent.file_type() {
                Ok(t) => t,
                Err(_) => continue,
            };
            if ft.is_dir() {
                stack.push(p);
            } else if ft.is_file() {
                if let Ok(m) = ent.metadata() {
                    total = total.saturating_add(m.len());
                }
            }
        }
    }
    Ok(total)
}

fn handle_queue_delete(cfg: &Config, user: &str, req: &Request) -> Response {
    if !is_admin(cfg, user) {
        return page_admin(cfg, user, None, None);
    }
    if let Some(r) = require_auth_post(req, user) {
        return r;
    }
    let form = form_body(req);
    let id = form.get("id").map(|s| s.as_str()).unwrap_or("");
    match queue::delete_queued(&cfg.data_dir, id) {
        Ok(true) => page_admin(cfg, user, Some("Queue entry deleted."), None),
        Ok(false) => page_admin(cfg, user, Some("Queue entry not found."), None),
        Err(e) => page_admin(cfg, user, Some(&format!("Delete failed: {}", e)), None),
    }
}

fn handle_admin_invite(cfg: &Config, user: &str, req: &Request, secure: bool) -> Response {
    if !is_admin(cfg, user) {
        return page_admin(cfg, user, Some("error: access denied"), None);
    }
    if let Some(r) = require_auth_post(req, user) {
        return r;
    }
    let form = form_body(req);
    let email_raw = form.get("email").map(|s| s.trim()).unwrap_or("");
    let send_to = form
        .get("send_to")
        .map(|s| s.trim())
        .filter(|s| !s.is_empty())
        .unwrap_or("");

    let domains = cfg.domains_list();
    let email = match invites::validate_invite_address(email_raw, &domains) {
        Ok(e) => e,
        Err(e) => {
            return page_admin(cfg, user, Some(&format!("error: {}", e)), None);
        }
    };
    if user_already_exists(cfg, &email) {
        return page_admin(
            cfg,
            user,
            Some(&format!("error: user {} already exists", email)),
            None,
        );
    }

    let created = match invites::create(
        &cfg.data_dir,
        &email,
        user,
        invites::DEFAULT_TTL_SECS,
    ) {
        Ok(c) => c,
        Err(e) => {
            return page_admin(cfg, user, Some(&format!("error: {}", e)), None);
        }
    };
    let url = build_invite_url(cfg, req, secure, &created.token);
    let mut note = format!("Invite created for {}.", email);
    if !send_to.is_empty() {
        match send_invite_email(cfg, user, send_to, &email, &url) {
            Ok(status) => {
                note.push(' ');
                note.push_str(&status);
            }
            Err(e) => {
                note.push_str(&format!(
                    " Email to {} failed ({}) — hand over the link below.",
                    send_to, e
                ));
            }
        }
    }
    let extra = invite_link_flash_html(&url, &note);
    page_admin(cfg, user, None, Some(&extra))
}

fn send_invite_email(
    cfg: &Config,
    admin: &str,
    to: &str,
    invited_addr: &str,
    link: &str,
) -> Result<String, String> {
    let from = user_from_addr(cfg, admin);
    let host = {
        let ph = cfg.public_host_name();
        if !ph.is_empty() {
            ph
        } else {
            cfg.primary_domain()
        }
    };
    let subject = format!("You're invited to {}", invited_addr);
    let body = format!(
        "You've been invited to {} on {}.\n\n\
         Set your password: {}\n\n\
         This link expires in 7 days. If you did not expect this, ignore this message.\n",
        invited_addr, host, link
    );
    let raw = build_rfc5322_message(
        &from,
        to,
        "",
        "",
        &subject,
        &body,
        "",
        "",
        &[],
        cfg,
    );
    deliver_like_submission(cfg, admin, &from, &[to.to_string()], &raw)?;
    // Local vs remote status for flash.
    if cfg.resolve_mailbox(to).is_some() {
        Ok(format!("Invite email delivered locally to {}.", to))
    } else {
        Ok(format!("Invite email queued for {}.", to))
    }
}

fn handle_admin_invite_revoke(cfg: &Config, user: &str, req: &Request) -> Response {
    if !is_admin(cfg, user) {
        return page_admin(cfg, user, Some("error: access denied"), None);
    }
    if let Some(r) = require_auth_post(req, user) {
        return r;
    }
    let form = form_body(req);
    let token_hash = form.get("token_hash").map(|s| s.as_str()).unwrap_or("");
    match invites::revoke_by_hash(&cfg.data_dir, token_hash) {
        Ok(true) => page_admin(cfg, user, Some("Invite revoked."), None),
        Ok(false) => page_admin(cfg, user, Some("error: invite not found"), None),
        Err(e) => page_admin(cfg, user, Some(&format!("error: {}", e)), None),
    }
}

fn handle_admin_invite_regenerate(
    cfg: &Config,
    user: &str,
    req: &Request,
    secure: bool,
) -> Response {
    if !is_admin(cfg, user) {
        return page_admin(cfg, user, Some("error: access denied"), None);
    }
    if let Some(r) = require_auth_post(req, user) {
        return r;
    }
    let form = form_body(req);
    let token_hash = form.get("token_hash").map(|s| s.as_str()).unwrap_or("");
    match invites::regenerate(&cfg.data_dir, token_hash) {
        Ok(Some(created)) => {
            let url = build_invite_url(cfg, req, secure, &created.token);
            let note = format!(
                "New invite link for {} (previous link is invalid).",
                created.invite.email
            );
            let extra = invite_link_flash_html(&url, &note);
            page_admin(cfg, user, None, Some(&extra))
        }
        Ok(None) => page_admin(cfg, user, Some("error: invite not found"), None),
        Err(e) => page_admin(cfg, user, Some(&format!("error: {}", e)), None),
    }
}

// ---------------------------------------------------------------------------
// Invite redemption (public)
// ---------------------------------------------------------------------------

fn page_invite_invalid() -> Response {
    page_invite_notice(
        "Invite unavailable",
        "This invite link is invalid or has expired — ask your admin for a new one.",
        404,
        "Not Found",
    )
}

fn page_invite_notice(title: &str, message: &str, status: u16, reason: &'static str) -> Response {
    let body = format!(
        "<div class=\"login-wrap\"><div class=\"pix-panel login-card\" style=\"max-width:26rem\">\
         <div class=\"login-brand\">{}<span>DESERTEMAIL</span></div>\
         <h1>{}</h1>\
         <p>{}</p>\
         <p class=\"muted\" style=\"text-align:center\"><a href=\"/login\">Back to login</a></p>\
         </div></div>",
        CACTUS_SVG,
        esc(title),
        esc(message)
    );
    Response::html(status, reason, page_shell("Invite", "", &body))
}

fn page_invite(cfg: &Config, req: &Request, error: Option<&str>, status: u16) -> Response {
    let token = req
        .query
        .get("token")
        .map(|s| s.as_str())
        .unwrap_or("");
    // POST re-renders with token from form; GET from query.
    let token = if token.is_empty() {
        form_body(req)
            .get("token")
            .map(|s| s.as_str().to_string())
            .unwrap_or_default()
    } else {
        token.to_string()
    };
    if token.is_empty() {
        return page_invite_invalid();
    }
    let inv = match invites::lookup(&cfg.data_dir, &token) {
        Ok(Some(i)) => i,
        Ok(None) | Err(_) => return page_invite_invalid(),
    };
    let err = error
        .map(|e| format!("<p class=\"err\">{}</p>", esc(e)))
        .unwrap_or_default();
    let reason = if status == 429 {
        "Too Many Requests"
    } else {
        "OK"
    };
    let body = format!(
        "<div class=\"login-wrap\"><div class=\"pix-panel login-card\" style=\"max-width:26rem\">\
         <div class=\"login-brand\">{}<span>DESERTEMAIL</span></div>\
         <h1>You've been invited</h1>\
         <p class=\"muted\" style=\"text-align:center;margin-top:-.35rem\">\
         Create your password for <strong>{}</strong></p>\
         {}\
         <form method=\"post\" action=\"/invite\" autocomplete=\"on\">\
         <input type=\"hidden\" name=\"token\" value=\"{}\">\
         <label>Password <span class=\"muted\">(at least 8 characters)</span></label>\
         <input type=\"password\" name=\"password\" id=\"invite-pass\" required minlength=\"8\" autocomplete=\"new-password\">\
         <label>Confirm password</label>\
         <input type=\"password\" name=\"password2\" id=\"invite-pass2\" required minlength=\"8\" autocomplete=\"new-password\">\
         <p class=\"muted\" style=\"margin:.35rem 0 0\">\
         <label style=\"display:inline;font-weight:500;text-transform:none;letter-spacing:0\">\
         <input type=\"checkbox\" id=\"invite-show\" style=\"width:auto;display:inline;margin-right:.35rem\" \
         onchange=\"var p=document.getElementById('invite-pass'),q=document.getElementById('invite-pass2');\
         var t=this.checked?'text':'password';p.type=t;q.type=t;\">Show passwords</label></p>\
         <p><button type=\"submit\">Create account</button></p></form></div></div>",
        CACTUS_SVG,
        esc(&inv.email),
        err,
        esc(&token)
    );
    Response::html(status, reason, page_shell("Invite", "", &body))
}

fn handle_invite_redeem(
    cfg: &Config,
    req: &Request,
    secure: bool,
    peer_ip: &str,
) -> Response {
    if !ratelimit::check_allowed(peer_ip) {
        return page_invite(cfg, req, Some("Too many attempts, try later"), 429);
    }
    if !same_origin_ok(req) {
        return page_invite(cfg, req, Some("Cross-origin request blocked"), 200);
    }
    let form = form_body(req);
    let token = form.get("token").map(|s| s.as_str()).unwrap_or("");
    let password = form.get("password").map(|s| s.as_str()).unwrap_or("");
    let password2 = form.get("password2").map(|s| s.as_str()).unwrap_or("");

    if token.is_empty() {
        return page_invite_invalid();
    }
    // Validate invite first (friendly error without consuming).
    let inv = match invites::lookup(&cfg.data_dir, token) {
        Ok(Some(i)) => i,
        Ok(None) | Err(_) => {
            ratelimit::record_failure(peer_ip);
            return page_invite_invalid();
        }
    };
    if password.len() < 8 {
        return page_invite(
            cfg,
            req,
            Some("Password must be at least 8 characters"),
            200,
        );
    }
    if password != password2 {
        return page_invite(cfg, req, Some("Passwords do not match"), 200);
    }
    if user_already_exists(cfg, &inv.email) {
        // Consume invite so the token cannot be reused.
        let _ = invites::redeem(&cfg.data_dir, token);
        return page_invite_notice(
            "Account exists",
            "This account already exists — ask your admin, or try logging in.",
            200,
            "OK",
        );
    }

    // Add user first, then delete invite (task order). Re-POST fails on user exists.
    let email_owned = inv.email.clone();
    let pass_owned = password.to_string();
    match persist_and_reload(cfg, |c| {
        // Refuse overwrite if someone raced us into [users].
        if useredit::list_users(c)
            .iter()
            .any(|u| u.eq_ignore_ascii_case(&email_owned))
        {
            return Err("user already exists".into());
        }
        useredit::add_user(c, &email_owned, &pass_owned)
    }) {
        Ok(()) => {
            let _ = invites::redeem(&cfg.data_dir, token);
            ratelimit::record_success(peer_ip);
            let user = email_owned.to_lowercase();
            let session = make_session_token(&user);
            set_session(&session, &user);
            util::log_event!(
                "info",
                "invite redeemed",
                "event" => "invite_redeem",
                "user" => user.as_str()
            );
            Response::redirect("/").with_cookie(&session_cookie(&session, secure))
        }
        Err(e) => {
            if e.contains("already exists") {
                let _ = invites::redeem(&cfg.data_dir, token);
            }
            ratelimit::record_failure(peer_ip);
            page_invite(cfg, req, Some(&e), 200)
        }
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

    #[test]
    fn csrf_token_stable_per_session_and_rejects_wrong() {
        let sess_a = "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa";
        let sess_b = "bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb";
        let t1 = csrf_token_for(sess_a);
        let t2 = csrf_token_for(sess_a);
        assert_eq!(t1, t2, "same session must derive the same CSRF token");
        assert_ne!(t1, csrf_token_for(sess_b), "different sessions must differ");
        assert_eq!(t1.len(), 64);
        assert!(t1.chars().all(|c| c.is_ascii_hexdigit()));
        // Constant-time helper rejects wrong token
        assert!(!passwd::ct_eq_str(&t1, &csrf_token_for(sess_b)));
        assert!(passwd::ct_eq_str(&t1, &csrf_token_for(sess_a)));
        // csrf_field embeds the token
        let field = csrf_field(sess_a);
        assert!(field.contains("name=\"csrf\""));
        assert!(field.contains(&t1));
        // inject into forms
        let html = r#"<form method="post" action="/send"><input name="to"></form>
<form method="get" action="/search"><input name="q"></form>"#;
        let out = inject_csrf_into_forms(html, sess_a);
        assert_eq!(out.matches("name=\"csrf\"").count(), 1);
        assert!(out.contains(&t1));
        // GET form must not get a token
        assert!(out.contains("method=\"get\""));
        let get_part = out.split("method=\"get\"").nth(1).unwrap();
        assert!(!get_part.contains("name=\"csrf\""));
    }

    #[test]
    fn tls_ux_decision_matrix() {
        // peer_loopback × connection_secure × tls_listener_active × trust_proxy × xfp
        // Loopback plaintext: no banner, no redirect
        assert_eq!(
            tls_ux_decision(true, false, false, false, Option::<&str>::None),
            TlsUxAction::None
        );
        assert_eq!(
            tls_ux_decision(true, false, true, false, Option::<&str>::None),
            TlsUxAction::None
        );
        // Non-loopback plaintext, no TLS listener: warn
        assert_eq!(
            tls_ux_decision(false, false, false, false, Option::<&str>::None),
            TlsUxAction::WarnCleartext
        );
        // Non-loopback plaintext, TLS listener active: redirect
        assert_eq!(
            tls_ux_decision(false, false, true, false, Option::<&str>::None),
            TlsUxAction::RedirectHttps
        );
        // Direct TLS: no warn/redirect
        assert_eq!(
            tls_ux_decision(false, true, true, false, Option::<&str>::None),
            TlsUxAction::None
        );
        // Proxy headers ignored by default (even if X-Forwarded-Proto: https)
        assert_eq!(
            tls_ux_decision(false, false, false, false, Some("https")),
            TlsUxAction::WarnCleartext
        );
        // trust_proxy_headers + X-Forwarded-Proto: https → treat as secure
        assert_eq!(
            tls_ux_decision(false, false, false, true, Some("https")),
            TlsUxAction::None
        );
        assert_eq!(
            tls_ux_decision(false, false, true, true, Some("https")),
            TlsUxAction::None
        );
        // trust_proxy but http forwarded still cleartext
        assert_eq!(
            tls_ux_decision(false, false, false, true, Some("http")),
            TlsUxAction::WarnCleartext
        );
        // HSTS only when connection is actually TLS
        assert!(should_add_hsts(true));
        assert!(!should_add_hsts(false));
        assert!(connection_is_https(true, false, Option::<&str>::None));
        assert!(!connection_is_https(false, false, Some("https")));
        assert!(connection_is_https(false, true, Some("https")));
        assert!(connection_is_https(false, true, Some("HTTPS, http")));
    }

    #[test]
    fn dns_records_for_sample_config() {
        let recs = build_dns_records(
            "example.test",
            "mail.example.test",
            Some("203.0.113.10"),
            "mail",
            Some("v=DKIM1; k=rsa; p=ABCDEF"),
        );
        assert_eq!(recs.len(), 5);
        assert_eq!(recs[0].rtype, "MX");
        assert_eq!(recs[0].name, "example.test.");
        assert_eq!(recs[0].value, "10 mail.example.test.");
        assert_eq!(recs[1].rtype, "A");
        assert_eq!(recs[1].name, "mail.example.test.");
        assert_eq!(recs[1].value, "203.0.113.10");
        assert_eq!(recs[2].kind, "spf");
        assert_eq!(recs[2].value, "v=spf1 mx ~all");
        assert_eq!(recs[3].kind, "dkim");
        assert_eq!(recs[3].name, "mail._domainkey.example.test.");
        assert_eq!(recs[3].value, "v=DKIM1; k=rsa; p=ABCDEF");
        assert_eq!(recs[4].kind, "dmarc");
        assert_eq!(recs[4].name, "_dmarc.example.test.");
        assert_eq!(
            recs[4].value,
            "v=DMARC1; p=none; rua=mailto:admin@example.test"
        );
    }

    #[test]
    fn dns_records_without_ip_or_dkim() {
        let recs = build_dns_records("example.com", "example.com", None, "mail", None);
        assert_eq!(recs[1].value, "YOUR_PUBLIC_IP");
        assert!(recs[3].value.contains("generate"));
    }

    #[test]
    fn snippet_extraction_collapses_ws() {
        let body = "Hello\n\n  world   from\tthe desert";
        let s = snippet_from_body(body, 80);
        assert_eq!(s, "Hello world from the desert");
        let long = "a".repeat(100);
        let s2 = snippet_from_body(&long, 10);
        assert!(s2.ends_with('…'));
        assert!(s2.chars().count() <= 10);
    }

    #[test]
    fn relative_date_formats() {
        // 2024-07-03 09:41:00 UTC
        let noonish = days_from_civil(2024, 7, 3).unwrap() as u64 * 86400 + 9 * 3600 + 41 * 60;
        let same_day = format_relative_date(
            "Wed, 03 Jul 2024 09:41:00 +0000",
            noonish + 3600,
        );
        assert_eq!(same_day, "09:41");
        let later = days_from_civil(2024, 12, 1).unwrap() as u64 * 86400;
        let same_year = format_relative_date("Wed, 03 Jul 2024 09:41:00 +0000", later);
        assert_eq!(same_year, "Jul 3");
        let next_year = days_from_civil(2025, 1, 1).unwrap() as u64 * 86400;
        let old = format_relative_date("Mon, 01 Dec 2024 12:00:00 +0000", next_year);
        assert_eq!(old, "2024-12-01");
    }

    #[test]
    fn mime_multipart_plain_and_attachment() {
        let raw = b"From: a@b\r\n\
To: c@d\r\n\
Subject: hi\r\n\
MIME-Version: 1.0\r\n\
Content-Type: multipart/mixed; boundary=\"BOUND\"\r\n\
\r\n\
--BOUND\r\n\
Content-Type: text/plain; charset=utf-8\r\n\
\r\n\
Hello body\r\n\
--BOUND\r\n\
Content-Type: application/octet-stream; name=\"note.txt\"\r\n\
Content-Transfer-Encoding: base64\r\n\
Content-Disposition: attachment; filename=\"note.txt\"\r\n\
\r\n\
SGVsbG8=\r\n\
--BOUND--\r\n";
        let parsed = parse_mime_message(raw);
        assert!(parsed.text.contains("Hello body"));
        assert_eq!(parsed.attachments.len(), 1);
        assert_eq!(parsed.attachments[0].filename, "note.txt");
        assert_eq!(parsed.attachments[0].data, b"Hello");
    }

    #[test]
    fn mime_html_fallback_stripped() {
        let raw = b"From: a@b\r\n\
Subject: x\r\n\
Content-Type: text/html; charset=utf-8\r\n\
\r\n\
<html><body><p>Hi <b>there</b></p><script>alert(1)</script></body></html>\r\n";
        let parsed = parse_mime_message(raw);
        assert!(parsed.was_html);
        assert!(parsed.text.contains("Hi"));
        assert!(parsed.text.contains("there"));
        assert!(!parsed.text.contains("<script"));
        assert!(!parsed.text.contains("alert"));
    }

    #[test]
    fn qp_and_b64_decode() {
        let qp = decode_quoted_printable(b"Hello=20World=\r\n!");
        assert_eq!(qp, b"Hello World!");
        let b64 = decode_transfer(b"SGVsbG8=", "base64");
        assert_eq!(b64, b"Hello");
    }

    #[test]
    fn mime_deeply_nested_multipart_does_not_recurse_unbounded() {
        // Build a message nested far deeper than MAX_MIME_DEPTH. With
        // panic=abort in release, unbounded recursion here would abort the
        // whole server; the walker must return without overflowing the stack.
        let depth = MAX_MIME_DEPTH + 200;
        let mut msg = String::from("From: a@b\r\nSubject: nested\r\n");
        for i in 0..depth {
            msg.push_str(&format!(
                "Content-Type: multipart/mixed; boundary=\"B{}\"\r\n\r\n--B{}\r\n",
                i, i
            ));
        }
        msg.push_str("Content-Type: text/plain\r\n\r\ndeep body\r\n");
        for i in (0..depth).rev() {
            msg.push_str(&format!("\r\n--B{}--\r\n", i));
        }
        // Must complete (no stack overflow / abort) and not panic.
        let parsed = parse_mime_message(msg.as_bytes());
        let _ = parsed.text;
    }

    #[test]
    fn mime_multipart_part_count_is_capped() {
        // A body split into far more parts than MAX_MIME_PARTS must terminate
        // and not accumulate unbounded work.
        let mut msg = String::from(
            "From: a@b\r\nSubject: many\r\nContent-Type: multipart/mixed; boundary=\"B\"\r\n\r\n",
        );
        for _ in 0..(MAX_MIME_PARTS + 500) {
            msg.push_str("--B\r\nContent-Type: text/plain\r\n\r\nx\r\n");
        }
        msg.push_str("--B--\r\n");
        let parsed = parse_mime_message(msg.as_bytes());
        let _ = parsed.text;
    }
}
