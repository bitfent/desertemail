//! Persistent outbound mail queue + delivery worker.
//! Disk: `{data_dir}/queue/` — one file per message.
//! Pure std, plain threads, exponential backoff, bounce after 24h.

use std::fs::{self, File, OpenOptions};
use std::io::{self, Read, Write};
use std::net::{SocketAddr, TcpStream, ToSocketAddrs};
use std::path::{Path, PathBuf};
use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::Arc;
use std::thread;
use std::time::Duration;

use crate::config::Config;
use crate::dkim;
use crate::dns;
use crate::storage::Maildir;
use crate::tls::{self, ClientConn};
use crate::util::{self, base64_encode, read_line, write_line, write_raw};

const SCAN_INTERVAL: Duration = Duration::from_secs(30);
const IO_TIMEOUT: Duration = Duration::from_secs(30);
const MAX_AGE_SECS: u64 = 24 * 3600;

/// Backoff delays (seconds) by retry_count index.
const BACKOFF_SECS: &[u64] = &[
    60,      // 1 min
    5 * 60,  // 5 min
    15 * 60, // 15 min
    60 * 60, // 1 h
    4 * 3600, // 4 h
];

static QUEUE_COUNTER: AtomicU64 = AtomicU64::new(0);

#[derive(Debug, Clone)]
pub struct QueueMessage {
    pub id: String,
    pub sender: String,
    pub recipients: Vec<String>,
    pub retry_count: u32,
    pub next_attempt: u64,
    pub created: u64,
    pub raw: Vec<u8>,
}

/// Enqueue a message for outbound delivery. Returns queue id.
pub fn enqueue(
    data_dir: &str,
    sender: &str,
    recipients: &[String],
    raw: &[u8],
) -> io::Result<String> {
    let dir = queue_dir(data_dir);
    fs::create_dir_all(&dir)?;

    let id = format!(
        "{}.{}{}",
        util::now_secs(),
        QUEUE_COUNTER.fetch_add(1, Ordering::SeqCst),
        std::process::id()
    );
    let path = dir.join(format!("{}.msg", id));
    let now = util::now_secs();

    let mut f = OpenOptions::new()
        .write(true)
        .create_new(true)
        .open(&path)?;

    writeln!(f, "id: {}", id)?;
    writeln!(f, "sender: {}", sender)?;
    writeln!(f, "recipients: {}", recipients.join(","))?;
    writeln!(f, "retry_count: 0")?;
    writeln!(f, "next_attempt: {}", now)?;
    writeln!(f, "created: {}", now)?;
    writeln!(f, "---")?;
    f.write_all(raw)?;
    f.sync_all()?;

    util::log!(
        "queue: enqueued {} for {} -> {:?}",
        id,
        sender,
        recipients
    );
    Ok(id)
}

/// List all messages currently in the outbound queue (metadata + raw body).
pub fn list_queue(data_dir: &str) -> io::Result<Vec<QueueMessage>> {
    let dir = queue_dir(data_dir);
    if !dir.exists() {
        return Ok(Vec::new());
    }
    let mut entries: Vec<PathBuf> = fs::read_dir(&dir)?
        .filter_map(|e| e.ok())
        .map(|e| e.path())
        .filter(|p| p.extension().map(|x| x == "msg").unwrap_or(false))
        .collect();
    entries.sort();
    let mut out = Vec::new();
    for path in entries {
        match load_message(&path) {
            Ok(msg) => out.push(msg),
            Err(e) => util::log!("queue: list skip {}: {}", path.display(), e),
        }
    }
    Ok(out)
}

/// Remove a queue file by id. Returns true if a file was deleted.
pub fn delete_queued(data_dir: &str, id: &str) -> io::Result<bool> {
    if id.is_empty()
        || id.contains('/')
        || id.contains('\\')
        || id.contains("..")
        || id.contains('\0')
    {
        return Ok(false);
    }
    let path = queue_dir(data_dir).join(format!("{}.msg", id));
    if path.is_file() {
        fs::remove_file(&path)?;
        util::log!("queue: deleted {} by admin", id);
        Ok(true)
    } else {
        Ok(false)
    }
}

/// Start background worker that scans the queue every 30s.
pub fn start_worker(cfg: Arc<Config>) {
    thread::spawn(move || {
        util::log!("queue worker started (scan every {}s)", SCAN_INTERVAL.as_secs());
        loop {
            if let Err(e) = process_queue(&cfg) {
                util::log!("queue worker error: {}", e);
            }
            thread::sleep(SCAN_INTERVAL);
        }
    });
}

fn queue_dir(data_dir: &str) -> PathBuf {
    Path::new(data_dir).join("queue")
}

fn process_queue(cfg: &Config) -> io::Result<()> {
    let dir = queue_dir(&cfg.data_dir);
    if !dir.exists() {
        return Ok(());
    }

    let now = util::now_secs();
    let mut entries: Vec<PathBuf> = fs::read_dir(&dir)?
        .filter_map(|e| e.ok())
        .map(|e| e.path())
        .filter(|p| p.extension().map(|x| x == "msg").unwrap_or(false))
        .collect();
    entries.sort();

    for path in entries {
        match load_message(&path) {
            Ok(msg) => {
                if msg.next_attempt > now {
                    continue;
                }
                // Age check: bounce after 24h
                if now.saturating_sub(msg.created) >= MAX_AGE_SECS {
                    util::log!("queue: {} expired after 24h, bouncing", msg.id);
                    bounce_message(cfg, &msg, "Message expired after 24 hours in queue");
                    let _ = fs::remove_file(&path);
                    continue;
                }
                match try_deliver(cfg, &msg) {
                    DeliverResult::Success => {
                        util::log!("queue: {} delivered, removing", msg.id);
                        let _ = fs::remove_file(&path);
                    }
                    DeliverResult::TempFail { reason, remaining } => {
                        util::log!("queue: {} temp fail: {}", msg.id, reason);
                        let next_retry = msg.retry_count + 1;
                        let delay = backoff_secs(msg.retry_count);
                        let next_attempt = now + delay;
                        let mut updated = msg.clone();
                        if !remaining.is_empty() {
                            updated.recipients = remaining;
                        }
                        if next_attempt.saturating_sub(msg.created) >= MAX_AGE_SECS
                            || now.saturating_sub(msg.created) >= MAX_AGE_SECS
                        {
                            bounce_message(
                                cfg,
                                &updated,
                                &format!("Delivery failed after retries: {}", reason),
                            );
                            let _ = fs::remove_file(&path);
                        } else {
                            let _ = rewrite_message(&path, &updated, next_retry, next_attempt);
                        }
                    }
                    DeliverResult::PermFail(reason) => {
                        util::log!("queue: {} perm fail: {}", msg.id, reason);
                        bounce_message(cfg, &msg, &reason);
                        let _ = fs::remove_file(&path);
                    }
                }
            }
            Err(e) => {
                util::log!("queue: skip bad file {}: {}", path.display(), e);
            }
        }
    }
    Ok(())
}

fn backoff_secs(retry_count: u32) -> u64 {
    let idx = retry_count as usize;
    if idx < BACKOFF_SECS.len() {
        BACKOFF_SECS[idx]
    } else {
        *BACKOFF_SECS.last().unwrap_or(&14400)
    }
}

fn load_message(path: &Path) -> io::Result<QueueMessage> {
    let mut content = Vec::new();
    File::open(path)?.read_to_end(&mut content)?;

    let sep = b"\n---\n";
    let sep_pos = content
        .windows(sep.len())
        .position(|w| w == sep)
        .ok_or_else(|| {
            io::Error::new(io::ErrorKind::InvalidData, "missing --- separator")
        })?;

    let header = String::from_utf8_lossy(&content[..sep_pos]);
    let body = content[sep_pos + sep.len()..].to_vec();

    let mut id = String::new();
    let mut sender = String::new();
    let mut recipients = Vec::new();
    let mut retry_count = 0u32;
    let mut next_attempt = 0u64;
    let mut created = 0u64;

    for line in header.lines() {
        let line = line.trim();
        if line.is_empty() {
            continue;
        }
        if let Some(colon) = line.find(':') {
            let key = line[..colon].trim().to_lowercase();
            let val = line[colon + 1..].trim();
            match key.as_str() {
                "id" => id = val.to_string(),
                "sender" => sender = val.to_string(),
                "recipients" => {
                    recipients = val
                        .split(',')
                        .map(|s| s.trim().to_string())
                        .filter(|s| !s.is_empty())
                        .collect();
                }
                "retry_count" => retry_count = val.parse().unwrap_or(0),
                "next_attempt" => next_attempt = val.parse().unwrap_or(0),
                "created" => created = val.parse().unwrap_or(0),
                _ => {}
            }
        }
    }

    if id.is_empty() {
        id = path
            .file_stem()
            .map(|s| s.to_string_lossy().into_owned())
            .unwrap_or_else(|| "unknown".into());
    }

    Ok(QueueMessage {
        id,
        sender,
        recipients,
        retry_count,
        next_attempt,
        created,
        raw: body,
    })
}

fn rewrite_message(
    path: &Path,
    msg: &QueueMessage,
    retry_count: u32,
    next_attempt: u64,
) -> io::Result<()> {
    let tmp = path.with_extension("tmp");
    {
        let mut f = OpenOptions::new()
            .write(true)
            .create(true)
            .truncate(true)
            .open(&tmp)?;
        writeln!(f, "id: {}", msg.id)?;
        writeln!(f, "sender: {}", msg.sender)?;
        writeln!(f, "recipients: {}", msg.recipients.join(","))?;
        writeln!(f, "retry_count: {}", retry_count)?;
        writeln!(f, "next_attempt: {}", next_attempt)?;
        writeln!(f, "created: {}", msg.created)?;
        writeln!(f, "---")?;
        f.write_all(&msg.raw)?;
        f.sync_all()?;
    }
    fs::rename(&tmp, path)?;
    Ok(())
}

enum DeliverResult {
    Success,
    TempFail { reason: String, remaining: Vec<String> },
    PermFail(String),
}

fn temp_fail(reason: String, remaining: Vec<String>) -> DeliverResult {
    DeliverResult::TempFail { reason, remaining }
}

fn try_deliver(cfg: &Config, msg: &QueueMessage) -> DeliverResult {
    if msg.recipients.is_empty() {
        return DeliverResult::PermFail("no recipients".into());
    }

    // DKIM: sign once per message (not per recipient domain) when configured
    // and the sender domain is local. Signature is applied to a local copy of
    // the raw body used for this delivery attempt.
    let raw = dkim_raw_for_send(cfg, msg);

    if let Some(ref smarthost) = cfg.smarthost {
        return deliver_via_smarthost(cfg, msg, smarthost, &raw);
    }

    // Direct MX: one SMTP session per recipient domain.
    let helo = helo_name(cfg);
    let mut remaining = Vec::new();
    let mut last_temp = String::new();
    let mut perm_failed: Vec<String> = Vec::new();
    let mut perm_reason = String::new();
    let mut any_ok = false;

    let mut by_domain: Vec<(String, Vec<String>)> = Vec::new();
    for r in &msg.recipients {
        let (_, domain) = util::parse_email_addr(r);
        if domain.is_empty() {
            perm_failed.push(r.clone());
            perm_reason = format!("invalid recipient {}", r);
            continue;
        }
        if let Some(entry) = by_domain.iter_mut().find(|(d, _)| d == &domain) {
            entry.1.push(r.clone());
        } else {
            by_domain.push((domain, vec![r.clone()]));
        }
    }

    for (domain, rcpts) in by_domain {
        match deliver_to_domain(&msg.sender, &rcpts, &raw, &domain, &helo) {
            DeliverResult::Success => any_ok = true,
            DeliverResult::TempFail { reason, .. } => {
                remaining.extend(rcpts);
                last_temp = reason;
            }
            DeliverResult::PermFail(r) => {
                perm_failed.extend(rcpts);
                perm_reason = r;
            }
        }
    }

    if !perm_failed.is_empty() {
        if remaining.is_empty() && !any_ok {
            // Whole message perm-failed; caller bounces all recipients and removes it.
            return DeliverResult::PermFail(perm_reason);
        }
        // Partial perm failure: bounce just those recipients now so they
        // aren't silently dropped when the rest is retried or delivered.
        let mut pm = msg.clone();
        pm.recipients = perm_failed;
        bounce_message(cfg, &pm, &perm_reason);
    }

    if remaining.is_empty() {
        return DeliverResult::Success;
    }

    temp_fail(
        if last_temp.is_empty() {
            "temporary failure".into()
        } else {
            last_temp
        },
        remaining,
    )
}

fn deliver_via_smarthost(
    cfg: &Config,
    msg: &QueueMessage,
    smarthost: &str,
    raw: &[u8],
) -> DeliverResult {
    let addr = match resolve_socket_addrs(smarthost) {
        Ok(a) => a,
        Err(e) => {
            return temp_fail(format!("smarthost resolve: {}", e), msg.recipients.clone())
        }
    };

    let server_name = host_from_hostport(smarthost);
    match smtp_send(
        &addr,
        &server_name,
        &helo_name(cfg),
        &msg.sender,
        &msg.recipients,
        raw,
        cfg.smarthost_user.as_deref(),
        cfg.smarthost_pass.as_deref(),
        true,
    ) {
        Ok(()) => DeliverResult::Success,
        Err(SmtpError::Temp(s)) => temp_fail(s, msg.recipients.clone()),
        Err(SmtpError::Perm(s)) => DeliverResult::PermFail(s),
        Err(SmtpError::Io(s)) => temp_fail(s, msg.recipients.clone()),
    }
}

/// Hostname portion of `host:port` (or bare host) for TLS SNI.
fn host_from_hostport(s: &str) -> String {
    // IPv6 in brackets: [::1]:25
    if let Some(rest) = s.strip_prefix('[') {
        if let Some(end) = rest.find(']') {
            return rest[..end].to_string();
        }
    }
    // host:port — split on last colon if single colon and not pure IPv6-looking
    if s.matches(':').count() == 1 {
        if let Some((h, _)) = s.rsplit_once(':') {
            return h.to_string();
        }
    }
    s.to_string()
}

/// If DKIM is configured and the sender is in a local domain, return the raw
/// message with a DKIM-Signature header prepended. Otherwise return a clone
/// of the original. Already-signed messages are left unchanged.
fn dkim_raw_for_send(cfg: &Config, msg: &QueueMessage) -> Vec<u8> {
    if has_dkim_signature(&msg.raw) {
        return msg.raw.clone();
    }
    let key = match cfg.dkim_key_clone() {
        Some(k) => k,
        None => return msg.raw.clone(),
    };
    let (_, domain) = util::parse_email_addr(&msg.sender);
    if domain.is_empty() || !cfg.is_our_domain(&domain) {
        return msg.raw.clone();
    }
    let selector = cfg.dkim_selector();
    match dkim::sign_and_prepend(&msg.raw, &domain, &selector, &key) {
        Some(signed) => {
            util::log!("queue: DKIM-signed {} (d={}, s={})", msg.id, domain, selector);
            signed
        }
        None => {
            util::log!("queue: DKIM sign failed for {}, sending unsigned", msg.id);
            msg.raw.clone()
        }
    }
}

fn has_dkim_signature(raw: &[u8]) -> bool {
    // Scan header block only (before blank line)
    let end = raw
        .windows(4)
        .position(|w| w == b"\r\n\r\n")
        .or_else(|| raw.windows(2).position(|w| w == b"\n\n"))
        .unwrap_or(raw.len());
    let hdr = &raw[..end];
    let mut i = 0;
    while i + 15 <= hdr.len() {
        if hdr[i..].len() >= 15
            && hdr[i..i + 15].eq_ignore_ascii_case(b"DKIM-Signature:")
        {
            return true;
        }
        // next line
        if let Some(rel) = hdr[i..].iter().position(|&b| b == b'\n') {
            i += rel + 1;
        } else {
            break;
        }
    }
    false
}

/// EHLO/HELO name: first configured domain, falling back to a placeholder.
fn helo_name(cfg: &Config) -> String {
    let d = cfg.primary_domain();
    if d.is_empty() {
        "desertemail.local".into()
    } else {
        d
    }
}

fn deliver_to_domain(
    sender: &str,
    recipients: &[String],
    raw: &[u8],
    domain: &str,
    helo: &str,
) -> DeliverResult {
    let hosts = match dns::smtp_hosts_for_domain(domain) {
        Ok(h) if !h.is_empty() => h,
        Ok(_) => {
            return temp_fail(
                format!("no MX/A for {}", domain),
                recipients.to_vec(),
            )
        }
        Err(e) => {
            return temp_fail(
                format!("DNS error for {}: {}", domain, e),
                recipients.to_vec(),
            )
        }
    };

    let mut last_err = temp_fail(format!("no hosts for {}", domain), recipients.to_vec());

    for host in hosts {
        let ips = match dns::resolve_a(&host) {
            Ok(v) if !v.is_empty() => v,
            Ok(_) => match format!("{}:25", host).to_socket_addrs() {
                Ok(iter) => {
                    let v: Vec<String> = iter.map(|a| a.ip().to_string()).collect();
                    if v.is_empty() {
                        last_err = temp_fail(format!("no A for {}", host), recipients.to_vec());
                        continue;
                    }
                    v
                }
                Err(e) => {
                    last_err = temp_fail(format!("resolve {}: {}", host, e), recipients.to_vec());
                    continue;
                }
            },
            Err(e) => {
                last_err = temp_fail(format!("A lookup {}: {}", host, e), recipients.to_vec());
                continue;
            }
        };

        for ip in ips {
            let target = if ip.starts_with('[') {
                format!("{}:25", ip)
            } else {
                format!("{}:25", ip)
            };
            let addrs = match target.to_socket_addrs() {
                Ok(a) => a.collect::<Vec<_>>(),
                Err(e) => {
                    last_err =
                        temp_fail(format!("bad addr {}: {}", target, e), recipients.to_vec());
                    continue;
                }
            };
            for addr in addrs {
                match smtp_send(
                    &addr,
                    &host,
                    helo,
                    sender,
                    recipients,
                    raw,
                    None,
                    None,
                    true,
                ) {
                    Ok(()) => return DeliverResult::Success,
                    Err(SmtpError::Perm(s)) => return DeliverResult::PermFail(s),
                    Err(SmtpError::Temp(s)) => {
                        last_err = temp_fail(s, recipients.to_vec());
                    }
                    Err(SmtpError::Io(s)) => {
                        last_err = temp_fail(s, recipients.to_vec());
                    }
                }
            }
        }
    }

    last_err
}

enum SmtpError {
    Temp(String),
    Perm(String),
    Io(String),
}

fn classify_code(code: u16, text: &str) -> SmtpError {
    if code >= 500 {
        SmtpError::Perm(format!("{} {}", code, text))
    } else if code >= 400 {
        SmtpError::Temp(format!("{} {}", code, text))
    } else {
        SmtpError::Io(format!("unexpected {} {}", code, text))
    }
}

/// Outbound SMTP. When `try_starttls` is true and the peer advertises STARTTLS,
/// upgrade with full cert validation (SNI = `server_name`). On handshake/cert
/// failure, log and reconnect plaintext without STARTTLS (opportunistic TLS).
fn smtp_send(
    addr: &SocketAddr,
    server_name: &str,
    helo_name: &str,
    sender: &str,
    recipients: &[String],
    raw: &[u8],
    auth_user: Option<&str>,
    auth_pass: Option<&str>,
    try_starttls: bool,
) -> Result<(), SmtpError> {
    let stream = TcpStream::connect_timeout(addr, IO_TIMEOUT)
        .map_err(|e| SmtpError::Io(format!("connect {}: {}", addr, e)))?;
    stream
        .set_read_timeout(Some(IO_TIMEOUT))
        .map_err(|e| SmtpError::Io(e.to_string()))?;
    stream
        .set_write_timeout(Some(IO_TIMEOUT))
        .map_err(|e| SmtpError::Io(e.to_string()))?;

    let mut reader = io::BufReader::new(ClientConn::Plain(stream));

    let (code, text, _) = read_smtp_reply(&mut reader)?;
    if code != 220 {
        return Err(classify_code(code, &text));
    }

    // EHLO, fall back to HELO
    write_line(reader.get_mut(), &format!("EHLO {}", helo_name))
        .map_err(|e| SmtpError::Io(e.to_string()))?;
    let (code, text, lines) = read_smtp_reply(&mut reader)?;
    let mut has_starttls = false;
    if code != 250 {
        write_line(reader.get_mut(), &format!("HELO {}", helo_name))
            .map_err(|e| SmtpError::Io(e.to_string()))?;
        let (code, text, _) = read_smtp_reply(&mut reader)?;
        if code != 250 {
            return Err(classify_code(code, &text));
        }
    } else {
        has_starttls = lines.iter().any(|l| {
            let u = l.to_uppercase();
            u.contains("STARTTLS")
        });
        let _ = text;
    }

    if try_starttls && has_starttls {
        write_line(reader.get_mut(), "STARTTLS").map_err(|e| SmtpError::Io(e.to_string()))?;
        let (code, text) = {
            let (c, t, _) = read_smtp_reply(&mut reader)?;
            (c, t)
        };
        if code == 220 {
            let plain = match reader.into_inner().into_plain() {
                Some(s) => s,
                None => {
                    return Err(SmtpError::Io("STARTTLS on non-plain conn".into()));
                }
            };
            match tls::connect_tls(plain, server_name) {
                Ok(tls_conn) => {
                    util::log!("outbound STARTTLS ok to {} ({})", server_name, addr);
                    reader = io::BufReader::new(tls_conn);
                    // Must EHLO again after STARTTLS.
                    write_line(reader.get_mut(), &format!("EHLO {}", helo_name))
                        .map_err(|e| SmtpError::Io(e.to_string()))?;
                    let (code, text, _) = read_smtp_reply(&mut reader)?;
                    if code != 250 {
                        return Err(classify_code(code, &text));
                    }
                }
                Err(e) => {
                    util::log!(
                        "outbound STARTTLS failed to {} ({}): {} — reconnecting plaintext",
                        server_name,
                        addr,
                        e
                    );
                    // Fresh TCP; never retry STARTTLS on this attempt.
                    return smtp_send(
                        addr,
                        server_name,
                        helo_name,
                        sender,
                        recipients,
                        raw,
                        auth_user,
                        auth_pass,
                        false,
                    );
                }
            }
        } else {
            util::log!(
                "outbound STARTTLS rejected by {} ({} {}): continuing plaintext",
                server_name,
                code,
                text
            );
        }
    }

    // Optional AUTH PLAIN for smarthost
    if let (Some(user), Some(pass)) = (auth_user, auth_pass) {
        let payload = format!("\0{}\0{}", user, pass);
        let b64 = base64_encode(payload.as_bytes());
        write_line(reader.get_mut(), &format!("AUTH PLAIN {}", b64))
            .map_err(|e| SmtpError::Io(e.to_string()))?;
        let (code, text, _) = read_smtp_reply(&mut reader)?;
        if code != 235 {
            return Err(classify_code(code, &text));
        }
    }

    write_line(reader.get_mut(), &format!("MAIL FROM:<{}>", sender))
        .map_err(|e| SmtpError::Io(e.to_string()))?;
    let (code, text, _) = read_smtp_reply(&mut reader)?;
    if code != 250 {
        let _ = write_line(reader.get_mut(), "QUIT");
        return Err(classify_code(code, &text));
    }

    for rcpt in recipients {
        write_line(reader.get_mut(), &format!("RCPT TO:<{}>", rcpt))
            .map_err(|e| SmtpError::Io(e.to_string()))?;
        let (code, text, _) = read_smtp_reply(&mut reader)?;
        if code != 250 && code != 251 {
            let _ = write_line(reader.get_mut(), "QUIT");
            return Err(classify_code(code, &text));
        }
    }

    write_line(reader.get_mut(), "DATA").map_err(|e| SmtpError::Io(e.to_string()))?;
    let (code, text, _) = read_smtp_reply(&mut reader)?;
    if code != 354 {
        let _ = write_line(reader.get_mut(), "QUIT");
        return Err(classify_code(code, &text));
    }

    // Dot-stuff and send body
    let body = dot_stuff(raw);
    write_raw(reader.get_mut(), &body).map_err(|e| SmtpError::Io(e.to_string()))?;
    write_line(reader.get_mut(), ".").map_err(|e| SmtpError::Io(e.to_string()))?;
    let (code, text, _) = read_smtp_reply(&mut reader)?;
    if code != 250 {
        let _ = write_line(reader.get_mut(), "QUIT");
        return Err(classify_code(code, &text));
    }

    let _ = write_line(reader.get_mut(), "QUIT");
    let _ = read_smtp_reply(&mut reader);
    Ok(())
}

fn dot_stuff(raw: &[u8]) -> Vec<u8> {
    let mut out = Vec::with_capacity(raw.len() + 64);
    let mut line_start = true;
    for &b in raw {
        if line_start && b == b'.' {
            out.push(b'.');
        }
        out.push(b);
        line_start = b == b'\n';
    }
    // Ensure ends with CRLF before the terminating dot line
    if !out.ends_with(b"\r\n") {
        if out.ends_with(b"\n") {
            // already LF
        } else {
            out.extend_from_slice(b"\r\n");
        }
    }
    out
}

/// Read a full SMTP multi-line reply. Returns (code, last-line-text, all-line-texts).
fn read_smtp_reply<R: io::BufRead>(
    reader: &mut R,
) -> Result<(u16, String, Vec<String>), SmtpError> {
    let mut lines = Vec::new();
    loop {
        let line = read_line(reader)
            .map_err(|e| SmtpError::Io(e.to_string()))?
            .ok_or_else(|| SmtpError::Io("EOF from SMTP peer".into()))?;
        if line.len() < 3 {
            return Err(SmtpError::Io(format!("short SMTP reply: {}", line)));
        }
        let code: u16 = line[..3].parse().unwrap_or(0);
        let cont = line.as_bytes().get(3) == Some(&b'-');
        let text = if line.len() > 4 {
            line[4..].to_string()
        } else {
            String::new()
        };
        lines.push(text.clone());
        if !cont {
            return Ok((code, text, lines));
        }
    }
}

fn resolve_socket_addrs(hostport: &str) -> io::Result<SocketAddr> {
    // host:port or bare host (assume 25)
    let s = if hostport.contains(':') {
        // careful with IPv6 — if multiple colons and no brackets, leave to parser
        hostport.to_string()
    } else {
        format!("{}:25", hostport)
    };
    s.to_socket_addrs()?
        .next()
        .ok_or_else(|| io::Error::new(io::ErrorKind::NotFound, "no address for smarthost"))
}

fn bounce_message(cfg: &Config, msg: &QueueMessage, reason: &str) {
    crate::metrics::inc_messages_bounced();
    let bounce_body = format!(
        "From: mailer-daemon@localhost\r\n\
         To: {}\r\n\
         Subject: Undelivered Mail Returned to Sender\r\n\
         MIME-Version: 1.0\r\n\
         Content-Type: text/plain; charset=utf-8\r\n\
         \r\n\
         This is the mail system at desertemail.\r\n\
         \r\n\
         Your message could not be delivered to: {}\r\n\
         \r\n\
         Reason: {}\r\n\
         \r\n\
         ----- Original message headers (truncated) -----\r\n\
         {}\r\n",
        msg.sender,
        msg.recipients.join(", "),
        reason,
        String::from_utf8_lossy(&msg.raw[..msg.raw.len().min(2048)])
    );

    // Deliver bounce to local sender Maildir if sender is local
    if let Some(mb) = cfg.resolve_mailbox(&msg.sender) {
        match Maildir::open(&cfg.data_dir, &mb) {
            Ok(md) => {
                if let Err(e) = md.deliver(bounce_body.as_bytes(), "mailer-daemon@localhost") {
                    util::log!("queue: bounce deliver failed: {}", e);
                } else {
                    util::log!("queue: bounce written to mailbox {}", mb);
                }
            }
            Err(e) => util::log!("queue: bounce open maildir: {}", e),
        }
    } else {
        util::log!(
            "queue: bounce for non-local sender {} (not stored): {}",
            msg.sender,
            reason
        );
    }
}
