//! Minimal SMTP server from scratch (RFC 5321 subset).
//! Handles inbound delivery + authenticated submission.
//! Optional STARTTLS (RFC 3207) and implicit SMTPS when TLS is configured.

use std::io::{self, BufReader, Write};
use std::net::TcpListener;
use std::sync::Arc;
use std::thread;

use rustls::ServerConfig;

use crate::auth;
use crate::config::Config;
use crate::limits;
use crate::queue;
use crate::ratelimit;
use crate::storage::Maildir;
use crate::tls::{self, Conn};
use crate::util::{self, read_line, write_line};

#[derive(Debug, Clone, PartialEq)]
enum State {
    Init,
    Greeted,
    MailFrom { from: String },
    RcptTo { from: String, rcpts: Vec<String> },
    Data { from: String, rcpts: Vec<String> },
    Quit,
}

pub struct SmtpServer {
    cfg: Arc<Config>,
    is_submission: bool,
    tls_cfg: Option<Arc<ServerConfig>>,
    /// True for smtps_listen: TLS handshake before banner, submission semantics.
    implicit_tls: bool,
}

impl SmtpServer {
    pub fn new(
        cfg: Arc<Config>,
        is_submission: bool,
        tls_cfg: Option<Arc<ServerConfig>>,
        implicit_tls: bool,
    ) -> Self {
        Self {
            cfg,
            is_submission,
            tls_cfg,
            implicit_tls,
        }
    }

    pub fn serve(&self, listener: TcpListener) {
        util::log!(
            "SMTP{}{} listening on {}",
            if self.is_submission { " submission" } else { "" },
            if self.implicit_tls { " (TLS)" } else { "" },
            listener
                .local_addr()
                .map(|a| a.to_string())
                .unwrap_or_else(|_| "?".into())
        );
        for stream in listener.incoming() {
            match stream {
                Ok(stream) => {
                    let ip = limits::peer_ip_from_stream(&stream);
                    let guard = match limits::try_acquire(&ip) {
                        Some(g) => g,
                        None => {
                            limits::apply_timeouts(&stream);
                            let mut s = stream;
                            let _ = s.write_all(b"421 Too many connections\r\n");
                            let _ = s.flush();
                            continue;
                        }
                    };
                    limits::apply_timeouts(&stream);
                    let cfg = Arc::clone(&self.cfg);
                    let is_sub = self.is_submission;
                    let tls_cfg = self.tls_cfg.clone();
                    let implicit = self.implicit_tls;
                    thread::spawn(move || {
                        let _guard = guard;
                        if let Err(e) = handle_client(stream, cfg, is_sub, tls_cfg, implicit) {
                            util::log!("SMTP client error: {}", e);
                        }
                    });
                }
                Err(e) => util::log!("SMTP accept error: {}", e),
            }
        }
    }
}

fn handle_client(
    stream: std::net::TcpStream,
    cfg: Arc<Config>,
    is_submission: bool,
    tls_cfg: Option<Arc<ServerConfig>>,
    implicit_tls: bool,
) -> io::Result<()> {
    // Timeouts already applied on accept; re-apply for safety after TLS upgrade paths.
    limits::apply_timeouts(&stream);

    let conn = if implicit_tls {
        let tc = tls_cfg.as_ref().ok_or_else(|| {
            io::Error::new(io::ErrorKind::Other, "implicit TLS without config")
        })?;
        let c = tls::accept_tls(stream, tc)?;
        c.set_timeouts(std::time::Duration::from_secs(limits::io_timeout_secs()));
        c
    } else {
        let c = Conn::Plain(stream);
        c.set_timeouts(std::time::Duration::from_secs(limits::io_timeout_secs()));
        c
    };

    let peer = conn.peer_addr_string();
    let peer_ip = limits::ip_key(&peer);
    util::log!(
        "SMTP connect from {}{}",
        peer,
        if conn.is_tls() { " (TLS)" } else { "" }
    );

    let mut reader = BufReader::new(conn);
    let mut is_tls = reader.get_ref().is_tls();

    write_line(reader.get_mut(), "220 desertemail ESMTP ready")?;

    let mut state = State::Init;
    let mut authenticated_user: Option<String> = None;
    let mut data_buf = Vec::new();
    let starttls_available = tls_cfg.is_some();

    loop {
        let line = match read_line(&mut reader)? {
            Some(l) => l,
            None => break,
        };
        util::log!("SMTP << {}", line);

        let parts: Vec<&str> = line.split_whitespace().collect();
        let cmd = parts.first().map(|s| s.to_uppercase()).unwrap_or_default();

        match (cmd.as_str(), &state) {
            ("EHLO" | "HELO", State::Init | State::Greeted) => {
                let domain = parts.get(1).copied().unwrap_or("localhost");
                write_line(
                    reader.get_mut(),
                    &format!("250-desertemail Hello {}", domain),
                )?;
                if starttls_available && !is_tls {
                    write_line(reader.get_mut(), "250-STARTTLS")?;
                }
                write_line(reader.get_mut(), "250-AUTH PLAIN LOGIN")?;
                write_line(reader.get_mut(), "250-SIZE 10485760")?;
                write_line(reader.get_mut(), "250-8BITMIME")?;
                write_line(reader.get_mut(), "250 OK")?;
                state = State::Greeted;
            }
            ("STARTTLS", _) if starttls_available && !is_tls => {
                write_line(reader.get_mut(), "220 Ready to start TLS")?;
                let plain = match reader.into_inner() {
                    Conn::Plain(s) => s,
                    Conn::Tls(_) => {
                        return Err(io::Error::new(
                            io::ErrorKind::Other,
                            "STARTTLS on already-TLS conn",
                        ));
                    }
                };
                let tc = match tls_cfg.as_ref() {
                    Some(t) => t,
                    None => {
                        return Err(io::Error::new(
                            io::ErrorKind::Other,
                            "STARTTLS without TLS config",
                        ));
                    }
                };
                let upgraded = tls::upgrade(plain, tc)?;
                upgraded.set_timeouts(std::time::Duration::from_secs(limits::io_timeout_secs()));
                reader = BufReader::new(upgraded);
                is_tls = true;
                state = State::Init;
                authenticated_user = None;
                data_buf.clear();
                util::log!("SMTP STARTTLS completed for {}", peer);
            }
            ("AUTH", _) if authenticated_user.is_none() => {
                if !ratelimit::check_allowed(&peer_ip) {
                    write_line(
                        reader.get_mut(),
                        "421 Too many failed attempts, try later",
                    )?;
                    break;
                }
                if cfg.require_tls_for_auth && !is_tls {
                    write_line(
                        reader.get_mut(),
                        "538 Encryption required for requested authentication mechanism",
                    )?;
                    continue;
                }
                if parts.len() >= 3 && parts.get(1).map(|s| s.eq_ignore_ascii_case("PLAIN")).unwrap_or(false) {
                    let b64 = parts.get(2).copied().unwrap_or("");
                    if let Some((user, pass)) = auth::decode_plain(b64) {
                        if auth::authenticate(&cfg, &user, &pass) {
                            ratelimit::record_success(&peer_ip);
                            authenticated_user = Some(user);
                            write_line(reader.get_mut(), "235 Authentication successful")?;
                        } else {
                            ratelimit::record_failure(&peer_ip);
                            write_line(reader.get_mut(), "535 Authentication failed")?;
                        }
                    } else {
                        write_line(reader.get_mut(), "501 Bad AUTH")?;
                    }
                } else if parts.len() == 2
                    && parts.get(1).map(|s| s.eq_ignore_ascii_case("PLAIN")).unwrap_or(false)
                {
                    write_line(reader.get_mut(), "334 ")?;
                    if let Some(b64) = read_line(&mut reader)? {
                        if let Some((user, pass)) = auth::decode_plain(&b64) {
                            if auth::authenticate(&cfg, &user, &pass) {
                                ratelimit::record_success(&peer_ip);
                                authenticated_user = Some(user);
                                write_line(reader.get_mut(), "235 Authentication successful")?;
                            } else {
                                ratelimit::record_failure(&peer_ip);
                                write_line(reader.get_mut(), "535 Authentication failed")?;
                            }
                        } else {
                            write_line(reader.get_mut(), "501 Bad AUTH")?;
                        }
                    }
                } else {
                    write_line(reader.get_mut(), "504 AUTH mechanism not available")?;
                }
            }
            ("MAIL", State::Greeted | State::MailFrom { .. } | State::RcptTo { .. }) => {
                if is_submission && authenticated_user.is_none() {
                    write_line(reader.get_mut(), "530 Authentication required")?;
                    continue;
                }
                let from = extract_angle(&line);
                if from.is_empty() {
                    write_line(reader.get_mut(), "501 Bad address")?;
                    continue;
                }
                state = State::MailFrom { from };
                write_line(reader.get_mut(), "250 OK")?;
            }
            ("RCPT", State::MailFrom { from: _ } | State::RcptTo { from: _, .. }) => {
                let rcpt = extract_angle(&line);
                if rcpt.is_empty() {
                    write_line(reader.get_mut(), "501 Bad address")?;
                    continue;
                }
                // Inbound (port 25 / non-submission): never open-relay.
                // Explicit domain check + mailbox resolution.
                let allowed = if is_submission {
                    true
                } else {
                    let (_local, domain) = util::parse_email_addr(&rcpt);
                    cfg.is_our_domain(&domain) && cfg.resolve_mailbox(&rcpt).is_some()
                };
                if !allowed {
                    write_line(reader.get_mut(), "550 No such user here")?;
                    continue;
                }
                // Outbound throttle on submission: count each accepted RCPT.
                if is_submission {
                    if let Some(ref user) = authenticated_user {
                        if !ratelimit::check_outbound(user, 1) {
                            write_line(
                                reader.get_mut(),
                                "452 Too many recipients; try later",
                            )?;
                            continue;
                        }
                        ratelimit::record_outbound(user, 1);
                    }
                }
                match state {
                    State::MailFrom { from: ref f } => {
                        state = State::RcptTo {
                            from: f.clone(),
                            rcpts: vec![rcpt],
                        };
                    }
                    State::RcptTo {
                        from: ref f,
                        ref mut rcpts,
                    } => {
                        rcpts.push(rcpt);
                        state = State::RcptTo {
                            from: f.clone(),
                            rcpts: rcpts.clone(),
                        };
                    }
                    _ => {
                        write_line(reader.get_mut(), "503 Bad sequence")?;
                        continue;
                    }
                }
                write_line(reader.get_mut(), "250 OK")?;
            }
            ("DATA", State::RcptTo { from, rcpts }) => {
                write_line(reader.get_mut(), "354 End data with <CR><LF>.<CR><LF>")?;
                state = State::Data {
                    from: from.clone(),
                    rcpts: rcpts.clone(),
                };
                data_buf.clear();
                loop {
                    let dline = match read_line(&mut reader)? {
                        Some(l) => l,
                        None => break,
                    };
                    if dline == "." {
                        break;
                    }
                    let content = if dline.starts_with('.') {
                        dline.get(1..).unwrap_or("")
                    } else {
                        dline.as_str()
                    };
                    data_buf.extend_from_slice(content.as_bytes());
                    data_buf.extend_from_slice(b"\r\n");
                }

                // Mail-loop guard: too many Received: headers.
                let hops = count_received_headers(&data_buf);
                if hops > cfg.max_received_hops {
                    util::log!(
                        "rejecting message: {} Received headers > max {}",
                        hops,
                        cfg.max_received_hops
                    );
                    write_line(
                        reader.get_mut(),
                        "554 Too many Received headers (mail loop)",
                    )?;
                    state = State::Greeted;
                    continue;
                }

                let delivered =
                    deliver_mail(&cfg, &state, &data_buf, is_submission, &authenticated_user);
                match delivered {
                    Ok(n) => {
                        write_line(reader.get_mut(), &format!("250 OK: queued as {} msgs", n))?;
                    }
                    Err(e) => {
                        util::log!("delivery error: {}", e);
                        write_line(reader.get_mut(), "451 Temporary failure")?;
                    }
                }
                state = State::Greeted;
            }
            ("RSET", _) => {
                state = State::Greeted;
                write_line(reader.get_mut(), "250 OK")?;
            }
            ("NOOP", _) | ("HELP", _) => {
                write_line(reader.get_mut(), "250 OK")?;
            }
            ("QUIT", _) => {
                write_line(reader.get_mut(), "221 Bye")?;
                break;
            }
            ("VRFY", _) | ("EXPN", _) => {
                write_line(reader.get_mut(), "252 Cannot VRFY")?;
            }
            _ => {
                write_line(reader.get_mut(), "500 Syntax error or bad sequence")?;
            }
        }
        if state == State::Quit {
            break;
        }
    }
    util::log!("SMTP disconnect {}", peer);
    Ok(())
}

/// Count `Received:` header fields in a raw message (case-insensitive).
/// Operates on bytes so multi-byte UTF-8 never panics on slicing.
pub fn count_received_headers(raw: &[u8]) -> usize {
    // Only scan the header section (before blank line).
    let header_end = raw
        .windows(4)
        .position(|w| w == b"\r\n\r\n")
        .map(|p| p)
        .or_else(|| raw.windows(2).position(|w| w == b"\n\n"))
        .unwrap_or(raw.len());
    let headers = raw.get(..header_end).unwrap_or(&[]);
    let mut count = 0usize;
    for line in headers.split(|&b| b == b'\n') {
        let line = if line.last() == Some(&b'\r') {
            line.get(..line.len().saturating_sub(1)).unwrap_or(&[])
        } else {
            line
        };
        // trim leading WSP
        let mut i = 0usize;
        while i < line.len() && (line[i] == b' ' || line[i] == b'\t') {
            i += 1;
        }
        let t = line.get(i..).unwrap_or(&[]);
        if t.len() >= 9 && t.get(..9).unwrap_or(&[]).eq_ignore_ascii_case(b"received:") {
            count += 1;
        }
    }
    count
}

/// Extract address from MAIL FROM:/RCPT TO: angle-bracket form (fuzz-visible).
pub fn extract_angle(line: &str) -> String {
    if let Some(start) = line.find('<') {
        if let Some(rel_end) = line.get(start..).and_then(|s| s.find('>')) {
            let end = start + rel_end;
            if let Some(inner) = line.get(start + 1..end) {
                return inner.trim().to_string();
            }
        }
    }
    if let Some(idx) = line.find(':') {
        if let Some(rest) = line.get(idx + 1..) {
            return rest
                .trim()
                .trim_matches(|c| c == '<' || c == '>')
                .to_string();
        }
    }
    String::new()
}

fn deliver_mail(
    cfg: &Config,
    state: &State,
    raw: &[u8],
    is_submission: bool,
    auth_user: &Option<String>,
) -> Result<usize, String> {
    let (from, rcpts) = match state {
        State::Data { from, rcpts } => (from.as_str(), rcpts.as_slice()),
        _ => return Err("bad state".into()),
    };

    let mut count = 0;
    if is_submission {
        if let Some(user) = auth_user {
            if let Some(mb) = cfg.resolve_mailbox(user) {
                let md = Maildir::open(&cfg.data_dir, &format!("{}/.Sent", mb))
                    .map_err(|e| e.to_string())?;
                md.deliver(raw, from).map_err(|e| e.to_string())?;
                count += 1;
            }
        }

        let mut remote: Vec<String> = Vec::new();
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
                "submission from {} to {:?}: enqueued as {} ({} remote)",
                from,
                remote,
                id,
                remote.len()
            );
            count += remote.len();
        }
    } else {
        for r in rcpts {
            if let Some(mb) = cfg.resolve_mailbox(r) {
                let md = Maildir::open(&cfg.data_dir, &mb).map_err(|e| e.to_string())?;
                md.deliver(raw, from).map_err(|e| e.to_string())?;
                count += 1;
            }
        }
    }
    if count == 0 {
        return Err("no recipients accepted".into());
    }
    Ok(count)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::config::Config;

    #[test]
    fn count_received_basic() {
        let msg = b"Received: from a\r\nReceived: from b\r\nFrom: x\r\n\r\nbody\r\n";
        assert_eq!(count_received_headers(msg), 2);
    }

    #[test]
    fn count_received_ignores_body() {
        let msg = b"From: x\r\n\r\nReceived: fake\r\n";
        assert_eq!(count_received_headers(msg), 0);
    }

    #[test]
    fn foreign_domain_rejected_by_is_our_domain() {
        let mut cfg = Config::default();
        cfg.domains = vec!["example.com".into()];
        cfg.catch_all = true;
        let rcpt = "victim@evil.com";
        let (_l, domain) = util::parse_email_addr(rcpt);
        assert!(!cfg.is_our_domain(&domain));
        assert!(cfg.resolve_mailbox(rcpt).is_none());
    }

    #[test]
    fn local_domain_accepted() {
        let mut cfg = Config::default();
        cfg.domains = vec!["example.com".into()];
        cfg.catch_all = true;
        assert!(cfg.is_our_domain("example.com"));
        assert!(cfg.resolve_mailbox("user@example.com").is_some());
    }

    #[test]
    fn hop_limit_exceeded() {
        let mut headers = String::new();
        for i in 0..31 {
            headers.push_str(&format!("Received: hop {}\r\n", i));
        }
        headers.push_str("\r\nbody\r\n");
        assert!(count_received_headers(headers.as_bytes()) > 30);
    }

    #[test]
    fn received_count_utf8_no_panic() {
        // Multi-byte chars near the 9-byte boundary must not panic.
        let msg = "Subject: caféééé\r\nFrom: x\r\n\r\nbody\r\n";
        assert_eq!(count_received_headers(msg.as_bytes()), 0);
        let msg2 = "ééééééééé\r\nReceived: from a\r\n\r\nbody\r\n";
        assert_eq!(count_received_headers(msg2.as_bytes()), 1);
        // Invalid UTF-8 also safe (lossy not needed; we scan bytes).
        let bad = b"\xff\xfe\xfd\xfc\xfb\xfa\xf9\xf8\xf7\r\n\r\n";
        assert_eq!(count_received_headers(bad), 0);
    }
}
