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
use crate::dkim::{self, DkimStatus};
use crate::dmarc::{self, DmarcPolicy};
use crate::limits;
use crate::metrics;
use crate::queue;
use crate::ratelimit;
use crate::spamscore::{self, GreylistDecision, SpamScore, SpamScoreInput};
use crate::spf::{self, SpfResult};
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
        let _ = listener.set_nonblocking(true);
        loop {
            if crate::shutdown::is_shutdown() {
                util::log!("SMTP listener shutting down");
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
                Err(ref e) if e.kind() == io::ErrorKind::WouldBlock => {
                    thread::sleep(std::time::Duration::from_millis(200));
                }
                Err(e) => {
                    if crate::shutdown::is_shutdown() {
                        break;
                    }
                    util::log!("SMTP accept error: {}", e);
                    thread::sleep(std::time::Duration::from_millis(200));
                }
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
    let mut helo_domain = String::from("unknown");
    let mut data_buf = Vec::new();
    let starttls_available = tls_cfg.is_some();
    let hostname_owned = cfg.primary_domain();
    let hostname = if hostname_owned.is_empty() {
        "desertemail"
    } else {
        hostname_owned.as_str()
    };

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
                helo_domain = domain.to_string();
                write_line(
                    reader.get_mut(),
                    &format!("250-desertemail Hello {}", domain),
                )?;
                if starttls_available && !is_tls {
                    write_line(reader.get_mut(), "250-STARTTLS")?;
                }
                write_line(reader.get_mut(), "250-AUTH PLAIN LOGIN")?;
                write_line(
                    reader.get_mut(),
                    &format!("250-SIZE {}", cfg.max_message_bytes),
                )?;
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
                    util::log_event!(
                        "warn",
                        "SMTP auth lockout",
                        "event" => "auth_lockout",
                        "ip" => &peer_ip,
                        "proto" => "smtp"
                    );
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
                            metrics::inc_auth_success();
                            authenticated_user = Some(user);
                            write_line(reader.get_mut(), "235 Authentication successful")?;
                        } else {
                            ratelimit::record_failure(&peer_ip);
                            metrics::inc_auth_failure();
                            util::log_event!(
                                "warn",
                                "SMTP auth failed",
                                "event" => "auth_fail",
                                "ip" => &peer_ip,
                                "user" => &user,
                                "proto" => "smtp",
                                "result" => "fail"
                            );
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
                                metrics::inc_auth_success();
                                authenticated_user = Some(user);
                                write_line(reader.get_mut(), "235 Authentication successful")?;
                            } else {
                                ratelimit::record_failure(&peer_ip);
                                metrics::inc_auth_failure();
                                util::log_event!(
                                    "warn",
                                    "SMTP auth failed",
                                    "event" => "auth_fail",
                                    "ip" => &peer_ip,
                                    "user" => &user,
                                    "proto" => "smtp",
                                    "result" => "fail"
                                );
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
                // Greylisting (inbound only, first RCPT establishes the triplet).
                if !is_submission && cfg.greylist {
                    let mail_from = match &state {
                        State::MailFrom { from } => from.as_str(),
                        State::RcptTo { from, .. } => from.as_str(),
                        _ => "",
                    };
                    // Only greylist on the first recipient of the transaction.
                    let is_first_rcpt = matches!(&state, State::MailFrom { .. });
                    if is_first_rcpt {
                        let now = util::now_secs();
                        // Opportunistic prune of expired greylist files (TTL + 1 day).
                        spamscore::greylist_prune(
                            &cfg.data_dir,
                            cfg.greylist_ttl_secs.saturating_add(86_400),
                            now,
                        );
                        let decision = spamscore::greylist_check(
                            &cfg.data_dir,
                            &peer_ip,
                            mail_from,
                            &rcpt,
                            cfg.greylist_delay_secs,
                            cfg.greylist_ttl_secs,
                            now,
                        );
                        if decision == GreylistDecision::Defer {
                            metrics::inc_greylist_rejects();
                            util::log!(
                                "greylist defer ip={} from={} rcpt={}",
                                peer_ip,
                                mail_from,
                                rcpt
                            );
                            write_line(
                                reader.get_mut(),
                                "451 Greylisted, try again shortly",
                            )?;
                            continue;
                        }
                        util::log!(
                            "greylist accept ip={} from={} rcpt={}",
                            peer_ip,
                            mail_from,
                            rcpt
                        );
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
                let from = from.clone();
                let rcpts = rcpts.clone();
                write_line(reader.get_mut(), "354 End data with <CR><LF>.<CR><LF>")?;
                state = State::Data {
                    from: from.clone(),
                    rcpts: rcpts.clone(),
                };
                data_buf.clear();
                let max_msg = cfg.max_message_bytes as usize;
                let mut oversized = false;
                loop {
                    let dline = match read_line(&mut reader)? {
                        Some(l) => l,
                        None => break,
                    };
                    if dline == "." {
                        break;
                    }
                    if oversized {
                        // Drain until terminating "." without growing the buffer.
                        continue;
                    }
                    let content = if dline.starts_with('.') {
                        dline.get(1..).unwrap_or("")
                    } else {
                        dline.as_str()
                    };
                    let add = content.len().saturating_add(2);
                    if data_buf.len().saturating_add(add) > max_msg {
                        oversized = true;
                        data_buf.clear();
                        continue;
                    }
                    data_buf.extend_from_slice(content.as_bytes());
                    data_buf.extend_from_slice(b"\r\n");
                }
                if oversized {
                    util::log!(
                        "rejecting message: size exceeds max_message_bytes={}",
                        cfg.max_message_bytes
                    );
                    write_line(
                        reader.get_mut(),
                        "552 5.3.4 Message size exceeds fixed maximum message size",
                    )?;
                    state = State::Greeted;
                    continue;
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

                // Inbound trust: SPF / DKIM / DMARC / spam score (annotate always;
                // reject only when config explicitly enables enforcement).
                let mut deliver_raw = data_buf.clone();
                if !is_submission {
                    match inbound_trust_check(
                        &cfg,
                        &peer_ip,
                        &helo_domain,
                        &from,
                        &data_buf,
                        hostname,
                    ) {
                        InboundAction::Reject(msg) => {
                            metrics::inc_spam_rejects();
                            util::log!("inbound reject: {}", msg);
                            write_line(reader.get_mut(), &msg)?;
                            state = State::Greeted;
                            continue;
                        }
                        InboundAction::Accept(annotated) => {
                            deliver_raw = annotated;
                        }
                    }
                }

                let delivered = deliver_mail(
                    &cfg,
                    &state,
                    &deliver_raw,
                    is_submission,
                    &authenticated_user,
                );
                match delivered {
                    Ok(n) => {
                        metrics::inc_messages_received();
                        metrics::inc_messages_delivered(n as u64);
                        write_line(reader.get_mut(), &format!("250 OK: queued as {} msgs", n))?;
                    }
                    Err(e) if e.contains("OVERQUOTA") || e.contains("Mailbox full") => {
                        util::log_event!(
                            "warn",
                            "mailbox full",
                            "event" => "overquota",
                            "result" => "reject"
                        );
                        write_line(reader.get_mut(), "452 4.2.2 Mailbox full")?;
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

/// Result of inbound SPF/DKIM/DMARC/spam processing.
enum InboundAction {
    Accept(Vec<u8>),
    Reject(String),
}

/// Run inbound trust checks, prepend Authentication-Results / Received-SPF /
/// optional X-Spam-* headers. Never rejects on TempError (DNS failure).
fn inbound_trust_check(
    cfg: &Config,
    peer_ip: &str,
    helo: &str,
    mail_from: &str,
    raw: &[u8],
    hostname: &str,
) -> InboundAction {
    let (_local, mail_domain) = util::parse_email_addr(mail_from);

    // --- SPF ---
    let spf_result = spf::check_spf(peer_ip, helo, &mail_domain);
    util::log!(
        "SPF {} client-ip={} helo={} mail_from_domain={}",
        spf_result.as_str(),
        peer_ip,
        helo,
        mail_domain
    );

    // --- DKIM ---
    let dkim_results = dkim::verify(raw, |name| {
        match crate::dns::resolve_txt(name) {
            Ok(txts) => {
                // Prefer a record containing p=
                for t in txts {
                    if t.to_ascii_lowercase().contains("p=") {
                        return Some(t);
                    }
                }
                None
            }
            Err(e) => {
                util::log!("DKIM DNS lookup {} failed: {}", name, e);
                None
            }
        }
    });
    for d in &dkim_results {
        util::log!(
            "DKIM {} d={} s={} ({})",
            d.status.as_str(),
            d.domain,
            d.selector,
            d.detail
        );
    }

    // --- DMARC ---
    let from_dom = spamscore::from_header_domain(raw);
    let from_dom = if from_dom.is_empty() {
        mail_domain.clone()
    } else {
        from_dom
    };
    // SPF authenticated domain is the MAIL FROM domain (or HELO if empty).
    let spf_auth_domain = if mail_domain.is_empty() {
        helo.trim_end_matches('.').to_lowercase()
    } else {
        mail_domain.clone()
    };
    let dmarc = dmarc::evaluate(&from_dom, spf_result, &spf_auth_domain, &dkim_results);
    util::log!(
        "DMARC {} policy={} disposition={} ({})",
        dmarc.as_ar_result(),
        dmarc.policy.as_str(),
        dmarc.disposition.as_str(),
        dmarc.detail
    );

    // --- DNSBL ---
    let dnsbl_hits = if cfg.dnsbls.is_empty() {
        0
    } else {
        spamscore::dnsbl_hit_count(peer_ip, &cfg.dnsbls)
    };
    if dnsbl_hits > 0 {
        util::log!("DNSBL hits={} ip={}", dnsbl_hits, peer_ip);
        if cfg.dnsbl_reject {
            return InboundAction::Reject(format!(
                "550 5.7.1 Listed on DNSBL ({} hit(s))",
                dnsbl_hits
            ));
        }
    }

    // --- Spam score ---
    let score_input = SpamScoreInput {
        client_ip: peer_ip,
        helo,
        spf: spf_result,
        dkim: &dkim_results,
        dmarc_pass: if dmarc.record_found {
            Some(dmarc.pass)
        } else {
            None
        },
        dmarc_record_found: dmarc.record_found,
        raw_message: raw,
        dnsbl_hits,
        check_ptr: cfg.spam_check_ptr,
    };
    let spam = SpamScore::compute(&score_input);
    util::log!(
        "spam_score={} reasons={:?}",
        spam.score,
        spam.reasons
    );

    if cfg.spam_score_reject > 0 && spam.score >= cfg.spam_score_reject {
        return InboundAction::Reject(format!(
            "550 5.7.1 Message rejected as spam (score {})",
            spam.score
        ));
    }

    // --- Enforcement (conservative; TempError never rejects) ---
    if cfg.dmarc_enforce && dmarc.record_found && !dmarc.pass {
        if dmarc.disposition == DmarcPolicy::Reject
            && spf_result != SpfResult::TempError
            && !dkim_results.iter().any(|d| d.status == DkimStatus::TempError)
        {
            return InboundAction::Reject(
                "550 5.7.1 DMARC policy reject".into(),
            );
        }
    }
    if cfg.spf_enforce
        && spf_result == SpfResult::Fail
        && dmarc.record_found
        && dmarc.disposition == DmarcPolicy::Reject
        && !dmarc.pass
    {
        return InboundAction::Reject("550 5.7.1 SPF fail and DMARC reject".into());
    }

    // Quarantine tag when DMARC says quarantine and enforce is on, or score tags.
    let mut quarantine = false;
    if cfg.dmarc_enforce
        && dmarc.record_found
        && !dmarc.pass
        && dmarc.disposition == DmarcPolicy::Quarantine
    {
        quarantine = true;
    }
    if spam.score >= cfg.spam_score_tag && cfg.spam_score_tag > 0 {
        quarantine = true;
    }

    // --- Build annotation headers ---
    let mut prefix = String::new();

    // Received-SPF
    let rspf = spf::received_spf_header(spf_result, peer_ip, helo, mail_from);
    prefix.push_str("Received-SPF: ");
    prefix.push_str(&rspf);
    prefix.push_str("\r\n");

    // Authentication-Results (RFC 8601)
    let mut ar = format!("Authentication-Results: {};", hostname);
    ar.push_str(&format!(" spf={}", spf_result.as_str()));
    if !spf_auth_domain.is_empty() {
        ar.push_str(&format!(" smtp.mailfrom={}", spf_auth_domain));
    }
    // DKIM methods
    let mut any_dkim = false;
    for d in &dkim_results {
        if d.status == DkimStatus::None && d.domain.is_empty() {
            ar.push_str("; dkim=none");
            any_dkim = true;
            break;
        }
        ar.push_str(&format!(
            "; dkim={} header.d={} header.s={}",
            d.status.as_str(),
            d.domain,
            d.selector
        ));
        any_dkim = true;
    }
    if !any_dkim {
        ar.push_str("; dkim=none");
    }
    ar.push_str(&format!(
        "; dmarc={} header.from={}",
        dmarc.as_ar_result(),
        if from_dom.is_empty() { "unknown" } else { &from_dom }
    ));
    if dmarc.record_found {
        ar.push_str(&format!(" policy.dmarc={}", dmarc.policy.as_str()));
    }
    prefix.push_str(&ar);
    prefix.push_str("\r\n");

    if quarantine || spam.score >= cfg.spam_score_tag && cfg.spam_score_tag > 0 {
        prefix.push_str("X-Spam-Flag: YES\r\n");
        prefix.push_str(&format!("X-Spam-Score: {}\r\n", spam.score));
        if !spam.reasons.is_empty() {
            prefix.push_str(&format!(
                "X-Spam-Status: Yes, score={} reasons=\"{}\"\r\n",
                spam.score,
                spam.reasons.join(", ")
            ));
        }
    } else if spam.score > 0 {
        prefix.push_str(&format!("X-Spam-Score: {}\r\n", spam.score));
    }

    let mut out = Vec::with_capacity(prefix.len() + raw.len());
    out.extend_from_slice(prefix.as_bytes());
    out.extend_from_slice(raw);
    InboundAction::Accept(out)
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
                check_quota(cfg, &mb, raw.len() as u64)?;
                let md = Maildir::open(&cfg.data_dir, &format!("{}/.Sent", mb))
                    .map_err(|e| e.to_string())?;
                md.deliver(raw, from).map_err(|e| e.to_string())?;
                Maildir::invalidate_quota_cache(&cfg.data_dir, &mb);
                count += 1;
            }
        }

        let mut remote: Vec<String> = Vec::new();
        for r in rcpts {
            if let Some(mb) = cfg.resolve_mailbox(r) {
                check_quota(cfg, &mb, raw.len() as u64)?;
                let md = Maildir::open(&cfg.data_dir, &mb).map_err(|e| e.to_string())?;
                md.deliver(raw, from).map_err(|e| e.to_string())?;
                Maildir::invalidate_quota_cache(&cfg.data_dir, &mb);
                count += 1;
            } else {
                remote.push(r.clone());
            }
        }

        if !remote.is_empty() {
            let id = queue::enqueue(&cfg.data_dir, from, &remote, raw).map_err(|e| e.to_string())?;
            metrics::inc_messages_queued();
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
                check_quota(cfg, &mb, raw.len() as u64)?;
                let md = Maildir::open(&cfg.data_dir, &mb).map_err(|e| e.to_string())?;
                md.deliver(raw, from).map_err(|e| e.to_string())?;
                Maildir::invalidate_quota_cache(&cfg.data_dir, &mb);
                count += 1;
            }
        }
    }
    if count == 0 {
        return Err("no recipients accepted".into());
    }
    Ok(count)
}

fn check_quota(cfg: &Config, mailbox_user: &str, extra: u64) -> Result<(), String> {
    let quota = cfg.quota_bytes_for(mailbox_user);
    if quota == 0 {
        return Ok(());
    }
    let cur = Maildir::mailbox_size(&cfg.data_dir, mailbox_user).unwrap_or(0);
    if Maildir::would_exceed_quota(cur, extra, quota) {
        return Err("OVERQUOTA Mailbox full".into());
    }
    Ok(())
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
        let cfg = Config::default();
        *cfg.domains.write().unwrap() = vec!["example.com".into()];
        let rcpt = "victim@evil.com";
        let (_l, domain) = util::parse_email_addr(rcpt);
        assert!(!cfg.is_our_domain(&domain));
        assert!(cfg.resolve_mailbox(rcpt).is_none());
    }

    #[test]
    fn local_domain_accepted() {
        let cfg = Config::default();
        *cfg.domains.write().unwrap() = vec!["example.com".into()];
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

    #[test]
    fn max_message_bytes_default() {
        let cfg = Config::default();
        assert_eq!(
            cfg.max_message_bytes,
            crate::config::DEFAULT_MAX_MESSAGE_BYTES
        );
        assert_eq!(cfg.max_message_bytes, 25 * 1024 * 1024);
    }
}
