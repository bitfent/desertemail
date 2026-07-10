//! Minimal IMAP4rev1 server (RFC 3501 subset) from scratch.
//! Supports: LOGIN, SELECT, LIST, FETCH (RFC822 / BODY[] / FLAGS / UID), LOGOUT, NOOP, CAPABILITY.
//! Optional STARTTLS (RFC 2595) and implicit IMAPS when TLS is configured.

use std::io::{self, BufReader};
use std::net::TcpListener;
use std::sync::Arc;
use std::thread;

use rustls::ServerConfig;

use crate::auth;
use crate::config::Config;
use crate::storage::{Maildir, MessageMeta};
use crate::tls::{self, Conn};
use crate::util::{self, read_line, write_line, write_raw};

pub struct ImapServer {
    cfg: Arc<Config>,
    tls_cfg: Option<Arc<ServerConfig>>,
    implicit_tls: bool,
}

impl ImapServer {
    pub fn new(
        cfg: Arc<Config>,
        tls_cfg: Option<Arc<ServerConfig>>,
        implicit_tls: bool,
    ) -> Self {
        Self {
            cfg,
            tls_cfg,
            implicit_tls,
        }
    }

    pub fn serve(&self, listener: TcpListener) {
        util::log!(
            "IMAP{} listening on {}",
            if self.implicit_tls { "S" } else { "" },
            listener.local_addr().unwrap()
        );
        for stream in listener.incoming() {
            match stream {
                Ok(stream) => {
                    let cfg = Arc::clone(&self.cfg);
                    let tls_cfg = self.tls_cfg.clone();
                    let implicit = self.implicit_tls;
                    thread::spawn(move || {
                        if let Err(e) = handle_client(stream, cfg, tls_cfg, implicit) {
                            util::log!("IMAP client error: {}", e);
                        }
                    });
                }
                Err(e) => util::log!("IMAP accept error: {}", e),
            }
        }
    }
}

#[derive(Debug)]
enum State {
    NotAuth,
    Auth { user: String },
    Selected {
        user: String,
        mailbox: String,
        msgs: Vec<MessageMeta>,
    },
}

fn handle_client(
    stream: std::net::TcpStream,
    cfg: Arc<Config>,
    tls_cfg: Option<Arc<ServerConfig>>,
    implicit_tls: bool,
) -> io::Result<()> {
    let conn = if implicit_tls {
        let tc = tls_cfg.as_ref().ok_or_else(|| {
            io::Error::new(io::ErrorKind::Other, "implicit TLS without config")
        })?;
        tls::accept_tls(stream, tc)?
    } else {
        Conn::Plain(stream)
    };

    let peer = conn.peer_addr_string();
    util::log!(
        "IMAP connect from {}{}",
        peer,
        if conn.is_tls() { " (TLS)" } else { "" }
    );

    let mut reader = BufReader::new(conn);
    let mut is_tls = reader.get_ref().is_tls();
    let starttls_available = tls_cfg.is_some();

    write_line(reader.get_mut(), "* OK desertemail IMAP4rev1 ready")?;

    let mut state = State::NotAuth;
    let mut tag = String::new();

    loop {
        let line = match read_line(&mut reader)? {
            Some(l) => l,
            None => break,
        };
        util::log!("IMAP << {}", line);

        let mut parts = line.splitn(2, ' ');
        tag = parts.next().unwrap_or("").to_string();
        let rest = parts.next().unwrap_or("").trim();
        let mut cmd_parts = rest.split_whitespace();
        let cmd = cmd_parts.next().unwrap_or("").to_uppercase();

        match (cmd.as_str(), &state) {
            ("CAPABILITY", _) => {
                if starttls_available && !is_tls {
                    write_line(
                        reader.get_mut(),
                        "* CAPABILITY IMAP4rev1 AUTH=PLAIN STARTTLS",
                    )?;
                } else {
                    write_line(reader.get_mut(), "* CAPABILITY IMAP4rev1 AUTH=PLAIN")?;
                }
                write_line(reader.get_mut(), &format!("{} OK CAPABILITY completed", tag))?;
            }
            ("STARTTLS", State::NotAuth) if starttls_available && !is_tls => {
                // RFC 2595: tagged OK, then upgrade. Only valid in NotAuth.
                write_line(reader.get_mut(), &format!("{} OK Begin TLS negotiation now", tag))?;
                let plain = match reader.into_inner() {
                    Conn::Plain(s) => s,
                    Conn::Tls(_) => {
                        return Err(io::Error::new(
                            io::ErrorKind::Other,
                            "STARTTLS on already-TLS conn",
                        ));
                    }
                };
                let tc = tls_cfg.as_ref().unwrap();
                let upgraded = tls::upgrade(plain, tc)?;
                reader = BufReader::new(upgraded);
                is_tls = true;
                state = State::NotAuth;
                util::log!("IMAP STARTTLS completed for {}", peer);
            }
            ("NOOP", _) => {
                write_line(reader.get_mut(), &format!("{} OK NOOP completed", tag))?;
            }
            ("LOGOUT", _) => {
                write_line(reader.get_mut(), "* BYE desertemail logging out")?;
                write_line(reader.get_mut(), &format!("{} OK LOGOUT completed", tag))?;
                break;
            }
            ("LOGIN", State::NotAuth) => {
                let (user, pass) = parse_login_args(rest);
                if auth::authenticate(&cfg, &user, &pass) {
                    // Map the login name to its mailbox the same way SMTP
                    // delivery does, so both sides use the same Maildir.
                    let mailbox = cfg.resolve_mailbox(&user).unwrap_or_else(|| user.clone());
                    state = State::Auth { user: mailbox };
                    write_line(reader.get_mut(), &format!("{} OK LOGIN completed", tag))?;
                    util::log!("IMAP login ok for {}", user);
                } else {
                    write_line(reader.get_mut(), &format!("{} NO LOGIN failed", tag))?;
                }
            }
            ("LIST", State::Auth { .. } | State::Selected { .. }) => {
                write_line(
                    reader.get_mut(),
                    "* LIST (\\HasNoChildren) \"/\" \"INBOX\"",
                )?;
                write_line(reader.get_mut(), &format!("{} OK LIST completed", tag))?;
            }
            ("SELECT" | "EXAMINE", State::Auth { user } | State::Selected { user, .. }) => {
                let mbox = cmd_parts.next().unwrap_or("INBOX").trim_matches('"');
                let mbox_name = if mbox.eq_ignore_ascii_case("inbox") {
                    "INBOX"
                } else {
                    mbox
                };
                let mb_path = if mbox_name == "INBOX" {
                    user.clone()
                } else {
                    format!("{}/{}", user, mbox_name)
                };
                match Maildir::open(&cfg.data_dir, &mb_path) {
                    Ok(md) => {
                        let msgs = md.list_messages().unwrap_or_default();
                        let exists = msgs.len();
                        let recent = msgs.iter().filter(|m| m.in_new).count();
                        write_line(reader.get_mut(), &format!("* {} EXISTS", exists))?;
                        write_line(reader.get_mut(), &format!("* {} RECENT", recent))?;
                        write_line(reader.get_mut(), "* OK [UIDVALIDITY 1] UIDs valid")?;
                        write_line(
                            reader.get_mut(),
                            &format!("* OK [UIDNEXT {}] Predicted next UID", exists + 1),
                        )?;
                        write_line(
                            reader.get_mut(),
                            "* FLAGS (\\Seen \\Answered \\Flagged \\Deleted \\Draft)",
                        )?;
                        write_line(
                            reader.get_mut(),
                            "* OK [PERMANENTFLAGS (\\Seen \\Deleted \\*)] Limited",
                        )?;
                        write_line(
                            reader.get_mut(),
                            &format!("{} OK [READ-WRITE] SELECT completed", tag),
                        )?;
                        state = State::Selected {
                            user: user.clone(),
                            mailbox: mb_path,
                            msgs,
                        };
                    }
                    Err(e) => {
                        write_line(
                            reader.get_mut(),
                            &format!("{} NO SELECT failed: {}", tag, e),
                        )?;
                    }
                }
            }
            ("FETCH", State::Selected { msgs, .. }) => {
                let seq_set = cmd_parts.next().unwrap_or("1");
                let items = rest.to_uppercase();
                let indices = parse_seq_set(seq_set, msgs.len());
                for idx in indices {
                    if idx == 0 || idx > msgs.len() {
                        continue;
                    }
                    let meta = &msgs[idx - 1];
                    let mut response = format!("* {} FETCH (", idx);
                    let mut first = true;
                    if items.contains("FLAGS") || items.contains("ALL") || items.contains("FAST") {
                        if !first {
                            response.push(' ');
                        }
                        response.push_str("FLAGS (\\Seen)");
                        first = false;
                    }
                    if items.contains("UID") || items.contains("ALL") {
                        if !first {
                            response.push(' ');
                        }
                        response.push_str(&format!("UID {}", meta.uid));
                        first = false;
                    }
                    if items.contains("RFC822.SIZE")
                        || items.contains("ALL")
                        || items.contains("FAST")
                    {
                        if !first {
                            response.push(' ');
                        }
                        response.push_str(&format!("RFC822.SIZE {}", meta.size));
                        first = false;
                    }
                    if items.contains("RFC822")
                        || items.contains("BODY[]")
                        || items.contains("BODY.PEEK[]")
                        || items.contains("ALL")
                    {
                        match std::fs::read(&meta.path) {
                            Ok(body) => {
                                if !first {
                                    response.push(' ');
                                }
                                response.push_str(&format!("RFC822 {{{}}}", body.len()));
                                write_line(reader.get_mut(), &response)?;
                                write_raw(reader.get_mut(), &body)?;
                                write_raw(reader.get_mut(), b")\r\n")?;
                                continue;
                            }
                            Err(_) => {
                                if !first {
                                    response.push(' ');
                                }
                                response.push_str("RFC822 {0}");
                            }
                        }
                    }
                    response.push(')');
                    write_line(reader.get_mut(), &response)?;
                }
                write_line(reader.get_mut(), &format!("{} OK FETCH completed", tag))?;
            }
            ("CLOSE", State::Selected { user, .. }) => {
                state = State::Auth { user: user.clone() };
                write_line(reader.get_mut(), &format!("{} OK CLOSE completed", tag))?;
            }
            ("UID", State::Selected { .. }) => {
                write_line(
                    reader.get_mut(),
                    &format!("{} OK UID command accepted (limited)", tag),
                )?;
            }
            _ => {
                write_line(
                    reader.get_mut(),
                    &format!("{} BAD Command unknown or arguments invalid", tag),
                )?;
            }
        }
    }
    util::log!("IMAP disconnect {}", peer);
    Ok(())
}

fn parse_login_args(rest: &str) -> (String, String) {
    let tokens: Vec<String> = {
        let mut t = Vec::new();
        let mut cur = String::new();
        let mut in_quote = false;
        for c in rest.chars() {
            if c == '"' {
                in_quote = !in_quote;
                continue;
            }
            if c.is_whitespace() && !in_quote {
                if !cur.is_empty() {
                    t.push(cur);
                    cur = String::new();
                }
            } else {
                cur.push(c);
            }
        }
        if !cur.is_empty() {
            t.push(cur);
        }
        t
    };
    if tokens.len() >= 3 {
        (tokens[1].clone(), tokens[2].clone())
    } else if tokens.len() == 2 {
        (tokens[0].clone(), tokens[1].clone())
    } else {
        (String::new(), String::new())
    }
}

fn parse_seq_set(s: &str, max: usize) -> Vec<usize> {
    let mut res = Vec::new();
    for part in s.split(',') {
        if part == "*" {
            if max > 0 {
                res.push(max);
            }
        } else if let Some((a, b)) = part.split_once(':') {
            let start: usize = a.parse().unwrap_or(1);
            let end = if b == "*" {
                max
            } else {
                b.parse().unwrap_or(max)
            };
            for i in start..=end.min(max) {
                res.push(i);
            }
        } else if let Ok(n) = part.parse::<usize>() {
            if n >= 1 && n <= max {
                res.push(n);
            }
        }
    }
    res.sort();
    res.dedup();
    res
}
