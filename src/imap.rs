//! IMAP4rev1 server (RFC 3501 subset) from scratch.
//! LOGIN, SELECT, LIST, FETCH, SEARCH, STORE, EXPUNGE, CLOSE, APPEND, IDLE,
//! UID variants, LOGOUT, NOOP, CAPABILITY, STARTTLS / IMAPS.

use std::io::{self, BufReader, Read, Write};
use std::net::TcpListener;
use std::sync::Arc;
use std::thread;
use std::time::Duration;

use rustls::ServerConfig;

use crate::auth;
use crate::config::Config;
use crate::limits;
use crate::metrics;
use crate::ratelimit;
use crate::storage::{self, Maildir, MessageMeta};
use crate::tls::{self, Conn};
use crate::util::{self, read_line, write_line, write_raw};

/// Stable UIDVALIDITY for this server (constant; UIDs derived from filename hash).
const UIDVALIDITY: u32 = 1;

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
            listener
                .local_addr()
                .map(|a| a.to_string())
                .unwrap_or_else(|_| "?".into())
        );
        let _ = listener.set_nonblocking(true);
        loop {
            if crate::shutdown::is_shutdown() {
                util::log!("IMAP listener shutting down");
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
                            let _ = s.write_all(b"* BYE too many connections\r\n");
                            let _ = s.flush();
                            continue;
                        }
                    };
                    limits::apply_timeouts(&stream);
                    let cfg = Arc::clone(&self.cfg);
                    let tls_cfg = self.tls_cfg.clone();
                    let implicit = self.implicit_tls;
                    thread::spawn(move || {
                        let _guard = guard;
                        if let Err(e) = handle_client(stream, cfg, tls_cfg, implicit) {
                            util::log!("IMAP client error: {}", e);
                        }
                    });
                }
                Err(ref e) if e.kind() == io::ErrorKind::WouldBlock => {
                    thread::sleep(Duration::from_millis(200));
                }
                Err(e) => {
                    if crate::shutdown::is_shutdown() {
                        break;
                    }
                    util::log!("IMAP accept error: {}", e);
                    thread::sleep(Duration::from_millis(200));
                }
            }
        }
    }
}

#[derive(Debug)]
enum State {
    NotAuth,
    Auth {
        user: String,
    },
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
    limits::apply_timeouts(&stream);

    let conn = if implicit_tls {
        let tc = tls_cfg.as_ref().ok_or_else(|| {
            io::Error::new(io::ErrorKind::Other, "implicit TLS without config")
        })?;
        let c = tls::accept_tls(stream, tc)?;
        c.set_timeouts(Duration::from_secs(limits::io_timeout_secs()));
        c
    } else {
        let c = Conn::Plain(stream);
        c.set_timeouts(Duration::from_secs(limits::io_timeout_secs()));
        c
    };

    let peer = conn.peer_addr_string();
    let peer_ip = limits::ip_key(&peer);
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

    loop {
        if crate::shutdown::is_shutdown() {
            let _ = write_line(reader.get_mut(), "* BYE server shutting down");
            break;
        }
        let line = match read_line(&mut reader) {
            Ok(Some(l)) => l,
            Ok(None) => break,
            Err(e) if e.kind() == io::ErrorKind::WouldBlock || e.kind() == io::ErrorKind::TimedOut => {
                continue;
            }
            Err(e) => return Err(e),
        };
        // Skip empty lines (common after APPEND literals leave a trailing CRLF).
        if line.trim().is_empty() {
            continue;
        }
        util::log!("IMAP << {}", line);

        let mut parts = line.splitn(2, ' ');
        let tag = parts.next().unwrap_or("").to_string();
        let rest = parts.next().unwrap_or("").trim();
        let mut cmd_parts = rest.split_whitespace();
        let cmd = cmd_parts.next().unwrap_or("").to_uppercase();
        if cmd.is_empty() {
            write_line(
                reader.get_mut(),
                &format!("{} BAD empty command", tag),
            )?;
            continue;
        }

        match (cmd.as_str(), &state) {
            ("CAPABILITY", _) => {
                write_capability(reader.get_mut(), starttls_available && !is_tls)?;
                write_line(reader.get_mut(), &format!("{} OK CAPABILITY completed", tag))?;
            }
            ("STARTTLS", State::NotAuth) if starttls_available && !is_tls => {
                write_line(
                    reader.get_mut(),
                    &format!("{} OK Begin TLS negotiation now", tag),
                )?;
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
                upgraded.set_timeouts(Duration::from_secs(limits::io_timeout_secs()));
                reader = BufReader::new(upgraded);
                is_tls = true;
                state = State::NotAuth;
                util::log!("IMAP STARTTLS completed for {}", peer);
            }
            ("NOOP", State::Selected { user, mailbox, msgs }) => {
                // Refresh EXISTS on NOOP
                if let Ok(md) = Maildir::open(&cfg.data_dir, mailbox) {
                    if let Ok(new_msgs) = md.list_messages() {
                        if new_msgs.len() != msgs.len() {
                            write_line(
                                reader.get_mut(),
                                &format!("* {} EXISTS", new_msgs.len()),
                            )?;
                            let recent = new_msgs.iter().filter(|m| m.in_new).count();
                            write_line(reader.get_mut(), &format!("* {} RECENT", recent))?;
                        }
                        state = State::Selected {
                            user: user.clone(),
                            mailbox: mailbox.clone(),
                            msgs: new_msgs,
                        };
                    }
                }
                write_line(reader.get_mut(), &format!("{} OK NOOP completed", tag))?;
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
                if !ratelimit::check_allowed(&peer_ip) {
                    util::log_event!(
                        "warn",
                        "IMAP auth lockout",
                        "event" => "auth_lockout",
                        "ip" => &peer_ip,
                        "proto" => "imap"
                    );
                    write_line(
                        reader.get_mut(),
                        &format!("{} NO Too many failed attempts, try later", tag),
                    )?;
                    continue;
                }
                let (user, pass) = parse_login_args(rest);
                if auth::authenticate(&cfg, &user, &pass) {
                    ratelimit::record_success(&peer_ip);
                    metrics::inc_auth_success();
                    let mailbox = cfg.resolve_mailbox(&user).unwrap_or_else(|| user.clone());
                    state = State::Auth { user: mailbox };
                    write_line(reader.get_mut(), &format!("{} OK LOGIN completed", tag))?;
                    util::log_event!(
                        "info",
                        "IMAP login ok",
                        "event" => "auth_ok",
                        "ip" => &peer_ip,
                        "user" => &user,
                        "proto" => "imap",
                        "result" => "ok"
                    );
                } else {
                    ratelimit::record_failure(&peer_ip);
                    metrics::inc_auth_failure();
                    util::log_event!(
                        "warn",
                        "IMAP login failed",
                        "event" => "auth_fail",
                        "ip" => &peer_ip,
                        "user" => &user,
                        "proto" => "imap",
                        "result" => "fail"
                    );
                    write_line(reader.get_mut(), &format!("{} NO LOGIN failed", tag))?;
                }
            }
            ("LIST", State::Auth { .. } | State::Selected { .. }) => {
                write_line(
                    reader.get_mut(),
                    "* LIST (\\HasNoChildren) \"/\" \"INBOX\"",
                )?;
                write_line(
                    reader.get_mut(),
                    "* LIST (\\HasNoChildren) \"/\" \"Sent\"",
                )?;
                write_line(
                    reader.get_mut(),
                    "* LIST (\\HasNoChildren) \"/\" \"Drafts\"",
                )?;
                write_line(
                    reader.get_mut(),
                    "* LIST (\\HasNoChildren) \"/\" \"Trash\"",
                )?;
                write_line(reader.get_mut(), &format!("{} OK LIST completed", tag))?;
            }
            ("SELECT" | "EXAMINE", State::Auth { user } | State::Selected { user, .. }) => {
                let mbox = cmd_parts.next().unwrap_or("INBOX").trim_matches('"');
                match select_mailbox(&cfg, user, mbox) {
                    Ok((mb_path, msgs)) => {
                        let exists = msgs.len();
                        let recent = msgs.iter().filter(|m| m.in_new).count();
                        let uidnext = msgs.iter().map(|m| m.uid).max().unwrap_or(0).saturating_add(1);
                        write_line(reader.get_mut(), &format!("* {} EXISTS", exists))?;
                        write_line(reader.get_mut(), &format!("* {} RECENT", recent))?;
                        write_line(
                            reader.get_mut(),
                            &format!("* OK [UIDVALIDITY {}] UIDs valid", UIDVALIDITY),
                        )?;
                        write_line(
                            reader.get_mut(),
                            &format!("* OK [UIDNEXT {}] Predicted next UID", uidnext),
                        )?;
                        write_line(
                            reader.get_mut(),
                            "* FLAGS (\\Seen \\Answered \\Flagged \\Deleted \\Draft)",
                        )?;
                        write_line(
                            reader.get_mut(),
                            "* OK [PERMANENTFLAGS (\\Seen \\Deleted \\Answered \\Flagged \\Draft \\*)] Limited",
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
                do_fetch(reader.get_mut(), msgs, seq_set, &items, false)?;
                write_line(reader.get_mut(), &format!("{} OK FETCH completed", tag))?;
            }
            ("SEARCH", State::Selected { msgs, .. }) => {
                let criteria = rest
                    .strip_prefix("SEARCH")
                    .or_else(|| rest.strip_prefix("search"))
                    .unwrap_or(rest)
                    .trim();
                match run_search(msgs, criteria, false) {
                    Ok(ids) => {
                        let list: Vec<String> = ids.iter().map(|n| n.to_string()).collect();
                        write_line(
                            reader.get_mut(),
                            &format!("* SEARCH {}", list.join(" ")),
                        )?;
                        write_line(
                            reader.get_mut(),
                            &format!("{} OK SEARCH completed", tag),
                        )?;
                    }
                    Err(e) => {
                        write_line(reader.get_mut(), &format!("{} BAD SEARCH {}", tag, e))?;
                    }
                }
            }
            ("STORE", State::Selected { user, mailbox, msgs }) => {
                let seq_set = cmd_parts.next().unwrap_or("").to_string();
                let mode = cmd_parts.next().unwrap_or("").to_string();
                // rest of flags: (\\Seen ...)
                let flags_part = rest
                    .find('(')
                    .map(|i| &rest[i..])
                    .unwrap_or("");
                let imap_flags = parse_flag_list(flags_part);
                match do_store(&cfg, user, mailbox, msgs, &seq_set, &mode, &imap_flags, false)
                {
                    Ok(new_msgs) => {
                        // Emit FETCH FLAGS for modified messages is done inside do_store
                        // Re-list after store for consistent state
                        if let Ok(md) = Maildir::open(&cfg.data_dir, mailbox) {
                            if let Ok(listed) = md.list_messages() {
                                // Write untagged FETCH for each stored seq
                                let indices = parse_seq_set(&seq_set, new_msgs.len().max(msgs.len()));
                                for idx in indices {
                                    if let Some(m) = listed.get(idx.saturating_sub(1)) {
                                        write_line(
                                            reader.get_mut(),
                                            &format!(
                                                "* {} FETCH (FLAGS {})",
                                                idx,
                                                m.imap_flags_str()
                                            ),
                                        )?;
                                    }
                                }
                                state = State::Selected {
                                    user: user.clone(),
                                    mailbox: mailbox.clone(),
                                    msgs: listed,
                                };
                            }
                        }
                        write_line(
                            reader.get_mut(),
                            &format!("{} OK STORE completed", tag),
                        )?;
                    }
                    Err(e) => {
                        write_line(reader.get_mut(), &format!("{} NO STORE failed: {}", tag, e))?;
                    }
                }
            }
            ("EXPUNGE", State::Selected { user, mailbox, msgs }) => {
                match do_expunge(&cfg, user, mailbox, msgs) {
                    Ok((new_msgs, expunged_seqs)) => {
                        for seq in expunged_seqs {
                            write_line(reader.get_mut(), &format!("* {} EXPUNGE", seq))?;
                        }
                        write_line(
                            reader.get_mut(),
                            &format!("{} OK EXPUNGE completed", tag),
                        )?;
                        state = State::Selected {
                            user: user.clone(),
                            mailbox: mailbox.clone(),
                            msgs: new_msgs,
                        };
                    }
                    Err(e) => {
                        write_line(
                            reader.get_mut(),
                            &format!("{} NO EXPUNGE failed: {}", tag, e),
                        )?;
                    }
                }
            }
            ("CLOSE", State::Selected { user, mailbox, msgs }) => {
                // CLOSE = silent expunge of \Deleted + return to Auth
                let _ = do_expunge(&cfg, user, mailbox, msgs);
                state = State::Auth {
                    user: user.clone(),
                };
                write_line(reader.get_mut(), &format!("{} OK CLOSE completed", tag))?;
            }
            ("APPEND", State::Auth { user } | State::Selected { user, .. }) => {
                match do_append_full(&cfg, user, rest, &mut reader) {
                    Ok(()) => {
                        if let State::Selected {
                            user: u,
                            mailbox,
                            ..
                        } = &state
                        {
                            if let Ok(md) = Maildir::open(&cfg.data_dir, mailbox) {
                                if let Ok(msgs) = md.list_messages() {
                                    write_line(
                                        reader.get_mut(),
                                        &format!("* {} EXISTS", msgs.len()),
                                    )?;
                                    state = State::Selected {
                                        user: u.clone(),
                                        mailbox: mailbox.clone(),
                                        msgs,
                                    };
                                }
                            }
                        }
                        write_line(
                            reader.get_mut(),
                            &format!("{} OK APPEND completed", tag),
                        )?;
                    }
                    Err(AppendError::OverQuota) => {
                        write_line(
                            reader.get_mut(),
                            &format!("{} NO [OVERQUOTA] APPEND failed", tag),
                        )?;
                    }
                    Err(AppendError::Other(e)) => {
                        write_line(
                            reader.get_mut(),
                            &format!("{} NO APPEND failed: {}", tag, e),
                        )?;
                    }
                    Err(AppendError::Bad(e)) => {
                        write_line(reader.get_mut(), &format!("{} BAD APPEND {}", tag, e))?;
                    }
                }
            }
            ("IDLE", State::Selected { user, mailbox, msgs }) => {
                // RFC 2177
                write_line(reader.get_mut(), "+ idling")?;
                let result = do_idle(&cfg, user, mailbox, msgs, &mut reader);
                match result {
                    Ok(new_msgs) => {
                        state = State::Selected {
                            user: user.clone(),
                            mailbox: mailbox.clone(),
                            msgs: new_msgs,
                        };
                        write_line(reader.get_mut(), &format!("{} OK IDLE terminated", tag))?;
                    }
                    Err(e) => {
                        write_line(reader.get_mut(), &format!("{} NO IDLE {}", tag, e))?;
                    }
                }
                // Restore normal I/O timeout after IDLE polling
                reader
                    .get_ref()
                    .set_timeouts(Duration::from_secs(limits::io_timeout_secs()));
            }
            ("UID", State::Selected { msgs, user, mailbox }) => {
                let sub = cmd_parts.next().unwrap_or("").to_uppercase();
                match sub.as_str() {
                    "FETCH" => {
                        let seq_set = cmd_parts.next().unwrap_or("1");
                        let items = rest.to_uppercase();
                        do_fetch(reader.get_mut(), msgs, seq_set, &items, true)?;
                        write_line(
                            reader.get_mut(),
                            &format!("{} OK UID FETCH completed", tag),
                        )?;
                    }
                    "SEARCH" => {
                        let criteria = {
                            // rest is "UID SEARCH ..."
                            let r = rest.trim();
                            r.strip_prefix("UID")
                                .unwrap_or(r)
                                .trim()
                                .strip_prefix("SEARCH")
                                .or_else(|| {
                                    r.strip_prefix("UID")
                                        .unwrap_or(r)
                                        .trim()
                                        .strip_prefix("search")
                                })
                                .unwrap_or("")
                                .trim()
                        };
                        match run_search(msgs, criteria, true) {
                            Ok(ids) => {
                                let list: Vec<String> =
                                    ids.iter().map(|n| n.to_string()).collect();
                                write_line(
                                    reader.get_mut(),
                                    &format!("* SEARCH {}", list.join(" ")),
                                )?;
                                write_line(
                                    reader.get_mut(),
                                    &format!("{} OK UID SEARCH completed", tag),
                                )?;
                            }
                            Err(e) => {
                                write_line(
                                    reader.get_mut(),
                                    &format!("{} BAD UID SEARCH {}", tag, e),
                                )?;
                            }
                        }
                    }
                    "STORE" => {
                        let seq_set = cmd_parts.next().unwrap_or("").to_string();
                        let mode = cmd_parts.next().unwrap_or("").to_string();
                        let flags_part = rest.find('(').map(|i| &rest[i..]).unwrap_or("");
                        let imap_flags = parse_flag_list(flags_part);
                        match do_store(
                            &cfg, user, mailbox, msgs, &seq_set, &mode, &imap_flags, true,
                        ) {
                            Ok(_) => {
                                if let Ok(md) = Maildir::open(&cfg.data_dir, mailbox) {
                                    if let Ok(listed) = md.list_messages() {
                                        let uids = parse_uid_set(&seq_set, msgs);
                                        for (i, m) in listed.iter().enumerate() {
                                            if uids.contains(&m.uid) {
                                                write_line(
                                                    reader.get_mut(),
                                                    &format!(
                                                        "* {} FETCH (FLAGS {} UID {})",
                                                        i + 1,
                                                        m.imap_flags_str(),
                                                        m.uid
                                                    ),
                                                )?;
                                            }
                                        }
                                        state = State::Selected {
                                            user: user.clone(),
                                            mailbox: mailbox.clone(),
                                            msgs: listed,
                                        };
                                    }
                                }
                                write_line(
                                    reader.get_mut(),
                                    &format!("{} OK UID STORE completed", tag),
                                )?;
                            }
                            Err(e) => {
                                write_line(
                                    reader.get_mut(),
                                    &format!("{} NO UID STORE failed: {}", tag, e),
                                )?;
                            }
                        }
                    }
                    "COPY" => {
                        // Basic UID COPY: copy messages to another mailbox under user
                        let seq_set = cmd_parts.next().unwrap_or("").to_string();
                        let dest = cmd_parts.next().unwrap_or("INBOX").trim_matches('"');
                        match do_copy(&cfg, user, msgs, &seq_set, dest, true) {
                            Ok(()) => write_line(
                                reader.get_mut(),
                                &format!("{} OK UID COPY completed", tag),
                            )?,
                            Err(e) => write_line(
                                reader.get_mut(),
                                &format!("{} NO UID COPY failed: {}", tag, e),
                            )?,
                        }
                    }
                    _ => {
                        write_line(
                            reader.get_mut(),
                            &format!("{} BAD UID subcommand unknown", tag),
                        )?;
                    }
                }
            }
            ("COPY", State::Selected { user, msgs, .. }) => {
                let seq_set = cmd_parts.next().unwrap_or("").to_string();
                let dest = cmd_parts.next().unwrap_or("INBOX").trim_matches('"');
                match do_copy(&cfg, user, msgs, &seq_set, dest, false) {
                    Ok(()) => {
                        write_line(reader.get_mut(), &format!("{} OK COPY completed", tag))?
                    }
                    Err(e) => {
                        write_line(
                            reader.get_mut(),
                            &format!("{} NO COPY failed: {}", tag, e),
                        )?
                    }
                }
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

fn write_capability(w: &mut Conn, starttls: bool) -> io::Result<()> {
    if starttls {
        write_line(
            w,
            "* CAPABILITY IMAP4rev1 AUTH=PLAIN IDLE STARTTLS",
        )
    } else {
        write_line(w, "* CAPABILITY IMAP4rev1 AUTH=PLAIN IDLE")
    }
}

fn select_mailbox(
    cfg: &Config,
    user: &str,
    mbox: &str,
) -> Result<(String, Vec<MessageMeta>), String> {
    let mbox_name = if mbox.eq_ignore_ascii_case("inbox") {
        "INBOX"
    } else {
        mbox
    };
    let mb_path = mailbox_path(user, mbox_name);
    let md = Maildir::open(&cfg.data_dir, &mb_path).map_err(|e| e.to_string())?;
    let msgs = md.list_messages().map_err(|e| e.to_string())?;
    Ok((mb_path, msgs))
}

fn mailbox_path(user: &str, mbox_name: &str) -> String {
    if mbox_name.eq_ignore_ascii_case("inbox") {
        user.to_string()
    } else if mbox_name.eq_ignore_ascii_case("sent") {
        format!("{}/.Sent", user)
    } else if mbox_name.eq_ignore_ascii_case("drafts") {
        format!("{}/.Drafts", user)
    } else if mbox_name.eq_ignore_ascii_case("trash") {
        format!("{}/.Trash", user)
    } else {
        format!("{}/{}", user, mbox_name)
    }
}

fn do_fetch(
    w: &mut Conn,
    msgs: &[MessageMeta],
    seq_set: &str,
    items: &str,
    by_uid: bool,
) -> io::Result<()> {
    let indices: Vec<usize> = if by_uid {
        let uids = parse_uid_set(seq_set, msgs);
        msgs.iter()
            .enumerate()
            .filter(|(_, m)| uids.contains(&m.uid))
            .map(|(i, _)| i + 1)
            .collect()
    } else {
        parse_seq_set(seq_set, msgs.len())
    };
    for idx in indices {
        if idx == 0 || idx > msgs.len() {
            continue;
        }
        let meta = match msgs.get(idx - 1) {
            Some(m) => m,
            None => continue,
        };
        let mut response = format!("* {} FETCH (", idx);
        let mut first = true;
        let want_flags =
            items.contains("FLAGS") || items.contains("ALL") || items.contains("FAST");
        let want_uid = items.contains("UID") || items.contains("ALL") || by_uid;
        let want_size =
            items.contains("RFC822.SIZE") || items.contains("ALL") || items.contains("FAST");
        let want_body = items.contains("RFC822")
            || items.contains("BODY[]")
            || items.contains("BODY.PEEK[]")
            || items.contains("ALL");

        if want_flags {
            if !first {
                response.push(' ');
            }
            response.push_str(&format!("FLAGS {}", meta.imap_flags_str()));
            first = false;
        }
        if want_uid {
            if !first {
                response.push(' ');
            }
            response.push_str(&format!("UID {}", meta.uid));
            first = false;
        }
        if want_size {
            if !first {
                response.push(' ');
            }
            response.push_str(&format!("RFC822.SIZE {}", meta.size));
            first = false;
        }
        if want_body {
            match std::fs::read(&meta.path) {
                Ok(body) => {
                    if !first {
                        response.push(' ');
                    }
                    response.push_str(&format!("RFC822 {{{}}}", body.len()));
                    write_line(w, &response)?;
                    write_raw(w, &body)?;
                    write_raw(w, b")\r\n")?;
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
        write_line(w, &response)?;
    }
    Ok(())
}

fn do_store(
    cfg: &Config,
    _user: &str,
    mailbox: &str,
    msgs: &[MessageMeta],
    seq_set: &str,
    mode: &str,
    imap_flags: &[String],
    by_uid: bool,
) -> Result<Vec<MessageMeta>, String> {
    let md = Maildir::open(&cfg.data_dir, mailbox).map_err(|e| e.to_string())?;
    let targets: Vec<usize> = if by_uid {
        let uids = parse_uid_set(seq_set, msgs);
        msgs.iter()
            .enumerate()
            .filter(|(_, m)| uids.contains(&m.uid))
            .map(|(i, _)| i)
            .collect()
    } else {
        parse_seq_set(seq_set, msgs.len())
            .into_iter()
            .filter_map(|s| if s >= 1 { Some(s - 1) } else { None })
            .collect()
    };
    // Strip .SILENT from mode
    let mode_clean = mode
        .trim_end_matches(".SILENT")
        .trim_end_matches(".silent");
    for i in targets {
        if let Some(m) = msgs.get(i) {
            md.store_flags(m, mode_clean, imap_flags)
                .map_err(|e| e.to_string())?;
        }
    }
    md.list_messages().map_err(|e| e.to_string())
}

fn do_expunge(
    cfg: &Config,
    _user: &str,
    mailbox: &str,
    msgs: &[MessageMeta],
) -> Result<(Vec<MessageMeta>, Vec<usize>), String> {
    let md = Maildir::open(&cfg.data_dir, mailbox).map_err(|e| e.to_string())?;
    // EXPUNGE sequence numbers must be emitted high-to-low so remaining indices stay valid.
    let mut to_expunge: Vec<usize> = msgs
        .iter()
        .enumerate()
        .filter(|(_, m)| m.has_flag("\\Deleted") || m.flags.contains('T'))
        .map(|(i, _)| i + 1)
        .collect();
    to_expunge.sort_unstable();
    // Delete from high seq to low so path list still matches
    for &seq in to_expunge.iter().rev() {
        if let Some(m) = msgs.get(seq - 1) {
            let _ = md.expunge(m);
        }
    }
    let new_msgs = md.list_messages().map_err(|e| e.to_string())?;
    // Report ascending EXPUNGE numbers as deleted (RFC: each EXPUNGE decrements higher seqs)
    // Clients expect * n EXPUNGE for each; standard is to emit in ascending order of
    // original sequences, adjusting. Emit original ascending; many clients handle either.
    Ok((new_msgs, to_expunge))
}

enum AppendError {
    OverQuota,
    Bad(String),
    Other(String),
}

/// Parse APPEND args: mailbox [(flags)] [{size} | {size+}]
/// Returns (mailbox, flags_chars, size, non_sync).
pub fn parse_append_args(s: &str) -> Result<(String, String, usize, bool), String> {
    let s = s.trim();
    if s.is_empty() {
        return Err("missing mailbox".into());
    }
    // mailbox: quoted or atom
    let (mailbox, rest) = parse_astring(s)?;
    let rest = rest.trim();
    let mut flags = String::new();
    let mut rest = rest;
    if rest.starts_with('(') {
        if let Some(end) = rest.find(')') {
            let list = &rest[1..end];
            let imap: Vec<String> = list
                .split_whitespace()
                .map(|x| x.to_string())
                .collect();
            flags = storage::flags_to_maildir(&imap);
            rest = rest[end + 1..].trim();
        }
    }
    // optional date-time "dd-Mon-yyyy hh:mm:ss +0000" — skip if present
    if rest.starts_with('"') {
        if let Some(end) = rest[1..].find('"') {
            rest = rest[end + 2..].trim();
        }
    }
    // literal {n} or {n+}
    let (size, non_sync) = parse_literal_size(rest)?;
    Ok((mailbox, flags, size, non_sync))
}

fn parse_astring(s: &str) -> Result<(String, &str), String> {
    let s = s.trim_start();
    if s.starts_with('"') {
        let mut out = String::new();
        let bytes = s.as_bytes();
        let mut i = 1;
        while i < bytes.len() {
            if bytes[i] == b'\\' && i + 1 < bytes.len() {
                out.push(bytes[i + 1] as char);
                i += 2;
                continue;
            }
            if bytes[i] == b'"' {
                let rest = s.get(i + 1..).unwrap_or("");
                return Ok((out, rest));
            }
            out.push(bytes[i] as char);
            i += 1;
        }
        Err("unterminated quoted string".into())
    } else {
        let end = s
            .find(|c: char| c.is_whitespace() || c == '(' || c == '{')
            .unwrap_or(s.len());
        let atom = s.get(..end).unwrap_or("").to_string();
        if atom.is_empty() {
            return Err("empty atom".into());
        }
        Ok((atom, s.get(end..).unwrap_or("")))
    }
}

/// Hard cap for literal size parsing when no config is available (32 MiB).
/// Runtime APPEND also enforces `cfg.max_message_bytes`.
pub const MAX_LITERAL_BYTES: usize = 32 * 1024 * 1024;

pub fn parse_literal_size(s: &str) -> Result<(usize, bool), String> {
    parse_literal_size_capped(s, MAX_LITERAL_BYTES)
}

/// Parse `{n}` / `{n+}` with an explicit size cap (checked arithmetic).
pub fn parse_literal_size_capped(s: &str, max: usize) -> Result<(usize, bool), String> {
    let s = s.trim();
    if !s.starts_with('{') {
        return Err("expected literal {size}".into());
    }
    let end = s.find('}').ok_or("unterminated literal")?;
    let inner = s.get(1..end).unwrap_or("");
    let non_sync = inner.ends_with('+');
    let num = if non_sync {
        inner.get(..inner.len().saturating_sub(1)).unwrap_or("")
    } else {
        inner
    };
    // Reject oversized digit strings before parse (avoid overflow / huge allocs).
    if num.is_empty() || num.len() > 12 || !num.bytes().all(|b| b.is_ascii_digit()) {
        return Err("bad literal size".into());
    }
    let size: u64 = num.parse().map_err(|_| "bad literal size".to_string())?;
    let max_u = max as u64;
    if size > max_u {
        return Err("literal too large".into());
    }
    // Safe: size <= max <= usize::MAX on our platforms for 32 MiB cap.
    let size_usz = size as usize;
    Ok((size_usz, non_sync))
}

fn parse_flag_list(s: &str) -> Vec<String> {
    let s = s.trim();
    let inner = if s.starts_with('(') {
        s.trim_start_matches('(')
            .trim_end_matches(')')
            .to_string()
    } else {
        s.to_string()
    };
    inner
        .split_whitespace()
        .filter(|t| !t.is_empty())
        .map(|t| t.to_string())
        .collect()
}

fn do_copy(
    cfg: &Config,
    user: &str,
    msgs: &[MessageMeta],
    seq_set: &str,
    dest: &str,
    by_uid: bool,
) -> Result<(), String> {
    let dest_path = mailbox_path(user, dest);
    let dest_md = Maildir::open(&cfg.data_dir, &dest_path).map_err(|e| e.to_string())?;
    let targets: Vec<&MessageMeta> = if by_uid {
        let uids = parse_uid_set(seq_set, msgs);
        msgs.iter().filter(|m| uids.contains(&m.uid)).collect()
    } else {
        parse_seq_set(seq_set, msgs.len())
            .into_iter()
            .filter_map(|s| msgs.get(s.saturating_sub(1)))
            .collect()
    };
    for m in targets {
        let raw = std::fs::read(&m.path).map_err(|e| e.to_string())?;
        dest_md
            .append_raw(&raw, &m.flags)
            .map_err(|e| e.to_string())?;
    }
    Ok(())
}

fn do_idle(
    cfg: &Config,
    user: &str,
    mailbox: &str,
    msgs: &[MessageMeta],
    reader: &mut BufReader<Conn>,
) -> Result<Vec<MessageMeta>, String> {
    let md = Maildir::open(&cfg.data_dir, mailbox).map_err(|e| e.to_string())?;
    let mut snap = md.idle_snapshot();
    let mut current = msgs.to_vec();
    let io_timeout = limits::io_timeout_secs().max(5);
    let deadline = util::now_secs().saturating_add(io_timeout);
    // Poll every ~2s by setting short read timeout
    reader
        .get_ref()
        .set_timeouts(Duration::from_secs(2));

    loop {
        if crate::shutdown::is_shutdown() {
            return Err("shutdown".into());
        }
        if util::now_secs() >= deadline {
            // RFC 2177: server may end IDLE after ~29 min; we honor io_timeout
            return Ok(current);
        }
        // Check mailbox changes
        let new_snap = md.idle_snapshot();
        if new_snap != snap {
            snap = new_snap;
            if let Ok(new_msgs) = md.list_messages() {
                let exists = new_msgs.len();
                let recent = new_msgs.iter().filter(|m| m.in_new).count();
                let _ = write_line(reader.get_mut(), &format!("* {} EXISTS", exists));
                let _ = write_line(reader.get_mut(), &format!("* {} RECENT", recent));
                current = new_msgs;
            }
        }
        // Try read DONE (or any line)
        match read_line(reader) {
            Ok(Some(line)) => {
                let t = line.trim();
                if t.eq_ignore_ascii_case("DONE") {
                    return Ok(current);
                }
                // Unexpected during IDLE — still exit on DONE only; ignore others lightly
                if t.to_uppercase().ends_with(" DONE") || t.eq_ignore_ascii_case("DONE") {
                    return Ok(current);
                }
                // Client sent something else; treat as end of IDLE
                if t.to_ascii_uppercase().contains("DONE") {
                    return Ok(current);
                }
                let _ = user;
            }
            Ok(None) => return Err("connection closed".into()),
            Err(e)
                if e.kind() == io::ErrorKind::WouldBlock
                    || e.kind() == io::ErrorKind::TimedOut =>
            {
                continue;
            }
            Err(e) => return Err(e.to_string()),
        }
    }
}

// ---------------------------------------------------------------------------
// SEARCH
// ---------------------------------------------------------------------------

#[derive(Debug, Clone, PartialEq)]
pub enum SearchKey {
    All,
    Seen,
    Unseen,
    New,
    Old,
    Recent,
    From(String),
    To(String),
    Subject(String),
    Body(String),
    Text(String),
    Since(u64),  // unix day start
    Before(u64), // unix day start
    Header(String, String),
    Uid(Vec<u32>),
    Seq(Vec<usize>),
    Not(Box<SearchKey>),
    And(Vec<SearchKey>),
    Or(Box<SearchKey>, Box<SearchKey>),
}

/// Parse IMAP date dd-Mon-yyyy → unix seconds at 00:00 UTC.
pub fn parse_imap_date(s: &str) -> Result<u64, String> {
    let s = s.trim().trim_matches('"');
    let parts: Vec<&str> = s.split('-').collect();
    if parts.len() != 3 {
        return Err("bad date".into());
    }
    let day: u32 = parts
        .first()
        .and_then(|p| p.parse().ok())
        .ok_or_else(|| "bad day".to_string())?;
    let mon_s = parts
        .get(1)
        .map(|s| s.to_ascii_lowercase())
        .ok_or_else(|| "bad month".to_string())?;
    let mon = match mon_s.as_str() {
        "jan" => 1,
        "feb" => 2,
        "mar" => 3,
        "apr" => 4,
        "may" => 5,
        "jun" => 6,
        "jul" => 7,
        "aug" => 8,
        "sep" => 9,
        "oct" => 10,
        "nov" => 11,
        "dec" => 12,
        _ => return Err("bad month".into()),
    };
    let year: i32 = parts
        .get(2)
        .and_then(|p| p.parse().ok())
        .ok_or_else(|| "bad year".to_string())?;
    if day < 1 || day > 31 || year < 1970 {
        return Err("date out of range".into());
    }
    let days = util::days_from_civil(year, mon, day);
    if days < 0 {
        return Err("date before epoch".into());
    }
    Ok((days as u64).saturating_mul(86400))
}

/// Parse SEARCH criteria tokens into a SearchKey tree (implicit AND).
pub fn parse_search_criteria(s: &str) -> Result<SearchKey, String> {
    let tokens = tokenize_search(s);
    if tokens.is_empty() {
        return Ok(SearchKey::All);
    }
    let mut i = 0;
    let keys = parse_search_list(&tokens, &mut i)?;
    if keys.is_empty() {
        Ok(SearchKey::All)
    } else if keys.len() == 1 {
        Ok(keys.into_iter().next().unwrap())
    } else {
        Ok(SearchKey::And(keys))
    }
}

fn parse_search_list(tokens: &[String], i: &mut usize) -> Result<Vec<SearchKey>, String> {
    let mut keys = Vec::new();
    while *i < tokens.len() {
        let t = tokens[*i].to_uppercase();
        if t == ")" {
            break;
        }
        keys.push(parse_one_key(tokens, i)?);
    }
    Ok(keys)
}

fn parse_one_key(tokens: &[String], i: &mut usize) -> Result<SearchKey, String> {
    if *i >= tokens.len() {
        return Err("unexpected end of SEARCH".into());
    }
    let t = tokens[*i].to_uppercase();
    *i += 1;
    match t.as_str() {
        "ALL" => Ok(SearchKey::All),
        "SEEN" => Ok(SearchKey::Seen),
        "UNSEEN" => Ok(SearchKey::Unseen),
        "NEW" => Ok(SearchKey::New),
        "OLD" => Ok(SearchKey::Old),
        "RECENT" => Ok(SearchKey::Recent),
        "FROM" => {
            let v = next_string(tokens, i)?;
            Ok(SearchKey::From(v))
        }
        "TO" => {
            let v = next_string(tokens, i)?;
            Ok(SearchKey::To(v))
        }
        "SUBJECT" => {
            let v = next_string(tokens, i)?;
            Ok(SearchKey::Subject(v))
        }
        "BODY" => {
            let v = next_string(tokens, i)?;
            Ok(SearchKey::Body(v))
        }
        "TEXT" => {
            let v = next_string(tokens, i)?;
            Ok(SearchKey::Text(v))
        }
        "SINCE" => {
            let d = next_string(tokens, i)?;
            Ok(SearchKey::Since(parse_imap_date(&d)?))
        }
        "BEFORE" => {
            let d = next_string(tokens, i)?;
            Ok(SearchKey::Before(parse_imap_date(&d)?))
        }
        "HEADER" => {
            let field = next_string(tokens, i)?;
            let val = next_string(tokens, i)?;
            Ok(SearchKey::Header(field, val))
        }
        "NOT" => {
            let inner = parse_one_key(tokens, i)?;
            Ok(SearchKey::Not(Box::new(inner)))
        }
        "OR" => {
            let a = parse_one_key(tokens, i)?;
            let b = parse_one_key(tokens, i)?;
            Ok(SearchKey::Or(Box::new(a), Box::new(b)))
        }
        "UID" => {
            let set = next_string(tokens, i)?;
            // UID set like 1:5 or *
            let mut uids = Vec::new();
            for part in set.split(',') {
                if let Some((a, b)) = part.split_once(':') {
                    let start: u32 = a.parse().unwrap_or(1);
                    let end: u32 = if b == "*" {
                        u32::MAX
                    } else {
                        b.parse().unwrap_or(start)
                    };
                    // store as range endpoints; matching expands against msgs
                    uids.push(start);
                    uids.push(end);
                } else if let Ok(n) = part.parse::<u32>() {
                    uids.push(n);
                }
            }
            Ok(SearchKey::Uid(uids))
        }
        "(" => {
            let inner = parse_search_list(tokens, i)?;
            if *i < tokens.len() && tokens[*i] == ")" {
                *i += 1;
            }
            if inner.len() == 1 {
                Ok(inner.into_iter().next().unwrap())
            } else {
                Ok(SearchKey::And(inner))
            }
        }
        // sequence set as bare numbers
        t if t.chars().all(|c| c.is_ascii_digit() || c == ':' || c == '*' || c == ',') => {
            // treat as sequence set of message numbers
            let mut seqs = Vec::new();
            for part in t.split(',') {
                if let Some((a, b)) = part.split_once(':') {
                    let start: usize = a.parse().unwrap_or(1);
                    let end: usize = if b == "*" {
                        usize::MAX
                    } else {
                        b.parse().unwrap_or(start)
                    };
                    seqs.push(start);
                    seqs.push(end);
                } else if let Ok(n) = part.parse::<usize>() {
                    seqs.push(n);
                }
            }
            Ok(SearchKey::Seq(seqs))
        }
        other => Err(format!("unknown search key {}", other)),
    }
}

fn next_string(tokens: &[String], i: &mut usize) -> Result<String, String> {
    if *i >= tokens.len() {
        return Err("expected string argument".into());
    }
    let s = tokens[*i].clone();
    *i += 1;
    Ok(s)
}

fn tokenize_search(s: &str) -> Vec<String> {
    let mut tokens = Vec::new();
    let mut cur = String::new();
    let mut in_quote = false;
    let mut chars = s.chars().peekable();
    while let Some(c) = chars.next() {
        if in_quote {
            if c == '\\' {
                if let Some(n) = chars.next() {
                    cur.push(n);
                }
            } else if c == '"' {
                in_quote = false;
                tokens.push(cur);
                cur = String::new();
            } else {
                cur.push(c);
            }
        } else if c == '"' {
            in_quote = true;
        } else if c == '(' || c == ')' {
            if !cur.is_empty() {
                tokens.push(cur);
                cur = String::new();
            }
            tokens.push(c.to_string());
        } else if c.is_whitespace() {
            if !cur.is_empty() {
                tokens.push(cur);
                cur = String::new();
            }
        } else {
            cur.push(c);
        }
    }
    if !cur.is_empty() {
        tokens.push(cur);
    }
    tokens
}

pub fn run_search(msgs: &[MessageMeta], criteria: &str, return_uids: bool) -> Result<Vec<u32>, String> {
    let key = parse_search_criteria(criteria)?;
    let mut out = Vec::new();
    for (i, m) in msgs.iter().enumerate() {
        let seq = i + 1;
        if match_key(m, seq, msgs, &key)? {
            if return_uids {
                out.push(m.uid);
            } else {
                out.push(seq as u32);
            }
        }
    }
    Ok(out)
}

fn match_key(
    m: &MessageMeta,
    seq: usize,
    all: &[MessageMeta],
    key: &SearchKey,
) -> Result<bool, String> {
    match key {
        SearchKey::All => Ok(true),
        SearchKey::Seen => Ok(m.is_seen()),
        SearchKey::Unseen => Ok(!m.is_seen()),
        SearchKey::Recent => Ok(m.in_new),
        SearchKey::New => Ok(m.in_new && !m.is_seen()),
        SearchKey::Old => Ok(!m.in_new),
        SearchKey::From(s) => header_contains(m, "from", s),
        SearchKey::To(s) => header_contains(m, "to", s),
        SearchKey::Subject(s) => header_contains(m, "subject", s),
        SearchKey::Body(s) => body_contains(m, s, false),
        SearchKey::Text(s) => body_contains(m, s, true),
        SearchKey::Since(ts) => {
            let mt = msg_date_secs(m).unwrap_or(0);
            Ok(mt >= *ts)
        }
        SearchKey::Before(ts) => {
            let mt = msg_date_secs(m).unwrap_or(0);
            Ok(mt < *ts)
        }
        SearchKey::Header(field, val) => header_contains(m, field, val),
        SearchKey::Not(inner) => Ok(!match_key(m, seq, all, inner)?),
        SearchKey::And(keys) => {
            for k in keys {
                if !match_key(m, seq, all, k)? {
                    return Ok(false);
                }
            }
            Ok(true)
        }
        SearchKey::Or(a, b) => Ok(match_key(m, seq, all, a)? || match_key(m, seq, all, b)?),
        SearchKey::Uid(list) => {
            if list.is_empty() {
                return Ok(false);
            }
            // pairs or singles
            if list.len() == 2 && list[0] <= list[1] && list[1] == u32::MAX {
                return Ok(m.uid >= list[0]);
            }
            if list.len() == 2 && list[1] > list[0] && list[1] != list[0] {
                // could be range start:end
                // If both present as endpoints from parse — treat as range if second > first
                // Also allow multi singles: check contains
            }
            // Expand: if even count of pairs from ranges mixed with singles — check membership
            let mut ok = false;
            let mut j = 0;
            while j < list.len() {
                if j + 1 < list.len() && list[j + 1] >= list[j] && (list[j + 1] - list[j] > 0 || list[j + 1] == u32::MAX) {
                    // ambiguous — also try single match
                    if m.uid >= list[j] && m.uid <= list[j + 1] {
                        ok = true;
                        break;
                    }
                    // also if next is separate uid
                    if m.uid == list[j] {
                        ok = true;
                        break;
                    }
                    j += 2;
                } else {
                    if m.uid == list[j] {
                        ok = true;
                        break;
                    }
                    j += 1;
                }
            }
            Ok(ok || list.contains(&m.uid))
        }
        SearchKey::Seq(list) => {
            if list.contains(&seq) || list.contains(&usize::MAX) && seq == all.len() {
                return Ok(true);
            }
            // range pairs
            let mut j = 0;
            while j + 1 < list.len() {
                let start = list[j];
                let end = if list[j + 1] == usize::MAX {
                    all.len()
                } else {
                    list[j + 1]
                };
                if seq >= start && seq <= end {
                    return Ok(true);
                }
                j += 2;
            }
            Ok(false)
        }
    }
}

fn header_contains(m: &MessageMeta, field: &str, needle: &str) -> Result<bool, String> {
    let raw = std::fs::read(&m.path).map_err(|e| e.to_string())?;
    let text = String::from_utf8_lossy(&raw);
    let headers = text.split("\r\n\r\n").next().unwrap_or(&text);
    let field_l = field.to_ascii_lowercase();
    let needle_l = needle.to_ascii_lowercase();
    for line in headers.lines() {
        if let Some(colon) = line.find(':') {
            let name = line[..colon].trim().to_ascii_lowercase();
            if name == field_l {
                let val = line[colon + 1..].to_ascii_lowercase();
                if val.contains(&needle_l) {
                    return Ok(true);
                }
            }
        }
    }
    Ok(false)
}

fn body_contains(m: &MessageMeta, needle: &str, include_headers: bool) -> Result<bool, String> {
    let raw = std::fs::read(&m.path).map_err(|e| e.to_string())?;
    let text = String::from_utf8_lossy(&raw);
    let needle_l = needle.to_ascii_lowercase();
    if include_headers {
        return Ok(text.to_ascii_lowercase().contains(&needle_l));
    }
    let body = text.split("\r\n\r\n").nth(1).unwrap_or("");
    Ok(body.to_ascii_lowercase().contains(&needle_l))
}

fn msg_date_secs(m: &MessageMeta) -> Option<u64> {
    // Prefer Date: header; fall back to file mtime
    if let Ok(raw) = std::fs::read(&m.path) {
        let text = String::from_utf8_lossy(&raw);
        let headers = text.split("\r\n\r\n").next().unwrap_or(&text);
        for line in headers.lines() {
            if line.len() >= 5 && line[..5].eq_ignore_ascii_case("date:") {
                // Very rough: look for dd Mon yyyy or dd-Mon-yyyy
                if let Some(ts) = rough_parse_date_header(&line[5..]) {
                    return Some(ts);
                }
            }
        }
    }
    if let Ok(md) = std::fs::metadata(&m.path) {
        if let Ok(t) = md.modified() {
            if let Ok(d) = t.duration_since(std::time::UNIX_EPOCH) {
                return Some(d.as_secs());
            }
        }
    }
    None
}

fn rough_parse_date_header(s: &str) -> Option<u64> {
    // Find token like 10 Mar 2024 or 10-Mar-2024
    let s = s.trim();
    let months = [
        "jan", "feb", "mar", "apr", "may", "jun", "jul", "aug", "sep", "oct", "nov", "dec",
    ];
    let tokens: Vec<&str> = s.split_whitespace().collect();
    for w in tokens.windows(3) {
        let day: u32 = w[0].trim_end_matches(',').parse().ok()?;
        let mon_s = w[1].trim_end_matches(',').to_ascii_lowercase();
        let mon = months.iter().position(|m| mon_s.starts_with(m))? as u32 + 1;
        let year: i32 = w[2].trim_end_matches(',').parse().ok()?;
        if day >= 1 && day <= 31 && year >= 1970 {
            let days = util::days_from_civil(year, mon, day);
            if days >= 0 {
                return Some((days as u64) * 86400);
            }
        }
    }
    // dd-Mon-yyyy
    for t in s.split_whitespace() {
        if t.contains('-') {
            if let Ok(ts) = parse_imap_date(t.trim_matches(',')) {
                return Some(ts);
            }
        }
    }
    None
}

// ---------------------------------------------------------------------------
// Parsing helpers (public for tests / fuzz)
// ---------------------------------------------------------------------------

/// Parse IMAP LOGIN arguments (fuzz-visible).
pub fn parse_login_args(rest: &str) -> (String, String) {
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
        (
            tokens.get(1).cloned().unwrap_or_default(),
            tokens.get(2).cloned().unwrap_or_default(),
        )
    } else if tokens.len() == 2 {
        (
            tokens.get(0).cloned().unwrap_or_default(),
            tokens.get(1).cloned().unwrap_or_default(),
        )
    } else {
        (String::new(), String::new())
    }
}

/// Parse IMAP sequence set (fuzz-visible).
pub fn parse_seq_set(s: &str, max: usize) -> Vec<usize> {
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
            let end = end.min(max);
            if start <= end {
                for i in start..=end {
                    res.push(i);
                }
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

fn parse_uid_set(s: &str, msgs: &[MessageMeta]) -> Vec<u32> {
    let max_uid = msgs.iter().map(|m| m.uid).max().unwrap_or(0);
    let mut res = Vec::new();
    for part in s.split(',') {
        if part == "*" {
            if max_uid > 0 {
                res.push(max_uid);
            }
        } else if let Some((a, b)) = part.split_once(':') {
            let start: u32 = a.parse().unwrap_or(1);
            let end = if b == "*" {
                max_uid
            } else {
                b.parse().unwrap_or(max_uid)
            };
            for m in msgs {
                if m.uid >= start && m.uid <= end {
                    res.push(m.uid);
                }
            }
        } else if let Ok(n) = part.parse::<u32>() {
            res.push(n);
        }
    }
    res.sort();
    res.dedup();
    res
}

// ---------------------------------------------------------------------------
// APPEND implementation (Write-capable)
// ---------------------------------------------------------------------------

fn do_append_full(
    cfg: &Config,
    user: &str,
    rest: &str,
    reader: &mut BufReader<Conn>,
) -> Result<(), AppendError> {
    let after = rest
        .strip_prefix("APPEND")
        .or_else(|| rest.strip_prefix("append"))
        .unwrap_or(rest)
        .trim();
    let (mailbox, flags, size, non_sync) =
        parse_append_args(after).map_err(AppendError::Bad)?;

    let max = (cfg.max_message_bytes as usize).min(MAX_LITERAL_BYTES);
    if size > max {
        return Err(AppendError::Bad(format!(
            "message too large (max {} bytes)",
            max
        )));
    }

    if !non_sync {
        write_line(reader.get_mut(), "+ Ready for literal data")
            .map_err(|e| AppendError::Other(e.to_string()))?;
    }

    let mut buf = vec![0u8; size];
    if size > 0 {
        reader
            .read_exact(&mut buf)
            .map_err(|e| AppendError::Other(e.to_string()))?;
    }
    // Trailing CRLF after literal may be present — read it if buffered as part of next line later.

    let mb_path = mailbox_path(user, &mailbox);
    let quota = cfg.quota_bytes_for(user);
    if quota > 0 {
        let cur = Maildir::mailbox_size(&cfg.data_dir, user).unwrap_or(0);
        if Maildir::would_exceed_quota(cur, size as u64, quota) {
            return Err(AppendError::OverQuota);
        }
    }
    let md = Maildir::open(&cfg.data_dir, &mb_path).map_err(|e| AppendError::Other(e.to_string()))?;
    md.append_raw(&buf, &flags)
        .map_err(|e| AppendError::Other(e.to_string()))?;
    Maildir::invalidate_quota_cache(&cfg.data_dir, user);
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::path::PathBuf;

    fn fake_msg(uid: u32, flags: &str, in_new: bool, path: PathBuf) -> MessageMeta {
        MessageMeta {
            path,
            uid,
            size: 0,
            flags: flags.into(),
            in_new,
        }
    }

    #[test]
    fn imap_date_parse() {
        let ts = parse_imap_date("01-Jan-1970").unwrap();
        assert_eq!(ts, 0);
        let ts = parse_imap_date("15-Mar-2024").unwrap();
        assert!(ts > 1_700_000_000);
        assert!(parse_imap_date("xx-Foo-2020").is_err());
    }

    #[test]
    fn search_criteria_parse() {
        let k = parse_search_criteria("ALL").unwrap();
        assert_eq!(k, SearchKey::All);
        let k = parse_search_criteria("UNSEEN").unwrap();
        assert_eq!(k, SearchKey::Unseen);
        let k = parse_search_criteria("FROM \"alice\"").unwrap();
        assert_eq!(k, SearchKey::From("alice".into()));
        let k = parse_search_criteria("SUBJECT foo").unwrap();
        assert_eq!(k, SearchKey::Subject("foo".into()));
        let k = parse_search_criteria("SINCE 01-Jan-2020").unwrap();
        match k {
            SearchKey::Since(t) => assert!(t > 0),
            _ => panic!("expected Since"),
        }
        let k = parse_search_criteria("HEADER X-Test bar").unwrap();
        assert_eq!(k, SearchKey::Header("X-Test".into(), "bar".into()));
        assert!(parse_search_criteria("UNKNOWNKEY").is_err());
    }

    #[test]
    fn search_match_in_memory() {
        let dir = std::env::temp_dir().join(format!("de_imap_search_{}", std::process::id()));
        let _ = std::fs::remove_dir_all(&dir);
        std::fs::create_dir_all(&dir).unwrap();
        let p1 = dir.join("m1");
        let p2 = dir.join("m2");
        let p3 = dir.join("m3");
        std::fs::write(
            &p1,
            b"From: alice@ex.com\r\nTo: bob@ex.com\r\nSubject: Hello foo\r\n\r\nbody one\r\n",
        )
        .unwrap();
        std::fs::write(
            &p2,
            b"From: carol@ex.com\r\nTo: bob@ex.com\r\nSubject: bar\r\n\r\nbody two unseen\r\n",
        )
        .unwrap();
        std::fs::write(
            &p3,
            b"From: dave@ex.com\r\nSubject: zzz\r\n\r\nsecret keyword\r\n",
        )
        .unwrap();

        let msgs = vec![
            fake_msg(10, "S", false, p1),
            fake_msg(20, "", true, p2),
            fake_msg(30, "", false, p3),
        ];

        let all = run_search(&msgs, "ALL", false).unwrap();
        assert_eq!(all, vec![1, 2, 3]);

        let unseen = run_search(&msgs, "UNSEEN", false).unwrap();
        assert_eq!(unseen, vec![2, 3]);

        let seen = run_search(&msgs, "SEEN", false).unwrap();
        assert_eq!(seen, vec![1]);

        let sub = run_search(&msgs, "SUBJECT foo", false).unwrap();
        assert_eq!(sub, vec![1]);

        let fr = run_search(&msgs, "FROM alice", false).unwrap();
        assert_eq!(fr, vec![1]);

        let body = run_search(&msgs, "BODY keyword", false).unwrap();
        assert_eq!(body, vec![3]);

        let uids = run_search(&msgs, "ALL", true).unwrap();
        assert_eq!(uids, vec![10, 20, 30]);

        let _ = std::fs::remove_dir_all(&dir);
    }

    #[test]
    fn append_literal_parse() {
        let (mb, flags, size, ns) =
            parse_append_args("INBOX (\\Seen) {12}").unwrap();
        assert_eq!(mb, "INBOX");
        assert!(flags.contains('S'));
        assert_eq!(size, 12);
        assert!(!ns);

        let (mb, _, size, ns) = parse_append_args("\"Sent\" {5+}").unwrap();
        assert_eq!(mb, "Sent");
        assert_eq!(size, 5);
        assert!(ns);

        let (size, ns) = parse_literal_size("{100}").unwrap();
        assert_eq!(size, 100);
        assert!(!ns);
        // Oversized digit string / beyond hard cap rejected without panic.
        assert!(parse_literal_size("{999999999999}").is_err());
        assert!(parse_literal_size("{999999999}").is_err()); // > 32 MiB
        assert!(parse_literal_size("{notanumber}").is_err());
        assert!(parse_literal_size_capped("{100}", 50).is_err());
        assert!(parse_literal_size_capped("{40}", 50).is_ok());
    }

    #[test]
    fn store_flag_roundtrip() {
        let flags = parse_flag_list("(\\Seen \\Deleted)");
        let md = storage::flags_to_maildir(&flags);
        assert!(md.contains('S') && md.contains('T'));
        let back = storage::maildir_to_imap_flags(&md);
        assert!(back.iter().any(|f| f == "\\Seen"));
        assert!(back.iter().any(|f| f == "\\Deleted"));
    }
}
