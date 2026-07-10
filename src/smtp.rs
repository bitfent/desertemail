//! Minimal SMTP server from scratch (RFC 5321 subset).
//! Handles inbound delivery + authenticated submission.
//! Pure std.

use std::io;
use std::net::{TcpListener, TcpStream};
use std::sync::Arc;
use std::thread;

use crate::auth;
use crate::config::Config;
use crate::storage::Maildir;
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
}

impl SmtpServer {
    pub fn new(cfg: Arc<Config>, is_submission: bool) -> Self {
        Self { cfg, is_submission }
    }

    pub fn serve(&self, listener: TcpListener) {
        util::log!(
            "SMTP{} listening on {}",
            if self.is_submission { " submission" } else { "" },
            listener.local_addr().unwrap()
        );
        for stream in listener.incoming() {
            match stream {
                Ok(stream) => {
                    let cfg = Arc::clone(&self.cfg);
                    let is_sub = self.is_submission;
                    thread::spawn(move || {
                        if let Err(e) = handle_client(stream, cfg, is_sub) {
                            util::log!("SMTP client error: {}", e);
                        }
                    });
                }
                Err(e) => util::log!("SMTP accept error: {}", e),
            }
        }
    }
}

fn handle_client(mut stream: TcpStream, cfg: Arc<Config>, is_submission: bool) -> io::Result<()> {
    let peer = stream.peer_addr().map(|a| a.to_string()).unwrap_or_else(|_| "?".into());
    util::log!("SMTP connect from {}", peer);

    write_line(&mut stream, "220 desertemail ESMTP ready")?;

    let mut state = State::Init;
    let mut authenticated_user: Option<String> = None;
    let mut data_buf = Vec::new();

    loop {
        let line = match read_line(&mut stream)? {
            Some(l) => l,
            None => break,
        };
        util::log!("SMTP << {}", line);

        let parts: Vec<&str> = line.split_whitespace().collect();
        let cmd = parts.first().map(|s| s.to_uppercase()).unwrap_or_default();

        match (cmd.as_str(), &state) {
            ("EHLO" | "HELO", State::Init | State::Greeted) => {
                let domain = parts.get(1).unwrap_or(&"localhost");
                write_line(&mut stream, &format!("250-desertemail Hello {}", domain))?;
                write_line(&mut stream, "250-AUTH PLAIN LOGIN")?;
                write_line(&mut stream, "250-SIZE 10485760")?;
                write_line(&mut stream, "250-8BITMIME")?;
                write_line(&mut stream, "250 OK")?;
                state = State::Greeted;
            }
            ("AUTH", _) if authenticated_user.is_none() => {
                if parts.len() >= 3 && parts[1].eq_ignore_ascii_case("PLAIN") {
                    if let Some((user, pass)) = auth::decode_plain(parts[2]) {
                        if auth::authenticate(&cfg, &user, &pass) {
                            authenticated_user = Some(user);
                            write_line(&mut stream, "235 Authentication successful")?;
                        } else {
                            write_line(&mut stream, "535 Authentication failed")?;
                        }
                    } else {
                        write_line(&mut stream, "501 Bad AUTH")?;
                    }
                } else if parts.len() == 2 && parts[1].eq_ignore_ascii_case("PLAIN") {
                    write_line(&mut stream, "334 ")?;
                    if let Some(b64) = read_line(&mut stream)? {
                        if let Some((user, pass)) = auth::decode_plain(&b64) {
                            if auth::authenticate(&cfg, &user, &pass) {
                                authenticated_user = Some(user);
                                write_line(&mut stream, "235 Authentication successful")?;
                            } else {
                                write_line(&mut stream, "535 Authentication failed")?;
                            }
                        } else {
                            write_line(&mut stream, "501 Bad AUTH")?;
                        }
                    }
                } else {
                    write_line(&mut stream, "504 AUTH mechanism not available")?;
                }
            }
            ("MAIL", State::Greeted | State::MailFrom { .. } | State::RcptTo { .. }) => {
                if is_submission && authenticated_user.is_none() {
                    write_line(&mut stream, "530 Authentication required")?;
                    continue;
                }
                let from = extract_angle(&line);
                if from.is_empty() {
                    write_line(&mut stream, "501 Bad address")?;
                    continue;
                }
                state = State::MailFrom { from };
                write_line(&mut stream, "250 OK")?;
            }
            ("RCPT", State::MailFrom { from } | State::RcptTo { from, .. }) => {
                let rcpt = extract_angle(&line);
                if rcpt.is_empty() {
                    write_line(&mut stream, "501 Bad address")?;
                    continue;
                }
                let allowed = if is_submission {
                    true
                } else {
                    cfg.resolve_mailbox(&rcpt).is_some()
                };
                if !allowed {
                    write_line(&mut stream, "550 No such user here")?;
                    continue;
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
                    _ => unreachable!(),
                }
                write_line(&mut stream, "250 OK")?;
            }
            ("DATA", State::RcptTo { from, rcpts }) => {
                write_line(&mut stream, "354 End data with <CR><LF>.<CR><LF>")?;
                state = State::Data {
                    from: from.clone(),
                    rcpts: rcpts.clone(),
                };
                data_buf.clear();
                loop {
                    let dline = match read_line(&mut stream)? {
                        Some(l) => l,
                        None => break,
                    };
                    if dline == "." {
                        break;
                    }
                    let content = if dline.starts_with('.') {
                        &dline[1..]
                    } else {
                        &dline
                    };
                    data_buf.extend_from_slice(content.as_bytes());
                    data_buf.extend_from_slice(b"\r\n");
                }
                let delivered = deliver_mail(&cfg, &state, &data_buf, is_submission, &authenticated_user);
                match delivered {
                    Ok(n) => {
                        write_line(&mut stream, &format!("250 OK: queued as {} msgs", n))?;
                    }
                    Err(e) => {
                        util::log!("delivery error: {}", e);
                        write_line(&mut stream, "451 Temporary failure")?;
                    }
                }
                state = State::Greeted;
            }
            ("RSET", _) => {
                state = State::Greeted;
                write_line(&mut stream, "250 OK")?;
            }
            ("NOOP", _) | ("HELP", _) => {
                write_line(&mut stream, "250 OK")?;
            }
            ("QUIT", _) => {
                write_line(&mut stream, "221 Bye")?;
                state = State::Quit;
                break;
            }
            ("VRFY", _) | ("EXPN", _) => {
                write_line(&mut stream, "252 Cannot VRFY")?;
            }
            _ => {
                write_line(&mut stream, "500 Syntax error or bad sequence")?;
            }
        }
        if state == State::Quit {
            break;
        }
    }
    util::log!("SMTP disconnect {}", peer);
    Ok(())
}

fn extract_angle(line: &str) -> String {
    if let Some(start) = line.find('<') {
        if let Some(end) = line[start..].find('>') {
            return line[start + 1..start + end].trim().to_string();
        }
    }
    if let Some(idx) = line.find(':') {
        return line[idx + 1..].trim().trim_matches(|c| c == '<' || c == '>').to_string();
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
        util::log!("submission from {} to {:?}: stored in Sent (full MX send not yet in zero-dep)", from, rcpts);
        for r in rcpts {
            if let Some(mb) = cfg.resolve_mailbox(r) {
                let md = Maildir::open(&cfg.data_dir, &mb).map_err(|e| e.to_string())?;
                md.deliver(raw, from).map_err(|e| e.to_string())?;
                count += 1;
            }
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
        return Err("no local recipients".into());
    }
    Ok(count)
}
