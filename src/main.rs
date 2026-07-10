//! DesertEmail - minimal email server in pure Rust (std + rustls).
//!
//! Run with: cargo run -- --config config.toml
//! Or release binary.

use std::env;
use std::io::{self, BufRead, Write};
use std::net::TcpListener;
use std::path::Path;
use std::sync::Arc;
use std::thread;

use desertemail::acme;
use desertemail::config::Config;
use desertemail::crypto;
use desertemail::dkim;
use desertemail::imap::ImapServer;
use desertemail::limits;
use desertemail::passwd;
use desertemail::queue;
use desertemail::ratelimit;
use desertemail::shutdown;
use desertemail::smtp::SmtpServer;
use desertemail::tls;
use desertemail::useredit;
use desertemail::util;
use desertemail::web;

fn main() {
    let args: Vec<String> = env::args().collect();
    // First pass: --config may appear anywhere (including after `user ...`).
    let mut config_path = "config.toml".to_string();
    let mut i = 1;
    while i < args.len() {
        if (args[i] == "--config" || args[i] == "-c") && i + 1 < args.len() {
            config_path = args[i + 1].clone();
            i += 1;
        }
        i += 1;
    }

    let mut dkim_dns_domain: Option<String> = None;
    let mut hash_password_mode: Option<Option<String>> = None; // Some(None)=prompt, Some(Some(p))=non-interactive
    let mut user_cmd: Option<UserCmd> = None;
    let mut i = 1;
    while i < args.len() {
        if args[i] == "--config" || args[i] == "-c" {
            if i + 1 < args.len() {
                i += 1; // already applied
            }
        } else if args[i] == "--dkim-dns" {
            if i + 1 < args.len() {
                dkim_dns_domain = Some(args[i + 1].clone());
                i += 1;
            } else {
                eprintln!("Usage: desertemail --dkim-dns <domain>");
                std::process::exit(1);
            }
        } else if args[i] == "--hash-password" {
            if i + 1 < args.len() && !args[i + 1].starts_with('-') {
                hash_password_mode = Some(Some(args[i + 1].clone()));
                i += 1;
            } else {
                hash_password_mode = Some(None);
            }
        } else if args[i] == "user" {
            // desertemail user <add|remove|list|passwd> ...
            user_cmd = Some(parse_user_cmd(&args, i + 1));
            break;
        } else if args[i] == "--help" || args[i] == "-h" {
            print_help();
            return;
        }
        i += 1;
    }

    if let Some(maybe_plain) = hash_password_mode {
        run_hash_password(maybe_plain);
        return;
    }

    if let Some(cmd) = user_cmd {
        run_user_cmd(&config_path, cmd);
        return;
    }

    // Server path only (not user/--hash-password CLI helpers).
    util::log!("desertemail starting");
    shutdown::install_handlers();

    let mut cfg = match Config::load(Path::new(&config_path)) {
        Ok(c) => {
            util::log!("loaded config from {}", config_path);
            c
        }
        Err(e) => {
            util::log!("failed to load config: {} — using defaults + trying example", e);
            match Config::load(Path::new("config.example.toml")) {
                Ok(c) => c,
                Err(_) => Config::default(),
            }
        }
    };

    // Security audit (loud non-fatal warnings)
    cfg.audit();

    // Structured logging mode (text default; json for fail2ban / processors)
    util::set_log_format(&cfg.log_format);

    // Apply runtime limiters from config
    ratelimit::configure_auth(
        cfg.auth_max_failures,
        cfg.auth_window_secs,
        cfg.auth_lockout_secs,
    );
    ratelimit::configure_outbound(cfg.outbound_max_rcpts_per_hour);
    limits::configure(cfg.max_connections, cfg.max_connections_per_ip);
    limits::configure_io_timeout(cfg.io_timeout_secs);

    // Load DKIM private key if configured
    if let Some(ref key_path) = cfg.dkim_key_file.clone() {
        match crypto::RsaKey::from_pem_file(Path::new(key_path)) {
            Ok(key) => {
                util::log!(
                    "DKIM: loaded key from {} (selector={}, {}-bit)",
                    key_path,
                    cfg.dkim_selector,
                    key.k * 8
                );
                cfg.dkim_key = Some(key);
            }
            Err(e) => {
                util::log!(
                    "warning: DKIM key file {} unreadable/unparseable ({}): outbound mail will be unsigned",
                    key_path,
                    e
                );
            }
        }
    }

    if let Some(domain) = dkim_dns_domain {
        print_dkim_dns(&cfg, &domain);
        return;
    }

    // Load TLS server config when both cert and key paths are set.
    let tls_cfg = match (
        cfg.tls_cert_file.as_ref(),
        cfg.tls_key_file.as_ref(),
    ) {
        (Some(cert), Some(key)) => match tls::load_server_config(cert, key) {
            Ok(c) => {
                util::log!("TLS enabled (cert={}, key={})", cert, key);
                Some(c)
            }
            Err(e) => {
                util::log!("warning: TLS disabled — failed to load cert/key: {}", e);
                None
            }
        },
        _ => {
            util::log!("TLS not configured (set tls_cert_file + tls_key_file to enable)");
            None
        }
    };

    let cfg = Arc::new(cfg);

    if let Err(e) = std::fs::create_dir_all(&cfg.data_dir) {
        util::log!("warning: cannot create data_dir {}: {}", cfg.data_dir, e);
    }
    if let Err(e) = std::fs::create_dir_all(format!("{}/queue", cfg.data_dir)) {
        util::log!("warning: cannot create queue dir: {}", e);
    }

    util::log!(
        "domains: {:?} | catch_all={} | data={} | smarthost={:?}",
        cfg.domains,
        cfg.catch_all,
        cfg.data_dir,
        cfg.smarthost
    );

    // Outbound MTA queue worker (MX / smarthost delivery + retries)
    queue::start_worker(Arc::clone(&cfg));

    // Webmail + admin UI (optional; disabled when web_listen is empty)
    if !cfg.web_listen.is_empty() {
        web::start(Arc::clone(&cfg));
    }
    if let Some(ref tc) = tls_cfg {
        if !cfg.web_tls_listen.is_empty() {
            web::start_tls(Arc::clone(&cfg), Arc::clone(tc));
        }
    }

    let smtp_listener = match TcpListener::bind(&cfg.smtp_listen) {
        Ok(l) => l,
        Err(e) => {
            util::log!("FATAL: cannot bind SMTP {}: {}", cfg.smtp_listen, e);
            std::process::exit(1);
        }
    };
    let sub_listener = match TcpListener::bind(&cfg.submission_listen) {
        Ok(l) => l,
        Err(e) => {
            util::log!("FATAL: cannot bind submission {}: {}", cfg.submission_listen, e);
            std::process::exit(1);
        }
    };
    let imap_listener = match TcpListener::bind(&cfg.imap_listen) {
        Ok(l) => l,
        Err(e) => {
            util::log!("FATAL: cannot bind IMAP {}: {}", cfg.imap_listen, e);
            std::process::exit(1);
        }
    };

    let mut handles = Vec::new();

    let cfg1 = Arc::clone(&cfg);
    let tls1 = tls_cfg.clone();
    handles.push(thread::spawn(move || {
        SmtpServer::new(cfg1, false, tls1, false).serve(smtp_listener);
    }));

    let cfg2 = Arc::clone(&cfg);
    let tls2 = tls_cfg.clone();
    handles.push(thread::spawn(move || {
        SmtpServer::new(cfg2, true, tls2, false).serve(sub_listener);
    }));

    let cfg3 = Arc::clone(&cfg);
    let tls3 = tls_cfg.clone();
    handles.push(thread::spawn(move || {
        ImapServer::new(cfg3, tls3, false).serve(imap_listener);
    }));

    // Implicit TLS listeners (only when TLS loaded and listen addr non-empty)
    if let Some(ref tc) = tls_cfg {
        if !cfg.smtps_listen.is_empty() {
            match TcpListener::bind(&cfg.smtps_listen) {
                Ok(l) => {
                    let cfg_s = Arc::clone(&cfg);
                    let tls_s = Some(Arc::clone(tc));
                    handles.push(thread::spawn(move || {
                        // SMTPS: submission semantics over implicit TLS
                        SmtpServer::new(cfg_s, true, tls_s, true).serve(l);
                    }));
                }
                Err(e) => util::log!("warning: cannot bind SMTPS {}: {}", cfg.smtps_listen, e),
            }
        }
        if !cfg.imaps_listen.is_empty() {
            match TcpListener::bind(&cfg.imaps_listen) {
                Ok(l) => {
                    let cfg_i = Arc::clone(&cfg);
                    let tls_i = Some(Arc::clone(tc));
                    handles.push(thread::spawn(move || {
                        ImapServer::new(cfg_i, tls_i, true).serve(l);
                    }));
                }
                Err(e) => util::log!("warning: cannot bind IMAPS {}: {}", cfg.imaps_listen, e),
            }
        }
    }

    // ACME auto-TLS: non-blocking background thread (needs port 80 / web_listen for HTTP-01)
    if cfg.acme {
        util::log!(
            "ACME enabled (directory={}); HTTP-01 via web_listen — port 80 must be reachable",
            cfg.acme_directory
        );
        acme::start_background(Arc::clone(&cfg));
    }

    util::log!("all servers running. SIGTERM/SIGINT (Ctrl-C) for graceful shutdown.");
    util::log!("Tip: use high ports + firewall port-forward, or run as root / with capabilities for 25/587/143.");

    // Wait until shutdown signal, then join listeners (they exit on flag).
    while !shutdown::is_shutdown() {
        thread::sleep(std::time::Duration::from_millis(300));
    }
    util::log!("shutdown requested — stopping listeners (in-flight connections finish shortly)");
    // Give in-flight handlers a short grace period, then exit. We do NOT join the
    // listener threads: they are blocked in TcpListener::accept() and cannot be
    // unblocked by a flag, so join() would hang forever. The outbound queue is
    // already durable on disk, so a clean exit here loses nothing.
    let _ = &handles; // handles intentionally not joined (see above)
    thread::sleep(std::time::Duration::from_secs(2));
    util::log!("desertemail stopped cleanly");
    std::process::exit(0);
}

fn print_help() {
    println!("Usage: desertemail [--config path/to/config.toml]");
    println!("       desertemail --dkim-dns <domain> [--config path]");
    println!("       desertemail --hash-password [plaintext]");
    println!("       desertemail user add <email> [--password <pw>] [--quota <mb>]");
    println!("       desertemail user remove <email>");
    println!("       desertemail user list");
    println!("       desertemail user passwd <email>");
    println!();
    println!("DKIM setup:");
    println!("  1. Generate a key:  openssl genrsa -out dkim.pem 2048");
    println!("  2. Set dkim_key_file / dkim_selector in config.toml");
    println!("  3. Publish DNS:     desertemail --dkim-dns example.com");
    println!("     (TXT at <selector>._domainkey.<domain>)");
    println!();
    println!("Password hashing:");
    println!("  desertemail --hash-password");
    println!("  desertemail --hash-password 'my secret'");
    println!("  Paste the pbkdf2_sha256$... string into [users] in config.toml");
    println!();
    println!("User management (edits config.toml [users]/[quotas] in place):");
    println!("  desertemail user add alice@example.com");
    println!("  desertemail user add bob --password secret --quota 512");
    println!("  desertemail user list");
    println!("  desertemail user passwd alice");
    println!("  desertemail user remove bob");
    println!();
    println!("See config.example.toml and README.md");
}

enum UserCmd {
    Add {
        email: String,
        password: Option<String>,
        quota_mb: Option<u64>,
    },
    Remove {
        email: String,
    },
    List,
    Passwd {
        email: String,
    },
}

fn parse_user_cmd(args: &[String], start: usize) -> UserCmd {
    if start >= args.len() {
        eprintln!("Usage: desertemail user <add|remove|list|passwd> ...");
        std::process::exit(1);
    }
    let sub = args[start].as_str();
    match sub {
        "list" => UserCmd::List,
        "add" => {
            if start + 1 >= args.len() {
                eprintln!("Usage: desertemail user add <email> [--password <pw>] [--quota <mb>]");
                std::process::exit(1);
            }
            let email = args[start + 1].clone();
            let mut password = None;
            let mut quota_mb = None;
            let mut j = start + 2;
            while j < args.len() {
                if args[j] == "--password" && j + 1 < args.len() {
                    password = Some(args[j + 1].clone());
                    j += 2;
                } else if args[j] == "--quota" && j + 1 < args.len() {
                    quota_mb = Some(args[j + 1].parse().unwrap_or(0));
                    j += 2;
                } else if args[j] == "--config" || args[j] == "-c" {
                    j += 2; // already handled for path; skip
                } else {
                    j += 1;
                }
            }
            UserCmd::Add {
                email,
                password,
                quota_mb,
            }
        }
        "remove" | "rm" | "del" => {
            if start + 1 >= args.len() {
                eprintln!("Usage: desertemail user remove <email>");
                std::process::exit(1);
            }
            UserCmd::Remove {
                email: args[start + 1].clone(),
            }
        }
        "passwd" | "password" => {
            if start + 1 >= args.len() {
                eprintln!("Usage: desertemail user passwd <email>");
                std::process::exit(1);
            }
            UserCmd::Passwd {
                email: args[start + 1].clone(),
            }
        }
        _ => {
            eprintln!("Unknown user subcommand: {}", sub);
            eprintln!("Usage: desertemail user <add|remove|list|passwd> ...");
            std::process::exit(1);
        }
    }
}

fn run_user_cmd(config_path: &str, cmd: UserCmd) {
    let path = Path::new(config_path);
    match cmd {
        UserCmd::List => {
            let content = match std::fs::read_to_string(path) {
                Ok(c) => c,
                Err(e) => {
                    eprintln!("error: cannot read {}: {}", config_path, e);
                    std::process::exit(1);
                }
            };
            let names = useredit::list_users(&content);
            if names.is_empty() {
                println!("(no users in {})", config_path);
            } else {
                for n in names {
                    println!("{}", n);
                }
            }
        }
        UserCmd::Add {
            email,
            password,
            quota_mb,
        } => {
            let pw = match password {
                Some(p) => p,
                None => {
                    let p1 = prompt_password("Password: ");
                    let p2 = prompt_password("Confirm:  ");
                    if p1 != p2 {
                        eprintln!("error: passwords do not match");
                        std::process::exit(1);
                    }
                    if p1.is_empty() {
                        eprintln!("error: empty password");
                        std::process::exit(1);
                    }
                    p1
                }
            };
            let email_c = email.clone();
            let pw_c = pw.clone();
            match useredit::edit_file(path, |c| useredit::add_user(c, &email_c, &pw_c)) {
                Ok(_) => println!("user added/updated: {}", email),
                Err(e) => {
                    eprintln!("error: {}", e);
                    std::process::exit(1);
                }
            }
            if let Some(mb) = quota_mb {
                let email_c = email.clone();
                if let Err(e) = useredit::edit_file(path, |c| useredit::set_quota(c, &email_c, mb))
                {
                    eprintln!("warning: user saved but quota failed: {}", e);
                } else {
                    println!("quota set: {} = {} MiB", email, mb);
                }
            }
        }
        UserCmd::Remove { email } => {
            let email_c = email.clone();
            match useredit::edit_file(path, |c| useredit::remove_user(c, &email_c)) {
                Ok(_) => println!("user removed: {}", email),
                Err(e) => {
                    eprintln!("error: {}", e);
                    std::process::exit(1);
                }
            }
        }
        UserCmd::Passwd { email } => {
            let p1 = prompt_password("New password: ");
            let p2 = prompt_password("Confirm:      ");
            if p1 != p2 {
                eprintln!("error: passwords do not match");
                std::process::exit(1);
            }
            if p1.is_empty() {
                eprintln!("error: empty password");
                std::process::exit(1);
            }
            let email_c = email.clone();
            match useredit::edit_file(path, |c| useredit::set_password(c, &email_c, &p1)) {
                Ok(_) => println!("password updated for: {}", email),
                Err(e) => {
                    eprintln!("error: {}", e);
                    std::process::exit(1);
                }
            }
        }
    }
}

fn run_hash_password(maybe_plain: Option<String>) {
    let password = match maybe_plain {
        Some(p) => p,
        None => {
            let p1 = prompt_password("Password: ");
            let p2 = prompt_password("Confirm:  ");
            if p1 != p2 {
                eprintln!("error: passwords do not match");
                std::process::exit(1);
            }
            if p1.is_empty() {
                eprintln!("error: empty password");
                std::process::exit(1);
            }
            p1
        }
    };
    let hashed = passwd::hash_password(&password);
    println!("{}", hashed);
}

fn prompt_password(prompt: &str) -> String {
    eprint!("{}", prompt);
    let _ = io::stderr().flush();
    // Hide echo on Unix via stty (no extra crates).
    #[cfg(unix)]
    let _ = std::process::Command::new("stty")
        .arg("-echo")
        .stdin(std::process::Stdio::inherit())
        .status();
    let mut line = String::new();
    let _ = io::stdin().lock().read_line(&mut line);
    #[cfg(unix)]
    {
        let _ = std::process::Command::new("stty")
            .arg("echo")
            .stdin(std::process::Stdio::inherit())
            .status();
        eprintln!();
    }
    while line.ends_with('\n') || line.ends_with('\r') {
        line.pop();
    }
    line
}

fn print_dkim_dns(cfg: &Config, domain: &str) {
    let key = match cfg.dkim_key.as_ref() {
        Some(k) => k,
        None => {
            eprintln!(
                "No DKIM key loaded. Set dkim_key_file in config, e.g.:\n\
                 dkim_key_file = \"dkim.pem\"\n\
                 Generate with: openssl genrsa -out dkim.pem 2048"
            );
            std::process::exit(1);
        }
    };
    let selector = &cfg.dkim_selector;
    let txt = dkim::dns_txt_record(key);
    println!("Publish this DNS TXT record:");
    println!();
    println!("  Name:  {}._domainkey.{}", selector, domain);
    println!("  Type:  TXT");
    println!("  Value: {}", txt);
    println!();
    println!("(Generate key with: openssl genrsa -out dkim.pem 2048)");
}
