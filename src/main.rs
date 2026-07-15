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
use desertemail::doctor::{self, DoctorOpts};
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
    let mut doctor_opts: Option<DoctorOpts> = None;
    let mut setup_cmd: Option<SetupCmd> = None;
    let mut restore_tar: Option<String> = None;
    let mut restore_force = false;
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
        } else if args[i] == "--restore" {
            if i + 1 < args.len() {
                restore_tar = Some(args[i + 1].clone());
                i += 1;
            } else {
                eprintln!("Usage: desertemail --restore <backup.tar> --config <target-config-path> [--force]");
                std::process::exit(1);
            }
        } else if args[i] == "--force" {
            restore_force = true;
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
        } else if args[i] == "doctor" {
            doctor_opts = Some(parse_doctor_opts(&args, i + 1));
            break;
        } else if args[i] == "setup" {
            setup_cmd = Some(parse_setup_cmd(&args, i + 1));
            break;
        } else if args[i] == "--help" || args[i] == "-h" || args[i] == "help" {
            print_help();
            return;
        }
        i += 1;
    }

    if let Some(tar_path) = restore_tar {
        run_restore(&tar_path, &config_path, restore_force);
        return;
    }

    if let Some(maybe_plain) = hash_password_mode {
        run_hash_password(maybe_plain);
        return;
    }

    if let Some(cmd) = user_cmd {
        run_user_cmd(&config_path, cmd);
        return;
    }

    if let Some(opts) = doctor_opts {
        run_doctor(&config_path, opts);
        return;
    }

    if let Some(cmd) = setup_cmd {
        run_setup_cmd(&config_path, cmd);
        return;
    }

    // Server path only (not user/--hash-password CLI helpers).
    util::log!("desertemail starting");
    shutdown::install_handlers();

    let cfg = match Config::load(Path::new(&config_path)) {
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
    if let Some(key_path) = cfg.dkim_key_file_path() {
        match crypto::RsaKey::from_pem_file(Path::new(&key_path)) {
            Ok(key) => {
                util::log!(
                    "DKIM: loaded key from {} (selector={}, {}-bit)",
                    key_path,
                    cfg.dkim_selector(),
                    key.k * 8
                );
                cfg.set_dkim_live(&cfg.dkim_selector(), Some(key_path), Some(key));
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
        cfg.domains_list(),
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

    // Best-effort automatic router port-forwarding + public-URL discovery so
    // the server is reachable from other machines right away (best-effort;
    // never fatal). Skipped only when auto_port_forward=false (still records
    // LAN URL + guidance in that case).
    desertemail::portmap::start(Arc::clone(&cfg));

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
    println!("       desertemail --restore <backup.tar> --config <target-config-path> [--force]");
    println!("       desertemail user add <email> [--password <pw>] [--quota <mb>]");
    println!("       desertemail user remove <email>");
    println!("       desertemail user list");
    println!("       desertemail user passwd <email> [--password <pw>]");
    println!("       desertemail doctor [--config path] [--domain <d>] [--host <mail.hostname>]");
    println!("                          [--public-ip <ip>] [--json] [--no-net]");
    println!("       desertemail setup                 # status + guided next steps");
    println!("       desertemail setup domain <domain> [--host <mail.hostname>]");
    println!("       desertemail setup dkim [--selector <s>] [--force]");
    println!("       desertemail setup https <domain> --email <email> [--check-only] [--yes]");
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
    println!("Backup restore (from Admin → Download backup, or deploy/backup.sh):");
    println!("  desertemail --restore desertemail-backup-….tar --config /etc/desertemail/config.toml");
    println!("  Adds --force to overwrite an existing config or non-empty data dir.");
    println!();
    println!("User management (edits config.toml [users]/[quotas] in place):");
    println!("  desertemail user add alice@example.com");
    println!("  desertemail user add bob --password 'longer-secret' --quota 512");
    println!("  desertemail user list");
    println!("  desertemail user passwd alice                # prompts; resets existing user");
    println!("  desertemail user passwd alice --password 'new-password'");
    println!("  desertemail user remove bob");
    println!("  Passwords must be at least 8 characters (no other rules).");
    println!();
    println!("Doctor (deployment readiness probe):");
    println!("  desertemail doctor");
    println!("  desertemail doctor --domain example.com --host mail.example.com");
    println!("  desertemail doctor --public-ip 203.0.113.10 --json");
    println!("  desertemail doctor --no-net   # DNS-only (skip TCP probes)");
    println!("  Exit code = number of blockers (Fail checks). 0 = ready.");
    println!();
    println!("Domain & HTTPS setup (SSH-friendly; same edits as the /dns web UI):");
    println!("  desertemail setup                 # where am I? checklist + next commands");
    println!("  desertemail setup domain <domain> [--host <mail.hostname>]");
    println!("  desertemail setup dkim [--selector <s>] [--force]");
    println!("  desertemail setup https <domain> --email <email> [--check-only] [--yes]");
    println!("  Example:");
    println!("    desertemail setup domain example.com --host mail.example.com");
    println!("    desertemail setup dkim");
    println!("    desertemail setup https mail.example.com --email you@example.com");
    println!();
    println!("See config.example.toml and README.md");
}

fn run_restore(tar_path: &str, config_path: &str, force: bool) {
    use desertemail::tarball;
    use std::fs;
    use std::path::PathBuf;

    let tar_bytes = match fs::read(tar_path) {
        Ok(b) => b,
        Err(e) => {
            eprintln!("error: cannot read {}: {}", tar_path, e);
            std::process::exit(1);
        }
    };

    let config_dest = PathBuf::from(config_path);
    let config_dir = config_dest
        .parent()
        .filter(|p| !p.as_os_str().is_empty())
        .map(|p| p.to_path_buf())
        .unwrap_or_else(|| PathBuf::from("."));
    let extras_dir = config_dir.clone();
    let data_dir = config_dir.join("data");

    if config_dest.exists() && !force {
        eprintln!(
            "error: config already exists at {} (pass --force to overwrite)",
            config_dest.display()
        );
        std::process::exit(1);
    }
    if data_dir.exists() {
        let non_empty = fs::read_dir(&data_dir)
            .map(|mut d| d.next().is_some())
            .unwrap_or(false);
        if non_empty && !force {
            eprintln!(
                "error: data dir {} is not empty (pass --force to overwrite)",
                data_dir.display()
            );
            std::process::exit(1);
        }
    }

    if let Err(e) = fs::create_dir_all(&config_dir) {
        eprintln!("error: cannot create {}: {}", config_dir.display(), e);
        std::process::exit(1);
    }
    if let Err(e) = fs::create_dir_all(&data_dir) {
        eprintln!("error: cannot create {}: {}", data_dir.display(), e);
        std::process::exit(1);
    }

    let summary = match tarball::extract_backup(&tar_bytes, &config_dest, &extras_dir, &data_dir) {
        Ok(s) => s,
        Err(e) => {
            eprintln!("error: restore failed: {}", e);
            std::process::exit(1);
        }
    };

    // Rewrite data_dir in restored config to the new location.
    let mut adjustments = Vec::new();
    match fs::read_to_string(&config_dest) {
        Ok(content) => {
            let new_data = data_dir.display().to_string();
            let rewritten = rewrite_config_data_dir(&content, &new_data);
            if rewritten != content {
                if let Err(e) = fs::write(&config_dest, &rewritten) {
                    eprintln!("error: cannot rewrite config: {}", e);
                    std::process::exit(1);
                }
                adjustments.push(format!("data_dir → {}", new_data));
            } else {
                // Ensure data_dir line exists / points correctly even if key missing.
                adjustments.push(format!("data_dir set to {}", new_data));
                if !content.lines().any(|l| {
                    let t = l.trim();
                    t.starts_with("data_dir") && t.contains('=')
                }) {
                    let mut c = content;
                    if !c.ends_with('\n') {
                        c.push('\n');
                    }
                    c.push_str(&format!("data_dir = \"{}\"\n", new_data));
                    let _ = fs::write(&config_dest, c);
                } else {
                    let forced = rewrite_config_data_dir_force(&content, &new_data);
                    let _ = fs::write(&config_dest, forced);
                }
            }
        }
        Err(e) => {
            eprintln!("error: restored config unreadable: {}", e);
            std::process::exit(1);
        }
    }

    // Point relative dkim/tls paths at extras next to config when those files landed there.
    println!("Restored {} files ({} bytes)", summary.files, summary.bytes);
    println!("  config: {}", config_dest.display());
    println!("  data:   {}", data_dir.display());
    println!("  extras: {} (DKIM/TLS basenames if present)", extras_dir.display());
    for a in &adjustments {
        println!("  adjusted: {}", a);
    }
    println!();
    println!("Start with: desertemail --config {}", config_dest.display());
}

/// Replace `data_dir = "..."` with a new path (preserves quoting style loosely).
fn rewrite_config_data_dir(content: &str, new_path: &str) -> String {
    let mut out = String::new();
    for line in content.lines() {
        let trimmed = line.trim();
        if trimmed.starts_with("data_dir") && trimmed.contains('=') && !trimmed.starts_with('#') {
            out.push_str(&format!("data_dir = \"{}\"", new_path));
        } else {
            out.push_str(line);
        }
        out.push('\n');
    }
    out
}

fn rewrite_config_data_dir_force(content: &str, new_path: &str) -> String {
    rewrite_config_data_dir(content, new_path)
}

fn parse_doctor_opts(args: &[String], start: usize) -> DoctorOpts {
    let mut opts = DoctorOpts::default();
    let mut domains: Vec<String> = Vec::new();
    let mut i = start;
    while i < args.len() {
        if (args[i] == "--config" || args[i] == "-c") && i + 1 < args.len() {
            i += 2; // already applied globally
        } else if args[i] == "--domain" && i + 1 < args.len() {
            domains.push(args[i + 1].clone());
            i += 2;
        } else if args[i] == "--host" && i + 1 < args.len() {
            opts.host = Some(args[i + 1].clone());
            i += 2;
        } else if args[i] == "--public-ip" && i + 1 < args.len() {
            opts.public_ip = Some(args[i + 1].clone());
            i += 2;
        } else if args[i] == "--json" {
            opts.json = true;
            i += 1;
        } else if args[i] == "--no-net" {
            opts.no_net = true;
            i += 1;
        } else if args[i] == "--help" || args[i] == "-h" {
            print_help();
            std::process::exit(0);
        } else {
            eprintln!("Unknown doctor option: {}", args[i]);
            eprintln!(
                "Usage: desertemail doctor [--config path] [--domain <d>] [--host <h>] [--public-ip <ip>] [--json] [--no-net]"
            );
            std::process::exit(1);
        }
    }
    if !domains.is_empty() {
        opts.domains = Some(domains);
    }
    opts
}

fn run_doctor(config_path: &str, opts: DoctorOpts) {
    let cfg = match Config::load(Path::new(config_path)) {
        Ok(c) => c,
        Err(e) => {
            // Fall back like the server path, but prefer explicit failure when domains overridden.
            eprintln!("warning: cannot load {}: {} — trying defaults", config_path, e);
            match Config::load(Path::new("config.example.toml")) {
                Ok(c) => c,
                Err(_) => Config::default(),
            }
        }
    };
    // Load DKIM key if configured (doctor compares published p= against this key).
    if let Some(key_path) = cfg.dkim_key_file_path() {
        match crypto::RsaKey::from_pem_file(Path::new(&key_path)) {
            Ok(key) => cfg.set_dkim_live(&cfg.dkim_selector(), Some(key_path.clone()), Some(key)),
            Err(e) => {
                eprintln!(
                    "warning: DKIM key file {} unreadable ({}): DKIM check will warn",
                    key_path, e
                );
            }
        }
    }
    let code = doctor::run(&cfg, &opts);
    std::process::exit(code);
}

enum SetupCmd {
    Status,
    Domain {
        domain: String,
        host: Option<String>,
    },
    Dkim {
        selector: Option<String>,
        force: bool,
    },
    Https {
        domain: String,
        email: String,
        check_only: bool,
        yes: bool,
    },
}

fn parse_setup_cmd(args: &[String], start: usize) -> SetupCmd {
    // Bare `setup` (or `setup status`): show the guided checklist.
    if start >= args.len() {
        return SetupCmd::Status;
    }
    let sub = args[start].as_str();
    match sub {
        "status" => SetupCmd::Status,
        "domain" => {
            if start + 1 >= args.len() || args[start + 1].starts_with('-') {
                eprintln!("Usage: desertemail setup domain <domain> [--host <mail.hostname>] [--config path]");
                std::process::exit(1);
            }
            let domain = args[start + 1].clone();
            let mut host = None;
            let mut j = start + 2;
            while j < args.len() {
                if args[j] == "--host" && j + 1 < args.len() {
                    host = Some(args[j + 1].clone());
                    j += 2;
                } else if args[j] == "--config" || args[j] == "-c" {
                    j += 2;
                } else if args[j] == "--help" || args[j] == "-h" {
                    print_help();
                    std::process::exit(0);
                } else {
                    eprintln!("Unknown setup domain option: {}", args[j]);
                    eprintln!(
                        "Usage: desertemail setup domain <domain> [--host <mail.hostname>] [--config path]"
                    );
                    std::process::exit(1);
                }
            }
            SetupCmd::Domain { domain, host }
        }
        "dkim" => {
            let mut selector = None;
            let mut force = false;
            let mut j = start + 1;
            while j < args.len() {
                if args[j] == "--selector" && j + 1 < args.len() {
                    selector = Some(args[j + 1].clone());
                    j += 2;
                } else if args[j] == "--force" {
                    force = true;
                    j += 1;
                } else if args[j] == "--config" || args[j] == "-c" {
                    j += 2;
                } else if args[j] == "--help" || args[j] == "-h" {
                    print_help();
                    std::process::exit(0);
                } else {
                    eprintln!("Unknown setup dkim option: {}", args[j]);
                    eprintln!(
                        "Usage: desertemail setup dkim [--selector <s>] [--force] [--config path]"
                    );
                    std::process::exit(1);
                }
            }
            SetupCmd::Dkim { selector, force }
        }
        "https" => {
            if start + 1 >= args.len() || args[start + 1].starts_with('-') {
                eprintln!(
                    "Usage: desertemail setup https <domain> --email <email> [--check-only] [--yes] [--config path]"
                );
                std::process::exit(1);
            }
            let domain = args[start + 1].clone();
            let mut email = None;
            let mut check_only = false;
            let mut yes = false;
            let mut j = start + 2;
            while j < args.len() {
                if args[j] == "--email" && j + 1 < args.len() {
                    email = Some(args[j + 1].clone());
                    j += 2;
                } else if args[j] == "--check-only" {
                    check_only = true;
                    j += 1;
                } else if args[j] == "--yes" || args[j] == "-y" {
                    yes = true;
                    j += 1;
                } else if args[j] == "--config" || args[j] == "-c" {
                    j += 2;
                } else if args[j] == "--help" || args[j] == "-h" {
                    print_help();
                    std::process::exit(0);
                } else {
                    eprintln!("Unknown setup https option: {}", args[j]);
                    eprintln!(
                        "Usage: desertemail setup https <domain> --email <email> [--check-only] [--yes] [--config path]"
                    );
                    std::process::exit(1);
                }
            }
            let email = match email {
                Some(e) if !e.trim().is_empty() => e,
                _ => {
                    eprintln!("error: --email is required for Let's Encrypt account contact");
                    eprintln!(
                        "Usage: desertemail setup https <domain> --email <email> [--check-only] [--yes]"
                    );
                    std::process::exit(1);
                }
            };
            SetupCmd::Https {
                domain,
                email,
                check_only,
                yes,
            }
        }
        // `setup --config path` / `setup -c path`: config was already applied
        // in the global pass — treat as bare `setup` (status).
        "--config" | "-c" => SetupCmd::Status,
        _ => {
            eprintln!("Unknown setup subcommand: {}", sub);
            eprintln!();
            eprintln!("Usage: desertemail setup                 # show status + next steps");
            eprintln!("       desertemail setup domain <domain> [--host <mail.hostname>]");
            eprintln!("       desertemail setup dkim [--selector <s>] [--force]");
            eprintln!("       desertemail setup https <domain> --email <email> [--check-only] [--yes]");
            std::process::exit(1);
        }
    }
}

fn run_setup_cmd(config_path: &str, cmd: SetupCmd) {
    let path = Path::new(config_path);
    match cmd {
        SetupCmd::Status => run_setup_status(path),
        SetupCmd::Domain { domain, host } => run_setup_domain(path, &domain, host.as_deref()),
        SetupCmd::Dkim { selector, force } => {
            run_setup_dkim(path, selector.as_deref(), force)
        }
        SetupCmd::Https {
            domain,
            email,
            check_only,
            yes,
        } => run_setup_https(path, &domain, &email, check_only, yes),
    }
}

/// `desertemail setup` with no subcommand: guided checklist for an SSH session.
/// Shows what is already configured, what is missing, and the exact commands
/// (with the right --config path) to finish, in order.
fn run_setup_status(config_path: &Path) {
    use std::io::IsTerminal;
    let color = std::env::var_os("NO_COLOR").is_none() && io::stdout().is_terminal();
    let mark = |done: bool| -> String {
        match (done, color) {
            (true, true) => "\x1b[32m✓\x1b[0m".into(),
            (true, false) => "[x]".into(),
            (false, true) => "\x1b[33m·\x1b[0m".into(),
            (false, false) => "[ ]".into(),
        }
    };
    let cfg_disp = config_path.display();

    println!("DesertEmail setup — status & next steps");
    println!();

    if !config_path.is_file() {
        println!("  {} config file: {} not found", mark(false), cfg_disp);
        println!();
        println!("No config yet. Either run the installer, or create one from the example:");
        println!("  cp config.example.toml config.toml && desertemail setup");
        println!("Point at an existing config with: desertemail setup --config /path/to/config.toml");
        std::process::exit(1);
    }

    let cfg = load_cfg_or_exit(config_path);

    // --- Gather state -----------------------------------------------------
    let domain = cfg.primary_domain();
    let domain_ok = !domain.is_empty() && domain != "localhost";
    let host = cfg.public_host_name();
    let users = cfg.user_names();
    let users_ok = !users.is_empty();
    let admin = cfg.admin_user_name().unwrap_or_default();
    let dkim_ok = cfg
        .dkim_key_file_path()
        .map(|p| Path::new(&p).is_file())
        .unwrap_or(false);
    let cert_ok = cfg
        .tls_cert_file
        .as_ref()
        .map(|p| Path::new(p).is_file())
        .unwrap_or(false);
    let https_ok = cfg.acme || cert_ok;
    let public_url = cfg.public_url_get();

    // --- Checklist ---------------------------------------------------------
    println!("  {} config file:  {}", mark(true), cfg_disp);
    if domain_ok {
        let host_note = if host.is_empty() {
            String::new()
        } else {
            format!("  (mail host: {})", host)
        };
        println!("  {} domain:       {}{}", mark(true), domain, host_note);
    } else {
        println!("  {} domain:       not set (still \"{}\")", mark(false), domain);
    }
    if users_ok {
        let admin_note = if admin.is_empty() {
            "no admin_user".to_string()
        } else {
            format!("admin: {}", admin)
        };
        println!(
            "  {} users:        {} user(s), {}",
            mark(true),
            users.len(),
            admin_note
        );
    } else {
        println!("  {} users:        none yet", mark(false));
    }
    if dkim_ok {
        println!(
            "  {} DKIM key:     {} (selector {})",
            mark(true),
            cfg.dkim_key_file_path().unwrap_or_default(),
            cfg.dkim_selector()
        );
    } else {
        println!("  {} DKIM key:     not generated", mark(false));
    }
    if https_ok {
        let detail = match (cfg.acme, cert_ok) {
            (true, true) => format!(
                "ACME on, cert at {}",
                cfg.tls_cert_file.as_deref().unwrap_or("")
            ),
            (true, false) => "ACME on, waiting for first certificate".to_string(),
            (false, _) => format!(
                "cert file {}",
                cfg.tls_cert_file.as_deref().unwrap_or("")
            ),
        };
        println!("  {} HTTPS:        {}", mark(cert_ok), detail);
    } else {
        println!("  {} HTTPS:        not configured (plain HTTP)", mark(false));
    }
    if !public_url.is_empty() {
        println!("  {} public URL:   {}", mark(true), public_url);
    }

    // --- Next steps (only what is missing, in order) ------------------------
    let mut steps: Vec<String> = Vec::new();
    if !domain_ok {
        steps.push(format!(
            "desertemail setup domain example.com --host mail.example.com -c {}",
            cfg_disp
        ));
    }
    if !users_ok {
        steps.push(format!(
            "desertemail user add you@{} -c {}",
            if domain_ok { domain.as_str() } else { "example.com" },
            cfg_disp
        ));
    }
    if !dkim_ok {
        steps.push(format!("desertemail setup dkim -c {}", cfg_disp));
    }
    if !https_ok {
        steps.push(format!(
            "desertemail setup https {} --email you@{} -c {}",
            if host.is_empty() {
                if domain_ok { domain.as_str() } else { "mail.example.com" }
            } else {
                host.as_str()
            },
            if domain_ok { domain.as_str() } else { "example.com" },
            cfg_disp
        ));
    }

    println!();
    if steps.is_empty() {
        println!("All set. Verify DNS and deliverability with:");
        println!("  desertemail doctor -c {}", cfg_disp);
        if cfg.acme && !cert_ok {
            println!();
            println!("ACME is enabled but no certificate yet — make sure port 80 is reachable");
            println!("and (re)start the server so the ACME worker can request it:");
            println!("  desertemail -c {}", cfg_disp);
        }
    } else {
        println!("Next steps (in order):");
        for (i, s) in steps.iter().enumerate() {
            println!("  {}. {}", i + 1, s);
        }
        println!();
        println!("Then check readiness:  desertemail doctor -c {}", cfg_disp);
    }
    println!();
    println!("All commands: desertemail --help   ·   web UI equivalent: http://<host>:8080/dns");
}

fn load_cfg_or_exit(config_path: &Path) -> Config {
    match Config::load(config_path) {
        Ok(c) => c,
        Err(e) => {
            eprintln!("error: cannot load {}: {}", config_path.display(), e);
            std::process::exit(1);
        }
    }
}

fn run_setup_domain(config_path: &Path, domain: &str, host: Option<&str>) {
    let domain = domain.trim().to_lowercase();
    if domain.is_empty() {
        eprintln!("error: domain required");
        std::process::exit(1);
    }
    let host_owned = host.map(|h| h.trim().trim_end_matches('.').to_lowercase());
    let domain_c = domain.clone();
    let host_c = host_owned.clone();
    match useredit::edit_file(config_path, |c| {
        let mut out = useredit::set_primary_domain(c, &domain_c)?;
        if let Some(ref h) = host_c {
            out = useredit::set_public_host(&out, h)?;
        }
        Ok(out)
    }) {
        Ok(_) => {
            println!("Wrote domains = [\"{}\"]", domain);
            if let Some(ref h) = host_owned {
                println!("Wrote public_host = \"{}\"", h);
            }
            println!();
            println!("Next: publish MX/A/SPF/DKIM/DMARC for this domain, then run:");
            println!("  desertemail doctor --config {}", config_path.display());
            println!("Or continue setup: desertemail setup dkim --config {}", config_path.display());
        }
        Err(e) => {
            eprintln!("error: {}", e);
            std::process::exit(1);
        }
    }
}

fn run_setup_dkim(config_path: &Path, selector_opt: Option<&str>, force: bool) {
    let cfg = load_cfg_or_exit(config_path);
    let key_path = match useredit::dkim_key_path_for_config(&cfg) {
        Ok(p) => p,
        Err(e) => {
            eprintln!("error: {}", e);
            std::process::exit(1);
        }
    };
    if key_path.is_file() && !force {
        eprintln!(
            "error: DKIM key already exists at {} — pass --force to overwrite",
            key_path.display()
        );
        eprintln!(
            "note: regenerating requires re-publishing the TXT at <selector>._domainkey.<domain>"
        );
        std::process::exit(1);
    }

    let key = match crypto::RsaKey::generate(2048) {
        Ok(k) => k,
        Err(e) => {
            eprintln!("error: key generation failed: {}", e);
            std::process::exit(1);
        }
    };
    let pem = key.to_pem_pkcs1();
    if let Some(parent) = key_path.parent() {
        if let Err(e) = std::fs::create_dir_all(parent) {
            eprintln!("error: cannot create key dir {}: {}", parent.display(), e);
            std::process::exit(1);
        }
    }
    if let Err(e) = std::fs::write(&key_path, pem.as_bytes()) {
        eprintln!("error: cannot write {}: {}", key_path.display(), e);
        std::process::exit(1);
    }
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        let _ = std::fs::set_permissions(&key_path, std::fs::Permissions::from_mode(0o600));
    }

    let selector = {
        if let Some(s) = selector_opt {
            s.trim().to_lowercase()
        } else {
            let s = cfg.dkim_selector();
            if s.is_empty() {
                "mail".into()
            } else {
                s
            }
        }
    };
    let path_str = key_path.to_string_lossy().to_string();
    let sel = selector.clone();
    let path_for_edit = path_str.clone();
    if let Err(e) = useredit::edit_file(config_path, |c| {
        useredit::set_dkim_paths(c, &sel, &path_for_edit)
    }) {
        eprintln!("error: key written but config update failed: {}", e);
        std::process::exit(1);
    }

    println!("DKIM key written to {} (mode 600)", key_path.display());
    println!("Selector: {}", selector);
    println!();
    let txt = dkim::dns_txt_record(&key);
    let domains = cfg.domains_list();
    if domains.is_empty() {
        println!("Publish this TXT record (Name uses your mail domain):");
        println!("  Name:  {}._domainkey.<domain>", selector);
        println!("  Value: {}", txt);
    } else {
        println!("Publish these DNS TXT records:");
        for d in &domains {
            println!("  Name:  {}._domainkey.{}", selector, d);
            println!("  Value: {}", txt);
            println!();
        }
    }
    println!("Then verify with: desertemail doctor --config {}", config_path.display());
}

fn run_setup_https(config_path: &Path, domain_raw: &str, email: &str, check_only: bool, yes: bool) {
    let domain = match useredit::normalize_https_domain(domain_raw) {
        Ok(d) => d,
        Err(e) => {
            eprintln!("error: {}", e);
            std::process::exit(1);
        }
    };
    let email = email.trim();
    if email.is_empty() || !email.contains('@') {
        eprintln!("error: a valid contact email is required for the Let's Encrypt account");
        std::process::exit(1);
    }

    let cfg = load_cfg_or_exit(config_path);
    let checks = doctor::run_https_checks_ui(&cfg, &domain);
    print_https_checks(&domain, &checks);

    let fails = checks
        .iter()
        .filter(|c| c.status == doctor::Status::Fail)
        .count();

    if check_only {
        std::process::exit(fails as i32);
    }

    if fails > 0 && !yes {
        eprintln!();
        eprintln!(
            "error: {} HTTPS check(s) failed — fix DNS/port 80, or pass --yes to write config anyway",
            fails
        );
        eprintln!("  desertemail setup https {} --email {} --check-only", domain, email);
        std::process::exit(1);
    }

    let (cert_path, key_path) = useredit::default_tls_paths(&cfg);
    let web_tls = if cfg.web_tls_listen.is_empty() {
        "0.0.0.0:8443"
    } else {
        ""
    };
    let url = format!("https://{}", domain);
    let domain_owned = domain.clone();
    let email_owned = email.to_string();
    let cert_owned = cert_path.clone();
    let key_owned = key_path.clone();
    let web_tls_owned = web_tls.to_string();
    let url_owned = url.clone();

    match useredit::edit_file(config_path, |c| {
        let out = useredit::enable_acme(
            c,
            &email_owned,
            &domain_owned,
            &cert_owned,
            &key_owned,
            &web_tls_owned,
        )?;
        useredit::set_public_url(&out, &url_owned)
    }) {
        Ok(_) => {
            println!();
            println!("Wrote ACME / TLS settings to {}", config_path.display());
            println!("  acme = true");
            println!("  acme_email = \"{}\"", email);
            println!("  acme_domains = [\"{}\"]", domain);
            println!("  tls_cert_file = \"{}\"", cert_path);
            println!("  tls_key_file = \"{}\"", key_path);
            if !web_tls.is_empty() {
                println!("  web_tls_listen = \"{}\"", web_tls);
            }
            println!("  public_url = \"{}\"", url);
            println!();
            println!("Next steps:");
            println!("  1. Keep port 80 reachable from the internet (ACME HTTP-01).");
            println!(
                "  2. Start or restart desertemail so the ACME background worker can request the certificate:"
            );
            println!("       desertemail --config {}", config_path.display());
            println!(
                "     (This CLI does not start the ACME thread — the server does that at startup when acme=true.)"
            );
            println!(
                "  3. After the cert is written to {}, HTTPS binds on web_tls_listen.",
                cert_path
            );
        }
        Err(e) => {
            eprintln!("error: {}", e);
            std::process::exit(1);
        }
    }
}

fn print_https_checks(domain: &str, checks: &[doctor::Check]) {
    use std::io::IsTerminal;
    let color = std::env::var_os("NO_COLOR").is_none() && io::stdout().is_terminal();
    println!("HTTPS readiness for {}", domain);
    println!();
    for c in checks {
        let glyph = match c.status {
            doctor::Status::Ok => {
                if color {
                    "\x1b[32m✓\x1b[0m"
                } else {
                    "ok"
                }
            }
            doctor::Status::Warn => {
                if color {
                    "\x1b[33m⚠\x1b[0m"
                } else {
                    "warn"
                }
            }
            doctor::Status::Fail => {
                if color {
                    "\x1b[31m✗\x1b[0m"
                } else {
                    "FAIL"
                }
            }
        };
        println!("  {} {} — {}", glyph, c.name, c.detail);
        if let Some(ref fix) = c.fix {
            if c.status != doctor::Status::Ok {
                for line in fix.lines() {
                    println!("      → fix: {}", line);
                }
            }
        }
    }
    let blockers = checks
        .iter()
        .filter(|c| c.status == doctor::Status::Fail)
        .count();
    let warnings = checks
        .iter()
        .filter(|c| c.status == doctor::Status::Warn)
        .count();
    println!();
    println!("{} blocker(s), {} warning(s)", blockers, warnings);
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
        password: Option<String>,
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
                eprintln!("Usage: desertemail user passwd <email> [--password <pw>]");
                std::process::exit(1);
            }
            let email = args[start + 1].clone();
            let mut password = None;
            let mut j = start + 2;
            while j < args.len() {
                if args[j] == "--password" && j + 1 < args.len() {
                    password = Some(args[j + 1].clone());
                    j += 2;
                } else if args[j] == "--config" || args[j] == "-c" {
                    j += 2; // already handled for path; skip
                } else {
                    j += 1;
                }
            }
            UserCmd::Passwd { email, password }
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
                    p1
                }
            };
            if let Err(e) = useredit::check_new_password(&pw) {
                eprintln!("error: {}", e);
                std::process::exit(1);
            }
            let email_c = email.clone();
            let pw_c = pw.clone();
            match useredit::edit_file(path, |c| useredit::add_user(c, &email_c, &pw_c)) {
                Ok(_) => println!("user added: {}", email),
                Err(e) => {
                    eprintln!("error: {}", e);
                    if e.contains("already exists") {
                        eprintln!(
                            "hint: use `desertemail user passwd {}` to reset the password",
                            email
                        );
                    }
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
        UserCmd::Passwd { email, password } => {
            let p1 = match password {
                Some(p) => p,
                None => {
                    let p1 = prompt_password("New password: ");
                    let p2 = prompt_password("Confirm:      ");
                    if p1 != p2 {
                        eprintln!("error: passwords do not match");
                        std::process::exit(1);
                    }
                    p1
                }
            };
            if let Err(e) = useredit::check_new_password(&p1) {
                eprintln!("error: {}", e);
                std::process::exit(1);
            }
            let email_c = email.clone();
            match useredit::edit_file(path, |c| useredit::set_password(c, &email_c, &p1)) {
                Ok(_) => println!("password updated for: {}", email),
                Err(e) => {
                    eprintln!("error: {}", e);
                    if e.contains("not found") {
                        eprintln!(
                            "hint: use `desertemail user add {}` to create the account",
                            email
                        );
                    }
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
    let key = match cfg.dkim_key_clone() {
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
    let selector = cfg.dkim_selector();
    let txt = dkim::dns_txt_record(&key);
    println!("Publish this DNS TXT record:");
    println!();
    println!("  Name:  {}._domainkey.{}", selector, domain);
    println!("  Type:  TXT");
    println!("  Value: {}", txt);
    println!();
    println!("(Generate key with: openssl genrsa -out dkim.pem 2048)");
}
