//! DesertEmail - zero-dependency email server in pure Rust.
//! 
//! Run with: cargo run -- --config config.toml
//! Or release binary.

mod auth;
mod config;
mod crypto;
mod dkim;
mod dns;
mod imap;
mod queue;
mod smtp;
mod storage;
mod util;

use std::env;
use std::net::TcpListener;
use std::path::Path;
use std::sync::Arc;
use std::thread;

use config::Config;
use imap::ImapServer;
use smtp::SmtpServer;

fn main() {
    util::log!("desertemail starting (pure Rust, zero deps)");

    let args: Vec<String> = env::args().collect();
    let mut config_path = "config.toml".to_string();
    let mut dkim_dns_domain: Option<String> = None;
    let mut i = 1;
    while i < args.len() {
        if args[i] == "--config" || args[i] == "-c" {
            if i + 1 < args.len() {
                config_path = args[i + 1].clone();
                i += 1;
            }
        } else if args[i] == "--dkim-dns" {
            if i + 1 < args.len() {
                dkim_dns_domain = Some(args[i + 1].clone());
                i += 1;
            } else {
                eprintln!("Usage: desertemail --dkim-dns <domain>");
                std::process::exit(1);
            }
        } else if args[i] == "--help" || args[i] == "-h" {
            println!("Usage: desertemail [--config path/to/config.toml]");
            println!("       desertemail --dkim-dns <domain> [--config path]");
            println!();
            println!("DKIM setup:");
            println!("  1. Generate a key:  openssl genrsa -out dkim.pem 2048");
            println!("  2. Set dkim_key_file / dkim_selector in config.toml");
            println!("  3. Publish DNS:     desertemail --dkim-dns example.com");
            println!("     (TXT at <selector>._domainkey.<domain>)");
            println!();
            println!("See config.example.toml and README.md");
            return;
        }
        i += 1;
    }

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

    let cfg1 = Arc::clone(&cfg);
    let t1 = thread::spawn(move || {
        SmtpServer::new(cfg1, false).serve(smtp_listener);
    });

    let cfg2 = Arc::clone(&cfg);
    let t2 = thread::spawn(move || {
        SmtpServer::new(cfg2, true).serve(sub_listener);
    });

    let cfg3 = Arc::clone(&cfg);
    let t3 = thread::spawn(move || {
        ImapServer::new(cfg3).serve(imap_listener);
    });

    util::log!("all servers running. Ctrl-C to stop.");
    util::log!("Tip: use high ports + firewall port-forward, or run as root / with capabilities for 25/587/143.");

    let _ = t1.join();
    let _ = t2.join();
    let _ = t3.join();
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
