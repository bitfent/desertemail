//! DesertEmail - zero-dependency email server in pure Rust.
//! 
//! Run with: cargo run -- --config config.toml
//! Or release binary.

mod auth;
mod config;
mod imap;
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
    let mut i = 1;
    while i < args.len() {
        if args[i] == "--config" || args[i] == "-c" {
            if i + 1 < args.len() {
                config_path = args[i + 1].clone();
                i += 1;
            }
        } else if args[i] == "--help" || args[i] == "-h" {
            println!("Usage: desertemail [--config path/to/config.toml]");
            println!("See config.example.toml and README.md");
            return;
        }
        i += 1;
    }

    let cfg = match Config::load(Path::new(&config_path)) {
        Ok(c) => {
            util::log!("loaded config from {}", config_path);
            Arc::new(c)
        }
        Err(e) => {
            util::log!("failed to load config: {} — using defaults + trying example", e);
            match Config::load(Path::new("config.example.toml")) {
                Ok(c) => Arc::new(c),
                Err(_) => Arc::new(Config::default()),
            }
        }
    };

    if let Err(e) = std::fs::create_dir_all(&cfg.data_dir) {
        util::log!("warning: cannot create data_dir {}: {}", cfg.data_dir, e);
    }

    util::log!(
        "domains: {:?} | catch_all={} | data={}",
        cfg.domains,
        cfg.catch_all,
        cfg.data_dir
    );

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
