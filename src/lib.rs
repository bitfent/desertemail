//! DesertEmail library surface (for unit tests and cargo-fuzz targets).
//! The binary entry point is `main.rs`.

pub mod acme;
pub mod auth;
pub mod config;
pub mod crypto;
pub mod dkim;
pub mod dmarc;
pub mod dns;
pub mod imap;
pub mod limits;
pub mod passwd;
pub mod queue;
pub mod ratelimit;
pub mod shutdown;
pub mod smtp;
pub mod spamscore;
pub mod spf;
pub mod storage;
pub mod tls;
pub mod util;
pub mod web;
