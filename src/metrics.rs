//! In-process Prometheus text-format metrics (no extra crates).
//!
//! Cheap AtomicU64 counters; queue depth is computed on scrape.

use std::path::Path;
use std::sync::atomic::{AtomicU64, Ordering};

/// Snapshot of all counters (for formatting / tests).
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct Snapshot {
    pub connections_total: u64,
    pub connections_active: u64,
    pub auth_successes: u64,
    pub auth_failures: u64,
    pub messages_received: u64,
    pub messages_delivered: u64,
    pub messages_queued: u64,
    pub messages_bounced: u64,
    pub greylist_rejects: u64,
    pub spam_rejects: u64,
    pub queue_depth: u64,
}

// Global counters
static CONNECTIONS_TOTAL: AtomicU64 = AtomicU64::new(0);
static CONNECTIONS_ACTIVE: AtomicU64 = AtomicU64::new(0);
static AUTH_SUCCESSES: AtomicU64 = AtomicU64::new(0);
static AUTH_FAILURES: AtomicU64 = AtomicU64::new(0);
static MESSAGES_RECEIVED: AtomicU64 = AtomicU64::new(0);
static MESSAGES_DELIVERED: AtomicU64 = AtomicU64::new(0);
static MESSAGES_QUEUED: AtomicU64 = AtomicU64::new(0);
static MESSAGES_BOUNCED: AtomicU64 = AtomicU64::new(0);
static GREYLIST_REJECTS: AtomicU64 = AtomicU64::new(0);
static SPAM_REJECTS: AtomicU64 = AtomicU64::new(0);

pub fn inc_connections_total() {
    CONNECTIONS_TOTAL.fetch_add(1, Ordering::Relaxed);
}

pub fn inc_connections_active() {
    CONNECTIONS_ACTIVE.fetch_add(1, Ordering::Relaxed);
}

pub fn dec_connections_active() {
    CONNECTIONS_ACTIVE.fetch_sub(1, Ordering::Relaxed);
}

pub fn inc_auth_success() {
    AUTH_SUCCESSES.fetch_add(1, Ordering::Relaxed);
}

pub fn inc_auth_failure() {
    AUTH_FAILURES.fetch_add(1, Ordering::Relaxed);
}

pub fn inc_messages_received() {
    MESSAGES_RECEIVED.fetch_add(1, Ordering::Relaxed);
}

pub fn inc_messages_delivered(n: u64) {
    MESSAGES_DELIVERED.fetch_add(n, Ordering::Relaxed);
}

pub fn inc_messages_queued() {
    MESSAGES_QUEUED.fetch_add(1, Ordering::Relaxed);
}

pub fn inc_messages_bounced() {
    MESSAGES_BOUNCED.fetch_add(1, Ordering::Relaxed);
}

pub fn inc_greylist_rejects() {
    GREYLIST_REJECTS.fetch_add(1, Ordering::Relaxed);
}

pub fn inc_spam_rejects() {
    SPAM_REJECTS.fetch_add(1, Ordering::Relaxed);
}

/// Count non-hidden files in `{data_dir}/queue` (best-effort).
pub fn queue_depth(data_dir: &str) -> u64 {
    let dir = Path::new(data_dir).join("queue");
    let rd = match std::fs::read_dir(&dir) {
        Ok(r) => r,
        Err(_) => return 0,
    };
    let mut n = 0u64;
    for ent in rd.flatten() {
        let name = ent.file_name();
        let s = name.to_string_lossy();
        if s.starts_with('.') {
            continue;
        }
        if ent.file_type().map(|t| t.is_file()).unwrap_or(false) {
            n = n.saturating_add(1);
        }
    }
    n
}

pub fn snapshot(data_dir: &str) -> Snapshot {
    Snapshot {
        connections_total: CONNECTIONS_TOTAL.load(Ordering::Relaxed),
        connections_active: CONNECTIONS_ACTIVE.load(Ordering::Relaxed),
        auth_successes: AUTH_SUCCESSES.load(Ordering::Relaxed),
        auth_failures: AUTH_FAILURES.load(Ordering::Relaxed),
        messages_received: MESSAGES_RECEIVED.load(Ordering::Relaxed),
        messages_delivered: MESSAGES_DELIVERED.load(Ordering::Relaxed),
        messages_queued: MESSAGES_QUEUED.load(Ordering::Relaxed),
        messages_bounced: MESSAGES_BOUNCED.load(Ordering::Relaxed),
        greylist_rejects: GREYLIST_REJECTS.load(Ordering::Relaxed),
        spam_rejects: SPAM_REJECTS.load(Ordering::Relaxed),
        queue_depth: queue_depth(data_dir),
    }
}

/// Format a snapshot as Prometheus text exposition format (0.0.4).
pub fn format_prometheus(s: &Snapshot) -> String {
    let mut out = String::with_capacity(1024);
    line(
        &mut out,
        "desertemail_connections_total",
        "Total accepted connections (all protocols)",
        "counter",
        s.connections_total,
    );
    line(
        &mut out,
        "desertemail_connections_active",
        "Currently active connections",
        "gauge",
        s.connections_active,
    );
    line(
        &mut out,
        "desertemail_auth_successes_total",
        "Successful authentications",
        "counter",
        s.auth_successes,
    );
    line(
        &mut out,
        "desertemail_auth_failures_total",
        "Failed authentications",
        "counter",
        s.auth_failures,
    );
    line(
        &mut out,
        "desertemail_messages_received_total",
        "Messages accepted via SMTP DATA",
        "counter",
        s.messages_received,
    );
    line(
        &mut out,
        "desertemail_messages_delivered_total",
        "Local Maildir deliveries",
        "counter",
        s.messages_delivered,
    );
    line(
        &mut out,
        "desertemail_messages_queued_total",
        "Messages enqueued for outbound delivery",
        "counter",
        s.messages_queued,
    );
    line(
        &mut out,
        "desertemail_messages_bounced_total",
        "Messages bounced after max retries",
        "counter",
        s.messages_bounced,
    );
    line(
        &mut out,
        "desertemail_greylist_rejects_total",
        "Greylist 451 deferrals",
        "counter",
        s.greylist_rejects,
    );
    line(
        &mut out,
        "desertemail_spam_rejects_total",
        "Spam / policy rejects (550)",
        "counter",
        s.spam_rejects,
    );
    line(
        &mut out,
        "desertemail_queue_depth",
        "Files currently in the outbound queue directory",
        "gauge",
        s.queue_depth,
    );
    out
}

fn line(out: &mut String, name: &str, help: &str, ty: &str, value: u64) {
    out.push_str("# HELP ");
    out.push_str(name);
    out.push(' ');
    out.push_str(help);
    out.push('\n');
    out.push_str("# TYPE ");
    out.push_str(name);
    out.push(' ');
    out.push_str(ty);
    out.push('\n');
    out.push_str(name);
    out.push(' ');
    out.push_str(&value.to_string());
    out.push('\n');
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn prometheus_text_format() {
        let s = Snapshot {
            connections_total: 10,
            connections_active: 2,
            auth_successes: 5,
            auth_failures: 3,
            messages_received: 7,
            messages_delivered: 6,
            messages_queued: 1,
            messages_bounced: 0,
            greylist_rejects: 4,
            spam_rejects: 1,
            queue_depth: 3,
        };
        let text = format_prometheus(&s);
        assert!(text.contains("# HELP desertemail_connections_total"));
        assert!(text.contains("# TYPE desertemail_connections_total counter"));
        assert!(text.contains("desertemail_connections_total 10\n"));
        assert!(text.contains("desertemail_connections_active 2\n"));
        assert!(text.contains("desertemail_auth_successes_total 5\n"));
        assert!(text.contains("desertemail_auth_failures_total 3\n"));
        assert!(text.contains("desertemail_messages_received_total 7\n"));
        assert!(text.contains("desertemail_messages_delivered_total 6\n"));
        assert!(text.contains("desertemail_messages_queued_total 1\n"));
        assert!(text.contains("desertemail_greylist_rejects_total 4\n"));
        assert!(text.contains("desertemail_spam_rejects_total 1\n"));
        assert!(text.contains("desertemail_queue_depth 3\n"));
        // TYPE lines for gauges
        assert!(text.contains("# TYPE desertemail_queue_depth gauge"));
    }
}
