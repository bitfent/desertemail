//! Global + per-IP connection limits with RAII slot release.
//! Also helpers for applying I/O timeouts on accepted sockets.

use std::collections::HashMap;
use std::net::TcpStream;
use std::sync::atomic::{AtomicUsize, Ordering};
use std::sync::{Mutex, OnceLock};
use std::time::Duration;

use crate::metrics;

/// Default max concurrent connections (all protocols).
pub const DEFAULT_MAX_CONNECTIONS: usize = 512;
/// Default max concurrent connections from a single IP.
pub const DEFAULT_MAX_PER_IP: usize = 20;
/// Default idle read/write timeout in seconds.
pub const DEFAULT_IO_TIMEOUT_SECS: u64 = 120;

/// Thread-safe connection counter (global + per-IP).
pub struct ConnLimiter {
    global: AtomicUsize,
    per_ip: Mutex<HashMap<String, usize>>,
    max_global: AtomicUsize,
    max_per_ip: AtomicUsize,
}

impl ConnLimiter {
    pub fn new(max_global: usize, max_per_ip: usize) -> Self {
        Self {
            global: AtomicUsize::new(0),
            per_ip: Mutex::new(HashMap::new()),
            max_global: AtomicUsize::new(max_global.max(1)),
            max_per_ip: AtomicUsize::new(max_per_ip.max(1)),
        }
    }

    pub fn configure(&self, max_global: usize, max_per_ip: usize) {
        self.max_global
            .store(max_global.max(1), Ordering::Relaxed);
        self.max_per_ip.store(max_per_ip.max(1), Ordering::Relaxed);
    }

    /// Try to acquire a connection slot for `ip`. Returns None if over limit.
    pub fn try_acquire(&self, ip: &str) -> Option<ConnGuard<'_>> {
        let max_g = self.max_global.load(Ordering::Relaxed);
        let max_ip = self.max_per_ip.load(Ordering::Relaxed);
        let mut map = self.per_ip.lock().ok()?;
        let cur_ip = map.get(ip).copied().unwrap_or(0);
        if cur_ip >= max_ip {
            return None;
        }
        let prev = self.global.fetch_add(1, Ordering::SeqCst);
        if prev >= max_g {
            self.global.fetch_sub(1, Ordering::SeqCst);
            return None;
        }
        *map.entry(ip.to_string()).or_insert(0) += 1;
        metrics::inc_connections_total();
        metrics::inc_connections_active();
        Some(ConnGuard {
            limiter: self,
            ip: ip.to_string(),
            active: true,
        })
    }

    fn release(&self, ip: &str) {
        self.global.fetch_sub(1, Ordering::SeqCst);
        metrics::dec_connections_active();
        if let Ok(mut map) = self.per_ip.lock() {
            if let Some(n) = map.get_mut(ip) {
                *n = n.saturating_sub(1);
                if *n == 0 {
                    map.remove(ip);
                }
            }
        }
    }

    /// Current global active connection count.
    pub fn active_count(&self) -> usize {
        self.global.load(Ordering::Relaxed)
    }
}

/// Active connections held by the global limiter.
pub fn active_connections() -> usize {
    global_limiter().active_count()
}

/// RAII guard: releases the connection slot when dropped.
pub struct ConnGuard<'a> {
    limiter: &'a ConnLimiter,
    ip: String,
    active: bool,
}

impl Drop for ConnGuard<'_> {
    fn drop(&mut self) {
        if self.active {
            self.active = false;
            self.limiter.release(&self.ip);
        }
    }
}

fn global_limiter() -> &'static ConnLimiter {
    static L: OnceLock<ConnLimiter> = OnceLock::new();
    L.get_or_init(|| ConnLimiter::new(DEFAULT_MAX_CONNECTIONS, DEFAULT_MAX_PER_IP))
}

/// Configure connection limits from config (call at startup).
pub fn configure(max_connections: usize, max_per_ip: usize) {
    global_limiter().configure(max_connections, max_per_ip);
}

/// Extract IP-only key from a peer address string (`ip:port` or `[v6]:port`).
pub fn ip_key(peer: &str) -> String {
    if peer.is_empty() || peer == "?" {
        return "unknown".into();
    }
    if let Some(rest) = peer.strip_prefix('[') {
        if let Some(end) = rest.find(']') {
            return rest[..end].to_string();
        }
    }
    if let Some((host, _port)) = peer.rsplit_once(':') {
        if !host.contains(':') {
            return host.to_string();
        }
    }
    peer.to_string()
}

/// Try to acquire a global connection slot for `ip`.
pub fn try_acquire(ip: &str) -> Option<ConnGuard<'static>> {
    global_limiter().try_acquire(ip)
}

/// Apply read/write timeouts on a raw TcpStream.
pub fn set_socket_timeouts(stream: &TcpStream, secs: u64) {
    let dur = Duration::from_secs(secs.max(1));
    let _ = stream.set_read_timeout(Some(dur));
    let _ = stream.set_write_timeout(Some(dur));
}

static IO_TIMEOUT: AtomicUsize = AtomicUsize::new(DEFAULT_IO_TIMEOUT_SECS as usize);

pub fn configure_io_timeout(secs: u64) {
    IO_TIMEOUT.store(secs.max(1) as usize, Ordering::Relaxed);
}

pub fn io_timeout_secs() -> u64 {
    IO_TIMEOUT.load(Ordering::Relaxed) as u64
}

pub fn apply_timeouts(stream: &TcpStream) {
    set_socket_timeouts(stream, io_timeout_secs());
}

/// Peer IP from a TcpStream (best-effort).
pub fn peer_ip_from_stream(stream: &TcpStream) -> String {
    stream
        .peer_addr()
        .map(|a| ip_key(&a.to_string()))
        .unwrap_or_else(|_| "unknown".into())
}

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn ip_key_v4() {
        assert_eq!(ip_key("192.168.1.1:12345"), "192.168.1.1");
    }

    #[test]
    fn ip_key_v6() {
        assert_eq!(ip_key("[2001:db8::1]:993"), "2001:db8::1");
    }

    #[test]
    fn global_and_per_ip_limits() {
        let lim = ConnLimiter::new(2, 2);
        let ip_a = "203.0.113.10";
        let ip_b = "203.0.113.11";

        let g1 = lim.try_acquire(ip_a).expect("first");
        let g2 = lim.try_acquire(ip_a).expect("second same ip under per-ip");
        assert!(lim.try_acquire(ip_a).is_none(), "per-ip cap");
        assert!(lim.try_acquire(ip_b).is_none(), "global cap");
        drop(g1);
        let g3 = lim.try_acquire(ip_b).expect("after release");
        drop(g2);
        drop(g3);
    }

    #[test]
    fn guard_releases_on_drop() {
        let lim = ConnLimiter::new(1, 1);
        let ip = "203.0.113.50";
        {
            let _g = lim.try_acquire(ip).expect("acquire");
            assert!(lim.try_acquire(ip).is_none());
        }
        assert!(lim.try_acquire(ip).is_some());
    }
}
