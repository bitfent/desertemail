//! Auth brute-force lockout + outbound abuse throttle.
//! Thread-safe, prune-on-access, injectable clock for tests.

use std::collections::HashMap;
use std::sync::Mutex;

use crate::util;

// ---------------------------------------------------------------------------
// Auth rate limit (per client IP)
// ---------------------------------------------------------------------------

#[derive(Debug, Clone)]
struct AuthState {
    /// Timestamps (secs) of recent failed attempts within the window.
    failures: Vec<u64>,
    /// If set and `now < lockout_until`, the IP is locked out.
    lockout_until: u64,
}

/// Thresholds for auth rate limiting.
#[derive(Debug, Clone, Copy)]
pub struct AuthLimits {
    pub max_failures: u32,
    pub window_secs: u64,
    pub lockout_secs: u64,
}

impl Default for AuthLimits {
    fn default() -> Self {
        Self {
            max_failures: 10,
            window_secs: 300,
            lockout_secs: 900,
        }
    }
}

struct AuthTracker {
    map: Mutex<HashMap<String, AuthState>>,
    limits: Mutex<AuthLimits>,
}

fn auth_tracker() -> &'static AuthTracker {
    use std::sync::OnceLock;
    static T: OnceLock<AuthTracker> = OnceLock::new();
    T.get_or_init(|| AuthTracker {
        map: Mutex::new(HashMap::new()),
        limits: Mutex::new(AuthLimits::default()),
    })
}

/// Configure thresholds (call once at startup from config).
pub fn configure_auth(max_failures: u32, window_secs: u64, lockout_secs: u64) {
    if let Ok(mut lim) = auth_tracker().limits.lock() {
        lim.max_failures = max_failures.max(1);
        lim.window_secs = window_secs.max(1);
        lim.lockout_secs = lockout_secs.max(1);
    }
}

fn current_limits() -> AuthLimits {
    auth_tracker()
        .limits
        .lock()
        .map(|l| *l)
        .unwrap_or_default()
}

/// Returns false if the IP is currently locked out.
pub fn check_allowed(ip: &str) -> bool {
    check_allowed_at(ip, util::now_secs())
}

/// Injectable-clock variant for tests.
pub fn check_allowed_at(ip: &str, now: u64) -> bool {
    let limits = current_limits();
    check_allowed_with(ip, now, &limits)
}

fn check_allowed_with(ip: &str, now: u64, limits: &AuthLimits) -> bool {
    let mut map = match auth_tracker().map.lock() {
        Ok(m) => m,
        Err(_) => return true, // fail open on poison
    };
    prune_auth(&mut map, now, limits);
    match map.get(ip) {
        Some(st) if st.lockout_until > now => false,
        _ => true,
    }
}

pub fn record_failure(ip: &str) {
    record_failure_at(ip, util::now_secs());
}

pub fn record_failure_at(ip: &str, now: u64) {
    let limits = current_limits();
    record_failure_with(ip, now, &limits);
}

fn record_failure_with(ip: &str, now: u64, limits: &AuthLimits) {
    let mut map = match auth_tracker().map.lock() {
        Ok(m) => m,
        Err(_) => return,
    };
    prune_auth(&mut map, now, limits);
    let st = map.entry(ip.to_string()).or_insert_with(|| AuthState {
        failures: Vec::new(),
        lockout_until: 0,
    });
    // Drop failures outside the window.
    let window_start = now.saturating_sub(limits.window_secs);
    st.failures.retain(|&t| t >= window_start);
    st.failures.push(now);
    if st.failures.len() as u32 >= limits.max_failures {
        st.lockout_until = now.saturating_add(limits.lockout_secs);
        st.failures.clear();
    }
}

pub fn record_success(ip: &str) {
    record_success_at(ip, util::now_secs());
}

pub fn record_success_at(ip: &str, now: u64) {
    let limits = current_limits();
    let mut map = match auth_tracker().map.lock() {
        Ok(m) => m,
        Err(_) => return,
    };
    prune_auth(&mut map, now, &limits);
    map.remove(ip);
}

fn prune_auth(map: &mut HashMap<String, AuthState>, now: u64, limits: &AuthLimits) {
    let window_start = now.saturating_sub(limits.window_secs);
    map.retain(|_, st| {
        if st.lockout_until > now {
            return true;
        }
        st.failures.retain(|&t| t >= window_start);
        // Keep entries that still have recent failures (or just expired lockout
        // with leftover data — drop empty).
        !st.failures.is_empty() || st.lockout_until > now
    });
}

// ---------------------------------------------------------------------------
// Outbound abuse throttle (per authenticated user, rolling hour)
// ---------------------------------------------------------------------------

struct OutboundState {
    /// (timestamp_secs, recipient_count) events in the window.
    events: Vec<(u64, u32)>,
}

struct OutboundTracker {
    map: Mutex<HashMap<String, OutboundState>>,
    max_rcpts: Mutex<u32>,
}

fn outbound_tracker() -> &'static OutboundTracker {
    use std::sync::OnceLock;
    static T: OnceLock<OutboundTracker> = OnceLock::new();
    T.get_or_init(|| OutboundTracker {
        map: Mutex::new(HashMap::new()),
        max_rcpts: Mutex::new(200),
    })
}

const OUTBOUND_WINDOW: u64 = 3600;

pub fn configure_outbound(max_rcpts_per_hour: u32) {
    if let Ok(mut m) = outbound_tracker().max_rcpts.lock() {
        *m = max_rcpts_per_hour.max(1);
    }
}

fn outbound_max() -> u32 {
    outbound_tracker()
        .max_rcpts
        .lock()
        .map(|m| *m)
        .unwrap_or(200)
}

/// Returns true if adding `n_rcpts` would stay under the hourly cap.
pub fn check_outbound(user: &str, n_rcpts: usize) -> bool {
    check_outbound_at(user, n_rcpts, util::now_secs())
}

pub fn check_outbound_at(user: &str, n_rcpts: usize, now: u64) -> bool {
    let max = outbound_max();
    let map = match outbound_tracker().map.lock() {
        Ok(m) => m,
        Err(_) => return true,
    };
    let window_start = now.saturating_sub(OUTBOUND_WINDOW);
    let used = map
        .get(user)
        .map(|st| {
            st.events
                .iter()
                .filter(|(t, _)| *t >= window_start)
                .map(|(_, n)| *n as u64)
                .sum::<u64>()
        })
        .unwrap_or(0);
    used.saturating_add(n_rcpts as u64) <= max as u64
}

pub fn record_outbound(user: &str, n_rcpts: usize) {
    record_outbound_at(user, n_rcpts, util::now_secs());
}

pub fn record_outbound_at(user: &str, n_rcpts: usize, now: u64) {
    if n_rcpts == 0 {
        return;
    }
    let mut map = match outbound_tracker().map.lock() {
        Ok(m) => m,
        Err(_) => return,
    };
    let window_start = now.saturating_sub(OUTBOUND_WINDOW);
    let st = map.entry(user.to_string()).or_insert(OutboundState {
        events: Vec::new(),
    });
    st.events.retain(|(t, _)| *t >= window_start);
    st.events.push((now, n_rcpts as u32));
}

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use super::*;
    use std::sync::Mutex;

    // Serialize tests that touch the global trackers.
    fn test_lock() -> std::sync::MutexGuard<'static, ()> {
        static L: std::sync::OnceLock<Mutex<()>> = std::sync::OnceLock::new();
        L.get_or_init(|| Mutex::new(()))
            .lock()
            .unwrap_or_else(|e| e.into_inner())
    }

    fn reset_auth() {
        configure_auth(3, 60, 100);
        if let Ok(mut m) = auth_tracker().map.lock() {
            m.clear();
        }
    }

    #[test]
    fn sliding_window_lockout() {
        let _g = test_lock();
        reset_auth();
        let ip = "198.51.100.1";

        assert!(check_allowed_at(ip, 1000));
        record_failure_at(ip, 1000);
        record_failure_at(ip, 1010);
        assert!(check_allowed_at(ip, 1020));
        record_failure_at(ip, 1020);
        // 3rd failure at t=1020 => lockout_until = 1120
        assert!(!check_allowed_at(ip, 1021));
        assert!(!check_allowed_at(ip, 1119));
        // At lockout_until, lockout ends (strict >)
        assert!(check_allowed_at(ip, 1120));
    }

    #[test]
    fn success_clears_failures() {
        let _g = test_lock();
        reset_auth();
        let ip = "198.51.100.2";
        record_failure_at(ip, 2000);
        record_failure_at(ip, 2001);
        record_success_at(ip, 2002);
        // Failures cleared — need 3 more to lock out
        record_failure_at(ip, 2003);
        record_failure_at(ip, 2004);
        assert!(check_allowed_at(ip, 2005));
        record_failure_at(ip, 2005);
        assert!(!check_allowed_at(ip, 2006));
    }

    #[test]
    fn window_expiry_prevents_lockout() {
        let _g = test_lock();
        reset_auth();
        let ip = "198.51.100.3";
        record_failure_at(ip, 3000);
        record_failure_at(ip, 3010);
        // Outside window — old failures pruned
        record_failure_at(ip, 3000 + 61);
        assert!(check_allowed_at(ip, 3000 + 61));
    }

    #[test]
    fn outbound_throttle() {
        let _g = test_lock();
        configure_outbound(5);
        if let Ok(mut m) = outbound_tracker().map.lock() {
            m.clear();
        }
        let u = "alice-outbound-test";
        assert!(check_outbound_at(u, 3, 5000));
        record_outbound_at(u, 3, 5000);
        assert!(check_outbound_at(u, 2, 5100));
        record_outbound_at(u, 2, 5100);
        assert!(!check_outbound_at(u, 1, 5200));
        // After full window from last event (t > 5100 + 3600-1), both events gone
        assert!(check_outbound_at(u, 5, 5100 + 3601));
    }
}
