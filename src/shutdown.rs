//! Graceful shutdown flag. SIGTERM/SIGINT (unix) or console Ctrl-C (windows).
//!
//! Uses the classic `signal(2)` handler (no libc crate). On Windows uses
//! `SetConsoleCtrlHandler`. Prefer unix SIGTERM for systemd.

use std::sync::atomic::{AtomicBool, Ordering};

static SHUTDOWN: AtomicBool = AtomicBool::new(false);

pub fn is_shutdown() -> bool {
    SHUTDOWN.load(Ordering::SeqCst)
}

pub fn request_shutdown() {
    SHUTDOWN.store(true, Ordering::SeqCst);
}

/// Install platform signal handlers. Safe to call once at startup.
pub fn install_handlers() {
    #[cfg(unix)]
    install_unix();
    #[cfg(windows)]
    install_windows();
}

#[cfg(unix)]
fn install_unix() {
    // signal(2) is available on all unix via libc linked by std.
    // SIGINT=2, SIGTERM=15 on Linux, macOS, *BSD.
    extern "C" {
        fn signal(sig: i32, handler: Option<unsafe extern "C" fn(i32)>) -> usize;
    }
    const SIGINT: i32 = 2;
    const SIGTERM: i32 = 15;

    unsafe extern "C" fn handler(_sig: i32) {
        // Async-signal-safe: only store an atomic.
        SHUTDOWN.store(true, Ordering::SeqCst);
    }

    unsafe {
        let _ = signal(SIGTERM, Some(handler));
        let _ = signal(SIGINT, Some(handler));
    }
}

#[cfg(windows)]
fn install_windows() {
    type HandlerRoutine = unsafe extern "system" fn(ctrl_type: u32) -> i32;
    extern "system" {
        fn SetConsoleCtrlHandler(handler: Option<HandlerRoutine>, add: i32) -> i32;
    }
    unsafe extern "system" fn handler(_ctrl: u32) -> i32 {
        SHUTDOWN.store(true, Ordering::SeqCst);
        1 // TRUE = handled
    }
    unsafe {
        let _ = SetConsoleCtrlHandler(Some(handler), 1);
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn flag_roundtrip() {
        let before = is_shutdown();
        request_shutdown();
        assert!(is_shutdown());
        SHUTDOWN.store(before, Ordering::SeqCst);
    }
}
