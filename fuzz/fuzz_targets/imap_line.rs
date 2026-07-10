#![no_main]
use libfuzzer_sys::fuzz_target;

fuzz_target!(|data: &[u8]| {
    let s = String::from_utf8_lossy(data);
    let _ = desertemail::imap::parse_login_args(&s);
    let _ = desertemail::imap::parse_seq_set(&s, 100);
    // Tag + command split (same as handler)
    let mut parts = s.splitn(2, ' ');
    let _ = parts.next();
    let rest = parts.next().unwrap_or("").trim();
    let mut cmd_parts = rest.split_whitespace();
    let _ = cmd_parts.next().unwrap_or("").to_uppercase();
});
