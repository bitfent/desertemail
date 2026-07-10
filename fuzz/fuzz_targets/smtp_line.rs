#![no_main]
use libfuzzer_sys::fuzz_target;

fuzz_target!(|data: &[u8]| {
    let s = String::from_utf8_lossy(data);
    let _ = desertemail::smtp::extract_angle(&s);
    let _ = desertemail::smtp::count_received_headers(data);
    // Simulate SMTP command line tokenization without network I/O.
    let parts: Vec<&str> = s.split_whitespace().collect();
    let _ = parts.first().map(|c| c.to_uppercase());
});
