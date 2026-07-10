//! Utility helpers: pure std, no deps.

use std::io::{self, BufRead, Write};
use std::net::TcpStream;
use std::time::{SystemTime, UNIX_EPOCH};

pub fn now_secs() -> u64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap_or_default()
        .as_secs()
}

pub fn now_millis() -> u128 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap_or_default()
        .as_millis()
}

/// Read one CRLF/LF-terminated line from a persistent buffered reader.
/// Callers must keep ONE BufReader per connection: constructing a fresh
/// BufReader per line would discard whatever the previous one buffered.
pub fn read_line<R: BufRead>(reader: &mut R) -> io::Result<Option<String>> {
    let mut line = String::new();
    let n = reader.read_line(&mut line)?;
    if n == 0 {
        return Ok(None);
    }
    if line.ends_with("\r\n") {
        line.truncate(line.len() - 2);
    } else if line.ends_with('\n') {
        line.truncate(line.len() - 1);
    }
    Ok(Some(line))
}

pub fn write_line(stream: &mut TcpStream, s: &str) -> io::Result<()> {
    stream.write_all(s.as_bytes())?;
    stream.write_all(b"\r\n")?;
    stream.flush()?;
    Ok(())
}

pub fn write_raw(stream: &mut TcpStream, data: &[u8]) -> io::Result<()> {
    stream.write_all(data)?;
    stream.flush()?;
    Ok(())
}

pub fn base64_decode(input: &str) -> Vec<u8> {
    const TABLE: &[u8] = b"ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/";
    let mut out = Vec::new();
    let mut buf = 0u32;
    let mut bits = 0u32;
    for c in input.chars() {
        if c == '=' {
            break;
        }
        let val = match TABLE.iter().position(|&x| x == c as u8) {
            Some(v) => v as u32,
            None => continue,
        };
        buf = (buf << 6) | val;
        bits += 6;
        if bits >= 8 {
            bits -= 8;
            out.push((buf >> bits) as u8);
            buf &= (1 << bits) - 1;
        }
    }
    out
}

#[allow(dead_code)]
pub fn base64_encode(input: &[u8]) -> String {
    const TABLE: &[u8] = b"ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/";
    let mut out = String::new();
    for chunk in input.chunks(3) {
        let mut n = 0u32;
        for (i, &b) in chunk.iter().enumerate() {
            n |= (b as u32) << (16 - 8 * i);
        }
        for i in 0..4 {
            if i * 6 / 8 < chunk.len() {
                let idx = ((n >> (18 - 6 * i)) & 0x3F) as usize;
                out.push(TABLE[idx] as char);
            } else {
                out.push('=');
            }
        }
    }
    out
}

/// RFC 2822 date string (UTC) for a unix timestamp.
pub fn rfc2822_date(secs: u64) -> String {
    const WD: &[&str] = &["Thu", "Fri", "Sat", "Sun", "Mon", "Tue", "Wed"];
    const MO: &[&str] = &[
        "Jan", "Feb", "Mar", "Apr", "May", "Jun", "Jul", "Aug", "Sep", "Oct", "Nov", "Dec",
    ];
    let days = (secs / 86400) as i64;
    let rem = secs % 86400;
    let h = rem / 3600;
    let m = (rem % 3600) / 60;
    let s = rem % 60;
    let (y, month, day) = civil_from_days(days);
    let wd = WD[(days.rem_euclid(7)) as usize];
    let mon = MO[(month as usize).saturating_sub(1).min(11)];
    format!(
        "{}, {:02} {} {:04} {:02}:{:02}:{:02} +0000",
        wd, day, mon, y, h, m, s
    )
}

/// Days since Unix epoch → (year, month, day). Howard Hinnant algorithm.
fn civil_from_days(mut z: i64) -> (i32, u32, u32) {
    z += 719468;
    let era = if z >= 0 { z } else { z - 146096 } / 146097;
    let doe = (z - era * 146097) as u64;
    let yoe = (doe - doe / 1460 + doe / 36524 - doe / 146096) / 365;
    let y = yoe as i64 + era * 400;
    let doy = doe - (365 * yoe + yoe / 4 - yoe / 100);
    let mp = (5 * doy + 2) / 153;
    let d = doy - (153 * mp + 2) / 5 + 1;
    let m = if mp < 10 { mp + 3 } else { mp - 9 };
    let y = if m <= 2 { y + 1 } else { y };
    (y as i32, m as u32, d as u32)
}

pub fn parse_email_addr(s: &str) -> (String, String) {
    let s = s.trim().trim_matches(|c| c == '<' || c == '>');
    if let Some(at) = s.find('@') {
        (s[..at].to_lowercase(), s[at + 1..].to_lowercase())
    } else {
        (s.to_lowercase(), String::new())
    }
}

#[macro_export]
macro_rules! log {
    ($($arg:tt)*) => {{
        use std::io::Write;
        let _ = writeln!(std::io::stderr(), "[{}] {}", $crate::util::now_secs(), format!($($arg)*));
    }};
}

pub use log;
