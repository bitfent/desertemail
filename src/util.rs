//! Utility helpers: std + ring's CSPRNG as randomness backstop (TLS lives in tls.rs).

use std::io::{self, BufRead, Write};
use std::sync::atomic::{AtomicU8, Ordering};
use std::time::{SystemTime, UNIX_EPOCH};

/// 0 = text (default), 1 = json
static LOG_FORMAT: AtomicU8 = AtomicU8::new(0);

pub fn set_log_format(fmt: &str) {
    match fmt.to_ascii_lowercase().as_str() {
        "json" => LOG_FORMAT.store(1, Ordering::Relaxed),
        _ => LOG_FORMAT.store(0, Ordering::Relaxed),
    }
}

pub fn log_format_is_json() -> bool {
    LOG_FORMAT.load(Ordering::Relaxed) == 1
}

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

/// Fill `buf` with random bytes from the OS CSPRNG (`/dev/urandom` or
/// BCryptGenRandom), falling back to ring's audited SystemRandom.
///
/// This feeds security-critical material (RSA primes, password salts, session
/// and invite tokens), so there is deliberately **no** weak fallback: if no
/// CSPRNG is available at all the process aborts rather than silently using
/// predictable randomness.
pub fn fill_random(buf: &mut [u8]) {
    if buf.is_empty() {
        return;
    }
    #[cfg(unix)]
    {
        use std::io::Read;
        if let Ok(mut f) = std::fs::File::open("/dev/urandom") {
            if f.read_exact(buf).is_ok() {
                return;
            }
        }
    }
    #[cfg(windows)]
    {
        #[link(name = "bcrypt")]
        extern "system" {
            fn BCryptGenRandom(
                h_algorithm: *mut core::ffi::c_void,
                pb_buffer: *mut u8,
                cb_buffer: u32,
                dw_flags: u32,
            ) -> i32;
        }
        const BCRYPT_USE_SYSTEM_PREFERRED_RNG: u32 = 0x0000_0002;
        let status = unsafe {
            BCryptGenRandom(
                core::ptr::null_mut(),
                buf.as_mut_ptr(),
                buf.len() as u32,
                BCRYPT_USE_SYSTEM_PREFERRED_RNG,
            )
        };
        if status == 0 {
            return;
        }
    }
    // OS path unavailable — use ring's audited CSPRNG (getrandom syscall etc.).
    use ring::rand::SecureRandom;
    if ring::rand::SystemRandom::new().fill(buf).is_ok() {
        return;
    }
    // No secure randomness anywhere: refuse to run rather than hand out
    // predictable session tokens / RSA primes.
    panic!("no secure random source available (/dev/urandom, BCrypt, and ring all failed)");
}

/// Hard cap on a single protocol line. Without it, a client sending an
/// endless byte stream with no `\n` makes `read_line` buffer unboundedly —
/// trivial memory exhaustion against SMTP/IMAP/HTTP. 1 MiB is far beyond any
/// legitimate command, request line, or header.
pub const MAX_LINE_BYTES: usize = 1024 * 1024;

/// Read one CRLF/LF-terminated line from a persistent buffered reader.
/// Callers must keep ONE BufReader per connection: constructing a fresh
/// BufReader per line would discard whatever the previous one buffered.
/// Lines longer than MAX_LINE_BYTES yield an InvalidData error (the caller
/// drops the connection).
pub fn read_line<R: BufRead>(reader: &mut R) -> io::Result<Option<String>> {
    let mut buf: Vec<u8> = Vec::new();
    loop {
        let available = reader.fill_buf()?;
        if available.is_empty() {
            if buf.is_empty() {
                return Ok(None);
            }
            break; // EOF terminates a final unterminated line
        }
        match available.iter().position(|&b| b == b'\n') {
            Some(pos) => {
                if buf.len() + pos + 1 > MAX_LINE_BYTES {
                    reader.consume(pos + 1);
                    return Err(io::Error::new(io::ErrorKind::InvalidData, "line too long"));
                }
                buf.extend_from_slice(&available[..=pos]);
                reader.consume(pos + 1);
                break;
            }
            None => {
                let n = available.len();
                if buf.len() + n > MAX_LINE_BYTES {
                    reader.consume(n);
                    return Err(io::Error::new(io::ErrorKind::InvalidData, "line too long"));
                }
                buf.extend_from_slice(available);
                reader.consume(n);
            }
        }
    }
    let mut line = String::from_utf8(buf)
        .map_err(|_| io::Error::new(io::ErrorKind::InvalidData, "stream did not contain valid UTF-8"))?;
    if line.ends_with("\r\n") {
        line.truncate(line.len() - 2);
    } else if line.ends_with('\n') {
        line.truncate(line.len() - 1);
    }
    Ok(Some(line))
}

pub fn write_line(stream: &mut impl Write, s: &str) -> io::Result<()> {
    // Single write of line+CRLF so STARTTLS clients never see a split
    // response (a trailing bare \r looked like TLS record type 13).
    let mut buf = Vec::with_capacity(s.len() + 2);
    buf.extend_from_slice(s.as_bytes());
    buf.extend_from_slice(b"\r\n");
    stream.write_all(&buf)?;
    stream.flush()?;
    Ok(())
}

pub fn write_raw(stream: &mut impl Write, data: &[u8]) -> io::Result<()> {
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

/// Base64url without padding (RFC 4648 §5) — used by JWS/ACME.
pub fn base64url_encode(input: &[u8]) -> String {
    let mut s = base64_encode(input);
    s = s.replace('+', "-").replace('/', "_");
    while s.ends_with('=') {
        s.pop();
    }
    s
}

pub fn base64url_decode(input: &str) -> Vec<u8> {
    let mut s = input.replace('-', "+").replace('_', "/");
    while s.len() % 4 != 0 {
        s.push('=');
    }
    base64_decode(&s)
}

/// Escape a string for inclusion in a JSON string value.
pub fn json_escape(s: &str) -> String {
    let mut out = String::with_capacity(s.len());
    for c in s.chars() {
        match c {
            '"' => out.push_str("\\\""),
            '\\' => out.push_str("\\\\"),
            '\n' => out.push_str("\\n"),
            '\r' => out.push_str("\\r"),
            '\t' => out.push_str("\\t"),
            c if (c as u32) < 0x20 => out.push_str(&format!("\\u{:04x}", c as u32)),
            c => out.push(c),
        }
    }
    out
}

/// Emit a structured log line. `fields` is a list of (key, value) pairs for JSON mode.
pub fn log_structured(level: &str, msg: &str, fields: &[(&str, &str)]) {
    use std::io::Write;
    let ts = now_secs();
    if log_format_is_json() {
        let mut field_json = String::new();
        for (i, (k, v)) in fields.iter().enumerate() {
            if i > 0 {
                field_json.push(',');
            }
            field_json.push_str(&format!(
                "\"{}\":\"{}\"",
                json_escape(k),
                json_escape(v)
            ));
        }
        let _ = writeln!(
            std::io::stderr(),
            "{{\"ts\":{},\"level\":\"{}\",\"msg\":\"{}\",\"fields\":{{{}}}}}",
            ts,
            json_escape(level),
            json_escape(msg),
            field_json
        );
    } else {
        if fields.is_empty() {
            let _ = writeln!(std::io::stderr(), "[{}] [{}] {}", ts, level, msg);
        } else {
            let mut extra = String::new();
            for (k, v) in fields {
                extra.push_str(&format!(" {}={}", k, v));
            }
            let _ = writeln!(
                std::io::stderr(),
                "[{}] [{}] {}{}",
                ts, level, msg, extra
            );
        }
    }
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
pub fn civil_from_days(mut z: i64) -> (i32, u32, u32) {
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

/// Days since Unix epoch for a calendar date (UTC midnight).
pub fn days_from_civil(y: i32, m: u32, d: u32) -> i64 {
    let mut y = y as i64;
    let m = m as i64;
    let d = d as i64;
    if m <= 2 {
        y -= 1;
    }
    let era = if y >= 0 { y } else { y - 399 } / 400;
    let yoe = (y - era * 400) as u64;
    let mp = if m > 2 { m - 3 } else { m + 9 };
    let doy = (153 * mp + 2) / 5 + d - 1;
    let doe = yoe * 365 + yoe / 4 - yoe / 100 + doy as u64;
    era * 146097 + doe as i64 - 719468
}

pub fn parse_email_addr(s: &str) -> (String, String) {
    let s = s.trim().trim_matches(|c| c == '<' || c == '>');
    if let Some(at) = s.find('@') {
        let local = s.get(..at).unwrap_or("").to_lowercase();
        let domain = s.get(at + 1..).unwrap_or("").to_lowercase();
        (local, domain)
    } else {
        (s.to_lowercase(), String::new())
    }
}

#[macro_export]
macro_rules! log {
    ($($arg:tt)*) => {{
        $crate::util::log_structured("info", &format!($($arg)*), &[]);
    }};
}

#[macro_export]
macro_rules! log_warn {
    ($($arg:tt)*) => {{
        $crate::util::log_structured("warn", &format!($($arg)*), &[]);
    }};
}

#[macro_export]
macro_rules! log_error {
    ($($arg:tt)*) => {{
        $crate::util::log_structured("error", &format!($($arg)*), &[]);
    }};
}

/// Structured log with key=value fields (for fail2ban / log processors).
/// Usage: `log_event!("info", "auth failed", "event" => "auth_fail", "ip" => &ip, "user" => &user);`
#[macro_export]
macro_rules! log_event {
    ($level:expr, $msg:expr $(, $key:expr => $val:expr)* $(,)?) => {{
        let fields: &[(&str, &str)] = &[$(($key, $val),)*];
        $crate::util::log_structured($level, $msg, fields);
    }};
}

pub use log;
pub use log_error;
pub use log_event;
pub use log_warn;

#[cfg(test)]
mod tests {
    use super::*;
    use std::io::BufReader;

    #[test]
    fn read_line_basic_crlf_lf_eof() {
        let mut r = BufReader::new(&b"hello\r\nworld\nlast"[..]);
        assert_eq!(read_line(&mut r).unwrap().as_deref(), Some("hello"));
        assert_eq!(read_line(&mut r).unwrap().as_deref(), Some("world"));
        assert_eq!(read_line(&mut r).unwrap().as_deref(), Some("last"));
        assert_eq!(read_line(&mut r).unwrap(), None);
    }

    #[test]
    fn read_line_rejects_oversized_line() {
        // A newline-free stream longer than MAX_LINE_BYTES must error instead
        // of buffering forever.
        let big = vec![b'a'; MAX_LINE_BYTES + 10];
        let mut r = BufReader::new(&big[..]);
        let err = read_line(&mut r).expect_err("oversized line must be rejected");
        assert_eq!(err.kind(), std::io::ErrorKind::InvalidData);
    }

    #[test]
    fn read_line_accepts_line_just_under_cap() {
        let mut data = vec![b'a'; 1000];
        data.push(b'\n');
        data.extend_from_slice(b"next\n");
        let mut r = BufReader::new(&data[..]);
        assert_eq!(read_line(&mut r).unwrap().map(|l| l.len()), Some(1000));
        assert_eq!(read_line(&mut r).unwrap().as_deref(), Some("next"));
    }
}
