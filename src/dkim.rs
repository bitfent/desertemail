//! DKIM signing (RFC 6376): relaxed/relaxed canonicalization, rsa-sha256.
//! Pure std; uses crate::crypto and crate::util::base64_encode.

use crate::crypto::{self, RsaKey};
use crate::util;

/// Headers we sign when present (order preserved in h=).
const SIGN_HEADERS: &[&str] = &["from", "to", "subject", "date", "message-id"];

/// Build a full `DKIM-Signature: ...` header (possibly folded) to prepend.
/// Returns None on failure.
pub fn sign(raw_message: &[u8], domain: &str, selector: &str, key: &RsaKey) -> Option<String> {
    let (headers, body) = split_message(raw_message);

    let body_canon = canonicalize_body_relaxed(body);
    let bh = util::base64_encode(&crypto::sha256(&body_canon));

    // Collect present signed headers in SIGN_HEADERS order (first instance each).
    let mut h_list: Vec<&str> = Vec::new();
    let mut signed_canon = String::new();
    for name in SIGN_HEADERS {
        if let Some(field) = find_header(&headers, name) {
            h_list.push(name);
            signed_canon.push_str(&canonicalize_header_relaxed(field));
        }
    }
    if h_list.is_empty() {
        return None;
    }
    let h_tag = h_list.join(":");

    // DKIM-Signature with empty b= for hashing
    let dkim_for_hash = format!(
        "DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed; d={}; s={}; h={}; bh={}; b=",
        domain, selector, h_tag, bh
    );
    // Canonicalize the DKIM-Signature header (empty b=); no trailing CRLF in hash input
    // per RFC 6376 §3.7: the CRLF terminating the header is included in relaxed form...
    // Actually: "the hash is computed over ... the canonicalized header fields ... each
    // terminated with CRLF, followed by the DKIM-Signature header field with b= empty,
    // without a trailing CRLF"
    let dkim_canon = canonicalize_header_relaxed(&dkim_for_hash);
    // strip trailing CRLF from DKIM-Signature contribution
    let dkim_canon = dkim_canon.trim_end_matches("\r\n");

    let mut to_sign = signed_canon;
    to_sign.push_str(dkim_canon);

    let sig = key.sign_sha256(to_sign.as_bytes()).ok()?;
    let b_tag = util::base64_encode(&sig);

    // Emit on ONE line (well under the 998-octet limit): the emitted header
    // must canonicalize to exactly the hashed text above. Folding it would
    // introduce FWS (e.g. before ';') that relaxed canonicalization keeps
    // as a space, invalidating the signature.
    Some(format!("{}{}", dkim_for_hash, b_tag))
}

/// Prepend DKIM-Signature to raw message bytes.
pub fn sign_and_prepend(
    raw_message: &[u8],
    domain: &str,
    selector: &str,
    key: &RsaKey,
) -> Option<Vec<u8>> {
    let sig_header = sign(raw_message, domain, selector, key)?;
    let mut out = Vec::with_capacity(sig_header.len() + 2 + raw_message.len());
    out.extend_from_slice(sig_header.as_bytes());
    if !sig_header.ends_with("\r\n") {
        out.extend_from_slice(b"\r\n");
    }
    out.extend_from_slice(raw_message);
    Some(out)
}

/// DNS TXT record value for publishing the public key.
/// `p=` is base64 of the DER SubjectPublicKeyInfo — the form produced by
/// `openssl rsa -pubout` and expected by real-world verifiers (Gmail,
/// OpenDKIM, dkimpy).
pub fn dns_txt_record(key: &RsaKey) -> String {
    let rsa_pub = key.public_key_der();
    let p = util::base64_encode(&spki_from_rsa_public_key(&rsa_pub));
    format!("v=DKIM1; k=rsa; p={}", p)
}

/// Wrap a DER RSAPublicKey in a SubjectPublicKeyInfo envelope:
/// SEQUENCE { SEQUENCE { OID rsaEncryption, NULL }, BIT STRING { key } }
fn spki_from_rsa_public_key(rsa_pub: &[u8]) -> Vec<u8> {
    const ALG_ID: &[u8] = &[
        0x30, 0x0d, 0x06, 0x09, 0x2a, 0x86, 0x48, 0x86, 0xf7, 0x0d, 0x01, 0x01, 0x01, 0x05, 0x00,
    ];
    let mut bitstring = vec![0x03];
    bitstring.extend_from_slice(&der_len(rsa_pub.len() + 1));
    bitstring.push(0x00); // zero unused bits
    bitstring.extend_from_slice(rsa_pub);

    let inner_len = ALG_ID.len() + bitstring.len();
    let mut out = vec![0x30];
    out.extend_from_slice(&der_len(inner_len));
    out.extend_from_slice(ALG_ID);
    out.extend_from_slice(&bitstring);
    out
}

/// DER definite-length encoding.
fn der_len(len: usize) -> Vec<u8> {
    if len < 128 {
        vec![len as u8]
    } else {
        let bytes: Vec<u8> = len.to_be_bytes().iter().copied().skip_while(|&b| b == 0).collect();
        let mut v = vec![0x80 | bytes.len() as u8];
        v.extend_from_slice(&bytes);
        v
    }
}

// ---------------------------------------------------------------------------
// Message parsing
// ---------------------------------------------------------------------------

fn split_message(raw: &[u8]) -> (Vec<String>, &[u8]) {
    // Find header/body separator: \r\n\r\n or \n\n
    let text = String::from_utf8_lossy(raw);
    let (hdr_str, body_start) = if let Some(i) = find_double_crlf(raw) {
        (
            String::from_utf8_lossy(raw.get(..i).unwrap_or(&[])).into_owned(),
            i.saturating_add(4),
        )
    } else if text.contains("\n\n") {
        // body starts after \n\n; if lines were LF-only
        let byte_i = raw
            .windows(2)
            .position(|w| w == b"\n\n")
            .unwrap_or(raw.len());
        (
            String::from_utf8_lossy(raw.get(..byte_i).unwrap_or(&[])).into_owned(),
            byte_i.saturating_add(2),
        )
    } else {
        (text.into_owned(), raw.len())
    };

    let headers = parse_header_fields(&hdr_str);
    let body = raw.get(body_start.min(raw.len())..).unwrap_or(&[]);
    (headers, body)
}

fn find_double_crlf(raw: &[u8]) -> Option<usize> {
    raw.windows(4).position(|w| w == b"\r\n\r\n")
}

/// Unfold and split into header fields (each without final CRLF, may contain internal folds).
fn parse_header_fields(hdr: &str) -> Vec<String> {
    let mut fields = Vec::new();
    let mut cur = String::new();
    for line in hdr.split('\n') {
        let line = line.strip_suffix('\r').unwrap_or(line);
        if line.is_empty() && cur.is_empty() {
            continue;
        }
        // continuation: starts with WSP
        if !cur.is_empty()
            && line
                .bytes()
                .next()
                .map(|b| b == b' ' || b == b'\t')
                .unwrap_or(false)
        {
            cur.push('\n');
            cur.push_str(line);
        } else {
            if !cur.is_empty() {
                fields.push(cur);
            }
            cur = line.to_string();
        }
    }
    if !cur.is_empty() {
        fields.push(cur);
    }
    fields
}

fn find_header<'a>(headers: &'a [String], name: &str) -> Option<&'a str> {
    for h in headers {
        if let Some(colon) = h.find(':') {
            let n = h.get(..colon).unwrap_or("").trim();
            if n.eq_ignore_ascii_case(name) {
                return Some(h.as_str());
            }
        }
    }
    None
}

// ---------------------------------------------------------------------------
// Canonicalization (RFC 6376 §3.4)
// ---------------------------------------------------------------------------

/// Relaxed header canonicalization of a single field. Returns `name:value\r\n`.
pub fn canonicalize_header_relaxed(field: &str) -> String {
    // field may contain folded lines with \n or \r\n
    let (name_raw, value) = if let Some(colon) = field.find(':') {
        (
            field.get(..colon).unwrap_or("").to_string(),
            field.get(colon + 1..).unwrap_or("").to_string(),
        )
    } else {
        (field.to_string(), String::new())
    };

    // lowercase name; trim WSP around name (before colon already split)
    let name = name_raw.to_ascii_lowercase().trim().to_string();

    // unfold: remove CRLF/LF that is followed by WSP (already in value as \n + WSP)
    // convert newlines in value to nothing (unfold)
    let mut unfolded = String::new();
    let bytes = value.as_bytes();
    let mut i = 0;
    while i < bytes.len() {
        if bytes[i] == b'\r' && i + 1 < bytes.len() && bytes[i + 1] == b'\n' {
            // CRLF: if next is WSP, skip CRLF (unfold); else skip (end)
            if i + 2 < bytes.len() && is_wsp(bytes[i + 2]) {
                i += 2;
                continue;
            }
            // trailing or not continuation — treat as line end, skip
            i += 2;
            continue;
        }
        if bytes[i] == b'\n' {
            if i + 1 < bytes.len() && is_wsp(bytes[i + 1]) {
                i += 1;
                continue;
            }
            i += 1;
            continue;
        }
        unfolded.push(bytes[i] as char);
        i += 1;
    }

    // collapse WSP to single SP
    let collapsed = collapse_wsp(&unfolded);
    // delete WSP at end of value
    let trimmed = collapsed.trim_end_matches(|c| c == ' ' || c == '\t');
    // delete WSP at start of value (WSP around colon)
    let trimmed = trimmed.trim_start_matches(|c| c == ' ' || c == '\t');

    format!("{}:{}\r\n", name, trimmed)
}

/// Relaxed body canonicalization.
pub fn canonicalize_body_relaxed(body: &[u8]) -> Vec<u8> {
    // Normalize to lines ending with \n for processing
    let mut lines: Vec<Vec<u8>> = Vec::new();
    let mut cur = Vec::new();
    let mut i = 0;
    while i < body.len() {
        if body[i] == b'\r' && i + 1 < body.len() && body[i + 1] == b'\n' {
            lines.push(cur);
            cur = Vec::new();
            i += 2;
        } else if body[i] == b'\n' {
            lines.push(cur);
            cur = Vec::new();
            i += 1;
        } else {
            cur.push(body[i]);
            i += 1;
        }
    }
    // incomplete last line without terminator
    if !cur.is_empty() {
        lines.push(cur);
    }

    // (a) strip trailing WSP per line; collapse internal WSP to single SP
    let mut processed: Vec<Vec<u8>> = lines
        .into_iter()
        .map(|line| {
            let mut v = line;
            while v.last().map(|b| is_wsp(*b)).unwrap_or(false) {
                v.pop();
            }
            collapse_wsp_bytes(&v)
        })
        .collect();

    // (b) ignore trailing empty lines
    while processed.last().map(|l| l.is_empty()).unwrap_or(false) {
        processed.pop();
    }

    // empty body → empty input (relaxed)
    if processed.is_empty() {
        return Vec::new();
    }

    let mut out = Vec::new();
    for line in &processed {
        out.extend_from_slice(line);
        out.extend_from_slice(b"\r\n");
    }
    out
}

fn is_wsp(b: u8) -> bool {
    b == b' ' || b == b'\t'
}

fn collapse_wsp(s: &str) -> String {
    let mut out = String::with_capacity(s.len());
    let mut prev_wsp = false;
    for c in s.chars() {
        if c == ' ' || c == '\t' {
            if !prev_wsp {
                out.push(' ');
                prev_wsp = true;
            }
        } else {
            out.push(c);
            prev_wsp = false;
        }
    }
    out
}

fn collapse_wsp_bytes(s: &[u8]) -> Vec<u8> {
    let mut out = Vec::with_capacity(s.len());
    let mut prev_wsp = false;
    for &b in s {
        if is_wsp(b) {
            if !prev_wsp {
                out.push(b' ');
                prev_wsp = true;
            }
        } else {
            out.push(b);
            prev_wsp = false;
        }
    }
    out
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn rfc6376_relaxed_header_example() {
        // RFC 6376 §3.4.5 Example 1 headers:
        // A: <SP> X <CRLF>
        // B <SP> : <SP> Y <HTAB><CRLF>
        //         <HTAB> Z <SP><SP><CRLF>
        let field_a = "A: X";
        let field_b = "B : Y\t\n\t Z  ";

        let ca = canonicalize_header_relaxed(field_a);
        assert_eq!(ca, "a:X\r\n");

        let cb = canonicalize_header_relaxed(field_b);
        // b:Y <SP> Z
        assert_eq!(cb, "b:Y Z\r\n");
    }

    #[test]
    fn rfc6376_relaxed_body_example() {
        // Body:
        // <SP> C <SP><CRLF>
        // D <SP><HTAB><SP> E <CRLF>
        // <CRLF>
        // <CRLF>
        let body = b" C \r\nD \t E\r\n\r\n\r\n";
        let canon = canonicalize_body_relaxed(body);
        // <SP> C <CRLF>
        // D <SP> E <CRLF>
        assert_eq!(canon, b" C\r\nD E\r\n");
    }

    #[test]
    fn rfc6376_relaxed_empty_body_hash() {
        let canon = canonicalize_body_relaxed(b"");
        assert!(canon.is_empty());
        let h = crypto::sha256(&canon);
        let b64 = util::base64_encode(&h);
        // RFC 6376 §3.4.4
        assert_eq!(b64, "47DEQpj8HBSa+/TImW+5JCeuQeRkm5NMpJWZG3hSuFU=");
    }

    #[test]
    fn rfc6376_full_message_relaxed() {
        // Full example from §3.4.5
        let msg = b"A: X\r\nB : Y\t\r\n\t Z  \r\n\r\n C \r\nD \t E\r\n\r\n\r\n";
        let (headers, body) = split_message(msg);
        assert_eq!(headers.len(), 2);
        let h0 = canonicalize_header_relaxed(&headers[0]);
        let h1 = canonicalize_header_relaxed(&headers[1]);
        assert_eq!(h0, "a:X\r\n");
        assert_eq!(h1, "b:Y Z\r\n");
        let bc = canonicalize_body_relaxed(body);
        assert_eq!(bc, b" C\r\nD E\r\n");
    }

    #[test]
    fn sign_produces_dkim_header() {
        let pem = "-----BEGIN RSA PRIVATE KEY-----\n\
MIICXQIBAAKBgQC+v+fwXgsS/AxQtvt+4WdkVebBKKRN79O/TH1gAQla79A5zjna\n\
LksqG/EuaVgRNo+fcxkuJd/xoPWP60vAZAZiojVk5g3BOYp3Qnl7d4W58QZPX9KU\n\
te+A4kO+HzZCZ9v/+MCOo/KwrHyEpWwrUJQCseWpmZgjF09f4s3QpnHq8wIDAQAB\n\
AoGBALtGQFo+ipLWAOVR8XLtrAvXRpmH5GBcQMFFQKZ7/gpY/k9yiFwMLWGnU1Ak\n\
vwEPV0zNvQAQ0WAyjkUBVzsJOTXz/nO2PeiR/eaIryuXnYxPkUb4PZ6/zFECPR2V\n\
/wg3YcbVrtCnmUKB62hluNOUArLGK3CUGmd3sCSLjJb4Iis5AkEA777lUJ4on28N\n\
kEIZ/Sd/BtKWsIZOd6l7ocp88dYbbqxGBCb7ZqUYywEmpMNazxy6BJcNGjhQsn/o\n\
DfmfHE33nQJBAMuunmhjCkbza81ylBJbYbbmDTGa79UrJjiPP9oWZg7BPuGYXD2V\n\
/y+5ETezFhLTaDNYB6QjKSHvNH9Zt0GOj88CQAtenjlohryo45fHyru6t8d3DTZp\n\
6Ca8nuRZWfuOD9b7zIY94wZHJhnagB6oNRJFZnz5POHVcd5FOpgPEoChIfECQGgz\n\
lWbiBEf4EJayn34ksgDYALf4A+qSgKM+5fO0sdGqm3jecZIwQrUvgNd2DzziWtSp\n\
nH8kXc62iaz9QPuQ65ECQQDZb9u4AHdPi9d5IINOMgN5mZ1TbDYH/z4s7QHeKGmK\n\
QnKcg6jvEzpc5zxAT1oYERfocK0XNetovfMnrwnC2Tqe\n\
-----END RSA PRIVATE KEY-----\n";
        let key = crypto::RsaKey::from_pem(pem).unwrap();
        let msg = b"From: alice@example.com\r\n\
To: bob@example.org\r\n\
Subject: Hi\r\n\
Date: Mon, 1 Jan 2024 00:00:00 +0000\r\n\
Message-ID: <1@example.com>\r\n\
\r\n\
Hello body\r\n";
        let hdr = sign(msg, "example.com", "mail", &key).expect("sign");
        assert!(hdr.starts_with("DKIM-Signature:"));
        assert!(hdr.contains("v=1"));
        assert!(hdr.contains("a=rsa-sha256"));
        assert!(hdr.contains("c=relaxed/relaxed"));
        assert!(hdr.contains("d=example.com"));
        assert!(hdr.contains("s=mail"));
        assert!(hdr.contains("bh="));
        assert!(hdr.contains("b="));
        assert!(hdr.contains("h="));
        // all present headers listed
        let lower = hdr.to_ascii_lowercase();
        assert!(lower.contains("from"));
        assert!(lower.contains("subject"));
    }
}
