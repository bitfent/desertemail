//! Password hashing: PBKDF2-HMAC-SHA256 from scratch on crypto::sha256.
//! Stored format: `pbkdf2_sha256$<iterations>$<salt_b64>$<hash_b64>`

use crate::crypto;
use crate::util;

/// Default PBKDF2 iteration count (OWASP-style recommendation for SHA-256).
pub const DEFAULT_ITERATIONS: u32 = 210_000;

const HASH_PREFIX: &str = "pbkdf2_sha256$";
const DK_LEN: usize = 32;
const SALT_LEN: usize = 16;

// ---------------------------------------------------------------------------
// HMAC-SHA256
// ---------------------------------------------------------------------------

fn hmac_sha256(key: &[u8], message: &[u8]) -> [u8; 32] {
    const BLOCK: usize = 64;
    let mut k = [0u8; BLOCK];
    if key.len() > BLOCK {
        let dig = crypto::sha256(key);
        k[..32].copy_from_slice(&dig);
    } else {
        k[..key.len()].copy_from_slice(key);
    }

    let mut ipad = [0x36u8; BLOCK];
    let mut opad = [0x5cu8; BLOCK];
    for i in 0..BLOCK {
        ipad[i] ^= k[i];
        opad[i] ^= k[i];
    }

    let mut inner = Vec::with_capacity(BLOCK + message.len());
    inner.extend_from_slice(&ipad);
    inner.extend_from_slice(message);
    let ih = crypto::sha256(&inner);

    let mut outer = Vec::with_capacity(BLOCK + 32);
    outer.extend_from_slice(&opad);
    outer.extend_from_slice(&ih);
    crypto::sha256(&outer)
}

// ---------------------------------------------------------------------------
// PBKDF2-HMAC-SHA256 (RFC 8018)
// ---------------------------------------------------------------------------

/// Derive `dk_len` bytes with PBKDF2-HMAC-SHA256.
pub fn pbkdf2_hmac_sha256(password: &[u8], salt: &[u8], iterations: u32, dk_len: usize) -> Vec<u8> {
    if iterations == 0 || dk_len == 0 {
        return Vec::new();
    }
    let hlen = 32usize;
    let n_blocks = (dk_len + hlen - 1) / hlen;
    let mut dk = Vec::with_capacity(n_blocks * hlen);

    for i in 1u32..=(n_blocks as u32) {
        let mut msg = Vec::with_capacity(salt.len() + 4);
        msg.extend_from_slice(salt);
        msg.extend_from_slice(&i.to_be_bytes());

        let mut u = hmac_sha256(password, &msg);
        let mut t = u;
        for _ in 1..iterations {
            u = hmac_sha256(password, &u);
            for j in 0..32 {
                t[j] ^= u[j];
            }
        }
        dk.extend_from_slice(&t);
    }
    dk.truncate(dk_len);
    dk
}

// ---------------------------------------------------------------------------
// Constant-time compare
// ---------------------------------------------------------------------------

fn ct_eq(a: &[u8], b: &[u8]) -> bool {
    if a.len() != b.len() {
        return false;
    }
    let mut diff = 0u8;
    for i in 0..a.len() {
        diff |= a[i] ^ b[i];
    }
    diff == 0
}

// ---------------------------------------------------------------------------
// Public API
// ---------------------------------------------------------------------------

fn random_salt() -> [u8; SALT_LEN] {
    let mut salt = [0u8; SALT_LEN];
    // Prefer OS CSPRNG via util; strengthen weak fallback with sha256(time+pid+mix).
    util::fill_random(&mut salt);
    let material = format!(
        "{}:{}:{}",
        util::now_millis(),
        std::process::id(),
        util::base64_encode(&salt)
    );
    let dig = crypto::sha256(material.as_bytes());
    // Mix: if OS RNG worked, XOR is harmless; if not, dig dominates entropy.
    for i in 0..SALT_LEN {
        salt[i] ^= dig[i];
    }
    salt
}

/// Hash `pass` with a fresh random salt. Returns the stored string format.
pub fn hash_password(pass: &str) -> String {
    hash_password_with(pass, &random_salt(), DEFAULT_ITERATIONS)
}

fn hash_password_with(pass: &str, salt: &[u8], iterations: u32) -> String {
    let dk = pbkdf2_hmac_sha256(pass.as_bytes(), salt, iterations, DK_LEN);
    format!(
        "{}{}${}${}",
        HASH_PREFIX,
        iterations,
        util::base64_encode(salt),
        util::base64_encode(&dk)
    )
}

/// Verify `pass` against a stored value.
///
/// If `stored` does not start with `pbkdf2_sha256$`, treat it as legacy
/// plaintext (exact compare). Callers should audit/warn about plaintext at startup.
pub fn verify_password(stored: &str, pass: &str) -> bool {
    if !stored.starts_with(HASH_PREFIX) {
        return stored == pass;
    }
    let rest = &stored[HASH_PREFIX.len()..];
    let mut parts = rest.splitn(3, '$');
    let iters_s = match parts.next() {
        Some(s) => s,
        None => return false,
    };
    let salt_b64 = match parts.next() {
        Some(s) => s,
        None => return false,
    };
    let hash_b64 = match parts.next() {
        Some(s) => s,
        None => return false,
    };
    let iterations: u32 = match iters_s.parse() {
        Ok(n) if n > 0 => n,
        _ => return false,
    };
    let salt = util::base64_decode(salt_b64);
    let expected = util::base64_decode(hash_b64);
    if expected.is_empty() {
        return false;
    }
    let derived = pbkdf2_hmac_sha256(pass.as_bytes(), &salt, iterations, expected.len());
    ct_eq(&derived, &expected)
}

/// True if the stored credential is a modern hash (not legacy plaintext).
pub fn is_hashed(stored: &str) -> bool {
    stored.starts_with(HASH_PREFIX)
}

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use super::*;

    // Known PBKDF2-HMAC-SHA256 vectors (password="password", salt="salt"):
    // Common test vectors (32-byte DK) used by many libraries / RFC-style examples.
    // c=1:
    //   120fb6cffcf8b32c43e7225256c4f837a86548c92ccc35480805987cb70be17b
    // c=4096:
    //   c5e478d59288c841aa530db6845c4c8d962893a001ce4e11a4963873aa98134a

    fn hex_to_bytes(s: &str) -> Vec<u8> {
        (0..s.len())
            .step_by(2)
            .filter_map(|i| {
                let end = (i + 2).min(s.len());
                u8::from_str_radix(&s[i..end], 16).ok()
            })
            .collect()
    }

    #[test]
    fn pbkdf2_sha256_vector_1_iter() {
        let dk = pbkdf2_hmac_sha256(b"password", b"salt", 1, 32);
        let expected = hex_to_bytes("120fb6cffcf8b32c43e7225256c4f837a86548c92ccc35480805987cb70be17b");
        assert_eq!(dk, expected);
    }

    #[test]
    fn pbkdf2_sha256_vector_4096_iters() {
        let dk = pbkdf2_hmac_sha256(b"password", b"salt", 4096, 32);
        let expected = hex_to_bytes("c5e478d59288c841aa530db6845c4c8d962893a001ce4e11a4963873aa98134a");
        assert_eq!(dk, expected);
    }

    #[test]
    fn hash_verify_round_trip() {
        // Use a fixed low-iter hash for speed in tests via the stored format.
        let salt = b"testsalt12345678"; // 16 bytes
        let stored = hash_password_with("s3cret!", salt, 1000);
        assert!(stored.starts_with(HASH_PREFIX));
        assert!(verify_password(&stored, "s3cret!"));
        assert!(!verify_password(&stored, "wrong"));
        assert!(!verify_password(&stored, ""));
    }

    #[test]
    fn hash_password_default_round_trip() {
        // Real default iterations — slower but validates the public API.
        let stored = hash_password("hello-world");
        assert!(is_hashed(&stored));
        assert!(verify_password(&stored, "hello-world"));
        assert!(!verify_password(&stored, "hello-world!"));
    }

    #[test]
    fn legacy_plaintext_compat() {
        assert!(verify_password("changeme", "changeme"));
        assert!(!verify_password("changeme", "other"));
        assert!(!is_hashed("changeme"));
    }

    #[test]
    fn malformed_stored_hash() {
        assert!(!verify_password("pbkdf2_sha256$", "x"));
        assert!(!verify_password("pbkdf2_sha256$abc$def$ghi", "x"));
        assert!(!verify_password("pbkdf2_sha256$0$c2FsdA==$YWJjZA==", "x"));
    }

    #[test]
    fn ct_eq_basic() {
        assert!(ct_eq(b"abc", b"abc"));
        assert!(!ct_eq(b"abc", b"abd"));
        assert!(!ct_eq(b"abc", b"ab"));
    }
}
