//! Cryptography for DKIM/ACME: SHA-256 via ring, minimal bignum, RSA PKCS#1 v1.5
//! (sign/verify via ring when possible; hand-rolled keygen + bignum remain).
//!
//! ring 0.17 is already compiled into every binary via rustls's "ring" feature;
//! using it for attacker-facing primitives adds no new supply-chain weight.

use std::fs;
use std::path::Path;

use ring::digest;
use ring::rand::SystemRandom;
use ring::signature::{self, RsaKeyPair};

use crate::util;

// ---------------------------------------------------------------------------
// SHA-256 (ring::digest — audited, constant-time implementation)
// ---------------------------------------------------------------------------

/// Compute SHA-256 digest of `data`.
pub fn sha256(data: &[u8]) -> [u8; 32] {
    let dig = digest::digest(&digest::SHA256, data);
    let mut out = [0u8; 32];
    out.copy_from_slice(dig.as_ref());
    out
}

/// Constant-time equality of two byte slices (via ring). Length mismatch → false.
#[allow(deprecated)] // ring re-exports constant_time as deprecated_constant_time; still the public API
pub fn ct_eq(a: &[u8], b: &[u8]) -> bool {
    ring::constant_time::verify_slices_are_equal(a, b).is_ok()
}

// ---------------------------------------------------------------------------
// Minimal unsigned bignum (little-endian u32 limbs)
// ---------------------------------------------------------------------------

/// Unsigned multi-precision integer (little-endian limbs).
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct BigUint {
    limbs: Vec<u32>,
}

impl BigUint {
    pub fn zero() -> Self {
        Self { limbs: vec![0] }
    }

    pub fn from_u32(v: u32) -> Self {
        Self { limbs: vec![v] }
    }

    /// Parse big-endian bytes (leading zeros stripped after).
    pub fn from_be_bytes(bytes: &[u8]) -> Self {
        if bytes.is_empty() {
            return Self::zero();
        }
        let mut limbs = Vec::new();
        let mut i = bytes.len();
        while i > 0 {
            let start = i.saturating_sub(4);
            let mut val = 0u32;
            for &b in &bytes[start..i] {
                val = (val << 8) | (b as u32);
            }
            limbs.push(val);
            i = start;
        }
        let mut n = Self { limbs };
        n.normalize();
        n
    }

    /// Big-endian bytes, minimal (no leading zero unless value is zero).
    pub fn to_be_bytes(&self) -> Vec<u8> {
        if self.is_zero() {
            return vec![0];
        }
        let mut out = Vec::with_capacity(self.limbs.len() * 4);
        let last = *self.limbs.last().unwrap();
        if last > 0x00ff_ffff {
            out.extend_from_slice(&last.to_be_bytes());
        } else if last > 0x0000_ffff {
            out.push((last >> 16) as u8);
            out.push((last >> 8) as u8);
            out.push(last as u8);
        } else if last > 0x0000_00ff {
            out.push((last >> 8) as u8);
            out.push(last as u8);
        } else {
            out.push(last as u8);
        }
        for &limb in self.limbs.iter().rev().skip(1) {
            out.extend_from_slice(&limb.to_be_bytes());
        }
        out
    }

    /// Fixed-width big-endian (left-padded with zeros). Used for RSA EM / signature.
    pub fn to_be_bytes_padded(&self, width: usize) -> Vec<u8> {
        let mut raw = self.to_be_bytes();
        if raw.len() > width {
            // drop leading zeros if any overflow is only padding
            while raw.len() > width && raw[0] == 0 {
                raw.remove(0);
            }
        }
        if raw.len() > width {
            return raw[raw.len() - width..].to_vec();
        }
        let mut out = vec![0u8; width - raw.len()];
        out.extend_from_slice(&raw);
        out
    }

    fn normalize(&mut self) {
        while self.limbs.len() > 1 && *self.limbs.last().unwrap() == 0 {
            self.limbs.pop();
        }
        if self.limbs.is_empty() {
            self.limbs.push(0);
        }
    }

    pub fn is_zero(&self) -> bool {
        self.limbs.iter().all(|&l| l == 0)
    }

    fn bit_len(&self) -> usize {
        if self.is_zero() {
            return 0;
        }
        let last = *self.limbs.last().unwrap();
        (self.limbs.len() - 1) * 32 + (32 - last.leading_zeros() as usize)
    }

    fn get_bit(&self, i: usize) -> bool {
        let limb = i / 32;
        let bit = i % 32;
        self.limbs.get(limb).map(|l| (l >> bit) & 1 == 1).unwrap_or(false)
    }

    fn cmp(&self, other: &Self) -> std::cmp::Ordering {
        let max = self.limbs.len().max(other.limbs.len());
        for i in (0..max).rev() {
            let x = self.limbs.get(i).copied().unwrap_or(0);
            let y = other.limbs.get(i).copied().unwrap_or(0);
            match x.cmp(&y) {
                std::cmp::Ordering::Equal => {}
                o => return o,
            }
        }
        std::cmp::Ordering::Equal
    }

    pub fn sub(&self, other: &Self) -> Option<Self> {
        if self.cmp(other) == std::cmp::Ordering::Less {
            return None;
        }
        let n = self.limbs.len();
        let mut limbs = Vec::with_capacity(n);
        let mut borrow = 0i64;
        for i in 0..n {
            let a = self.limbs[i] as i64;
            let b = other.limbs.get(i).copied().unwrap_or(0) as i64;
            let mut d = a - b - borrow;
            if d < 0 {
                d += 1i64 << 32;
                borrow = 1;
            } else {
                borrow = 0;
            }
            limbs.push(d as u32);
        }
        let mut r = Self { limbs };
        r.normalize();
        Some(r)
    }

    pub fn mul(&self, other: &Self) -> Self {
        if self.is_zero() || other.is_zero() {
            return Self::zero();
        }
        let mut limbs = vec![0u32; self.limbs.len() + other.limbs.len()];
        for i in 0..self.limbs.len() {
            let mut carry = 0u64;
            for j in 0..other.limbs.len() {
                let p = (self.limbs[i] as u64) * (other.limbs[j] as u64)
                    + limbs[i + j] as u64
                    + carry;
                limbs[i + j] = p as u32;
                carry = p >> 32;
            }
            let mut k = i + other.limbs.len();
            while carry > 0 {
                if k >= limbs.len() {
                    limbs.push(0);
                }
                let s = limbs[k] as u64 + carry;
                limbs[k] = s as u32;
                carry = s >> 32;
                k += 1;
            }
        }
        let mut r = Self { limbs };
        r.normalize();
        r
    }

    /// Integer division: returns (quotient, remainder).
    pub fn div_rem(&self, divisor: &Self) -> (Self, Self) {
        assert!(!divisor.is_zero(), "division by zero");
        if self.cmp(divisor) == std::cmp::Ordering::Less {
            return (Self::zero(), self.clone());
        }
        if divisor.limbs.len() == 1 {
            return self.div_rem_u32(divisor.limbs[0]);
        }

        // Knuth long division (binary shift method — simple and correct)
        let mut rem = self.clone();
        let mut quot = Self::zero();
        let shift = self.bit_len().saturating_sub(divisor.bit_len());
        let mut d = divisor.clone();
        // d <<= shift
        d = d.shl(shift);

        for s in (0..=shift).rev() {
            if rem.cmp(&d) != std::cmp::Ordering::Less {
                rem = rem.sub(&d).unwrap();
                // set bit s in quot
                quot = quot.set_bit(s);
            }
            d = d.shr1();
        }
        rem.normalize();
        quot.normalize();
        (quot, rem)
    }

    fn div_rem_u32(&self, d: u32) -> (Self, Self) {
        assert!(d != 0);
        let mut quot = vec![0u32; self.limbs.len()];
        let mut rem = 0u64;
        for i in (0..self.limbs.len()).rev() {
            let cur = (rem << 32) | self.limbs[i] as u64;
            quot[i] = (cur / d as u64) as u32;
            rem = cur % d as u64;
        }
        let mut q = Self { limbs: quot };
        q.normalize();
        (q, Self::from_u32(rem as u32))
    }

    fn shl(&self, bits: usize) -> Self {
        if bits == 0 || self.is_zero() {
            return self.clone();
        }
        let limb_shift = bits / 32;
        let bit_shift = bits % 32;
        let mut limbs = vec![0u32; limb_shift];
        if bit_shift == 0 {
            limbs.extend_from_slice(&self.limbs);
        } else {
            let mut carry = 0u32;
            for &l in &self.limbs {
                limbs.push((l << bit_shift) | carry);
                carry = l >> (32 - bit_shift);
            }
            if carry > 0 {
                limbs.push(carry);
            }
        }
        let mut r = Self { limbs };
        r.normalize();
        r
    }

    fn shr1(&self) -> Self {
        let mut limbs = self.limbs.clone();
        let mut carry = 0u32;
        for l in limbs.iter_mut().rev() {
            let new_carry = *l & 1;
            *l = (*l >> 1) | (carry << 31);
            carry = new_carry;
        }
        let mut r = Self { limbs };
        r.normalize();
        r
    }

    fn set_bit(&self, bit: usize) -> Self {
        let limb = bit / 32;
        let b = bit % 32;
        let mut limbs = self.limbs.clone();
        if limbs.len() <= limb {
            limbs.resize(limb + 1, 0);
        }
        limbs[limb] |= 1u32 << b;
        Self { limbs }
    }

    pub fn rem(&self, modulus: &Self) -> Self {
        self.div_rem(modulus).1
    }

    pub fn add(&self, other: &Self) -> Self {
        let n = self.limbs.len().max(other.limbs.len());
        let mut limbs = Vec::with_capacity(n + 1);
        let mut carry = 0u64;
        for i in 0..n {
            let a = self.limbs.get(i).copied().unwrap_or(0) as u64;
            let b = other.limbs.get(i).copied().unwrap_or(0) as u64;
            let s = a + b + carry;
            limbs.push(s as u32);
            carry = s >> 32;
        }
        if carry > 0 {
            limbs.push(carry as u32);
        }
        let mut r = Self { limbs };
        r.normalize();
        r
    }

    /// Modular inverse via signed extended Euclidean algorithm, or None if not invertible.
    pub fn mod_inverse(&self, modulus: &Self) -> Option<Self> {
        if modulus.is_zero() {
            return None;
        }
        let a = self.rem(modulus);
        if a.is_zero() {
            return None;
        }
        // Track coefficient of `a` with an explicit sign bit.
        let mut old_r = modulus.clone();
        let mut r = a;
        let mut old_s = Self::zero();
        let mut old_s_neg = false;
        let mut s = Self::from_u32(1);
        let mut s_neg = false;

        while !r.is_zero() {
            let (q, _) = old_r.div_rem(&r);
            let new_r = old_r.sub(&q.mul(&r)).unwrap_or(Self::zero());
            old_r = r;
            r = new_r;

            // new_s = old_s - q * s  (signed)
            let qs = q.mul(&s);
            let qs_neg = s_neg;
            let (ns, ns_neg) = signed_sub(&old_s, old_s_neg, &qs, qs_neg);
            old_s = s;
            old_s_neg = s_neg;
            s = ns;
            s_neg = ns_neg;
        }
        // gcd must be 1
        if !(old_r.limbs.len() == 1 && old_r.limbs[0] == 1) {
            return None;
        }
        let inv = if old_s_neg {
            modulus.sub(&old_s.rem(modulus))?
        } else {
            old_s.rem(modulus)
        };
        Some(inv)
    }

    /// Modular exponentiation: self^exp mod modulus (square-and-multiply).
    pub fn modpow(&self, exp: &Self, modulus: &Self) -> Self {
        if modulus.is_zero() {
            return Self::zero();
        }
        if modulus.limbs.len() == 1 && modulus.limbs[0] == 1 {
            return Self::zero();
        }
        let mut result = Self::from_u32(1);
        let mut base = self.rem(modulus);
        let bits = exp.bit_len();
        for i in 0..bits {
            if exp.get_bit(i) {
                result = result.mul(&base).rem(modulus);
            }
            base = base.mul(&base).rem(modulus);
        }
        result
    }
}

/// Signed subtraction of two non-negative BigUints with independent sign flags.
/// Returns (abs, is_negative).
fn signed_sub(a: &BigUint, a_neg: bool, b: &BigUint, b_neg: bool) -> (BigUint, bool) {
    // a - b with signs
    match (a_neg, b_neg) {
        (false, false) => {
            if a.cmp(b) != std::cmp::Ordering::Less {
                (a.sub(b).unwrap_or(BigUint::zero()), false)
            } else {
                (b.sub(a).unwrap_or(BigUint::zero()), true)
            }
        }
        (true, true) => {
            // -|a| - (-|b|) = |b| - |a|
            if b.cmp(a) != std::cmp::Ordering::Less {
                (b.sub(a).unwrap_or(BigUint::zero()), false)
            } else {
                (a.sub(b).unwrap_or(BigUint::zero()), true)
            }
        }
        (false, true) => (a.add(b), false),  // a - (-b) = a+b
        (true, false) => (a.add(b), true),   // -a - b = -(a+b)
    }
}

// ---------------------------------------------------------------------------
// RSA PKCS#1 v1.5 (RSASSA-PKCS1-v1_5 with SHA-256)
// ---------------------------------------------------------------------------

/// DigestInfo prefix for SHA-256 (RFC 8017 / PKCS#1).
const SHA256_DIGESTINFO_PREFIX: &[u8] = &[
    0x30, 0x31, 0x30, 0x0d, 0x06, 0x09, 0x60, 0x86, 0x48, 0x01, 0x65, 0x03, 0x04, 0x02, 0x01,
    0x05, 0x00, 0x04, 0x20,
];

/// RSA private key (n, e, d + optional CRT factors for ring signing).
///
/// Signing prefers ring's constant-time CRT path (requires full PKCS#1 factors).
/// Keys loaded from OpenSSL PEM already include p/q; pure keygen fills them;
/// n/e/d-only keys recover primes on demand. ring only signs ≥2048-bit moduli;
/// smaller legacy keys fall back to hand-rolled modpow (documented below).
#[derive(Clone, Debug)]
pub struct RsaKey {
    pub n: BigUint,
    pub e: BigUint,
    pub d: BigUint,
    /// Modulus size in bytes (k).
    pub k: usize,
    /// CRT components when known (p > q, dP, dQ, qInv).
    crt: Option<RsaCrt>,
}

/// Chinese Remainder Theorem private factors.
#[derive(Clone, Debug)]
struct RsaCrt {
    p: BigUint,
    q: BigUint,
    d_p: BigUint,
    d_q: BigUint,
    q_inv: BigUint,
}

impl RsaKey {
    /// Load PEM from file (PKCS#1 or PKCS#8).
    pub fn from_pem_file(path: &Path) -> Result<Self, String> {
        let data = fs::read_to_string(path).map_err(|e| format!("read key: {}", e))?;
        Self::from_pem(&data)
    }

    /// Parse PEM string: `BEGIN RSA PRIVATE KEY` or `BEGIN PRIVATE KEY`.
    pub fn from_pem(pem: &str) -> Result<Self, String> {
        let der = pem_to_der(pem)?;
        parse_rsa_private_key_der(&der)
    }

    /// Generate an RSA key of `bits` (e.g. 2048). Slow with schoolbook arithmetic;
    /// intended for one-shot ACME account/cert keys, not hot paths.
    /// Prefers openssl CLI when available for speed; falls back to pure-Rust.
    pub fn generate(bits: usize) -> Result<Self, String> {
        if bits < 512 || bits % 8 != 0 {
            return Err("RSA bits must be >= 512 and multiple of 8".into());
        }
        // Prefer openssl for production-sized keys (fast + well-tested).
        if bits >= 1024 {
            if let Ok(key) = generate_via_openssl(bits) {
                return Ok(key);
            }
        }
        generate_rsa_pure(bits)
    }

    /// PKCS#1 PEM (`BEGIN RSA PRIVATE KEY`).
    pub fn to_pem_pkcs1(&self) -> String {
        let der = self.to_der_pkcs1();
        let b64 = util::base64_encode(&der);
        let mut out = String::from("-----BEGIN RSA PRIVATE KEY-----\n");
        for chunk in b64.as_bytes().chunks(64) {
            out.push_str(&String::from_utf8_lossy(chunk));
            out.push('\n');
        }
        out.push_str("-----END RSA PRIVATE KEY-----\n");
        out
    }

    /// PKCS#1 RSAPrivateKey DER (version, n, e, d, p, q, dP, dQ, qInv).
    /// CRT factors are recovered from n/e/d when not already present.
    pub fn to_der_pkcs1(&self) -> Vec<u8> {
        let crt = self.ensure_crt().ok();
        let mut body = Vec::new();
        body.extend_from_slice(&encode_der_integer(&BigUint::from_u32(0))); // version
        body.extend_from_slice(&encode_der_integer(&self.n));
        body.extend_from_slice(&encode_der_integer(&self.e));
        body.extend_from_slice(&encode_der_integer(&self.d));
        if let Some(c) = crt {
            body.extend_from_slice(&encode_der_integer(&c.p));
            body.extend_from_slice(&encode_der_integer(&c.q));
            body.extend_from_slice(&encode_der_integer(&c.d_p));
            body.extend_from_slice(&encode_der_integer(&c.d_q));
            body.extend_from_slice(&encode_der_integer(&c.q_inv));
        } else {
            // Last-resort zeros (cannot feed ring; modpow path still works).
            let zero = encode_der_integer(&BigUint::from_u32(0));
            for _ in 0..5 {
                body.extend_from_slice(&zero);
            }
        }
        der_tlv(0x30, &body)
    }

    /// PKCS#8 PrivateKeyInfo DER wrapping PKCS#1 RSAPrivateKey (for ring::RsaKeyPair::from_pkcs8).
    pub fn to_der_pkcs8(&self) -> Vec<u8> {
        // AlgorithmIdentifier: rsaEncryption OID 1.2.840.113549.1.1.1 + NULL
        let oid_rsa = [
            0x06, 0x09, 0x2a, 0x86, 0x48, 0x86, 0xf7, 0x0d, 0x01, 0x01, 0x01,
        ];
        let mut alg = Vec::new();
        alg.extend_from_slice(&oid_rsa);
        alg.extend_from_slice(&[0x05, 0x00]);
        let alg_seq = der_tlv(0x30, &alg);
        let pkcs1 = self.to_der_pkcs1();
        let oct = der_tlv(0x04, &pkcs1);
        let mut body = Vec::new();
        body.extend_from_slice(&encode_der_integer(&BigUint::from_u32(0))); // version
        body.extend_from_slice(&alg_seq);
        body.extend_from_slice(&oct);
        der_tlv(0x30, &body)
    }

    /// Ensure CRT factors exist (parse-time, keygen, or recover from n/e/d).
    fn ensure_crt(&self) -> Result<RsaCrt, String> {
        if let Some(ref c) = self.crt {
            return Ok(c.clone());
        }
        recover_crt(&self.n, &self.e, &self.d)
    }

    fn with_crt_filled(mut self) -> Self {
        if self.crt.is_none() {
            self.crt = recover_crt(&self.n, &self.e, &self.d).ok();
        }
        self
    }

    /// SubjectPublicKeyInfo DER for RSA (needed by PKCS#10 CSR).
    pub fn spki_der(&self) -> Vec<u8> {
        // AlgorithmIdentifier: rsaEncryption OID 1.2.840.113549.1.1.1 + NULL
        let oid_rsa = [
            0x06, 0x09, 0x2a, 0x86, 0x48, 0x86, 0xf7, 0x0d, 0x01, 0x01, 0x01,
        ];
        let mut alg = Vec::new();
        alg.extend_from_slice(&oid_rsa);
        alg.extend_from_slice(&[0x05, 0x00]); // NULL
        let alg_seq = der_tlv(0x30, &alg);
        let rsa_pub = self.public_key_der();
        let mut bit_str = Vec::with_capacity(1 + rsa_pub.len());
        bit_str.push(0x00); // unused bits
        bit_str.extend_from_slice(&rsa_pub);
        let bit_tlv = der_tlv(0x03, &bit_str);
        let mut spki = Vec::new();
        spki.extend_from_slice(&alg_seq);
        spki.extend_from_slice(&bit_tlv);
        der_tlv(0x30, &spki)
    }

    /// Build a minimal PKCS#10 CSR DER for `common_name` (and optional SANs via CN only).
    /// Signed with sha256WithRSAEncryption.
    pub fn build_csr_der(&self, common_name: &str, san_dns: &[String]) -> Result<Vec<u8>, String> {
        // certificationRequestInfo
        let version = encode_der_integer(&BigUint::from_u32(0));
        let subject = der_name_cn(common_name, san_dns);
        let spki = self.spki_der();
        // attributes [0] EMPTY
        let attrs = der_tlv(0xa0, &[]);
        let mut info = Vec::new();
        info.extend_from_slice(&version);
        info.extend_from_slice(&subject);
        info.extend_from_slice(&spki);
        info.extend_from_slice(&attrs);
        let info_seq = der_tlv(0x30, &info);

        let sig = self.sign_sha256(&info_seq)?;
        // signatureAlgorithm sha256WithRSAEncryption
        let oid_sha256_rsa = [
            0x06, 0x09, 0x2a, 0x86, 0x48, 0x86, 0xf7, 0x0d, 0x01, 0x01, 0x0b,
        ];
        let mut sigalg = Vec::new();
        sigalg.extend_from_slice(&oid_sha256_rsa);
        sigalg.extend_from_slice(&[0x05, 0x00]);
        let sigalg_seq = der_tlv(0x30, &sigalg);
        let mut bit = Vec::with_capacity(1 + sig.len());
        bit.push(0x00);
        bit.extend_from_slice(&sig);
        let sig_bit = der_tlv(0x03, &bit);

        let mut csr = Vec::new();
        csr.extend_from_slice(&info_seq);
        csr.extend_from_slice(&sigalg_seq);
        csr.extend_from_slice(&sig_bit);
        Ok(der_tlv(0x30, &csr))
    }

    /// RSASSA-PKCS1-v1_5 sign of a raw message (hash is computed here).
    ///
    /// Prefers ring's constant-time CRT signer (PKCS#8 DER). ring only accepts
    /// moduli in [2048, 4096] bits with e ≥ 65537; smaller legacy DKIM keys
    /// fall back to hand-rolled modpow (`sign_sha256_modpow`).
    pub fn sign_sha256(&self, message: &[u8]) -> Result<Vec<u8>, String> {
        match self.sign_sha256_ring(message) {
            Ok(sig) => Ok(sig),
            Err(ring_err) => {
                // ring rejects <2048-bit keys; keep legacy path for those only.
                if self.k * 8 < 2048 {
                    self.sign_sha256_modpow(message)
                } else {
                    Err(ring_err)
                }
            }
        }
    }

    /// ring-backed PKCS#1 v1.5 SHA-256 signature.
    fn sign_sha256_ring(&self, message: &[u8]) -> Result<Vec<u8>, String> {
        let pkcs8 = self.to_der_pkcs8();
        let key_pair = RsaKeyPair::from_pkcs8(&pkcs8)
            .map_err(|e| format!("ring RSA key rejected: {}", e))?;
        let mut sig = vec![0u8; key_pair.public().modulus_len()];
        let rng = SystemRandom::new();
        key_pair
            .sign(&signature::RSA_PKCS1_SHA256, &rng, message, &mut sig)
            .map_err(|_| "ring RSA sign failed".to_string())?;
        Ok(sig)
    }

    /// Hand-rolled RSASSA-PKCS1-v1_5 (modpow). Used as fallback for <2048-bit
    /// keys and for cross-check tests against ring output.
    pub fn sign_sha256_modpow(&self, message: &[u8]) -> Result<Vec<u8>, String> {
        let hash = sha256(message);
        self.sign_digest_sha256_modpow(&hash)
    }

    /// Sign a precomputed SHA-256 digest (32 bytes) via hand-rolled modpow.
    fn sign_digest_sha256_modpow(&self, hash: &[u8]) -> Result<Vec<u8>, String> {
        if hash.len() != 32 {
            return Err("SHA-256 digest must be 32 bytes".into());
        }
        let mut t = Vec::with_capacity(SHA256_DIGESTINFO_PREFIX.len() + 32);
        t.extend_from_slice(SHA256_DIGESTINFO_PREFIX);
        t.extend_from_slice(hash);

        let k = self.k;
        if k < t.len() + 11 {
            return Err("RSA modulus too small for PKCS#1 v1.5".into());
        }

        // EM = 0x00 || 0x01 || PS || 0x00 || T
        let mut em = vec![0u8; k];
        em[0] = 0x00;
        em[1] = 0x01;
        let ps_len = k - t.len() - 3;
        for i in 0..ps_len {
            em[2 + i] = 0xff;
        }
        em[2 + ps_len] = 0x00;
        em[3 + ps_len..].copy_from_slice(&t);

        let m = BigUint::from_be_bytes(&em);
        let s = m.modpow(&self.d, &self.n);
        Ok(s.to_be_bytes_padded(k))
    }

    /// DER-encoded RSAPublicKey (SEQUENCE { n, e }) for DKIM DNS TXT `p=`.
    /// Per RFC 6376 §3.6.1 (k=rsa). Built from modulus n and public exponent e.
    pub fn public_key_der(&self) -> Vec<u8> {
        let n_bytes = encode_der_integer(&self.n);
        let e_bytes = encode_der_integer(&self.e);
        let mut rsa_pub = Vec::new();
        rsa_pub.extend_from_slice(&n_bytes);
        rsa_pub.extend_from_slice(&e_bytes);
        der_tlv(0x30, &rsa_pub)
    }

    /// RSASSA-PKCS1-v1_5 verify of a raw message against a signature.
    pub fn verify_sha256(&self, message: &[u8], signature: &[u8]) -> bool {
        let pub_key = RsaPublicKey {
            n: self.n.clone(),
            e: self.e.clone(),
            k: self.k,
        };
        pub_key.verify_sha256(message, signature)
    }
}

/// RSA public key only (n, e) for DKIM verification.
#[derive(Clone, Debug)]
pub struct RsaPublicKey {
    pub n: BigUint,
    pub e: BigUint,
    pub k: usize,
}

impl RsaPublicKey {
    /// Parse DER RSAPublicKey (SEQUENCE { n, e }) or SubjectPublicKeyInfo wrapping it.
    pub fn from_der(der: &[u8]) -> Result<Self, String> {
        // Try SPKI first: SEQUENCE { AlgorithmIdentifier, BIT STRING }
        if let Ok(pk) = parse_spki_rsa(der) {
            return Ok(pk);
        }
        parse_rsa_public_key_der(der)
    }

    /// Verify PKCS#1 v1.5 SHA-256 signature.
    ///
    /// Prefers ring:
    /// - `RSA_PKCS1_2048_8192_SHA256` for moduli ≥ 2048 bits
    /// - `RSA_PKCS1_1024_8192_SHA256_FOR_LEGACY_USE_ONLY` for 1024–2047 bit DKIM keys
    ///   still seen in the wild
    /// Hand-rolled modpow verify is kept only for sizes ring rejects (<1024 bits).
    pub fn verify_sha256(&self, message: &[u8], signature: &[u8]) -> bool {
        if self.verify_sha256_ring(message, signature) {
            return true;
        }
        // ring returned false — either invalid sig or unsupported size.
        // Only fall back for sizes ring cannot check (modulus < 1024 bits).
        if self.k * 8 < 1024 {
            return self.verify_sha256_modpow(message, signature);
        }
        false
    }

    fn verify_sha256_ring(&self, message: &[u8], signature: &[u8]) -> bool {
        let n_bytes = self.n.to_be_bytes();
        let e_bytes = self.e.to_be_bytes();
        let components = signature::RsaPublicKeyComponents {
            n: n_bytes.as_slice(),
            e: e_bytes.as_slice(),
        };
        // Prefer modern 2048+ params; fall through to legacy 1024+ for smaller keys.
        if self.k >= 256 {
            if components
                .verify(&signature::RSA_PKCS1_2048_8192_SHA256, message, signature)
                .is_ok()
            {
                return true;
            }
        }
        if self.k >= 128 {
            return components
                .verify(
                    &signature::RSA_PKCS1_1024_8192_SHA256_FOR_LEGACY_USE_ONLY,
                    message,
                    signature,
                )
                .is_ok();
        }
        false
    }

    /// Hand-rolled verify (for <1024-bit moduli ring rejects, and tests).
    pub fn verify_sha256_modpow(&self, message: &[u8], signature: &[u8]) -> bool {
        let hash = sha256(message);
        if hash.len() != 32 {
            return false;
        }
        let k = self.k;
        if signature.len() != k || k < 11 {
            return false;
        }
        let s = BigUint::from_be_bytes(signature);
        if s.cmp(&self.n) != std::cmp::Ordering::Less {
            return false;
        }
        let m = s.modpow(&self.e, &self.n);
        let em = m.to_be_bytes_padded(k);

        if em.get(0).copied() != Some(0x00) || em.get(1).copied() != Some(0x01) {
            return false;
        }
        let mut i = 2usize;
        while i < em.len() && em.get(i).copied() == Some(0xff) {
            i += 1;
        }
        if i < 10 {
            return false;
        }
        if em.get(i).copied() != Some(0x00) {
            return false;
        }
        i += 1;
        let t = em.get(i..).unwrap_or(&[]);
        if t.len() != SHA256_DIGESTINFO_PREFIX.len() + 32 {
            return false;
        }
        if t.get(..SHA256_DIGESTINFO_PREFIX.len()).unwrap_or(&[]) != SHA256_DIGESTINFO_PREFIX {
            return false;
        }
        let digest_ok = t
            .get(SHA256_DIGESTINFO_PREFIX.len()..)
            .unwrap_or(&[])
            .len()
            == 32
            && ct_eq(
                t.get(SHA256_DIGESTINFO_PREFIX.len()..).unwrap_or(&[]),
                &hash,
            );
        digest_ok
    }
}

fn parse_rsa_public_key_der(der: &[u8]) -> Result<RsaPublicKey, String> {
    let mut top = DerReader::new(der);
    let mut seq = top.enter_sequence()?;
    let n = seq.read_integer()?;
    let e = seq.read_integer()?;
    let k = (n.bit_len() + 7) / 8;
    if k < 64 {
        return Err(format!("RSA modulus too small ({} bytes)", k));
    }
    Ok(RsaPublicKey { n, e, k })
}

fn parse_spki_rsa(der: &[u8]) -> Result<RsaPublicKey, String> {
    let mut top = DerReader::new(der);
    let mut seq = top.enter_sequence()?;
    // AlgorithmIdentifier SEQUENCE
    let _alg = seq.expect_tag(0x30)?;
    // BIT STRING
    let bits = seq.expect_tag(0x03)?;
    if bits.is_empty() {
        return Err("empty BIT STRING".into());
    }
    // first byte = number of unused bits
    let key_der = bits.get(1..).ok_or("BIT STRING truncated")?;
    parse_rsa_public_key_der(key_der)
}

pub fn encode_der_integer(n: &BigUint) -> Vec<u8> {
    let mut bytes = n.to_be_bytes();
    // DER INTEGER: if high bit set, prepend 0x00 (positive)
    if bytes[0] & 0x80 != 0 {
        bytes.insert(0, 0x00);
    }
    der_tlv(0x02, &bytes)
}

pub fn der_tlv(tag: u8, value: &[u8]) -> Vec<u8> {
    let mut out = Vec::with_capacity(2 + value.len() + 4);
    out.push(tag);
    encode_der_length(&mut out, value.len());
    out.extend_from_slice(value);
    out
}

fn encode_der_length(out: &mut Vec<u8>, len: usize) {
    if len < 0x80 {
        out.push(len as u8);
    } else if len <= 0xff {
        out.push(0x81);
        out.push(len as u8);
    } else if len <= 0xffff {
        out.push(0x82);
        out.push((len >> 8) as u8);
        out.push(len as u8);
    } else {
        out.push(0x83);
        out.push((len >> 16) as u8);
        out.push((len >> 8) as u8);
        out.push(len as u8);
    }
}

/// X.500 Name: CN=<common_name>. Optional SANs are encoded only in CN list for simplicity
/// (ACME HTTP-01 uses CN + we put first domain as CN; multi-domain via multiple CN RDNs).
fn der_name_cn(common_name: &str, san_dns: &[String]) -> Vec<u8> {
    // AttributeTypeAndValue: OID 2.5.4.3 (CN) + UTF8String
    let oid_cn = [0x06, 0x03, 0x55, 0x04, 0x03];
    let mut names: Vec<String> = vec![common_name.to_string()];
    for s in san_dns {
        if s != common_name && !names.contains(s) {
            names.push(s.clone());
        }
    }
    let mut rdns = Vec::new();
    // Only first CN in subject (ACME validates via CSR SAN extension is optional for LE
    // if order identifiers match; LE accepts CN-only CSRs for single name).
    let cn = names.first().map(|s| s.as_str()).unwrap_or(common_name);
    let mut atv = Vec::new();
    atv.extend_from_slice(&oid_cn);
    atv.extend_from_slice(&der_tlv(0x0c, cn.as_bytes())); // UTF8String
    let atv_seq = der_tlv(0x30, &atv);
    let set = der_tlv(0x31, &atv_seq); // SET OF AttributeTypeAndValue
    rdns.extend_from_slice(&set);
    // If multiple SANs, add subjectAltName extension via attributes is complex;
    // LE accepts CSR with just CN for one domain; multi-domain order uses same key
    // and identifiers from the order. Add extra CN RDNs for visibility.
    for extra in names.iter().skip(1) {
        let mut atv = Vec::new();
        atv.extend_from_slice(&oid_cn);
        atv.extend_from_slice(&der_tlv(0x0c, extra.as_bytes()));
        let atv_seq = der_tlv(0x30, &atv);
        let set = der_tlv(0x31, &atv_seq);
        rdns.extend_from_slice(&set);
    }
    der_tlv(0x30, &rdns)
}

fn generate_via_openssl(bits: usize) -> Result<RsaKey, String> {
    let tmp = std::env::temp_dir().join(format!(
        "de_rsa_{}_{}.pem",
        std::process::id(),
        util::now_millis()
    ));
    let status = std::process::Command::new("openssl")
        .args([
            "genrsa",
            "-out",
            tmp.to_str().unwrap_or("de_rsa.pem"),
            &bits.to_string(),
        ])
        .stdout(std::process::Stdio::null())
        .stderr(std::process::Stdio::null())
        .status()
        .map_err(|e| format!("openssl: {}", e))?;
    if !status.success() {
        let _ = fs::remove_file(&tmp);
        return Err("openssl genrsa failed".into());
    }
    let key = RsaKey::from_pem_file(&tmp);
    let _ = fs::remove_file(&tmp);
    key
}

fn generate_rsa_pure(bits: usize) -> Result<RsaKey, String> {
    let e = BigUint::from_u32(65537);
    let prime_bits = bits / 2;
    let mut attempts = 0u32;
    loop {
        attempts += 1;
        if attempts > 200 {
            return Err("RSA prime generation failed".into());
        }
        let mut p = random_prime(prime_bits)?;
        let mut q = random_prime(prime_bits)?;
        if p.cmp(&q) == std::cmp::Ordering::Equal {
            continue;
        }
        // ring expects 0 < q < p < n
        if p.cmp(&q) == std::cmp::Ordering::Less {
            std::mem::swap(&mut p, &mut q);
        }
        let n = p.mul(&q);
        if n.bit_len() < bits - 1 {
            continue;
        }
        let p1 = p.sub(&BigUint::from_u32(1)).ok_or("p-1")?;
        let q1 = q.sub(&BigUint::from_u32(1)).ok_or("q-1")?;
        let phi = p1.mul(&q1);
        let d = match e.mod_inverse(&phi) {
            Some(d) => d,
            None => continue,
        };
        let d_p = d.rem(&p1);
        let d_q = d.rem(&q1);
        let q_inv = match q.mod_inverse(&p) {
            Some(qi) => qi,
            None => continue,
        };
        let k = (n.bit_len() + 7) / 8;
        return Ok(RsaKey {
            n,
            e,
            d,
            k,
            crt: Some(RsaCrt {
                p,
                q,
                d_p,
                d_q,
                q_inv,
            }),
        });
    }
}

/// Euclidean GCD.
fn gcd(a: &BigUint, b: &BigUint) -> BigUint {
    let mut a = a.clone();
    let mut b = b.clone();
    while !b.is_zero() {
        let r = a.rem(&b);
        a = b;
        b = r;
    }
    a
}

/// Build CRT components from primes p > q and private exponent d.
fn crt_from_primes(p: BigUint, q: BigUint, d: &BigUint) -> Result<RsaCrt, String> {
    let (p, q) = if p.cmp(&q) == std::cmp::Ordering::Less {
        (q, p)
    } else {
        (p, q)
    };
    let one = BigUint::from_u32(1);
    let p1 = p.sub(&one).ok_or("p-1")?;
    let q1 = q.sub(&one).ok_or("q-1")?;
    let d_p = d.rem(&p1);
    let d_q = d.rem(&q1);
    let q_inv = q
        .mod_inverse(&p)
        .ok_or_else(|| "qInv not invertible".to_string())?;
    Ok(RsaCrt {
        p,
        q,
        d_p,
        d_q,
        q_inv,
    })
}

/// Recover CRT factors from n, e, d (Boneh-style: factor n via ed−1).
fn recover_crt(n: &BigUint, e: &BigUint, d: &BigUint) -> Result<RsaCrt, String> {
    let one = BigUint::from_u32(1);
    let ed = e.mul(d);
    let ktot = ed.sub(&one).ok_or("ed-1 underflow")?;
    // ktot = t * 2^s with t odd
    let mut t = ktot.clone();
    let mut s = 0u32;
    while !t.is_zero() && !t.get_bit(0) {
        t = t.shr1();
        s += 1;
    }
    if s == 0 {
        return Err("cannot recover primes: ed-1 odd".into());
    }
    let n_minus = n.sub(&one).ok_or("n-1")?;

    // Try small odd bases (deterministic, sufficient for RSA moduli we generate).
    for a_u in (2u32..200).step_by(2) {
        let a = BigUint::from_u32(a_u);
        if a.cmp(n) != std::cmp::Ordering::Less {
            break;
        }
        let mut k = t.clone();
        // Walk k = t, 2t, 4t, ... while k < ktot
        loop {
            let cand = a.modpow(&k, n);
            if cand.cmp(&one) != std::cmp::Ordering::Equal
                && cand.cmp(&n_minus) != std::cmp::Ordering::Equal
            {
                let cand2 = cand.mul(&cand).rem(n);
                if cand2.cmp(&one) == std::cmp::Ordering::Equal {
                    let cand_m1 = cand.sub(&one).unwrap_or(BigUint::zero());
                    let p = gcd(&cand_m1, n);
                    if p.cmp(&one) == std::cmp::Ordering::Greater && p.cmp(n) == std::cmp::Ordering::Less
                    {
                        let q = n.div_rem(&p).0;
                        if !q.is_zero() && p.mul(&q).cmp(n) == std::cmp::Ordering::Equal {
                            return crt_from_primes(p, q, d);
                        }
                    }
                }
            }
            // k *= 2; stop when k >= ktot
            let k2 = k.shl(1);
            if k2.cmp(&ktot) != std::cmp::Ordering::Less {
                break;
            }
            k = k2;
        }
    }
    Err("prime recovery failed".into())
}

fn random_prime(bits: usize) -> Result<BigUint, String> {
    if bits < 16 {
        return Err("prime bits too small".into());
    }
    let nbytes = (bits + 7) / 8;
    let mut buf = vec![0u8; nbytes];
    for _ in 0..10_000 {
        util::fill_random(&mut buf);
        // set top bit and bottom bit (odd)
        if let Some(first) = buf.first_mut() {
            *first |= 0x80;
            // clear bits above `bits`
            let excess = nbytes * 8 - bits;
            if excess > 0 {
                *first &= 0xff >> excess;
                *first |= 1 << (7 - excess);
            }
        }
        if let Some(last) = buf.last_mut() {
            *last |= 1;
        }
        let n = BigUint::from_be_bytes(&buf);
        if is_probable_prime(&n) {
            return Ok(n);
        }
    }
    Err("could not find prime".into())
}

fn is_probable_prime(n: &BigUint) -> bool {
    if n.is_zero() {
        return false;
    }
    // small primes trial division
    const SMALL: &[u32] = &[
        3, 5, 7, 11, 13, 17, 19, 23, 29, 31, 37, 41, 43, 47, 53, 59, 61, 67, 71, 73, 79, 83, 89,
        97,
    ];
    for &p in SMALL {
        let d = BigUint::from_u32(p);
        if n.cmp(&d) == std::cmp::Ordering::Equal {
            return true;
        }
        if n.rem(&d).is_zero() {
            return false;
        }
    }
    // Miller-Rabin with fixed bases (deterministic for < 2^64; probabilistic else)
    let bases: &[u32] = &[2, 3, 5, 7, 11, 13, 23];
    // write n-1 = 2^s * d
    let one = BigUint::from_u32(1);
    let n_minus = match n.sub(&one) {
        Some(x) => x,
        None => return false,
    };
    let mut d = n_minus.clone();
    let mut s = 0u32;
    while !d.is_zero() && !d.get_bit(0) {
        d = d.shr1();
        s += 1;
    }
    for &a in bases {
        if !miller_rabin_round(n, &n_minus, &d, s, a) {
            return false;
        }
    }
    true
}

fn miller_rabin_round(n: &BigUint, n_minus: &BigUint, d: &BigUint, s: u32, a: u32) -> bool {
    let base = BigUint::from_u32(a);
    if base.cmp(n) != std::cmp::Ordering::Less {
        return true;
    }
    let mut x = base.modpow(d, n);
    let one = BigUint::from_u32(1);
    if x.cmp(&one) == std::cmp::Ordering::Equal || x.cmp(n_minus) == std::cmp::Ordering::Equal {
        return true;
    }
    for _ in 1..s {
        x = x.mul(&x).rem(n);
        if x.cmp(n_minus) == std::cmp::Ordering::Equal {
            return true;
        }
        if x.cmp(&one) == std::cmp::Ordering::Equal {
            return false;
        }
    }
    false
}

// ---------------------------------------------------------------------------
// PEM / DER parsing
// ---------------------------------------------------------------------------

fn pem_to_der(pem: &str) -> Result<Vec<u8>, String> {
    let mut b64 = String::new();
    let mut in_body = false;
    for line in pem.lines() {
        let line = line.trim();
        if line.starts_with("-----BEGIN ") {
            in_body = true;
            continue;
        }
        if line.starts_with("-----END ") {
            break;
        }
        if in_body {
            b64.push_str(line);
        }
    }
    if b64.is_empty() {
        return Err("no PEM body found".into());
    }
    Ok(util::base64_decode(&b64))
}

struct DerReader<'a> {
    data: &'a [u8],
    pos: usize,
}

impl<'a> DerReader<'a> {
    fn new(data: &'a [u8]) -> Self {
        Self { data, pos: 0 }
    }

    fn remaining(&self) -> usize {
        self.data.len().saturating_sub(self.pos)
    }

    fn read_tag_len(&mut self) -> Result<(u8, usize), String> {
        if self.pos >= self.data.len() {
            return Err("DER: unexpected end".into());
        }
        let tag = self.data[self.pos];
        self.pos += 1;
        if self.pos >= self.data.len() {
            return Err("DER: missing length".into());
        }
        let first = self.data[self.pos];
        self.pos += 1;
        let len = if first < 0x80 {
            first as usize
        } else {
            let n = (first & 0x7f) as usize;
            if n == 0 || n > 4 || self.remaining() < n {
                return Err("DER: bad length".into());
            }
            let mut l = 0usize;
            for _ in 0..n {
                l = (l << 8) | (self.data[self.pos] as usize);
                self.pos += 1;
            }
            l
        };
        if self.remaining() < len {
            return Err("DER: truncated value".into());
        }
        Ok((tag, len))
    }

    fn expect_tag(&mut self, want: u8) -> Result<&'a [u8], String> {
        let (tag, len) = self.read_tag_len()?;
        if tag != want {
            return Err(format!("DER: expected tag 0x{:02x}, got 0x{:02x}", want, tag));
        }
        let start = self.pos;
        self.pos += len;
        Ok(&self.data[start..self.pos])
    }

    fn read_integer(&mut self) -> Result<BigUint, String> {
        let bytes = self.expect_tag(0x02)?;
        // skip leading zero sign byte
        let mut i = 0;
        while i + 1 < bytes.len() && bytes[i] == 0 {
            i += 1;
        }
        Ok(BigUint::from_be_bytes(&bytes[i..]))
    }

    fn enter_sequence(&mut self) -> Result<DerReader<'a>, String> {
        let bytes = self.expect_tag(0x30)?;
        Ok(DerReader::new(bytes))
    }

    fn read_octet_string(&mut self) -> Result<&'a [u8], String> {
        self.expect_tag(0x04)
    }

    fn skip_value(&mut self) -> Result<(), String> {
        let (_tag, len) = self.read_tag_len()?;
        self.pos += len;
        Ok(())
    }
}

fn parse_rsa_private_key_der(der: &[u8]) -> Result<RsaKey, String> {
    let mut top = DerReader::new(der);
    let mut seq = top.enter_sequence()?;

    // Peek version / structure: PKCS#1 starts with version INTEGER 0,
    // PKCS#8 has version then AlgorithmIdentifier SEQUENCE.
    // Read first INTEGER (version).
    let _version = seq.read_integer()?;

    // If next tag is SEQUENCE, this is PKCS#8.
    if seq.pos < seq.data.len() && seq.data[seq.pos] == 0x30 {
        // AlgorithmIdentifier
        seq.skip_value()?;
        // privateKey OCTET STRING containing RSAPrivateKey
        let inner = seq.read_octet_string()?;
        return parse_pkcs1_rsa(inner);
    }

    // PKCS#1: already consumed version; next is n, e, d, ...
    parse_pkcs1_rsa_after_version(&mut seq)
}

fn parse_pkcs1_rsa(der: &[u8]) -> Result<RsaKey, String> {
    let mut seq = DerReader::new(der).enter_sequence()?;
    let _version = seq.read_integer()?;
    parse_pkcs1_rsa_after_version(&mut seq)
}

fn parse_pkcs1_rsa_after_version(seq: &mut DerReader<'_>) -> Result<RsaKey, String> {
    let n = seq.read_integer()?;
    let e = seq.read_integer()?;
    let d = seq.read_integer()?;
    let k = (n.bit_len() + 7) / 8;
    if k < 64 {
        return Err(format!("RSA modulus too small ({} bytes)", k));
    }
    // Optional CRT: p, q, dP, dQ, qInv (present in OpenSSL traditional keys).
    let crt = {
        let p = seq.read_integer().ok();
        let q = seq.read_integer().ok();
        let d_p = seq.read_integer().ok();
        let d_q = seq.read_integer().ok();
        let q_inv = seq.read_integer().ok();
        match (p, q, d_p, d_q, q_inv) {
            (Some(p), Some(q), Some(d_p), Some(d_q), Some(q_inv))
                if !p.is_zero() && !q.is_zero() =>
            {
                // Prefer recomputed CRT with ordered p > q; fall back to wire values.
                crt_from_primes(p.clone(), q.clone(), &d).ok().or(Some(RsaCrt {
                    p,
                    q,
                    d_p,
                    d_q,
                    q_inv,
                }))
            }
            _ => None,
        }
    };
    let key = RsaKey {
        n,
        e,
        d,
        k,
        crt,
    };
    Ok(key.with_crt_filled())
}

#[cfg(test)]
mod tests {
    use super::*;

    fn hex(s: &str) -> Vec<u8> {
        let s: String = s.chars().filter(|c| !c.is_whitespace()).collect();
        (0..s.len())
            .step_by(2)
            .map(|i| u8::from_str_radix(&s[i..i + 2], 16).unwrap())
            .collect()
    }

    #[test]
    fn sha256_empty() {
        let h = sha256(b"");
        assert_eq!(
            h,
            hex("e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855")[..]
        );
    }

    #[test]
    fn sha256_abc() {
        let h = sha256(b"abc");
        assert_eq!(
            h,
            hex("ba7816bf8f01cfea414140de5dae2223b00361a396177a9cb410ff61f20015ad")[..]
        );
    }

    #[test]
    fn sha256_long() {
        // > 64 bytes (NIST multi-block vector, 112 octets)
        let input = b"abcdefghbcdefghicdefghijdefghijkefghijklfghijklmghijklmnhijklmnoijklmnopjklmnopqklmnopqrlmnopqrsmnopqrstnopqrstu";
        assert!(input.len() > 64);
        let h = sha256(input);
        assert_eq!(
            h,
            hex("cf5b16a778af8380036ce59e7b0492370b249b11e8f07a51afac45037afee9d1")[..]
        );
    }

    #[test]
    fn modpow_small() {
        // 3^5 mod 13 = 243 mod 13 = 9
        let r = BigUint::from_u32(3)
            .modpow(&BigUint::from_u32(5), &BigUint::from_u32(13));
        assert_eq!(r, BigUint::from_u32(9));

        // 2^10 mod 1000 = 24
        let r = BigUint::from_u32(2)
            .modpow(&BigUint::from_u32(10), &BigUint::from_u32(1000));
        assert_eq!(r, BigUint::from_u32(24));

        // 7^0 mod 5 = 1
        let r = BigUint::from_u32(7)
            .modpow(&BigUint::from_u32(0), &BigUint::from_u32(5));
        assert_eq!(r, BigUint::from_u32(1));
    }

    #[test]
    fn biguint_mul() {
        let a = BigUint::from_be_bytes(&1_000_000_007u64.to_be_bytes());
        let b = BigUint::from_be_bytes(&1_000_000_009u64.to_be_bytes());
        let p = a.mul(&b);
        let v: u128 = 1_000_000_007u128 * 1_000_000_009u128;
        let mut bytes = v.to_be_bytes().to_vec();
        while bytes.len() > 1 && bytes[0] == 0 {
            bytes.remove(0);
        }
        assert_eq!(p.to_be_bytes(), bytes);
    }

    /// Embedded 1024-bit PKCS#1 test key (openssl genrsa -traditional 1024).
    const TEST_RSA_PEM: &str = "-----BEGIN RSA PRIVATE KEY-----\n\
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

    #[test]
    fn rsa_sign_roundtrip_pkcs1() {
        let key = RsaKey::from_pem(TEST_RSA_PEM).expect("parse key");
        let msg = b"hello dkim signing test";
        // 1024-bit: production path falls back to modpow (ring needs ≥2048).
        let sig = key.sign_sha256(msg).expect("sign");
        assert_eq!(sig.len(), key.k);

        // Verify via ring legacy path (1024-bit).
        assert!(key.verify_sha256(msg, &sig));
        assert!(!key.verify_sha256(b"other", &sig));

        // Verify: sig^e mod n should equal PKCS#1 EM
        let s = BigUint::from_be_bytes(&sig);
        let em_int = s.modpow(&key.e, &key.n);
        let em = em_int.to_be_bytes_padded(key.k);
        assert_eq!(em[0], 0x00);
        assert_eq!(em[1], 0x01);
        let hash = sha256(msg);
        assert_eq!(&em[em.len() - 32..], &hash[..]);
        assert_eq!(
            &em[em.len() - 32 - SHA256_DIGESTINFO_PREFIX.len()..em.len() - 32],
            SHA256_DIGESTINFO_PREFIX
        );
    }

    #[test]
    fn pem_pkcs1_parse() {
        let key = RsaKey::from_pem(TEST_RSA_PEM).expect("pkcs1");
        assert_eq!(key.k, 128); // 1024-bit
        assert!(!key.n.is_zero());
        assert!(!key.d.is_zero());
        // RSAPublicKey is a DER SEQUENCE of two INTEGERs
        let pk = key.public_key_der();
        assert_eq!(pk[0], 0x30);
        assert!(pk.len() > 50);
    }

    /// 2048-bit PKCS#1 test key (openssl genrsa -traditional 2048).
    const TEST_RSA_2048_PEM: &str = "-----BEGIN RSA PRIVATE KEY-----\n\
MIIEpAIBAAKCAQEAzP1CkDQ0bHZfqokzpQ0l7EmsQJdphXbmUhapkPwqCZMLAMEF\n\
yFF3vGKGWo33crlBqT5JdlnTvxnx3K3U8KUmoYpewBbp8jNJjKQNromLzPLvVcgO\n\
48/mXtP5NW4QimJuPFbA0iSNxM0g/LWTjn8OV+FbSQUsj6VCq64B7J2uWrkzKWwU\n\
/edcfU4np6Y6XJBzE0J16y9J9rodnK9Y3ihrTPNLJuQRwXwmaaVuI/3QDASIQ/Nm\n\
R8a1BSLUte37NT/Fn7zhAFegZ7CdPj9/qYVJXran0/XPtgPnHccS22rgDQ03edY4\n\
s22FyKKlGa3t5p8MC5rfrtRjVL9DdqR0qk1uUwIDAQABAoIBACBSUJQHPzrY4VW0\n\
43lDXPboWOooVaGPMVrBKwRq1kADOOlqBfzjZ5NDH7cYimtC7aj/YrrwB/SqZRns\n\
KNa226P9+tmj40hmsNKlrWiXVH1A0t7+N+bQyZyrJLC5hY8kXQhTj3yy+c2NoIVo\n\
JfeCbiMKLAgT8kZGAwCp47DI3gx8veA1QLbQOT6Vm0IJRpOqRKI2WwrHzJxzRXJX\n\
w20c4TiHNkoTHVxXeUEPCLvL2HlUuHVPUKgqTxdhbvgWLr4XVe9QLx9LCHkzlJ8R\n\
AeH5EuNl3jFgWfRgPr2B2CYzHHS+G3VbTZkPsi6uj3qRtpUfYB7VPl6ttpkYsyLv\n\
ndtkmLkCgYEA6+9J0UzOVHw+kX5HOmVpjinI41u5vcfsnpR3RE2sVcAFF+uQp0c9\n\
OD1CKC8g+cCvo0OGvDOxHgHHqh9MkQUf9l7vgx1CZXJDtGkyh+ydmvTs2CT2PAQa\n\
be0ES65zGlAMkGjmLhXY7SjSJXS6JO6Vw33JfqKHwAaM35HzbRrBVDsCgYEA3mw8\n\
VBDM7Lui0jWx+hVH3Fc8RpzqTyV6cdMpKOtMQAcHn1/oH0pGhWqmSqFsK+umgS/y\n\
O6yt6uelYUarWnMpAyzhkkWUZmTLcDR54xCOB0PgyWW6j7Nku4dH/seDQeVSATgJ\n\
X7Euf1IkgKgn3kDvJ0cROoB/sJnvchXZTfFeJMkCgYB+YPn4jBzFspvNUYgT5rio\n\
9wbtinevCcVcmIheZQDYGfhgfMVKZWWMl3u1jLEsNyOd35DvhPzt5uQt44Ae+lDJ\n\
psbDQ8wKDS/pFqSDnKI7m9C2Yu4m7ce+dERlybdMM+7W9+m8a+V7++69M452M/qy\n\
8dEZ7TOsD5YsN8DeA4PlewKBgQDVjf5uiKL5OT8frcZwYzZX7LpG4ipmS4nA+Amw\n\
7BqN7zH2Z9MrF9mWB8waI9sEYIHB0BM4EJf7zuYO/BdSBPf/wHvkQUI2/dgGp5vP\n\
0/lKKHYPaMkzZ/7zvvP1QAJapp+R5Ae8BRar0GaT0OBWmOoGQEnebbosCeDJHQlD\n\
uNe3YQKBgQC2sLcyhreBjix/BLaK3FYqXdMFCLcSoYlqtNnczUDHB9+CNRwcRPtl\n\
p6xZlYK4ogaJsMKk3xgBHWRt3GQMNZMm7JJWibT/pATArltbu/dzLO6UmA1LqiT2\n\
uRAQIMqcXXVWXhYZQEb8l0Mc825lcOygXyURYHnRQ3Mygepx4wLv7w==\n\
-----END RSA PRIVATE KEY-----\n";

    /// ring-signed output must equal hand-rolled modpow for fixed key+message
    /// (PKCS#1 v1.5 is deterministic; both implement the same padding).
    #[test]
    fn ring_sign_matches_modpow_fixed_key() {
        let key = RsaKey::from_pem(TEST_RSA_2048_PEM).expect("parse 2048 key");
        assert_eq!(key.k, 256);
        let msg = b"fixed message for ring vs modpow cross-check";
        let ring_sig = key.sign_sha256_ring(msg).expect("ring sign");
        let modpow_sig = key.sign_sha256_modpow(msg).expect("modpow sign");
        assert_eq!(
            ring_sig, modpow_sig,
            "ring and modpow PKCS#1 v1.5 signatures must be identical"
        );
        assert!(key.verify_sha256(msg, &ring_sig));
        assert!(key
            .public_key_for_test()
            .verify_sha256_modpow(msg, &ring_sig));
    }

    #[test]
    fn generated_key_signs_via_ring() {
        // Prefer openssl path when available; else pure-Rust (slower).
        let key = RsaKey::generate(2048).expect("generate");
        assert!(key.k >= 256);
        let msg = b"keygen round-trip through ring";
        let sig = key.sign_sha256(msg).expect("sign via ring");
        assert!(key.verify_sha256(msg, &sig), "ring verify");
        assert!(
            key.public_key_for_test().verify_sha256_modpow(msg, &sig),
            "modpow verify of ring signature"
        );
    }
}

impl RsaKey {
    /// Test helper: view as public key.
    #[cfg(test)]
    fn public_key_for_test(&self) -> RsaPublicKey {
        RsaPublicKey {
            n: self.n.clone(),
            e: self.e.clone(),
            k: self.k,
        }
    }
}

