//! Pure-std cryptography for DKIM: SHA-256, minimal bignum, RSA PKCS#1 v1.5, PEM/DER.
//! No external crates. Performance is not critical.

use std::fs;
use std::path::Path;

use crate::util;

// ---------------------------------------------------------------------------
// SHA-256 (FIPS 180-4)
// ---------------------------------------------------------------------------

const SHA256_K: [u32; 64] = [
    0x428a2f98, 0x71374491, 0xb5c0fbcf, 0xe9b5dba5, 0x3956c25b, 0x59f111f1, 0x923f82a4,
    0xab1c5ed5, 0xd807aa98, 0x12835b01, 0x243185be, 0x550c7dc3, 0x72be5d74, 0x80deb1fe,
    0x9bdc06a7, 0xc19bf174, 0xe49b69c1, 0xefbe4786, 0x0fc19dc6, 0x240ca1cc, 0x2de92c6f,
    0x4a7484aa, 0x5cb0a9dc, 0x76f988da, 0x983e5152, 0xa831c66d, 0xb00327c8, 0xbf597fc7,
    0xc6e00bf3, 0xd5a79147, 0x06ca6351, 0x14292967, 0x27b70a85, 0x2e1b2138, 0x4d2c6dfc,
    0x53380d13, 0x650a7354, 0x766a0abb, 0x81c2c92e, 0x92722c85, 0xa2bfe8a1, 0xa81a664b,
    0xc24b8b70, 0xc76c51a3, 0xd192e819, 0xd6990624, 0xf40e3585, 0x106aa070, 0x19a4c116,
    0x1e376c08, 0x2748774c, 0x34b0bcb5, 0x391c0cb3, 0x4ed8aa4a, 0x5b9cca4f, 0x682e6ff3,
    0x748f82ee, 0x78a5636f, 0x84c87814, 0x8cc70208, 0x90befffa, 0xa4506ceb, 0xbef9a3f7,
    0xc67178f2,
];

/// Compute SHA-256 digest of `data`.
pub fn sha256(data: &[u8]) -> [u8; 32] {
    let mut h: [u32; 8] = [
        0x6a09e667, 0xbb67ae85, 0x3c6ef372, 0xa54ff53a, 0x510e527f, 0x9b05688c, 0x1f83d9ab,
        0x5be0cd19,
    ];

    let bit_len = (data.len() as u64).wrapping_mul(8);
    // padded message: data || 0x80 || zeros || 8-byte length
    let mut msg = data.to_vec();
    msg.push(0x80);
    while (msg.len() % 64) != 56 {
        msg.push(0);
    }
    msg.extend_from_slice(&bit_len.to_be_bytes());

    for chunk in msg.chunks_exact(64) {
        let mut w = [0u32; 64];
        for i in 0..16 {
            w[i] = u32::from_be_bytes([
                chunk[i * 4],
                chunk[i * 4 + 1],
                chunk[i * 4 + 2],
                chunk[i * 4 + 3],
            ]);
        }
        for i in 16..64 {
            let s0 = w[i - 15].rotate_right(7) ^ w[i - 15].rotate_right(18) ^ (w[i - 15] >> 3);
            let s1 = w[i - 2].rotate_right(17) ^ w[i - 2].rotate_right(19) ^ (w[i - 2] >> 10);
            w[i] = w[i - 16]
                .wrapping_add(s0)
                .wrapping_add(w[i - 7])
                .wrapping_add(s1);
        }

        let mut a = h[0];
        let mut b = h[1];
        let mut c = h[2];
        let mut d = h[3];
        let mut e = h[4];
        let mut f = h[5];
        let mut g = h[6];
        let mut hh = h[7];

        for i in 0..64 {
            let s1 = e.rotate_right(6) ^ e.rotate_right(11) ^ e.rotate_right(25);
            let ch = (e & f) ^ ((!e) & g);
            let t1 = hh
                .wrapping_add(s1)
                .wrapping_add(ch)
                .wrapping_add(SHA256_K[i])
                .wrapping_add(w[i]);
            let s0 = a.rotate_right(2) ^ a.rotate_right(13) ^ a.rotate_right(22);
            let maj = (a & b) ^ (a & c) ^ (b & c);
            let t2 = s0.wrapping_add(maj);

            hh = g;
            g = f;
            f = e;
            e = d.wrapping_add(t1);
            d = c;
            c = b;
            b = a;
            a = t1.wrapping_add(t2);
        }

        h[0] = h[0].wrapping_add(a);
        h[1] = h[1].wrapping_add(b);
        h[2] = h[2].wrapping_add(c);
        h[3] = h[3].wrapping_add(d);
        h[4] = h[4].wrapping_add(e);
        h[5] = h[5].wrapping_add(f);
        h[6] = h[6].wrapping_add(g);
        h[7] = h[7].wrapping_add(hh);
    }

    let mut out = [0u8; 32];
    for (i, &v) in h.iter().enumerate() {
        out[i * 4..(i + 1) * 4].copy_from_slice(&v.to_be_bytes());
    }
    out
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

// ---------------------------------------------------------------------------
// RSA PKCS#1 v1.5 (RSASSA-PKCS1-v1_5 with SHA-256)
// ---------------------------------------------------------------------------

/// DigestInfo prefix for SHA-256 (RFC 8017 / PKCS#1).
const SHA256_DIGESTINFO_PREFIX: &[u8] = &[
    0x30, 0x31, 0x30, 0x0d, 0x06, 0x09, 0x60, 0x86, 0x48, 0x01, 0x65, 0x03, 0x04, 0x02, 0x01,
    0x05, 0x00, 0x04, 0x20,
];

/// RSA private key (n, e, d only; plain modpow signing).
#[derive(Clone, Debug)]
pub struct RsaKey {
    pub n: BigUint,
    pub e: BigUint,
    pub d: BigUint,
    /// Modulus size in bytes (k).
    pub k: usize,
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

    /// RSASSA-PKCS1-v1_5 sign of a raw message (hash is computed here).
    pub fn sign_sha256(&self, message: &[u8]) -> Result<Vec<u8>, String> {
        let hash = sha256(message);
        self.sign_digest_sha256(&hash)
    }

    /// Sign a precomputed SHA-256 digest (32 bytes).
    pub fn sign_digest_sha256(&self, hash: &[u8]) -> Result<Vec<u8>, String> {
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
}

fn encode_der_integer(n: &BigUint) -> Vec<u8> {
    let mut bytes = n.to_be_bytes();
    // DER INTEGER: if high bit set, prepend 0x00 (positive)
    if bytes[0] & 0x80 != 0 {
        bytes.insert(0, 0x00);
    }
    der_tlv(0x02, &bytes)
}

fn der_tlv(tag: u8, value: &[u8]) -> Vec<u8> {
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
    // remaining p, q, etc. ignored
    let k = (n.bit_len() + 7) / 8;
    if k < 64 {
        return Err(format!("RSA modulus too small ({} bytes)", k));
    }
    Ok(RsaKey { n, e, d, k })
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
        let sig = key.sign_sha256(msg).expect("sign");
        assert_eq!(sig.len(), key.k);

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
}

