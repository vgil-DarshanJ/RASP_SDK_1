//! Port of the hashing helpers: `RaspTamperAnalysis.sha256Hex` /
//! `dexSha256` / `normalizeHex` / `dexIndex`, the signing-certificate digest
//! of `RaspSigningProbes`, and `RaspCertificatePinProbes.spkiPin` / `isPin`
//! (with `RaspBase64`). Digests are uppercase hex like the Kotlin side.
//! [constant_time_eq] compares hashes without an early exit.

use sha2::{Digest, Sha256};

/// A `classesN.dex` number too large for an Int (Kotlin's `toInt()` throws there).
#[derive(Debug, PartialEq, Eq, Clone, Copy)]
pub struct DexIndexOverflow;

pub fn sha256(bytes: &[u8]) -> [u8; 32] {
    Sha256::digest(bytes).into()
}

/// Uppercase hex.
pub fn hex_upper(bytes: &[u8]) -> String {
    const DIGITS: &[u8; 16] = b"0123456789ABCDEF";
    let mut out = String::with_capacity(bytes.len() * 2);
    for b in bytes {
        out.push(char::from(DIGITS[usize::from(b >> 4)]));
        out.push(char::from(DIGITS[usize::from(b & 0x0f)]));
    }
    out
}

/// `RaspTamperAnalysis.sha256Hex` and the signing-certificate digest.
pub fn sha256_hex(bytes: &[u8]) -> String {
    hex_upper(&sha256(bytes))
}

/// `RaspTamperAnalysis.dexIndex`: `classes.dex` = 1, `classesN.dex` = N; any
/// other name sorts last. `Err` where Kotlin's `toInt()` would throw (a
/// number too large for an Int).
pub fn dex_index(name: &str) -> Result<i32, DexIndexOverflow> {
    let Some(middle) = name.strip_prefix("classes").and_then(|r| r.strip_suffix(".dex")) else {
        return Ok(i32::MAX);
    };
    if !middle.chars().all(|c| c.is_ascii_digit()) {
        return Ok(i32::MAX);
    }
    if middle.is_empty() {
        return Ok(1);
    }
    middle.parse::<i32>().map_err(|_| DexIndexOverflow)
}

/// `RaspTamperAnalysis.dexSha256`: SHA-256 over, for each entry in
/// [dex_index] order (stable), the name (UTF-8), one 0 byte, then the bytes.
/// `Ok(None)` with no entries; `Err` where Kotlin would throw.
pub fn dex_sha256(entries: &[(&str, &[u8])]) -> Result<Option<String>, DexIndexOverflow> {
    if entries.is_empty() {
        return Ok(None);
    }
    let mut keyed = Vec::with_capacity(entries.len());
    for (name, bytes) in entries {
        keyed.push((dex_index(name)?, *name, *bytes));
    }
    keyed.sort_by_key(|(index, _, _)| *index);
    let mut hasher = Sha256::new();
    for (_, name, bytes) in keyed {
        hasher.update(name.as_bytes());
        hasher.update([0u8]);
        hasher.update(bytes);
    }
    Ok(Some(hex_upper(&hasher.finalize())))
}

/// `RaspTamperAnalysis.normalizeHex`: without `:`, whitespace and `-`, uppercase; `None` when empty.
pub fn normalize_hex(value: &str) -> Option<String> {
    let out: String = value
        .chars()
        .filter(|c| !(*c == ':' || *c == '-' || crate::text::is_regex_space(*c)))
        .collect::<String>()
        .to_uppercase();
    if out.is_empty() {
        None
    } else {
        Some(out)
    }
}

const ALPHABET: &[u8; 64] = b"ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/";

/// `RaspBase64.encode`: standard alphabet with padding.
pub fn base64_encode(bytes: &[u8]) -> String {
    let mut out = String::with_capacity(bytes.len().div_ceil(3) * 4);
    let sextet = |n: u32, shift: u32| char::from(ALPHABET[((n >> shift) & 63) as usize]);
    for chunk in bytes.chunks(3) {
        let b0 = u32::from(chunk.first().copied().unwrap_or(0));
        let b1 = u32::from(chunk.get(1).copied().unwrap_or(0));
        let b2 = u32::from(chunk.get(2).copied().unwrap_or(0));
        let n = (b0 << 16) | (b1 << 8) | b2;
        out.push(sextet(n, 18));
        out.push(sextet(n, 12));
        out.push(if chunk.len() > 1 { sextet(n, 6) } else { '=' });
        out.push(if chunk.len() > 2 { sextet(n, 0) } else { '=' });
    }
    out
}

/// `RaspBase64.decode`: trailing `=` ignored, any other character outside
/// the alphabet or a length of 1 mod 4 is malformed (`None`).
pub fn base64_decode(text: &str) -> Option<Vec<u8>> {
    let s = text.trim_end_matches('=');
    let mut values = Vec::with_capacity(s.len());
    for c in s.bytes() {
        values.push(ALPHABET.iter().position(|a| *a == c)? as u32);
    }
    if values.len() % 4 == 1 {
        return None;
    }
    let mut out = Vec::with_capacity(values.len() * 3 / 4);
    let (mut buffer, mut bits) = (0u32, 0u32);
    for v in values {
        buffer = (buffer << 6) | v;
        bits += 6;
        if bits >= 8 {
            bits -= 8;
            out.push(((buffer >> bits) & 0xff) as u8);
        }
    }
    Some(out)
}

/// `RaspCertificatePinProbes.spkiPin`: `sha256/` + Base64(SHA-256(SPKI DER)).
pub fn spki_pin(spki_der: &[u8]) -> String {
    format!("sha256/{}", base64_encode(&sha256(spki_der)))
}

/// `RaspCertificatePinProbes.isPin`.
pub fn is_pin(value: &str) -> bool {
    value
        .strip_prefix("sha256/")
        .and_then(base64_decode)
        .is_some_and(|bytes| bytes.len() == 32)
}

/// Equal-length inputs are compared without an early exit (time does not
/// depend on where they differ); different lengths are simply unequal.
pub fn constant_time_eq(a: &[u8], b: &[u8]) -> bool {
    if a.len() != b.len() {
        return false;
    }
    a.iter().zip(b).fold(0u8, |acc, (x, y)| acc | (x ^ y)) == 0
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn sha256_known_vector() {
        assert_eq!(sha256_hex(b"abc"), "BA7816BF8F01CFEA414140DE5DAE2223B00361A396177A9CB410FF61F20015AD");
    }

    #[test]
    fn dex_order_and_errors() {
        let a = dex_sha256(&[("classes2.dex", b"B"), ("classes.dex", b"A")]).unwrap();
        let b = dex_sha256(&[("classes.dex", b"A"), ("classes2.dex", b"B")]).unwrap();
        assert_eq!(a, b);
        assert_eq!(dex_sha256(&[]), Ok(None));
        assert!(dex_sha256(&[("classes99999999999.dex", b"x")]).is_err());
        assert_eq!(dex_index("classes.dex"), Ok(1));
        assert_eq!(dex_index("other.dex"), Ok(i32::MAX));
    }

    #[test]
    fn base64_roundtrip_and_pins() {
        for n in 0..40u8 {
            let data: Vec<u8> = (0..n).collect();
            assert_eq!(base64_decode(&base64_encode(&data)).unwrap(), data);
        }
        assert!(base64_decode("a$b").is_none());
        assert!(base64_decode("abcde").is_none());
        assert!(is_pin(&spki_pin(b"spki")));
        assert!(!is_pin("sha256/AAAA"));
        assert!(!is_pin("sha1/AAAA"));
    }

    #[test]
    fn normalize_and_compare() {
        assert_eq!(normalize_hex("ab:cd -ef\t01").as_deref(), Some("ABCDEF01"));
        assert_eq!(normalize_hex(" : "), None);
        assert!(constant_time_eq(b"ABC", b"ABC"));
        assert!(!constant_time_eq(b"ABC", b"ABD"));
        assert!(!constant_time_eq(b"ABC", b"AB"));
    }
}
