//! Successor identity fingerprinting.
//!
//! The successor public key is recorded as a sha256 commitment. It is
//! metadata for humans and audit trails — the timelock itself is keyed to the
//! drand beacon, so possession of this value grants no decryption power.

use std::path::Path;

use sha2::{Digest, Sha256};

use crate::error::{Error, Result};

/// Accepts either a filesystem path (file contents are hashed) or an inline
/// hex string. Returns `sha256:<hex>`.
pub fn fingerprint_successor(input: &str) -> Result<String> {
    let trimmed = input.trim();
    if trimmed.is_empty() {
        return Err(Error::BadInput(
            "--successor-pub is empty; pass a file path or a hex key".into(),
        ));
    }

    let path = Path::new(trimmed);
    if path.is_file() {
        let bytes = std::fs::read(path)
            .map_err(|e| Error::BadInput(format!("cannot read successor file {trimmed}: {e}")))?;
        return Ok(digest_bytes(bytes.trim_ascii()));
    }

    // Not a file: must be an inline hex blob.
    let hexish = trimmed.strip_prefix("0x").unwrap_or(trimmed);
    if hexish.len() < 8 {
        return Err(Error::BadInput(format!(
            "{trimmed:?} is neither a readable file nor a plausible hex key"
        )));
    }
    hex::decode(hexish).map_err(|_| {
        Error::BadInput(format!(
            "{trimmed:?} is neither a readable file nor valid hex"
        ))
    })?;
    Ok(digest_bytes(trimmed.as_bytes()))
}

fn digest_bytes(data: &[u8]) -> String {
    let mut h = Sha256::new();
    h.update(b"ferry-deadman/successor/v1");
    h.update(data);
    format!("sha256:{}", hex::encode(h.finalize()))
}

/// Short display form: first 16 chars after the prefix.
pub fn short(fp: &str) -> String {
    fp.chars().take(7 + 16).collect()
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn fingerprints_inline_hex() {
        let a = fingerprint_successor("aabbccddeeff00112233445566778899").unwrap();
        assert!(a.starts_with("sha256:"));
        assert_eq!(a.len(), 7 + 64);
        // same input, same fingerprint
        assert_eq!(
            a,
            fingerprint_successor("aabbccddeeff00112233445566778899").unwrap()
        );
        assert_ne!(
            a,
            fingerprint_successor("aabbccddeeff0011223344556677889a").unwrap()
        );
    }

    #[test]
    fn rejects_junk() {
        assert!(fingerprint_successor("").is_err());
        assert!(fingerprint_successor("   ").is_err());
        assert!(fingerprint_successor("zzzz-not-valid").is_err());
        assert!(fingerprint_successor("0x1234").is_err()); // too short
    }

    #[test]
    fn fingerprints_file_contents() {
        let tmp = tempfile::tempdir().unwrap();
        let p = tmp.path().join("succ.pub");
        std::fs::write(
            &p,
            b"-----BEGIN PUBLIC KEY-----\nabc\n-----END PUBLIC KEY-----\n",
        )
        .unwrap();
        let fp1 = fingerprint_successor(p.to_str().unwrap()).unwrap();
        // trailing whitespace in the file does not change the fingerprint
        std::fs::write(
            &p,
            b"-----BEGIN PUBLIC KEY-----\nabc\n-----END PUBLIC KEY-----\n\n\n",
        )
        .unwrap();
        let fp2 = fingerprint_successor(p.to_str().unwrap()).unwrap();
        assert_eq!(fp1, fp2);
    }
}
