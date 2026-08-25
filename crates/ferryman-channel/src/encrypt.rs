//! At-rest payload encryption for channel artifacts, keyed by a master secret.
//!
//! Artifacts are opaque once they leave the channel: the plaintext is encrypted
//! with ChaCha20-Poly1305 under a key derived from the master secret, and the
//! result is stored as hex with the random 12-byte nonce prepended to the
//! ciphertext (which already carries its authentication tag).

use anyhow::{Context, Result, anyhow, bail};
use chacha20poly1305::{
    ChaCha20Poly1305, Nonce,
    aead::{Aead, KeyInit},
};
use rand::Rng;
use sha2::{Digest, Sha256};

/// Derive a 32-byte encryption key from a master secret with SHA-256.
///
/// This is intentionally a one-shot derivation, not a password KDF: the caller
/// is expected to supply a high-entropy secret, and the hash only normalises it
/// to the key size ChaCha20-Poly1305 expects.
#[must_use]
pub fn derive_key(master_secret: &str) -> [u8; 32] {
    let digest = Sha256::digest(master_secret.as_bytes());
    let mut key = [0_u8; 32];
    key.copy_from_slice(&digest);
    key
}

/// Encrypt `plaintext` and return it as hex: `nonce(12) || ciphertext+tag`.
pub fn encrypt(key: &[u8; 32], plaintext: &[u8]) -> Result<String> {
    let cipher =
        ChaCha20Poly1305::new_from_slice(key).map_err(|_| anyhow!("invalid encryption key"))?;
    let mut nonce = [0_u8; 12];
    rand::rng().fill_bytes(&mut nonce);
    let ciphertext = cipher
        .encrypt(&Nonce::from(nonce), plaintext)
        .map_err(|_| anyhow!("encryption failed"))?;

    let mut payload = Vec::with_capacity(nonce.len() + ciphertext.len());
    payload.extend_from_slice(&nonce);
    payload.extend_from_slice(&ciphertext);
    Ok(hex::encode(payload))
}

/// Decrypt a value produced by [`encrypt`].
///
/// The nonce and ciphertext are split back apart before decryption; ChaCha20-
/// Poly1305 authenticates the ciphertext, so any tampering fails here rather
/// than yielding corrupt plaintext.
pub fn decrypt(key: &[u8; 32], encoded: &str) -> Result<Vec<u8>> {
    let payload = hex::decode(encoded).context("encrypted payload is not valid hex")?;
    if payload.len() <= 12 {
        bail!("encrypted payload is missing its nonce");
    }
    let (nonce, ciphertext) = payload.split_at(12);
    let cipher =
        ChaCha20Poly1305::new_from_slice(key).map_err(|_| anyhow!("invalid encryption key"))?;
    cipher
        .decrypt(
            &Nonce::try_from(nonce).map_err(|_| anyhow!("encrypted payload nonce is malformed"))?,
            ciphertext,
        )
        .map_err(|_| anyhow!("encrypted payload authentication failed"))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn derive_key_is_sha256_of_the_secret() {
        let key = derive_key("master-secret");
        let expected = Sha256::digest(b"master-secret");
        assert_eq!(&key[..], expected.as_slice());
    }

    #[test]
    fn encryption_round_trips() {
        let key = derive_key("master-secret");
        let plaintext: &[u8] = b"channel artifact bytes";
        let encoded = encrypt(&key, plaintext).expect("encrypt");
        assert_ne!(encoded.as_bytes(), plaintext);
        let decoded = decrypt(&key, &encoded).expect("decrypt");
        assert_eq!(decoded, plaintext.to_vec());
    }

    #[test]
    fn tampering_a_byte_fails_decryption() {
        let key = derive_key("master-secret");
        let encoded = encrypt(&key, b"tamper-proof").expect("encrypt");
        let mut payload = hex::decode(&encoded).expect("hex payload");
        let last = payload.len() - 1;
        payload[last] ^= 0x01;
        assert!(decrypt(&key, &hex::encode(payload)).is_err());
    }

    #[test]
    fn a_wrong_key_fails_decryption() {
        let encoded = encrypt(&derive_key("one secret"), b"payload").expect("encrypt");
        assert!(decrypt(&derive_key("another secret"), &encoded).is_err());
    }

    #[test]
    fn each_encryption_uses_a_fresh_nonce() {
        let key = derive_key("master-secret");
        let first = encrypt(&key, b"same plaintext").expect("encrypt");
        let second = encrypt(&key, b"same plaintext").expect("encrypt");
        assert_ne!(first, second);
    }
}
