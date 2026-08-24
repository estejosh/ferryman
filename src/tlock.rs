//! Sealing and opening the archive-encryption key against a beacon round.
//!
//! Two backends share one interface:
//!
//! **drand (real)** — the 16-byte seed that keys the archive is encrypted with
//! the `tlock` crate's identity-based encryption to the future round R. The
//! private key for that identity *is* drand's signature of round R, which does
//! not exist until time(round(R)). Nobody — including the owner — can open the
//! blob early. Ciphertext layout: `[0x01] || U(96) || V(16) || W(16)`.
//!
//! **simulate** — the wrap key is derived from a deterministic fake signature.
//! It carries zero secrecy; the timelock is enforced by policy (the gate in
//! `Beacon::wait_for_signature`) so tests can run offline and deterministically.
//! Layout: `[0x00] || nonce(12) || AES-256-GCM(master_key)`.

use aes_gcm::aead::Aead;
use aes_gcm::{Aes256Gcm, KeyInit, Nonce};
use hkdf::Hkdf;
use rand::RngCore;
use rand::rngs::OsRng;
use sha2::{Digest, Sha256};

use crate::beacon::{Beacon, sim_signature};
use crate::error::{Error, Result};

pub const KEY_BLOB_TAG_DRAND: u8 = 0x01;
pub const KEY_BLOB_TAG_SIM: u8 = 0x00;

const TLOCK_SEED_LEN: usize = 16;
const MASTER_KEY_LEN: usize = 32;

/// Fill a buffer from the OS CSPRNG.
pub fn fill_random(buf: &mut [u8]) {
    OsRng.fill_bytes(buf);
}

fn decrypt_quietly(dst: &mut [u8], src: &[u8], sig: &[u8]) -> Result<()> {
    let hook = std::panic::take_hook();
    std::panic::set_hook(Box::new(|_| {}));
    let outcome = std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| {
        tlock::decrypt(dst, src, sig).map_err(|e| {
            Error::Corrupt(format!(
                "timelock decryption failed (wrong signature or tampered artifact): {e}"
            ))
        })
    }));
    let _ = std::panic::take_hook();
    std::panic::set_hook(hook);
    match outcome {
        Ok(Ok(())) => Ok(()),
        Ok(Err(e)) => Err(Error::Corrupt(format!(
            "timelock decryption failed (wrong signature or tampered artifact): {e}"
        ))),
        Err(_) => Err(Error::Corrupt(
            "timelock decryption failed: signature does not match the sealed round".into(),
        )),
    }
}

fn derive_archive_key(seed: &[u8]) -> [u8; MASTER_KEY_LEN] {
    let mut h = Sha256::new();
    h.update(b"ferry-deadman/archive-key/v1");
    h.update(seed);
    h.finalize().into()
}

fn sim_wrap_key(sig: &[u8]) -> Result<[u8; 32]> {
    let hk = Hkdf::<Sha256>::new(Some(b"ferry-deadman/sim-salt/v1"), sig);
    let mut okm = [0u8; 32];
    hk.expand(b"ferry-deadman/sim-wrap/v1", &mut okm)
        .map_err(|_| Error::Other("hkdf expand failed".into()))?;
    Ok(okm)
}

/// Generate a fresh master key and seal it to `round`.
///
/// Returns `(master_key, key_blob)`. The master key never touches disk in the
/// clear; it lives only inside this call chain and the sealed payload.
pub fn seal_master_key(beacon: &Beacon, round: u64) -> Result<([u8; MASTER_KEY_LEN], Vec<u8>)> {
    match beacon {
        Beacon::Drand(p) => {
            // pk is hex on G2 (96 bytes) for quicknet-style chains.
            let pk = hex::decode(&p.info.public_key)
                .map_err(|_| Error::other("chain info public_key is not valid hex"))?;
            if !(pk.len() == 96 || pk.len() == 48) {
                return Err(Error::other(format!(
                    "unsupported drand public key size {}",
                    pk.len()
                )));
            }
            let mut seed = [0u8; TLOCK_SEED_LEN];
            OsRng.fill_bytes(&mut seed);
            let mut blob = vec![KEY_BLOB_TAG_DRAND];
            tlock::encrypt(&mut blob, &seed[..], &pk[..], round)
                .map_err(|e| Error::other(format!("tlock encryption failed: {e}")))?;
            Ok((derive_archive_key(&seed), blob))
        }
        Beacon::Sim(_) => {
            let mut master = [0u8; MASTER_KEY_LEN];
            OsRng.fill_bytes(&mut master);
            let wrap = sim_wrap_key(&sim_signature(round))?;
            let mut nonce_bytes = [0u8; 12];
            OsRng.fill_bytes(&mut nonce_bytes);
            let cipher = Aes256Gcm::new_from_slice(&wrap)
                .map_err(|_| Error::Other("aes key init failed".into()))?;
            let ct = cipher
                .encrypt(&Nonce::from(nonce_bytes), master.as_slice())
                .map_err(|_| Error::Other("aes-gcm seal failed".into()))?;
            let mut blob = Vec::with_capacity(1 + 12 + ct.len());
            blob.push(KEY_BLOB_TAG_SIM);
            blob.extend_from_slice(&nonce_bytes);
            blob.extend_from_slice(&ct);
            Ok((master, blob))
        }
    }
}

/// Open a sealed key blob with the beacon signature of its unlock round.
pub fn open_master_key(blob: &[u8], round_signature: &[u8]) -> Result<[u8; MASTER_KEY_LEN]> {
    match blob.first() {
        Some(&KEY_BLOB_TAG_DRAND) => {
            if round_signature.len() != 48 && round_signature.len() != 96 {
                return Err(Error::Corrupt(format!(
                    "signature has unsupported size {}",
                    round_signature.len()
                )));
            }
            // The upstream tlock crate signals some bad inputs with internal
            // assertions rather than Result errors; convert those panics into
            // clean errors so hostile artifacts can never crash the CLI.
            let mut seed = [0u8; TLOCK_SEED_LEN];
            decrypt_quietly(&mut seed, &blob[1..], round_signature)?;
            Ok(derive_archive_key(&seed))
        }
        Some(&KEY_BLOB_TAG_SIM) => {
            if blob.len() < 1 + 12 + 16 {
                return Err(Error::Corrupt("sim key blob too short".into()));
            }
            let mut nonce_bytes = [0u8; 12];
            nonce_bytes.copy_from_slice(&blob[1..13]);
            let nonce = Nonce::from(nonce_bytes);
            let ct = &blob[13..];
            let wrap = sim_wrap_key(round_signature)?;
            let cipher = Aes256Gcm::new_from_slice(&wrap)
                .map_err(|_| Error::Other("aes key init failed".into()))?;
            let pt = cipher.decrypt(&nonce, ct).map_err(|_| {
                Error::Corrupt("sim key unwrap failed: signature mismatch or corruption".into())
            })?;
            let mut master = [0u8; MASTER_KEY_LEN];
            if pt.len() != MASTER_KEY_LEN {
                return Err(Error::Corrupt("unwrapped key has wrong length".into()));
            }
            master.copy_from_slice(&pt);
            Ok(master)
        }
        Some(other) => Err(Error::Corrupt(format!(
            "unknown key blob tag {other:#04x} — produced by a different version?"
        ))),
        None => Err(Error::Corrupt("key blob is empty".into())),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn sim_seal_open_roundtrip() {
        let b = Beacon::sim(10_000);
        let unlock_round = b.unlock_round(10_000, 5); // ~10005
        assert!(b.round_time(unlock_round) >= 10_004);
        let (master, blob) = seal_master_key(&b, unlock_round).unwrap();
        // opening with the deterministic sim signature recovers the key
        let sig = sim_signature(unlock_round);
        let got = open_master_key(&blob, &sig).unwrap();
        assert_eq!(master, got);
    }

    #[test]
    fn sim_wrong_signature_fails() {
        let b = Beacon::sim(10_000);
        let (_, blob) = seal_master_key(&b, 10_005).unwrap();
        let bad = sim_signature(9_999);
        assert!(open_master_key(&blob, &bad).is_err());
        let flipped = {
            let mut s = sim_signature(10_005);
            s[7] ^= 0xff;
            s
        };
        assert!(open_master_key(&blob, &flipped).is_err());
    }

    #[test]
    fn unknown_tag_rejected() {
        assert!(open_master_key(&[0xff, 0, 1], &[0u8; 64]).is_err());
        assert!(open_master_key(&[], &[0u8; 64]).is_err());
    }

    #[test]
    fn short_blobs_rejected() {
        let sig = sim_signature(1);
        assert!(open_master_key(&[KEY_BLOB_TAG_SIM, 1, 2], &sig).is_err());
        assert!(open_master_key(&[KEY_BLOB_TAG_DRAND, 1], &sig).is_err());
    }
}
