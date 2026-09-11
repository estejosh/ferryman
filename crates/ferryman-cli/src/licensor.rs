//! The licensor's own key: minted here, sealed here, and never held by anything else.
//!
//! # Why this is not the operator key
//!
//! An operator identity is a *person* - it approves work, it lives on the machines they
//! use, and it is derived from their seed so it comes back from a recovery phrase. The
//! licensor key is the *company*: it signs entitlements, it is used a handful of times a
//! year, and it should spend the rest of its life somewhere cold. Deriving it from a
//! person's seed would tie the ability to license the product to one human's identity,
//! which is exactly the coupling a business does not want.
//!
//! # What travels and what does not
//!
//! The file this writes is ciphertext: the secret key sealed with a password, by the
//! same construction the operator record uses (PBKDF2-SHA256, 600k iterations, then
//! XChaCha20-Poly1305). Sealed, it can be carried anywhere - a backup, another machine,
//! an end-to-end encrypted message to yourself. The password must travel by a different
//! route than the file, or the two together are just the key.

use anyhow::{Context, Result, bail};
use chacha20poly1305::{
    XChaCha20Poly1305, XNonce,
    aead::{Aead, KeyInit},
};
use ed25519_dalek::SigningKey;
use serde::{Deserialize, Serialize};
use sha2::Sha256;
use std::path::{Path, PathBuf};

const FORMAT: &str = "ferryman-licensor/v1";
const ITERATIONS: u32 = 600_000;
/// The shortest password we will seal a licensor key with. This one signs money.
const MIN_PASSWORD_LEN: usize = 12;

/// A licensor key at rest. Everything here is either public or ciphertext.
#[derive(Debug, Serialize, Deserialize)]
pub struct SealedLicensor {
    pub format: String,
    /// Compiled into every binary that must check an entitlement. Public by design.
    pub public_key_hex: String,
    pub salt_hex: String,
    pub nonce_hex: String,
    pub sealed_hex: String,
    pub created: String,
}

fn derive(password: &str, salt: &[u8]) -> [u8; 32] {
    let mut key = [0u8; 32];
    pbkdf2::pbkdf2_hmac::<Sha256>(password.as_bytes(), salt, ITERATIONS, &mut key);
    key
}

/// Where a licensor key lives unless told otherwise: beside the machine's own state,
/// not in any project and never in a channel. A channel is carried to other people.
#[must_use]
pub fn default_path() -> Option<PathBuf> {
    ferryman_channel::licensing::machine_state_dir().map(|dir| dir.join("licensor.json"))
}

/// Mint a licensor keypair and seal the secret half with a password.
///
/// Refuses to overwrite: a licensor key that gets replaced silently invalidates every
/// entitlement ever issued under it, and the only symptom would be customers reporting
/// that their licence stopped verifying.
pub fn keygen(out: &Path, password: &str) -> Result<SealedLicensor> {
    if password.chars().count() < MIN_PASSWORD_LEN {
        bail!("use at least {MIN_PASSWORD_LEN} characters: this key signs every licence you sell");
    }
    if out.exists() {
        bail!(
            "{} already exists. Replacing a licensor key invalidates every entitlement issued \
             under the old one - move it aside deliberately if that is what you mean",
            out.display()
        );
    }

    let mut secret = [0u8; 32];
    rand::Rng::fill_bytes(&mut rand::rng(), &mut secret);
    let signing = SigningKey::from_bytes(&secret);

    let mut salt = [0u8; 16];
    let mut nonce = [0u8; 24];
    rand::Rng::fill_bytes(&mut rand::rng(), &mut salt);
    rand::Rng::fill_bytes(&mut rand::rng(), &mut nonce);

    let cipher = XChaCha20Poly1305::new_from_slice(&derive(password, &salt))
        .map_err(|_| anyhow::anyhow!("derive the sealing key"))?;
    let sealed = cipher
        .encrypt(&XNonce::from(nonce), secret.as_slice())
        .map_err(|_| anyhow::anyhow!("seal the licensor key"))?;

    let record = SealedLicensor {
        format: FORMAT.to_string(),
        public_key_hex: hex::encode(signing.verifying_key().to_bytes()),
        salt_hex: hex::encode(salt),
        nonce_hex: hex::encode(nonce),
        sealed_hex: hex::encode(sealed),
        created: chrono::Utc::now().to_rfc3339(),
    };
    if let Some(parent) = out.parent() {
        std::fs::create_dir_all(parent)?;
    }
    std::fs::write(out, serde_json::to_vec_pretty(&record)?)
        .with_context(|| format!("write {}", out.display()))?;
    Ok(record)
}

/// Open a sealed licensor key. The password is asked for at the terminal by the caller
/// and never reaches this from an argument, where it would sit in shell history and in
/// the process list for anyone on the machine to read.
///
/// Unused by any command yet - issuing is the next half - and kept because the round
/// trip is what the tests prove. A seal nobody has ever opened is not known to work.
#[allow(dead_code)]
pub fn open(from: &Path, password: &str) -> Result<SigningKey> {
    let text = std::fs::read_to_string(from).with_context(|| format!("read {}", from.display()))?;
    let record: SealedLicensor =
        serde_json::from_str(&text).context("that file is not a sealed licensor key")?;
    if record.format != FORMAT {
        bail!("unsupported licensor key format: {}", record.format);
    }
    let salt = hex::decode(&record.salt_hex).context("unreadable salt")?;
    let nonce: [u8; 24] = hex::decode(&record.nonce_hex)
        .context("unreadable nonce")?
        .try_into()
        .map_err(|_| anyhow::anyhow!("the nonce is the wrong length"))?;
    let sealed = hex::decode(&record.sealed_hex).context("unreadable sealed key")?;

    let cipher = XChaCha20Poly1305::new_from_slice(&derive(password, &salt))
        .map_err(|_| anyhow::anyhow!("derive the sealing key"))?;
    let opened = cipher
        .decrypt(&XNonce::from(nonce), sealed.as_slice())
        .map_err(|_| anyhow::anyhow!("wrong password, or the file has been altered"))?;
    let secret: [u8; 32] = opened
        .try_into()
        .map_err(|_| anyhow::anyhow!("the sealed key is the wrong length"))?;

    let signing = SigningKey::from_bytes(&secret);
    if hex::encode(signing.verifying_key().to_bytes()) != record.public_key_hex {
        bail!("this file's secret and public halves do not match");
    }
    Ok(signing)
}

#[cfg(test)]
mod tests {
    use super::*;

    /// The whole contract: sealed with a password, opens with that password and nothing
    /// else, and the file on disk never contains the secret.
    #[test]
    fn a_licensor_key_round_trips_and_the_file_holds_no_secret() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("licensor.json");

        let record = keygen(&path, "a long enough password").unwrap();
        let opened = open(&path, "a long enough password").unwrap();
        assert_eq!(
            hex::encode(opened.verifying_key().to_bytes()),
            record.public_key_hex
        );

        let on_disk = std::fs::read_to_string(&path).unwrap();
        assert!(
            !on_disk.contains(&hex::encode(opened.to_bytes())),
            "the secret key must not be readable in the file"
        );
        assert!(open(&path, "the wrong password").is_err());
    }

    /// Replacing a licensor key invalidates every entitlement issued under it, so it
    /// cannot be something that happens by running a command twice.
    #[test]
    fn minting_over_an_existing_licensor_key_is_refused() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("licensor.json");
        keygen(&path, "a long enough password").unwrap();
        assert!(keygen(&path, "a long enough password").is_err());
    }

    /// This key signs money. A four-character password is not a password.
    #[test]
    fn a_short_password_is_refused() {
        let dir = tempfile::tempdir().unwrap();
        assert!(keygen(&dir.path().join("licensor.json"), "short").is_err());
    }
}
