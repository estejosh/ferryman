#![forbid(unsafe_code)]
//! Small operator utility for the one secret a local Bridge needs for recovery.
//! It writes directly to the OS keychain and never prints the key material.

use anyhow::{Context, Result, bail};
use chacha20poly1305::{
    XChaCha20Poly1305, XNonce,
    aead::{Aead, KeyInit},
};
use clap::{Parser, Subcommand};
use pbkdf2::pbkdf2_hmac;
use rand::RngCore;
use serde::{Deserialize, Serialize};
use sha2::Sha256;
use std::{fs::OpenOptions, path::PathBuf};
use uuid::Uuid;

#[derive(Parser)]
struct Cli {
    #[arg(long, default_value = "Ferryman")]
    service: String,
    #[arg(long, default_value = "recovery")]
    account: String,
    #[command(subcommand)]
    command: Command,
}
#[derive(Subcommand)]
enum Command {
    Bootstrap,
    Verify,
    /// Create an encrypted pairing file for a second trusted machine.
    PairingExport {
        #[arg(long)]
        output: PathBuf,
    },
    /// Import an encrypted pairing file created on another trusted machine.
    PairingImport {
        #[arg(long)]
        input: PathBuf,
    },
}

#[derive(Serialize, Deserialize)]
struct PairingFile {
    format: String,
    salt_hex: String,
    nonce_hex: String,
    ciphertext_hex: String,
}

const PAIRING_ITERATIONS: u32 = 600_000;

fn valid_key(key: &str) -> bool {
    key.len() == 64 && key.bytes().all(|byte| byte.is_ascii_hexdigit())
}

fn pairing_key(passphrase: &str, salt: &[u8]) -> [u8; 32] {
    let mut key = [0_u8; 32];
    pbkdf2_hmac::<Sha256>(passphrase.as_bytes(), salt, PAIRING_ITERATIONS, &mut key);
    key
}

fn prompt_pairing_passphrase(confirm: bool) -> Result<String> {
    let passphrase =
        rpassword::prompt_password("Pairing passphrase (keep it separate from the file): ")?;
    if passphrase.len() < 12 {
        bail!("pairing passphrase must be at least 12 characters")
    }
    if confirm {
        let repeated = rpassword::prompt_password("Repeat pairing passphrase: ")?;
        if passphrase != repeated {
            bail!("pairing passphrases did not match")
        }
    }
    Ok(passphrase)
}

fn main() -> Result<()> {
    let cli = Cli::parse();
    let entry = keyring::Entry::new(&cli.service, &cli.account)?;
    match cli.command {
        Command::Bootstrap => {
            if entry.get_password().is_ok() {
                bail!(
                    "a recovery key already exists for keychain:{}:{}; refusing to replace it",
                    cli.service,
                    cli.account
                );
            }
            // Two UUIDv4 values provide a fresh 244-bit random value while
            // keeping a simple portable 64-hex-character representation.
            let key = format!("{}{}", Uuid::new_v4().simple(), Uuid::new_v4().simple());
            entry.set_password(&key)?;
            println!(
                "Recovery key created securely. Set FERRYMAN_RECOVERY_KEY_REFERENCE=keychain:{}:{}",
                cli.service, cli.account
            );
        }
        Command::Verify => {
            let key = entry.get_password()?;
            if !valid_key(&key) {
                bail!("keychain entry is not a 32-byte hexadecimal recovery key");
            }
            println!(
                "Recovery key reference is valid: keychain:{}:{}",
                cli.service, cli.account
            );
        }
        Command::PairingExport { output } => {
            let recovery_key = entry
                .get_password()
                .context("no local recovery key exists; run `ferryman-key bootstrap` first")?;
            if !valid_key(&recovery_key) {
                bail!("keychain entry is not a 32-byte hexadecimal recovery key")
            }
            let passphrase = prompt_pairing_passphrase(true)?;
            let mut salt = [0_u8; 16];
            let mut nonce = [0_u8; 24];
            rand::rng().fill_bytes(&mut salt);
            rand::rng().fill_bytes(&mut nonce);
            let cipher = XChaCha20Poly1305::new_from_slice(&pairing_key(&passphrase, &salt))?;
            let ciphertext = cipher
                .encrypt(XNonce::from_slice(&nonce), recovery_key.as_bytes())
                .map_err(|_| anyhow::anyhow!("could not encrypt recovery-key pairing file"))?;
            let pairing = PairingFile {
                format: "ferryman-key-pairing/v1".into(),
                salt_hex: hex::encode(salt),
                nonce_hex: hex::encode(nonce),
                ciphertext_hex: hex::encode(ciphertext),
            };
            let file = OpenOptions::new()
                .write(true)
                .create_new(true)
                .open(&output)
                .with_context(|| {
                    format!(
                        "refusing to replace existing pairing file {}",
                        output.display()
                    )
                })?;
            serde_json::to_writer_pretty(file, &pairing)?;
            println!(
                "Encrypted pairing file created at {}. Copy it to the second machine, then delete it after import.",
                output.display()
            );
        }
        Command::PairingImport { input } => {
            if entry.get_password().is_ok() {
                bail!(
                    "a recovery key already exists for keychain:{}:{}; refusing to replace it",
                    cli.service,
                    cli.account
                );
            }
            let pairing: PairingFile = serde_json::from_reader(
                std::fs::File::open(&input)
                    .with_context(|| format!("could not open {}", input.display()))?,
            )?;
            if pairing.format != "ferryman-key-pairing/v1" {
                bail!("unsupported pairing file format")
            }
            let salt = hex::decode(pairing.salt_hex)?;
            let nonce = hex::decode(pairing.nonce_hex)?;
            if salt.len() != 16 || nonce.len() != 24 {
                bail!("invalid pairing file salt or nonce")
            }
            let passphrase = prompt_pairing_passphrase(false)?;
            let cipher = XChaCha20Poly1305::new_from_slice(&pairing_key(&passphrase, &salt))?;
            let recovery_key = String::from_utf8(
                cipher
                    .decrypt(
                        XNonce::from_slice(&nonce),
                        hex::decode(pairing.ciphertext_hex)?.as_ref(),
                    )
                    .map_err(|_| {
                        anyhow::anyhow!(
                            "pairing passphrase was incorrect or pairing file was altered"
                        )
                    })?,
            )
            .context("pairing file did not contain a valid recovery key")?;
            if !valid_key(&recovery_key) {
                bail!("pairing file did not contain a valid recovery key")
            }
            entry.set_password(&recovery_key)?;
            println!(
                "Recovery key imported securely. Delete the pairing file now that both machines are paired."
            );
        }
    }
    Ok(())
}
