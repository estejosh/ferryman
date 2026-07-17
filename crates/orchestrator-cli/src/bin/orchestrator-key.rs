#![forbid(unsafe_code)]
//! Small operator utility for the one secret a local Bridge needs for recovery.
//! It writes directly to the OS keychain and never prints the key material.

use anyhow::{Result, bail};
use clap::{Parser, Subcommand};
use uuid::Uuid;

#[derive(Parser)]
struct Cli {
    #[arg(long, default_value = "OrchestratorBridge")]
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
                "Recovery key created securely. Set ORCHESTRATOR_RECOVERY_KEY_REFERENCE=keychain:{}:{}",
                cli.service, cli.account
            );
        }
        Command::Verify => {
            let key = entry.get_password()?;
            if key.len() != 64 || !key.bytes().all(|byte| byte.is_ascii_hexdigit()) {
                bail!("keychain entry is not a 32-byte hexadecimal recovery key");
            }
            println!(
                "Recovery key reference is valid: keychain:{}:{}",
                cli.service, cli.account
            );
        }
    }
    Ok(())
}
