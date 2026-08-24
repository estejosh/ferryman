#![forbid(unsafe_code)]

use std::path::PathBuf;
use std::process::ExitCode;

use clap::{Parser, Subcommand};

use ferry_deadman::commands::{self, ArmArgs, TestTriggerArgs};
use ferry_deadman::error::Result;

#[derive(Parser)]
#[command(
    name = "ferry-deadman",
    version,
    about = "Timelocked succession for any git repo — your projects outlive you, provably.",
    after_help = "Exit codes: 0 ok · 1 error · 2 bad input / not armed · 3 still time-locked"
)]
struct Cli {
    #[command(subcommand)]
    command: Command_,
}

#[derive(Subcommand)]
enum Command_ {
    /// Seal the repo so it becomes decryptable only after a future beacon round.
    Arm {
        /// Path to the git repository.
        #[arg(long)]
        repo: PathBuf,
        /// Successor public key: a file path or an inline hex string.
        #[arg(long)]
        successor_pub: String,
        /// Silence window before unlock, e.g. 30d, 12h, 45m, 90s.
        #[arg(long, default_value = "30d")]
        window: String,
        /// Also archive conventional secret files (.env*, *.key, *.pem, secrets/).
        #[arg(long)]
        include_secrets: bool,
        /// drand endpoint base URL (default: api.drand.sh, then cloudflare mirror).
        #[arg(long)]
        beacon: Option<String>,
        /// Use the offline deterministic fake beacon. NO REAL PROTECTION.
        #[arg(long)]
        simulate: bool,
    },
    /// Prove you are alive: re-seal at a NEW future round and prune the old artifact.
    Heartbeat {
        #[arg(long)]
        repo: PathBuf,
    },
    /// Show armed state, next unlock round/time, last heartbeat.
    Status {
        #[arg(long)]
        repo: PathBuf,
    },
    /// Remove config and all local sealed artifacts.
    Disarm {
        #[arg(long)]
        repo: PathBuf,
    },
    /// Drill: wait out (or simulate) the unlock round, then decrypt + verify in a sandbox.
    TestTrigger {
        #[arg(long)]
        repo: PathBuf,
        /// Max time to wait for the beacon signature, e.g. 45s, 10m.
        #[arg(long)]
        max_wait: Option<String>,
        /// Keep the recovered tree for inspection instead of cleaning up.
        #[arg(long)]
        keep: bool,
    },
}

fn main() -> ExitCode {
    let cli = Cli::parse();
    match dispatch(cli) {
        Ok(()) => ExitCode::SUCCESS,
        Err(e) => {
            eprintln!("error: {e}");
            ExitCode::from(u8::try_from(e.exit_code()).unwrap_or(1))
        }
    }
}

fn dispatch(cli: Cli) -> Result<()> {
    match cli.command {
        Command_::Arm {
            repo,
            successor_pub,
            window,
            include_secrets,
            beacon,
            simulate,
        } => commands::arm(&ArmArgs {
            repo,
            successor_pub,
            window,
            include_secrets,
            beacon,
            simulate,
        }),
        Command_::Heartbeat { repo } => commands::heartbeat(&repo),
        Command_::Status { repo } => commands::status(&repo),
        Command_::Disarm { repo } => commands::disarm(&repo),
        Command_::TestTrigger {
            repo,
            max_wait,
            keep,
        } => {
            let max_wait = match max_wait {
                // `--max-wait 0s` means "fail immediately if still locked".
                Some(s) => Some(ferry_deadman::duration::parse_window_allow_zero(&s)?),
                None => None,
            };
            commands::test_trigger(&TestTriggerArgs {
                repo,
                max_wait,
                keep,
            })
        }
    }
}
