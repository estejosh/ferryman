#![forbid(unsafe_code)]

use std::path::{Path, PathBuf};
use std::process::ExitCode;

use clap::{Parser, Subcommand};

use ferry_deadman::commands::{self, ArmArgs, TestTriggerArgs};
use ferry_deadman::error::Result;

#[derive(Parser)]
#[command(
    name = "ferry-deadman",
    version,
    about = "Timelocked succession for any git repo — your projects outlive you, provably.",
    after_help = "Settings resolve as: defaults < deadman.toml < CLI flags.\nExit codes: 0 ok · 1 error · 2 bad input / not armed · 3 still time-locked"
)]
struct Cli {
    #[command(subcommand)]
    command: Command_,
}

#[derive(Subcommand)]
enum Command_ {
    /// Write a commented deadman.toml template into the repo.
    Init {
        /// Path to the git repository.
        #[arg(long, default_value = ".")]
        repo: PathBuf,
        /// Overwrite an existing deadman.toml.
        #[arg(long)]
        force: bool,
    },
    /// Seal the repo so it becomes decryptable only after a future beacon round.
    Arm {
        /// Path to the git repository.
        #[arg(long, default_value = ".")]
        repo: PathBuf,
        /// Read settings from this file instead of <repo>/deadman.toml.
        #[arg(long)]
        config: Option<PathBuf>,
        /// Successor as [name=]key (repeatable). Key: file path or inline hex.
        #[arg(long = "successor", value_name = "[NAME=]KEY")]
        successors: Vec<String>,
        /// Silence window before unlock, e.g. 30d, 12h, 1h30m. [default: 30d]
        #[arg(long)]
        window: Option<String>,
        /// drand endpoint base URL (default: public quicknet mirrors).
        #[arg(long)]
        beacon: Option<String>,
        /// Use the offline deterministic fake beacon. NO REAL PROTECTION.
        #[arg(long)]
        simulate: bool,
        /// Force archiving of conventional secret files (.env*, *.key, *.pem, secrets/).
        #[arg(long)]
        include_secrets: bool,
        /// Force exclusion of conventional secret files.
        #[arg(long, conflicts_with = "include_secrets")]
        no_include_secrets: bool,
        /// Extra gitignore-style globs to archive beyond the bundle (repeatable).
        #[arg(long = "include", value_name = "GLOB")]
        includes: Vec<String>,
        /// Replacement archiver shell line; must write ONE file at $FERRY_DEADMAN_OUT.
        #[arg(long, value_name = "CMD")]
        archive_cmd: Option<String>,
    },
    /// Prove you are alive: re-seal at a NEW future round and prune old artifacts.
    Heartbeat {
        #[arg(long, default_value = ".")]
        repo: PathBuf,
    },
    /// Show armed state, next unlock round/time, last heartbeat.
    Status {
        #[arg(long, default_value = ".")]
        repo: PathBuf,
    },
    /// Remove deadman.toml and all local sealed artifacts.
    Disarm {
        #[arg(long, default_value = ".")]
        repo: PathBuf,
    },
    /// Drill: wait out (or simulate) the unlock round, then decrypt + verify in a sandbox.
    TestTrigger {
        #[arg(long, default_value = ".")]
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
    // Piping output into `head` must not panic (Rust ignores SIGPIPE by
    // default); exit quietly like a well-behaved filter instead.
    std::panic::set_hook(Box::new(|info| {
        let broken_pipe = info
            .payload()
            .downcast_ref::<String>()
            .is_some_and(|m| m.contains("Broken pipe"))
            || info
                .payload()
                .downcast_ref::<&str>()
                .is_some_and(|m| m.contains("Broken pipe"));
        if broken_pipe {
            std::process::exit(141); // 128 + SIGPIPE
        }
        eprintln!("{info}");
    }));

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
        Command_::Init { repo, force } => commands::init(&repo, force),
        Command_::Arm {
            repo,
            config,
            successors,
            window,
            beacon,
            simulate,
            include_secrets,
            no_include_secrets,
            includes,
            archive_cmd,
        } => {
            let mut successors_parsed = Vec::new();
            for s in &successors {
                successors_parsed.push(commands::parse_successor(s)?);
            }
            commands::arm(&ArmArgs {
                repo,
                config,
                successors: successors_parsed,
                window,
                include_secrets: if include_secrets {
                    Some(true)
                } else if no_include_secrets {
                    Some(false)
                } else {
                    None
                },
                includes,
                beacon,
                simulate,
                archive_cmd,
            })
        }
        Command_::Heartbeat { repo } => run(&repo, RunKind::Heartbeat),
        Command_::Status { repo } => run(&repo, RunKind::Status),
        Command_::Disarm { repo } => run(&repo, RunKind::Disarm),
        Command_::TestTrigger {
            repo,
            max_wait,
            keep,
        } => {
            // `--max-wait 0s` means "fail immediately if still locked".
            let max_wait = match max_wait {
                Some(s) => Some(ferry_deadman::duration::parse_window_allow_zero(&s)?),
                None => None,
            };
            let args = TestTriggerArgs {
                repo: repo.clone(),
                max_wait,
                keep,
            };
            run_trigger(args)
        }
    }
}

/// Which ordinary command is about to run — used for the automatic any-cli
/// heartbeat that some repos opt into.
enum RunKind {
    Heartbeat,
    Status,
    Disarm,
}

fn run(repo: &Path, kind: RunKind) -> Result<()> {
    match kind {
        RunKind::Heartbeat => commands::heartbeat(repo),
        RunKind::Status => commands::status(repo),
        RunKind::Disarm => commands::disarm(repo),
    }
}

fn run_trigger(args: TestTriggerArgs) -> Result<()> {
    commands::test_trigger(&args)
}
