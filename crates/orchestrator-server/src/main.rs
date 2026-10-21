use anyhow::Result;
use clap::Parser;
use orchestrator_core::SqliteStore;
use orchestrator_server::{
    AppState, app,
    telegram::TelegramGate,
    workspace::{provision_private_repository, select_artifact_root},
};
use std::{net::SocketAddr, path::PathBuf};

#[derive(Parser)]
struct Args {
    #[arg(long, default_value = "./.data/bridge.db")]
    database: PathBuf,
    #[arg(long, default_value = "./.data/artifacts")]
    artifacts: PathBuf,
    /// Use this existing mapped/network directory for artifacts when available.
    #[arg(long, env = "ORCHESTRATOR_NETWORK_ARTIFACTS")]
    network_artifacts: Option<PathBuf>,
    #[arg(long, default_value = "./.data/projects")]
    workspace_root: PathBuf,
    /// Bridge-owned memory, kept outside project workspaces and agent control.
    #[arg(long, default_value = "./.data/bridge-memory")]
    memory_root: PathBuf,
    /// Local root for encrypted continuity packs and read-only recovery workspaces.
    #[arg(long, default_value = "./.data/recovery")]
    recovery_root: PathBuf,
    /// Private repository used only for encrypted recovery packs.
    #[arg(long, env = "ORCHESTRATOR_RECOVERY_GIT_REPOSITORY")]
    recovery_git_repository: Option<String>,
    #[arg(
        long,
        env = "ORCHESTRATOR_RECOVERY_GIT_BRANCH",
        default_value = "bridge/recovery"
    )]
    recovery_git_branch: String,
    #[arg(long, default_value_t = 104857600)]
    max_artifact_bytes: u64,
    #[arg(long, default_value = "127.0.0.1:8787")]
    listen: SocketAddr,
    #[arg(long)]
    no_demo_project: bool,
    /// Require ORCHESTRATOR_ADMIN_TOKEN for project creation and disable demo bootstrap.
    #[arg(long)]
    production: bool,
    /// Required only when production mode binds directly to a non-loopback address.
    #[arg(long)]
    tls_terminated: bool,
}
#[tokio::main]
async fn main() -> Result<()> {
    tracing_subscriber::fmt()
        .json()
        .with_env_filter(tracing_subscriber::EnvFilter::from_default_env())
        .init();
    let args = Args::parse();
    if args.production && !args.listen.ip().is_loopback() && !args.tls_terminated {
        anyhow::bail!(
            "production mode refuses a non-loopback listener without --tls-terminated; terminate TLS at a trusted reverse proxy"
        )
    }
    let admin_token_env = std::env::var("ORCHESTRATOR_ADMIN_TOKEN").ok();
    if !args.listen.ip().is_loopback() && admin_token_env.is_none() {
        anyhow::bail!(
            "refusing to bind {} (non-loopback) without ORCHESTRATOR_ADMIN_TOKEN set; without it, anyone reaching this port can create a project with a self-chosen token — set ORCHESTRATOR_ADMIN_TOKEN or use --production",
            args.listen
        )
    }
    if let Some(parent) = args.database.parent() {
        tokio::fs::create_dir_all(parent).await?
    };
    let artifacts = select_artifact_root(args.artifacts, args.network_artifacts);
    tokio::fs::create_dir_all(&artifacts).await?;
    tokio::fs::create_dir_all(&args.workspace_root).await?;
    tokio::fs::create_dir_all(&args.memory_root).await?;
    let store = SqliteStore::open(&args.database)?;
    if !args.no_demo_project && !args.production {
        let demo_workspace =
            provision_private_repository(&args.workspace_root, "demo", "Demo project")?;
        let _ = store.create_project(
            "demo",
            "Demo project",
            "demo-local-token",
            &demo_workspace.to_string_lossy(),
        );
    }
    let mut state = AppState::new(store, artifacts)
        .with_workspace_root(args.workspace_root)
        .with_memory_root(args.memory_root)
        .with_max_artifact_bytes(args.max_artifact_bytes);
    tokio::fs::create_dir_all(&args.recovery_root).await?;
    let recovery_key = load_recovery_key(args.production)?;
    state = state.with_recovery_key(args.recovery_root, recovery_key.0, recovery_key.1);
    if let Some(repository) = args.recovery_git_repository {
        state = state.with_git_recovery(repository, args.recovery_git_branch);
    }
    match std::env::var("ORCHESTRATOR_MEMORY_WRITE_TOKEN") {
        Ok(memory_write_token) => state = state.with_memory_write_token(memory_write_token),
        Err(_) if args.production => {
            anyhow::bail!("ORCHESTRATOR_MEMORY_WRITE_TOKEN is required with --production")
        }
        Err(_) => {}
    }
    if args.production {
        let admin_token = admin_token_env.clone().ok_or_else(|| {
            anyhow::anyhow!("ORCHESTRATOR_ADMIN_TOKEN is required with --production")
        })?;
        if std::env::var("ORCHESTRATOR_MEMORY_WRITE_TOKEN")
            .ok()
            .as_deref()
            == Some(admin_token.as_str())
        {
            anyhow::bail!("production requires distinct admin and memory-write credentials")
        }
        state = state.with_admin_token(admin_token);
    } else if let Some(admin_token) = admin_token_env {
        state = state.with_admin_token(admin_token);
    }
    let telegram_store = state.store.clone();
    match TelegramGate::from_config(
        load_telegram_bot_token()?,
        telegram_approver_id(),
        telegram_chat_id(),
    ) {
        Some(gate) => {
            gate.spawn(telegram_store);
            tracing::info!("telegram approval gate armed");
        }
        None => {
            tracing::info!(
                "telegram approval gate not configured (TELEGRAM_BOT_TOKEN/_KEYRING_REFERENCE or TELEGRAM_APPROVER_ID missing) — fails closed, no Telegram approval path opened"
            );
        }
    }
    let listener = tokio::net::TcpListener::bind(args.listen).await?;
    tracing::info!(address=%args.listen,"orchestrator bridge listening");
    axum::serve(listener, app(state)).await?;
    Ok(())
}

/// `TELEGRAM_BOT_TOKEN` (dev-friendly, an explicit secret in the environment) takes
/// priority; otherwise `TELEGRAM_BOT_TOKEN_KEYRING_REFERENCE` (`service:account`) reads
/// it from the OS keyring, mirroring `load_recovery_key`'s reference-by-name pattern so
/// the token itself never has to live in bridge configuration or process arguments.
/// Never logged, never returned in an error message.
fn load_telegram_bot_token() -> Result<Option<String>> {
    if let Ok(token) = std::env::var("TELEGRAM_BOT_TOKEN") {
        return Ok(Some(token));
    }
    let Ok(reference) = std::env::var("TELEGRAM_BOT_TOKEN_KEYRING_REFERENCE") else {
        return Ok(None);
    };
    let Some((service, account)) = reference.split_once(':') else {
        anyhow::bail!("TELEGRAM_BOT_TOKEN_KEYRING_REFERENCE must use service:account");
    };
    let entry = keyring::Entry::new(service, account)?;
    Ok(Some(entry.get_password()?))
}

fn telegram_approver_id() -> Option<i64> {
    std::env::var("TELEGRAM_APPROVER_ID")
        .ok()
        .and_then(|value| value.parse::<i64>().ok())
}

fn telegram_chat_id() -> Option<i64> {
    std::env::var("TELEGRAM_CHAT_ID")
        .ok()
        .and_then(|value| value.parse::<i64>().ok())
}

/// Development accepts an explicitly named environment value. Production reads
/// from the operating-system keychain by reference so the key material never
/// belongs in Bridge configuration, packs, SQLite, or logs.
fn load_recovery_key(production: bool) -> Result<(String, [u8; 32])> {
    let configured_reference = std::env::var("ORCHESTRATOR_RECOVERY_KEY_REFERENCE").ok();
    let raw = if production || configured_reference.is_some() {
        let reference = configured_reference.ok_or_else(|| anyhow::anyhow!("ORCHESTRATOR_RECOVERY_KEY_REFERENCE (keychain:service:account) is required with --production"))?;
        let fields: Vec<_> = reference.splitn(3, ':').collect();
        if fields.len() != 3 || fields[0] != "keychain" {
            anyhow::bail!("recovery key reference must use keychain:service:account")
        }
        let entry = keyring::Entry::new(fields[1], fields[2])?;
        (reference, entry.get_password()?)
    } else {
        let value=std::env::var("ORCHESTRATOR_RECOVERY_KEY_HEX").map_err(|_| anyhow::anyhow!("ORCHESTRATOR_RECOVERY_KEY_HEX is required to create or recover encrypted continuity packs in development"))?;
        ("env:ORCHESTRATOR_RECOVERY_KEY_HEX".into(), value)
    };
    let bytes = hex::decode(raw.1)?;
    let key: [u8; 32] = bytes.try_into().map_err(|_| {
        anyhow::anyhow!("recovery key must be exactly 32 bytes (64 hex characters)")
    })?;
    Ok((raw.0, key))
}
