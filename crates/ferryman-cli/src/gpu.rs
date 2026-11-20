//! `ferry gpu`: sugar over the machine scheduler's `gpu` lane (ADR 0033, `docs/GPU_SCHEDULER.md`).
//!
//! The lane is [`ferryman_ops::gpu`]; this only types it. A command that is not an order
//! (a render, a training run, a script that starts its own server) asks here for the card
//! and gives it back.

use std::process::Command as Process;
use std::time::Duration;

use anyhow::{Context, Result, bail};
use clap::Subcommand;
use ferryman_ops::gpu::{Ask, Gpu, GpuConfig, Hold, Wait};
use serde_json::json;

#[derive(Subcommand, Debug, Clone)]
pub enum GpuCommand {
    /// Wait for the card, run a command with it, give it back. Exits with the command's code.
    Run {
        /// Who is asking. A name under `[gpu.tenants]` in ferry.toml starts that server
        /// with the grant and stops it when the lane has been idle.
        #[arg(long)]
        tenant: String,
        /// Video memory the command needs, in MB.
        #[arg(long, default_value_t = 0)]
        vram: u64,
        /// Higher goes first. Orders use 0 (low), 10 (normal) and 20 (high).
        #[arg(long, default_value_t = 10)]
        priority: i64,
        /// Give up after this many seconds in the line.
        #[arg(long)]
        wait: Option<u64>,
        #[arg(last = true, required = true)]
        command: Vec<String>,
    },
    /// Wait for the card and print the grant's id. For a script that starts its own server:
    /// it holds the card while `--pid` (default: the process that called this) runs, and
    /// gives it back with `ferry gpu release <id>`.
    Acquire {
        #[arg(long)]
        tenant: String,
        #[arg(long, default_value_t = 0)]
        vram: u64,
        #[arg(long, default_value_t = 10)]
        priority: i64,
        /// The process that holds the card. A grant is kept while it runs.
        #[arg(long)]
        pid: Option<u32>,
        #[arg(long)]
        wait: Option<u64>,
    },
    /// Give the card back, or leave the line.
    Release { id: String },
    /// The line: who holds the card, who waits, in what order, and what holds memory
    /// without a grant.
    Status {
        #[arg(long)]
        json: bool,
    },
    /// Put a waiting request first in line, or give it a priority. The master's lever.
    Bump {
        id: String,
        #[arg(long)]
        priority: Option<i64>,
    },
}

fn open() -> Result<Gpu> {
    let root = ferryman_channel::ferry::find_root().map(|root| root.path);
    let config = match &root {
        Some(root) => GpuConfig::load(root)?,
        None => GpuConfig::default(),
    };
    let dir =
        ferryman_ops::gpu::state_dir().context("no per-user state directory on this machine")?;
    Ok(Gpu::new(dir, config))
}

fn wait_for(secs: Option<u64>) -> Wait {
    Wait {
        timeout: secs.map(Duration::from_secs),
        ..Wait::default()
    }
}

/// `ferry gpu ...`. The number is the exit code `ferry` should leave with.
///
/// # Errors
/// The lane could not be opened, the request was refused or timed out, or the command
/// could not be started.
pub fn command(command: GpuCommand) -> Result<i32> {
    let gpu = open()?;
    match command {
        GpuCommand::Run {
            tenant,
            vram,
            priority,
            wait,
            command,
        } => {
            let ask = Ask {
                id: Gpu::new_id(&tenant),
                who: tenant,
                vram_mb: vram,
                priority,
                pid: Some(std::process::id()),
            };
            eprintln!("gpu: waiting for the card as {}", ask.id);
            let id = gpu.acquire(&ask, &wait_for(wait))?;
            let hold = Hold::new(&gpu, id);
            eprintln!("gpu: granted {}", hold.id());
            let (program, args) = command.split_first().context("no command after --")?;
            let status = Process::new(program)
                .args(args)
                .env("FERRYMAN_GPU_GRANT", hold.id())
                .env("FERRYMAN_GPU_VRAM_MB", vram.to_string())
                .status()
                .with_context(|| format!("start '{program}'"))?;
            drop(hold);
            Ok(status.code().unwrap_or(1))
        }
        GpuCommand::Acquire {
            tenant,
            vram,
            priority,
            pid,
            wait,
        } => {
            let own = std::process::id();
            let pid = pid.or_else(|| ferryman_ops::gpu::parent_map().get(&own).copied());
            let ask = Ask {
                id: Gpu::new_id(&tenant),
                who: tenant,
                vram_mb: vram,
                priority,
                pid,
            };
            let id = gpu.acquire(&ask, &wait_for(wait))?;
            println!("{id}");
            Ok(0)
        }
        GpuCommand::Release { id } => {
            gpu.release(&id)?;
            Ok(0)
        }
        GpuCommand::Bump { id, priority } => {
            if !gpu.bump(&id, priority)? {
                bail!("'{id}' is not waiting in the gpu line");
            }
            Ok(0)
        }
        GpuCommand::Status { json } => {
            let (rows, tenants) = gpu.snapshot(ferryman_ops::gpu::now())?;
            let unmanaged = gpu.unmanaged_now()?;
            if json {
                let procs: Vec<_> = unmanaged
                    .iter()
                    .map(|p| json!({"pid": p.pid, "name": p.name, "vram_mb": p.vram_mb}))
                    .collect();
                let out = json!({"rows": rows, "tenants": tenants, "unmanaged": procs});
                println!("{}", serde_json::to_string_pretty(&out)?);
                return Ok(0);
            }
            let limits = gpu.config.limits();
            println!(
                "gpu lane: width {}, budget {} MB",
                limits.width, limits.budget
            );
            if rows.is_empty() {
                println!("  nobody holds the card and nobody is waiting");
            }
            for row in &rows {
                let place = row
                    .position
                    .map_or_else(|| "holds".to_string(), |n| format!("#{n}"));
                println!(
                    "  {place:<6} {:<28} {:>6} MB  waited {:>4}s  priority {} (now {})",
                    row.id, row.cost, row.wait_secs, row.priority, row.effective
                );
            }
            if !tenants.is_empty() {
                println!("servers up: {}", tenants.join(", "));
            }
            for p in &unmanaged {
                println!(
                    "holding memory with no grant: pid {} {} ({} MB)",
                    p.pid, p.name, p.vram_mb
                );
            }
            Ok(0)
        }
    }
}
