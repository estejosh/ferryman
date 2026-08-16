//! Session trajectories: the full record of a run - what was asked (prompt
//! digest), what came back (output), which engine produced it, and whether it
//! succeeded. Kept in the synced channel so a reviewer can replay *how* the
//! work happened rather than only read the verdict, and so the benchmark has a
//! corpus of real runs.

use std::collections::BTreeMap;
use std::fs;
use std::path::PathBuf;

use anyhow::{Result, bail};
use chrono::{DateTime, Utc};
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};

use crate::ProjectRoute;

/// Output beyond this many bytes is truncated in the trajectory; the digest is
/// always of the full prompt.
const OUTPUT_CAP: usize = 64 * 1024;

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct Trajectory {
    pub order_id: String,
    pub agent: String,
    pub engine: String,
    pub revision: u32,
    pub at: DateTime<Utc>,
    pub ok: bool,
    /// SHA-256 hex of the exact prompt, so the run can be replayed verbatim.
    pub prompt_digest: String,
    /// The captured stdout, truncated to a sane cap.
    pub output: String,
}

/// SHA-256 hex of a prompt, for replay without storing the full text.
#[must_use]
pub fn digest(text: &str) -> String {
    hex::encode(Sha256::digest(text.as_bytes()))
}

/// Cap an output for storage; the marker is append-only so it cannot be
/// mistaken for the engine's own text.
#[must_use]
pub fn truncate(text: &str) -> String {
    if text.len() <= OUTPUT_CAP {
        text.to_string()
    } else {
        let mut out: String = text.chars().take(OUTPUT_CAP).collect();
        out.push_str("\n\u{2026}[truncated]");
        out
    }
}

/// Record a trajectory in the synced channel. One writer per path: the agent
/// writes only its own revision file.
pub fn record_trajectory(route: &ProjectRoute, trajectory: &Trajectory) -> Result<PathBuf> {
    if !crate::is_safe_component(&trajectory.order_id)
        || !crate::is_safe_component(&trajectory.agent)
    {
        bail!("trajectory ids must be path-safe identifiers");
    }
    let path = route
        .communications
        .join("trajectories")
        .join(&trajectory.order_id)
        .join(format!("{}.{:03}.json", trajectory.agent, trajectory.revision));
    crate::write_task_file(&path, trajectory)?;
    Ok(path)
}

/// What one agent has been doing, summarised for a dashboard: its most recent
/// engine, when that was, and how many runs are on record. Keeps "which machine"
/// and "which model" distinct — an agent is the machine, the engine is the model
/// it drove.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct AgentRuns {
    pub engine: String,
    pub last_active: DateTime<Utc>,
    pub runs: usize,
}

/// Per-agent run summary, from the synced trajectory files.
pub fn agent_runs(route: &ProjectRoute) -> Result<BTreeMap<String, AgentRuns>> {
    let mut out: BTreeMap<String, AgentRuns> = BTreeMap::new();
    let root = route.communications.join("trajectories");
    if !root.is_dir() {
        return Ok(out);
    }
    for order in fs::read_dir(&root)? {
        let order = order?.path();
        if !order.is_dir() {
            continue;
        }
        for entry in fs::read_dir(&order)? {
            let path = entry?.path();
            if path.extension().and_then(|ext| ext.to_str()) != Some("json") {
                continue;
            }
            let Ok(text) = fs::read_to_string(&path) else {
                continue;
            };
            let Ok(trajectory) = serde_json::from_str::<Trajectory>(&text) else {
                continue;
            };
            let entry = out.entry(trajectory.agent.clone()).or_insert(AgentRuns {
                engine: trajectory.engine.clone(),
                last_active: trajectory.at,
                runs: 0,
            });
            entry.runs += 1;
            if trajectory.at > entry.last_active {
                entry.last_active = trajectory.at;
                entry.engine = trajectory.engine.clone();
            }
        }
    }
    Ok(out)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn a_digest_is_stable_and_hex() {
        assert_eq!(digest("hi"), digest("hi"));
        assert_eq!(digest("hi").len(), 64);
        assert_ne!(digest("hi"), digest("bye"));
    }

    #[test]
    fn truncation_marks_itself() {
        let long = "x".repeat(OUTPUT_CAP + 100);
        let out = truncate(&long);
        assert!(out.len() <= OUTPUT_CAP + 20);
        assert!(out.ends_with("[truncated]"));
        assert_eq!(truncate("short"), "short");
    }
}
