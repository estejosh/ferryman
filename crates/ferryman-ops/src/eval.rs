//! Benchmarking: run several engines over the same tasks and score them, so the
//! fleet knows which CLI wins on which work instead of guessing.
//!
//! This is Ferryman's answer to SWE-agent's benchmark mode. It is deliberately
//! minimal: a `bench.json` in the attachment lists engines and tasks; each task
//! scores against a result contract (its `require` keys), and every outcome is
//! recorded in the synced learning database so the comparison accumulates.

use std::path::Path;
use std::time::Duration;

use anyhow::{Context, Result};
use serde::{Deserialize, Serialize};

use crate::agent::{Runner, run_engine_prompt};

/// An engine to benchmark: any agent CLI, with its own args and runner.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct BenchEngine {
    pub name: String,
    pub command: String,
    #[serde(default)]
    pub args: Vec<String>,
    /// Runner, same syntax as `sandbox`: ""/none, `podman:IMG`, `docker:IMG`, or a
    /// bare `IMG` (podman). Empty means bare.
    #[serde(default)]
    pub runner: String,
}

/// One benchmark task. Its result must carry the `require` keys to pass.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct BenchTask {
    pub id: String,
    pub prompt: String,
    /// Required top-level keys in the result; scoring uses a result contract.
    #[serde(default)]
    pub require: Vec<String>,
}

/// The `bench.json` file.
#[derive(Debug, Clone, Default, Serialize, Deserialize)]
pub struct BenchConfig {
    #[serde(default, rename = "engines")]
    pub engines: Vec<BenchEngine>,
    #[serde(default, rename = "tasks")]
    pub tasks: Vec<BenchTask>,
}

/// One engine × task result.
#[derive(Debug, Clone)]
pub struct BenchResult {
    pub engine: String,
    pub task: String,
    pub accepted: bool,
    pub note: String,
}

/// Load `bench.json` from the attachment. Missing file is an error with a hint.
pub fn load_bench(attachment: &Path) -> Result<BenchConfig> {
    let path = attachment.join("bench.json");
    let text = std::fs::read_to_string(&path).with_context(|| {
        format!(
            "read {}; write it with \"engines\" and \"tasks\" arrays",
            path.display()
        )
    })?;
    serde_json::from_str(&text).with_context(|| format!("parse {}", path.display()))
}

/// Run every engine over every task, score, and record each outcome in the
/// learning database. Returns the results for display.
pub async fn run_bench(
    route: &ferryman_channel::ProjectRoute,
    config: &BenchConfig,
    workspace: &Path,
) -> Result<Vec<BenchResult>> {
    let mut results = Vec::new();
    for engine in &config.engines {
        let runner = Runner::parse(&engine.runner)?;
        for task in &config.tasks {
            let stdout = run_engine_prompt(
                &runner,
                &engine.command,
                &engine.args,
                workspace,
                &task.prompt,
                Duration::from_secs(300),
            )
            .await?;
            let payload: serde_json::Value = match serde_json::from_str(stdout.trim()) {
                Ok(value) => value,
                Err(_) => serde_json::json!({ "output": stdout.trim() }),
            };
            let contract = ferryman_channel::contract::ResultContract {
                required: task.require.clone(),
            };
            let missing = contract.violations(&payload);
            let accepted = missing.is_empty();
            let note = if accepted {
                "ok".to_string()
            } else {
                format!("missing: {}", missing.join(", "))
            };
            ferryman_channel::learning::record_learning(
                route,
                &ferryman_channel::learning::Learning {
                    at: chrono::Utc::now(),
                    engine: engine.name.clone(),
                    task_id: task.id.clone(),
                    source: "eval".to_string(),
                    accepted,
                    note: note.clone(),
                },
            )?;
            results.push(BenchResult {
                engine: engine.name.clone(),
                task: task.id.clone(),
                accepted,
                note,
            });
        }
    }
    Ok(results)
}
