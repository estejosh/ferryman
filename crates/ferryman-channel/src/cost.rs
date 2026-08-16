//! Cost/token accounting: aggregate learnings and trajectories into per-engine
//! usage and cost estimates.

use std::{
    cmp::Ordering,
    collections::BTreeMap,
    fs,
    path::{Path, PathBuf},
};

use anyhow::Result;
use serde_json::Value;

use crate::ProjectRoute;

/// Per-engine usage and cost totals.
///
/// `runs` counts recorded trajectories, `accepted` counts accepted learnings,
/// and the token totals are summed from any `usage` payload found on those
/// trajectories. Cost is estimated from a per-engine list-price table (see
/// `price_for`); unknown engines fall back to a conservative default.
#[derive(Debug, Clone, PartialEq)]
pub struct EngineCost {
    pub engine: String,
    pub runs: usize,
    pub accepted: usize,
    pub prompt_tokens: u64,
    pub completion_tokens: u64,
    pub estimated_cost_usd: f64,
}

/// Per-million-token list prices, looked up per engine by name. Published list
/// prices rounded to two decimals, kept as a maintainable table rather than
/// fetched from a vendor at runtime (the dashboard works offline). Unknown
/// engines fall back to the defaults below.
struct EnginePrice {
    prompt_per_million: f64,
    completion_per_million: f64,
}

/// Default list prices, per million tokens, for engines without a table entry.
const DEFAULT_PROMPT_PER_MILLION: f64 = 3.0;
const DEFAULT_COMPLETION_PER_MILLION: f64 = 15.0;

/// Look up an engine's list price. Matching is by name substring so
/// `claude-sonnet-4-5` and `deepseek-v4-pro` land in the right bucket, and a
/// new model variant inherits its family's price without a table edit.
fn price_for(engine: &str) -> EnginePrice {
    let key = engine.to_ascii_lowercase();
    let (prompt_per_million, completion_per_million) = match key.as_str() {
        e if e.contains("claude") => (3.0, 15.0),
        e if e.contains("deepseek") => (0.27, 1.10),
        e if e.contains("gpt-4o-mini") => (0.15, 0.60),
        e if e.contains("gpt-4o") || e.contains("gpt-4") => (2.50, 10.0),
        e if e.contains("o1") || e.contains("o3") || e.contains("o4") => (15.0, 60.0),
        _ => (DEFAULT_PROMPT_PER_MILLION, DEFAULT_COMPLETION_PER_MILLION),
    };
    EnginePrice {
        prompt_per_million,
        completion_per_million,
    }
}

fn trajectories_root(route: &ProjectRoute) -> PathBuf {
    route.communications.join("trajectories")
}

/// Estimate spend for one engine from its token counts and list price.
fn estimate_cost(engine: &str, prompt_tokens: u64, completion_tokens: u64) -> f64 {
    let price = price_for(engine);
    (prompt_tokens as f64 * price.prompt_per_million
        + completion_tokens as f64 * price.completion_per_million)
        / 1_000_000.0
}

/// Rough token count: about four characters per token for English prose. Good
/// enough to size a project before the first call; not a substitute for a
/// vendor's exact count.
#[must_use]
pub fn estimate_tokens(text: &str) -> u64 {
    text.chars().count().div_ceil(4) as u64
}

/// Estimate the cost of sending one prompt to one engine: input tokens at the
/// engine's prompt price, plus `output_tokens` at its completion price.
#[must_use]
pub fn estimate_prompt_cost(engine: &str, prompt: &str, output_tokens: u64) -> f64 {
    let input_tokens = estimate_tokens(prompt);
    let price = price_for(engine);
    (input_tokens as f64 * price.prompt_per_million
        + output_tokens as f64 * price.completion_per_million)
        / 1_000_000.0
}

/// The published price families, for a `ferry cost rates` listing. Prices are per
/// million tokens. Unknown engines fall back to the default family.
#[must_use]
pub fn published_rates() -> Vec<(&'static str, f64, f64)> {
    vec![
        ("claude (sonnet/opus)", 3.0, 15.0),
        ("deepseek", 0.27, 1.10),
        ("gpt-4o-mini", 0.15, 0.60),
        ("gpt-4o / gpt-4", 2.50, 10.0),
        ("o1 / o3 / o4", 15.0, 60.0),
        ("default (unknown)", 3.0, 15.0),
    ]
}

/// Pull a usage count out of a trajectory/result payload.
///
/// Trajectories are read as raw JSON so this stays tolerant of both the typed
/// [`crate::trajectory::Trajectory`] shape (which has no usage yet) and richer
/// result-like payloads carrying `payload.usage.prompt_tokens` /
/// `payload.usage.completion_tokens`.
fn usage_tokens(value: &Value, key: &str) -> u64 {
    let payload_pointer = format!("/payload/usage/{key}");
    let top_level_pointer = format!("/usage/{key}");
    value
        .pointer(&payload_pointer)
        .and_then(Value::as_u64)
        .or_else(|| value.pointer(&top_level_pointer).and_then(Value::as_u64))
        .unwrap_or(0)
}

/// The engine a trajectory belongs to. Trajectories carry a top-level `engine`;
/// result-shaped payloads carry `produced_by` instead.
fn trajectory_engine(value: &Value) -> Option<String> {
    value
        .get("engine")
        .and_then(Value::as_str)
        .filter(|engine| !engine.is_empty())
        .map(str::to_string)
        .or_else(|| {
            value
                .pointer("/payload/produced_by")
                .and_then(Value::as_str)
                .filter(|engine| !engine.is_empty())
                .map(str::to_string)
        })
        .or_else(|| {
            value
                .pointer("/produced_by")
                .and_then(Value::as_str)
                .filter(|engine| !engine.is_empty())
                .map(str::to_string)
        })
}

/// Collect every JSON trajectory file below `dir`. Unreadable or malformed
/// files are skipped rather than failing the whole accounting pass.
fn collect_trajectories(dir: &Path, out: &mut Vec<Value>) -> Result<()> {
    if !dir.is_dir() {
        return Ok(());
    }
    for entry in fs::read_dir(dir)? {
        let entry = entry?;
        let path = entry.path();
        if path.is_dir() {
            collect_trajectories(&path, out)?;
        } else if path.extension().and_then(|extension| extension.to_str()) == Some("json") {
            let Ok(text) = fs::read_to_string(&path) else {
                continue;
            };
            if let Ok(value) = serde_json::from_str::<Value>(&text) {
                out.push(value);
            }
        }
    }
    Ok(())
}

/// Aggregate learnings and trajectory usage into per-engine totals, most
/// expensive first.
pub fn engine_costs(route: &ProjectRoute) -> Result<Vec<EngineCost>> {
    let mut costs: BTreeMap<String, EngineCost> = BTreeMap::new();

    for learning in crate::learning::read_learnings(route)? {
        if learning.engine.is_empty() {
            continue;
        }
        let entry = costs
            .entry(learning.engine.clone())
            .or_insert_with(|| EngineCost {
                engine: learning.engine.clone(),
                runs: 0,
                accepted: 0,
                prompt_tokens: 0,
                completion_tokens: 0,
                estimated_cost_usd: 0.0,
            });
        if learning.accepted {
            entry.accepted += 1;
        }
    }

    let mut trajectories = Vec::new();
    collect_trajectories(&trajectories_root(route), &mut trajectories)?;
    for value in trajectories {
        let Some(engine) = trajectory_engine(&value) else {
            continue;
        };
        let entry = costs.entry(engine.clone()).or_insert_with(|| EngineCost {
            engine,
            runs: 0,
            accepted: 0,
            prompt_tokens: 0,
            completion_tokens: 0,
            estimated_cost_usd: 0.0,
        });
        entry.runs += 1;
        entry.prompt_tokens += usage_tokens(&value, "prompt_tokens");
        entry.completion_tokens += usage_tokens(&value, "completion_tokens");
    }

    for entry in costs.values_mut() {
        entry.estimated_cost_usd =
            estimate_cost(&entry.engine, entry.prompt_tokens, entry.completion_tokens);
    }

    let mut costs: Vec<EngineCost> = costs.into_values().collect();
    costs.sort_by(|a, b| {
        b.estimated_cost_usd
            .partial_cmp(&a.estimated_cost_usd)
            .unwrap_or(Ordering::Equal)
            .then_with(|| a.engine.cmp(&b.engine))
    });
    Ok(costs)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::ProjectRoute;

    fn route(dir: &std::path::Path) -> ProjectRoute {
        let workspace = dir.join("workspace");
        let attachment = workspace.join(".ferryman");
        ProjectRoute {
            project_id: "ferryman".into(),
            workspace,
            attachment: attachment.clone(),
            communications: attachment.join("ferryman"),
            shared_remote: "ferryman-ferryman".into(),
            git_remote: String::new(),
            git_visibility: String::new(),
            agents: Vec::new(),
        }
    }

    fn learning(engine: &str, accepted: bool) -> crate::learning::Learning {
        crate::learning::Learning {
            at: chrono::Utc::now(),
            engine: engine.into(),
            agent: None,
            task_id: "t-1".into(),
            source: "eval".into(),
            accepted,
            note: String::new(),
        }
    }

    #[test]
    fn aggregates_learnings_and_trajectory_usage() {
        let dir = tempfile::tempdir().unwrap();
        let route = route(dir.path());

        crate::learning::record_learning(&route, &learning("claude", true)).unwrap();
        crate::learning::record_learning(&route, &learning("claude", false)).unwrap();
        crate::learning::record_learning(&route, &learning("deepseek", true)).unwrap();

        crate::trajectory::record_trajectory(
            &route,
            &crate::trajectory::Trajectory {
                order_id: "t-1".into(),
                agent: "agent".into(),
                engine: "claude".into(),
                revision: 1,
                at: chrono::Utc::now(),
                ok: true,
                prompt_digest: crate::trajectory::digest("prompt"),
                output: "output".into(),
            },
        )
        .unwrap();

        let deepseek_path = route.communications.join("trajectories/t-2/agent.001.json");
        std::fs::create_dir_all(deepseek_path.parent().unwrap()).unwrap();
        std::fs::write(
            &deepseek_path,
            serde_json::to_string(&serde_json::json!({
                "engine": "deepseek",
                "payload": {
                    "usage": {
                        "prompt_tokens": 1000,
                        "completion_tokens": 200
                    }
                }
            }))
            .unwrap(),
        )
        .unwrap();

        let costs = engine_costs(&route).unwrap();
        assert_eq!(costs.len(), 2);

        assert_eq!(costs[0].engine, "deepseek");
        assert_eq!(costs[0].runs, 1);
        assert_eq!(costs[0].accepted, 1);
        assert_eq!(costs[0].prompt_tokens, 1000);
        assert_eq!(costs[0].completion_tokens, 200);
        // deepseek list price: $0.27/M prompt + $1.10/M completion, so
        // 1000 prompt + 200 completion tokens = (270 + 220) / 1e6 dollars.
        assert!((costs[0].estimated_cost_usd - 0.00049).abs() < 1e-9);

        assert_eq!(costs[1].engine, "claude");
        assert_eq!(costs[1].runs, 1);
        assert_eq!(costs[1].accepted, 1);
        assert_eq!(costs[1].prompt_tokens, 0);
        assert_eq!(costs[1].completion_tokens, 0);
        assert_eq!(costs[1].estimated_cost_usd, 0.0);
    }

    #[test]
    fn empty_route_has_no_costs() {
        let dir = tempfile::tempdir().unwrap();
        let route = route(dir.path());
        assert!(engine_costs(&route).unwrap().is_empty());
    }

    #[test]
    fn token_estimate_is_about_four_chars_per_token() {
        assert_eq!(estimate_tokens(""), 0);
        assert_eq!(estimate_tokens("abcd"), 1);
        assert_eq!(estimate_tokens("hello world"), 3);
        assert_eq!(estimate_tokens(&"a".repeat(100)), 25);
    }

    #[test]
    fn prompt_cost_uses_prompt_and_completion_prices() {
        // deepseek: $0.27/M prompt, $1.10/M completion. 400 chars = 100 input
        // tokens, plus 1000 output tokens -> (27 + 1100) / 1e6 dollars.
        let cost = estimate_prompt_cost("deepseek", &"a".repeat(400), 1000);
        assert!((cost - 0.001127).abs() < 1e-12);
        // Unknown engines fall back to the default ($3 / $15).
        let unknown = estimate_prompt_cost("mystery-engine", "hello", 0);
        assert!((unknown - estimate_prompt_cost("claude", "hello", 0)).abs() < 1e-12);
    }
}
