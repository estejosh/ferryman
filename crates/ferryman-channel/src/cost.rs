//! Cost/token accounting: aggregate learnings and trajectories into per-engine
//! usage and cost estimates.

use std::{
    cmp::Ordering,
    collections::BTreeMap,
    fs,
    path::{Path, PathBuf},
};

use anyhow::Result;
use serde::Deserialize;
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

/// Per-million-token list prices, looked up per engine by name. Unknown engines
/// fall back to the defaults below.
#[derive(Debug, Clone, Copy, PartialEq)]
pub struct EnginePrice {
    pub prompt_per_million: f64,
    pub completion_per_million: f64,
}

/// One engine-family override from a `rates.toml`. The name matches by
/// substring, so `claude-sonnet-4-5` inherits the `claude` row.
#[derive(Debug, Clone, Deserialize)]
struct EngineRate {
    name: String,
    prompt_per_million: f64,
    completion_per_million: f64,
    /// Optional capability override; falls back to the built-in table when absent.
    #[serde(default)]
    quality: Option<f64>,
}

#[derive(Debug, Clone, Deserialize, Default)]
struct RatesFile {
    #[serde(default)]
    engine: Vec<EngineRate>,
}

/// Editable per-engine rates: the built-in table, optionally overridden by a
/// `rates.toml` beside the channel, so prices move without a rebuild. Matching
/// is by name substring, first match wins — list specific names before families.
#[derive(Debug, Clone, Default)]
pub struct Rates {
    overrides: Vec<EngineRate>,
}

/// Default list prices, per million tokens, for engines without a table entry.
const DEFAULT_PROMPT_PER_MILLION: f64 = 3.0;
const DEFAULT_COMPLETION_PER_MILLION: f64 = 15.0;

impl Rates {
    /// The built-in table with no file overrides.
    #[must_use]
    pub fn defaults() -> Self {
        Self::default()
    }

    /// Load `rates.toml` from the channel, then the attachment. A missing or
    /// malformed file falls back to the built-in table.
    #[must_use]
    pub fn load(route: &ProjectRoute) -> Self {
        for dir in [&route.communications, &route.attachment] {
            let path = dir.join("rates.toml");
            if let Ok(text) = fs::read_to_string(&path)
                && let Ok(file) = toml::from_str::<RatesFile>(&text)
            {
                return Self {
                    overrides: file.engine,
                };
            }
        }
        Self::default()
    }

    /// The price for an engine, matching by name substring — file overrides
    /// first (first match wins), then the built-in defaults.
    #[must_use]
    pub fn price_for(&self, engine: &str) -> EnginePrice {
        let key = engine.to_ascii_lowercase();
        for entry in &self.overrides {
            if key.contains(&entry.name.to_ascii_lowercase()) {
                return EnginePrice {
                    prompt_per_million: entry.prompt_per_million,
                    completion_per_million: entry.completion_per_million,
                };
            }
        }
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

    /// The quality for an engine: file override first (first match wins), then
    /// the built-in capability table.
    #[must_use]
    pub fn quality_for(&self, engine: &str) -> f64 {
        let key = engine.to_ascii_lowercase();
        for entry in &self.overrides {
            if key.contains(&entry.name.to_ascii_lowercase()) {
                return entry.quality.unwrap_or_else(|| quality_for(engine));
            }
        }
        quality_for(engine)
    }
}

fn trajectories_root(route: &ProjectRoute) -> PathBuf {
    route.communications.join("trajectories")
}

/// Estimate spend for one engine from its token counts and list price.
fn estimate_cost(rates: &Rates, engine: &str, prompt_tokens: u64, completion_tokens: u64) -> f64 {
    let price = rates.price_for(engine);
    (prompt_tokens as f64 * price.prompt_per_million
        + completion_tokens as f64 * price.completion_per_million)
        / 1_000_000.0
}

/// Feature keywords that each suggest one more work item, for a rough project
/// scope estimate from a natural-language description.
const FEATURE_SIGNALS: &[&str] = &[
    "auth",
    "login",
    "signup",
    "database",
    "api",
    "endpoint",
    "frontend",
    "ui",
    "dashboard",
    "test",
    "deploy",
    "search",
    "payment",
    "email",
    "notification",
    "admin",
    "report",
    "integration",
    "migration",
    "queue",
    "worker",
    "mobile",
    "desktop",
    "cli",
    "sync",
    "import",
    "export",
    "cache",
    "monitor",
    "backup",
];

/// Tokens a single work item costs, before the revision factor. Rough defaults
/// for a coding task: standing context plus the task in, code plus explanation out.
pub const PROMPT_TOKENS_PER_TASK: u64 = 3000;
pub const COMPLETION_TOKENS_PER_TASK: u64 = 2500;
/// Some work gets sent back for revision; this multiplies the token totals.
pub const REVISION_FACTOR: f64 = 1.5;

/// A rough project-scope estimate: one base task, plus one per significant
/// feature mentioned, scaled a little by description length. Deliberately a
/// heuristic — the goal is "an idea of the cost", not a bid.
#[must_use]
pub fn estimate_task_count(description: &str) -> u64 {
    let lower = description.to_ascii_lowercase();
    let signals = FEATURE_SIGNALS
        .iter()
        .filter(|s| lower.contains(**s))
        .count() as u64;
    let length = (description.split_whitespace().count() as u64) / 40;
    (1 + signals + length).clamp(1, 200)
}

/// Model a whole project as `tasks` work items: total prompt and completion
/// tokens, with the revision factor applied. Returns `(tasks, prompt, completion)`.
#[must_use]
pub fn estimate_project_tokens(description: &str, tasks_hint: Option<u64>) -> (u64, u64, u64) {
    let tasks = tasks_hint.unwrap_or_else(|| estimate_task_count(description));
    let prompt = (tasks as f64 * PROMPT_TOKENS_PER_TASK as f64 * REVISION_FACTOR) as u64;
    let completion = (tasks as f64 * COMPLETION_TOKENS_PER_TASK as f64 * REVISION_FACTOR) as u64;
    (tasks, prompt, completion)
}

/// Total project cost for one engine, from the project's token totals.
#[must_use]
pub fn project_cost(
    rates: &Rates,
    engine: &str,
    prompt_tokens: u64,
    completion_tokens: u64,
) -> f64 {
    let price = rates.price_for(engine);
    (prompt_tokens as f64 * price.prompt_per_million
        + completion_tokens as f64 * price.completion_per_million)
        / 1_000_000.0
}

/// A rough model-capability score in [0, 1], for the project-quality estimate.
/// Static and approximate — a quality *hint*, not a benchmark result, and it
/// drifts as vendors ship new models. Matching is by name substring, like prices.
#[must_use]
pub fn quality_for(engine: &str) -> f64 {
    let key = engine.to_ascii_lowercase();
    if key.contains("o1") || key.contains("o3") || key.contains("o4") {
        0.95
    } else if key.contains("claude") {
        0.90
    } else if key.contains("gpt-4o") && !key.contains("mini") {
        0.85
    } else if key.contains("deepseek") {
        0.78
    } else if key.contains("gpt-4o-mini") {
        0.65
    } else {
        0.70
    }
}

/// A qualitative label for a capability score.
#[must_use]
pub fn quality_label(score: f64) -> &'static str {
    if score >= 0.90 {
        "frontier"
    } else if score >= 0.80 {
        "strong"
    } else if score >= 0.70 {
        "capable"
    } else if score >= 0.60 {
        "basic"
    } else {
        "weak"
    }
}

/// The effective quality for an engine on a project: measured confidence from
/// recorded outcomes when there are any, else the capability score. Returns
/// `(score, measured, total, accepted)` — `measured` distinguishes a real signal
/// from the static capability hint, and the counts let a caller show the evidence.
#[must_use]
pub fn effective_quality(
    route: &ProjectRoute,
    rates: &Rates,
    engine: &str,
) -> (f64, bool, usize, usize) {
    if let Some((confidence, total, accepted)) = measured_quality(route, engine) {
        return (confidence, true, total, accepted);
    }
    (rates.quality_for(engine), false, 0, 0)
}

/// Measured quality for an engine family from recorded outcomes: matches both
/// the recorded engine (command) and the agent name, so an agent named
/// `fang-deepseek` counts toward the "deepseek" family. Returns
/// `(confidence, total, accepted)` when there are any matching outcomes.
fn measured_quality(route: &ProjectRoute, engine_key: &str) -> Option<(f64, usize, usize)> {
    let key = engine_key.to_ascii_lowercase();
    let learnings = crate::learning::read_learnings(route).ok()?;
    let mut total = 0;
    let mut accepted = 0;
    for learning in &learnings {
        let engine_matches = learning.engine.to_ascii_lowercase().contains(&key);
        let agent_matches = learning
            .agent
            .as_deref()
            .map(|a| a.to_ascii_lowercase().contains(&key))
            .unwrap_or(false);
        let model_matches = learning
            .model
            .as_deref()
            .map(|m| m.to_ascii_lowercase().contains(&key))
            .unwrap_or(false);
        if engine_matches || agent_matches || model_matches {
            total += 1;
            if learning.accepted {
                accepted += 1;
            }
        }
    }
    if total == 0 {
        return None;
    }
    Some((
        (accepted as f64 + 1.0) / (total as f64 + 2.0),
        total,
        accepted,
    ))
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

    let rates = Rates::load(route);
    for entry in costs.values_mut() {
        entry.estimated_cost_usd = estimate_cost(
            &rates,
            &entry.engine,
            entry.prompt_tokens,
            entry.completion_tokens,
        );
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
            model: None,
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
    fn project_scope_grows_with_features_and_length() {
        assert_eq!(estimate_task_count(""), 1);
        assert_eq!(estimate_task_count("a tiny script"), 1);
        // Feature keywords each add a task.
        let features = estimate_task_count(
            "a service with auth, login, an api, a database, tests, and a dashboard",
        );
        assert!(features >= 7, "got {features}");
        // A long description adds tasks by length too.
        let long = estimate_task_count(&"word ".repeat(200));
        assert!(long >= 6, "got {long}");
        // The estimate is clamped to a sane range.
        let huge = estimate_task_count(&"auth api database ".repeat(500));
        assert!(huge <= 200);
    }

    #[test]
    fn project_tokens_scale_with_tasks_and_revisions() {
        let (tasks, prompt, completion) = estimate_project_tokens("a simple tool", Some(10));
        assert_eq!(tasks, 10);
        assert_eq!(prompt, (10.0 * 3000.0 * 1.5) as u64);
        assert_eq!(completion, (10.0 * 2500.0 * 1.5) as u64);
    }

    #[test]
    fn project_cost_uses_both_prices() {
        let rates = Rates::defaults();
        // deepseek: $0.27/M prompt, $1.10/M completion.
        let cost = project_cost(&rates, "deepseek", 45000, 37500);
        // (45000*0.27 + 37500*1.10) / 1e6 = (12150 + 41250) / 1e6.
        assert!((cost - 0.0534).abs() < 1e-9);
    }

    #[test]
    fn quality_is_a_static_capability_hint() {
        assert!(quality_for("o3-mini") > quality_for("claude-sonnet-4-5"));
        assert!(quality_for("claude") > quality_for("deepseek"));
        assert!(quality_for("gpt-4o") > quality_for("gpt-4o-mini"));
        assert_eq!(quality_label(0.95), "frontier");
        assert_eq!(quality_label(0.85), "strong");
        assert_eq!(quality_label(0.78), "capable");
        assert_eq!(quality_label(0.65), "basic");
    }

    #[test]
    fn quality_can_be_overridden_in_rates_toml() {
        let dir = tempfile::tempdir().unwrap();
        let route = route(dir.path());
        std::fs::create_dir_all(&route.communications).unwrap();
        std::fs::write(
            route.communications.join("rates.toml"),
            "[[engine]]\nname = \"mystery\"\nprompt_per_million = 7.5\ncompletion_per_million = 22.0\nquality = 0.99\n",
        )
        .unwrap();
        let rates = Rates::load(&route);
        assert_eq!(rates.quality_for("mystery-engine"), 0.99);
        // Not overridden -> built-in table.
        assert_eq!(rates.quality_for("claude"), 0.90);
    }

    #[test]
    fn effective_quality_prefers_measured_outcomes() {
        let dir = tempfile::tempdir().unwrap();
        let route = route(dir.path());
        let rates = Rates::defaults();
        // No learnings -> capability only, flagged as not measured.
        let (score, measured, _, _) = effective_quality(&route, &rates, "claude");
        assert!(!measured);
        assert_eq!(score, 0.90);
        // Record three accepted deepseek outcomes -> measured confidence wins.
        for _ in 0..3 {
            let mut l = learning("deepseek", true);
            l.source = "live".into();
            crate::learning::record_learning(&route, &l).unwrap();
        }
        let (score, measured, total, accepted) = effective_quality(&route, &rates, "deepseek");
        assert!(measured);
        assert_eq!(total, 3);
        assert_eq!(accepted, 3);
        assert!((score - 4.0 / 5.0).abs() < 1e-9); // (3+1)/(3+2)
    }

    #[test]
    fn measured_quality_matches_agent_names_too() {
        let dir = tempfile::tempdir().unwrap();
        let route = route(dir.path());
        let rates = Rates::defaults();
        // An agent named for the engine counts toward that engine's family even
        // when the recorded command is something else (e.g. the CLI shim).
        let mut l = learning("cline", true);
        l.source = "live".into();
        l.agent = Some("fang-deepseek".into());
        crate::learning::record_learning(&route, &l).unwrap();
        let (score, measured, total, accepted) = effective_quality(&route, &rates, "deepseek");
        assert!(measured);
        assert_eq!(total, 1);
        assert_eq!(accepted, 1);
        assert!((score - 2.0 / 3.0).abs() < 1e-9); // (1+1)/(1+2)
    }

    #[test]
    fn measured_quality_matches_the_declared_model() {
        let dir = tempfile::tempdir().unwrap();
        let route = route(dir.path());
        let rates = Rates::defaults();
        // A stable agent nickname with a declared model: the model field is what
        // credits the engine family, not the nickname.
        let mut l = learning("cline", true);
        l.source = "live".into();
        l.agent = Some("fang".into());
        l.model = Some("deepseek-v4-pro".into());
        crate::learning::record_learning(&route, &l).unwrap();
        let (_, measured, total, accepted) = effective_quality(&route, &rates, "deepseek");
        assert!(measured);
        assert_eq!(total, 1);
        assert_eq!(accepted, 1);
    }

    #[test]
    fn rates_toml_overrides_the_built_in_table() {
        let dir = tempfile::tempdir().unwrap();
        let route = route(dir.path());
        std::fs::create_dir_all(&route.communications).unwrap();
        std::fs::write(
            route.communications.join("rates.toml"),
            "[[engine]]\nname = \"mystery\"\nprompt_per_million = 7.5\ncompletion_per_million = 22.0\n",
        )
        .unwrap();
        let rates = Rates::load(&route);
        let price = rates.price_for("mystery-engine");
        assert_eq!(price.prompt_per_million, 7.5);
        assert_eq!(price.completion_per_million, 22.0);
        // Unmatched names still hit the built-in defaults.
        let default = rates.price_for("some-other");
        assert_eq!(default.prompt_per_million, 3.0);
        assert_eq!(default.completion_per_million, 15.0);
    }
}
