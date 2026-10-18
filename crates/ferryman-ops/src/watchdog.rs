//! `ferry watchdog`: notice when this machine stops doing its job, fix the few things
//! that are safe to fix, and say what it saw where every machine can read it.
//!
//! Every failure that cost days on a two-machine fleet was one nothing reported: a
//! channel Syncthing did not sync, a Syncthing that had quietly stopped, an engine key
//! that never reached the worker, a model the probe called "up" that never answered. So
//! this is built as plain code that gathers facts first. A local decision model (Ollama's
//! `/v1/systemone`, e.g. `nimble`) only picks from a fixed list of actions, and every
//! action is checked against the facts before it runs - a model cannot ask for a fix the
//! facts do not call for. Without a model it decides by the same rules. A larger local
//! model may write the one-paragraph explanation; that is optional too.
//!
//! The report goes to `<fleet>/watchdog/<machine>.json`, which Syncthing carries to
//! every machine, and each run prints it.

use std::{
    path::{Path, PathBuf},
    process::Command,
    time::Duration,
};

use anyhow::{Context, Result};
use chrono::{DateTime, Utc};
use serde::{Deserialize, Serialize};
use serde_json::{Value, json};

/// The fixed set of things the watchdog may do. Nothing else is reachable.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum Action {
    Nothing,
    StartSyncthing,
    RepairChannels,
    /// Run `repos sync` and rename aside locks that name dead processes. Never signs.
    RepairLayout,
    RestartWorkers,
    AlertOnly,
}

impl Action {
    pub const ALL: [Action; 6] = [
        Action::Nothing,
        Action::StartSyncthing,
        Action::RepairChannels,
        Action::RepairLayout,
        Action::RestartWorkers,
        Action::AlertOnly,
    ];

    #[must_use]
    pub fn key(self) -> &'static str {
        match self {
            Action::Nothing => "nothing",
            Action::StartSyncthing => "start_syncthing",
            Action::RepairChannels => "repair_channels",
            Action::RepairLayout => "repair_layout",
            Action::RestartWorkers => "restart_workers",
            Action::AlertOnly => "alert_only",
        }
    }

    fn describe(self) -> &'static str {
        match self {
            Action::Nothing => "everything this machine needs is healthy; no action",
            Action::StartSyncthing => {
                "this machine's Syncthing is not running, so nothing reaches or leaves it"
            }
            Action::RepairChannels => {
                "a channel is NOT SYNCED: the worker reads a different folder from the one \
                 Syncthing syncs"
            }
            Action::RepairLayout => {
                "the fixed layout is incomplete: a live project has no repos/<project> clone, a folder is missing, or a worker lock names a dead process"
            }
            Action::RestartWorkers => "a Ferryman worker service has failed or stopped",
            Action::AlertOnly => {
                "something is wrong that none of the actions fix, such as an engine that \
                 refuses requests or never answers, or a missing key"
            }
        }
    }

    fn from_key(key: &str) -> Option<Self> {
        Self::ALL.into_iter().find(|a| a.key() == key)
    }
}

/// One channel and whether this machine actually syncs what its worker reads.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct ChannelFact {
    pub project: String,
    /// `synced`, `NOT SYNCED (reads A, syncs B)`, or `unknown`.
    pub state: String,
    #[serde(skip)]
    pub split: Option<(PathBuf, PathBuf, PathBuf)>,
}

/// One engine and what a one-token request to it actually did.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct EngineFact {
    pub engine: String,
    pub model: String,
    /// `ok (850ms)`, or why not.
    pub state: String,
}

/// Everything the watchdog decides from. Gathered by code, never by a model.
#[derive(Debug, Clone, Default, Serialize, Deserialize)]
pub struct Facts {
    pub machine: String,
    pub ferry_version: String,
    pub syncthing: String,
    pub syncthing_down: bool,
    pub channels: Vec<ChannelFact>,
    pub services: Vec<(String, String)>,
    pub engines: Vec<EngineFact>,
    /// The ferry root, when this machine has one.
    #[serde(default)]
    pub root: Option<PathBuf>,
    /// Live projects with no attached `repos/<project>`, with why.
    #[serde(default)]
    pub unsynced: Vec<String>,
    /// Worker locks naming a process that is proven dead.
    #[serde(default)]
    pub dead_locks: usize,
    /// A fixed folder (comms, repos, work) is missing.
    #[serde(default)]
    pub missing_folders: bool,
    /// Layout problems no automatic action fixes (the worker count, the service).
    #[serde(default)]
    pub layout_notes: Vec<String>,
}

impl Facts {
    #[must_use]
    pub fn split_channels(&self) -> usize {
        self.channels.iter().filter(|c| c.split.is_some()).count()
    }

    #[must_use]
    pub fn failed_services(&self) -> Vec<&str> {
        self.services
            .iter()
            .filter(|(_, state)| state != "active")
            .map(|(unit, _)| unit.as_str())
            .collect()
    }

    /// Whether `repos sync` or a lock archive would change anything.
    #[must_use]
    pub fn layout_repairable(&self) -> bool {
        !self.unsynced.is_empty() || self.dead_locks > 0 || self.missing_folders
    }

    #[must_use]
    pub fn bad_engines(&self) -> Vec<&EngineFact> {
        self.engines
            .iter()
            .filter(|e| !e.state.starts_with("ok") && !e.state.starts_with("unprobed"))
            .collect()
    }

    /// Whether the facts call for `action`. The guard every decision passes through.
    #[must_use]
    pub fn supports(&self, action: Action) -> bool {
        match action {
            Action::Nothing => self.healthy(),
            Action::StartSyncthing => self.syncthing_down,
            Action::RepairChannels => self.split_channels() > 0,
            Action::RepairLayout => self.layout_repairable(),
            Action::RestartWorkers => !self.failed_services().is_empty(),
            Action::AlertOnly => !self.healthy(),
        }
    }

    #[must_use]
    pub fn healthy(&self) -> bool {
        !self.syncthing_down
            && self.split_channels() == 0
            && !self.layout_repairable()
            && self.layout_notes.is_empty()
            && self.failed_services().is_empty()
            && self.bad_engines().is_empty()
    }

    /// The rules, in order of what unblocks most. Used when no model is available, and
    /// as the answer whenever the model's pick is not supported by the facts.
    #[must_use]
    pub fn rule(&self) -> Action {
        if self.syncthing_down {
            Action::StartSyncthing
        } else if self.split_channels() > 0 {
            Action::RepairChannels
        } else if self.layout_repairable() {
            Action::RepairLayout
        } else if !self.failed_services().is_empty() {
            Action::RestartWorkers
        } else if !self.bad_engines().is_empty() || !self.layout_notes.is_empty() {
            Action::AlertOnly
        } else {
            Action::Nothing
        }
    }

    /// The facts as the short text a decision model reads.
    #[must_use]
    pub fn as_text(&self) -> String {
        let mut out = format!(
            "machine {} running ferry {}\nsyncthing: {}\n",
            self.machine, self.ferry_version, self.syncthing
        );
        let split: Vec<_> = self.channels.iter().filter(|c| c.split.is_some()).collect();
        out.push_str(&format!(
            "channels: {} checked, {} NOT SYNCED\n",
            self.channels.len(),
            split.len()
        ));
        for c in split {
            out.push_str(&format!("  {}: {}\n", c.project, c.state));
        }
        for line in &self.unsynced {
            out.push_str(&format!("layout: no clone for {line}\n"));
        }
        if self.dead_locks > 0 {
            out.push_str(&format!(
                "layout: {} worker lock(s) name a dead process\n",
                self.dead_locks
            ));
        }
        for line in &self.layout_notes {
            out.push_str(&format!("layout: {line}\n"));
        }
        for (unit, state) in &self.services {
            out.push_str(&format!("service {unit}: {state}\n"));
        }
        for e in &self.engines {
            out.push_str(&format!("engine {} ({}): {}\n", e.engine, e.model, e.state));
        }
        out
    }
}

/// Every workspace with a channel: those under `comms`, plus every project repo the
/// ferry root knows (machines that keep `.ferryman` in each repo, not under comms).
fn workspaces(comms: &Path) -> Vec<PathBuf> {
    let mut found: Vec<PathBuf> = std::fs::read_dir(comms)
        .into_iter()
        .flatten()
        .flatten()
        .map(|e| e.path())
        .chain(
            ferryman_channel::ferry::find_root_from(comms)
                .or_else(ferryman_channel::ferry::find_root)
                .map(|root| root.projects())
                .unwrap_or_default()
                .into_iter()
                .filter_map(|entry| entry.repo),
        )
        .filter(|p| p.join(".ferryman").join("bridge.toml").is_file())
        .collect();
    found.sort();
    found.dedup();
    found
}

fn services() -> Vec<(String, String)> {
    if !cfg!(target_os = "linux") {
        return Vec::new();
    }
    let Ok(out) = Command::new("systemctl")
        .args([
            "--user",
            "list-units",
            "ferryman*",
            "--all",
            "--no-legend",
            "--plain",
        ])
        .output()
    else {
        return Vec::new();
    };
    String::from_utf8_lossy(&out.stdout)
        .lines()
        .filter_map(|line| {
            let mut parts = line.split_whitespace();
            let unit = parts.next()?;
            let _load = parts.next()?;
            let active = parts.next()?;
            unit.ends_with(".service").then(|| {
                (
                    unit.trim_end_matches(".service").to_string(),
                    active.to_string(),
                )
            })
        })
        .collect()
}

/// The layout facts: whether every live project has its clone, the folders are there, and
/// what else the layout check would say. Read only.
fn gather_layout(comms: &Path, facts: &mut Facts) {
    let Some(root) =
        ferryman_channel::ferry::find_root_from(comms).or_else(ferryman_channel::ferry::find_root)
    else {
        return;
    };
    let report = crate::layout::inspect_live(&root, &crate::machine::scan());
    facts.unsynced = crate::repos::unsynced(&root)
        .into_iter()
        .map(|(project, why)| format!("{project} ({why})"))
        .collect();
    facts.dead_locks = report
        .stale
        .iter()
        .filter(|lock| lock.proven_dead())
        .count();
    facts.missing_folders = report.checks.iter().any(|c| c.name == "folders" && !c.ok);
    facts.layout_notes = report
        .checks
        .iter()
        .filter(|c| !c.ok && !matches!(c.name, "folders" | "repos" | "locks"))
        .map(|c| format!("{}: {}", c.name, c.detail))
        .collect();
    facts.root = Some(root.path);
}

/// What the watchdog says about one engine: the same honest reading `ferry engines`
/// gives, and the runs that failed on it.
///
/// `ok (850ms)` only when something returned a real completion - the one-token request
/// for an endpoint, the worker's own tiny-prompt run for a CLI that wraps one. An
/// endpoint that merely answered is "reachable only", an engine that cannot be tried
/// cheaply is "unprobed", and an engine that proved itself but has failed real runs
/// since is "says up, but recent runs failed" - a fact in its own right, because that is
/// the shape the hung model had.
#[must_use]
pub(crate) fn engine_state_text(
    spec: &crate::engines::EngineSpec,
    probe: &crate::engines::Probe,
    state: &crate::engines::EngineState,
    failing: Option<&str>,
) -> String {
    use crate::engines::Proof;
    // A CLI in front of an endpoint is proved by running the CLI, which the worker does
    // and records; the endpoint answering says nothing about it.
    let proof = if spec.kind == crate::engines::Kind::Cli && spec.base_url.is_some() {
        crate::engines::proof_of(spec, state)
    } else {
        probe.proof
    };
    let headline = match (&probe.down, &probe.exhausted) {
        (Some(why), _) => return failing.map_or_else(|| why.clone(), |f| format!("{why}; {f}")),
        (None, Some(why)) => return format!("out of quota: {why}"),
        (None, None) => match proof {
            Proof::Answered => format!(
                "ok ({}ms)",
                probe.latency_ms.or(state.latency_ms).unwrap_or_default()
            ),
            Proof::Reachable => "reachable only: no completion has been seen from it".to_string(),
            Proof::Unprobed => "unprobed".to_string(),
        },
    };
    match failing {
        Some(failed) if proof == Proof::Answered => {
            format!("says up, but recent runs failed: {failed}")
        }
        Some(failed) => format!("{headline}; recent runs failed: {failed}"),
        None => headline,
    }
}

/// Gather the facts. Engines are probed with a real one-token request each, once per
/// distinct endpoint and model, whatever their configured probe.
pub async fn gather(comms: &Path) -> Facts {
    let mut facts = Facts {
        machine: crate::identity::machine_name().unwrap_or_else(|_| "this machine".into()),
        ferry_version: env!("CARGO_PKG_VERSION").to_string(),
        services: services(),
        ..Facts::default()
    };
    match ferryman_channel::syncthing_health() {
        Ok(health) => {
            let up = health.peers.iter().filter(|p| p.connected).count();
            facts.syncthing = format!(
                "running, {up} of {} device(s) connected",
                health.peers.len()
            );
        }
        Err(error) => {
            facts.syncthing = format!("NOT RUNNING: {error:#}");
            facts.syncthing_down = true;
        }
    }
    gather_layout(comms, &mut facts);
    let mut seen: Vec<(String, String)> = Vec::new();
    for ws in workspaces(comms) {
        let attachment = ws.join(".ferryman");
        let Ok(route) = ferryman_channel::load_route(&attachment) else {
            continue;
        };
        let (state, split) = match crate::syncthing::channel_sync(&route) {
            crate::syncthing::ChannelSync::Synced => ("synced".to_string(), None),
            crate::syncthing::ChannelSync::Unknown => ("unknown".to_string(), None),
            crate::syncthing::ChannelSync::Split { syncs } => (
                format!(
                    "NOT SYNCED (reads {}, syncs {})",
                    route.communications.display(),
                    syncs.display()
                ),
                Some((
                    route.attachment.clone(),
                    route.communications.clone(),
                    syncs,
                )),
            ),
        };
        facts.channels.push(ChannelFact {
            project: route.project_id.clone(),
            state,
            split,
        });
        let Ok(config) = crate::agent::AgentConfig::load(&attachment) else {
            continue;
        };
        let ledger = crate::engines::Ledger::load(&config.agent);
        let now = chrono::Utc::now();
        for spec in &config.engines {
            // What the worker has seen of this engine's real runs, which a probe cannot
            // say: an engine can answer a one-token request all day and still hang on work.
            let failing = crate::engines::recent_failures(&ledger.state(&spec.name), now);
            let (Some(base), Some(model)) = (&spec.base_url, &spec.model) else {
                if let Some(failed) = failing {
                    facts.engines.push(EngineFact {
                        engine: spec.name.clone(),
                        model: spec.model.clone().unwrap_or_default(),
                        state: format!("recent runs failed: {failed}"),
                    });
                }
                continue;
            };
            let id = (base.clone(), model.clone());
            if seen.contains(&id) {
                continue;
            }
            seen.push(id);
            let key = crate::engines::engine_key(&route, &config.agent, spec)
                .ok()
                .flatten();
            let mut chat = spec.clone();
            chat.probe_chat = true;
            let probe = crate::engines::probe(&chat, key.as_deref()).await;
            let state =
                engine_state_text(spec, &probe, &ledger.state(&spec.name), failing.as_deref());
            facts.engines.push(EngineFact {
                engine: spec.name.clone(),
                model: model.clone(),
                state,
            });
        }
    }
    facts
}

/// What decided, and how sure it was.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Decision {
    pub action: Action,
    /// `rules`, or the model that chose.
    pub by: String,
    pub confidence: Option<f64>,
    /// Set when the model's pick was not supported by the facts and the rules overrode it.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub overruled: Option<String>,
}

/// Ask the decision model, then hold its pick against the facts.
pub async fn decide(facts: &Facts, ollama: &str, model: Option<&str>) -> Decision {
    let rules = Decision {
        action: facts.rule(),
        by: "rules".into(),
        confidence: None,
        overruled: None,
    };
    let Some(model) = model else {
        return rules;
    };
    let criteria: serde_json::Map<String, Value> = Action::ALL
        .iter()
        .map(|a| (a.key().to_string(), Value::String(a.describe().into())))
        .collect();
    let body = json!({
        "model": model,
        "state": facts.as_text(),
        "questions": {
            "action": {
                "type": "choice",
                "instructions": "You watch one machine in a fleet of AI workers. From these \
                    facts, which single action helps most right now?",
                "criteria": criteria,
            }
        }
    });
    let Ok(http) = reqwest::Client::builder()
        .timeout(Duration::from_secs(120))
        .build()
    else {
        return rules;
    };
    let answer: Option<Value> = async {
        let response = http
            .post(format!("{}/v1/systemone", ollama.trim_end_matches('/')))
            .json(&body)
            .send()
            .await
            .ok()?;
        if !response.status().is_success() {
            return None;
        }
        response.json().await.ok()
    }
    .await;
    let Some(answer) = answer.as_ref().and_then(|a| a.pointer("/answers/action")) else {
        return Decision {
            overruled: Some(format!("{model} did not answer; decided by rules")),
            ..rules
        };
    };
    let picked = answer
        .get("choice")
        .and_then(Value::as_str)
        .and_then(Action::from_key);
    let confidence = answer.get("confidence").and_then(Value::as_f64);
    match picked {
        Some(action) if facts.supports(action) && confidence.unwrap_or(0.0) >= 0.6 => Decision {
            action,
            by: model.to_string(),
            confidence,
            overruled: None,
        },
        Some(action) => Decision {
            overruled: Some(format!(
                "{model} picked {} ({}), which the facts do not support",
                action.key(),
                confidence.map_or("no confidence".into(), |c| format!("{c:.2}"))
            )),
            ..rules
        },
        None => Decision {
            overruled: Some(format!("{model} gave no usable answer")),
            ..rules
        },
    }
}

/// Carry out the decision. Only ever one of the fixed actions.
pub fn act(facts: &Facts, action: Action) -> Vec<String> {
    let mut done = Vec::new();
    match action {
        Action::Nothing | Action::AlertOnly => {}
        Action::StartSyncthing => match crate::syncthing::start() {
            Ok(health) => done.push(format!("started Syncthing at {}", health.api_base)),
            Err(error) => done.push(format!("could not start Syncthing: {error:#}")),
        },
        Action::RepairChannels => {
            for c in &facts.channels {
                let Some((attachment, reads, syncs)) = &c.split else {
                    continue;
                };
                match crate::syncthing::repoint_channel(attachment, reads, syncs) {
                    Ok(r) => done.push(format!(
                        "repaired {}: now reads {} (copied {} file(s))",
                        c.project,
                        r.to.display(),
                        r.copied
                    )),
                    Err(error) => done.push(format!("could not repair {}: {error:#}", c.project)),
                }
            }
        }
        Action::RepairLayout => done.extend(repair_layout(facts)),
        Action::RestartWorkers => {
            for unit in facts.failed_services() {
                let ok = Command::new("systemctl")
                    .args(["--user", "restart", unit])
                    .status()
                    .is_ok_and(|s| s.success());
                done.push(format!(
                    "{} {unit}",
                    if ok { "restarted" } else { "could not restart" }
                ));
            }
        }
    }
    done
}

/// Put the layout back: make the three folders, run `repos sync` (clone, fetch and attach
/// every live project; no roster, key, device or Syncthing folder is touched) and rename
/// aside locks whose process is proven dead. Nothing is signed or deleted.
fn repair_layout(facts: &Facts) -> Vec<String> {
    let mut done = Vec::new();
    let Some(root) = facts
        .root
        .as_deref()
        .and_then(ferryman_channel::ferry::find_root_from)
    else {
        return vec!["no ferry root to repair a layout in".into()];
    };
    for (_, folder) in root.top_folders() {
        if !folder.is_dir() && std::fs::create_dir_all(&folder).is_ok() {
            done.push(format!("made {}", folder.display()));
        }
    }
    done.extend(crate::layout::make_project_folders(&root));
    match crate::repos::sync(&root, &crate::repos::Options::default()) {
        Ok(rows) => {
            for row in rows {
                match &row.status {
                    crate::repos::Status::Done(_) => {
                        done.push(format!("repos sync {}: {}", row.project, row.word()));
                    }
                    crate::repos::Status::Skipped(crate::repos::Skip::Failed(why)) => {
                        done.push(format!("repos sync {} failed: {why}", row.project));
                    }
                    _ => {}
                }
            }
        }
        Err(error) => done.push(format!("repos sync failed: {error:#}")),
    }
    for line in crate::layout::archive_stale(&crate::layout::stale_locks(&root)) {
        done.push(format!("archived a stale lock: {line}"));
    }
    done
}

/// A short plain-English account from a larger local model, when one is configured and
/// something is wrong. Best effort: no answer means no explanation, never a failure.
pub async fn explain(
    facts: &Facts,
    decision: &Decision,
    done: &[String],
    ollama: &str,
    model: &str,
) -> Option<String> {
    let prompt = format!(
        "You are the watchdog for one machine in a fleet of AI workers. In three short \
         sentences for the owner, who is not technical: what is wrong, what was done, and \
         what (if anything) they should do. Do not invent facts.\n\nFacts:\n{}\nDecision: \
         {} (by {})\nDone: {}\n",
        facts.as_text(),
        decision.action.key(),
        decision.by,
        if done.is_empty() {
            "nothing".to_string()
        } else {
            done.join("; ")
        }
    );
    let http = reqwest::Client::builder()
        .timeout(Duration::from_secs(240))
        .build()
        .ok()?;
    let response: Value = http
        .post(format!("{}/api/generate", ollama.trim_end_matches('/')))
        .json(&json!({
            "model": model, "prompt": prompt, "stream": false, "think": false,
            "options": {"num_ctx": 4096}
        }))
        .send()
        .await
        .ok()?
        .json()
        .await
        .ok()?;
    response
        .get("response")
        .and_then(Value::as_str)
        .map(|s| s.trim().to_string())
        .filter(|s| !s.is_empty())
}

/// What one run saw and did, as every machine reads it.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Report {
    pub at: DateTime<Utc>,
    pub machine: String,
    pub healthy: bool,
    pub facts: String,
    pub decision: Decision,
    pub done: Vec<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub explanation: Option<String>,
}

/// Where reports go: the fleet folder, which Syncthing carries to every machine.
pub fn report_dir() -> Result<PathBuf> {
    ferryman_channel::licensing::fleet_dir()
        .map(|d| d.join("watchdog"))
        .context("no fleet folder on this machine")
}

/// Write this machine's report beside the others.
pub fn publish(report: &Report) -> Result<PathBuf> {
    let dir = report_dir()?;
    std::fs::create_dir_all(&dir)?;
    let path = dir.join(format!("{}.json", report.machine));
    std::fs::write(&path, serde_json::to_vec_pretty(report)?)?;
    Ok(path)
}

/// Every machine's latest report.
pub fn reports() -> Vec<Report> {
    let Ok(dir) = report_dir() else {
        return Vec::new();
    };
    let mut out: Vec<Report> = std::fs::read_dir(dir)
        .into_iter()
        .flatten()
        .flatten()
        .filter(|e| e.path().extension().is_some_and(|x| x == "json"))
        .filter_map(|e| serde_json::from_slice(&std::fs::read(e.path()).ok()?).ok())
        .collect();
    out.sort_by(|a, b| a.machine.cmp(&b.machine));
    out
}

#[cfg(test)]
mod tests {
    use super::*;

    fn healthy() -> Facts {
        Facts {
            machine: "grouchly".into(),
            ferry_version: "0.5.25".into(),
            syncthing: "running, 2 of 2 device(s) connected".into(),
            services: vec![("ferryman-fleet".into(), "active".into())],
            engines: vec![EngineFact {
                engine: "deepseek".into(),
                model: "m".into(),
                state: "ok (900ms)".into(),
            }],
            ..Facts::default()
        }
    }

    #[test]
    fn a_healthy_machine_needs_nothing() {
        let f = healthy();
        assert!(f.healthy());
        assert_eq!(f.rule(), Action::Nothing);
        assert!(f.supports(Action::Nothing));
        assert!(!f.supports(Action::StartSyncthing));
        assert!(!f.supports(Action::RestartWorkers));
    }

    #[test]
    fn an_engine_that_says_up_while_its_recent_runs_failed_is_a_fact_of_its_own() {
        use crate::engines::{EngineSpec, EngineState, Kind, Paid, Probe, Proof, Tier};
        let spec = EngineSpec {
            name: "deepseek".into(),
            kind: Kind::Http,
            tier: Tier::Build,
            paid: Paid::Prepaid,
            command: String::new(),
            args: Vec::new(),
            model: Some("m".into()),
            base_url: Some("fake://ok:fine".into()),
            key: None,
            env: Vec::new(),
            probe_chat: true,
            weekly_requests: None,
            weekly_usd: None,
            provider: None,
            route: Vec::new(),
            class: None,
            effort_args: std::collections::BTreeMap::new(),
            supports_effort: false,
            declared: ferryman_channel::capability::Declared::default(),
        };
        let answered = Probe {
            latency_ms: Some(300),
            proof: Proof::Answered,
            ..Probe::default()
        };
        let state = EngineState::default();
        let say =
            |probe: &Probe, failing: Option<&str>| engine_state_text(&spec, probe, &state, failing);

        assert_eq!(say(&answered, None), "ok (300ms)");
        let lying = say(&answered, Some("2 run(s) failed in a row: timed out"));
        assert!(
            lying.starts_with("says up, but recent runs failed"),
            "{lying}"
        );
        let reachable = Probe {
            proof: Proof::Reachable,
            ..Probe::default()
        };
        assert!(say(&reachable, None).starts_with("reachable only"));
        let unprobed = Probe {
            proof: Proof::Unprobed,
            ..Probe::default()
        };
        assert_eq!(say(&unprobed, None), "unprobed");

        // Each of those is read right: only a real completion is ok, and unprobed is not a
        // fault in itself, but the other two are.
        let facts = |state: String| Facts {
            engines: vec![EngineFact {
                engine: "deepseek".into(),
                model: "m".into(),
                state,
            }],
            ..Facts::default()
        };
        assert!(facts(say(&answered, None)).healthy());
        assert!(facts(say(&unprobed, None)).healthy());
        assert!(!facts(say(&reachable, None)).healthy());
        assert!(!facts(lying).healthy());
    }

    #[test]
    fn the_rules_fix_what_unblocks_most_first() {
        let mut f = healthy();
        f.engines[0].state = "unreachable: timed out".into();
        assert_eq!(f.rule(), Action::AlertOnly);
        f.services[0].1 = "failed".into();
        assert_eq!(f.rule(), Action::RestartWorkers);
        f.channels.push(ChannelFact {
            project: "bullship".into(),
            state: "NOT SYNCED".into(),
            split: Some((PathBuf::from("a"), PathBuf::from("b"), PathBuf::from("c"))),
        });
        assert_eq!(f.rule(), Action::RepairChannels);
        f.syncthing_down = true;
        assert_eq!(f.rule(), Action::StartSyncthing);
    }

    #[test]
    fn a_model_cannot_ask_for_a_fix_the_facts_do_not_call_for() {
        let f = healthy();
        for action in [
            Action::StartSyncthing,
            Action::RepairChannels,
            Action::RestartWorkers,
        ] {
            assert!(
                !f.supports(action),
                "{action:?} must be refused on a healthy machine"
            );
        }
    }

    #[test]
    fn the_facts_read_as_short_text() {
        let mut f = healthy();
        f.engines[0].state = "the key was refused (HTTP 401)".into();
        let text = f.as_text();
        assert!(text.contains("machine grouchly"));
        assert!(text.contains("engine deepseek (m): the key was refused"));
        assert!(text.len() < 2000);
    }

    #[test]
    fn an_incomplete_layout_is_repaired_before_workers_are_restarted() {
        let mut f = healthy();
        f.services[0].1 = "failed".into();
        assert_eq!(f.rule(), Action::RestartWorkers);
        f.unsynced.push("quantly (not a clone)".into());
        assert!(!f.healthy());
        assert!(f.supports(Action::RepairLayout));
        assert_eq!(f.rule(), Action::RepairLayout);
        f.unsynced.clear();
        f.dead_locks = 1;
        assert_eq!(f.rule(), Action::RepairLayout);
        assert!(f.as_text().contains("name a dead process"));
    }

    #[test]
    fn a_healthy_layout_is_not_repaired_and_a_model_cannot_ask_for_it() {
        let f = healthy();
        assert!(!f.supports(Action::RepairLayout));
    }

    #[test]
    fn layout_problems_nothing_repairs_are_only_reported() {
        let mut f = healthy();
        f.layout_notes
            .push("one worker: 2 workers on this machine".into());
        assert!(!f.healthy());
        assert!(!f.supports(Action::RepairLayout));
        assert_eq!(f.rule(), Action::AlertOnly);
    }

    #[test]
    fn repairing_the_layout_makes_folders_and_renames_dead_locks_and_signs_nothing() {
        ferryman_channel::licensing::use_machine_state_dir_per_thread(
            std::env::temp_dir().join(format!("ferryman-watchdog-selftest-{}", std::process::id())),
        );
        let dir = tempfile::tempdir().unwrap();
        let root = ferryman_channel::ferry::Root::create_with_layout(&dir.path().join("ferry"), 1)
            .unwrap();
        let channel = root.comms_home("quantly");
        std::fs::create_dir_all(&channel).unwrap();
        let repo = dir.path().join("human").join("quantly");
        std::fs::create_dir_all(repo.join(".ferryman")).unwrap();
        root.adopt("quantly", &channel, Some(&repo)).unwrap();
        let lock = repo.join(".ferryman").join("worker-old.lock");
        std::fs::write(&lock, "999999999").unwrap();
        std::fs::remove_dir_all(root.work()).ok();
        let mut f = healthy();
        f.root = Some(root.path.clone());
        f.missing_folders = true;
        f.dead_locks = 1;

        let done = act(&f, Action::RepairLayout);

        assert!(root.work().is_dir(), "{done:?}");
        assert!(!lock.exists());
        assert!(
            repo.join(".ferryman/worker-old.lock.stale-999999999")
                .is_file(),
            "{done:?}"
        );
        // Nothing was signed: no flag file, no roster entry appeared in the channel.
        let entries: Vec<_> = std::fs::read_dir(&channel).unwrap().flatten().collect();
        assert!(entries.is_empty(), "{entries:?}");
    }

    #[test]
    fn every_action_round_trips_its_key() {
        for a in Action::ALL {
            assert_eq!(Action::from_key(a.key()), Some(a));
        }
        assert_eq!(Action::from_key("rm -rf"), None);
    }
}
