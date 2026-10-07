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
    RestartWorkers,
    AlertOnly,
}

impl Action {
    pub const ALL: [Action; 5] = [
        Action::Nothing,
        Action::StartSyncthing,
        Action::RepairChannels,
        Action::RestartWorkers,
        Action::AlertOnly,
    ];

    #[must_use]
    pub fn key(self) -> &'static str {
        match self {
            Action::Nothing => "nothing",
            Action::StartSyncthing => "start_syncthing",
            Action::RepairChannels => "repair_channels",
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

    #[must_use]
    pub fn bad_engines(&self) -> Vec<&EngineFact> {
        self.engines
            .iter()
            .filter(|e| !e.state.starts_with("ok"))
            .collect()
    }

    /// Whether the facts call for `action`. The guard every decision passes through.
    #[must_use]
    pub fn supports(&self, action: Action) -> bool {
        match action {
            Action::Nothing => self.healthy(),
            Action::StartSyncthing => self.syncthing_down,
            Action::RepairChannels => self.split_channels() > 0,
            Action::RestartWorkers => !self.failed_services().is_empty(),
            Action::AlertOnly => !self.healthy(),
        }
    }

    #[must_use]
    pub fn healthy(&self) -> bool {
        !self.syncthing_down
            && self.split_channels() == 0
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
        } else if !self.failed_services().is_empty() {
            Action::RestartWorkers
        } else if !self.bad_engines().is_empty() {
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
        for spec in &config.engines {
            let (Some(base), Some(model)) = (&spec.base_url, &spec.model) else {
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
            let state = match (&probe.down, &probe.exhausted, probe.latency_ms) {
                (Some(why), _, _) => why.clone(),
                (None, Some(why), _) => format!("out of quota: {why}"),
                (None, None, Some(ms)) => format!("ok ({ms}ms)"),
                (None, None, None) => "no answer".to_string(),
            };
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
    fn every_action_round_trips_its_key() {
        for a in Action::ALL {
            assert_eq!(Action::from_key(a.key()), Some(a));
        }
        assert_eq!(Action::from_key("rm -rf"), None);
    }
}
