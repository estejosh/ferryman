//! A durable, synced record of what worked.
//!
//! The ledger proves *what happened*; this proves *what worked*. Every time a
//! result is accepted (or sent back) - and every time the benchmark runs - one
//! structured line is appended recording the engine that produced the work and
//! the outcome. Because the file lives in the synced channel, the whole team
//! learns from every machine's results, not just its own.
//!
//! It is deliberately simpler than the ledger: no signature and no hash chain,
//! because it is derived data rather than a trust boundary. A corrupt line is
//! skipped on read instead of failing the read.

use std::{
    collections::BTreeMap,
    fs::{self, OpenOptions},
    io::Write,
    path::PathBuf,
};

use anyhow::Result;
use chrono::{DateTime, Utc};
use serde::{Deserialize, Serialize};

use crate::ProjectRoute;

/// One recorded outcome: an engine produced work for a task, and it was
/// accepted or not.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct Learning {
    pub at: DateTime<Utc>,
    /// The engine that produced the work (the agent CLI command).
    pub engine: String,
    /// The order/task it was for.
    pub task_id: String,
    /// `eval` for benchmark runs, `live` for real accepted/rejected work.
    pub source: String,
    pub accepted: bool,
    /// Reviewer notes, or the missing keys / score for an eval.
    pub note: String,
}

/// Per-engine totals, derived from the learnings.
#[derive(Debug, Clone, PartialEq)]
pub struct EngineStats {
    pub engine: String,
    pub total: usize,
    pub accepted: usize,
}

impl EngineStats {
    #[must_use]
    pub fn rate(&self) -> f64 {
        if self.total == 0 {
            0.0
        } else {
            self.accepted as f64 / self.total as f64
        }
    }

    /// Confidence in [0, 1] that this engine does good work: the observed
    /// acceptance rate pulled toward 0.5 by a two-sample prior, so a single
    /// accepted result is not mistaken for certainty and one rejected result is
    /// not mistaken for doom. The more samples, the more the rate is believed.
    #[must_use]
    pub fn confidence(&self) -> f64 {
        (self.accepted as f64 + 1.0) / (self.total as f64 + 2.0)
    }

    /// A short natural-language verdict, e.g. "high confidence (14/15 accepted)".
    /// The count is included because confidence is only as meaningful as the
    /// number of samples behind it.
    #[must_use]
    pub fn describe(&self) -> String {
        if self.total == 0 {
            return "no data yet".to_string();
        }
        let band = match self.confidence() {
            c if c >= 0.85 => "high confidence",
            c if c >= 0.70 => "moderate confidence",
            c if c >= 0.55 => "low confidence",
            _ => "mostly rejected",
        };
        format!("{band} ({}/{} accepted)", self.accepted, self.total)
    }
}

fn learnings_path(route: &ProjectRoute) -> PathBuf {
    route.communications.join("learnings.jsonl")
}

/// Append one learning. Atomic append; best-effort git backstop like the ledger.
pub fn record_learning(route: &ProjectRoute, learning: &Learning) -> Result<()> {
    let path = learnings_path(route);
    if let Some(parent) = path.parent() {
        fs::create_dir_all(parent)?;
    }
    let line = serde_json::to_string(learning)?;
    let mut file = OpenOptions::new().create(true).append(true).open(&path)?;
    writeln!(file, "{line}")?;
    drop(file);
    let _ = crate::snapshot_channel_to_git(route);
    Ok(())
}

/// Read every learning, oldest first. Unparseable lines (a rare torn append)
/// are skipped rather than failing the whole read.
pub fn read_learnings(route: &ProjectRoute) -> Result<Vec<Learning>> {
    let path = learnings_path(route);
    if !path.is_file() {
        return Ok(Vec::new());
    }
    let mut out = Vec::new();
    for line in fs::read_to_string(&path)?.lines() {
        if line.trim().is_empty() {
            continue;
        }
        if let Ok(learning) = serde_json::from_str::<Learning>(line) {
            out.push(learning);
        }
    }
    Ok(out)
}

/// Aggregate learnings into per-engine totals, most-tested first.
pub fn engine_stats(route: &ProjectRoute) -> Result<Vec<EngineStats>> {
    let mut totals: BTreeMap<String, EngineStats> = BTreeMap::new();
    for learning in read_learnings(route)? {
        let stats = totals
            .entry(learning.engine.clone())
            .or_insert_with(|| EngineStats {
                engine: learning.engine.clone(),
                total: 0,
                accepted: 0,
            });
        stats.total += 1;
        if learning.accepted {
            stats.accepted += 1;
        }
    }
    let mut stats: Vec<EngineStats> = totals.into_values().collect();
    stats.sort_by(|a, b| b.total.cmp(&a.total).then_with(|| a.engine.cmp(&b.engine)));
    Ok(stats)
}

/// Record the outcome of a real review, so the fleet learns from live work.
///
/// Finds the result the review judged and the engine that produced it, then
/// appends a `live` learning. Safe to call again (a re-review adds a line).
pub fn record_outcome(
    route: &ProjectRoute,
    order_id: &str,
    revision: u32,
    accepted: bool,
    notes: &str,
) -> Result<()> {
    let Ok(task) = crate::read_task(route, order_id) else {
        return Ok(());
    };
    let Some(result) = task.results.iter().find(|r| r.revision == revision) else {
        return Ok(());
    };
    let engine = result
        .payload
        .get("produced_by")
        .and_then(|v| v.as_str())
        .filter(|s| !s.is_empty())
        .unwrap_or(&result.agent)
        .to_string();
    record_learning(
        route,
        &Learning {
            at: Utc::now(),
            engine,
            task_id: order_id.to_string(),
            source: "live".to_string(),
            accepted,
            note: notes.trim().to_string(),
        },
    )
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

    fn learning(engine: &str, accepted: bool) -> Learning {
        Learning {
            at: Utc::now(),
            engine: engine.into(),
            task_id: "t-1".into(),
            source: "eval".into(),
            accepted,
            note: String::new(),
        }
    }

    #[test]
    fn stats_aggregate_per_engine_acceptance() {
        let dir = tempfile::tempdir().unwrap();
        let route = route(dir.path());
        record_learning(&route, &learning("claude", true)).unwrap();
        record_learning(&route, &learning("claude", false)).unwrap();
        record_learning(&route, &learning("deepseek", true)).unwrap();
        let stats = engine_stats(&route).unwrap();
        assert_eq!(stats.len(), 2);
        assert_eq!(stats[0].engine, "claude");
        assert_eq!(stats[0].total, 2);
        assert_eq!(stats[0].accepted, 1);
        assert!((stats[0].rate() - 0.5).abs() < f64::EPSILON);
        assert_eq!(stats[1].engine, "deepseek");
        assert_eq!(stats[1].rate(), 1.0);
    }

    #[test]
    fn a_torn_line_is_skipped_not_fatal() {
        let dir = tempfile::tempdir().unwrap();
        let route = route(dir.path());
        std::fs::create_dir_all(&route.communications).unwrap();
        std::fs::write(route.communications.join("learnings.jsonl"), "{not json}\n").unwrap();
        record_learning(&route, &learning("claude", true)).unwrap();
        assert_eq!(read_learnings(&route).unwrap().len(), 1);
    }

    #[test]
    fn confidence_is_rate_pulled_toward_a_prior() {
        // No data: the honest answer is 50/50, not "perfect" or "useless".
        assert!(
            (EngineStats {
                engine: "x".into(),
                total: 0,
                accepted: 0,
            }
            .confidence()
                - 0.5)
                .abs()
                < f64::EPSILON
        );
        // One accepted sample is promising but not certain.
        let one = EngineStats {
            engine: "x".into(),
            total: 1,
            accepted: 1,
        };
        assert!((one.confidence() - 2.0 / 3.0).abs() < f64::EPSILON);
        // Lots of accepted work converges toward certainty.
        let many = EngineStats {
            engine: "x".into(),
            total: 15,
            accepted: 14,
        };
        assert!((many.confidence() - 15.0 / 17.0).abs() < f64::EPSILON);
        assert!(many.confidence() > 0.85);
    }

    #[test]
    fn describe_is_natural_language_with_the_counts() {
        let none = EngineStats {
            engine: "x".into(),
            total: 0,
            accepted: 0,
        };
        assert_eq!(none.describe(), "no data yet");
        let good = EngineStats {
            engine: "x".into(),
            total: 15,
            accepted: 14,
        };
        assert_eq!(good.describe(), "high confidence (14/15 accepted)");
        let bad = EngineStats {
            engine: "x".into(),
            total: 6,
            accepted: 1,
        };
        assert_eq!(bad.describe(), "mostly rejected (1/6 accepted)");
    }
}
