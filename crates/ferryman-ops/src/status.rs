//! Why is the worker not claiming? One read-only answer.
//!
//! `ferry doctor` proves the *setup* is sound; this proves what the *loop* is
//! doing right now. Between them they close the gap where a novice stares at an
//! idle machine and the only honest tool was reading a log file. The questions
//! this answers all had answers already - the governor computes its decision on
//! every poll, the worker lock and heartbeats are written while tasks run -
//! they were just never surfaced in one place.
//!
//! Read-only by the same rule as [`crate::doctor`]: nothing here claims,
//! releases, or writes anything, and it returns data for the caller to present.

use anyhow::{Context, Result};
use chrono::Utc;
use ferryman_channel::TaskState;
use serde::Serialize;
use std::path::Path;

use crate::agent::AgentConfig;
use crate::governor;

/// The task this agent currently holds, when it holds one.
#[derive(Debug, Clone, Serialize)]
pub struct CurrentTask {
    pub order_id: String,
    /// Seconds since this agent's last heartbeat for it. Fresh beats mean the
    /// engine is running; a lapsed beat is exactly what the channel reads as
    /// `Stale`, and this reports the same evidence rather than a new opinion.
    pub heartbeat_age_secs: Option<i64>,
}

/// Everything that decides whether work happens on this machine right now.
#[derive(Debug, Clone, Serialize)]
pub struct AgentStatus {
    pub project: String,
    pub agent: String,
    pub engine: String,
    pub engine_on_path: bool,
    /// Whether this machine's worker loop process is alive (its own lock, its
    /// own pid - never another machine's).
    pub worker_alive: bool,
    pub current_task: Option<CurrentTask>,
    /// Whether the loop would claim a new task if one were open this instant.
    pub ready_to_claim: bool,
    /// Why not, verbatim from the same decision the loop acts on, naming the
    /// setting that causes it. `None` when ready.
    pub claim_blocked_reason: Option<String>,
    /// The deliberate pause (`ferry pause`), if set. Also reflected inside
    /// `claim_blocked_reason`; kept separate because it outranks everything
    /// and survives a reboot.
    pub paused: Option<String>,
    /// The configured working hours, as written, when there are any.
    pub claim_window: Option<String>,
    pub poll_secs: u64,
    pub memory_available_mb: Option<u64>,
    pub min_free_ram_mb: u64,
    /// This machine's most recent local log lines, newest last.
    pub recent_log: Vec<String>,
}

/// The task held by `agent` among `tasks`, with heartbeat age against `now`.
///
/// A pure function of its inputs: staleness reasoning should not need a clock
/// hidden inside it.
#[must_use]
pub fn current_task(
    tasks: &[ferryman_channel::Task],
    agent: &str,
    now: chrono::DateTime<Utc>,
) -> Option<CurrentTask> {
    // (most recent claim instant, report) so one agent holding several orders
    // answers with the one it started latest - the loop works one at a time,
    // but recovery and retries can leave two holds in the channel at once.
    let mut found: Option<(chrono::DateTime<Utc>, CurrentTask)> = None;
    for task in tasks {
        // Held but not yet finished. `Claimed` covers the healthy case; `Stale`
        // is the same hold with a lapsed heartbeat and is display-only in the
        // channel too, so both belong here under "currently held".
        let state = task.state_at(now);
        let held = matches!(state, TaskState::Claimed { .. } | TaskState::Stale { .. });
        let mine = task.holder() == Some(agent);
        if !(held && mine) {
            continue;
        }
        let claimed_at = task
            .claims
            .iter()
            .filter(|c| c.agent == agent)
            .map(|c| c.claimed_at)
            .max();
        let Some(claimed_at) = claimed_at else {
            continue;
        };
        if found.as_ref().is_some_and(|(when, _)| *when >= claimed_at) {
            continue;
        }
        let age = task
            .heartbeats
            .iter()
            .filter(|h| h.agent == agent)
            .max_by_key(|h| h.at)
            .map(|h| (now - h.at).num_seconds());
        found = Some((
            claimed_at,
            CurrentTask {
                order_id: task.order.id.clone(),
                heartbeat_age_secs: age,
            },
        ));
    }
    found.map(|(_, current)| current)
}

/// Assemble the status for the project containing `start`.
pub fn examine(start: &Path) -> Result<AgentStatus> {
    let route = ferryman_channel::route_for(start)
        .context("no Ferryman channel found; run 'ferry enable' in the project first")?;
    let config = AgentConfig::load(&route.attachment)?;

    let tasks = ferryman_channel::list_tasks(&route)?;
    let now = Utc::now();
    let current_task = current_task(&tasks, &config.agent, now);

    let gate = governor::may_claim(&config);
    let (ready_to_claim, claim_blocked_reason) = match gate {
        governor::Decision::Go => (true, None),
        governor::Decision::Wait(reason) => (false, Some(reason)),
    };

    Ok(AgentStatus {
        project: route.project_id.clone(),
        agent: config.agent.clone(),
        engine: config.command.clone(),
        engine_on_path: crate::doctor::find_on_path(&config.command).is_some(),
        worker_alive: crate::agent::worker_alive(&route.attachment, &config.agent),
        current_task,
        ready_to_claim,
        claim_blocked_reason,
        paused: governor::paused(),
        claim_window: config.claim_window.map(|w| w.describe()),
        poll_secs: config.poll.as_secs(),
        memory_available_mb: governor::available_memory_mb(),
        min_free_ram_mb: config.min_free_ram_mb,
        recent_log: crate::runlog::tail(5),
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn an_unenabled_directory_is_an_error_not_a_blank_status() {
        let dir = tempfile::tempdir().unwrap();
        assert!(examine(dir.path()).is_err());
    }

    #[test]
    fn an_enabled_project_without_a_worker_reports_exactly_that() {
        let dir = crate::enable::tests_support::enabled_project("definitely-not-an-engine-9x7");
        let status = examine(&dir).unwrap();
        assert!(!status.worker_alive);
        assert!(!status.engine_on_path);
        assert!(status.current_task.is_none());
        // The gate answer depends on the machine (memory, presence), so only
        // its shape is asserted here - the reasons themselves have their own
        // tested home in the governor.
        assert_eq!(status.ready_to_claim, status.claim_blocked_reason.is_none());
    }

    #[test]
    fn the_worker_lock_is_what_liveness_reads() {
        // Own pid: alive everywhere by definition, including platforms where
        // liveness cannot actually be checked and assumes yes.
        let dir = crate::enable::tests_support::enabled_project("true");
        let attachment = dir.join(".ferryman");
        let path = attachment.join(format!("worker-{}.lock", "tester"));
        std::fs::write(&path, std::process::id().to_string()).unwrap();
        let status = examine(&dir).unwrap();
        assert!(status.worker_alive, "our own pid must read as alive");
        std::fs::remove_file(&path).unwrap();
        assert!(!examine(&dir).unwrap().worker_alive);
    }

    #[test]
    fn a_held_task_with_a_fresh_heartbeat_is_the_current_task() {
        // The selection logic, fed the channel's own types directly so no
        // sleeping or signing is needed to exercise it.
        let now = chrono::Utc::now();
        let order = |id: &str| ferryman_channel::Order {
            id: id.into(),
            project_id: "demo".into(),
            issued_by: "issuer".into(),
            assigned_to: None,
            created_at: now - chrono::Duration::minutes(5),
            payload: serde_json::json!({"task": "do a thing"}),
            requires_review: false,
            requires_approval: false,
            depends_on: vec![],
            signed_by: None,
            signature: None,
            result_contract: None,
        };
        let claim = ferryman_channel::Claim {
            order_id: "t-hold".into(),
            agent: "tester".into(),
            claimed_at: now - chrono::Duration::seconds(30),
        };
        let task = ferryman_channel::Task {
            order: order("t-hold"),
            claims: vec![claim],
            results: vec![],
            reviews: vec![],
            recommendations: vec![],
            releases: vec![],
            kills: vec![],
            heartbeats: vec![ferryman_channel::Heartbeat {
                order_id: "t-hold".into(),
                agent: "tester".into(),
                run: "run-1".into(),
                pid: 4242,
                at: now - chrono::Duration::seconds(12),
            }],
        };

        let current = current_task(std::slice::from_ref(&task), "tester", now)
            .expect("the held task must be reported");
        assert_eq!(current.order_id, "t-hold");
        assert_eq!(current.heartbeat_age_secs, Some(12));

        // Another agent's hold is not ours.
        assert!(current_task(std::slice::from_ref(&task), "someone-else", now).is_none());

        // An unheld task is nobody's current task.
        let idle = ferryman_channel::Task {
            order: order("t-idle"),
            claims: vec![],
            results: vec![],
            reviews: vec![],
            recommendations: vec![],
            releases: vec![],
            kills: vec![],
            heartbeats: vec![],
        };
        assert!(current_task(std::slice::from_ref(&idle), "tester", now).is_none());
    }
}
