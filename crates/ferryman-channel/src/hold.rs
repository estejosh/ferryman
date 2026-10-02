//! Why a worker has not started an order it could have.
//!
//! A worker declines an order for reasons that are not failures: the interface contract
//! it depends on is not locked yet, or another agent is already editing the same files.
//! Declining silently looks identical to "the worker is down", so the reason is written
//! down, signed, where everyone can read it:
//!
//! ```text
//! tasks/t-4f2a/
//!   hold.fang.json     fang is not starting this, and why
//! ```
//!
//! One writer per path, like every other file in a task directory. A hold is rewritten
//! only when its reason CHANGES: a worker polls every few seconds, and a record that was
//! refreshed on every pass would be thousands of identical writes synced to every
//! machine. It is removed when the worker claims the order.

use std::fs;

use anyhow::{Result, bail};
use chrono::{DateTime, Utc};
use serde::{Deserialize, Serialize};

use crate::{AgentIdentity, ProjectRoute, SignatureCheck, check_signature, is_safe_component};

/// A signed statement that `agent` is holding off on `order_id`, and why.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct Hold {
    pub order_id: String,
    pub agent: String,
    pub reason: String,
    pub at: DateTime<Utc>,
    pub signed_by: String,
    pub signature: String,
}

fn payload(hold: &Hold) -> String {
    format!(
        "ferryman-hold-v1\n{}\n{}\n{}\n{}",
        hold.order_id,
        hold.agent,
        hold.reason,
        hold.at.to_rfc3339()
    )
}

fn path(route: &ProjectRoute, order_id: &str, agent: &str) -> std::path::PathBuf {
    crate::task_dir(route, order_id).join(format!("hold.{agent}.json"))
}

fn holds(route: &ProjectRoute, hold: &Hold) -> bool {
    hold.agent.eq_ignore_ascii_case(&hold.signed_by)
        && check_signature(
            Some(&hold.signed_by),
            Some(&hold.signature),
            &payload(hold),
            &route.agents,
        ) == SignatureCheck::Valid
}

/// Record that `identity` is holding off on `order_id` because of `reason`.
///
/// Returns whether anything was written: `false` when the same reason is already
/// recorded, which is the normal case on every pass after the first.
pub fn record(
    route: &ProjectRoute,
    identity: &AgentIdentity,
    order_id: &str,
    reason: &str,
) -> Result<bool> {
    if !is_safe_component(order_id) {
        bail!("order id must be a path-safe identifier");
    }
    if !is_safe_component(identity.name()) {
        bail!("agent name must be a path-safe identifier");
    }
    if !crate::task_dir(route, order_id).is_dir() {
        bail!("there is no order {order_id} to hold");
    }
    let file = path(route, order_id, identity.name());
    if let Ok(bytes) = fs::read(&file)
        && let Ok(existing) = serde_json::from_slice::<Hold>(&bytes)
        && existing.reason == reason
        && holds(route, &existing)
    {
        return Ok(false);
    }
    let mut hold = Hold {
        order_id: order_id.to_string(),
        agent: identity.name().to_string(),
        reason: reason.to_string(),
        at: Utc::now(),
        signed_by: identity.name().to_string(),
        signature: String::new(),
    };
    hold.signature = identity.sign_bytes(payload(&hold).as_bytes());
    crate::write_task_file(&file, &hold)?;
    Ok(true)
}

/// Forget `agent`'s hold on `order_id`. Called when the worker claims the order, so a
/// reason that no longer applies does not outlive the condition. Best effort.
pub fn clear(route: &ProjectRoute, order_id: &str, agent: &str) {
    if is_safe_component(order_id) && is_safe_component(agent) {
        let _ = fs::remove_file(path(route, order_id, agent));
    }
}

/// Every hold on `order_id` whose signature verifies.
#[must_use]
pub fn read(route: &ProjectRoute, order_id: &str) -> Vec<Hold> {
    if !is_safe_component(order_id) {
        return Vec::new();
    }
    let Ok(entries) = fs::read_dir(crate::task_dir(route, order_id)) else {
        return Vec::new();
    };
    let mut found: Vec<Hold> = entries
        .flatten()
        .filter(|entry| {
            let name = entry.file_name();
            let name = name.to_string_lossy();
            name.starts_with("hold.") && name.ends_with(".json")
        })
        .filter_map(|entry| serde_json::from_slice::<Hold>(&fs::read(entry.path()).ok()?).ok())
        .filter(|hold| hold.order_id == order_id && holds(route, hold))
        .collect();
    found.sort_by(|a, b| a.agent.cmp(&b.agent));
    found
}
