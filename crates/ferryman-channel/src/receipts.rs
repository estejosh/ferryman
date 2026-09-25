//! Delivered and read receipts for orders, and each worker's presence in a channel.
//!
//! # Why these exist
//!
//! An order that never reached its machine looked exactly like one that reached it and
//! sat there: `Offered`, and nothing else. Ten channels once stopped syncing to one
//! machine and nothing anywhere said so for weeks. The orders were in the folder, the
//! folder was on the issuer's disk, and every display was satisfied with that.
//!
//! These files are the missing signals, each written by the side that knows:
//!
//! ```text
//! tasks/t-4f2a/
//!   delivered.fang.json   fang's worker has seen the order - written even when held off
//!   read.fang.json        fang loaded it to act on, or a live session was shown it
//! presence/
//!   fang.json             fang's worker is alive on this channel, and on which machine
//! ```
//!
//! Each path has one writer, the agent it names, and each file is signed by that agent,
//! so a peer cannot say "delivered" on another machine's behalf. Receipts are written
//! once and never replaced. Presence is rewritten, but at most every five minutes, so a
//! quiet fleet does not keep Syncthing busy with nothing to say.

use std::{
    fs,
    path::{Path, PathBuf},
};

use anyhow::{Result, bail};
use chrono::{DateTime, Duration, Utc};
use serde::{Deserialize, Serialize, de::DeserializeOwned};

use crate::{
    AgentIdentity, AgentRoute, ProjectRoute, SignatureCheck, Task, TaskState, check_signature,
    is_safe_component, task_dir, write_task_file,
};

/// An order nobody has receipted this long after it was issued has probably not reached
/// the machine it is for.
pub const UNDELIVERED_AFTER_SECS: i64 = 5 * 60;
/// An order delivered this long ago and still unread is waiting on a worker that is
/// paused, held off, or stuck.
pub const UNREAD_AFTER_SECS: i64 = 15 * 60;
/// The least time between two rewrites of one worker's presence file.
pub const PRESENCE_REFRESH_SECS: i64 = 5 * 60;
/// A worker not seen for this long is reported as absent.
pub const PRESENCE_ABSENT_AFTER_SECS: i64 = 60 * 60;

/// An agent's worker has seen an order meant for it.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct OrderDelivered {
    pub order_id: String,
    pub agent: String,
    /// The machine the worker runs on, so "delivered" says where as well as to whom.
    pub machine: String,
    pub delivered_at: DateTime<Utc>,
    pub ferry_version: String,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub signed_by: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub signature: Option<String>,
}

/// An agent has actually taken an order in: its worker loaded it to hand to the engine,
/// or a live session was shown its text.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct OrderRead {
    pub order_id: String,
    pub agent: String,
    pub read_at: DateTime<Utc>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub signed_by: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub signature: Option<String>,
}

/// A worker saying it is alive on this channel, and whether it is allowed to work.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct Presence {
    pub agent: String,
    pub machine: String,
    pub seen_at: DateTime<Utc>,
    pub ferry_version: String,
    /// Someone ran `ferry pause` on this machine.
    pub paused: bool,
    /// Why the worker is not taking work, when it is not: a pause, the governor, a
    /// missing grant. Absent when it is free to work.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub held: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub signed_by: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub signature: Option<String>,
}

fn delivered_payload(receipt: &OrderDelivered) -> String {
    format!(
        "ferryman-delivered-v1\n{}\n{}\n{}\n{}\n{}",
        receipt.order_id,
        receipt.agent,
        receipt.machine,
        receipt.delivered_at.to_rfc3339(),
        receipt.ferry_version,
    )
}

fn read_payload(receipt: &OrderRead) -> String {
    format!(
        "ferryman-read-v1\n{}\n{}\n{}",
        receipt.order_id,
        receipt.agent,
        receipt.read_at.to_rfc3339(),
    )
}

fn presence_payload(presence: &Presence) -> String {
    format!(
        "ferryman-presence-v1\n{}\n{}\n{}\n{}\n{}\n{}",
        presence.agent,
        presence.machine,
        presence.seen_at.to_rfc3339(),
        presence.ferry_version,
        presence.paused,
        presence.held.as_deref().unwrap_or(""),
    )
}

/// Check a signature, and that the signer is the agent the record is about.
///
/// A receipt is a statement about one agent, so only that agent may make it. A valid
/// signature by somebody else is still a forgery of this record.
fn verify_as(
    agent: &str,
    signed_by: Option<&String>,
    signature: Option<&String>,
    payload: &str,
    roster: &[AgentRoute],
) -> SignatureCheck {
    if signed_by.is_some_and(|signer| !signer.eq_ignore_ascii_case(agent)) {
        return SignatureCheck::Invalid;
    }
    check_signature(signed_by, signature, payload, roster)
}

/// Who says this order was delivered, checkably.
#[must_use]
pub fn verify_delivered(receipt: &OrderDelivered, roster: &[AgentRoute]) -> SignatureCheck {
    verify_as(
        &receipt.agent,
        receipt.signed_by.as_ref(),
        receipt.signature.as_ref(),
        &delivered_payload(receipt),
        roster,
    )
}

/// Who says this order was read, checkably.
#[must_use]
pub fn verify_read(receipt: &OrderRead, roster: &[AgentRoute]) -> SignatureCheck {
    verify_as(
        &receipt.agent,
        receipt.signed_by.as_ref(),
        receipt.signature.as_ref(),
        &read_payload(receipt),
        roster,
    )
}

/// Who says this worker is alive, checkably.
#[must_use]
pub fn verify_presence(presence: &Presence, roster: &[AgentRoute]) -> SignatureCheck {
    verify_as(
        &presence.agent,
        presence.signed_by.as_ref(),
        presence.signature.as_ref(),
        &presence_payload(presence),
        roster,
    )
}

/// This machine's name as a person would recognise it: the first label of the hostname,
/// lowercased. Display only - nothing is decided by it.
#[must_use]
pub fn machine_label() -> String {
    hostname::get()
        .map(|host| host.to_string_lossy().into_owned())
        .unwrap_or_default()
        .split('.')
        .next()
        .unwrap_or_default()
        .to_lowercase()
}

fn delivered_path(route: &ProjectRoute, order_id: &str, agent: &str) -> PathBuf {
    task_dir(route, order_id).join(format!("delivered.{agent}.json"))
}

fn read_path(route: &ProjectRoute, order_id: &str, agent: &str) -> PathBuf {
    task_dir(route, order_id).join(format!("read.{agent}.json"))
}

fn presence_path(route: &ProjectRoute, agent: &str) -> PathBuf {
    route
        .communications
        .join("presence")
        .join(format!("{agent}.json"))
}

/// Write a receipt that must never change once written.
///
/// The same content again is fine and does nothing; different content is refused, the
/// way a second acknowledgement of one message is. A receipt records the first time
/// something happened, and a later rewrite would quietly move that instant.
fn write_once<T: Serialize + DeserializeOwned + PartialEq>(
    path: &Path,
    value: &T,
    what: &str,
) -> Result<bool> {
    if path.exists() {
        let existing = fs::read_to_string(path)
            .ok()
            .and_then(|text| serde_json::from_str::<T>(&text).ok());
        if existing.as_ref() == Some(value) {
            return Ok(false);
        }
        bail!(
            "refusing to overwrite {what} {} with different content",
            path.display()
        )
    }
    write_task_file(path, value)?;
    Ok(true)
}

fn check_names(order_id: &str, agent: &str) -> Result<()> {
    if !is_safe_component(order_id) {
        bail!("order id must be a path-safe identifier")
    }
    if !is_safe_component(agent) {
        bail!("agent name must be a path-safe identifier")
    }
    Ok(())
}

/// Write a delivered receipt exactly as given. Returns whether anything was written.
pub fn write_delivered(route: &ProjectRoute, receipt: &OrderDelivered) -> Result<bool> {
    check_names(&receipt.order_id, &receipt.agent)?;
    let path = delivered_path(route, &receipt.order_id, &receipt.agent);
    write_once(&path, receipt, "delivered receipt")
}

/// Write a read receipt exactly as given. Returns whether anything was written.
pub fn write_read(route: &ProjectRoute, receipt: &OrderRead) -> Result<bool> {
    check_names(&receipt.order_id, &receipt.agent)?;
    let path = read_path(route, &receipt.order_id, &receipt.agent);
    write_once(&path, receipt, "read receipt")
}

/// Record, signed, that this agent's worker has seen an order. Returns whether a new
/// receipt was written; the first sighting stands, so a second call writes nothing.
pub fn record_delivered(
    route: &ProjectRoute,
    order_id: &str,
    identity: &AgentIdentity,
    machine: &str,
    ferry_version: &str,
) -> Result<bool> {
    check_names(order_id, identity.name())?;
    if delivered_path(route, order_id, identity.name()).exists() {
        return Ok(false);
    }
    if !task_dir(route, order_id).join("order.json").is_file() {
        bail!("there is no order {order_id} to receipt")
    }
    let mut receipt = OrderDelivered {
        order_id: order_id.to_string(),
        agent: identity.name().to_string(),
        machine: machine.to_string(),
        delivered_at: Utc::now(),
        ferry_version: ferry_version.to_string(),
        signed_by: Some(identity.name().to_string()),
        signature: None,
    };
    receipt.signature = Some(identity.sign_bytes(delivered_payload(&receipt).as_bytes()));
    write_delivered(route, &receipt)
}

/// Record, signed, that this agent has read an order. Returns whether a new receipt was
/// written; the first reading stands.
pub fn record_read(route: &ProjectRoute, order_id: &str, identity: &AgentIdentity) -> Result<bool> {
    check_names(order_id, identity.name())?;
    if read_path(route, order_id, identity.name()).exists() {
        return Ok(false);
    }
    if !task_dir(route, order_id).join("order.json").is_file() {
        bail!("there is no order {order_id} to receipt")
    }
    let mut receipt = OrderRead {
        order_id: order_id.to_string(),
        agent: identity.name().to_string(),
        read_at: Utc::now(),
        signed_by: Some(identity.name().to_string()),
        signature: None,
    };
    receipt.signature = Some(identity.sign_bytes(read_payload(&receipt).as_bytes()));
    write_read(route, &receipt)
}

/// Every receipt in one task's directory, each with what its signature check said.
#[derive(Debug, Clone, Default)]
pub struct Receipts {
    pub delivered: Vec<(OrderDelivered, SignatureCheck)>,
    pub read: Vec<(OrderRead, SignatureCheck)>,
}

/// Read one task's receipts.
///
/// Syncthing conflict copies (`delivered.fang.sync-conflict-....json`) are read like any
/// other: each is checked on its own, and the earliest valid one is what counts. A
/// receipt claiming a different order than the directory it sits in is reported as
/// invalid rather than counted, because it was copied there by something.
pub fn read_receipts(route: &ProjectRoute, order_id: &str) -> Result<Receipts> {
    let mut receipts = Receipts::default();
    let Ok(entries) = fs::read_dir(task_dir(route, order_id)) else {
        return Ok(receipts);
    };
    for entry in entries.flatten() {
        let path = entry.path();
        let Some(name) = path.file_name().and_then(|n| n.to_str()) else {
            continue;
        };
        if !Path::new(name)
            .extension()
            .is_some_and(|ext| ext.eq_ignore_ascii_case("json"))
        {
            continue;
        }
        let Ok(text) = fs::read_to_string(&path) else {
            continue;
        };
        if name.starts_with("delivered.")
            && let Ok(value) = serde_json::from_str::<OrderDelivered>(&text)
        {
            let check = if value.order_id == order_id {
                verify_delivered(&value, &route.agents)
            } else {
                SignatureCheck::Invalid
            };
            receipts.delivered.push((value, check));
        } else if name.starts_with("read.")
            && let Ok(value) = serde_json::from_str::<OrderRead>(&text)
        {
            let check = if value.order_id == order_id {
                verify_read(&value, &route.agents)
            } else {
                SignatureCheck::Invalid
            };
            receipts.read.push((value, check));
        }
    }
    receipts.delivered.sort_by_key(|(r, _)| r.delivered_at);
    receipts.read.sort_by_key(|(r, _)| r.read_at);
    Ok(receipts)
}

/// How far an order has got, in the order it gets there.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum Stage {
    Sent,
    Delivered,
    Read,
    Claimed,
    Done,
}

impl Stage {
    #[must_use]
    pub fn as_str(self) -> &'static str {
        match self {
            Self::Sent => "sent",
            Self::Delivered => "delivered",
            Self::Read => "read",
            Self::Claimed => "claimed",
            Self::Done => "done",
        }
    }
}

/// Where one unfinished order has got to, and whether that is worrying.
#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
pub struct OrderProgress {
    pub order_id: String,
    /// Who it is addressed to; `None` for an open order.
    pub to: Option<String>,
    /// The furthest stage it has reached.
    pub stage: Stage,
    /// When it reached that stage.
    pub since: DateTime<Utc>,
    /// Who took it there. `None` while it is only sent.
    pub by: Option<String>,
    pub sent_at: DateTime<Utc>,
    /// Receipts that are present but do not verify, as `delivered.fang (Invalid)`. They
    /// are shown, and they move nothing.
    pub unverified: Vec<String>,
    pub warning: Option<String>,
}

/// Where an order has got to, or `None` once it is finished or killed.
///
/// Only valid receipts count, and for an addressed order only the assignee's: another
/// machine seeing an order that is not for it says nothing about whether it arrived where
/// it was sent.
#[must_use]
pub fn progress_at(task: &Task, receipts: &Receipts, now: DateTime<Utc>) -> Option<OrderProgress> {
    if matches!(
        task.state_at(now),
        TaskState::Accepted | TaskState::Done | TaskState::Killed { .. }
    ) {
        return None;
    }
    let to = task.order.assigned_to.clone();
    let counts = |agent: &str| {
        to.as_deref()
            .is_none_or(|assignee| assignee.eq_ignore_ascii_case(agent))
    };
    let mut unverified = Vec::new();
    let mut reached = (Stage::Sent, task.order.created_at, None::<String>);
    let mut advance = |stage: Stage, at: DateTime<Utc>, by: &str| {
        if stage > reached.0 {
            reached = (stage, at, Some(by.to_string()));
        }
    };
    for (receipt, check) in &receipts.delivered {
        if *check != SignatureCheck::Valid {
            unverified.push(format!("delivered.{} ({check:?})", receipt.agent));
        }
    }
    for (receipt, check) in &receipts.read {
        if *check != SignatureCheck::Valid {
            unverified.push(format!("read.{} ({check:?})", receipt.agent));
        }
    }
    // Earliest first, so the first valid one is the one that counts.
    if let Some((receipt, _)) = receipts
        .delivered
        .iter()
        .find(|(r, check)| *check == SignatureCheck::Valid && counts(&r.agent))
    {
        advance(Stage::Delivered, receipt.delivered_at, &receipt.agent);
    }
    if let Some((receipt, _)) = receipts
        .read
        .iter()
        .find(|(r, check)| *check == SignatureCheck::Valid && counts(&r.agent))
    {
        advance(Stage::Read, receipt.read_at, &receipt.agent);
    }
    if let Some(claim) = task
        .claims
        .iter()
        .filter(|claim| counts(&claim.agent) && !task.released(&claim.agent))
        .min_by_key(|claim| claim.claimed_at)
    {
        advance(Stage::Claimed, claim.claimed_at, &claim.agent);
    }
    if let Some(result) = task.results.iter().max_by_key(|r| r.revision) {
        advance(Stage::Done, result.submitted_at, &result.agent);
    }
    let (stage, since, by) = reached;
    let waited = now.signed_duration_since(since);
    let warning = match stage {
        Stage::Sent if waited > Duration::seconds(UNDELIVERED_AFTER_SECS) => Some(match &to {
            Some(agent) => format!(
                "not delivered after {}: {agent}'s worker has not seen it - is this channel \
                 syncing to its machine, and is the worker running?",
                short_age(waited)
            ),
            None => format!(
                "not delivered after {}: no worker has seen it - is this channel syncing, \
                 and is any worker running?",
                short_age(waited)
            ),
        }),
        Stage::Delivered if waited > Duration::seconds(UNREAD_AFTER_SECS) => Some(format!(
            "delivered {} ago but not read: {}'s worker is paused, held off, or stuck",
            short_age(waited),
            by.as_deref().unwrap_or("the")
        )),
        _ => None,
    };
    Some(OrderProgress {
        order_id: task.order.id.clone(),
        to,
        stage,
        since,
        by,
        sent_at: task.order.created_at,
        unverified,
        warning,
    })
}

/// [`progress_at`] for one task, reading its receipts. A directory that cannot be read
/// has no receipts, which is the conservative answer: it makes an order look less far
/// along, never further.
#[must_use]
pub fn progress(route: &ProjectRoute, task: &Task, now: DateTime<Utc>) -> Option<OrderProgress> {
    let receipts = read_receipts(route, &task.order.id).unwrap_or_default();
    progress_at(task, &receipts, now)
}

/// Where every unfinished order in the channel has got to, oldest first.
pub fn channel_progress(route: &ProjectRoute, now: DateTime<Utc>) -> Result<Vec<OrderProgress>> {
    Ok(crate::list_tasks(route)?
        .iter()
        .filter_map(|task| progress(route, task, now))
        .collect())
}

/// Rewrite this worker's presence in the channel, unless it did so recently.
///
/// Returns whether the file was written. At most one write per
/// [`PRESENCE_REFRESH_SECS`], whatever changed: every write is a file Syncthing carries
/// to every machine, and a worker polling every ten seconds would otherwise send one each
/// time. A clock that has jumped backwards past the last write is treated as due, so the
/// file cannot be stuck in the future.
pub fn refresh_presence(
    route: &ProjectRoute,
    identity: &AgentIdentity,
    machine: &str,
    ferry_version: &str,
    held: Option<String>,
    paused: bool,
    now: DateTime<Utc>,
) -> Result<bool> {
    let agent = identity.name();
    if !is_safe_component(agent) {
        bail!("agent name must be a path-safe identifier")
    }
    let path = presence_path(route, agent);
    if let Ok(text) = fs::read_to_string(&path)
        && let Ok(existing) = serde_json::from_str::<Presence>(&text)
        && existing.agent.eq_ignore_ascii_case(agent)
    {
        let since = now.signed_duration_since(existing.seen_at);
        if since >= Duration::zero() && since < Duration::seconds(PRESENCE_REFRESH_SECS) {
            return Ok(false);
        }
    }
    let mut presence = Presence {
        agent: agent.to_string(),
        machine: machine.to_string(),
        seen_at: now,
        ferry_version: ferry_version.to_string(),
        paused,
        held,
        signed_by: Some(agent.to_string()),
        signature: None,
    };
    presence.signature = Some(identity.sign_bytes(presence_payload(&presence).as_bytes()));
    write_task_file(&path, &presence)?;
    Ok(true)
}

/// Every worker's presence in this channel, newest first, one per agent.
///
/// Conflict copies are read too, and for each agent the newest *valid* record wins; an
/// agent with no valid record is shown by its newest one, still marked unverified.
pub fn list_presence(route: &ProjectRoute) -> Result<Vec<(Presence, SignatureCheck)>> {
    let Ok(entries) = fs::read_dir(route.communications.join("presence")) else {
        return Ok(Vec::new());
    };
    let mut all: Vec<(Presence, SignatureCheck)> = entries
        .flatten()
        .map(|entry| entry.path())
        .filter(|path| {
            path.extension()
                .is_some_and(|ext| ext.eq_ignore_ascii_case("json"))
        })
        .filter_map(|path| fs::read_to_string(path).ok())
        .filter_map(|text| serde_json::from_str::<Presence>(&text).ok())
        .map(|presence| {
            let check = verify_presence(&presence, &route.agents);
            (presence, check)
        })
        .collect();
    // Valid before unverified, then newest first; the first per agent is kept.
    all.sort_by(|(a, a_check), (b, b_check)| {
        (*b_check == SignatureCheck::Valid)
            .cmp(&(*a_check == SignatureCheck::Valid))
            .then(b.seen_at.cmp(&a.seen_at))
    });
    let mut kept: Vec<(Presence, SignatureCheck)> = Vec::new();
    for (presence, check) in all {
        if !kept
            .iter()
            .any(|(p, _)| p.agent.eq_ignore_ascii_case(&presence.agent))
        {
            kept.push((presence, check));
        }
    }
    kept.sort_by_key(|(p, _)| std::cmp::Reverse(p.seen_at));
    Ok(kept)
}

/// A roster agent or a machine that has not been seen lately.
#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
pub struct Absence {
    pub agent: String,
    /// The machine it was last seen on, if it was ever seen.
    pub machine: Option<String>,
    pub last_seen: Option<DateTime<Utc>>,
}

/// Who should have been seen in the last [`PRESENCE_ABSENT_AFTER_SECS`] and was not.
///
/// Every roster agent except people - `operator` and `master` roles run no worker, so
/// their silence means nothing - plus any agent whose presence file has gone quiet, which
/// catches a machine the roster does not list. Only a valid presence counts as seen.
#[must_use]
pub fn absent_at(
    roster: &[AgentRoute],
    presence: &[(Presence, SignatureCheck)],
    now: DateTime<Utc>,
) -> Vec<Absence> {
    let limit = Duration::seconds(PRESENCE_ABSENT_AFTER_SECS);
    let seen = |agent: &str| {
        presence
            .iter()
            .filter(|(p, check)| {
                *check == SignatureCheck::Valid && p.agent.eq_ignore_ascii_case(agent)
            })
            .max_by_key(|(p, _)| p.seen_at)
            .map(|(p, _)| p)
    };
    let mut names: Vec<String> = roster
        .iter()
        .filter(|agent| {
            !agent.role.eq_ignore_ascii_case("operator")
                && !agent.role.eq_ignore_ascii_case("master")
        })
        .map(|agent| agent.name.clone())
        .collect();
    for (p, _) in presence {
        if !names.iter().any(|name| name.eq_ignore_ascii_case(&p.agent)) {
            names.push(p.agent.clone());
        }
    }
    names
        .into_iter()
        .filter_map(|name| {
            let last = seen(&name);
            if last.is_some_and(|p| now.signed_duration_since(p.seen_at) <= limit) {
                return None;
            }
            Some(Absence {
                agent: name,
                machine: last.map(|p| p.machine.clone()),
                last_seen: last.map(|p| p.seen_at),
            })
        })
        .collect()
}

/// A duration as a person reads it at a glance: `45s`, `12m`, `3h`, `2d`.
#[must_use]
pub fn short_age(age: Duration) -> String {
    let seconds = age.num_seconds().max(0);
    match seconds {
        0..60 => format!("{seconds}s"),
        60..3_600 => format!("{}m", seconds / 60),
        3_600..172_800 => format!("{}h", seconds / 3_600),
        _ => format!("{}d", seconds / 86_400),
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::{Order, TaskResult, issue_order, list_tasks, read_task, route_for};
    use serde_json::json;

    fn identity(name: &str, seed: u8) -> AgentIdentity {
        AgentIdentity::from_seed(name, [seed; 32])
    }

    fn roster_entry(identity: &AgentIdentity, role: &str) -> AgentRoute {
        AgentRoute {
            name: identity.name().to_string(),
            role: role.into(),
            capabilities: Vec::new(),
            public_key: Some(identity.public_key_hex()),
            encryption_key: None,
        }
    }

    /// A channel whose roster knows fang, nebra and the operator, and the three
    /// identities. Keys come from fixed seeds, so nothing touches a key store.
    fn channel() -> (
        tempfile::TempDir,
        ProjectRoute,
        AgentIdentity,
        AgentIdentity,
        AgentIdentity,
    ) {
        let temp = tempfile::tempdir().unwrap();
        let workspace = temp.path().join("project");
        let attachment = workspace.join(".ferryman");
        let communications = attachment.join("ferryman");
        fs::create_dir_all(&communications).unwrap();
        fs::write(
            attachment.join("bridge.toml"),
            format!(
                "project = \"demo\"\nworkspace = \"{}\"\nattachment = \"{}\"\ncommunications = \"{}\"\nshared_remote = \"demo-ferryman\"\ngit_remote = \"\"\ngit_visibility = \"private\"\n",
                workspace.display().to_string().replace('\\', "/"),
                attachment.display().to_string().replace('\\', "/"),
                communications.display().to_string().replace('\\', "/")
            ),
        )
        .unwrap();
        let mut route = route_for(&workspace).unwrap();
        let fang = identity("fang", 1);
        let nebra = identity("nebra", 2);
        let operator = identity("operator", 3);
        route.agents = vec![
            roster_entry(&fang, "worker"),
            roster_entry(&nebra, "worker"),
            roster_entry(&operator, "operator"),
        ];
        (temp, route, fang, nebra, operator)
    }

    fn issue(route: &ProjectRoute, by: &AgentIdentity, id: &str, to: Option<&str>) {
        issue_at(route, by, id, to, Utc::now());
    }

    fn issue_at(
        route: &ProjectRoute,
        by: &AgentIdentity,
        id: &str,
        to: Option<&str>,
        at: DateTime<Utc>,
    ) {
        let mut order = Order {
            id: id.into(),
            project_id: "demo".into(),
            issued_by: by.name().into(),
            assigned_to: to.map(ToString::to_string),
            created_at: at,
            payload: json!({"task": "write the report"}),
            requires_review: false,
            requires_approval: false,
            depends_on: Vec::new(),
            signed_by: None,
            signature: None,
            result_contract: None,
        };
        by.sign_order(&mut order);
        issue_order(route, &order).unwrap();
    }

    #[test]
    fn a_receipt_is_written_once_and_the_first_sighting_stands() {
        let (_t, route, fang, _, operator) = channel();
        issue(&route, &operator, "t-1", Some("fang"));
        assert!(record_delivered(&route, "t-1", &fang, "beastly", "0.5.15").unwrap());
        let first = read_receipts(&route, "t-1").unwrap().delivered[0].0.clone();
        assert!(
            !record_delivered(&route, "t-1", &fang, "beastly", "0.5.16").unwrap(),
            "a second sighting writes nothing"
        );
        let after = read_receipts(&route, "t-1").unwrap();
        assert_eq!(after.delivered.len(), 1);
        assert_eq!(after.delivered[0].0, first, "the first instant is kept");
        assert_eq!(after.delivered[0].1, SignatureCheck::Valid);

        // Rewriting the same bytes is harmless; anything different is refused.
        assert!(!write_delivered(&route, &first).unwrap());
        let mut moved = first.clone();
        moved.delivered_at += Duration::minutes(3);
        let error = write_delivered(&route, &moved).unwrap_err();
        assert!(
            format!("{error:#}").contains("refusing to overwrite"),
            "{error:#}"
        );

        assert!(record_read(&route, "t-1", &fang).unwrap());
        assert!(!record_read(&route, "t-1", &fang).unwrap());
        let read = read_receipts(&route, "t-1").unwrap().read;
        let mut later = read[0].0.clone();
        later.read_at += Duration::minutes(1);
        assert!(write_read(&route, &later).is_err());
    }

    #[test]
    fn there_is_no_receipt_for_an_order_that_does_not_exist() {
        let (_t, route, fang, _, _) = channel();
        assert!(record_delivered(&route, "t-nope", &fang, "beastly", "0").is_err());
        assert!(!task_dir(&route, "t-nope").exists(), "no stray directory");
    }

    #[test]
    fn a_forged_or_misfiled_receipt_is_shown_unverified_and_counts_for_nothing() {
        let (_t, route, fang, nebra, operator) = channel();
        issue(&route, &operator, "t-1", Some("fang"));
        issue(&route, &operator, "t-2", Some("fang"));
        // nebra signs a receipt claiming to be fang: a valid signature, by the wrong agent.
        let mut forged = OrderDelivered {
            order_id: "t-1".into(),
            agent: "fang".into(),
            machine: "elsewhere".into(),
            delivered_at: Utc::now(),
            ferry_version: "0".into(),
            signed_by: Some("nebra".into()),
            signature: None,
        };
        forged.signature = Some(nebra.sign_bytes(delivered_payload(&forged).as_bytes()));
        write_delivered(&route, &forged).unwrap();
        // A genuine receipt for t-2, copied into t-1's directory as a conflict copy.
        record_read(&route, "t-2", &fang).unwrap();
        fs::copy(
            read_path(&route, "t-2", "fang"),
            task_dir(&route, "t-1").join("read.fang.sync-conflict-20260925-101010-ABCDEFG.json"),
        )
        .unwrap();

        let receipts = read_receipts(&route, "t-1").unwrap();
        assert_eq!(receipts.delivered[0].1, SignatureCheck::Invalid);
        assert_eq!(receipts.read[0].1, SignatureCheck::Invalid);
        let task = read_task(&route, "t-1").unwrap();
        let progress = progress_at(&task, &receipts, Utc::now()).unwrap();
        assert_eq!(progress.stage, Stage::Sent);
        assert_eq!(
            progress.unverified,
            ["delivered.fang (Invalid)", "read.fang (Invalid)"]
        );
    }

    #[test]
    fn a_conflict_copy_of_a_valid_receipt_is_tolerated() {
        let (_t, route, fang, _, operator) = channel();
        issue(&route, &operator, "t-1", Some("fang"));
        record_delivered(&route, "t-1", &fang, "beastly", "0").unwrap();
        fs::copy(
            delivered_path(&route, "t-1", "fang"),
            task_dir(&route, "t-1").join("delivered.fang.sync-conflict-20260925-1-X.json"),
        )
        .unwrap();
        let task = read_task(&route, "t-1").unwrap();
        let progress = progress(&route, &task, Utc::now()).unwrap();
        assert_eq!(progress.stage, Stage::Delivered);
        assert!(progress.unverified.is_empty());
        assert_eq!(
            task.state(),
            TaskState::Offered { to: "fang".into() },
            "receipts do not disturb the task's own state"
        );
    }

    #[test]
    fn the_stage_is_the_furthest_one_reached_by_the_agent_it_was_sent_to() {
        let (_t, route, fang, nebra, operator) = channel();
        let issued = Utc::now() - Duration::minutes(2);
        issue_at(&route, &operator, "t-1", Some("fang"), issued);
        let at = |route: &ProjectRoute| {
            let task = read_task(route, "t-1").unwrap();
            progress(route, &task, Utc::now()).unwrap()
        };
        let sent = at(&route);
        assert_eq!(
            (sent.stage, sent.since, sent.by),
            (Stage::Sent, issued, None)
        );
        assert_eq!(sent.warning, None, "two minutes is not yet late");

        // Another machine seeing it says nothing about fang.
        record_delivered(&route, "t-1", &nebra, "nebra-pc", "0").unwrap();
        assert_eq!(at(&route).stage, Stage::Sent);

        record_delivered(&route, "t-1", &fang, "beastly", "0").unwrap();
        let delivered = at(&route);
        assert_eq!(delivered.stage, Stage::Delivered);
        assert_eq!(delivered.by.as_deref(), Some("fang"));

        record_read(&route, "t-1", &fang).unwrap();
        assert_eq!(at(&route).stage, Stage::Read);

        crate::claim_order(&route, "t-1", "fang").unwrap();
        assert_eq!(at(&route).stage, Stage::Claimed);

        let mut result = TaskResult {
            order_id: "t-1".into(),
            agent: "fang".into(),
            revision: 1,
            submitted_at: Utc::now(),
            payload: json!({"output": "done"}),
            signed_by: None,
            signature: None,
        };
        fang.sign_result(&mut result);
        crate::submit_result(&route, &result).unwrap();
        assert!(
            channel_progress(&route, Utc::now()).unwrap().is_empty(),
            "a finished order is no longer open, so it has no stage to report"
        );
    }

    #[test]
    fn an_open_order_counts_whoever_saw_it() {
        let (_t, route, _, nebra, operator) = channel();
        issue(&route, &operator, "t-1", None);
        record_delivered(&route, "t-1", &nebra, "nebra-pc", "0").unwrap();
        let task = read_task(&route, "t-1").unwrap();
        let progress = progress(&route, &task, Utc::now()).unwrap();
        assert_eq!(progress.stage, Stage::Delivered);
        assert_eq!(progress.by.as_deref(), Some("nebra"));
    }

    #[test]
    fn a_late_order_warns_at_each_stage_it_is_stuck_in() {
        let (_t, route, fang, _, operator) = channel();
        let issued = Utc::now() - Duration::minutes(40);
        issue_at(&route, &operator, "t-1", Some("fang"), issued);
        let task = read_task(&route, "t-1").unwrap();
        let receipts = Receipts::default();

        let early = progress_at(&task, &receipts, issued + Duration::minutes(4)).unwrap();
        assert_eq!(early.warning, None);
        let late = progress_at(&task, &receipts, issued + Duration::minutes(6)).unwrap();
        let warning = late.warning.unwrap();
        assert!(warning.contains("not delivered after 6m"), "{warning}");
        assert!(warning.contains("fang"), "{warning}");

        record_delivered(&route, "t-1", &fang, "beastly", "0").unwrap();
        let receipts = read_receipts(&route, "t-1").unwrap();
        let delivered_at = receipts.delivered[0].0.delivered_at;
        let fresh = progress_at(&task, &receipts, delivered_at + Duration::minutes(14)).unwrap();
        assert_eq!(fresh.warning, None, "delivered recently is not yet unread");
        let stuck = progress_at(&task, &receipts, delivered_at + Duration::minutes(16)).unwrap();
        let warning = stuck.warning.unwrap();
        assert!(
            warning.contains("delivered 16m ago but not read"),
            "{warning}"
        );

        record_read(&route, "t-1", &fang).unwrap();
        let receipts = read_receipts(&route, "t-1").unwrap();
        let read = progress_at(&task, &receipts, delivered_at + Duration::hours(5)).unwrap();
        assert_eq!(read.stage, Stage::Read);
        assert_eq!(
            read.warning, None,
            "read is somebody's attention; no warning"
        );
    }

    #[test]
    fn presence_is_rewritten_at_most_every_five_minutes() {
        let (_t, route, fang, _, _) = channel();
        let start = Utc::now();
        assert!(refresh_presence(&route, &fang, "beastly", "0.5.15", None, false, start).unwrap());
        assert!(
            !refresh_presence(
                &route,
                &fang,
                "beastly",
                "0.5.15",
                Some("paused".into()),
                true,
                start + Duration::minutes(4)
            )
            .unwrap(),
            "four minutes later nothing is written, even though the state changed"
        );
        let listed = list_presence(&route).unwrap();
        assert_eq!(listed.len(), 1);
        assert_eq!(listed[0].0.seen_at, start);
        assert!(!listed[0].0.paused);
        assert_eq!(listed[0].1, SignatureCheck::Valid);

        assert!(
            refresh_presence(
                &route,
                &fang,
                "beastly",
                "0.5.15",
                Some("paused".into()),
                true,
                start + Duration::minutes(6)
            )
            .unwrap()
        );
        let listed = list_presence(&route).unwrap();
        assert!(listed[0].0.paused);
        assert_eq!(listed[0].0.held.as_deref(), Some("paused"));

        // A clock that went backwards does not strand the file in the future.
        assert!(refresh_presence(&route, &fang, "beastly", "0", None, false, start).unwrap());
    }

    #[test]
    fn a_worker_not_seen_for_an_hour_is_named_and_people_are_not() {
        let (_t, route, fang, nebra, _) = channel();
        let now = Utc::now();
        refresh_presence(&route, &fang, "beastly", "0", None, false, now).unwrap();
        refresh_presence(
            &route,
            &nebra,
            "nebra-pc",
            "0",
            None,
            false,
            now - Duration::hours(3),
        )
        .unwrap();
        let presence = list_presence(&route).unwrap();
        let absent = absent_at(&route.agents, &presence, now);
        assert_eq!(absent.len(), 1, "{absent:?}");
        assert_eq!(absent[0].agent, "nebra");
        assert_eq!(absent[0].machine.as_deref(), Some("nebra-pc"));

        // A roster worker never seen at all is absent too; the operator never is.
        let mut roster = route.agents.clone();
        roster.push(roster_entry(&identity("wisp", 4), "worker"));
        let absent = absent_at(&roster, &presence, now);
        assert!(
            absent
                .iter()
                .any(|a| a.agent == "wisp" && a.last_seen.is_none())
        );
        assert!(!absent.iter().any(|a| a.agent == "operator"));
    }

    #[test]
    fn an_unsigned_presence_is_listed_but_does_not_count_as_seen() {
        let (_t, route, _, _, _) = channel();
        let fake = Presence {
            agent: "nebra".into(),
            machine: "nebra-pc".into(),
            seen_at: Utc::now(),
            ferry_version: "0".into(),
            paused: false,
            held: None,
            signed_by: None,
            signature: None,
        };
        write_task_file(&presence_path(&route, "nebra"), &fake).unwrap();
        let presence = list_presence(&route).unwrap();
        assert_eq!(presence[0].1, SignatureCheck::Unsigned);
        let absent = absent_at(&route.agents, &presence, Utc::now());
        assert!(absent.iter().any(|a| a.agent == "nebra"));
    }

    #[test]
    fn a_released_claim_does_not_count_as_claimed() {
        let (_t, route, fang, _, operator) = channel();
        issue(&route, &operator, "t-1", Some("fang"));
        crate::claim_order(&route, "t-1", "fang").unwrap();
        crate::release_claim(&route, "t-1", "fang", "fang", "test", &fang).unwrap();
        let tasks = list_tasks(&route).unwrap();
        let progress = progress(&route, &tasks[0], Utc::now()).unwrap();
        assert_eq!(progress.stage, Stage::Sent);
    }

    #[test]
    fn ages_read_at_a_glance() {
        assert_eq!(short_age(Duration::seconds(-5)), "0s");
        assert_eq!(short_age(Duration::seconds(45)), "45s");
        assert_eq!(short_age(Duration::minutes(12)), "12m");
        assert_eq!(short_age(Duration::hours(3)), "3h");
        assert_eq!(short_age(Duration::days(9)), "9d");
    }
}
