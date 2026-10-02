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
    /// A result came back, and its own evidence - or its emptiness - refutes it. Never
    /// shown as done.
    Refuted,
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
            Self::Refuted => "refuted",
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
    let mut refuted = None;
    if let Some(result) = task.results.iter().max_by_key(|r| r.revision) {
        let found = crate::evidence::classify(&task.order.payload, result);
        if found.status == crate::evidence::Status::Refuted {
            advance(Stage::Refuted, result.submitted_at, &result.agent);
            refuted = Some(found.reasons.join("; "));
        } else {
            advance(Stage::Done, result.submitted_at, &result.agent);
        }
    }
    let (stage, since, by) = reached;
    let waited = now.signed_duration_since(since);
    let warning = match stage {
        Stage::Refuted => Some(format!(
            "r{} came back refuted by its own evidence, not done: {}",
            task.latest_revision().unwrap_or(1),
            refuted.unwrap_or_default()
        )),
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

// --- engines ------------------------------------------------------------------------------
//
// Presence says a worker is alive. The engines file beside it says what that worker can
// run right now: which engines, which are out of credit and until when, which answered
// their last probe. It is what lets anyone ask "who can build this week" without asking
// every machine. Same rules as presence: one writer, signed, rewritten at most every
// five minutes - sooner only when an engine's state actually changed, and never more
// than once a minute. It never carries a credential or a reference to one.

/// The least time between two rewrites of one worker's engines file, even when
/// something changed.
pub const ENGINES_MIN_SECS: i64 = 60;

/// One engine, as the worker running it reports it.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
pub struct EngineReport {
    pub name: String,
    /// `cli` or `http`.
    pub kind: String,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub model: Option<String>,
    /// `judge`, `build` or `chore`.
    pub tier: String,
    /// `subscription`, `prepaid`, `free-tier`, `local` or `unknown`.
    pub paid: String,
    /// `up`, `down`, `exhausted` or `unknown`.
    pub state: String,
    /// When an exhausted engine is expected back.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub until: Option<DateTime<Utc>>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub reason: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub latency_ms: Option<u64>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub balance: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub checked_at: Option<DateTime<Utc>>,
    /// How far this engine's claims have held up against the worker's own evidence.
    /// `None` until one of its results has been checked.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub trust: Option<EngineTrust>,
    /// What the engine policy ranks by: where it is served from, whether a weekly cap
    /// bounds it, what it spent this week, and whether a free tier asked for money.
    /// `None` from a worker older than the engine policy.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub billing: Option<EngineBilling>,
    /// The engine's size class, `small`, `medium` or `large`: what its operator declared,
    /// else guessed from its model's name. `None` from a worker older than classes.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub class: Option<String>,
    /// What the engine can do: modalities, strengths, context window, cost and whether it
    /// is local - the operator's declared values, else guessed from the model and kind
    /// (see [`crate::capability`]). `None` from a worker older than capability profiles.
    /// A v2-only field, like `class`.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub capabilities: Option<crate::capability::Capabilities>,
}

/// How one engine is billed, as far as the worker running it can tell. Never a
/// credential: the host is the endpoint's host name only.
#[derive(Debug, Clone, Default, Serialize, Deserialize, PartialEq)]
pub struct EngineBilling {
    /// The endpoint's host, e.g. `integrate.api.nvidia.com`. `None` for a CLI engine
    /// that names no endpoint.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub host: Option<String>,
    /// A weekly request or dollar cap is set in agent.toml.
    #[serde(default)]
    pub capped: bool,
    /// The weekly request cap, when agent.toml sets one. Published because a project's
    /// `subscription_roles` honours a subscription only when it has one.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub weekly_requests: Option<u64>,
    /// The ISO week the counts are for.
    #[serde(default)]
    pub week: String,
    #[serde(default)]
    pub requests: u64,
    /// Dollars spent this week: what the provider reported, else list prices. A free
    /// tier or local engine counts nothing unless its provider reports a cost.
    #[serde(default)]
    pub spend_usd: f64,
    /// Why a free-tier engine is flagged - it asked for payment, ran out of quota or
    /// reported a cost - while the flag lasts.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub flag: Option<String>,
    /// For a gateway engine (OmniRoute): the provider/models its route ends at, so a
    /// policy can see - and block - what is really behind it.
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub route: Vec<String>,
}

/// What a worker's own evidence says about how far one engine's (and so one model's)
/// claims can be believed: results the evidence agreed with, results it refuted, and
/// whether that has demoted the engine to chore work until it passes the canary.
/// Published inside the signed engines inventory, so every machine reads the same.
#[derive(Debug, Clone, Default, Serialize, Deserialize, PartialEq, Eq)]
pub struct EngineTrust {
    pub verified: u64,
    #[serde(alias = "contradicted")]
    pub refuted: u64,
    #[serde(default)]
    pub unverified: u64,
    /// Refutations inside the rolling window that decides demotion.
    #[serde(default)]
    pub recent: u32,
    #[serde(default)]
    pub demoted: bool,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub demoted_at: Option<DateTime<Utc>>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub canary_passed_at: Option<DateTime<Utc>>,
}

impl EngineTrust {
    /// Verified results as a share of those the evidence decided, `None` before any.
    #[must_use]
    pub fn score(&self) -> Option<u64> {
        let decided = self.verified + self.refuted;
        (decided > 0).then(|| self.verified * 100 / decided)
    }

    /// `trust 67% (4 verified, 2 refuted, 1 unverified) - DEMOTED to chore work (2
    /// recent refutations) until it passes the canary`
    #[must_use]
    pub fn describe(&self) -> String {
        let mut text = format!(
            "trust {} ({} verified, {} refuted, {} unverified)",
            self.score()
                .map_or("-".to_string(), |score| format!("{score}%")),
            self.verified,
            self.refuted,
            self.unverified
        );
        if self.demoted {
            text.push_str(&format!(
                " - DEMOTED to chore work ({} recent refutations) until it passes the canary",
                self.recent
            ));
        } else if let Some(at) = self.canary_passed_at {
            text.push_str(&format!(" - canary passed {}", at.format("%a %H:%M UTC")));
        }
        text
    }
}

impl EngineReport {
    /// The report without what changes on every probe, for deciding whether anything
    /// worth telling the fleet has changed.
    fn settled(&self) -> Self {
        Self {
            latency_ms: None,
            checked_at: None,
            ..self.clone()
        }
    }
}

/// A worker's engines, signed.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
pub struct EngineInventory {
    pub agent: String,
    pub machine: String,
    pub updated_at: DateTime<Utc>,
    pub ferry_version: String,
    pub engines: Vec<EngineReport>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub signed_by: Option<String>,
    /// Signs the v1 view of the inventory: the engines without the fields v0.5.17 did not
    /// know (`class`, `capabilities`, `billing.weekly_requests`). That is exactly what an older verifier
    /// recomputes after it deserializes and drops what it does not know, so a new
    /// inventory still verifies on an old peer.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub signature: Option<String>,
    /// Signs the whole inventory, new fields included. A verifier that knows it requires
    /// it whenever a v2-only field is present, so those fields cannot be forged or
    /// stripped-and-replaced under the v1 signature alone.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub signature_v2: Option<String>,
}

impl EngineInventory {
    /// Whether any field a v0.5.17 verifier would drop is set.
    fn has_v2_fields(&self) -> bool {
        self.engines.iter().any(|e| {
            e.class.is_some()
                || e.capabilities.is_some()
                || e.billing
                    .as_ref()
                    .is_some_and(|b| b.weekly_requests.is_some())
        })
    }
}

/// The engines as v0.5.17 serializes them: without `class`, `capabilities` and
/// `weekly_requests`.
fn engines_v1_json(engines: &[EngineReport]) -> String {
    let mut value = serde_json::to_value(engines).unwrap_or_default();
    if let Some(list) = value.as_array_mut() {
        for engine in list {
            let Some(engine) = engine.as_object_mut() else {
                continue;
            };
            engine.remove("class");
            engine.remove("capabilities");
            if let Some(billing) = engine.get_mut("billing").and_then(|b| b.as_object_mut()) {
                billing.remove("weekly_requests");
            }
        }
    }
    serde_jcs::to_string(&value).unwrap_or_default()
}

/// What `signature` covers: byte for byte what v0.5.17 signed.
fn engines_payload(inventory: &EngineInventory) -> String {
    format!(
        "ferryman-engines-v1\n{}\n{}\n{}\n{}\n{}",
        inventory.agent,
        inventory.machine,
        inventory.updated_at.to_rfc3339(),
        inventory.ferry_version,
        engines_v1_json(&inventory.engines),
    )
}

/// What `signature_v2` covers: every field of every engine.
fn engines_payload_v2(inventory: &EngineInventory) -> String {
    format!(
        "ferryman-engines-v2\n{}\n{}\n{}\n{}\n{}",
        inventory.agent,
        inventory.machine,
        inventory.updated_at.to_rfc3339(),
        inventory.ferry_version,
        serde_jcs::to_string(&inventory.engines).unwrap_or_default(),
    )
}

fn engines_path(route: &ProjectRoute, agent: &str) -> PathBuf {
    route
        .communications
        .join("engines")
        .join(format!("{agent}.json"))
}

/// Who says this is what their worker can run, checkably.
#[must_use]
pub fn verify_engines(inventory: &EngineInventory, roster: &[AgentRoute]) -> SignatureCheck {
    let v1 = verify_as(
        &inventory.agent,
        inventory.signed_by.as_ref(),
        inventory.signature.as_ref(),
        &engines_payload(inventory),
        roster,
    );
    if !inventory.has_v2_fields() {
        return v1;
    }
    // A v2-only field is present: the v1 signature does not cover it, so it counts only
    // with a valid v2 signature over the whole inventory.
    let v2 = verify_as(
        &inventory.agent,
        inventory.signed_by.as_ref(),
        inventory.signature_v2.as_ref(),
        &engines_payload_v2(inventory),
        roster,
    );
    if v1 == SignatureCheck::Valid && v2 == SignatureCheck::Valid {
        SignatureCheck::Valid
    } else {
        SignatureCheck::Invalid
    }
}

/// Publish this worker's engines, signed. Returns whether anything was written.
///
/// Written when the last write is five minutes old, or when an engine's state changed
/// and the last write is at least a minute old. A clock that went backwards past the
/// last write counts as due, as for presence.
pub fn refresh_engines(
    route: &ProjectRoute,
    identity: &AgentIdentity,
    machine: &str,
    ferry_version: &str,
    engines: Vec<EngineReport>,
    now: DateTime<Utc>,
) -> Result<bool> {
    let agent = identity.name();
    if !is_safe_component(agent) {
        bail!("agent name must be a path-safe identifier")
    }
    let path = engines_path(route, agent);
    if let Ok(text) = fs::read_to_string(&path)
        && let Ok(existing) = serde_json::from_str::<EngineInventory>(&text)
        && existing.agent.eq_ignore_ascii_case(agent)
    {
        let since = now.signed_duration_since(existing.updated_at);
        if since >= Duration::zero() {
            let changed = existing.engines.len() != engines.len()
                || existing
                    .engines
                    .iter()
                    .zip(&engines)
                    .any(|(old, new)| old.settled() != new.settled());
            let floor = if changed {
                ENGINES_MIN_SECS
            } else {
                PRESENCE_REFRESH_SECS
            };
            if since < Duration::seconds(floor) {
                return Ok(false);
            }
        }
    }
    let mut inventory = EngineInventory {
        agent: agent.to_string(),
        machine: machine.to_string(),
        updated_at: now,
        ferry_version: ferry_version.to_string(),
        engines,
        signed_by: Some(agent.to_string()),
        signature: None,
        signature_v2: None,
    };
    inventory.signature = Some(identity.sign_bytes(engines_payload(&inventory).as_bytes()));
    inventory.signature_v2 = Some(identity.sign_bytes(engines_payload_v2(&inventory).as_bytes()));
    write_task_file(&path, &inventory)?;
    Ok(true)
}

/// Every worker's engines file in this channel, newest valid one per agent first.
pub fn list_engines(route: &ProjectRoute) -> Result<Vec<(EngineInventory, SignatureCheck)>> {
    let Ok(entries) = fs::read_dir(route.communications.join("engines")) else {
        return Ok(Vec::new());
    };
    let mut all: Vec<(EngineInventory, SignatureCheck)> = entries
        .flatten()
        .map(|entry| entry.path())
        .filter(|path| {
            path.extension()
                .is_some_and(|ext| ext.eq_ignore_ascii_case("json"))
        })
        .filter_map(|path| fs::read_to_string(path).ok())
        .filter_map(|text| serde_json::from_str::<EngineInventory>(&text).ok())
        .map(|inventory| {
            let check = verify_engines(&inventory, &route.agents);
            (inventory, check)
        })
        .collect();
    all.sort_by(|(a, a_check), (b, b_check)| {
        (*b_check == SignatureCheck::Valid)
            .cmp(&(*a_check == SignatureCheck::Valid))
            .then(b.updated_at.cmp(&a.updated_at))
    });
    let mut kept: Vec<(EngineInventory, SignatureCheck)> = Vec::new();
    for (inventory, check) in all {
        if !kept
            .iter()
            .any(|(i, _)| i.agent.eq_ignore_ascii_case(&inventory.agent))
        {
            kept.push((inventory, check));
        }
    }
    Ok(kept)
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
            interface: None,
            touches: Vec::new(),
            needs: None,
            allow_overlap: false,
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

    /// The grouchly answer: a redirect and seven placeholders. It is not done, and the
    /// progress view says so rather than "done".
    #[test]
    fn a_refuted_result_is_shown_as_refuted_never_as_done() {
        let (_t, route, fang, _, operator) = channel();
        issue(&route, &operator, "t-1", Some("fang"));
        crate::claim_order(&route, "t-1", "fang").unwrap();
        let mut result = TaskResult {
            order_id: "t-1".into(),
            agent: "fang".into(),
            revision: 1,
            submitted_at: Utc::now(),
            payload: json!({"output": "better suited to 'nebra'\n1. no output\n2. no output"}),
            signed_by: None,
            signature: None,
        };
        fang.sign_result(&mut result);
        crate::submit_result(&route, &result).unwrap();
        let open = channel_progress(&route, Utc::now()).unwrap();
        assert_eq!(
            open.len(),
            1,
            "still open: a refuted result is not finished"
        );
        assert_eq!(open[0].stage, Stage::Refuted);
        assert_eq!(open[0].stage.as_str(), "refuted");
        assert!(
            open[0]
                .warning
                .as_deref()
                .is_some_and(|w| w.contains("not done") && w.contains("hands the work")),
            "{:?}",
            open[0].warning
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

    fn engine(state: &str) -> EngineReport {
        EngineReport {
            name: "nvidia".into(),
            kind: "http".into(),
            model: Some("qwen/qwen3-coder".into()),
            tier: "build".into(),
            paid: "free-tier".into(),
            state: state.into(),
            until: None,
            reason: None,
            latency_ms: Some(8000),
            balance: None,
            checked_at: Some(Utc::now()),
            trust: None,
            billing: None,
            class: None,
            capabilities: None,
        }
    }

    #[test]
    fn the_engines_file_is_signed_and_rate_limited_like_presence() {
        let (_t, route, fang, _, _) = channel();
        let start = Utc::now();
        assert!(
            refresh_engines(
                &route,
                &fang,
                "grouchly",
                "0.5.15",
                vec![engine("up")],
                start
            )
            .unwrap()
        );
        let listed = list_engines(&route).unwrap();
        assert_eq!(listed.len(), 1);
        assert_eq!(listed[0].1, SignatureCheck::Valid);
        assert_eq!(listed[0].0.machine, "grouchly");

        // Only the latency moved: nothing worth a write for five minutes.
        let mut slower = engine("up");
        slower.latency_ms = Some(40_000);
        assert!(
            !refresh_engines(
                &route,
                &fang,
                "grouchly",
                "0.5.15",
                vec![slower.clone()],
                start + Duration::minutes(4)
            )
            .unwrap()
        );
        // A real change waits only for the one-minute floor.
        assert!(
            !refresh_engines(
                &route,
                &fang,
                "grouchly",
                "0.5.15",
                vec![engine("exhausted")],
                start + Duration::seconds(30)
            )
            .unwrap()
        );
        assert!(
            refresh_engines(
                &route,
                &fang,
                "grouchly",
                "0.5.15",
                vec![engine("exhausted")],
                start + Duration::seconds(90)
            )
            .unwrap()
        );
        assert_eq!(
            list_engines(&route).unwrap()[0].0.engines[0].state,
            "exhausted"
        );
        assert!(
            refresh_engines(
                &route,
                &fang,
                "grouchly",
                "0.5.15",
                vec![slower],
                start + Duration::minutes(7)
            )
            .unwrap()
        );
    }

    #[test]
    fn an_engines_file_edited_or_written_for_someone_else_does_not_verify() {
        let (_t, route, fang, nebra, _) = channel();
        refresh_engines(
            &route,
            &fang,
            "grouchly",
            "0",
            vec![engine("up")],
            Utc::now(),
        )
        .unwrap();
        let path = engines_path(&route, "fang");
        let mut tampered: EngineInventory =
            serde_json::from_str(&fs::read_to_string(&path).unwrap()).unwrap();
        tampered.engines[0].state = "exhausted".into();
        write_task_file(&path, &tampered).unwrap();
        assert_eq!(list_engines(&route).unwrap()[0].1, SignatureCheck::Invalid);

        // nebra signing a file about fang is a forgery of fang's record.
        let mut forged = tampered.clone();
        forged.signed_by = Some("nebra".into());
        forged.signature = Some(nebra.sign_bytes(engines_payload(&forged).as_bytes()));
        assert_eq!(
            verify_engines(&forged, &route.agents),
            SignatureCheck::Invalid
        );
    }

    // The shapes v0.5.17 had, copied here so the test does not follow the live structs.
    #[derive(Debug, Clone, Serialize, Deserialize)]
    struct OldEngineBilling {
        #[serde(default, skip_serializing_if = "Option::is_none")]
        host: Option<String>,
        #[serde(default)]
        capped: bool,
        #[serde(default)]
        week: String,
        #[serde(default)]
        requests: u64,
        #[serde(default)]
        spend_usd: f64,
        #[serde(default, skip_serializing_if = "Option::is_none")]
        flag: Option<String>,
        #[serde(default, skip_serializing_if = "Vec::is_empty")]
        route: Vec<String>,
    }

    #[derive(Debug, Clone, Serialize, Deserialize)]
    struct OldEngineReport {
        name: String,
        kind: String,
        #[serde(default, skip_serializing_if = "Option::is_none")]
        model: Option<String>,
        tier: String,
        paid: String,
        state: String,
        #[serde(default, skip_serializing_if = "Option::is_none")]
        until: Option<DateTime<Utc>>,
        #[serde(default, skip_serializing_if = "Option::is_none")]
        reason: Option<String>,
        #[serde(default, skip_serializing_if = "Option::is_none")]
        latency_ms: Option<u64>,
        #[serde(default, skip_serializing_if = "Option::is_none")]
        balance: Option<String>,
        #[serde(default, skip_serializing_if = "Option::is_none")]
        checked_at: Option<DateTime<Utc>>,
        #[serde(default, skip_serializing_if = "Option::is_none")]
        trust: Option<EngineTrust>,
        #[serde(default, skip_serializing_if = "Option::is_none")]
        billing: Option<OldEngineBilling>,
    }

    #[derive(Debug, Clone, Serialize, Deserialize)]
    struct OldEngineInventory {
        agent: String,
        machine: String,
        updated_at: DateTime<Utc>,
        ferry_version: String,
        engines: Vec<OldEngineReport>,
        #[serde(default, skip_serializing_if = "Option::is_none")]
        signed_by: Option<String>,
        #[serde(default, skip_serializing_if = "Option::is_none")]
        signature: Option<String>,
    }

    /// What a v0.5.17 peer does with an engines file: read it into its own struct, drop
    /// what it does not know, and check the signature over what it re-serializes.
    fn old_peer_accepts(text: &str, roster: &[AgentRoute]) -> bool {
        let Ok(old) = serde_json::from_str::<OldEngineInventory>(text) else {
            return false;
        };
        let payload = format!(
            "ferryman-engines-v1\n{}\n{}\n{}\n{}\n{}",
            old.agent,
            old.machine,
            old.updated_at.to_rfc3339(),
            old.ferry_version,
            serde_jcs::to_string(&old.engines).unwrap_or_default(),
        );
        verify_as(
            &old.agent,
            old.signed_by.as_ref(),
            old.signature.as_ref(),
            &payload,
            roster,
        ) == SignatureCheck::Valid
    }

    fn upgraded_engine() -> EngineReport {
        let mut upgraded = engine("up");
        upgraded.class = Some("small".into());
        upgraded.billing = Some(EngineBilling {
            host: Some("integrate.api.nvidia.com".into()),
            capped: true,
            weekly_requests: Some(500),
            week: "2026-W40".into(),
            requests: 12,
            spend_usd: 0.25,
            flag: None,
            route: vec!["a/b".into()],
        });
        upgraded
    }

    #[test]
    fn an_upgraded_inventory_still_verifies_on_a_v0_5_17_peer_and_its_new_fields_cannot_be_forged()
    {
        let (_t, route, fang, _, _) = channel();
        refresh_engines(
            &route,
            &fang,
            "grouchly",
            "0.5.18",
            vec![upgraded_engine()],
            Utc::now(),
        )
        .unwrap();
        let path = engines_path(&route, "fang");
        let text = fs::read_to_string(&path).unwrap();
        assert!(text.contains("\"class\"") && text.contains("weekly_requests"));
        assert!(
            old_peer_accepts(&text, &route.agents),
            "the old verifier must not skip an upgraded worker's inventory"
        );
        let listed = list_engines(&route).unwrap();
        assert_eq!(listed[0].1, SignatureCheck::Valid);
        assert_eq!(listed[0].0.engines[0].class.as_deref(), Some("small"));

        // Forging the new fields under the v1 signature alone does not verify.
        let original: EngineInventory = serde_json::from_str(&text).unwrap();
        let mut forged_class = original.clone();
        forged_class.engines[0].class = Some("large".into());
        assert_eq!(
            verify_engines(&forged_class, &route.agents),
            SignatureCheck::Invalid
        );
        let mut forged_cap = original.clone();
        forged_cap.engines[0]
            .billing
            .as_mut()
            .unwrap()
            .weekly_requests = Some(1_000_000);
        assert_eq!(
            verify_engines(&forged_cap, &route.agents),
            SignatureCheck::Invalid
        );
        // Dropping the v2 signature while keeping the fields does not verify either.
        let mut stripped = original.clone();
        stripped.signature_v2 = None;
        assert_eq!(
            verify_engines(&stripped, &route.agents),
            SignatureCheck::Invalid
        );
        // Adding a field to a v1-only inventory is a forgery too.
        let mut v1_only = original.clone();
        v1_only.engines[0].class = None;
        v1_only.engines[0].billing.as_mut().unwrap().weekly_requests = None;
        v1_only.signature_v2 = None;
        assert_eq!(
            verify_engines(&v1_only, &route.agents),
            SignatureCheck::Valid
        );
        v1_only.engines[0].class = Some("large".into());
        assert_eq!(
            verify_engines(&v1_only, &route.agents),
            SignatureCheck::Invalid
        );
        // The v1 view tampered (a state change) fails on the old peer and the new one.
        let mut tampered = original;
        tampered.engines[0].state = "exhausted".into();
        assert!(!old_peer_accepts(
            &serde_json::to_string(&tampered).unwrap(),
            &route.agents
        ));
        assert_eq!(
            verify_engines(&tampered, &route.agents),
            SignatureCheck::Invalid
        );
    }

    #[test]
    fn capabilities_are_v2_only_so_a_v0_5_17_peer_still_verifies_and_they_cannot_be_forged() {
        use crate::capability::{Capabilities, Cost, Modality};
        let (_t, route, fang, _, _) = channel();
        // Nothing but a capability profile is new on this line.
        let mut engine = engine("up");
        engine.capabilities = Some(Capabilities {
            modalities: vec![Modality::Text, Modality::Vision],
            strengths: vec!["docs".into()],
            context_k: Some(128),
            cost: Some(Cost::FREE),
            local: true,
        });
        assert!(engine.class.is_none());
        refresh_engines(
            &route,
            &fang,
            "grouchly",
            "0.5.18",
            vec![engine],
            Utc::now(),
        )
        .unwrap();
        let text = fs::read_to_string(engines_path(&route, "fang")).unwrap();
        assert!(text.contains("\"capabilities\"") && text.contains("signature_v2"));
        assert!(
            old_peer_accepts(&text, &route.agents),
            "the old verifier must still accept a worker that only added capabilities"
        );
        let listed = list_engines(&route).unwrap();
        assert_eq!(listed[0].1, SignatureCheck::Valid);
        let original = listed[0].0.clone();
        assert_eq!(
            original.engines[0]
                .capabilities
                .as_ref()
                .unwrap()
                .modalities,
            vec![Modality::Text, Modality::Vision]
        );

        // Claiming a modality under the v1 signature alone does not verify.
        let mut forged = original.clone();
        forged.engines[0]
            .capabilities
            .as_mut()
            .unwrap()
            .modalities
            .push(Modality::Code);
        assert_eq!(
            verify_engines(&forged, &route.agents),
            SignatureCheck::Invalid
        );
        let mut cheaper = original.clone();
        cheaper.engines[0].capabilities.as_mut().unwrap().cost = None;
        assert_eq!(
            verify_engines(&cheaper, &route.agents),
            SignatureCheck::Invalid
        );
        // Stripping the v2 signature while keeping the profile does not verify either.
        let mut stripped = original.clone();
        stripped.signature_v2 = None;
        assert_eq!(
            verify_engines(&stripped, &route.agents),
            SignatureCheck::Invalid
        );
        // Without a profile, an old-style inventory is as valid as ever.
        let mut bare = original;
        bare.engines[0].capabilities = None;
        bare.signature_v2 = None;
        assert_eq!(verify_engines(&bare, &route.agents), SignatureCheck::Valid);
    }

    #[test]
    fn a_modality_from_a_newer_version_survives_a_round_trip_and_still_verifies() {
        use crate::capability::{Capabilities, Modality};
        let (_t, route, fang, _, _) = channel();
        let mut engine = engine("up");
        engine.capabilities = Some(Capabilities {
            modalities: vec![Modality::Text, Modality::Other("hologram".into())],
            ..Capabilities::default()
        });
        refresh_engines(
            &route,
            &fang,
            "grouchly",
            "0.5.18",
            vec![engine],
            Utc::now(),
        )
        .unwrap();
        let listed = list_engines(&route).unwrap();
        assert_eq!(listed[0].1, SignatureCheck::Valid);
        assert!(
            listed[0].0.engines[0]
                .capabilities
                .as_ref()
                .unwrap()
                .has(&Modality::Other("hologram".into()))
        );
    }

    #[test]
    fn an_old_workers_inventory_verifies_on_a_new_peer_without_a_v2_signature() {
        let (_t, route, fang, _, _) = channel();
        let engines = vec![OldEngineReport {
            name: "nvidia".into(),
            kind: "http".into(),
            model: None,
            tier: "build".into(),
            paid: "free-tier".into(),
            state: "up".into(),
            until: None,
            reason: None,
            latency_ms: None,
            balance: None,
            checked_at: None,
            trust: None,
            billing: Some(OldEngineBilling {
                host: None,
                capped: false,
                week: "2026-W39".into(),
                requests: 1,
                spend_usd: 0.0,
                flag: None,
                route: Vec::new(),
            }),
        }];
        let mut old = OldEngineInventory {
            agent: "fang".into(),
            machine: "grouchly".into(),
            updated_at: Utc::now(),
            ferry_version: "0.5.17".into(),
            engines,
            signed_by: Some("fang".into()),
            signature: None,
        };
        let payload = format!(
            "ferryman-engines-v1\n{}\n{}\n{}\n{}\n{}",
            old.agent,
            old.machine,
            old.updated_at.to_rfc3339(),
            old.ferry_version,
            serde_jcs::to_string(&old.engines).unwrap(),
        );
        old.signature = Some(fang.sign_bytes(payload.as_bytes()));
        let new: EngineInventory =
            serde_json::from_str(&serde_json::to_string(&old).unwrap()).unwrap();
        assert!(new.signature_v2.is_none());
        assert_eq!(verify_engines(&new, &route.agents), SignatureCheck::Valid);
    }
}
