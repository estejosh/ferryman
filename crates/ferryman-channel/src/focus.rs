//! The swarm's focus: which projects the fleet is spending itself on right now.
//!
//! One person runs many projects, and the weekly self-improve loop and the fleet's
//! workers used to treat every one the same. The focus is the master's own word about
//! which ones matter this month, so the swarm can give them most of the improve time and
//! the first claim on a worker, and leave the rest a trickle.
//!
//! ```text
//! <ferryman channel>/FOCUS     the master's signed record: a tier per project, each
//!                              with an optional expiry, a sequence number
//! ```
//!
//! # Tiers
//!
//! `focus` (weight 12), `normal` (3, and what a project with no entry is), `background`
//! (1, a trickle) and `paused` (0: the swarm starts nothing of its own there). A person's
//! own orders are never held back by a tier: it decides what the swarm does on its own
//! initiative - the improve loop's planning and the width of improvement orders - and the
//! order workers look at projects in.
//!
//! # Where it lives, and why
//!
//! In the channel of one *home* project, `ferryman` unless `FERRYMAN_FOCUS_HOME` names
//! another. Not in the ferry root: the root's manifest is machine-local by design and
//! never syncs. Not as a file in every project's channel: thirty copies is thirty places
//! to roll back and thirty sequence numbers to keep in step. The home channel is already
//! carried to every machine in the fleet by Syncthing, has the master the fleet already
//! trusts, and every machine that runs a worker has it. A machine that does not have the
//! home channel has no focus, which reads as every project being `normal`: exactly how
//! the swarm behaved before this existed.
//!
//! # Trust
//!
//! The same shape as [`crate::policy`]'s `ENGINE_POLICY`. The record is honoured only when
//! it is signed by the home channel's master, or by a delegate holding the master's
//! `improve` delegation (the Telegram bridge), over exactly what it says, and the home
//! project id is in the signed payload so a record cannot be lifted from another channel.
//! It is checked every time it is read; nothing on disk is trusted. It carries a `seq`,
//! and this machine remembers - outside the synced folder - the highest it has accepted
//! and the last good record: an older signed copy put back, or the file deleted, leaves
//! the last good one in force and raises a notice. Clearing is therefore a newer, empty
//! record, never deleting the file.

use std::collections::BTreeMap;
use std::path::{Path, PathBuf};

use anyhow::{Context, Result, bail};
use chrono::{DateTime, Duration, Utc};
use serde::{Deserialize, Serialize};

use crate::policy::{Signed, notice, resolve};
use crate::{AgentIdentity, Order, ProjectRoute, SignatureCheck};

/// The file inside the home channel.
pub const FOCUS: &str = "FOCUS";
/// The project whose channel holds the record, unless [`HOME_ENV`] says otherwise.
pub const DEFAULT_HOME: &str = "ferryman";
/// Names another home project. Read at the machine, never from a channel.
pub const HOME_ENV: &str = "FERRYMAN_FOCUS_HOME";
/// Most projects one record names.
pub const MAX_PROJECTS: usize = 256;
/// Longest an entry may last, in days.
pub const MAX_DAYS: i64 = 366;
/// A project never gets more than this many times the per-project default in a week.
pub const MAX_FACTOR: usize = 3;

/// How much of the swarm a project gets.
///
/// Ordered by claim order: `Focus` first, `Paused` last.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash, Serialize, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum Tier {
    Focus,
    Normal,
    Background,
    Paused,
}

impl Tier {
    pub const ALL: [Tier; 4] = [Tier::Focus, Tier::Normal, Tier::Background, Tier::Paused];

    #[must_use]
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::Focus => "focus",
            Self::Normal => "normal",
            Self::Background => "background",
            Self::Paused => "paused",
        }
    }

    /// # Errors
    /// Anything that is not one of the four tiers.
    pub fn parse(text: &str) -> Result<Self> {
        match text.trim().to_ascii_lowercase().as_str() {
            "focus" => Ok(Self::Focus),
            "normal" => Ok(Self::Normal),
            "background" => Ok(Self::Background),
            "paused" | "pause" => Ok(Self::Paused),
            other => bail!("a tier is focus, normal, background or paused, not '{other}'"),
        }
    }

    /// The share of the weekly improve budget a project of this tier counts for.
    #[must_use]
    pub const fn weight(self) -> u64 {
        match self {
            Self::Focus => 12,
            Self::Normal => 3,
            Self::Background => 1,
            Self::Paused => 0,
        }
    }

    /// What it means, in a line.
    #[must_use]
    pub const fn describe(self) -> &'static str {
        match self {
            Self::Focus => "most of the improve time, first claim on workers",
            Self::Normal => "a fair share (a project with no entry is normal)",
            Self::Background => "a trickle: one improvement order a week, one at a time",
            Self::Paused => "nothing of the swarm's own; a person's orders still run",
        }
    }
}

impl std::fmt::Display for Tier {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str(self.as_str())
    }
}

/// One project's entry: its tier, and when it stops holding.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct Pin {
    pub tier: Tier,
    /// After this the entry no longer counts and the project reads as unset. `None`: it
    /// holds until it is changed.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub until: Option<DateTime<Utc>>,
}

impl Pin {
    /// Whether the entry still counts at `now`.
    #[must_use]
    pub fn holds(&self, now: DateTime<Utc>) -> bool {
        self.until.is_none_or(|until| now < until)
    }

    /// The entry as a person reads it: `focus until 2026-11-04`.
    #[must_use]
    pub fn describe(&self) -> String {
        match self.until {
            Some(until) => format!("{} until {}", self.tier, until.format("%Y-%m-%d")),
            None => self.tier.to_string(),
        }
    }
}

/// What the [`FOCUS`] file holds.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct FocusSetting {
    /// The project whose channel this is in. Part of what is signed.
    pub home: String,
    pub projects: BTreeMap<String, Pin>,
    pub set_at: DateTime<Utc>,
    pub signed_by: String,
    pub signature: String,
    /// Whose word this is, when a delegate signed it for them. Honoured only under a valid
    /// `improve` delegation from the master.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub on_behalf_of: Option<String>,
    /// One more than the highest `seq` the signer saw: a machine can tell an older signed
    /// record put back from a newer one.
    pub seq: u64,
}

impl FocusSetting {
    /// Exactly what `signature` covers.
    fn payload(&self) -> String {
        let mut payload = format!(
            "ferryman-focus-v1\n{}\n{}\n{}\nseq:{}",
            self.home,
            self.set_at.to_rfc3339(),
            serde_jcs::to_string(&self.projects).unwrap_or_default(),
            self.seq
        );
        if let Some(principal) = &self.on_behalf_of {
            payload.push_str(&format!("\nfor:{principal}"));
        }
        payload
    }

    fn sign(&mut self, signer: &AgentIdentity) {
        self.signature = signer.sign_bytes(self.payload().as_bytes());
    }

    /// Who set it, as a person reads it: `josh`, or `josh via telegram-grouchly`.
    #[must_use]
    pub fn set_by(&self) -> String {
        match &self.on_behalf_of {
            Some(principal) => crate::delegation::label(principal, &self.signed_by),
            None => self.signed_by.clone(),
        }
    }
}

/// Refuse a record whose entries mean nothing.
fn check_projects(projects: &BTreeMap<String, Pin>) -> Result<()> {
    if projects.len() > MAX_PROJECTS {
        bail!("a focus record names at most {MAX_PROJECTS} projects");
    }
    for name in projects.keys() {
        if !crate::is_safe_component(name) {
            bail!("a project id is letters, digits, '.', '-' or '_', not '{name}'");
        }
    }
    Ok(())
}

impl Signed for FocusSetting {
    const FILE: &'static str = FOCUS;
    const STATE: &'static str = "focus";
    const LABEL: &'static str = "focus";
    const QUESTION: &'static str = "focus";
    fn seq(&self) -> u64 {
        self.seq
    }
    fn set_at(&self) -> DateTime<Utc> {
        self.set_at
    }
    /// Whether this is the master's word for the fleet, read in `home`'s channel: signed
    /// by the master or by a delegate holding `improve` for them, over what it says.
    fn is_genuine(&self, channel: &Path, home: &str) -> bool {
        let Ok(roster) = crate::read_agent_roster(channel) else {
            return false;
        };
        let Ok(Some(master)) = crate::master::read_master_at(channel, &roster) else {
            return false;
        };
        let principal = self
            .on_behalf_of
            .clone()
            .unwrap_or_else(|| self.signed_by.clone());
        self.home == home
            && master.project_id == home
            && self.seq >= 1
            && principal.eq_ignore_ascii_case(&master.master)
            && check_projects(&self.projects).is_ok()
            && crate::delegation::authority(
                channel,
                home,
                &principal,
                &self.signed_by,
                crate::delegation::IMPROVE,
                Utc::now(),
            )
            .allowed()
            && crate::check_signature(
                Some(&self.signed_by),
                Some(&self.signature),
                &self.payload(),
                &roster,
            ) == SignatureCheck::Valid
    }
}

// --- reading ---------------------------------------------------------------------------

/// The home project's id on this machine.
#[must_use]
pub fn home_project() -> String {
    std::env::var(HOME_ENV)
        .ok()
        .map(|home| home.trim().to_string())
        .filter(|home| crate::is_safe_component(home))
        .unwrap_or_else(|| DEFAULT_HOME.to_string())
}

/// Where the home project's channel is on this machine, from the ferry root's manifest.
#[must_use]
pub fn home_channel() -> Option<PathBuf> {
    let home = home_project();
    crate::ferry::find_root()?
        .read()
        .projects
        .into_iter()
        .find(|entry| entry.project_id == home && entry.channel.is_dir())
        .map(|entry| entry.channel)
}

/// The focus in force, as read and verified now.
#[derive(Debug, Clone, Default)]
pub struct Focus {
    pub home: String,
    /// The master's record, when there is one and it verifies - or, when the channel's file
    /// went back or vanished, the last good one this machine saw.
    pub setting: Option<FocusSetting>,
    /// What is wrong with the channel's file, when this machine is holding on to an
    /// earlier record.
    pub notice: Option<String>,
    /// `setting` is this machine's memory, not the channel's file.
    pub from_memory: bool,
}

/// The focus in force for the home project whose channel is `channel`.
#[must_use]
pub fn in_force(channel: &Path, home: &str) -> Focus {
    let resolved = resolve::<FocusSetting>(channel, home);
    Focus {
        home: home.to_string(),
        setting: resolved.setting,
        notice: notice::<FocusSetting>(channel, home),
        from_memory: resolved.from_memory,
    }
}

/// The focus in force on this machine: the home channel found through the ferry root. With
/// no root, no home channel here or no record, nothing is set and every project is normal.
#[must_use]
pub fn current() -> Focus {
    match home_channel() {
        Some(channel) => in_force(&channel, &home_project()),
        None => Focus {
            home: home_project(),
            ..Focus::default()
        },
    }
}

impl Focus {
    /// Whether any entry is in force. With none, nothing here changes any behaviour.
    #[must_use]
    pub fn is_set(&self) -> bool {
        self.setting
            .as_ref()
            .is_some_and(|setting| !setting.projects.is_empty())
    }

    /// The entry for `project`, if it is there and has not expired.
    #[must_use]
    pub fn pin(&self, project: &str, now: DateTime<Utc>) -> Option<&Pin> {
        self.setting
            .as_ref()?
            .projects
            .get(project)
            .filter(|pin| pin.holds(now))
    }

    /// The tier `project` is in: its entry, or normal.
    #[must_use]
    pub fn tier(&self, project: &str, now: DateTime<Utc>) -> Tier {
        self.pin(project, now).map_or(Tier::Normal, |pin| pin.tier)
    }

    /// Entries whose time has run out: they no longer count, and are dropped at the next
    /// signing.
    #[must_use]
    pub fn expired(&self, now: DateTime<Utc>) -> Vec<(&String, &Pin)> {
        self.setting.as_ref().map_or_else(Vec::new, |setting| {
            setting
                .projects
                .iter()
                .filter(|(_, pin)| !pin.holds(now))
                .collect()
        })
    }

    /// The order a worker looks at projects in: focus first, then normal (and everything
    /// unset), then background, then paused. Within a tier the order given is kept, so a
    /// fleet that was fair stays fair among equals. Pure: nothing is read.
    ///
    /// This is the function a loop serving several projects calls once a pass:
    /// `focus.claim_order(&ids, now)`.
    #[must_use]
    pub fn claim_order(&self, projects: &[String], now: DateTime<Utc>) -> Vec<String> {
        let mut ordered: Vec<String> = projects.to_vec();
        ordered.sort_by_key(|project| self.tier(project, now));
        ordered
    }

    /// The width a role may have at once in `project`: the policy's `base` (`None` is no
    /// cap), scaled by the tier. Focus keeps the policy's; normal gets half of it, rounded
    /// up; background one; paused none. With no focus set, the policy's, unchanged.
    #[must_use]
    pub fn width(&self, project: &str, base: Option<u8>, now: DateTime<Utc>) -> Option<u8> {
        if !self.is_set() {
            return base;
        }
        width_for(self.tier(project, now), base)
    }
}

/// [`Focus::claim_order`] for this machine's focus: the one call a fleet loop needs.
#[must_use]
pub fn claim_order(projects: &[String]) -> Vec<String> {
    current().claim_order(projects, Utc::now())
}

/// The width a role may have at once for a project in `tier`, given the policy's `base`.
#[must_use]
pub fn width_for(tier: Tier, base: Option<u8>) -> Option<u8> {
    match tier {
        Tier::Focus => base,
        Tier::Normal => base.map(|width| width.div_ceil(2).max(1)),
        Tier::Background => Some(base.map_or(1, |width| width.min(1))),
        Tier::Paused => Some(0),
    }
}

/// Why a worker should not claim `order` yet because of its project's tier: an improvement
/// order, and the tier allows fewer of the role at once than are claimed now. `None` for
/// every other order - a person's own are never held - and whenever no focus is set.
#[must_use]
pub fn hold_for_order(route: &ProjectRoute, order: &Order, focus: &Focus) -> Option<String> {
    if !crate::policy::is_improvement_order(order) || !focus.is_set() {
        return None;
    }
    let now = Utc::now();
    let tier = focus.tier(&route.project_id, now);
    let role = crate::policy::order_role(order);
    let (policy, _) = crate::policy::effective(&route.communications, &route.project_id);
    let base = policy.width_for(role);
    let width = width_for(tier, base);
    if width == base {
        return None;
    }
    let width = width?;
    let tasks = crate::list_tasks(route).ok()?;
    let claimed = crate::policy::claimed_per_role(route, &tasks)
        .get(&role)
        .copied()
        .unwrap_or(0);
    (claimed >= usize::from(width)).then(|| {
        if tier == Tier::Paused {
            format!(
                "focus: {} is paused, so the swarm starts no improvement work there",
                route.project_id
            )
        } else {
            format!(
                "focus: {} is {tier}, so at most {width} {} at once, and that many are claimed",
                route.project_id,
                role.as_str()
            )
        }
    })
}

/// [`hold_for_order`] under this machine's focus, reading nothing for an order that is not
/// an improvement: what a worker asks before claiming.
#[must_use]
pub fn hold_for(route: &ProjectRoute, order: &Order) -> Option<String> {
    if !crate::policy::is_improvement_order(order) {
        return None;
    }
    hold_for_order(route, order, &current())
}

// --- the budget ------------------------------------------------------------------------

/// What one project gets of the week's improve budget.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Share {
    pub project: String,
    pub tier: Tier,
    /// Improvement orders to plan this week. Zero for a paused project.
    pub orders: usize,
}

/// Split a weekly improve budget over `projects` by tier weight.
///
/// The budget is `per_project` orders for each project that is not paused - what the loop
/// planned for each before there was a focus, so the total does not change; the focus
/// only moves it. Each project gets its weight's share, rounded with the largest
/// remainders first, at least one (a background project is a trickle, not nothing) and at
/// most [`MAX_FACTOR`] times `per_project`. Paused projects get none. With every project
/// in one tier each simply gets `per_project`. The result is in claim order: focus first.
/// Pure.
#[must_use]
pub fn allocate(projects: &[(String, Tier)], per_project: usize) -> Vec<Share> {
    let mut shares: Vec<Share> = projects
        .iter()
        .map(|(project, tier)| Share {
            project: project.clone(),
            tier: *tier,
            orders: 0,
        })
        .collect();
    shares.sort_by_key(|share| share.tier);
    let live: Vec<usize> = (0..shares.len())
        .filter(|index| shares[*index].tier != Tier::Paused)
        .collect();
    if live.is_empty() || per_project == 0 {
        return shares;
    }
    let budget = per_project * live.len();
    let cap = per_project.saturating_mul(MAX_FACTOR).max(1);
    let total: u64 = live.iter().map(|index| shares[*index].tier.weight()).sum();
    let mut remainders: Vec<(usize, u64)> = Vec::new();
    for index in &live {
        let numerator = budget as u64 * shares[*index].tier.weight();
        let whole = (numerator / total) as usize;
        shares[*index].orders = whole.clamp(1, cap);
        // A project lifted to one, or held at the cap, is not owed a remainder.
        if whole >= 1 && whole < cap {
            remainders.push((*index, numerator % total));
        }
    }
    remainders.sort_by(|a, b| b.1.cmp(&a.1).then(a.0.cmp(&b.0)));
    let mut left = budget.saturating_sub(live.iter().map(|index| shares[*index].orders).sum());
    while left > 0 {
        let mut gave = false;
        for (index, _) in &remainders {
            if left == 0 {
                break;
            }
            if shares[*index].orders < cap {
                shares[*index].orders += 1;
                left -= 1;
                gave = true;
            }
        }
        if !gave {
            break;
        }
    }
    shares
}

/// One project as the focus screens show it: its tier, what that comes to this week, and
/// the width its improvement orders may run at.
#[derive(Debug, Clone, PartialEq, Serialize)]
pub struct Overview {
    pub project: String,
    pub tier: Tier,
    /// The entry that put it in this tier, as a person reads it; `None` for normal by
    /// default.
    pub entry: Option<String>,
    pub expires: Option<DateTime<Utc>>,
    /// Self-improve is on here. The budget only reaches projects that have it on: that
    /// stays a per-project choice of the master's, and no tier switches it.
    pub improving: bool,
    /// Improvement orders planned this week, for a project that is improving.
    pub orders: Option<usize>,
    /// How many of a role may run at once: the policy's width under the tier, `None` for
    /// no cap.
    pub width: BTreeMap<String, Option<u8>>,
}

/// Improvement orders planned per project in a week when the loop is given no other number:
/// the same as `ferry improve plan --max`'s default.
pub const PER_PROJECT: usize = 5;

/// The focus laid over `projects` (id and channel): each one's tier, its share of the
/// week's improve budget of `per_project` orders each, and its widths. Archived projects
/// are left out - they get nothing. In claim order: focus first.
#[must_use]
pub fn overview(
    projects: &[(String, PathBuf)],
    focus: &Focus,
    per_project: usize,
    now: DateTime<Utc>,
) -> Vec<Overview> {
    let live: Vec<&(String, PathBuf)> = projects
        .iter()
        .filter(|(project, channel)| !crate::ferry::is_archived(channel, project))
        .collect();
    let improving: Vec<(String, Tier)> = live
        .iter()
        .filter(|(project, channel)| crate::ferry::self_improve_enabled(channel, project))
        .map(|(project, _)| (project.clone(), focus.tier(project, now)))
        .collect();
    let shares = allocate(&improving, per_project);
    let mut rows: Vec<Overview> = live
        .iter()
        .map(|(project, channel)| {
            let pin = focus.pin(project, now);
            let (policy, _) = crate::policy::effective(channel, project);
            let share = shares.iter().find(|share| share.project == *project);
            Overview {
                project: project.clone(),
                tier: pin.map_or(Tier::Normal, |pin| pin.tier),
                entry: pin.map(Pin::describe),
                expires: pin.and_then(|pin| pin.until),
                improving: share.is_some(),
                orders: share.map(|share| share.orders),
                width: ["build", "chore"]
                    .into_iter()
                    .filter_map(|name| {
                        let role = crate::policy::Role::parse(name).ok()?;
                        Some((
                            name.to_string(),
                            focus.width(project, policy.width_for(role), now),
                        ))
                    })
                    .collect(),
            }
        })
        .collect();
    rows.sort_by(|a, b| a.tier.cmp(&b.tier).then(a.project.cmp(&b.project)));
    rows
}

// --- signing ---------------------------------------------------------------------------

/// Set `project` to `tier`, lasting `days` days when given, in `projects`.
///
/// # Errors
/// A length of time that is not between one day and [`MAX_DAYS`], or a bad project id.
pub fn pin_project(
    projects: &mut BTreeMap<String, Pin>,
    project: &str,
    tier: Tier,
    days: Option<i64>,
    now: DateTime<Utc>,
) -> Result<()> {
    if !crate::is_safe_component(project) {
        bail!("a project id is letters, digits, '.', '-' or '_', not '{project}'");
    }
    let until = match days {
        None => None,
        Some(days) if (1..=MAX_DAYS).contains(&days) => Some(now + Duration::days(days)),
        Some(days) => bail!("--days is from 1 to {MAX_DAYS}, not {days}"),
    };
    projects.insert(project.to_string(), Pin { tier, until });
    Ok(())
}

/// Change the fleet's focus, signed by `signer` - the master of the home project in
/// `channel`, or a delegate holding the master's `improve` delegation (`on_behalf_of`).
/// `change` is given the entries still holding and edits them. Expired entries are
/// dropped. Returns whether anything changed; the same entries again write nothing,
/// unless the channel's file is not the record in force (it went back, or is gone), which
/// signing again repairs.
///
/// # Errors
/// A signer who is not the master or the master's delegate, a channel that is not here,
/// or entries that mean nothing.
pub fn set(
    channel: &Path,
    home: &str,
    signer: &AgentIdentity,
    on_behalf_of: Option<&str>,
    change: impl FnOnce(&mut BTreeMap<String, Pin>) -> Result<()>,
    now: DateTime<Utc>,
) -> Result<bool> {
    if !channel.is_dir() {
        bail!(
            "{home}'s channel is not on this machine ({}), and the focus lives there",
            channel.display()
        );
    }
    let on_behalf_of =
        on_behalf_of.filter(|principal| !principal.eq_ignore_ascii_case(signer.name()));
    match on_behalf_of {
        None => crate::ferry::require_master(channel, home, signer, "set the focus")?,
        Some(principal) => {
            let Some(master) = crate::ferry::master_of(channel)? else {
                bail!("{home} has no master, and only its master sets the focus");
            };
            if !principal.eq_ignore_ascii_case(&master) {
                bail!("only {master}, {home}'s master, sets the focus - not {principal}");
            }
            if let crate::delegation::Authority::Refused(why) = crate::delegation::authority(
                channel,
                home,
                principal,
                signer.name(),
                crate::delegation::IMPROVE,
                now,
            ) {
                bail!(
                    "{} cannot set the focus for {principal}: {why}",
                    signer.name()
                );
            }
        }
    }
    let resolved = resolve::<FocusSetting>(channel, home);
    let existing: BTreeMap<String, Pin> = resolved
        .setting
        .as_ref()
        .map(|setting| setting.projects.clone())
        .unwrap_or_default();
    let mut next: BTreeMap<String, Pin> = existing
        .iter()
        .filter(|(_, pin)| pin.holds(now))
        .map(|(project, pin)| (project.clone(), pin.clone()))
        .collect();
    change(&mut next)?;
    check_projects(&next)?;
    if !resolved.from_memory && resolved.setting.is_some() && next == existing {
        return Ok(false);
    }
    if resolved.setting.is_none() && next.is_empty() {
        return Ok(false);
    }
    let seq = resolved
        .high
        .max(resolved.setting.as_ref().map_or(0, |setting| setting.seq))
        + 1;
    let mut setting = FocusSetting {
        home: home.to_string(),
        projects: next,
        set_at: now,
        signed_by: signer.name().to_string(),
        signature: String::new(),
        on_behalf_of: on_behalf_of.map(str::to_string),
        seq,
    };
    setting.sign(signer);
    let path = channel.join(FOCUS);
    crate::atomic_json(&path, &setting).with_context(|| format!("writing {}", path.display()))?;
    Ok(true)
}

/// What is wrong with the channel's focus record, when this machine is holding on to an
/// earlier one because the file went back, vanished or stopped verifying.
#[must_use]
pub fn rollback_notice(channel: &Path, home: &str) -> Option<String> {
    notice::<FocusSetting>(channel, home)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::AgentRoute;

    const HOME: &str = "ferryman";

    fn person(name: &str, seed: u8) -> AgentIdentity {
        AgentIdentity::from_seed(name, [seed; 32])
    }

    /// The home project's channel, its master `members[0]`, every member on its roster; and
    /// this thread's own machine-state directory, so rollback memory is never shared.
    fn route(dir: &Path, members: &[&AgentIdentity]) -> ProjectRoute {
        crate::licensing::use_machine_state_dir_per_thread(dir.join("state"));
        let communications = dir.join("ferryman-ferryman");
        std::fs::create_dir_all(&communications).unwrap();
        let mut route = ProjectRoute {
            project_id: HOME.into(),
            workspace: dir.join("ferryman"),
            attachment: dir.join("attachment"),
            communications,
            shared_remote: String::new(),
            git_remote: String::new(),
            git_visibility: String::new(),
            agents: Vec::new(),
        };
        for member in members {
            let agent = AgentRoute {
                name: member.name().into(),
                role: "operator".into(),
                capabilities: Vec::new(),
                public_key: Some(member.public_key_hex()),
                encryption_key: None,
            };
            crate::register_agent(&route, &agent).unwrap();
            route.agents.push(agent);
        }
        crate::master::initialize_master(&route, members[0], members[0].name()).unwrap();
        route
    }

    fn pin(entries: &mut BTreeMap<String, Pin>, project: &str, tier: Tier, days: Option<i64>) {
        pin_project(entries, project, tier, days, Utc::now()).unwrap();
    }

    fn put(channel: &Path, signer: &AgentIdentity, projects: &[(&str, Tier)]) -> bool {
        set(
            channel,
            HOME,
            signer,
            None,
            |entries| {
                entries.clear();
                for (project, tier) in projects {
                    pin(entries, project, *tier, None);
                }
                Ok(())
            },
            Utc::now(),
        )
        .unwrap()
    }

    fn tiers(channel: &Path) -> Vec<(String, Tier)> {
        let focus = in_force(channel, HOME);
        let now = Utc::now();
        focus.setting.map_or_else(Vec::new, |setting| {
            setting
                .projects
                .iter()
                .filter(|(_, pin)| pin.holds(now))
                .map(|(project, pin)| (project.clone(), pin.tier))
                .collect()
        })
    }

    fn with(entries: &[(&str, Tier)]) -> Focus {
        let mut projects = BTreeMap::new();
        for (project, tier) in entries {
            pin(&mut projects, project, *tier, None);
        }
        Focus {
            home: HOME.into(),
            setting: Some(FocusSetting {
                home: HOME.into(),
                projects,
                set_at: Utc::now(),
                signed_by: "josh".into(),
                signature: String::new(),
                on_behalf_of: None,
                seq: 1,
            }),
            notice: None,
            from_memory: false,
        }
    }

    #[test]
    fn only_the_master_or_an_improve_delegate_signs_the_focus() {
        let dir = tempfile::tempdir().unwrap();
        let josh = person("josh", 1);
        let grouchly = person("grouchly", 2);
        let bridge = person("telegram-grouchly", 3);
        let route = route(dir.path(), &[&josh, &grouchly, &bridge]);
        let channel = &route.communications;
        let now = Utc::now();
        let change = |entries: &mut BTreeMap<String, Pin>| {
            pin(entries, "bullship", Tier::Focus, None);
            Ok(())
        };

        assert!(
            !in_force(channel, HOME).is_set(),
            "nothing signed, nothing set"
        );
        // A member who is not the master.
        assert!(set(channel, HOME, &grouchly, None, change, now).is_err());
        // Someone using the master's name with another key.
        assert!(set(channel, HOME, &person("josh", 9), None, change, now).is_err());
        // A delegate with no delegation.
        assert!(set(channel, HOME, &bridge, Some("josh"), change, now).is_err());
        assert!(!channel.join(FOCUS).exists());

        assert!(set(channel, HOME, &josh, None, change, now).unwrap());
        assert!(
            !set(channel, HOME, &josh, None, change, now).unwrap(),
            "the same entries again write nothing"
        );
        assert_eq!(tiers(channel), [("bullship".to_string(), Tier::Focus)]);

        // A delegation for orders only is not enough; improve is.
        crate::delegation::grant(
            channel,
            HOME,
            &josh,
            "telegram-grouchly",
            &["orders".to_string()],
            None,
        )
        .unwrap();
        assert!(set(channel, HOME, &bridge, Some("josh"), change, now).is_err());
        crate::delegation::grant(
            channel,
            HOME,
            &josh,
            "telegram-grouchly",
            &["improve".to_string()],
            None,
        )
        .unwrap();
        assert!(
            set(
                channel,
                HOME,
                &bridge,
                Some("josh"),
                |entries| {
                    pin(entries, "waitlyfi", Tier::Paused, None);
                    Ok(())
                },
                now
            )
            .unwrap()
        );
        let setting = in_force(channel, HOME).setting.unwrap();
        assert_eq!(setting.set_by(), "josh via telegram-grouchly");
        assert_eq!(
            setting.projects.len(),
            2,
            "the delegate edits, not replaces"
        );
        // Acting for someone who is not the master is refused whatever the delegation.
        assert!(set(channel, HOME, &bridge, Some("grouchly"), change, now).is_err());
    }

    #[test]
    fn an_edited_forged_lifted_or_garbled_record_is_ignored() {
        let dir = tempfile::tempdir().unwrap();
        let josh = person("josh", 1);
        let grouchly = person("grouchly", 2);
        let route = route(dir.path(), &[&josh, &grouchly]);
        let channel = &route.communications;
        let signed = [("bullship", Tier::Focus), ("graea", Tier::Background)];
        assert!(put(channel, &josh, &signed));
        let want: Vec<(String, Tier)> = signed.iter().map(|(p, t)| (p.to_string(), *t)).collect();
        assert_eq!(tiers(channel), want);

        let path = channel.join(FOCUS);
        let good: FocusSetting = serde_json::from_slice(&std::fs::read(&path).unwrap()).unwrap();

        // Edited after signing: the machine keeps what the master last signed.
        let mut edited = good.clone();
        edited.projects.get_mut("graea").unwrap().tier = Tier::Focus;
        crate::atomic_json(&path, &edited).unwrap();
        assert_eq!(tiers(channel), want);
        assert!(in_force(channel, HOME).from_memory);

        // Validly signed by a member who is not the master, with a higher seq.
        let mut forged = FocusSetting {
            signed_by: "grouchly".into(),
            seq: 99,
            ..good.clone()
        };
        forged.projects.insert(
            "redaktly".into(),
            Pin {
                tier: Tier::Focus,
                until: None,
            },
        );
        forged.sign(&grouchly);
        crate::atomic_json(&path, &forged).unwrap();
        assert_eq!(tiers(channel), want);

        // Signed by the master, but for another home project.
        let mut lifted = FocusSetting {
            home: "elsewhere".into(),
            seq: 100,
            ..good.clone()
        };
        lifted.sign(&josh);
        crate::atomic_json(&path, &lifted).unwrap();
        assert_eq!(tiers(channel), want);

        // Unsigned.
        let mut unsigned = good;
        unsigned.signature.clear();
        unsigned.seq = 101;
        crate::atomic_json(&path, &unsigned).unwrap();
        assert_eq!(tiers(channel), want);

        // Garbage.
        std::fs::write(&path, "everything is focus").unwrap();
        assert_eq!(tiers(channel), want);
        assert!(rollback_notice(channel, HOME).is_some());

        // Signing again puts the file right, above every seq that was seen.
        assert!(put(channel, &josh, &[("quantly", Tier::Focus)]));
        assert_eq!(tiers(channel), [("quantly".to_string(), Tier::Focus)]);
        assert!(!in_force(channel, HOME).from_memory);
    }

    #[test]
    fn an_older_signed_copy_or_a_deleted_file_cannot_roll_the_focus_back() {
        let dir = tempfile::tempdir().unwrap();
        let josh = person("josh", 1);
        let route = route(dir.path(), &[&josh]);
        let channel = &route.communications;
        let path = channel.join(FOCUS);

        assert!(put(channel, &josh, &[("bullship", Tier::Focus)]));
        let first = std::fs::read(&path).unwrap();
        assert!(put(channel, &josh, &[("bullship", Tier::Paused)]));
        let seq_two = in_force(channel, HOME).setting.unwrap().seq;
        assert!(seq_two > 1);
        assert_eq!(tiers(channel), [("bullship".to_string(), Tier::Paused)]);

        // The first record is genuine, signed, and older: it does not come back.
        std::fs::write(&path, &first).unwrap();
        let held = in_force(channel, HOME);
        assert_eq!(tiers(channel), [("bullship".to_string(), Tier::Paused)]);
        assert!(held.from_memory && held.notice.is_some());

        // Nor does deleting the file make everything normal again.
        std::fs::remove_file(&path).unwrap();
        let held = in_force(channel, HOME);
        assert_eq!(tiers(channel), [("bullship".to_string(), Tier::Paused)]);
        assert!(held.from_memory && held.notice.is_some());

        // The master signing once more repairs the channel and goes above what was seen.
        assert!(put(channel, &josh, &[("bullship", Tier::Paused)]));
        let repaired = in_force(channel, HOME);
        assert!(!repaired.from_memory && repaired.notice.is_none());
        assert!(repaired.setting.unwrap().seq > seq_two);
    }
    #[test]
    fn clearing_is_a_newer_empty_record_and_nothing_resurrects_the_old_one() {
        let dir = tempfile::tempdir().unwrap();
        let josh = person("josh", 1);
        let route = route(dir.path(), &[&josh]);
        let channel = &route.communications;
        let path = channel.join(FOCUS);

        assert!(
            !put(channel, &josh, &[]),
            "clearing a focus that was never set writes nothing"
        );
        assert!(put(channel, &josh, &[("bullship", Tier::Focus)]));
        let old = std::fs::read(&path).unwrap();
        assert!(put(channel, &josh, &[]));
        assert!(path.exists(), "the file stays, now empty and newer");
        assert!(!in_force(channel, HOME).is_set());
        std::fs::write(&path, &old).unwrap();
        assert!(
            !in_force(channel, HOME).is_set(),
            "the old record put back does not bring the focus back"
        );
    }

    #[test]
    fn an_entry_lapses_at_its_expiry_and_is_dropped_at_the_next_signing() {
        let dir = tempfile::tempdir().unwrap();
        let josh = person("josh", 1);
        let route = route(dir.path(), &[&josh]);
        let channel = &route.communications;
        let now = Utc::now();
        assert!(
            set(
                channel,
                HOME,
                &josh,
                None,
                |entries| {
                    pin_project(entries, "bullship", Tier::Focus, Some(7), now)?;
                    pin_project(entries, "graea", Tier::Paused, None, now)
                },
                now
            )
            .unwrap()
        );
        let focus = in_force(channel, HOME);
        assert_eq!(focus.tier("bullship", now), Tier::Focus);
        let later = now + Duration::days(8);
        assert_eq!(focus.tier("bullship", later), Tier::Normal);
        assert_eq!(
            focus.tier("graea", later),
            Tier::Paused,
            "no expiry, no lapse"
        );
        assert_eq!(focus.expired(later).len(), 1);
        assert!(focus.expired(now).is_empty());

        // Signing anything later leaves the lapsed entry out of the new record.
        assert!(
            set(
                channel,
                HOME,
                &josh,
                None,
                |entries| pin_project(entries, "oddsports", Tier::Background, None, later),
                later
            )
            .unwrap()
        );
        let projects = in_force(channel, HOME).setting.unwrap().projects;
        assert_eq!(
            projects.keys().cloned().collect::<Vec<_>>(),
            ["graea", "oddsports"]
        );
    }

    #[test]
    fn entries_are_checked_before_they_are_signed() {
        let now = Utc::now();
        let mut entries = BTreeMap::new();
        assert!(pin_project(&mut entries, "bullship", Tier::Focus, Some(0), now).is_err());
        assert!(
            pin_project(
                &mut entries,
                "bullship",
                Tier::Focus,
                Some(MAX_DAYS + 1),
                now
            )
            .is_err()
        );
        assert!(pin_project(&mut entries, "../etc", Tier::Focus, None, now).is_err());
        assert!(pin_project(&mut entries, "", Tier::Focus, None, now).is_err());
        assert!(entries.is_empty());
        pin_project(&mut entries, "bullship", Tier::Focus, Some(MAX_DAYS), now).unwrap();
        assert_eq!(
            entries["bullship"].until,
            Some(now + Duration::days(MAX_DAYS))
        );
        assert!(Tier::parse("urgent").is_err());
        for tier in Tier::ALL {
            assert_eq!(Tier::parse(tier.as_str()).unwrap(), tier);
        }
        assert!(Tier::Focus < Tier::Normal && Tier::Background < Tier::Paused);
    }

    #[test]
    fn workers_look_at_focus_projects_first_and_equals_keep_their_order() {
        let ids: Vec<String> = ["zeta", "quantly", "alpha", "bullship", "graea", "mid"]
            .iter()
            .map(ToString::to_string)
            .collect();
        let now = Utc::now();
        // Nothing set: the order given, untouched.
        assert_eq!(Focus::default().claim_order(&ids, now), ids);
        let focus = with(&[
            ("bullship", Tier::Focus),
            ("quantly", Tier::Focus),
            ("zeta", Tier::Background),
            ("graea", Tier::Paused),
        ]);
        assert_eq!(
            focus.claim_order(&ids, now),
            ["quantly", "bullship", "alpha", "mid", "zeta", "graea"],
            "focus, then normal (everything unset), background, paused; stable inside a tier"
        );
        // A lapsed entry no longer counts.
        let later = now + Duration::days(400);
        let mut lapsed = with(&[("bullship", Tier::Focus)]);
        lapsed
            .setting
            .as_mut()
            .unwrap()
            .projects
            .get_mut("bullship")
            .unwrap()
            .until = Some(now + Duration::days(1));
        assert_eq!(lapsed.claim_order(&ids, later), ids);
    }

    fn named(count: usize, tier: Tier) -> Vec<(String, Tier)> {
        (0..count).map(|n| (format!("{tier}{n}"), tier)).collect()
    }

    fn orders(shares: &[Share]) -> Vec<usize> {
        shares.iter().map(|share| share.orders).collect()
    }

    #[test]
    fn the_budget_is_split_by_weight_and_the_total_does_not_move() {
        // Everyone in one tier: exactly what each had before there was a focus.
        for tier in [Tier::Focus, Tier::Normal, Tier::Background] {
            assert_eq!(orders(&allocate(&named(3, tier), 5)), [5, 5, 5], "{tier}");
        }
        assert_eq!(orders(&allocate(&named(3, Tier::Paused), 5)), [0, 0, 0]);

        // 15 orders over weights 12 : 3 : 1 - largest remainder, one at least, none paused.
        let mixed = allocate(
            &[
                ("d".to_string(), Tier::Paused),
                ("c".to_string(), Tier::Background),
                ("b".to_string(), Tier::Normal),
                ("a".to_string(), Tier::Focus),
            ],
            5,
        );
        assert_eq!(
            mixed
                .iter()
                .map(|s| (s.project.as_str(), s.orders))
                .collect::<Vec<_>>(),
            [("a", 11), ("b", 3), ("c", 1), ("d", 0)],
            "in claim order, focus first"
        );

        // One focus among many background: capped at three times the usual, the total kept.
        let mut crowd = named(1, Tier::Focus);
        crowd.extend(named(9, Tier::Background));
        let shares = allocate(&crowd, 5);
        assert_eq!(shares[0].orders, 15, "never more than 3x per_project");
        assert!(shares[1..].iter().all(|s| s.orders >= 1));
        assert_eq!(shares.iter().map(|s| s.orders).sum::<usize>(), 50);

        // Whatever the mix, the total stays near per_project for each project that is not
        // paused (the one-order floor can lift it a little), nobody is over the cap, and
        // a paused project gets nothing.
        for per in [1, 2, 5, 7] {
            for (focus, normal, background, paused) in
                [(1, 0, 4, 1), (3, 3, 3, 3), (0, 2, 0, 0), (2, 5, 1, 0)]
            {
                let mut projects = named(focus, Tier::Focus);
                projects.extend(named(normal, Tier::Normal));
                projects.extend(named(background, Tier::Background));
                projects.extend(named(paused, Tier::Paused));
                let live = focus + normal + background;
                let shares = allocate(&projects, per);
                let total: usize = shares.iter().map(|s| s.orders).sum();
                let label = format!("{per} per project, {focus}/{normal}/{background}/{paused}");
                assert!(total <= per * live + live, "{label}: {total}");
                assert!(total >= live.min(per * live), "{label}: {total}");
                for share in &shares {
                    if share.tier == Tier::Paused {
                        assert_eq!(share.orders, 0, "{label}");
                    } else {
                        assert!((1..=per * MAX_FACTOR).contains(&share.orders), "{label}");
                    }
                }
            }
        }
        assert!(allocate(&[], 5).is_empty());
        assert_eq!(orders(&allocate(&named(3, Tier::Focus), 0)), [0, 0, 0]);
    }
    #[test]
    fn a_tier_scales_the_width_and_with_no_focus_the_policys_width_is_untouched() {
        assert_eq!(width_for(Tier::Focus, Some(4)), Some(4));
        assert_eq!(width_for(Tier::Focus, None), None);
        assert_eq!(width_for(Tier::Normal, Some(4)), Some(2));
        assert_eq!(width_for(Tier::Normal, Some(1)), Some(1));
        assert_eq!(width_for(Tier::Normal, None), None);
        assert_eq!(width_for(Tier::Background, Some(4)), Some(1));
        assert_eq!(width_for(Tier::Background, None), Some(1));
        assert_eq!(width_for(Tier::Paused, Some(4)), Some(0));
        assert_eq!(width_for(Tier::Paused, None), Some(0));
        let now = Utc::now();
        assert_eq!(Focus::default().width("p", Some(3), now), Some(3));
        assert_eq!(Focus::default().width("p", None, now), None);
        let focus = with(&[("p", Tier::Paused), ("q", Tier::Focus)]);
        assert_eq!(focus.width("p", Some(3), now), Some(0));
        assert_eq!(focus.width("q", Some(3), now), Some(3));
        assert_eq!(
            focus.width("unset", Some(3), now),
            Some(2),
            "unset is normal"
        );
    }

    fn improvement(id: &str, improvement: bool) -> Order {
        let tags: Vec<&str> = if improvement {
            vec!["improvement"]
        } else {
            vec![]
        };
        Order {
            id: id.into(),
            project_id: HOME.into(),
            issued_by: "josh".into(),
            assigned_to: None,
            created_at: Utc::now(),
            payload: serde_json::json!({ "tier": "build", "tags": tags }),
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
        }
    }

    #[test]
    fn a_workers_claim_is_held_only_for_an_improvement_order_past_its_tiers_width() {
        let dir = tempfile::tempdir().unwrap();
        let josh = person("josh", 1);
        let route = route(dir.path(), &[&josh]);
        let mut running = improvement("running", true);
        josh.sign_order(&mut running);
        crate::issue_order(&route, &running).unwrap();
        crate::claim_order(&route, "running", "wisp").unwrap();
        let next = improvement("next", true);
        let direct = improvement("mine", false);

        // No focus set: nothing is held, whatever the tier would have been.
        assert_eq!(hold_for_order(&route, &next, &Focus::default()), None);

        let background = with(&[(HOME, Tier::Background)]);
        let held = hold_for_order(&route, &next, &background).expect("one at a time, and one is");
        assert!(
            held.contains("background") && held.contains("at most 1"),
            "{held}"
        );
        assert_eq!(
            hold_for_order(&route, &direct, &background),
            None,
            "a person's own order is never held"
        );
        let focused = with(&[(HOME, Tier::Focus)]);
        assert_eq!(hold_for_order(&route, &next, &focused), None);
        let paused = with(&[(HOME, Tier::Paused)]);
        let held = hold_for_order(&route, &next, &paused).expect("paused starts nothing");
        assert!(held.contains("paused"), "{held}");
        assert_eq!(hold_for_order(&route, &direct, &paused), None);
    }

    #[test]
    fn the_overview_budgets_only_projects_that_are_improving() {
        let dir = tempfile::tempdir().unwrap();
        let josh = person("josh", 1);
        let route = route(dir.path(), &[&josh]);
        let channel = route.communications.clone();
        let projects = vec![(HOME.to_string(), channel.clone())];
        let now = Utc::now();
        let focus = with(&[(HOME, Tier::Focus)]);
        let rows = overview(&projects, &focus, PER_PROJECT, now);
        assert_eq!(rows.len(), 1);
        assert_eq!(rows[0].tier, Tier::Focus);
        assert!(
            !rows[0].improving && rows[0].orders.is_none(),
            "self-improve is off, and no tier switches it on"
        );
        assert_eq!(rows[0].entry.as_deref(), Some("focus"));
        crate::ferry::set_self_improve_as(&channel, HOME, true, &josh, None).unwrap();
        let rows = overview(&projects, &focus, PER_PROJECT, now);
        assert!(rows[0].improving);
        assert_eq!(
            rows[0].orders,
            Some(PER_PROJECT),
            "a lone project gets its usual"
        );
    }
}
