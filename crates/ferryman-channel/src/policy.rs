//! The engine policy: which AI engines, on which machines, may do a project's background
//! work, and in what order.
//!
//! ```text
//! <channel>/ENGINE_POLICY                      the master's signed policy, or their signed "auto"
//! <channel>/improve/<week>/steps/<agent>.json  which engine on which machine did each improve
//!                                              step, signed by the agent that did it
//! ```
//!
//! # Why
//!
//! The improve loop and its orders run with nobody watching. Left to the operator's
//! engine order, a background loop happily spends someone's Claude or Codex subscription
//! limits - the ones they need on Thursday. The policy says, per project, which engines
//! each role of background work prefers, which it must never use, and which machines may
//! run it. With no policy set the fleet chooses for itself ("auto"): local and free
//! engines first, subscriptions never.
//!
//! # Background and direct work
//!
//! Background work is improvement orders (and their audit verifications) and the improve
//! loop's own planning and review. An order a person gives directly is theirs to spend
//! on: `protect_subscriptions` never touches it, and `never` does only when the policy
//! says `never_applies_to = "all"`.
//!
//! # No fallback
//!
//! When nothing the policy allows can do the work, the work waits. It never falls back to
//! a blocked engine. The loop records why, and asks the master once a week per role
//! (a signed question, with buttons on the phone).
//!
//! # Trust
//!
//! Exactly [`crate::ferry::SELF_IMPROVE`]'s: the file is honoured only when the project's
//! master signed it, by the key the channel knows them by, or their delegate did under an
//! `improve` delegation. Anything else - unsigned, edited, forged, lifted from another
//! project - is ignored, and the project runs on auto.

use std::{
    collections::{BTreeMap, BTreeSet},
    path::Path,
};

use anyhow::{Context, Result, bail};
use chrono::{DateTime, Duration, Utc};
use serde::{Deserialize, Serialize};

use crate::{
    AgentIdentity, ProjectRoute, SignatureCheck,
    receipts::{EngineReport, PRESENCE_ABSENT_AFTER_SECS},
};

/// The file, inside a channel, that holds the master's signed engine policy.
pub const ENGINE_POLICY: &str = "ENGINE_POLICY";
/// How long a free-tier engine that asked for money stays ranked down in auto mode.
pub const FLAG_DAYS: i64 = 7;
/// Engine inventories older than this are not counted as the fleet.
pub const INVENTORY_FRESH_HOURS: i64 = 24;
/// The answer that accepts the recommended policy.
pub const ACCEPT_RECOMMENDED: &str = "Accept recommended";
/// The answer that leaves held work waiting.
pub const KEEP_HOLDING: &str = "Keep holding";
/// Step records kept per agent per week.
const KEEP_STEPS: usize = 200;
/// Longest selector accepted.
const SELECTOR_CHARS: usize = 120;

/// A kind of background work.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash, Serialize, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum Role {
    /// The improve loop turning evidence into a plan.
    Plan,
    /// Improvement orders at build tier, and audit verifications.
    Build,
    /// The improve loop judging a plan or a result.
    Review,
    /// Improvement orders at chore tier.
    Chore,
}

impl Role {
    pub const ALL: [Role; 4] = [Role::Plan, Role::Build, Role::Review, Role::Chore];

    pub fn parse(value: &str) -> Result<Self> {
        match value.trim().to_ascii_lowercase().as_str() {
            "plan" => Ok(Self::Plan),
            "build" => Ok(Self::Build),
            "review" => Ok(Self::Review),
            "chore" => Ok(Self::Chore),
            other => bail!("a role is plan, build, review or chore, not '{other}'"),
        }
    }

    #[must_use]
    pub fn as_str(self) -> &'static str {
        match self {
            Self::Plan => "plan",
            Self::Build => "build",
            Self::Review => "review",
            Self::Chore => "chore",
        }
    }

    /// The tier the role's work asks for.
    #[must_use]
    pub fn tier(self) -> &'static str {
        match self {
            Self::Plan | Self::Review => "judge",
            Self::Build => "build",
            Self::Chore => "chore",
        }
    }

    /// The role an order of this tier plays.
    #[must_use]
    pub fn for_order_tier(tier: &str) -> Self {
        if tier.eq_ignore_ascii_case("chore") {
            Self::Chore
        } else {
            Self::Build
        }
    }
}

/// Which work `never` applies to.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default, Serialize, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum NeverScope {
    /// Only background work: a person's own orders may still use any engine.
    #[default]
    Background,
    /// Every order, a person's own included.
    All,
}

/// What fm may merge on its own once an improvement holds both keys.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default, Serialize, Deserialize)]
#[serde(rename_all = "kebab-case")]
pub enum AutoMerge {
    /// Nothing: every approved improvement waits for the master to merge it.
    #[default]
    None,
    /// Docs, tests and dependency bumps only; anything touching code or config waits.
    LowRisk,
}

impl AutoMerge {
    pub fn parse(value: &str) -> Result<Self> {
        match value.trim().to_ascii_lowercase().replace('_', "-").as_str() {
            "none" | "off" | "no" | "false" => Ok(Self::None),
            "low-risk" | "lowrisk" | "on" | "yes" | "true" => Ok(Self::LowRisk),
            other => bail!("auto_merge is none or low-risk, not '{other}'"),
        }
    }

    #[must_use]
    pub fn as_str(self) -> &'static str {
        match self {
            Self::None => "none",
            Self::LowRisk => "low-risk",
        }
    }

    fn is_none(&self) -> bool {
        *self == Self::None
    }
}

/// Whether work is the fleet's own or a person's.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Work {
    Background,
    Direct,
}

fn yes() -> bool {
    true
}

/// One project's engine policy.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct Policy {
    /// Per role (`plan`, `build`, `review`, `chore`): selectors, most preferred first.
    /// Engines no selector matches come after, in auto order.
    #[serde(default, skip_serializing_if = "BTreeMap::is_empty")]
    pub prefer: BTreeMap<String, Vec<String>>,
    /// Selectors that must never be used for background work.
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub never: Vec<String>,
    /// Agents or machines allowed to run this project's self-improve work. Empty is any.
    #[serde(default, rename = "where", skip_serializing_if = "Vec::is_empty")]
    pub machines: Vec<String>,
    /// Per role: dollars the fleet may spend on it in one ISO week.
    #[serde(default, skip_serializing_if = "BTreeMap::is_empty")]
    pub caps_usd: BTreeMap<String, f64>,
    /// Never spend a subscription on background work.
    #[serde(default = "yes")]
    pub protect_subscriptions: bool,
    #[serde(default)]
    pub never_applies_to: NeverScope,
    /// What fm merges on its own after both keys: `none` (the default) or `low-risk`
    /// (docs, tests, dependency bumps). Left out of the signed JSON when `none`, so a
    /// policy signed before this existed still verifies.
    #[serde(default, skip_serializing_if = "AutoMerge::is_none")]
    pub auto_merge: AutoMerge,
}

impl Default for Policy {
    fn default() -> Self {
        Self {
            prefer: BTreeMap::new(),
            never: Vec::new(),
            machines: Vec::new(),
            caps_usd: BTreeMap::new(),
            protect_subscriptions: true,
            never_applies_to: NeverScope::Background,
            auto_merge: AutoMerge::None,
        }
    }
}

impl Policy {
    /// Refuse a policy with a role, selector or cap that means nothing.
    pub fn check(&self) -> Result<()> {
        for (role, list) in &self.prefer {
            Role::parse(role)?;
            for selector in list {
                check_selector(selector)?;
            }
        }
        for selector in self.never.iter().chain(&self.machines) {
            check_selector(selector)?;
        }
        for (role, cap) in &self.caps_usd {
            Role::parse(role)?;
            if !cap.is_finite() || *cap < 0.0 {
                bail!("the {role} cap must be a dollar amount of zero or more");
            }
        }
        Ok(())
    }

    /// The role's preference list, empty when it has none.
    #[must_use]
    pub fn preferences(&self, role: Role) -> &[String] {
        self.prefer.get(role.as_str()).map_or(&[], Vec::as_slice)
    }

    /// Where the engine stands in the role's list: the first selector it matches.
    #[must_use]
    pub fn preference(&self, role: Role, engine: &Candidate) -> Option<usize> {
        self.preferences(role)
            .iter()
            .position(|selector| matches(selector, engine))
    }

    /// Why this engine may not do this work, or `None` when it may.
    #[must_use]
    pub fn blocked(&self, engine: &Candidate, work: Work) -> Option<String> {
        if (work == Work::Background || self.never_applies_to == NeverScope::All)
            && let Some(selector) = self.never.iter().find(|s| matches(s, engine))
        {
            return Some(format!("never: matches '{selector}'"));
        }
        if work == Work::Background
            && self.protect_subscriptions
            && engine.paid_class() == "subscription"
        {
            return Some(if engine.paid == "subscription" {
                "a subscription, and protect_subscriptions is on".to_string()
            } else {
                format!(
                    "taken for a subscription ({} CLI with no paid= set), and \
                     protect_subscriptions is on",
                    engine.name
                )
            });
        }
        None
    }

    /// Whether this agent, on this machine, may run the project's self-improve work.
    #[must_use]
    pub fn allows_machine(&self, agent: &str, machine: &str) -> bool {
        self.machines.is_empty()
            || self
                .machines
                .iter()
                .any(|m| m.eq_ignore_ascii_case(agent) || m.eq_ignore_ascii_case(machine))
    }

    #[must_use]
    pub fn cap(&self, role: Role) -> Option<f64> {
        self.caps_usd.get(role.as_str()).copied()
    }

    /// Never use `engine` for background work. Returns whether anything changed.
    pub fn block(&mut self, engine: &str) -> bool {
        let selector = format!("name:{}", engine.trim().to_ascii_lowercase());
        for list in self.prefer.values_mut() {
            list.retain(|s| !s.eq_ignore_ascii_case(&selector));
        }
        if self.never.iter().any(|s| s.eq_ignore_ascii_case(&selector)) {
            return false;
        }
        self.never.push(selector);
        true
    }

    /// Put `engine` first for every role, and lift any `never` naming it exactly.
    pub fn move_to_top(&mut self, engine: &str) {
        let selector = format!("name:{}", engine.trim().to_ascii_lowercase());
        self.never.retain(|s| !s.eq_ignore_ascii_case(&selector));
        for role in Role::ALL {
            let list = self.prefer.entry(role.as_str().to_string()).or_default();
            list.retain(|s| !s.eq_ignore_ascii_case(&selector));
            list.insert(0, selector.clone());
        }
    }

    /// The simple choice: `selector` first for improvement work - planning and building.
    pub fn set_improvement_engine(&mut self, selector: &str) {
        for role in [Role::Plan, Role::Build] {
            self.prefer
                .insert(role.as_str().to_string(), vec![selector.trim().to_string()]);
        }
    }

    /// The simple choice: `selector` first for review.
    pub fn set_review_engine(&mut self, selector: &str) {
        self.prefer.insert(
            Role::Review.as_str().to_string(),
            vec![selector.trim().to_string()],
        );
    }

    /// What does improvement work first, when the policy says.
    #[must_use]
    pub fn improvement_engine(&self) -> Option<&str> {
        self.preferences(Role::Build).first().map(String::as_str)
    }

    /// What reviews first, when the policy says.
    #[must_use]
    pub fn review_engine(&self) -> Option<&str> {
        self.preferences(Role::Review).first().map(String::as_str)
    }

    /// One line per part, as a person reads it.
    #[must_use]
    pub fn describe(&self) -> Vec<String> {
        let mut lines = Vec::new();
        for role in Role::ALL {
            let list = self.preferences(role);
            if !list.is_empty() {
                lines.push(format!(
                    "prefer for {}: {}",
                    role.as_str(),
                    list.join(" > ")
                ));
            }
        }
        if !self.never.is_empty() {
            lines.push(format!("never: {}", self.never.join(", ")));
        }
        lines.push(format!(
            "where: {}",
            if self.machines.is_empty() {
                "any worker".to_string()
            } else {
                self.machines.join(", ")
            }
        ));
        for (role, cap) in &self.caps_usd {
            lines.push(format!("{role} capped at ${cap:.2} a week"));
        }
        lines.push(format!(
            "subscriptions {} for background work",
            if self.protect_subscriptions {
                "protected"
            } else {
                "allowed"
            }
        ));
        if self.never_applies_to == NeverScope::All {
            lines.push("never applies to people's own orders too".to_string());
        }
        lines.push(
            match self.auto_merge {
                AutoMerge::None => "auto-merge: none - you merge every approved improvement",
                AutoMerge::LowRisk => {
                    "auto-merge: docs, tests and dependency bumps after both approvals"
                }
            }
            .to_string(),
        );
        lines
    }
}

fn check_selector(selector: &str) -> Result<()> {
    let trimmed = selector.trim();
    if trimmed.is_empty() || trimmed.chars().count() > SELECTOR_CHARS {
        bail!("a selector must be 1 to {SELECTOR_CHARS} characters");
    }
    if let Some(class) = trimmed.strip_prefix("paid:")
        && !matches!(
            normal_paid(class).as_str(),
            "subscription" | "prepaid" | "free-tier" | "local" | "unknown"
        )
    {
        bail!("paid:{class} names no paid class (subscription, prepaid, free-tier, local)");
    }
    Ok(())
}

fn normal_paid(class: &str) -> String {
    match class.trim().to_ascii_lowercase().as_str() {
        "free" | "freetier" | "free_tier" => "free-tier".to_string(),
        other => other.to_string(),
    }
}

// --- engines, as the policy sees them --------------------------------------------------

/// One engine on one worker, as the policy matches and ranks it. Built from a worker's
/// signed inventory line, so every machine ranks the fleet the same way.
#[derive(Debug, Clone, Default, PartialEq)]
pub struct Candidate {
    pub agent: String,
    pub machine: String,
    /// Its place in the operator's list on that worker.
    pub order: usize,
    pub name: String,
    pub model: Option<String>,
    /// `judge`, `build` or `chore`, as configured.
    pub tier: String,
    /// `subscription`, `prepaid`, `free-tier`, `local` or `unknown`, as configured.
    pub paid: String,
    pub host: Option<String>,
    /// A weekly cap bounds it.
    pub capped: bool,
    /// `up`, `down`, `exhausted` or `unknown`.
    pub state: String,
    /// When an exhausted engine is expected back.
    pub until: Option<DateTime<Utc>>,
    pub verified: u64,
    pub refuted: u64,
    pub demoted: bool,
    /// Dollars spent this week.
    pub spend_usd: f64,
    /// Why a free tier is flagged, while it is.
    pub flag: Option<String>,
    /// For a gateway engine (OmniRoute): the provider/models its route ends at. A
    /// selector that names any of them matches, so `never claude` holds through it.
    pub route: Vec<String>,
}

impl Candidate {
    #[must_use]
    pub fn from_report(agent: &str, machine: &str, order: usize, report: &EngineReport) -> Self {
        let trust = report.trust.clone().unwrap_or_default();
        let billing = report.billing.clone().unwrap_or_default();
        Self {
            agent: agent.to_string(),
            machine: machine.to_string(),
            order,
            name: report.name.clone(),
            model: report.model.clone(),
            tier: report.tier.clone(),
            paid: report.paid.clone(),
            host: billing.host,
            capped: billing.capped,
            state: report.state.clone(),
            until: report.until,
            verified: trust.verified,
            refuted: trust.refuted,
            demoted: trust.demoted,
            spend_usd: billing.spend_usd,
            flag: billing.flag,
            route: billing.route,
        }
    }

    /// How it is paid for, as the policy counts it: as configured - except that a
    /// `claude` or `codex` CLI with nothing configured is taken for the subscription it
    /// almost always is, so an unmarked Claude Code never quietly spends its limits in
    /// the background. Setting `paid` in agent.toml overrides this.
    #[must_use]
    pub fn paid_class(&self) -> &str {
        let unmarked_cli = self.paid == "unknown" && self.host.is_none();
        let name = self.name.to_ascii_lowercase();
        let model = self.model.as_deref().unwrap_or("").to_ascii_lowercase();
        if unmarked_cli
            && (name.starts_with("claude")
                || name.starts_with("codex")
                || model.starts_with("claude")
                || model.starts_with("anthropic/"))
        {
            return "subscription";
        }
        &self.paid
    }

    /// The tier it may work at now: chore while demoted.
    fn level(&self) -> u8 {
        if self.demoted {
            0
        } else {
            tier_level(&self.tier)
        }
    }

    fn usable(&self) -> bool {
        self.state != "exhausted"
    }

    fn trust_score(&self) -> Option<u64> {
        let decided = self.verified + self.refuted;
        (decided > 0).then(|| self.verified * 100 / decided)
    }

    fn cost_per_verified(&self) -> Option<f64> {
        (self.verified > 0 && self.spend_usd > 0.0).then(|| self.spend_usd / self.verified as f64)
    }

    /// `nemotron on grouchly`
    #[must_use]
    pub fn label(&self) -> String {
        format!("{} on {}", self.name, self.machine)
    }

    /// `free-tier, 12 verified, 0 refuted`
    #[must_use]
    pub fn facts(&self) -> String {
        let mut text = self.paid_class().to_string();
        if self.paid_class() == "prepaid" {
            text.push_str(if self.capped {
                " with a cap"
            } else {
                " with no cap"
            });
        }
        text.push_str(&format!(
            ", {} verified, {} refuted",
            self.verified, self.refuted
        ));
        if let Some(cost) = self.cost_per_verified() {
            text.push_str(&format!(", ${cost:.2} per verified result"));
        }
        if self.demoted {
            text.push_str(", demoted");
        }
        if let Some(flag) = &self.flag {
            text.push_str(&format!(", flagged: {flag}"));
        }
        text
    }
}

fn tier_level(tier: &str) -> u8 {
    match tier.trim().to_ascii_lowercase().as_str() {
        "chore" => 0,
        "judge" => 2,
        _ => 1,
    }
}

/// How auto mode ranks the way an engine is paid for, lowest first: local, free tier,
/// prepaid with a cap, unknown (and a free tier that asked for money), prepaid with no
/// cap, subscription.
#[must_use]
pub fn auto_rank(engine: &Candidate) -> u8 {
    match engine.paid_class() {
        "local" => 0,
        "free-tier" if engine.flag.is_none() => 1,
        "prepaid" if engine.capped => 2,
        "free-tier" | "unknown" => 3,
        "prepaid" => 4,
        _ => 5,
    }
}

// --- selectors ---------------------------------------------------------------------------

/// Whether a selector picks out this engine. Case never matters.
///
/// - `paid:free-tier` (also `paid:subscription`, `paid:prepaid`, `paid:local`,
///   `paid:unknown`): how it is paid for;
/// - `model:nvidia/nemotron*`: a model glob; `name:nemotron` (or `engine:`): the engine's
///   name in agent.toml, glob allowed; `host:deepseek.com` (or `provider:`): the endpoint
///   host or any subdomain of it;
/// - anything with `*`, `?` or `/` is a glob over the engine name and the model;
/// - a bare word matches an engine of that name, or one whose model or host contains it:
///   `claude` matches the `claude` engine and every `claude-*` model, `deepseek` matches
///   `api.deepseek.com`.
#[must_use]
pub fn matches(selector: &str, engine: &Candidate) -> bool {
    let selector = selector.trim().to_ascii_lowercase();
    let name = engine.name.to_ascii_lowercase();
    let model = engine.model.as_deref().unwrap_or("").to_ascii_lowercase();
    let host = engine.host.as_deref().unwrap_or("").to_ascii_lowercase();
    let (kind, pattern) = match selector.split_once(':') {
        Some((kind, rest))
            if matches!(
                kind,
                "paid" | "model" | "name" | "engine" | "host" | "provider"
            ) =>
        {
            (kind, rest.trim())
        }
        _ => ("", selector.as_str()),
    };
    if pattern.is_empty() {
        return false;
    }
    // A gateway's route: `cc/claude-sonnet-4-6`, `nvidia/nemotron-70b:free`.
    let route: Vec<String> = engine
        .route
        .iter()
        .map(|step| step.to_ascii_lowercase())
        .collect();
    let provider_of = |step: &String| step.split('/').next().unwrap_or_default().to_string();
    match kind {
        "paid" => normal_paid(pattern) == engine.paid_class(),
        "model" => {
            (!model.is_empty() && glob(pattern, &model))
                || route.iter().any(|step| glob(pattern, step))
        }
        "name" | "engine" => glob(pattern, &name),
        "host" | "provider" => {
            (!host.is_empty() && (glob(pattern, &host) || host.ends_with(&format!(".{pattern}"))))
                || route.iter().any(|step| provider_of(step) == pattern)
        }
        _ if pattern.contains(['*', '?', '/']) => {
            glob(pattern, &name)
                || (!model.is_empty() && glob(pattern, &model))
                || route.iter().any(|step| glob(pattern, step))
        }
        _ => {
            name == pattern
                || model.contains(pattern)
                || host.contains(pattern)
                || route.iter().any(|step| step.contains(pattern))
        }
    }
}

/// `*` any run of characters, `?` any one; everything else literal.
#[must_use]
pub fn glob(pattern: &str, text: &str) -> bool {
    let p: Vec<char> = pattern.chars().collect();
    let t: Vec<char> = text.chars().collect();
    let (mut pi, mut ti) = (0, 0);
    let mut star: Option<(usize, usize)> = None;
    while ti < t.len() {
        if pi < p.len() && (p[pi] == '?' || p[pi] == t[ti]) {
            pi += 1;
            ti += 1;
        } else if pi < p.len() && p[pi] == '*' {
            star = Some((pi, ti));
            pi += 1;
        } else if let Some((star_p, star_t)) = star {
            pi = star_p + 1;
            ti = star_t + 1;
            star = Some((star_p, star_t + 1));
        } else {
            return false;
        }
    }
    p[pi..].iter().all(|c| *c == '*')
}

// --- ranking -----------------------------------------------------------------------------

/// Every engine, sorted for one role: the ones that may do it now, the ones that may but
/// are out of credit, and the ones the policy blocks.
#[derive(Debug, Clone, Default, PartialEq)]
pub struct Ranking {
    /// Indexes into the engines given, best first: allowed, able to do the role, usable.
    pub order: Vec<usize>,
    /// Allowed and able, but exhausted until a reset, with the reason.
    pub out: Vec<(usize, String)>,
    /// Blocked by the policy, with the reason.
    pub blocked: Vec<(usize, String)>,
}

impl Ranking {
    /// Why nothing can do the work, for a hold.
    #[must_use]
    pub fn why_none(&self, role: Role, engines: &[Candidate]) -> String {
        let mut parts: Vec<String> = Vec::new();
        for (index, why) in self.out.iter().chain(&self.blocked) {
            parts.push(format!("{} {why}", engines[*index].label()));
        }
        if parts.is_empty() {
            format!("no engine able to do {} work is known", role.as_str())
        } else {
            format!(
                "no allowed engine can do {} work now - {}",
                role.as_str(),
                parts.join("; ")
            )
        }
    }
}

/// How far an engine at `level` is from the work, `None` when it cannot do it.
fn fit(role: Role, wanted: u8, level: u8) -> Option<u8> {
    match role {
        // Review is a judge's work, and only a judge's.
        Role::Review => (level == 2).then_some(0),
        // A judge plans; a builder plans only when no judge can, marked unreviewed.
        Role::Plan => (level >= 1).then(|| 2 - level),
        // Never below the tier; the nearest tier first, so a judge builds last.
        Role::Build | Role::Chore => (level >= wanted).then(|| level - wanted),
    }
}

/// Rank `engines` for `role` at the order's `tier` under `policy`.
///
/// Blocked engines (`never`, subscriptions while protected, a machine outside `where`)
/// are set aside. The rest are grouped by the role's preference list - listed engines in
/// the listed order, then the unlisted in auto order - and within a group by the rules
/// engines always followed: the nearest tier, an engine that answered its probe before
/// one that did not, better trust, cheaper per verified result, then the operator's
/// order.
#[must_use]
pub fn rank(policy: &Policy, role: Role, tier: &str, work: Work, engines: &[Candidate]) -> Ranking {
    let wanted = tier_level(tier);
    let listed = policy.preferences(role).len();
    let mut ranking = Ranking::default();
    let mut keyed = Vec::new();
    for (index, engine) in engines.iter().enumerate() {
        let Some(distance) = fit(role, wanted, engine.level()) else {
            continue;
        };
        if work == Work::Background && !policy.allows_machine(&engine.agent, &engine.machine) {
            ranking.blocked.push((
                index,
                format!("is not in where ({})", policy.machines.join(", ")),
            ));
            continue;
        }
        if let Some(why) = policy.blocked(engine, work) {
            ranking.blocked.push((index, why));
            continue;
        }
        if !engine.usable() {
            ranking.out.push((
                index,
                match engine.until {
                    Some(until) => format!("is out until {}", until.format("%a %H:%M UTC")),
                    None => "is out of credit".to_string(),
                },
            ));
            continue;
        }
        // A plan a judge wrote needs no second reading, so among engines the operator
        // ranked alike a judge plans first, whatever it costs.
        let group = if work == Work::Background {
            (
                policy.preference(role, engine).unwrap_or(listed),
                if role == Role::Plan { distance } else { 0 },
                auto_rank(engine),
            )
        } else {
            (0, 0, 0)
        };
        let key = (
            group,
            distance,
            engine.state == "down",
            std::cmp::Reverse(engine.trust_score().unwrap_or(50)),
            // Cents per verified result; unknown sorts after known.
            engine
                .cost_per_verified()
                .map_or(u64::MAX, |cost| (cost * 100.0) as u64),
            engine.order,
        );
        keyed.push((key, index));
    }
    keyed.sort();
    ranking.order = keyed.into_iter().map(|(_, index)| index).collect();
    ranking
}

/// The policy as it falls on the fleet: per role, who does the work in which order and
/// who is out of credit; and every engine the policy blocks, with why. For the
/// dashboard and `--json`.
#[must_use]
pub fn view(policy: &Policy, engines: &[Candidate]) -> serde_json::Value {
    let describe = |engine: &Candidate| {
        serde_json::json!({
            "engine": engine.name,
            "agent": engine.agent,
            "machine": engine.machine,
            "model": engine.model,
            "paid": engine.paid_class(),
            "facts": engine.facts(),
        })
    };
    let mut roles = serde_json::Map::new();
    let mut blocked: Vec<serde_json::Value> = Vec::new();
    let mut seen = BTreeSet::new();
    for role in Role::ALL {
        let ranking = rank(policy, role, role.tier(), Work::Background, engines);
        roles.insert(
            role.as_str().to_string(),
            serde_json::json!({
                "order": ranking.order.iter().map(|i| describe(&engines[*i])).collect::<Vec<_>>(),
                "out": ranking.out.iter().map(|(i, why)| {
                    let mut line = describe(&engines[*i]);
                    line["why"] = serde_json::json!(why);
                    line
                }).collect::<Vec<_>>(),
            }),
        );
        for (index, why) in ranking.blocked {
            if seen.insert(engines[index].label()) {
                let mut line = describe(&engines[index]);
                line["why"] = serde_json::json!(why);
                blocked.push(line);
            }
        }
    }
    serde_json::json!({ "roles": roles, "blocked": blocked })
}

/// What a person picks from: every engine the fleet published that can improve (plan
/// and build) or review, once each by name, with how it is paid for, the machines it is
/// on, whether the policy blocks it, and whether it is what auto recommends. The value
/// to set is the selector `name:<engine>`.
#[must_use]
pub fn choices(policy: &Policy, engines: &[Candidate], recommended: &Policy) -> serde_json::Value {
    let option = |engine: &Candidate, recommend: Option<&str>| {
        let selector = format!("name:{}", engine.name.to_ascii_lowercase());
        let machines: Vec<String> = engines
            .iter()
            .filter(|other| other.name.eq_ignore_ascii_case(&engine.name))
            .map(|other| other.machine.clone())
            .collect();
        serde_json::json!({
            "selector": selector,
            "label": label(engine),
            "paid": engine.paid_class(),
            "machines": machines,
            "blocked": policy.blocked(engine, Work::Background),
            "recommended": recommend.is_some_and(|chosen| chosen.eq_ignore_ascii_case(&selector)),
        })
    };
    let mut improve = Vec::new();
    let mut review = Vec::new();
    let mut seen = BTreeSet::new();
    for engine in engines {
        if !seen.insert(engine.name.to_ascii_lowercase()) {
            continue;
        }
        if engine.level() >= 1 {
            improve.push(option(engine, recommended.improvement_engine()));
        }
        if engine.level() == 2 {
            review.push(option(engine, recommended.review_engine()));
        }
    }
    serde_json::json!({
        "improve": improve,
        "review": review,
        "current": { "improve": policy.improvement_engine(), "review": policy.review_engine() },
        "recommended": {
            "improve": recommended.improvement_engine(),
            "review": recommended.review_engine(),
        },
    })
}

/// How a person reads an engine: `nemotron (nvidia/nemotron-70b)`, or for a gateway
/// route `OmniRoute: free-stack`.
#[must_use]
pub fn label(engine: &Candidate) -> String {
    match (&engine.model, engine.route.is_empty()) {
        (Some(model), false) => format!("OmniRoute: {model}"),
        (Some(model), true) => format!("{} ({model})", engine.name),
        (None, _) => engine.name.clone(),
    }
}

/// [`view`] as lines a person reads: one per role, one per blocked engine.
#[must_use]
pub fn summary(policy: &Policy, engines: &[Candidate]) -> Vec<String> {
    let mut lines = Vec::new();
    let mut blocked: Vec<String> = Vec::new();
    for role in Role::ALL {
        let ranking = rank(policy, role, role.tier(), Work::Background, engines);
        let order: Vec<String> = ranking
            .order
            .iter()
            .map(|index| engines[*index].label())
            .collect();
        let mut line = format!(
            "{:<7}{}",
            role.as_str(),
            if order.is_empty() {
                "nothing allowed can do it now - it waits".to_string()
            } else {
                order.join(" > ")
            }
        );
        if !ranking.out.is_empty() {
            let out: Vec<String> = ranking
                .out
                .iter()
                .map(|(index, why)| format!("{} {why}", engines[*index].label()))
                .collect();
            line.push_str(&format!(" (also allowed: {})", out.join(", ")));
        }
        lines.push(line);
        for (index, why) in ranking.blocked {
            let text = format!("blocked {}: {why}", engines[index].label());
            if !blocked.contains(&text) {
                blocked.push(text);
            }
        }
    }
    lines.extend(blocked);
    lines
}

// --- auto: the policy the fleet would choose ---------------------------------------------

/// A proposed policy, with one line of reason per choice.
#[derive(Debug, Clone, PartialEq)]
pub struct Recommendation {
    pub policy: Policy,
    pub reasons: Vec<String>,
}

fn ordinal(rank: usize) -> String {
    match rank {
        0 => "first".to_string(),
        1 => "second".to_string(),
        2 => "third".to_string(),
        n => format!("#{}", n + 1),
    }
}

/// What auto mode would choose, from the engines the fleet published and the workers
/// that are online now.
///
/// For each role the allowed engines in auto order - local, free tier, capped prepaid,
/// unknown, uncapped prepaid; subscriptions never while protected - with ties broken by
/// trust, then cost per verified result, then the operator's order; plan and review
/// prefer a judge-tier engine. An engine that is out of credit today still has its
/// place: the recommendation is a standing order, not today's weather. `where` is the
/// workers online now and not paused.
#[must_use]
pub fn recommend(engines: &[Candidate], online: &[String]) -> Recommendation {
    // One entry per engine name: the same engine on two machines is one choice, and its
    // record is the two machines' together.
    let mut merged: Vec<Candidate> = Vec::new();
    for engine in engines {
        match merged
            .iter_mut()
            .find(|seen| seen.name.eq_ignore_ascii_case(&engine.name))
        {
            Some(seen) => {
                seen.verified += engine.verified;
                seen.refuted += engine.refuted;
                seen.spend_usd += engine.spend_usd;
                seen.demoted &= engine.demoted;
                seen.flag = seen.flag.take().or_else(|| engine.flag.clone());
                seen.capped &= engine.capped;
            }
            None => {
                let mut first = engine.clone();
                first.state = "up".to_string();
                first.until = None;
                merged.push(first);
            }
        }
    }
    let base = Policy::default();
    let mut policy = Policy::default();
    let mut reasons = Vec::new();
    for role in Role::ALL {
        let ranking = rank(&base, role, role.tier(), Work::Background, &merged);
        let list: Vec<String> = ranking
            .order
            .iter()
            .map(|index| format!("name:{}", merged[*index].name.to_ascii_lowercase()))
            .collect();
        for (place, index) in ranking.order.iter().enumerate() {
            let engine = &merged[*index];
            let judge = if matches!(role, Role::Plan | Role::Review) && engine.tier == "judge" {
                "judge tier, "
            } else {
                ""
            };
            reasons.push(format!(
                "{} {} for {}: {judge}{}",
                engine.name,
                ordinal(place),
                role.as_str(),
                engine.facts()
            ));
        }
        if list.is_empty() {
            reasons.push(format!(
                "nothing for {}: no allowed engine can do it, so it would wait",
                role.as_str()
            ));
        } else {
            policy.prefer.insert(role.as_str().to_string(), list);
        }
    }
    let mut blocked = BTreeSet::new();
    for engine in &merged {
        if let Some(why) = base.blocked(engine, Work::Background)
            && blocked.insert(engine.name.to_ascii_lowercase())
        {
            reasons.push(format!("{} never for background work: {why}", engine.name));
        }
    }
    let mut machines: Vec<String> = Vec::new();
    for agent in online {
        if !machines.iter().any(|m| m.eq_ignore_ascii_case(agent)) {
            machines.push(agent.clone());
        }
    }
    if machines.is_empty() {
        reasons.push("where: any worker (none is online now to choose from)".to_string());
    } else {
        reasons.push(format!(
            "where: {} - online now and not paused",
            machines.join(", ")
        ));
    }
    policy.machines = machines;
    Recommendation { policy, reasons }
}

/// Every engine the fleet published into this channel: valid, signed inventories no
/// older than [`INVENTORY_FRESH_HOURS`].
#[must_use]
pub fn fleet(route: &ProjectRoute, now: DateTime<Utc>) -> Vec<Candidate> {
    let mut out = Vec::new();
    for (inventory, check) in crate::receipts::list_engines(route).unwrap_or_default() {
        if check != SignatureCheck::Valid
            || now.signed_duration_since(inventory.updated_at)
                > Duration::hours(INVENTORY_FRESH_HOURS)
        {
            continue;
        }
        for (order, report) in inventory.engines.iter().enumerate() {
            out.push(Candidate::from_report(
                &inventory.agent,
                &inventory.machine,
                order,
                report,
            ));
        }
    }
    out
}

/// Workers seen lately in this channel and not paused: the machines that are on.
#[must_use]
pub fn online(route: &ProjectRoute, now: DateTime<Utc>) -> Vec<String> {
    crate::receipts::list_presence(route)
        .unwrap_or_default()
        .into_iter()
        .filter(|(presence, check)| {
            *check == SignatureCheck::Valid
                && !presence.paused
                && now.signed_duration_since(presence.seen_at)
                    <= Duration::seconds(PRESENCE_ABSENT_AFTER_SECS)
        })
        .map(|(presence, _)| presence.agent)
        .collect()
}

/// The recommendation for one project, from its channel.
#[must_use]
pub fn recommend_for(route: &ProjectRoute, now: DateTime<Utc>) -> Recommendation {
    recommend(&fleet(route, now), &online(route, now))
}

// --- the master's signed setting ---------------------------------------------------------

/// What the [`ENGINE_POLICY`] file holds.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct PolicySetting {
    pub project_id: String,
    /// `None`: the master chose auto.
    #[serde(default)]
    pub policy: Option<Policy>,
    pub set_at: DateTime<Utc>,
    pub signed_by: String,
    pub signature: String,
    /// Whose policy this is, when a delegate signed it. Honoured only under a valid
    /// `improve` delegation from the master.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub on_behalf_of: Option<String>,
}

impl PolicySetting {
    /// `josh`, or `josh via telegram-grouchly`.
    #[must_use]
    pub fn set_by(&self) -> String {
        match &self.on_behalf_of {
            Some(principal) => crate::delegation::label(principal, &self.signed_by),
            None => self.signed_by.clone(),
        }
    }
}

/// Exactly what the signature covers: the project, when, the whole policy in canonical
/// JSON, and for a delegate the principal.
fn setting_payload(setting: &PolicySetting) -> String {
    let mut payload = format!(
        "ferryman-engine-policy-v1\n{}\n{}\n{}",
        setting.project_id,
        setting.set_at.to_rfc3339(),
        serde_jcs::to_string(&setting.policy).unwrap_or_default()
    );
    if let Some(principal) = &setting.on_behalf_of {
        payload.push_str(&format!("\nfor:{principal}"));
    }
    payload
}

/// The master's engine policy setting for the project in `channel`, when there is one
/// and it verifies. Anything else is `None`, which means auto.
#[must_use]
pub fn setting(channel: &Path, project_id: &str) -> Option<PolicySetting> {
    let setting: PolicySetting =
        serde_json::from_slice(&std::fs::read(channel.join(ENGINE_POLICY)).ok()?).ok()?;
    let roster = crate::read_agent_roster(channel).ok()?;
    let master = crate::master::read_master_at(channel, &roster).ok()??;
    let principal = setting
        .on_behalf_of
        .clone()
        .unwrap_or_else(|| setting.signed_by.clone());
    (setting.project_id == project_id
        && master.project_id == project_id
        && principal.eq_ignore_ascii_case(&master.master)
        && setting
            .policy
            .as_ref()
            .is_none_or(|policy| policy.check().is_ok())
        && crate::delegation::authority(
            channel,
            project_id,
            &principal,
            &setting.signed_by,
            crate::delegation::IMPROVE,
            Utc::now(),
        )
        .allowed()
        && crate::check_signature(
            Some(&setting.signed_by),
            Some(&setting.signature),
            &setting_payload(&setting),
            &roster,
        ) == SignatureCheck::Valid)
        .then_some(setting)
}

/// The policy in force for a project: the master's, or auto's defaults when they set
/// none, chose auto, or the file does not verify. With the setting, when there is one.
#[must_use]
pub fn effective(channel: &Path, project_id: &str) -> (Policy, Option<PolicySetting>) {
    let setting = setting(channel, project_id);
    (
        setting
            .as_ref()
            .and_then(|setting| setting.policy.clone())
            .unwrap_or_default(),
        setting,
    )
}

/// Whether the master has set a policy of their own (not auto) for the project.
#[must_use]
pub fn is_set(channel: &Path, project_id: &str) -> bool {
    setting(channel, project_id).is_some_and(|setting| setting.policy.is_some())
}

/// Set the project's engine policy, signed by its master. `None` goes back to auto.
/// Returns whether anything changed.
pub fn set_policy(
    channel: &Path,
    project_id: &str,
    policy: Option<Policy>,
    signer: &AgentIdentity,
) -> Result<bool> {
    set_policy_as(channel, project_id, policy, signer, None)
}

/// [`set_policy`], signed by a delegate for `on_behalf_of`, who must be the master and
/// must have delegated `improve` to the signer. `None` is the signer's own.
pub fn set_policy_as(
    channel: &Path,
    project_id: &str,
    policy: Option<Policy>,
    signer: &AgentIdentity,
    on_behalf_of: Option<&str>,
) -> Result<bool> {
    if !channel.is_dir() {
        bail!(
            "{project_id}'s channel is not on this machine ({})",
            channel.display()
        );
    }
    if let Some(policy) = &policy {
        policy.check()?;
    }
    let on_behalf_of =
        on_behalf_of.filter(|principal| !principal.eq_ignore_ascii_case(signer.name()));
    match on_behalf_of {
        None => crate::ferry::require_master(channel, project_id, signer, "set the engine policy")?,
        Some(principal) => {
            let Some(master) = crate::ferry::master_of(channel)? else {
                bail!("{project_id} has no master, and only its master sets the engine policy");
            };
            if !principal.eq_ignore_ascii_case(&master) {
                bail!(
                    "only {master}, {project_id}'s master, sets the engine policy - not {principal}"
                );
            }
            if let crate::delegation::Authority::Refused(why) = crate::delegation::authority(
                channel,
                project_id,
                principal,
                signer.name(),
                crate::delegation::IMPROVE,
                Utc::now(),
            ) {
                bail!(
                    "{} cannot set the engine policy for {principal}: {why}",
                    signer.name()
                );
            }
        }
    }
    if setting(channel, project_id).is_some_and(|existing| existing.policy == policy) {
        return Ok(false);
    }
    let mut setting = PolicySetting {
        project_id: project_id.to_owned(),
        policy,
        set_at: Utc::now(),
        signed_by: signer.name().to_owned(),
        signature: String::new(),
        on_behalf_of: on_behalf_of.map(str::to_owned),
    };
    setting.signature = signer.sign_bytes(setting_payload(&setting).as_bytes());
    let path = channel.join(ENGINE_POLICY);
    crate::atomic_json(&path, &setting).with_context(|| format!("writing {}", path.display()))?;
    Ok(true)
}

// --- who did each step --------------------------------------------------------------------

/// One improve step, as the agent that did it records it.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct Step {
    /// `gather`, `plan`, `review` or `build`.
    pub step: String,
    /// The policy role it was done under, when it used an engine.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub role: Option<String>,
    pub at: DateTime<Utc>,
    pub agent: String,
    pub machine: String,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub engine: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub model: Option<String>,
    /// Dollars, where known: what the provider reported, else list prices.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub cost_usd: Option<f64>,
    /// The improvement order, for a build.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub order: Option<String>,
    /// `done`, or what happened instead: `held: ...`, `failed: ...`.
    pub outcome: String,
}

impl Step {
    /// `plan: nemotron (nvidia/nemotron-70b) on grouchly, $0.00 - done`
    #[must_use]
    pub fn describe(&self) -> String {
        let what = match &self.order {
            Some(order) => format!("{} {order}", self.step),
            None => self.step.clone(),
        };
        let engine = match (&self.engine, &self.model) {
            (Some(engine), Some(model)) => format!("{engine} ({model})"),
            (Some(engine), None) => engine.clone(),
            _ => "no engine".to_string(),
        };
        let cost = self
            .cost_usd
            .map(|cost| format!(", ${cost:.2}"))
            .unwrap_or_default();
        format!(
            "{what}: {engine} on {} ({}){cost} - {}",
            self.machine, self.agent, self.outcome
        )
    }
}

/// One agent's step records for one week, signed by that agent. One writer per file.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct StepLog {
    pub agent: String,
    pub week: String,
    #[serde(default)]
    pub steps: Vec<Step>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub signed_by: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub signature: Option<String>,
}

fn steps_payload(log: &StepLog) -> String {
    format!(
        "ferryman-improve-steps-v1\n{}\n{}\n{}",
        log.agent,
        log.week,
        serde_jcs::to_string(&log.steps).unwrap_or_default()
    )
}

fn steps_dir(route: &ProjectRoute, week: &str) -> std::path::PathBuf {
    route
        .communications
        .join("improve")
        .join(week)
        .join("steps")
}

/// Add a step to this agent's signed record for `week`.
pub fn record_step(
    route: &ProjectRoute,
    identity: &AgentIdentity,
    week: &str,
    step: Step,
) -> Result<()> {
    let agent = identity.name();
    if !crate::is_safe_component(agent) || !crate::is_safe_component(week) {
        bail!("agent and week must be path-safe");
    }
    let path = steps_dir(route, week).join(format!("{agent}.json"));
    let mut log = std::fs::read(&path)
        .ok()
        .and_then(|bytes| serde_json::from_slice::<StepLog>(&bytes).ok())
        .filter(|log| log.agent.eq_ignore_ascii_case(agent) && log.week == week)
        .unwrap_or(StepLog {
            agent: agent.to_string(),
            week: week.to_string(),
            steps: Vec::new(),
            signed_by: None,
            signature: None,
        });
    log.steps.push(step);
    if log.steps.len() > KEEP_STEPS {
        let excess = log.steps.len() - KEEP_STEPS;
        log.steps.drain(..excess);
    }
    log.signed_by = Some(agent.to_string());
    log.signature = Some(identity.sign_bytes(steps_payload(&log).as_bytes()));
    crate::atomic_json(&path, &log).with_context(|| format!("writing {}", path.display()))
}

/// Every step recorded for `week` whose log verifies as its agent's, oldest first.
#[must_use]
pub fn read_steps(route: &ProjectRoute, week: &str) -> Vec<Step> {
    let Ok(entries) = std::fs::read_dir(steps_dir(route, week)) else {
        return Vec::new();
    };
    let mut steps: Vec<Step> = entries
        .flatten()
        .map(|entry| entry.path())
        .filter(|path| {
            path.extension()
                .is_some_and(|ext| ext.eq_ignore_ascii_case("json"))
        })
        .filter_map(|path| std::fs::read(path).ok())
        .filter_map(|bytes| serde_json::from_slice::<StepLog>(&bytes).ok())
        .filter(|log| {
            log.week == week
                && log
                    .signed_by
                    .as_deref()
                    .is_some_and(|signer| signer.eq_ignore_ascii_case(&log.agent))
                && crate::check_signature(
                    log.signed_by.as_ref(),
                    log.signature.as_ref(),
                    &steps_payload(log),
                    &route.agents,
                ) == SignatureCheck::Valid
        })
        .flat_map(|log| {
            let agent = log.agent.clone();
            // A step is the signing agent's statement about itself.
            log.steps
                .into_iter()
                .filter(move |step| step.agent.eq_ignore_ascii_case(&agent))
        })
        .collect();
    steps.sort_by_key(|step| step.at);
    steps
}

/// The newest record of each step (and of each order's build) in `week`.
#[must_use]
pub fn latest_steps(route: &ProjectRoute, week: &str) -> Vec<Step> {
    let mut latest: BTreeMap<(String, String), Step> = BTreeMap::new();
    for step in read_steps(route, week) {
        latest.insert(
            (step.step.clone(), step.order.clone().unwrap_or_default()),
            step,
        );
    }
    let mut out: Vec<Step> = latest.into_values().collect();
    out.sort_by_key(|step| step.at);
    out
}

/// What the fleet spent on one role in `week`, from the signed step records.
#[must_use]
pub fn role_spend(route: &ProjectRoute, week: &str, role: Role) -> f64 {
    read_steps(route, week)
        .iter()
        .filter(|step| step.role.as_deref() == Some(role.as_str()))
        .filter_map(|step| step.cost_usd)
        .sum()
}

/// Why a role's weekly cap stops more of its work, or `None` when it does not.
#[must_use]
pub fn over_cap(route: &ProjectRoute, policy: &Policy, week: &str, role: Role) -> Option<String> {
    let cap = policy.cap(role)?;
    let spent = role_spend(route, week, role);
    (spent >= cap).then(|| {
        format!(
            "the {} cap of ${cap:.2} a week is spent (${spent:.2})",
            role.as_str()
        )
    })
}

// --- asking the master --------------------------------------------------------------------

/// Ask the master what to do about held background work: once per role per week,
/// however many machines and hours it stays held. Returns whether it was asked now.
pub fn ask_hold(
    route: &ProjectRoute,
    identity: &AgentIdentity,
    role: Role,
    week: &str,
    why: &str,
) -> Result<bool> {
    crate::questions::ask(
        route,
        identity,
        &format!(
            "engine-hold-{}-{}",
            role.as_str(),
            week.to_ascii_lowercase()
        ),
        crate::questions::POLICY,
        &format!(
            "Self-improve {} work in {} is on hold: {why}.\n\nNothing fell back to an engine \
             the policy blocks. Accept the recommended engine policy, change it (dashboard \
             Teammates page, or Engines on the phone), or keep holding.",
            role.as_str(),
            route.project_id
        ),
        &[ACCEPT_RECOMMENDED.to_string(), KEEP_HOLDING.to_string()],
        None,
    )
}

/// Tell the master a free-tier engine asked for money: once per engine per week. Auto
/// mode already ranks it down; blocking it is their call. Returns whether it was asked.
pub fn ask_free_tier(
    route: &ProjectRoute,
    identity: &AgentIdentity,
    engine: &str,
    week: &str,
    why: &str,
) -> Result<bool> {
    crate::questions::ask(
        route,
        identity,
        &format!(
            "free-tier-{}-{}",
            engine.to_ascii_lowercase(),
            week.to_ascii_lowercase()
        ),
        crate::questions::POLICY,
        &format!(
            "{engine} is marked free-tier, but on {} it {why}. It may no longer be free. \
             Auto mode now ranks it after paid engines with a cap; block it for background \
             work, or keep using it.",
            identity.name()
        ),
        &[format!("Block {engine}"), "Keep using it".to_string()],
        None,
    )
}

/// What an answer to a policy question asks to change, applied to `policy`: accept
/// the recommendation, or block an engine. `None` when the answer changes nothing.
#[must_use]
pub fn answer_changes(answer: &str, policy: &Policy, recommended: &Policy) -> Option<Policy> {
    if answer.eq_ignore_ascii_case(ACCEPT_RECOMMENDED) {
        return Some(recommended.clone());
    }
    let engine = answer.strip_prefix("Block ")?.trim();
    let mut changed = policy.clone();
    changed.block(engine).then_some(changed)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::AgentRoute;

    fn person(name: &str, seed: u8) -> AgentIdentity {
        AgentIdentity::from_seed(name, [seed; 32])
    }

    /// A channel whose master is `members[0]`, every member on its roster.
    fn route(dir: &Path, members: &[&AgentIdentity]) -> ProjectRoute {
        let communications = dir.join("demo-ferryman");
        std::fs::create_dir_all(&communications).unwrap();
        let mut route = ProjectRoute {
            project_id: "demo".into(),
            workspace: dir.join("demo"),
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

    fn engine(name: &str, tier: &str, paid: &str) -> Candidate {
        Candidate {
            agent: "grouchly".into(),
            machine: "grouchly".into(),
            name: name.into(),
            tier: tier.into(),
            paid: paid.into(),
            state: "up".into(),
            ..Candidate::default()
        }
    }

    fn names(ranking: &Ranking, engines: &[Candidate]) -> Vec<String> {
        ranking
            .order
            .iter()
            .map(|index| engines[*index].name.clone())
            .collect()
    }

    #[test]
    fn selectors_match_by_name_model_glob_paid_class_and_host() {
        let mut nemotron = engine("nvidia", "build", "free-tier");
        nemotron.model = Some("nvidia/llama-3.1-nemotron-70b-instruct".into());
        nemotron.host = Some("integrate.api.nvidia.com".into());
        let mut deepseek = engine("deepseek", "build", "prepaid");
        deepseek.model = Some("deepseek-chat".into());
        deepseek.host = Some("api.deepseek.com".into());
        let claude = engine("claude", "judge", "unknown");

        assert!(matches("nvidia/*nemotron*", &nemotron), "a model glob");
        assert!(matches("model:NVIDIA/*", &nemotron), "case never matters");
        assert!(!matches("model:nvidia/*", &deepseek));
        assert!(
            matches("nemotron", &nemotron),
            "a bare word inside the model"
        );
        assert!(matches("paid:free-tier", &nemotron));
        assert!(matches("paid:free", &nemotron), "free is free-tier");
        assert!(!matches("paid:free-tier", &deepseek));
        assert!(matches("host:deepseek.com", &deepseek), "a subdomain");
        assert!(matches("provider:api.deepseek.com", &deepseek));
        assert!(!matches("host:nvidia.com", &deepseek));
        assert!(matches("deepseek", &deepseek), "a bare word in the host");
        assert!(matches("name:deep*", &deepseek));
        assert!(matches("claude", &claude), "a bare word is the engine name");
        assert!(
            matches("paid:subscription", &claude),
            "an unmarked claude CLI is taken for a subscription"
        );
        assert!(!matches("claude", &deepseek));
        assert!(!matches("", &deepseek));
        assert!(!matches("name:", &deepseek));
        assert!(glob("a*c?e", "abbbcde") && !glob("a*c?e", "abce"));
    }

    #[test]
    fn auto_ranks_local_then_free_then_capped_prepaid_and_never_a_subscription() {
        let mut capped = engine("deepseek", "build", "prepaid");
        capped.capped = true;
        let engines = vec![
            engine("claude", "build", "subscription"),
            engine("uncapped", "build", "prepaid"),
            engine("mystery", "build", "unknown"),
            capped,
            engine("nemotron", "build", "free-tier"),
            engine("ollama", "build", "local"),
        ];
        let ranking = rank(
            &Policy::default(),
            Role::Build,
            "build",
            Work::Background,
            &engines,
        );
        assert_eq!(
            names(&ranking, &engines),
            ["ollama", "nemotron", "deepseek", "mystery", "uncapped"]
        );
        assert_eq!(ranking.blocked.len(), 1);
        assert_eq!(engines[ranking.blocked[0].0].name, "claude");
        assert!(ranking.blocked[0].1.contains("subscription"));

        // A person's own order is theirs to spend on.
        let direct = rank(
            &Policy::default(),
            Role::Build,
            "build",
            Work::Direct,
            &engines,
        );
        assert!(direct.blocked.is_empty());
        assert_eq!(direct.order[0], 0, "operator order for direct work");

        // With protection off, a subscription is allowed, last.
        let open = Policy {
            protect_subscriptions: false,
            ..Policy::default()
        };
        let ranking = rank(&open, Role::Build, "build", Work::Background, &engines);
        assert_eq!(names(&ranking, &engines).last().unwrap(), "claude");
    }

    #[test]
    fn ties_break_on_trust_then_cost_per_verified_then_operator_order() {
        let mut a = engine("a", "build", "free-tier");
        a.verified = 3;
        a.refuted = 3;
        let mut b = engine("b", "build", "free-tier");
        b.verified = 9;
        b.refuted = 1;
        b.order = 1;
        let mut c = engine("c", "build", "free-tier");
        c.verified = 9;
        c.refuted = 1;
        c.spend_usd = 0.9;
        c.order = 2;
        let mut d = engine("d", "build", "free-tier");
        d.verified = 9;
        d.refuted = 1;
        d.spend_usd = 0.1;
        d.order = 3;
        let mut demoted = engine("e", "build", "local");
        demoted.demoted = true;
        let engines = vec![a, b, c, d, demoted];
        let ranking = rank(
            &Policy::default(),
            Role::Build,
            "build",
            Work::Background,
            &engines,
        );
        assert_eq!(
            names(&ranking, &engines),
            ["d", "c", "b", "a"],
            "trust first; among equals the cheaper verified result; a demoted engine \
             takes no build work"
        );
    }

    #[test]
    fn a_free_tier_that_asked_for_money_is_ranked_down() {
        let mut flagged = engine("nemotron", "build", "free-tier");
        flagged.flag = Some("returned HTTP 402".into());
        let mut capped = engine("deepseek", "build", "prepaid");
        capped.capped = true;
        let engines = vec![flagged, capped];
        let ranking = rank(
            &Policy::default(),
            Role::Build,
            "build",
            Work::Background,
            &engines,
        );
        assert_eq!(names(&ranking, &engines), ["deepseek", "nemotron"]);
    }

    #[test]
    fn preferences_order_first_and_never_is_never_for_background_work() {
        let mut nemotron = engine("nvidia", "build", "free-tier");
        nemotron.model = Some("nvidia/nemotron-70b".into());
        let mut deepseek = engine("deepseek", "judge", "prepaid");
        deepseek.host = Some("api.deepseek.com".into());
        let engines = vec![
            engine("claude", "judge", "prepaid"),
            deepseek,
            nemotron,
            engine("ollama", "build", "local"),
        ];
        let mut policy = Policy {
            never: vec!["claude".into()],
            ..Policy::default()
        };
        for role in Role::ALL {
            policy.prefer.insert(
                role.as_str().into(),
                vec!["nvidia/nemotron*".into(), "deepseek".into()],
            );
        }
        let build = rank(&policy, Role::Build, "build", Work::Background, &engines);
        assert_eq!(names(&build, &engines), ["nvidia", "deepseek", "ollama"]);
        assert!(
            build
                .blocked
                .iter()
                .any(|(i, why)| *i == 0 && why.contains("never"))
        );
        // Planning follows the list too: the operator chose nemotron to plan.
        let plan = rank(&policy, Role::Plan, "judge", Work::Background, &engines);
        assert_eq!(names(&plan, &engines)[0], "nvidia");
        // Review is a judge's: only deepseek can.
        let review = rank(&policy, Role::Review, "judge", Work::Background, &engines);
        assert_eq!(names(&review, &engines), ["deepseek"]);

        // `never` leaves a person's own order alone unless it says "all".
        let direct = rank(&policy, Role::Build, "build", Work::Direct, &engines);
        assert!(direct.order.contains(&0));
        policy.never_applies_to = NeverScope::All;
        let direct = rank(&policy, Role::Build, "build", Work::Direct, &engines);
        assert!(!direct.order.contains(&0));

        // Everything blocked or out: nothing, and why.
        let only_claude = vec![engines[0].clone()];
        let none = rank(
            &policy,
            Role::Build,
            "build",
            Work::Background,
            &only_claude,
        );
        assert!(none.order.is_empty());
        assert!(
            none.why_none(Role::Build, &only_claude)
                .contains("claude on grouchly never")
        );
    }

    /// Claude reached through OmniRoute is still Claude: `never claude` and subscription
    /// protection see through the gateway to the route it ends at.
    #[test]
    fn never_and_protection_see_through_a_gateway_route() {
        let gateway = |name: &str, paid: &str, model: &str, route: &[&str]| {
            let mut engine = engine(name, "build", paid);
            engine.model = Some(model.into());
            engine.host = Some("localhost".into());
            engine.route = route.iter().map(ToString::to_string).collect();
            engine
        };
        let engines = vec![
            gateway(
                "omniroute.claude-first",
                "subscription",
                "claude-first",
                &["cc/claude-sonnet-4-6", "nvidia/nemotron-70b:free"],
            ),
            gateway(
                "omniroute.free-stack",
                "free-tier",
                "free-stack",
                &["nvidia/nemotron-70b:free"],
            ),
            gateway(
                "omniroute.or-claude",
                "unknown",
                "openrouter/anthropic/claude-sonnet-4",
                &["openrouter/anthropic/claude-sonnet-4"],
            ),
        ];
        assert!(matches("claude", &engines[0]), "the route names it");
        assert!(matches("provider:cc", &engines[0]));
        assert!(matches("model:*nemotron*", &engines[1]));
        assert!(!matches("claude", &engines[1]));
        let protected = rank(
            &Policy::default(),
            Role::Build,
            "build",
            Work::Background,
            &engines,
        );
        assert_eq!(
            names(&protected, &engines),
            ["omniroute.free-stack", "omniroute.or-claude"],
            "a Claude Code step makes the combo a subscription"
        );
        let never = Policy {
            never: vec!["claude".into()],
            ..Policy::default()
        };
        let ranking = rank(&never, Role::Build, "build", Work::Background, &engines);
        assert_eq!(names(&ranking, &engines), ["omniroute.free-stack"]);
        assert_eq!(ranking.blocked.len(), 2);
    }

    #[test]
    fn the_simple_choice_sets_improvement_and_review_and_lists_what_to_pick() {
        let mut policy = Policy::default();
        policy.set_improvement_engine("name:nemotron");
        policy.set_review_engine("name:deepseek");
        assert_eq!(policy.preferences(Role::Plan), ["name:nemotron"]);
        assert_eq!(policy.preferences(Role::Build), ["name:nemotron"]);
        assert_eq!(policy.review_engine(), Some("name:deepseek"));
        policy.check().unwrap();
        let engines = vec![
            engine("nemotron", "build", "free-tier"),
            engine("deepseek", "judge", "prepaid"),
            engine("claude", "judge", "subscription"),
            engine("ollama", "chore", "local"),
        ];
        let recommended = recommend(&engines, &[]).policy;
        let picks = choices(&policy, &engines, &recommended);
        let improve = picks["improve"].as_array().unwrap();
        assert_eq!(improve.len(), 3, "a chore engine cannot improve: {picks}");
        assert_eq!(improve[0]["selector"], "name:nemotron");
        assert_eq!(improve[0]["recommended"], true);
        assert_eq!(improve[0]["paid"], "free-tier");
        let review = picks["review"].as_array().unwrap();
        assert_eq!(review.len(), 2, "only a judge reviews: {picks}");
        assert_eq!(review[0]["recommended"], true);
        assert!(
            review[1]["blocked"]
                .as_str()
                .unwrap()
                .contains("subscription")
        );
        assert_eq!(picks["current"]["improve"], "name:nemotron");
    }

    #[test]
    fn where_limits_background_work_to_the_named_machines() {
        let policy = Policy {
            machines: vec!["grouchly".into()],
            ..Policy::default()
        };
        assert!(policy.allows_machine("wisp", "GROUCHLY"));
        assert!(policy.allows_machine("grouchly", "anything"));
        assert!(!policy.allows_machine("beastly", "beastly"));
        assert!(Policy::default().allows_machine("beastly", "beastly"));
        let mut there = engine("ollama", "build", "local");
        there.agent = "beastly".into();
        there.machine = "beastly".into();
        let ranking = rank(&policy, Role::Build, "build", Work::Background, &[there]);
        assert!(ranking.order.is_empty());
        assert!(ranking.blocked[0].1.contains("not in where"));
    }

    #[test]
    fn the_recommendation_gives_one_reason_per_choice() {
        let mut nemotron = engine("nemotron", "build", "free-tier");
        nemotron.verified = 12;
        let mut judge = engine("deepseek", "judge", "prepaid");
        judge.capped = true;
        judge.verified = 4;
        let mut elsewhere = engine("nemotron", "build", "free-tier");
        elsewhere.machine = "beastly".into();
        elsewhere.verified = 3;
        elsewhere.state = "exhausted".into();
        let engines = vec![
            nemotron,
            judge,
            engine("claude", "judge", "unknown"),
            elsewhere,
        ];
        let proposal = recommend(&engines, &["grouchly".to_string()]);
        assert_eq!(
            proposal.policy.preferences(Role::Build),
            ["name:nemotron", "name:deepseek"]
        );
        assert_eq!(
            proposal.policy.preferences(Role::Review),
            ["name:deepseek"],
            "review is a judge's"
        );
        assert_eq!(
            proposal.policy.preferences(Role::Plan)[0],
            "name:deepseek",
            "a judge plans first"
        );
        assert_eq!(proposal.policy.machines, ["grouchly"]);
        assert!(proposal.policy.protect_subscriptions);
        assert!(
            proposal
                .reasons
                .contains(&"nemotron first for build: free-tier, 15 verified, 0 refuted".into()),
            "{:#?}",
            proposal.reasons
        );
        assert!(
            proposal
                .reasons
                .iter()
                .any(|r| r.starts_with("claude never for background work")),
            "{:#?}",
            proposal.reasons
        );
        proposal.policy.check().unwrap();
    }

    /// Off-the-shelf trust: the master's word, travelling with the channel; nobody
    /// else's, however it got there.
    #[test]
    fn only_the_masters_signed_policy_counts_and_a_forged_one_is_ignored() {
        let dir = tempfile::tempdir().unwrap();
        let josh = person("josh", 1);
        let grouchly = person("grouchly", 2);
        let route = route(dir.path(), &[&josh, &grouchly]);
        let channel = &route.communications;
        let mut mine = Policy::default();
        mine.never.push("claude".into());

        assert!(setting(channel, "demo").is_none(), "auto by default");
        assert!(set_policy(channel, "demo", Some(mine.clone()), &grouchly).is_err());
        let impostor = person("josh", 9);
        assert!(set_policy(channel, "demo", Some(mine.clone()), &impostor).is_err());
        assert!(!channel.join(ENGINE_POLICY).exists());

        assert!(set_policy(channel, "demo", Some(mine.clone()), &josh).unwrap());
        assert!(!set_policy(channel, "demo", Some(mine.clone()), &josh).unwrap());
        assert_eq!(effective(channel, "demo").0, mine);
        assert!(is_set(channel, "demo"));

        // Edited after signing: ignored, and the project runs on auto.
        let path = channel.join(ENGINE_POLICY);
        let mut edited: PolicySetting =
            serde_json::from_slice(&std::fs::read(&path).unwrap()).unwrap();
        edited.policy.as_mut().unwrap().never.clear();
        crate::atomic_json(&path, &edited).unwrap();
        assert!(setting(channel, "demo").is_none());
        assert_eq!(effective(channel, "demo").0, Policy::default());

        // Validly signed, but by a member who is not the master.
        let mut forged = PolicySetting {
            project_id: "demo".into(),
            policy: Some(Policy {
                protect_subscriptions: false,
                ..Policy::default()
            }),
            set_at: Utc::now(),
            signed_by: "grouchly".into(),
            signature: String::new(),
            on_behalf_of: None,
        };
        forged.signature = grouchly.sign_bytes(setting_payload(&forged).as_bytes());
        crate::atomic_json(&path, &forged).unwrap();
        assert!(setting(channel, "demo").is_none());
        // Unsigned.
        forged.signature.clear();
        crate::atomic_json(&path, &forged).unwrap();
        assert!(effective(channel, "demo").0.protect_subscriptions);
        // Lifted from another project.
        let mut lifted = forged.clone();
        lifted.project_id = "elsewhere".into();
        lifted.signed_by = "josh".into();
        lifted.signature = josh.sign_bytes(setting_payload(&lifted).as_bytes());
        crate::atomic_json(&path, &lifted).unwrap();
        assert!(setting(channel, "demo").is_none());
        // Garbage.
        std::fs::write(&path, "prefer nemotron").unwrap();
        assert!(setting(channel, "demo").is_none());

        // The master goes back to auto, signed.
        assert!(set_policy(channel, "demo", Some(mine), &josh).unwrap());
        assert!(set_policy(channel, "demo", None, &josh).unwrap());
        assert!(setting(channel, "demo").is_some() && !is_set(channel, "demo"));
    }

    #[test]
    fn a_delegate_sets_the_policy_only_under_an_improve_delegation() {
        let dir = tempfile::tempdir().unwrap();
        let josh = person("josh", 1);
        let bridge = person("telegram-grouchly", 3);
        let route = route(dir.path(), &[&josh, &bridge]);
        let channel = &route.communications;
        let mut policy = Policy::default();
        policy.move_to_top("nemotron");
        assert!(
            set_policy_as(channel, "demo", Some(policy.clone()), &bridge, Some("josh")).is_err()
        );
        crate::delegation::grant(
            channel,
            "demo",
            &josh,
            "telegram-grouchly",
            &["improve".to_string()],
            None,
        )
        .unwrap();
        assert!(
            set_policy_as(channel, "demo", Some(policy.clone()), &bridge, Some("josh")).unwrap()
        );
        let set = setting(channel, "demo").unwrap();
        assert_eq!(set.set_by(), "josh via telegram-grouchly");
        assert_eq!(
            set.policy.unwrap().preferences(Role::Build),
            ["name:nemotron"]
        );
    }

    #[test]
    fn block_and_move_to_top_edit_the_lists() {
        let mut policy = Policy::default();
        policy.move_to_top("deepseek");
        policy.move_to_top("nemotron");
        assert_eq!(
            policy.preferences(Role::Review),
            ["name:nemotron", "name:deepseek"]
        );
        assert!(policy.block("nemotron"));
        assert!(!policy.block("NEMOTRON"), "once");
        assert_eq!(policy.preferences(Role::Build), ["name:deepseek"]);
        assert_eq!(policy.never, ["name:nemotron"]);
        policy.move_to_top("nemotron");
        assert!(policy.never.is_empty(), "moving it up lifts the block");
        let recommended = Policy {
            machines: vec!["grouchly".into()],
            ..Policy::default()
        };
        assert_eq!(
            answer_changes(ACCEPT_RECOMMENDED, &policy, &recommended),
            Some(recommended.clone())
        );
        let blocked = answer_changes("Block claude", &policy, &recommended).unwrap();
        assert_eq!(blocked.never, ["name:claude"]);
        assert!(answer_changes(KEEP_HOLDING, &policy, &recommended).is_none());
        assert!(
            Policy {
                caps_usd: BTreeMap::from([("build".to_string(), -1.0)]),
                ..Policy::default()
            }
            .check()
            .is_err()
        );
        assert!(
            Policy {
                prefer: BTreeMap::from([("dance".to_string(), vec!["x".to_string()])]),
                ..Policy::default()
            }
            .check()
            .is_err()
        );
    }

    /// Held work asks the master once a week per role, however often it is held.
    #[test]
    fn a_hold_is_asked_once_per_role_per_week() {
        let dir = tempfile::tempdir().unwrap();
        let josh = person("josh", 1);
        let wisp = person("wisp", 2);
        let route = route(dir.path(), &[&josh, &wisp]);
        assert!(ask_hold(&route, &wisp, Role::Build, "2026-W40", "all blocked").unwrap());
        assert!(!ask_hold(&route, &wisp, Role::Build, "2026-W40", "still").unwrap());
        assert!(ask_hold(&route, &wisp, Role::Plan, "2026-W40", "all blocked").unwrap());
        assert!(ask_hold(&route, &wisp, Role::Build, "2026-W41", "again").unwrap());
        let pending = crate::questions::pending(&route);
        assert_eq!(pending.len(), 3);
        assert!(pending.iter().all(|q| q.kind == crate::questions::POLICY));
        assert_eq!(pending[0].options, [ACCEPT_RECOMMENDED, KEEP_HOLDING]);
        assert!(ask_free_tier(&route, &wisp, "nemotron", "2026-W40", "returned 402").unwrap());
        assert!(!ask_free_tier(&route, &wisp, "nemotron", "2026-W40", "again").unwrap());
    }

    #[test]
    fn step_records_are_signed_by_their_agent_and_a_forged_one_is_dropped() {
        let dir = tempfile::tempdir().unwrap();
        let josh = person("josh", 1);
        let wisp = person("wisp", 2);
        let route = route(dir.path(), &[&josh, &wisp]);
        let step = |name: &str, cost: f64| Step {
            step: name.into(),
            role: Some(if name == "build" { "build" } else { name }.into()),
            at: Utc::now(),
            agent: "wisp".into(),
            machine: "grouchly".into(),
            engine: Some("nemotron".into()),
            model: Some("nvidia/nemotron".into()),
            cost_usd: Some(cost),
            order: None,
            outcome: "done".into(),
        };
        record_step(&route, &wisp, "2026-W40", step("plan", 0.25)).unwrap();
        record_step(&route, &wisp, "2026-W40", step("plan", 0.5)).unwrap();
        record_step(&route, &wisp, "2026-W40", step("review", 1.0)).unwrap();
        assert_eq!(read_steps(&route, "2026-W40").len(), 3);
        assert_eq!(latest_steps(&route, "2026-W40").len(), 2);
        assert!((role_spend(&route, "2026-W40", Role::Plan) - 0.75).abs() < 1e-9);
        let capped = Policy {
            caps_usd: BTreeMap::from([("plan".to_string(), 0.5)]),
            ..Policy::default()
        };
        assert!(over_cap(&route, &capped, "2026-W40", Role::Plan).is_some());
        assert!(over_cap(&route, &capped, "2026-W40", Role::Build).is_none());
        assert!(
            latest_steps(&route, "2026-W40")[0]
                .describe()
                .contains("nemotron (nvidia/nemotron) on grouchly (wisp), $0.50 - done")
        );

        // Somebody else writes a log in wisp's name.
        let mut forged = StepLog {
            agent: "wisp".into(),
            week: "2026-W40".into(),
            steps: vec![step("plan", 99.0)],
            signed_by: Some("josh".into()),
            signature: None,
        };
        forged.signature = Some(josh.sign_bytes(steps_payload(&forged).as_bytes()));
        crate::atomic_json(&steps_dir(&route, "2026-W40").join("wisp.json"), &forged).unwrap();
        assert!(read_steps(&route, "2026-W40").is_empty());
    }
}
