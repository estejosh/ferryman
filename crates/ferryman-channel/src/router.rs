//! The smart router, part 2: choosing the engine.
//!
//! The rule is **use the cheapest engine that will most likely do it well**, and escalate
//! only when a cheaper engine has failed at that kind of work. Part 1 decided what an engine
//! can do ([`crate::capability`]) and what an order needs ([`crate::work`]); this decides
//! which engine gets it, and writes down why.
//!
//! # What runs before any scoring
//!
//! [`route`] starts from [`crate::policy::rank`], so everything the engine policy already
//! decides is decided first and exactly as before: the `never` list, `protect_subscriptions`
//! and `subscription_roles` (with their weekly caps), `caps_usd` (checked by the caller),
//! `where`, an engine that is out of credit, and the tiers - a chore engine never builds, a
//! demoted engine only does chore work, review is a judge's alone. The adversary is never
//! routed: [`Role::Adversary`] is returned in its own policy order whatever the policy says.
//! Scoring only ever chooses among engines that ranking let through.
//!
//! # The filters the router adds
//!
//! - **Modalities.** The engine must have every modality the work needs; code work needs
//!   `code`, which only a `cli` engine can have. An engine whose profile is empty (a hand
//!   built candidate, or a worker that published none) counts as text-only.
//! - **HTTP engines are text only.** An `http` engine is asked once, in text, and answers in
//!   text: `chat_body` sends no images, audio or files. So an `http` engine is never given
//!   work that needs anything but `text`, whatever its profile says - a `vision` guessed
//!   from a model name, or even declared, would still receive no image. To route vision work,
//!   point a `cli` engine at the model and declare `vision` on it. (Sending images to an
//!   endpoint - OpenAI-style `image_url` parts - is a separate feature; until it exists this
//!   rule is the honest one.)
//! - **Context.** An engine whose window is known and smaller than the work wants is out. An
//!   unknown window is not a reason to exclude.
//! - **Code needs an engine that can edit files, unless there is none.** When no engine the
//!   policy lets through has `code` (a fleet of `http` engines only), code work is not
//!   held: the router drops the `code` requirement, as builds on such a fleet always ran,
//!   and the reason says so. With one cli engine up, http engines are never given code work.
//! - **Planning** prefers a judge-tier engine only as a tie-break (the existing rule: a plan
//!   a judge wrote needs no second reading); a builder the operator listed, or one that is
//!   cheaper and sufficient, can plan, marked unreviewed as before.
//! - **Escalation.** An engine that already failed this order (its result was refuted by
//!   its own evidence, or sent back with changes requested) is out, and the next engine must
//!   have a higher success estimate than the failed one had.
//!
//! # The success estimate
//!
//! For one engine and one kind of work, `p` is a Beta posterior.
//!
//! The prior mean is set by the engine's size class - large 0.80, medium 0.70, small 0.55 -
//! plus 0.05 for every strength tag that matches the kind (`code` for code-change, `tests`
//! and `code` for tests, `docs`, `review` and `reasoning`, ...), at most 0.10; minus 0.10
//! for every class the engine is below the size of the work (a small engine on large work).
//! The prior counts for [`PRIOR_WEIGHT`] observations.
//!
//! The evidence is the worker's ledger of this engine's results for this kind, verified or
//! refuted by the worker's own checks, each weighted by `0.5^(age / 14 days)` so that old
//! results fade: [`Outcome`]. `p = (prior * 4 + verified) / (4 + verified + refuted)`.
//!
//! So a medium engine starts at 0.70 and is below the default threshold of 0.75; it is
//! tried for work only when nothing sufficient is cheaper, and proves itself, or not, one
//! verified result at a time. A large engine starts above it.
//!
//! # The expected cost
//!
//! One call is estimated at 3k/1k, 12k/3k or 48k/10k tokens in/out for small, medium and
//! large work (more input when the work wants a bigger context), times the engine's price.
//!
//! - local and free-tier engines: 0;
//! - a free tier that asked for money (flagged): priced as an unpriced paid engine, until
//!   the flag lapses;
//! - a priced engine: its price;
//! - an **unpriced** paid engine (prepaid or unknown, no `cost_*` declared) is not free: it
//!   is assumed to cost [`ASSUMED_COST`] - $5 in / $25 out per million tokens, a frontier
//!   model's list price - so a declared price always beats a guess;
//! - a subscription costs nothing per call, but its scarcity is priced: [`SCARCITY_BASE_USD`]
//!   scaled up to ten times as the weekly request cap runs down (`1 + 9 * (1 - left)^2`).
//!   With no cap known, half is assumed to be left.
//!
//! # The choice
//!
//! The *sufficient set* is every engine with `p` at or above the threshold for the kind
//! (0.75 by default, `thresholds` in the policy per kind) - and above the failed engine's
//! `p` when escalating. The winner is the cheapest of them. Costs within 10% (or half a
//! tenth of a cent) of the cheapest count as tied, and ties go to the operator's **bias**
//! (the policy's `bias` weights, then the engine's place in the role's `prefer` list), then
//! the nearer tier, then the faster engine, then the order the policy and the engine list
//! already gave (how engines nothing else distinguishes were always told apart, so a fleet
//! of look-alikes behaves as it did), and last the name. With an empty sufficient set the
//! winner is the highest `p` (within 0.005, the cheaper). Bias never lets a dearer engine
//! beat a cheaper sufficient one; to force an order use `routing = "ordered"`.
//!
//! # Explainability
//!
//! [`route`] returns a [`Decision`]: every candidate with its `p`, price and, when it was
//! left out, why; the winner; and one line - `nvidia: free, p 0.81 for docs >= 0.75,
//! cheapest sufficient`. Workers record it beside the step and in the result;
//! `ferry route explain`, `ferry route simulate` and the dashboard show it.

use std::cmp::Ordering;

use chrono::{DateTime, Datelike, Duration, Utc};
use serde::{Deserialize, Serialize};
use serde_json::Value;

use crate::{
    capability::{Cost, Modality},
    policy::{Candidate, ModelClass, Policy, Role, Routing, Work, rank},
    work::{Needs, Size, WorkKind, resolve_modalities},
};

/// The success probability an engine must reach to count as sufficient, unless the policy
/// says otherwise for the kind.
pub const DEFAULT_THRESHOLD: f64 = 0.75;
/// How long it takes a ledger result to count for half as much.
pub const HALF_LIFE_DAYS: f64 = 14.0;
/// How many observations the class prior is worth.
pub const PRIOR_WEIGHT: f64 = 4.0;
/// Added to the prior for each strength tag that matches the kind of work.
pub const STRENGTH_BONUS: f64 = 0.05;
/// The most the matching strengths add.
pub const STRENGTH_CAP: f64 = 0.10;
/// Taken off the prior for each class an engine is below the size of the work.
pub const SIZE_PENALTY: f64 = 0.10;
/// What an unpriced paid engine is assumed to cost: a frontier model's list price.
pub const ASSUMED_COST: Cost = Cost {
    per_call_usd: 0.0,
    per_mtok_in_usd: 5.0,
    per_mtok_out_usd: 25.0,
};
/// What one call on a subscription with its whole weekly cap left is worth, in dollars.
pub const SCARCITY_BASE_USD: f64 = 0.02;
/// Costs this close (dollars) to the cheapest are tied, whatever their size.
pub const TIE_ABSOLUTE_USD: f64 = 0.0005;
/// Costs within this share of the cheapest are tied.
pub const TIE_RELATIVE: f64 = 0.10;
/// Success estimates this close are tied when none is sufficient.
pub const P_TIE: f64 = 0.005;
/// The most candidates a recorded decision keeps (the ones that mattered, best first).
pub const MAX_RECORDED: usize = 12;

// --- the ledger: how an engine's work of each kind has turned out -------------------------

/// How one engine's work of one kind has turned out: verified and refuted results,
/// age-weighted, in thousandths of a result so the figure signs and compares exactly.
/// Published (v2-only) inside the engine's trust line.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct Outcome {
    /// The kind of work: `docs`, `code-change`, ...
    pub kind: String,
    /// Results the worker's checks agreed with, as of [`Self::at`], in thousandths.
    pub verified_milli: u64,
    /// Results the worker's checks refuted, as of [`Self::at`], in thousandths.
    pub refuted_milli: u64,
    /// When the weights were last brought up to date.
    pub at: DateTime<Utc>,
}

/// The share of a result's weight left after `age`: 1 at once, a half after
/// [`HALF_LIFE_DAYS`]. A clock that went backwards counts as no time.
#[must_use]
pub fn decay(age: Duration) -> f64 {
    let days = age.num_seconds() as f64 / 86_400.0;
    if days <= 0.0 {
        1.0
    } else {
        0.5_f64.powf(days / HALF_LIFE_DAYS)
    }
}

impl Outcome {
    /// The weights as of `now`: (verified, refuted), in results.
    #[must_use]
    pub fn weights(&self, now: DateTime<Utc>) -> (f64, f64) {
        let fade = decay(now.signed_duration_since(self.at));
        (
            self.verified_milli as f64 / 1000.0 * fade,
            self.refuted_milli as f64 / 1000.0 * fade,
        )
    }

    /// Count one result as of `now`, after fading what was counted before.
    pub fn record(&mut self, verified: bool, now: DateTime<Utc>) {
        let (v, r) = self.weights(now);
        let (v, r) = if verified { (v + 1.0, r) } else { (v, r + 1.0) };
        self.verified_milli = (v * 1000.0).round() as u64;
        self.refuted_milli = (r * 1000.0).round() as u64;
        if now > self.at {
            self.at = now;
        }
    }

    /// The share of decided results that were verified, and how many are counted, as of
    /// `now`. `None` before anything is counted.
    #[must_use]
    pub fn rate(&self, now: DateTime<Utc>) -> Option<(f64, f64)> {
        let (v, r) = self.weights(now);
        (v + r > 0.001).then(|| (v / (v + r), v + r))
    }
}

/// Count one verified (`true`) or refuted (`false`) result for `kind` in `list`.
/// Kinds that have faded to nothing are dropped, so the list stays short.
pub fn record_outcome(list: &mut Vec<Outcome>, kind: &str, verified: bool, now: DateTime<Utc>) {
    match list.iter_mut().find(|outcome| outcome.kind == kind) {
        Some(outcome) => outcome.record(verified, now),
        None => {
            let mut outcome = Outcome {
                kind: kind.to_string(),
                verified_milli: 0,
                refuted_milli: 0,
                at: now,
            };
            outcome.record(verified, now);
            list.push(outcome);
        }
    }
    list.retain(|outcome| outcome.rate(now).is_some());
}

/// One engine's best kinds as (kind, share verified, results counted), most decided results
/// first.
#[must_use]
pub fn top_kinds(
    outcomes: &[Outcome],
    now: DateTime<Utc>,
    limit: usize,
) -> Vec<(String, f64, f64)> {
    let mut found: Vec<(String, f64, f64)> = outcomes
        .iter()
        .filter_map(|outcome| {
            outcome
                .rate(now)
                .map(|(rate, decided)| (outcome.kind.clone(), rate, decided))
        })
        .collect();
    found.sort_by(|a, b| {
        b.2.total_cmp(&a.2)
            .then(b.1.total_cmp(&a.1))
            .then(a.0.cmp(&b.0))
    });
    found.truncate(limit);
    found
}

// --- the estimate --------------------------------------------------------------------------

/// The strength tags that help with a kind of work.
#[must_use]
pub fn strength_tags(kind: WorkKind) -> &'static [&'static str] {
    match kind {
        WorkKind::CodeChange => &["code"],
        WorkKind::Tests => &["tests", "code"],
        WorkKind::Docs => &["docs"],
        WorkKind::Review => &["review", "reasoning"],
        WorkKind::Plan => &["reasoning"],
        WorkKind::Research => &["reasoning", "long-context"],
        WorkKind::Translate => &["translation"],
        _ => &[],
    }
}

/// How an engine's success estimate for some work came about.
#[derive(Debug, Clone, Copy, PartialEq)]
pub struct Estimate {
    /// The probability the engine does this work well.
    pub p: f64,
    /// Before the ledger: class, strengths and size.
    pub prior: f64,
    /// The ledger's age-weighted verified and refuted results for this kind.
    pub verified: f64,
    pub refuted: f64,
}

/// The prior mean for an engine on work: its class, plus matching strengths, minus the size
/// of the work above the class.
#[must_use]
pub fn prior(engine: &Candidate, needs: &Needs) -> f64 {
    let class = engine.class();
    let base = match class {
        ModelClass::Large => 0.80,
        ModelClass::Medium => 0.70,
        ModelClass::Small => 0.55,
    };
    let matched = strength_tags(needs.kind)
        .iter()
        .filter(|tag| engine.capabilities.has_strength(tag))
        .count();
    let bonus = (matched as f64 * STRENGTH_BONUS).min(STRENGTH_CAP);
    let size = match needs.size {
        Size::Small => 0,
        Size::Medium => 1,
        Size::Large => 2,
    };
    let gap = size - class as i32;
    let penalty = if gap > 0 {
        f64::from(gap) * SIZE_PENALTY
    } else {
        0.0
    };
    (base + bonus - penalty).clamp(0.05, 0.95)
}

/// The success estimate of `engine` for `needs` as of `now`.
#[must_use]
pub fn estimate(engine: &Candidate, needs: &Needs, now: DateTime<Utc>) -> Estimate {
    let prior = prior(engine, needs);
    let kind = needs.kind.as_str();
    let (verified, refuted) = engine
        .outcomes
        .iter()
        .filter(|outcome| outcome.kind == kind)
        .fold((0.0, 0.0), |(v, r), outcome| {
            let (more_v, more_r) = outcome.weights(now);
            (v + more_v, r + more_r)
        });
    let p = (prior * PRIOR_WEIGHT + verified) / (PRIOR_WEIGHT + verified + refuted);
    Estimate {
        p: p.clamp(0.0, 1.0),
        prior,
        verified,
        refuted,
    }
}

// --- the price -------------------------------------------------------------------------------

/// What one call on an engine is expected to cost, and how that was worked out.
#[derive(Debug, Clone, PartialEq)]
pub struct Price {
    pub usd: f64,
    /// `free`, `local`, `~$0.012`, `unpriced, assumed ~$0.21`, `subscription, 72% of the
    /// weekly cap left`.
    pub note: String,
}

/// The tokens one call is estimated to read and write: by size, and at least the context
/// the work wants.
#[must_use]
pub fn tokens(needs: &Needs) -> (u64, u64) {
    let (read, wrote) = match needs.size {
        Size::Small => (3_000, 1_000),
        Size::Medium => (12_000, 3_000),
        Size::Large => (48_000, 10_000),
    };
    (read.max(u64::from(needs.min_context_k) * 1_000), wrote)
}

/// `2026-W40`: the ISO week `now` falls in, as workers write it.
#[must_use]
pub fn iso_week(now: DateTime<Utc>) -> String {
    let week = now.iso_week();
    format!("{}-W{:02}", week.year(), week.week())
}

/// How much of a weekly request cap is left, `None` without a cap. Only this week's count
/// counts.
#[must_use]
pub fn cap_left(engine: &Candidate, now: DateTime<Utc>) -> Option<f64> {
    let cap = engine.weekly_requests.filter(|cap| *cap > 0)?;
    let used = if engine.week == iso_week(now) {
        engine.requests
    } else {
        0
    };
    Some((1.0 - used as f64 / cap as f64).clamp(0.0, 1.0))
}

fn money(usd: f64) -> String {
    if usd >= 0.1 {
        format!("~${usd:.2}")
    } else if usd >= 0.001 {
        format!("~${usd:.3}")
    } else {
        format!("~${usd:.4}")
    }
}

/// The expected price of one call of `engine` on `needs`.
#[must_use]
pub fn price(engine: &Candidate, needs: &Needs, now: DateTime<Utc>) -> Price {
    let (read, wrote) = tokens(needs);
    let caps = &engine.capabilities;
    let paid = engine.paid_class();
    let priced = |cost: &Cost| cost.estimate(read, wrote);
    // How it is paid for decides first: a subscription is scarce wherever its endpoint
    // is, and only then does being local make a call free.
    if paid == "subscription" {
        let left = cap_left(engine, now);
        let scarcity = SCARCITY_BASE_USD * (1.0 + 9.0 * (1.0 - left.unwrap_or(0.5)).powi(2));
        let own = caps.cost.as_ref().map_or(0.0, priced);
        return Price {
            usd: own + scarcity,
            note: match left {
                Some(left) => format!(
                    "subscription, {:.0}% of the weekly cap left",
                    (left * 100.0).round()
                ),
                None => "subscription, no weekly cap known".to_string(),
            },
        };
    }
    if paid == "local" || caps.local {
        return Price {
            usd: caps.cost.as_ref().map_or(0.0, priced),
            note: "local".to_string(),
        };
    }
    if paid == "free-tier" {
        if engine.flag.is_some() {
            let usd = priced(&ASSUMED_COST);
            return Price {
                usd,
                note: format!(
                    "free tier but flagged for asking for money, assumed {}",
                    money(usd)
                ),
            };
        }
        return Price {
            usd: caps.cost.as_ref().map_or(0.0, priced),
            note: "free".to_string(),
        };
    }
    match &caps.cost {
        Some(cost) if cost.is_free() => Price {
            usd: 0.0,
            note: "free".to_string(),
        },
        Some(cost) => {
            let usd = priced(cost);
            Price {
                usd,
                note: money(usd),
            }
        }
        None => {
            let usd = priced(&ASSUMED_COST);
            Price {
                usd,
                note: format!("unpriced, assumed {}", money(usd)),
            }
        }
    }
}

// --- bias ----------------------------------------------------------------------------------------

/// The operator's weight for an engine in a role: the largest policy `bias` whose selector
/// matches it, plus up to one point for its place in the role's `prefer` list (the first
/// entry the most). Higher goes first among engines of equal price.
#[must_use]
pub fn bias(policy: &Policy, role: Role, engine: &Candidate) -> f64 {
    let explicit = policy
        .bias
        .iter()
        .filter(|(selector, _)| crate::policy::matches(selector, engine))
        .map(|(_, weight)| *weight)
        .fold(None, |best: Option<f64>, weight| {
            Some(best.map_or(weight, |best| best.max(weight)))
        })
        .unwrap_or(0.0);
    let listed = policy.preferences(role).len();
    let place = policy
        .preference(role, engine)
        .map_or(0.0, |place| (listed - place) as f64 / (listed + 1) as f64);
    explicit + place
}

// --- the decision ----------------------------------------------------------------------------------

/// One engine the router looked at.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct Considered {
    pub engine: String,
    pub agent: String,
    pub machine: String,
    /// The success estimate for this kind of work. `None` for an engine the policy set
    /// aside before it was scored.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub p: Option<f64>,
    /// The expected dollars for one call, as [`Price`] works it out.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub cost_usd: Option<f64>,
    /// How that was worked out: `free`, `subscription, 72% of the weekly cap left`, ...
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub price: Option<String>,
    /// Reached the threshold (and beat a failed engine's estimate, when escalating).
    #[serde(default)]
    pub sufficient: bool,
    /// Why it was left out, when it was.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub excluded: Option<String>,
}

/// The engine the router chose.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct Pick {
    pub engine: String,
    pub agent: String,
    pub machine: String,
    pub p: f64,
    pub cost_usd: f64,
}

/// Why this engine: recorded beside the step, in the result and shown by
/// `ferry route explain`.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct Decision {
    /// `smart` or `ordered`.
    pub routing: String,
    pub role: String,
    pub kind: String,
    pub size: String,
    /// The modalities the work needs.
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub needs: Vec<String>,
    /// The success probability that counts as sufficient for this kind.
    pub threshold: f64,
    /// Engines looked at: the winner and the rest in the order they would be tried, then
    /// the ones left out with why.
    pub candidates: Vec<Considered>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub winner: Option<Pick>,
    /// One line: `nvidia: free, p 0.81 for docs >= 0.75, cheapest sufficient`.
    pub reason: String,
    /// Engines that failed this order earlier, when this is a retry.
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub failed: Vec<String>,
    /// The success estimate a retry had to beat.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub must_beat: Option<f64>,
}

impl Decision {
    /// What `ferry route explain` prints, one line each.
    #[must_use]
    pub fn lines(&self) -> Vec<String> {
        let mut out = vec![format!(
            "routing {} for {} work ({}, {}), threshold {:.2}",
            self.routing, self.kind, self.role, self.size, self.threshold
        )];
        if !self.failed.is_empty() {
            out.push(format!(
                "  retry: {} failed this order{}",
                self.failed.join(", "),
                self.must_beat
                    .map(|p| format!("; the next engine needs p above {p:.2}"))
                    .unwrap_or_default()
            ));
        }
        for candidate in &self.candidates {
            let mark = match (&candidate.excluded, self.winner.as_ref()) {
                (Some(_), _) => "x",
                (None, Some(win))
                    if win.engine == candidate.engine && win.machine == candidate.machine =>
                {
                    ">"
                }
                (None, _) if candidate.sufficient => "+",
                _ => "-",
            };
            let facts = match (&candidate.p, &candidate.price) {
                (Some(p), Some(price)) => format!("p {p:.2}, {price}"),
                (Some(p), None) => format!("p {p:.2}"),
                _ => String::new(),
            };
            out.push(format!(
                "  {mark} {:<14} {:<12} {}{}",
                candidate.engine,
                candidate.machine,
                facts,
                candidate
                    .excluded
                    .as_ref()
                    .map(|why| format!("out: {why}"))
                    .unwrap_or_default()
            ));
        }
        out.push(format!("  => {}", self.reason));
        out
    }
}

/// The recorded reason in a result payload (`routing.reason`), when a worker wrote one.
#[must_use]
pub fn reason_of(payload: &Value) -> Option<String> {
    payload
        .get("routing")?
        .get("reason")?
        .as_str()
        .map(str::to_string)
}

/// The recorded decision in a result payload, when a worker wrote one.
#[must_use]
pub fn decision_of(payload: &Value) -> Option<Decision> {
    serde_json::from_value(payload.get("routing")?.clone()).ok()
}

/// An engine that already failed this order, and the estimate it had.
#[derive(Debug, Clone, PartialEq)]
pub struct Failed {
    pub engine: String,
    pub p: Option<f64>,
}

/// What a routing call is told besides the engines and the policy.
#[derive(Debug, Clone, Copy)]
pub struct Context<'a> {
    pub now: DateTime<Utc>,
    /// Engines to leave out: already asked in this attempt (out of credit, or down).
    pub tried: &'a [String],
    /// Engines that failed this order: left out, and the next must beat their estimate.
    pub failed: &'a [Failed],
}

impl Context<'_> {
    #[must_use]
    pub fn new(now: DateTime<Utc>) -> Self {
        Self {
            now,
            tried: &[],
            failed: &[],
        }
    }
}

/// The decision and the engines in the order they should be tried: indexes into the
/// engines given, the winner first.
#[derive(Debug, Clone, PartialEq)]
pub struct Routed {
    pub decision: Decision,
    pub order: Vec<usize>,
}

/// The role work of a kind is done under: planning plans, review reviews, chores are
/// chores; everything else builds.
#[must_use]
pub fn role_for(kind: WorkKind) -> Role {
    match kind {
        WorkKind::Plan => Role::Plan,
        WorkKind::Review => Role::Review,
        WorkKind::Chore => Role::Chore,
        _ => Role::Build,
    }
}

/// What the improve loop's own steps need, which no order carries: planning is large
/// reasoning work, review is medium, a chore small.
#[must_use]
pub fn needs_for_role(role: Role) -> Needs {
    let (kind, size) = match role {
        Role::Plan => (WorkKind::Plan, Size::Large),
        Role::Review | Role::Adversary => (WorkKind::Review, Size::Medium),
        Role::Chore => (WorkKind::Chore, Size::Small),
        Role::Build => (WorkKind::CodeChange, Size::Medium),
    };
    Needs {
        modalities: resolve_modalities(&[], kind),
        kind,
        size,
        min_context_k: 0,
    }
}

fn round3(value: f64) -> f64 {
    (value * 1000.0).round() / 1000.0
}

struct Scored {
    index: usize,
    estimate: Estimate,
    price: Price,
    bias: f64,
    distance: i16,
    /// Where `rank` put it among the engines this call may use: the policy's order, then the
    /// operator's own, which is what settles engines nothing else tells apart.
    place: usize,
    sufficient: bool,
}

/// Choose among `engines` for `needs` done under `role` at `tier`. Everything the policy
/// decides comes first - see the module notes - and with `routing = "ordered"` (or for the
/// adversary) nothing else does: the order is [`rank`]'s, as it always was.
#[must_use]
pub fn route(
    policy: &Policy,
    role: Role,
    tier: &str,
    work: Work,
    needs: &Needs,
    engines: &[Candidate],
    context: &Context,
) -> Routed {
    let ranking = rank(policy, role, tier, work, engines);
    let threshold = policy.threshold_for(needs.kind);
    let smart = policy.routing == Routing::Smart && role != Role::Adversary;
    let mut decision = Decision {
        routing: if smart { "smart" } else { "ordered" }.to_string(),
        role: role.as_str().to_string(),
        kind: needs.kind.as_str().to_string(),
        size: needs.size.as_str().to_string(),
        needs: needs.modalities.iter().map(ToString::to_string).collect(),
        threshold,
        candidates: Vec::new(),
        winner: None,
        reason: String::new(),
        failed: context.failed.iter().map(|f| f.engine.clone()).collect(),
        must_beat: None,
    };
    let considered = |engine: &Candidate, excluded: Option<String>| Considered {
        engine: engine.name.clone(),
        agent: engine.agent.clone(),
        machine: engine.machine.clone(),
        p: None,
        cost_usd: None,
        price: None,
        sufficient: false,
        excluded,
    };
    let mut excluded: Vec<Considered> = Vec::new();
    for (index, why) in ranking.out.iter().chain(&ranking.blocked) {
        excluded.push(considered(&engines[*index], Some(why.clone())));
    }

    // Only a cli engine can edit files, so code work goes to one. But a fleet of http
    // engines only has always been able to take build orders (they answer in text and own
    // up to changing nothing), so when no engine at all could do the work with `code`
    // required, `code` is not required: nothing is worse than a hold.
    let relaxed_code = smart
        && needs.modalities.contains(&Modality::Code)
        && !ranking
            .order
            .iter()
            .any(|&index| unable(&engines[index], needs).is_ok());
    let relaxed;
    let needs_here = if relaxed_code {
        relaxed = Needs {
            modalities: needs
                .modalities
                .iter()
                .filter(|modality| **modality != Modality::Code)
                .cloned()
                .collect(),
            ..needs.clone()
        };
        &relaxed
    } else {
        needs
    };

    // What the policy let through, less what this call leaves out.
    let mut pool: Vec<usize> = Vec::new();
    for &index in &ranking.order {
        let engine = &engines[index];
        let left_out = if context.tried.contains(&engine.name) {
            Some("already asked in this attempt".to_string())
        } else if !smart {
            None
        } else if let Some(failed) = context.failed.iter().find(|f| f.engine == engine.name) {
            Some(match failed.p {
                Some(p) => format!("failed this order earlier at p {p:.2}"),
                None => "failed this order earlier".to_string(),
            })
        } else {
            unable(engine, needs_here).err()
        };
        match left_out {
            Some(why) => excluded.push(considered(engine, Some(why))),
            None => pool.push(index),
        }
    }

    if !smart {
        // Today's order, scored only so the record says what it would have meant.
        let mut candidates = Vec::new();
        for &index in &pool {
            let engine = &engines[index];
            let estimate = estimate(engine, needs, context.now);
            let price = price(engine, needs, context.now);
            candidates.push(Considered {
                p: Some(round3(estimate.p)),
                cost_usd: Some(round3(price.usd)),
                price: Some(price.note),
                sufficient: estimate.p + 1e-9 >= threshold,
                ..considered(engine, None)
            });
        }
        if let Some(&first) = pool.first() {
            let engine = &engines[first];
            let estimate = estimate(engine, needs, context.now);
            let price = price(engine, needs, context.now);
            decision.reason = if role == Role::Adversary {
                format!(
                    "{}: the adversary is never routed; first in its own policy order",
                    engine.name
                )
            } else {
                format!(
                    "{}: first allowed engine in the policy order (routing is ordered)",
                    engine.name
                )
            };
            decision.winner = Some(Pick {
                engine: engine.name.clone(),
                agent: engine.agent.clone(),
                machine: engine.machine.clone(),
                p: round3(estimate.p),
                cost_usd: round3(price.usd),
            });
        } else {
            decision.reason = none_reason(&ranking.why_none(role, engines), &excluded);
        }
        decision.candidates = finish(candidates, excluded);
        return Routed {
            decision,
            order: pool,
        };
    }

    // Smart: score what is left.
    let floor = context
        .failed
        .iter()
        .filter_map(|failed| failed.p)
        .fold(None, |best: Option<f64>, p| {
            Some(best.map_or(p, |best| best.max(p)))
        });
    decision.must_beat = floor.map(round3);
    let wanted = crate::policy::tier_level(tier);
    let scored: Vec<Scored> = pool
        .iter()
        .enumerate()
        .map(|(place, &index)| {
            let engine = &engines[index];
            let estimate = estimate(engine, needs, context.now);
            let sufficient =
                estimate.p + 1e-9 >= threshold && floor.is_none_or(|f| estimate.p > f + 1e-9);
            let level = i16::from(engine.level());
            Scored {
                index,
                place,
                estimate,
                price: price(engine, needs, context.now),
                bias: bias(policy, role, engine),
                // As `rank` measures it: a judge plans first, a builder builds first and a
                // judge builds last.
                distance: if role == Role::Plan {
                    2 - level
                } else {
                    level - i16::from(wanted)
                },
                sufficient,
            }
        })
        .collect();

    // The order they would be tried in: the winner among the sufficient first, and so on.
    let mut order_positions: Vec<usize> = Vec::new();
    let mut left: Vec<usize> = (0..scored.len()).collect();
    let mut tied_with_winner: Vec<usize> = Vec::new();
    while !left.is_empty() {
        let sufficient: Vec<usize> = left
            .iter()
            .copied()
            .filter(|position| scored[*position].sufficient)
            .collect();
        let (pick, tied) = if sufficient.is_empty() {
            best_estimate(&left, &scored, engines)
        } else {
            best_priced(&sufficient, &scored, engines)
        };
        if order_positions.is_empty() {
            tied_with_winner = tied;
        }
        order_positions.push(pick);
        left.retain(|position| *position != pick);
    }

    let candidates: Vec<Considered> = order_positions
        .iter()
        .map(|&position| {
            let s = &scored[position];
            let engine = &engines[s.index];
            Considered {
                p: Some(round3(s.estimate.p)),
                cost_usd: Some(round3(s.price.usd)),
                price: Some(s.price.note.clone()),
                sufficient: s.sufficient,
                ..considered(engine, None)
            }
        })
        .collect();
    match order_positions.first().map(|&position| &scored[position]) {
        Some(win) => {
            let engine = &engines[win.index];
            decision.winner = Some(Pick {
                engine: engine.name.clone(),
                agent: engine.agent.clone(),
                machine: engine.machine.clone(),
                p: round3(win.estimate.p),
                cost_usd: round3(win.price.usd),
            });
            decision.reason = winner_reason(
                win,
                engine,
                needs,
                threshold,
                &tied_with_winner,
                &scored,
                engines,
                floor,
            );
            if relaxed_code {
                decision.reason.push_str(
                    "; no engine that can edit files is up, so a text-only one takes it as \
                     it always has",
                );
            }
        }
        None => decision.reason = none_reason(&ranking.why_none(role, engines), &excluded),
    }
    decision.candidates = finish(candidates, excluded);
    // `scored` was built from `pool` in order, so a position in one is a place in the other.
    let order = order_positions
        .iter()
        .map(|position| pool[*position])
        .collect();
    Routed { decision, order }
}

/// Whether the engine can do work that needs this at all.
fn unable(engine: &Candidate, needs: &Needs) -> Result<(), String> {
    let caps = &engine.capabilities;
    let has = |modality: &Modality| {
        if caps.modalities.is_empty() {
            *modality == Modality::Text
        } else {
            caps.has(modality)
        }
    };
    let missing: Vec<String> = needs
        .modalities
        .iter()
        .filter(|modality| !has(modality))
        .map(ToString::to_string)
        .collect();
    if !missing.is_empty() {
        return Err(format!(
            "cannot do {}: it lacks {}",
            needs.kind.as_str(),
            missing.join("+")
        ));
    }
    if engine.http {
        let beyond: Vec<String> = needs
            .modalities
            .iter()
            .filter(|modality| **modality != Modality::Text)
            .map(ToString::to_string)
            .collect();
        if !beyond.is_empty() {
            return Err(format!(
                "an http engine is sent text only, so it cannot take {} work; a cli engine \
                 that declares it can",
                beyond.join("+")
            ));
        }
    }
    if let Some(window) = caps.context_k
        && window < needs.min_context_k
    {
        return Err(format!(
            "its {window}k context is under the {}k this work wants",
            needs.min_context_k
        ));
    }
    Ok(())
}

/// The tie-break after price: bias (higher first), the nearer tier, the faster engine, then
/// the order the policy and the engine list already gave - which is how engines that look
/// the same to the router were always told apart, so a fleet whose engines nothing
/// distinguishes behaves as it did - and last the name and machine.
fn tie_break(a: &Scored, b: &Scored, engines: &[Candidate]) -> Ordering {
    let (ea, eb) = (&engines[a.index], &engines[b.index]);
    b.bias
        .total_cmp(&a.bias)
        .then(a.distance.cmp(&b.distance))
        .then(
            ea.latency_ms
                .unwrap_or(u64::MAX)
                .cmp(&eb.latency_ms.unwrap_or(u64::MAX)),
        )
        .then(a.place.cmp(&b.place))
        .then(ea.name.cmp(&eb.name))
        .then(ea.machine.cmp(&eb.machine))
        .then(a.index.cmp(&b.index))
}

/// The cheapest of `pool` (positions in `scored`), costs within the tie band counting as
/// equal and settled by [`tie_break`]; and who was in that band.
fn best_priced(pool: &[usize], scored: &[Scored], engines: &[Candidate]) -> (usize, Vec<usize>) {
    let cheapest = pool
        .iter()
        .map(|position| scored[*position].price.usd)
        .fold(f64::INFINITY, f64::min);
    let band = (cheapest * TIE_RELATIVE).max(TIE_ABSOLUTE_USD);
    let mut tied: Vec<usize> = pool
        .iter()
        .copied()
        .filter(|position| scored[*position].price.usd <= cheapest + band)
        .collect();
    tied.sort_by(|a, b| tie_break(&scored[*a], &scored[*b], engines));
    (tied[0], tied)
}

/// The most likely to succeed of `pool`, estimates within [`P_TIE`] counting as equal and
/// settled by price, then [`tie_break`].
fn best_estimate(pool: &[usize], scored: &[Scored], engines: &[Candidate]) -> (usize, Vec<usize>) {
    let best = pool
        .iter()
        .map(|position| scored[*position].estimate.p)
        .fold(f64::NEG_INFINITY, f64::max);
    let mut tied: Vec<usize> = pool
        .iter()
        .copied()
        .filter(|position| scored[*position].estimate.p >= best - P_TIE)
        .collect();
    tied.sort_by(|a, b| {
        scored[*a]
            .price
            .usd
            .total_cmp(&scored[*b].price.usd)
            .then_with(|| tie_break(&scored[*a], &scored[*b], engines))
    });
    (tied[0], tied)
}

#[allow(clippy::too_many_arguments)]
fn winner_reason(
    win: &Scored,
    engine: &Candidate,
    needs: &Needs,
    threshold: f64,
    tied: &[usize],
    scored: &[Scored],
    engines: &[Candidate],
    floor: Option<f64>,
) -> String {
    let kind = needs.kind.as_str();
    let mut text = if win.sufficient {
        format!(
            "{}: {}, p {:.2} for {kind} >= {threshold:.2}, cheapest sufficient",
            engine.name, win.price.note, win.estimate.p
        )
    } else {
        format!(
            "{}: {}, p {:.2} for {kind}, the highest of the engines that can do it (none reach \
             {threshold:.2}{})",
            engine.name,
            win.price.note,
            win.estimate.p,
            floor
                .map(|p| format!(" and beat the {p:.2} of the engine that failed"))
                .unwrap_or_default()
        )
    };
    let rivals: Vec<&Scored> = tied
        .iter()
        .map(|position| &scored[*position])
        .filter(|other| other.index != win.index)
        .collect();
    if win.sufficient && !rivals.is_empty() {
        let names: Vec<&str> = rivals
            .iter()
            .map(|other| engines[other.index].name.as_str())
            .collect();
        let decider = if rivals.iter().any(|other| other.bias < win.bias) {
            "bias put it first"
        } else if rivals.iter().any(|other| other.distance != win.distance) {
            "the nearer tier put it first"
        } else {
            "speed and its place in the list put it first"
        };
        text.push_str(&format!(
            "; tied on price with {}, {decider}",
            names.join(", ")
        ));
    }
    if let Some(p) = floor
        && win.sufficient
    {
        text.push_str(&format!(
            "; escalated: it beats the {p:.2} of the engine that failed"
        ));
    }
    text
}

fn none_reason(why: &str, excluded: &[Considered]) -> String {
    let left_out: Vec<String> = excluded
        .iter()
        .filter_map(|candidate| {
            candidate
                .excluded
                .as_ref()
                .map(|reason| format!("{} {reason}", candidate.engine))
        })
        .collect();
    if left_out.is_empty() {
        format!("no engine: {why}")
    } else {
        format!("no engine can take it now: {}", left_out.join("; "))
    }
}

/// Candidates scored, then those left out, cut to what a record keeps.
fn finish(mut scored: Vec<Considered>, excluded: Vec<Considered>) -> Vec<Considered> {
    scored.extend(excluded);
    scored.truncate(MAX_RECORDED);
    scored
}

// --- simulating ----------------------------------------------------------------------------------------

/// What `ferry route simulate` and the dashboard run: the ranking for work of this kind and
/// size over `engines`, under the project's policy, without running anything. The engines
/// are what the fleet published, so a machine's own view can differ only in how fresh its
/// ledger is.
#[must_use]
pub fn simulate(
    policy: &Policy,
    engines: &[Candidate],
    needs: &Needs,
    now: DateTime<Utc>,
) -> Routed {
    let role = role_for(needs.kind);
    route(
        policy,
        role,
        role.tier(),
        Work::Background,
        needs,
        engines,
        &Context::new(now),
    )
}

/// The work a simulation is asked about: a kind, a size, and any modalities beyond what the
/// kind implies.
pub fn simulated_needs(kind: &str, size: &str, extra: &[String]) -> anyhow::Result<Needs> {
    let kind = WorkKind::parse(kind)?;
    let size = Size::parse(size)?;
    let mut signals = Vec::new();
    for word in extra {
        signals.extend(Modality::parse_list(word)?);
    }
    Ok(Needs {
        modalities: resolve_modalities(&signals, kind),
        kind,
        size,
        min_context_k: 0,
    })
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::capability::Capabilities;

    fn now() -> DateTime<Utc> {
        "2026-10-02T12:00:00Z".parse().unwrap()
    }

    fn caps(modalities: &[Modality], cost: Option<Cost>) -> Capabilities {
        Capabilities {
            modalities: modalities.to_vec(),
            strengths: Vec::new(),
            context_k: None,
            cost,
            local: false,
        }
    }

    fn per_call(usd: f64) -> Option<Cost> {
        Some(Cost {
            per_call_usd: usd,
            ..Cost::default()
        })
    }

    /// A cli engine at build tier with the class, payment and price given.
    fn engine(name: &str, class: ModelClass, paid: &str, cost: Option<Cost>) -> Candidate {
        Candidate {
            agent: "wisp".into(),
            machine: "box".into(),
            name: name.into(),
            tier: "build".into(),
            paid: paid.into(),
            class: Some(class),
            state: "up".into(),
            capabilities: caps(&[Modality::Text, Modality::Code], cost),
            ..Candidate::default()
        }
    }

    fn http(name: &str, class: ModelClass, paid: &str) -> Candidate {
        Candidate {
            http: true,
            capabilities: caps(&[Modality::Text], Some(Cost::FREE)),
            ..engine(name, class, paid, Some(Cost::FREE))
        }
    }

    fn needs(kind: WorkKind, size: Size) -> Needs {
        Needs {
            modalities: resolve_modalities(&[], kind),
            kind,
            size,
            min_context_k: 0,
        }
    }

    fn pick(routed: &Routed, engines: &[Candidate]) -> Option<String> {
        routed.order.first().map(|i| engines[*i].name.clone())
    }

    fn run(policy: &Policy, needs: &Needs, engines: &[Candidate]) -> Routed {
        let role = role_for(needs.kind);
        route(
            policy,
            role,
            role.tier(),
            Work::Background,
            needs,
            engines,
            &Context::new(now()),
        )
    }

    fn retry(failed: &[Failed], engines: &[Candidate], needs: &Needs) -> Routed {
        route(
            &Policy::default(),
            Role::Build,
            "build",
            Work::Background,
            needs,
            engines,
            &Context {
                now: now(),
                tried: &[],
                failed,
            },
        )
    }

    #[test]
    fn a_result_counts_for_half_as_much_after_fourteen_days() {
        assert!((decay(Duration::days(14)) - 0.5).abs() < 1e-9);
        assert!((decay(Duration::days(28)) - 0.25).abs() < 1e-9);
        assert_eq!(decay(Duration::days(-3)), 1.0, "a clock gone backwards");
        let mut list = Vec::new();
        let then = now() - Duration::days(14);
        record_outcome(&mut list, "docs", true, then);
        record_outcome(&mut list, "docs", true, then);
        let (v, r) = list[0].weights(now());
        assert!(
            (v - 1.0).abs() < 0.01 && r == 0.0,
            "two results, half left: {v}"
        );
        // A new result is counted at full weight beside the faded ones.
        record_outcome(&mut list, "docs", false, now());
        let (v, r) = list[0].weights(now());
        assert!((v - 1.0).abs() < 0.01 && (r - 1.0).abs() < 0.01);
        // And what has faded to nothing is dropped.
        let mut old = Vec::new();
        record_outcome(&mut old, "docs", true, now() - Duration::days(400));
        record_outcome(&mut old, "tests", true, now());
        assert_eq!(old.len(), 1);
        assert_eq!(old[0].kind, "tests");
    }

    #[test]
    fn the_prior_follows_class_strengths_and_the_size_of_the_work() {
        let mut large = engine("a", ModelClass::Large, "free-tier", Some(Cost::FREE));
        let medium = engine("b", ModelClass::Medium, "free-tier", Some(Cost::FREE));
        let small = engine("c", ModelClass::Small, "free-tier", Some(Cost::FREE));
        let docs = needs(WorkKind::Docs, Size::Small);
        assert!((prior(&large, &docs) - 0.80).abs() < 1e-9);
        assert!((prior(&medium, &docs) - 0.70).abs() < 1e-9);
        assert!((prior(&small, &docs) - 0.55).abs() < 1e-9);
        // A matching strength adds 0.05 each, to 0.10: tests matches `tests` and `code`.
        let tests = needs(WorkKind::Tests, Size::Small);
        large.capabilities.strengths = vec!["code".into()];
        assert!((prior(&large, &tests) - 0.85).abs() < 1e-9);
        large.capabilities.strengths = vec!["code".into(), "tests".into(), "docs".into()];
        assert!(
            (prior(&large, &tests) - 0.90).abs() < 1e-9,
            "capped at +0.10"
        );
        assert!(
            (prior(&large, &docs) - 0.85).abs() < 1e-9,
            "docs matches docs only"
        );
        // Work bigger than the class costs 0.10 a step.
        let big = needs(WorkKind::Docs, Size::Large);
        assert!((prior(&small, &big) - 0.35).abs() < 1e-9);
        assert!((prior(&medium, &big) - 0.60).abs() < 1e-9);
        assert!((prior(&medium, &needs(WorkKind::Docs, Size::Medium)) - 0.70).abs() < 1e-9);
    }

    #[test]
    fn the_ledger_moves_the_estimate_for_that_kind_only() {
        let mut medium = engine("b", ModelClass::Medium, "free-tier", Some(Cost::FREE));
        let docs = needs(WorkKind::Docs, Size::Medium);
        assert!((estimate(&medium, &docs, now()).p - 0.70).abs() < 1e-9);
        for _ in 0..4 {
            record_outcome(&mut medium.outcomes, "docs", true, now());
        }
        // (0.7*4 + 4) / (4 + 4) = 0.85
        assert!((estimate(&medium, &docs, now()).p - 0.85).abs() < 1e-3);
        // Other kinds are untouched.
        let tests = needs(WorkKind::Tests, Size::Medium);
        assert!((estimate(&medium, &tests, now()).p - 0.70).abs() < 1e-9);
        // Refutations pull it down, and they fade.
        for _ in 0..4 {
            record_outcome(&mut medium.outcomes, "tests", false, now());
        }
        assert!(estimate(&medium, &tests, now()).p < 0.40);
        let later = now() + Duration::days(140);
        assert!(
            (estimate(&medium, &tests, later).p - 0.70).abs() < 0.01,
            "ten half-lives on, it is the prior again"
        );
    }

    #[test]
    fn free_and_large_wins_and_the_line_says_why() {
        let nvidia = engine("nvidia", ModelClass::Large, "free-tier", Some(Cost::FREE));
        let sonnet = engine(
            "sonnet",
            ModelClass::Medium,
            "prepaid",
            Some(Cost {
                per_call_usd: 0.0,
                per_mtok_in_usd: 3.0,
                per_mtok_out_usd: 15.0,
            }),
        );
        let engines = [sonnet, nvidia];
        let routed = run(
            &Policy::default(),
            &needs(WorkKind::Docs, Size::Small),
            &engines,
        );
        assert_eq!(pick(&routed, &engines).as_deref(), Some("nvidia"));
        assert_eq!(
            routed.decision.reason,
            "nvidia: free, p 0.80 for docs >= 0.75, cheapest sufficient"
        );
        assert_eq!(routed.decision.routing, "smart");
        assert_eq!(routed.decision.winner.as_ref().unwrap().cost_usd, 0.0);
        // The loser is recorded with its own p and price.
        let sonnet = &routed.decision.candidates[1];
        assert_eq!(sonnet.engine, "sonnet");
        assert!(!sonnet.sufficient && sonnet.p == Some(0.7));
        assert!(sonnet.cost_usd.unwrap() > 0.0);
    }

    #[test]
    fn a_cheaper_engine_that_is_not_sufficient_does_not_win() {
        let free_small = engine("tiny", ModelClass::Small, "free-tier", Some(Cost::FREE));
        let paid_large = engine("big", ModelClass::Large, "prepaid", per_call(0.01));
        let engines = [free_small, paid_large];
        let routed = run(
            &Policy::default(),
            &needs(WorkKind::Docs, Size::Small),
            &engines,
        );
        assert_eq!(pick(&routed, &engines).as_deref(), Some("big"));
        assert!(routed.decision.reason.contains("cheapest sufficient"));
    }

    #[test]
    fn proving_itself_lets_a_cheap_engine_take_the_work_and_failing_takes_it_back() {
        let mut tiny = engine("tiny", ModelClass::Small, "free-tier", Some(Cost::FREE));
        let big = engine("big", ModelClass::Large, "prepaid", per_call(0.05));
        let docs = needs(WorkKind::Docs, Size::Small);
        for _ in 0..6 {
            record_outcome(&mut tiny.outcomes, "docs", true, now());
        }
        let engines = [tiny.clone(), big.clone()];
        assert_eq!(
            pick(&run(&Policy::default(), &docs, &engines), &engines).as_deref(),
            Some("tiny"),
            "six verified docs results lift 0.55 to 0.82"
        );
        // It is proven for docs, not for code: the ledger is per kind.
        let code = needs(WorkKind::CodeChange, Size::Small);
        assert_eq!(
            pick(&run(&Policy::default(), &code, &engines), &engines).as_deref(),
            Some("big")
        );
        for _ in 0..8 {
            record_outcome(&mut tiny.outcomes, "docs", false, now());
        }
        let engines = [tiny, big];
        assert_eq!(
            pick(&run(&Policy::default(), &docs, &engines), &engines).as_deref(),
            Some("big")
        );
    }

    #[test]
    fn with_nothing_sufficient_the_highest_estimate_wins() {
        let a = engine("a", ModelClass::Small, "free-tier", Some(Cost::FREE));
        let b = engine("b", ModelClass::Medium, "free-tier", Some(Cost::FREE));
        let engines = [a, b];
        let routed = run(
            &Policy::default(),
            &needs(WorkKind::Docs, Size::Small),
            &engines,
        );
        assert_eq!(pick(&routed, &engines).as_deref(), Some("b"));
        assert!(
            routed
                .decision
                .reason
                .contains("the highest of the engines that can do it")
                && routed.decision.reason.contains("none reach 0.75"),
            "{}",
            routed.decision.reason
        );
        assert!(routed.decision.candidates.iter().all(|c| !c.sufficient));
    }

    #[test]
    fn the_threshold_is_the_policys_per_kind() {
        let medium = engine("m", ModelClass::Medium, "free-tier", Some(Cost::FREE));
        let large = engine("l", ModelClass::Large, "prepaid", per_call(0.01));
        let engines = [medium, large];
        let docs = needs(WorkKind::Docs, Size::Medium);
        assert_eq!(
            pick(&run(&Policy::default(), &docs, &engines), &engines).as_deref(),
            Some("l")
        );
        let mut lax = Policy::default();
        lax.thresholds.insert("docs".into(), 0.65);
        lax.check().unwrap();
        let routed = run(&lax, &docs, &engines);
        assert_eq!(pick(&routed, &engines).as_deref(), Some("m"));
        assert!(
            routed.decision.reason.contains(">= 0.65"),
            "{}",
            routed.decision.reason
        );
        // Another kind keeps the default.
        let code = needs(WorkKind::CodeChange, Size::Medium);
        assert_eq!(
            pick(&run(&lax, &code, &engines), &engines).as_deref(),
            Some("l")
        );
        let mut bad = Policy::default();
        bad.thresholds.insert("docs".into(), 1.5);
        assert!(bad.check().is_err());
        bad.thresholds.clear();
        bad.thresholds.insert("nonsense".into(), 0.5);
        assert!(bad.check().is_err());
    }

    #[test]
    fn bias_and_the_prefer_list_break_ties_in_price_and_nothing_else() {
        let a = engine("alpha", ModelClass::Large, "free-tier", Some(Cost::FREE));
        let b = engine("beta", ModelClass::Large, "free-tier", Some(Cost::FREE));
        let engines = [a, b];
        let docs = needs(WorkKind::Docs, Size::Small);
        // No bias: the name settles it.
        assert_eq!(
            pick(&run(&Policy::default(), &docs, &engines), &engines).as_deref(),
            Some("alpha")
        );
        // The prefer list is a bias.
        let mut prefer = Policy::default();
        prefer.prefer.insert(
            "build".into(),
            vec!["name:beta".into(), "name:alpha".into()],
        );
        let routed = run(&prefer, &docs, &engines);
        assert_eq!(pick(&routed, &engines).as_deref(), Some("beta"));
        assert!(
            routed
                .decision
                .reason
                .contains("tied on price with alpha, bias put it first")
        );
        // An explicit weight outranks list position.
        let mut weighted = prefer.clone();
        weighted.bias.insert("name:alpha".into(), 5.0);
        weighted.check().unwrap();
        assert_eq!(
            pick(&run(&weighted, &docs, &engines), &engines).as_deref(),
            Some("alpha")
        );
        // But bias never lets a dearer engine win.
        let dear = engine("dear", ModelClass::Large, "prepaid", per_call(0.5));
        let all = [engines[0].clone(), engines[1].clone(), dear];
        let mut loud = Policy::default();
        loud.bias.insert("name:dear".into(), 100.0);
        assert_ne!(
            pick(&run(&loud, &docs, &all), &all).as_deref(),
            Some("dear")
        );
    }

    #[test]
    fn josh_example_nvidia_then_sonnet_then_haiku_with_local_models_eligible() {
        let nvidia = engine("nvidia", ModelClass::Large, "free-tier", Some(Cost::FREE));
        let mut sonnet = engine(
            "sonnet",
            ModelClass::Medium,
            "subscription",
            Some(Cost::FREE),
        );
        sonnet.capabilities.strengths = vec!["code".into(), "docs".into()];
        sonnet.weekly_requests = Some(500);
        let mut haiku = engine("haiku", ModelClass::Small, "subscription", Some(Cost::FREE));
        haiku.weekly_requests = Some(500);
        let mut ollama = engine("ollama", ModelClass::Small, "local", Some(Cost::FREE));
        ollama.capabilities.local = true;
        let engines = [haiku, sonnet, ollama, nvidia];
        let mut policy = Policy {
            protect_subscriptions: false,
            ..Policy::default()
        };
        policy.prefer.insert(
            "build".into(),
            vec![
                "name:nvidia".into(),
                "name:sonnet".into(),
                "name:haiku".into(),
                "paid:local".into(),
            ],
        );
        let docs = needs(WorkKind::Docs, Size::Medium);
        // NVIDIA is free and large: it wins while it is up.
        let routed = run(&policy, &docs, &engines);
        assert_eq!(pick(&routed, &engines).as_deref(), Some("nvidia"));
        // Out of credit, Sonnet comes next: sufficient with its docs strength, where haiku
        // and the local model are not.
        let mut down = engines.clone();
        down[3].state = "exhausted".into();
        let routed = run(&policy, &docs, &down);
        assert_eq!(
            pick(&routed, &down).as_deref(),
            Some("sonnet"),
            "{:?}",
            routed.decision
        );
        // Local models are eligible: proven at docs, the free local one beats a subscription.
        for _ in 0..8 {
            record_outcome(&mut down[2].outcomes, "docs", true, now());
        }
        assert_eq!(
            pick(&run(&policy, &docs, &down), &down).as_deref(),
            Some("ollama")
        );
        // And with haiku proven too, price is tied between the two subscriptions and bias
        // puts Sonnet before Haiku.
        let mut proven = engines.clone();
        proven[3].state = "exhausted".into();
        proven[2].state = "exhausted".into();
        for _ in 0..8 {
            record_outcome(&mut proven[0].outcomes, "docs", true, now());
        }
        let routed = run(&policy, &docs, &proven);
        assert_eq!(pick(&routed, &proven).as_deref(), Some("sonnet"));
        assert!(
            routed
                .decision
                .reason
                .contains("tied on price with haiku, bias put it first"),
            "{}",
            routed.decision.reason
        );
    }

    #[test]
    fn a_retry_leaves_out_the_failed_engine_and_needs_a_higher_estimate() {
        let nvidia = engine("nvidia", ModelClass::Large, "free-tier", Some(Cost::FREE));
        let mut sonnet = engine("sonnet", ModelClass::Large, "prepaid", per_call(0.01));
        sonnet.capabilities.strengths = vec!["docs".into()];
        let mut haiku = engine("haiku", ModelClass::Medium, "prepaid", per_call(0.001));
        haiku.capabilities.strengths = vec!["docs".into()];
        let engines = [haiku, nvidia, sonnet];
        let docs = needs(WorkKind::Docs, Size::Small);
        let first = run(&Policy::default(), &docs, &engines);
        assert_eq!(pick(&first, &engines).as_deref(), Some("nvidia"));
        let failed = [Failed {
            engine: "nvidia".into(),
            p: Some(0.80),
        }];
        let again = retry(&failed, &engines, &docs);
        // Haiku is sufficient on its own (0.75) but must beat 0.80; sonnet does (0.85).
        assert_eq!(
            pick(&again, &engines).as_deref(),
            Some("sonnet"),
            "{:?}",
            again.decision
        );
        assert!(again.decision.reason.contains("escalated"));
        assert_eq!(again.decision.must_beat, Some(0.8));
        let left_out = again
            .decision
            .candidates
            .iter()
            .find(|c| c.engine == "nvidia")
            .unwrap();
        assert!(
            left_out
                .excluded
                .as_ref()
                .unwrap()
                .contains("failed this order earlier at p 0.80")
        );
        // With only engines that cannot beat it, the best of them still does the work.
        let weak = [engines[0].clone()];
        let again = retry(&failed, &weak, &docs);
        assert_eq!(pick(&again, &weak).as_deref(), Some("haiku"));
        assert!(again.decision.reason.contains("none reach"));
        // And when every engine failed there is none.
        let all = [
            Failed {
                engine: "haiku".into(),
                p: None,
            },
            Failed {
                engine: "nvidia".into(),
                p: None,
            },
            Failed {
                engine: "sonnet".into(),
                p: None,
            },
        ];
        let none = retry(&all, &engines, &docs);
        assert!(none.order.is_empty());
        assert!(
            none.decision
                .reason
                .starts_with("no engine can take it now")
        );
    }

    #[test]
    fn work_needs_the_modalities_and_an_http_engine_gets_text_only() {
        let mut seer = engine("seer", ModelClass::Large, "prepaid", Some(Cost::FREE));
        seer.capabilities.modalities = vec![Modality::Text, Modality::Vision, Modality::Code];
        let blind = engine("blind", ModelClass::Large, "free-tier", Some(Cost::FREE));
        let mut api = http("api", ModelClass::Large, "free-tier");
        api.capabilities.modalities = vec![Modality::Text, Modality::Vision];
        let engines = [blind, api, seer];
        let vision = Needs {
            modalities: resolve_modalities(&[Modality::Vision], WorkKind::Docs),
            kind: WorkKind::Docs,
            size: Size::Small,
            min_context_k: 0,
        };
        let routed = run(&Policy::default(), &vision, &engines);
        assert_eq!(pick(&routed, &engines).as_deref(), Some("seer"));
        let why = |name: &str| {
            routed
                .decision
                .candidates
                .iter()
                .find(|c| c.engine == name)
                .and_then(|c| c.excluded.clone())
                .unwrap()
        };
        assert!(why("blind").contains("lacks vision"));
        assert!(
            why("api").contains("http engine is sent text only"),
            "{}",
            why("api")
        );
        // Code-change needs a cli engine that has `code`: with one up, the http engine is out.
        let code = needs(WorkKind::CodeChange, Size::Small);
        let only_api = [http("api", ModelClass::Large, "free-tier")];
        let with_cli = [
            http("api", ModelClass::Large, "free-tier"),
            engine("cli", ModelClass::Large, "prepaid", per_call(0.5)),
        ];
        let routed = run(&Policy::default(), &code, &with_cli);
        assert_eq!(
            pick(&routed, &with_cli).as_deref(),
            Some("cli"),
            "only a cli engine edits files, however much cheaper the http one is"
        );
        assert!(
            routed.decision.candidates.iter().any(|c| c.engine == "api"
                && c.excluded
                    .as_ref()
                    .is_some_and(|why| why.contains("lacks code"))),
            "{:?}",
            routed.decision
        );
        // With no engine that can edit files at all, the work is not held: a fleet of http
        // engines only has always taken build orders, and still does - and says so.
        let routed = run(&Policy::default(), &code, &only_api);
        assert_eq!(pick(&routed, &only_api).as_deref(), Some("api"));
        assert!(
            routed
                .decision
                .reason
                .contains("no engine that can edit files"),
            "{}",
            routed.decision.reason
        );
        // An http engine does text work.
        let text = needs(WorkKind::Docs, Size::Small);
        assert_eq!(
            pick(&run(&Policy::default(), &text, &only_api), &only_api).as_deref(),
            Some("api")
        );
        // A window smaller than the work wants is out; an unknown one is not.
        let mut small_window = engine("window", ModelClass::Large, "free-tier", Some(Cost::FREE));
        small_window.capabilities.context_k = Some(8);
        let mut wide = needs(WorkKind::Docs, Size::Small);
        wide.min_context_k = 32;
        let both = [
            small_window,
            engine("open", ModelClass::Large, "free-tier", Some(Cost::FREE)),
        ];
        let routed = run(&Policy::default(), &wide, &both);
        assert_eq!(pick(&routed, &both).as_deref(), Some("open"));
        assert!(routed.decision.candidates.iter().any(|c| {
            c.excluded
                .as_ref()
                .is_some_and(|why| why.contains("8k context is under the 32k"))
        }));
    }

    #[test]
    fn an_engine_with_no_profile_is_text_only() {
        let mut bare = engine("bare", ModelClass::Large, "free-tier", Some(Cost::FREE));
        bare.capabilities = Capabilities::default();
        let engines = [bare];
        assert_eq!(
            pick(
                &run(
                    &Policy::default(),
                    &needs(WorkKind::Docs, Size::Small),
                    &engines
                ),
                &engines
            )
            .as_deref(),
            Some("bare")
        );
        // Beside an engine that can edit files, it is out of code work.
        let both = [
            engines[0].clone(),
            engine("cli", ModelClass::Large, "prepaid", per_call(0.5)),
        ];
        assert_eq!(
            pick(
                &run(
                    &Policy::default(),
                    &needs(WorkKind::CodeChange, Size::Small),
                    &both
                ),
                &both
            )
            .as_deref(),
            Some("cli")
        );
    }

    #[test]
    fn an_unpriced_paid_engine_is_not_free() {
        let unpriced = engine("mystery", ModelClass::Large, "prepaid", None);
        let priced = engine("priced", ModelClass::Large, "prepaid", per_call(0.02));
        let docs = needs(WorkKind::Docs, Size::Medium);
        let p = price(&unpriced, &docs, now());
        // 12k in at $5/M plus 3k out at $25/M.
        assert!((p.usd - 0.135).abs() < 1e-9, "{}", p.usd);
        assert!(p.note.starts_with("unpriced, assumed ~$0.1"), "{}", p.note);
        let engines = [unpriced, priced];
        assert_eq!(
            pick(&run(&Policy::default(), &docs, &engines), &engines).as_deref(),
            Some("priced"),
            "a declared price beats a guess"
        );
        // A free tier that asked for money is priced like an unpriced one while flagged.
        let mut flagged = engine("flagged", ModelClass::Large, "free-tier", Some(Cost::FREE));
        assert_eq!(price(&flagged, &docs, now()).usd, 0.0);
        flagged.flag = Some("asked for payment".into());
        assert!(price(&flagged, &docs, now()).usd > 0.1);
    }

    #[test]
    fn a_subscription_costs_more_as_its_weekly_cap_runs_down() {
        let mut sub = engine("sub", ModelClass::Large, "subscription", Some(Cost::FREE));
        sub.weekly_requests = Some(100);
        let docs = needs(WorkKind::Docs, Size::Small);
        let fresh = price(&sub, &docs, now());
        assert!((fresh.usd - SCARCITY_BASE_USD).abs() < 1e-9);
        assert_eq!(fresh.note, "subscription, 100% of the weekly cap left");
        sub.week = iso_week(now());
        sub.requests = 50;
        let half = price(&sub, &docs, now());
        sub.requests = 90;
        let low = price(&sub, &docs, now());
        sub.requests = 100;
        let empty = price(&sub, &docs, now());
        assert!(fresh.usd < half.usd && half.usd < low.usd && low.usd < empty.usd);
        assert!((empty.usd - SCARCITY_BASE_USD * 10.0).abs() < 1e-9);
        // Last week's count says nothing about this one.
        sub.week = "2026-W01".into();
        assert_eq!(price(&sub, &docs, now()).note, fresh.note);
        // With no cap known, half is assumed.
        sub.weekly_requests = None;
        assert_eq!(
            price(&sub, &docs, now()).note,
            "subscription, no weekly cap known"
        );
        // Free beats a subscription.
        let free = engine("free", ModelClass::Large, "free-tier", Some(Cost::FREE));
        let engines = [sub, free];
        let open = Policy {
            protect_subscriptions: false,
            ..Policy::default()
        };
        assert_eq!(
            pick(&run(&open, &docs, &engines), &engines).as_deref(),
            Some("free")
        );
    }

    #[test]
    fn the_policys_background_rules_run_before_any_scoring() {
        let nvidia = engine("nvidia", ModelClass::Large, "free-tier", Some(Cost::FREE));
        let claude = engine(
            "claude",
            ModelClass::Large,
            "subscription",
            Some(Cost::FREE),
        );
        let engines = [nvidia, claude];
        let docs = needs(WorkKind::Docs, Size::Small);
        // A subscription is protected: it is out however good it is.
        let routed = run(&Policy::default(), &docs, &engines);
        assert_eq!(pick(&routed, &engines).as_deref(), Some("nvidia"));
        let blocked = routed
            .decision
            .candidates
            .iter()
            .find(|c| c.engine == "claude")
            .unwrap();
        assert!(
            blocked
                .excluded
                .as_ref()
                .unwrap()
                .contains("protect_subscriptions")
        );
        // `never` is final, and `where` too.
        let never = Policy {
            never: vec!["name:nvidia".into()],
            ..Policy::default()
        };
        assert!(
            run(&never, &docs, &engines).order.is_empty(),
            "never falls back to a blocked engine"
        );
        let elsewhere = Policy {
            machines: vec!["other".into()],
            ..Policy::default()
        };
        assert!(run(&elsewhere, &docs, &engines).order.is_empty());
        // A chore engine never builds, however cheap and sure.
        let mut chore = engine("chore", ModelClass::Large, "free-tier", Some(Cost::FREE));
        chore.tier = "chore".into();
        let only = [chore];
        assert!(
            run(
                &Policy::default(),
                &needs(WorkKind::CodeChange, Size::Small),
                &only
            )
            .order
            .is_empty()
        );
        let chores = needs(WorkKind::Chore, Size::Small);
        assert_eq!(
            pick(&run(&Policy::default(), &chores, &only), &only).as_deref(),
            Some("chore")
        );
        // Out of credit is out.
        let mut spent = engine("spent", ModelClass::Large, "free-tier", Some(Cost::FREE));
        spent.state = "exhausted".into();
        assert!(run(&Policy::default(), &docs, &[spent]).order.is_empty());
    }

    #[test]
    fn ordered_keeps_the_policy_order_and_the_adversary_is_never_routed() {
        let cheap = engine("cheap", ModelClass::Large, "free-tier", Some(Cost::FREE));
        let dear = engine("dear", ModelClass::Large, "prepaid", per_call(1.0));
        let engines = [cheap, dear];
        let mut ordered = Policy {
            routing: Routing::Ordered,
            ..Policy::default()
        };
        ordered.prefer.insert(
            "build".into(),
            vec!["name:dear".into(), "name:cheap".into()],
        );
        let docs = needs(WorkKind::Docs, Size::Small);
        let routed = run(&ordered, &docs, &engines);
        let by_rank = rank(&ordered, Role::Build, "build", Work::Background, &engines).order;
        assert_eq!(routed.order, by_rank, "exactly rank's order");
        assert_eq!(pick(&routed, &engines).as_deref(), Some("dear"));
        assert_eq!(routed.decision.routing, "ordered");
        assert!(
            routed
                .decision
                .reason
                .starts_with("dear: first allowed engine in the policy order")
        );
        // Smart, the same lists are only a bias: the free one wins.
        let mut smart = ordered.clone();
        smart.routing = Routing::Smart;
        assert_eq!(
            pick(&run(&smart, &docs, &engines), &engines).as_deref(),
            Some("cheap")
        );
        // The adversary is ranked as it always was, even under smart.
        let mut judge = engine("judge", ModelClass::Large, "free-tier", Some(Cost::FREE));
        judge.tier = "judge".into();
        let pair = [
            judge,
            engine("builder", ModelClass::Large, "free-tier", Some(Cost::FREE)),
        ];
        let adversary = route(
            &smart,
            Role::Adversary,
            "judge",
            Work::Background,
            &needs_for_role(Role::Adversary),
            &pair,
            &Context::new(now()),
        );
        assert_eq!(adversary.decision.routing, "ordered");
        assert_eq!(
            adversary.order,
            rank(&smart, Role::Adversary, "judge", Work::Background, &pair).order
        );
        assert!(adversary.decision.reason.contains("never routed"));
        // Tried engines are skipped in ordered mode too.
        let tried = ["dear".to_string()];
        let routed = route(
            &ordered,
            Role::Build,
            "build",
            Work::Background,
            &docs,
            &engines,
            &Context {
                now: now(),
                tried: &tried,
                failed: &[],
            },
        );
        assert_eq!(pick(&routed, &engines).as_deref(), Some("cheap"));
    }

    #[test]
    fn a_judge_plans_first_among_equals_and_a_cheaper_builder_still_can() {
        let mut judge = engine("judge", ModelClass::Large, "prepaid", per_call(0.3));
        judge.tier = "judge".into();
        let builder = engine("builder", ModelClass::Large, "free-tier", Some(Cost::FREE));
        let plan = needs_for_role(Role::Plan);
        let plans = |engines: &[Candidate]| {
            let routed = route(
                &Policy::default(),
                Role::Plan,
                "judge",
                Work::Background,
                &plan,
                engines,
                &Context::new(now()),
            );
            pick(&routed, engines)
        };
        // A free builder that is sufficient plans, as cheapest sufficient (a plan it writes
        // is marked unreviewed, as before).
        assert_eq!(
            plans(&[builder.clone(), judge.clone()]).as_deref(),
            Some("builder")
        );
        // Among engines that cost the same, the judge plans: a plan it wrote needs no
        // second reading.
        let mut free_judge = judge.clone();
        free_judge.capabilities.cost = Some(Cost::FREE);
        free_judge.paid = "free-tier".into();
        assert_eq!(
            plans(&[builder.clone(), free_judge]).as_deref(),
            Some("judge")
        );
        // With no judge, a builder plans.
        let alone = [builder];
        let routed = route(
            &Policy::default(),
            Role::Plan,
            "judge",
            Work::Background,
            &plan,
            &alone,
            &Context::new(now()),
        );
        assert_eq!(pick(&routed, &alone).as_deref(), Some("builder"));
    }

    #[test]
    fn a_decision_survives_its_json_and_names_its_reason() {
        let nvidia = engine("nvidia", ModelClass::Large, "free-tier", Some(Cost::FREE));
        let engines = [nvidia];
        let routed = run(
            &Policy::default(),
            &needs(WorkKind::Docs, Size::Small),
            &engines,
        );
        let value = serde_json::to_value(&routed.decision).unwrap();
        let payload = serde_json::json!({ "routing": value });
        assert_eq!(
            reason_of(&payload).as_deref(),
            Some("nvidia: free, p 0.80 for docs >= 0.75, cheapest sufficient")
        );
        assert_eq!(decision_of(&payload).unwrap(), routed.decision);
        assert!(reason_of(&serde_json::json!({})).is_none());
        let lines = routed.decision.lines().join("\n");
        assert!(
            lines.contains("> nvidia") && lines.contains("=> nvidia: free"),
            "{lines}"
        );
    }

    #[test]
    fn simulating_runs_the_same_choice_without_an_order() {
        let nvidia = engine("nvidia", ModelClass::Large, "free-tier", Some(Cost::FREE));
        let mut seer = engine("seer", ModelClass::Large, "prepaid", Some(Cost::FREE));
        seer.capabilities.modalities = vec![Modality::Text, Modality::Vision];
        let engines = [nvidia, seer];
        let wanted = simulated_needs("docs", "small", &[]).unwrap();
        assert_eq!(
            pick(
                &simulate(&Policy::default(), &engines, &wanted, now()),
                &engines
            )
            .as_deref(),
            Some("nvidia")
        );
        let vision = simulated_needs("docs", "small", &["vision".to_string()]).unwrap();
        assert_eq!(
            pick(
                &simulate(&Policy::default(), &engines, &vision, now()),
                &engines
            )
            .as_deref(),
            Some("seer")
        );
        assert!(simulated_needs("sorcery", "small", &[]).is_err());
        assert!(simulated_needs("docs", "huge", &[]).is_err());
        assert!(simulated_needs("docs", "small", &["telepathy".to_string()]).is_err());
    }

    #[test]
    fn the_top_kinds_are_the_most_decided_ones() {
        let mut list = Vec::new();
        for _ in 0..5 {
            record_outcome(&mut list, "docs", true, now());
        }
        record_outcome(&mut list, "docs", false, now());
        for _ in 0..2 {
            record_outcome(&mut list, "tests", true, now());
        }
        record_outcome(&mut list, "plan", true, now());
        let top = top_kinds(&list, now(), 2);
        assert_eq!(top.len(), 2);
        assert_eq!(top[0].0, "docs");
        assert!((top[0].1 - 5.0 / 6.0).abs() < 1e-3 && (top[0].2 - 6.0).abs() < 1e-3);
        assert_eq!(top[1].0, "tests");
    }
}
