//! The several engines one agent can run, which of them can run right now, and falling
//! back between them when one runs out of credit.
//!
//! # Why an agent has more than one engine
//!
//! A worker used to know exactly one engine. When that engine's prepaid balance ran out
//! it failed every order within a second, counted each failure against the order, backed
//! off, and eventually gave up - and it could not even act on an order telling it to
//! switch engines, because acting on anything needs an engine. The subscription engine
//! runs out mid-week, the prepaid ones run dry, the free tier is slow, and a local model
//! is always there. A fleet that must keep moving all week needs all of them, in order.
//!
//! # What this module decides
//!
//! - **Which engine runs an order**: the first usable one in the operator's order, at the
//!   order's tier or above. Chore engines never take build work; a judge engine builds
//!   only when every build engine is out.
//! - **Whether a failure is the engine's wallet or the work**: [`quota_reset`]. Running
//!   out of credit is not a failed attempt - the same order goes straight to the next
//!   engine and nothing is counted against it.
//! - **Whether an engine can run at all**, from a cheap probe every ten minutes and from
//!   the weekly caps the operator set.
//!
//! State lives on this machine, per agent, in the machine state directory: it describes
//! this machine's credentials and wallets, and a different machine has different ones.
//! What other machines should know is published, signed and without credentials, through
//! [`ferryman_channel::receipts::refresh_engines`].

use std::{
    collections::{BTreeMap, HashMap},
    path::{Path, PathBuf},
    time::{Duration, Instant},
};

use anyhow::{Context, Result, bail};
use chrono::{DateTime, Datelike, Utc};
use ferryman_channel::{ProjectRoute, receipts::EngineReport, trajectory::TokenUsage};
use serde::{Deserialize, Serialize};
use serde_json::{Value, json};

/// How often each engine is probed.
pub const PROBE_EVERY_SECS: i64 = 10 * 60;
/// How long an engine that ran out of credit is left alone when it did not say when it
/// will be back.
pub const DEFAULT_EXHAUSTED_HOURS: i64 = 6;
/// A rate limit that asks for a wait this long is a quota, not a hiccup.
const LONG_RETRY_SECS: u64 = 10 * 60;
/// The most a probe may take. The free tier is slow to answer prompts, not to list models.
const PROBE_TIMEOUT: Duration = Duration::from_secs(30);
/// How much of an engine's complaint is kept in the inventory.
const REASON_CHARS: usize = 200;
/// Refuted results, inside [`TRUST_WINDOW_DAYS`], that demote an engine to chore
/// work until it passes the canary.
pub const DEMOTE_AFTER: usize = 2;
/// The rolling window refutations are counted over.
pub const TRUST_WINDOW_DAYS: i64 = 14;
/// How often a demoted engine is given the canary.
pub const CANARY_EVERY_SECS: i64 = 60 * 60;
/// The file the canary asks for.
pub const CANARY_FILE: &str = "CANARY.txt";

/// What kind of work an engine is trusted with. Ordered: a judge can do anything a
/// builder can, a builder anything a chore engine can.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash, Serialize, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum Tier {
    Chore,
    Build,
    Judge,
}

impl Tier {
    pub fn parse(value: &str) -> Result<Self> {
        match value.trim().to_ascii_lowercase().as_str() {
            "chore" => Ok(Self::Chore),
            "build" | "" => Ok(Self::Build),
            "judge" => Ok(Self::Judge),
            other => bail!("tier must be judge, build or chore, not '{other}'"),
        }
    }

    #[must_use]
    pub fn as_str(self) -> &'static str {
        match self {
            Self::Chore => "chore",
            Self::Build => "build",
            Self::Judge => "judge",
        }
    }
}

/// How an engine is paid for, which is what decides how it runs out.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "kebab-case")]
pub enum Paid {
    Subscription,
    Prepaid,
    FreeTier,
    Local,
    Unknown,
}

impl Paid {
    pub fn parse(value: &str) -> Result<Self> {
        match value.trim().to_ascii_lowercase().as_str() {
            "subscription" => Ok(Self::Subscription),
            "prepaid" => Ok(Self::Prepaid),
            "free-tier" | "free" => Ok(Self::FreeTier),
            "local" => Ok(Self::Local),
            "unknown" | "" => Ok(Self::Unknown),
            other => bail!("paid must be subscription, prepaid, free-tier or local, not '{other}'"),
        }
    }

    #[must_use]
    pub fn as_str(self) -> &'static str {
        match self {
            Self::Subscription => "subscription",
            Self::Prepaid => "prepaid",
            Self::FreeTier => "free-tier",
            Self::Local => "local",
            Self::Unknown => "unknown",
        }
    }
}

/// How Ferryman talks to an engine.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum Kind {
    /// An agent CLI, run the way the single `command` always was.
    Cli,
    /// An OpenAI-compatible endpoint, asked once per order. It answers in text: it
    /// cannot edit files, so it suits judging, planning and chores. Pointing a CLI
    /// engine at the same endpoint is how an HTTP-only model builds.
    Http,
}

impl Kind {
    #[must_use]
    pub fn as_str(self) -> &'static str {
        match self {
            Self::Cli => "cli",
            Self::Http => "http",
        }
    }
}

/// One engine, as `agent.toml` describes it.
#[derive(Debug, Clone, PartialEq)]
pub struct EngineSpec {
    pub name: String,
    pub kind: Kind,
    pub tier: Tier,
    pub paid: Paid,
    /// The CLI to run. Empty for an HTTP engine.
    pub command: String,
    /// The CLI's arguments. `{prompt}`, `{model}` and `{base_url}` are filled in.
    pub args: Vec<String>,
    pub model: Option<String>,
    /// An OpenAI-compatible base URL, e.g. `https://integrate.api.nvidia.com/v1`. For an
    /// HTTP engine it is the engine; for a CLI engine it is only what the probe checks.
    pub base_url: Option<String>,
    /// `secret:NAME` or `env:NAME`, never the key itself.
    pub key: Option<String>,
    /// Extra environment for a CLI engine. Values may be `secret:NAME` or `env:NAME`.
    pub env: Vec<(String, String)>,
    /// Probe with a one-token request instead of listing models. For providers whose
    /// model list names models that then answer 404.
    pub probe_chat: bool,
    pub weekly_requests: Option<u64>,
    pub weekly_usd: Option<f64>,
}

impl EngineSpec {
    /// The engine an `agent.toml` without an `engines` list has always run.
    #[must_use]
    pub fn implicit(command: &str, args: &[String], model: Option<&str>) -> Self {
        Self {
            name: engine_label(command),
            kind: Kind::Cli,
            tier: Tier::Build,
            paid: Paid::Unknown,
            command: command.to_string(),
            args: args.to_vec(),
            model: model.map(str::to_string),
            base_url: None,
            key: None,
            env: Vec::new(),
            probe_chat: false,
            weekly_requests: None,
            weekly_usd: None,
        }
    }

    /// The CLI arguments with this engine's model and endpoint filled in. `{prompt}` is
    /// left for the runner, which fills it last.
    #[must_use]
    pub fn cli_args(&self) -> Vec<String> {
        self.args
            .iter()
            .map(|arg| {
                arg.replace("{model}", self.model.as_deref().unwrap_or(""))
                    .replace("{base_url}", self.base_url.as_deref().unwrap_or(""))
            })
            .collect()
    }
}

/// A short name for a command: its file name, lowercased, without `.exe`.
#[must_use]
pub fn engine_label(command: &str) -> String {
    let file = command
        .rsplit(['/', '\\'])
        .next()
        .unwrap_or(command)
        .to_ascii_lowercase();
    file.strip_suffix(".exe").unwrap_or(&file).to_string()
}

fn is_engine_name(name: &str) -> bool {
    !name.is_empty()
        && name.len() <= 40
        && name
            .chars()
            .all(|c| c.is_ascii_alphanumeric() || c == '-' || c == '_')
}

/// Read the engines out of `agent.toml`'s flat fields.
///
/// No `engines` key means exactly the one engine `command` names, as before. With one:
///
/// ```toml
/// engines = ["nvidia", "deepseek"]
/// engine.nvidia.kind = "http"
/// engine.nvidia.base_url = "https://integrate.api.nvidia.com/v1"
/// engine.nvidia.model = "qwen/qwen3-coder-480b-a35b-instruct"
/// engine.nvidia.key = "secret:NVIDIA_API_KEY"
/// engine.nvidia.tier = "build"
/// engine.nvidia.paid = "free-tier"
/// engine.deepseek.tier = "build"
/// engine.deepseek.paid = "prepaid"
/// ```
///
/// A CLI engine with no `command` of its own runs the top-level `command` and `args`,
/// so the old single-engine config becomes one entry in the list by naming it.
pub fn parse_engines(
    fields: &HashMap<String, String>,
    command: &str,
    args: &[String],
    model: Option<&str>,
) -> Result<Vec<EngineSpec>> {
    let Some(list) = fields
        .get("engines")
        .filter(|value| !value.trim().is_empty())
    else {
        return Ok(vec![EngineSpec::implicit(command, args, model)]);
    };
    let names: Vec<String> = serde_json::from_str(list)
        .context("engines must be a JSON array of names, e.g. [\"nvidia\",\"deepseek\"]")?;
    if names.is_empty() {
        bail!("engines is empty; leave it out to run only 'command'")
    }
    let mut out: Vec<EngineSpec> = Vec::new();
    for name in names {
        if !is_engine_name(&name) {
            bail!("engine name '{name}' must be letters, digits, '-' or '_'")
        }
        if out.iter().any(|e| e.name.eq_ignore_ascii_case(&name)) {
            bail!("engine '{name}' is listed twice")
        }
        let get = |field: &str| {
            fields
                .get(&format!("engine.{name}.{field}"))
                .map(|value| value.trim().to_string())
                .filter(|value| !value.is_empty())
        };
        let own_command = get("command");
        let base_url = get("base_url").map(|url| url.trim_end_matches('/').to_string());
        let kind = match get("kind").as_deref() {
            Some("http") => Kind::Http,
            Some("cli") => Kind::Cli,
            None if own_command.is_none() && base_url.is_some() => Kind::Http,
            None => Kind::Cli,
            Some(other) => bail!("engine.{name}.kind must be cli or http, not '{other}'"),
        };
        let key = get("key");
        if let Some(key) = &key
            && !(key.starts_with("secret:") || key.starts_with("env:"))
        {
            bail!(
                "engine.{name}.key must be secret:NAME or env:NAME - the key itself never \
                 goes in agent.toml"
            )
        }
        let env = match get("env") {
            None => Vec::new(),
            Some(raw) => serde_json::from_str::<BTreeMap<String, String>>(&raw)
                .with_context(|| format!("engine.{name}.env must be a JSON object of NAME: value"))?
                .into_iter()
                .collect(),
        };
        let engine_args = match get("args") {
            Some(raw) => serde_json::from_str(&raw)
                .with_context(|| format!("engine.{name}.args must be a JSON array of strings"))?,
            None => match &own_command {
                Some(own) => crate::agent::AgentConfig::default_args(own),
                None => args.to_vec(),
            },
        };
        let number = |field: &str| -> Result<Option<u64>> {
            get(field)
                .map(|value| {
                    value
                        .parse::<u64>()
                        .with_context(|| format!("engine.{name}.{field} must be a whole number"))
                })
                .transpose()
        };
        let weekly_usd = get("weekly_usd")
            .map(|value| {
                value
                    .parse::<f64>()
                    .with_context(|| format!("engine.{name}.weekly_usd must be a number"))
            })
            .transpose()?;
        let spec_model = get("model").or_else(|| {
            (kind == Kind::Cli && own_command.is_none())
                .then(|| model.map(str::to_string))
                .flatten()
        });
        if kind == Kind::Http && (base_url.is_none() || spec_model.is_none()) {
            bail!("engine.{name} is an http engine and needs both base_url and model")
        }
        let paid = match get("paid") {
            Some(value) => Paid::parse(&value)?,
            None if base_url.as_deref().is_some_and(is_local_url) => Paid::Local,
            None => Paid::Unknown,
        };
        out.push(EngineSpec {
            kind,
            tier: Tier::parse(&get("tier").unwrap_or_default())?,
            paid,
            command: match kind {
                Kind::Cli => own_command.unwrap_or_else(|| command.to_string()),
                Kind::Http => String::new(),
            },
            args: engine_args,
            model: spec_model,
            base_url,
            key,
            env,
            probe_chat: get("probe").as_deref() == Some("chat"),
            weekly_requests: number("weekly_requests")?,
            weekly_usd,
            name,
        });
    }
    Ok(out)
}

fn is_local_url(url: &str) -> bool {
    let rest = url.split("://").nth(1).unwrap_or(url);
    ["localhost", "127.0.0.1", "[::1]", "0.0.0.0"]
        .iter()
        .any(|host| rest.starts_with(host))
}

// --- what this machine knows about each engine -----------------------------------------

/// This machine's record of one engine.
#[derive(Debug, Clone, Default, Serialize, Deserialize, PartialEq)]
pub struct EngineState {
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub exhausted_until: Option<DateTime<Utc>>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub exhausted_reason: Option<String>,
    /// Why the last probe failed, when it did.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub down: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub checked_at: Option<DateTime<Utc>>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub latency_ms: Option<u64>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub balance: Option<String>,
    /// The ISO week the counts below belong to.
    #[serde(default)]
    pub week: String,
    #[serde(default)]
    pub requests: u64,
    #[serde(default)]
    pub spend_usd: f64,
    /// Results whose worker-recorded evidence agreed with the claim.
    #[serde(default)]
    pub verified: u64,
    /// Results whose evidence refuted the claim, ever.
    #[serde(default, alias = "contradicted")]
    pub refuted: u64,
    /// Results the evidence could neither confirm nor refute.
    #[serde(default)]
    pub unverified: u64,
    /// When each refutation inside [`TRUST_WINDOW_DAYS`] happened.
    #[serde(
        default,
        alias = "contradictions",
        skip_serializing_if = "Vec::is_empty"
    )]
    pub refutations: Vec<DateTime<Utc>>,
    /// Demoted to chore work after [`DEMOTE_AFTER`] refutations, until the canary
    /// passes.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub demoted_at: Option<DateTime<Utc>>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub canary_tried_at: Option<DateTime<Utc>>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub canary_passed_at: Option<DateTime<Utc>>,
    /// A free-tier engine that asked for payment, ran out of quota or reported a cost:
    /// why, and when. Auto mode ranks it down for [`ferryman_channel::policy::FLAG_DAYS`].
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub free_tier_flag: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub free_tier_flagged_at: Option<DateTime<Utc>>,
}

impl EngineState {
    /// Whether refuted results have demoted this engine to chore work.
    #[must_use]
    pub fn demoted(&self) -> bool {
        self.demoted_at.is_some()
    }

    /// Why a free tier is flagged, while the flag lasts.
    #[must_use]
    pub fn free_tier_flag(&self, now: DateTime<Utc>) -> Option<String> {
        let at = self.free_tier_flagged_at?;
        (now.signed_duration_since(at)
            < chrono::Duration::days(ferryman_channel::policy::FLAG_DAYS))
        .then(|| self.free_tier_flag.clone())
        .flatten()
    }
}

/// Flag a free-tier engine that asked for money. Returns whether it was not flagged
/// already, so the master is told once rather than on every failure.
pub fn flag_free_tier(agent: &str, engine: &str, reason: &str, now: DateTime<Utc>) -> bool {
    let mut fresh = false;
    update(agent, |ledger| {
        let state = ledger.entry(engine);
        fresh = state.free_tier_flag(now).is_none();
        state.free_tier_flag = Some(clip(reason));
        state.free_tier_flagged_at = Some(now);
    });
    fresh
}

/// Every engine one agent runs on this machine.
#[derive(Debug, Clone, Default, Serialize, Deserialize)]
pub struct Ledger {
    #[serde(default)]
    pub engines: BTreeMap<String, EngineState>,
}

/// Where an agent's engine ledger lives on this machine.
#[must_use]
pub fn ledger_path(agent: &str) -> Option<PathBuf> {
    let name = ferryman_channel::canonical_agent_name(agent);
    #[cfg(test)]
    {
        // Tests never touch the real machine's ledger, and threads never share one.
        let thread = format!("{:?}", std::thread::current().id())
            .chars()
            .filter(char::is_ascii_alphanumeric)
            .collect::<String>();
        Some(
            std::env::temp_dir()
                .join(format!("ferryman-ops-engines-{}", std::process::id()))
                .join(thread)
                .join(format!("{name}.json")),
        )
    }
    #[cfg(not(test))]
    {
        ferryman_channel::licensing::machine_state_dir()
            .map(|dir| dir.join("engines").join(format!("{name}.json")))
    }
}

impl Ledger {
    /// Read the ledger. A missing or unreadable one is empty: nothing known yet.
    #[must_use]
    pub fn load(agent: &str) -> Self {
        ledger_path(agent)
            .and_then(|path| std::fs::read_to_string(path).ok())
            .and_then(|text| serde_json::from_str(&text).ok())
            .unwrap_or_default()
    }

    pub fn save(&self, agent: &str) -> Result<()> {
        let Some(path) = ledger_path(agent) else {
            return Ok(());
        };
        if let Some(parent) = path.parent() {
            std::fs::create_dir_all(parent)?;
        }
        let temp = path.with_extension("json.tmp");
        std::fs::write(&temp, serde_json::to_vec_pretty(self)?)?;
        std::fs::rename(&temp, &path).with_context(|| format!("write {}", path.display()))
    }

    #[must_use]
    pub fn state(&self, engine: &str) -> EngineState {
        self.engines.get(engine).cloned().unwrap_or_default()
    }

    fn entry(&mut self, engine: &str) -> &mut EngineState {
        self.engines.entry(engine.to_string()).or_default()
    }
}

/// Change an agent's ledger. Best effort: the ledger informs choices, it never blocks
/// work.
pub fn update(agent: &str, change: impl FnOnce(&mut Ledger)) {
    let mut ledger = Ledger::load(agent);
    change(&mut ledger);
    if let Err(error) = ledger.save(agent) {
        tracing::warn!("could not save the engine ledger for {agent}: {error:#}");
    }
}

/// Mark an engine out of credit until `until`.
pub fn mark_exhausted(agent: &str, engine: &str, until: DateTime<Utc>, reason: &str) {
    update(agent, |ledger| {
        let state = ledger.entry(engine);
        state.exhausted_until = Some(until);
        state.exhausted_reason = Some(clip(reason));
    });
}

/// Count one request, and what it cost, against the engine's week.
pub fn record_use(agent: &str, engine: &str, cost_usd: f64, now: DateTime<Utc>) {
    update(agent, |ledger| {
        let state = ledger.entry(engine);
        let week = iso_week(now);
        if state.week != week {
            state.week = week;
            state.requests = 0;
            state.spend_usd = 0.0;
        }
        state.requests += 1;
        state.spend_usd += cost_usd.max(0.0);
    });
}

/// `2026-W39`: the ISO week `now` falls in.
#[must_use]
pub fn iso_week(now: DateTime<Utc>) -> String {
    let week = now.iso_week();
    format!("{}-W{:02}", week.year(), week.week())
}

/// The next Monday, 00:00 UTC.
#[must_use]
pub fn next_week(now: DateTime<Utc>) -> DateTime<Utc> {
    let days = 7 - u64::from(now.weekday().num_days_from_monday());
    (now.date_naive() + chrono::Days::new(days))
        .and_hms_opt(0, 0, 0)
        .map_or(now, |midnight| midnight.and_utc())
}

/// Whether an engine can be given work.
#[derive(Debug, Clone, PartialEq)]
pub enum Availability {
    /// The last probe answered.
    Up,
    /// Never probed yet.
    Unknown,
    /// The last probe failed. Still tried, after everything that is up.
    Down(String),
    /// Out of credit, or over the operator's weekly cap. Not tried until `until`.
    Exhausted {
        until: DateTime<Utc>,
        reason: String,
    },
}

impl Availability {
    #[must_use]
    pub fn usable(&self) -> bool {
        !matches!(self, Self::Exhausted { .. })
    }

    #[must_use]
    pub fn describe(&self) -> String {
        match self {
            Self::Up => "up".to_string(),
            Self::Unknown => "not probed yet".to_string(),
            Self::Down(why) => format!("down: {why}"),
            Self::Exhausted { until, reason } => format!(
                "exhausted until {}: {reason}",
                until.format("%a %Y-%m-%d %H:%M UTC")
            ),
        }
    }
}

/// What the ledger and the caps say about one engine at `now`.
#[must_use]
pub fn availability(spec: &EngineSpec, state: &EngineState, now: DateTime<Utc>) -> Availability {
    if let Some(until) = state.exhausted_until
        && until > now
    {
        return Availability::Exhausted {
            until,
            reason: state
                .exhausted_reason
                .clone()
                .unwrap_or_else(|| "out of credit".to_string()),
        };
    }
    if state.week == iso_week(now) {
        let over = match (spec.weekly_requests, spec.weekly_usd) {
            (Some(cap), _) if state.requests >= cap => {
                Some(format!("weekly cap of {cap} requests reached"))
            }
            (_, Some(cap)) if state.spend_usd >= cap => {
                Some(format!("weekly budget of ${cap:.2} spent"))
            }
            _ => None,
        };
        if let Some(reason) = over {
            return Availability::Exhausted {
                until: next_week(now),
                reason,
            };
        }
    }
    match (&state.down, state.checked_at) {
        (Some(why), _) => Availability::Down(why.clone()),
        (None, None) => Availability::Unknown,
        (None, Some(_)) => Availability::Up,
    }
}

/// The engine to run next for work wanting `wanted`, skipping those already `tried`.
///
/// Never below `wanted`. Among the rest: the nearest tier first - so a judge builds only
/// when every builder is out - then engines that answered their probe before those that
/// did not, then the operator's order.
#[must_use]
pub fn pick<'a>(
    specs: &'a [EngineSpec],
    ledger: &Ledger,
    now: DateTime<Utc>,
    wanted: Tier,
    tried: &[String],
) -> Option<&'a EngineSpec> {
    specs
        .iter()
        .enumerate()
        .filter(|(_, spec)| !tried.contains(&spec.name))
        .filter_map(|(index, spec)| {
            let state = ledger.state(&spec.name);
            // A demoted engine is trusted with chore work only, whatever its own tier.
            let tier = effective_tier(spec, &state);
            if tier < wanted {
                return None;
            }
            let available = availability(spec, &state, now);
            available.usable().then(|| {
                let down = matches!(available, Availability::Down(_));
                ((tier as u8 - wanted as u8, down, index), spec)
            })
        })
        .min_by_key(|(rank, _)| *rank)
        .map(|(_, spec)| spec)
}

/// The best engine of exactly `tier` that is up, for asking rather than building.
#[must_use]
pub fn best_up<'a>(
    specs: &'a [EngineSpec],
    ledger: &Ledger,
    now: DateTime<Utc>,
    tier: Tier,
) -> Option<&'a EngineSpec> {
    let usable: Vec<&EngineSpec> = specs
        .iter()
        .filter(|spec| effective_tier(spec, &ledger.state(&spec.name)) == tier)
        .filter(|spec| availability(spec, &ledger.state(&spec.name), now).usable())
        .collect();
    usable
        .iter()
        .find(|spec| {
            !matches!(
                availability(spec, &ledger.state(&spec.name), now),
                Availability::Down(_)
            )
        })
        .or(usable.first())
        .copied()
}

/// Why no engine can take work at all, or `None` when at least one can.
#[must_use]
pub fn all_exhausted(specs: &[EngineSpec], ledger: &Ledger, now: DateTime<Utc>) -> Option<String> {
    let mut why = Vec::new();
    for spec in specs {
        match availability(spec, &ledger.state(&spec.name), now) {
            Availability::Exhausted { until, reason } => why.push(format!(
                "{} until {} ({reason})",
                spec.name,
                until.format("%a %H:%M UTC")
            )),
            _ => return None,
        }
    }
    Some(format!("every engine is out of credit: {}", why.join("; ")))
}

// --- the engine policy ------------------------------------------------------------------

/// This worker's engines as the engine policy ranks them: the same lines it publishes,
/// so a local choice and the fleet's view of it can never disagree.
#[must_use]
pub fn candidates(
    agent: &str,
    machine: &str,
    specs: &[EngineSpec],
    ledger: &Ledger,
    now: DateTime<Utc>,
) -> Vec<ferryman_channel::policy::Candidate> {
    reports(specs, ledger, now)
        .iter()
        .enumerate()
        .map(|(order, report)| {
            ferryman_channel::policy::Candidate::from_report(agent, machine, order, report)
        })
        .collect()
}

/// The engine to run next for background work in `role`, skipping those already
/// `tried`: the policy's choice, or why there is none. Never falls back to an engine the
/// policy blocks - with nothing allowed, the work waits.
///
/// `tier` is the order's tier for build and chore work; plan and review ignore it.
#[allow(clippy::too_many_arguments)]
pub fn choose<'a>(
    specs: &'a [EngineSpec],
    ledger: &Ledger,
    now: DateTime<Utc>,
    policy: &ferryman_channel::policy::Policy,
    role: ferryman_channel::policy::Role,
    tier: Tier,
    tried: &[String],
    (agent, machine): (&str, &str),
) -> std::result::Result<&'a EngineSpec, String> {
    let all = candidates(agent, machine, specs, ledger, now);
    let ranking = ferryman_channel::policy::rank(
        policy,
        role,
        tier.as_str(),
        ferryman_channel::policy::Work::Background,
        &all,
    );
    ranking
        .order
        .iter()
        .map(|index| &specs[*index])
        .find(|spec| !tried.contains(&spec.name))
        .ok_or_else(|| {
            if ranking.order.is_empty() {
                ranking.why_none(role, &all)
            } else {
                format!(
                    "every allowed engine for {} work was tried ({})",
                    role.as_str(),
                    tried.join(", ")
                )
            }
        })
}

/// The engine to run next for a person's own order: [`pick`], except that a policy whose
/// `never` applies to all work is honoured. Subscriptions are never protected from the
/// person who pays for them.
#[must_use]
pub fn pick_direct<'a>(
    specs: &'a [EngineSpec],
    ledger: &Ledger,
    now: DateTime<Utc>,
    wanted: Tier,
    tried: &[String],
    policy: &ferryman_channel::policy::Policy,
    (agent, machine): (&str, &str),
) -> Option<&'a EngineSpec> {
    if policy.never_applies_to != ferryman_channel::policy::NeverScope::All {
        return pick(specs, ledger, now, wanted, tried);
    }
    let all = candidates(agent, machine, specs, ledger, now);
    let mut skip = tried.to_vec();
    for (spec, candidate) in specs.iter().zip(&all) {
        if policy
            .blocked(candidate, ferryman_channel::policy::Work::Direct)
            .is_some()
        {
            skip.push(spec.name.clone());
        }
    }
    pick(specs, ledger, now, wanted, &skip)
}

/// The host of an endpoint URL, never more: no path, no credentials, no port.
#[must_use]
pub fn url_host(url: &str) -> Option<String> {
    let rest = url.split("://").nth(1).unwrap_or(url);
    let authority = rest.split(['/', '?', '#']).next()?;
    let host = authority.rsplit('@').next()?;
    let host = if host.starts_with('[') {
        host.split(']').next().map(|h| format!("{h}]"))?
    } else {
        host.split(':').next()?.to_string()
    };
    (!host.is_empty()).then(|| host.to_ascii_lowercase())
}

// --- trust: whether an engine's claims hold up ------------------------------------------

/// The tier an engine may work at now: its own, or chore while it is demoted.
#[must_use]
pub fn effective_tier(spec: &EngineSpec, state: &EngineState) -> Tier {
    if state.demoted() {
        spec.tier.min(Tier::Chore)
    } else {
        spec.tier
    }
}

/// Count one result's evidence for the engine that produced it, on this machine.
/// [`DEMOTE_AFTER`] refutations inside [`TRUST_WINDOW_DAYS`] demote it to chore work
/// until it passes the canary. Returns whether this result demoted it.
pub fn record_verification(
    agent: &str,
    engine: &str,
    status: ferryman_channel::evidence::Status,
    now: DateTime<Utc>,
) -> bool {
    let mut demoted = false;
    update(agent, |ledger| {
        demoted = ledger.entry(engine).note(status, now)
    });
    demoted
}

impl EngineState {
    /// Count one verification outcome. Returns whether it demoted the engine.
    pub fn note(&mut self, status: ferryman_channel::evidence::Status, now: DateTime<Utc>) -> bool {
        use ferryman_channel::evidence::Status;
        let window = now - chrono::Duration::days(TRUST_WINDOW_DAYS);
        self.refutations.retain(|at| *at > window);
        match status {
            Status::Verified => self.verified += 1,
            Status::Refuted => {
                self.refuted += 1;
                self.refutations.push(now);
                if !self.demoted() && self.refutations.len() >= DEMOTE_AFTER {
                    self.demoted_at = Some(now);
                    self.canary_tried_at = None;
                    return true;
                }
            }
            Status::Unverified => self.unverified += 1,
            Status::NotApplicable => {}
        }
        false
    }

    /// Count one canary run. A pass lifts the demotion and clears the recent
    /// refutations; the lifetime counts stay.
    pub fn canary(&mut self, passed: bool, now: DateTime<Utc>) {
        self.canary_tried_at = Some(now);
        if passed {
            self.canary_passed_at = Some(now);
            self.demoted_at = None;
            self.refutations.clear();
        }
    }
}

/// Whether a demoted engine is due its canary: never tried since demotion, or not for
/// [`CANARY_EVERY_SECS`].
#[must_use]
pub fn canary_due(state: &EngineState, now: DateTime<Utc>) -> bool {
    state.demoted()
        && state.canary_tried_at.is_none_or(|at| {
            let since = now.signed_duration_since(at);
            since < chrono::Duration::zero()
                || since >= chrono::Duration::seconds(CANARY_EVERY_SECS)
        })
}

/// Record a canary run. A pass lifts the demotion and clears the recent
/// refutations; the lifetime counts stay.
pub fn record_canary(agent: &str, engine: &str, passed: bool, now: DateTime<Utc>) {
    update(agent, |ledger| ledger.entry(engine).canary(passed, now));
}

/// The trust line published for an engine, once anything is known.
#[must_use]
pub fn trust(state: &EngineState) -> Option<ferryman_channel::receipts::EngineTrust> {
    (state.verified > 0 || state.refuted > 0 || state.unverified > 0 || state.demoted()).then(
        || ferryman_channel::receipts::EngineTrust {
            verified: state.verified,
            refuted: state.refuted,
            unverified: state.unverified,
            recent: u32::try_from(state.refutations.len()).unwrap_or(u32::MAX),
            demoted: state.demoted(),
            demoted_at: state.demoted_at,
            canary_passed_at: state.canary_passed_at,
        },
    )
}

fn git_in(dir: &Path, args: &[&str]) -> Option<String> {
    let out = std::process::Command::new("git")
        .arg("-C")
        .arg(dir)
        .args(args)
        .stdin(std::process::Stdio::null())
        .output()
        .ok()?;
    out.status
        .success()
        .then(|| String::from_utf8_lossy(&out.stdout).trim().to_string())
}

/// Make the canary's throwaway repository in the empty directory `dir`: one commit, so
/// there is a `HEAD` to measure from. Returns that commit and the line the engine is
/// asked to write.
pub fn canary_repo(dir: &Path) -> Result<(String, String)> {
    std::fs::create_dir_all(dir).with_context(|| format!("create {}", dir.display()))?;
    for args in [
        vec!["init", "-q", "--template="],
        vec!["config", "user.email", "canary@ferryman.invalid"],
        vec!["config", "user.name", "ferryman canary"],
    ] {
        git_in(dir, &args).with_context(|| format!("git {args:?} in {}", dir.display()))?;
    }
    std::fs::write(
        dir.join("README.md"),
        "A throwaway repository for a canary.\n",
    )?;
    git_in(dir, &["add", "README.md"]).context("git add")?;
    git_in(dir, &["commit", "-q", "-m", "start"]).context("git commit")?;
    let base = git_in(dir, &["rev-parse", "HEAD"]).context("git rev-parse")?;
    let token = format!("ferryman canary {}", ferryman_channel::new_run_id());
    Ok((base, token))
}

/// What the canary asks.
#[must_use]
pub fn canary_prompt(token: &str) -> String {
    format!(
        "This is a short test of whether you can change files and commit them. In the \
         current directory, which is a git repository, create a file named {CANARY_FILE} \
         containing exactly this one line:\n\n{token}\n\nThen commit it with git (git add \
         {CANARY_FILE}, then git commit -m \"canary\"). Reply with the commit hash."
    )
}

/// Whether the canary was really done: a new commit after `base` that adds the file with
/// the line in it. Checked with git, never taken from the engine's answer.
#[must_use]
pub fn canary_holds(dir: &Path, base: &str, token: &str) -> bool {
    let range = format!("{base}..HEAD");
    let committed = git_in(dir, &["log", "--format=%H", &range, "--", CANARY_FILE])
        .is_some_and(|commits| !commits.is_empty());
    let content = git_in(dir, &["show", &format!("HEAD:{CANARY_FILE}")]);
    committed && content.is_some_and(|text| text.contains(token))
}

// --- telling a wallet from a failure ---------------------------------------------------

/// An engine that cannot take this order now, for a reason that is not the order's.
///
/// Returned as an error from a run, so the loop can tell it apart from a task that
/// failed: it is never counted as an attempt, and the order goes to the next engine.
#[derive(Debug)]
pub struct Unavailable {
    pub engine: String,
    /// Out of credit until then. `None` when the engine simply cannot run here - an
    /// endpoint that did not answer, a key not held in this channel.
    pub until: Option<DateTime<Utc>>,
    pub reason: String,
}

impl std::fmt::Display for Unavailable {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self.until {
            Some(until) => write!(
                f,
                "engine '{}' is out of credit until {}: {}",
                self.engine,
                until.format("%a %Y-%m-%d %H:%M UTC"),
                self.reason
            ),
            None => write!(
                f,
                "engine '{}' cannot run here: {}",
                self.engine, self.reason
            ),
        }
    }
}

impl std::error::Error for Unavailable {}

/// When an engine that said this will have credit again, or `None` when what it said
/// is an ordinary failure.
///
/// Out of credit: HTTP 402, "insufficient balance", "usage limit", credit that has run
/// out, a daily rate limit, or a 429 that asks for a wait of ten minutes or more. The
/// reset is read from the message when it gives one (a `retry-after`, "try again in
/// 2h13m", Claude's `limit reached|<epoch>`), otherwise six hours.
#[must_use]
pub fn quota_reset(text: &str, now: DateTime<Utc>) -> Option<DateTime<Utc>> {
    let t = text.to_ascii_lowercase();
    const OUT_OF_CREDIT: [&str; 17] = [
        "insufficient balance",
        "insufficient_balance",
        "insufficient credit",
        "insufficient funds",
        "insufficient_quota",
        "exceeded your current quota",
        "quota exceeded",
        "quota_exceeded",
        "usage limit",
        "out of credits",
        "credit balance is too low",
        "payment required",
        "http 402",
        "status 402",
        "error 402",
        "\"code\":402",
        "code: 402",
    ];
    let hard = OUT_OF_CREDIT.iter().any(|marker| t.contains(marker));
    let credit = t.contains("credit")
        && [
            "insufficient",
            "exhausted",
            "out of",
            "run out",
            "ran out",
            "not enough",
            "no remaining",
        ]
        .iter()
        .any(|word| t.contains(word));
    let limited = t.contains("429") || t.contains("too many requests") || t.contains("rate limit");
    let daily = limited
        && ["per day", "daily", "requests per day", "rpd"]
            .iter()
            .any(|word| t.contains(word));
    let wait = retry_after(&t);
    let long_wait = limited && wait.is_some_and(|w| w >= Duration::from_secs(LONG_RETRY_SECS));
    if !(hard || credit || daily || long_wait) {
        return None;
    }
    let until = epoch_reset(&t, now)
        .or_else(|| wait.and_then(|w| chrono::Duration::from_std(w).ok().map(|w| now + w)))
        .unwrap_or(now + chrono::Duration::hours(DEFAULT_EXHAUSTED_HOURS));
    Some(until.clamp(
        now + chrono::Duration::minutes(1),
        now + chrono::Duration::days(8),
    ))
}

/// Claude Code's `usage limit reached|1759000000`.
fn epoch_reset(t: &str, now: DateTime<Utc>) -> Option<DateTime<Utc>> {
    t.match_indices('|').find_map(|(at, _)| {
        let digits: String = t[at + 1..]
            .chars()
            .take_while(char::is_ascii_digit)
            .collect();
        (digits.len() == 10)
            .then(|| digits.parse::<i64>().ok())
            .flatten()
            .and_then(|secs| DateTime::from_timestamp(secs, 0))
            .filter(|at| *at > now)
    })
}

/// A wait the message asks for, from the markers providers use.
fn retry_after(t: &str) -> Option<Duration> {
    const MARKERS: [&str; 7] = [
        "retry-after",
        "retry_after",
        "retry after",
        "try again in",
        "resets in",
        "reset in",
        "retry in",
    ];
    MARKERS.iter().find_map(|marker| {
        t.match_indices(marker).find_map(|(at, _)| {
            let rest = t[at + marker.len()..].trim_start_matches([':', '"', '=', ' ', '\'']);
            parse_wait(rest)
        })
    })
}

/// `3600`, `3600s`, `45 minutes`, `2h13m`, `1.5 hours`.
fn parse_wait(text: &str) -> Option<Duration> {
    let mut rest = text;
    let mut total = 0.0_f64;
    let mut any = false;
    loop {
        let number: String = rest
            .chars()
            .take_while(|c| c.is_ascii_digit() || *c == '.')
            .collect();
        if number.is_empty() {
            break;
        }
        let Ok(value) = number.parse::<f64>() else {
            break;
        };
        rest = rest[number.len()..].trim_start();
        let unit: String = rest.chars().take_while(char::is_ascii_alphabetic).collect();
        let scale = match unit.as_str() {
            "ms" => 0.001,
            "" | "s" | "sec" | "secs" | "second" | "seconds" => 1.0,
            "m" | "min" | "mins" | "minute" | "minutes" => 60.0,
            "h" | "hr" | "hrs" | "hour" | "hours" => 3600.0,
            "d" | "day" | "days" => 86_400.0,
            _ => 1.0,
        };
        total += value * scale;
        any = true;
        rest = &rest[unit.len()..];
        if unit.is_empty() || !rest.starts_with(|c: char| c.is_ascii_digit()) {
            break;
        }
    }
    (any && total.is_finite() && total >= 0.0).then(|| Duration::from_secs_f64(total))
}

fn clip(text: &str) -> String {
    let text = text.trim();
    if text.chars().count() <= REASON_CHARS {
        return text.to_string();
    }
    let kept: String = text.chars().take(REASON_CHARS).collect();
    format!("{kept}...")
}

fn redact(text: &str, key: Option<&str>) -> String {
    match key {
        Some(key) if key.len() >= 8 => text.replace(key, "[redacted]"),
        _ => text.to_string(),
    }
}

// --- credentials ------------------------------------------------------------------------

/// Resolve one configured value: `env:NAME` from this worker's environment,
/// `secret:NAME` from this channel's sealed secrets, anything else as written.
pub fn resolve_value(route: &ProjectRoute, agent: &str, value: &str) -> Result<String> {
    if let Some(name) = value.strip_prefix("env:") {
        return std::env::var(name)
            .with_context(|| format!("environment variable {name} is not set for this worker"));
    }
    let Some(name) = value.strip_prefix("secret:") else {
        return Ok(value.to_string());
    };
    let encryption =
        ferryman_channel::secrets::EncryptionIdentity::load_existing(agent, &route.attachment)?;
    let resolved = ferryman_channel::secrets::resolve_credentials(
        route,
        HashMap::from([("value".to_string(), value.to_string())]),
        encryption.as_ref(),
    )?;
    match resolved.get("value") {
        Some(found) if found != value => Ok(found.clone()),
        _ => bail!(
            "secret {name} is not held in the {} channel",
            route.project_id
        ),
    }
}

/// The engine's key, resolved, when it has one.
pub fn engine_key(route: &ProjectRoute, agent: &str, spec: &EngineSpec) -> Result<Option<String>> {
    spec.key
        .as_deref()
        .map(|key| resolve_value(route, agent, key))
        .transpose()
}

/// The environment a CLI engine runs with, resolved.
pub fn engine_env(
    route: &ProjectRoute,
    agent: &str,
    spec: &EngineSpec,
) -> Result<Vec<(String, String)>> {
    spec.env
        .iter()
        .map(|(name, value)| Ok((name.clone(), resolve_value(route, agent, value)?)))
        .collect()
}

// --- asking an OpenAI-compatible endpoint ----------------------------------------------

/// What one request to an HTTP engine came back with.
#[derive(Debug, Clone, Default)]
pub struct ChatRun {
    pub ok: bool,
    pub text: String,
    /// Why it failed, as the provider said it. Never carries the key.
    pub detail: String,
    pub usage: Option<TokenUsage>,
    /// Dollars, when the provider itself said what the request cost (OpenRouter's
    /// `usage.cost`, say). A free tier that reports a cost is flagged.
    pub cost_usd: Option<f64>,
    /// Nothing answered at all.
    pub unreachable: bool,
}

fn client(timeout: Duration) -> Result<reqwest::Client> {
    reqwest::Client::builder()
        .timeout(timeout)
        .connect_timeout(Duration::from_secs(20))
        .build()
        .context("build the HTTP client")
}

/// Ask an HTTP engine one prompt.
pub async fn chat(
    spec: &EngineSpec,
    key: Option<&str>,
    prompt: &str,
    timeout: Duration,
) -> ChatRun {
    let base = spec.base_url.as_deref().unwrap_or_default();
    #[cfg(test)]
    if let Some(canned) = base.strip_prefix("fake://") {
        return fake_chat(canned);
    }
    let body = json!({
        "model": spec.model,
        "messages": [{"role": "user", "content": prompt}],
        "stream": false,
    });
    let run = async {
        let mut request = client(timeout)?
            .post(format!("{base}/chat/completions"))
            .json(&body);
        if let Some(key) = key {
            request = request.bearer_auth(key);
        }
        Ok::<_, anyhow::Error>(request.send().await)
    };
    let response = match run.await {
        Ok(Ok(response)) => response,
        Ok(Err(error)) => {
            return ChatRun {
                detail: redact(&format!("could not reach {base}: {error}"), key),
                unreachable: error.is_connect() || error.is_request(),
                ..ChatRun::default()
            };
        }
        Err(error) => {
            return ChatRun {
                detail: format!("{error:#}"),
                unreachable: true,
                ..ChatRun::default()
            };
        }
    };
    let status = response.status();
    let retry = response
        .headers()
        .get(reqwest::header::RETRY_AFTER)
        .and_then(|value| value.to_str().ok())
        .map(|value| format!(" retry-after: {value}"))
        .unwrap_or_default();
    let text = response.text().await.unwrap_or_default();
    if !status.is_success() {
        return ChatRun {
            detail: redact(
                &format!("HTTP {}{retry}: {}", status.as_u16(), clip(&text)),
                key,
            ),
            ..ChatRun::default()
        };
    }
    chat_reply(&text)
}

/// Read an OpenAI-shaped chat completion.
fn chat_reply(body: &str) -> ChatRun {
    let Ok(value) = serde_json::from_str::<Value>(body) else {
        return ChatRun {
            detail: format!("the reply was not JSON: {}", clip(body)),
            ..ChatRun::default()
        };
    };
    if let Some(error) = value.get("error") {
        return ChatRun {
            detail: clip(&error.to_string()),
            ..ChatRun::default()
        };
    }
    let message = &value["choices"][0]["message"];
    let answer = message["content"]
        .as_str()
        .filter(|text| !text.trim().is_empty())
        .or_else(|| message["reasoning_content"].as_str())
        .unwrap_or_default()
        .trim()
        .to_string();
    let usage = value.get("usage").and_then(|usage| {
        Some(TokenUsage {
            prompt_tokens: usage.get("prompt_tokens")?.as_u64()?,
            completion_tokens: usage.get("completion_tokens")?.as_u64()?,
        })
    });
    let cost_usd = value["usage"]["cost"]
        .as_f64()
        .or_else(|| value["cost"].as_f64())
        .filter(|cost| cost.is_finite() && *cost >= 0.0);
    if answer.is_empty() {
        return ChatRun {
            detail: "the reply carried no answer".to_string(),
            usage,
            cost_usd,
            ..ChatRun::default()
        };
    }
    ChatRun {
        ok: true,
        text: answer,
        usage,
        cost_usd,
        ..ChatRun::default()
    }
}

/// Canned replies for tests: `fake://ok:<answer>`, `fake://quota`, `fake://down`, and
/// `fake://paid:<answer>`, an answer whose provider says it cost a cent.
#[cfg(test)]
fn fake_chat(canned: &str) -> ChatRun {
    if let Some(answer) = canned.strip_prefix("paid:") {
        return ChatRun {
            ok: true,
            text: answer.to_string(),
            cost_usd: Some(0.01),
            ..ChatRun::default()
        };
    }
    match canned {
        "quota" => ChatRun {
            detail: "HTTP 402: Insufficient Balance".to_string(),
            ..ChatRun::default()
        },
        "down" => ChatRun {
            detail: "could not reach fake://down: connection refused".to_string(),
            unreachable: true,
            ..ChatRun::default()
        },
        other => ChatRun {
            ok: true,
            text: other.strip_prefix("ok:").unwrap_or(other).to_string(),
            ..ChatRun::default()
        },
    }
}

// --- probing ----------------------------------------------------------------------------

/// What one cheap probe found.
#[derive(Debug, Clone, Default, PartialEq)]
pub struct Probe {
    pub latency_ms: Option<u64>,
    pub down: Option<String>,
    /// The provider said, in so many words, that there is no credit.
    pub exhausted: Option<String>,
    /// The provider's balance endpoint says there is credit.
    pub funded: Option<bool>,
    pub balance: Option<String>,
}

/// Probe one engine: list its models (or ask for one token), and read its balance where
/// the provider has an endpoint for that. A CLI engine with no endpoint is only looked
/// for on PATH, because running it would cost a real request.
pub async fn probe(spec: &EngineSpec, key: Option<&str>) -> Probe {
    let Some(base) = spec.base_url.as_deref() else {
        let found = Path::new(&spec.command).is_file()
            || crate::doctor::find_on_path(&spec.command).is_some();
        return Probe {
            down: (!found).then(|| format!("'{}' is not on PATH", spec.command)),
            ..Probe::default()
        };
    };
    #[cfg(test)]
    if let Some(canned) = base.strip_prefix("fake://") {
        // `quota` lists its models happily, the way a real provider does for a key with
        // nothing on it: only running a prompt finds the empty wallet.
        return match canned {
            "empty" => Probe {
                exhausted: Some("HTTP 402: Insufficient Balance".into()),
                latency_ms: Some(5),
                ..Probe::default()
            },
            "down" => Probe {
                down: Some("connection refused".into()),
                ..Probe::default()
            },
            _ => Probe {
                latency_ms: Some(5),
                ..Probe::default()
            },
        };
    }
    let Ok(http) = client(PROBE_TIMEOUT) else {
        return Probe {
            down: Some("could not build an HTTP client".into()),
            ..Probe::default()
        };
    };
    let started = Instant::now();
    let request = if spec.probe_chat {
        http.post(format!("{base}/chat/completions")).json(&json!({
            "model": spec.model,
            "messages": [{"role": "user", "content": "ping"}],
            "max_tokens": 1,
        }))
    } else {
        http.get(format!("{base}/models"))
    };
    let request = match key {
        Some(key) => request.bearer_auth(key),
        None => request,
    };
    let mut found = Probe::default();
    match request.send().await {
        Err(error) => {
            found.down = Some(clip(&redact(&format!("unreachable: {error}"), key)));
        }
        Ok(response) => {
            found.latency_ms =
                Some(u64::try_from(started.elapsed().as_millis()).unwrap_or(u64::MAX));
            let status = response.status().as_u16();
            let body = response.text().await.unwrap_or_default();
            let said = clip(&redact(&format!("HTTP {status}: {body}"), key));
            match status {
                200..=299 => {
                    if !spec.probe_chat
                        && let Some(model) = &spec.model
                        && let Some(ids) = model_ids(&body)
                        && !ids.is_empty()
                        && !ids.iter().any(|id| id == model)
                    {
                        found.down = Some(format!("model '{model}' is not offered by {base}"));
                    }
                }
                402 => found.exhausted = Some(said),
                401 | 403 => found.down = Some(format!("the key was refused (HTTP {status})")),
                429 if quota_reset(&said, Utc::now()).is_some() => found.exhausted = Some(said),
                429 => {}
                _ => found.down = Some(said),
            }
        }
    }
    if let Some(key) = key {
        balance(&http, base, key, &mut found).await;
    }
    found
}

fn model_ids(body: &str) -> Option<Vec<String>> {
    let value: Value = serde_json::from_str(body).ok()?;
    Some(
        value
            .get("data")?
            .as_array()?
            .iter()
            .filter_map(|model| model.get("id").and_then(Value::as_str).map(str::to_string))
            .collect(),
    )
}

/// Read the balance, for the providers that publish one.
async fn balance(http: &reqwest::Client, base: &str, key: &str, found: &mut Probe) {
    async fn get(http: &reqwest::Client, url: &str, key: &str) -> Option<Value> {
        let response = http.get(url).bearer_auth(key).send().await.ok()?;
        if !response.status().is_success() {
            return None;
        }
        response.json::<Value>().await.ok()
    }
    if base.contains("deepseek.com") {
        if let Some(value) = get(http, "https://api.deepseek.com/user/balance", key).await {
            let available = value.get("is_available").and_then(Value::as_bool);
            if let Some(info) = value["balance_infos"]
                .as_array()
                .and_then(|all| all.first())
            {
                found.balance = Some(format!(
                    "{} {}",
                    info["total_balance"].as_str().unwrap_or("?"),
                    info["currency"].as_str().unwrap_or("")
                ));
            }
            found.funded = available;
            if available == Some(false) {
                found.exhausted = Some("DeepSeek reports the balance is empty".to_string());
            }
        }
    } else if base.contains("openrouter.ai") {
        if let Some(value) = get(http, &format!("{base}/credits"), key).await {
            let total = value["data"]["total_credits"].as_f64();
            let used = value["data"]["total_usage"].as_f64();
            if let (Some(total), Some(used)) = (total, used) {
                let left = total - used;
                found.balance = Some(format!("{left:.2} USD"));
                found.funded = Some(left > 0.0);
                if left <= 0.0 {
                    found.exhausted = Some("OpenRouter credits are used up".to_string());
                }
            }
        }
        if let Some(value) = get(http, &format!("{base}/key"), key).await
            && let Some(left) = value["data"]["limit_remaining"].as_f64()
            && left <= 0.0
        {
            found.funded = Some(false);
            found.exhausted = Some("the OpenRouter key's limit is reached".to_string());
        }
    }
}

/// Record a probe in the ledger.
///
/// A probe that lists models does not prove there is credit - a provider happily lists
/// models to a key with nothing on it - so a good probe does not lift an exhaustion. A
/// balance endpoint that says there is credit does.
pub fn apply_probe(ledger: &mut Ledger, engine: &str, probe: &Probe, now: DateTime<Utc>) {
    let state = ledger.entry(engine);
    state.checked_at = Some(now);
    state.latency_ms = probe.latency_ms;
    state.down = probe.down.clone();
    if probe.balance.is_some() {
        state.balance = probe.balance.clone();
    }
    if let Some(reason) = &probe.exhausted {
        if state.exhausted_until.is_none_or(|until| until <= now) {
            state.exhausted_until = Some(
                quota_reset(reason, now)
                    .unwrap_or(now + chrono::Duration::hours(DEFAULT_EXHAUSTED_HOURS)),
            );
            state.exhausted_reason = Some(clip(reason));
        }
    } else if probe.funded == Some(true) {
        state.exhausted_until = None;
        state.exhausted_reason = None;
    }
}

/// Probe every engine whose last probe is older than [`PROBE_EVERY_SECS`].
///
/// An engine whose key this channel does not hold is skipped here rather than marked
/// down: the same agent may serve a channel that does hold it, and that channel's pass
/// will probe it. Returns how many engines were probed.
pub async fn probe_due(
    route: &ProjectRoute,
    agent: &str,
    specs: &[EngineSpec],
    now: DateTime<Utc>,
) -> usize {
    let ledger = Ledger::load(agent);
    let mut results = Vec::new();
    for spec in specs {
        let checked = ledger.state(&spec.name).checked_at;
        let due = checked.is_none_or(|at| {
            let since = now.signed_duration_since(at);
            since < chrono::Duration::zero() || since >= chrono::Duration::seconds(PROBE_EVERY_SECS)
        });
        if !due {
            continue;
        }
        let Ok(key) = engine_key(route, agent, spec) else {
            continue;
        };
        results.push((spec.name.clone(), probe(spec, key.as_deref()).await));
    }
    if results.is_empty() {
        return 0;
    }
    let count = results.len();
    update(agent, |ledger| {
        for (name, found) in &results {
            apply_probe(ledger, name, found, now);
        }
    });
    count
}

/// The inventory lines for every engine, for the signed engines file. No credentials:
/// the key reference is not included either, only what the engine is and how it is.
#[must_use]
pub fn reports(specs: &[EngineSpec], ledger: &Ledger, now: DateTime<Utc>) -> Vec<EngineReport> {
    specs
        .iter()
        .map(|spec| {
            let state = ledger.state(&spec.name);
            let available = availability(spec, &state, now);
            let (status, until, reason) = match &available {
                Availability::Up => ("up", None, None),
                Availability::Unknown => ("unknown", None, None),
                Availability::Down(why) => ("down", None, Some(why.clone())),
                Availability::Exhausted { until, reason } => {
                    ("exhausted", Some(*until), Some(reason.clone()))
                }
            };
            EngineReport {
                name: spec.name.clone(),
                kind: spec.kind.as_str().to_string(),
                model: spec.model.clone(),
                tier: spec.tier.as_str().to_string(),
                paid: spec.paid.as_str().to_string(),
                state: status.to_string(),
                until,
                reason,
                latency_ms: state.latency_ms,
                balance: state.balance.clone(),
                checked_at: state.checked_at,
                trust: trust(&state),
                billing: Some(billing(spec, &state, now)),
            }
        })
        .collect()
}

/// What the engine policy ranks by, as this machine knows it.
fn billing(
    spec: &EngineSpec,
    state: &EngineState,
    now: DateTime<Utc>,
) -> ferryman_channel::receipts::EngineBilling {
    let this_week = state.week == iso_week(now);
    ferryman_channel::receipts::EngineBilling {
        host: spec.base_url.as_deref().and_then(url_host),
        capped: spec.weekly_usd.is_some() || spec.weekly_requests.is_some(),
        week: iso_week(now),
        requests: if this_week { state.requests } else { 0 },
        spend_usd: if this_week { state.spend_usd } else { 0.0 },
        flag: (spec.paid == Paid::FreeTier)
            .then(|| state.free_tier_flag(now))
            .flatten(),
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use chrono::TimeZone;

    fn fields(text: &str) -> HashMap<String, String> {
        text.lines()
            .filter_map(|line| line.split_once('='))
            .map(|(key, value)| {
                (
                    key.trim().to_string(),
                    value.trim().trim_matches('"').to_string(),
                )
            })
            .collect()
    }

    fn http(name: &str, tier: Tier, url: &str) -> EngineSpec {
        EngineSpec {
            name: name.into(),
            kind: Kind::Http,
            tier,
            paid: Paid::Prepaid,
            command: String::new(),
            args: Vec::new(),
            model: Some("m".into()),
            base_url: Some(url.into()),
            key: None,
            env: Vec::new(),
            probe_chat: false,
            weekly_requests: None,
            weekly_usd: None,
        }
    }

    fn monday_noon() -> DateTime<Utc> {
        Utc.with_ymd_and_hms(2026, 9, 28, 12, 0, 0).unwrap()
    }

    #[test]
    fn a_config_without_engines_runs_its_one_command_as_before() {
        let args = vec!["-p".to_string(), "{prompt}".to_string()];
        let engines = parse_engines(
            &fields("agent = \"a\""),
            "/usr/bin/Claude.exe",
            &args,
            Some("x"),
        )
        .unwrap();
        assert_eq!(engines.len(), 1);
        assert_eq!(engines[0].name, "claude");
        assert_eq!(engines[0].kind, Kind::Cli);
        assert_eq!(engines[0].tier, Tier::Build);
        assert_eq!(engines[0].args, args);
        assert_eq!(engines[0].model.as_deref(), Some("x"));
    }

    #[test]
    fn engines_are_read_in_order_with_their_tiers_and_endpoints() {
        let text = r#"
engines = ["nvidia", "deepseek", "local"]
engine.nvidia.base_url = "https://integrate.api.nvidia.com/v1/"
engine.nvidia.model = "qwen/qwen3-coder-480b-a35b-instruct"
engine.nvidia.key = "secret:NVIDIA_API_KEY"
engine.nvidia.paid = "free-tier"
engine.nvidia.weekly_requests = "500"
engine.deepseek.tier = "build"
engine.deepseek.paid = "prepaid"
engine.deepseek.weekly_usd = "5"
engine.local.base_url = "http://localhost:1234/v1"
engine.local.model = "qwen2.5-coder"
engine.local.tier = "chore"
"#;
        let args = vec!["-p".to_string(), "{prompt}".to_string()];
        let engines = parse_engines(
            &fields(text),
            "ferryman-cline",
            &args,
            Some("deepseek-v4-pro"),
        )
        .unwrap();
        let names: Vec<&str> = engines.iter().map(|e| e.name.as_str()).collect();
        assert_eq!(names, ["nvidia", "deepseek", "local"]);
        assert_eq!(engines[0].kind, Kind::Http);
        assert_eq!(
            engines[0].base_url.as_deref(),
            Some("https://integrate.api.nvidia.com/v1")
        );
        assert_eq!(engines[0].weekly_requests, Some(500));
        // A CLI engine with no command of its own is the old `command`, unchanged.
        assert_eq!(engines[1].kind, Kind::Cli);
        assert_eq!(engines[1].command, "ferryman-cline");
        assert_eq!(engines[1].model.as_deref(), Some("deepseek-v4-pro"));
        assert_eq!(engines[1].weekly_usd, Some(5.0));
        assert_eq!(
            engines[2].paid,
            Paid::Local,
            "localhost is local unless told otherwise"
        );
        assert_eq!(engines[2].tier, Tier::Chore);
    }

    #[test]
    fn a_key_written_into_the_file_is_refused() {
        let text = "engines = [\"n\"]\nengine.n.base_url = \"https://x/v1\"\nengine.n.model = \"m\"\nengine.n.key = \"nvapi-abc123\"";
        let error = parse_engines(&fields(text), "c", &[], None).unwrap_err();
        assert!(
            format!("{error}").contains("secret:NAME or env:NAME"),
            "{error}"
        );
    }

    #[test]
    fn running_out_of_credit_is_told_apart_from_failing() {
        let now = monday_noon();
        for said in [
            "Insufficient Balance (request_id: 1a47)",
            "HTTP 402: {\"error\":{\"message\":\"Payment Required\"}}",
            "Claude AI usage limit reached|1790000000",
            "Your credit balance is too low to access the API",
            "You exceeded your current quota, please check your plan and billing details",
            "429 Too Many Requests: rate limit of 50 requests per day reached",
            "HTTP 429 retry-after: 3600: slow down",
        ] {
            assert!(quota_reset(said, now).is_some(), "should be quota: {said}");
        }
        for said in [
            "error[E0308]: mismatched types",
            "Failed to authenticate: OAuth session expired",
            "HTTP 429 retry-after: 20: slow down",
            "HTTP 500: internal error",
            "test result: FAILED. 3 passed; 1 failed",
        ] {
            assert!(
                quota_reset(said, now).is_none(),
                "should be ordinary: {said}"
            );
        }
    }

    #[test]
    fn the_reset_is_read_from_the_message_when_it_gives_one() {
        let now = monday_noon();
        let epoch = now + chrono::Duration::hours(3);
        let claude = format!("usage limit reached|{}", epoch.timestamp());
        assert_eq!(quota_reset(&claude, now), Some(epoch));
        assert_eq!(
            quota_reset("insufficient_quota: try again in 2h13m", now),
            Some(now + chrono::Duration::minutes(133))
        );
        assert_eq!(
            quota_reset("HTTP 429 retry-after: 3600", now),
            Some(now + chrono::Duration::hours(1))
        );
        assert_eq!(
            quota_reset("Insufficient Balance", now),
            Some(now + chrono::Duration::hours(DEFAULT_EXHAUSTED_HOURS)),
            "no reset given: six hours"
        );
    }

    #[test]
    fn an_exhausted_engine_is_skipped_until_its_reset_and_then_used_again() {
        let now = monday_noon();
        let specs = vec![
            http("deepseek", Tier::Build, "https://api.deepseek.com"),
            http("nvidia", Tier::Build, "https://integrate.api.nvidia.com/v1"),
        ];
        let mut ledger = Ledger::default();
        ledger.engines.insert(
            "deepseek".into(),
            EngineState {
                exhausted_until: Some(now + chrono::Duration::hours(6)),
                exhausted_reason: Some("Insufficient Balance".into()),
                ..EngineState::default()
            },
        );
        let chosen = pick(&specs, &ledger, now, Tier::Build, &[]).unwrap();
        assert_eq!(chosen.name, "nvidia");
        assert!(all_exhausted(&specs, &ledger, now).is_none());

        let later = now + chrono::Duration::hours(6) + chrono::Duration::seconds(1);
        assert_eq!(
            pick(&specs, &ledger, later, Tier::Build, &[]).unwrap().name,
            "deepseek"
        );
    }

    #[test]
    fn fallback_never_goes_below_the_tier_and_judges_build_only_as_a_last_resort() {
        let now = monday_noon();
        let specs = vec![
            http("claude", Tier::Judge, "https://a/v1"),
            http("deepseek", Tier::Build, "https://b/v1"),
            http("local", Tier::Chore, "http://localhost:1/v1"),
        ];
        let ledger = Ledger::default();
        assert_eq!(
            pick(&specs, &ledger, now, Tier::Build, &[]).unwrap().name,
            "deepseek"
        );
        let tried = vec!["deepseek".to_string()];
        assert_eq!(
            pick(&specs, &ledger, now, Tier::Build, &tried)
                .unwrap()
                .name,
            "claude"
        );
        let tried = vec!["deepseek".to_string(), "claude".to_string()];
        assert!(
            pick(&specs, &ledger, now, Tier::Build, &tried).is_none(),
            "a chore engine never takes build work"
        );
        assert_eq!(
            pick(&specs, &ledger, now, Tier::Chore, &[]).unwrap().name,
            "local"
        );
    }

    #[test]
    fn a_weekly_cap_exhausts_the_engine_until_monday() {
        let now = monday_noon() + chrono::Duration::days(2);
        let mut spec = http("openrouter", Tier::Build, "https://openrouter.ai/api/v1");
        spec.weekly_requests = Some(2);
        let state = EngineState {
            week: iso_week(now),
            requests: 2,
            ..EngineState::default()
        };
        match availability(&spec, &state, now) {
            Availability::Exhausted { until, reason } => {
                assert_eq!(until, Utc.with_ymd_and_hms(2026, 10, 5, 0, 0, 0).unwrap());
                assert!(reason.contains("2 requests"), "{reason}");
            }
            other => panic!("expected exhausted, got {other:?}"),
        }
        // Last week's count does not carry over.
        let stale = EngineState {
            week: "2026-W01".into(),
            ..state
        };
        assert!(availability(&spec, &stale, now).usable());
    }

    #[test]
    fn a_probe_that_finds_no_credit_exhausts_and_a_funded_balance_lifts_it() {
        let now = monday_noon();
        let mut ledger = Ledger::default();
        apply_probe(
            &mut ledger,
            "deepseek",
            &Probe {
                exhausted: Some("DeepSeek reports the balance is empty".into()),
                ..Probe::default()
            },
            now,
        );
        assert!(
            ledger
                .state("deepseek")
                .exhausted_until
                .is_some_and(|u| u > now)
        );
        // A model list alone proves nothing about credit.
        apply_probe(&mut ledger, "deepseek", &Probe::default(), now);
        assert!(
            ledger
                .state("deepseek")
                .exhausted_until
                .is_some_and(|u| u > now)
        );
        apply_probe(
            &mut ledger,
            "deepseek",
            &Probe {
                funded: Some(true),
                balance: Some("4.20 USD".into()),
                ..Probe::default()
            },
            now,
        );
        assert!(ledger.state("deepseek").exhausted_until.is_none());
        assert_eq!(
            ledger.state("deepseek").balance.as_deref(),
            Some("4.20 USD")
        );
    }

    #[test]
    fn the_inventory_carries_no_credential_or_reference_to_one() {
        let mut spec = http("nvidia", Tier::Build, "https://integrate.api.nvidia.com/v1");
        spec.key = Some("secret:NVIDIA_API_KEY".into());
        let reports = reports(&[spec], &Ledger::default(), monday_noon());
        let text = serde_json::to_string(&reports).unwrap();
        assert!(!text.contains("NVIDIA_API_KEY"), "{text}");
        assert!(!text.contains("secret:"), "{text}");
        assert_eq!(reports[0].state, "unknown");
    }

    /// `never` is never used for background work, not even when it is the only engine
    /// up and `pick` would have taken it: the work waits, with the reason.
    #[test]
    fn background_work_never_falls_back_to_a_blocked_engine() {
        use ferryman_channel::policy::{NeverScope, Policy, Role};
        let now = monday_noon();
        let mut claude = http("claude", Tier::Judge, "https://api.anthropic.com/v1");
        claude.paid = Paid::Subscription;
        let mut nemotron = http(
            "nemotron",
            Tier::Build,
            "https://integrate.api.nvidia.com/v1",
        );
        nemotron.paid = Paid::FreeTier;
        let specs = vec![claude, nemotron];
        let ledger = Ledger::default();
        let here = ("wisp", "grouchly");
        let auto = Policy::default();
        assert_eq!(
            choose(
                &specs,
                &ledger,
                now,
                &auto,
                Role::Build,
                Tier::Build,
                &[],
                here
            )
            .unwrap()
            .name,
            "nemotron"
        );
        let tried = vec!["nemotron".to_string()];
        let held = choose(
            &specs,
            &ledger,
            now,
            &auto,
            Role::Build,
            Tier::Build,
            &tried,
            here,
        )
        .unwrap_err();
        assert!(held.contains("was tried"), "{held}");
        assert_eq!(
            pick(&specs, &ledger, now, Tier::Build, &tried)
                .unwrap()
                .name,
            "claude",
            "the old rule would have fallen back to the subscription"
        );
        let never_nvidia = Policy {
            never: vec!["host:nvidia.com".into()],
            ..Policy::default()
        };
        let why = choose(
            &specs,
            &ledger,
            now,
            &never_nvidia,
            Role::Build,
            Tier::Build,
            &[],
            here,
        )
        .unwrap_err();
        assert!(
            why.contains("nemotron on grouchly never") && why.contains("claude on grouchly"),
            "{why}"
        );
        // A person's own order may use anything - unless never says all work.
        assert_eq!(
            pick_direct(&specs, &ledger, now, Tier::Build, &[], &never_nvidia, here)
                .unwrap()
                .name,
            "nemotron"
        );
        let everything = Policy {
            never_applies_to: NeverScope::All,
            ..never_nvidia
        };
        assert_eq!(
            pick_direct(&specs, &ledger, now, Tier::Build, &[], &everything, here)
                .unwrap()
                .name,
            "claude"
        );
    }

    #[test]
    fn only_the_host_of_an_endpoint_is_published() {
        assert_eq!(
            url_host("https://integrate.api.nvidia.com/v1").as_deref(),
            Some("integrate.api.nvidia.com")
        );
        assert_eq!(
            url_host("http://user:pass@LOCALHOST:1234/v1").as_deref(),
            Some("localhost")
        );
        assert_eq!(url_host("http://[::1]:8080/").as_deref(), Some("[::1]"));
        let mut spec = http("n", Tier::Build, "https://a.example/v1");
        spec.weekly_usd = Some(3.0);
        let billing = reports(&[spec], &Ledger::default(), monday_noon())[0]
            .billing
            .clone()
            .unwrap();
        assert_eq!(billing.host.as_deref(), Some("a.example"));
        assert!(billing.capped);
    }

    /// Repeated refutations inside the window demote an engine to chore work; build
    /// work goes to the next engine; only the canary brings it back. Unverified results
    /// are counted but never demote.
    #[test]
    fn refutations_demote_an_engine_and_only_the_canary_restores_it() {
        use ferryman_channel::evidence::Status;
        let now = monday_noon();
        let specs = vec![
            http("nemotron", Tier::Build, "https://example.invalid/v1"),
            http("deepseek", Tier::Build, "https://example.invalid/v1"),
        ];
        let mut state = EngineState::default();
        // One refutation three weeks ago has left the window by now.
        assert!(!state.note(Status::Refuted, now - chrono::Duration::days(21)));
        assert!(!state.note(Status::Unverified, now));
        assert!(!state.note(Status::Unverified, now));
        assert!(!state.note(Status::Refuted, now));
        assert!(!state.demoted(), "one refutation in the window, not two");
        assert!(state.note(Status::Refuted, now), "the second one demotes");
        assert!(!state.note(Status::Refuted, now), "demoted once, not again");
        assert!(state.demoted());
        assert_eq!((state.refuted, state.unverified, state.verified), (4, 2, 0));
        assert_eq!(effective_tier(&specs[0], &state), Tier::Chore);

        let mut ledger = Ledger::default();
        ledger.engines.insert("nemotron".into(), state.clone());
        assert_eq!(
            pick(&specs, &ledger, now, Tier::Build, &[]).map(|s| s.name.as_str()),
            Some("deepseek"),
            "build work is routed past a demoted engine"
        );
        assert_eq!(
            pick(&specs[..1], &ledger, now, Tier::Chore, &[]).map(|s| s.name.as_str()),
            Some("nemotron"),
            "chore and canary work still go to it"
        );
        assert!(pick(&specs[..1], &ledger, now, Tier::Build, &[]).is_none());
        let published = reports(&specs, &ledger, now);
        let trust = published[0].trust.clone().unwrap();
        assert!(trust.demoted && trust.demoted_at == Some(now));
        assert_eq!(trust.score(), Some(0));
        assert!(trust.describe().contains("DEMOTED"), "{}", trust.describe());
        assert!(
            published[1].trust.is_none(),
            "nothing known, nothing claimed"
        );

        // A failed canary changes nothing but when the next one is due.
        assert!(canary_due(&state, now));
        state.canary(false, now);
        assert!(state.demoted() && !canary_due(&state, now));
        assert!(canary_due(&state, now + chrono::Duration::hours(1)));
        // A pass restores its tier and clears the window; the history stays.
        state.canary(true, now + chrono::Duration::hours(1));
        assert!(!state.demoted());
        assert_eq!(effective_tier(&specs[0], &state), Tier::Build);
        assert!(state.refutations.is_empty());
        assert_eq!(state.refuted, 4);
        assert!(!state.note(Status::Refuted, now + chrono::Duration::hours(2)));
        assert!(!state.demoted(), "a fresh window after the canary");
    }
}
