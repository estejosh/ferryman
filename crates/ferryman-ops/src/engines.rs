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
use ferryman_channel::{
    ProjectRoute,
    policy::{Effort, ModelClass},
    receipts::EngineReport,
    trajectory::TokenUsage,
};
use serde::{Deserialize, Serialize};
use serde_json::{Value, json};

/// How often each engine is probed.
pub const PROBE_EVERY_SECS: i64 = 10 * 60;
/// How long an engine that ran out of credit is left alone when it did not say when it
/// will be back.
pub const DEFAULT_EXHAUSTED_HOURS: i64 = 6;
/// A rate limit that asks for a wait this long is a quota, not a hiccup.
const LONG_RETRY_SECS: u64 = 10 * 60;
/// The most a probe's side requests (balance, combos) may take.
const PROBE_TIMEOUT: Duration = Duration::from_secs(30);
/// How long an honest probe waits for a one-token completion. An engine that accepts the
/// request and then sits on it for longer than this is not up: that is exactly how a model
/// that listed fine and answered nothing was reported "up, 0.3 s" while every order sent to
/// it timed out (grouchly, 2026-10-12).
pub const PROVE_DEADLINE: Duration = Duration::from_secs(20);
/// How long a CLI engine that wraps an API is given to answer a tiny prompt.
pub const CLI_PROVE_DEADLINE: Duration = Duration::from_secs(45);
/// The least time between two tiny-prompt probes of one CLI engine. A real prompt is a
/// real request, so it is cached and rationed; a failed run asks for a fresh one at once.
pub const CLI_PROBE_EVERY_SECS: i64 = 15 * 60;
/// How long an engine is left alone after a run failed on it: 15 minutes, then an hour,
/// then four, for each failure in a row. One run that works resets the ladder.
pub const COOLOFF_STEPS_SECS: [i64; 3] = [15 * 60, 60 * 60, 4 * 60 * 60];
/// Failures in a row after which the owner is told, unless agent.toml says otherwise
/// (`engine_alert_after`).
pub const DEFAULT_ALERT_AFTER: u32 = 2;
/// The most engines one order is handed through in one attempt, unless agent.toml says
/// otherwise (`max_engines_per_order`).
pub const DEFAULT_ENGINES_PER_ORDER: usize = 3;
/// How many orders an engine's record names as affected by its failures.
const AFFECTED_ORDERS: usize = 10;
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
    /// The CLI's arguments. `{prompt}`, `{model}`, `{base_url}` and `{effort}` are filled
    /// in; `{effort}` reads `low`, `medium` or `high`, as the engine policy asks of the
    /// role the engine is doing.
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
    /// `omniroute` for an OmniRoute gateway; see [`crate::omniroute`].
    pub provider: Option<String>,
    /// For a gateway engine: the provider/models its route ends at, as its probe found.
    pub route: Vec<String>,
    /// The size class its operator declares (`engine.<name>.class = "small"`). It wins
    /// over [`guess_class`](ferryman_channel::policy::guess_class) on the model's name.
    pub class: Option<ModelClass>,
    /// Extra arguments per effort level, for a CLI whose effort flag is not one `{effort}`
    /// can express, e.g. `engine.<name>.effort_args = {"low":["-c","x=low"],...}`. They go
    /// in just before the argument that holds `{prompt}`. Keys are `low`, `medium`, `high`.
    pub effort_args: BTreeMap<String, Vec<String>>,
    /// An HTTP engine takes a `reasoning_effort` field (`engine.<name>.supports_effort =
    /// "true"`). Off by default: an endpoint that does not know the field may refuse it.
    pub supports_effort: bool,
    /// What the operator says the engine can do (`engine.<name>.modalities`, `strengths`,
    /// `context_k`, `cost_per_call_usd`, `cost_per_mtok_in_usd`, `cost_per_mtok_out_usd`,
    /// `local`). Whatever is left out is guessed; see [`capabilities`].
    pub declared: ferryman_channel::capability::Declared,
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
            provider: None,
            route: Vec::new(),
            class: None,
            effort_args: BTreeMap::new(),
            supports_effort: false,
            declared: ferryman_channel::capability::Declared::default(),
        }
    }

    /// What this engine can do: [`capabilities`].
    #[must_use]
    pub fn capabilities(&self) -> ferryman_channel::capability::Capabilities {
        capabilities(self)
    }

    /// The CLI arguments with this engine's model and endpoint filled in, and no effort
    /// asked: `{effort}` reads `medium` and `effort_args` add nothing. `{prompt}` is left
    /// for the runner, which fills it last.
    #[must_use]
    pub fn cli_args(&self) -> Vec<String> {
        self.cli_args_at(None)
    }

    /// [`Self::cli_args`] for work asked to run at `effort`: `{effort}` is filled in like
    /// `{model}`, and the engine's `effort_args` for that level go in just before the
    /// argument that holds `{prompt}` (at the end when none does).
    #[must_use]
    pub fn cli_args_at(&self, effort: Option<Effort>) -> Vec<String> {
        let level = effort.unwrap_or(Effort::Medium);
        let fill = |arg: &String| {
            arg.replace("{model}", self.model.as_deref().unwrap_or(""))
                .replace("{base_url}", self.base_url.as_deref().unwrap_or(""))
                .replace("{effort}", level.as_str())
        };
        let mut args: Vec<String> = self.args.iter().map(fill).collect();
        if effort.is_some()
            && let Some(extra) = self.effort_args.get(level.as_str())
        {
            let at = self
                .args
                .iter()
                .position(|arg| arg.contains("{prompt}"))
                .unwrap_or(args.len());
            args.splice(at..at, extra.iter().map(fill));
        }
        args
    }

    /// Whether anything in this engine's setup acts on an effort: `{effort}` in its
    /// arguments, `effort_args`, or an HTTP engine that `supports_effort`. What is
    /// recorded as the effort a step ran at is only ever an effort that was applied.
    #[must_use]
    pub fn applies_effort(&self) -> bool {
        self.supports_effort
            || !self.effort_args.is_empty()
            || self.args.iter().any(|arg| arg.contains("{effort}"))
    }

    /// Its size class: the operator's word, else guessed from its model's name (or its
    /// own name, with no model).
    #[must_use]
    pub fn class(&self) -> ModelClass {
        self.class.unwrap_or_else(|| {
            ferryman_channel::policy::guess_class(self.model.as_deref().unwrap_or(&self.name))
        })
    }
}

/// What an engine can do: modalities, strengths, context window, cost and whether it is
/// local. What the operator declared in `agent.toml` wins, field by field; the rest is
/// guessed from the engine's name, model, command, kind, endpoint and how it is paid
/// for. This is what the signed engine inventory publishes (see [`reports`]) and what the
/// smart router reads. The rules and their limits are in
/// [`ferryman_channel::capability`].
#[must_use]
pub fn capabilities(spec: &EngineSpec) -> ferryman_channel::capability::Capabilities {
    ferryman_channel::capability::resolve(
        &spec.declared,
        &ferryman_channel::capability::Basis {
            name: &spec.name,
            model: spec.model.as_deref(),
            command: &spec.command,
            cli: spec.kind == Kind::Cli,
            base_url: spec.base_url.as_deref(),
            paid: spec.paid.as_str(),
            gateway: spec.provider.is_some()
                || !spec.route.is_empty()
                || crate::omniroute::is_omniroute(spec),
        },
    )
}

/// Read what an operator declared an engine can do. All of it is optional: lists are a
/// JSON array or words separated by commas, prices are dollars, and a typo is refused so
/// it cannot silently leave an engine unable (or newly able) to take work.
fn parse_declared(
    name: &str,
    get: &dyn Fn(&str) -> Option<String>,
) -> Result<ferryman_channel::capability::Declared> {
    use ferryman_channel::capability::{Cost, Declared, Modality, check_context_k};
    let modalities = match get("modalities") {
        Some(raw) => {
            Modality::parse_list(&raw).with_context(|| format!("engine.{name}.modalities"))?
        }
        None => Vec::new(),
    };
    let strengths = match get("strengths") {
        Some(raw) => {
            let words: Vec<String> = if raw.trim_start().starts_with('[') {
                serde_json::from_str(&raw).with_context(|| {
                    format!("engine.{name}.strengths must be a JSON array of words")
                })?
            } else {
                raw.split(',').map(str::to_string).collect()
            };
            let mut tags: Vec<String> = words
                .iter()
                .map(|word| word.trim().to_ascii_lowercase())
                .filter(|word| !word.is_empty())
                .collect();
            tags.sort();
            tags.dedup();
            tags
        }
        None => Vec::new(),
    };
    let context_k = get("context_k")
        .map(|value| {
            let k = value.parse::<u32>().with_context(|| {
                format!("engine.{name}.context_k must be a whole number of thousands of tokens")
            })?;
            check_context_k(k).with_context(|| format!("engine.{name}.context_k"))?;
            Ok::<_, anyhow::Error>(k)
        })
        .transpose()?;
    let price = |field: &str| -> Result<Option<f64>> {
        get(field)
            .map(|value| {
                let dollars = value
                    .parse::<f64>()
                    .with_context(|| format!("engine.{name}.{field} must be a number"))?;
                if !dollars.is_finite() || dollars < 0.0 {
                    bail!("engine.{name}.{field} must be zero or more dollars")
                }
                Ok(dollars)
            })
            .transpose()
    };
    let (per_call, per_in, per_out) = (
        price("cost_per_call_usd")?,
        price("cost_per_mtok_in_usd")?,
        price("cost_per_mtok_out_usd")?,
    );
    let cost = (per_call.is_some() || per_in.is_some() || per_out.is_some()).then(|| Cost {
        per_call_usd: per_call.unwrap_or(0.0),
        per_mtok_in_usd: per_in.unwrap_or(0.0),
        per_mtok_out_usd: per_out.unwrap_or(0.0),
    });
    let local = match get("local").as_deref() {
        None => None,
        Some("true") => Some(true),
        Some("false") => Some(false),
        Some(other) => bail!("engine.{name}.local must be true or false, not '{other}'"),
    };
    Ok(Declared {
        modalities,
        strengths,
        context_k,
        cost,
        local,
    })
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
        let provider = get("provider").map(|provider| provider.to_ascii_lowercase());
        // An OmniRoute engine with no address is the local one on its default port.
        let base_url = get("base_url")
            .or_else(|| {
                (provider.as_deref() == Some("omniroute"))
                    .then(|| crate::omniroute::DEFAULT_URL.to_string())
            })
            .map(|url| url.trim_end_matches('/').to_string());
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
        let class = get("class")
            .map(|value| ModelClass::parse(&value).with_context(|| format!("engine.{name}.class")))
            .transpose()?;
        let effort_args = match get("effort_args") {
            None => BTreeMap::new(),
            Some(raw) => {
                let parsed = serde_json::from_str::<BTreeMap<String, Vec<String>>>(&raw)
                    .with_context(|| {
                        format!(
                            "engine.{name}.effort_args must be a JSON object of level: [args], \
                             e.g. {{\"low\":[\"--effort\",\"low\"]}}"
                        )
                    })?;
                let mut by_level = BTreeMap::new();
                for (level, extra) in parsed {
                    let level = Effort::parse(&level)
                        .with_context(|| format!("engine.{name}.effort_args"))?;
                    by_level.insert(level.as_str().to_string(), extra);
                }
                by_level
            }
        };
        let supports_effort = match get("supports_effort").as_deref() {
            None | Some("false") => false,
            Some("true") => true,
            Some(other) => {
                bail!("engine.{name}.supports_effort must be true or false, not '{other}'")
            }
        };
        let declared = parse_declared(&name, &get)?;
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
        // An http engine is probed by asking it for one token unless told `probe =
        // "models"`: a model list proves nothing about whether it answers. A gateway
        // keeps listing its models, which is how its routes are read.
        let probe_chat = probe_with_chat(get("probe").as_deref(), base_url.as_deref())
            || (kind == Kind::Http
                && get("probe").is_none()
                && provider.as_deref() != Some("omniroute"));
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
            probe_chat,
            weekly_requests: number("weekly_requests")?,
            weekly_usd,
            provider,
            route: Vec::new(),
            class,
            effort_args,
            supports_effort,
            declared,
            name,
        });
    }
    Ok(out)
}

/// Whether to probe an engine with a one-token request rather than by listing models.
///
/// `probe = "chat"` or `probe = "models"` decides. Unset, NVIDIA's endpoint defaults to
/// chat: its model list names every model in the catalogue, including ones a given
/// account cannot run, so a listing probe reported such a model up while every real
/// request to it failed or timed out. Found on grouchly, 2026-10-07.
fn probe_with_chat(setting: Option<&str>, base_url: Option<&str>) -> bool {
    match setting {
        Some("chat") => true,
        Some(_) => false,
        None => base_url
            .and_then(url_host)
            .is_some_and(|host| host == "integrate.api.nvidia.com"),
    }
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
    /// What an OmniRoute gateway offers, from its last probe.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub gateway: Option<crate::omniroute::Catalog>,
    /// How this engine's results have turned out per kind of work - verified or refuted by
    /// this worker's own checks, age-weighted with a 14-day half-life - which is what the
    /// smart router's success estimate learns from. Published in the engine's trust line.
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub outcomes: Vec<ferryman_channel::router::Outcome>,
    /// What the last probe proved. `None` in a ledger written before probes said.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub proof: Option<Proof>,
    /// The last tiny-prompt run of a CLI engine that wraps an API.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub cli_probe: Option<CliProbe>,
    /// Runs that failed on this engine in a row (a timeout, a stall, no tokens, an
    /// error). One run that works sets it back to nothing.
    #[serde(default)]
    pub fail_streak: u32,
    /// Not given work until then, because runs failed on it.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub cooloff_until: Option<DateTime<Utc>>,
    /// When the current cool-off began.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub cooloff_started: Option<DateTime<Utc>>,
    /// Why the last run failed, and on which model and when.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub last_failure: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub last_failure_at: Option<DateTime<Utc>>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub failed_model: Option<String>,
    /// The last run on it that worked.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub last_ok_at: Option<DateTime<Utc>>,
    /// Orders its failures have touched since it last worked.
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub failed_orders: Vec<String>,
    /// The owner was told about the current cool-off, and by which question.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub alerted_at: Option<DateTime<Utc>>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub alert_question: Option<String>,
}

/// What a probe proved about an engine.
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum Proof {
    /// It returned a real completion to a request just now.
    Answered,
    /// Something answered at its address, but no completion was seen: a model list, a
    /// rate limit, an accepted request that never finished.
    Reachable,
    /// Nothing was asked of it. A CLI that wraps no endpoint cannot be tried without
    /// spending a real request, so it is only found on PATH.
    #[default]
    Unprobed,
}

impl Proof {
    #[must_use]
    pub fn as_str(self) -> &'static str {
        match self {
            Self::Answered => "answered",
            Self::Reachable => "reachable",
            Self::Unprobed => "unprobed",
        }
    }
}

/// One tiny-prompt run of a CLI engine that wraps an API.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct CliProbe {
    pub at: DateTime<Utc>,
    pub ok: bool,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub ms: Option<u64>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub reason: Option<String>,
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
    /// Questions to the owner whose signed answers this machine has already acted on.
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub applied: Vec<String>,
}

/// Where an agent's engine ledger lives on this machine.
#[must_use]
pub fn ledger_path(agent: &str) -> Option<PathBuf> {
    let name = ferryman_channel::canonical_agent_name(agent);
    #[cfg(test)]
    {
        // Tests never touch the real machine's ledger, and threads never share one -
        // except threads named `shared-ledger-*`, which a test starts to put several
        // writers on one file.
        let thread = if std::thread::current()
            .name()
            .is_some_and(|name| name.starts_with("shared-ledger"))
        {
            "shared".to_string()
        } else {
            format!("{:?}", std::thread::current().id())
                .chars()
                .filter(char::is_ascii_alphanumeric)
                .collect::<String>()
        };
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
    // Read, change, write back as one step. A worker running several orders at once has
    // several finishing together, and each one counts its own request and its own
    // verification: two of them reading the same file and writing back their own copy
    // would lose one of the counts.
    static ONE_AT_A_TIME: std::sync::Mutex<()> = std::sync::Mutex::new(());
    let _one = ONE_AT_A_TIME
        .lock()
        .unwrap_or_else(std::sync::PoisonError::into_inner);
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
    /// A probe got a real completion out of it, and nothing has failed on it since.
    Up,
    /// Never probed yet.
    Unknown,
    /// Probed, but nothing proves it can answer: only reachable, never asked, or a run
    /// failed on it since its last probe. Used, after everything that is proven.
    Unproven(String),
    /// The last probe failed. Still tried, after everything that is up.
    Down(String),
    /// Runs failed on it, so it is left alone until `until`; then it is probed again
    /// before it is trusted. Not tried until then.
    CoolingOff {
        until: DateTime<Utc>,
        reason: String,
    },
    /// Out of credit, or over the operator's weekly cap. Not tried until `until`.
    Exhausted {
        until: DateTime<Utc>,
        reason: String,
    },
}

impl Availability {
    #[must_use]
    pub fn usable(&self) -> bool {
        !matches!(self, Self::Exhausted { .. } | Self::CoolingOff { .. })
    }

    #[must_use]
    pub fn describe(&self) -> String {
        match self {
            Self::Up => "up".to_string(),
            Self::Unknown => "not probed yet".to_string(),
            Self::Unproven(why) => format!("not proven: {why}"),
            Self::Down(why) => format!("down: {why}"),
            Self::CoolingOff { until, reason } => format!(
                "cooling off until {}: {reason}",
                until.format("%a %Y-%m-%d %H:%M UTC")
            ),
            Self::Exhausted { until, reason } => format!(
                "exhausted until {}: {reason}",
                until.format("%a %Y-%m-%d %H:%M UTC")
            ),
        }
    }
}

/// Whether this engine's tiny-prompt run, not its endpoint, is what proves it: a CLI that
/// wraps an API (it names a `base_url`).
fn proved_by_cli(spec: &EngineSpec) -> bool {
    spec.kind == Kind::Cli && spec.base_url.is_some()
}

/// When this engine was last probed in the way that proves it.
fn proved_at(spec: &EngineSpec, state: &EngineState) -> Option<DateTime<Utc>> {
    if proved_by_cli(spec) {
        state.cli_probe.as_ref().map(|probe| probe.at)
    } else {
        state.checked_at
    }
}

/// What the probes prove about the engine, as it is published: `answered`, `reachable` or
/// `unprobed`. A run that failed since the proof was taken withdraws it.
#[must_use]
pub fn proof_of(spec: &EngineSpec, state: &EngineState) -> Proof {
    let base = if proved_by_cli(spec) {
        match &state.cli_probe {
            Some(probe) if probe.ok => Proof::Answered,
            Some(_) => Proof::Reachable,
            None => match state.proof {
                Some(Proof::Unprobed) | None => Proof::Unprobed,
                Some(_) => Proof::Reachable,
            },
        }
    } else {
        state.proof.unwrap_or_default()
    };
    if base == Proof::Unprobed {
        return base;
    }
    let failed_since = match (state.last_failure_at, proved_at(spec, state)) {
        (Some(failed), Some(proved)) => failed > proved,
        (Some(_), None) => true,
        _ => false,
    };
    if failed_since { Proof::Reachable } else { base }
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
    // Runs failed on it: left alone until the cool-off ends, however its last probe went.
    if let Some(until) = state.cooloff_until
        && until > now
    {
        return Availability::CoolingOff {
            until,
            reason: state
                .last_failure
                .clone()
                .unwrap_or_else(|| "runs failed on it".to_string()),
        };
    }
    if let Some(why) = &state.down {
        return Availability::Down(why.clone());
    }
    if proved_by_cli(spec)
        && let Some(probe) = state.cli_probe.as_ref().filter(|probe| !probe.ok)
    {
        return Availability::Down(
            probe
                .reason
                .clone()
                .unwrap_or_else(|| "its tiny test prompt got no answer".to_string()),
        );
    }
    if state.checked_at.is_none() && state.cli_probe.is_none() {
        return Availability::Unknown;
    }
    match proof_of(spec, state) {
        Proof::Answered => Availability::Up,
        Proof::Reachable => Availability::Unproven(
            if state
                .last_failure_at
                .is_some_and(|failed| proved_at(spec, state).is_none_or(|proved| failed > proved))
            {
                "a run failed on it since it was last probed".to_string()
            } else {
                "reachable only: no completion has been seen from it".to_string()
            },
        ),
        Proof::Unprobed => Availability::Unproven(if spec.base_url.is_none() {
            "unprobed: it cannot be tried without spending a real request".to_string()
        } else {
            "unprobed: not asked for a completion yet".to_string()
        }),
    }
}

/// Whether an engine goes behind every engine that is fine: its last probe failed, or it
/// answered but never completed anything (or a run failed since). An engine that simply
/// cannot be probed cheaply is not distrusted for that; it is shown as `unprobed`.
fn distrusted(spec: &EngineSpec, state: &EngineState, available: &Availability) -> bool {
    match available {
        Availability::Down(_) => true,
        Availability::Unproven(_) => proof_of(spec, state) == Proof::Reachable,
        _ => false,
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
                let down = distrusted(spec, &state, &available);
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
            let state = ledger.state(&spec.name);
            !distrusted(spec, &state, &availability(spec, &state, now))
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

/// The engines as the policy sees them: each configured one, with a gateway's (OmniRoute's)
/// paid class and route read from its last probe, followed by one engine per combo and
/// free model the gateway offers. What a worker publishes and chooses among.
#[must_use]
pub fn effective_specs(specs: &[EngineSpec], ledger: &Ledger) -> Vec<EngineSpec> {
    specs
        .iter()
        .flat_map(|spec| crate::omniroute::expand(spec, ledger.state(&spec.name).gateway.as_ref()))
        .collect()
}

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
pub fn choose(
    specs: &[EngineSpec],
    ledger: &Ledger,
    now: DateTime<Utc>,
    policy: &ferryman_channel::policy::Policy,
    role: ferryman_channel::policy::Role,
    tier: Tier,
    tried: &[String],
    (agent, machine): (&str, &str),
) -> std::result::Result<EngineSpec, String> {
    let specs = effective_specs(specs, ledger);
    let all = candidates(agent, machine, &specs, ledger, now);
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
        .cloned()
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

/// [`choose`] with the smart router: the engine to run `needs` next in `role`, the decision
/// that says why, and - when the policy's `routing` is `ordered` - exactly [`choose`]'s
/// engine.
///
/// The policy's background rules run first, as in [`choose`] (the router starts from the
/// same ranking), so nothing here can reach an engine `choose` would not. `failed` are the
/// engines that already failed this order, and the choice must beat them; `tried` are the
/// ones already asked in this attempt. `work` is [`Work::Background`] for the fleet's own
/// work and [`Work::Direct`] for a person's order that needs a capability only the router
/// knows about.
///
/// [`Work::Background`]: ferryman_channel::policy::Work::Background
/// [`Work::Direct`]: ferryman_channel::policy::Work::Direct
#[allow(clippy::too_many_arguments)]
pub fn choose_routed(
    specs: &[EngineSpec],
    ledger: &Ledger,
    now: DateTime<Utc>,
    policy: &ferryman_channel::policy::Policy,
    (role, tier, work): (
        ferryman_channel::policy::Role,
        Tier,
        ferryman_channel::policy::Work,
    ),
    needs: &ferryman_channel::work::Needs,
    (failed, tried): (&[ferryman_channel::router::Failed], &[String]),
    (agent, machine): (&str, &str),
) -> std::result::Result<(EngineSpec, ferryman_channel::router::Decision), String> {
    let specs = effective_specs(specs, ledger);
    let all = candidates(agent, machine, &specs, ledger, now);
    let routed = ferryman_channel::router::route(
        policy,
        role,
        tier.as_str(),
        work,
        needs,
        &all,
        &ferryman_channel::router::Context { now, tried, failed },
    );
    match routed.order.first() {
        Some(index) => Ok((specs[*index].clone(), routed.decision)),
        None => {
            let ranking = ferryman_channel::policy::rank(policy, role, tier.as_str(), work, &all);
            Err(if ranking.order.is_empty() {
                ranking.why_none(role, &all)
            } else if ranking
                .order
                .iter()
                .all(|index| tried.contains(&specs[*index].name))
            {
                format!(
                    "every allowed engine for {} work was tried ({})",
                    role.as_str(),
                    tried.join(", ")
                )
            } else {
                routed.decision.reason
            })
        }
    }
}

/// The effort the engine policy asked `role` to run at, as it is recorded beside the
/// engine that ran it - and only when that engine acts on an effort at all, so a record
/// never claims an effort that was not applied.
#[must_use]
pub fn effort_used(
    route: &ProjectRoute,
    role: ferryman_channel::policy::Role,
    engine: Option<&EngineSpec>,
) -> Option<String> {
    engine.filter(|engine| engine.applies_effort())?;
    let (policy, _) = ferryman_channel::policy::effective(&route.communications, &route.project_id);
    Some(policy.effort_for(role).as_str().to_string())
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
    record_verification_for(agent, engine, None, status, now)
}

/// [`record_verification`] for work of a known `kind` (`docs`, `code-change`, ...): a
/// verified or refuted result is also counted against that kind in the engine's per-kind
/// outcomes, which is what the smart router estimates success from. A result the evidence
/// could not decide counts for nothing there.
pub fn record_verification_for(
    agent: &str,
    engine: &str,
    kind: Option<&str>,
    status: ferryman_channel::evidence::Status,
    now: DateTime<Utc>,
) -> bool {
    use ferryman_channel::evidence::Status;
    let mut demoted = false;
    update(agent, |ledger| {
        let state = ledger.entry(engine);
        demoted = state.note(status, now);
        if let Some(kind) = kind
            && matches!(status, Status::Verified | Status::Refuted)
        {
            ferryman_channel::router::record_outcome(
                &mut state.outcomes,
                kind,
                status == Status::Verified,
                now,
            );
        }
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
            kinds: state.outcomes.clone(),
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

/// A failure reason shortened to what fits a ledger line or a notice.
pub fn clip_reason(text: &str) -> String {
    clip(text)
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
    /// The request was accepted and then not answered within the deadline.
    pub timed_out: bool,
}

fn client(timeout: Duration) -> Result<reqwest::Client> {
    reqwest::Client::builder()
        .timeout(timeout)
        .connect_timeout(Duration::from_secs(20))
        .build()
        .context("build the HTTP client")
}

/// The request an HTTP engine is sent. `reasoning_effort` is added only when the engine
/// says it `supports_effort` and an effort was asked for: nothing changes for an engine
/// that has not opted in.
#[must_use]
pub fn chat_body(spec: &EngineSpec, prompt: &str, effort: Option<Effort>) -> Value {
    let mut body = json!({
        "model": spec.model,
        "messages": [{"role": "user", "content": prompt}],
        "stream": false,
    });
    if spec.supports_effort
        && let Some(effort) = effort
    {
        body["reasoning_effort"] = json!(effort.as_str());
    }
    body
}

/// Ask an HTTP engine one prompt, at `effort` when it takes one.
pub async fn chat(
    spec: &EngineSpec,
    key: Option<&str>,
    prompt: &str,
    timeout: Duration,
    effort: Option<Effort>,
) -> ChatRun {
    let base = spec.base_url.as_deref().unwrap_or_default();
    #[cfg(test)]
    if let Some(canned) = base.strip_prefix("fake://") {
        return fake_chat(canned, prompt, &chat_body(spec, prompt, effort)).await;
    }
    let body = chat_body(spec, prompt, effort);
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
            // A request that was sent and never answered is not an endpoint that cannot
            // be reached: it is a model that hangs, which is the engine's failure.
            let timed_out = error.is_timeout();
            return ChatRun {
                detail: redact(
                    &if timed_out {
                        format!(
                            "{base} took the request and returned no answer within {}s",
                            timeout.as_secs()
                        )
                    } else {
                        format!("could not reach {base}: {error}")
                    },
                    key,
                ),
                unreachable: !timed_out && (error.is_connect() || error.is_request()),
                timed_out,
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
    // OmniRoute says what each request cost, $0 for a free route.
    let gateway_cost = response
        .headers()
        .get("x-omniroute-response-cost")
        .and_then(|value| value.to_str().ok())
        .and_then(|value| value.trim().parse::<f64>().ok())
        .filter(|cost| cost.is_finite() && *cost >= 0.0);
    let text = match response.text().await {
        Ok(text) => text,
        Err(error) if error.is_timeout() => {
            return ChatRun {
                detail: format!(
                    "{base} started to answer and did not finish within {}s",
                    timeout.as_secs()
                ),
                timed_out: true,
                ..ChatRun::default()
            };
        }
        Err(_) => String::new(),
    };
    if !status.is_success() {
        return ChatRun {
            detail: redact(
                &format!("HTTP {}{retry}: {}", status.as_u16(), clip(&text)),
                key,
            ),
            ..ChatRun::default()
        };
    }
    let mut run = chat_reply(&text);
    run.cost_usd = run.cost_usd.or(gateway_cost);
    run
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

/// One request a `fake://slow:` engine answered: which test's key, what it was asked, the
/// request body it was sent, and when it started and finished.
#[cfg(test)]
#[derive(Debug, Clone)]
pub(crate) struct SlowRun {
    pub key: String,
    pub prompt: String,
    pub body: Value,
    pub started: Instant,
    pub finished: Instant,
}

#[cfg(test)]
pub(crate) fn slow_runs() -> &'static std::sync::Mutex<Vec<SlowRun>> {
    static RUNS: std::sync::Mutex<Vec<SlowRun>> = std::sync::Mutex::new(Vec::new());
    &RUNS
}

/// Canned replies for tests: `fake://ok:<answer>`, `fake://quota`, `fake://down`,
/// `fake://paid:<answer>`, an answer whose provider says it cost a cent, and
/// `fake://slow:<key>:<millis>:<answer>`, an answer that takes its time and is logged in
/// [`slow_runs`] under `<key>`, so a test can see which requests overlapped (an answer of
/// `quota` is the out-of-credit error, after the same wait).
#[cfg(test)]
async fn fake_chat(canned: &str, prompt: &str, body: &Value) -> ChatRun {
    if let Some(rest) = canned.strip_prefix("slow:") {
        let mut parts = rest.splitn(3, ':');
        let key = parts.next().unwrap_or_default().to_string();
        let millis: u64 = parts.next().and_then(|m| m.parse().ok()).unwrap_or(0);
        let answer = parts.next().unwrap_or_default().to_string();
        let started = Instant::now();
        tokio::time::sleep(Duration::from_millis(millis)).await;
        slow_runs()
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner)
            .push(SlowRun {
                key,
                prompt: prompt.to_string(),
                body: body.clone(),
                started,
                finished: Instant::now(),
            });
        if answer == "quota" {
            return ChatRun {
                detail: "HTTP 402: Insufficient Balance".to_string(),
                ..ChatRun::default()
            };
        }
        return ChatRun {
            ok: true,
            text: answer,
            ..ChatRun::default()
        };
    }
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
        // Takes the request and never answers it: the deadline passes.
        // (`hangrun` is the one that answered its probe and hangs on real work: the
        // incident. `hang` hangs the probe too.)
        "hang" | "hangrun" => {
            tokio::time::sleep(Duration::from_millis(5)).await;
            ChatRun {
                detail: "fake://hang took the request and returned no answer within 300s"
                    .to_string(),
                timed_out: true,
                ..ChatRun::default()
            }
        }
        // Answers, with nothing in the answer: no tokens.
        "silent" => ChatRun {
            detail: "the reply carried no answer".to_string(),
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
    /// What an OmniRoute gateway offers.
    pub catalog: Option<crate::omniroute::Catalog>,
    /// What this probe proved: a real completion, an address that answered, or nothing.
    pub proof: Proof,
}

/// Whether a chat-completions reply carries a completion: a well-formed `choices` entry
/// and no error. With one token asked for, the text may be empty; the entry is the proof.
fn completion_in(body: &str) -> bool {
    let Ok(value) = serde_json::from_str::<Value>(body) else {
        return false;
    };
    value.get("error").is_none() && value["choices"].as_array().is_some_and(|c| !c.is_empty())
}

/// What an engine that took a request and never finished it is called.
fn not_proven(deadline: Duration) -> String {
    format!(
        "took the request but returned no completion within {}s",
        deadline.as_secs().max(1)
    )
}

/// Probe one engine, honestly: it is only called up when it has just returned a real
/// completion. An endpoint is asked for one token (`probe = "chat"`, the default for an
/// http engine and for NVIDIA); listing models proves only that something is there. A CLI
/// engine with no endpoint is only looked for on PATH, because running it would cost a
/// real request, and says so: unprobed. A CLI engine that wraps an endpoint gets its
/// proof from [`crate::agent`]'s tiny-prompt run through the CLI itself; the endpoint
/// answering never proves the CLI in front of it works.
pub async fn probe(spec: &EngineSpec, key: Option<&str>) -> Probe {
    probe_within(spec, key, PROVE_DEADLINE).await
}

/// [`probe`], waiting at most `deadline` for the completion.
pub async fn probe_within(spec: &EngineSpec, key: Option<&str>, deadline: Duration) -> Probe {
    let mut found = probe_endpoint(spec, key, deadline).await;
    if proved_by_cli(spec) && found.proof == Proof::Answered {
        found.proof = Proof::Reachable;
    }
    found
}

async fn probe_endpoint(spec: &EngineSpec, key: Option<&str>, deadline: Duration) -> Probe {
    let Some(base) = spec.base_url.as_deref() else {
        let found = Path::new(&spec.command).is_file()
            || crate::doctor::find_on_path(&spec.command).is_some();
        return Probe {
            down: (!found).then(|| format!("'{}' is not on PATH", spec.command)),
            proof: Proof::Unprobed,
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
                proof: Proof::Reachable,
                ..Probe::default()
            },
            "down" => Probe {
                down: Some("connection refused".into()),
                ..Probe::default()
            },
            // Reachable, takes the request, never completes it.
            "hang" => {
                // A fake never makes a test wait out a real deadline.
                let wait = deadline.min(Duration::from_millis(50));
                let _ = tokio::time::timeout(wait, std::future::pending::<()>()).await;
                Probe {
                    down: Some(not_proven(deadline)),
                    proof: Proof::Reachable,
                    ..Probe::default()
                }
            }
            // Lists its models and nothing more.
            "reach" => Probe {
                latency_ms: Some(5),
                proof: Proof::Reachable,
                ..Probe::default()
            },
            _ => Probe {
                latency_ms: Some(5),
                proof: Proof::Answered,
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
            "stream": false,
        }))
    } else {
        http.get(format!("{base}/models"))
    };
    let request = match key {
        Some(key) => request.bearer_auth(key),
        None => request,
    }
    .timeout(deadline);
    let mut found = Probe::default();
    // Sending and reading the body are one deadline: a reply that starts and never ends
    // is no completion either.
    let reply = async {
        let response = request.send().await?;
        let status = response.status().as_u16();
        let body = response.text().await?;
        Ok::<_, reqwest::Error>((status, body))
    }
    .await;
    match reply {
        Err(error) if error.is_timeout() => {
            found.down = Some(not_proven(deadline));
            found.proof = Proof::Reachable;
        }
        Err(error) => {
            found.down = Some(clip(&redact(&format!("unreachable: {error}"), key)));
        }
        Ok((status, body)) => {
            found.latency_ms =
                Some(u64::try_from(started.elapsed().as_millis()).unwrap_or(u64::MAX));
            let said = clip(&redact(&format!("HTTP {status}: {body}"), key));
            // Whatever answered, it was reachable; only a completion lifts it above that.
            found.proof = Proof::Reachable;
            match status {
                200..=299 => {
                    if spec.probe_chat {
                        if completion_in(&body) {
                            found.proof = Proof::Answered;
                        } else {
                            found.down = Some(clip(&redact(
                                &format!("HTTP {status} but no completion: {body}"),
                                key,
                            )));
                        }
                    }
                    if !spec.probe_chat && crate::omniroute::is_omniroute(spec) {
                        found.catalog = Some(crate::omniroute::Catalog {
                            models: crate::omniroute::parse_models(&body),
                            ..Default::default()
                        });
                    }
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
    // A combo's steps, when OmniRoute lets this key read them: what decides whether a
    // route ends at somebody's plan.
    if let Some(catalog) = found.catalog.as_mut() {
        let mut request = http.get(format!("{}/api/combos", crate::omniroute::api_root(base)));
        if let Some(key) = key {
            request = request.bearer_auth(key);
        }
        if let Ok(response) = request.send().await
            && response.status().is_success()
            && let Some(combos) = response
                .text()
                .await
                .ok()
                .and_then(|body| crate::omniroute::parse_combos(&body))
        {
            catalog.combos = combos;
            catalog.combos_known = true;
        }
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
    state.proof = Some(probe.proof);
    if probe.balance.is_some() {
        state.balance = probe.balance.clone();
    }
    if probe.catalog.is_some() {
        state.gateway.clone_from(&probe.catalog);
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

/// Whether an engine's endpoint is due a probe: never probed, probed [`PROBE_EVERY_SECS`]
/// ago or more, or probed before a run failed on it or before its cool-off ended - so
/// that an engine coming out of a cool-off is trusted again only on seeing it answer.
/// Never while it is cooling off: nothing is spent on an engine that is being left alone.
#[must_use]
pub fn endpoint_probe_due(state: &EngineState, now: DateTime<Utc>) -> bool {
    if state.cooloff_until.is_some_and(|until| until > now) {
        return false;
    }
    state.checked_at.is_none_or(|at| {
        let since = now.signed_duration_since(at);
        since < chrono::Duration::zero()
            || since >= chrono::Duration::seconds(PROBE_EVERY_SECS)
            || state.cooloff_until.is_some_and(|until| at < until)
            || state.last_failure_at.is_some_and(|failed| at < failed)
    })
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
        let state = ledger.state(&spec.name);
        // Nothing is spent on an engine that is cooling off; when the cool-off ends it is
        // probed at once, however recently it was probed before, so it is trusted again
        // only on seeing it answer.
        if !endpoint_probe_due(&state, now) {
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
                // Not proven is not up: said as unknown, with what is missing.
                Availability::Unproven(why) => ("unknown", None, Some(why.clone())),
                Availability::Down(why) => ("down", None, Some(why.clone())),
                // Down, with the time it is expected back: a policy reads that as out of
                // the running until then.
                Availability::CoolingOff { until, reason } => (
                    "down",
                    Some(*until),
                    Some(format!(
                        "cooling off after {} failed run(s) in a row: {reason}",
                        state.fail_streak.max(1)
                    )),
                ),
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
                class: Some(spec.class().as_str().to_string()),
                capabilities: Some(capabilities(spec)),
                proof: Some(proof_of(spec, &state).as_str().to_string()),
            }
        })
        .collect()
}

// --- runs that fail: cool-off, and telling the owner ------------------------------------

/// What one failed run did to its engine's record.
#[derive(Debug, Clone, PartialEq)]
pub struct Strike {
    /// Failed runs in a row, this one included.
    pub streak: u32,
    /// The engine is left alone until then.
    pub cooloff_until: DateTime<Utc>,
    /// When this cool-off began; the owner is told once per cool-off.
    pub cooloff_started: DateTime<Utc>,
    /// Whether the owner should be told now: the streak reached `alert_after` and nobody
    /// has been told about this cool-off.
    pub alert: bool,
    /// Orders its failures have touched since it last worked, oldest first.
    pub orders: Vec<String>,
}

/// How long the `streak`th failure in a row leaves an engine alone.
#[must_use]
pub fn cooloff_for(streak: u32) -> chrono::Duration {
    let step = usize::try_from(streak.saturating_sub(1)).map_or(2, |step| step.min(2));
    chrono::Duration::seconds(COOLOFF_STEPS_SECS[step])
}

/// A run failed on this engine: it timed out, stalled, returned no tokens or errored.
/// The engine is marked down with the reason and left alone for 15 minutes, then an
/// hour, then four, for each failure in a row. A second failure that lands while the
/// engine is already cooling off (two orders were running on it together) is recorded as
/// affected but does not climb the ladder.
pub fn record_run_failure(
    agent: &str,
    engine: &str,
    (model, order): (Option<&str>, &str),
    reason: &str,
    alert_after: u32,
    now: DateTime<Utc>,
) -> Strike {
    let mut strike = None;
    update(agent, |ledger| {
        let state = ledger.entry(engine);
        let cooling = state.cooloff_until.is_some_and(|until| until > now);
        if !cooling {
            state.fail_streak = state.fail_streak.saturating_add(1);
            state.cooloff_started = Some(now);
            state.cooloff_until = Some(now + cooloff_for(state.fail_streak));
        }
        state.last_failure = Some(clip(reason));
        state.last_failure_at = Some(now);
        state.failed_model = model.map(str::to_string);
        if !state.failed_orders.iter().any(|known| known == order) {
            state.failed_orders.push(order.to_string());
            let extra = state.failed_orders.len().saturating_sub(AFFECTED_ORDERS);
            state.failed_orders.drain(..extra);
        }
        let started = state.cooloff_started.unwrap_or(now);
        let alert = !cooling
            && state.fail_streak >= alert_after.max(1)
            && state.alerted_at.is_none_or(|told| told < started);
        if alert {
            state.alerted_at = Some(now);
        }
        strike = Some(Strike {
            streak: state.fail_streak,
            cooloff_until: state.cooloff_until.unwrap_or(now),
            cooloff_started: started,
            alert,
            orders: state.failed_orders.clone(),
        });
    });
    strike.unwrap_or_else(|| Strike {
        streak: 1,
        cooloff_until: now,
        cooloff_started: now,
        alert: false,
        orders: Vec::new(),
    })
}

/// A run worked on this engine: the ladder starts over.
pub fn record_run_success(agent: &str, engine: &str, now: DateTime<Utc>) {
    update(agent, |ledger| {
        let state = ledger.entry(engine);
        let was_failing = state.fail_streak > 0 || state.cooloff_until.is_some();
        state.last_ok_at = Some(now);
        if was_failing {
            state.fail_streak = 0;
            state.cooloff_until = None;
            state.cooloff_started = None;
            state.failed_orders.clear();
            state.alerted_at = None;
            state.alert_question = None;
        }
    });
}

/// The owner said to try this engine again: forget its cool-off. Its record of the last
/// failure stays, so it still reads as unproven until a probe sees it answer.
pub fn clear_cooloff(agent: &str, engine: &str) {
    update(agent, |ledger| {
        let state = ledger.entry(engine);
        state.cooloff_until = None;
        state.fail_streak = 0;
        state.alerted_at = None;
        // A probe is due at once: the failure is newer than the last one.
    });
}

/// Note which question told the owner about this engine's cool-off.
pub fn note_alert(agent: &str, engine: &str, question: &str) {
    update(agent, |ledger| {
        ledger.entry(engine).alert_question = Some(question.to_string());
    });
}

/// Mark a question's answer as acted on, once.
pub fn mark_applied(agent: &str, question: &str) {
    update(agent, |ledger| {
        if !ledger.applied.iter().any(|known| known == question) {
            ledger.applied.push(question.to_string());
            let extra = ledger.applied.len().saturating_sub(200);
            ledger.applied.drain(..extra);
        }
    });
}

/// Runs failed on this engine since it last worked, recently enough to say so: what the
/// watchdog sets beside an engine that says it is up. `None` when nothing has failed or
/// it worked since.
#[must_use]
pub fn recent_failures(state: &EngineState, now: DateTime<Utc>) -> Option<String> {
    let failed = state.last_failure_at?;
    if now.signed_duration_since(failed) > chrono::Duration::hours(24) {
        return None;
    }
    if state.last_ok_at.is_some_and(|ok| ok > failed) {
        return None;
    }
    Some(format!(
        "{} run(s) failed in a row, the last {} ago: {}",
        state.fail_streak.max(1),
        ferryman_channel::receipts::short_age(now.signed_duration_since(failed)),
        state.last_failure.as_deref().unwrap_or("no reason given")
    ))
}

/// Whether a CLI engine that wraps an API is due its tiny-prompt run: never run, run
/// [`CLI_PROBE_EVERY_SECS`] ago or more, or a run has failed on it since. Not while it is
/// cooling off: nothing is spent on an engine that is being left alone.
#[must_use]
pub fn cli_probe_due(spec: &EngineSpec, state: &EngineState, now: DateTime<Utc>) -> bool {
    if !proved_by_cli(spec) || state.cooloff_until.is_some_and(|until| until > now) {
        return false;
    }
    match &state.cli_probe {
        None => true,
        Some(last) => {
            let since = now.signed_duration_since(last.at);
            since < chrono::Duration::zero()
                || since >= chrono::Duration::seconds(CLI_PROBE_EVERY_SECS)
                || state.last_failure_at.is_some_and(|failed| failed > last.at)
        }
    }
}

/// Record the outcome of a CLI engine's tiny-prompt run.
pub fn record_cli_probe(agent: &str, engine: &str, probe: CliProbe) {
    update(agent, |ledger| {
        let state = ledger.entry(engine);
        if probe.ok {
            state.latency_ms = probe.ms;
        }
        state.cli_probe = Some(probe);
    });
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
        weekly_requests: spec.weekly_requests,
        week: iso_week(now),
        requests: if this_week { state.requests } else { 0 },
        spend_usd: if this_week { state.spend_usd } else { 0.0 },
        flag: (spec.paid == Paid::FreeTier)
            .then(|| state.free_tier_flag(now))
            .flatten(),
        route: spec.route.clone(),
    }
}

#[cfg(test)]
mod probe_choice_tests {
    use super::probe_with_chat;

    #[test]
    fn nvidia_is_probed_with_a_real_request_unless_told_otherwise() {
        let nvidia = Some("https://integrate.api.nvidia.com/v1");
        assert!(
            probe_with_chat(None, nvidia),
            "its model list proves nothing"
        );
        assert!(
            !probe_with_chat(Some("models"), nvidia),
            "an explicit setting wins"
        );
        assert!(!probe_with_chat(None, Some("https://api.deepseek.com")));
        assert!(probe_with_chat(
            Some("chat"),
            Some("https://api.deepseek.com")
        ));
        assert!(!probe_with_chat(None, None));
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
            provider: None,
            route: Vec::new(),
            class: None,
            effort_args: BTreeMap::new(),
            supports_effort: false,
            declared: ferryman_channel::capability::Declared::default(),
        }
    }

    fn monday_noon() -> DateTime<Utc> {
        Utc.with_ymd_and_hms(2026, 9, 28, 12, 0, 0).unwrap()
    }

    /// An endpoint on this machine is a local model only when nobody says it is somebody's
    /// paid API behind a proxy: an OmniRoute gateway (by port, name or provider), or an
    /// engine its operator marked prepaid, a subscription or a free tier, costs what that
    /// says and is never priced as free.
    #[test]
    fn a_paid_or_gateway_endpoint_on_this_machine_is_not_a_free_local_model() {
        let caps = |url: &str, paid: Paid, provider: Option<&str>| {
            let mut spec = http("e", Tier::Build, url);
            spec.paid = paid;
            spec.provider = provider.map(str::to_string);
            capabilities(&spec)
        };
        // A model server nobody said anything about: local, and free.
        let plain = caps("http://localhost:1234/v1", Paid::Unknown, None);
        assert!(plain.local && plain.cost.is_some_and(|c| c.is_free()));
        // OmniRoute on its own port or by its provider: a gateway, not local, not free.
        for spec in [
            caps("http://localhost:20128/v1", Paid::Unknown, None),
            caps("http://127.0.0.1:9000/v1", Paid::Unknown, Some("omniroute")),
            caps("http://192.168.1.20/omniroute/v1", Paid::Unknown, None),
        ] {
            assert!(!spec.local, "{spec:?}");
            assert!(spec.cost.is_none(), "{spec:?}");
        }
        // Said to be paid: not local however near it is.
        for paid in [Paid::Prepaid, Paid::Subscription, Paid::FreeTier] {
            assert!(
                !caps("http://localhost:1234/v1", paid, None).local,
                "{paid:?}"
            );
        }
        // Said to be local, it is, gateway or not.
        assert!(caps("http://localhost:20128/v1", Paid::Local, None).local);
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

    // --- effort, class and concurrent writers ---------------------------------------------

    fn cli(args: &[&str]) -> EngineSpec {
        let mut spec = EngineSpec::implicit(
            "codex",
            &args.iter().map(ToString::to_string).collect::<Vec<_>>(),
            Some("gpt-5-mini"),
        );
        spec.name = "codex".into();
        spec
    }

    #[test]
    fn effort_fills_its_placeholder_like_the_model_and_adds_the_engines_own_args() {
        let spec = cli(&[
            "exec",
            "-c",
            "model_reasoning_effort={effort}",
            "-m",
            "{model}",
            "{prompt}",
        ]);
        assert_eq!(
            spec.cli_args_at(Some(Effort::High)),
            [
                "exec",
                "-c",
                "model_reasoning_effort=high",
                "-m",
                "gpt-5-mini",
                "{prompt}"
            ]
        );
        assert_eq!(
            spec.cli_args_at(Some(Effort::Low))[2],
            "model_reasoning_effort=low"
        );
        // No effort asked: the placeholder reads medium, as the plain `cli_args` always has.
        assert_eq!(spec.cli_args()[2], "model_reasoning_effort=medium");
        assert!(spec.applies_effort());

        // Per-level args go in just before the prompt, and only when an effort was asked.
        let mut flagged = cli(&["run", "--auto", "{prompt}"]);
        flagged.effort_args = BTreeMap::from([
            (
                "high".to_string(),
                vec!["--think".to_string(), "{effort}".to_string()],
            ),
            ("low".to_string(), vec!["--quick".to_string()]),
        ]);
        assert_eq!(
            flagged.cli_args_at(Some(Effort::High)),
            ["run", "--auto", "--think", "high", "{prompt}"]
        );
        assert_eq!(
            flagged.cli_args_at(Some(Effort::Low)),
            ["run", "--auto", "--quick", "{prompt}"]
        );
        assert_eq!(
            flagged.cli_args_at(Some(Effort::Medium)),
            ["run", "--auto", "{prompt}"],
            "a level with no extra args adds none"
        );
        assert_eq!(flagged.cli_args(), ["run", "--auto", "{prompt}"]);
        assert!(flagged.applies_effort());
        // Without a prompt placeholder they follow the rest.
        let mut bare = cli(&["go"]);
        bare.effort_args = BTreeMap::from([("high".to_string(), vec!["--hard".to_string()])]);
        assert_eq!(bare.cli_args_at(Some(Effort::High)), ["go", "--hard"]);

        // An engine that says nothing about effort is untouched by it, and says so.
        let plain = cli(&["-p", "{prompt}"]);
        assert_eq!(plain.cli_args_at(Some(Effort::High)), plain.cli_args());
        assert!(!plain.applies_effort());
    }

    #[test]
    fn an_http_engine_is_sent_a_reasoning_effort_only_when_it_says_it_takes_one() {
        let mut spec = http("nvidia", Tier::Build, "https://example.invalid/v1");
        let body = chat_body(&spec, "hi", Some(Effort::High));
        assert!(
            body.get("reasoning_effort").is_none(),
            "off by default: {body}"
        );
        assert_eq!(body["messages"][0]["content"], "hi");
        spec.supports_effort = true;
        assert_eq!(
            chat_body(&spec, "hi", Some(Effort::High))["reasoning_effort"],
            "high"
        );
        assert_eq!(
            chat_body(&spec, "hi", Some(Effort::Low))["reasoning_effort"],
            "low"
        );
        assert!(
            chat_body(&spec, "hi", None)
                .get("reasoning_effort")
                .is_none(),
            "no effort asked, none sent"
        );
        assert!(spec.applies_effort());
        assert_eq!(
            chat_body(
                &http("x", Tier::Build, "https://example.invalid/v1"),
                "hi",
                None
            ),
            json!({ "model": "m", "messages": [{"role": "user", "content": "hi"}], "stream": false }),
            "an engine that has not opted in is sent exactly what it always was"
        );
    }

    #[test]
    fn effort_class_and_the_effort_flags_are_read_from_agent_toml() {
        let parsed = parse_engines(
            &fields(
                "engines = [\"codex\", \"mini\"]\n\
                 engine.codex.command = \"codex\"\n\
                 engine.codex.args = [\"exec\",\"-c\",\"model_reasoning_effort={effort}\",\"{prompt}\"]\n\
                 engine.codex.model = \"gpt-5\"\n\
                 engine.codex.class = \"large\"\n\
                 engine.mini.base_url = \"https://example.invalid/v1\"\n\
                 engine.mini.model = \"gpt-5-mini\"\n\
                 engine.mini.supports_effort = \"true\"\n\
                 engine.mini.effort_args = {\"HIGH\":[\"--hard\"]}\n",
            ),
            "claude",
            &[],
            None,
        )
        .unwrap();
        assert_eq!(parsed[0].class, Some(ModelClass::Large));
        assert_eq!(parsed[0].class(), ModelClass::Large, "declared");
        assert!(!parsed[0].supports_effort && parsed[0].effort_args.is_empty());
        assert_eq!(parsed[1].class, None);
        assert_eq!(
            parsed[1].class(),
            ModelClass::Small,
            "guessed from gpt-5-mini"
        );
        assert!(parsed[1].supports_effort);
        assert_eq!(
            parsed[1].effort_args["high"],
            ["--hard"],
            "levels are folded"
        );
        // A declared class beats the guess whichever way it points.
        let mut sonnet = cli(&["{prompt}"]);
        sonnet.model = Some("claude-sonnet-4".into());
        assert_eq!(sonnet.class(), ModelClass::Medium);
        sonnet.class = Some(ModelClass::Small);
        assert_eq!(sonnet.class(), ModelClass::Small);

        let refuse = |extra: &str| {
            parse_engines(
                &fields(&format!(
                    "engines = [\"e\"]\nengine.e.command = \"c\"\n{extra}\n"
                )),
                "c",
                &[],
                None,
            )
            .unwrap_err()
            .to_string()
        };
        assert!(refuse("engine.e.class = \"huge\"").contains("engine.e.class"));
        assert!(refuse("engine.e.effort_args = {\"extreme\":[]}").contains("effort_args"));
        assert!(refuse("engine.e.effort_args = [1]").contains("effort_args"));
        assert!(refuse("engine.e.supports_effort = \"maybe\"").contains("supports_effort"));
    }

    #[test]
    fn the_inventory_carries_the_class_and_the_weekly_request_cap() {
        let mut spec = cli(&["{prompt}"]);
        spec.paid = Paid::Subscription;
        spec.weekly_requests = Some(200);
        spec.model = Some("claude-haiku-4".into());
        let reports = reports(&[spec.clone()], &Ledger::default(), monday_noon());
        assert_eq!(reports[0].class.as_deref(), Some("small"));
        assert_eq!(
            reports[0].billing.as_ref().unwrap().weekly_requests,
            Some(200)
        );
        let candidate = ferryman_channel::policy::Candidate::from_report("a", "m", 0, &reports[0]);
        assert_eq!(candidate.class(), ModelClass::Small);
        assert_eq!(candidate.weekly_requests, Some(200));
        // A line from a worker older than classes has none, and the fleet guesses.
        let mut old = reports[0].clone();
        old.class = None;
        old.billing = None;
        let candidate = ferryman_channel::policy::Candidate::from_report("a", "m", 0, &old);
        assert_eq!(
            candidate.class(),
            ModelClass::Small,
            "guessed from the model"
        );
        assert_eq!(candidate.weekly_requests, None);
        let published = serde_json::to_value(&old).unwrap();
        assert!(
            published.get("class").is_none(),
            "left out when unknown: {published}"
        );
    }

    /// Several threads each count requests against the same engine in one ledger: every
    /// count lands. Each thread's name starts `shared-ledger`, which the test ledger path
    /// takes to mean one shared file rather than one per thread.
    #[test]
    fn concurrent_writers_lose_no_ledger_update() {
        let now = monday_noon();
        let agent = format!("swarm-ledger-{}", std::process::id());
        let threads: Vec<_> = (0..8)
            .map(|n| {
                let agent = agent.clone();
                std::thread::Builder::new()
                    .name(format!("shared-ledger-{n}"))
                    .spawn(move || {
                        for _ in 0..25 {
                            record_use(&agent, "swarm", 0.01, now);
                        }
                        record_verification(
                            &agent,
                            "swarm",
                            ferryman_channel::evidence::Status::Verified,
                            now,
                        );
                    })
                    .unwrap()
            })
            .collect();
        for thread in threads {
            thread.join().unwrap();
        }
        let ledger = std::thread::Builder::new()
            .name("shared-ledger-reader".into())
            .spawn(move || Ledger::load(&agent))
            .unwrap()
            .join()
            .unwrap();
        let state = ledger.state("swarm");
        assert_eq!(state.requests, 200, "{state:?}");
        assert_eq!(state.verified, 8, "{state:?}");
        assert!((state.spend_usd - 2.0).abs() < 1e-6, "{state:?}");
    }

    #[test]
    fn outcomes_are_kept_per_kind_fade_with_age_and_ride_the_inventory() {
        use ferryman_channel::evidence::Status;
        let agent = format!("outcomes-{}", std::process::id());
        let now = monday_noon();
        for _ in 0..3 {
            record_verification_for(&agent, "nvidia", Some("docs"), Status::Verified, now);
        }
        record_verification_for(&agent, "nvidia", Some("docs"), Status::Refuted, now);
        record_verification_for(&agent, "nvidia", Some("code-change"), Status::Refuted, now);
        // A result the evidence could not decide counts for the engine, not for a kind,
        // and so does one with no kind.
        record_verification_for(&agent, "nvidia", Some("docs"), Status::Unverified, now);
        record_verification(&agent, "nvidia", Status::Verified, now);
        let ledger = Ledger::load(&agent);
        let state = ledger.state("nvidia");
        assert_eq!((state.verified, state.refuted, state.unverified), (4, 2, 1));
        let docs = state.outcomes.iter().find(|o| o.kind == "docs").unwrap();
        let (verified, refuted) = docs.weights(now);
        assert!((verified - 3.0).abs() < 1e-3 && (refuted - 1.0).abs() < 1e-3);
        let code = state
            .outcomes
            .iter()
            .find(|o| o.kind == "code-change")
            .unwrap();
        assert!(
            (code.weights(now).1 - 1.0).abs() < 1e-3,
            "kept apart from docs"
        );
        // A fortnight on, every result counts for half.
        let later = now + chrono::Duration::days(14);
        let (verified, refuted) = docs.weights(later);
        assert!((verified - 1.5).abs() < 1e-3 && (refuted - 0.5).abs() < 1e-3);
        // The share of results that held up is the same; there are fewer of them.
        let (rate, decided) = docs.rate(later).unwrap();
        assert!((rate - 0.75).abs() < 1e-3 && (decided - 2.0).abs() < 1e-3);

        // Published in the engine's trust line, and read back as the fleet's view of it.
        let spec = http("nvidia", Tier::Build, "https://integrate.api.nvidia.com/v1");
        let reports = reports(&[spec], &ledger, now);
        let published = reports[0].trust.as_ref().unwrap();
        assert_eq!(published.kinds.len(), 2);
        let candidate = ferryman_channel::policy::Candidate::from_report("a", "m", 0, &reports[0]);
        assert_eq!(candidate.outcomes, published.kinds);
        // A worker that has no kinds yet publishes none.
        assert!(trust(&EngineState::default()).is_none());
    }

    /// Two fake engines, one free and one paid, both large: what the router picks, what
    /// `ordered` picks (exactly [`choose`]), and what happens once the free one fails.
    #[test]
    fn the_router_picks_the_cheapest_sufficient_engine_and_ordered_is_choose() {
        use ferryman_channel::{
            capability::Cost,
            evidence::Status,
            policy::{Policy, Role, Routing, Work},
        };
        let now = monday_noon();
        let here = ("wisp", "grouchly");
        let mut free = http("free", Tier::Build, "https://free.example/v1");
        free.paid = Paid::FreeTier;
        free.class = Some(ModelClass::Large);
        free.declared.cost = Some(Cost::FREE);
        let mut dear = http("dear", Tier::Build, "https://dear.example/v1");
        dear.paid = Paid::Prepaid;
        dear.class = Some(ModelClass::Large);
        dear.declared.cost = Some(Cost {
            per_call_usd: 0.0,
            per_mtok_in_usd: 3.0,
            per_mtok_out_usd: 15.0,
        });
        let specs = vec![dear, free];
        let needs = ferryman_channel::router::simulated_needs("docs", "small", &[]).unwrap();
        let go = |policy: &Policy, ledger: &Ledger, failed: &[ferryman_channel::router::Failed]| {
            choose_routed(
                &specs,
                ledger,
                now,
                policy,
                (Role::Build, Tier::Build, Work::Background),
                &needs,
                (failed, &[]),
                here,
            )
            .unwrap()
        };
        let smart = Policy::default();
        let (picked, decision) = go(&smart, &Ledger::default(), &[]);
        assert_eq!(picked.name, "free", "{}", decision.reason);
        assert!(
            decision.reason.contains("cheapest sufficient"),
            "{}",
            decision.reason
        );
        assert_eq!(decision.routing, "smart");

        // Ordered is choose(), whatever the prices say.
        let mut ordered = Policy {
            routing: Routing::Ordered,
            ..Policy::default()
        };
        ordered
            .prefer
            .insert("build".into(), vec!["name:dear".into()]);
        let (picked, decision) = go(&ordered, &Ledger::default(), &[]);
        let old = choose(
            &specs,
            &Ledger::default(),
            now,
            &ordered,
            Role::Build,
            Tier::Build,
            &[],
            here,
        )
        .unwrap();
        assert_eq!((picked.name.as_str(), old.name.as_str()), ("dear", "dear"));
        assert_eq!(decision.routing, "ordered");
        // Smart with the same prefer list: the preference is only a bias, so it does not
        // beat a cheaper engine that is sufficient.
        let mut biased = smart.clone();
        biased
            .prefer
            .insert("build".into(), vec!["name:dear".into()]);
        assert_eq!(go(&biased, &Ledger::default(), &[]).0.name, "free");

        // The free engine's docs work gets refuted once: it stops being sufficient and
        // the paid one takes docs work, while the free one is still the pick for tests.
        let agent = format!("router-learns-{}", std::process::id());
        record_verification_for(&agent, "free", Some("docs"), Status::Refuted, now);
        let learned = Ledger::load(&agent);
        let (picked, decision) = go(&smart, &learned, &[]);
        assert_eq!(picked.name, "dear", "{}", decision.reason);
        let tests = ferryman_channel::router::simulated_needs("tests", "small", &[]).unwrap();
        let (picked, _) = choose_routed(
            &specs,
            &learned,
            now,
            &smart,
            (Role::Build, Tier::Build, Work::Background),
            &tests,
            (&[], &[]),
            here,
        )
        .unwrap();
        assert_eq!(
            picked.name, "free",
            "what failed at docs is not held against tests"
        );

        // After a failure on this order the failed engine is out, whatever it learned.
        let failure = |engine: &str, agent: &str| ferryman_channel::router::Failed {
            agent: agent.into(),
            machine: here.1.into(),
            engine: engine.into(),
            p: Some(0.8),
        };
        let failed = [failure("free", here.0)];
        let (picked, decision) = go(&smart, &Ledger::default(), &failed);
        assert_eq!(picked.name, "dear");
        assert_eq!(decision.failed, ["free"]);
        // Another agent's `free` that failed is not this agent's `free`.
        let (picked, _) = go(&smart, &Ledger::default(), &[failure("free", "ember")]);
        assert_ne!(picked.name, "dear", "free is not out for wisp");
        // With everything out nothing waits: the likeliest engine tries again.
        let both = [failed[0].clone(), failure("dear", here.0)];
        let (_, again) = choose_routed(
            &specs,
            &Ledger::default(),
            now,
            &smart,
            (Role::Build, Tier::Build, Work::Background),
            &needs,
            (&both, &[]),
            here,
        )
        .expect("every engine failed once: try again, do not hold");
        assert!(again.reason.contains("tries again"), "{}", again.reason);
    }

    // --- honest probes, and runs that fail ----------------------------------------------

    fn answering(name: &str, canned: &str) -> EngineSpec {
        let mut spec = http(name, Tier::Build, &format!("fake://{canned}"));
        spec.probe_chat = true;
        spec
    }

    fn a_cli_engine(name: &str, base_url: Option<&str>) -> EngineSpec {
        let mut spec = http(name, Tier::Build, "unused");
        spec.kind = Kind::Cli;
        spec.base_url = base_url.map(str::to_string);
        spec.command = std::env::current_exe()
            .unwrap()
            .to_string_lossy()
            .into_owned();
        spec.probe_chat = base_url.is_some();
        spec
    }

    #[tokio::test]
    async fn an_endpoint_that_takes_the_request_and_never_completes_is_not_proven_and_the_router_skips_it()
     {
        let now = Utc::now();
        let hung = answering("hung", "hang");
        let reach = answering("reach", "reach");
        let good = answering("good", "ok:fine");
        let mut ledger = Ledger::default();
        for spec in [&hung, &reach, &good] {
            // A deadline of milliseconds: the fake never answers `hang`.
            let found = probe_within(spec, None, Duration::from_millis(20)).await;
            apply_probe(&mut ledger, &spec.name, &found, now);
        }

        assert_eq!(proof_of(&hung, &ledger.state("hung")), Proof::Reachable);
        assert!(matches!(
            availability(&hung, &ledger.state("hung"), now),
            Availability::Down(why) if why.contains("no completion")
        ));
        assert!(matches!(
            availability(&reach, &ledger.state("reach"), now),
            Availability::Unproven(_)
        ));
        assert_eq!(
            availability(&good, &ledger.state("good"), now),
            Availability::Up
        );

        let specs = [hung, reach, good];
        let reports = reports(&specs, &ledger, now);
        let [hung, reach, good] = reports.as_slice() else {
            panic!("three reports")
        };
        assert_eq!(hung.state, "down");
        assert_eq!(reach.state, "unknown", "reachable is not up");
        assert_eq!(reach.state_label(), "reachable only");
        assert_eq!(good.state, "up");
        assert!(
            good.state_label().starts_with("up, answered in "),
            "{}",
            good.state_label()
        );
        // The hung engine is listed first, and is still not given the work.
        let picked = pick(&specs, &ledger, now, Tier::Build, &[]).unwrap();
        assert_eq!(picked.name, "good");
    }

    #[tokio::test]
    async fn an_engine_that_cannot_be_probed_cheaply_says_unprobed_never_up() {
        let now = Utc::now();
        let shell = a_cli_engine("shell", None);
        let found = probe(&shell, None).await;
        assert_eq!(found.proof, Proof::Unprobed);
        assert!(found.down.is_none(), "it is on PATH: {:?}", found.down);
        let mut ledger = Ledger::default();
        apply_probe(&mut ledger, "shell", &found, now);

        assert!(matches!(
            availability(&shell, &ledger.state("shell"), now),
            Availability::Unproven(why) if why.starts_with("unprobed")
        ));
        let report = &reports(std::slice::from_ref(&shell), &ledger, now)[0];
        assert_eq!(report.state, "unknown");
        assert_eq!(report.proof.as_deref(), Some("unprobed"));
        assert_eq!(report.state_label(), "unprobed");
        // Unprobed is a thing to say, not a reason to refuse it work.
        assert!(pick(&[shell], &ledger, now, Tier::Build, &[]).is_some());
    }

    #[tokio::test]
    async fn a_cli_that_wraps_an_api_is_proven_by_its_own_tiny_prompt_and_not_by_the_endpoint() {
        let now = Utc::now();
        let shim = a_cli_engine("shim", Some("fake://ok:fine"));
        let found = probe_within(&shim, None, Duration::from_millis(20)).await;
        assert_eq!(
            found.proof,
            Proof::Reachable,
            "the endpoint answering says nothing about the shim in front of it"
        );
        let mut ledger = Ledger::default();
        apply_probe(&mut ledger, "shim", &found, now);
        assert!(matches!(
            availability(&shim, &ledger.state("shim"), now),
            Availability::Unproven(_)
        ));
        assert!(cli_probe_due(&shim, &ledger.state("shim"), now));

        // Its tiny prompt came back.
        let state = ledger.engines.get_mut("shim").unwrap();
        state.cli_probe = Some(CliProbe {
            at: now,
            ok: true,
            ms: Some(900),
            reason: None,
        });
        state.latency_ms = Some(900);
        assert_eq!(
            availability(&shim, &ledger.state("shim"), now),
            Availability::Up
        );
        let report = &reports(std::slice::from_ref(&shim), &ledger, now)[0];
        assert_eq!(report.state_label(), "up, answered in 0.9 s");
        // Cached and rationed: not again inside 15 minutes, again after.
        let state = ledger.state("shim");
        assert!(!cli_probe_due(
            &shim,
            &state,
            now + chrono::Duration::minutes(14)
        ));
        assert!(cli_probe_due(
            &shim,
            &state,
            now + chrono::Duration::minutes(16)
        ));
        // And at once after a run failed on it.
        let mut failed = state.clone();
        failed.last_failure_at = Some(now + chrono::Duration::minutes(1));
        assert!(cli_probe_due(
            &shim,
            &failed,
            now + chrono::Duration::minutes(2)
        ));
        assert_eq!(
            proof_of(&shim, &failed),
            Proof::Reachable,
            "a failure withdraws the proof"
        );
        // A tiny prompt that got nothing is down, whatever the endpoint says.
        let mut dead = state;
        dead.cli_probe = Some(CliProbe {
            at: now,
            ok: false,
            ms: None,
            reason: Some("no answer to a tiny prompt before its deadline".into()),
        });
        assert!(matches!(
            availability(&shim, &dead, now),
            Availability::Down(_)
        ));
    }

    #[test]
    fn failed_runs_climb_the_cooloff_ladder_alert_once_per_cooloff_and_a_good_run_resets_it() {
        let agent = "ladder-agent";
        let spec = answering("e", "ok:fine");
        let t0 = Utc::now();
        let minutes = chrono::Duration::minutes;

        let first = record_run_failure(agent, "e", (Some("m"), "o1"), "timed out", 2, t0);
        assert_eq!(first.streak, 1);
        assert_eq!(first.cooloff_until, t0 + minutes(15));
        assert!(!first.alert, "one failed run is a bad run, not an engine");
        let state = Ledger::load(agent).state("e");
        assert!(matches!(
            availability(&spec, &state, t0 + minutes(1)),
            Availability::CoolingOff { .. }
        ));
        assert!(!availability(&spec, &state, t0 + minutes(1)).usable());
        assert_eq!(state.failed_model.as_deref(), Some("m"));

        // A second order failing together with the first does not climb the ladder.
        let together = record_run_failure(
            agent,
            "e",
            (Some("m"), "o2"),
            "timed out",
            2,
            t0 + minutes(1),
        );
        assert_eq!(together.streak, 1);
        assert!(!together.alert);
        assert_eq!(together.orders, ["o1", "o2"]);

        let t1 = t0 + minutes(16);
        let second = record_run_failure(agent, "e", (Some("m"), "o3"), "timed out", 2, t1);
        assert_eq!(second.streak, 2);
        assert_eq!(second.cooloff_until, t1 + minutes(60));
        assert!(second.alert, "two in a row tell the owner");
        let again = record_run_failure(
            agent,
            "e",
            (Some("m"), "o4"),
            "timed out",
            2,
            t1 + minutes(1),
        );
        assert!(!again.alert, "once for this cool-off");

        let t2 = t1 + minutes(61);
        let third = record_run_failure(agent, "e", (Some("m"), "o5"), "timed out", 2, t2);
        assert_eq!(third.streak, 3);
        assert_eq!(third.cooloff_until, t2 + minutes(240));
        let t3 = t2 + minutes(241);
        let fourth = record_run_failure(agent, "e", (Some("m"), "o6"), "timed out", 2, t3);
        assert_eq!(
            fourth.cooloff_until,
            t3 + minutes(240),
            "four hours is the most"
        );

        record_run_success(agent, "e", t3 + minutes(1));
        let state = Ledger::load(agent).state("e");
        assert_eq!(state.fail_streak, 0);
        assert!(state.cooloff_until.is_none() && state.failed_orders.is_empty());
        assert!(availability(&spec, &state, t3 + minutes(2)).usable());
    }

    #[test]
    fn when_the_cooloff_ends_the_engine_is_probed_again_before_it_is_trusted() {
        let agent = "expiry-agent";
        let spec = answering("e", "ok:fine");
        let t0 = Utc::now();
        let minutes = chrono::Duration::minutes;
        let mut ledger = Ledger::default();
        // It answered a probe a minute ago, then a run on it hung.
        apply_probe(
            &mut ledger,
            "e",
            &Probe {
                latency_ms: Some(300),
                proof: Proof::Answered,
                ..Probe::default()
            },
            t0 - minutes(1),
        );
        ledger.save(agent).unwrap();
        record_run_failure(agent, "e", (Some("m"), "o1"), "timed out", 2, t0);
        let state = Ledger::load(agent).state("e");

        assert!(
            !endpoint_probe_due(&state, t0 + minutes(5)),
            "nothing is spent on an engine that is being left alone"
        );
        let back = t0 + minutes(16);
        assert!(
            endpoint_probe_due(&state, back),
            "the cool-off is over, so it is probed at once"
        );
        // The owner saying "retry now" lifts the cool-off early: due at once too, because
        // the failure is newer than the last probe.
        clear_cooloff(agent, "e");
        let mut recent = Ledger::load(agent).state("e");
        assert!(recent.cooloff_until.is_none());
        recent.checked_at = Some(t0 - minutes(1));
        assert!(endpoint_probe_due(&recent, t0 + minutes(2)));
        // Until a probe sees it answer, it is not up.
        assert!(matches!(
            availability(&spec, &state, back),
            Availability::Unproven(why) if why.contains("a run failed")
        ));
        let mut ledger = Ledger::load(agent);
        apply_probe(
            &mut ledger,
            "e",
            &Probe {
                latency_ms: Some(300),
                proof: Proof::Answered,
                ..Probe::default()
            },
            back,
        );
        assert_eq!(
            availability(&spec, &ledger.state("e"), back),
            Availability::Up
        );
        assert!(!endpoint_probe_due(&ledger.state("e"), back + minutes(1)));
    }
}
