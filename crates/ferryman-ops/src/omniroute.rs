//! OmniRoute: a free, self-hosted AI gateway, as a first-class engine.
//!
//! OmniRoute (github.com/diegosouzapw/OmniRoute, MIT) puts one OpenAI-compatible
//! endpoint - `http://localhost:20128/v1` by default - in front of hundreds of providers,
//! many of them free, with quota-aware fallback and "combos": named routes over several
//! models. To Ferryman it is an `http` engine whose `model` is an OmniRoute model or
//! combo, so it needs nothing new to run. What it needs is to be *seen through*:
//!
//! - **How each route is paid for.** A model OmniRoute reaches through a person's plan -
//!   Claude Code or Codex signed in with OAuth, Cursor, Copilot - spends that plan's
//!   limits exactly as the CLI would, so it is `subscription`, and `protect_subscriptions`
//!   and `never claude` block it even through the gateway. A `:free` model is
//!   `free-tier`. A combo is what its steps are: any subscription step makes it a
//!   subscription, all free steps make it free.
//! - **What it offers.** The probe lists `/v1/models` (combos are listed first, owned by
//!   `combo`) and, when the key may read it, `/api/combos` for each combo's steps. Its
//!   combos and free models are published as engines of their own - `omniroute.auto`,
//!   `omniroute.free-stack` - so the dashboard, Telegram and the policy can pick one.
//!
//! Nothing here runs OmniRoute or changes its configuration.

use std::time::Duration;

use serde::{Deserialize, Serialize};
use serde_json::Value;

use crate::engines::{EngineSpec, Kind, Paid};

/// Where OmniRoute listens when nobody said otherwise.
pub const DEFAULT_URL: &str = "http://localhost:20128/v1";
/// How many of its combos, and of its free models, are offered as engines of their own.
const OFFER_EACH: usize = 8;
/// How deep combo references are followed.
const DEPTH: usize = 4;

/// OmniRoute providers that sign in with a person's plan rather than an API key: routing
/// through them spends that plan. Matched against a model's provider prefix or owner.
pub const SUBSCRIPTION_PROVIDERS: &[&str] = &[
    "cc",
    "claude",
    "claude-code",
    "anthropic-oauth",
    "codex",
    "cx",
    "openai-codex",
    "chatgpt",
    "cursor",
    "copilot",
    "gh",
    "github-copilot",
];

/// What the probe learned about an OmniRoute instance.
#[derive(Debug, Clone, Default, PartialEq, Serialize, Deserialize)]
pub struct Catalog {
    #[serde(default)]
    pub models: Vec<Model>,
    #[serde(default)]
    pub combos: Vec<Combo>,
    /// Whether `/api/combos` could be read, so a combo's steps are known.
    #[serde(default)]
    pub combos_known: bool,
}

#[derive(Debug, Clone, Default, PartialEq, Serialize, Deserialize)]
pub struct Model {
    pub id: String,
    #[serde(default)]
    pub owned_by: String,
}

#[derive(Debug, Clone, Default, PartialEq, Serialize, Deserialize)]
pub struct Combo {
    pub name: String,
    /// `provider/model`, `provider/*` for a wildcard, or `combo:<name>` for a reference.
    #[serde(default)]
    pub steps: Vec<String>,
}

/// Whether an engine is an OmniRoute endpoint: `provider = "omniroute"`, or a base URL on
/// OmniRoute's port or naming it.
#[must_use]
pub fn is_omniroute(spec: &EngineSpec) -> bool {
    spec.provider
        .as_deref()
        .is_some_and(|provider| provider.eq_ignore_ascii_case("omniroute"))
        || spec.base_url.as_deref().is_some_and(|url| {
            let url = url.to_ascii_lowercase();
            url.contains(":20128") || url.contains("omniroute")
        })
}

/// The models `/v1/models` lists: `data[].id` and `owned_by`.
#[must_use]
pub fn parse_models(body: &str) -> Vec<Model> {
    let Ok(value) = serde_json::from_str::<Value>(body) else {
        return Vec::new();
    };
    value["data"]
        .as_array()
        .into_iter()
        .flatten()
        .filter_map(|model| {
            Some(Model {
                id: model.get("id")?.as_str()?.to_string(),
                owned_by: model["owned_by"].as_str().unwrap_or_default().to_string(),
            })
        })
        .collect()
}

/// The combos `/api/combos` lists, each with its steps.
#[must_use]
pub fn parse_combos(body: &str) -> Option<Vec<Combo>> {
    let value = serde_json::from_str::<Value>(body).ok()?;
    let combos = value.get("combos")?.as_array()?;
    Some(
        combos
            .iter()
            .filter(|combo| combo["isActive"].as_bool() != Some(false))
            .filter_map(|combo| {
                let name = combo.get("name")?.as_str()?.to_string();
                let steps = combo["models"]
                    .as_array()
                    .into_iter()
                    .flatten()
                    .filter_map(step)
                    .collect();
                Some(Combo { name, steps })
            })
            .collect(),
    )
}

fn step(value: &Value) -> Option<String> {
    if let Some(text) = value.as_str() {
        return Some(text.to_string());
    }
    let text = |key: &str| value.get(key).and_then(Value::as_str).map(str::trim);
    match text("kind") {
        Some("combo-ref") => text("comboName").map(|name| format!("combo:{name}")),
        Some("provider-wildcard") => Some(format!(
            "{}/{}",
            text("providerId")?,
            text("modelPattern").unwrap_or("*")
        )),
        _ => {
            let model = text("model")?;
            match text("providerId").or_else(|| text("provider")) {
                Some(provider) if !model.contains('/') => Some(format!("{provider}/{model}")),
                _ => Some(model.to_string()),
            }
        }
    }
}

fn is_subscription_provider(provider: &str) -> bool {
    SUBSCRIPTION_PROVIDERS
        .iter()
        .any(|known| known.eq_ignore_ascii_case(provider.trim()))
}

/// How one model, reached through OmniRoute, is paid for.
#[must_use]
pub fn classify_model(id: &str, owned_by: &str) -> &'static str {
    let provider = if owned_by.is_empty() || owned_by == "combo" {
        id.split('/').next().unwrap_or_default()
    } else {
        owned_by
    };
    if is_subscription_provider(provider)
        || id.split('/').next().is_some_and(is_subscription_provider)
    {
        "subscription"
    } else if id.ends_with(":free") {
        "free-tier"
    } else {
        "unknown"
    }
}

/// How a model or combo is paid for, and what its route ends at.
///
/// A combo whose steps are known is what its steps are. One whose steps cannot be read
/// is taken for a subscription when this OmniRoute has any subscription provider
/// connected - it may route there - and otherwise for unknown, or free when its name
/// says so.
#[must_use]
pub fn resolve(id: &str, catalog: &Catalog) -> (&'static str, Vec<String>) {
    resolve_at(id, catalog, 0)
}

fn resolve_at(id: &str, catalog: &Catalog, depth: usize) -> (&'static str, Vec<String>) {
    if let Some(combo) = catalog
        .combos
        .iter()
        .find(|combo| combo.name.eq_ignore_ascii_case(id))
    {
        let mut route = Vec::new();
        let mut classes = Vec::new();
        for step in &combo.steps {
            let (class, steps) = match step.strip_prefix("combo:") {
                Some(inner) if depth < DEPTH => resolve_at(inner, catalog, depth + 1),
                Some(_) => ("unknown", vec![step.clone()]),
                None => (classify_model(step, ""), vec![step.clone()]),
            };
            classes.push(class);
            route.extend(steps);
        }
        return (combine(&classes), route);
    }
    let owned_by = catalog
        .models
        .iter()
        .find(|model| model.id.eq_ignore_ascii_case(id))
        .map(|model| model.owned_by.as_str())
        .unwrap_or_default();
    if owned_by == "combo" || id.starts_with("auto") {
        let may_reach_a_plan = catalog.models.iter().any(|model| {
            model.owned_by != "combo"
                && classify_model(&model.id, &model.owned_by) == "subscription"
        });
        let class = if may_reach_a_plan {
            "subscription"
        } else if id.to_ascii_lowercase().contains("free") {
            "free-tier"
        } else {
            "unknown"
        };
        return (class, vec![format!("{id} (combo; steps not readable)")]);
    }
    (classify_model(id, owned_by), vec![id.to_string()])
}

fn combine(classes: &[&'static str]) -> &'static str {
    if classes.contains(&"subscription") {
        "subscription"
    } else if !classes.is_empty() && classes.iter().all(|class| *class == "free-tier") {
        "free-tier"
    } else {
        "unknown"
    }
}

/// How an OmniRoute engine counts: what its route says, unless the operator set `paid`
/// and the route is not a subscription - a subscription behind the gateway is one
/// whatever the config says, so it can never be spent in the background by mistake.
#[must_use]
pub fn effective_paid(configured: Paid, derived: &str) -> Paid {
    match (derived, configured) {
        ("subscription", _) => Paid::Subscription,
        (_, Paid::Unknown) => Paid::parse(derived).unwrap_or(Paid::Unknown),
        (_, configured) => configured,
    }
}

fn slug(id: &str) -> String {
    id.chars()
        .map(|c| {
            if c.is_ascii_alphanumeric() || matches!(c, '-' | '_' | '.') {
                c.to_ascii_lowercase()
            } else {
                '_'
            }
        })
        .collect()
}

/// An OmniRoute engine as the policy should see it - its configured model's paid class
/// and route - followed by one engine per combo and free model it offers. Anything else
/// comes back as it is.
#[must_use]
pub fn expand(spec: &EngineSpec, catalog: Option<&Catalog>) -> Vec<EngineSpec> {
    let Some(catalog) = catalog.filter(|_| is_omniroute(spec)) else {
        return vec![spec.clone()];
    };
    let mut base = spec.clone();
    if let Some(model) = &spec.model {
        let (paid, route) = resolve(model, catalog);
        base.paid = effective_paid(spec.paid, paid);
        base.route = route;
    }
    let mut out = vec![base];
    // A CLI runs whatever its own flags say; only an endpoint engine can be pointed at
    // another model by Ferryman.
    if spec.kind != Kind::Http {
        return out;
    }
    let combos: Vec<String> = catalog
        .models
        .iter()
        .filter(|model| model.owned_by == "combo")
        .map(|model| model.id.clone())
        .chain(catalog.combos.iter().map(|combo| combo.name.clone()))
        .fold(Vec::new(), |mut seen, id| {
            if !seen
                .iter()
                .any(|known: &String| known.eq_ignore_ascii_case(&id))
            {
                seen.push(id);
            }
            seen
        });
    let free: Vec<String> = catalog
        .models
        .iter()
        .filter(|model| model.owned_by != "combo" && model.id.ends_with(":free"))
        .map(|model| model.id.clone())
        .collect();
    for id in combos
        .into_iter()
        .take(OFFER_EACH)
        .chain(free.into_iter().take(OFFER_EACH))
    {
        if spec
            .model
            .as_deref()
            .is_some_and(|model| model.eq_ignore_ascii_case(&id))
        {
            continue;
        }
        let (paid, route) = resolve(&id, catalog);
        let mut offer = spec.clone();
        offer.name = format!("{}.{}", spec.name, slug(&id));
        offer.model = Some(id);
        offer.paid = Paid::parse(paid).unwrap_or(Paid::Unknown);
        offer.route = route;
        // Caps and probes belong to the configured engine; an offer is counted on its own.
        offer.weekly_requests = None;
        offer.weekly_usd = None;
        out.push(offer);
    }
    out
}

/// The address of OmniRoute's management API beside its `/v1` endpoint.
#[must_use]
pub fn api_root(base_url: &str) -> String {
    let base = base_url.trim_end_matches('/');
    base.strip_suffix("/v1").unwrap_or(base).to_string()
}

/// Whether OmniRoute answers on this machine, and what it offers. Two seconds at most;
/// no key, so only what it lists to anyone.
pub async fn detect() -> Option<Catalog> {
    let client = reqwest::Client::builder()
        .timeout(Duration::from_secs(2))
        .connect_timeout(Duration::from_secs(1))
        .build()
        .ok()?;
    let response = client
        .get(format!("{DEFAULT_URL}/models"))
        .send()
        .await
        .ok()?;
    if !response.status().is_success() {
        return None;
    }
    let models = parse_models(&response.text().await.ok()?);
    (!models.is_empty()).then_some(Catalog {
        models,
        combos: Vec::new(),
        combos_known: false,
    })
}

/// Whether anything listens on OmniRoute's default port here. Cheap enough for setup.
#[must_use]
pub fn listening() -> bool {
    std::net::TcpStream::connect_timeout(
        &std::net::SocketAddr::from(([127, 0, 0, 1], 20128)),
        Duration::from_millis(300),
    )
    .is_ok()
}

/// The agent.toml lines that add a local OmniRoute, running `model`.
#[must_use]
pub fn config_snippet(model: &str) -> String {
    format!(
        "engines = [\"omniroute\"]   # add to your existing list\n\
         engine.omniroute.provider = \"omniroute\"\n\
         engine.omniroute.kind = \"http\"\n\
         engine.omniroute.base_url = \"{DEFAULT_URL}\"\n\
         engine.omniroute.model = \"{model}\"\n\
         engine.omniroute.key = \"secret:OMNIROUTE_API_KEY\"\n\
         engine.omniroute.tier = \"build\""
    )
}

/// What to say about a local OmniRoute that no engine uses yet.
#[must_use]
pub fn suggestion(catalog: &Catalog) -> String {
    let combos: Vec<&str> = catalog
        .models
        .iter()
        .filter(|model| model.owned_by == "combo")
        .map(|model| model.id.as_str())
        .take(6)
        .collect();
    let free = catalog
        .models
        .iter()
        .filter(|model| model.id.ends_with(":free"))
        .count();
    let pick = catalog
        .models
        .iter()
        .find(|model| model.owned_by == "combo" && resolve(&model.id, catalog).0 == "free-tier")
        .or_else(|| {
            catalog
                .models
                .iter()
                .find(|model| model.id.ends_with(":free"))
        })
        .map_or("auto", |model| model.id.as_str());
    format!(
        "OmniRoute answers at {DEFAULT_URL}: {} models, {free} of them free{}. It is a free \
         gateway to many providers; add it as an engine and a free combo becomes a strong \
         improvement engine:\n\n{}",
        catalog.models.len(),
        if combos.is_empty() {
            String::new()
        } else {
            format!(", combos {}", combos.join(", "))
        },
        config_snippet(pick)
    )
}

#[cfg(test)]
mod tests {
    use super::*;

    fn spec(model: &str) -> EngineSpec {
        let mut spec = EngineSpec::implicit("c", &[], None);
        spec.name = "omniroute".into();
        spec.kind = Kind::Http;
        spec.base_url = Some(DEFAULT_URL.into());
        spec.model = Some(model.into());
        spec
    }

    fn catalog() -> Catalog {
        let models = parse_models(
            r#"{"object":"list","data":[
                {"id":"free-stack","owned_by":"combo"},
                {"id":"claude-first","owned_by":"combo"},
                {"id":"cc/claude-sonnet-4-6","owned_by":"cc"},
                {"id":"nvidia/nemotron-70b:free","owned_by":"nvidia"},
                {"id":"openrouter/deepseek/deepseek-chat:free","owned_by":"openrouter"},
                {"id":"deepseek/deepseek-chat","owned_by":"deepseek"}
            ]}"#,
        );
        let combos = parse_combos(
            r#"{"total":2,"combos":[
                {"name":"free-stack","isActive":true,"models":[
                    {"kind":"model","model":"nvidia/nemotron-70b:free"},
                    {"kind":"model","model":"deepseek/deepseek-chat:free","providerId":"openrouter"}]},
                {"name":"claude-first","models":[
                    {"kind":"model","model":"claude-sonnet-4-6","providerId":"cc"},
                    {"kind":"combo-ref","comboName":"free-stack"}]}
            ]}"#,
        )
        .unwrap();
        Catalog {
            models,
            combos,
            combos_known: true,
        }
    }

    #[test]
    fn a_route_is_paid_for_the_way_its_steps_are() {
        let catalog = catalog();
        assert_eq!(resolve("free-stack", &catalog).0, "free-tier");
        let (paid, route) = resolve("claude-first", &catalog);
        assert_eq!(paid, "subscription", "one Claude Code step makes it a plan");
        assert!(
            route.contains(&"cc/claude-sonnet-4-6".to_string()),
            "{route:?}"
        );
        assert!(
            route.contains(&"nvidia/nemotron-70b:free".to_string()),
            "{route:?}"
        );
        assert_eq!(resolve("cc/claude-sonnet-4-6", &catalog).0, "subscription");
        assert_eq!(resolve("nvidia/nemotron-70b:free", &catalog).0, "free-tier");
        assert_eq!(resolve("deepseek/deepseek-chat", &catalog).0, "unknown");
        // A combo nobody can read the steps of, on an instance with Claude Code in it,
        // may route there: it counts as a subscription.
        let unreadable = Catalog {
            combos: Vec::new(),
            combos_known: false,
            ..catalog.clone()
        };
        assert_eq!(resolve("free-stack", &unreadable).0, "subscription");
        let no_plans = Catalog {
            models: parse_models(r#"{"data":[{"id":"auto","owned_by":"combo"}]}"#),
            ..Catalog::default()
        };
        assert_eq!(resolve("auto", &no_plans).0, "unknown");
    }

    #[test]
    fn an_omniroute_engine_offers_its_combos_and_free_models_as_engines() {
        let engines = expand(&spec("claude-first"), Some(&catalog()));
        let names: Vec<&str> = engines.iter().map(|e| e.name.as_str()).collect();
        assert_eq!(names[0], "omniroute");
        assert_eq!(engines[0].paid, Paid::Subscription, "its own route decides");
        assert!(names.contains(&"omniroute.free-stack"), "{names:?}");
        assert!(
            names.contains(&"omniroute.nvidia_nemotron-70b_free"),
            "{names:?}"
        );
        let free = engines
            .iter()
            .find(|e| e.name == "omniroute.free-stack")
            .unwrap();
        assert_eq!(free.paid, Paid::FreeTier);
        assert_eq!(free.model.as_deref(), Some("free-stack"));
        // Configured paid is kept - unless the route is a subscription.
        let mut said_free = spec("claude-first");
        said_free.paid = Paid::FreeTier;
        assert_eq!(
            expand(&said_free, Some(&catalog()))[0].paid,
            Paid::Subscription
        );
        // Not OmniRoute: untouched.
        let mut other = spec("m");
        other.base_url = Some("https://api.deepseek.com".into());
        assert_eq!(expand(&other, Some(&catalog())), vec![other.clone()]);
        assert!(is_omniroute(&spec("m")));
    }

    #[test]
    fn the_suggestion_names_a_free_combo_and_the_config_to_add() {
        let text = suggestion(&catalog());
        assert!(
            text.contains("engine.omniroute.model = \"nvidia/nemotron-70b:free\"")
                || text.contains("free-stack"),
            "{text}"
        );
        assert!(text.contains("localhost:20128"));
        assert_eq!(
            api_root("http://localhost:20128/v1/"),
            "http://localhost:20128"
        );
    }
}
