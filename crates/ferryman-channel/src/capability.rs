//! What an engine can do: its capability profile.
//!
//! The smart router (see `docs/ENGINE_SETUP.md`) sends each piece of work to the cheapest
//! engine that will most likely do it well. To do that it has to know what an engine can
//! do at all - read an image, transcribe audio, edit files in a worktree - what it is good
//! at, how much it can read at once, and what it costs. That is a [`Capabilities`].
//!
//! # Declared beats guessed
//!
//! The operator can say any of it in `agent.toml` (`engine.<name>.modalities`, `strengths`,
//! `context_k`, `cost_per_*_usd`, `local`); that is a [`Declared`], and a declared field
//! always wins over a guess, whole: declaring `modalities` replaces the guessed list, it
//! does not add to it. Everything left undeclared is guessed by [`resolve`] from the
//! engine's name, model, command, kind, endpoint and how it is paid for - sensibly, and
//! with every rule unit-tested here. A guess is never published as the operator's word,
//! but the profile that results is published (v2-only, signed) in the engine inventory, so
//! every machine ranks the fleet from the same facts.
//!
//! # What the pieces mean
//!
//! - [`Modality`]: `text`, `code` (edits files in a worktree, so only a `cli` engine can
//!   have it: a declared `code` on an `http` engine is dropped), `vision` (reads images),
//!   `image`, `video` (generate or edit), `audio_in` (speech to text), `audio_out` (text to
//!   speech) and `embed`.
//! - [`Cost`]: `None` means "no price known and the engine is billed per use" - a prepaid
//!   engine nobody priced. It is not zero, and a ranking must not treat it as free. Local,
//!   free-tier and subscription engines are `Some(Cost::FREE)`: a subscription is zero
//!   marginal cost and its scarcity is the weekly cap's job, not a price's.
//! - `context_k` is in thousands of tokens. Only an explicit `128k`-style token in the
//!   name is guessed, because a wrong guess would exclude an engine from work it could do;
//!   unknown stays `None` and a caller must not filter on it.

use std::{collections::BTreeSet, fmt, net::IpAddr};

use anyhow::{Result, bail};
use serde::{Deserialize, Deserializer, Serialize, Serializer};

/// One thing an engine can take in or produce. Serialized as its lowercase wire name;
/// a name this version does not know is kept as [`Modality::Other`] so a newer peer's
/// inventory still round-trips (and verifies) here.
#[derive(Debug, Clone, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub enum Modality {
    Text,
    /// Edits files in a worktree. Only a `cli` engine.
    Code,
    /// Reads images.
    Vision,
    /// Generates images.
    Image,
    /// Generates or edits video.
    Video,
    /// Speech to text.
    AudioIn,
    /// Text to speech.
    AudioOut,
    Embed,
    /// A modality a newer version added.
    Other(String),
}

impl Modality {
    /// Every modality this version knows, in wire order.
    pub const KNOWN: [Modality; 8] = [
        Modality::Text,
        Modality::Code,
        Modality::Vision,
        Modality::Image,
        Modality::Video,
        Modality::AudioIn,
        Modality::AudioOut,
        Modality::Embed,
    ];

    /// The wire name: `text`, `code`, `vision`, `image`, `video`, `audio_in`, `audio_out`,
    /// `embed`.
    #[must_use]
    pub fn as_str(&self) -> &str {
        match self {
            Self::Text => "text",
            Self::Code => "code",
            Self::Vision => "vision",
            Self::Image => "image",
            Self::Video => "video",
            Self::AudioIn => "audio_in",
            Self::AudioOut => "audio_out",
            Self::Embed => "embed",
            Self::Other(name) => name,
        }
    }

    /// Read a name a person typed: case and `-`/`_` do not matter; anything this version
    /// does not know is refused, so a typo in `agent.toml` fails loudly.
    pub fn parse(value: &str) -> Result<Self> {
        let normal = value.trim().to_ascii_lowercase().replace('-', "_");
        Self::KNOWN
            .iter()
            .find(|known| known.as_str() == normal)
            .cloned()
            .ok_or_else(|| {
                anyhow::anyhow!(
                    "a modality is text, code, vision, image, video, audio_in, audio_out or \
                     embed, not '{}'",
                    value.trim()
                )
            })
    }

    /// Read a name off the wire: unknown names are kept, not refused.
    #[must_use]
    pub fn from_wire(value: &str) -> Self {
        Self::KNOWN
            .iter()
            .find(|known| known.as_str() == value)
            .cloned()
            .unwrap_or_else(|| Self::Other(value.to_string()))
    }

    /// A list as `agent.toml` writes it: a JSON array (`["text","vision"]`) or names
    /// separated by commas or spaces. Sorted, without repeats.
    pub fn parse_list(value: &str) -> Result<Vec<Self>> {
        let names: Vec<String> = if value.trim_start().starts_with('[') {
            serde_json::from_str(value)
                .map_err(|e| anyhow::anyhow!("not a JSON array of names: {e}"))?
        } else {
            value
                .split([',', ' '])
                .map(str::trim)
                .filter(|name| !name.is_empty())
                .map(str::to_string)
                .collect()
        };
        let mut out = BTreeSet::new();
        for name in names {
            out.insert(Self::parse(&name)?);
        }
        Ok(out.into_iter().collect())
    }

    /// Produces or consumes something other than text chat: image, video, audio, embeddings.
    #[must_use]
    pub fn is_media(&self) -> bool {
        matches!(
            self,
            Self::Image | Self::Video | Self::AudioIn | Self::AudioOut | Self::Embed
        )
    }
}

impl fmt::Display for Modality {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(self.as_str())
    }
}

impl Serialize for Modality {
    fn serialize<S: Serializer>(&self, serializer: S) -> std::result::Result<S::Ok, S::Error> {
        serializer.serialize_str(self.as_str())
    }
}

impl<'de> Deserialize<'de> for Modality {
    fn deserialize<D: Deserializer<'de>>(deserializer: D) -> std::result::Result<Self, D::Error> {
        let name = String::deserialize(deserializer)?;
        Ok(Self::from_wire(&name))
    }
}

/// What an engine costs. Dollars; per million tokens for the token prices.
#[derive(Debug, Clone, Copy, Default, PartialEq, Serialize, Deserialize)]
pub struct Cost {
    #[serde(default)]
    pub per_call_usd: f64,
    #[serde(default)]
    pub per_mtok_in_usd: f64,
    #[serde(default)]
    pub per_mtok_out_usd: f64,
}

impl Cost {
    /// Zero marginal cost: local, free tier, and a subscription's per-call price.
    pub const FREE: Cost = Cost {
        per_call_usd: 0.0,
        per_mtok_in_usd: 0.0,
        per_mtok_out_usd: 0.0,
    };

    #[must_use]
    pub fn is_free(&self) -> bool {
        self.per_call_usd == 0.0 && self.per_mtok_in_usd == 0.0 && self.per_mtok_out_usd == 0.0
    }

    /// Dollars for one call that reads `tokens_in` and writes `tokens_out`.
    #[must_use]
    pub fn estimate(&self, tokens_in: u64, tokens_out: u64) -> f64 {
        self.per_call_usd
            + self.per_mtok_in_usd * tokens_in as f64 / 1_000_000.0
            + self.per_mtok_out_usd * tokens_out as f64 / 1_000_000.0
    }
}

/// One engine's capability profile, resolved: what is published in the signed engine
/// inventory (v2-only, so a v0.5.17 peer still verifies the rest) and what the router
/// reads. Build it with [`resolve`]; read an inventory line's with
/// [`Capabilities::for_report`].
#[derive(Debug, Clone, Default, PartialEq, Serialize, Deserialize)]
pub struct Capabilities {
    /// Sorted, without repeats.
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub modalities: Vec<Modality>,
    /// Free tags: `code`, `reasoning`, `docs`, `tests`, `review`, `translation`,
    /// `long-context`, `math`. Lowercase, sorted, without repeats.
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub strengths: Vec<String>,
    /// The context window in thousands of tokens, when known.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub context_k: Option<u32>,
    /// `None`: no price known, billed per use. See the module notes.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub cost: Option<Cost>,
    /// Runs on this machine or a private network: nothing leaves it.
    #[serde(default)]
    pub local: bool,
}

impl Capabilities {
    #[must_use]
    pub fn has(&self, modality: &Modality) -> bool {
        self.modalities.contains(modality)
    }

    /// Every one of `needed` (vacuously true for none).
    #[must_use]
    pub fn has_all(&self, needed: &[Modality]) -> bool {
        needed.iter().all(|m| self.has(m))
    }

    #[must_use]
    pub fn has_strength(&self, tag: &str) -> bool {
        self.strengths.iter().any(|s| s.eq_ignore_ascii_case(tag))
    }

    /// `text+code+vision`, or `-` when there are none.
    #[must_use]
    pub fn modalities_label(&self) -> String {
        if self.modalities.is_empty() {
            "-".to_string()
        } else {
            self.modalities
                .iter()
                .map(Modality::as_str)
                .collect::<Vec<_>>()
                .join("+")
        }
    }

    /// One line for a person: `text+code, strengths code, 128k context, free, local`.
    #[must_use]
    pub fn describe(&self) -> String {
        let mut parts = vec![self.modalities_label()];
        if !self.strengths.is_empty() {
            parts.push(format!("strengths {}", self.strengths.join(",")));
        }
        if let Some(k) = self.context_k {
            parts.push(format!("{k}k context"));
        }
        match &self.cost {
            Some(cost) if cost.is_free() => parts.push("free".to_string()),
            Some(cost) => parts.push(format!(
                "${} per call, ${}/${} per Mtok in/out",
                cost.per_call_usd, cost.per_mtok_in_usd, cost.per_mtok_out_usd
            )),
            None => parts.push("price unknown".to_string()),
        }
        if self.local {
            parts.push("local".to_string());
        }
        parts.join(", ")
    }

    /// The profile of an inventory line: what its worker published, else - for a worker
    /// older than capability profiles - the guess [`resolve`] makes from what the line
    /// does say. The `bool` is whether it was guessed here.
    #[must_use]
    pub fn for_report(report: &crate::receipts::EngineReport) -> (Self, bool) {
        if let Some(published) = &report.capabilities {
            return (published.clone(), false);
        }
        let host = report
            .billing
            .as_ref()
            .and_then(|billing| billing.host.as_deref());
        let basis = Basis {
            name: &report.name,
            model: report.model.as_deref(),
            command: "",
            cli: report.kind == "cli",
            // Only the host is published; a host is all the local check needs.
            base_url: host,
            paid: &report.paid,
            gateway: !report.billing.as_ref().is_none_or(|b| b.route.is_empty()),
        };
        (resolve(&Declared::default(), &basis), true)
    }
}

/// What an operator declared for one engine. Every field is optional; `None` or empty
/// means "guess it".
#[derive(Debug, Clone, Default, PartialEq)]
pub struct Declared {
    pub modalities: Vec<Modality>,
    pub strengths: Vec<String>,
    pub context_k: Option<u32>,
    pub cost: Option<Cost>,
    pub local: Option<bool>,
}

impl Declared {
    #[must_use]
    pub fn is_empty(&self) -> bool {
        *self == Self::default()
    }
}

/// What the guesses are made from: the engine as `agent.toml` describes it.
#[derive(Debug, Clone, Copy)]
pub struct Basis<'a> {
    pub name: &'a str,
    pub model: Option<&'a str>,
    /// The CLI's command; empty for an HTTP engine.
    pub command: &'a str,
    /// A `cli` engine (as opposed to `http`).
    pub cli: bool,
    /// The endpoint, or just its host.
    pub base_url: Option<&'a str>,
    /// `subscription`, `prepaid`, `free-tier`, `local` or `unknown`.
    pub paid: &'a str,
    /// A gateway or proxy (OmniRoute, LiteLLM, a provider route): what is behind the
    /// endpoint is somebody else's model, so the endpoint being on this network says
    /// nothing about where it runs or what it costs.
    pub gateway: bool,
}

/// The profile of an engine: declared fields win, the rest is guessed.
#[must_use]
pub fn resolve(declared: &Declared, basis: &Basis) -> Capabilities {
    let names = Names::new(basis);
    let mut modalities: BTreeSet<Modality> = if declared.modalities.is_empty() {
        guess_modalities(basis)
    } else {
        declared.modalities.iter().cloned().collect()
    };
    // Editing files in a worktree needs a process on the machine: an endpoint cannot.
    if !basis.cli {
        modalities.remove(&Modality::Code);
    }
    let context_k = declared.context_k.or_else(|| guess_context_k(&names));
    let mut strengths: BTreeSet<String> = if declared.strengths.is_empty() {
        guess_strengths(&names, context_k)
    } else {
        declared
            .strengths
            .iter()
            .map(|s| s.trim().to_ascii_lowercase())
            .filter(|s| !s.is_empty())
            .collect()
    };
    if declared.strengths.is_empty() && context_k.is_some_and(|k| k >= LONG_CONTEXT_K) {
        strengths.insert("long-context".to_string());
    }
    let local = declared
        .local
        .unwrap_or_else(|| guess_local(basis, &modalities));
    let cost = declared.cost.or_else(|| guess_cost(basis.paid, local));
    Capabilities {
        modalities: modalities.into_iter().collect(),
        strengths: strengths.into_iter().collect(),
        context_k,
        cost,
        local,
    }
}

/// A context window of this many thousand tokens counts as `long-context`.
pub const LONG_CONTEXT_K: u32 = 200;

/// The lowercased things an engine is called, as tokens and as one string with `_` and
/// spaces turned into `-`, so `stable_diffusion` and `stable-diffusion` both match.
struct Names {
    joined: String,
    tokens: Vec<String>,
}

impl Names {
    fn new(basis: &Basis) -> Self {
        let command = basis
            .command
            .rsplit(['/', '\\'])
            .next()
            .unwrap_or(basis.command);
        let all = [Some(basis.name), basis.model, Some(command)];
        let joined = all
            .iter()
            .flatten()
            .map(|part| part.to_ascii_lowercase().replace(['_', ' '], "-"))
            .collect::<Vec<_>>()
            .join(" ");
        let tokens = joined
            .split(|c: char| !c.is_ascii_alphanumeric())
            .filter(|token| !token.is_empty())
            .map(str::to_string)
            .collect();
        Self { joined, tokens }
    }

    fn token(&self, word: &str) -> bool {
        self.tokens.iter().any(|token| token == word)
    }

    /// `wan`, `wan2`, `wan21`: the word followed by digits only.
    fn token_numbered(&self, word: &str) -> bool {
        self.tokens.iter().any(|token| {
            token
                .strip_prefix(word)
                .is_some_and(|rest| rest.chars().all(|c| c.is_ascii_digit()))
        })
    }

    fn contains(&self, part: &str) -> bool {
        self.joined.contains(part)
    }
}

/// The modalities an engine's names give away, then the defaults: a `cli` engine edits
/// files and reads text, an `http` engine reads text - unless its names say it makes
/// pictures, video or sound, in which case it does only that until its operator says
/// otherwise.
#[must_use]
pub fn guess_modalities(basis: &Basis) -> BTreeSet<Modality> {
    let names = Names::new(basis);
    let mut found = BTreeSet::new();
    // Reads images: vl, vision, llava.
    if names.token("vl") || names.contains("vision") || names.contains("llava") {
        found.insert(Modality::Vision);
    }
    // The agent CLIs and hosted families that take screenshots. Only a CLI: Ferryman's
    // HTTP call sends text, so a family name alone does not make an endpoint see.
    if basis.cli
        && (names.token("claude")
            || names.token("gemini")
            || names.contains("gpt-4o")
            || names.contains("gpt-4.1")
            || names.contains("gpt-5"))
    {
        found.insert(Modality::Vision);
    }
    if names.contains("whisper") || names.token("stt") {
        found.insert(Modality::AudioIn);
    }
    if names.token("tts") || names.contains("kokoro") || names.contains("piper") {
        found.insert(Modality::AudioOut);
    }
    if names.contains("flux")
        || names.contains("sdxl")
        || names.contains("stable-diffusion")
        || names.contains("comfyui")
    {
        found.insert(Modality::Image);
    }
    if names.token_numbered("wan")
        || names.contains("hunyuan-video")
        || names.contains("hunyuanvideo")
        || names.token_numbered("ltx")
        || names.token_numbered("ltxv")
    {
        found.insert(Modality::Video);
    }
    if names.contains("embed") {
        found.insert(Modality::Embed);
    }
    if !found.iter().any(Modality::is_media) {
        found.insert(Modality::Text);
        if basis.cli {
            found.insert(Modality::Code);
        }
    }
    found
}

fn guess_strengths(names: &Names, context_k: Option<u32>) -> BTreeSet<String> {
    let mut found = BTreeSet::new();
    if names.contains("coder")
        || names.contains("codestral")
        || names.contains("devstral")
        || names.contains("codellama")
        || names.contains("codex")
    {
        found.insert("code".to_string());
    }
    if names.contains("reasoner")
        || names.contains("thinking")
        || names.contains("qwq")
        || names.token("r1")
        || names.token("o1")
        || names.token("o3")
    {
        found.insert("reasoning".to_string());
    }
    if names.contains("math") {
        found.insert("math".to_string());
    }
    if names.contains("translat") || names.contains("nllb") || names.contains("madlad") {
        found.insert("translation".to_string());
    }
    if context_k.is_some_and(|k| k >= LONG_CONTEXT_K) {
        found.insert("long-context".to_string());
    }
    found
}

/// A window named outright: `128k`, `32k`, `1m` (a million, so 1000). Nothing else is
/// guessed.
fn guess_context_k(names: &Names) -> Option<u32> {
    names.tokens.iter().find_map(|token| {
        let (digits, scale) = if let Some(digits) = token.strip_suffix('k') {
            (digits, 1)
        } else {
            (token.strip_suffix('m')?, 1000)
        };
        let value: u32 = digits.parse().ok()?;
        let k = value.checked_mul(scale)?;
        // `4k` is a window; `1k` and `0k` are model-name noise.
        (4..=10_000).contains(&k).then_some(k)
    })
}

/// Zero for local, free-tier and subscription engines; unknown for the rest.
fn guess_cost(paid: &str, local: bool) -> Option<Cost> {
    let free = local || matches!(paid.trim(), "local" | "free-tier" | "free" | "subscription");
    free.then_some(Cost::FREE)
}

/// Local when it says so, when its endpoint is on this machine or a private network and
/// nobody said it is paid for, or (with no endpoint at all) when it is a media CLI nobody
/// marked as paid: a whisper, ComfyUI or TTS runner is a program on the box. An agent CLI
/// with no endpoint (`claude`, `codex`) is not local: it calls out. An endpoint on this
/// network is not local when it is a gateway or proxy (OmniRoute, LiteLLM) or when its
/// operator said it is prepaid, a subscription or a free tier: the model behind it is
/// someone else's, and it costs what that says.
fn guess_local(basis: &Basis, modalities: &BTreeSet<Modality>) -> bool {
    let paid = basis.paid.trim();
    if paid == "local" {
        return true;
    }
    match basis.base_url {
        Some(url) => {
            !basis.gateway
                && paid == "unknown"
                && host_of(url).is_some_and(|host| is_private_host(&host))
        }
        None => {
            basis.cli && basis.paid.trim() == "unknown" && modalities.iter().any(Modality::is_media)
        }
    }
}

/// The host of a URL (or a bare host): no scheme, credentials, port or path.
#[must_use]
pub fn host_of(url: &str) -> Option<String> {
    let rest = url.split("://").nth(1).unwrap_or(url);
    let authority = rest.split(['/', '?', '#']).next()?;
    let host = authority.rsplit('@').next()?;
    let host = if let Some(bracketed) = host.strip_prefix('[') {
        bracketed.split(']').next()?.to_string()
    } else {
        host.split(':').next()?.to_string()
    };
    (!host.is_empty()).then(|| host.to_ascii_lowercase())
}

/// Whether a host is this machine or a private network: `localhost`, `.local`/`.lan`
/// names, loopback, RFC 1918, link-local, unique-local IPv6 and the 100.64.0.0/10 range
/// that Tailscale and carrier-grade NAT use.
#[must_use]
pub fn is_private_host(host: &str) -> bool {
    let host = host.trim().trim_end_matches('.').to_ascii_lowercase();
    if host == "localhost"
        || host.ends_with(".localhost")
        || host.ends_with(".local")
        || host.ends_with(".lan")
        || host.ends_with(".internal")
    {
        return true;
    }
    match host.parse::<IpAddr>() {
        Ok(IpAddr::V4(ip)) => {
            let [a, b, ..] = ip.octets();
            ip.is_loopback()
                || ip.is_private()
                || ip.is_link_local()
                || ip.is_unspecified()
                || (a == 100 && (64..=127).contains(&b))
        }
        Ok(IpAddr::V6(ip)) => {
            let first = ip.segments()[0];
            ip.is_loopback()
                || ip.is_unspecified()
                || (first & 0xfe00) == 0xfc00
                || (first & 0xffc0) == 0xfe80
        }
        Err(_) => false,
    }
}

/// Refuse a context window that cannot be one.
pub fn check_context_k(value: u32) -> Result<()> {
    if value == 0 {
        bail!("context_k must be a whole number of thousands of tokens, 1 or more")
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    fn cli<'a>(name: &'a str, model: Option<&'a str>) -> Basis<'a> {
        Basis {
            name,
            model,
            command: "",
            cli: true,
            base_url: None,
            paid: "unknown",
            gateway: false,
        }
    }

    fn http<'a>(name: &'a str, model: &'a str, url: &'a str, paid: &'a str) -> Basis<'a> {
        Basis {
            name,
            model: Some(model),
            command: "",
            cli: false,
            base_url: Some(url),
            paid,
            gateway: false,
        }
    }

    fn mods(basis: &Basis) -> Vec<String> {
        resolve(&Declared::default(), basis)
            .modalities
            .iter()
            .map(ToString::to_string)
            .collect()
    }

    #[test]
    fn modality_names_round_trip_and_unknown_ones_are_kept() {
        for m in Modality::KNOWN {
            assert_eq!(Modality::parse(m.as_str()).unwrap(), m);
            let json = serde_json::to_string(&m).unwrap();
            assert_eq!(serde_json::from_str::<Modality>(&json).unwrap(), m);
        }
        assert_eq!(Modality::parse(" Audio-In ").unwrap(), Modality::AudioIn);
        assert!(Modality::parse("smell").is_err(), "a typo fails loudly");
        // A newer peer's modality survives a read and a write, so its signature holds.
        let other: Modality = serde_json::from_str("\"hologram\"").unwrap();
        assert_eq!(other, Modality::Other("hologram".into()));
        assert_eq!(serde_json::to_string(&other).unwrap(), "\"hologram\"");
    }

    #[test]
    fn modality_lists_read_as_json_or_words_without_repeats() {
        assert_eq!(
            Modality::parse_list("[\"vision\",\"text\",\"vision\"]").unwrap(),
            vec![Modality::Text, Modality::Vision]
        );
        assert_eq!(
            Modality::parse_list("text, audio_out audio-out").unwrap(),
            vec![Modality::Text, Modality::AudioOut]
        );
        assert!(Modality::parse_list("text, smell").is_err());
        assert!(Modality::parse_list("[1,2]").is_err());
    }

    #[test]
    fn a_cli_engine_edits_files_and_reads_text_by_default() {
        assert_eq!(mods(&cli("myagent", None)), ["text", "code"]);
    }

    #[test]
    fn an_http_engine_reads_text_by_default() {
        let spec = http(
            "nv",
            "llama-3.3-70b",
            "https://api.example.com/v1",
            "prepaid",
        );
        assert_eq!(mods(&spec), ["text"]);
    }

    #[test]
    fn vl_vision_and_llava_in_a_name_mean_vision() {
        for model in [
            "qwen2.5-vl-72b-instruct",
            "Qwen/Qwen2.5-VL-7B",
            "llama-3.2-11b-vision-instruct",
            "llava-1.6-34b",
        ] {
            let spec = http("e", model, "http://localhost:1234/v1", "local");
            assert_eq!(mods(&spec), ["text", "vision"], "{model}");
        }
        // `vl` is a token, not a substring: no false positive inside another word.
        let spec = http("e", "nvlink-chat-7b", "http://localhost:1/v1", "local");
        assert_eq!(mods(&spec), ["text"]);
    }

    #[test]
    fn agent_cli_families_see_images_but_an_endpoint_does_not_on_a_name_alone() {
        assert_eq!(
            mods(&cli("claude", Some("claude-sonnet-4-5"))),
            ["text", "code", "vision"]
        );
        assert_eq!(
            mods(&cli("g", Some("gemini-2.5-pro"))),
            ["text", "code", "vision"]
        );
        assert_eq!(
            mods(&cli("c", Some("gpt-5-mini"))),
            ["text", "code", "vision"]
        );
        assert_eq!(mods(&cli("c", Some("gpt-4o"))), ["text", "code", "vision"]);
        let endpoint = http(
            "or",
            "anthropic/claude-3-haiku",
            "https://x.ai/v1",
            "prepaid",
        );
        assert_eq!(mods(&endpoint), ["text"]);
    }

    #[test]
    fn whisper_means_speech_to_text_and_only_that() {
        let mut b = cli("whisper", Some("whisper-large-v3"));
        b.command = "C:\\tools\\whisper-cli.exe";
        assert_eq!(mods(&b), ["audio_in"]);
    }

    #[test]
    fn tts_kokoro_and_piper_mean_text_to_speech() {
        assert_eq!(mods(&cli("speak", Some("kokoro-82m"))), ["audio_out"]);
        assert_eq!(mods(&cli("speak", Some("piper-en-us"))), ["audio_out"]);
        assert_eq!(mods(&cli("tts", None)), ["audio_out"]);
        assert_eq!(mods(&cli("speak", Some("xtts_v2-tts"))), ["audio_out"]);
        // A word that merely contains the letters is not a TTS engine.
        assert_eq!(mods(&cli("matts", None)), ["text", "code"]);
    }

    #[test]
    fn flux_sdxl_stable_diffusion_and_comfyui_mean_image_generation() {
        for name in [
            "flux-dev",
            "sdxl-turbo",
            "stable-diffusion-3",
            "stable_diffusion_xl",
            "comfyui",
        ] {
            assert_eq!(mods(&cli("gen", Some(name))), ["image"], "{name}");
        }
        // A runner named only by its command is found through the command.
        let mut b = cli("art", None);
        b.command = "/usr/local/bin/comfyui-run";
        assert_eq!(mods(&b), ["image"]);
    }

    #[test]
    fn wan_hunyuan_video_and_ltx_mean_video() {
        for name in [
            "wan2.1-t2v-14b",
            "wan-2.2",
            "Wan2_1",
            "hunyuan-video",
            "hunyuanvideo-i2v",
            "ltx-video",
            "ltxv-13b",
            "ltx2",
        ] {
            assert_eq!(mods(&cli("vid", Some(name))), ["video"], "{name}");
        }
        // Not video: a name that only starts or contains the letters.
        assert_eq!(mods(&cli("a", Some("wandb-helper"))), ["text", "code"]);
        assert_eq!(mods(&cli("a", Some("hunyuan-large"))), ["text", "code"]);
        assert_eq!(mods(&cli("a", Some("saltxy"))), ["text", "code"]);
    }

    #[test]
    fn embed_means_embeddings_and_not_chat() {
        let spec = http(
            "emb",
            "nomic-embed-text",
            "http://localhost:11434/v1",
            "local",
        );
        assert_eq!(mods(&spec), ["embed"]);
        let spec = http(
            "emb",
            "text-embedding-3-small",
            "https://api.example.com/v1",
            "prepaid",
        );
        assert_eq!(mods(&spec), ["embed"]);
    }

    #[test]
    fn declared_modalities_replace_the_guess_whole() {
        let declared = Declared {
            modalities: vec![Modality::Text, Modality::Vision],
            ..Declared::default()
        };
        let got = resolve(&declared, &cli("whisper", Some("whisper-large-v3")));
        assert_eq!(got.modalities, vec![Modality::Text, Modality::Vision]);
    }

    #[test]
    fn only_a_cli_engine_can_have_code() {
        let declared = Declared {
            modalities: vec![Modality::Text, Modality::Code],
            ..Declared::default()
        };
        let spec = http("e", "m", "https://x.example/v1", "prepaid");
        let got = resolve(&declared, &spec);
        assert_eq!(got.modalities, vec![Modality::Text]);
        let got = resolve(&declared, &cli("c", None));
        assert_eq!(got.modalities, vec![Modality::Text, Modality::Code]);
    }

    #[test]
    fn coder_codestral_and_devstral_are_code_strengths() {
        for model in [
            "qwen/qwen3-coder-480b",
            "codestral-latest",
            "devstral-small",
            "deepseek-coder-v2",
            "codellama-34b",
        ] {
            let got = resolve(&Declared::default(), &cli("e", Some(model)));
            assert_eq!(got.strengths, ["code"], "{model}");
        }
        let plain = resolve(&Declared::default(), &cli("e", Some("llama-3.3-70b")));
        assert!(plain.strengths.is_empty());
    }

    #[test]
    fn reasoning_math_and_translation_strengths_are_guessed_from_the_name() {
        let tags = |model: &str| resolve(&Declared::default(), &cli("e", Some(model))).strengths;
        assert_eq!(tags("deepseek-reasoner"), ["reasoning"]);
        assert_eq!(tags("deepseek-r1-distill-70b"), ["reasoning"]);
        assert_eq!(tags("qwq-32b"), ["reasoning"]);
        assert_eq!(tags("o3-mini"), ["reasoning"]);
        assert_eq!(tags("qwen2.5-math-72b"), ["math"]);
        assert_eq!(tags("nllb-200-translation"), ["translation"]);
        // `r1` and `o3` are tokens: a longer word does not count.
        assert!(tags("hr10-chat").is_empty());
    }

    #[test]
    fn declared_strengths_replace_guessed_ones() {
        let declared = Declared {
            strengths: vec!["Docs".into(), " review ".into(), "docs".into()],
            ..Declared::default()
        };
        let got = resolve(&declared, &cli("e", Some("qwen3-coder")));
        assert_eq!(got.strengths, ["docs", "review"]);
    }

    #[test]
    fn a_window_in_the_name_is_the_context_and_nothing_else_is_guessed() {
        let k = |model: &str| resolve(&Declared::default(), &cli("e", Some(model))).context_k;
        assert_eq!(k("llama-3.1-8b-instruct-128k"), Some(128));
        assert_eq!(k("mistral-32k"), Some(32));
        assert_eq!(k("gemini-1m"), Some(1000));
        assert_eq!(k("gemini-2.5-pro"), None, "no number, no guess");
        assert_eq!(k("model-1k"), None, "too small to be a window");
        assert_eq!(k("llama-70b"), None, "a parameter count is not a window");
        let declared = Declared {
            context_k: Some(64),
            ..Declared::default()
        };
        let got = resolve(&declared, &cli("e", Some("x-128k")));
        assert_eq!(got.context_k, Some(64), "declared wins");
    }

    #[test]
    fn a_large_window_is_a_long_context_strength() {
        let got = resolve(&Declared::default(), &cli("e", Some("model-1m")));
        assert_eq!(got.strengths, ["long-context"]);
        let declared = Declared {
            context_k: Some(256),
            ..Declared::default()
        };
        let got = resolve(&declared, &cli("e", Some("model")));
        assert_eq!(got.strengths, ["long-context"]);
        let small = Declared {
            context_k: Some(32),
            ..Declared::default()
        };
        assert!(
            resolve(&small, &cli("e", Some("model")))
                .strengths
                .is_empty()
        );
    }

    #[test]
    fn local_free_and_subscription_engines_cost_nothing_and_prepaid_is_unpriced() {
        let cost = |paid: &str| {
            let spec = http("e", "m", "https://api.example.com/v1", paid);
            resolve(&Declared::default(), &spec).cost
        };
        assert_eq!(cost("local"), Some(Cost::FREE));
        assert_eq!(cost("free-tier"), Some(Cost::FREE));
        assert_eq!(cost("subscription"), Some(Cost::FREE));
        assert_eq!(cost("prepaid"), None, "unpriced is not free");
        assert_eq!(cost("unknown"), None);
        // On a private network it is free whatever it says about payment.
        let lan = http("e", "m", "http://192.168.1.20:8000/v1", "unknown");
        assert_eq!(resolve(&Declared::default(), &lan).cost, Some(Cost::FREE));
    }

    #[test]
    fn a_declared_price_wins_and_estimates() {
        let price = Cost {
            per_call_usd: 0.04,
            per_mtok_in_usd: 3.0,
            per_mtok_out_usd: 15.0,
        };
        let declared = Declared {
            cost: Some(price),
            ..Declared::default()
        };
        let spec = http("e", "m", "https://api.example.com/v1", "free-tier");
        let got = resolve(&declared, &spec);
        assert_eq!(got.cost, Some(price));
        let dollars = price.estimate(1_000_000, 100_000);
        assert!((dollars - (0.04 + 3.0 + 1.5)).abs() < 1e-9);
        assert!(!price.is_free());
    }

    #[test]
    fn local_follows_the_endpoint_host() {
        let local =
            |url: &str| resolve(&Declared::default(), &http("e", "m", url, "unknown")).local;
        assert!(local("http://localhost:1234/v1"));
        assert!(local("http://127.0.0.1:8080/v1"));
        assert!(local("http://[::1]:8080/v1"));
        assert!(local("http://10.0.0.5/v1"));
        assert!(local("http://172.20.1.1:11434/v1"));
        assert!(local("http://192.168.0.9/v1"));
        assert!(local("http://100.101.102.103:8000/v1"), "tailscale");
        assert!(local("http://gpu-box.lan:8000/v1"));
        assert!(local("http://user:pw@studio.local/v1"));
        assert!(!local("https://integrate.api.nvidia.com/v1"));
        assert!(!local("http://172.32.0.1/v1"), "outside 172.16/12");
        assert!(!local("http://100.128.0.1/v1"), "outside 100.64/10");
        assert!(!local("https://localhost.evil.example/v1"));
    }

    #[test]
    fn a_paid_engine_behind_a_local_address_is_not_local_and_not_free() {
        let caps = |paid: &str, gateway: bool| {
            let mut basis = http("e", "m", "http://localhost:20128/v1", paid);
            basis.gateway = gateway;
            resolve(&Declared::default(), &basis)
        };
        // Nobody said anything: a local server.
        let plain = caps("unknown", false);
        assert!(plain.local && plain.cost.is_some_and(|c| c.is_free()));
        // Said to be paid: a proxy to somebody's API, however near.
        for paid in ["prepaid", "subscription", "free-tier"] {
            assert!(!caps(paid, false).local, "{paid}");
        }
        assert!(caps("prepaid", false).cost.is_none(), "unpriced, not free");
        // A gateway is never guessed local, even unmarked...
        let gateway = caps("unknown", true);
        assert!(!gateway.local);
        assert!(gateway.cost.is_none(), "{gateway:?}");
        // ...unless the operator says paid = local.
        assert!(caps("local", true).local);
        // And a declared value still wins.
        let declared = Declared {
            local: Some(true),
            ..Declared::default()
        };
        let mut basis = http("e", "m", "http://localhost:20128/v1", "prepaid");
        basis.gateway = true;
        assert!(resolve(&declared, &basis).local);
    }

    #[test]
    fn local_for_a_cli_means_paid_local_or_a_media_runner_nobody_priced() {
        let caps = |b: &Basis| resolve(&Declared::default(), b);
        // An agent CLI with no endpoint calls out.
        assert!(!caps(&cli("claude", Some("claude-sonnet-4-5"))).local);
        assert!(!caps(&cli("codex", None)).local);
        // A whisper or ComfyUI runner is a program on the box.
        assert!(caps(&cli("whisper", Some("whisper-large-v3"))).local);
        assert!(caps(&cli("comfy", Some("flux-dev"))).local);
        // Unless it says it is paid.
        let mut paid = cli("comfy", Some("flux-dev"));
        paid.paid = "prepaid";
        assert!(!caps(&paid).local);
        // Or says it is local.
        let mut local = cli("myagent", None);
        local.paid = "local";
        assert!(caps(&local).local);
    }

    #[test]
    fn a_declared_local_wins_either_way() {
        let yes = Declared {
            local: Some(true),
            ..Declared::default()
        };
        let no = Declared {
            local: Some(false),
            ..Declared::default()
        };
        let remote = http("e", "m", "https://api.example.com/v1", "prepaid");
        let lan = http("e", "m", "http://localhost:1/v1", "local");
        assert!(resolve(&yes, &remote).local);
        assert!(!resolve(&no, &lan).local);
    }

    #[test]
    fn hosts_come_out_of_urls_without_credentials_ports_or_paths() {
        assert_eq!(
            host_of("https://User:pw@Api.Example.com:8443/v1/x?y=1").as_deref(),
            Some("api.example.com")
        );
        assert_eq!(
            host_of("http://[fd00::1]:80/v1").as_deref(),
            Some("fd00::1")
        );
        assert_eq!(host_of("studio.local").as_deref(), Some("studio.local"));
        assert_eq!(host_of("http:///v1"), None);
        assert!(is_private_host("fd00::1"));
        assert!(is_private_host("fe80::1"));
        assert!(!is_private_host("2001:4860:4860::8888"));
    }

    #[test]
    fn the_profile_serializes_without_empty_fields_and_reads_back() {
        let caps = Capabilities {
            modalities: vec![Modality::Text, Modality::Vision],
            strengths: vec![],
            context_k: Some(128),
            cost: Some(Cost::FREE),
            local: true,
        };
        let json = serde_json::to_value(&caps).unwrap();
        assert!(json.get("strengths").is_none());
        assert_eq!(json["modalities"], serde_json::json!(["text", "vision"]));
        let back: Capabilities = serde_json::from_value(json).unwrap();
        assert_eq!(back, caps);
        let empty: Capabilities = serde_json::from_str("{}").unwrap();
        assert_eq!(empty, Capabilities::default());
        assert_eq!(empty.modalities_label(), "-");
    }

    #[test]
    fn has_all_and_describe_read_naturally() {
        let caps = resolve(
            &Declared::default(),
            &http("e", "qwen3-coder-128k", "http://localhost:1/v1", "local"),
        );
        assert!(caps.has(&Modality::Text));
        assert!(caps.has_all(&[Modality::Text]));
        assert!(!caps.has_all(&[Modality::Text, Modality::Code]));
        assert!(caps.has_all(&[]));
        assert!(caps.has_strength("CODE"));
        assert_eq!(
            caps.describe(),
            "text, strengths code, 128k context, free, local"
        );
    }
}
