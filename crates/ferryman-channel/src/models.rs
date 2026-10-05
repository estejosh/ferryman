//! What each model is actually good at: the router's built-in model profiles.
//!
//! The router ([`crate::router`]) used to know three things about an engine: how big it is
//! (small, medium, large), what its operator said it is strong at, and how its own results
//! have turned out. It did not know that Claude Haiku is a fine chore engine, that
//! Nemotron is a better writer than reviewer, or that a 7b Qwen is not a planner. This
//! module is that knowledge: a curated table from model families to a prior success
//! estimate, `p`, for each kind of work.
//!
//! # These are priors, not facts
//!
//! Every number here is a conservative starting guess about a family, written down by a
//! person. It is what the router believes before it has seen the engine work. It still
//! counts for [`crate::router::PRIOR_WEIGHT`] observations only, so a few verified or
//! refuted results from the worker's own ledger move it, and a model that does better or
//! worse than its family is found out. Nothing here is a benchmark score, and a newer model
//! of a family is matched to its family's row until someone gives it its own.
//!
//! The numbers are for **medium-sized work**. Large work takes [`LARGE_WORK_STEP`] (0.05)
//! off for each class the model is below large, so a small model loses a little more on a
//! big job than a large one does. Small work takes nothing off.
//!
//! # How a model is found
//!
//! [`profile_for`] reads the engine's model string. Case does not matter and `-`, `_`, `:`,
//! `/` and spaces all separate words, so `Claude-Sonnet-4-5`, `claude_sonnet_4_5` and the
//! bare `sonnet` alias the claude CLI takes are the same family. When the model string is
//! empty or names nothing in the table, the engine's own name is read the same way. A model
//! that matches nothing has no profile, and the router keeps using its size class, exactly
//! as before.
//!
//! The first family that matches wins, from the most specific to the most general, so
//! `llama-3.1-nemotron-70b` is a Nemotron and `deepseek-r1-distill-qwen-32b` is a DeepSeek
//! distill, not a Qwen.
//!
//! # Models whose size is in the name
//!
//! Open families come in sizes, and the size is most of what a name tells you. For Qwen,
//! Llama, Mistral, the GLM sizes in the name, small DeepSeek distills and Nemotrons named
//! by size, the profile is a **base level that grows with the parameter count** (see
//! [`level`]: about 0.58 at 7b, 0.66 at 14b, 0.74 at 32b, 0.80 at 72b), plus a small offset
//! per kind that says what the family is relatively better or worse at. A `-coder` variant
//! is better at code and tests and worse at everything else; a `vl` (vision) variant is a
//! little worse at text work than its text twin; a reasoning variant (`qwq`, `thinking`,
//! an R1 distill) is better at planning and review and worse at chores.
//!
//! A mixture-of-experts model names two sizes (`235b-a22b`: 235 billion in all, 22 billion
//! active). It is scaled by the geometric mean of the two (about 72b there), which is how it
//! behaves in practice. `8x7b` counts as three times the expert size. A name with no size
//! at all is scaled as a small-to-medium model (14b for Qwen, 8b for Llama, 7b for
//! Mistral), because a wrong guess upward sends work to a model that cannot do it.
//!
//! # What an operator can still say
//!
//! A model with no profile is scored by its class and strengths, as before. For a model
//! with a profile **the profile wins over the class**: the class on an engine is a size
//! guess made from the same name, and the profile is a better one. Declared or guessed
//! strengths still add the usual 0.05 each (to 0.10) for the kinds they help, except the
//! tags the profile already priced in (`code` on a `-coder`, `reasoning` on an R1), so a
//! name is never counted twice. The ledger moves it from there.

use crate::{
    policy::ModelClass,
    work::{Size, WorkKind},
};

/// The kinds a profile has a number for, in the order of its priors. The kinds that are
/// about a medium rather than about judgement (transcribe, image, video, audio) have none:
/// they are matched on what the engine can take in or put out, not on how good it is at
/// the work.
const KINDS: [WorkKind; 8] = [
    WorkKind::CodeChange,
    WorkKind::Review,
    WorkKind::Plan,
    WorkKind::Docs,
    WorkKind::Tests,
    WorkKind::Chore,
    WorkKind::Research,
    WorkKind::Translate,
];

/// Taken off a profile's prior on large work for each class the model is below large.
pub const LARGE_WORK_STEP: f64 = 0.05;

/// Priors or offsets in [`KINDS`] order: code-change, review, plan, docs, tests, chore,
/// research, translate.
type Priors = [f64; 8];

/// What a family of models is good at.
#[derive(Debug, Clone, PartialEq)]
pub struct Profile {
    /// The family the model was matched to: `claude-sonnet`, `nemotron-super`,
    /// `qwen ~14b`. What `ferry route simulate` shows.
    pub family: String,
    /// How big the model is, for the size-of-work adjustment.
    pub class: ModelClass,
    priors: Priors,
    /// Strength tags the priors already reflect, so a declared or guessed tag is not
    /// counted twice.
    credited: &'static [&'static str],
}

impl Profile {
    /// The prior mean success estimate for work of `kind` and `size`, `None` for the kinds
    /// a profile says nothing about (transcribe, image, video, audio). `other` is the
    /// model's average over the kinds it has numbers for.
    #[must_use]
    pub fn prior(&self, kind: WorkKind, size: Size) -> Option<f64> {
        let base = if kind == WorkKind::Other {
            self.priors.iter().sum::<f64>() / 8.0
        } else {
            self.priors[KINDS.iter().position(|known| *known == kind)?]
        };
        let steps = match (size, self.class) {
            (Size::Large, ModelClass::Medium) => 1,
            (Size::Large, ModelClass::Small) => 2,
            _ => 0,
        };
        Some((base - f64::from(steps) * LARGE_WORK_STEP).clamp(0.05, 0.95))
    }

    /// Whether the priors already reflect this strength tag.
    #[must_use]
    pub fn credits(&self, tag: &str) -> bool {
        self.credited.contains(&tag)
    }
}

/// The profile for an engine: by its model string, else by its name. `None` when neither
/// is a model this table knows.
#[must_use]
pub fn profile_for(model: Option<&str>, name: &str) -> Option<Profile> {
    model
        .map(str::trim)
        .filter(|model| !model.is_empty())
        .and_then(from_text)
        .or_else(|| from_text(name))
}

// --- sizes ---------------------------------------------------------------------------------

/// Where the base level of a sized model stands at some parameter counts (billions): the
/// level between two is read off a straight line in the logarithm of the size.
const LADDER: [(f64, f64); 8] = [
    (1.0, 0.40),
    (3.0, 0.48),
    (7.0, 0.58),
    (14.0, 0.66),
    (32.0, 0.74),
    (72.0, 0.80),
    (200.0, 0.85),
    (400.0, 0.88),
];

/// The base level of a model with this many billion (effective) parameters, before the
/// family's per-kind offsets.
#[must_use]
pub fn level(billions: f64) -> f64 {
    let (first, last) = (LADDER[0], LADDER[LADDER.len() - 1]);
    if billions <= first.0 {
        return first.1;
    }
    if billions >= last.0 {
        return last.1;
    }
    for pair in LADDER.windows(2) {
        let (low, high) = (pair[0], pair[1]);
        if billions <= high.0 {
            let share = (billions / low.0).ln() / (high.0 / low.0).ln();
            return low.1 + share * (high.1 - low.1);
        }
    }
    last.1
}

/// `14b`, `1.5b`, `8x7b`: a count of billions, an expert mixture as three times the expert.
fn count(token: &str) -> Option<f64> {
    let digits = token.strip_suffix('b')?;
    if let Some((experts, each)) = digits.split_once('x') {
        number(experts)?;
        return Some(number(each)? * 3.0);
    }
    number(digits)
}

fn number(text: &str) -> Option<f64> {
    if text.is_empty() || !text.chars().all(|c| c.is_ascii_digit() || c == '.') {
        return None;
    }
    text.parse().ok()
}

/// The effective parameters (billions) a name gives: the size, or for a mixture of experts
/// (`235b-a22b`) the geometric mean of the total and the active count.
fn parameters(tokens: &[String]) -> Option<f64> {
    let total = tokens.iter().find_map(|token| count(token));
    let active = tokens
        .iter()
        .find_map(|token| count(token.strip_prefix('a')?));
    match (total, active) {
        (Some(total), Some(active)) if active < total => Some((total * active).sqrt()),
        (total, _) => total,
    }
}

fn round2(value: f64) -> f64 {
    (value * 100.0).round() / 100.0
}

fn size_label(billions: f64) -> String {
    let text = if billions >= 10.0 {
        format!("{billions:.0}")
    } else {
        format!("{billions:.1}")
    };
    text.trim_end_matches(".0").to_string()
}

/// A sized family: [`level`] for its size plus the family's offsets.
fn scaled(
    family: &str,
    billions: f64,
    offsets: Priors,
    credited: &'static [&'static str],
) -> Profile {
    let base = level(billions);
    let class = if billions < 10.0 {
        ModelClass::Small
    } else if billions < 70.0 {
        ModelClass::Medium
    } else {
        ModelClass::Large
    };
    let mut priors = offsets;
    for prior in &mut priors {
        *prior = round2(base + *prior).clamp(0.05, 0.95);
    }
    Profile {
        family: format!("{family} ~{}b", size_label(billions)),
        class,
        priors,
        credited,
    }
}

/// One model with its own numbers.
fn fixed(
    family: &str,
    class: ModelClass,
    priors: Priors,
    credited: &'static [&'static str],
) -> Profile {
    Profile {
        family: family.to_string(),
        class,
        priors,
        credited,
    }
}

// What a family is relatively better or worse at than its size alone says, in
// `KINDS` order: code, review, plan, docs, tests, chore, research, translate.
const GENERAL: Priors = [0.00, -0.02, -0.03, 0.02, -0.02, 0.02, -0.03, 0.00];
const QWEN: Priors = [0.00, -0.03, -0.04, 0.04, -0.02, 0.04, -0.04, 0.02];
const LLAMA: Priors = [-0.04, -0.02, -0.02, 0.02, -0.03, 0.00, -0.02, 0.00];
const MISTRAL: Priors = [-0.03, -0.02, -0.03, 0.00, -0.02, 0.00, -0.03, 0.02];
const CODER: Priors = [0.08, -0.02, -0.08, -0.06, 0.06, -0.02, -0.10, -0.06];
const REASONER: Priors = [0.02, 0.03, 0.04, -0.04, -0.02, -0.06, 0.02, -0.03];
const SEES: Priors = [-0.06, -0.04, -0.05, -0.02, -0.04, 0.00, -0.04, 0.00];

// --- reading a name -------------------------------------------------------------------------

/// A model string as lowercase words: split at anything but a letter, digit or the dot of
/// a version.
struct Name {
    tokens: Vec<String>,
    joined: String,
}

impl Name {
    fn new(text: &str) -> Self {
        let lower = text.to_ascii_lowercase();
        let tokens: Vec<String> = lower
            .split(|c: char| !(c.is_ascii_alphanumeric() || c == '.'))
            .filter(|token| token.chars().any(|c| c.is_ascii_alphanumeric()))
            .map(str::to_string)
            .collect();
        let joined = tokens.join("-");
        Self { tokens, joined }
    }

    /// The word, whole.
    fn has(&self, word: &str) -> bool {
        self.tokens.iter().any(|token| token == word)
    }

    /// The text, anywhere, across word breaks (`flash-lite`, `gpt-5`).
    fn contains(&self, part: &str) -> bool {
        self.joined.contains(part)
    }

    fn billions(&self) -> Option<f64> {
        parameters(&self.tokens)
    }
}

fn from_text(text: &str) -> Option<Profile> {
    let name = Name::new(text);
    claude(&name)
        .or_else(|| codex(&name))
        .or_else(|| gpt(&name))
        .or_else(|| gemini(&name))
        .or_else(|| deepseek(&name))
        .or_else(|| nemotron(&name))
        .or_else(|| qwen(&name))
        .or_else(|| glm(&name))
        .or_else(|| kimi(&name))
        .or_else(|| codestral(&name))
        .or_else(|| mistral(&name))
        .or_else(|| llama(&name))
}

// --- the families ---------------------------------------------------------------------------
// Each row: code, review, plan, docs, tests, chore, research, translate.

fn claude(n: &Name) -> Option<Profile> {
    if n.has("opus") {
        Some(fixed(
            "claude-opus",
            ModelClass::Large,
            [0.92, 0.92, 0.93, 0.90, 0.90, 0.88, 0.90, 0.88],
            &[],
        ))
    } else if n.has("sonnet") {
        Some(fixed(
            "claude-sonnet",
            ModelClass::Large,
            [0.88, 0.87, 0.86, 0.86, 0.86, 0.84, 0.82, 0.84],
            &[],
        ))
    } else if n.has("haiku") {
        Some(fixed(
            "claude-haiku",
            ModelClass::Small,
            [0.72, 0.70, 0.66, 0.78, 0.76, 0.82, 0.68, 0.78],
            &[],
        ))
    } else {
        None
    }
}

fn codex(n: &Name) -> Option<Profile> {
    if !n.contains("codex") {
        return None;
    }
    Some(if n.has("mini") {
        fixed(
            "codex-mini",
            ModelClass::Medium,
            [0.78, 0.72, 0.64, 0.66, 0.78, 0.76, 0.60, 0.62],
            &["code"],
        )
    } else {
        fixed(
            "codex",
            ModelClass::Large,
            [0.92, 0.86, 0.76, 0.72, 0.90, 0.80, 0.70, 0.70],
            &["code"],
        )
    })
}

fn gpt(n: &Name) -> Option<Profile> {
    if !(n.contains("gpt-5") || n.has("gpt5")) {
        return None;
    }
    Some(if n.has("nano") {
        fixed(
            "gpt-5-nano",
            ModelClass::Small,
            [0.62, 0.58, 0.55, 0.70, 0.66, 0.72, 0.55, 0.70],
            &[],
        )
    } else if n.has("mini") {
        fixed(
            "gpt-5-mini",
            ModelClass::Medium,
            [0.76, 0.74, 0.72, 0.78, 0.78, 0.80, 0.72, 0.80],
            &[],
        )
    } else {
        fixed(
            "gpt-5",
            ModelClass::Large,
            [0.90, 0.88, 0.88, 0.84, 0.88, 0.82, 0.88, 0.86],
            &[],
        )
    })
}

fn gemini(n: &Name) -> Option<Profile> {
    if !n.contains("gemini") {
        return None;
    }
    Some(if n.contains("flash-lite") {
        fixed(
            "gemini-flash-lite",
            ModelClass::Small,
            [0.62, 0.58, 0.55, 0.72, 0.65, 0.74, 0.58, 0.78],
            &[],
        )
    } else if n.has("pro") || n.has("ultra") {
        fixed(
            "gemini-pro",
            ModelClass::Large,
            [0.84, 0.84, 0.86, 0.84, 0.82, 0.80, 0.88, 0.88],
            &[],
        )
    } else {
        // `flash`, and a bare `gemini` we cannot place: the cheaper reading.
        fixed(
            "gemini-flash",
            ModelClass::Medium,
            [0.74, 0.72, 0.72, 0.78, 0.76, 0.80, 0.76, 0.84],
            &[],
        )
    })
}

fn deepseek(n: &Name) -> Option<Profile> {
    if !n.contains("deepseek") {
        return None;
    }
    let reasoning = n.has("r1") || n.contains("reasoner");
    // A distill or a small coder has its size in the name and is scaled by it. The full
    // models name 600b or more, or nothing.
    if let Some(billions) = n.billions()
        && billions < 100.0
    {
        return Some(if reasoning || n.contains("distill") {
            scaled("deepseek-r1-distill", billions, REASONER, &["reasoning"])
        } else if n.contains("coder") {
            scaled("deepseek-coder", billions, CODER, &["code"])
        } else {
            scaled("deepseek", billions, GENERAL, &[])
        });
    }
    Some(if reasoning {
        fixed(
            "deepseek-r1",
            ModelClass::Large,
            [0.80, 0.82, 0.84, 0.72, 0.76, 0.66, 0.82, 0.74],
            &["reasoning"],
        )
    } else if n.has("v4") && n.has("pro") {
        fixed(
            "deepseek-v4-pro",
            ModelClass::Large,
            [0.86, 0.84, 0.86, 0.82, 0.84, 0.80, 0.84, 0.82],
            &[],
        )
    } else if n.has("v4") {
        fixed(
            "deepseek-v4",
            ModelClass::Medium,
            [0.82, 0.78, 0.78, 0.80, 0.80, 0.80, 0.78, 0.80],
            &[],
        )
    } else {
        fixed(
            "deepseek-v3",
            ModelClass::Medium,
            [0.78, 0.74, 0.74, 0.78, 0.76, 0.78, 0.74, 0.78],
            &[],
        )
    })
}

fn nemotron(n: &Name) -> Option<Profile> {
    if !n.contains("nemotron") {
        return None;
    }
    if n.has("ultra") {
        return Some(fixed(
            "nemotron-ultra",
            ModelClass::Large,
            [0.80, 0.80, 0.80, 0.82, 0.78, 0.80, 0.80, 0.80],
            &[],
        ));
    }
    if n.has("nano") {
        return Some(fixed(
            "nemotron-nano",
            ModelClass::Small,
            [0.60, 0.58, 0.55, 0.70, 0.62, 0.72, 0.55, 0.66],
            &[],
        ));
    }
    if !n.has("super")
        && let Some(billions) = n.billions()
    {
        // An older Nemotron named by size only (`llama-3.1-nemotron-70b`): scaled, and a
        // little under the same size of a family tuned for work.
        let tuned = GENERAL.map(|offset| offset - 0.04);
        return Some(scaled("nemotron", billions, tuned, &[]));
    }
    Some(fixed(
        "nemotron-super",
        ModelClass::Medium,
        [0.72, 0.72, 0.70, 0.78, 0.72, 0.80, 0.72, 0.76],
        &[],
    ))
}

fn qwen(n: &Name) -> Option<Profile> {
    if !(n.contains("qwen") || n.contains("qwq")) {
        return None;
    }
    let billions = n.billions().unwrap_or(if n.has("max") {
        200.0
    } else if n.has("plus") {
        72.0
    } else {
        14.0
    });
    let sees = n
        .tokens
        .iter()
        .any(|token| token == "vl" || (token.starts_with("qwen") && token.ends_with("vl")));
    let (label, offsets, credited): (&str, Priors, &'static [&'static str]) = if n.contains("coder")
    {
        ("qwen-coder", CODER, &["code"])
    } else if sees {
        ("qwen-vl", SEES, &[])
    } else if n.contains("qwq") || n.contains("thinking") {
        ("qwq", REASONER, &["reasoning"])
    } else {
        ("qwen", QWEN, &[])
    };
    // Qwen3 is a generation on from Qwen2.5 at the same size.
    let newer = if n.tokens.iter().any(|token| token.starts_with("qwen3")) {
        0.02
    } else {
        0.0
    };
    Some(scaled(
        label,
        billions,
        offsets.map(|o| o + newer),
        credited,
    ))
}

fn glm(n: &Name) -> Option<Profile> {
    if !n.contains("glm") {
        return None;
    }
    if n.has("flash") {
        return Some(fixed(
            "glm-flash",
            ModelClass::Medium,
            [0.72, 0.66, 0.64, 0.72, 0.70, 0.74, 0.64, 0.74],
            &[],
        ));
    }
    if n.has("air") {
        return Some(fixed(
            "glm-air",
            ModelClass::Medium,
            [0.76, 0.72, 0.72, 0.74, 0.74, 0.76, 0.70, 0.76],
            &[],
        ));
    }
    if let Some(billions) = n.billions()
        && billions < 100.0
    {
        return Some(scaled("glm", billions, GENERAL, &[]));
    }
    Some(fixed(
        "glm-4.x",
        ModelClass::Large,
        [0.84, 0.78, 0.78, 0.78, 0.80, 0.76, 0.76, 0.80],
        &[],
    ))
}

fn kimi(n: &Name) -> Option<Profile> {
    n.contains("kimi").then(|| {
        fixed(
            "kimi",
            ModelClass::Large,
            [0.84, 0.80, 0.80, 0.82, 0.80, 0.76, 0.82, 0.82],
            &[],
        )
    })
}

fn codestral(n: &Name) -> Option<Profile> {
    if n.contains("codestral") {
        Some(scaled(
            "codestral",
            n.billions().unwrap_or(22.0),
            CODER,
            &["code"],
        ))
    } else if n.contains("devstral") {
        Some(scaled(
            "devstral",
            n.billions().unwrap_or(24.0),
            CODER,
            &["code"],
        ))
    } else {
        None
    }
}

fn mistral(n: &Name) -> Option<Profile> {
    let family = ["mistral", "mixtral", "ministral", "magistral"]
        .into_iter()
        .find(|word| n.contains(word))?;
    let billions = n.billions().unwrap_or(if n.has("large") {
        123.0
    } else if n.has("medium") {
        60.0
    } else if n.has("small") || family == "magistral" {
        24.0
    } else if n.has("nemo") {
        12.0
    } else if family == "mixtral" {
        25.0
    } else if family == "ministral" {
        8.0
    } else {
        7.0
    });
    Some(if family == "magistral" {
        scaled("magistral", billions, REASONER, &["reasoning"])
    } else {
        scaled("mistral", billions, MISTRAL, &[])
    })
}

fn llama(n: &Name) -> Option<Profile> {
    // A word that starts with it, not a name that merely ends in it: `ollama` is the
    // runner, not the model.
    if !n
        .tokens
        .iter()
        .any(|token| token.starts_with("llama") || token == "codellama")
    {
        return None;
    }
    // Llama 4 names the active experts (`17b-16e`), which is not its size: Scout is
    // read as a 60b and Maverick as a 100b.
    let four = n.contains("llama-4") || n.tokens.iter().any(|token| token.starts_with("llama4"));
    let billions = if four && n.has("maverick") {
        100.0
    } else if four {
        60.0
    } else {
        n.billions().unwrap_or(8.0)
    };
    Some(scaled("llama", billions, LLAMA, &[]))
}

#[cfg(test)]
mod tests {
    use super::*;

    const ALL: [WorkKind; 8] = KINDS;

    fn family(model: &str) -> Option<String> {
        profile_for(Some(model), "").map(|profile| profile.family)
    }

    fn at(model: &str, kind: WorkKind) -> f64 {
        profile_for(Some(model), "")
            .unwrap_or_else(|| panic!("{model} has no profile"))
            .prior(kind, Size::Medium)
            .unwrap()
    }

    #[test]
    fn claude_is_found_by_alias_by_full_name_and_by_engine_name() {
        for (model, want) in [
            ("sonnet", "claude-sonnet"),
            ("SONNET", "claude-sonnet"),
            ("opus", "claude-opus"),
            ("haiku", "claude-haiku"),
            ("claude-sonnet-4-5-20250929", "claude-sonnet"),
            ("anthropic/claude-3.5-haiku", "claude-haiku"),
            ("us.anthropic.claude-opus-4-1-v1:0", "claude-opus"),
            ("sonnet[1m]", "claude-sonnet"),
        ] {
            assert_eq!(family(model).as_deref(), Some(want), "{model}");
        }
        // No model string: the engine's name is read the same way.
        assert_eq!(
            profile_for(None, "claude-haiku").unwrap().family,
            "claude-haiku"
        );
        assert_eq!(
            profile_for(Some("  "), "claude-opus").unwrap().family,
            "claude-opus"
        );
        // The model string wins when it names a family; the name is the fallback.
        assert_eq!(
            profile_for(Some("haiku"), "claude-opus").unwrap().family,
            "claude-haiku"
        );
        assert_eq!(
            profile_for(Some("some-model-nobody-knows"), "sonnet")
                .unwrap()
                .family,
            "claude-sonnet"
        );
        // A bare `claude` names no model, so there is nothing to profile.
        assert!(profile_for(None, "claude").is_none());
    }

    #[test]
    fn opus_is_above_sonnet_and_sonnet_above_haiku_at_everything() {
        for kind in ALL {
            assert!(at("opus", kind) >= at("sonnet", kind), "{kind:?}");
            assert!(at("sonnet", kind) >= at("haiku", kind), "{kind:?}");
        }
        // But haiku is a chore engine first: its best kind.
        let haiku = profile_for(Some("haiku"), "").unwrap();
        let best = ALL
            .iter()
            .map(|kind| haiku.prior(*kind, Size::Medium).unwrap())
            .fold(0.0, f64::max);
        assert!((haiku.prior(WorkKind::Chore, Size::Medium).unwrap() - best).abs() < 1e-9);
    }

    #[test]
    fn the_gpt_5_family_codex_and_gemini() {
        for (model, want) in [
            ("gpt-5", "gpt-5"),
            ("gpt-5.1", "gpt-5"),
            ("openai/gpt-5-mini", "gpt-5-mini"),
            ("gpt-5-nano", "gpt-5-nano"),
            ("gpt-5-codex", "codex"),
            ("codex-mini-latest", "codex-mini"),
            ("gemini-2.5-pro", "gemini-pro"),
            ("gemini-2.5-flash", "gemini-flash"),
            ("gemini-2.5-flash-lite", "gemini-flash-lite"),
            ("gemini", "gemini-flash"),
        ] {
            assert_eq!(family(model).as_deref(), Some(want), "{model}");
        }
        // Codex is the one to ask for code and tests, and not for words.
        assert!(at("gpt-5-codex", WorkKind::CodeChange) > at("gpt-5", WorkKind::CodeChange));
        assert!(at("gpt-5-codex", WorkKind::Docs) < at("gpt-5", WorkKind::Docs));
        assert!(at("gemini-pro", WorkKind::Research) > at("gemini-pro", WorkKind::CodeChange));
        for kind in ALL {
            assert!(at("gpt-5", kind) > at("gpt-5-mini", kind), "{kind:?}");
            assert!(at("gpt-5-mini", kind) > at("gpt-5-nano", kind), "{kind:?}");
            assert!(
                at("gemini-pro", kind) >= at("gemini-flash", kind),
                "{kind:?}"
            );
            assert!(
                at("gemini-flash", kind) > at("gemini-flash-lite", kind),
                "{kind:?}"
            );
        }
    }

    #[test]
    fn deepseek_v3_v4_v4_pro_and_r1() {
        for (model, want) in [
            ("deepseek-chat", "deepseek-v3"),
            ("deepseek-v3.1", "deepseek-v3"),
            ("deepseek-v3:671b", "deepseek-v3"),
            ("deepseek-v4", "deepseek-v4"),
            ("deepseek-v4-pro", "deepseek-v4-pro"),
            ("deepseek-r1", "deepseek-r1"),
            ("deepseek-reasoner", "deepseek-r1"),
        ] {
            assert_eq!(family(model).as_deref(), Some(want), "{model}");
        }
        for kind in [WorkKind::CodeChange, WorkKind::Review, WorkKind::Plan] {
            assert!(
                at("deepseek-v4-pro", kind) > at("deepseek-v4", kind),
                "{kind:?}"
            );
            assert!(
                at("deepseek-v4", kind) > at("deepseek-v3", kind),
                "{kind:?}"
            );
        }
        // R1 thinks first: better at plans than v3, worse at a quick chore.
        assert!(at("deepseek-r1", WorkKind::Plan) > at("deepseek-v3", WorkKind::Plan));
        assert!(at("deepseek-r1", WorkKind::Chore) < at("deepseek-v3", WorkKind::Chore));
        // A distill is a small model with R1's habits, scaled by the size in its name,
        // and it is not read as a Qwen.
        let distill = profile_for(Some("deepseek-r1-distill-qwen-32b"), "").unwrap();
        assert_eq!(distill.family, "deepseek-r1-distill ~32b");
        assert!(
            distill.prior(WorkKind::Plan, Size::Medium).unwrap()
                < at("deepseek-r1", WorkKind::Plan)
        );
        assert!(distill.credits("reasoning"));
    }

    #[test]
    fn nemotron_super_ultra_and_nano() {
        for (model, want) in [
            ("nvidia/nemotron-3-super-120b-a12b", "nemotron-super"),
            ("nemotron-super", "nemotron-super"),
            ("nvidia/llama-3.1-nemotron-ultra-253b-v1", "nemotron-ultra"),
            ("nvidia/nemotron-nano-9b-v2", "nemotron-nano"),
            ("nemotron", "nemotron-super"),
        ] {
            assert_eq!(family(model).as_deref(), Some(want), "{model}");
        }
        for kind in ALL {
            assert!(
                at("nemotron-ultra", kind) >= at("nemotron-super", kind),
                "{kind:?}"
            );
            assert!(
                at("nemotron-super", kind) > at("nemotron-nano", kind),
                "{kind:?}"
            );
        }
        // Words and chores it does well, reviews and plans it does not.
        assert!(at("nemotron-super", WorkKind::Docs) > at("nemotron-super", WorkKind::Review));
        assert!(at("nemotron-super", WorkKind::Chore) > at("nemotron-super", WorkKind::Plan));
        // An older one named by size is a Nemotron, scaled, and not a Llama.
        let old = profile_for(Some("nvidia/llama-3.1-nemotron-70b-instruct"), "").unwrap();
        assert_eq!(old.family, "nemotron ~70b");
    }

    #[test]
    fn qwen_scales_with_the_parameter_count_in_the_name() {
        for kind in ALL {
            let sizes = ["qwen2.5:7b", "qwen2.5:14b", "qwen2.5:32b", "qwen2.5:72b"];
            let priors: Vec<f64> = sizes.iter().map(|m| at(m, kind)).collect();
            assert!(
                priors.windows(2).all(|w| w[0] < w[1]),
                "{kind:?} {priors:?}"
            );
        }
        assert_eq!(family("qwen2.5:14b-instruct").as_deref(), Some("qwen ~14b"));
        // A 14b is a fair chore and docs engine and not a reviewer.
        assert!(at("qwen2.5:14b-instruct", WorkKind::Chore) >= 0.70 - 1e-9);
        assert!(at("qwen2.5:14b-instruct", WorkKind::Docs) >= 0.70 - 1e-9);
        assert!(at("qwen2.5:14b-instruct", WorkKind::Review) < 0.70);
        // A 7b earns nothing at the bar.
        for kind in ALL {
            assert!(at("qwen2.5:7b", kind) < 0.70, "{kind:?}");
        }
        // Coder variants are stronger on code and tests, weaker at everything else.
        assert!(
            at("qwen2.5-coder:32b", WorkKind::CodeChange) > at("qwen2.5:32b", WorkKind::CodeChange)
        );
        assert!(at("qwen2.5-coder:32b", WorkKind::Tests) > at("qwen2.5:32b", WorkKind::Tests));
        assert!(at("qwen2.5-coder:32b", WorkKind::Plan) < at("qwen2.5:32b", WorkKind::Plan));
        assert!(at("qwen2.5-coder:32b", WorkKind::Docs) < at("qwen2.5:32b", WorkKind::Docs));
        assert!(
            profile_for(Some("qwen2.5-coder:32b"), "")
                .unwrap()
                .credits("code")
        );
        // Vision variants are a little worse at text work than the text model.
        let vl = profile_for(Some("qwen2.5vl:7b"), "").unwrap();
        assert_eq!(vl.family, "qwen-vl ~7b");
        for kind in [WorkKind::CodeChange, WorkKind::Review, WorkKind::Plan] {
            assert!(
                vl.prior(kind, Size::Medium).unwrap() < at("qwen2.5:7b", kind),
                "{kind:?}"
            );
        }
        assert_eq!(
            family("qwen2-vl-72b-instruct").as_deref(),
            Some("qwen-vl ~72b")
        );
        // Qwen3 is a step on from 2.5 at the same size.
        assert!(at("qwen3:14b", WorkKind::Docs) > at("qwen2.5:14b", WorkKind::Docs));
        // A mixture of experts is scaled by the geometric mean of total and active.
        assert_eq!(family("qwen3-235b-a22b").as_deref(), Some("qwen ~72b"));
        assert_eq!(family("qwen3-30b-a3b").as_deref(), Some("qwen ~9.5b"));
        // With no size in the name it is scaled as a 14b, `max` as a large one.
        assert_eq!(family("qwen-turbo").as_deref(), Some("qwen ~14b"));
        assert_eq!(family("qwen-max").as_deref(), Some("qwen ~200b"));
        assert_eq!(family("qwq-32b").as_deref(), Some("qwq ~32b"));
    }

    #[test]
    fn glm_llama_mistral_and_kimi() {
        for (model, want) in [
            ("glm-4.7", "glm-4.x"),
            ("glm-4.6", "glm-4.x"),
            ("zai/glm-4.5-air", "glm-air"),
            ("glm-4.7-flash", "glm-flash"),
            ("glm-4-9b-chat", "glm ~9b"),
            ("llama3.1:8b", "llama ~8b"),
            ("codellama:13b", "llama ~13b"),
            ("meta-llama/Llama-3.3-70B-Instruct", "llama ~70b"),
            ("llama-4-scout-17b-16e-instruct", "llama ~60b"),
            ("llama-4-maverick", "llama ~100b"),
            ("mistral-large-2411", "mistral ~123b"),
            ("mistral-small-3.1", "mistral ~24b"),
            ("mistral", "mistral ~7b"),
            ("mixtral-8x7b-instruct", "mistral ~21b"),
            ("ministral-8b", "mistral ~8b"),
            ("codestral-25.01", "codestral ~22b"),
            ("devstral-small", "devstral ~24b"),
            ("kimi-k2-instruct", "kimi"),
            ("moonshotai/Kimi-K2.5", "kimi"),
        ] {
            assert_eq!(family(model).as_deref(), Some(want), "{model}");
        }
        assert!(at("glm-4.7", WorkKind::CodeChange) > at("glm-air", WorkKind::CodeChange));
        assert!(at("glm-air", WorkKind::CodeChange) > at("glm-flash", WorkKind::CodeChange));
        assert!(at("llama3.3:70b", WorkKind::Docs) > at("llama3.1:8b", WorkKind::Docs));
        // Code specialists: good at code and tests, poor planners, and counted as code.
        for model in ["codestral", "devstral"] {
            assert!(at(model, WorkKind::CodeChange) > at(model, WorkKind::Plan) + 0.10);
            assert!(profile_for(Some(model), "").unwrap().credits("code"));
        }
        assert!(at("devstral", WorkKind::CodeChange) > at("mistral-small", WorkKind::CodeChange));
    }

    #[test]
    fn a_model_the_table_does_not_know_has_no_profile() {
        for model in [
            "gemma-3-27b",
            "phi-4",
            "gpt-oss-120b",
            "gpt-4o",
            "moonshot-v1-8k",
            "my-finetune",
            "llava:7b",
        ] {
            assert!(family(model).is_none(), "{model}");
        }
        assert!(profile_for(None, "nvidia").is_none());
        assert!(profile_for(None, "ollama").is_none());
        // The runner's name does not matter when the model is known, or when it is not.
        assert_eq!(
            profile_for(Some("qwen2.5:14b"), "ollama").unwrap().family,
            "qwen ~14b"
        );
        assert!(profile_for(Some("my-finetune"), "ollama").is_none());
        assert!(profile_for(Some(""), "").is_none());
    }

    #[test]
    fn large_work_takes_a_step_off_for_each_class_below_large() {
        let large = profile_for(Some("sonnet"), "").unwrap();
        let medium = profile_for(Some("deepseek-v4"), "").unwrap();
        let small = profile_for(Some("haiku"), "").unwrap();
        let docs = |p: &Profile, size| p.prior(WorkKind::Docs, size).unwrap();
        assert!((docs(&large, Size::Large) - docs(&large, Size::Medium)).abs() < 1e-9);
        assert!((docs(&medium, Size::Medium) - docs(&medium, Size::Large) - 0.05).abs() < 1e-9);
        assert!((docs(&small, Size::Medium) - docs(&small, Size::Large) - 0.10).abs() < 1e-9);
        // Small work takes nothing off.
        assert!((docs(&small, Size::Small) - docs(&small, Size::Medium)).abs() < 1e-9);
    }

    #[test]
    fn media_kinds_have_no_prior_and_other_is_the_average() {
        let profile = profile_for(Some("opus"), "").unwrap();
        for kind in [
            WorkKind::Transcribe,
            WorkKind::Image,
            WorkKind::Video,
            WorkKind::Audio,
        ] {
            assert!(profile.prior(kind, Size::Medium).is_none(), "{kind:?}");
        }
        let mean = ALL
            .iter()
            .map(|kind| profile.prior(*kind, Size::Medium).unwrap())
            .sum::<f64>()
            / 8.0;
        assert!((profile.prior(WorkKind::Other, Size::Medium).unwrap() - mean).abs() < 1e-9);
    }

    #[test]
    fn sizes_are_read_from_names_and_the_level_grows_with_them() {
        let tokens = |text: &str| Name::new(text).tokens;
        assert_eq!(parameters(&tokens("llama3.1:8b")), Some(8.0));
        assert_eq!(parameters(&tokens("model-1.5b-chat")), Some(1.5));
        assert_eq!(parameters(&tokens("mixtral-8x22b")), Some(66.0));
        assert_eq!(parameters(&tokens("glm-4.7-flash")), None);
        let moe = parameters(&tokens("nemotron-3-super-120b-a12b")).unwrap();
        assert!((moe - (120.0_f64 * 12.0).sqrt()).abs() < 1e-9);
        // The anchors are exact, between them it rises, and it stops at either end.
        assert!((level(7.0) - 0.58).abs() < 1e-9);
        assert!((level(14.0) - 0.66).abs() < 1e-9);
        assert!((level(72.0) - 0.80).abs() < 1e-9);
        assert!(level(20.0) > level(14.0) && level(20.0) < level(32.0));
        assert!((level(0.1) - 0.40).abs() < 1e-9);
        assert!((level(2000.0) - 0.88).abs() < 1e-9);
    }

    #[test]
    fn every_prior_is_a_conservative_probability() {
        for model in [
            "opus",
            "sonnet",
            "haiku",
            "gpt-5",
            "gpt-5-codex",
            "gemini-pro",
            "deepseek-v4-pro",
            "deepseek-r1",
            "nemotron-ultra",
            "qwen3-coder:480b",
            "qwen2.5:0.5b",
            "glm-4.7",
            "llama3.1:405b",
            "mistral-large",
            "kimi-k2",
        ] {
            for size in [Size::Small, Size::Medium, Size::Large] {
                for kind in ALL {
                    let p = profile_for(Some(model), "")
                        .unwrap()
                        .prior(kind, size)
                        .unwrap();
                    assert!((0.05..=0.95).contains(&p), "{model} {kind:?}: {p}");
                }
            }
        }
        // Nothing starts at certainty: the best row is still under 0.95.
        assert!(at("opus", WorkKind::Plan) < 0.95);
    }
}
