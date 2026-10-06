//! The `SUGGESTIONS` record: a project's master opening it to outside suggestions.
//!
//! ```text
//! <project channel>/SUGGESTIONS                    the master's signed record, with a seq
//! <project channel>/suggestion-terms/<sha>.md     every terms text ever offered, by hash
//! ```
//!
//! The same shape as `FOCUS` and `ENGINE_POLICY`: honoured only when the project's master
//! signed it, over exactly what it says, with the project id in the signed payload; checked
//! every time it is read; and each machine remembers - outside the synced folder - the
//! highest `seq` it has accepted and the last good record, so an older signed copy put back,
//! or the file deleted, leaves the last good one in force and raises a notice.
//!
//! The public half of it is the [`Offer`]: signed on its own by the owner's key, so it can be
//! put in an invite or in the inbox repository and checked by someone who is on no roster.

use std::collections::BTreeMap;
use std::path::Path;

use anyhow::{Context, Result, bail};
use chrono::{DateTime, Utc};
use serde::{Deserialize, Serialize};

use super::inbox::InboxRef;
use super::{has_hidden_text, is_hidden, sealed_payload, sha256_hex, verify_hex};
use crate::policy::{Signed, notice, resolve};
use crate::{AgentIdentity, SignatureCheck, check_signature};

/// The file inside the project's channel.
pub const SUGGESTIONS: &str = "SUGGESTIONS";
/// What an [`Offer`] says it is.
pub const OFFER_FORMAT: &str = "ferryman-offer/v1";
/// The terms file in the inbox repository.
pub const TERMS_FILE: &str = "TERMS.md";
/// The machine-readable page in the inbox repository; its `offer` is the signed [`Offer`].
pub const OFFER_FILE: &str = "ferryman-suggest.json";
/// Longest terms text accepted.
pub const MAX_TERMS_BYTES: usize = 64 * 1024;
/// A line the shipped template carries, so an untouched copy is recognised.
pub const DRAFT_MARKER: &str = "FERRYMAN-DRAFT-TERMS";
/// The shipped draft terms: a starting point for the owner and their lawyer, not terms.
pub const TEMPLATE: &str = include_str!("../../../../docs/templates/SUGGESTION_TERMS.md");

/// The fields every suggestion has, before the type's own.
pub const BASE_FIELDS: [&str; 3] = ["title", "pitch", "why"];

/// One field a kind of suggestion has, with its hard cap.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct FieldSpec {
    pub id: String,
    pub label: String,
    pub max: usize,
    #[serde(default)]
    pub required: bool,
}

/// A kind of suggestion the project takes, and the fields it adds to title, pitch and why.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct TypeSpec {
    pub id: String,
    pub label: String,
    #[serde(default)]
    pub fields: Vec<FieldSpec>,
}

/// Caps and rates. The defaults are what the owner gets without saying anything.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct Limits {
    pub title_max: usize,
    pub pitch_max: usize,
    pub why_max: usize,
    /// Suggestions one contributor may have open at once.
    pub open_per_contributor: u32,
    /// New suggestions one contributor may send in 24 hours.
    pub new_per_day: u32,
    /// How many times the owner's side may ask the contributor to clarify.
    pub clarification_rounds: u32,
    /// Days the contributor has to answer a question before the suggestion is closed.
    pub answer_days: u32,
}

impl Default for Limits {
    fn default() -> Self {
        Self {
            title_max: 80,
            pitch_max: 1000,
            why_max: 500,
            open_per_contributor: 3,
            new_per_day: 1,
            clarification_rounds: 2,
            answer_days: 14,
        }
    }
}

/// Which terms a suggestion is sent under.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct TermsRef {
    pub version: u32,
    pub sha256: String,
    /// The path in the inbox repository.
    pub file: String,
}

/// Whether the project is taking suggestions.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum Status {
    Open,
    Closed,
}

/// What the owner publishes: everything a contributor needs to know, signed by the owner.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct Offer {
    pub format: String,
    pub project_id: String,
    /// What the product is called to the outside.
    pub display_name: String,
    /// `github:owner/repo`.
    pub inbox: String,
    pub terms: TermsRef,
    pub types: Vec<TypeSpec>,
    pub limits: Limits,
    pub status: Status,
    /// The owner's name and public key: what the invite is checked against, and pinned.
    pub owner: String,
    pub owner_key: String,
    pub issued_at: DateTime<Utc>,
    /// The record's `seq` when this was signed: an older offer cannot stand for a newer one.
    pub seq: u64,
    pub signature: String,
}

impl Offer {
    /// Exactly what `signature` covers.
    #[must_use]
    pub fn payload(&self) -> String {
        sealed_payload("ferryman-offer-v1", self)
    }

    /// Whether the owner's key signed this offer.
    #[must_use]
    pub fn verify(&self) -> bool {
        self.format == OFFER_FORMAT
            && verify_hex(
                &self.owner,
                &self.owner_key,
                &self.payload(),
                &self.signature,
            )
    }

    #[must_use]
    pub fn is_open(&self) -> bool {
        self.status == Status::Open
    }

    #[must_use]
    pub fn type_spec(&self, id: &str) -> Option<&TypeSpec> {
        self.types.iter().find(|spec| spec.id == id)
    }

    /// A short, readable fingerprint of the owner's key, for a person to compare.
    #[must_use]
    pub fn fingerprint(&self) -> String {
        sha256_hex(self.owner_key.as_bytes())[..16].to_string()
    }

    /// Where the terms are, for a person to open: in the inbox repository.
    ///
    /// # Errors
    /// An inbox that is not one this version understands.
    pub fn terms_url(&self) -> Result<String> {
        Ok(InboxRef::parse(&self.inbox)?.file_url(&self.terms.file))
    }

    /// Every field a suggestion of `kind` may carry: `(id, label, cap, required)`.
    #[must_use]
    pub fn field_specs(&self, kind: &str) -> Vec<(String, String, usize, bool)> {
        let mut specs = vec![
            (
                "title".to_string(),
                "Title".to_string(),
                self.limits.title_max,
                true,
            ),
            (
                "pitch".to_string(),
                "Pitch".to_string(),
                self.limits.pitch_max,
                true,
            ),
            (
                "why".to_string(),
                "Why it fits".to_string(),
                self.limits.why_max,
                true,
            ),
        ];
        if let Some(spec) = self.type_spec(kind) {
            specs.extend(spec.fields.iter().map(|field| {
                (
                    field.id.clone(),
                    field.label.clone(),
                    field.max,
                    field.required,
                )
            }));
        }
        specs
    }

    /// What is wrong with a suggestion's fields, said precisely enough to fix: empty when
    /// it fits. The same caps are enforced on the owner's side, so this is a courtesy to
    /// the contributor and never the only check.
    #[must_use]
    pub fn check_fields(&self, kind: &str, fields: &BTreeMap<String, String>) -> Vec<String> {
        let mut problems = Vec::new();
        if self.type_spec(kind).is_none() {
            let ids: Vec<&str> = self.types.iter().map(|spec| spec.id.as_str()).collect();
            problems.push(format!(
                "'{kind}' is not a kind of suggestion this project takes (it takes: {})",
                ids.join(", ")
            ));
            return problems;
        }
        let specs = self.field_specs(kind);
        for key in fields.keys() {
            if !specs.iter().any(|(id, ..)| id == key) {
                problems.push(format!("'{key}' is not a field of a {kind} suggestion"));
            }
        }
        let mut total = 0usize;
        for (id, label, max, required) in &specs {
            let value = fields.get(id).map_or("", |value| value.trim());
            if value.is_empty() {
                if *required {
                    problems.push(format!("{label} is required"));
                }
                continue;
            }
            let count = value.chars().count();
            total += count;
            if count > *max {
                problems.push(format!(
                    "{label} is {count} characters; the limit is {max} (cut {})",
                    count - max
                ));
            }
            if value
                .chars()
                .any(|c| c.is_control() && !matches!(c, '\n' | '\t'))
            {
                problems.push(format!("{label} has control characters in it"));
            }
            if value.chars().any(is_hidden) {
                problems.push(format!(
                    "{label} has hidden or direction-changing characters in it (zero-width \
                     spaces, text-direction marks): take them out"
                ));
            }
            if id == "title" && value.contains('\n') {
                problems.push("Title is one line".to_string());
            }
        }
        if total > 12_000 {
            problems.push("the whole suggestion is too long".to_string());
        }
        problems
    }
}

/// Where the owner's own rubric and canon are, for the triage model: paths inside the
/// project's own repository, never sent to anyone but the model.
#[derive(Debug, Clone, Default, PartialEq, Eq, Serialize, Deserialize)]
pub struct TriageConfig {
    /// What counts as a good suggestion here (`docs/suggestions/TRIAGE.md`).
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub rubric: Option<String>,
    /// What the product is and is not (`docs/design/CANON.md`).
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub canon: Option<String>,
}

impl TriageConfig {
    fn is_empty(&self) -> bool {
        self.rubric.is_none() && self.canon.is_none()
    }
}

/// What the `SUGGESTIONS` file holds.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct SuggestionsRecord {
    pub project_id: String,
    pub offer: Offer,
    /// The full terms text. Its hash is in the signed offer.
    pub terms_text: String,
    #[serde(default, skip_serializing_if = "TriageConfig::is_empty")]
    pub triage: TriageConfig,
    pub set_at: DateTime<Utc>,
    pub signed_by: String,
    pub signature: String,
    pub seq: u64,
}

fn safe_relative(path: &str) -> bool {
    !path.is_empty()
        && path.len() <= 200
        && !path.starts_with('/')
        && !path.starts_with('\\')
        && !path.contains(':')
        && !path
            .split(['/', '\\'])
            .any(|part| part == ".." || part.is_empty())
}

impl SuggestionsRecord {
    fn payload(&self) -> String {
        format!(
            "ferryman-suggestions-v1\n{}\n{}\nseq:{}\n{}\n{}",
            self.project_id,
            self.set_at.to_rfc3339(),
            self.seq,
            self.offer.signature,
            serde_jcs::to_string(&self.triage).unwrap_or_default()
        )
    }

    /// Refuse a record whose parts mean nothing.
    ///
    /// # Errors
    /// The first thing that is wrong.
    pub fn check(&self) -> Result<()> {
        let offer = &self.offer;
        if !crate::is_safe_component(&self.project_id) || offer.project_id != self.project_id {
            bail!("the offer is for a different project than the record");
        }
        let name_len = offer.display_name.trim().chars().count();
        if !(1..=80).contains(&name_len)
            || offer
                .display_name
                .chars()
                .any(|c| c.is_control() || is_hidden(c))
        {
            bail!("the product's name is 1 to 80 characters, on one line");
        }
        InboxRef::parse(&offer.inbox)?;
        if offer.terms.version == 0 || offer.terms.file != TERMS_FILE {
            bail!("the terms need a version, and live in {TERMS_FILE}");
        }
        if self.terms_text.trim().is_empty() || self.terms_text.len() > MAX_TERMS_BYTES {
            bail!("the terms are empty or longer than {MAX_TERMS_BYTES} bytes");
        }
        if sha256_hex(self.terms_text.as_bytes()) != offer.terms.sha256 {
            bail!("the terms text does not hash to the value the offer names");
        }
        if offer.types.is_empty() || offer.types.len() > 12 {
            bail!("a project takes between 1 and 12 kinds of suggestion");
        }
        let mut seen = Vec::new();
        for spec in &offer.types {
            if !crate::is_safe_component(&spec.id) || spec.id.len() > 24 || spec.label.len() > 60 {
                bail!(
                    "a kind of suggestion is a short id (letters, digits, '-', '_'), not '{}'",
                    spec.id
                );
            }
            if seen.contains(&&spec.id) {
                bail!("the kind '{}' is listed twice", spec.id);
            }
            seen.push(&spec.id);
            if spec.fields.len() > 8 {
                bail!("a kind has at most 8 fields of its own");
            }
            let mut field_ids = Vec::new();
            for field in &spec.fields {
                if !crate::is_safe_component(&field.id)
                    || field.id.len() > 24
                    || BASE_FIELDS.contains(&field.id.as_str())
                    || field_ids.contains(&&field.id)
                {
                    bail!("'{}' is not a usable field id for '{}'", field.id, spec.id);
                }
                field_ids.push(&field.id);
                if !(1..=2000).contains(&field.max) {
                    bail!("the cap on '{}' is 1 to 2000 characters", field.id);
                }
            }
        }
        let limits = &offer.limits;
        let fine = (1..=200).contains(&limits.title_max)
            && (1..=4000).contains(&limits.pitch_max)
            && (1..=2000).contains(&limits.why_max)
            && (1..=20).contains(&limits.open_per_contributor)
            && (1..=20).contains(&limits.new_per_day)
            && limits.clarification_rounds <= 5
            && (1..=90).contains(&limits.answer_days);
        if !fine {
            bail!(
                "limits out of range: title 1-200, pitch 1-4000, why 1-2000, open 1-20, per day \
                 1-20, rounds 0-5, answer window 1-90 days"
            );
        }
        for path in [&self.triage.rubric, &self.triage.canon]
            .into_iter()
            .flatten()
        {
            if !safe_relative(path) {
                bail!("'{path}' is not a path inside the project's repository");
            }
        }
        Ok(())
    }
}

impl Signed for SuggestionsRecord {
    const FILE: &'static str = SUGGESTIONS;
    const STATE: &'static str = "suggestions";
    const LABEL: &'static str = "suggestions record";
    const QUESTION: &'static str = "suggestions";
    fn seq(&self) -> u64 {
        self.seq
    }
    fn set_at(&self) -> DateTime<Utc> {
        self.set_at
    }
    /// Whether this is the master's word for `project_id`, read in its channel: signed by
    /// the master over what it says (and the offer by the master's key), with the terms
    /// text hashing to what the offer names.
    fn is_genuine(&self, channel: &Path, project_id: &str) -> bool {
        let Ok(roster) = crate::read_agent_roster(channel) else {
            return false;
        };
        let Ok(Some(master)) = crate::master::read_master_at(channel, &roster) else {
            return false;
        };
        let master_key = roster
            .iter()
            .find(|agent| agent.name.eq_ignore_ascii_case(&master.master))
            .and_then(|agent| agent.public_key.clone());
        self.project_id == project_id
            && master.project_id == project_id
            && self.seq >= 1
            && self.offer.seq == self.seq
            && self.signed_by.eq_ignore_ascii_case(&master.master)
            && self.offer.owner.eq_ignore_ascii_case(&master.master)
            && master_key.as_deref() == Some(self.offer.owner_key.as_str())
            && self.offer.verify()
            && self.check().is_ok()
            && check_signature(
                Some(&self.signed_by),
                Some(&self.signature),
                &self.payload(),
                &roster,
            ) == SignatureCheck::Valid
    }
}

// --- reading ---------------------------------------------------------------------------

/// The record in force for `project_id`, as read and verified now. When the channel's file
/// went back or vanished this is the last good one this machine saw.
#[must_use]
pub fn current(channel: &Path, project_id: &str) -> Option<SuggestionsRecord> {
    resolve::<SuggestionsRecord>(channel, project_id).setting
}

/// What is wrong with the channel's record, when this machine is holding on to an earlier one.
#[must_use]
pub fn rollback_notice(channel: &Path, project_id: &str) -> Option<String> {
    notice::<SuggestionsRecord>(channel, project_id)
}

/// Whether the project is taking suggestions now.
#[must_use]
pub fn is_open(channel: &Path, project_id: &str) -> bool {
    current(channel, project_id).is_some_and(|record| record.offer.is_open())
}

// --- the terms guard -------------------------------------------------------------------

/// What the template's placeholders are called, so one whose braces were mangled is still
/// recognised.
const PLACEHOLDER_NAMES: [&str; 8] = [
    "product_name",
    "owner_name",
    "inbox_url",
    "product_license",
    "payment_statement",
    "credits_location",
    "governing_law",
    "contact_email",
];

/// Sentences only the shipped template says (folded, see [`fold_for_guard`]).
const DRAFT_SENTENCES: [&str; 3] = [
    "replacethistextwithtermsyoustandbehind",
    "ferrymandoesnotwriteyourterms",
    "startingpointfortheownerandtheirlawyer",
];

/// `text` lowercased, with every space, line break, hyphen and hidden character removed and the
/// look-alike braces folded to `{` and `}`: what the draft guard compares, so case, spacing,
/// zero-width characters and full-width braces do not get a draft past it.
fn fold_for_guard(text: &str) -> String {
    text.chars()
        .filter(|c| !c.is_whitespace() && *c != '-' && !is_hidden(*c))
        .map(|c| match c {
            '\u{FF5B}' | '\u{2774}' | '\u{FE5B}' | '\u{2983}' => '{',
            '\u{FF5D}' | '\u{2775}' | '\u{FE5C}' | '\u{2984}' => '}',
            other => other,
        })
        .flat_map(char::to_lowercase)
        .collect()
}

/// Whether `text` is the shipped template, or still carries what must be filled in: the
/// marker line, a `{{placeholder}}` (however the braces are spaced or spelled), a
/// placeholder's name, a sentence only the template says, or the template itself.
#[must_use]
pub fn is_draft(text: &str) -> bool {
    let folded = fold_for_guard(text);
    folded.contains(&fold_for_guard(DRAFT_MARKER))
        || folded.contains("{{")
        || folded.contains("}}")
        || PLACEHOLDER_NAMES.iter().any(|name| folded.contains(name))
        || DRAFT_SENTENCES.iter().any(|line| folded.contains(line))
        || folded == fold_for_guard(TEMPLATE)
}

fn ensure_terms(text: &str, accept_draft: bool) -> Result<()> {
    if text.trim().is_empty() {
        bail!("the terms file is empty");
    }
    if text.len() > MAX_TERMS_BYTES {
        bail!("the terms are longer than {MAX_TERMS_BYTES} bytes");
    }
    if has_hidden_text(text) {
        bail!(
            "the terms have a control character, a zero-width character or a text-direction \
             mark in them. A person is asked to agree to what they see, and those change what \
             a screen shows: take them out (an escape sequence in a terms file is never right)"
        );
    }
    if is_draft(text) && !accept_draft {
        bail!(
            "these terms are still the DRAFT template (or have {{{{placeholders}}}} left in them). \
             Ferryman does not write your terms and this is not legal advice: replace the draft \
             with terms you stand behind, or pass --accept-draft-terms to publish it as it is"
        );
    }
    Ok(())
}

// --- the types and limits an owner writes ----------------------------------------------

fn capitalise(id: &str) -> String {
    let mut chars = id.chars();
    chars.next().map_or_else(String::new, |first| {
        first.to_uppercase().chain(chars).collect::<String>()
    })
}

fn field(id: &str, max: usize, required: bool) -> FieldSpec {
    FieldSpec {
        id: id.to_string(),
        label: capitalise(id),
        max,
        required,
    }
}

/// The kinds a project takes when its owner names none.
#[must_use]
pub fn default_types() -> Vec<TypeSpec> {
    ["idea", "bug", "content"]
        .iter()
        .map(|id| builtin_type(id))
        .collect()
}

fn builtin_type(id: &str) -> TypeSpec {
    let fields = match id {
        "bug" => vec![field("steps", 500, true), field("expected", 300, false)],
        "content" => vec![field("where", 200, false)],
        "balance" => vec![field("numbers", 400, true)],
        _ => Vec::new(),
    };
    TypeSpec {
        id: id.to_string(),
        label: capitalise(id),
        fields,
    }
}

/// `idea,bug:steps=500!+expected=300,content:where=200`: kinds separated by commas; after a
/// colon the kind's own fields, each `id=cap`, joined by `+`, a trailing `!` meaning
/// required. A bare kind uses the built-in fields when it has some (`bug`, `content`,
/// `balance`), none otherwise.
///
/// # Errors
/// A kind or field that means nothing.
pub fn parse_types(spec: &str) -> Result<Vec<TypeSpec>> {
    let mut types = Vec::new();
    for part in spec
        .split(',')
        .map(str::trim)
        .filter(|part| !part.is_empty())
    {
        let (id, extras) = part.split_once(':').unwrap_or((part, ""));
        let id = id.trim().to_ascii_lowercase();
        if !crate::is_safe_component(&id) {
            bail!("a kind of suggestion is letters, digits, '-' or '_', not '{id}'");
        }
        let mut kind = builtin_type(&id);
        if !extras.trim().is_empty() {
            kind.fields.clear();
            for item in extras
                .split('+')
                .map(str::trim)
                .filter(|item| !item.is_empty())
            {
                let (name, cap) = item
                    .split_once('=')
                    .with_context(|| format!("a field is id=cap, not '{item}'"))?;
                let (cap, required) = cap
                    .trim()
                    .strip_suffix('!')
                    .map_or((cap.trim(), false), |cap| (cap.trim(), true));
                let cap: usize = cap
                    .parse()
                    .with_context(|| format!("the cap on '{name}' is a number, not '{cap}'"))?;
                kind.fields.push(field(name.trim(), cap, required));
            }
        }
        types.push(kind);
    }
    if types.is_empty() {
        bail!("name at least one kind of suggestion");
    }
    Ok(types)
}

/// `open=3,per_day=1,rounds=2,days=14,title=80,pitch=1000,why=500` laid over `limits`.
///
/// # Errors
/// A name that is not one of those, or a value that is not a number.
pub fn parse_limits(spec: &str, mut limits: Limits) -> Result<Limits> {
    for part in spec
        .split(',')
        .map(str::trim)
        .filter(|part| !part.is_empty())
    {
        let (name, value) = part
            .split_once('=')
            .with_context(|| format!("a limit is name=number, not '{part}'"))?;
        let number: u32 = value
            .trim()
            .parse()
            .with_context(|| format!("'{value}' is not a number"))?;
        let size = number as usize;
        match name.trim() {
            "open" => limits.open_per_contributor = number,
            "per_day" | "day" => limits.new_per_day = number,
            "rounds" => limits.clarification_rounds = number,
            "days" => limits.answer_days = number,
            "title" => limits.title_max = size,
            "pitch" => limits.pitch_max = size,
            "why" => limits.why_max = size,
            other => {
                bail!("unknown limit '{other}' (open, per_day, rounds, days, title, pitch, why)")
            }
        }
    }
    Ok(limits)
}

// --- signing ---------------------------------------------------------------------------

/// What an owner chooses when they open a project.
#[derive(Debug, Clone)]
pub struct OpenArgs {
    pub display_name: String,
    pub inbox: String,
    pub terms_text: String,
    pub types: Vec<TypeSpec>,
    pub limits: Limits,
    pub triage: TriageConfig,
    /// Publish the draft template as it is.
    pub accept_draft_terms: bool,
}

struct Draft {
    display_name: String,
    inbox: String,
    terms_text: String,
    terms_version: u32,
    types: Vec<TypeSpec>,
    limits: Limits,
    status: Status,
    triage: TriageConfig,
}

fn commit(
    channel: &Path,
    project_id: &str,
    signer: &AgentIdentity,
    now: DateTime<Utc>,
    build: impl FnOnce(Option<&SuggestionsRecord>) -> Result<Draft>,
) -> Result<SuggestionsRecord> {
    if !channel.is_dir() {
        bail!(
            "{project_id}'s channel is not on this machine ({})",
            channel.display()
        );
    }
    crate::ferry::require_master(channel, project_id, signer, "open it to suggestions")?;
    let resolved = resolve::<SuggestionsRecord>(channel, project_id);
    let draft = build(resolved.setting.as_ref())?;
    let seq = resolved
        .high
        .max(resolved.setting.as_ref().map_or(0, |record| record.seq))
        + 1;
    let mut offer = Offer {
        format: OFFER_FORMAT.to_string(),
        project_id: project_id.to_string(),
        display_name: draft.display_name.trim().to_string(),
        inbox: InboxRef::parse(&draft.inbox)?.spec(),
        terms: TermsRef {
            version: draft.terms_version,
            sha256: sha256_hex(draft.terms_text.as_bytes()),
            file: TERMS_FILE.to_string(),
        },
        types: draft.types,
        limits: draft.limits,
        status: draft.status,
        owner: signer.name().to_string(),
        owner_key: signer.public_key_hex(),
        issued_at: now,
        seq,
        signature: String::new(),
    };
    offer.signature = signer.sign_bytes(offer.payload().as_bytes());
    let mut record = SuggestionsRecord {
        project_id: project_id.to_string(),
        offer,
        terms_text: draft.terms_text,
        triage: draft.triage,
        set_at: now,
        signed_by: signer.name().to_string(),
        signature: String::new(),
        seq,
    };
    record.check()?;
    record.signature = signer.sign_bytes(record.payload().as_bytes());
    // Every text ever offered, by hash: the legal record of what an acceptance meant.
    // Not `suggestions/`: on a case-insensitive disk that is the same name as the record.
    let archive = channel.join("suggestion-terms");
    std::fs::create_dir_all(&archive)?;
    let kept = archive.join(format!("{}.md", record.offer.terms.sha256));
    if !kept.exists() {
        std::fs::write(&kept, record.terms_text.as_bytes())?;
    }
    let path = channel.join(SUGGESTIONS);
    crate::atomic_json(&path, &record).with_context(|| format!("writing {}", path.display()))?;
    Ok(record)
}

/// Open the project to suggestions, signed as its master: new, or again with new choices.
/// The terms version goes up when the text changed.
///
/// # Errors
/// A signer who is not the project's master, a draft terms text without `accept_draft_terms`,
/// or a record whose parts mean nothing.
pub fn open(
    channel: &Path,
    project_id: &str,
    signer: &AgentIdentity,
    args: OpenArgs,
    now: DateTime<Utc>,
) -> Result<SuggestionsRecord> {
    ensure_terms(&args.terms_text, args.accept_draft_terms)?;
    commit(channel, project_id, signer, now, |existing| {
        let terms_version = match existing {
            Some(record) if record.offer.terms.sha256 == sha256_hex(args.terms_text.as_bytes()) => {
                record.offer.terms.version
            }
            Some(record) => record.offer.terms.version + 1,
            None => 1,
        };
        Ok(Draft {
            display_name: args.display_name,
            inbox: args.inbox,
            terms_text: args.terms_text,
            terms_version,
            types: args.types,
            limits: args.limits,
            status: Status::Open,
            triage: args.triage,
        })
    })
}

fn same_with(record: &SuggestionsRecord, status: Status, terms: Option<(String, u32)>) -> Draft {
    let (terms_text, terms_version) =
        terms.unwrap_or_else(|| (record.terms_text.clone(), record.offer.terms.version));
    Draft {
        display_name: record.offer.display_name.clone(),
        inbox: record.offer.inbox.clone(),
        terms_text,
        terms_version,
        types: record.offer.types.clone(),
        limits: record.offer.limits.clone(),
        status,
        triage: record.triage.clone(),
    }
}

/// Stop taking suggestions, signed. What is already in flight is still decided, answered
/// and built. Returns whether anything changed.
///
/// # Errors
/// A signer who is not the master, or a project that was never opened.
pub fn close(
    channel: &Path,
    project_id: &str,
    signer: &AgentIdentity,
    now: DateTime<Utc>,
) -> Result<bool> {
    let Some(existing) = current(channel, project_id) else {
        bail!("{project_id} has not been opened to suggestions");
    };
    if !existing.offer.is_open() {
        return Ok(false);
    }
    commit(channel, project_id, signer, now, |record| {
        Ok(same_with(
            record.context("the record is gone")?,
            Status::Closed,
            None,
        ))
    })?;
    Ok(true)
}

/// Replace the terms: a new version, so every earlier acceptance stops counting for new
/// submissions (what is already in flight keeps the terms it was sent under).
///
/// # Errors
/// A signer who is not the master, a project never opened, draft terms without
/// `accept_draft_terms`, or terms that did not change.
pub fn set_terms(
    channel: &Path,
    project_id: &str,
    signer: &AgentIdentity,
    terms_text: &str,
    accept_draft_terms: bool,
    now: DateTime<Utc>,
) -> Result<SuggestionsRecord> {
    ensure_terms(terms_text, accept_draft_terms)?;
    commit(channel, project_id, signer, now, |record| {
        let record = record.context("open the project to suggestions first")?;
        if record.offer.terms.sha256 == sha256_hex(terms_text.as_bytes()) {
            bail!(
                "those are the terms already in force (version {})",
                record.offer.terms.version
            );
        }
        Ok(same_with(
            record,
            record.offer.status,
            Some((terms_text.to_string(), record.offer.terms.version + 1)),
        ))
    })
}

#[cfg(test)]
pub(crate) mod tests {
    use super::*;
    use crate::{AgentRoute, ProjectRoute};

    pub(crate) const PROJECT: &str = "idle-ish";

    pub(crate) fn person(name: &str, seed: u8) -> AgentIdentity {
        AgentIdentity::from_seed(name, [seed; 32])
    }

    /// The project's channel with its master `members[0]` and every member on its roster,
    /// and this thread's own machine-state directory so rollback memory is never shared.
    pub(crate) fn route(dir: &Path, members: &[&AgentIdentity]) -> ProjectRoute {
        crate::licensing::use_machine_state_dir_per_thread(dir.join("state"));
        let communications = dir.join("idle-ish-ferryman");
        std::fs::create_dir_all(&communications).unwrap();
        let mut route = ProjectRoute {
            project_id: PROJECT.into(),
            workspace: dir.join("idle-ish"),
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

    pub(crate) fn terms() -> String {
        "Terms v1. You grant the owner a license to use your suggestion. No payment. Credit.\n"
            .to_string()
    }

    pub(crate) fn args(terms_text: &str) -> OpenArgs {
        OpenArgs {
            display_name: "Idle-ish".into(),
            inbox: "github:estejosh/idle-ish-ideas".into(),
            terms_text: terms_text.to_string(),
            types: default_types(),
            limits: Limits::default(),
            triage: TriageConfig::default(),
            accept_draft_terms: false,
        }
    }

    pub(crate) fn open_it(route: &ProjectRoute, master: &AgentIdentity) -> SuggestionsRecord {
        open(
            &route.communications,
            PROJECT,
            master,
            args(&terms()),
            Utc::now(),
        )
        .unwrap()
    }

    #[test]
    fn the_master_opens_a_project_and_every_machine_reads_it_back() {
        let dir = tempfile::tempdir().unwrap();
        let josh = person("josh", 1);
        let route = route(dir.path(), &[&josh]);
        assert!(current(&route.communications, PROJECT).is_none());
        let record = open_it(&route, &josh);
        assert_eq!(record.seq, 1);
        assert_eq!(record.offer.terms.version, 1);
        assert!(record.offer.verify());
        let read = current(&route.communications, PROJECT).unwrap();
        assert_eq!(read, record);
        assert!(is_open(&route.communications, PROJECT));
        // The terms are archived by hash.
        let kept = route
            .communications
            .join("suggestion-terms")
            .join(format!("{}.md", record.offer.terms.sha256));
        assert_eq!(std::fs::read_to_string(kept).unwrap(), terms());
        // Closing is a newer record, and re-opening a newer one again.
        assert!(close(&route.communications, PROJECT, &josh, Utc::now()).unwrap());
        assert!(!is_open(&route.communications, PROJECT));
        assert!(!close(&route.communications, PROJECT, &josh, Utc::now()).unwrap());
        assert_eq!(current(&route.communications, PROJECT).unwrap().seq, 2);
    }

    #[test]
    fn only_the_master_signs_and_a_forged_record_is_not_read() {
        let dir = tempfile::tempdir().unwrap();
        let josh = person("josh", 1);
        let mallory = person("mallory", 2);
        let route = route(dir.path(), &[&josh, &mallory]);
        let refused = open(
            &route.communications,
            PROJECT,
            &mallory,
            args(&terms()),
            Utc::now(),
        );
        assert!(refused.is_err(), "a roster member who is not the master");
        assert!(current(&route.communications, PROJECT).is_none());

        let record = open_it(&route, &josh);
        // A machine that has read it once remembers it.
        assert_eq!(current(&route.communications, PROJECT).unwrap(), record);
        // Terms edited after signing: the hash no longer matches.
        let mut edited = record.clone();
        edited
            .terms_text
            .push_str("\nYou also give us your house.\n");
        std::fs::write(
            route.communications.join(SUGGESTIONS),
            serde_json::to_vec(&edited).unwrap(),
        )
        .unwrap();
        let read = resolve::<SuggestionsRecord>(&route.communications, PROJECT);
        assert!(read.from_memory, "the edited file is not honoured");
        assert_eq!(read.setting.unwrap(), record);

        // Re-signed by someone else on the roster, as the master: not the master's key.
        let mut forged = record.clone();
        forged.signed_by = "mallory".into();
        forged.signature = mallory.sign_bytes(forged.payload().as_bytes());
        std::fs::write(
            route.communications.join(SUGGESTIONS),
            serde_json::to_vec(&forged).unwrap(),
        )
        .unwrap();
        assert_eq!(current(&route.communications, PROJECT).unwrap(), record);
    }

    #[test]
    fn an_older_signed_record_put_back_or_a_deleted_file_changes_nothing() {
        let dir = tempfile::tempdir().unwrap();
        let josh = person("josh", 1);
        let route = route(dir.path(), &[&josh]);
        let first = open_it(&route, &josh);
        let older = std::fs::read(route.communications.join(SUGGESTIONS)).unwrap();
        assert!(close(&route.communications, PROJECT, &josh, Utc::now()).unwrap());
        assert!(!is_open(&route.communications, PROJECT));
        // Syncthing (or a person) puts the old, open, signed copy back.
        std::fs::write(route.communications.join(SUGGESTIONS), older).unwrap();
        let after = current(&route.communications, PROJECT).unwrap();
        assert_eq!(after.seq, 2, "the closed record stays in force");
        assert!(!after.offer.is_open());
        assert!(rollback_notice(&route.communications, PROJECT).is_some());
        assert_eq!(first.seq, 1);
        // Deleting the file leaves the last good one in force too.
        std::fs::remove_file(route.communications.join(SUGGESTIONS)).unwrap();
        assert_eq!(current(&route.communications, PROJECT).unwrap().seq, 2);
        // Signing again repairs it, with a newer seq.
        let again = open_it(&route, &josh);
        assert_eq!(again.seq, 3);
    }

    #[test]
    fn new_terms_are_a_new_version_and_the_draft_is_refused() {
        let dir = tempfile::tempdir().unwrap();
        let josh = person("josh", 1);
        let route = route(dir.path(), &[&josh]);
        let first = open_it(&route, &josh);
        let second = set_terms(
            &route.communications,
            PROJECT,
            &josh,
            "Terms v2, changed.\n",
            false,
            Utc::now(),
        )
        .unwrap();
        assert_eq!(second.offer.terms.version, 2);
        assert_ne!(second.offer.terms.sha256, first.offer.terms.sha256);
        assert!(
            set_terms(
                &route.communications,
                PROJECT,
                &josh,
                "Terms v2, changed.\n",
                false,
                Utc::now()
            )
            .is_err(),
            "the same terms again"
        );
        // The untouched template, or one with placeholders, is refused without the flag.
        assert!(is_draft(TEMPLATE));
        assert!(is_draft("Licensed to {{OWNER}} for free."));
        assert!(!is_draft("Licensed to Josh for free."));
        let refused = open(
            &route.communications,
            PROJECT,
            &josh,
            args(TEMPLATE),
            Utc::now(),
        );
        assert!(format!("{:#}", refused.unwrap_err()).contains("DRAFT"));
        let mut accepted = args(TEMPLATE);
        accepted.accept_draft_terms = true;
        assert!(open(&route.communications, PROJECT, &josh, accepted, Utc::now()).is_ok());
    }

    #[test]
    fn the_draft_cannot_get_out_by_spacing_case_or_look_alike_characters() {
        let variants = [
            TEMPLATE.replace("FERRYMAN-DRAFT-TERMS", "ferryman-draft-terms"),
            TEMPLATE.replace("FERRYMAN-DRAFT-TERMS", "Ferryman - Draft - Terms"),
            TEMPLATE.replace("\n", "\r\n"),
            format!("{TEMPLATE}\n\n"),
            TEMPLATE.replace("{{", "{ {").replace("}}", "} }"),
            TEMPLATE.replace("{{", "\u{FF5B}\u{FF5B}").replace("}}", "\u{FF5D}\u{FF5D}"),
            TEMPLATE.replace("{{", "{{ ").replace("}}", " }}"),
            // The marker comment and every brace taken out, but a placeholder name left.
            "Terms for suggestions to {PRODUCT_NAME}. You grant a license.".to_string(),
            "Terms. Contact: [CONTACT_EMAIL]".to_string(),
            // Only the owner's half-finished edit of the draft's own sentences.
            "You grant a license.\nDRAFT. Not legal advice. Replace this text with terms you stand behind.\n".to_string(),
            "A half-edited copy {{OWNER_NAME".to_string(),
            "closing braces only PRODUCT}}".to_string(),
        ];
        for text in variants {
            assert!(is_draft(&text), "{text:?}");
            assert!(ensure_terms(&text, false).is_err(), "{text:?}");
            assert!(ensure_terms(&text, true).is_ok(), "{text:?}");
        }
        // A zero-width character in the marker is seen through (and the text is refused anyway).
        let zero_width = TEMPLATE.replace("FERRYMAN-DRAFT-TERMS", "FERRYMAN\u{200B}-DRAFT-TERMS");
        assert!(is_draft(&zero_width));
        assert!(ensure_terms(&zero_width, true).is_err());
        // Real terms are not mistaken for a draft.
        assert!(!is_draft(
            "Terms. The product name is Idle-ish. You grant the owner a license. No payment. \
             Questions: josh@example.com. Governed by the laws of Ohio.\n"
        ));
        assert!(!is_draft(&terms()));
    }

    #[test]
    fn terms_with_hidden_or_escape_characters_are_never_published() {
        for text in [
            "Terms.\u{1b}[8m You give us everything.\u{1b}[0m\n",
            "Terms \u{202E}reversed\n",
            "Terms\u{200B} with zero-width\n",
            "Terms \u{E0049}tag characters\n",
        ] {
            assert!(ensure_terms(text, true).is_err(), "{text:?}");
        }
        assert!(ensure_terms("Plain terms\r\nwith tabs\tand CRLF.\n", false).is_ok());
    }

    #[test]
    fn hidden_characters_in_a_suggestion_are_refused_with_the_field_named() {
        let dir = tempfile::tempdir().unwrap();
        let josh = person("josh", 1);
        let route = route(dir.path(), &[&josh]);
        let record = open_it(&route, &josh);
        let mut fields = BTreeMap::new();
        fields.insert("title".to_string(), "Timer\u{202E}".to_string());
        fields.insert("pitch".to_string(), "ok\u{E0049}\u{E0067}".to_string());
        fields.insert("why".to_string(), "fine\u{200B}".to_string());
        let problems = record.offer.check_fields("idea", &fields);
        for label in ["Title", "Pitch", "Why it fits"] {
            assert!(
                problems
                    .iter()
                    .any(|p| p.starts_with(label) && p.contains("hidden")),
                "{label}: {problems:?}"
            );
        }
    }

    #[test]
    fn types_and_limits_parse_and_fields_are_capped() {
        let types = parse_types("idea,bug:steps=500!+expected=300,balance").unwrap();
        assert_eq!(types.len(), 3);
        assert_eq!(types[1].fields[0].id, "steps");
        assert!(types[1].fields[0].required);
        assert_eq!(types[1].fields[1].max, 300);
        assert_eq!(
            types[2].fields[0].id, "numbers",
            "the built-in fields of balance"
        );
        assert!(parse_types("bad id").is_err());
        assert!(parse_types("bug:steps").is_err());
        let limits = parse_limits("open=5,per_day=2,pitch=600", Limits::default()).unwrap();
        assert_eq!(
            (
                limits.open_per_contributor,
                limits.new_per_day,
                limits.pitch_max
            ),
            (5, 2, 600)
        );
        assert!(parse_limits("bogus=1", Limits::default()).is_err());

        let dir = tempfile::tempdir().unwrap();
        let josh = person("josh", 1);
        let route = route(dir.path(), &[&josh]);
        let record = open_it(&route, &josh);
        let offer = &record.offer;
        let mut fields = BTreeMap::new();
        fields.insert("title".to_string(), "x".repeat(81));
        fields.insert("pitch".to_string(), "ok".to_string());
        fields.insert("bogus".to_string(), "no".to_string());
        let problems = offer.check_fields("idea", &fields);
        assert!(
            problems
                .iter()
                .any(|p| p.contains("Title is 81 characters"))
        );
        assert!(
            problems
                .iter()
                .any(|p| p.contains("Why it fits is required"))
        );
        assert!(problems.iter().any(|p| p.contains("'bogus'")));
        assert!(!offer.check_fields("nonsense", &fields).is_empty());
        fields.insert("title".to_string(), "fine".to_string());
        fields.insert("why".to_string(), "because".to_string());
        fields.remove("bogus");
        assert!(offer.check_fields("idea", &fields).is_empty());
        // A bug needs its steps.
        assert!(
            offer
                .check_fields("bug", &fields)
                .iter()
                .any(|p| p.contains("Steps is required"))
        );
    }
}
