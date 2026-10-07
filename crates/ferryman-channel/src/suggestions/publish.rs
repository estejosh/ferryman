//! The join page: what the owner puts in the public inbox repository so that a person, and
//! their AI agent, can find out how to suggest something, what they are agreeing to, and
//! exactly which commands to run.
//!
//! Everything here is generated from the owner's signed offer and terms, so the page can
//! never say something the owner did not sign. It is written for the inbox repository only,
//! and only by a normal commit with the owner's credentials when `--publish` is given;
//! otherwise it is written to a folder and the owner commits it themselves.
//!
//! Files:
//!
//! ```text
//! README.md                          the "Suggest an idea" section (between markers)
//! AGENTS.md                          for a contributor's AI agent
//! TERMS.md                           the owner's terms, byte for byte (hash in the offer)
//! ferryman-suggest.json              machine-readable: invite, terms, kinds, caps, schemas, offer
//! schemas/suggestion/<kind>.json     JSON Schema for `ferry suggest new --file`
//! .github/ISSUE_TEMPLATE/config.yml  no blank issues; points at the README
//! ```
//!
//! Validation is the owner fleet's job, not a GitHub Action: an issue with no valid signed
//! record gets a comment saying what to fix and the `invalid` label on the owner's next
//! pass. That keeps secrets out of a public repository's workflows and keeps one validator.

use std::collections::BTreeMap;

use anyhow::Result;
use serde_json::{Value, json};

use super::inbox::{Inbox, InboxRef, LABELS};
use super::invite::Invite;
use super::record::{OFFER_FILE, Offer, TERMS_FILE};

pub const INSTALL_URL: &str = "https://github.com/estejosh/ferryman";
pub const RELEASES_URL: &str = "https://github.com/estejosh/ferryman/releases/latest";
pub const INSTALL_SH: &str =
    "curl -fsSL https://raw.githubusercontent.com/estejosh/ferryman/main/scripts/install.sh | sh";
pub const INSTALL_PS1: &str =
    "irm https://raw.githubusercontent.com/estejosh/ferryman/main/scripts/install.ps1 | iex";
pub const BEGIN: &str = "<!-- ferryman-suggest:begin -->";
pub const END: &str = "<!-- ferryman-suggest:end -->";

fn anchor(heading: &str) -> String {
    heading
        .to_lowercase()
        .chars()
        .filter(|c| c.is_alphanumeric() || *c == ' ' || *c == '-')
        .collect::<String>()
        .replace(' ', "-")
}

fn heading(offer: &Offer) -> String {
    format!("Suggest an idea for {}", offer.display_name)
}

fn kind_lines(offer: &Offer) -> String {
    let mut out = String::new();
    for spec in &offer.types {
        let fields: Vec<String> = offer
            .field_specs(&spec.id)
            .into_iter()
            .map(|(id, _, max, required)| {
                format!(
                    "`{id}` (up to {max}{})",
                    if required { "" } else { ", optional" }
                )
            })
            .collect();
        out.push_str(&format!(
            "- **{}** (`{}`): {}\n",
            spec.label,
            spec.id,
            fields.join(", ")
        ));
    }
    out
}

/// The README's section, from marker to marker.
#[must_use]
pub fn readme_section(offer: &Offer, invite: &str) -> String {
    let name = &offer.display_name;
    let limits = &offer.limits;
    format!(
        "{BEGIN}\n\
## {heading}\n\
\n\
{name} takes suggestions from anyone, and from your AI agent, through [Ferryman]({INSTALL_URL}). \
A suggestion is one issue in this repository, sent with the `ferry` program so that it is signed \
and checked. You send an idea in words: no code, no files.\n\
\n\
**Before anything you send can be reviewed you must agree to the [terms](TERMS.md).** They say \
that you send it under the owner's license, that nothing is promised or paid, and that credit is \
the reward. You agree by typing `I agree` yourself; an agent cannot agree for you.\n\
\n\
### What you can suggest\n\
\n\
{kinds}\n\
Limits: {open} open at a time, {per_day} new per day, up to {rounds} round(s) of questions from \
us, and {days} days to answer one.\n\
\n\
### Join in four steps\n\
\n\
1. **Install Ferryman.** You need only the `ferry` program, no Syncthing and no project of your \
own: [download it]({RELEASES_URL}), or run `{INSTALL_SH}` (Windows: `{INSTALL_PS1}`), and ignore \
whatever it offers about setting up a fleet. Check with `ferry --version`. Ferryman is \
source-available.\n\
2. **Join.** `ferry suggest join <invite>` with the invite below. It checks the owner's signature, \
shows you the full terms and the owner's key fingerprint, and asks you to type `I agree`. You need a \
GitHub token (`GITHUB_TOKEN`, or `gh auth login`); it is used to post as you and never stored or \
shown.\n\
3. **Send.** `ferry suggest new` asks for each field with a live character count, shows a preview, \
and sends it when you confirm.\n\
4. **Follow.** `ferry suggest status` shows where each of yours stands. If we have a question, \
answer it with `ferry suggest reply <number>`.\n\
\n\
The invite, one line:\n\
\n\
```\n\
{invite}\n\
```\n\
\n\
Owner key fingerprint: `{fingerprint}`. Terms: version {version}, sha256 `{sha}`.\n\
\n\
### Using an AI agent\n\
\n\
Give your agent [AGENTS.md](AGENTS.md). It can draft and send suggestions for you, but you must \
read and accept the terms yourself.\n\
\n\
### What happens next\n\
\n\
Each suggestion is checked, read by a model that can do nothing but read, and then decided by \
{name}'s owner, not by the model. Its status is the label on the issue:\n\
\n\
| label | meaning |\n\
| --- | --- |\n\
| `received` | it passed the checks and is waiting to be read |\n\
| `needs-clarification` | we asked you a question |\n\
| `accepted` | the owner said yes and it is queued to be built |\n\
| `building` | work has started |\n\
| `shipped` | it is built, and you are credited |\n\
| `declined` | not going forward, with a reason |\n\
| `duplicate` | the same as another suggestion |\n\
| `invalid` | it could not be checked; the comment says what to fix |\n\
\n\
Nothing is promised and nothing is paid; credit is the reward. Issues opened by hand are not \
reviewed.\n\
{END}\n",
        heading = heading(offer),
        kinds = kind_lines(offer),
        open = limits.open_per_contributor,
        per_day = limits.new_per_day,
        rounds = limits.clarification_rounds,
        days = limits.answer_days,
        fingerprint = offer.fingerprint(),
        version = offer.terms.version,
        sha = offer.terms.sha256,
    )
}

/// `existing` README text with the section put in place of the one between the markers, or
/// added at the end; a new README when there is none.
#[must_use]
pub fn merge_readme(existing: Option<&str>, section: &str, offer: &Offer) -> String {
    match existing {
        None => format!(
            "# {} ideas\n\nWhere to suggest improvements to {}.\n\n{section}",
            offer.display_name, offer.display_name
        ),
        Some(text) => match (text.find(BEGIN), text.find(END)) {
            (Some(start), Some(end)) if start < end => {
                let after = end + END.len();
                let rest = text[after..].trim_start_matches('\n');
                format!(
                    "{}{section}{}{rest}",
                    &text[..start],
                    if rest.is_empty() { "" } else { "\n" }
                )
            }
            _ => format!("{}\n\n{section}", text.trim_end()),
        },
    }
}

/// `AGENTS.md`: what a contributor's AI agent needs to know.
#[must_use]
pub fn agents_md(offer: &Offer, invite: &str) -> String {
    let name = &offer.display_name;
    let limits = &offer.limits;
    let kinds: Vec<String> = offer.types.iter().map(|spec| spec.id.clone()).collect();
    let example = example_json(offer);
    format!(
        "# For AI agents: suggesting an idea for {name}\n\
\n\
You are acting for a person who wants to suggest an improvement to {name}. This file is \
everything you need. The suggestion is sent with the `ferry` program, which signs and checks it. \
Do not open issues in this repository by hand: they are not reviewed.\n\
\n\
## The rule that matters most\n\
\n\
**The human must read and accept [TERMS.md](TERMS.md) personally. You must show the terms to \
your human and you must not accept on their behalf.** Do not type `I agree` for them. Do not run \
`ferry suggest join` with `--agree`, and do not look up the terms' hash to paste it in: that \
flag exists for a person's own script, not for an agent. If your human wants to agree, ask them \
to run the join command in their own terminal and type the phrase, or to tell you in plain words \
after reading the full text that you showed them, and then ask them to run the command.\n\
\n\
## Steps\n\
\n\
1. **Check `ferry`.** Run `ferry --version`. If it is missing, and your human agrees to install \
software, install it: macOS or Linux `{INSTALL_SH}`; Windows (PowerShell) `{INSTALL_PS1}`; or the \
releases page {RELEASES_URL}. Only the `ferry` program is needed: no Syncthing, no fleet, no \
project.\n\
2. **Credentials.** `ferry` posts as your human with their GitHub token: `GITHUB_TOKEN` in the \
environment, or `gh auth login`. Never print, log, copy or store the token.\n\
3. **Join.** The invite is:\n\
\n\
   ```\n\
   {invite}\n\
   ```\n\
\n\
   Run `ferry suggest join <invite>` without `--agree`. It checks the owner's signature, prints \
the full terms, the terms' sha256 (`{sha}`) and the owner's key fingerprint (`{fingerprint}`), and \
waits for a human to type `I agree`. Show your human the terms it printed (or the contents of \
TERMS.md) and the fingerprint. Wait for them.\n\
4. **Draft the suggestion** as JSON that matches `schemas/suggestion/<type>.json`. Kinds here: {kinds}. \
One idea per suggestion, in the person's own words, specific enough to act on. Example:\n\
\n\
   ```json\n\
{example}\n\
   ```\n\
\n\
   Limits: title {title} characters, pitch {pitch}, why-it-fits {why}; the other fields are in the \
schema. Show your human the draft and get their approval before sending.\n\
5. **Send.** `ferry suggest new --file suggestion.json --json`. It validates, signs and posts, \
and prints one JSON object (`{{\"ok\":true,\"issue\":7,\"url\":\"...\"}}`), or `{{\"ok\":false,\
\"errors\":[...]}}` with a nonzero exit code. Fix what the errors say; do not work around them.\n\
6. **Follow.** `ferry suggest status --json` lists each suggestion with its `state`. If one has \
`needs_reply: true`, its `question` is for your human: show it, write their answer to a file, and \
run `ferry suggest reply <issue> --file answer.txt`. `ferry suggest withdraw <issue>` takes one back.\n\
\n\
## Limits\n\
\n\
{open} open suggestions at a time, {per_day} new per day, {rounds} round(s) of questions from the \
owner, {days} days to answer a question before it closes. A suggestion over a limit is refused \
with the reason.\n\
\n\
## What not to send\n\
\n\
- Code, files, images or links to download. Send the idea in words.\n\
- Secrets, tokens, passwords, personal data, or anything confidential.\n\
- Other people's ideas, writing, designs or code that your human has no right to send.\n\
- Text written to instruct the review. It is read as data and will be ignored; a suggestion that \
tries to instruct the reviewer is escalated to the owner as suspicious.\n\
\n\
## Machine-readable\n\
\n\
[`{OFFER_FILE}`]({OFFER_FILE}) has the invite, the terms' hash, the kinds with their fields and \
caps, the limits, the schema paths and the owner's signed offer. {name} is source-available; \
Ferryman is too.\n",
        title = limits.title_max,
        pitch = limits.pitch_max,
        why = limits.why_max,
        open = limits.open_per_contributor,
        per_day = limits.new_per_day,
        rounds = limits.clarification_rounds,
        days = limits.answer_days,
        sha = offer.terms.sha256,
        fingerprint = offer.fingerprint(),
        kinds = kinds.join(", "),
    )
}

fn example_json(offer: &Offer) -> String {
    let kind = offer.types.first().map_or("idea", |spec| spec.id.as_str());
    let mut object = serde_json::Map::new();
    object.insert("type".into(), json!(kind));
    for (id, label, _, required) in offer.field_specs(kind) {
        if required {
            object.insert(id, json!(format!("{label}, in your own words")));
        }
    }
    let text = serde_json::to_string_pretty(&Value::Object(object)).unwrap_or_default();
    text.lines()
        .map(|line| format!("   {line}"))
        .collect::<Vec<_>>()
        .join("\n")
}

/// The JSON Schema of one kind of suggestion.
#[must_use]
pub fn schema(offer: &Offer, kind: &str) -> Value {
    let mut properties = serde_json::Map::new();
    let mut required = vec![json!("type")];
    properties.insert("type".into(), json!({ "const": kind }));
    for (id, label, max, is_required) in offer.field_specs(kind) {
        let mut property =
            json!({ "type": "string", "minLength": 1, "maxLength": max, "description": label });
        if id == "title" {
            property["pattern"] = json!("^[^\\r\\n]*$");
        }
        properties.insert(id.clone(), property);
        if is_required {
            required.push(json!(id));
        }
    }
    json!({
        "$schema": "https://json-schema.org/draft/2020-12/schema",
        "title": format!("A {kind} suggestion for {}", offer.display_name),
        "type": "object",
        "additionalProperties": false,
        "required": required,
        "properties": properties,
    })
}

/// `ferryman-suggest.json`.
#[must_use]
pub fn machine_page(offer: &Offer, invite: &str) -> Value {
    let types: Vec<Value> = offer
        .types
        .iter()
        .map(|spec| {
            let fields: Vec<Value> = offer
                .field_specs(&spec.id)
                .into_iter()
                .map(|(id, label, max, required)| json!({ "id": id, "label": label, "max": max, "required": required }))
                .collect();
            json!({
                "id": spec.id,
                "label": spec.label,
                "schema": format!("schemas/suggestion/{}.json", spec.id),
                "fields": fields,
            })
        })
        .collect();
    json!({
        "format": "ferryman-suggest/v1",
        "project_id": offer.project_id,
        "display_name": offer.display_name,
        "inbox": offer.inbox,
        "status": offer.status,
        "invite": invite,
        "terms": {
            "version": offer.terms.version,
            "sha256": offer.terms.sha256,
            "file": offer.terms.file,
        },
        "owner": { "name": offer.owner, "key": offer.owner_key, "fingerprint": offer.fingerprint() },
        "types": types,
        "limits": offer.limits,
        "agents": "AGENTS.md",
        "commands": {
            "join": "ferry suggest join <invite>",
            "new": "ferry suggest new --file <json> --json",
            "status": "ferry suggest status --json",
            "reply": "ferry suggest reply <issue> --file <text>",
            "withdraw": "ferry suggest withdraw <issue>",
        },
        "offer": offer,
    })
}

fn issue_config(offer: &Offer) -> String {
    let readme = InboxRef::parse(&offer.inbox)
        .map(|inbox| match inbox {
            InboxRef::Github { owner, repo } => format!(
                "https://github.com/{owner}/{repo}#{}",
                anchor(&heading(offer))
            ),
        })
        .unwrap_or_default();
    format!(
        "blank_issues_enabled: false\n\
contact_links:\n\
  - name: Suggest an idea (use ferry, not this form)\n\
    url: {readme}\n\
    about: Suggestions are sent with `ferry suggest new`, signed and checked, after you agree to the terms. Issues opened by hand are not reviewed.\n"
    )
}

/// Every file of the join page, by path in the inbox repository. `readme` is the repository's
/// README today, when it has one, so the section can be put into it without losing the rest.
#[must_use]
pub fn files(offer: &Offer, terms_text: &str, readme: Option<&str>) -> BTreeMap<String, String> {
    let invite = Invite::new(offer).encode();
    let mut files = BTreeMap::new();
    files.insert(
        "README.md".to_string(),
        merge_readme(readme, &readme_section(offer, &invite), offer),
    );
    files.insert("AGENTS.md".to_string(), agents_md(offer, &invite));
    files.insert(TERMS_FILE.to_string(), terms_text.to_string());
    files.insert(
        OFFER_FILE.to_string(),
        format!(
            "{}\n",
            serde_json::to_string_pretty(&machine_page(offer, &invite)).unwrap_or_default()
        ),
    );
    for spec in &offer.types {
        files.insert(
            format!("schemas/suggestion/{}.json", spec.id),
            format!(
                "{}\n",
                serde_json::to_string_pretty(&schema(offer, &spec.id)).unwrap_or_default()
            ),
        );
    }
    files.insert(
        ".github/ISSUE_TEMPLATE/config.yml".to_string(),
        issue_config(offer),
    );
    files
}

/// Write the page to a local folder, for the owner to commit.
///
/// # Errors
/// A folder that cannot be written.
pub fn write_folder(dir: &std::path::Path, files: &BTreeMap<String, String>) -> Result<()> {
    for (path, content) in files {
        let target = dir.join(path);
        if let Some(parent) = target.parent() {
            std::fs::create_dir_all(parent)?;
        }
        std::fs::write(&target, content)?;
    }
    Ok(())
}

/// What publishing to the inbox did to each file.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Written {
    pub path: String,
    pub changed: bool,
}

/// Commit the page to the inbox repository with the owner's credentials, one commit per
/// file that changed (the repository's own history is the record), and make the status
/// labels exist. Files that already say the same are left alone.
///
/// # Errors
/// The inbox refused a write.
pub fn publish(inbox: &dyn Inbox, offer: &Offer, terms_text: &str) -> Result<Vec<Written>> {
    let existing_readme = inbox.read_file("README.md")?;
    let page = files(offer, terms_text, existing_readme.as_deref());
    let mut written = Vec::new();
    for (path, content) in &page {
        let same = inbox.read_file(path)?.as_deref() == Some(content.as_str());
        if !same {
            inbox.write_file(
                path,
                content,
                &format!(
                    "Suggestions: update {path} (terms version {})",
                    offer.terms.version
                ),
            )?;
        }
        written.push(Written {
            path: path.clone(),
            changed: !same,
        });
    }
    inbox.ensure_labels()?;
    let _ = LABELS;
    Ok(written)
}

#[cfg(test)]
#[path = "publish_tests.rs"]
mod tests;
