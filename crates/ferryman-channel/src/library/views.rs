//! Generated views: fact pages the librarian refreshes from live state.
//!
//! The library holds what people and agents *said*; these pages hold what the fleet's own
//! files *show*: the machines and the workers on them, the engines, each project's focus
//! tier and whether self-improve is on, which projects take suggestions and where, and where
//! each secret lives (names and recipients, never a value). They are read-only, marked
//! `generated`, stamped with when and by whom, and signed by the agent that wrote them so a
//! peer cannot slip one in. They are not facts: nobody confirms them, and the next refresh
//! replaces them.
//!
//! ```text
//! <home channel>/library/views.<agent>__<machine>.json     one writer per file
//! ```

use std::collections::{BTreeMap, BTreeSet};
use std::path::{Path, PathBuf};

use anyhow::{Result, bail};
use chrono::{DateTime, Utc};
use serde::{Deserialize, Serialize};

use super::guard;
use crate::focus::Focus;
use crate::{AgentIdentity, AgentRoute, SignatureCheck};

/// Most rows one view may carry.
pub const MAX_ROWS: usize = 400;
/// Longest a row's text may be, in characters.
pub const MAX_ROW_TEXT: usize = 600;
const MAX_FILE: u64 = 1024 * 1024;

/// One findable line of a view.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct ViewRow {
    /// `view:<view>:<slug>`.
    pub id: String,
    pub subject: String,
    pub text: String,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub project: Option<String>,
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub tags: Vec<String>,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct View {
    pub name: String,
    pub title: String,
    pub rows: Vec<ViewRow>,
}

/// What a machine writes: its views, signed.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct ViewsFile {
    pub home: String,
    pub machine: String,
    pub generated_at: DateTime<Utc>,
    pub generated_by: String,
    /// Always `generated`.
    pub source: String,
    pub views: Vec<View>,
    pub signature: String,
}

/// A view row as read back, with where it came from.
#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
pub struct GeneratedRow {
    pub row: ViewRow,
    pub view: String,
    pub generated_at: DateTime<Utc>,
    pub generated_by: String,
    pub machine: String,
}

fn slug(text: &str) -> String {
    let cleaned: String = text
        .chars()
        .map(|c| {
            if c.is_ascii_alphanumeric() || matches!(c, '.' | '_') {
                c.to_ascii_lowercase()
            } else {
                '-'
            }
        })
        .take(48)
        .collect();
    let cleaned = cleaned.trim_matches('-').to_string();
    if cleaned.is_empty() {
        "x".to_string()
    } else {
        cleaned
    }
}

fn row(view: &str, key: &str, subject: &str, text: &str, project: Option<&str>) -> Option<ViewRow> {
    let text: String = crate::suggestions::plain(text, MAX_ROW_TEXT);
    let subject = crate::suggestions::plain(subject, 80);
    // A name that looks like a secret is dropped rather than shown.
    if text.is_empty() || guard::any_secret(&[&text, &subject]) {
        return None;
    }
    Some(ViewRow {
        id: format!("view:{view}:{}", slug(key)),
        subject,
        text,
        project: project.map(str::to_string),
        tags: vec!["generated".to_string(), view.to_string()],
    })
}

fn list(items: &BTreeSet<String>) -> String {
    if items.is_empty() {
        "none".to_string()
    } else {
        items.iter().cloned().collect::<Vec<_>>().join(", ")
    }
}

type Engine = (String, String, String, BTreeSet<String>, BTreeSet<String>);

/// Build every view from the ferry root on this machine and the `focus` in force. Pure
/// reading: nothing is written, nothing run, no network.
#[must_use]
pub fn generate(root: &crate::ferry::Root, focus: &Focus, now: DateTime<Utc>) -> Vec<View> {
    let entries: Vec<_> = root
        .projects()
        .into_iter()
        .filter(|entry| entry.channel.is_dir() && !entry.is_archived())
        .collect();
    let mut projects = Vec::new();
    let mut inboxes = Vec::new();
    let mut secrets = Vec::new();
    let mut improving = BTreeSet::new();
    let mut not_improving = BTreeSet::new();
    // (machine) -> agent -> (seen, version, up engines, other engines)
    #[allow(clippy::type_complexity)]
    let mut machines: BTreeMap<String, BTreeMap<String, (DateTime<Utc>, String, Vec<String>)>> =
        BTreeMap::new();
    let mut engines: BTreeMap<String, Engine> = BTreeMap::new();
    for entry in &entries {
        let id = &entry.project_id;
        let channel = &entry.channel;
        let master = crate::ferry::master_of(channel).ok().flatten();
        let on = crate::ferry::self_improve_enabled(channel, id);
        if on {
            improving.insert(id.clone());
        } else {
            not_improving.insert(id.clone());
        }
        let tier = focus
            .pin(id, now)
            .map_or_else(|| "normal".to_string(), crate::focus::Pin::describe);
        let offer = crate::suggestions::record::current(channel, id);
        let offer_text = offer.as_ref().map_or_else(
            || "not open to suggestions".to_string(),
            |record| {
                format!(
                    "takes suggestions at {} ({})",
                    record.offer.inbox,
                    if record.offer.is_open() {
                        "open"
                    } else {
                        "closed"
                    }
                )
            },
        );
        projects.extend(row(
            "projects",
            id,
            id,
            &format!(
                "{id}: master {}; focus {tier}; self-improve {}; {offer_text}",
                master.as_deref().unwrap_or("none yet"),
                if on { "on" } else { "off" },
            ),
            Some(id),
        ));
        if let Some(record) = &offer {
            inboxes.extend(row(
                "suggestion-inboxes",
                id,
                &format!("{id} suggestions"),
                &format!(
                    "{id} (shown to outsiders as {}): inbox {}, {}, terms {}",
                    record.offer.display_name,
                    record.offer.inbox,
                    if record.offer.is_open() {
                        "open"
                    } else {
                        "closed"
                    },
                    record.offer.terms.version
                ),
                Some(id),
            ));
        }
        let Ok((mut route, _)) = entry.route(root) else {
            continue;
        };
        route.agents = crate::read_agent_roster(channel).unwrap_or_default();
        for summary in crate::secrets::list_secrets(&route).unwrap_or_default() {
            secrets.extend(row(
                "secrets",
                &format!("{id}-{}", summary.name),
                &format!("secret {}", summary.name),
                &format!(
                    "Secret named {} for project {id}: sealed in the channel for {} (set by {} on {}). \
                     Only the name and who can open it are listed; the value is never shown.",
                    summary.name,
                    summary.recipients.join(", "),
                    summary.signed_by.as_deref().unwrap_or("unknown"),
                    summary.created_at.get(..10).unwrap_or(&summary.created_at),
                ),
                Some(id),
            ));
        }
        for (inventory, check) in crate::receipts::list_engines(&route).unwrap_or_default() {
            if check != SignatureCheck::Valid {
                continue;
            }
            let machine = inventory.machine.to_lowercase();
            let up: Vec<String> = inventory
                .engines
                .iter()
                .filter(|engine| engine.state == "up")
                .map(|engine| engine.name.clone())
                .collect();
            let newest = machines
                .entry(machine.clone())
                .or_default()
                .entry(inventory.agent.to_lowercase())
                .or_insert_with(|| {
                    (
                        inventory.updated_at,
                        inventory.ferry_version.clone(),
                        up.clone(),
                    )
                });
            if newest.0 < inventory.updated_at {
                *newest = (inventory.updated_at, inventory.ferry_version.clone(), up);
            }
            for engine in &inventory.engines {
                let slot = engines.entry(engine.name.clone()).or_insert_with(|| {
                    (
                        engine.kind.clone(),
                        engine.tier.clone(),
                        engine.paid.clone(),
                        BTreeSet::new(),
                        BTreeSet::new(),
                    )
                });
                if engine.state == "up" {
                    slot.3.insert(machine.clone());
                } else {
                    slot.4.insert(machine.clone());
                }
            }
        }
    }
    let machine_rows: Vec<ViewRow> = machines
        .iter()
        .filter_map(|(machine, workers)| {
            let described: Vec<String> = workers
                .iter()
                .map(|(agent, (seen, version, up))| {
                    format!(
                        "{agent} (ferry {version}, last reported {}; engines up: {})",
                        seen.format("%Y-%m-%d %H:%M UTC"),
                        if up.is_empty() {
                            "none".to_string()
                        } else {
                            up.join(", ")
                        }
                    )
                })
                .collect();
            row(
                "machines",
                machine,
                machine,
                &format!("{machine} runs workers: {}", described.join("; ")),
                None,
            )
        })
        .collect();
    let engine_rows: Vec<ViewRow> = engines
        .iter()
        .filter_map(|(name, (kind, tier, paid, up, down))| {
            row(
                "engines",
                name,
                name,
                &format!(
                    "engine {name}: {kind}, tier {tier}, paid {paid}; up on {}; not up on {}",
                    list(up),
                    list(down)
                ),
                None,
            )
        })
        .collect();
    let improve_rows: Vec<ViewRow> = row(
        "self-improve",
        "all",
        "self-improve",
        &format!(
            "Self-improve is on for: {}. Off for: {}.",
            list(&improving),
            list(&not_improving)
        ),
        None,
    )
    .into_iter()
    .collect();
    let mut views = vec![
        View {
            name: "machines".into(),
            title: "Machines and their workers".into(),
            rows: machine_rows,
        },
        View {
            name: "engines".into(),
            title: "Engines".into(),
            rows: engine_rows,
        },
        View {
            name: "projects".into(),
            title: "Projects, their focus tier and self-improve".into(),
            rows: projects,
        },
        View {
            name: "self-improve".into(),
            title: "Self-improve".into(),
            rows: improve_rows,
        },
        View {
            name: "suggestion-inboxes".into(),
            title: "Suggestion inboxes".into(),
            rows: inboxes,
        },
        View {
            name: "secrets".into(),
            title: "Where each secret lives (names only)".into(),
            rows: secrets,
        },
    ];
    for view in &mut views {
        view.rows.truncate(MAX_ROWS);
    }
    views
}

fn payload(file: &ViewsFile) -> String {
    crate::suggestions::sealed_payload("ferryman-library-views-v1", file)
}

fn path_for(channel: &Path, author: &str, machine: &str) -> PathBuf {
    channel
        .join(super::store::DIR)
        .join(format!("views.{author}__{machine}.json"))
}

/// When `author` last wrote this machine's views, if it has.
#[must_use]
pub fn last_written(channel: &Path, author: &str) -> Option<DateTime<Utc>> {
    let path = path_for(channel, author, &super::store::machine_name());
    serde_json::from_slice::<ViewsFile>(&std::fs::read(path).ok()?)
        .ok()
        .map(|file| file.generated_at)
}

/// Write this machine's views, signed by `identity`. One file per agent and machine.
///
/// # Errors
/// The signer is not on the home channel's roster, or the file could not be written.
pub fn write(
    channel: &Path,
    home: &str,
    identity: &AgentIdentity,
    views: Vec<View>,
    now: DateTime<Utc>,
) -> Result<PathBuf> {
    if !channel.is_dir() {
        bail!("{home}'s channel is not on this machine");
    }
    super::store::require_on_roster(channel, identity)?;
    let machine = super::store::machine_name();
    let mut file = ViewsFile {
        home: home.to_string(),
        machine: machine.clone(),
        generated_at: now,
        generated_by: identity.name().to_string(),
        source: "generated".to_string(),
        views,
        signature: String::new(),
    };
    file.signature = identity.sign_bytes(payload(&file).as_bytes());
    let path = path_for(channel, identity.name(), &machine);
    crate::atomic_json(&path, &file)?;
    Ok(path)
}

fn verified(file: &ViewsFile, home: &str, roster: &[AgentRoute]) -> bool {
    file.home == home
        && file.source == "generated"
        && crate::check_signature(
            Some(&file.generated_by),
            Some(&file.signature),
            &payload(file),
            roster,
        ) == SignatureCheck::Valid
}

/// Every generated row in the home channel's view files that verifies, the newest version of
/// each view winning.
#[must_use]
pub fn read(channel: &Path, home: &str) -> Vec<GeneratedRow> {
    let roster = crate::read_agent_roster(channel).unwrap_or_default();
    let Ok(entries) = std::fs::read_dir(channel.join(super::store::DIR)) else {
        return Vec::new();
    };
    let mut files: Vec<ViewsFile> = entries
        .flatten()
        .filter(|entry| {
            entry.file_name().to_str().is_some_and(|name| {
                name.starts_with("views.")
                    && name.ends_with(".json")
                    && !name.contains(".sync-conflict-")
            }) && entry.metadata().is_ok_and(|meta| meta.len() <= MAX_FILE)
        })
        .filter_map(|entry| std::fs::read(entry.path()).ok())
        .filter_map(|bytes| serde_json::from_slice::<ViewsFile>(&bytes).ok())
        .filter(|file| verified(file, home, &roster))
        .collect();
    files.sort_by_key(|file| std::cmp::Reverse(file.generated_at));
    let mut taken: BTreeSet<String> = BTreeSet::new();
    let mut out = Vec::new();
    for file in files {
        for view in file.views {
            if !taken.insert(view.name.clone()) {
                continue;
            }
            for row in view.rows.into_iter().take(MAX_ROWS) {
                // Believed only if it still passes the guard and the shape rules.
                if row.id.starts_with(&format!("view:{}:", view.name))
                    && row.text.chars().count() <= MAX_ROW_TEXT
                    && !guard::any_secret(&[&row.text, &row.subject])
                {
                    out.push(GeneratedRow {
                        row,
                        view: view.name.clone(),
                        generated_at: file.generated_at,
                        generated_by: file.generated_by.clone(),
                        machine: file.machine.clone(),
                    });
                }
            }
        }
    }
    out
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::{ProjectRoute, receipts};

    fn person(name: &str, seed: u8) -> AgentIdentity {
        AgentIdentity::from_seed(name, [seed; 32])
    }

    fn project(dir: &Path, id: &str, members: &[&AgentIdentity]) -> ProjectRoute {
        let communications = dir.join(format!("{id}-ferryman"));
        std::fs::create_dir_all(&communications).unwrap();
        let mut route = ProjectRoute {
            project_id: id.into(),
            workspace: dir.join(id),
            attachment: dir.join(format!("{id}-attachment")),
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

    fn engine(name: &str, state: &str) -> receipts::EngineReport {
        receipts::EngineReport {
            name: name.into(),
            kind: "http".into(),
            model: None,
            tier: "chore".into(),
            paid: "prepaid".into(),
            state: state.into(),
            until: None,
            reason: None,
            latency_ms: None,
            balance: None,
            checked_at: None,
            trust: None,
            billing: None,
            class: None,
            capabilities: None,
        }
    }

    #[test]
    fn the_views_show_live_state_and_never_a_secret_value() {
        let dir = tempfile::tempdir().unwrap();
        super::super::store::use_state_dir_for_this_thread(dir.path().join("state"));
        let josh = person("josh", 1);
        let worker = person("beastly-worker", 2);
        let harbor_key = crate::secrets::EncryptionIdentity::from_seed("harbor", [9; 32]);
        let alpha = project(dir.path(), "alpha", &[&josh, &worker]);
        let beta = project(dir.path(), "beta", &[&josh]);
        crate::register_agent(
            &alpha,
            &AgentRoute {
                name: "harbor".into(),
                role: "worker".into(),
                capabilities: Vec::new(),
                public_key: Some(person("harbor", 3).public_key_hex()),
                encryption_key: Some(harbor_key.public_key_hex()),
            },
        )
        .unwrap();
        let mut alpha = alpha;
        alpha.agents = crate::read_agent_roster(&alpha.communications).unwrap();
        crate::ferry::set_self_improve(&alpha.communications, "alpha", true, &josh).unwrap();
        receipts::refresh_engines(
            &alpha,
            &worker,
            "beastly",
            "0.5.26",
            vec![engine("deepseek", "up"), engine("nemotron", "down")],
            Utc::now(),
        )
        .unwrap();
        // A secret whose value must never appear anywhere.
        let value = format!("nvapi-{}", "Zx9Qw3Er7Ty1Ui5Op8As2Df6Gh4Jk0Lm".repeat(2));
        crate::secrets::set_secret(&alpha, &josh, "nvidiaapi", &value, &["harbor".to_string()])
            .unwrap();

        let root = crate::ferry::Root {
            path: dir.path().join("ferry"),
        };
        std::fs::create_dir_all(&root.path).unwrap();
        root.adopt("alpha", &alpha.communications, None).unwrap();
        root.adopt("beta", &beta.communications, None).unwrap();
        let now = Utc::now();
        let views = generate(&root, &Focus::default(), now);
        let names: Vec<&str> = views.iter().map(|v| v.name.as_str()).collect();
        assert_eq!(
            names,
            [
                "machines",
                "engines",
                "projects",
                "self-improve",
                "suggestion-inboxes",
                "secrets"
            ]
        );
        let text = |name: &str| {
            views
                .iter()
                .find(|v| v.name == name)
                .unwrap()
                .rows
                .iter()
                .map(|r| r.text.clone())
                .collect::<Vec<_>>()
                .join("\n")
        };
        assert!(
            text("machines").contains("beastly runs workers: beastly-worker"),
            "{}",
            text("machines")
        );
        assert!(text("machines").contains("engines up: deepseek"));
        assert!(
            text("engines")
                .contains("engine deepseek: http, tier chore, paid prepaid; up on beastly")
        );
        assert!(
            text("engines").contains("nemotron") && text("engines").contains("not up on beastly")
        );
        assert!(text("projects").contains("alpha: master josh; focus normal; self-improve on"));
        assert!(text("projects").contains("beta: master josh; focus normal; self-improve off"));
        assert!(text("self-improve").contains("on for: alpha. Off for: beta"));
        assert!(text("secrets").contains("Secret named nvidiaapi for project alpha"));
        assert!(text("secrets").contains("harbor"));
        for view in &views {
            for row in &view.rows {
                assert!(row.id.starts_with(&format!("view:{}:", view.name)));
                assert!(row.tags.contains(&"generated".to_string()));
            }
        }
        assert!(
            !serde_json::to_string(&views)
                .unwrap()
                .contains(&value[6..30])
        );

        // Signed by the writer, read back from any machine, and not by a stranger.
        let channel = &alpha.communications;
        write(channel, "alpha", &josh, views.clone(), now).unwrap();
        let rows = read(channel, "alpha");
        assert_eq!(
            rows.len(),
            views.iter().map(|v| v.rows.len()).sum::<usize>()
        );
        assert!(
            rows.iter()
                .all(|r| r.generated_by == "josh" && r.generated_at == now)
        );
        assert_eq!(last_written(channel, "josh"), Some(now));
        // Another home project's name does not read them.
        assert!(read(channel, "elsewhere").is_empty());
        // Edited after signing: not believed.
        let path = path_for(channel, "josh", &super::super::store::machine_name());
        let edited = std::fs::read_to_string(&path)
            .unwrap()
            .replace("self-improve on", "self-improve OFF");
        std::fs::write(&path, edited).unwrap();
        assert!(read(channel, "alpha").is_empty());
        // A signer off the roster cannot write at all.
        assert!(write(channel, "alpha", &person("stranger", 8), views, now).is_err());
    }
}
