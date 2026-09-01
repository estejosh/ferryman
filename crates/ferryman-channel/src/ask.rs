//! MAARAG — multi-agent auditable retrieval-augmented generation.
//!
//! The retrieval half of `ferry ask`: a deterministic keyword search over the
//! fleet's signed knowledge — the memory bank, the attribution ledger,
//! learnings, and task results — returning every match with its provenance so
//! the answer can be audited rather than trusted. No embeddings and no model in
//! the retrieval path: the same keyword-overlap rule the skills router and
//! `routing_hint` already use.
//!
//! Generation — composing prose from these claims — is the agent CLI's job and
//! is deliberately kept out of this module, which must stay offline and
//! deterministic.

use anyhow::Result;
use serde::Serialize;
use serde_json::Value;

use crate::{ProjectRoute, TaskState};

/// One retrieved claim: a matched excerpt plus the provenance that makes it
/// auditable — where it came from, who signed it, and its verification status.
#[derive(Debug, Clone, Serialize, PartialEq, Eq)]
pub struct Claim {
    /// Which store it came from: `memory`, `ledger`, `learning`, or `task`.
    pub source: String,
    /// Where exactly: a file path or an id.
    pub location: String,
    /// The identity that signed it; empty for shared fleet memory.
    pub signer: String,
    /// Its verification/acceptance status.
    pub status: String,
    /// When it was recorded, if known.
    pub at: Option<String>,
    /// The matched text, trimmed.
    pub excerpt: String,
}

/// Search the fleet's knowledge for `question` and return the matching claims,
/// most relevant first.
pub fn ask(route: &ProjectRoute, question: &str) -> Result<Vec<Claim>> {
    let q = words(question);
    if q.is_empty() {
        return Ok(Vec::new());
    }
    let mut scored: Vec<(Claim, usize)> = Vec::new();
    scored.extend(memory_claims(route, &q)?);
    scored.extend(ledger_claims(route, &q)?);
    scored.extend(learning_claims(route, &q)?);
    scored.extend(task_claims(route, &q)?);
    scored.sort_by_key(|(_, score)| std::cmp::Reverse(*score));
    Ok(scored.into_iter().map(|(claim, _)| claim).collect())
}

/// Significant words, for keyword overlap — the same rule the skills router and
/// `routing_hint` use, so "creating" matches "create".
fn words(text: &str) -> Vec<String> {
    text.split(|c: char| !c.is_alphanumeric())
        .map(str::to_lowercase)
        .filter(|w| w.len() >= 4)
        .collect()
}

/// How many question words overlap `text`, with the same prefix rule as the
/// skills router. Each question word is counted at most once.
fn hits(question: &[String], text: &str) -> usize {
    let text_words = words(text);
    let mut hits = 0;
    for q in question {
        for t in &text_words {
            if t == q
                || (t.len() >= 4
                    && q.len() >= 4
                    && (t.starts_with(q.as_str()) || q.starts_with(t.as_str())))
            {
                hits += 1;
                break;
            }
        }
    }
    hits
}

/// The first 200 characters of `text`, with an ellipsis when truncated.
fn excerpt(text: &str) -> String {
    let text = text.trim();
    if text.chars().count() <= 200 {
        return text.to_string();
    }
    let mut out: String = text.chars().take(197).collect();
    out.push('…');
    out
}

fn memory_claims(route: &ProjectRoute, q: &[String]) -> Result<Vec<(Claim, usize)>> {
    let mut out = Vec::new();
    let bank = crate::memory::memory_bank_dir(route);
    if !bank.is_dir() {
        return Ok(out);
    }
    for entry in std::fs::read_dir(&bank)? {
        let entry = entry?;
        let path = entry.path();
        if path.extension().and_then(|e| e.to_str()) != Some("md") {
            continue;
        }
        let name = path
            .file_name()
            .and_then(|n| n.to_str())
            .unwrap_or("")
            .to_string();
        let content = std::fs::read_to_string(&path).unwrap_or_default();
        let score = hits(q, &content);
        if score == 0 {
            continue;
        }
        out.push((
            Claim {
                source: "memory".into(),
                location: format!("memory-bank/{name}"),
                signer: String::new(),
                status: "shared fleet memory".into(),
                at: None,
                excerpt: excerpt(&content),
            },
            score,
        ));
    }
    let agents = bank.join("agents");
    if agents.is_dir() {
        for entry in std::fs::read_dir(&agents)? {
            let entry = entry?;
            let path = entry.path();
            if path.extension().and_then(|e| e.to_str()) != Some("md") {
                continue;
            }
            let slug = path
                .file_stem()
                .and_then(|s| s.to_str())
                .unwrap_or("")
                .to_string();
            let content = std::fs::read_to_string(&path).unwrap_or_default();
            let score = hits(q, &content);
            if score == 0 {
                continue;
            }
            out.push((
                Claim {
                    source: "memory".into(),
                    location: format!("memory-bank/agents/{slug}.md"),
                    signer: slug,
                    status: "agent specialization".into(),
                    at: None,
                    excerpt: excerpt(&content),
                },
                score,
            ));
        }
    }
    Ok(out)
}

fn ledger_claims(route: &ProjectRoute, q: &[String]) -> Result<Vec<(Claim, usize)>> {
    let mut out = Vec::new();
    let log = crate::ledger::read_ledger(route)?;
    for (i, e) in log.entries.iter().enumerate() {
        let text = format!("{} {}", e.kind, e.summary);
        let score = hits(q, &text);
        if score == 0 {
            continue;
        }
        out.push((
            Claim {
                source: "ledger".into(),
                location: format!("ledger #{}", i + 1),
                signer: e.actor.clone(),
                status: if log.intact {
                    "signed, ledger intact".into()
                } else {
                    "signed, ledger broken".into()
                },
                at: Some(e.created_at.to_rfc3339()),
                excerpt: excerpt(&e.summary),
            },
            score,
        ));
    }
    Ok(out)
}

fn learning_claims(route: &ProjectRoute, q: &[String]) -> Result<Vec<(Claim, usize)>> {
    let mut out = Vec::new();
    let learnings = crate::learning::read_learnings(route)?;
    for l in &learnings {
        let text = format!("{} {}", l.note, l.source);
        let score = hits(q, &text);
        if score == 0 {
            continue;
        }
        out.push((
            Claim {
                source: "learning".into(),
                location: format!("task {}", l.task_id),
                signer: l.agent.clone().unwrap_or_else(|| l.engine.clone()),
                status: if l.accepted {
                    "accepted".into()
                } else {
                    "sent back".into()
                },
                at: Some(l.at.to_rfc3339()),
                excerpt: excerpt(&l.note),
            },
            score,
        ));
    }
    Ok(out)
}

fn task_claims(route: &ProjectRoute, q: &[String]) -> Result<Vec<(Claim, usize)>> {
    let mut out = Vec::new();
    let tasks = crate::list_tasks(route)?;
    for task in &tasks {
        let task_text = task
            .order
            .payload
            .get("task")
            .and_then(Value::as_str)
            .unwrap_or("");
        let mut text = task_text.to_string();
        let mut result_agent = String::new();
        for r in &task.results {
            let output = result_text(&r.payload);
            if !output.is_empty() {
                text.push(' ');
                text.push_str(&output);
                result_agent = r.agent.clone();
            }
        }
        let score = hits(q, &text);
        if score == 0 {
            continue;
        }
        let signer = if !task.order.issued_by.is_empty() {
            task.order.issued_by.clone()
        } else {
            result_agent
        };
        let body = if !task_text.is_empty() {
            task_text
        } else {
            text.trim()
        };
        out.push((
            Claim {
                source: "task".into(),
                location: format!("task {}", task.order.id),
                signer,
                status: state_name(&task.state()).to_string(),
                at: Some(task.order.created_at.to_rfc3339()),
                excerpt: excerpt(body),
            },
            score,
        ));
    }
    Ok(out)
}

fn result_text(payload: &Value) -> String {
    match payload {
        Value::String(text) => text.clone(),
        other => other
            .get("output")
            .or_else(|| other.get("result"))
            .and_then(Value::as_str)
            .map(String::from)
            .unwrap_or_default(),
    }
}

fn state_name(state: &TaskState) -> &'static str {
    match state {
        TaskState::Open => "open",
        TaskState::Offered { .. } => "offered",
        TaskState::Claimed { .. } => "claimed",
        TaskState::Stale { .. } => "stale",
        TaskState::AwaitingReview { .. } => "awaiting review",
        TaskState::ChangesRequested { .. } => "changes requested",
        TaskState::Accepted => "accepted",
        TaskState::Done => "done",
        TaskState::Killed { .. } => "killed",
    }
}

/// Render an auditable answer for a terminal.
pub fn render(question: &str, claims: &[Claim]) -> String {
    let mut out = format!("Q: {question}\n");
    match claims.len() {
        0 => out.push_str("No claims found in the channel's knowledge.\n"),
        1 => out.push_str("1 claim found.\n\n"),
        n => out.push_str(&format!("{n} claims found.\n\n")),
    }
    for (i, claim) in claims.iter().enumerate() {
        out.push_str(&format!(
            "{}. {} — \"{}\"\n",
            i + 1,
            claim.location,
            claim.excerpt
        ));
        let signer = if claim.signer.is_empty() {
            "(shared)".to_string()
        } else {
            claim.signer.clone()
        };
        let at = claim
            .at
            .as_deref()
            .map(|a| format!(" · {a}"))
            .unwrap_or_default();
        out.push_str(&format!(
            "   {} · signer: {} · status: {}{}\n\n",
            claim.source, signer, claim.status, at
        ));
    }
    out.trim_end().to_string()
}

#[cfg(test)]
mod tests {
    use super::*;

    fn route(dir: &std::path::Path) -> ProjectRoute {
        let workspace = dir.join("workspace");
        let attachment = workspace.join(".ferryman");
        ProjectRoute {
            project_id: "ferryman".into(),
            workspace,
            attachment: attachment.clone(),
            communications: attachment.join("ferryman"),
            shared_remote: "ferryman-ferryman".into(),
            git_remote: String::new(),
            git_visibility: String::new(),
            agents: Vec::new(),
        }
    }

    #[test]
    fn words_drop_short_tokens_and_hits_match_exact_and_prefix() {
        let q = words("why did we choose syncthing over a central server");
        assert!(q.contains(&"syncthing".to_string()));
        assert!(!q.iter().any(|w| w == "why")); // < 4 letters
        // Exact match.
        assert_eq!(hits(&words("syncthing"), "choosing syncthing"), 1);
        // True prefix: "databases" matches "database".
        assert_eq!(hits(&words("database"), "managing databases"), 1);
        // No overlap.
        assert_eq!(hits(&words("database"), "baking bread"), 0);
    }

    #[test]
    fn an_underspecified_question_finds_nothing() {
        let dir = tempfile::tempdir().unwrap();
        assert!(ask(&route(dir.path()), "the").unwrap().is_empty());
    }

    #[test]
    fn memory_claims_carry_provenance() {
        let dir = tempfile::tempdir().unwrap();
        let route = route(dir.path());
        let bank = crate::memory::memory_bank_dir(&route);
        std::fs::create_dir_all(bank.join("agents")).unwrap();
        std::fs::write(
            bank.join("decisions.md"),
            "We chose Syncthing for zero-server sync.",
        )
        .unwrap();
        std::fs::write(
            bank.join("agents/fang.md"),
            "fang is good at syncthing debugging",
        )
        .unwrap();
        let claims = ask(&route, "why syncthing").unwrap();
        assert!(!claims.is_empty());
        let shared = claims
            .iter()
            .find(|c| c.location == "memory-bank/decisions.md")
            .unwrap();
        assert_eq!(shared.signer, "");
        assert_eq!(shared.status, "shared fleet memory");
        let agent = claims
            .iter()
            .find(|c| c.location == "memory-bank/agents/fang.md")
            .unwrap();
        assert_eq!(agent.signer, "fang");
        assert_eq!(agent.status, "agent specialization");
    }

    #[test]
    fn render_lists_each_claim_with_its_signer() {
        let claims = vec![Claim {
            source: "memory".into(),
            location: "memory-bank/decisions.md".into(),
            signer: String::new(),
            status: "shared fleet memory".into(),
            at: None,
            excerpt: "We chose Syncthing.".into(),
        }];
        let text = render("why syncthing", &claims);
        assert!(text.contains("1 claim found"));
        assert!(text.contains("memory-bank/decisions.md"));
        assert!(text.contains("signer: (shared)"));
    }
}
