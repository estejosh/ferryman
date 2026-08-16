//! Per-agent specialization memory.
//!
//! The project memory bank (`<channel>/memory-bank/`) carries what everyone in
//! the project shares. This module adds the per-agent layer that keeps one
//! agent's expertise from becoming everyone's bloat: each agent keeps its own
//! profile at `memory-bank/agents/<slug>.md` — what it has become good at, and
//! the conventions it has established. The worker injects an agent's own
//! profile into its prompts, and `ferry loadmem --agent <name>` loads one on
//! demand, so an agent that got good at Rust keeps its Rust memory instead of a
//! diluted general one.

use std::path::{Path, PathBuf};

use crate::ProjectRoute;

/// The synced memory bank directory for a project.
#[must_use]
pub fn memory_bank_dir(route: &ProjectRoute) -> PathBuf {
    route.communications.join("memory-bank")
}

/// Where one agent's specialization profile lives, given the memory bank dir.
#[must_use]
pub fn agent_profile_path(bank: &Path, agent: &str) -> PathBuf {
    bank.join("agents").join(format!("{}.md", slugify(agent)))
}

/// An agent's specialization profile, if it has written one.
#[must_use]
pub fn load_agent_profile(bank: &Path, agent: &str) -> Option<String> {
    std::fs::read_to_string(agent_profile_path(bank, agent)).ok()
}

/// Every agent profile in the bank: `(agent slug, one-line summary)`.
///
/// The summary is the file's first non-empty line, which the profile convention
/// keeps short ("what this agent is strong at") so a chooser can show it.
#[must_use]
pub fn list_agent_profiles(bank: &Path) -> Vec<(String, String)> {
    let dir = bank.join("agents");
    let Ok(entries) = std::fs::read_dir(&dir) else {
        return Vec::new();
    };
    let mut out = Vec::new();
    for entry in entries.flatten() {
        let path = entry.path();
        if path.extension().and_then(|ext| ext.to_str()) != Some("md") {
            continue;
        }
        let Some(agent) = path.file_stem().and_then(|stem| stem.to_str()) else {
            continue;
        };
        let summary = std::fs::read_to_string(&path)
            .ok()
            .map(|text| summary_of(&text))
            .unwrap_or_default();
        out.push((agent.to_string(), summary));
    }
    out.sort_by(|a, b| a.0.cmp(&b.0));
    out
}

/// Like [`list_agent_profiles`], minus one agent: the roster the agent is shown,
/// so it knows who else is available and what they are practiced at, without
/// re-reading its own profile as if it were a stranger's.
#[must_use]
pub fn list_peer_profiles(bank: &Path, self_agent: &str) -> Vec<(String, String)> {
    let me = slugify(self_agent);
    list_agent_profiles(bank)
        .into_iter()
        .filter(|(agent, _)| *agent != me)
        .collect()
}

/// One agent's specialization summary — its profile's first line, capped to a
/// single short line — for discovery views that need the whole fleet at a glance.
#[must_use]
pub fn agent_summary(bank: &Path, agent: &str) -> Option<String> {
    load_agent_profile(bank, agent).map(|profile| summarize(&summary_of(&profile)))
}

/// Significant words, for keyword overlap — the same shape the skills router
/// uses, so "creating" matches "create".
fn words(text: &str) -> Vec<String> {
    text.split(|c: char| !c.is_alphanumeric())
        .map(str::to_lowercase)
        .filter(|w| w.len() >= 4)
        .collect()
}

/// A deterministic routing hint: when the task text overlaps a peer's
/// specialization summary more than the agent's own, name that peer. This is the
/// reliable half of routing — a model's own judgement is the unreliable half
/// (it would rather just do the work), so we compute the match ourselves and
/// tell the agent plainly.
#[must_use]
pub fn routing_hint(bank: &Path, self_agent: &str, task: &str) -> Option<String> {
    let task_words = words(task);
    if task_words.is_empty() {
        return None;
    }
    let self_summary = load_agent_profile(bank, self_agent)
        .map(|profile| summary_of(&profile))
        .unwrap_or_default();
    let hits = |summary: &str| {
        let summary_words = words(summary);
        task_words
            .iter()
            .filter(|w| {
                summary_words.iter().any(|p| {
                    p == *w
                        || (p.len() >= 4
                            && w.len() >= 4
                            && (p.starts_with(w.as_str()) || w.starts_with(p.as_str())))
                })
            })
            .count()
    };
    let self_hits = hits(&self_summary);
    let mut best: Option<(String, usize)> = None;
    for (peer, summary) in list_peer_profiles(bank, self_agent) {
        let count = hits(&summary);
        if count > self_hits && count > best.as_ref().map_or(0, |(_, b)| *b) {
            best = Some((peer, count));
        }
    }
    best.map(|(peer, _)| {
        format!(
            "This task appears to match '{peer}'s listed specialty more than your own. \
             If it is outside yours, say so plainly so the operator can route it to '{peer}'."
        )
    })
}

/// Where the generated roster lives: one line per agent, beside the `agents/`
/// profiles it summarises.
#[must_use]
pub fn roster_path(bank: &Path) -> PathBuf {
    bank.join("roster.md")
}

/// The generated roster, if it has been written.
#[must_use]
pub fn load_roster(bank: &Path) -> Option<String> {
    std::fs::read_to_string(roster_path(bank)).ok()
}

/// Regenerate the roster from the current profiles: one line per agent, with the
/// same one-line summary the chooser shows. When there are no profiles, any stale
/// roster is removed rather than rewritten empty.
pub fn regenerate_roster(bank: &Path) -> std::io::Result<()> {
    let path = roster_path(bank);
    let profiles = list_agent_profiles(bank);
    if profiles.is_empty() {
        let _ = std::fs::remove_file(&path);
        return Ok(());
    }
    let mut out = String::from(
        "# Agent roster\n\n\
         One line per agent: who is available and what they are practiced at.\n\
         Generated from memory-bank/agents/*.md — edit a profile, then run\n\
         `ferry loadmem` to refresh this file.\n\n",
    );
    for (agent, summary) in &profiles {
        let summary = summarize(summary);
        if summary.is_empty() {
            out.push_str(&format!("- {agent}\n"));
        } else {
            out.push_str(&format!("- {agent} — {summary}\n"));
        }
    }
    std::fs::write(&path, out)
}

/// Append one line to an agent's profile, creating the file and its `agents/`
/// directory on first use. Does not touch the roster: that is a derived view,
/// regenerated by `ferry loadmem`, so concurrent machines never race on it.
pub fn append_agent_profile(bank: &Path, agent: &str, line: &str) -> std::io::Result<()> {
    let path = agent_profile_path(bank, agent);
    if let Some(dir) = path.parent() {
        std::fs::create_dir_all(dir)?;
    }
    use std::io::Write;
    let mut file = std::fs::OpenOptions::new()
        .create(true)
        .append(true)
        .open(&path)?;
    writeln!(file, "{line}")
}

/// The one-line summary of a profile: its first non-empty line, with a leading
/// `- YYYY-MM-DD ` bullet stripped, so a profile that started life as an
/// auto-recorded activity still reads as what the agent does, not its date.
fn summary_of(text: &str) -> String {
    let first = text
        .lines()
        .find(|line| !line.trim().is_empty())
        .unwrap_or("")
        .trim();
    strip_dated_bullet(first).to_string()
}

/// Strip a leading `- YYYY-MM-DD ` when present, leaving the note. A bare `- `
/// without a date is left alone: it may be a summary that legitimately starts
/// with a dash.
fn strip_dated_bullet(line: &str) -> &str {
    let Some(rest) = line.strip_prefix("- ") else {
        return line;
    };
    let Some((date, rest)) = rest.split_once(' ') else {
        return line;
    };
    let looks_like_date = date.len() == 10
        && date.as_bytes().get(4) == Some(&b'-')
        && date.as_bytes().get(7) == Some(&b'-')
        && date.chars().all(|c| c.is_ascii_digit() || c == '-');
    if looks_like_date { rest } else { line }
}

/// Cap a summary to one short line, so a roster of many agents stays cheap to
/// read and cheap to put in a prompt.
#[must_use]
pub fn summarize(text: &str) -> String {
    let text = text.trim();
    if text.chars().count() <= 120 {
        return text.to_string();
    }
    let mut out: String = text.chars().take(117).collect();
    out.push('…');
    out
}

/// Lowercase and collapse non-alphanumerics to a single dash — the same slug
/// rule the fleet protocol derives project slugs from directory names.
#[must_use]
pub fn slugify(name: &str) -> String {
    let mut out = String::new();
    for ch in name.chars() {
        if ch.is_alphanumeric() {
            out.push(ch.to_ascii_lowercase());
        } else if !out.is_empty() && !out.ends_with('-') {
            out.push('-');
        }
    }
    while out.ends_with('-') {
        out.pop();
    }
    out
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn slugify_matches_the_fleet_rule() {
        assert_eq!(slugify("My Agent"), "my-agent");
        assert_eq!(slugify("claude-code"), "claude-code");
        assert_eq!(slugify("  claw  "), "claw");
        assert_eq!(slugify("Rust/Ownership"), "rust-ownership");
        assert_eq!(slugify(""), "");
    }

    #[test]
    fn profiles_are_listed_with_their_first_line_as_summary() {
        let dir = tempfile::tempdir().unwrap();
        let bank = dir.path();
        std::fs::create_dir_all(bank.join("agents")).unwrap();
        std::fs::write(
            bank.join("agents/claw.md"),
            "Rust: ownership, borrow checker, async\n\ndetails follow\n",
        )
        .unwrap();
        std::fs::write(bank.join("agents/fang.md"), "SQL and migrations\n").unwrap();
        std::fs::write(bank.join("agents/ignore.txt"), "not a profile\n").unwrap();

        let profiles = list_agent_profiles(bank);
        assert_eq!(
            profiles,
            vec![
                (
                    "claw".to_string(),
                    "Rust: ownership, borrow checker, async".to_string()
                ),
                ("fang".to_string(), "SQL and migrations".to_string()),
            ]
        );
    }

    #[test]
    fn a_missing_profile_is_none_not_an_error() {
        let dir = tempfile::tempdir().unwrap();
        assert!(load_agent_profile(dir.path(), "nobody").is_none());
    }

    #[test]
    fn peer_profiles_exclude_the_agent_itself() {
        let dir = tempfile::tempdir().unwrap();
        let bank = dir.path();
        std::fs::create_dir_all(bank.join("agents")).unwrap();
        std::fs::write(bank.join("agents/claw.md"), "Rust\n").unwrap();
        std::fs::write(bank.join("agents/fang.md"), "SQL\n").unwrap();

        let peers = list_peer_profiles(bank, "claw");
        assert_eq!(peers, vec![("fang".to_string(), "SQL".to_string())]);
        // The name is slugified before the comparison, so "My Agent" matches
        // the on-disk `my-agent.md`.
        let none = list_peer_profiles(bank, "fang");
        assert_eq!(none, vec![("claw".to_string(), "Rust".to_string())]);
    }

    #[test]
    fn append_and_regenerate_keep_the_roster_in_step() {
        let dir = tempfile::tempdir().unwrap();
        let bank = dir.path();
        append_agent_profile(bank, "claw", "Rust: ownership, borrow checker, async").unwrap();
        append_agent_profile(bank, "fang", "SQL migrations").unwrap();

        regenerate_roster(bank).unwrap();
        let roster = load_roster(bank).unwrap();
        assert!(roster.contains("- claw — Rust: ownership, borrow checker, async"));
        assert!(roster.contains("- fang — SQL migrations"));
    }

    #[test]
    fn summarize_caps_long_lines() {
        let short = summarize("Rust: ownership");
        assert_eq!(short, "Rust: ownership");
        let long = summarize(&"x".repeat(500));
        assert_eq!(long.chars().count(), 118); // 117 chars + ellipsis
        assert!(long.ends_with('…'));
    }

    #[test]
    fn routing_hint_names_a_peer_when_the_task_matches_them() {
        let dir = tempfile::tempdir().unwrap();
        let bank = dir.path();
        std::fs::create_dir_all(bank.join("agents")).unwrap();
        std::fs::write(
            bank.join("agents/claw.md"),
            "Rust: ownership, borrow checker, async\n",
        )
        .unwrap();
        std::fs::write(
            bank.join("agents/fang.md"),
            "SQL migrations and dashboard frontend\n",
        )
        .unwrap();

        // A Rust task matches claw, not fang, so fang is pointed at claw.
        let hint = routing_hint(
            bank,
            "fang",
            "fix the rust borrow checker error in this function",
        )
        .unwrap();
        assert!(hint.contains("claw"), "got: {hint}");
        // A SQL task matches fang itself, so there is nothing to route away.
        assert!(routing_hint(bank, "fang", "write a database migration for postgres").is_none());
        // No significant task words -> no hint.
        assert!(routing_hint(bank, "fang", "ok").is_none());
    }

    #[test]
    fn summary_strips_a_leading_dated_bullet() {
        assert_eq!(summary_of("Rust: ownership\n"), "Rust: ownership");
        assert_eq!(
            summary_of("- 2026-08-16 Rust: ownership\n"),
            "Rust: ownership"
        );
        assert_eq!(
            summary_of("- 2026-08-16 task-12: wrote a parser\n"),
            "task-12: wrote a parser"
        );
        assert_eq!(summary_of("- not a date\n"), "- not a date");
    }
}
