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
            .and_then(|text| {
                text.lines()
                    .find(|line| !line.trim().is_empty())
                    .map(str::to_string)
            })
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
}
