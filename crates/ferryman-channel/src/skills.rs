//! Skills: composable, task-scoped packages of expertise, in the `SKILL.md`
//! convention used by google/skills, Claude Code, Codex, and Prime Agent.
//!
//! A skill is a directory holding a `SKILL.md` with a small frontmatter
//! (`name`, `description`) and a markdown body. The worker loads only the
//! skills whose description overlaps the task, so expertise is added without
//! bloating every prompt - the "add tools without touching the agent core"
//! pattern, in its lightweight markdown form.
//!
//! Skills live in the attachment (`.ferryman/skills/`), not the synced channel:
//! they are trusted instructions injected into agent prompts, so only the
//! operator may author them. A skill in the synced channel would be a
//! prompt-injection vector any peer could plant — the same reason `sources.toml`
//! and `bench.json` are operator-local.

use std::path::PathBuf;

use anyhow::{Result, bail};
use serde::{Deserialize, Serialize};

use crate::ProjectRoute;

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct Skill {
    pub name: String,
    /// When to use it - also the routing signal.
    pub description: String,
    /// The markdown body, frontmatter stripped.
    pub body: String,
}

fn skills_dir(route: &ProjectRoute) -> PathBuf {
    route.attachment.join("skills")
}

/// Load every skill from the channel's `skills/` directory, named first.
/// A missing directory is not an error: no skills means no change.
pub fn load_skills(route: &ProjectRoute) -> Result<Vec<Skill>> {
    let dir = skills_dir(route);
    let mut out = Vec::new();
    let Ok(entries) = std::fs::read_dir(&dir) else {
        return Ok(out);
    };
    for entry in entries.flatten() {
        let skill_dir = entry.path();
        if !skill_dir.is_dir() {
            continue;
        }
        let path = skill_dir.join("SKILL.md");
        let Ok(text) = std::fs::read_to_string(&path) else {
            continue;
        };
        // A malformed skill is skipped, never fatal: one bad file must not stop
        // the whole worker.
        if let Ok(skill) = parse_skill(&text) {
            out.push(skill);
        }
    }
    out.sort_by(|a, b| a.name.cmp(&b.name));
    Ok(out)
}

/// Skills whose description overlaps the task, most relevant first.
///
/// Matching is keyword overlap on significant words (>= 4 letters), with a
/// prefix check so "create" also matches "creating". Deliberately approximate:
/// it needs no embeddings and no network, and the agent itself reads the
/// selected skill's body and can ignore it if it does not apply.
pub fn route<'a>(skills: &'a [Skill], task: &str) -> Vec<&'a Skill> {
    let task_words = words(task);
    let mut scored: Vec<(&Skill, usize)> = skills
        .iter()
        .map(|skill| {
            let overlap = overlaps(&words(&skill.description), &task_words);
            (skill, overlap)
        })
        .filter(|(_, overlap)| *overlap > 0)
        .collect();
    scored.sort_by(|a, b| b.1.cmp(&a.1).then_with(|| a.0.name.cmp(&b.0.name)));
    scored.into_iter().map(|(skill, _)| skill).collect()
}

/// Render the selected skills as a prompt block. Empty when none selected.
pub fn render(skills: &[&Skill]) -> String {
    if skills.is_empty() {
        return String::new();
    }
    let mut out = String::from(
        "The following project skills apply to this task. Follow their instructions.\n\n",
    );
    for skill in skills {
        out.push_str(&format!(
            "## Skill: {}\n{}\n\n",
            skill.name,
            skill.body.trim()
        ));
    }
    out
}

/// Parse a `SKILL.md` into its parts. Handles `name:` and `description:` as
/// single-line values or as a `>-`/`|` block scalar (the google/skills style).
fn parse_skill(text: &str) -> Result<Skill> {
    let text = text.trim_start_matches('\u{feff}').trim_start();
    let Some(after_dashes) = text.strip_prefix("---") else {
        bail!("SKILL.md must start with '---' frontmatter");
    };
    let (front, body) = after_dashes
        .split_once("\n---")
        .map(|(f, b)| (f, b.trim_start_matches('\n')))
        .ok_or_else(|| anyhow::anyhow!("SKILL.md frontmatter is not closed with '---'"))?;

    let mut name = String::new();
    let mut description = String::new();
    let mut block: Vec<String> = Vec::new();
    let mut block_folded = false;
    let mut in_block = false;
    let mut block_indent = 0usize;

    for line in front.lines() {
        let trimmed = line.trim();
        let indent = line.len() - line.trim_start().len();
        if in_block {
            if trimmed.is_empty() {
                block.push(String::new());
                continue;
            }
            if indent > block_indent {
                block.push(trimmed.to_string());
                continue;
            }
            in_block = false;
        }
        if let Some(value) = line.strip_prefix("name:") {
            name = value.trim().trim_matches('"').to_string();
        } else if let Some(value) = line.strip_prefix("description:") {
            let value = value.trim();
            if matches!(value, ">-" | ">- " | "|" | "|-" | "|- " | ">") {
                in_block = true;
                block_folded = value.starts_with('>');
                block_indent = indent;
                block.clear();
            } else if !value.is_empty() {
                description = value.trim_matches('"').to_string();
            }
        }
        // `metadata:` and any other key are ignored (routing/org hints).
    }
    if in_block {
        description = if block_folded {
            block.join(" ")
        } else {
            block.join("\n")
        };
    }
    if name.is_empty() {
        bail!("SKILL.md frontmatter needs a 'name'");
    }
    Ok(Skill {
        name,
        description,
        body: body.to_string(),
    })
}

fn words(text: &str) -> Vec<String> {
    text.split(|c: char| !c.is_alphanumeric())
        .map(str::to_lowercase)
        .filter(|w| w.len() >= 4)
        .collect()
}

fn overlaps(a: &[String], b: &[String]) -> usize {
    let mut hits = 0;
    for x in a {
        for y in b {
            if x == y
                || (x.len() >= 4
                    && y.len() >= 4
                    && (x.starts_with(y.as_str()) || y.starts_with(x.as_str())))
            {
                hits += 1;
            }
        }
    }
    hits
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::ProjectRoute;

    fn test_route(dir: &std::path::Path) -> ProjectRoute {
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
    fn a_skill_parses_block_and_inline_frontmatter() {
        let skill = parse_skill(
            "---\nname: alloydb-basics\nmetadata:\n  category: Databases\ndescription: >-\n  Manages clusters for AlloyDB.\n  Do NOT use for Cloud SQL.\n---\n# AlloyDB Basics\n\ngcloud alloydb clusters create ...\n",
        )
        .unwrap();
        assert_eq!(skill.name, "alloydb-basics");
        assert_eq!(
            skill.description,
            "Manages clusters for AlloyDB. Do NOT use for Cloud SQL."
        );
        assert!(skill.body.contains("# AlloyDB Basics"));
    }

    #[test]
    fn routing_matches_significant_words_with_prefixes() {
        let skill = Skill {
            name: "db".into(),
            description: "Creating and configuring databases".into(),
            body: "".into(),
        };
        let skills = [skill];
        let matched = route(&skills, "create a database cluster now");
        assert_eq!(matched.len(), 1);
        let other = [Skill {
            name: "db".into(),
            description: "baking bread loaves".into(),
            body: "".into(),
        }];
        let none = route(&other, "deploy a web service");
        assert!(none.is_empty());
    }

    #[test]
    fn a_malformed_skill_is_skipped_not_fatal() {
        let dir = tempfile::tempdir().unwrap();
        let route = test_route(dir.path());
        let skills = route.attachment.join("skills");
        std::fs::create_dir_all(skills.join("good")).unwrap();
        std::fs::create_dir_all(skills.join("bad")).unwrap();
        std::fs::write(
            skills.join("good/SKILL.md"),
            "---\nname: good\ndescription: help with tests\n---\n# Good\n",
        )
        .unwrap();
        std::fs::write(skills.join("bad/SKILL.md"), "no frontmatter here\n").unwrap();
        let loaded = load_skills(&route).unwrap();
        assert_eq!(loaded.len(), 1);
        assert_eq!(loaded[0].name, "good");
    }
}
