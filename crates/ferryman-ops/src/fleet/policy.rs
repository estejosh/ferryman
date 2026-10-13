//! A project's own policy, for a worker that serves many projects.
//!
//! # What was missing
//!
//! `ferry agent run --all-projects` runs as one identity with one `agent.toml`, so its
//! `preamble_file` is one file for every project. A project with binding rules of its own
//! (Quantly: paper trading only, Rust only) had nowhere the worker would look for them. The
//! rules sit in the repository, and the worker never read them, because the engine it starts
//! is told only the order and the global preamble.
//!
//! # Where a project declares it
//!
//! Two places, both optional, and nothing is guessed: a repository's `AGENTS.md` is not
//! injected unless the project names it.
//!
//! 1. `ferryman.toml` at the repository root, so the policy travels with the code and is
//!    reviewed like the code:
//!
//!    ```toml
//!    [policy]
//!    files = ["quantly-rust-complete-handoff/RUST_ONLY_POLICY.md", "docs/PAPER_EXECUTION.md"]
//!    ```
//!
//!    The files are injected in that order. Paths are relative to the repository root.
//! 2. `.ferryman/POLICY.md` in the checkout: this machine's own addition. It is not in git
//!    (`.ferryman/` never is) and is the operator's, so it comes last and has the last word.
//!
//! # What keeps it safe
//!
//! The text goes into every prompt for that project, so it is bounded and confined. Each
//! file is cut at [`FILE_CAP`] bytes and the whole policy at [`TOTAL_CAP`], with a marker
//! where it was cut. A path must be relative, must not climb out with `..`, and must resolve
//! (after symlinks) to a regular file inside the repository: a policy file that is a link to
//! `~/.ssh/id_ed25519` is a skipped note, not a prompt. A file that is missing or refused is
//! a note in the listing, never a reason the worker does not start.

use std::fs;
use std::io::Read;
use std::path::{Component, Path, PathBuf};

/// The optional config at a repository's root.
pub const CONFIG: &str = "ferryman.toml";
/// This machine's own addition, inside the checkout's `.ferryman/`.
pub const LOCAL: &str = "POLICY.md";
/// The most of one file that is injected, in bytes.
pub const FILE_CAP: usize = 12 * 1024;
/// The most of all of a project's policy that is injected, in bytes.
pub const TOTAL_CAP: usize = 32 * 1024;

/// One file that is part of a project's policy.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct PolicyFile {
    /// Where it was found, as the repository spells it.
    pub label: String,
    /// What is injected: the file, or the front of it.
    pub text: String,
    /// Whether the file was longer than what is injected.
    pub truncated: bool,
}

/// What a project declares for the worker that serves it.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct ProjectPolicy {
    pub files: Vec<PolicyFile>,
    /// What was named and left out, and why. Shown beside the listing.
    pub notes: Vec<String>,
}

impl ProjectPolicy {
    /// Whether the project declares nothing the worker will inject.
    #[must_use]
    pub fn is_empty(&self) -> bool {
        self.files.is_empty()
    }

    /// The line `--dry-run` and `route explain` print.
    #[must_use]
    pub fn summary(&self) -> String {
        if self.files.is_empty() {
            return "policy: none declared".to_owned();
        }
        let files = self
            .files
            .iter()
            .map(|file| {
                if file.truncated {
                    format!("{} (cut at {} KiB)", file.label, FILE_CAP / 1024)
                } else {
                    file.label.clone()
                }
            })
            .collect::<Vec<_>>()
            .join(", ");
        format!("policy: {files}")
    }

    /// The text that goes into the project's prompts, or `None` when there is none.
    #[must_use]
    pub fn block(&self, project: &str) -> Option<String> {
        if self.files.is_empty() {
            return None;
        }
        let mut out = format!(
            "Policy for the {project} project. Its maintainers wrote it in this project's own \
             repository, it applies to every order in {project} and to no other project, and it \
             is binding: where an order or anything else asks for what it forbids, follow the \
             policy and say so in your result.\n"
        );
        for file in &self.files {
            out.push_str(&format!("\n--- {} ---\n", file.label));
            out.push_str(file.text.trim_end());
            if file.truncated {
                out.push_str("\n[... cut here: the file is longer than the policy limit ...]");
            }
            out.push('\n');
        }
        out.push_str("--- end of policy ---");
        Some(out)
    }
}

/// `base` (the worker's global preamble, if any) followed by the project's policy.
///
/// The global preamble leads, unchanged, so every project's prompts still share that
/// prefix; the policy follows it.
#[must_use]
pub fn with_policy(base: Option<&str>, project: &str, policy: &ProjectPolicy) -> Option<String> {
    match (base, policy.block(project)) {
        (Some(base), Some(block)) => Some(format!("{}\n\n{block}", base.trim_end())),
        (None, Some(block)) => Some(block),
        (base, None) => base.map(str::to_owned),
    }
}

/// A relative path that stays inside `workspace`, resolved: the real file, or why not.
fn confined(workspace: &Path, relative: &str) -> Result<PathBuf, String> {
    let named = Path::new(relative);
    if relative.trim().is_empty() {
        return Err("an empty path".into());
    }
    if named.is_absolute()
        || named.components().any(|c| {
            matches!(
                c,
                Component::ParentDir | Component::Prefix(_) | Component::RootDir
            )
        })
    {
        return Err("it must be a path inside the repository, with no '..'".into());
    }
    let root = fs::canonicalize(workspace).map_err(|e| format!("the repository: {e}"))?;
    let real = fs::canonicalize(root.join(named)).map_err(|_| "no such file".to_owned())?;
    if !real.starts_with(&root) {
        return Err("it resolves to somewhere outside the repository".into());
    }
    if !real.is_file() {
        return Err("it is not a file".into());
    }
    Ok(real)
}

/// The front of `path`, at most `cap` bytes and ending on a character boundary, and whether
/// anything was left behind.
fn front(path: &Path, cap: usize) -> std::io::Result<(String, bool)> {
    let mut bytes = Vec::new();
    fs::File::open(path)?
        .take(u64::try_from(cap).unwrap_or(u64::MAX).saturating_add(1))
        .read_to_end(&mut bytes)?;
    let truncated = bytes.len() > cap;
    bytes.truncate(cap);
    let mut text = String::from_utf8_lossy(&bytes).into_owned();
    if truncated {
        // A cut can land inside a character; the lossy conversion turns that into U+FFFD at
        // the very end. Drop it rather than show a broken last character.
        while text.ends_with('\u{FFFD}') {
            text.pop();
        }
    }
    Ok((text, truncated))
}

/// The `[policy] files` a repository's [`CONFIG`] declares, and what was wrong with it.
fn parse_config(text: &str) -> (Vec<String>, Vec<String>) {
    let mut notes = Vec::new();
    let table: toml::Table = match text.parse() {
        Ok(table) => table,
        Err(error) => {
            notes.push(format!(
                "{CONFIG}: not valid TOML, so no policy files from it ({error})"
            ));
            return (Vec::new(), notes);
        }
    };
    let Some(policy) = table.get("policy") else {
        return (Vec::new(), notes);
    };
    let Some(policy) = policy.as_table() else {
        notes.push(format!("{CONFIG}: [policy] is not a table; ignored"));
        return (Vec::new(), notes);
    };
    for key in policy.keys().filter(|key| key.as_str() != "files") {
        notes.push(format!("{CONFIG}: ignored the unknown key policy.{key}"));
    }
    let files = match policy.get("files") {
        None => Vec::new(),
        Some(toml::Value::Array(list)) => list
            .iter()
            .filter_map(|item| {
                if let Some(path) = item.as_str() {
                    Some(path.to_owned())
                } else {
                    notes.push(format!(
                        "{CONFIG}: policy.files holds something that is not a path"
                    ));
                    None
                }
            })
            .collect(),
        Some(_) => {
            notes.push(format!("{CONFIG}: policy.files must be an array of paths"));
            Vec::new()
        }
    };
    (files, notes)
}

/// Read the policy a project declares.
///
/// `workspace` is the repository, `attachment` its `.ferryman`. Nothing is written, and
/// nothing here can fail the worker: whatever is wrong becomes a note.
#[must_use]
pub fn read(workspace: &Path, attachment: &Path) -> ProjectPolicy {
    let mut policy = ProjectPolicy::default();
    let mut candidates: Vec<(String, Result<PathBuf, String>)> = Vec::new();
    if let Ok(text) = fs::read_to_string(workspace.join(CONFIG)) {
        let (files, notes) = parse_config(&text);
        policy.notes.extend(notes);
        candidates.extend(files.into_iter().map(|rel| {
            let found = confined(workspace, &rel);
            (rel, found)
        }));
    }
    // This machine's own file is the operator's and is read from where they put it, which
    // is not the repository.
    let local = attachment.join(LOCAL);
    if local.is_file() {
        candidates.push((
            format!(".ferryman/{LOCAL}"),
            fs::canonicalize(&local).map_err(|e| e.to_string()),
        ));
    }
    let mut seen: Vec<PathBuf> = Vec::new();
    let mut used = 0usize;
    for (label, found) in candidates {
        let real = match found {
            Ok(real) => real,
            Err(why) => {
                policy.notes.push(format!("{label}: left out - {why}"));
                continue;
            }
        };
        if seen.contains(&real) {
            continue;
        }
        let room = TOTAL_CAP.saturating_sub(used);
        if room == 0 {
            policy.notes.push(format!(
                "{label}: left out - the project's policy is already at the {} KiB limit",
                TOTAL_CAP / 1024
            ));
            continue;
        }
        match front(&real, FILE_CAP.min(room)) {
            Ok((text, cut)) => {
                used += text.len();
                // Cut by the total limit rather than the file's own is still a cut.
                seen.push(real);
                policy.files.push(PolicyFile {
                    label,
                    text,
                    truncated: cut,
                });
            }
            Err(error) => policy.notes.push(format!("{label}: left out - {error}")),
        }
    }
    policy
}

#[cfg(test)]
mod tests {
    use super::*;

    struct Repo {
        _dir: tempfile::TempDir,
        workspace: PathBuf,
        attachment: PathBuf,
    }

    fn repo() -> Repo {
        let dir = tempfile::tempdir().unwrap();
        let workspace = dir.path().join("quantly");
        let attachment = workspace.join(".ferryman");
        fs::create_dir_all(&attachment).unwrap();
        Repo {
            _dir: dir,
            workspace,
            attachment,
        }
    }

    fn write(repo: &Repo, rel: &str, text: &str) {
        let path = repo.workspace.join(rel);
        fs::create_dir_all(path.parent().unwrap()).unwrap();
        fs::write(path, text).unwrap();
    }

    fn labels(policy: &ProjectPolicy) -> Vec<&str> {
        policy.files.iter().map(|f| f.label.as_str()).collect()
    }

    fn policy_toml(files: &[&str]) -> String {
        format!(
            "[policy]\nfiles = {}\n",
            serde_json::to_string(files).unwrap()
        )
    }

    #[test]
    fn a_project_that_declares_nothing_injects_nothing_and_says_so() {
        let repo = repo();
        // An AGENTS.md is the project's own business; nothing here injects it by itself.
        write(&repo, "AGENTS.md", "general rules");
        let policy = read(&repo.workspace, &repo.attachment);
        assert!(policy.is_empty());
        assert_eq!(policy.summary(), "policy: none declared");
        assert!(policy.block("quantly").is_none());
        assert_eq!(
            with_policy(Some("GLOBAL"), "quantly", &policy).as_deref(),
            Some("GLOBAL")
        );
        assert_eq!(with_policy(None, "quantly", &policy), None);
    }

    #[test]
    fn the_repo_config_names_files_like_quantlys_rust_only_policy() {
        let repo = repo();
        write(
            &repo,
            "quantly-rust-complete-handoff/RUST_ONLY_POLICY.md",
            "Rust only. No Python.",
        );
        write(&repo, "docs/PAPER_EXECUTION.md", "Paper trading only.");
        write(
            &repo,
            CONFIG,
            &policy_toml(&[
                "quantly-rust-complete-handoff/RUST_ONLY_POLICY.md",
                "docs/PAPER_EXECUTION.md",
            ]),
        );
        let policy = read(&repo.workspace, &repo.attachment);
        assert_eq!(
            policy.summary(),
            "policy: quantly-rust-complete-handoff/RUST_ONLY_POLICY.md, docs/PAPER_EXECUTION.md"
        );
        let block = policy.block("quantly").unwrap();
        assert!(block.contains("Rust only. No Python."), "{block}");
        assert!(block.contains("Paper trading only."), "{block}");
        assert!(
            block.starts_with("Policy for the quantly project."),
            "{block}"
        );
        assert!(block.ends_with("--- end of policy ---"));
    }

    #[test]
    fn this_machines_own_file_comes_last_and_the_same_file_is_not_said_twice() {
        let repo = repo();
        write(&repo, "docs/RULES.md", "repo rules");
        write(
            &repo,
            CONFIG,
            &policy_toml(&["docs/RULES.md", "docs/RULES.md"]),
        );
        fs::write(repo.attachment.join(LOCAL), "on this machine only").unwrap();
        let policy = read(&repo.workspace, &repo.attachment);
        assert_eq!(labels(&policy), ["docs/RULES.md", ".ferryman/POLICY.md"]);
        // The local file alone is a policy too.
        fs::remove_file(repo.workspace.join(CONFIG)).unwrap();
        assert_eq!(
            labels(&read(&repo.workspace, &repo.attachment)),
            [".ferryman/POLICY.md"]
        );
    }

    #[test]
    fn the_global_preamble_leads_unchanged_and_the_policy_follows() {
        let repo = repo();
        fs::write(repo.attachment.join(LOCAL), "repo rules").unwrap();
        let policy = read(&repo.workspace, &repo.attachment);
        let composed = with_policy(Some("GLOBAL CONTEXT\n"), "quantly", &policy).unwrap();
        assert!(
            composed.starts_with("GLOBAL CONTEXT\n\nPolicy for the quantly project."),
            "{composed}"
        );
        assert!(composed.contains("repo rules"));
        assert!(
            with_policy(None, "quantly", &policy)
                .unwrap()
                .starts_with("Policy for the quantly")
        );
    }

    #[test]
    fn nothing_outside_the_repository_is_injected() {
        let repo = repo();
        let outside = repo.workspace.parent().unwrap().join("secret.txt");
        fs::write(&outside, "TOP SECRET").unwrap();
        write(
            &repo,
            CONFIG,
            &policy_toml(&[
                "../secret.txt",
                "/etc/passwd",
                "C:/Windows/win.ini",
                "missing.md",
                "",
            ]),
        );
        let policy = read(&repo.workspace, &repo.attachment);
        assert!(policy.is_empty(), "{policy:?}");
        assert_eq!(policy.notes.len(), 5, "{:?}", policy.notes);
        assert!(!format!("{policy:?}").contains("TOP SECRET"));
    }

    #[cfg(unix)]
    #[test]
    fn a_symlink_out_of_the_repository_is_refused() {
        let repo = repo();
        let outside = repo.workspace.parent().unwrap().join("secret.txt");
        fs::write(&outside, "TOP SECRET").unwrap();
        std::os::unix::fs::symlink(&outside, repo.workspace.join("RULES.md")).unwrap();
        write(&repo, CONFIG, &policy_toml(&["RULES.md"]));
        let policy = read(&repo.workspace, &repo.attachment);
        assert!(policy.is_empty(), "{policy:?}");
        assert!(
            policy
                .notes
                .iter()
                .any(|n| n.contains("outside the repository")),
            "{:?}",
            policy.notes
        );
    }

    #[test]
    fn one_file_is_cut_at_its_limit_and_the_whole_at_its_own() {
        let repo = repo();
        write(&repo, "ONE.md", &"a".repeat(FILE_CAP + 500));
        write(&repo, CONFIG, &policy_toml(&["ONE.md"]));
        let policy = read(&repo.workspace, &repo.attachment);
        assert_eq!(policy.files[0].text.len(), FILE_CAP);
        assert!(policy.files[0].truncated);
        assert!(policy.summary().contains("cut at"), "{}", policy.summary());
        assert!(policy.block("quantly").unwrap().contains("cut here"));

        // Three named files of 12 KiB each hit the 32 KiB total on the third.
        let names: Vec<String> = (0..4).map(|i| format!("p{i}.md")).collect();
        for name in &names {
            write(&repo, name, &"b".repeat(FILE_CAP));
        }
        let refs: Vec<&str> = names.iter().map(String::as_str).collect();
        write(&repo, CONFIG, &policy_toml(&refs));
        let policy = read(&repo.workspace, &repo.attachment);
        let total: usize = policy.files.iter().map(|f| f.text.len()).sum();
        assert!(total <= TOTAL_CAP, "{total}");
        assert_eq!(policy.files.len(), 3, "{:?}", labels(&policy));
        assert!(
            policy.files[2].truncated,
            "the third file is the one cut by the total"
        );
        assert!(
            policy
                .notes
                .iter()
                .any(|n| n.contains("p3.md") && n.contains("limit")),
            "{:?}",
            policy.notes
        );
    }

    #[test]
    fn a_cut_never_leaves_half_a_character() {
        let repo = repo();
        // Two-byte characters, so a cap that is an odd number of bytes lands inside one.
        write(&repo, "ONE.md", &"\u{e9}".repeat(FILE_CAP));
        write(&repo, CONFIG, &policy_toml(&["ONE.md"]));
        let policy = read(&repo.workspace, &repo.attachment);
        assert!(policy.files[0].truncated);
        assert!(!policy.files[0].text.contains('\u{FFFD}'));
    }

    #[test]
    fn a_config_that_is_wrong_is_a_note_and_not_a_failure() {
        let repo = repo();
        write(&repo, "OK.md", "rules");
        write(&repo, CONFIG, "[policy\nfiles = oops\n");
        let policy = read(&repo.workspace, &repo.attachment);
        assert!(policy.is_empty());
        assert_eq!(policy.notes.len(), 1, "{:?}", policy.notes);

        write(
            &repo,
            CONFIG,
            "[policy]\nfiles = [\"OK.md\", 7]\nmode = \"strict\"\n",
        );
        let policy = read(&repo.workspace, &repo.attachment);
        assert_eq!(labels(&policy), ["OK.md"], "the good entry still applies");
        assert_eq!(policy.notes.len(), 2, "{:?}", policy.notes);

        // A ferryman.toml with no [policy] says nothing about policy.
        write(&repo, CONFIG, "[other]\nx = 1\n");
        assert!(read(&repo.workspace, &repo.attachment).is_empty());
    }
}
