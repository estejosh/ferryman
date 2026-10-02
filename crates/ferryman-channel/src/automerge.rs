//! Auto-merge: once an improvement holds both keys, fm may merge it on its own - but
//! only low-risk work, and only where the project's engine policy says
//! `auto_merge = "low-risk"`. The default is `none`: every approved improvement waits
//! for the master, as it always did.
//!
//! ```text
//! <channel>/merges/<order>/r<rev>.authorized.<agent>.json  both keys held: the owner may merge
//! <channel>/merges/<order>/r<rev>.merged.<agent>.json      merged, into what, at which commit
//! <channel>/merges/<order>/r<rev>.held.<agent>.json        not merged on its own, and why
//! ```
//!
//! Low risk means every file the branch changes is one of:
//!
//! - **docs**: `*.md`, `docs/**`, license-like text (LICENSE, COPYING, NOTICE, AUTHORS),
//!   and Rust files whose change is to comments only;
//! - **tests**: `tests/**` (not under `src/`), `*_test.*`, `test_*.*`, `*.spec.*` and
//!   `*.test.*` for languages other than Rust, and Rust files changed only inside a
//!   `#[cfg(test)]` module that runs to the end of the file;
//! - **dependencies**: a lockfile changed in place, or a manifest whose only change is
//!   dependency versions - `Cargo.toml`, `package.json`, `pyproject.toml`,
//!   `requirements*.txt`, `go.mod`. A new dependency, a feature, a source, a script, the
//!   package's own version: code.
//!
//! Anything else - code, config, an added or removed lockfile, an executable bit, a
//! symlink, a submodule, more than [`MAX_FILES`] files - is code, and the improvement
//! waits for the master, "approved, ready to merge".
//!
//! The classification reads the branch as git has it - every file between the default
//! branch and the reviewed commit - rather than trusting a summary, and it is run by the
//! worker that built the branch, in its own repository, right before it merges. The
//! merge is a fast-forward when it can be and a merge commit otherwise; the default
//! branch is pushed only when that worker already pushes for the project, never with
//! force. Anything that goes wrong - a conflict, a branch that moved after review, a
//! checkout with uncommitted changes, a remote ahead of it, a push refused - leaves it
//! for the master. fm cannot see CI, so it does not wait on it: the checks the worker
//! ran are in the evidence the review engine judged.
//!
//! The same gate applies to every project, fm's own included: there is no exemption.

use std::collections::BTreeMap;
use std::path::{Path, PathBuf};
use std::process::{Command, Stdio};

use anyhow::{Context, Result, bail};
use chrono::{DateTime, Utc};
use serde::{Deserialize, Serialize};
use serde_json::Value;

use crate::{AgentIdentity, ProjectRoute, SignatureCheck, Task, policy::AutoMerge};

/// More changed files than this is not low risk: it is a change nobody can skim.
pub const MAX_FILES: usize = 300;

pub const AUTHORIZED: &str = "authorized";
pub const MERGED: &str = "merged";
pub const HELD: &str = "held";

/// What one changed file is.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum Kind {
    Docs,
    Tests,
    Deps,
    Code,
}

impl Kind {
    #[must_use]
    pub fn as_str(self) -> &'static str {
        match self {
            Self::Docs => "docs",
            Self::Tests => "tests",
            Self::Deps => "deps",
            Self::Code => "code",
        }
    }
}

/// One `@@ -a,b +c,d @@` hunk of a zero-context diff.
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq)]
pub struct Hunk {
    pub old_start: usize,
    pub old_len: usize,
    pub new_start: usize,
    pub new_len: usize,
}

/// One file the branch changes, as git has it.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct FileChange {
    pub path: String,
    /// The text before, when it existed and is text.
    pub old: Option<String>,
    /// The text after, when it exists and is text.
    pub new: Option<String>,
    pub existed: bool,
    pub exists: bool,
    pub hunks: Vec<Hunk>,
    /// Not text on one side or the other.
    pub binary: bool,
    /// An executable bit, a symlink or a submodule, on either side.
    pub unusual: bool,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct Classified {
    pub path: String,
    pub kind: Kind,
    pub why: String,
}

/// Every changed file, classified.
#[derive(Debug, Clone, Default, PartialEq, Eq, Serialize, Deserialize)]
pub struct Risk {
    pub files: Vec<Classified>,
}

impl Risk {
    /// Something changed, and all of it is docs, tests or dependency versions.
    #[must_use]
    pub fn low(&self) -> bool {
        !self.files.is_empty() && self.files.iter().all(|file| file.kind != Kind::Code)
    }

    /// `low risk: 2 docs, 1 tests` or `touches code or config: src/lib.rs (code)`.
    #[must_use]
    pub fn describe(&self) -> String {
        let code: Vec<&Classified> = self
            .files
            .iter()
            .filter(|file| file.kind == Kind::Code)
            .collect();
        if !code.is_empty() {
            let named: Vec<String> = code
                .iter()
                .take(5)
                .map(|file| format!("{} ({})", file.path, file.why))
                .collect();
            return format!(
                "touches code or config: {}{}",
                named.join(", "),
                if code.len() > 5 {
                    format!(" and {} more", code.len() - 5)
                } else {
                    String::new()
                }
            );
        }
        if self.files.is_empty() {
            return "changes nothing".to_string();
        }
        let mut counts: BTreeMap<Kind, usize> = BTreeMap::new();
        for file in &self.files {
            *counts.entry(file.kind).or_default() += 1;
        }
        let parts: Vec<String> = counts
            .iter()
            .map(|(kind, count)| format!("{count} {}", kind.as_str()))
            .collect();
        format!("low risk: {}", parts.join(", "))
    }
}

/// Classify every change.
#[must_use]
pub fn classify(changes: &[FileChange]) -> Risk {
    Risk {
        files: changes.iter().map(classify_file).collect(),
    }
}

/// Classify one change. When in doubt: code.
#[must_use]
pub fn classify_file(change: &FileChange) -> Classified {
    let (kind, why) = kind_of(change);
    Classified {
        path: change.path.clone(),
        kind,
        why: why.to_string(),
    }
}

const LOCKFILES: &[&str] = &[
    "Cargo.lock",
    "package-lock.json",
    "npm-shrinkwrap.json",
    "pnpm-lock.yaml",
    "yarn.lock",
    "go.sum",
    "poetry.lock",
    "uv.lock",
];

fn kind_of(change: &FileChange) -> (Kind, &'static str) {
    let path = change.path.as_str();
    if change.unusual {
        return (Kind::Code, "an executable bit, a symlink or a submodule");
    }
    if is_docs_path(path) {
        return (Kind::Docs, "documentation");
    }
    if is_test_path(path) {
        return (Kind::Tests, "a test file");
    }
    let name = file_name(path);
    if LOCKFILES.contains(&name) {
        return if change.existed && change.exists && !change.binary {
            (Kind::Deps, "a lockfile")
        } else {
            (Kind::Code, "a lockfile added or removed")
        };
    }
    let (Some(old), Some(new)) = (change.old.as_deref(), change.new.as_deref()) else {
        return (
            Kind::Code,
            if change.binary {
                "not text"
            } else if !change.existed {
                "a new file"
            } else {
                "a deleted file"
            },
        );
    };
    let versions_only = |same: bool| {
        if same {
            (Kind::Deps, "dependency versions only")
        } else {
            (Kind::Code, "changes more than dependency versions")
        }
    };
    match name {
        "Cargo.toml" => {
            return versions_only(same_some(cargo_versionless(old), cargo_versionless(new)));
        }
        "pyproject.toml" => {
            return versions_only(same_some(py_versionless(old), py_versionless(new)));
        }
        "package.json" => {
            return versions_only(same_some(npm_versionless(old), npm_versionless(new)));
        }
        "go.mod" => return versions_only(gomod_versionless(old) == gomod_versionless(new)),
        _ if is_requirements(name) => {
            return versions_only(req_versionless(old) == req_versionless(new));
        }
        _ => {}
    }
    if path.ends_with(".rs") {
        if rust_tests_only(old, new, &change.hunks) {
            return (Kind::Tests, "inside #[cfg(test)] only");
        }
        if rust_comments_only(old, new) {
            return (Kind::Docs, "comments only");
        }
    }
    (Kind::Code, "code")
}

fn same_some<T: PartialEq>(old: Option<T>, new: Option<T>) -> bool {
    matches!((old, new), (Some(old), Some(new)) if old == new)
}

fn file_name(path: &str) -> &str {
    path.rsplit('/').next().unwrap_or(path)
}

fn is_docs_path(path: &str) -> bool {
    let lower = path.to_ascii_lowercase();
    if lower.ends_with(".md") || lower.starts_with("docs/") {
        return true;
    }
    let name = file_name(&lower);
    let (stem, ext) = name.split_once('.').unwrap_or((name, ""));
    matches!(ext, "" | "txt" | "md")
        && [
            "license",
            "licence",
            "copying",
            "notice",
            "authors",
            "contributors",
            "copyright",
        ]
        .iter()
        .any(|word| stem == *word || stem.starts_with(&format!("{word}-")))
}

fn is_test_path(path: &str) -> bool {
    let parts: Vec<&str> = path.split('/').collect();
    let Some((name, dirs)) = parts.split_last() else {
        return false;
    };
    if let Some(at) = dirs.iter().position(|dir| *dir == "tests")
        && !dirs[..at].contains(&"src")
    {
        return true;
    }
    // Rust test code is a `tests/` directory or a `#[cfg(test)]` module: a file named
    // like a test under `src/` may well be compiled into the library.
    if name.ends_with(".rs") {
        return false;
    }
    let lower = name.to_ascii_lowercase();
    let Some((stem, _)) = lower.rsplit_once('.') else {
        return false;
    };
    stem.ends_with("_test")
        || stem.ends_with(".spec")
        || stem.ends_with(".test")
        || (lower.starts_with("test_") && !stem.is_empty())
}

fn is_requirements(name: &str) -> bool {
    let lower = name.to_ascii_lowercase();
    lower.starts_with("requirements") && lower.ends_with(".txt")
}

// --- manifests: equal once every dependency version is taken out -----------------------

/// `Cargo.toml` with every dependency's version replaced by `*`.
fn cargo_versionless(text: &str) -> Option<toml::Value> {
    let mut value: toml::Value = toml::from_str(text).ok()?;
    let table = value.as_table_mut()?;
    strip_dependency_tables(table);
    if let Some(workspace) = table
        .get_mut("workspace")
        .and_then(toml::Value::as_table_mut)
    {
        strip_dependency_tables(workspace);
    }
    if let Some(targets) = table.get_mut("target").and_then(toml::Value::as_table_mut) {
        for target in targets.iter_mut().map(|(_, value)| value) {
            if let Some(target) = target.as_table_mut() {
                strip_dependency_tables(target);
            }
        }
    }
    Some(value)
}

fn strip_dependency_tables(table: &mut toml::map::Map<String, toml::Value>) {
    for key in [
        "dependencies",
        "dev-dependencies",
        "build-dependencies",
        "dev_dependencies",
        "build_dependencies",
    ] {
        if let Some(dependencies) = table.get_mut(key).and_then(toml::Value::as_table_mut) {
            for dependency in dependencies.iter_mut().map(|(_, value)| value) {
                match dependency {
                    toml::Value::String(version) => *version = "*".to_string(),
                    toml::Value::Table(spec) => {
                        if let Some(version) = spec.get_mut("version") {
                            *version = toml::Value::String("*".to_string());
                        }
                    }
                    _ => {}
                }
            }
        }
    }
}

/// `pyproject.toml` with every dependency's version taken out: PEP 621 and 735 lists,
/// and Poetry's tables.
fn py_versionless(text: &str) -> Option<toml::Value> {
    let mut value: toml::Value = toml::from_str(text).ok()?;
    let table = value.as_table_mut()?;
    if let Some(project) = table.get_mut("project").and_then(toml::Value::as_table_mut) {
        if let Some(list) = project.get_mut("dependencies") {
            strip_requirement_list(list);
        }
        if let Some(extras) = project
            .get_mut("optional-dependencies")
            .and_then(toml::Value::as_table_mut)
        {
            extras
                .iter_mut()
                .for_each(|(_, list)| strip_requirement_list(list));
        }
    }
    if let Some(groups) = table
        .get_mut("dependency-groups")
        .and_then(toml::Value::as_table_mut)
    {
        groups
            .iter_mut()
            .for_each(|(_, list)| strip_requirement_list(list));
    }
    if let Some(poetry) = table
        .get_mut("tool")
        .and_then(toml::Value::as_table_mut)
        .and_then(|tool| tool.get_mut("poetry"))
        .and_then(toml::Value::as_table_mut)
    {
        strip_dependency_tables(poetry);
        if let Some(groups) = poetry.get_mut("group").and_then(toml::Value::as_table_mut) {
            for (_, group) in groups.iter_mut() {
                if let Some(group) = group.as_table_mut() {
                    strip_dependency_tables(group);
                }
            }
        }
    }
    Some(value)
}

fn strip_requirement_list(list: &mut toml::Value) {
    for item in list.as_array_mut().into_iter().flatten() {
        if let toml::Value::String(requirement) = item
            && let Some(name) = requirement_name(requirement)
        {
            *requirement = name;
        }
    }
}

/// The name (and extras) of a requirement whose remainder is a version spec and nothing
/// else - no markers, no URL. `None` otherwise, so the line is compared as it is.
fn requirement_name(requirement: &str) -> Option<String> {
    let requirement = requirement.trim();
    let end = requirement
        .find(|c: char| !(c.is_ascii_alphanumeric() || "._-".contains(c)))
        .unwrap_or(requirement.len());
    if end == 0 {
        return None;
    }
    let mut name = requirement[..end]
        .to_ascii_lowercase()
        .replace(['_', '.'], "-");
    let mut rest = requirement[end..].trim_start();
    if rest.starts_with('[') {
        let close = rest.find(']')?;
        name.push_str(&rest[..=close].replace(' ', ""));
        rest = rest[close + 1..].trim_start();
    }
    rest.chars()
        .all(|c| c.is_ascii_alphanumeric() || " .*+!=<>~,-".contains(c))
        .then_some(name)
}

/// `requirements*.txt`, one entry per line, with versions taken out of plain requirements.
fn req_versionless(text: &str) -> Vec<String> {
    text.lines()
        .map(str::trim)
        .filter(|line| !line.is_empty() && !line.starts_with('#'))
        .map(|line| {
            if line.starts_with('-') {
                line.to_string()
            } else {
                requirement_name(line).unwrap_or_else(|| line.to_string())
            }
        })
        .collect()
}

/// `package.json` with plain version ranges in the dependency maps replaced by `*`. A
/// git, file, link, workspace or alias spec is left as it is.
fn npm_versionless(text: &str) -> Option<Value> {
    let mut value: Value = serde_json::from_str(text).ok()?;
    for key in [
        "dependencies",
        "devDependencies",
        "peerDependencies",
        "optionalDependencies",
    ] {
        if let Some(dependencies) = value.get_mut(key).and_then(Value::as_object_mut) {
            for spec in dependencies.iter_mut().map(|(_, value)| value) {
                if spec.as_str().is_some_and(|range| {
                    !range.trim().is_empty()
                        && range
                            .chars()
                            .all(|c| c.is_ascii_alphanumeric() || " .^~<>=*|-+".contains(c))
                }) {
                    *spec = Value::String("*".to_string());
                }
            }
        }
    }
    Some(value)
}

/// `go.mod`, line by line, with the version taken out of each `require`.
fn gomod_versionless(text: &str) -> Vec<String> {
    fn requirement(entry: &str) -> String {
        let (body, comment) = match entry.split_once("//") {
            Some((body, comment)) => (body.trim(), Some(comment.trim())),
            None => (entry.trim(), None),
        };
        let parts: Vec<&str> = body.split_whitespace().collect();
        if let [module, version] = parts[..]
            && version.starts_with('v')
            && version[1..].starts_with(|c: char| c.is_ascii_digit())
        {
            return match comment {
                Some(comment) => format!("{module} V // {comment}"),
                None => format!("{module} V"),
            };
        }
        entry.trim().to_string()
    }
    let mut out = Vec::new();
    let mut in_require = false;
    for line in text.lines().map(str::trim).filter(|line| !line.is_empty()) {
        if in_require {
            if line == ")" {
                in_require = false;
                out.push(")".to_string());
            } else {
                out.push(requirement(line));
            }
        } else if line == "require (" {
            in_require = true;
            out.push(line.to_string());
        } else if let Some(entry) = line.strip_prefix("require ") {
            out.push(format!("require {}", requirement(entry)));
        } else {
            out.push(line.to_string());
        }
    }
    out
}

// --- Rust: comments only, or inside the test module only ---------------------------------

/// Rust source as code characters (with their 0-based line) and literals, comments gone.
#[derive(Debug, Clone, PartialEq, Eq)]
enum Tok {
    Code(char, usize),
    Literal(String),
}

/// Lex just enough Rust to tell code from comments and literals. `None` for anything it
/// cannot finish - an unterminated string or comment - which then counts as code.
fn rust_tokens(text: &str) -> Option<Vec<Tok>> {
    let chars: Vec<char> = text.chars().collect();
    let mut out = Vec::new();
    let mut line = 0usize;
    let mut i = 0usize;
    let ident = |c: char| c.is_alphanumeric() || c == '_';
    while i < chars.len() {
        let c = chars[i];
        let next = chars.get(i + 1).copied();
        if c == '/' && next == Some('/') {
            while i < chars.len() && chars[i] != '\n' {
                i += 1;
            }
            out.push(Tok::Code(' ', line));
            continue;
        }
        if c == '/' && next == Some('*') {
            let mut depth = 1;
            i += 2;
            while depth > 0 {
                let a = *chars.get(i)?;
                let b = chars.get(i + 1).copied();
                if a == '/' && b == Some('*') {
                    depth += 1;
                    i += 2;
                } else if a == '*' && b == Some('/') {
                    depth -= 1;
                    i += 2;
                } else {
                    if a == '\n' {
                        line += 1;
                    }
                    i += 1;
                }
            }
            out.push(Tok::Code(' ', line));
            continue;
        }
        let after_ident = i > 0 && ident(chars[i - 1]);
        if !after_ident && (c == 'r' || (c == 'b' && next == Some('r'))) {
            let mut j = if c == 'b' { i + 2 } else { i + 1 };
            let mut hashes = 0;
            while chars.get(j) == Some(&'#') {
                hashes += 1;
                j += 1;
            }
            if chars.get(j) == Some(&'"') {
                let start = i;
                j += 1;
                loop {
                    let a = *chars.get(j)?;
                    if a == '"' && (0..hashes).all(|k| chars.get(j + 1 + k) == Some(&'#')) {
                        j += 1 + hashes;
                        break;
                    }
                    if a == '\n' {
                        line += 1;
                    }
                    j += 1;
                }
                out.push(Tok::Literal(chars[start..j].iter().collect()));
                i = j;
                continue;
            }
        }
        if c == '"' {
            let start = i;
            let mut j = i + 1;
            loop {
                let a = *chars.get(j)?;
                if a == '\\' {
                    if chars.get(j + 1) == Some(&'\n') {
                        line += 1;
                    }
                    j += 2;
                    continue;
                }
                if a == '\n' {
                    line += 1;
                }
                j += 1;
                if a == '"' {
                    break;
                }
            }
            out.push(Tok::Literal(chars[start..j].iter().collect()));
            i = j;
            continue;
        }
        if c == '\'' {
            if next == Some('\\') {
                let mut j = i + 3;
                while *chars.get(j)? != '\'' {
                    if chars[j] == '\n' || j - i > 12 {
                        return None;
                    }
                    j += 1;
                }
                out.push(Tok::Literal(chars[i..=j].iter().collect()));
                i = j + 1;
                continue;
            }
            if chars.get(i + 2) == Some(&'\'') {
                out.push(Tok::Literal(chars[i..i + 3].iter().collect()));
                i += 3;
                continue;
            }
            // A lifetime or a label.
        }
        out.push(Tok::Code(c, line));
        if c == '\n' {
            line += 1;
        }
        i += 1;
    }
    Some(out)
}

/// The code with comments out and whitespace runs folded; literals kept exactly.
fn rust_normal(text: &str) -> Option<String> {
    let mut out = String::new();
    for token in rust_tokens(text)? {
        match token {
            Tok::Code(c, _) if c.is_whitespace() => {
                if !out.ends_with(' ') {
                    out.push(' ');
                }
            }
            Tok::Code(c, _) => out.push(c),
            Tok::Literal(literal) => {
                out.push('\u{1}');
                out.push_str(&literal);
                out.push('\u{1}');
            }
        }
    }
    Some(out.trim().to_string())
}

fn rust_comments_only(old: &str, new: &str) -> bool {
    old != new && same_some(rust_normal(old), rust_normal(new))
}

/// The 1-based line of the `mod` a `#[cfg(test)]` module opens on, when that module runs
/// to the end of the file - checked by matching its braces as code, so a brace in a
/// string, a comment or an indented line cannot fake the end of it.
fn trailing_test_module(text: &str) -> Option<usize> {
    let lines: Vec<&str> = text.lines().collect();
    let tokens = rust_tokens(text)?;
    for (at, line) in lines.iter().enumerate() {
        if line.trim_end() != "#[cfg(test)]"
            || !tokens
                .iter()
                .any(|token| matches!(token, Tok::Code('#', l) if *l == at))
        {
            continue;
        }
        let Some(module) = (at + 1..lines.len()).find(|k| !lines[*k].trim().is_empty()) else {
            continue;
        };
        let head = lines[module].trim_end();
        let opens_a_module = ["mod ", "pub mod ", "pub(crate) mod "]
            .iter()
            .any(|prefix| head.starts_with(prefix))
            && head.ends_with('{');
        if !opens_a_module {
            continue;
        }
        let Some(open) = tokens
            .iter()
            .position(|token| matches!(token, Tok::Code('{', l) if *l == module))
        else {
            continue;
        };
        let mut depth = 0i64;
        let mut close = None;
        for (k, token) in tokens.iter().enumerate().skip(open) {
            match token {
                Tok::Code('{', _) => depth += 1,
                Tok::Code('}', _) => {
                    depth -= 1;
                    if depth == 0 {
                        close = Some(k);
                        break;
                    }
                }
                _ => {}
            }
        }
        let Some(close) = close else {
            continue;
        };
        if tokens[close + 1..]
            .iter()
            .all(|token| matches!(token, Tok::Code(c, _) if c.is_whitespace()))
        {
            return Some(module + 1);
        }
    }
    None
}

/// Every hunk falls after the line that opens the trailing test module, before and after.
fn rust_tests_only(old: &str, new: &str, hunks: &[Hunk]) -> bool {
    let (Some(old_module), Some(new_module)) =
        (trailing_test_module(old), trailing_test_module(new))
    else {
        return false;
    };
    !hunks.is_empty()
        && hunks.iter().all(|hunk| {
            hunk.old_len + hunk.new_len > 0
                && (hunk.old_len == 0 || hunk.old_start > old_module)
                && (hunk.new_len == 0 || hunk.new_start > new_module)
        })
}

// --- git ---------------------------------------------------------------------------------

fn git_out(dir: &Path, args: &[&str]) -> Result<Vec<u8>> {
    let output = Command::new("git")
        .arg("-C")
        .arg(dir)
        .args(args)
        .stdin(Stdio::null())
        .output()
        .with_context(|| format!("git {}", args.join(" ")))?;
    if !output.status.success() {
        bail!(
            "git {} failed: {}",
            args.iter()
                .find(|arg| !arg.starts_with('-') && !arg.contains('='))
                .unwrap_or(&""),
            String::from_utf8_lossy(&output.stderr).trim()
        );
    }
    Ok(output.stdout)
}

fn git_text(dir: &Path, args: &[&str]) -> Result<String> {
    Ok(String::from_utf8_lossy(&git_out(dir, args)?)
        .trim()
        .to_string())
}

fn path_arg(path: &Path) -> Result<&str> {
    path.to_str().context("path is not valid UTF-8")
}

/// The hunks of a `git diff -U0`.
fn hunks_of(diff: &str) -> Vec<Hunk> {
    let range = |text: &str| -> Option<(usize, usize)> {
        match text.split_once(',') {
            Some((start, len)) => Some((start.parse().ok()?, len.parse().ok()?)),
            None => Some((text.parse().ok()?, 1)),
        }
    };
    diff.lines()
        .filter_map(|line| line.strip_prefix("@@ -"))
        .filter_map(|rest| {
            let (ranges, _) = rest.split_once(" @@")?;
            let (old, new) = ranges.split_once(" +")?;
            let (old_start, old_len) = range(old)?;
            let (new_start, new_len) = range(new)?;
            Some(Hunk {
                old_start,
                old_len,
                new_start,
                new_len,
            })
        })
        .collect()
}

/// Every file `tip` changes since it left `base`: what merging it would bring in.
pub fn changes(repo: &Path, base: &str, tip: &str) -> Result<Vec<FileChange>> {
    let from = git_text(repo, &["merge-base", base, tip])?;
    let raw = git_out(
        repo,
        &[
            "diff",
            "--raw",
            "-z",
            "--no-renames",
            "--no-abbrev",
            "--no-ext-diff",
            &from,
            tip,
        ],
    )?;
    let raw = String::from_utf8_lossy(&raw).to_string();
    let mut fields = raw.split('\0').filter(|field| !field.is_empty());
    let mut out = Vec::new();
    while let Some(meta) = fields.next() {
        let path = fields.next().context("git diff --raw ended early")?;
        if out.len() >= MAX_FILES {
            bail!("more than {MAX_FILES} files changed");
        }
        let parts: Vec<&str> = meta.trim_start_matches(':').split_whitespace().collect();
        let [old_mode, new_mode, old_blob, new_blob, _] = parts[..] else {
            bail!("unreadable git diff --raw line: {meta}");
        };
        let existed = old_mode != "000000";
        let exists = new_mode != "000000";
        let plain = |mode: &str| mode == "100644" || mode == "000000";
        let unusual = !plain(old_mode) || !plain(new_mode);
        let read = |present: bool, blob: &str| -> Result<(Option<String>, bool)> {
            if !present || unusual {
                return Ok((None, false));
            }
            match String::from_utf8(git_out(repo, &["cat-file", "blob", blob])?) {
                Ok(text) if !text.contains('\0') => Ok((Some(text), false)),
                _ => Ok((None, true)),
            }
        };
        let (old, old_binary) = read(existed, old_blob)?;
        let (new, new_binary) = read(exists, new_blob)?;
        let hunks = if unusual || old_binary || new_binary {
            Vec::new()
        } else {
            let literal = format!(":(literal){path}");
            hunks_of(&String::from_utf8_lossy(&git_out(
                repo,
                &[
                    "diff",
                    "-U0",
                    "--no-color",
                    "--no-ext-diff",
                    "--no-renames",
                    &from,
                    tip,
                    "--",
                    &literal,
                ],
            )?))
        };
        out.push(FileChange {
            path: path.to_string(),
            old,
            new,
            existed,
            exists,
            hunks,
            binary: old_binary || new_binary,
            unusual,
        });
    }
    Ok(out)
}

/// The local branch work merges into: what `origin/HEAD` names, else `main` or `master`.
/// `None` when there is no such branch here.
#[must_use]
pub fn default_branch(repo: &Path) -> Option<String> {
    let (base, guessed) = crate::worktree::task_base(repo);
    if guessed {
        return None;
    }
    let name = base
        .trim_start_matches("refs/remotes/")
        .trim_start_matches("refs/heads/");
    let name = name.strip_prefix("origin/").unwrap_or(name).to_string();
    git_out(
        repo,
        &[
            "rev-parse",
            "--verify",
            "--quiet",
            &format!("refs/heads/{name}"),
        ],
    )
    .ok()
    .map(|_| name)
}

/// Where `branch` is checked out, if anywhere.
fn checked_out_at(repo: &Path, branch: &str) -> Option<PathBuf> {
    let listing = git_text(repo, &["worktree", "list", "--porcelain"]).ok()?;
    let wanted = format!("branch refs/heads/{branch}");
    listing.split("\n\n").find_map(|block| {
        let mut lines = block.lines();
        let path = lines.next()?.strip_prefix("worktree ")?;
        lines
            .any(|line| line.trim() == wanted)
            .then(|| PathBuf::from(path))
    })
}

fn is_ancestor(repo: &Path, ancestor: &str, of: &str) -> bool {
    git_out(repo, &["merge-base", "--is-ancestor", ancestor, of]).is_ok()
}

/// A merge that happened.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Merge {
    pub into: String,
    pub commit: String,
    pub fast_forward: bool,
    /// The remote the default branch was pushed to, when it was.
    pub pushed: Option<String>,
}

/// Merge `branch`, which must still be at `reviewed`, into `into`: a fast-forward when
/// it can be, a merge commit by `agent` otherwise. With `push`, the default branch must
/// not be behind that remote first, and is pushed after - never forced; a refused push
/// puts the default branch back. Nothing is left half done: a conflict is aborted.
pub fn merge(
    repo: &Path,
    branch: &str,
    reviewed: &str,
    into: &str,
    agent: &str,
    message: &str,
    push: Option<&str>,
) -> Result<Merge> {
    let tip = git_text(
        repo,
        &["rev-parse", "--verify", &format!("refs/heads/{branch}")],
    )?;
    if tip != reviewed {
        bail!(
            "{branch} is at {}, not at the reviewed {}",
            short(&tip),
            short(reviewed)
        );
    }
    let target = format!("refs/heads/{into}");
    let before = git_text(repo, &["rev-parse", "--verify", &target])?;
    if let Some(remote) = push {
        git_out(repo, &["fetch", "--quiet", remote, into])
            .with_context(|| format!("could not fetch {remote} {into}"))?;
        let theirs = git_text(repo, &["rev-parse", "--verify", "FETCH_HEAD"])?;
        if !is_ancestor(repo, &theirs, &before) {
            bail!("{into} is behind {remote}/{into}; it needs a pull first");
        }
    }
    let checked_out = checked_out_at(repo, into);
    let (dir, scratch) = match &checked_out {
        Some(dir) => {
            let dirty = git_text(dir, &["status", "--porcelain", "--untracked-files=no"])?;
            if !dirty.is_empty() {
                bail!(
                    "{into} is checked out at {} with uncommitted changes",
                    dir.display()
                );
            }
            (dir.clone(), false)
        }
        None => {
            let dir = std::env::temp_dir().join(format!(
                "ferryman-merge-{}-{}-{}",
                crate::source::slug(branch),
                std::process::id(),
                Utc::now().timestamp_nanos_opt().unwrap_or_default()
            ));
            git_out(repo, &["worktree", "add", "--quiet", path_arg(&dir)?, into])?;
            (dir, true)
        }
    };
    let merged = merge_in(&dir, &tip, agent, message);
    if scratch {
        let _ = git_out(repo, &["worktree", "remove", "--force", path_arg(&dir)?]);
        let _ = git_out(repo, &["worktree", "prune"]);
    }
    let fast_forward = merged?;
    let commit = git_text(repo, &["rev-parse", "--verify", &target])?;
    let mut pushed = None;
    if let Some(remote) = push {
        let refspec = format!("{target}:{target}");
        if let Err(error) = git_out(repo, &["push", "--quiet", remote, &refspec]) {
            match &checked_out {
                Some(dir) => {
                    let _ = git_out(dir, &["reset", "--quiet", "--keep", &before]);
                }
                None => {
                    let _ = git_out(repo, &["update-ref", &target, &before, &commit]);
                }
            }
            return Err(error.context(format!("{remote} refused {into}; merged nothing")));
        }
        pushed = Some(remote.to_string());
    }
    Ok(Merge {
        into: into.to_string(),
        commit,
        fast_forward,
        pushed,
    })
}

/// Merge `tip` into what `dir` has checked out. `true` for a fast-forward.
fn merge_in(dir: &Path, tip: &str, agent: &str, message: &str) -> Result<bool> {
    if git_out(dir, &["merge", "--ff-only", "--quiet", tip]).is_ok() {
        return Ok(true);
    }
    let name = format!("user.name={agent}");
    let email = format!("user.email={agent}@ferryman.invalid");
    match git_out(
        dir,
        &[
            "-c",
            &name,
            "-c",
            &email,
            "-c",
            "commit.gpgsign=false",
            "merge",
            "--no-ff",
            "--no-edit",
            "--quiet",
            "-m",
            message,
            tip,
        ],
    ) {
        Ok(_) => Ok(false),
        Err(error) => {
            let _ = git_out(dir, &["merge", "--abort"]);
            Err(error.context("it does not merge cleanly"))
        }
    }
}

fn short(commit: &str) -> &str {
    &commit[..commit.len().min(9)]
}

// --- the signed record -------------------------------------------------------------------

/// A step of one improvement revision's auto-merge, signed by the agent that took it.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct MergeRecord {
    pub order_id: String,
    pub revision: u32,
    /// [`AUTHORIZED`], [`MERGED`] or [`HELD`].
    pub status: String,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub branch: Option<String>,
    /// The reviewed commit: the one both keys were given for.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub head: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub into: Option<String>,
    /// The default branch's commit after the merge.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub commit: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub pushed: Option<String>,
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub files: Vec<Classified>,
    /// What happened, or why it was held.
    pub note: String,
    pub by: String,
    pub at: DateTime<Utc>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub signed_by: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub signature: Option<String>,
}

impl MergeRecord {
    fn payload(&self) -> String {
        let bare = Self {
            signed_by: None,
            signature: None,
            ..self.clone()
        };
        format!(
            "ferryman-merge-v1\n{}",
            serde_jcs::to_string(&bare).unwrap_or_default()
        )
    }

    /// `improve-2026-w40-1 r1 merged into main at 1a2b3c4d5 (low risk: 2 docs)`
    #[must_use]
    pub fn describe(&self) -> String {
        match self.status.as_str() {
            MERGED => format!(
                "{} r{} merged into {} at {}{} - {}",
                self.order_id,
                self.revision,
                self.into.as_deref().unwrap_or("the default branch"),
                short(self.commit.as_deref().unwrap_or_default()),
                self.pushed
                    .as_deref()
                    .map(|remote| format!(", pushed to {remote}"))
                    .unwrap_or_default(),
                self.note
            ),
            HELD => format!(
                "{} r{} not merged on its own: {}",
                self.order_id, self.revision, self.note
            ),
            _ => format!(
                "{} r{} authorized to merge: {}",
                self.order_id, self.revision, self.note
            ),
        }
    }
}

fn merges_dir(route: &ProjectRoute, order_id: &str) -> PathBuf {
    route.communications.join("merges").join(order_id)
}

/// Sign and write `record` as `identity`.
pub fn record(
    route: &ProjectRoute,
    identity: &AgentIdentity,
    mut record: MergeRecord,
) -> Result<MergeRecord> {
    if !crate::is_safe_component(&record.order_id) || !crate::is_safe_component(identity.name()) {
        bail!("order and agent must be path-safe");
    }
    if ![AUTHORIZED, MERGED, HELD].contains(&record.status.as_str()) {
        bail!("a merge record is authorized, merged or held");
    }
    record.by = identity.name().to_string();
    record.signed_by = None;
    record.signature = None;
    let signature = identity.sign_bytes(record.payload().as_bytes());
    record.signed_by = Some(identity.name().to_string());
    record.signature = Some(signature);
    let path = merges_dir(route, &record.order_id).join(format!(
        "r{}.{}.{}.json",
        record.revision,
        record.status,
        identity.name()
    ));
    crate::atomic_json(&path, &record).with_context(|| format!("writing {}", path.display()))?;
    Ok(record)
}

fn read_records(route: &ProjectRoute, dir: &Path) -> Vec<MergeRecord> {
    let Ok(entries) = std::fs::read_dir(dir) else {
        return Vec::new();
    };
    let roster = crate::gate::roster(route);
    let mut found: Vec<MergeRecord> = entries
        .flatten()
        .filter(|entry| {
            entry
                .file_name()
                .to_str()
                .is_some_and(|name| name.ends_with(".json") && !name.contains(".sync-conflict-"))
        })
        .filter_map(|entry| std::fs::read(entry.path()).ok())
        .filter_map(|bytes| serde_json::from_slice::<MergeRecord>(&bytes).ok())
        .filter(|record| {
            record
                .signed_by
                .as_deref()
                .is_some_and(|signer| signer.eq_ignore_ascii_case(&record.by))
                && crate::check_signature(
                    record.signed_by.as_ref(),
                    record.signature.as_ref(),
                    &record.payload(),
                    &roster,
                ) == SignatureCheck::Valid
        })
        .collect();
    found.sort_by_key(|record| std::cmp::Reverse(record.at));
    found
}

/// Every record for one revision that verifies, newest first.
#[must_use]
pub fn records(route: &ProjectRoute, order_id: &str, revision: u32) -> Vec<MergeRecord> {
    read_records(route, &merges_dir(route, order_id))
        .into_iter()
        .filter(|record| record.order_id == order_id && record.revision == revision)
        .collect()
}

/// Every merge fm made on its own in this channel, newest first.
#[must_use]
pub fn merged(route: &ProjectRoute) -> Vec<MergeRecord> {
    let Ok(orders) = std::fs::read_dir(route.communications.join("merges")) else {
        return Vec::new();
    };
    let mut out: Vec<MergeRecord> = orders
        .flatten()
        .filter_map(|entry| {
            let order = entry.file_name().to_str()?.to_string();
            Some(
                read_records(route, &entry.path())
                    .into_iter()
                    .filter(move |record| record.order_id == order && record.status == MERGED),
            )
        })
        .flatten()
        .collect();
    out.sort_by_key(|record| std::cmp::Reverse(record.at));
    out
}

/// Where one revision's auto-merge stands.
#[derive(Debug, Clone, PartialEq)]
pub enum Stage {
    Open,
    Authorized(MergeRecord),
    Merged(MergeRecord),
    Held(MergeRecord),
}

#[must_use]
pub fn stage(route: &ProjectRoute, order_id: &str, revision: u32) -> Stage {
    let found = records(route, order_id, revision);
    let first = |status: &str| found.iter().find(|record| record.status == status).cloned();
    if let Some(record) = first(MERGED) {
        Stage::Merged(record)
    } else if let Some(record) = first(HELD) {
        Stage::Held(record)
    } else if let Some(record) = first(AUTHORIZED) {
        Stage::Authorized(record)
    } else {
        Stage::Open
    }
}

/// The commit the worker recorded as the tip of its branch: what both keys were given for.
fn reviewed_head(task: &Task, revision: u32) -> Option<String> {
    task.results
        .iter()
        .find(|result| result.revision == revision)?
        .payload
        .get("worktree_head")
        .and_then(Value::as_str)
        .map(str::to_string)
}

/// Record that `task`'s newest revision holds both keys and the policy lets fm merge
/// low-risk work, so the worker that built it may. Refused unless both are true.
pub fn authorize(
    route: &ProjectRoute,
    identity: &AgentIdentity,
    task: &Task,
) -> Result<MergeRecord> {
    let (policy, _) = crate::policy::effective(&route.communications, &route.project_id);
    if policy.auto_merge != AutoMerge::LowRisk {
        bail!("{}'s engine policy does not auto-merge", route.project_id);
    }
    let state = crate::gate::gate(route, task, &policy);
    let (true, Some(revision)) = (state.approved(), state.revision) else {
        bail!("{} does not hold both keys", task.order.id);
    };
    // Nothing merges on its own past an adversary Block nobody answered, whatever mode
    // the adversary is in: a merge no one is watching must not carry one.
    if let Some(block) =
        crate::adversary::unresolved_block(route, &policy, &task.order.id, revision)
    {
        bail!(
            "{} r{revision} has an unresolved adversary Block ({}); it is not merged on its \
             own - the master overrides it or sends the work back",
            task.order.id,
            block.finding.describe()
        );
    }
    let worker = task
        .results
        .iter()
        .find(|result| result.revision == revision)
        .map(|result| result.agent.clone())
        .unwrap_or_default();
    record(
        route,
        identity,
        MergeRecord {
            order_id: task.order.id.clone(),
            revision,
            status: AUTHORIZED.to_string(),
            branch: Some(crate::worktree::branch_name(&task.order.id, &worker)),
            head: reviewed_head(task, revision),
            into: None,
            commit: None,
            pushed: None,
            files: Vec::new(),
            note: format!(
                "both keys held and auto_merge is low-risk; {worker}, who built it, merges it \
                 if every file is docs, tests or dependency versions"
            ),
            by: identity.name().to_string(),
            at: Utc::now(),
            signed_by: None,
            signature: None,
        },
    )
}

/// What [`run`] did with one improvement.
#[derive(Debug, Clone, PartialEq)]
pub enum Outcome {
    Merged(MergeRecord),
    Held(MergeRecord),
}

/// Merge, or hold for the master, each authorized improvement `identity` built in this
/// project's workspace. Every condition is checked again here, from the channel and
/// from git, rather than taken from the authorization: the policy, both keys, the
/// reviewed commit, and every changed file.
#[must_use]
pub fn run(route: &ProjectRoute, identity: &AgentIdentity, push: Option<&str>) -> Vec<Outcome> {
    let (policy, _) = crate::policy::effective(&route.communications, &route.project_id);
    if policy.auto_merge != AutoMerge::LowRisk {
        return Vec::new();
    }
    let me = identity.name();
    let mut out = Vec::new();
    for task in crate::list_tasks(route).unwrap_or_default() {
        if !crate::gate::gated(&task.order.payload) {
            continue;
        }
        let state = crate::gate::gate(route, &task, &policy);
        let (true, Some(revision)) = (state.approved(), state.revision) else {
            continue;
        };
        let Some(result) = task.results.iter().find(|r| r.revision == revision) else {
            continue;
        };
        if crate::adversary::unresolved_block(route, &policy, &task.order.id, revision).is_some() {
            continue;
        }
        if !result.agent.eq_ignore_ascii_case(me)
            || !matches!(stage(route, &task.order.id, revision), Stage::Authorized(_))
        {
            continue;
        }
        let branch = crate::worktree::branch_name(&task.order.id, &result.agent);
        let head = reviewed_head(&task, revision);
        let mut entry = MergeRecord {
            order_id: task.order.id.clone(),
            revision,
            status: HELD.to_string(),
            branch: Some(branch.clone()),
            head: head.clone(),
            into: None,
            commit: None,
            pushed: None,
            files: Vec::new(),
            note: String::new(),
            by: me.to_string(),
            at: Utc::now(),
            signed_by: None,
            signature: None,
        };
        match attempt(route, &task, &branch, head.as_deref(), me, push) {
            Ok((merge, risk)) => {
                entry.status = MERGED.to_string();
                entry.note = format!(
                    "{}; {}",
                    risk.describe(),
                    if merge.fast_forward {
                        "fast-forward"
                    } else {
                        "merge commit"
                    }
                );
                entry.into = Some(merge.into);
                entry.commit = Some(merge.commit);
                entry.pushed = merge.pushed;
                entry.files = risk.files;
            }
            Err((why, files)) => {
                entry.note = why;
                entry.files = files;
            }
        }
        if let Ok(entry) = record(route, identity, entry) {
            out.push(if entry.status == MERGED {
                Outcome::Merged(entry)
            } else {
                Outcome::Held(entry)
            });
        }
    }
    out
}

fn attempt(
    route: &ProjectRoute,
    task: &Task,
    branch: &str,
    head: Option<&str>,
    agent: &str,
    push: Option<&str>,
) -> std::result::Result<(Merge, Risk), (String, Vec<Classified>)> {
    let repo = &route.workspace;
    let held = |why: String| (why, Vec::new());
    if !crate::worktree::is_git_repo(repo) {
        return Err(held("the workspace is not a git repository".to_string()));
    }
    let head = head.ok_or_else(|| held("the result names no reviewed commit".to_string()))?;
    let into = default_branch(repo)
        .ok_or_else(|| held("there is no main or master branch to merge into".to_string()))?;
    let risk = changes(repo, &format!("refs/heads/{into}"), head)
        .map(|found| classify(&found))
        .map_err(|error| held(format!("could not read what it changes: {error:#}")))?;
    if !risk.low() {
        return Err((risk.describe(), risk.files));
    }
    let message = format!(
        "Merge {branch}: {}\n\nMerged by fm on its own after both keys - the review engine's \
         verdict and the master's approval - because it is {}.",
        crate::gate::title(task),
        risk.describe()
    );
    match merge(repo, branch, head, &into, agent, &message, push) {
        Ok(merge) => Ok((merge, risk)),
        Err(error) => Err((format!("the merge failed: {error:#}"), risk.files)),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn changed(path: &str, old: &str, new: &str) -> FileChange {
        FileChange {
            path: path.to_string(),
            old: Some(old.to_string()),
            new: Some(new.to_string()),
            existed: true,
            exists: true,
            hunks: vec![Hunk::default()],
            binary: false,
            unusual: false,
        }
    }

    fn added(path: &str, new: &str) -> FileChange {
        FileChange {
            old: None,
            existed: false,
            ..changed(path, "", new)
        }
    }

    fn kind(change: &FileChange) -> Kind {
        classify_file(change).kind
    }

    #[test]
    fn docs_and_tests_are_known_by_their_paths() {
        for path in [
            "README.md",
            "crates/x/CHANGELOG.md",
            "docs/setup.html",
            "docs/img/flow.png",
            "LICENSE",
            "LICENSE-MIT",
            "COPYING.txt",
        ] {
            assert_eq!(kind(&added(path, "x")), Kind::Docs, "{path}");
        }
        for path in [
            "tests/cli.rs",
            "crates/ferryman-ops/tests/fleet.rs",
            "web/src/app.spec.ts",
            "web/src/app.test.tsx",
            "pkg/sync_test.go",
            "test_sync.py",
        ] {
            assert_eq!(kind(&added(path, "x")), Kind::Tests, "{path}");
        }
        for path in [
            "src/lib.rs",
            "src/tests/mod.rs",
            "src/test_helpers.rs",
            "crates/x/src/sync_test.rs",
            "license_check.sh",
            "Makefile",
            ".github/workflows/ci.yml",
        ] {
            assert_eq!(kind(&added(path, "x")), Kind::Code, "{path}");
        }
        let mut script = added("docs/build.sh", "x");
        script.unusual = true;
        assert_eq!(
            kind(&script),
            Kind::Code,
            "an executable bit is never low risk"
        );
    }

    #[test]
    fn a_lockfile_changed_in_place_is_a_dependency_change() {
        assert_eq!(kind(&changed("Cargo.lock", "a", "b")), Kind::Deps);
        assert_eq!(kind(&changed("web/pnpm-lock.yaml", "a", "b")), Kind::Deps);
        assert_eq!(kind(&changed("go.sum", "a", "b")), Kind::Deps);
        assert_eq!(kind(&added("yarn.lock", "b")), Kind::Code, "a new lockfile");
    }

    #[test]
    fn a_manifest_is_low_risk_only_when_versions_alone_change() {
        let cargo = "[package]\nname = \"x\"\nversion = \"0.5.16\"\n\n[dependencies]\nserde = \"1.0.200\"\ntokio = { version = \"1.40\", features = [\"rt\"] }\n\n[workspace.dependencies]\nanyhow = \"1\"\n";
        let bump = cargo
            .replace("1.0.200", "1.0.210")
            .replace("\"1.40\"", "\"1.41\"")
            .replace("anyhow = \"1\"", "anyhow = \"1.0.90\"");
        assert_eq!(kind(&changed("Cargo.toml", cargo, &bump)), Kind::Deps);
        let feature = cargo.replace("[\"rt\"]", "[\"rt\", \"process\"]");
        assert_eq!(kind(&changed("Cargo.toml", cargo, &feature)), Kind::Code);
        let new_dependency = cargo.replace("[workspace", "rand = \"0.8\"\n\n[workspace");
        assert_eq!(
            kind(&changed("Cargo.toml", cargo, &new_dependency)),
            Kind::Code
        );
        let own_version = cargo.replace("0.5.16", "0.5.17");
        assert_eq!(
            kind(&changed("Cargo.toml", cargo, &own_version)),
            Kind::Code
        );
        let source = cargo.replace(
            "serde = \"1.0.200\"",
            "serde = { git = \"https://example.com/serde\" }",
        );
        assert_eq!(kind(&changed("Cargo.toml", cargo, &source)), Kind::Code);

        let npm = r#"{"name": "web", "scripts": {"build": "vite build"}, "dependencies": {"react": "^18.2.0", "mine": "github:me/mine"}, "devDependencies": {"vite": "~5.0.0"}}"#;
        let bump = npm
            .replace("^18.2.0", "^18.3.1")
            .replace("~5.0.0", "~5.4.0");
        assert_eq!(kind(&changed("web/package.json", npm, &bump)), Kind::Deps);
        let script = npm.replace("vite build", "vite build && curl example.com");
        assert_eq!(kind(&changed("web/package.json", npm, &script)), Kind::Code);
        let git = npm.replace("github:me/mine", "github:someone/else");
        assert_eq!(kind(&changed("web/package.json", npm, &git)), Kind::Code);

        let requirements = "# pinned\nrequests==2.31.0\nflask[async]>=3.0,<4\n";
        let bump = requirements.replace("2.31.0", "2.32.3");
        assert_eq!(
            kind(&changed("requirements-dev.txt", requirements, &bump)),
            Kind::Deps
        );
        let index = format!("--extra-index-url https://example.com/simple\n{requirements}");
        assert_eq!(
            kind(&changed("requirements.txt", requirements, &index)),
            Kind::Code
        );
        let url = requirements.replace("requests==2.31.0", "requests @ https://example.com/r.whl");
        assert_eq!(
            kind(&changed("requirements.txt", requirements, &url)),
            Kind::Code
        );

        let pyproject = "[project]\nname = \"x\"\ndependencies = [\"httpx>=0.27\", \"rich==13.7.0\"]\n\n[tool.ruff]\nline-length = 100\n";
        let bump = pyproject
            .replace("0.27", "0.28")
            .replace("13.7.0", "13.9.4");
        assert_eq!(
            kind(&changed("pyproject.toml", pyproject, &bump)),
            Kind::Deps
        );
        let config = pyproject.replace("100", "120");
        assert_eq!(
            kind(&changed("pyproject.toml", pyproject, &config)),
            Kind::Code
        );

        let gomod = "module example.com/x\n\ngo 1.22\n\nrequire (\n\tgolang.org/x/sync v0.7.0\n\tgithub.com/a/b v1.2.3 // indirect\n)\n";
        let bump = gomod
            .replace("v0.7.0", "v0.8.0")
            .replace("v1.2.3", "v1.2.4");
        assert_eq!(kind(&changed("go.mod", gomod, &bump)), Kind::Deps);
        let replace = format!("{gomod}\nreplace golang.org/x/sync => ../sync\n");
        assert_eq!(kind(&changed("go.mod", gomod, &replace)), Kind::Code);
    }

    const LIB: &str = "pub fn add(a: u32, b: u32) -> u32 {\n    a + b\n}\n\n#[cfg(test)]\nmod tests {\n    use super::*;\n\n    #[test]\n    fn adds() {\n        assert_eq!(add(1, 2), 3);\n    }\n}\n";

    fn rust(old: &str, new: &str, hunks: &[Hunk]) -> Kind {
        kind(&FileChange {
            hunks: hunks.to_vec(),
            ..changed("src/lib.rs", old, new)
        })
    }

    #[test]
    fn a_rust_change_inside_the_test_module_only_is_a_test_change() {
        let more = LIB.replace(
            "        assert_eq!(add(1, 2), 3);\n",
            "        assert_eq!(add(1, 2), 3);\n        assert_eq!(add(0, 0), 0);\n",
        );
        let inside = [Hunk {
            old_start: 11,
            old_len: 0,
            new_start: 12,
            new_len: 1,
        }];
        assert_eq!(rust(LIB, &more, &inside), Kind::Tests);

        let code = LIB.replace("    a + b\n", "    a.wrapping_add(b)\n");
        let outside = [Hunk {
            old_start: 2,
            old_len: 1,
            new_start: 2,
            new_len: 1,
        }];
        assert_eq!(rust(LIB, &code, &outside), Kind::Code);

        // Closing the test module early with an indented brace and adding code after it
        // is not a test change, however it is indented.
        let escape = LIB.replace(
            "        assert_eq!(add(1, 2), 3);\n    }\n}\n",
            "        assert_eq!(add(1, 2), 3);\n    }\n    }\n    pub fn sneaky() {}\n    mod more {\n}\n",
        );
        let at_the_end = [Hunk {
            old_start: 13,
            old_len: 0,
            new_start: 13,
            new_len: 3,
        }];
        assert_eq!(rust(LIB, &escape, &at_the_end), Kind::Code);
    }

    #[test]
    fn a_rust_change_to_comments_only_is_documentation() {
        let commented = LIB.replace(
            "pub fn add(",
            "/// Adds two numbers.\n// and nothing else\npub fn add(",
        );
        let at_the_top = Hunk {
            old_start: 0,
            old_len: 0,
            new_start: 1,
            new_len: 2,
        };
        assert_eq!(rust(LIB, &commented, &[at_the_top]), Kind::Docs);
        let block = LIB.replace("a + b", "a /* the sum */ + b");
        let line_two = Hunk {
            old_start: 2,
            old_len: 1,
            new_start: 2,
            new_len: 1,
        };
        assert_eq!(rust(LIB, &block, &[line_two]), Kind::Docs);
        // `//` inside a string is not a comment.
        let with_string = "fn url() -> &'static str {\n    \"https://example.com\"\n}\n";
        let changed_string = with_string.replace("example.com", "example.org");
        assert_eq!(
            rust(with_string, &changed_string, &[Hunk::default()]),
            Kind::Code
        );
        let raw = "const Q: &str = r#\"a // b\"#;\n";
        assert_eq!(
            rust(raw, &raw.replace("// b", "// c"), &[Hunk::default()]),
            Kind::Code
        );
    }

    #[test]
    fn mixed_code_and_docs_is_not_low_risk() {
        let risk = classify(&[
            added("docs/guide.md", "x"),
            changed("src/main.rs", "fn main() {}\n", "fn main() { run() }\n"),
        ]);
        assert!(!risk.low());
        assert!(
            risk.describe().contains("src/main.rs"),
            "{}",
            risk.describe()
        );
        let risk = classify(&[added("docs/guide.md", "x"), added("tests/it.rs", "x")]);
        assert!(risk.low());
        assert_eq!(risk.describe(), "low risk: 1 docs, 1 tests");
        assert!(!classify(&[]).low(), "an empty change merges nothing");
    }

    #[test]
    fn hunks_are_read_from_a_zero_context_diff() {
        let diff = "diff --git a/x b/x\n--- a/x\n+++ b/x\n@@ -3 +3,2 @@ fn x\n-a\n+b\n+c\n@@ -10,0 +12 @@\n+d\n";
        assert_eq!(
            hunks_of(diff),
            vec![
                Hunk {
                    old_start: 3,
                    old_len: 1,
                    new_start: 3,
                    new_len: 2
                },
                Hunk {
                    old_start: 10,
                    old_len: 0,
                    new_start: 12,
                    new_len: 1
                },
            ]
        );
    }
}
