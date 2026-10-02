//! Evidence a worker records about its own work, outside the model's control.
//!
//! # The incident this exists for
//!
//! On 2026-09-27 a headless worker was asked to clone seven repositories and fetch six.
//! It answered "cloned (success)" for every one within seventeen seconds. A follow-up
//! asking for the raw `git rev-parse` output came back "missing" for every path,
//! including repositories that certainly existed. The model had invented both answers,
//! and nothing between the engine and the reviewer could tell.
//!
//! So the worker process - Ferryman's own code, not the engine - looks at the workspace
//! before and after the engine runs and writes down what git says: the branch, `HEAD`
//! before and after, the commits made, the diff, and what changed without being
//! committed. When the order names checks (`cargo test`, `npm test`, ...) the worker runs
//! them itself and records their exit codes. All of it goes into the signed result as
//! `evidence`, beside the claim.
//!
//! # What is decided from it
//!
//! [`judge`] is deliberately small and deterministic. A result is `verified`,
//! `unverified` or `refuted`:
//!
//! - an order that needs code changes, with no commit and no diff, is `unverified` -
//!   or `refuted` when the answer claims success anyway;
//! - an answer that says it changed or committed files, with no commit and no diff, is
//!   `refuted`;
//! - an answer that names a commit hash the workspace does not have is `refuted`;
//! - an order that names checks, with evidence that ran none, is `refuted`; a check that
//!   exited non-zero is `refuted` when the answer claims success anyway;
//! - an answer that is a refusal, a redirect ("better suited to ...") with nothing
//!   after it, a placeholder ("no output" for every item) or empty is `refuted` - with
//!   or without evidence, so results from workers older than this module are caught
//!   too;
//! - a verification order must cite `file:line`, and a citation that does not exist in
//!   the workspace is `refuted`.
//!
//! A `refuted` result - and an `unverified` one whose order needed evidence - cannot be
//! accepted by review: see [`blocking_reason`], which recomputes the decision from the
//! recorded facts rather than trusting the recorded status. A refuted result never
//! counts as done ([`crate::TaskState::Refuted`]).
//!
//! # Recording a decision
//!
//! The worker's signed result is never edited. Whoever checks it - a reviewer, `ferry
//! improve review` - writes its own signed [`Verification`] beside it
//! (`verification.<verifier>.<rev>.json`) and a `verification` entry in its ledger.

use std::{
    collections::BTreeMap,
    hash::{Hash, Hasher},
    io::Read,
    path::Path,
    process::{Command, Stdio},
    time::{Duration, Instant},
};

use anyhow::{Result, bail};
use chrono::{DateTime, Utc};
use serde::{Deserialize, Serialize};
use serde_json::Value;
use sha2::{Digest, Sha256};

use crate::{AgentIdentity, AgentRoute, ProjectRoute, SignatureCheck, TaskResult};

/// The shape of the `evidence` block. Bumped when a field changes meaning; a new
/// optional field does not bump it.
pub const EVIDENCE_SCHEMA: u32 = 1;

/// Where the channel sits inside a workspace. The worker writes receipts there while the
/// engine runs, so it is never counted as the engine's work.
const CHANNEL_DIR: &str = ".ferryman";
/// The most checks run for one result.
const MAX_CHECKS: usize = 3;
/// How much of a check's output is kept.
const TAIL_CHARS: usize = 1200;
/// How many commits are listed.
const MAX_COMMITS: usize = 50;
/// How many uncommitted paths are listed.
const MAX_PATHS: usize = 50;
/// How many committed paths are listed.
const MAX_TOUCHED: usize = 200;

/// What the evidence says about the claim.
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "kebab-case")]
pub enum Status {
    /// The evidence agrees with the claim.
    Verified,
    /// The evidence cannot support the claim: nothing to show for work that needed some.
    Unverified,
    /// The evidence, or the answer itself, disagrees with the claim. Never success.
    #[serde(alias = "contradicted")]
    Refuted,
    /// Nothing checkable: not a git workspace, no checks, nothing required. Reported as
    /// unverified; it blocks nothing.
    #[default]
    NotApplicable,
}

impl Status {
    #[must_use]
    pub fn as_str(self) -> &'static str {
        match self {
            Self::Verified => "verified",
            Self::Unverified => "unverified",
            Self::Refuted => "refuted",
            Self::NotApplicable => "not-applicable",
        }
    }

    /// The three-way class a person reads: `verified`, `unverified` or `refuted`.
    #[must_use]
    pub fn class(self) -> &'static str {
        match self {
            Self::Verified => "verified",
            Self::Refuted => "refuted",
            Self::Unverified | Self::NotApplicable => "unverified",
        }
    }

    /// Whether a result in this state may not be accepted.
    #[must_use]
    pub fn blocks_acceptance(self) -> bool {
        matches!(self, Self::Unverified | Self::Refuted)
    }
}

/// One check the worker ran itself.
#[derive(Debug, Clone, Default, PartialEq, Eq, Serialize, Deserialize)]
pub struct CheckRun {
    pub command: String,
    /// `None` when it could not be started, or was stopped at the time limit.
    pub exit_code: Option<i32>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub error: Option<String>,
    pub seconds: u64,
    /// The end of what it printed, stdout then stderr.
    #[serde(default, skip_serializing_if = "String::is_empty")]
    pub tail: String,
    /// SHA-256 of everything it printed, so the tail can be matched to a full log.
    #[serde(default, skip_serializing_if = "String::is_empty")]
    pub digest: String,
}

/// A commit hash the answer names, and whether the workspace has it.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct ClaimedCommit {
    pub hash: String,
    pub exists: bool,
}

/// One `file:line` a verification answer cited, and whether it is there.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct Citation {
    pub cite: String,
    pub found: bool,
}

/// What the worker recorded around one engine run.
#[derive(Debug, Clone, Default, PartialEq, Eq, Serialize, Deserialize)]
pub struct Evidence {
    /// [`EVIDENCE_SCHEMA`] when written; 0 for the first records, which had none.
    #[serde(default)]
    pub schema: u32,
    /// Always `worker`: written by Ferryman's worker process, never by the engine.
    pub recorded_by: String,
    /// When the engine was handed the order.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub started_at: Option<DateTime<Utc>>,
    /// Wall-clock seconds the engine ran, measured by the worker.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub duration_secs: Option<u64>,
    /// Whether the work ran in a git workspace, so there is anything to measure.
    pub git: bool,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub branch: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub head_before: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub head_after: Option<String>,
    /// `<short hash> <subject>` for each commit between the two heads.
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub commits: Vec<String>,
    /// `git diff --shortstat` from `head_before` to the working tree.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub diff_stat: Option<String>,
    /// Paths changed during the run and not committed by the engine.
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub uncommitted: Vec<String>,
    /// Every path the worker's commit changed, read from git after the commit. Where
    /// `uncommitted` is what the engine left lying about, this is what actually went
    /// into the branch.
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub touched_files: Vec<String>,
    /// Things a reviewer may want to know that are NOT findings: nothing here counts for
    /// or against the result, and [`judge`] never reads it. Today: that the commit
    /// strayed outside the files its order said it would touch.
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub notes: Vec<String>,
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub checks: Vec<CheckRun>,
    /// Commit hashes the answer names, looked up in the workspace by the worker.
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub claimed_commits: Vec<ClaimedCommit>,
    /// For a verification order: its verdict, as the answer gave it.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub verdict: Option<String>,
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub citations: Vec<Citation>,
    #[serde(default)]
    pub status: Status,
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub reasons: Vec<String>,
}
impl Evidence {
    /// Record what the commit changed, and note - for reviewers, not as a finding - when
    /// some of it falls outside the globs the order declared in `touches`. An order that
    /// declared nothing is never noted: it made no promise to stray from.
    pub fn record_touched(&mut self, touches: &[String], changed: &[String]) {
        if let Some(note) = crate::overlap::scope_note(touches, changed)
            && !self.notes.contains(&note)
        {
            self.notes.push(note);
        }
        self.touched_files = changed.iter().take(MAX_TOUCHED).cloned().collect();
    }

    /// Whether the run left anything behind: a commit, or a changed path.
    #[must_use]
    pub fn changed(&self) -> bool {
        !self.commits.is_empty() || !self.uncommitted.is_empty()
    }

    /// One line for a person.
    #[must_use]
    pub fn describe(&self) -> String {
        let mut parts = Vec::new();
        if self.git {
            let short = |head: &Option<String>| {
                head.as_deref()
                    .map_or("none".to_string(), |h| h.chars().take(9).collect())
            };
            parts.push(format!(
                "HEAD {} -> {}, {} commit(s), {} uncommitted path(s)",
                short(&self.head_before),
                short(&self.head_after),
                self.commits.len(),
                self.uncommitted.len()
            ));
            if let Some(stat) = &self.diff_stat {
                parts.push(stat.clone());
            }
        } else {
            parts.push("not a git workspace".to_string());
        }
        if let Some(seconds) = self.duration_secs {
            parts.push(format!("ran {seconds}s"));
        }
        for check in &self.checks {
            parts.push(format!(
                "`{}` {}",
                check.command,
                check.exit_code.map_or_else(
                    || "did not finish".to_string(),
                    |code| format!("exit {code}")
                )
            ));
        }
        let mut line = format!("{}: {}", self.status.as_str(), parts.join("; "));
        if !self.reasons.is_empty() {
            line.push_str(&format!(" - {}", self.reasons.join("; ")));
        }
        for note in &self.notes {
            line.push_str(&format!(" [{note}]"));
        }
        line
    }
}

/// The workspace as it was before the engine ran.
#[derive(Debug, Clone, Default)]
pub struct Before {
    pub branch: Option<String>,
    pub head: Option<String>,
    dirty: BTreeMap<String, u64>,
}

fn git(dir: &Path, args: &[&str]) -> Option<String> {
    let out = Command::new("git")
        .arg("-C")
        .arg(dir)
        .args(args)
        .stdin(Stdio::null())
        .output()
        .ok()?;
    out.status
        .success()
        .then(|| String::from_utf8_lossy(&out.stdout).trim().to_string())
}

/// Every changed or untracked path outside the channel, with a fingerprint of its
/// status and contents, so a path the engine touched differs from before even when it
/// was already dirty.
fn dirty_map(dir: &Path) -> BTreeMap<String, u64> {
    let exclude = format!(":(exclude){CHANNEL_DIR}");
    let Some(listing) = Command::new("git")
        .arg("-C")
        .arg(dir)
        .args([
            "status",
            "--porcelain=v1",
            "-z",
            "--untracked-files=all",
            "--",
            ".",
            &exclude,
        ])
        .stdin(Stdio::null())
        .output()
        .ok()
        .filter(|out| out.status.success())
    else {
        return BTreeMap::new();
    };
    let text = String::from_utf8_lossy(&listing.stdout).to_string();
    let mut entries = text.split('\0');
    let mut map = BTreeMap::new();
    while let Some(entry) = entries.next() {
        if entry.len() < 4 {
            continue;
        }
        let (status, path) = entry.split_at(3);
        // A rename or copy is followed by the path it came from.
        if status.starts_with('R') || status.starts_with('C') {
            let _ = entries.next();
        }
        let mut hasher = std::collections::hash_map::DefaultHasher::new();
        status.hash(&mut hasher);
        if let Ok(bytes) = std::fs::read(dir.join(path)) {
            bytes.hash(&mut hasher);
        }
        map.insert(path.to_string(), hasher.finish());
    }
    map
}

/// Look at `dir` before the engine runs. `None` when it is not inside a git work tree.
#[must_use]
pub fn before(dir: &Path) -> Option<Before> {
    if git(dir, &["rev-parse", "--is-inside-work-tree"]).as_deref() != Some("true") {
        return None;
    }
    Some(Before {
        branch: git(dir, &["rev-parse", "--abbrev-ref", "HEAD"]),
        head: git(dir, &["rev-parse", "--verify", "--quiet", "HEAD"]),
        dirty: dirty_map(dir),
    })
}

/// Look at `dir` again after the engine ran, and record what changed since `before`.
/// Not yet judged: see [`judge`].
#[must_use]
pub fn after(dir: &Path, before: Option<&Before>) -> Evidence {
    let mut evidence = Evidence {
        schema: EVIDENCE_SCHEMA,
        recorded_by: "worker".to_string(),
        ..Evidence::default()
    };
    let Some(before) = before else {
        return evidence;
    };
    evidence.git = true;
    evidence.branch = git(dir, &["rev-parse", "--abbrev-ref", "HEAD"]).or(before.branch.clone());
    evidence.head_before = before.head.clone();
    evidence.head_after = git(dir, &["rev-parse", "--verify", "--quiet", "HEAD"]);
    let limit = format!("-{MAX_COMMITS}");
    let range = match (&before.head, &evidence.head_after) {
        (Some(from), Some(to)) if from != to => Some(format!("{from}..{to}")),
        (None, Some(to)) => Some(to.clone()),
        _ => None,
    };
    if let Some(range) = range {
        evidence.commits = git(dir, &["log", &limit, "--format=%h %s", &range])
            .map(|text| text.lines().map(str::to_string).collect())
            .unwrap_or_default();
    }
    if let Some(from) = &before.head {
        let exclude = format!(":(exclude){CHANNEL_DIR}");
        evidence.diff_stat = git(dir, &["diff", "--shortstat", from, "--", ".", &exclude])
            .filter(|stat| !stat.is_empty());
    }
    let now = dirty_map(dir);
    let mut changed: Vec<String> = now
        .iter()
        .filter(|(path, print)| before.dirty.get(*path) != Some(print))
        .map(|(path, _)| path.clone())
        .chain(
            before
                .dirty
                .keys()
                .filter(|path| !now.contains_key(*path))
                .cloned(),
        )
        .collect();
    changed.sort();
    changed.dedup();
    changed.truncate(MAX_PATHS);
    evidence.uncommitted = changed;
    evidence
}

// --- what the order asks for ------------------------------------------------------------

/// An improvement order's kind, when it has one: `verification` for the orders that
/// confirm or refute a claim.
fn improvement_kind(payload: &Value) -> Option<&str> {
    payload
        .get("improvement")
        .and_then(|improvement| improvement.get("kind"))
        .and_then(Value::as_str)
}

fn tagged(payload: &Value, tag: &str) -> bool {
    payload
        .get("tags")
        .and_then(Value::as_array)
        .is_some_and(|tags| tags.iter().any(|t| t.as_str() == Some(tag)))
}

/// Whether the order confirms or refutes a claim rather than changing anything.
#[must_use]
pub fn is_verification(payload: &Value) -> bool {
    improvement_kind(payload) == Some("verification")
}

/// Whether the order can only be done by changing code: every improvement order except
/// a verification, and any order that says `"requires_changes": true`.
#[must_use]
pub fn requires_changes(payload: &Value) -> bool {
    payload.get("requires_changes").and_then(Value::as_bool) == Some(true)
        || (tagged(payload, "improvement") && !is_verification(payload))
}

/// The acceptance criteria the order states.
#[must_use]
pub fn acceptance(payload: &Value) -> Vec<String> {
    payload
        .get("improvement")
        .and_then(|improvement| improvement.get("acceptance"))
        .or_else(|| payload.get("acceptance"))
        .and_then(Value::as_array)
        .into_iter()
        .flatten()
        .filter_map(Value::as_str)
        .map(str::to_string)
        .collect()
}
/// The programs a check may start with, and the words that make one.
const CHECKS: &[&[&str]] = &[
    &["cargo", "test"],
    &["cargo", "clippy"],
    &["cargo", "build"],
    &["cargo", "check"],
    &["cargo", "fmt"],
    &["npm", "test"],
    &["npm", "run"],
    &["pnpm", "test"],
    &["pnpm", "run"],
    &["yarn", "test"],
    &["yarn", "run"],
    &["go", "test"],
    &["go", "vet"],
    &["pytest"],
    &["make", "test"],
    &["make", "check"],
];

/// Words that end a command written into a sentence: "cargo test -p x passes".
const STOP: &[&str] = &[
    "passes",
    "pass",
    "passing",
    "succeeds",
    "succeed",
    "is",
    "are",
    "and",
    "with",
    "should",
    "must",
    "green",
    "clean",
    "cleanly",
    "exits",
    "exit",
    "returns",
    "still",
    "without",
    "on",
    "in",
    "for",
    "to",
    "then",
    "after",
    "before",
    "or",
    "runs",
    "works",
    "successfully",
    "locally",
    "too",
    "also",
    "again",
    "the",
    "a",
    "an",
];

fn safe_token(token: &str) -> bool {
    !token.is_empty()
        && token
            .chars()
            .all(|c| c.is_ascii_alphanumeric() || "-_./:=@+,".contains(c))
}

fn clean_token(token: &str) -> &str {
    token
        .trim_matches(|c: char| "`\"'()[];,".contains(c))
        .trim_end_matches(['.', ':'])
}

/// The commands one piece of text names, as argument lists. After the program and its
/// subcommand only flags, and the value right after a flag, are taken: prose never is.
fn commands_in(text: &str) -> Vec<Vec<String>> {
    let tokens: Vec<&str> = text.split_whitespace().map(clean_token).collect();
    let mut found = Vec::new();
    let mut i = 0;
    while i < tokens.len() {
        let Some(prefix) = CHECKS.iter().find(|prefix| {
            tokens.len() >= i + prefix.len()
                && prefix
                    .iter()
                    .zip(&tokens[i..])
                    .all(|(want, got)| got.eq_ignore_ascii_case(want))
        }) else {
            i += 1;
            continue;
        };
        let mut argv: Vec<String> = prefix.iter().map(|word| (*word).to_string()).collect();
        let mut j = i + prefix.len();
        // `npm run lint`: the script name.
        if prefix.last() == Some(&"run")
            && let Some(script) = tokens.get(j).filter(|token| safe_token(token))
        {
            argv.push((*script).to_string());
            j += 1;
        }
        while let Some(token) = tokens.get(j) {
            let lower = token.to_ascii_lowercase();
            let after_flag = argv
                .last()
                .is_some_and(|last| last.starts_with('-') && !last.contains('='));
            let takes = safe_token(token)
                && !STOP.contains(&lower.as_str())
                && (token.starts_with('-') || after_flag);
            if !takes {
                break;
            }
            argv.push((*token).to_string());
            j += 1;
        }
        found.push(argv);
        i = j.max(i + 1);
    }
    found
}

/// The checks acceptance criteria name, at most three, each once. Text in backticks is
/// read on its own when a line has any, so prose around a command cannot leak into it.
#[must_use]
pub fn named_checks(acceptance: &[String]) -> Vec<Vec<String>> {
    let mut checks: Vec<Vec<String>> = Vec::new();
    for line in acceptance {
        let quoted: Vec<&str> = line.split('`').skip(1).step_by(2).collect();
        let pieces = if quoted.is_empty() {
            vec![line.as_str()]
        } else {
            quoted
        };
        for piece in pieces {
            for argv in commands_in(piece) {
                if !checks.contains(&argv) {
                    checks.push(argv);
                }
            }
        }
    }
    checks.truncate(MAX_CHECKS);
    checks
}

/// The checks an order requires: those its acceptance criteria name, then any it lists
/// under `"checks"` - read the same way, so a listed command is only ever one of the
/// known check programs with its flags, never a shell line.
#[must_use]
pub fn required_checks(payload: &Value) -> Vec<Vec<String>> {
    let mut lines = acceptance(payload);
    lines.extend(
        payload
            .get("checks")
            .and_then(Value::as_array)
            .into_iter()
            .flatten()
            .filter_map(Value::as_str)
            .map(|command| format!("`{command}`")),
    );
    named_checks(&lines)
}

fn program(name: &str) -> String {
    if cfg!(windows) && matches!(name, "npm" | "pnpm" | "yarn" | "npx") {
        format!("{name}.cmd")
    } else {
        name.to_string()
    }
}

fn drain<R: Read + Send + 'static>(pipe: Option<R>) -> std::thread::JoinHandle<Vec<u8>> {
    std::thread::spawn(move || {
        let mut buffer = Vec::new();
        if let Some(mut pipe) = pipe {
            let _ = pipe.read_to_end(&mut buffer);
        }
        buffer
    })
}

fn tail(text: &str) -> String {
    let count = text.chars().count();
    text.chars()
        .skip(count.saturating_sub(TAIL_CHARS))
        .collect()
}

/// Run one check in `dir`, directly (no shell), for at most `limit`.
#[must_use]
pub fn run_check(dir: &Path, argv: &[String], limit: Duration) -> CheckRun {
    let command = argv.join(" ");
    let started = Instant::now();
    let failed = |error: String| CheckRun {
        command: command.clone(),
        error: Some(error),
        ..CheckRun::default()
    };
    let Some((name, args)) = argv.split_first() else {
        return failed("no command".to_string());
    };
    let mut child = match Command::new(program(name))
        .args(args)
        .current_dir(dir)
        .stdin(Stdio::null())
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .spawn()
    {
        Ok(child) => child,
        Err(error) => return failed(format!("could not start: {error}")),
    };
    let out = drain(child.stdout.take());
    let err = drain(child.stderr.take());
    let status = loop {
        match child.try_wait() {
            Ok(Some(status)) => break Ok(status),
            Ok(None) if started.elapsed() >= limit => {
                let _ = child.kill();
                let _ = child.wait();
                break Err(format!("stopped after {}s", limit.as_secs()));
            }
            Ok(None) => std::thread::sleep(Duration::from_millis(100)),
            Err(error) => break Err(format!("{error}")),
        }
    };
    let seconds = started.elapsed().as_secs();
    match status {
        Ok(status) => {
            let mut text = String::from_utf8_lossy(&out.join().unwrap_or_default()).to_string();
            text.push_str(&String::from_utf8_lossy(&err.join().unwrap_or_default()));
            CheckRun {
                command,
                exit_code: Some(status.code().unwrap_or(-1)),
                error: None,
                seconds,
                digest: hex::encode(Sha256::digest(text.as_bytes())),
                tail: tail(text.trim()),
            }
        }
        // A killed check's children may still hold the pipes; their readers are left
        // to finish on their own rather than waited for.
        Err(error) => CheckRun {
            seconds,
            ..failed(error)
        },
    }
}
// --- what the answer claims -------------------------------------------------------------

/// Whether an answer admits it did not do the work. Anything else submitted as a result
/// is a claim of success.
#[must_use]
pub fn admits_failure(answer: &str) -> bool {
    let lower = answer.to_lowercase();
    [
        "could not",
        "couldn't",
        "unable to",
        "failed to",
        "did not",
        "didn't",
        "was not able",
        "wasn't able",
        "cannot ",
        "can't ",
        "blocked",
        "no changes",
        "nothing to change",
        "not done",
    ]
    .iter()
    .any(|phrase| lower.contains(phrase))
}

/// Whether an answer says it changed or committed files in this workspace.
#[must_use]
pub fn claims_change(answer: &str) -> bool {
    let lower = answer.to_lowercase();
    !admits_failure(answer)
        && [
            "committed",
            "i have added",
            "i've added",
            "i added",
            "i have created",
            "i've created",
            "i created",
            "i have modified",
            "i modified",
            "i have updated",
            "i've updated",
            "i updated",
            "i have implemented",
            "i implemented",
            "i have fixed",
            "i've fixed",
            "i fixed",
            "changes have been made",
            "files changed",
        ]
        .iter()
        .any(|phrase| lower.contains(phrase))
}

/// Lines that stand for an answer without being one.
const PLACEHOLDERS: &[&str] = &[
    "no output",
    "(no output)",
    "<no output>",
    "n/a",
    "placeholder",
    "todo",
    "tbd",
    "lorem ipsum",
    "<output>",
    "[output]",
];

/// Words that hand the work to someone else instead of doing it.
const REDIRECTS: &[&str] = &[
    "better suited to",
    "better suited for",
    "better handled by",
    "should be handled by",
    "please assign",
    "reassign this",
];

/// Openings of a refusal.
const REFUSALS: &[&str] = &[
    "i can't help",
    "i cannot help",
    "i can't assist",
    "i cannot assist",
    "i won't",
    "i will not",
    "i'm sorry, but i can",
    "i am sorry, but i can",
    "as an ai",
];

/// One line with its list marker taken off: `1. no output` -> `no output`.
fn item_text(line: &str) -> &str {
    let line = line.trim();
    let line = line
        .strip_prefix("- ")
        .or_else(|| line.strip_prefix("* "))
        .unwrap_or(line);
    let digits = line.chars().take_while(char::is_ascii_digit).count();
    let line = if digits > 0 {
        line[digits..]
            .strip_prefix(". ")
            .or_else(|| line[digits..].strip_prefix(") "))
            .or_else(|| line[digits..].strip_prefix(": "))
            .unwrap_or(line)
    } else {
        line
    };
    line.trim().trim_end_matches(['.', ':']).trim()
}

/// Of [`PLACEHOLDERS`], the ones that are never a real answer even alone. "no output"
/// can be the honest answer to one command; seven of them in a row is not.
const ALWAYS_PLACEHOLDERS: &[&str] = &[
    "placeholder",
    "todo",
    "tbd",
    "lorem ipsum",
    "<output>",
    "[output]",
];

fn is_placeholder(line: &str) -> bool {
    let item = item_text(line).to_lowercase();
    // `1. no output`, `ps aux: no output`, or the bare words.
    PLACEHOLDERS.contains(&item.as_str())
        || PLACEHOLDERS.iter().any(|p| {
            item.strip_suffix(p).is_some_and(|rest| {
                let rest = rest.trim_end();
                rest.ends_with(':') && rest.chars().count() <= 60
            })
        })
}

/// Why an answer is not an answer at all, or `None` when it is one: empty; a refusal; a
/// redirect ("better suited to ...") with nothing done after it; or nothing but
/// placeholders ("no output" for every item). Judged from the text alone, so it holds
/// for results that carry no evidence.
///
/// A redirect followed by real work is an answer: the worker is asked to say so when a
/// peer is a better fit, and then do its best anyway.
#[must_use]
pub fn non_answer(answer: &str) -> Option<String> {
    let text = answer.trim();
    if text.is_empty() {
        return Some("the answer is empty".to_string());
    }
    let lower = text.to_lowercase();
    if text.chars().count() < 400 && REFUSALS.iter().any(|r| lower.starts_with(r)) {
        return Some(format!("the answer is a refusal: \"{}\"", clip(text, 80)));
    }
    let lines: Vec<&str> = text.lines().filter(|l| !l.trim().is_empty()).collect();
    let redirect = |line: &str| {
        let lower = line.to_lowercase();
        REDIRECTS.iter().any(|r| lower.contains(r))
    };
    let work: Vec<&str> = lines
        .iter()
        .copied()
        .filter(|line| !redirect(line))
        .collect();
    let placeholders = work.iter().filter(|line| is_placeholder(line)).count();
    let redirected = work.len() < lines.len();
    if redirected && placeholders == work.len() {
        return Some(format!(
            "the answer hands the work elsewhere and does none of it: \"{}\"",
            clip(lines[0], 80)
        ));
    }
    if placeholders == work.len() && placeholders >= 2 {
        return Some(format!(
            "every item is a placeholder (\"{}\")",
            item_text(work[0])
        ));
    }
    if lines.len() == 1 && ALWAYS_PLACEHOLDERS.contains(&item_text(text).to_lowercase().as_str()) {
        return Some(format!(
            "the answer is a placeholder: \"{}\"",
            clip(text, 80)
        ));
    }
    None
}

fn clip(text: &str, chars: usize) -> String {
    let flat = text.split_whitespace().collect::<Vec<_>>().join(" ");
    if flat.chars().count() > chars {
        format!("{}...", flat.chars().take(chars).collect::<String>())
    } else {
        flat
    }
}

/// Commit hashes an answer names: a run of 7 to 40 hex digits with both a digit and a
/// letter in it, in an answer that talks about commits. Words like `deadbeef` or
/// `facade` never count - they have no digit.
#[must_use]
pub fn claimed_hashes(answer: &str) -> Vec<String> {
    if !answer.to_lowercase().contains("commit") {
        return Vec::new();
    }
    let mut found: Vec<String> = Vec::new();
    for token in answer.split(|c: char| !c.is_ascii_alphanumeric()) {
        let hex = token.chars().all(|c| c.is_ascii_hexdigit());
        let digit = token.chars().any(|c| c.is_ascii_digit());
        let letter = token.chars().any(|c| c.is_ascii_alphabetic());
        if hex && digit && letter && (7..=40).contains(&token.len()) {
            let hash = token.to_ascii_lowercase();
            if !found.contains(&hash) {
                found.push(hash);
            }
        }
    }
    found.truncate(20);
    found
}

/// Look up every commit hash the answer names in the workspace at `dir`.
pub fn check_claimed_commits(evidence: &mut Evidence, dir: &Path, answer: &str) {
    if !evidence.git {
        return;
    }
    evidence.claimed_commits = claimed_hashes(answer)
        .into_iter()
        .map(|hash| ClaimedCommit {
            exists: git(dir, &["cat-file", "-e", &format!("{hash}^{{commit}}")]).is_some(),
            hash,
        })
        .collect();
}

/// The last JSON object in `text` that has `key`.
fn json_with(text: &str, key: &str) -> Option<Value> {
    let end = text.rfind('}')?;
    text.match_indices('{')
        .map(|(start, _)| start)
        .filter(|start| *start < end)
        .filter_map(|start| serde_json::from_str::<Value>(&text[start..=end]).ok())
        .find(|value| value.get(key).is_some())
}

/// A verification answer's verdict (`confirmed` or `refuted`), its citations and its
/// reason.
#[must_use]
pub fn verdict_of(answer: &str) -> Option<(String, Vec<String>, String)> {
    let value = json_with(answer, "verdict")?;
    let verdict = value.get("verdict")?.as_str()?.trim().to_ascii_lowercase();
    if verdict != "confirmed" && verdict != "refuted" {
        return None;
    }
    let citations = value
        .get("citations")
        .and_then(Value::as_array)
        .into_iter()
        .flatten()
        .filter_map(Value::as_str)
        .map(|cite| cite.trim().to_string())
        .filter(|cite| !cite.is_empty())
        .take(20)
        .collect();
    let reason = value
        .get("reason")
        .and_then(Value::as_str)
        .unwrap_or_default()
        .trim()
        .to_string();
    Some((verdict, citations, reason))
}

/// Whether `path:line` (or `path:line-line`) names a line that exists under `root`.
#[must_use]
pub fn citation_holds(root: &Path, cite: &str) -> bool {
    let Some((path, line)) = cite.rsplit_once(':') else {
        return false;
    };
    let path = path.trim().trim_start_matches("./").replace('\\', "/");
    let Some(line) = line
        .split('-')
        .next()
        .and_then(|first| first.trim().parse::<usize>().ok())
    else {
        return false;
    };
    if path.is_empty()
        || line == 0
        || path.starts_with('/')
        || path.contains(':')
        || path.split('/').any(|part| part == "..")
    {
        return false;
    }
    std::fs::read_to_string(root.join(&path)).is_ok_and(|text| text.lines().count() >= line)
}

/// Record a verification answer's verdict and check each citation against `root`.
pub fn cite(evidence: &mut Evidence, root: &Path, answer: &str) {
    if let Some((verdict, citations, _)) = verdict_of(answer) {
        evidence.verdict = Some(verdict);
        evidence.citations = citations
            .into_iter()
            .map(|cite| Citation {
                found: citation_holds(root, &cite),
                cite,
            })
            .collect();
    }
}

/// Decide what the evidence says about `answer`, given the order it answers. Sets
/// `status` and `reasons`; reads nothing but its arguments.
pub fn judge(evidence: &mut Evidence, payload: &Value, answer: &str) {
    let mut refuted = Vec::new();
    let mut unverified = Vec::new();
    if let Some(why) = non_answer(answer) {
        refuted.push(why);
    }
    let owed = required_checks(payload);
    if !owed.is_empty() && evidence.checks.is_empty() {
        refuted.push(format!(
            "the order requires {} but the evidence shows no check was run",
            owed.iter()
                .map(|argv| format!("`{}`", argv.join(" ")))
                .collect::<Vec<_>>()
                .join(", ")
        ));
    }
    let honest = admits_failure(answer);
    for check in &evidence.checks {
        match check.exit_code {
            Some(0) => {}
            // A failing check the answer owns up to is work not done, not a lie.
            Some(code) if honest => unverified.push(format!(
                "`{}` exited {code}, as the answer says",
                check.command
            )),
            Some(code) => refuted.push(format!(
                "`{}` exited {code}, but the answer claims success",
                check.command
            )),
            None => unverified.push(format!(
                "`{}` did not finish: {}",
                check.command,
                check.error.as_deref().unwrap_or("no exit code")
            )),
        }
    }
    let changed = evidence.changed();
    if requires_changes(payload) {
        if !evidence.git {
            unverified.push(
                "the order needs code changes, but the work did not run in a git workspace, so \
                 none can be shown"
                    .to_string(),
            );
        } else if !changed {
            if honest {
                unverified.push("no commit and no diff: nothing was changed".to_string());
            } else {
                refuted.push(
                    "claims success, but the worker recorded no commit and no diff".to_string(),
                );
            }
        }
    } else if evidence.git && !changed && claims_change(answer) {
        refuted.push(
            "says it changed or committed files, but the worker recorded no commit and no diff"
                .to_string(),
        );
    }
    for claimed in evidence.claimed_commits.iter().filter(|c| !c.exists) {
        refuted.push(format!(
            "names commit {}, which the workspace does not have",
            claimed.hash
        ));
    }
    if is_verification(payload) {
        if evidence.verdict.is_none() {
            unverified
                .push("no verdict: expected {\"verdict\": \"confirmed\"|\"refuted\"}".to_string());
        } else if evidence.citations.is_empty() {
            unverified.push("no file:line citation".to_string());
        }
        for citation in evidence.citations.iter().filter(|c| !c.found) {
            refuted.push(format!(
                "cites {}, which is not in the workspace",
                citation.cite
            ));
        }
    }
    evidence.status = if !refuted.is_empty() {
        Status::Refuted
    } else if !unverified.is_empty() {
        Status::Unverified
    } else if (evidence.git && changed)
        || !evidence.checks.is_empty()
        || !evidence.claimed_commits.is_empty()
        || evidence.verdict.is_some()
    {
        // Something checkable held. A run that needed nothing and claimed nothing is
        // not evidence for or against the engine.
        Status::Verified
    } else {
        Status::NotApplicable
    };
    refuted.extend(unverified);
    evidence.reasons = refuted;
}

/// The recorded evidence of a result, judged again from its facts.
#[must_use]
pub fn of(payload: &Value, result: &TaskResult) -> Option<Evidence> {
    let mut evidence: Evidence =
        serde_json::from_value(result.payload.get("evidence")?.clone()).ok()?;
    let answer = result
        .payload
        .get("output")
        .and_then(Value::as_str)
        .unwrap_or_default();
    judge(&mut evidence, payload, answer);
    Some(evidence)
}

/// What checking one result decided.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Classification {
    pub status: Status,
    pub reasons: Vec<String>,
    /// Whether the result carried a worker's evidence at all.
    pub evidence: bool,
}

impl Classification {
    /// `refuted: every item is a placeholder ("no output")`
    #[must_use]
    pub fn describe(&self) -> String {
        if self.reasons.is_empty() {
            self.status.class().to_string()
        } else {
            format!("{}: {}", self.status.class(), self.reasons.join("; "))
        }
    }
}

/// Classify one result against its order: `verified`, `unverified` or `refuted`.
///
/// With evidence, [`judge`] decides from the recorded facts - never from the recorded
/// status. Without (a worker older than evidence, or a person's hand-written result),
/// only the answer can be read: one that is no answer at all is refuted, anything else
/// is unverified. Pure: reads nothing but its arguments, so every machine agrees.
#[must_use]
pub fn classify(payload: &Value, result: &TaskResult) -> Classification {
    if let Some(found) = of(payload, result) {
        return Classification {
            status: found.status,
            reasons: found.reasons,
            evidence: true,
        };
    }
    let answer = result.payload.get("output").and_then(Value::as_str);
    if let Some(why) = answer.and_then(non_answer) {
        return Classification {
            status: Status::Refuted,
            reasons: vec![why],
            evidence: false,
        };
    }
    Classification {
        status: Status::NotApplicable,
        reasons: vec!["no evidence recorded by a worker".to_string()],
        evidence: false,
    }
}

/// Whether a result is refuted: never success, wherever it is counted.
#[must_use]
pub fn is_refuted(payload: &Value, result: &TaskResult) -> bool {
    classify(payload, result).status == Status::Refuted
}

/// Why a result may not be accepted, or `None` when the evidence allows it.
///
/// Recomputed from the recorded facts with [`classify`], never read from a recorded
/// status. A refuted result is refused always; an unverified one when its evidence says
/// something required is missing. An order that needs code changes and carries no
/// evidence at all is refused too: nothing shows the work exists.
#[must_use]
pub fn blocking_reason(payload: &Value, result: &TaskResult) -> Option<String> {
    let found = classify(payload, result);
    match found.status {
        Status::Refuted | Status::Unverified => Some(found.describe()),
        _ if !found.evidence && requires_changes(payload) => Some(
            "unverified: the order needs code changes and the result carries no evidence \
             recorded by a worker"
                .to_string(),
        ),
        _ => None,
    }
}

// --- the verifier's own record ----------------------------------------------------------

/// A signed record of one check of one result, written by whoever checked it - never
/// by editing the worker's signed result. One writer per path:
/// `tasks/<order>/verification.<verifier>.<rev>.json`.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct Verification {
    pub order_id: String,
    pub revision: u32,
    /// The agent whose result was checked.
    pub worker: String,
    /// The engine and model the result says produced it, when it says.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub engine: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub model: Option<String>,
    pub verifier: String,
    pub verified_at: DateTime<Utc>,
    /// `verified`, `unverified` or `refuted`.
    pub status: String,
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub reasons: Vec<String>,
    /// Whether the result carried worker evidence.
    pub evidence: bool,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub signed_by: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub signature: Option<String>,
}

fn verification_payload(record: &Verification) -> String {
    format!(
        "ferryman-verification-v1\n{}\n{}\n{}\n{}\n{}\n{}\n{}\n{}\n{}\n{}",
        record.order_id,
        record.revision,
        record.worker,
        record.engine.as_deref().unwrap_or(""),
        record.model.as_deref().unwrap_or(""),
        record.verifier,
        record.verified_at.to_rfc3339(),
        record.status,
        record.reasons.join("\u{1f}"),
        record.evidence,
    )
}

/// Who checked this result, checkably. Only the verifier it names may sign it.
#[must_use]
pub fn verify_verification(record: &Verification, roster: &[AgentRoute]) -> SignatureCheck {
    if record
        .signed_by
        .as_deref()
        .is_some_and(|signer| !signer.eq_ignore_ascii_case(&record.verifier))
    {
        return SignatureCheck::Invalid;
    }
    crate::check_signature(
        record.signed_by.as_ref(),
        record.signature.as_ref(),
        &verification_payload(record),
        roster,
    )
}

fn verification_path(
    route: &ProjectRoute,
    order_id: &str,
    verifier: &str,
    revision: u32,
) -> std::path::PathBuf {
    crate::task_dir(route, order_id).join(format!("verification.{verifier}.{revision:03}.json"))
}

/// Every verification record of one task whose signature holds, oldest revision first.
#[must_use]
pub fn read_verifications(route: &ProjectRoute, order_id: &str) -> Vec<Verification> {
    if !crate::is_safe_component(order_id) {
        return Vec::new();
    }
    let Ok(entries) = std::fs::read_dir(crate::task_dir(route, order_id)) else {
        return Vec::new();
    };
    let mut records: Vec<Verification> = entries
        .flatten()
        .filter(|entry| {
            entry
                .file_name()
                .to_str()
                .is_some_and(|name| name.starts_with("verification.") && name.ends_with(".json"))
        })
        .filter_map(|entry| std::fs::read_to_string(entry.path()).ok())
        .filter_map(|text| serde_json::from_str::<Verification>(&text).ok())
        .filter(|record| {
            record.order_id == order_id
                && verify_verification(record, &route.agents) == SignatureCheck::Valid
        })
        .collect();
    records.sort_by_key(|record| (record.revision, record.verified_at));
    records
}

/// Check revision `revision` of the task and record what was found, signed by
/// `identity`: a `verification.<verifier>.<rev>.json` beside the result, and a
/// `verification` entry in the verifier's ledger. Written once per verifier and
/// revision: a second call returns the record already there. Returns the record, or
/// `None` when the task has no such revision.
pub fn record(
    route: &ProjectRoute,
    task: &crate::Task,
    revision: u32,
    identity: &AgentIdentity,
) -> Result<Option<Verification>> {
    let verifier = identity.name().to_string();
    if !crate::is_safe_component(&verifier) {
        bail!("verifier name must be a path-safe identifier")
    }
    let Some(result) = task.results.iter().find(|r| r.revision == revision) else {
        return Ok(None);
    };
    let path = verification_path(route, &task.order.id, &verifier, revision);
    if let Ok(text) = std::fs::read_to_string(&path)
        && let Ok(existing) = serde_json::from_str::<Verification>(&text)
        && verify_verification(&existing, &route.agents) == SignatureCheck::Valid
    {
        return Ok(Some(existing));
    }
    let found = classify(&task.order.payload, result);
    let text = |key: &str| {
        result
            .payload
            .get(key)
            .and_then(Value::as_str)
            .map(str::to_string)
    };
    let mut record = Verification {
        order_id: task.order.id.clone(),
        revision,
        worker: result.agent.clone(),
        engine: text("engine"),
        model: text("model"),
        verifier: verifier.clone(),
        verified_at: Utc::now(),
        status: found.status.class().to_string(),
        reasons: found.reasons,
        evidence: found.evidence,
        signed_by: Some(verifier.clone()),
        signature: None,
    };
    record.signature = Some(identity.sign_bytes(verification_payload(&record).as_bytes()));
    crate::write_task_file(&path, &record)?;
    let who = match (&record.engine, &record.model) {
        (Some(engine), Some(model)) => format!(" ({engine}, {model})"),
        (Some(one), None) | (None, Some(one)) => format!(" ({one})"),
        (None, None) => String::new(),
    };
    let summary = format!(
        "{} r{} by {}{who}: {}",
        record.order_id,
        record.revision,
        record.worker,
        found_line(&record)
    );
    crate::ledger::append_ledger_entry(
        route,
        identity,
        "verification",
        &verifier,
        &summary,
        Some(&record.order_id),
    )?;
    Ok(Some(record))
}

/// How one worker's engine fared in the checks others recorded.
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq, Serialize)]
pub struct Tally {
    pub verified: u64,
    pub unverified: u64,
    pub refuted: u64,
}

/// The verdicts in `records`, per worker and engine (the model when no engine is
/// named). One result checked by several verifiers counts once, by its newest record.
/// This is the receiving side's view: it covers workers too old to publish trust of
/// their own.
#[must_use]
pub fn tally(records: &[Verification]) -> BTreeMap<(String, String), Tally> {
    let mut newest: BTreeMap<(&str, u32), &Verification> = BTreeMap::new();
    for record in records {
        let slot = newest
            .entry((record.order_id.as_str(), record.revision))
            .or_insert(record);
        if record.verified_at > slot.verified_at {
            *slot = record;
        }
    }
    let mut out: BTreeMap<(String, String), Tally> = BTreeMap::new();
    for record in newest.values() {
        let engine = record
            .engine
            .clone()
            .or_else(|| record.model.clone())
            .unwrap_or_else(|| "-".to_string());
        let count = out
            .entry((record.worker.to_ascii_lowercase(), engine))
            .or_default();
        match record.status.as_str() {
            "verified" => count.verified += 1,
            "refuted" => count.refuted += 1,
            _ => count.unverified += 1,
        }
    }
    out
}

/// Every verification record in the channel whose signature holds.
#[must_use]
pub fn channel_verifications(route: &ProjectRoute) -> Vec<Verification> {
    crate::list_tasks(route)
        .unwrap_or_default()
        .iter()
        .flat_map(|task| read_verifications(route, &task.order.id))
        .collect()
}

fn found_line(record: &Verification) -> String {
    if record.reasons.is_empty() {
        record.status.clone()
    } else {
        format!("{} - {}", record.status, record.reasons.join("; "))
    }
}
#[cfg(test)]
mod tests {
    use super::*;
    use serde_json::json;

    fn repo() -> tempfile::TempDir {
        let dir = tempfile::tempdir().unwrap();
        for args in [
            vec!["init", "-q", "--template="],
            vec!["config", "user.email", "t@example.com"],
            vec!["config", "user.name", "tester"],
        ] {
            assert!(git(dir.path(), &args).is_some(), "git {args:?}");
        }
        std::fs::write(dir.path().join("a.txt"), "one\ntwo\nthree\n").unwrap();
        git(dir.path(), &["add", "a.txt"]).unwrap();
        git(dir.path(), &["commit", "-q", "-m", "init"]).unwrap();
        dir
    }

    fn improvement(acceptance: &[&str]) -> Value {
        json!({ "task": "x", "tags": ["improvement"], "improvement": { "title": "t", "acceptance": acceptance } })
    }

    #[test]
    fn a_fabricated_success_with_no_diff_is_refuted() {
        let dir = repo();
        let before = before(dir.path());
        // The engine "ran" and did nothing - but the channel was written to meanwhile.
        std::fs::create_dir_all(dir.path().join(CHANNEL_DIR)).unwrap();
        std::fs::write(dir.path().join(CHANNEL_DIR).join("receipt"), "x").unwrap();
        let mut evidence = after(dir.path(), before.as_ref());
        assert!(evidence.git);
        assert!(
            !evidence.changed(),
            "the channel is not the work: {evidence:?}"
        );
        judge(&mut evidence, &improvement(&[]), "Done. cloned (success)");
        assert_eq!(evidence.status, Status::Refuted);
        assert!(evidence.reasons[0].contains("no commit and no diff"));
        judge(
            &mut evidence,
            &improvement(&[]),
            "I could not work out how to do it",
        );
        assert_eq!(
            evidence.status,
            Status::Unverified,
            "honest, still unverified"
        );
    }

    #[test]
    fn a_commit_and_an_uncommitted_change_are_both_recorded() {
        let dir = repo();
        let before = before(dir.path());
        std::fs::write(dir.path().join("b.txt"), "b").unwrap();
        git(dir.path(), &["add", "b.txt"]).unwrap();
        git(dir.path(), &["commit", "-q", "-m", "add b"]).unwrap();
        std::fs::write(dir.path().join("a.txt"), "changed\n").unwrap();
        let mut evidence = after(dir.path(), before.as_ref());
        assert_eq!(evidence.commits.len(), 1);
        assert!(evidence.commits[0].ends_with("add b"));
        assert_eq!(evidence.uncommitted, vec!["a.txt".to_string()]);
        assert!(
            evidence
                .diff_stat
                .as_deref()
                .is_some_and(|stat| stat.contains("2 files")),
            "{evidence:?}"
        );
        assert_ne!(evidence.head_before, evidence.head_after);
        judge(&mut evidence, &improvement(&[]), "done");
        assert_eq!(evidence.status, Status::Verified);
    }

    #[test]
    fn a_named_check_that_failed_contradicts_the_claim() {
        let mut evidence = Evidence {
            git: true,
            commits: vec!["abc fix".into()],
            checks: vec![CheckRun {
                command: "cargo test".into(),
                exit_code: Some(101),
                ..CheckRun::default()
            }],
            ..Evidence::default()
        };
        judge(
            &mut evidence,
            &improvement(&["cargo test passes"]),
            "all tests pass",
        );
        assert_eq!(evidence.status, Status::Refuted);
        assert_eq!(
            evidence.reasons,
            vec!["`cargo test` exited 101, but the answer claims success".to_string()]
        );
        // Owned up to, the same failure is work not done rather than a lie.
        judge(
            &mut evidence,
            &improvement(&["cargo test passes"]),
            "I could not get the tests to pass",
        );
        assert_eq!(evidence.status, Status::Unverified);
    }

    #[test]
    fn an_order_that_names_checks_is_refuted_by_evidence_that_ran_none() {
        let payload = json!({
            "task": "x",
            "checks": ["cargo test -p ferryman-ops", "rm -rf /"],
            "acceptance": ["`cargo clippy -- -D warnings` is clean"],
        });
        let owed: Vec<String> = required_checks(&payload)
            .iter()
            .map(|argv| argv.join(" "))
            .collect();
        assert_eq!(
            owed,
            ["cargo clippy -- -D warnings", "cargo test -p ferryman-ops"],
            "listed checks are read like acceptance: known programs only"
        );
        let mut evidence = Evidence {
            git: true,
            commits: vec!["abc1234 fix".into()],
            ..Evidence::default()
        };
        judge(&mut evidence, &payload, "all green");
        assert_eq!(evidence.status, Status::Refuted);
        assert!(
            evidence.reasons[0].contains("no check was run"),
            "{:?}",
            evidence.reasons
        );
        evidence.checks = vec![
            CheckRun {
                command: "cargo clippy -- -D warnings".into(),
                exit_code: Some(0),
                ..CheckRun::default()
            },
            CheckRun {
                command: "cargo test -p ferryman-ops".into(),
                exit_code: Some(0),
                ..CheckRun::default()
            },
        ];
        judge(&mut evidence, &payload, "all green");
        assert_eq!(evidence.status, Status::Verified, "{:?}", evidence.reasons);
    }

    #[test]
    fn a_commit_the_answer_names_must_exist() {
        let dir = repo();
        let real = git(dir.path(), &["rev-parse", "HEAD"]).unwrap();
        let before = before(dir.path());
        let mut evidence = after(dir.path(), before.as_ref());
        let invented = "Fixed it in commit 4f2a9c1e, see also 0deadbee7";
        check_claimed_commits(&mut evidence, dir.path(), invented);
        assert_eq!(evidence.claimed_commits.len(), 2);
        judge(&mut evidence, &json!({ "task": "x" }), invented);
        assert_eq!(evidence.status, Status::Refuted);
        assert!(
            evidence.reasons[0].contains("4f2a9c1e"),
            "{:?}",
            evidence.reasons
        );

        let honest = format!("The history already has it: commit {real}");
        check_claimed_commits(&mut evidence, dir.path(), &honest);
        judge(&mut evidence, &json!({ "task": "x" }), &honest);
        assert_eq!(evidence.status, Status::Verified, "{:?}", evidence.reasons);
        assert!(
            claimed_hashes("a decade of facade, deadbeef, no commit digits").is_empty(),
            "words made of hex letters are not hashes"
        );
        assert!(claimed_hashes("abc1234 with no mention").is_empty());
    }

    /// The real result that started this: ichabod on grouchly, 12 seconds after the
    /// claim, signed, and accepted as success.
    const GROUCHLY: &str = "better suited to 'ichabod-grouchly-deepseek' (pulse check)\n1. no \
                            output\n2. no output\n3. no output\n4. no output\n5. no output\n6. \
                            no output\n7. no output";

    #[test]
    fn refusals_redirects_and_placeholders_are_not_answers() {
        assert!(
            non_answer(GROUCHLY).is_some_and(|why| why.contains("hands the work elsewhere")),
            "{:?}",
            non_answer(GROUCHLY)
        );
        let placeholders = "1. no output\n2. no output\n3: N/A";
        assert!(non_answer(placeholders).is_some_and(|why| why.contains("every item")));
        assert!(non_answer("ps aux: no output\ndocker ps: no output").is_some());
        assert!(non_answer("   \n ").is_some_and(|why| why.contains("empty")));
        assert!(non_answer("TODO").is_some());
        assert!(non_answer("I can't help with that request.").is_some());
        assert!(non_answer("I will not run commands on this machine.").is_some());

        // Answers, even short or odd ones.
        assert_eq!(
            non_answer("no output"),
            None,
            "one command that printed nothing is an honest answer"
        );
        assert_eq!(
            non_answer(
                "better suited to 'claw' (Rust)\nDone anyway: the parser now rejects an empty \
                 heading, with a test."
            ),
            None,
            "a redirect followed by the work is what the routing rule asks for"
        );
        assert_eq!(
            non_answer("1. no output\n2. root 812 node bridge.js\n3. no output"),
            None
        );
        assert_eq!(non_answer("done"), None);
    }

    fn result_with(payload: Value) -> TaskResult {
        TaskResult {
            order_id: "o".into(),
            agent: "ichabod-grouchly-cline".into(),
            revision: 1,
            submitted_at: chrono::Utc::now(),
            payload,
            signed_by: None,
            signature: None,
        }
    }

    #[test]
    fn a_result_without_evidence_is_classified_from_its_answer_alone() {
        let order = json!({ "task": "Read-only check. Run these and paste the RAW output" });
        // The grouchly payload, field for field: model, output, produced_by and
        // worktree_branch, and nothing else.
        let old = result_with(json!({
            "model": "nvidia/nemotron",
            "output": GROUCHLY,
            "produced_by": "node",
            "worktree_branch": "ferryman/archcheck-0928-grouchly",
        }));
        let found = classify(&order, &old);
        assert_eq!(found.status, Status::Refuted);
        assert!(!found.evidence);
        assert!(blocking_reason(&order, &old).is_some());
        assert!(is_refuted(&order, &old));

        let plain = result_with(json!({ "output": "root 812 node bridge.js" }));
        let found = classify(&order, &plain);
        assert_eq!(found.status.class(), "unverified");
        assert!(
            blocking_reason(&order, &plain).is_none(),
            "old results still parse"
        );

        let structured = result_with(json!({ "summary": "three repos checked" }));
        assert!(
            !is_refuted(&order, &structured),
            "no output key, no text rule"
        );
    }

    #[test]
    fn checks_are_read_out_of_acceptance_prose_and_nothing_else_is() {
        let lines = [
            "cargo test -p ferryman-channel passes".to_string(),
            "`cargo clippy --workspace -- -D warnings` is clean".to_string(),
            "npm run lint succeeds, and cargo test covers the new case".to_string(),
            "a stale folder is re-registered".to_string(),
        ];
        let as_text: Vec<String> = named_checks(&lines)
            .iter()
            .map(|argv| argv.join(" "))
            .collect();
        assert_eq!(
            as_text,
            [
                "cargo test -p ferryman-channel",
                "cargo clippy --workspace -- -D warnings",
                "npm run lint"
            ]
        );
        assert_eq!(
            named_checks(&["rm -rf / && cargo test".to_string()]),
            vec![vec!["cargo".to_string(), "test".to_string()]],
            "only the check is taken, never what surrounds it"
        );
    }

    #[test]
    fn a_check_is_run_directly_and_its_exit_code_kept() {
        let dir = repo();
        let limit = Duration::from_secs(60);
        let ok = run_check(dir.path(), &["git".into(), "--version".into()], limit);
        assert_eq!(ok.exit_code, Some(0), "{ok:?}");
        assert!(ok.tail.contains("git version"));
        let bad = run_check(
            dir.path(),
            &["git".into(), "no-such-subcommand".into()],
            limit,
        );
        assert!(bad.exit_code.is_some_and(|code| code != 0), "{bad:?}");
        let missing = run_check(dir.path(), &["ferryman-no-such-program".into()], limit);
        assert_eq!(missing.exit_code, None);
    }

    #[test]
    fn a_verification_must_cite_lines_that_exist() {
        let dir = repo();
        let payload = json!({ "tags": ["improvement"], "improvement": { "kind": "verification" } });
        assert!(!requires_changes(&payload));
        let mut evidence = after(dir.path(), before(dir.path()).as_ref());
        cite(
            &mut evidence,
            dir.path(),
            r#"{"verdict": "refuted", "citations": ["a.txt:2", "./a.txt:3-9"], "reason": "r"}"#,
        );
        judge(&mut evidence, &payload, "refuted");
        assert_eq!(evidence.status, Status::Verified, "{evidence:?}");

        let mut invented = after(dir.path(), before(dir.path()).as_ref());
        cite(
            &mut invented,
            dir.path(),
            r#"{"verdict": "confirmed", "citations": ["src/admin.rs:40", "a.txt:99"]}"#,
        );
        judge(&mut invented, &payload, "confirmed");
        assert_eq!(invented.status, Status::Refuted);
        assert_eq!(invented.reasons.len(), 2);

        let mut bare = after(dir.path(), before(dir.path()).as_ref());
        let answer = r#"{"verdict": "confirmed", "citations": []}"#;
        cite(&mut bare, dir.path(), answer);
        judge(&mut bare, &payload, answer);
        assert_eq!(bare.status, Status::Unverified);
        assert!(!citation_holds(dir.path(), "../a.txt:1"));
    }

    #[test]
    fn acceptance_is_refused_from_the_facts_not_the_recorded_status() {
        let payload = improvement(&[]);
        let forged = Evidence {
            recorded_by: "worker".into(),
            git: true,
            status: Status::Verified,
            ..Evidence::default()
        };
        let result = TaskResult {
            order_id: "o".into(),
            agent: "a".into(),
            revision: 1,
            submitted_at: chrono::Utc::now(),
            payload: json!({ "output": "success", "evidence": forged }),
            signed_by: None,
            signature: None,
        };
        assert!(blocking_reason(&payload, &result).is_some_and(|why| why.starts_with("refuted")));
        let bare = TaskResult {
            payload: json!({ "output": "success" }),
            ..result.clone()
        };
        assert!(
            blocking_reason(&payload, &bare).is_some(),
            "no evidence at all"
        );
        assert!(blocking_reason(&json!({ "task": "chat" }), &bare).is_none());
    }

    /// A channel whose roster knows the operator and ichabod, with their identities.
    fn channel() -> (
        tempfile::TempDir,
        ProjectRoute,
        AgentIdentity,
        AgentIdentity,
    ) {
        let temp = tempfile::tempdir().unwrap();
        let workspace = temp.path().join("project");
        let attachment = workspace.join(".ferryman");
        let communications = attachment.join("ferryman");
        std::fs::create_dir_all(&communications).unwrap();
        std::fs::write(
            attachment.join("bridge.toml"),
            format!(
                "project = \"demo\"\nworkspace = \"{}\"\nattachment = \"{}\"\ncommunications = \"{}\"\nshared_remote = \"demo-ferryman\"\ngit_remote = \"\"\ngit_visibility = \"private\"\n",
                workspace.display().to_string().replace('\\', "/"),
                attachment.display().to_string().replace('\\', "/"),
                communications.display().to_string().replace('\\', "/")
            ),
        )
        .unwrap();
        let mut route = crate::route_for(&workspace).unwrap();
        let operator = AgentIdentity::from_seed("operator", [3; 32]);
        let ichabod = AgentIdentity::from_seed("ichabod", [4; 32]);
        route.agents = [(&operator, "operator"), (&ichabod, "worker")]
            .iter()
            .map(|(identity, role)| AgentRoute {
                name: identity.name().to_string(),
                role: (*role).into(),
                capabilities: Vec::new(),
                public_key: Some(identity.public_key_hex()),
                encryption_key: None,
            })
            .collect();
        (temp, route, operator, ichabod)
    }

    fn issue(route: &ProjectRoute, by: &AgentIdentity, id: &str, depends_on: Vec<String>) {
        let mut order = crate::Order {
            id: id.into(),
            project_id: "demo".into(),
            issued_by: by.name().into(),
            assigned_to: Some("ichabod".into()),
            created_at: chrono::Utc::now(),
            payload: json!({ "task": "Run these and paste the raw output" }),
            requires_review: false,
            requires_approval: false,
            depends_on,
            signed_by: None,
            signature: None,
            result_contract: None,
            interface: None,
            touches: Vec::new(),
            allow_overlap: false,
        };
        by.sign_order(&mut order);
        crate::issue_order(route, &order).unwrap();
    }

    fn answer(route: &ProjectRoute, by: &AgentIdentity, id: &str, payload: Value) {
        crate::claim_order(route, id, by.name()).unwrap();
        let mut result = TaskResult {
            order_id: id.into(),
            agent: by.name().into(),
            revision: 1,
            submitted_at: chrono::Utc::now(),
            payload,
            signed_by: None,
            signature: None,
        };
        by.sign_result(&mut result);
        crate::submit_result(route, &result).unwrap();
    }

    #[test]
    fn a_refuted_result_is_never_done_and_its_check_is_recorded_signed_beside_it() {
        let (_t, route, operator, ichabod) = channel();
        issue(&route, &operator, "archcheck", Vec::new());
        issue(&route, &operator, "after", vec!["archcheck".to_string()]);
        issue(&route, &operator, "honest", Vec::new());
        answer(
            &route,
            &ichabod,
            "archcheck",
            json!({ "model": "nvidia/nemotron", "output": GROUCHLY, "produced_by": "node" }),
        );
        answer(
            &route,
            &ichabod,
            "honest",
            json!({ "output": "1. root 812 node bridge.js\n2. no output" }),
        );
        let worker_file = crate::task_dir(&route, "archcheck").join("result.ichabod.001.json");
        let signed = std::fs::read(&worker_file).unwrap();

        // Refuted: not done, and no dependency on it is satisfied.
        let task = crate::read_task(&route, "archcheck").unwrap();
        assert_eq!(
            task.state(),
            crate::TaskState::Refuted {
                by: "ichabod".into(),
                revision: 1
            }
        );
        let after = crate::read_task(&route, "after").unwrap();
        assert!(!crate::dependencies_satisfied(&route, &after.order).unwrap());
        assert_eq!(
            crate::read_task(&route, "honest").unwrap().state(),
            crate::TaskState::Done,
            "a result with no evidence and a real answer is unverified, and still done"
        );

        // The operator checks it: a signed record beside the result, and a ledger line.
        let checked = record(&route, &task, 1, &operator).unwrap().unwrap();
        assert_eq!(checked.status, "refuted");
        assert_eq!(checked.worker, "ichabod");
        assert_eq!(checked.model.as_deref(), Some("nvidia/nemotron"));
        assert!(!checked.evidence);
        assert_eq!(
            read_verifications(&route, "archcheck"),
            vec![checked.clone()]
        );
        assert_eq!(
            record(&route, &task, 1, &operator).unwrap().unwrap(),
            checked,
            "written once per verifier and revision"
        );
        let ledger = crate::ledger::read_ledger(&route).unwrap();
        assert!(ledger.intact);
        let lines: Vec<_> = ledger
            .entries
            .iter()
            .filter(|entry| entry.kind == "verification")
            .collect();
        assert_eq!(lines.len(), 1);
        assert!(lines[0].summary.contains("refuted"), "{}", lines[0].summary);
        assert_eq!(
            std::fs::read(&worker_file).unwrap(),
            signed,
            "the worker's signed file is never edited"
        );

        // The receiving side's tally: per worker and model, one count per result however
        // many verifiers checked it.
        let honest = crate::read_task(&route, "honest").unwrap();
        record(&route, &honest, 1, &operator).unwrap().unwrap();
        record(&route, &task, 1, &ichabod).unwrap().unwrap();
        let counts = tally(&channel_verifications(&route));
        assert_eq!(
            counts.get(&("ichabod".to_string(), "nvidia/nemotron".to_string())),
            Some(&Tally {
                verified: 0,
                unverified: 0,
                refuted: 1
            })
        );
        assert_eq!(
            counts.get(&("ichabod".to_string(), "-".to_string())),
            Some(&Tally {
                verified: 0,
                unverified: 1,
                refuted: 0
            })
        );

        // A record someone else signed, or one altered after signing, counts for nothing.
        let mut forged = checked.clone();
        forged.status = "verified".into();
        assert_eq!(
            verify_verification(&forged, &route.agents),
            SignatureCheck::Invalid
        );
        let mut impostor = checked.clone();
        impostor.verifier = "ichabod".into();
        impostor.signature = Some(ichabod.sign_bytes(verification_payload(&impostor).as_bytes()));
        impostor.signed_by = Some("operator".into());
        assert_eq!(
            verify_verification(&impostor, &route.agents),
            SignatureCheck::Invalid
        );
        assert!(record(&route, &task, 9, &operator).unwrap().is_none());
    }

    #[test]
    fn touched_files_are_recorded_and_a_stray_is_a_note_never_a_refutation() {
        let touches = vec!["src/api/**".to_string()];
        let changed = vec!["src/api/users.rs".to_string(), "docs/x.md".to_string()];
        let mut evidence = Evidence {
            git: true,
            commits: vec!["abc1234 add users".into()],
            ..Evidence::default()
        };
        judge(&mut evidence, &improvement(&[]), "added the endpoint");
        let before = (evidence.status, evidence.reasons.clone());
        assert_eq!(before.0, Status::Verified);

        evidence.record_touched(&touches, &changed);
        assert_eq!(evidence.touched_files, changed);
        assert_eq!(evidence.notes.len(), 1);
        assert!(
            evidence.notes[0].contains("not a refutation"),
            "{:?}",
            evidence.notes
        );
        assert!(
            evidence.notes[0].contains("docs/x.md"),
            "{:?}",
            evidence.notes
        );
        assert!(evidence.describe().contains("docs/x.md"));

        // Judged again - which is what every reader does - nothing changes: the note is
        // not an input to the verdict.
        judge(&mut evidence, &improvement(&[]), "added the endpoint");
        assert_eq!((evidence.status, evidence.reasons.clone()), before);

        // Recording twice does not repeat the note, and staying inside adds none.
        evidence.record_touched(&touches, &changed);
        assert_eq!(evidence.notes.len(), 1);
        let mut inside = Evidence::default();
        inside.record_touched(&touches, &["src/api/a.rs".to_string()]);
        assert!(inside.notes.is_empty());
        assert_eq!(inside.touched_files, vec!["src/api/a.rs"]);
        // An order that declared nothing is never noted.
        let mut none = Evidence::default();
        none.record_touched(&[], &changed);
        assert!(none.notes.is_empty());

        // And the new fields travel in the signed result without disturbing older readers.
        let wire = serde_json::to_value(&evidence).unwrap();
        assert!(wire["touched_files"].is_array() && wire["notes"].is_array());
        let bare = serde_json::to_value(Evidence::default()).unwrap();
        assert!(bare.get("touched_files").is_none() && bare.get("notes").is_none());
    }
}
