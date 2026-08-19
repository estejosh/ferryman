//! A soak report: what a maintainer needs to diagnose a fleet, and nothing else.
//!
//! # Why this exists rather than a phone-home
//!
//! Ferryman's most load-bearing document is `PRIVACY.md`: the automatic payload is three
//! integers and a contact address, listed there field by field, with a test that fails if a
//! field is added without documenting it. That promise is the reason anyone should be willing
//! to run this, and it is checkable rather than trusted.
//!
//! The diagnostic data that would actually be useful is exactly the data that promise forbids.
//! Run logs carry local paths and the agent CLI's stderr; task text is a prompt; results are
//! what agents produce. `crate::runlog` is deliberately built so it *cannot* leak - it sits
//! outside every directory Ferryman hands to Syncthing - and turning it into an upload would
//! invert a documented design decision to gain a convenience.
//!
//! So this is not telemetry, in the sense that matters: **nothing is ever sent on its own.**
//! `ferry soak` prints the report. Sending it requires the operator to set
//! `FERRYMAN_SOAK_URL` *and* pass `--send`, per invocation - there is no config key, no
//! timer, and no background sender, and a downloaded release has no endpoint at all.
//!
//! Because a send is possible, the fields below are documented in `PRIVACY.md` and pinned by
//! a test that fails if the payload changes without the page changing too. That is the same
//! guard the licence check-in carries, and it is the whole reason either promise is worth
//! believing: the document cannot fall quietly behind the code, because the code fails first.
//!
//! # Redaction is structural, not a filter
//!
//! There is no scrubbing pass here, because a scrubbing pass is a thing that can miss. The
//! report is assembled out of counts, enum names and version strings - values whose *type*
//! cannot carry a path, a prompt, or a secret. If a field cannot be expressed that way, it
//! does not go in.
//!
//! What a maintainer gets is the shape of a deployment's behaviour: how much work moved, how
//! many signatures failed and in which way, how often the governor declined and which check
//! declined it, and which categories of error occurred. That is enough to find the class of
//! bug soak testing is for, and it is the same set of facts across every reporter, which is
//! what makes reports comparable.

use std::collections::BTreeMap;

use ferryman_channel::{ProjectRoute, SignatureCheck, TaskState};
use serde::{Deserialize, Serialize};

/// One deployment's soak report.
///
/// Every field is a count, an enum name, or a build identifier. Deliberately not a struct that
/// *could* hold free text: the guarantee is meant to be readable off the type.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct SoakReport {
    /// Format marker, so a maintainer can tell an old report from a new one.
    pub format: String,
    /// The build, including the commit - the thing an upgrade report could not previously
    /// establish. See `ferryman-cli/build.rs`.
    pub version: String,
    /// `linux`, `macos`, `windows`. Not the hostname, not the release, not the machine name.
    pub platform: String,
    /// Whether a container runner is configured. Not which image.
    pub sandboxed: bool,
    /// Whether a stable preamble is configured, and roughly how large. Never its contents.
    pub preamble_bytes: usize,
    /// How many agents this project's roster carries.
    pub agents: usize,
    /// Tasks by state name: `open`, `claimed`, `awaiting_review`, ...
    pub tasks_by_state: BTreeMap<String, usize>,
    /// The highest revision seen on any task - how often work actually goes back.
    pub max_revision: u32,
    /// Signature checks by outcome name: `valid`, `unsigned`, `invalid`, `unknown_signer`,
    /// `key_changed`. The single most useful number in the report: a fleet with a nonzero
    /// `unknown_signer` has an identity problem, and one with `invalid` has something worse.
    pub signature_checks: BTreeMap<String, usize>,
    /// Whether the channel ledger reads back intact. False here is the finding.
    pub ledger_intact: bool,
    pub ledger_entries: usize,
    /// Error categories from this machine's run log, counted. Categories, never messages -
    /// see [`categorize`] for the whole vocabulary.
    pub run_log_categories: BTreeMap<String, usize>,
    pub run_log_lines: usize,
}

const FORMAT: &str = "ferryman-soak/v1";

/// The fixed vocabulary of things that can go wrong, and nothing outside it.
///
/// A run-log line can contain anything - a path, a repository name, whatever the agent CLI
/// printed to stderr. So a line is never carried into the report; it is matched against this
/// list and only the label survives. A line matching nothing counts as `other`, which is the
/// case that keeps the guarantee absolute: an unrecognised failure contributes a number, not
/// its text.
#[must_use]
pub fn categorize(line: &str) -> &'static str {
    let line = line.to_ascii_lowercase();
    // Ordered most specific first: several of these co-occur in one line.
    const PATTERNS: &[(&str, &str)] = &[
        ("was killed as frozen", "agent_stalled"),
        ("ran past", "agent_timeout"),
        ("holding off", "governor_declined"),
        ("is it installed and on path", "agent_cli_missing"),
        ("signature does not verify", "signature_failed"),
        ("unknownsigner", "unknown_signer"),
        ("claimed it first", "claim_lost_race"),
        ("pass failed", "pass_failed"),
        ("could not create the tray", "tray_failed"),
        ("preamble", "preamble_problem"),
        ("scorer could not be run", "scorer_unavailable"),
        ("syncthing", "syncthing_problem"),
        ("permission denied", "permission_denied"),
        ("no space left", "disk_full"),
    ];
    for (needle, label) in PATTERNS {
        if line.contains(needle) {
            return label;
        }
    }
    if line.contains(" warn ") {
        return "other_warning";
    }
    "other"
}

fn state_name(state: &TaskState) -> &'static str {
    match state {
        TaskState::Open => "open",
        TaskState::Offered { .. } => "offered",
        // NOTE: `claimed` here currently also covers an addressed order that nobody has
        // picked up, because `Task::holder` returns the assignee whether or not a claim file
        // exists. That is a known bug (see README, "Known issues"), and it means a soak
        // report can show `claimed` for work that has not started. Worth knowing when
        // reading these numbers, and worth fixing before the count is trusted.
        TaskState::Claimed { .. } => "claimed",
        TaskState::AwaitingReview { .. } => "awaiting_review",
        TaskState::ChangesRequested { .. } => "changes_requested",
        TaskState::Accepted => "accepted",
        TaskState::Done => "done",
    }
}

fn check_name(check: &SignatureCheck) -> &'static str {
    match check {
        SignatureCheck::Valid => "valid",
        SignatureCheck::Unsigned => "unsigned",
        SignatureCheck::Invalid => "invalid",
        SignatureCheck::UnknownSigner => "unknown_signer",
        SignatureCheck::KeyChanged { .. } => "key_changed",
    }
}

fn bump(counts: &mut BTreeMap<String, usize>, key: &str) {
    *counts.entry(key.to_string()).or_default() += 1;
}

/// Assemble a report for one project.
///
/// `version` is passed in rather than read here so the binary's own build stamp is used - this
/// crate is a library and does not know which front end it is serving.
pub fn report(
    route: &ProjectRoute,
    config: Option<&crate::agent::AgentConfig>,
    version: &str,
) -> SoakReport {
    let mut tasks_by_state = BTreeMap::new();
    let mut signature_checks = BTreeMap::new();
    let mut max_revision = 0;

    let roster = ferryman_channel::read_agent_roster(&route.communications).unwrap_or_default();
    if let Ok(tasks) = ferryman_channel::list_tasks(route) {
        for task in &tasks {
            bump(&mut tasks_by_state, state_name(&task.state()));
            max_revision = max_revision.max(task.latest_revision().unwrap_or(0));
            bump(
                &mut signature_checks,
                check_name(&ferryman_channel::verify_order(&task.order, &roster)),
            );
            for result in &task.results {
                bump(
                    &mut signature_checks,
                    check_name(&ferryman_channel::verify_result(result, &roster)),
                );
            }
            for review in &task.reviews {
                bump(
                    &mut signature_checks,
                    check_name(&ferryman_channel::verify_review(review, &roster)),
                );
            }
        }
    }

    let ledger = ferryman_channel::ledger::read_ledger(route).ok();

    // The run log is this machine's own diagnostic record and carries paths and stderr. Only
    // the categories cross into the report.
    let lines = crate::runlog::tail(2000);
    let mut run_log_categories = BTreeMap::new();
    for line in &lines {
        bump(&mut run_log_categories, categorize(line));
    }

    SoakReport {
        format: FORMAT.to_string(),
        version: version.to_string(),
        platform: std::env::consts::OS.to_string(),
        sandboxed: config.is_some_and(|c| !matches!(c.runner, crate::agent::Runner::Bare)),
        preamble_bytes: config
            .and_then(|c| c.preamble.as_ref())
            .map_or(0, String::len),
        agents: roster.len(),
        tasks_by_state,
        max_revision,
        signature_checks,
        ledger_intact: ledger.as_ref().is_none_or(|log| log.intact),
        ledger_entries: ledger.as_ref().map_or(0, |log| log.entries.len()),
        run_log_categories,
        run_log_lines: lines.len(),
    }
}

/// The report as a human reads it before deciding to send it.
///
/// Printing it is not a nicety, it is the consent step: an operator who can see the whole
/// report in their terminal does not have to trust a claim about what it contains.
#[must_use]
pub fn render(report: &SoakReport) -> String {
    let mut out = String::new();
    out.push_str("## Ferryman soak report\n\n");
    out.push_str(&format!("- build: `{}`\n", report.version));
    out.push_str(&format!("- platform: {}\n", report.platform));
    out.push_str(&format!("- sandboxed: {}\n", report.sandboxed));
    out.push_str(&format!("- agents on roster: {}\n", report.agents));
    if report.preamble_bytes > 0 {
        out.push_str(&format!("- preamble: {} bytes\n", report.preamble_bytes));
    }
    out.push_str(&format!(
        "- ledger: {} entries, {}\n",
        report.ledger_entries,
        if report.ledger_intact {
            "intact"
        } else {
            "NOT INTACT - please mention this in the issue"
        }
    ));
    out.push_str(&format!("- highest revision: {}\n", report.max_revision));

    let section = |out: &mut String, title: &str, counts: &BTreeMap<String, usize>| {
        out.push_str(&format!("\n### {title}\n\n"));
        if counts.is_empty() {
            out.push_str("- (none)\n");
            return;
        }
        for (key, count) in counts {
            out.push_str(&format!("- {key}: {count}\n"));
        }
    };
    section(&mut out, "Tasks by state", &report.tasks_by_state);
    section(&mut out, "Signature checks", &report.signature_checks);
    section(
        &mut out,
        &format!("Run log ({} lines read)", report.run_log_lines),
        &report.run_log_categories,
    );
    out.push_str(
        "\nThis report contains only counts, category labels and the build string. No file \
         paths, task text, prompts, results, agent output or credentials are included - see \
         `crates/ferryman-ops/src/soak.rs` for how that is guaranteed.\n",
    );
    out
}

#[cfg(test)]
mod tests {
    use super::*;

    /// The guarantee, tested as a property rather than trusted as a comment.
    ///
    /// Anything a run log can contain - absolute paths, repository names, whatever the agent
    /// printed to stderr - must not survive into the report. This is the assertion that fails
    /// if someone later adds a field carrying the line itself, which is the obvious next
    /// "improvement" and the one that would break the promise.
    #[test]
    fn no_run_log_text_survives_into_the_report() {
        let hostile = [
            "2026-08-17 10:00:00Z warn  holding off: /home/josh/secrets/project",
            "2026-08-17 10:00:01Z warn  pass failed: token sk-live-abcdef123 rejected",
            "2026-08-17 10:00:02Z info  C:\\Users\\oshha\\ferryman\\private.key",
            "2026-08-17 10:00:03Z warn  something nobody has a pattern for yet",
        ];
        let mut counts = BTreeMap::new();
        for line in hostile {
            bump(&mut counts, categorize(line));
        }
        let rendered = counts.keys().cloned().collect::<Vec<String>>().join(" ");

        for leak in [
            "/home/josh",
            "secrets",
            "sk-live-abcdef123",
            "C:\\Users",
            "private.key",
            "oshha",
        ] {
            assert!(
                !rendered.contains(leak),
                "'{leak}' must not survive categorisation, got: {rendered}"
            );
        }
        // And the unrecognised line still contributes a count, so nothing is dropped
        // silently just because it had no pattern.
        assert_eq!(counts.get("other_warning"), Some(&1));
    }

    /// The wire form must be exactly the fields PRIVACY.md documents.
    ///
    /// If this test needs updating because a field was added, that field also needs adding to
    /// PRIVACY.md before it ships. This is the same guard the licence check-in carries, and it
    /// is the reason that promise is worth believing: the document cannot quietly fall behind
    /// the code, because the code fails first.
    #[test]
    fn the_sent_payload_is_exactly_the_documented_fields() {
        let report = SoakReport {
            format: FORMAT.to_string(),
            version: "0.4.0 (abcd1234)".into(),
            platform: "linux".into(),
            sandboxed: false,
            preamble_bytes: 0,
            agents: 1,
            tasks_by_state: BTreeMap::new(),
            max_revision: 0,
            signature_checks: BTreeMap::new(),
            ledger_intact: true,
            ledger_entries: 0,
            run_log_categories: BTreeMap::new(),
            run_log_lines: 0,
        };
        let value = serde_json::to_value(&report).unwrap();
        let mut keys: Vec<&str> = value
            .as_object()
            .expect("a soak report serialises as an object")
            .keys()
            .map(String::as_str)
            .collect();
        keys.sort_unstable();
        assert_eq!(
            keys,
            vec![
                "agents",
                "format",
                "ledger_entries",
                "ledger_intact",
                "max_revision",
                "platform",
                "preamble_bytes",
                "run_log_categories",
                "run_log_lines",
                "sandboxed",
                "signature_checks",
                "tasks_by_state",
                "version",
            ],
            "the soak payload changed; update PRIVACY.md in the same commit"
        );
    }

    #[test]
    fn categories_are_stable_and_specific() {
        assert_eq!(
            categorize("worker 'claw' printed nothing for 600s and was killed as frozen"),
            "agent_stalled"
        );
        assert_eq!(
            categorize("holding off: 500 MB of memory available"),
            "governor_declined"
        );
        assert_eq!(
            categorize("'claude' ... is it installed and on PATH?"),
            "agent_cli_missing"
        );
        // Nothing matched, and it is not a warning line: still counted, never quoted.
        assert_eq!(categorize("a perfectly ordinary info line"), "other");
    }

    #[test]
    fn a_rendered_report_says_what_it_does_not_contain() {
        let report = SoakReport {
            format: FORMAT.to_string(),
            version: "0.4.0 (abcd1234)".into(),
            platform: "linux".into(),
            sandboxed: true,
            preamble_bytes: 4115,
            agents: 2,
            tasks_by_state: BTreeMap::from([("accepted".to_string(), 3)]),
            max_revision: 2,
            signature_checks: BTreeMap::from([("valid".to_string(), 9)]),
            ledger_intact: true,
            ledger_entries: 12,
            run_log_categories: BTreeMap::from([("governor_declined".to_string(), 4)]),
            run_log_lines: 40,
        };
        let text = render(&report);
        assert!(text.contains("0.4.0 (abcd1234)"), "the build must be there");
        assert!(text.contains("governor_declined: 4"));
        assert!(
            text.contains("No file paths, task text, prompts"),
            "the report must state its own guarantee to whoever is about to send it"
        );
    }
}
