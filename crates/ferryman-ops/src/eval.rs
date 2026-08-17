//! Benchmarking: run several engines over the same tasks and score them, so the
//! fleet knows which CLI wins on which work instead of guessing.
//!
//! This is Ferryman's answer to SWE-agent's benchmark mode. It is deliberately
//! minimal: a `bench.json` in the attachment lists engines and tasks; each task
//! scores against a result contract (its `require` keys), and every outcome is
//! recorded in the synced learning database so the comparison accumulates.

use std::path::Path;
use std::time::Duration;

use anyhow::{Context, Result};
use serde::{Deserialize, Serialize};

use crate::agent::{Runner, run_engine_prompt};

/// What running a scorer told us.
///
/// Three outcomes, not two. "The scorer says this output is wrong" and "the scorer could not
/// be run" are completely different facts, and collapsing them into `false` is what made this
/// dangerous: the verdict is written to `learnings.jsonl` in the **synced** channel, so a
/// scorer that could not start recorded a fabricated failure against that engine on every
/// machine in the fleet, permanently, in an append-only log.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Scored {
    Passed,
    Failed,
    /// The scorer itself did not run. Says nothing about the engine.
    NotRun,
}

/// Run a scorer command over the engine's output; exit 0 means pass. The
/// output is written to the command's stdin, so a scorer like `grep -q 42`
/// or a test runner reads it directly.
///
/// Uses the shared [`ferryman_channel::source::shell_command`] rather than `sh` directly.
/// This function had exactly the bug that helper exists to prevent: `Command::new("sh")` on a
/// platform with no `sh`, whose spawn failure was indistinguishable from a low score. On
/// Windows that meant every benchmarked task recorded as a failure.
fn scorer_passes(scorer: &str, output: &str) -> Scored {
    use std::io::Write;
    use std::process::Stdio;
    let Ok(mut child) = ferryman_channel::source::shell_command(scorer)
        .stdin(Stdio::piped())
        .stdout(Stdio::null())
        .stderr(Stdio::null())
        .spawn()
    else {
        return Scored::NotRun;
    };
    let Some(mut stdin) = child.stdin.take() else {
        return Scored::NotRun;
    };
    if let Err(error) = stdin.write_all(output.as_bytes()) {
        // A broken pipe is the scorer declining to read, not a failure to run it.
        //
        // Plenty of correct scorers never read stdin, or stop reading early: `exit 0`,
        // `test -f build/report.json`, a `grep -q` that matches in the first line. The
        // child exits, the pipe closes, and our write returns EPIPE. Whether that happens
        // is a race between the child exiting and this thread writing - which is exactly
        // why it showed up as a FLAKE rather than a failure, passing three runs in four.
        //
        // Treating it as `NotRun` meant a scorer's verdict was silently discarded some of
        // the time, and since `NotRun` abstains from the fleet-wide learning record, the
        // benchmark would quietly under-count results on a machine whose timing happened
        // to lose. Any other write error is a genuine inability to talk to the child.
        if error.kind() != std::io::ErrorKind::BrokenPipe {
            return Scored::NotRun;
        }
    }
    drop(stdin);
    match child.wait() {
        // Only here has the scorer actually reached a verdict about the output.
        Ok(status) if status.success() => Scored::Passed,
        Ok(_) => Scored::Failed,
        Err(_) => Scored::NotRun,
    }
}

/// An engine to benchmark: any agent CLI, with its own args and runner.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct BenchEngine {
    pub name: String,
    pub command: String,
    #[serde(default)]
    pub args: Vec<String>,
    /// Runner, same syntax as `sandbox`: ""/none, `podman:IMG`, `docker:IMG`, or a
    /// bare `IMG` (podman). Empty means bare.
    #[serde(default)]
    pub runner: String,
}

/// One benchmark task. Its result must carry the `require` keys to pass, and
/// must pass the optional `scorer` command if one is set.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct BenchTask {
    pub id: String,
    pub prompt: String,
    /// Required top-level keys in the result; scoring uses a result contract.
    #[serde(default)]
    pub require: Vec<String>,
    /// Optional shell command that scores the result; exit 0 = pass. The
    /// engine's stdout is written to the command's stdin.
    #[serde(default)]
    pub scorer: Option<String>,
}

/// The `bench.json` file.
#[derive(Debug, Clone, Default, Serialize, Deserialize)]
pub struct BenchConfig {
    #[serde(default, rename = "engines")]
    pub engines: Vec<BenchEngine>,
    #[serde(default, rename = "tasks")]
    pub tasks: Vec<BenchTask>,
}

/// One engine × task result.
#[derive(Debug, Clone)]
pub struct BenchResult {
    pub engine: String,
    pub task: String,
    pub accepted: bool,
    pub note: String,
}

/// Load `bench.json` from the attachment. Missing file is an error with a hint.
pub fn load_bench(attachment: &Path) -> Result<BenchConfig> {
    let path = attachment.join("bench.json");
    let text = std::fs::read_to_string(&path).with_context(|| {
        format!(
            "read {}; write it with \"engines\" and \"tasks\" arrays",
            path.display()
        )
    })?;
    serde_json::from_str(&text).with_context(|| format!("parse {}", path.display()))
}

/// Run every engine over every task, score, and record each outcome in the
/// learning database. Returns the results for display.
pub async fn run_bench(
    route: &ferryman_channel::ProjectRoute,
    config: &BenchConfig,
    workspace: &Path,
) -> Result<Vec<BenchResult>> {
    let mut results = Vec::new();
    for engine in &config.engines {
        let runner = Runner::parse(&engine.runner)?;
        for task in &config.tasks {
            let stdout = run_engine_prompt(
                &runner,
                &engine.command,
                &engine.args,
                workspace,
                &task.prompt,
                Duration::from_secs(300),
            )
            .await?;
            let payload: serde_json::Value = match serde_json::from_str(stdout.trim()) {
                Ok(value) => value,
                Err(_) => serde_json::json!({ "output": stdout.trim() }),
            };
            let contract = ferryman_channel::contract::ResultContract {
                required: task.require.clone(),
            };
            let missing = contract.violations(&payload);
            let contract_ok = missing.is_empty();
            let scored = match task.scorer.as_ref() {
                Some(scorer) => scorer_passes(scorer, stdout.trim()),
                None => Scored::Passed,
            };
            let accepted = contract_ok && scored == Scored::Passed;
            let note = if accepted {
                "ok".to_string()
            } else if !contract_ok {
                format!("missing: {}", missing.join(", "))
            } else if scored == Scored::NotRun {
                format!(
                    "scorer could not be run: {}",
                    task.scorer.as_deref().unwrap_or("(none)")
                )
            } else {
                "scorer failed".to_string()
            };
            // A benchmark whose scorer never ran is NOT evidence about the engine, and it
            // must not be filed as if it were. `learnings.jsonl` is in the synced channel and
            // feeds the confidence figures every machine displays and routes work by, so one
            // broken scorer would otherwise write a fabricated verdict against this engine to
            // the whole fleet, in an append-only log with nothing to un-poison it with.
            //
            // The run is still reported to the operator below, so a broken scorer is visible
            // rather than silently skipped. It is only the fleet-wide record that abstains.
            if scored != Scored::NotRun {
                ferryman_channel::learning::record_learning(
                    route,
                    &ferryman_channel::learning::Learning {
                        at: chrono::Utc::now(),
                        engine: engine.name.clone(),
                        agent: None,
                        model: None,
                        task_id: task.id.clone(),
                        source: "eval".to_string(),
                        accepted,
                        note: note.clone(),
                    },
                )?;
            }
            results.push(BenchResult {
                engine: engine.name.clone(),
                task: task.id.clone(),
                accepted,
                note,
            });
        }
    }
    Ok(results)
}

#[cfg(test)]
mod tests {
    use super::*;

    /// The three outcomes must stay three. Collapsing "could not run" into "failed" is what
    /// wrote fabricated verdicts into the fleet's synced confidence data on every Windows
    /// machine, and it is the kind of simplification someone will reach for again.
    /// A scorer that never reads its input still gets a verdict, every time.
    ///
    /// This is the regression test for a flake that took three runs in four to show: the
    /// child exits without reading stdin, the pipe closes, and `write_all` returns EPIPE.
    /// Reading that as "could not run" silently threw away a real verdict, and because
    /// `NotRun` abstains from the fleet-wide learning record, a benchmark would quietly
    /// under-count on whichever machine's timing lost the race.
    ///
    /// Repeated deliberately: once is not a test of a race, it is a coin flip. The output
    /// is large enough that a single `write_all` cannot fit in the pipe buffer, which is
    /// what makes losing the race the likely outcome rather than the rare one.
    #[test]
    fn a_scorer_that_ignores_its_input_still_reports_a_verdict() {
        let big = "x".repeat(256 * 1024);
        for attempt in 0..25 {
            assert_eq!(
                scorer_passes("exit 0", &big),
                Scored::Passed,
                "attempt {attempt}: a scorer may exit without reading stdin"
            );
            assert_eq!(
                scorer_passes("exit 7", &big),
                Scored::Failed,
                "attempt {attempt}: and its non-zero exit is still a verdict"
            );
        }
    }

    #[test]
    fn a_scorer_that_cannot_run_is_not_a_failing_engine() {
        // Exit 0 on every platform.
        assert_eq!(scorer_passes("exit 0", "anything"), Scored::Passed);
        // Exit non-zero: a real verdict about the output.
        assert_eq!(scorer_passes("exit 3", "anything"), Scored::Failed);
        // A program that does not exist: the scorer could not reach a verdict at all. Note
        // this goes through the shell, so it is the shell that fails - which is exactly the
        // shape of the original bug, where the shell itself was missing.
        assert_eq!(
            scorer_passes("ferryman-no-such-program-exists-anywhere", "anything"),
            Scored::Failed,
            "a missing program is the shell reporting non-zero, which IS a verdict"
        );
    }

    /// The scorer really does read the engine's output on stdin, on this platform.
    #[test]
    fn the_output_reaches_the_scorer_on_stdin() {
        let scorer = if cfg!(windows) {
            "findstr 42 >nul"
        } else {
            "grep -q 42"
        };
        assert_eq!(scorer_passes(scorer, "the answer is 42"), Scored::Passed);
        assert_eq!(scorer_passes(scorer, "the answer is 41"), Scored::Failed);
    }
}
