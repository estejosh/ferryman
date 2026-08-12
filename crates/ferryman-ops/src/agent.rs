//! The agentic half: a machine that picks work up, runs an agent CLI on it, and
//! optionally judges what comes back.
//!
//! Everything here reads and writes the synced folder directly. There is no server to
//! start, no port to open and no token to mint - which is the whole reason this exists
//! rather than the older HTTP worker, whose lease/heartbeat protocol required every
//! machine to be reachable from every other one.
//!
//! # Ferryman does not choose your risk level
//!
//! A reviewing agent can be given the last word, or it can be made to hand its verdict
//! to a human. That is [`ReviewMode`], it comes from the operator's config file, and
//! there is no clever default that decides it for them: how much a model is trusted to
//! approve unsupervised is a property of the work and the team, not of this program.
//!
//! # Isolation - read before pointing this at a real agent
//!
//! The agent CLI spawned here runs with the FULL privileges of the OS user that started
//! the loop, in its working directory, with no sandbox from Ferryman. Ferryman
//! coordinates agents; it does not contain them. Give each worker its own
//! least-privilege account and its own disposable directory, and prefer the agent's own
//! sandbox flags over trusting this process to hold it back.

use crate::Progress;
use anyhow::{Context, Result, anyhow, bail};
use ferryman_channel::{
    AgentIdentity, ProjectRoute, Recommendation, Review, Task, TaskResult, TaskState,
};
use serde_json::{Value, json};
use std::collections::HashMap;
use std::fs;
use std::path::{Path, PathBuf};
use std::process::Stdio;
use std::time::Duration;
use tokio::io::AsyncReadExt;
use tokio::process::Command;

/// How much authority the operator has given the reviewing agent.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ReviewMode {
    /// The agent's verdict stands. The loop runs unattended.
    Auto,
    /// The agent judges and explains, and a human settles it. The reasoning is written
    /// into the channel so whoever settles it can see the case rather than a verdict.
    Confirm,
    /// No agent judgement at all. Results wait for a person.
    Off,
}

impl ReviewMode {
    pub fn parse(value: &str) -> Result<Self> {
        match value.trim() {
            "auto" => Ok(Self::Auto),
            "confirm" => Ok(Self::Confirm),
            "off" => Ok(Self::Off),
            other => bail!("review must be 'auto', 'confirm' or 'off', not '{other}'"),
        }
    }

    #[must_use]
    pub fn as_str(self) -> &'static str {
        match self {
            Self::Auto => "auto",
            Self::Confirm => "confirm",
            Self::Off => "off",
        }
    }
}

/// What this machine runs, and how far it is trusted.
#[derive(Debug, Clone)]
pub struct AgentConfig {
    /// The name this agent joined the channel under. Its signing key is filed under it.
    pub agent: String,
    /// Kept so the roster entry and the config cannot drift apart, even though the
    /// loops themselves do not branch on it.
    #[allow(dead_code)]
    pub role: String,
    /// The agent binary. Ferryman runs no models itself and is not tied to one vendor.
    pub command: String,
    /// Passed to the binary verbatim. The literal token `{prompt}` is replaced with the
    /// prompt; everything else is untouched, so a different CLI's flags need a config
    /// edit rather than a new build.
    pub args: Vec<String>,
    pub timeout: Duration,
    pub review: ReviewMode,
    pub poll: Duration,
}

impl AgentConfig {
    /// Where the config lives: beside the attachment, never inside the synced folder.
    #[must_use]
    pub fn path(attachment: &Path) -> PathBuf {
        attachment.join("agent.toml")
    }

    /// The file written by `ferry enable`.
    ///
    /// Parsed by hand in the same flat `key = "value"` shape as `bridge.toml`, which
    /// keeps this crate free of a TOML dependency it would otherwise pull in for six
    /// keys. `args` is a JSON array because a list does not fit that shape.
    pub fn load(attachment: &Path) -> Result<Self> {
        let path = Self::path(attachment);
        let text = fs::read_to_string(&path).with_context(|| {
            format!(
                "read {}; run 'ferry enable' in this project first",
                path.display()
            )
        })?;
        Self::parse(&text).with_context(|| format!("{} is not valid", path.display()))
    }

    fn parse(text: &str) -> Result<Self> {
        let mut fields: HashMap<String, String> = HashMap::new();
        for line in text.lines() {
            let line = line.trim();
            if line.is_empty() || line.starts_with('#') {
                continue;
            }
            let Some((key, value)) = line.split_once('=') else {
                bail!("line is not key = value: {line}")
            };
            fields.insert(
                key.trim().to_string(),
                value.trim().trim_matches('"').to_string(),
            );
        }
        let take = |key: &str| -> Result<String> {
            fields
                .get(key)
                .cloned()
                .with_context(|| format!("missing '{key}'"))
        };
        let args_raw = fields
            .get("args")
            .cloned()
            .unwrap_or_else(|| r#"["-p","{prompt}"]"#.to_string());
        let args: Vec<String> = serde_json::from_str(&args_raw)
            .context("args must be a JSON array of strings, e.g. [\"-p\",\"{prompt}\"]")?;
        let number = |key: &str, default: u64| -> Result<u64> {
            match fields.get(key) {
                None => Ok(default),
                Some(value) => value
                    .parse()
                    .with_context(|| format!("{key} must be a whole number of seconds")),
            }
        };
        Ok(Self {
            agent: take("agent")?,
            role: fields
                .get("role")
                .cloned()
                .unwrap_or_else(|| "worker".to_string()),
            command: take("command")?,
            args,
            timeout: Duration::from_secs(number("timeout_secs", 900)?),
            review: ReviewMode::parse(
                &fields
                    .get("review")
                    .cloned()
                    .unwrap_or_else(|| "confirm".to_string()),
            )?,
            poll: Duration::from_secs(number("poll_secs", 10)?),
        })
    }

    /// Render the file. Used by `ferry enable`, and the comments are the documentation
    /// most operators will actually read.
    #[must_use]
    pub fn render(
        agent: &str,
        role: &str,
        command: &str,
        args: &[String],
        review: ReviewMode,
    ) -> String {
        let args = serde_json::to_string(args).unwrap_or_else(|_| "[]".into());
        format!(
            r#"# Written by 'ferry enable'. Safe to edit; re-running enable will not
# overwrite it.

# The name this agent signs as. Its private key lives beside this file and is
# never synced.
agent = "{agent}"
role = "{role}"

# What actually does the work. Ferryman runs no models itself - point this at
# whichever agent CLI you use. {{prompt}} is replaced with the task; every other
# argument is passed through untouched.
command = "{command}"
args = {args}
timeout_secs = "900"

# How much authority the reviewing agent has. This is YOUR call, not Ferryman's:
#   auto    - the agent's verdict stands, and the loop runs unattended
#   confirm - the agent judges and explains; a human settles it
#   off     - no agent judgement; results wait for a person
review = "{review}"

# How often to look for new work, in seconds.
poll_secs = "10"
"#,
            review = review.as_str()
        )
    }
}

/// What the agent CLI printed, and whether it got to finish.
struct AgentRun {
    stdout: String,
    stderr: String,
    ok: bool,
}

/// Run the configured agent CLI over a prompt.
///
/// stdout is the result. stderr is kept because a failed run's only explanation is
/// usually there, and discarding it turns a diagnosable problem into a silent retry.
async fn run_agent(config: &AgentConfig, prompt: &str) -> Result<AgentRun> {
    let args: Vec<String> = config
        .args
        .iter()
        .map(|arg| arg.replace("{prompt}", prompt))
        .collect();
    let mut child = Command::new(&config.command)
        .args(&args)
        .stdin(Stdio::null())
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .spawn()
        .with_context(|| format!("start '{}'; is it installed and on PATH?", config.command))?;
    let mut stdout_pipe = child.stdout.take().ok_or_else(|| anyhow!("no stdout"))?;
    let mut stderr_pipe = child.stderr.take().ok_or_else(|| anyhow!("no stderr"))?;
    let mut stdout = String::new();
    let mut stderr = String::new();
    let collect = async {
        stdout_pipe.read_to_string(&mut stdout).await?;
        stderr_pipe.read_to_string(&mut stderr).await?;
        child.wait().await
    };
    // An agent that hangs must not hold the claim forever - the task would look held by
    // a live worker while nothing is happening.
    let status = match tokio::time::timeout(config.timeout, collect).await {
        Ok(result) => result?,
        Err(_) => {
            let _ = child.start_kill();
            bail!(
                "'{}' ran past {}s and was killed",
                config.command,
                config.timeout.as_secs()
            )
        }
    };
    Ok(AgentRun {
        stdout,
        stderr,
        ok: status.success(),
    })
}

/// The prompt for a first attempt, or for a revision.
///
/// A revision deliberately repeats the original task, the rejected attempt and the
/// reviewer's notes. Sending only the notes is the tempting shortcut and it is how you
/// get an agent that fixes the complaint and quietly loses the requirement.
/// Told to the agent on every task, before the work itself.
///
/// The first outside user ran a task, wrote its answer to stdout, and closed by saying
/// "I have not submitted this, since that would be an outward-facing write." It had
/// already been submitted - the loop captures stdout and publishes it. The agent was
/// being careful about a boundary it could not see, and reported a state that was not
/// true, into a signed artefact carrying its name.
///
/// An agent that does not know it is publishing will also write deliberation, ask
/// clarifying questions, or hedge - all of which become the result. Saying so costs two
/// sentences.
const PUBLISHING_NOTICE: &str = "\
Everything you print to stdout becomes your submitted result, signed with your name and \
carried to the other machines on this channel. You do not need to submit it yourself and \
you cannot take it back. Print the deliverable and nothing else - no preamble, no \
commentary on whether you should submit, no questions.\n\n";

fn work_prompt(task: &Task) -> String {
    let request = format!(
        "{PUBLISHING_NOTICE}{}",
        task.order
            .payload
            .get("task")
            .and_then(Value::as_str)
            .map(str::to_string)
            .unwrap_or_else(|| task.order.payload.to_string())
    );
    let Some(revision) = task.latest_revision() else {
        return request;
    };
    // Only a rejection asks for more work. Matching on "a review exists" would rewrite
    // an accepted task's prompt into "fix this", which is how an agent gets told to
    // improve work that was already signed off.
    let Some(sent_back) = task
        .reviews
        .iter()
        .find(|r| r.revision == revision && !r.accepted)
    else {
        return request;
    };
    let previous = task
        .results
        .iter()
        .find(|r| r.revision == revision)
        .map(|r| r.payload.to_string())
        .unwrap_or_default();
    format!(
        "{request}\n\n\
         Your previous attempt was sent back for revision.\n\n\
         What you submitted:\n{previous}\n\n\
         What the reviewer said to change:\n{}\n\n\
         Produce a corrected version. Keep everything that was already right.",
        sent_back.notes.as_deref().unwrap_or("(no notes given)")
    )
}

/// Ask for a verdict in a shape that can be parsed without guessing.
fn review_prompt(task: &Task, revision: u32) -> String {
    let request = task
        .order
        .payload
        .get("task")
        .and_then(Value::as_str)
        .map(str::to_string)
        .unwrap_or_else(|| task.order.payload.to_string());
    let submitted = task
        .results
        .iter()
        .find(|r| r.revision == revision)
        .map(|r| r.payload.to_string())
        .unwrap_or_default();
    format!(
        "You are reviewing another agent's work.\n\n\
         The task was:\n{request}\n\n\
         What was submitted:\n{submitted}\n\n\
         Decide whether this should be accepted or sent back for another revision. \
         Judge it against the task as stated, not against what you would have done.\n\n\
         Reply with exactly one JSON object and nothing else:\n\
         {{\"accept\": true|false, \"reasoning\": \"one or two sentences\"}}\n\
         If you send it back, the reasoning must say specifically what to change."
    )
}

/// A verdict as the reviewing agent gave it.
#[derive(Debug)]
struct Verdict {
    accept: bool,
    reasoning: String,
}

/// Pull the verdict out of whatever the agent printed.
///
/// Agents wrap JSON in prose and fences no matter how firmly they are asked not to, so
/// the last balanced object in the output is used. A run that cannot be parsed is an
/// error rather than a default: defaulting to accept approves unread work, and
/// defaulting to reject silently burns revisions.
fn parse_verdict(output: &str) -> Result<Verdict> {
    let start = output.rfind('{').context("no JSON object in the reply")?;
    let end = output[start..]
        .rfind('}')
        .context("no closing brace in the reply")?;
    let value: Value = serde_json::from_str(&output[start..=start + end])
        .context("the reply was not the JSON object the prompt asked for")?;
    let accept = value
        .get("accept")
        .and_then(Value::as_bool)
        .context("the reply has no boolean 'accept'")?;
    let reasoning = value
        .get("reasoning")
        .and_then(Value::as_str)
        .unwrap_or("")
        .trim()
        .to_string();
    if !accept && reasoning.is_empty() {
        bail!("work was rejected with no reason, which a worker cannot act on")
    }
    Ok(Verdict {
        accept,
        reasoning: if reasoning.is_empty() {
            "accepted without comment".to_string()
        } else {
            reasoning
        },
    })
}

/// Do one pass of available work. Returns how many tasks were acted on.
///
/// Separate from the loop so it can be run once (`--once`) in a cron job or a test,
/// rather than only as a daemon.
pub async fn work_once(
    route: &ProjectRoute,
    config: &AgentConfig,
    report: &dyn Progress,
) -> Result<usize> {
    let identity = AgentIdentity::load_or_create(&config.agent, &route.attachment)?;
    let mut acted = 0;
    for task in ferryman_channel::work_for(route, &config.agent)? {
        let id = task.order.id.clone();
        match task.state() {
            TaskState::Open => {
                ferryman_channel::claim_order(route, &id, &config.agent)?;
                // Re-read: another machine's claim may have arrived while this one was
                // being written, and the older claim wins. Acting on a stale read is
                // how two agents end up doing the same task.
                let task = ferryman_channel::read_task(route, &id)?;
                if task.holder() != Some(config.agent.as_str()) {
                    report.info(&format!(
                        "  {id}: {} claimed it first, backing off",
                        task.holder().unwrap_or("someone")
                    ));
                    continue;
                }
                do_work(route, config, &identity, &task, report).await?;
                acted += 1;
            }
            TaskState::Claimed { .. } | TaskState::ChangesRequested { .. } => {
                do_work(route, config, &identity, &task, report).await?;
                acted += 1;
            }
            _ => {}
        }
    }
    Ok(acted)
}

async fn do_work(
    route: &ProjectRoute,
    config: &AgentConfig,
    identity: &AgentIdentity,
    task: &Task,
    report: &dyn Progress,
) -> Result<()> {
    let id = &task.order.id;
    let revision = task.latest_revision().unwrap_or(0) + 1;
    report.info(&format!(
        "  {id}: running {} (revision {revision})",
        config.command
    ));
    let run = run_agent(config, &work_prompt(task)).await?;
    if !run.ok {
        // Left claimed on purpose. Marking it failed would need a state this protocol
        // does not have, and inventing one here would be a worse lie than silence.
        bail!(
            "'{}' failed on {id}: {}",
            config.command,
            run.stderr.trim().lines().next().unwrap_or("no output")
        )
    }
    let mut result = TaskResult {
        order_id: id.clone(),
        agent: config.agent.clone(),
        revision,
        submitted_at: chrono::Utc::now(),
        payload: json!({
            "output": run.stdout.trim(),
            "produced_by": config.command,
        }),
        signed_by: None,
        signature: None,
    };
    identity.sign_result(&mut result);
    ferryman_channel::submit_result(route, &result)?;
    report.info(&format!(
        "  {id}: submitted revision {revision}, signed by {}",
        config.agent
    ));
    Ok(())
}

/// Judge whatever is waiting, according to the authority the operator granted.
pub async fn review_once(
    route: &ProjectRoute,
    config: &AgentConfig,
    report: &dyn Progress,
) -> Result<usize> {
    if config.review == ReviewMode::Off {
        report.info("review is off; results wait for a person");
        return Ok(0);
    }
    let identity = AgentIdentity::load_or_create(&config.agent, &route.attachment)?;
    let mut acted = 0;
    let mut skipped_own = 0;
    for task in ferryman_channel::list_tasks(route)? {
        let TaskState::AwaitingReview { by, revision } = task.state() else {
            continue;
        };
        // Reviewing your own work is not review. Saying so out loud matters: a single
        // machine configured as both worker and reviewer would otherwise look like a
        // reviewer that silently does nothing, and the operator would go hunting for a
        // bug instead of starting a second agent.
        if by == config.agent {
            skipped_own += 1;
            continue;
        }
        // Do not re-judge something already sitting in front of a human.
        if task.pending_recommendation().is_some() {
            continue;
        }
        let id = task.order.id.clone();
        report.info(&format!("  {id}: judging revision {revision}"));
        let run = run_agent(config, &review_prompt(&task, revision)).await?;
        if !run.ok {
            bail!(
                "'{}' failed reviewing {id}: {}",
                config.command,
                run.stderr.trim().lines().next().unwrap_or("no output")
            )
        }
        let verdict = parse_verdict(&run.stdout)
            .with_context(|| format!("could not read a verdict for {id}"))?;
        match config.review {
            ReviewMode::Auto => {
                let mut review = Review {
                    order_id: id.clone(),
                    revision,
                    reviewer: config.agent.clone(),
                    reviewed_at: chrono::Utc::now(),
                    accepted: verdict.accept,
                    notes: Some(verdict.reasoning.clone()),
                    signed_by: None,
                    signature: None,
                };
                identity.sign_review(&mut review);
                ferryman_channel::submit_review(route, &review)?;
                report.info(&format!(
                    "  {id}: {} - {}",
                    if verdict.accept {
                        "accepted"
                    } else {
                        "sent back"
                    },
                    verdict.reasoning
                ));
            }
            ReviewMode::Confirm => {
                let mut recommendation = Recommendation {
                    order_id: id.clone(),
                    revision,
                    reviewer: config.agent.clone(),
                    recommended_at: chrono::Utc::now(),
                    accept: verdict.accept,
                    reasoning: verdict.reasoning.clone(),
                    signed_by: None,
                    signature: None,
                };
                identity.sign_recommendation(&mut recommendation);
                ferryman_channel::submit_recommendation(route, &recommendation)?;
                report.info(&format!(
                    "  {id}: recommends {} - {}",
                    if verdict.accept { "accept" } else { "changes" },
                    verdict.reasoning
                ));
                report.info(&format!(
                    "  {id}: waiting for a human; settle it with 'ferry channel review'"
                ));
            }
            ReviewMode::Off => unreachable!("returned above"),
        }
        acted += 1;
    }
    if acted == 0 && skipped_own > 0 {
        report.info(&format!(
            "  {skipped_own} result(s) waiting, but all of them are '{}'s own work - \
             an agent does not review itself. Run the reviewer as a different agent.",
            config.agent
        ));
    }
    Ok(acted)
}

/// Everything a human has been asked to settle.
pub fn pending(route: &ProjectRoute) -> Result<Vec<(String, Recommendation)>> {
    let roster = ferryman_channel::read_agent_roster(&route.communications)?;
    let mut waiting = Vec::new();
    for task in ferryman_channel::list_tasks(route)? {
        if let Some(recommendation) = task.pending_recommendation() {
            // Show the signature check beside the advice: a recommendation is read by a
            // human who is about to act on it, so a forged one is as good as a verdict.
            let check = ferryman_channel::verify_recommendation(recommendation, &roster);
            waiting.push((format!("{check:?}"), recommendation.clone()));
        }
    }
    Ok(waiting)
}

#[cfg(test)]
mod tests {
    use super::*;
    use ferryman_channel::{Claim, Order, Review};

    fn order(id: &str) -> Order {
        Order {
            id: id.into(),
            project_id: "p".into(),
            issued_by: "orchestrator".into(),
            assigned_to: None,
            created_at: chrono::Utc::now(),
            payload: json!({ "task": "write the report" }),
            requires_review: true,
            signed_by: None,
            signature: None,
        }
    }

    fn task_with(results: Vec<TaskResult>, reviews: Vec<Review>) -> Task {
        Task {
            order: order("t-1"),
            claims: vec![Claim {
                order_id: "t-1".into(),
                agent: "worker".into(),
                claimed_at: chrono::Utc::now(),
            }],
            results,
            reviews,
            recommendations: Vec::new(),
        }
    }

    fn result(revision: u32, body: &str) -> TaskResult {
        TaskResult {
            order_id: "t-1".into(),
            agent: "worker".into(),
            revision,
            submitted_at: chrono::Utc::now(),
            payload: json!({ "output": body }),
            signed_by: None,
            signature: None,
        }
    }

    #[test]
    fn a_first_attempt_is_the_task_plus_the_publishing_notice() {
        let prompt = work_prompt(&task_with(Vec::new(), Vec::new()));
        assert!(prompt.ends_with("write the report"));
        // The notice is not decoration: without it an agent reported that it had not
        // submitted work that had already been published under its own signature.
        assert!(prompt.contains("becomes your submitted result"));
    }

    #[test]
    fn a_revision_still_tells_the_agent_it_is_publishing() {
        let review = Review {
            order_id: "t-1".into(),
            revision: 1,
            reviewer: "orchestrator".into(),
            reviewed_at: chrono::Utc::now(),
            accepted: false,
            notes: Some("wrong totals".into()),
            signed_by: None,
            signature: None,
        };
        let prompt = work_prompt(&task_with(vec![result(1, "first go")], vec![review]));
        assert!(prompt.contains("becomes your submitted result"));
    }

    #[test]
    fn a_revision_carries_the_task_the_attempt_and_the_notes() {
        let review = Review {
            order_id: "t-1".into(),
            revision: 1,
            reviewer: "orchestrator".into(),
            reviewed_at: chrono::Utc::now(),
            accepted: false,
            notes: Some("the summary contradicts the table".into()),
            signed_by: None,
            signature: None,
        };
        let prompt = work_prompt(&task_with(vec![result(1, "first go")], vec![review]));
        // All three, because notes alone produce an agent that fixes the complaint and
        // drops the original requirement.
        assert!(prompt.contains("write the report"));
        assert!(prompt.contains("first go"));
        assert!(prompt.contains("the summary contradicts the table"));
    }

    #[test]
    fn an_accepted_revision_does_not_ask_for_more_work() {
        let review = Review {
            order_id: "t-1".into(),
            revision: 1,
            reviewer: "orchestrator".into(),
            reviewed_at: chrono::Utc::now(),
            accepted: true,
            notes: None,
            signed_by: None,
            signature: None,
        };
        let prompt = work_prompt(&task_with(vec![result(1, "first go")], vec![review]));
        assert!(!prompt.contains("sent back for revision"));
    }

    #[test]
    fn a_verdict_survives_the_prose_agents_wrap_it_in() {
        let verdict = parse_verdict(
            "Sure! Here's my assessment:\n```json\n{\"accept\": false, \
             \"reasoning\": \"the totals do not add up\"}\n```\nHope that helps.",
        )
        .unwrap();
        assert!(!verdict.accept);
        assert_eq!(verdict.reasoning, "the totals do not add up");
    }

    #[test]
    fn a_rejection_with_no_reason_is_refused() {
        // Not a default-to-something case: a worker cannot act on "no", and silently
        // accepting instead would approve unread work.
        let error = parse_verdict(r#"{"accept": false, "reasoning": "  "}"#).unwrap_err();
        assert!(error.to_string().contains("no reason"));
    }

    #[test]
    fn unparseable_output_is_an_error_not_a_guess() {
        assert!(parse_verdict("I think it looks fine to me").is_err());
    }

    #[test]
    fn config_round_trips_through_the_file_enable_writes() {
        let rendered = AgentConfig::render(
            "beastly",
            "worker",
            "claude",
            &["-p".into(), "{prompt}".into()],
            ReviewMode::Confirm,
        );
        let config = AgentConfig::parse(&rendered).unwrap();
        assert_eq!(config.agent, "beastly");
        assert_eq!(config.command, "claude");
        assert_eq!(config.args, vec!["-p", "{prompt}"]);
        assert_eq!(config.review, ReviewMode::Confirm);
        assert_eq!(config.timeout, Duration::from_secs(900));
    }

    #[test]
    fn review_mode_defaults_to_asking_a_human() {
        // The safe end of the scale. An operator who wants unattended approval has to
        // say so, rather than discovering they had it.
        let config = AgentConfig::parse("agent = \"a\"\ncommand = \"claude\"\n").unwrap();
        assert_eq!(config.review, ReviewMode::Confirm);
    }

    #[test]
    fn an_unknown_review_mode_is_refused_rather_than_assumed() {
        let error =
            AgentConfig::parse("agent=\"a\"\ncommand=\"c\"\nreview=\"yolo\"\n").unwrap_err();
        assert!(format!("{error:#}").contains("auto"));
    }
}
