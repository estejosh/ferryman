//! HONE agent worker adapter.
//!
//! Leases a job from the Orchestrator Bridge, runs a REAL agent
//! (`claude -p "<prompt>" --permission-mode auto` by default), streams the agent's
//! stdout back to the bridge as `worker.log` events, uploads the full transcript as an
//! artifact, and completes the job idempotently. This is the piece the bridge does not
//! ship: the bridge orchestrates and gates; this worker actually runs a model.
//!
//! Config via env (all optional except where noted):
//!   BRIDGE_ENDPOINT   default http://127.0.0.1:8787
//!   BRIDGE_PROJECT    default "hone"                 (project slug to serve)
//!   BRIDGE_TOKEN      REQUIRED  project bearer token used ONLY to register as a worker.
//!                     Registration returns a short-lived, worker-scoped token; that
//!                     scoped token — not this one — is what the WorkerClient uses after.
//!   AGENT_CMD         default "claude"               (the agent binary)
//!   AGENT_ARGS_JSON   default '["-p","{prompt}","--permission-mode","auto"]'
//!                     JSON array; the literal token {prompt} is replaced with the job's
//!                     input.prompt. Lets us target codex or a different flag set without
//!                     recompiling.
//!   AGENT_TIMEOUT_SECS default 900  (kill + retry a run that overruns)
//!
//! The worker holds NO approval/admin capability: worker tokens cannot approve jobs,
//! write memory, or touch recovery keys (bridge-enforced). A `--requires-approval` job
//! will not even be leased until an operator approves it — this worker never sees it
//! until then.

use anyhow::{Context, Result, anyhow};
use orchestrator_worker_sdk::WorkerClient;
use serde_json::{Value, json};
use std::process::Stdio;
use std::time::Duration;
use tokio::io::{AsyncBufReadExt, BufReader};
use tokio::process::Command;

fn env_or(key: &str, default: &str) -> String {
    std::env::var(key).unwrap_or_else(|_| default.to_string())
}

/// Build the agent argv, substituting {prompt} for the job's prompt.
fn build_args(prompt: &str) -> Result<Vec<String>> {
    let raw = env_or(
        "AGENT_ARGS_JSON",
        r#"["-p","{prompt}","--permission-mode","auto"]"#,
    );
    let parsed: Vec<String> =
        serde_json::from_str(&raw).context("AGENT_ARGS_JSON must be a JSON array of strings")?;
    Ok(parsed
        .into_iter()
        .map(|a| a.replace("{prompt}", prompt))
        .collect())
}

#[tokio::main]
async fn main() -> Result<()> {
    let endpoint = env_or("BRIDGE_ENDPOINT", "http://127.0.0.1:8787");
    let project = env_or("BRIDGE_PROJECT", "hone");
    let token = std::env::var("BRIDGE_TOKEN")
        .context("BRIDGE_TOKEN (the project bearer token) is required to register the worker")?;
    let agent_cmd = env_or("AGENT_CMD", "claude");
    let timeout_secs: u64 = env_or("AGENT_TIMEOUT_SECS", "900").parse().unwrap_or(900);

    let client = WorkerClient::register(
        endpoint.clone(),
        project.clone(),
        token,
        vec!["hone-agent".into()],
    )
    .await
    .context("worker registration failed — is the bridge up and the project token valid?")?;

    eprintln!("[hone-agent-worker] registered on {endpoint} project={project}; polling for jobs");

    loop {
        let lease = match client.lease().await {
            Ok(Some(lease)) => lease,
            Ok(None) => {
                tokio::time::sleep(Duration::from_secs(1)).await;
                continue;
            }
            Err(e) => {
                eprintln!("[hone-agent-worker] lease error: {e}; backing off");
                tokio::time::sleep(Duration::from_secs(3)).await;
                continue;
            }
        };

        let job_id = lease.job.id.clone();
        let lease_id = lease.lease_id.clone();
        eprintln!("[hone-agent-worker] leased job {job_id}");

        // Job input contract: {"prompt": "<what the agent should do>"}.
        let prompt = lease
            .job
            .input
            .get("prompt")
            .and_then(Value::as_str)
            .map(str::to_owned);

        let outcome = match prompt {
            Some(prompt) if !prompt.trim().is_empty() => {
                run_agent(&client, &job_id, &agent_cmd, &prompt, timeout_secs).await
            }
            _ => Err(anyhow!("job input missing non-empty string field 'prompt'")),
        };

        match outcome {
            Ok(result) => {
                // Non-retryable success completion. Idempotent: re-completing the same
                // lease is a no-op on the bridge side.
                if let Err(e) = client
                    .complete(&job_id, &lease_id, result, false)
                    .await
                {
                    eprintln!("[hone-agent-worker] complete(success) failed for {job_id}: {e}");
                }
            }
            Err(e) => {
                let _ = client
                    .event(
                        &job_id,
                        "worker.log",
                        json!({"stream":"error","message": e.to_string()}),
                    )
                    .await;
                // retryable=true: transient (timeout, spawn failure) — let the bridge's
                // retry/backoff re-queue up to max_attempts. A malformed-input error is
                // not really retryable, but leaving retry to the bridge's attempt cap is
                // safer than silently succeeding; the error is in the event log + result.
                let result = json!({"ok": false, "error": e.to_string()});
                if let Err(ce) = client.complete(&job_id, &lease_id, result, true).await {
                    eprintln!("[hone-agent-worker] complete(failure) failed for {job_id}: {ce}");
                }
            }
        }
    }
}

/// Spawn the agent, stream stdout+stderr to the bridge as events, upload the transcript,
/// return the structured result for completion.
async fn run_agent(
    client: &WorkerClient,
    job_id: &str,
    agent_cmd: &str,
    prompt: &str,
    timeout_secs: u64,
) -> Result<Value> {
    let args = build_args(prompt)?;
    client
        .event(
            job_id,
            "worker.progress",
            json!({"percent":1,"message":format!("starting {agent_cmd}")}),
        )
        .await
        .ok();

    let mut child = Command::new(agent_cmd)
        .args(&args)
        .stdin(Stdio::null())
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .kill_on_drop(true) // a timed-out run drops `child`; ensure the OS process dies with it
        .spawn()
        .with_context(|| format!("failed to spawn agent '{agent_cmd}' — is it on PATH?"))?;

    let stdout = child.stdout.take().expect("piped stdout");
    let stderr = child.stderr.take().expect("piped stderr");

    let mut out_reader = BufReader::new(stdout).lines();
    let mut err_reader = BufReader::new(stderr).lines();
    let mut transcript = String::new();

    // Drain both streams concurrently until BOTH hit EOF, then wait on the process.
    // Each stream is guarded by a done-flag so a closed stream's select! arm can't
    // busy-spin on an immediate Ok(None), and so stdout closing first never drops
    // still-buffered stderr (and vice versa).
    let run = async {
        let mut out_done = false;
        let mut err_done = false;
        while !(out_done && err_done) {
            tokio::select! {
                line = out_reader.next_line(), if !out_done => match line? {
                    Some(l) => {
                        transcript.push_str(&l);
                        transcript.push('\n');
                        client.event(job_id, "worker.log", json!({"stream":"stdout","message":l})).await.ok();
                    }
                    None => out_done = true,
                },
                line = err_reader.next_line(), if !err_done => match line? {
                    Some(l) => {
                        transcript.push_str("[stderr] ");
                        transcript.push_str(&l);
                        transcript.push('\n');
                        client.event(job_id, "worker.log", json!({"stream":"stderr","message":l})).await.ok();
                    }
                    None => err_done = true,
                },
            }
        }
        let status = child.wait().await?;
        Ok::<_, anyhow::Error>(status)
    };

    let status = match tokio::time::timeout(Duration::from_secs(timeout_secs), run).await {
        Ok(result) => result?,
        Err(_) => {
            // Timed out — kill and surface as a retryable failure.
            return Err(anyhow!("agent run exceeded {timeout_secs}s timeout"));
        }
    };

    // Upload the full transcript as an artifact regardless of exit status (a failed run's
    // transcript is exactly what you want to inspect).
    let artifact = client
        .artifact(job_id, "agent-transcript.txt", transcript.clone().into_bytes())
        .await
        .map(|meta| meta.get("id").and_then(Value::as_str).map(str::to_owned))
        .unwrap_or(None);

    let code = status.code();
    if status.success() {
        client
            .event(job_id, "worker.progress", json!({"percent":100,"message":"agent finished"}))
            .await
            .ok();
        Ok(json!({
            "ok": true,
            "exit_code": code,
            "transcript_artifact_id": artifact,
            "transcript_len": transcript.len(),
        }))
    } else {
        // Non-zero exit → let the completion path mark it retryable via the Err branch.
        Err(anyhow!(
            "agent exited with status {:?}",
            code
        ))
    }
}
