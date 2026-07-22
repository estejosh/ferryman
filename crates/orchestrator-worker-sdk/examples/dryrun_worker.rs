//! Throwaway worker for the Telegram approval-gate dry-run acceptance test.
//!
//! Point this at a disposable project (NOT `hone`) whose jobs all `require_approval`.
//! When a job is approved (via `/approve_<id>` on Telegram, or the CLI/API directly)
//! this worker leases it, writes a harmless `dryrun-approved-<job_id>.txt` file so the
//! approval is trivially observable, records a `dryrun.approved` event, and completes
//! the job. Denied jobs are never leased, so nothing is written for them. Deleting the
//! output file fully reverses the only side effect this worker has.
//!
//! Env vars: `ORCHESTRATOR_ENDPOINT` (default `http://127.0.0.1:8787`),
//! `DRYRUN_PROJECT` (default `telegram-dryrun`), `DRYRUN_TOKEN` (required — that
//! project's token, not any real operator/approval credential), `DRYRUN_OUT_DIR`
//! (default `.`).

use orchestrator_worker_sdk::WorkerClient;
use serde_json::json;
use std::time::Duration;

#[tokio::main]
async fn main() -> anyhow::Result<()> {
    let endpoint =
        std::env::var("ORCHESTRATOR_ENDPOINT").unwrap_or_else(|_| "http://127.0.0.1:8787".into());
    let project = std::env::var("DRYRUN_PROJECT").unwrap_or_else(|_| "telegram-dryrun".into());
    let token = std::env::var("DRYRUN_TOKEN").map_err(|_| {
        anyhow::anyhow!("DRYRUN_TOKEN must be set to the throwaway project's own token")
    })?;
    let out_dir = std::env::var("DRYRUN_OUT_DIR").unwrap_or_else(|_| ".".into());

    let client = WorkerClient::register(endpoint, project, token, vec!["dryrun".into()]).await?;
    println!("dryrun worker registered; waiting for approved throwaway jobs...");
    loop {
        let Some(lease) = client.lease().await? else {
            tokio::time::sleep(Duration::from_secs(1)).await;
            continue;
        };
        let job_id = lease.job.id.clone();
        let path = std::path::Path::new(&out_dir).join(format!("dryrun-approved-{job_id}.txt"));
        tokio::fs::write(
            &path,
            format!("Telegram approval gate dry run: job {job_id} was approved and executed.\n"),
        )
        .await?;
        client
            .event(
                &job_id,
                "dryrun.approved",
                json!({"path": path.to_string_lossy()}),
            )
            .await?;
        client
            .complete(
                &job_id,
                &lease.lease_id,
                json!({"wrote": path.to_string_lossy()}),
                false,
            )
            .await?;
        println!("dry-run job {job_id} approved -> wrote {}", path.display());
    }
}
