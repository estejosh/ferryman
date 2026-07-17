use orchestrator_worker_sdk::WorkerClient;
use serde_json::json;
use std::time::Duration;

#[tokio::main]
async fn main() -> anyhow::Result<()> {
    let client = WorkerClient::register(
        "http://127.0.0.1:8787".into(),
        "demo".into(),
        "demo-local-token".into(),
        vec!["mock".into()],
    )
    .await?;
    loop {
        if let Some(lease) = client.lease().await? {
            client
                .event(
                    &lease.job.id,
                    "worker.progress",
                    json!({"percent":50,"message":"mock worker processing"}),
                )
                .await?;
            client
                .complete(
                    &lease.job.id,
                    &lease.lease_id,
                    json!({"echo":lease.job.input,"worker":"mock"}),
                    false,
                )
                .await?;
        } else {
            tokio::time::sleep(Duration::from_secs(1)).await;
        }
    }
}
