#![forbid(unsafe_code)]
use anyhow::Result;
use orchestrator_core::Lease;
use serde_json::{Value, json};

/// Minimal HTTP worker client. Keep the execution loop in the integrator's worker process.
pub struct WorkerClient {
    endpoint: String,
    project: String,
    token: String,
    worker_id: String,
    client: reqwest::Client,
}
impl WorkerClient {
    pub async fn register(
        endpoint: String,
        project: String,
        token: String,
        capabilities: Vec<String>,
    ) -> Result<Self> {
        let client = reqwest::Client::new();
        let response = client
            .post(format!("{endpoint}/v1/projects/{project}/workers"))
            .bearer_auth(&token)
            .json(&json!({"capabilities":capabilities}))
            .send()
            .await?
            .error_for_status()?;
        let body: Value = response.json().await?;
        let worker_id = body["id"]
            .as_str()
            .ok_or_else(|| anyhow::anyhow!("bridge worker response lacked id"))?
            .to_string();
        Ok(Self {
            endpoint,
            project,
            token,
            worker_id,
            client,
        })
    }
    pub async fn lease(&self) -> Result<Option<Lease>> {
        let response = self
            .client
            .post(format!(
                "{}/v1/projects/{}/workers/{}/lease",
                self.endpoint, self.project, self.worker_id
            ))
            .bearer_auth(&self.token)
            .send()
            .await?;
        if response.status() == reqwest::StatusCode::NO_CONTENT {
            return Ok(None);
        };
        Ok(Some(response.error_for_status()?.json().await?))
    }
    pub async fn event(&self, job_id: &str, kind: &str, payload: Value) -> Result<()> {
        self.client
            .post(format!(
                "{}/v1/projects/{}/jobs/{job_id}/events/log",
                self.endpoint, self.project
            ))
            .bearer_auth(&self.token)
            .json(&json!({"kind":kind,"payload":payload}))
            .send()
            .await?
            .error_for_status()?;
        Ok(())
    }
    pub async fn complete(
        &self,
        job_id: &str,
        lease_id: &str,
        result: Value,
        retryable: bool,
    ) -> Result<()> {
        self.client
            .post(format!(
                "{}/v1/projects/{}/jobs/{job_id}/complete",
                self.endpoint, self.project
            ))
            .bearer_auth(&self.token)
            .json(&json!({"lease_id":lease_id,"result":result,"retryable":retryable}))
            .send()
            .await?
            .error_for_status()?;
        Ok(())
    }
}
