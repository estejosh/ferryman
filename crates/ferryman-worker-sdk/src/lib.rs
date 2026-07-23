#![forbid(unsafe_code)]
use anyhow::Result;
use ferryman_core::Lease;
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
        let worker_id = body["worker"]["id"]
            .as_str()
            .ok_or_else(|| anyhow::anyhow!("bridge worker response lacked id"))?
            .to_string();
        Ok(Self {
            endpoint,
            project,
            token: body["worker_token"]
                .as_str()
                .ok_or_else(|| {
                    anyhow::anyhow!("bridge worker response lacked short-lived worker token")
                })?
                .to_string(),
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
            .json(&json!({"worker_id":self.worker_id,"kind":kind,"payload":payload}))
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
            .json(&json!({"worker_id":self.worker_id,"lease_id":lease_id,"result":result,"retryable":retryable}))
            .send()
            .await?
            .error_for_status()?;
        Ok(())
    }

    /// Upload an artifact body for a job and return the stored artifact metadata (the
    /// bridge identifies artifacts by sha256 digest, not a name). Wraps
    /// `POST /v1/projects/{project}/jobs/{job_id}/artifacts` (octet-stream), which the
    /// worker protocol exposes but the SDK did not previously wrap. The `_name` is kept
    /// for caller ergonomics/logging; the server does not consume it.
    ///
    /// Note the worker id goes in the `x-ferryman-worker-id` header here, unlike
    /// `event`/`complete` which carry it in the JSON body — that asymmetry is the
    /// server's contract, not a bug in this wrapper.
    pub async fn artifact(&self, job_id: &str, _name: &str, bytes: Vec<u8>) -> Result<Value> {
        let response = self
            .client
            .post(format!(
                "{}/v1/projects/{}/jobs/{job_id}/artifacts",
                self.endpoint, self.project
            ))
            .bearer_auth(&self.token)
            .header("x-ferryman-worker-id", &self.worker_id)
            .header("content-type", "application/octet-stream")
            .body(bytes)
            .send()
            .await?
            .error_for_status()?;
        Ok(response.json().await?)
    }
}
