#![forbid(unsafe_code)]
pub mod continuity;
pub mod recovery_targets;
pub mod telegram;
pub mod workspace;

use std::{convert::Infallible, path::PathBuf, sync::Arc, time::Duration};

use anyhow::Result;
use async_stream::stream;
use axum::{
    Json, Router,
    body::Bytes,
    extract::{Path, State},
    http::{HeaderMap, StatusCode, header::HeaderName},
    response::{
        IntoResponse, Response,
        sse::{Event as SseEvent, KeepAlive, Sse},
    },
    routing::{get, post},
};
use orchestrator_core::{
    Agent, AgentPersistence, Artifact, JobStatus, NewJob, PolicyEnvelope, Project,
    ProjectMemoryEntry, SqliteStore,
};
use serde::{Deserialize, Serialize};
use serde_json::{Value, json};
use tokio::{fs, io::AsyncWriteExt, time};
use tower_http::{
    request_id::{MakeRequestUuid, PropagateRequestIdLayer, SetRequestIdLayer},
    trace::TraceLayer,
};

#[derive(Clone)]
pub struct AppState {
    pub store: SqliteStore,
    pub artifact_root: Arc<PathBuf>,
    admin_token: Option<Arc<String>>,
    workspace_root: Arc<PathBuf>,
    memory_root: Arc<PathBuf>,
    memory_write_token: Option<Arc<String>>,
    max_artifact_bytes: u64,
    pub recovery_root: Arc<PathBuf>,
    git_recovery: Option<Arc<recovery_targets::GitRecoveryTarget>>,
    recovery_key: Option<Arc<[u8; 32]>>,
    recovery_key_reference: Arc<String>,
}
impl AppState {
    pub fn new(store: SqliteStore, artifact_root: PathBuf) -> Self {
        Self {
            store,
            artifact_root: Arc::new(artifact_root),
            admin_token: None,
            workspace_root: Arc::new(PathBuf::from("./.data/projects")),
            memory_root: Arc::new(PathBuf::from("./.data/bridge-memory")),
            memory_write_token: None,
            max_artifact_bytes: 100 * 1024 * 1024,
            recovery_root: Arc::new(PathBuf::from("./.data/recovery")),
            git_recovery: None,
            recovery_key: None,
            recovery_key_reference: Arc::new("unconfigured".into()),
        }
    }
    pub fn with_admin_token(mut self, admin_token: String) -> Self {
        self.admin_token = Some(Arc::new(admin_token));
        self
    }
    pub fn with_workspace_root(mut self, workspace_root: PathBuf) -> Self {
        self.workspace_root = Arc::new(workspace_root);
        self
    }
    pub fn with_memory_root(mut self, memory_root: PathBuf) -> Self {
        self.memory_root = Arc::new(memory_root);
        self
    }
    pub fn with_memory_write_token(mut self, memory_write_token: String) -> Self {
        self.memory_write_token = Some(Arc::new(memory_write_token));
        self
    }
    pub fn with_max_artifact_bytes(mut self, max_artifact_bytes: u64) -> Self {
        self.max_artifact_bytes = max_artifact_bytes;
        self
    }
    pub fn with_recovery_key(
        mut self,
        recovery_root: PathBuf,
        reference: String,
        key: [u8; 32],
    ) -> Self {
        self.recovery_root = Arc::new(recovery_root);
        self.recovery_key = Some(Arc::new(key));
        self.recovery_key_reference = Arc::new(reference);
        self
    }
    pub fn recovery_key(&self) -> Result<[u8; 32]> {
        self.recovery_key
            .as_ref()
            .map(|key| **key)
            .ok_or_else(|| anyhow::anyhow!("recovery encryption key is not configured"))
    }
    pub fn recovery_key_reference(&self) -> &str {
        self.recovery_key_reference.as_ref()
    }
    pub fn with_git_recovery(mut self, repository: String, branch: String) -> Self {
        self.git_recovery = Some(Arc::new(recovery_targets::GitRecoveryTarget {
            repository,
            branch,
            work_root: self.recovery_root.join("git-delivery"),
        }));
        self
    }
    pub fn git_recovery(&self) -> Option<Arc<recovery_targets::GitRecoveryTarget>> {
        self.git_recovery.clone()
    }
}

pub fn app(state: AppState) -> Router {
    Router::new()
        .route("/healthz", get(health))
        .route("/v1/metrics", get(metrics))
        .route("/v1/projects", post(create_project))
        .route(
            "/v1/projects/{project_id}/agents",
            post(create_agent).get(list_agents),
        )
        .route(
            "/v1/projects/{project_id}/memory",
            post(record_memory).get(list_memory),
        )
        .route(
            "/v1/projects/{project_id}/memory/candidates",
            get(list_memory_candidates),
        )
        .route(
            "/v1/projects/{project_id}/memory/candidates/{candidate_id}/approve",
            post(approve_memory_candidate),
        )
        .route(
            "/v1/projects/{project_id}/consents",
            post(create_consent).get(list_consents),
        )
        .route(
            "/v1/projects/{project_id}/consents/{consent_id}/approve",
            post(approve_consent),
        )
        .route(
            "/v1/projects/{project_id}/consents/{consent_id}/reject",
            post(reject_consent),
        )
        .route(
            "/v1/projects/{project_id}/outbound-submissions",
            post(propose_outbound_submission),
        )
        .route(
            "/v1/projects/{project_id}/improvement-proposals",
            post(propose_improvement),
        )
        .route(
            "/v1/projects/{project_id}/continuity-pack",
            get(continuity_pack),
        )
        .route(
            "/v1/projects/{project_id}/continuity-packs",
            post(create_continuity_pack),
        )
        .route(
            "/v1/projects/{project_id}/continuity-packs/{pack_hash}/recover",
            post(recover_continuity_pack),
        )
        .route(
            "/v1/projects/{project_id}/continuity-packs/{pack_hash}/delivery-consents",
            post(create_recovery_delivery_consent),
        )
        .route(
            "/v1/projects/{project_id}/continuity-packs/{pack_hash}/deliver",
            post(deliver_recovery_pack),
        )
        .route(
            "/v1/projects/{project_id}/recovery-drill",
            post(run_recovery_drill),
        )
        .route("/v1/projects/{project_id}/timeline", get(timeline))
        .route(
            "/v1/projects/{project_id}/policy/simulate",
            post(simulate_policy),
        )
        .route(
            "/v1/projects/{project_id}/jobs",
            post(submit_job).get(list_jobs),
        )
        .route("/v1/projects/{project_id}/jobs/{job_id}", get(get_job))
        .route(
            "/v1/projects/{project_id}/jobs/{job_id}/approve",
            post(approve_job),
        )
        .route(
            "/v1/projects/{project_id}/jobs/{job_id}/cancel",
            post(cancel_job),
        )
        .route(
            "/v1/projects/{project_id}/jobs/{job_id}/events",
            get(job_events),
        )
        .route(
            "/v1/projects/{project_id}/jobs/{job_id}/artifacts",
            post(upload_artifact).get(list_artifacts),
        )
        .route(
            "/v1/projects/{project_id}/jobs/{job_id}/artifact-bypass/approve",
            post(approve_artifact_bypass),
        )
        .route(
            "/v1/projects/{project_id}/artifacts/{artifact_id}",
            get(get_artifact),
        )
        .route(
            "/v1/projects/{project_id}/artifacts/{artifact_id}/content",
            get(download_artifact),
        )
        .route("/v1/projects/{project_id}/workers", post(register_worker))
        .route(
            "/v1/projects/{project_id}/workers/{worker_id}/heartbeat",
            post(heartbeat),
        )
        .route(
            "/v1/projects/{project_id}/workers/{worker_id}/lease",
            post(lease_job),
        )
        .route(
            "/v1/projects/{project_id}/jobs/{job_id}/events/log",
            post(worker_event),
        )
        .route(
            "/v1/projects/{project_id}/jobs/{job_id}/complete",
            post(complete_job),
        )
        .layer(PropagateRequestIdLayer::new(HeaderName::from_static(
            "x-request-id",
        )))
        .layer(SetRequestIdLayer::new(
            HeaderName::from_static("x-request-id"),
            MakeRequestUuid,
        ))
        .layer(TraceLayer::new_for_http())
        .with_state(state)
}

#[derive(Serialize)]
struct ErrorBody {
    code: &'static str,
    message: String,
}
struct ApiError(StatusCode, &'static str, String);
impl ApiError {
    fn bad(message: impl Into<String>) -> Self {
        Self(StatusCode::BAD_REQUEST, "bad_request", message.into())
    }
    fn unauthenticated() -> Self {
        Self(
            StatusCode::UNAUTHORIZED,
            "unauthenticated",
            "missing or invalid project token".into(),
        )
    }
    fn not_found() -> Self {
        Self(
            StatusCode::NOT_FOUND,
            "not_found",
            "resource not found or not in the required state".into(),
        )
    }
    fn internal(error: anyhow::Error) -> Self {
        Self(
            StatusCode::INTERNAL_SERVER_ERROR,
            "internal",
            error.to_string(),
        )
    }
}
impl IntoResponse for ApiError {
    fn into_response(self) -> Response {
        (
            self.0,
            Json(ErrorBody {
                code: self.1,
                message: self.2,
            }),
        )
            .into_response()
    }
}
type ApiResult<T> = std::result::Result<T, ApiError>;
fn checked(state: &AppState, headers: &HeaderMap, project: &str) -> ApiResult<()> {
    let token = headers
        .get("authorization")
        .and_then(|h| h.to_str().ok())
        .and_then(|h| h.strip_prefix("Bearer "))
        .ok_or_else(ApiError::unauthenticated)?;
    if state
        .store
        .authenticate(project, token)
        .map_err(ApiError::internal)?
    {
        Ok(())
    } else {
        Err(ApiError::unauthenticated())
    }
}
fn checked_admin(state: &AppState, headers: &HeaderMap) -> ApiResult<()> {
    let Some(expected) = &state.admin_token else {
        return Ok(());
    };
    let supplied = headers
        .get("authorization")
        .and_then(|header| header.to_str().ok())
        .and_then(|header| header.strip_prefix("Bearer "));
    if supplied == Some(expected.as_str()) {
        Ok(())
    } else {
        Err(ApiError::unauthenticated())
    }
}
fn checked_memory_write(state: &AppState, headers: &HeaderMap, project: &str) -> ApiResult<()> {
    checked(state, headers, project)?;
    let Some(expected) = &state.memory_write_token else {
        return Ok(());
    };
    let supplied = headers
        .get("x-orchestrator-memory-token")
        .and_then(|header| header.to_str().ok());
    if supplied == Some(expected.as_str()) {
        Ok(())
    } else {
        Err(ApiError::unauthenticated())
    }
}
fn checked_worker(
    state: &AppState,
    headers: &HeaderMap,
    project: &str,
    worker: &str,
) -> ApiResult<()> {
    let token = headers
        .get("authorization")
        .and_then(|header| header.to_str().ok())
        .and_then(|header| header.strip_prefix("Bearer "))
        .ok_or_else(ApiError::unauthenticated)?;
    if state
        .store
        .authenticate_worker(project, worker, token)
        .map_err(ApiError::internal)?
    {
        Ok(())
    } else {
        Err(ApiError::unauthenticated())
    }
}

async fn health() -> Json<Value> {
    Json(json!({"status":"ok","api_version":"v1"}))
}
async fn metrics(State(state): State<AppState>) -> ApiResult<Json<Value>> {
    let (queue_depth, healthy_workers) = state.store.metrics().map_err(ApiError::internal)?;
    Ok(Json(
        json!({"queue_depth":queue_depth,"healthy_workers":healthy_workers}),
    ))
}
#[derive(Deserialize)]
struct CreateProject {
    id: String,
    name: String,
    token: String,
}
async fn create_project(
    State(state): State<AppState>,
    headers: HeaderMap,
    Json(input): Json<CreateProject>,
) -> ApiResult<(StatusCode, Json<Project>)> {
    checked_admin(&state, &headers)?;
    if input.id.is_empty() || input.token.len() < 12 {
        return Err(ApiError::bad(
            "id is required and token must contain at least 12 characters",
        ));
    };
    let workspace_path =
        workspace::provision_private_repository(&state.workspace_root, &input.id, &input.name)
            .map_err(ApiError::internal)?;
    let project = state
        .store
        .create_project(
            &input.id,
            &input.name,
            &input.token,
            &workspace_path.to_string_lossy(),
        )
        .map_err(ApiError::internal)?;
    Ok((StatusCode::CREATED, Json(project)))
}
#[derive(Deserialize)]
struct CreateAgent {
    role: String,
    description: String,
    persistence: AgentPersistence,
}
async fn create_agent(
    State(state): State<AppState>,
    headers: HeaderMap,
    Path(project_id): Path<String>,
    Json(input): Json<CreateAgent>,
) -> ApiResult<(StatusCode, Json<Agent>)> {
    checked(&state, &headers, &project_id)?;
    if input.role.trim().is_empty() || input.description.trim().is_empty() {
        return Err(ApiError::bad("role and description are required"));
    }
    let project = state
        .store
        .get_project(&project_id)
        .map_err(ApiError::internal)?
        .ok_or_else(ApiError::not_found)?;
    let (name, path) = workspace::write_agent_profile(
        &project,
        &input.role,
        &input.description,
        &input.persistence,
    )
    .map_err(ApiError::internal)?;
    let agent = state
        .store
        .ensure_agent(Agent {
            id: uuid::Uuid::new_v4().to_string(),
            project_id,
            name,
            role: input.role,
            description: input.description,
            persistence: input.persistence,
            profile_path: path.to_string_lossy().into(),
            created_at: chrono::Utc::now().to_rfc3339(),
        })
        .map_err(ApiError::internal)?;
    Ok((StatusCode::CREATED, Json(agent)))
}
async fn list_agents(
    State(state): State<AppState>,
    headers: HeaderMap,
    Path(project_id): Path<String>,
) -> ApiResult<Json<Value>> {
    checked(&state, &headers, &project_id)?;
    let items = state
        .store
        .list_agents(&project_id)
        .map_err(ApiError::internal)?;
    Ok(Json(json!({"items":items})))
}
#[derive(Deserialize)]
struct RecordMemory {
    category: String,
    content: String,
    source: Option<String>,
}
async fn record_memory(
    State(state): State<AppState>,
    headers: HeaderMap,
    Path(project_id): Path<String>,
    Json(input): Json<RecordMemory>,
) -> ApiResult<(StatusCode, Json<ProjectMemoryEntry>)> {
    checked_memory_write(&state, &headers, &project_id)?;
    if input.category.trim().is_empty()
        || input.content.trim().is_empty()
        || input.content.len() > 32_000
    {
        return Err(ApiError::bad(
            "category and non-empty content up to 32,000 bytes are required",
        ));
    }
    let entry = state
        .store
        .record_memory(
            &project_id,
            &input.category,
            &input.content,
            input.source.as_deref().unwrap_or("operator"),
        )
        .map_err(ApiError::internal)?;
    append_memory_mirror(&state.memory_root, &project_id, &entry)
        .await
        .map_err(ApiError::internal)?;
    Ok((StatusCode::CREATED, Json(entry)))
}
#[derive(Deserialize)]
struct MemoryQuery {
    limit: Option<u32>,
}
async fn list_memory(
    State(state): State<AppState>,
    headers: HeaderMap,
    Path(project_id): Path<String>,
    axum::extract::Query(query): axum::extract::Query<MemoryQuery>,
) -> ApiResult<Json<Value>> {
    checked(&state, &headers, &project_id)?;
    let items = state
        .store
        .project_memory(&project_id, query.limit.unwrap_or(100))
        .map_err(ApiError::internal)?;
    Ok(Json(json!({"items":items})))
}
async fn list_memory_candidates(
    State(state): State<AppState>,
    headers: HeaderMap,
    Path(project): Path<String>,
) -> ApiResult<Json<Value>> {
    checked(&state, &headers, &project)?;
    Ok(Json(
        json!({"items":state.store.list_memory_candidates(&project).map_err(ApiError::internal)?}),
    ))
}
async fn approve_memory_candidate(
    State(state): State<AppState>,
    headers: HeaderMap,
    Path((project, candidate)): Path<(String, String)>,
) -> ApiResult<Json<ProjectMemoryEntry>> {
    checked_memory_write(&state, &headers, &project)?;
    let entry = state
        .store
        .approve_memory_candidate(&project, &candidate)
        .map_err(ApiError::internal)?
        .ok_or_else(ApiError::not_found)?;
    append_memory_mirror(&state.memory_root, &project, &entry)
        .await
        .map_err(ApiError::internal)?;
    Ok(Json(entry))
}
#[derive(Deserialize)]
struct NewConsent {
    kind: String,
    #[serde(default)]
    payload: Value,
    /// RFC 3339 expiry; an expired manifest cannot be approved or executed.
    expires_at: Option<String>,
}
async fn create_consent(
    State(state): State<AppState>,
    headers: HeaderMap,
    Path(project): Path<String>,
    Json(body): Json<NewConsent>,
) -> ApiResult<(StatusCode, Json<Value>)> {
    checked(&state, &headers, &project)?;
    if body.kind.trim().is_empty() {
        return Err(ApiError::bad("consent kind is required"));
    };
    if let Some(expiry) = &body.expires_at {
        chrono::DateTime::parse_from_rfc3339(expiry)
            .map_err(|_| ApiError::bad("expires_at must be RFC 3339"))?;
    }
    let request = state
        .store
        .create_consent(
            &project,
            &body.kind,
            body.payload,
            body.expires_at.as_deref(),
        )
        .map_err(ApiError::internal)?;
    Ok((StatusCode::CREATED, Json(json!(request))))
}
async fn list_consents(
    State(state): State<AppState>,
    headers: HeaderMap,
    Path(project): Path<String>,
) -> ApiResult<Json<Value>> {
    checked(&state, &headers, &project)?;
    Ok(Json(
        json!({"items":state.store.list_consents(&project).map_err(ApiError::internal)?}),
    ))
}
async fn approve_consent(
    State(state): State<AppState>,
    headers: HeaderMap,
    Path((project, id)): Path<(String, String)>,
) -> ApiResult<Json<Value>> {
    checked(&state, &headers, &project)?;
    let approver = headers
        .get("x-orchestrator-approver")
        .and_then(|value| value.to_str().ok())
        .filter(|value| !value.trim().is_empty())
        .ok_or_else(|| ApiError::bad("x-orchestrator-approver is required"))?;
    state
        .store
        .resolve_consent(&project, &id, true, approver)
        .map_err(ApiError::internal)?
        .map(|request| Json(json!(request)))
        .ok_or_else(ApiError::not_found)
}
async fn reject_consent(
    State(state): State<AppState>,
    headers: HeaderMap,
    Path((project, id)): Path<(String, String)>,
) -> ApiResult<Json<Value>> {
    checked(&state, &headers, &project)?;
    let approver = headers
        .get("x-orchestrator-approver")
        .and_then(|value| value.to_str().ok())
        .filter(|value| !value.trim().is_empty())
        .ok_or_else(|| ApiError::bad("x-orchestrator-approver is required"))?;
    state
        .store
        .resolve_consent(&project, &id, false, approver)
        .map_err(ApiError::internal)?
        .map(|request| Json(json!(request)))
        .ok_or_else(ApiError::not_found)
}
#[derive(Deserialize)]
struct OutboundProposal {
    provider: String,
    destination: String,
    #[serde(default)]
    files: Vec<Value>,
    #[serde(default)]
    patch: Option<String>,
    #[serde(default)]
    redactions: Vec<String>,
    reason: String,
    #[serde(default)]
    evidence_links: Vec<String>,
    #[serde(default)]
    expected_benefit: String,
    #[serde(default)]
    risk: String,
    #[serde(default)]
    rollback: String,
    expires_at: Option<String>,
}
async fn propose_outbound_submission(
    State(state): State<AppState>,
    headers: HeaderMap,
    Path(project): Path<String>,
    Json(body): Json<OutboundProposal>,
) -> ApiResult<(StatusCode, Json<Value>)> {
    checked(&state, &headers, &project)?;
    if !matches!(
        body.provider.as_str(),
        "github" | "google_drive" | "mega" | "private_git"
    ) || body.destination.trim().is_empty()
        || body.reason.trim().is_empty()
    {
        return Err(ApiError::bad(
            "provider, destination, and reason are required; provider must be github, google_drive, mega, or private_git",
        ));
    }
    if let Some(expiry) = &body.expires_at {
        chrono::DateTime::parse_from_rfc3339(expiry)
            .map_err(|_| ApiError::bad("expires_at must be RFC 3339"))?;
    }
    let manifest = json!({"format":"orchestrator-bridge-outbound-manifest/v1","provider":body.provider,"destination":body.destination,"files":body.files,"patch":body.patch,"redactions":body.redactions,"reason":body.reason,"evidence_links":body.evidence_links,"expected_benefit":body.expected_benefit,"risk":body.risk,"rollback":body.rollback,"delivery":"draft_pr_only_or_opaque_encrypted_blob"});
    let consent = state
        .store
        .create_consent(
            &project,
            "outbound_submission",
            manifest,
            body.expires_at.as_deref(),
        )
        .map_err(ApiError::internal)?;
    Ok((
        StatusCode::CREATED,
        Json(
            json!({"status":"pending_consent","submission_manifest":consent.payload,"manifest_hash":consent.manifest_hash,"consent":consent,"delivery_performed":false}),
        ),
    ))
}
#[derive(Deserialize)]
struct ImprovementProposal {
    reason: String,
    #[serde(default)]
    evidence_links: Vec<String>,
    #[serde(default)]
    proposed_patch: String,
    #[serde(default)]
    risk: String,
}
async fn propose_improvement(
    State(state): State<AppState>,
    headers: HeaderMap,
    Path(project): Path<String>,
    Json(body): Json<ImprovementProposal>,
) -> ApiResult<(StatusCode, Json<Value>)> {
    checked(&state, &headers, &project)?;
    if body.reason.trim().is_empty() {
        return Err(ApiError::bad("reason is required"));
    }
    let proposal = json!({"format":"orchestrator-bridge-improvement-proposal/v1","reason":body.reason,"evidence_links":body.evidence_links,"proposed_patch":body.proposed_patch,"risk":body.risk,"source":"operator_or_readiness_evidence","autonomous_write":false});
    let consent = state
        .store
        .create_consent(&project, "improvement_proposal", proposal, None)
        .map_err(ApiError::internal)?;
    Ok((
        StatusCode::CREATED,
        Json(
            json!({"status":"proposal_only","manifest_hash":consent.manifest_hash,"consent":consent,"source_project_modified":false,"external_delivery_performed":false}),
        ),
    ))
}
async fn continuity_pack(
    State(state): State<AppState>,
    headers: HeaderMap,
    Path(project): Path<String>,
) -> ApiResult<Json<Value>> {
    checked(&state, &headers, &project)?;
    let project_record = state
        .store
        .get_project(&project)
        .map_err(ApiError::internal)?
        .ok_or_else(ApiError::not_found)?;
    let jobs=state.store.list_jobs(&project,500,None,None).map_err(ApiError::internal)?.into_iter().map(|job|json!({"id":job.id,"status":job.status,"attempts":job.attempts,"max_attempts":job.max_attempts,"created_at":job.created_at,"updated_at":job.updated_at})).collect::<Vec<_>>();
    Ok(Json(
        json!({"format":"orchestrator-bridge-continuity-pack/v1","generated_at":chrono::Utc::now().to_rfc3339(),"project":project_record,"memory":state.store.project_memory(&project,500).map_err(ApiError::internal)?,"memory_candidates":state.store.list_memory_candidates(&project).map_err(ApiError::internal)?,"agents":state.store.list_agents(&project).map_err(ApiError::internal)?,"consents":state.store.list_consents(&project).map_err(ApiError::internal)?,"jobs":jobs}),
    ))
}
async fn create_continuity_pack(
    State(state): State<AppState>,
    headers: HeaderMap,
    Path(project): Path<String>,
) -> ApiResult<(StatusCode, Json<Value>)> {
    checked(&state, &headers, &project)?;
    let result = continuity::build_pack(&state, &project)
        .await
        .map_err(ApiError::internal)?;
    Ok((StatusCode::CREATED, Json(json!(result))))
}
async fn recover_continuity_pack(
    State(state): State<AppState>,
    headers: HeaderMap,
    Path((project, pack_hash)): Path<(String, String)>,
) -> ApiResult<Json<Value>> {
    checked(&state, &headers, &project)?;
    Ok(Json(json!(
        continuity::verify_and_recover(&state, &project, &pack_hash)
            .await
            .map_err(ApiError::internal)?
    )))
}
#[derive(Deserialize)]
struct RecoveryDelivery {
    target: String,
    expires_at: Option<String>,
}
async fn create_recovery_delivery_consent(
    State(state): State<AppState>,
    headers: HeaderMap,
    Path((project, pack_hash)): Path<(String, String)>,
    Json(body): Json<RecoveryDelivery>,
) -> ApiResult<(StatusCode, Json<Value>)> {
    checked(&state, &headers, &project)?;
    if body.target != "private_git" {
        return Err(ApiError::bad(
            "only private_git is configured in this build; Drive and MEGA remain disabled until configured",
        ));
    }
    if let Some(expiry) = &body.expires_at {
        chrono::DateTime::parse_from_rfc3339(expiry)
            .map_err(|_| ApiError::bad("expires_at must be RFC 3339"))?;
    }
    let target = state
        .git_recovery()
        .ok_or_else(|| ApiError::bad("private Git recovery is not configured"))?;
    let manifest = continuity::load_manifest(&state, &project, &pack_hash)
        .await
        .map_err(ApiError::internal)?;
    let payload = json!({"format":"orchestrator-bridge-recovery-delivery/v1","provider":"private_git","bundle_sha256":manifest.bundle_sha256,"manifest_hmac_sha256":manifest.manifest_hmac_sha256,"repository":target.repository,"branch":target.branch});
    let consent = state
        .store
        .create_consent(
            &project,
            "recovery_upload",
            payload,
            body.expires_at.as_deref(),
        )
        .map_err(ApiError::internal)?;
    Ok((StatusCode::CREATED, Json(json!(consent))))
}
#[derive(Deserialize)]
struct DeliverRecovery {
    consent_id: String,
}
async fn deliver_recovery_pack(
    State(state): State<AppState>,
    headers: HeaderMap,
    Path((project, pack_hash)): Path<(String, String)>,
    Json(body): Json<DeliverRecovery>,
) -> ApiResult<Json<Value>> {
    checked(&state, &headers, &project)?;
    let consent = state
        .store
        .list_consents(&project)
        .map_err(ApiError::internal)?
        .into_iter()
        .find(|item| {
            item.id == body.consent_id
                && item.status == "approved"
                && item.kind == "recovery_upload"
                && item.payload.get("bundle_sha256").and_then(Value::as_str)
                    == Some(pack_hash.as_str())
        })
        .ok_or_else(ApiError::not_found)?;
    let target = state
        .git_recovery()
        .ok_or_else(|| ApiError::bad("private Git recovery is not configured"))?;
    if consent.payload.get("repository").and_then(Value::as_str) != Some(target.repository.as_str())
        || consent.payload.get("branch").and_then(Value::as_str) != Some(target.branch.as_str())
    {
        return Err(ApiError::bad(
            "configured Git recovery target differs from the approved delivery manifest",
        ));
    }
    let receipt = continuity::deliver_to_git(&state, &project, &pack_hash, target.as_ref())
        .await
        .map_err(ApiError::internal)?;
    state.store.append_project_event(&project,"recovery.delivery_succeeded",json!({"consent_id":consent.id,"target":receipt.target,"remote_id":receipt.remote_id,"bundle_sha256":receipt.sha256})).map_err(ApiError::internal)?;
    Ok(Json(json!(receipt)))
}
async fn run_recovery_drill(
    State(state): State<AppState>,
    headers: HeaderMap,
    Path(project): Path<String>,
) -> ApiResult<Json<Value>> {
    checked(&state, &headers, &project)?;
    Ok(Json(
        continuity::recovery_drill(&state, &project)
            .await
            .map_err(ApiError::internal)?,
    ))
}
#[derive(Deserialize)]
struct TimelineQuery {
    after: Option<i64>,
    limit: Option<u32>,
    job_id: Option<String>,
    category: Option<String>,
}
async fn timeline(
    State(state): State<AppState>,
    headers: HeaderMap,
    Path(project): Path<String>,
    axum::extract::Query(query): axum::extract::Query<TimelineQuery>,
) -> ApiResult<Json<Value>> {
    checked(&state, &headers, &project)?;
    let items = state
        .store
        .timeline(
            &project,
            query.after.unwrap_or(0),
            query.limit.unwrap_or(100),
            query.job_id.as_deref(),
            query.category.as_deref(),
        )
        .map_err(ApiError::internal)?;
    Ok(Json(
        json!({"items":items,"next_cursor":items.last().map(|event|event.id)}),
    ))
}
#[derive(Deserialize)]
struct PolicySimulation {
    #[serde(default)]
    policy: PolicyEnvelope,
    #[serde(default)]
    artifact_bytes: u64,
    #[serde(default)]
    outbound: bool,
}
async fn simulate_policy(
    State(state): State<AppState>,
    headers: HeaderMap,
    Path(project): Path<String>,
    Json(input): Json<PolicySimulation>,
) -> ApiResult<Json<Value>> {
    checked(&state, &headers, &project)?;
    let mut allowed = Vec::new();
    let mut denied = Vec::new();
    let mut consents = Vec::new();
    for (name, access) in [
        ("filesystem", &input.policy.filesystem),
        ("network", &input.policy.network),
        ("shell", &input.policy.shell),
    ] {
        if matches!(access, orchestrator_core::Access::Deny) {
            denied.push(name);
        } else {
            allowed.push(name);
        }
    }
    if input.outbound || !matches!(input.policy.network, orchestrator_core::Access::Deny) {
        consents.push("external_communication");
    }
    if input.artifact_bytes > state.max_artifact_bytes {
        consents.push("artifact_quota_bypass");
    }
    if input.policy.budget_cents.is_some() {
        consents.push("money_budget_action");
    }
    Ok(Json(
        json!({"mutated":false,"allowed_capabilities":allowed,"denied_capabilities":denied,"required_consents":consents,"storage_destination":"local_disk","artifact_quota":state.max_artifact_bytes,"estimated_retained_data":input.artifact_bytes,"rules":["local-first storage","explicit consent for outbound/network","per-job artifact quota"]}),
    ))
}
async fn append_memory_mirror(
    root: &std::path::Path,
    project_id: &str,
    entry: &ProjectMemoryEntry,
) -> Result<()> {
    let directory = workspace::project_directory(root, project_id)?;
    fs::create_dir_all(&directory).await?;
    let mut file = fs::OpenOptions::new()
        .create(true)
        .append(true)
        .open(directory.join("MEMORY.md"))
        .await?;
    file.write_all(
        format!(
            "\n## {} · {}\n\n{}\n\n_Source: {} | Entry: {}_\n",
            entry.created_at, entry.category, entry.content, entry.source, entry.id
        )
        .as_bytes(),
    )
    .await?;
    Ok(())
}
#[derive(Deserialize)]
struct SubmitJob {
    input: Value,
    #[serde(default)]
    policy: PolicyEnvelope,
    #[serde(default)]
    requires_approval: bool,
    #[serde(default = "default_attempts")]
    max_attempts: u32,
    idempotency_key: Option<String>,
    #[serde(default)]
    approval_ttl_seconds: Option<i64>,
}
fn default_attempts() -> u32 {
    3
}
async fn submit_job(
    State(state): State<AppState>,
    headers: HeaderMap,
    Path(project): Path<String>,
    Json(input): Json<SubmitJob>,
) -> ApiResult<(StatusCode, Json<orchestrator_core::Job>)> {
    checked(&state, &headers, &project)?;
    let job = state
        .store
        .submit_job(
            &project,
            NewJob {
                input: input.input,
                policy: input.policy,
                requires_approval: input.requires_approval,
                max_attempts: input.max_attempts,
                idempotency_key: input.idempotency_key,
                approval_ttl_seconds: input.approval_ttl_seconds,
            },
        )
        .map_err(ApiError::internal)?;
    Ok((StatusCode::ACCEPTED, Json(job)))
}
#[derive(Deserialize)]
struct JobList {
    limit: Option<u32>,
    cursor: Option<String>,
    status: Option<JobStatus>,
}
async fn list_jobs(
    State(state): State<AppState>,
    headers: HeaderMap,
    Path(project): Path<String>,
    axum::extract::Query(query): axum::extract::Query<JobList>,
) -> ApiResult<Json<Value>> {
    checked(&state, &headers, &project)?;
    let jobs = state
        .store
        .list_jobs(
            &project,
            query.limit.unwrap_or(50),
            query.cursor.as_deref(),
            query.status.as_ref(),
        )
        .map_err(ApiError::internal)?;
    Ok(Json(
        json!({"items":jobs,"next_cursor":jobs.last().map(|j|j.id.clone())}),
    ))
}
async fn get_job(
    State(state): State<AppState>,
    headers: HeaderMap,
    Path((project, job)): Path<(String, String)>,
) -> ApiResult<Json<orchestrator_core::Job>> {
    checked(&state, &headers, &project)?;
    state
        .store
        .get_job(&project, &job)
        .map_err(ApiError::internal)?
        .map(Json)
        .ok_or_else(ApiError::not_found)
}
async fn approve_job(
    State(state): State<AppState>,
    headers: HeaderMap,
    Path((project, job)): Path<(String, String)>,
) -> ApiResult<Json<orchestrator_core::Job>> {
    checked(&state, &headers, &project)?;
    state
        .store
        .approve(&project, &job)
        .map_err(ApiError::internal)?
        .map(Json)
        .ok_or_else(ApiError::not_found)
}
async fn cancel_job(
    State(state): State<AppState>,
    headers: HeaderMap,
    Path((project, job)): Path<(String, String)>,
) -> ApiResult<Json<orchestrator_core::Job>> {
    checked(&state, &headers, &project)?;
    state
        .store
        .cancel(&project, &job)
        .map_err(ApiError::internal)?
        .map(Json)
        .ok_or_else(ApiError::not_found)
}
async fn job_events(
    State(state): State<AppState>,
    headers: HeaderMap,
    Path((project, job)): Path<(String, String)>,
) -> ApiResult<Sse<impl futures_util::Stream<Item = Result<SseEvent, Infallible>>>> {
    checked(&state, &headers, &project)?;
    let output = stream! {let mut after=0;let mut interval=time::interval(Duration::from_millis(400));loop{interval.tick().await;match state.store.events(&project,&job,after){Ok(events)=>for event in events{after=event.id;let data=serde_json::to_string(&event).unwrap_or_else(|_|"{}".into());yield Ok(SseEvent::default().id(event.id.to_string()).event(event.kind).data(data));},Err(_)=>break}}};
    Ok(Sse::new(output).keep_alive(KeepAlive::default()))
}
#[derive(Deserialize)]
struct RegisterWorker {
    capabilities: Vec<String>,
}
async fn register_worker(
    State(state): State<AppState>,
    headers: HeaderMap,
    Path(project): Path<String>,
    Json(body): Json<RegisterWorker>,
) -> ApiResult<(StatusCode, Json<orchestrator_core::WorkerRegistration>)> {
    checked(&state, &headers, &project)?;
    Ok((
        StatusCode::CREATED,
        Json(
            state
                .store
                .register_worker(&project, body.capabilities)
                .map_err(ApiError::internal)?,
        ),
    ))
}
async fn heartbeat(
    State(state): State<AppState>,
    headers: HeaderMap,
    Path((project, worker)): Path<(String, String)>,
) -> ApiResult<StatusCode> {
    checked_worker(&state, &headers, &project, &worker)?;
    if state
        .store
        .heartbeat(
            &project,
            &worker,
            orchestrator_core::DEFAULT_LEASE_TTL_SECONDS,
        )
        .map_err(ApiError::internal)?
    {
        Ok(StatusCode::NO_CONTENT)
    } else {
        Err(ApiError::not_found())
    }
}
async fn lease_job(
    State(state): State<AppState>,
    headers: HeaderMap,
    Path((project, worker)): Path<(String, String)>,
) -> ApiResult<Response> {
    checked_worker(&state, &headers, &project, &worker)?;
    match state
        .store
        .lease(
            &project,
            &worker,
            orchestrator_core::DEFAULT_LEASE_TTL_SECONDS,
        )
        .map_err(ApiError::internal)?
    {
        Some(lease) => Ok((StatusCode::OK, Json(lease)).into_response()),
        None => Ok(StatusCode::NO_CONTENT.into_response()),
    }
}
#[derive(Deserialize)]
struct WorkerEvent {
    worker_id: String,
    kind: String,
    #[serde(default)]
    payload: Value,
}
async fn worker_event(
    State(state): State<AppState>,
    headers: HeaderMap,
    Path((project, job)): Path<(String, String)>,
    Json(body): Json<WorkerEvent>,
) -> ApiResult<StatusCode> {
    checked_worker(&state, &headers, &project, &body.worker_id)?;
    state
        .store
        .append_worker_event(&project, &job, &body.kind, body.payload)
        .map_err(ApiError::internal)?;
    Ok(StatusCode::ACCEPTED)
}
#[derive(Deserialize)]
struct Complete {
    worker_id: String,
    lease_id: String,
    result: Value,
    #[serde(default)]
    retryable: bool,
}
async fn complete_job(
    State(state): State<AppState>,
    headers: HeaderMap,
    Path((project, job)): Path<(String, String)>,
    Json(body): Json<Complete>,
) -> ApiResult<Json<orchestrator_core::Job>> {
    checked_worker(&state, &headers, &project, &body.worker_id)?;
    state
        .store
        .complete(&project, &job, &body.lease_id, body.result, body.retryable)
        .map_err(ApiError::internal)?
        .map(Json)
        .ok_or_else(ApiError::not_found)
}
async fn upload_artifact(
    State(state): State<AppState>,
    headers: HeaderMap,
    Path((project, job)): Path<(String, String)>,
    body: Bytes,
) -> ApiResult<(StatusCode, Json<Artifact>)> {
    let worker = headers
        .get("x-orchestrator-worker-id")
        .and_then(|value| value.to_str().ok())
        .ok_or_else(|| ApiError::bad("x-orchestrator-worker-id is required for artifact upload"))?;
    checked_worker(&state, &headers, &project, worker)?;
    if state
        .store
        .get_job(&project, &job)
        .map_err(ApiError::internal)?
        .is_none()
    {
        return Err(ApiError::not_found());
    };
    let approved_limit = state
        .store
        .artifact_bypass_limit(&project, &job)
        .map_err(ApiError::internal)?
        .unwrap_or(0);
    let allowed_limit = state.max_artifact_bytes.max(approved_limit);
    if body.len() as u64 > allowed_limit {
        state
            .store
            .append_worker_event(
                &project,
                &job,
                "artifact.quota_exceeded",
                json!({"requested_bytes":body.len(),"allowed_bytes":allowed_limit}),
            )
            .map_err(ApiError::internal)?;
        return Err(ApiError(
            StatusCode::PAYLOAD_TOO_LARGE,
            "artifact_quota_exceeded",
            format!(
                "artifact exceeds {allowed_limit} bytes; request an orchestrator approval at /v1/projects/{project}/jobs/{job}/artifact-bypass/approve"
            ),
        ));
    }
    let digest = sha256(&body);
    fs::create_dir_all(state.artifact_root.as_ref())
        .await
        .map_err(|e| ApiError::internal(e.into()))?;
    let path = state.artifact_root.join(&digest);
    if fs::metadata(&path).await.is_err() {
        fs::write(&path, &body)
            .await
            .map_err(|e| ApiError::internal(e.into()))?
    };
    let artifact = state
        .store
        .create_artifact(
            &project,
            &job,
            &digest,
            "application/octet-stream",
            body.len() as u64,
        )
        .map_err(ApiError::internal)?;
    // Artifacts are intentionally never mirrored as a side effect.  External
    // providers may receive only encrypted continuity packs through a consent-
    // bound recovery target, never raw job artifacts.
    Ok((StatusCode::CREATED, Json(artifact)))
}
#[derive(Deserialize)]
struct ArtifactBypass {
    max_bytes: u64,
}
async fn approve_artifact_bypass(
    State(state): State<AppState>,
    headers: HeaderMap,
    Path((project, job)): Path<(String, String)>,
    Json(body): Json<ArtifactBypass>,
) -> ApiResult<Json<Value>> {
    const MAX_BYPASS_BYTES: u64 = 4 * 1024 * 1024 * 1024;
    checked(&state, &headers, &project)?;
    if body.max_bytes <= state.max_artifact_bytes || body.max_bytes > MAX_BYPASS_BYTES {
        return Err(ApiError::bad(
            "max_bytes must exceed the default limit and not exceed 4 GiB",
        ));
    };
    if !state
        .store
        .approve_artifact_bypass(&project, &job, body.max_bytes)
        .map_err(ApiError::internal)?
    {
        return Err(ApiError::not_found());
    };
    state
        .store
        .append_worker_event(
            &project,
            &job,
            "artifact.bypass_approved",
            json!({"max_bytes":body.max_bytes}),
        )
        .map_err(ApiError::internal)?;
    Ok(Json(json!({"job_id":job,"max_bytes":body.max_bytes})))
}
async fn list_artifacts(
    State(state): State<AppState>,
    headers: HeaderMap,
    Path((project, job)): Path<(String, String)>,
) -> ApiResult<Json<Value>> {
    checked(&state, &headers, &project)?;
    let items = state
        .store
        .list_artifacts(&project, &job)
        .map_err(ApiError::internal)?;
    Ok(Json(json!({"items":items})))
}
async fn get_artifact(
    State(state): State<AppState>,
    headers: HeaderMap,
    Path((project, artifact_id)): Path<(String, String)>,
) -> ApiResult<Json<Artifact>> {
    checked(&state, &headers, &project)?;
    state
        .store
        .get_artifact(&project, &artifact_id)
        .map_err(ApiError::internal)?
        .map(Json)
        .ok_or_else(ApiError::not_found)
}
async fn download_artifact(
    State(state): State<AppState>,
    headers: HeaderMap,
    Path((project, artifact_id)): Path<(String, String)>,
) -> ApiResult<Response> {
    checked(&state, &headers, &project)?;
    let artifact = state
        .store
        .get_artifact(&project, &artifact_id)
        .map_err(ApiError::internal)?
        .ok_or_else(ApiError::not_found)?;
    let content = fs::read(state.artifact_root.join(&artifact.sha256))
        .await
        .map_err(|_| ApiError::not_found())?;
    Ok(([("content-type", artifact.content_type)], content).into_response())
}
fn sha256(body: &Bytes) -> String {
    use sha2::Digest;
    hex::encode(sha2::Sha256::digest(body))
}

#[cfg(test)]
mod tests {
    use super::*;
    use axum::{body::Body, http::Request};
    use http_body_util::BodyExt;
    use tower::ServiceExt;
    #[tokio::test]
    async fn http_server_isolates_projects_and_protects_recovery_memory() {
        let dir = std::env::temp_dir().join(format!("bridge-http-test-{}", uuid::Uuid::new_v4()));
        std::fs::create_dir_all(&dir).unwrap();
        let store = SqliteStore::open(dir.join("bridge.db")).unwrap();
        store
            .create_project("alpha", "Alpha", "alpha-token-1234", "")
            .unwrap();
        store
            .create_project("beta", "Beta", "beta-token-12345", "")
            .unwrap();
        let state = AppState::new(store, dir.join("artifacts"))
            .with_memory_root(dir.join("memory"))
            .with_memory_write_token("memory-token-1234".into());
        let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
        let address = listener.local_addr().unwrap();
        let (shutdown_sender, shutdown_receiver) = tokio::sync::oneshot::channel::<()>();
        tokio::spawn(async move {
            axum::serve(listener, app(state))
                .with_graceful_shutdown(async {
                    let _ = shutdown_receiver.await;
                })
                .await
                .unwrap();
        });
        let client = reqwest::Client::new();
        let job = client
            .post(format!("http://{address}/v1/projects/alpha/jobs"))
            .bearer_auth("alpha-token-1234")
            .json(&json!({"input":{"test":true}}))
            .send()
            .await
            .unwrap()
            .error_for_status()
            .unwrap()
            .json::<Value>()
            .await
            .unwrap();
        let job_id = job["id"].as_str().unwrap();
        let other_project = client
            .get(format!("http://{address}/v1/projects/alpha/jobs/{job_id}"))
            .bearer_auth("beta-token-12345")
            .send()
            .await
            .unwrap();
        assert_eq!(other_project.status(), StatusCode::UNAUTHORIZED);
        let denied_memory = client
            .post(format!("http://{address}/v1/projects/alpha/memory"))
            .bearer_auth("alpha-token-1234")
            .json(&json!({"category":"decision","content":"should be rejected"}))
            .send()
            .await
            .unwrap();
        assert_eq!(denied_memory.status(), StatusCode::UNAUTHORIZED);
        let accepted_memory = client
            .post(format!("http://{address}/v1/projects/alpha/memory"))
            .bearer_auth("alpha-token-1234")
            .header("x-orchestrator-memory-token", "memory-token-1234")
            .json(&json!({"category":"decision","content":"durable decision"}))
            .send()
            .await
            .unwrap();
        assert_eq!(accepted_memory.status(), StatusCode::CREATED);
        let _ = shutdown_sender.send(());
    }
    #[tokio::test]
    async fn approval_lease_retry_and_artifact_are_durable() {
        let dir = std::env::temp_dir().join(format!("bridge-test-{}", uuid::Uuid::new_v4()));
        std::fs::create_dir_all(&dir).unwrap();
        let store = SqliteStore::open(dir.join("bridge.db")).unwrap();
        store
            .create_project(
                "p",
                "Project",
                "0123456789abcdef",
                &dir.join("project").to_string_lossy(),
            )
            .unwrap();
        let api = app(AppState::new(store.clone(), dir.join("artifacts"))
            .with_memory_root(dir.join("memory")));
        let auth = "Bearer 0123456789abcdef";
        let request = |method: &str, uri: String, body: String| {
            Request::builder()
                .method(method)
                .uri(uri)
                .header("authorization", auth)
                .header("content-type", "application/json")
                .body(Body::from(body))
                .unwrap()
        };
        let response = api
            .clone()
            .oneshot(request(
                "POST",
                "/v1/projects/p/jobs".into(),
                r#"{"input":{"x":1},"requires_approval":true,"max_attempts":2}"#.into(),
            ))
            .await
            .unwrap();
        assert_eq!(response.status(), StatusCode::ACCEPTED);
        let json: Value =
            serde_json::from_slice(&response.into_body().collect().await.unwrap().to_bytes())
                .unwrap();
        let job = json["id"].as_str().unwrap().to_string();
        let lease = api
            .clone()
            .oneshot(request(
                "POST",
                "/v1/projects/p/workers".into(),
                r#"{"capabilities":["mock"]}"#.into(),
            ))
            .await
            .unwrap();
        let worker: Value =
            serde_json::from_slice(&lease.into_body().collect().await.unwrap().to_bytes()).unwrap();
        let worker_id = worker["worker"]["id"].as_str().unwrap().to_string();
        let worker_auth = format!("Bearer {}", worker["worker_token"].as_str().unwrap());
        let worker_request = |method: &str, uri: String, body: String| {
            Request::builder()
                .method(method)
                .uri(uri)
                .header("authorization", &worker_auth)
                .header("content-type", "application/json")
                .body(Body::from(body))
                .unwrap()
        };
        let no_lease = api
            .clone()
            .oneshot(worker_request(
                "POST",
                format!("/v1/projects/p/workers/{worker_id}/lease"),
                "".into(),
            ))
            .await
            .unwrap();
        assert_eq!(no_lease.status(), StatusCode::NO_CONTENT);
        api.clone()
            .oneshot(request(
                "POST",
                format!("/v1/projects/p/jobs/{job}/approve"),
                "".into(),
            ))
            .await
            .unwrap();
        let leased = api
            .clone()
            .oneshot(worker_request(
                "POST",
                format!("/v1/projects/p/workers/{worker_id}/lease"),
                "".into(),
            ))
            .await
            .unwrap();
        let data: Value =
            serde_json::from_slice(&leased.into_body().collect().await.unwrap().to_bytes())
                .unwrap();
        let lease_id = data["lease_id"].as_str().unwrap();
        let retry = api
            .clone()
            .oneshot(worker_request(
                "POST",
                format!("/v1/projects/p/jobs/{job}/complete"),
                json!({"worker_id":worker_id,"lease_id":lease_id,"result":{"error":"temporary"},"retryable":true})
                    .to_string(),
            ))
            .await
            .unwrap();
        assert_eq!(retry.status(), StatusCode::OK);
        assert_eq!(
            store.get_job("p", &job).unwrap().unwrap().status,
            JobStatus::Queued
        );
        let uploaded = api
            .clone()
            .oneshot(
                Request::builder()
                    .method("POST")
                    .uri(format!("/v1/projects/p/jobs/{job}/artifacts"))
                    .header("authorization", &worker_auth)
                    .header("x-orchestrator-worker-id", &worker_id)
                    .body(Body::from("artifact"))
                    .unwrap(),
            )
            .await
            .unwrap();
        assert_eq!(uploaded.status(), StatusCode::CREATED);
        let memory = api.clone().oneshot(request("POST", "/v1/projects/p/memory".into(), r#"{"category":"decision","content":"Keep this fact after worker replacement.","source":"operator"}"#.into())).await.unwrap();
        assert_eq!(memory.status(), StatusCode::CREATED);
        let mirror_path = dir.join("memory/p/MEMORY.md");
        let mut mirror = String::new();
        for _ in 0..20 {
            mirror = std::fs::read_to_string(&mirror_path).unwrap_or_default();
            if mirror.contains("Keep this fact after worker replacement.") {
                break;
            }
            tokio::time::sleep(Duration::from_millis(25)).await;
        }
        assert!(mirror.contains("Keep this fact after worker replacement."));
    }
    #[tokio::test]
    async fn encrypted_pack_round_trip_is_read_only_and_authenticated() {
        let dir = std::env::temp_dir().join(format!("bridge-pack-test-{}", uuid::Uuid::new_v4()));
        let workspace = dir.join("project");
        std::fs::create_dir_all(&workspace).unwrap();
        std::fs::write(
            workspace.join("bridge-project.toml"),
            "format = \"orchestrator-bridge-project/v1\"\n",
        )
        .unwrap();
        let store = SqliteStore::open(dir.join("bridge.db")).unwrap();
        store
            .create_project("pack", "Pack", "pack-token", &workspace.to_string_lossy())
            .unwrap();
        store
            .record_memory("pack", "decision", "keep local", "operator")
            .unwrap();
        let state = AppState::new(store, dir.join("artifacts")).with_recovery_key(
            dir.join("recovery"),
            "test:key".into(),
            [7; 32],
        );
        let pack = continuity::build_pack(&state, "pack").await.unwrap();
        let briefing = continuity::verify_and_recover(&state, "pack", &pack.manifest.bundle_sha256)
            .await
            .unwrap();
        assert!(!briefing.automatic_dispatch);
        assert!(
            std::path::Path::new(&briefing.recovery_workspace)
                .join("RECOVERY-READ-ONLY.md")
                .exists()
        );
        let tampered = std::path::Path::new(&pack.directory).join("bundle.obpack");
        std::fs::write(&tampered, b"tampered").unwrap();
        assert!(
            continuity::verify_and_recover(&state, "pack", &pack.manifest.bundle_sha256)
                .await
                .is_err()
        );
    }
}
