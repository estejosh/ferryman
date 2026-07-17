//! Authenticated, local-first continuity packs.  A pack is opaque on disk and
//! contains only state the Bridge owns or has been told to retain.  Import is
//! deliberately read-only: verification and a resume briefing never lease or
//! dispatch work.

use std::{
    fs as stdfs,
    path::{Path, PathBuf},
};

use anyhow::{Context, Result, anyhow, bail};
use chacha20poly1305::{
    XChaCha20Poly1305, XNonce,
    aead::{Aead, KeyInit, OsRng, rand_core::RngCore},
};
use hmac::{Hmac, Mac};
use orchestrator_core::{
    Agent, Artifact, ConsentRequest, Event, Job, JobStatus, MemoryCandidate, Project,
    ProjectMemoryEntry,
};
use serde::{Deserialize, Serialize};
use serde_json::Value;
use sha2::{Digest, Sha256};
use uuid::Uuid;

use crate::AppState;
use crate::recovery_targets::{GitRecoveryTarget, Receipt, RecoveryTarget};

const FORMAT: &str = "orchestrator-bridge-continuity-pack/v2";
type HmacSha256 = Hmac<Sha256>;

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct PackArtifact {
    pub id: String,
    pub job_id: String,
    pub sha256: String,
    pub content_type: String,
    pub byte_len: u64,
    pub created_at: String,
    pub content: Vec<u8>,
}
impl From<Artifact> for PackArtifact {
    fn from(value: Artifact) -> Self {
        Self {
            id: value.id,
            job_id: value.job_id,
            sha256: value.sha256,
            content_type: value.content_type,
            byte_len: value.byte_len,
            created_at: value.created_at,
            content: Vec::new(),
        }
    }
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SafeJob {
    pub id: String,
    pub status: JobStatus,
    pub attempts: u32,
    pub max_attempts: u32,
    pub requires_approval: bool,
    pub created_at: String,
    pub updated_at: String,
}
impl From<Job> for SafeJob {
    fn from(job: Job) -> Self {
        Self {
            id: job.id,
            status: job.status,
            attempts: job.attempts,
            max_attempts: job.max_attempts,
            requires_approval: job.requires_approval,
            created_at: job.created_at,
            updated_at: job.updated_at,
        }
    }
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct PackPayload {
    pub format: String,
    pub project: Project,
    pub project_manifest_toml: String,
    pub agents: Vec<Agent>,
    pub approved_memory: Vec<ProjectMemoryEntry>,
    pub pending_memory: Vec<MemoryCandidate>,
    pub consents: Vec<ConsentRequest>,
    pub policy_snapshots: Vec<Value>,
    pub jobs: Vec<SafeJob>,
    pub timeline: Vec<Event>,
    pub artifacts: Vec<PackArtifact>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct PackEntry {
    pub artifact_id: String,
    pub sha256: String,
    pub byte_len: u64,
}
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct EncryptionMetadata {
    pub algorithm: String,
    pub key_reference: String,
    pub wrapped_data_key_nonce: String,
    pub wrapped_data_key: String,
}
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct PackManifest {
    pub format: String,
    pub pack_id: String,
    pub project_id: String,
    pub created_at: String,
    pub bundle_sha256: String,
    pub compressed_payload_sha256: String,
    pub byte_len: u64,
    pub artifacts: Vec<PackEntry>,
    pub encryption: EncryptionMetadata,
    pub provenance: Vec<String>,
    pub manifest_hmac_sha256: String,
}
#[derive(Debug, Clone, Serialize, Deserialize)]
struct Envelope {
    nonce: Vec<u8>,
    ciphertext: Vec<u8>,
}
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct RecoveryBriefing {
    pub project_id: String,
    pub pack_id: String,
    pub active_jobs: Vec<String>,
    pub unresolved_consents: Vec<String>,
    pub pending_memory_candidates: Vec<String>,
    pub failed_or_retryable_jobs: Vec<String>,
    pub recovery_workspace: String,
    pub automatic_dispatch: bool,
}
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct PackResult {
    pub manifest: PackManifest,
    pub directory: String,
}

pub async fn build_pack(state: &AppState, project_id: &str) -> Result<PackResult> {
    let project = state
        .store
        .get_project(project_id)?
        .ok_or_else(|| anyhow!("project not found"))?;
    let manifest_path = PathBuf::from(&project.workspace_path).join("bridge-project.toml");
    let project_manifest_toml = tokio::fs::read_to_string(&manifest_path)
        .await
        .unwrap_or_default();
    let artifacts = state.store.project_artifacts(project_id)?;
    let mut packed = Vec::with_capacity(artifacts.len());
    for metadata in artifacts {
        let path = state.artifact_root.join(&metadata.sha256);
        let content = tokio::fs::read(&path)
            .await
            .with_context(|| format!("read retained artifact {}", metadata.id))?;
        if sha(&content) != metadata.sha256 || content.len() as u64 != metadata.byte_len {
            bail!("artifact {} failed local integrity check", metadata.id);
        }
        let mut item = PackArtifact::from(metadata);
        item.content = content;
        packed.push(item);
    }
    let jobs = state.store.list_jobs(project_id, 500, None, None)?;
    let policy_snapshots = jobs
        .iter()
        .map(|j| serde_json::to_value(&j.policy).unwrap_or(Value::Null))
        .collect();
    let payload = PackPayload {
        format: FORMAT.into(),
        project,
        project_manifest_toml,
        agents: state.store.list_agents(project_id)?,
        approved_memory: state.store.project_memory(project_id, 5_000)?,
        pending_memory: state.store.list_memory_candidates(project_id)?,
        consents: state.store.list_consents(project_id)?,
        policy_snapshots,
        jobs: jobs.into_iter().map(SafeJob::from).collect(),
        timeline: state.store.timeline(project_id, 0, 500, None, None)?,
        artifacts: packed,
    };
    let plaintext = serde_json::to_vec(&payload)?;
    let compressed = zstd::stream::encode_all(plaintext.as_slice(), 6)?;
    let master_key = state.recovery_key()?;
    let mut data_key = [0u8; 32];
    OsRng.fill_bytes(&mut data_key);
    let encrypted = encrypt(&data_key, &compressed)?;
    let wrapped = encrypt(&master_key, &data_key)?;
    let bundle = serde_json::to_vec(&encrypted)?;
    let bundle_sha256 = sha(&bundle);
    let mut manifest = PackManifest {
        format: FORMAT.into(),
        pack_id: Uuid::new_v4().to_string(),
        project_id: project_id.into(),
        created_at: chrono::Utc::now().to_rfc3339(),
        bundle_sha256,
        compressed_payload_sha256: sha(&compressed),
        byte_len: bundle.len() as u64,
        artifacts: payload
            .artifacts
            .iter()
            .map(|a| PackEntry {
                artifact_id: a.id.clone(),
                sha256: a.sha256.clone(),
                byte_len: a.byte_len,
            })
            .collect(),
        encryption: EncryptionMetadata {
            algorithm: "XChaCha20-Poly1305 + HMAC-SHA256".into(),
            key_reference: state.recovery_key_reference().into(),
            wrapped_data_key_nonce: hex::encode(wrapped.nonce),
            wrapped_data_key: hex::encode(wrapped.ciphertext),
        },
        provenance: vec![
            format!("project:{}", project_id),
            "bridge:local-first".into(),
        ],
        manifest_hmac_sha256: String::new(),
    };
    manifest.manifest_hmac_sha256 = manifest_hmac(&master_key, &manifest)?;
    let directory = state
        .recovery_root
        .join("packs")
        .join(project_id)
        .join(&manifest.bundle_sha256);
    tokio::fs::create_dir_all(&directory).await?;
    tokio::fs::write(
        directory.join("manifest.json"),
        serde_json::to_vec_pretty(&manifest)?,
    )
    .await?;
    tokio::fs::write(directory.join("bundle.obpack"), &bundle).await?;
    state.store.append_project_event(project_id, "recovery.pack_created", serde_json::json!({"pack_id":manifest.pack_id,"manifest_hash":manifest.manifest_hmac_sha256,"bundle_sha256":manifest.bundle_sha256,"bytes":manifest.byte_len}))?;
    Ok(PackResult {
        manifest,
        directory: directory.to_string_lossy().into_owned(),
    })
}

pub async fn verify_and_recover(
    state: &AppState,
    project_id: &str,
    pack_hash: &str,
) -> Result<RecoveryBriefing> {
    if !pack_hash.chars().all(|c| c.is_ascii_hexdigit()) || pack_hash.len() != 64 {
        bail!("pack hash must be a SHA-256 hex digest");
    }
    let directory = state
        .recovery_root
        .join("packs")
        .join(project_id)
        .join(pack_hash);
    let manifest: PackManifest =
        serde_json::from_slice(&tokio::fs::read(directory.join("manifest.json")).await?)?;
    if manifest.format != FORMAT
        || manifest.project_id != project_id
        || manifest.bundle_sha256 != pack_hash
    {
        bail!("invalid pack manifest identity");
    }
    let master_key = state.recovery_key()?;
    if manifest_hmac(&master_key, &manifest)? != manifest.manifest_hmac_sha256 {
        bail!("pack manifest authentication failed");
    }
    let bundle = tokio::fs::read(directory.join("bundle.obpack")).await?;
    if sha(&bundle) != manifest.bundle_sha256 || bundle.len() as u64 != manifest.byte_len {
        bail!("bundle hash or byte count mismatch");
    }
    let encrypted: Envelope = serde_json::from_slice(&bundle)?;
    let wrapped = Envelope {
        nonce: hex::decode(&manifest.encryption.wrapped_data_key_nonce)?,
        ciphertext: hex::decode(&manifest.encryption.wrapped_data_key)?,
    };
    let data_key = decrypt(&master_key, &wrapped)?;
    if data_key.len() != 32 {
        bail!("invalid wrapped data encryption key");
    }
    let compressed = decrypt(&data_key, &encrypted)?;
    if sha(&compressed) != manifest.compressed_payload_sha256 {
        bail!("compressed payload hash mismatch");
    }
    let raw = zstd::stream::decode_all(compressed.as_slice())?;
    let payload: PackPayload = serde_json::from_slice(&raw)?;
    if payload.format != FORMAT || payload.project.id != project_id {
        bail!("payload identity mismatch");
    }
    if payload.artifacts.len() != manifest.artifacts.len() {
        bail!("artifact manifest count mismatch");
    }
    for artifact in &payload.artifacts {
        if sha(&artifact.content) != artifact.sha256
            || artifact.content.len() as u64 != artifact.byte_len
        {
            bail!("artifact {} integrity check failed", artifact.id);
        }
    }
    let workspace = state
        .recovery_root
        .join("recovered")
        .join(project_id)
        .join(&manifest.pack_id);
    if workspace.exists() {
        tokio::fs::remove_dir_all(&workspace).await?;
    }
    tokio::fs::create_dir_all(workspace.join("artifacts")).await?;
    for artifact in &payload.artifacts {
        tokio::fs::write(
            workspace.join("artifacts").join(&artifact.sha256),
            &artifact.content,
        )
        .await?;
    }
    tokio::fs::write(
        workspace.join("payload.json"),
        serde_json::to_vec_pretty(&payload)?,
    )
    .await?;
    let briefing = RecoveryBriefing {
        project_id: project_id.into(),
        pack_id: manifest.pack_id.clone(),
        active_jobs: payload
            .jobs
            .iter()
            .filter(|j| {
                matches!(
                    j.status,
                    JobStatus::Queued | JobStatus::Leased | JobStatus::PendingApproval
                )
            })
            .map(|j| j.id.clone())
            .collect(),
        unresolved_consents: payload
            .consents
            .iter()
            .filter(|c| c.status == "pending")
            .map(|c| c.id.clone())
            .collect(),
        pending_memory_candidates: payload
            .pending_memory
            .iter()
            .filter(|c| c.status == "pending")
            .map(|c| c.id.clone())
            .collect(),
        failed_or_retryable_jobs: payload
            .jobs
            .iter()
            .filter(|j| matches!(j.status, JobStatus::Failed | JobStatus::Cancelled))
            .map(|j| j.id.clone())
            .collect(),
        recovery_workspace: workspace.to_string_lossy().into_owned(),
        automatic_dispatch: false,
    };
    tokio::fs::write(
        workspace.join("resume-briefing.json"),
        serde_json::to_vec_pretty(&briefing)?,
    )
    .await?;
    tokio::fs::write(workspace.join("RECOVERY-READ-ONLY.md"), b"# Verified recovery workspace\n\nThis workspace is evidence only. The Bridge will never resume or dispatch work from import. Review `resume-briefing.json` and create new approved work deliberately.\n").await?;
    readonly_tree(&workspace)?;
    state.store.append_project_event(project_id, "recovery.pack_verified", serde_json::json!({"pack_id":manifest.pack_id,"bundle_sha256":manifest.bundle_sha256,"recovery_workspace":briefing.recovery_workspace}))?;
    Ok(briefing)
}

pub async fn load_manifest(
    state: &AppState,
    project_id: &str,
    pack_hash: &str,
) -> Result<PackManifest> {
    if !pack_hash
        .chars()
        .all(|character| character.is_ascii_hexdigit())
        || pack_hash.len() != 64
    {
        bail!("pack hash must be a SHA-256 hex digest");
    }
    let manifest: PackManifest = serde_json::from_slice(
        &tokio::fs::read(
            state
                .recovery_root
                .join("packs")
                .join(project_id)
                .join(pack_hash)
                .join("manifest.json"),
        )
        .await?,
    )?;
    if manifest.format != FORMAT
        || manifest.project_id != project_id
        || manifest.bundle_sha256 != pack_hash
    {
        bail!("invalid pack manifest identity");
    }
    let master_key = state.recovery_key()?;
    if manifest_hmac(&master_key, &manifest)? != manifest.manifest_hmac_sha256 {
        bail!("pack manifest authentication failed");
    }
    Ok(manifest)
}

pub async fn deliver_to_git(
    state: &AppState,
    project_id: &str,
    pack_hash: &str,
    target: &GitRecoveryTarget,
) -> Result<Receipt> {
    let manifest = load_manifest(state, project_id, pack_hash).await?;
    let directory = state
        .recovery_root
        .join("packs")
        .join(project_id)
        .join(pack_hash);
    let bundle = tokio::fs::read(directory.join("bundle.obpack")).await?;
    if sha(&bundle) != manifest.bundle_sha256 {
        bail!("local bundle hash mismatch before recovery delivery");
    }
    let manifest_bytes = serde_json::to_vec_pretty(&manifest)?;
    target.availability().await?;
    let receipt = target
        .upload_pack_and_manifest(&manifest.bundle_sha256, &bundle, &manifest_bytes)
        .await?;
    target.verify_remote_hash(&receipt).await?;
    Ok(receipt)
}

pub async fn recovery_drill(state: &AppState, project_id: &str) -> Result<serde_json::Value> {
    let result = build_pack(state, project_id).await?;
    match verify_and_recover(state, project_id, &result.manifest.bundle_sha256).await {
        Ok(briefing) => {
            state.store.append_project_event(
                project_id,
                "recovery.drill_passed",
                serde_json::json!({"pack_id":result.manifest.pack_id} ),
            )?;
            Ok(serde_json::json!({"passed":true,"pack":result,"briefing":briefing}))
        }
        Err(error) => {
            state.store.append_project_event(
                project_id,
                "recovery.drill_failed",
                serde_json::json!({"pack_id":result.manifest.pack_id,"error":error.to_string()}),
            )?;
            Err(error)
        }
    }
}

fn encrypt(key: &[u8], plaintext: &[u8]) -> Result<Envelope> {
    let cipher =
        XChaCha20Poly1305::new_from_slice(key).map_err(|_| anyhow!("invalid encryption key"))?;
    let mut nonce = [0u8; 24];
    OsRng.fill_bytes(&mut nonce);
    let ciphertext = cipher
        .encrypt(XNonce::from_slice(&nonce), plaintext)
        .map_err(|_| anyhow!("encryption failed"))?;
    Ok(Envelope {
        nonce: nonce.to_vec(),
        ciphertext,
    })
}
fn decrypt(key: &[u8], envelope: &Envelope) -> Result<Vec<u8>> {
    if envelope.nonce.len() != 24 {
        bail!("invalid encryption nonce");
    }
    let cipher =
        XChaCha20Poly1305::new_from_slice(key).map_err(|_| anyhow!("invalid encryption key"))?;
    cipher
        .decrypt(
            XNonce::from_slice(&envelope.nonce),
            envelope.ciphertext.as_ref(),
        )
        .map_err(|_| anyhow!("encrypted pack authentication failed"))
}
fn unsigned_manifest(manifest: &PackManifest) -> Result<Vec<u8>> {
    let mut copy = manifest.clone();
    copy.manifest_hmac_sha256.clear();
    Ok(serde_json::to_vec(&copy)?)
}
fn manifest_hmac(key: &[u8], manifest: &PackManifest) -> Result<String> {
    let mut mac =
        <HmacSha256 as Mac>::new_from_slice(key).map_err(|_| anyhow!("invalid HMAC key"))?;
    mac.update(&unsigned_manifest(manifest)?);
    Ok(hex::encode(mac.finalize().into_bytes()))
}
fn sha(bytes: &[u8]) -> String {
    hex::encode(Sha256::digest(bytes))
}
fn readonly_tree(path: &Path) -> Result<()> {
    for entry in stdfs::read_dir(path)? {
        let entry = entry?;
        let child = entry.path();
        if child.is_dir() {
            readonly_tree(&child)?;
        } else {
            let mut permissions = stdfs::metadata(&child)?.permissions();
            permissions.set_readonly(true);
            stdfs::set_permissions(child, permissions)?;
        }
    }
    Ok(())
}
