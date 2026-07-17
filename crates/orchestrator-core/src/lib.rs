#![forbid(unsafe_code)]

use std::{
    path::Path,
    sync::{Arc, Mutex},
};

use anyhow::{Context, Result, anyhow};
use chrono::Utc;
use rusqlite::{Connection, OptionalExtension, params};
use serde::{Deserialize, Serialize};
use serde_json::{Value, json};
use sha2::{Digest, Sha256};
use uuid::Uuid;

pub const API_VERSION: &str = "v1";

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "snake_case")]
pub enum JobStatus {
    PendingApproval,
    Queued,
    Leased,
    Succeeded,
    Failed,
    Cancelled,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct PolicyEnvelope {
    #[serde(default)]
    pub filesystem: Access,
    #[serde(default)]
    pub network: Access,
    #[serde(default)]
    pub shell: Access,
    #[serde(default)]
    pub secrets: Vec<String>,
    #[serde(default)]
    pub budget_cents: Option<u64>,
}
#[derive(Debug, Clone, Serialize, Deserialize, Default)]
#[serde(rename_all = "snake_case")]
pub enum Access {
    #[default]
    Deny,
    ReadOnly,
    Allow,
}
impl Default for PolicyEnvelope {
    fn default() -> Self {
        Self {
            filesystem: Access::Deny,
            network: Access::Deny,
            shell: Access::Deny,
            secrets: vec![],
            budget_cents: None,
        }
    }
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Project {
    pub id: String,
    pub name: String,
    pub workspace_path: String,
    pub created_at: String,
}
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "snake_case")]
pub enum AgentPersistence {
    Temporal,
    Permanent,
}
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Agent {
    pub id: String,
    pub project_id: String,
    pub name: String,
    pub role: String,
    pub description: String,
    pub persistence: AgentPersistence,
    pub profile_path: String,
    pub created_at: String,
}
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ProjectMemoryEntry {
    pub id: String,
    pub project_id: String,
    pub category: String,
    pub content: String,
    pub source: String,
    pub created_at: String,
}
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ConsentRequest {
    pub id: String,
    pub project_id: String,
    pub kind: String,
    pub payload: Value,
    pub manifest_hash: String,
    pub status: String,
    pub created_at: String,
    pub resolved_at: Option<String>,
    pub expires_at: Option<String>,
    pub approver: Option<String>,
}
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct MemoryCandidate {
    pub id: String,
    pub project_id: String,
    pub job_id: Option<String>,
    pub category: String,
    pub content: String,
    pub source: String,
    pub status: String,
    pub created_at: String,
    pub resolved_at: Option<String>,
}
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Job {
    pub id: String,
    pub project_id: String,
    pub status: JobStatus,
    pub input: Value,
    pub policy: PolicyEnvelope,
    pub requires_approval: bool,
    pub attempts: u32,
    pub max_attempts: u32,
    pub result: Option<Value>,
    pub created_at: String,
    pub updated_at: String,
}
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Event {
    pub id: i64,
    pub job_id: Option<String>,
    pub kind: String,
    pub payload: Value,
    pub occurred_at: String,
}
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Lease {
    pub lease_id: String,
    pub job: Job,
    pub expires_at: String,
}
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Artifact {
    pub id: String,
    pub job_id: String,
    pub sha256: String,
    pub content_type: String,
    pub byte_len: u64,
    pub created_at: String,
}
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Worker {
    pub id: String,
    pub project_id: String,
    pub capabilities: Vec<String>,
    pub last_heartbeat: String,
}
#[derive(Debug, Clone)]
pub struct NewJob {
    pub input: Value,
    pub policy: PolicyEnvelope,
    pub requires_approval: bool,
    pub max_attempts: u32,
    pub idempotency_key: Option<String>,
}

/// A stable adapter boundary. Adapters advertise and execute capabilities; the bridge owns state.
pub trait Adapter: Send + Sync {
    fn api_version(&self) -> &'static str {
        "v1"
    }
    fn capabilities(&self) -> Vec<String>;
}

#[derive(Clone)]
pub struct SqliteStore {
    conn: Arc<Mutex<Connection>>,
}

impl SqliteStore {
    pub fn open(path: impl AsRef<Path>) -> Result<Self> {
        let conn = Connection::open(path).context("open sqlite database")?;
        conn.pragma_update(None, "journal_mode", "WAL")?;
        conn.execute_batch("PRAGMA foreign_keys = ON;
CREATE TABLE IF NOT EXISTS projects (id TEXT PRIMARY KEY, name TEXT NOT NULL, workspace_path TEXT NOT NULL DEFAULT '', token_hash TEXT NOT NULL UNIQUE, created_at TEXT NOT NULL);
CREATE TABLE IF NOT EXISTS jobs (id TEXT PRIMARY KEY, project_id TEXT NOT NULL REFERENCES projects(id), idempotency_key TEXT, status TEXT NOT NULL, input_json TEXT NOT NULL, policy_json TEXT NOT NULL, requires_approval INTEGER NOT NULL, attempts INTEGER NOT NULL DEFAULT 0, max_attempts INTEGER NOT NULL, available_at TEXT NOT NULL, lease_id TEXT, lease_expires_at TEXT, worker_id TEXT, result_json TEXT, created_at TEXT NOT NULL, updated_at TEXT NOT NULL, UNIQUE(project_id, idempotency_key));
CREATE TABLE IF NOT EXISTS events (id INTEGER PRIMARY KEY AUTOINCREMENT, project_id TEXT NOT NULL REFERENCES projects(id), job_id TEXT, kind TEXT NOT NULL, payload_json TEXT NOT NULL, occurred_at TEXT NOT NULL);
CREATE INDEX IF NOT EXISTS events_project_job_idx ON events(project_id, job_id, id);
CREATE TABLE IF NOT EXISTS workers (id TEXT PRIMARY KEY, project_id TEXT NOT NULL REFERENCES projects(id), capabilities_json TEXT NOT NULL, last_heartbeat TEXT NOT NULL);
CREATE TABLE IF NOT EXISTS artifacts (id TEXT PRIMARY KEY, project_id TEXT NOT NULL REFERENCES projects(id), job_id TEXT NOT NULL REFERENCES jobs(id), sha256 TEXT NOT NULL, content_type TEXT NOT NULL, byte_len INTEGER NOT NULL, created_at TEXT NOT NULL);")?;
        let _ = conn.execute(
            "ALTER TABLE projects ADD COLUMN workspace_path TEXT NOT NULL DEFAULT ''",
            [],
        );
        conn.execute_batch("CREATE TABLE IF NOT EXISTS agents (id TEXT PRIMARY KEY, project_id TEXT NOT NULL REFERENCES projects(id), name TEXT NOT NULL, role TEXT NOT NULL, description TEXT NOT NULL, persistence TEXT NOT NULL, profile_path TEXT NOT NULL, created_at TEXT NOT NULL, UNIQUE(project_id, name));")?;
        conn.execute_batch("CREATE TABLE IF NOT EXISTS project_memory (id TEXT PRIMARY KEY, project_id TEXT NOT NULL REFERENCES projects(id), category TEXT NOT NULL, content TEXT NOT NULL, source TEXT NOT NULL, created_at TEXT NOT NULL);
CREATE INDEX IF NOT EXISTS project_memory_project_idx ON project_memory(project_id, created_at, id);")?;
        conn.execute_batch("CREATE TABLE IF NOT EXISTS artifact_bypasses (project_id TEXT NOT NULL REFERENCES projects(id), job_id TEXT NOT NULL REFERENCES jobs(id), max_bytes INTEGER NOT NULL, approved_at TEXT NOT NULL, PRIMARY KEY(project_id, job_id));")?;
        conn.execute_batch("CREATE TABLE IF NOT EXISTS consent_requests (id TEXT PRIMARY KEY, project_id TEXT NOT NULL REFERENCES projects(id), kind TEXT NOT NULL, payload_json TEXT NOT NULL, status TEXT NOT NULL, created_at TEXT NOT NULL, resolved_at TEXT);
CREATE TABLE IF NOT EXISTS memory_candidates (id TEXT PRIMARY KEY, project_id TEXT NOT NULL REFERENCES projects(id), job_id TEXT, category TEXT NOT NULL, content TEXT NOT NULL, source TEXT NOT NULL, status TEXT NOT NULL, created_at TEXT NOT NULL, resolved_at TEXT);
")?;
        let _ = conn.execute(
            "ALTER TABLE consent_requests ADD COLUMN manifest_hash TEXT NOT NULL DEFAULT ''",
            [],
        );
        let _ = conn.execute(
            "ALTER TABLE consent_requests ADD COLUMN expires_at TEXT",
            [],
        );
        let _ = conn.execute("ALTER TABLE consent_requests ADD COLUMN approver TEXT", []);
        Ok(Self {
            conn: Arc::new(Mutex::new(conn)),
        })
    }
    fn db(&self) -> Result<std::sync::MutexGuard<'_, Connection>> {
        self.conn
            .lock()
            .map_err(|_| anyhow!("database mutex poisoned"))
    }
    pub fn create_project(
        &self,
        id: &str,
        name: &str,
        token: &str,
        workspace_path: &str,
    ) -> Result<Project> {
        let now = now();
        let project = Project {
            id: id.into(),
            name: name.into(),
            workspace_path: workspace_path.into(),
            created_at: now.clone(),
        };
        self.db()?.execute(
            "INSERT INTO projects (id,name,workspace_path,token_hash,created_at) VALUES (?1,?2,?3,?4,?5)",
            params![id, name, workspace_path, hash(token), now],
        )?;
        Ok(project)
    }
    pub fn authenticate(&self, project_id: &str, token: &str) -> Result<bool> {
        let stored_hash: Option<String> = self
            .db()?
            .query_row(
                "SELECT token_hash FROM projects WHERE id=?1",
                [project_id],
                |r| r.get(0),
            )
            .optional()?;
        Ok(stored_hash.is_some_and(|stored| stored == hash(token)))
    }
    pub fn get_project(&self, project_id: &str) -> Result<Option<Project>> {
        let db = self.db()?;
        db.query_row(
            "SELECT id,name,workspace_path,created_at FROM projects WHERE id=?1",
            [project_id],
            project_from_row,
        )
        .optional()
        .map_err(Into::into)
    }
    pub fn submit_job(&self, project_id: &str, new: NewJob) -> Result<Job> {
        if let Some(key) = &new.idempotency_key
            && let Some(job) = self.find_by_idempotency(project_id, key)?
        {
            return Ok(job);
        }
        let now = now();
        let id = Uuid::new_v4().to_string();
        let status = if new.requires_approval {
            JobStatus::PendingApproval
        } else {
            JobStatus::Queued
        };
        let job = Job {
            id: id.clone(),
            project_id: project_id.into(),
            status: status.clone(),
            input: new.input,
            policy: new.policy,
            requires_approval: new.requires_approval,
            attempts: 0,
            max_attempts: new.max_attempts.max(1),
            result: None,
            created_at: now.clone(),
            updated_at: now.clone(),
        };
        let mut db = self.db()?;
        let tx = db.transaction()?;
        tx.execute("INSERT INTO jobs (id,project_id,idempotency_key,status,input_json,policy_json,requires_approval,attempts,max_attempts,available_at,created_at,updated_at) VALUES (?1,?2,?3,?4,?5,?6,?7,0,?8,?9,?9,?9)", params![job.id, project_id, new.idempotency_key, status_text(&status), serde_json::to_string(&job.input)?, serde_json::to_string(&job.policy)?, i64::from(job.requires_approval), i64::from(job.max_attempts), now])?;
        append_event(
            &tx,
            project_id,
            Some(&id),
            "job.submitted",
            json!({"status": status_text(&status)}),
        )?;
        tx.commit()?;
        Ok(job)
    }
    pub fn get_job(&self, project_id: &str, job_id: &str) -> Result<Option<Job>> {
        let db = self.db()?;
        read_job(
            &db,
            "SELECT id,project_id,status,input_json,policy_json,requires_approval,attempts,max_attempts,result_json,created_at,updated_at FROM jobs WHERE project_id=?1 AND id=?2",
            params![project_id, job_id],
        )
    }
    pub fn list_jobs(
        &self,
        project_id: &str,
        limit: u32,
        cursor: Option<&str>,
        status: Option<&JobStatus>,
    ) -> Result<Vec<Job>> {
        let db = self.db()?;
        let mut query = "SELECT id,project_id,status,input_json,policy_json,requires_approval,attempts,max_attempts,result_json,created_at,updated_at FROM jobs WHERE project_id=?1".to_string();
        if cursor.is_some() {
            query.push_str(" AND id > ?2");
        }
        if status.is_some() {
            query.push_str(if cursor.is_some() {
                " AND status=?3"
            } else {
                " AND status=?2"
            });
        }
        let limit_parameter = match (cursor.is_some(), status.is_some()) {
            (true, true) => "?4",
            (true, false) | (false, true) => "?3",
            (false, false) => "?2",
        };
        query.push_str(&format!(" ORDER BY id LIMIT {limit_parameter}"));
        let mut statement = db.prepare(&query)?;
        let mut rows = match (cursor, status) {
            (Some(c), Some(s)) => statement.query(params![
                project_id,
                c,
                status_text(s),
                i64::from(limit.min(100))
            ])?,
            (Some(c), None) => {
                statement.query(params![project_id, c, i64::from(limit.min(100))])?
            }
            (None, Some(s)) => statement.query(params![
                project_id,
                status_text(s),
                i64::from(limit.min(100))
            ])?,
            (None, None) => statement.query(params![project_id, i64::from(limit.min(100))])?,
        };
        let mut result = vec![];
        while let Some(row) = rows.next()? {
            result.push(job_from_row(row)?);
        }
        Ok(result)
    }
    pub fn approve(&self, project_id: &str, job_id: &str) -> Result<Option<Job>> {
        self.transition(
            project_id,
            job_id,
            JobStatus::PendingApproval,
            JobStatus::Queued,
            "job.approved",
            json!({}),
        )
    }
    pub fn cancel(&self, project_id: &str, job_id: &str) -> Result<Option<Job>> {
        let now = now();
        let mut db = self.db()?;
        let tx = db.transaction()?;
        let count = tx.execute("UPDATE jobs SET status='cancelled',updated_at=?3 WHERE project_id=?1 AND id=?2 AND status IN ('pending_approval','queued','leased')", params![project_id,job_id,now])?;
        if count == 0 {
            tx.commit()?;
            return Ok(None);
        }
        append_event(&tx, project_id, Some(job_id), "job.cancelled", json!({}))?;
        tx.commit()?;
        drop(db);
        self.get_job(project_id, job_id)
    }
    fn transition(
        &self,
        project_id: &str,
        job_id: &str,
        from: JobStatus,
        to: JobStatus,
        event: &str,
        payload: Value,
    ) -> Result<Option<Job>> {
        let now = now();
        let mut db = self.db()?;
        let tx = db.transaction()?;
        let count = tx.execute(
            "UPDATE jobs SET status=?4,updated_at=?3 WHERE project_id=?1 AND id=?2 AND status=?5",
            params![
                project_id,
                job_id,
                now,
                status_text(&to),
                status_text(&from)
            ],
        )?;
        if count > 0 {
            append_event(&tx, project_id, Some(job_id), event, payload)?;
        }
        tx.commit()?;
        drop(db);
        if count > 0 {
            self.get_job(project_id, job_id)
        } else {
            Ok(None)
        }
    }
    pub fn register_worker(&self, project_id: &str, capabilities: Vec<String>) -> Result<Worker> {
        let worker = Worker {
            id: Uuid::new_v4().to_string(),
            project_id: project_id.into(),
            capabilities,
            last_heartbeat: now(),
        };
        self.db()?.execute("INSERT INTO workers(id,project_id,capabilities_json,last_heartbeat) VALUES(?1,?2,?3,?4)",params![worker.id,project_id,serde_json::to_string(&worker.capabilities)?,worker.last_heartbeat])?;
        Ok(worker)
    }
    pub fn ensure_agent(&self, agent: Agent) -> Result<Agent> {
        let db = self.db()?;
        let existing = db
            .query_row(
                "SELECT id,project_id,name,role,description,persistence,profile_path,created_at FROM agents WHERE project_id=?1 AND name=?2",
                params![agent.project_id, agent.name],
                agent_from_row,
            )
            .optional()?;
        if let Some(existing) = existing {
            return Ok(existing);
        }
        db.execute(
            "INSERT INTO agents(id,project_id,name,role,description,persistence,profile_path,created_at) VALUES(?1,?2,?3,?4,?5,?6,?7,?8)",
            params![agent.id,agent.project_id,agent.name,agent.role,agent.description,persistence_text(&agent.persistence),agent.profile_path,agent.created_at],
        )?;
        Ok(agent)
    }
    pub fn list_agents(&self, project_id: &str) -> Result<Vec<Agent>> {
        let db = self.db()?;
        let mut statement = db.prepare("SELECT id,project_id,name,role,description,persistence,profile_path,created_at FROM agents WHERE project_id=?1 ORDER BY name")?;
        let rows = statement.query_map([project_id], agent_from_row)?;
        rows.collect::<rusqlite::Result<Vec<_>>>()
            .map_err(Into::into)
    }
    pub fn record_memory(
        &self,
        project_id: &str,
        category: &str,
        content: &str,
        source: &str,
    ) -> Result<ProjectMemoryEntry> {
        let entry = ProjectMemoryEntry {
            id: Uuid::new_v4().to_string(),
            project_id: project_id.into(),
            category: category.into(),
            content: content.into(),
            source: source.into(),
            created_at: now(),
        };
        self.db()?.execute("INSERT INTO project_memory(id,project_id,category,content,source,created_at) VALUES(?1,?2,?3,?4,?5,?6)",params![entry.id,entry.project_id,entry.category,entry.content,entry.source,entry.created_at])?;
        Ok(entry)
    }
    pub fn project_memory(&self, project_id: &str, limit: u32) -> Result<Vec<ProjectMemoryEntry>> {
        let db = self.db()?;
        let mut statement=db.prepare("SELECT id,project_id,category,content,source,created_at FROM project_memory WHERE project_id=?1 ORDER BY created_at, id LIMIT ?2")?;
        let rows = statement.query_map(
            params![project_id, i64::from(limit.min(500))],
            memory_from_row,
        )?;
        rows.collect::<rusqlite::Result<Vec<_>>>()
            .map_err(Into::into)
    }
    pub fn heartbeat(&self, project_id: &str, worker_id: &str) -> Result<bool> {
        Ok(self.db()?.execute(
            "UPDATE workers SET last_heartbeat=?3 WHERE id=?1 AND project_id=?2",
            params![worker_id, project_id, now()],
        )? == 1)
    }
    pub fn lease(
        &self,
        project_id: &str,
        worker_id: &str,
        ttl_seconds: i64,
    ) -> Result<Option<Lease>> {
        let now = now();
        let expires = (Utc::now() + chrono::Duration::seconds(ttl_seconds)).to_rfc3339();
        let mut db = self.db()?;
        let tx = db.transaction()?;
        // In v0.1 a poll for work also reaps stale leases. A later background reaper
        // can invoke the same transition without changing the job semantics.
        let stale_jobs = {
            let mut statement = tx.prepare(
                "SELECT id, attempts, max_attempts FROM jobs WHERE project_id=?1 AND status='leased' AND lease_expires_at<=?2",
            )?;
            let rows = statement.query_map(params![project_id, now], |row| {
                Ok((
                    row.get::<_, String>(0)?,
                    row.get::<_, i64>(1)?,
                    row.get::<_, i64>(2)?,
                ))
            })?;
            rows.collect::<rusqlite::Result<Vec<_>>>()?
        };
        for (stale_id, attempts, max_attempts) in stale_jobs {
            let state = if attempts < max_attempts {
                "queued"
            } else {
                "failed"
            };
            tx.execute(
                "UPDATE jobs SET status=?2,available_at=?3,lease_id=NULL,lease_expires_at=NULL,updated_at=?3 WHERE id=?1",
                params![stale_id, state, now],
            )?;
            append_event(
                &tx,
                project_id,
                Some(&stale_id),
                if state == "queued" {
                    "job.lease_expired"
                } else {
                    "job.failed"
                },
                json!({"reason":"lease_expired"}),
            )?;
        }
        let job_id:Option<String>=tx.query_row("SELECT id FROM jobs WHERE project_id=?1 AND status='queued' AND available_at<=?2 ORDER BY created_at LIMIT 1",params![project_id,now],|r|r.get(0)).optional()?;
        let Some(job_id) = job_id else {
            tx.commit()?;
            return Ok(None);
        };
        let lease_id = Uuid::new_v4().to_string();
        tx.execute("UPDATE jobs SET status='leased',attempts=attempts+1,lease_id=?3,lease_expires_at=?4,worker_id=?5,updated_at=?2 WHERE id=?1",params![job_id,now,lease_id,expires,worker_id])?;
        append_event(
            &tx,
            project_id,
            Some(&job_id),
            "job.leased",
            json!({"worker_id":worker_id}),
        )?;
        tx.commit()?;
        drop(db);
        let job = self
            .get_job(project_id, &job_id)?
            .ok_or_else(|| anyhow!("leased job disappeared"))?;
        Ok(Some(Lease {
            lease_id,
            job,
            expires_at: expires,
        }))
    }
    pub fn complete(
        &self,
        project_id: &str,
        job_id: &str,
        lease_id: &str,
        result: Value,
        retryable: bool,
    ) -> Result<Option<Job>> {
        let current = self.get_job(project_id, job_id)?;
        let Some(current) = current else {
            return Ok(None);
        };
        if current.status == JobStatus::Succeeded {
            return Ok(Some(current));
        }
        let mut db = self.db()?;
        let tx = db.transaction()?;
        let now = now();
        let (status, available_at, event) = if retryable && current.attempts < current.max_attempts
        {
            (
                "queued",
                (Utc::now() + chrono::Duration::seconds(2_i64.pow(current.attempts.min(6))))
                    .to_rfc3339(),
                "job.retry_scheduled",
            )
        } else if retryable {
            ("failed", now.clone(), "job.failed")
        } else {
            ("succeeded", now.clone(), "job.succeeded")
        };
        let changed=tx.execute("UPDATE jobs SET status=?4,result_json=?5,available_at=?6,lease_id=NULL,lease_expires_at=NULL,updated_at=?3 WHERE project_id=?1 AND id=?2 AND status='leased' AND lease_id=?7",params![project_id,job_id,now,status,serde_json::to_string(&result)?,available_at,lease_id])?;
        if changed > 0 {
            append_event(
                &tx,
                project_id,
                Some(job_id),
                event,
                json!({"retryable":retryable}),
            )?;
        }
        tx.commit()?;
        drop(db);
        if changed > 0 {
            if status == "succeeded" {
                let _ = self.propose_memory(project_id, Some(job_id), "job_completion", &format!("Job {job_id} completed successfully. Review its result and artifacts for durable project facts."), "bridge.flight_recorder");
            }
            self.get_job(project_id, job_id)
        } else {
            Ok(None)
        }
    }
    pub fn append_worker_event(
        &self,
        project_id: &str,
        job_id: &str,
        kind: &str,
        payload: Value,
    ) -> Result<()> {
        let db = self.db()?;
        append_event(&db, project_id, Some(job_id), kind, redact(payload))
    }
    /// Adds a bridge-owned, append-only decision record.  Unlike worker events it
    /// is not tied to a job, which lets recovery, consent, and policy activity
    /// share one ordered timeline with job events.
    pub fn append_project_event(&self, project_id: &str, kind: &str, payload: Value) -> Result<()> {
        let db = self.db()?;
        append_event(&db, project_id, None, kind, redact(payload))
    }
    pub fn events(&self, project_id: &str, job_id: &str, after: i64) -> Result<Vec<Event>> {
        let db = self.db()?;
        let mut stmt=db.prepare("SELECT id,job_id,kind,payload_json,occurred_at FROM events WHERE project_id=?1 AND job_id=?2 AND id>?3 ORDER BY id")?;
        let rows = stmt.query_map(params![project_id, job_id, after], |r| {
            Ok(Event {
                id: r.get(0)?,
                job_id: r.get(1)?,
                kind: r.get(2)?,
                payload: serde_json::from_str::<Value>(&r.get::<_, String>(3)?)
                    .unwrap_or(json!({})),
                occurred_at: r.get(4)?,
            })
        })?;
        rows.collect::<rusqlite::Result<Vec<_>>>()
            .map_err(Into::into)
    }
    pub fn timeline(
        &self,
        project_id: &str,
        after: i64,
        limit: u32,
        job_id: Option<&str>,
        category: Option<&str>,
    ) -> Result<Vec<Event>> {
        let db = self.db()?;
        let mut statement = db.prepare(
            "SELECT id,job_id,kind,payload_json,occurred_at FROM events
             WHERE project_id=?1 AND id>?2
             AND (?3 IS NULL OR job_id=?3)
             AND (?4 IS NULL OR kind LIKE ?4 || '%')
             ORDER BY id ASC LIMIT ?5",
        )?;
        let rows = statement.query_map(
            params![
                project_id,
                after,
                job_id,
                category,
                i64::from(limit.min(500))
            ],
            |r| {
                Ok(Event {
                    id: r.get(0)?,
                    job_id: r.get(1)?,
                    kind: r.get(2)?,
                    payload: serde_json::from_str::<Value>(&r.get::<_, String>(3)?)
                        .unwrap_or(json!({})),
                    occurred_at: r.get(4)?,
                })
            },
        )?;
        rows.collect::<rusqlite::Result<Vec<_>>>()
            .map_err(Into::into)
    }
    pub fn create_artifact(
        &self,
        project_id: &str,
        job_id: &str,
        sha256: &str,
        content_type: &str,
        byte_len: u64,
    ) -> Result<Artifact> {
        let artifact = Artifact {
            id: Uuid::new_v4().to_string(),
            job_id: job_id.into(),
            sha256: sha256.into(),
            content_type: content_type.into(),
            byte_len,
            created_at: now(),
        };
        self.db()?.execute("INSERT INTO artifacts(id,project_id,job_id,sha256,content_type,byte_len,created_at) VALUES(?1,?2,?3,?4,?5,?6,?7)",params![artifact.id,project_id,job_id,sha256,content_type,i64::try_from(byte_len)?,artifact.created_at])?;
        self.append_worker_event(
            project_id,
            job_id,
            "artifact.stored",
            json!({"artifact_id":artifact.id,"sha256":sha256}),
        )?;
        Ok(artifact)
    }
    pub fn list_artifacts(&self, project_id: &str, job_id: &str) -> Result<Vec<Artifact>> {
        let db = self.db()?;
        let mut statement = db.prepare("SELECT id,job_id,sha256,content_type,byte_len,created_at FROM artifacts WHERE project_id=?1 AND job_id=?2 ORDER BY created_at,id")?;
        let rows = statement.query_map(params![project_id, job_id], artifact_from_row)?;
        rows.collect::<rusqlite::Result<Vec<_>>>()
            .map_err(Into::into)
    }
    pub fn get_artifact(&self, project_id: &str, artifact_id: &str) -> Result<Option<Artifact>> {
        let db = self.db()?;
        db.query_row("SELECT id,job_id,sha256,content_type,byte_len,created_at FROM artifacts WHERE project_id=?1 AND id=?2", params![project_id, artifact_id], artifact_from_row).optional().map_err(Into::into)
    }
    pub fn project_artifacts(&self, project_id: &str) -> Result<Vec<Artifact>> {
        let db = self.db()?;
        let mut statement = db.prepare("SELECT id,job_id,sha256,content_type,byte_len,created_at FROM artifacts WHERE project_id=?1 ORDER BY created_at,id")?;
        let rows = statement.query_map([project_id], artifact_from_row)?;
        rows.collect::<rusqlite::Result<Vec<_>>>()
            .map_err(Into::into)
    }
    pub fn metrics(&self) -> Result<(i64, i64)> {
        let db = self.db()?;
        Ok((
            db.query_row(
                "SELECT count(*) FROM jobs WHERE status IN ('queued','pending_approval')",
                [],
                |r| r.get(0),
            )?,
            db.query_row(
                "SELECT count(*) FROM workers WHERE last_heartbeat > ?1",
                [(Utc::now() - chrono::Duration::minutes(2)).to_rfc3339()],
                |r| r.get(0),
            )?,
        ))
    }
    fn find_by_idempotency(&self, project_id: &str, key: &str) -> Result<Option<Job>> {
        let db = self.db()?;
        read_job(
            &db,
            "SELECT id,project_id,status,input_json,policy_json,requires_approval,attempts,max_attempts,result_json,created_at,updated_at FROM jobs WHERE project_id=?1 AND idempotency_key=?2",
            params![project_id, key],
        )
    }
}

fn read_job<P: rusqlite::Params>(db: &Connection, sql: &str, params: P) -> Result<Option<Job>> {
    db.query_row(sql, params, job_from_row)
        .optional()
        .map_err(Into::into)
}
impl SqliteStore {
    pub fn approve_artifact_bypass(
        &self,
        project_id: &str,
        job_id: &str,
        max_bytes: u64,
    ) -> Result<bool> {
        let updated=self.db()?.execute("INSERT INTO artifact_bypasses(project_id,job_id,max_bytes,approved_at) SELECT ?1,?2,?3,?4 WHERE EXISTS(SELECT 1 FROM jobs WHERE project_id=?1 AND id=?2) ON CONFLICT(project_id,job_id) DO UPDATE SET max_bytes=excluded.max_bytes,approved_at=excluded.approved_at",params![project_id,job_id,i64::try_from(max_bytes)?,now()])?;
        Ok(updated == 1)
    }
    pub fn artifact_bypass_limit(&self, project_id: &str, job_id: &str) -> Result<Option<u64>> {
        let limit: Option<i64> = self
            .db()?
            .query_row(
                "SELECT max_bytes FROM artifact_bypasses WHERE project_id=?1 AND job_id=?2",
                params![project_id, job_id],
                |row| row.get(0),
            )
            .optional()?;
        limit
            .map(|value| u64::try_from(value).map_err(Into::into))
            .transpose()
    }
    pub fn create_consent(
        &self,
        project_id: &str,
        kind: &str,
        payload: Value,
        expires_at: Option<&str>,
    ) -> Result<ConsentRequest> {
        let payload = redact(payload);
        let request = ConsentRequest {
            id: Uuid::new_v4().to_string(),
            project_id: project_id.into(),
            kind: kind.into(),
            manifest_hash: sha256_json(&payload),
            payload,
            status: "pending".into(),
            created_at: now(),
            resolved_at: None,
            expires_at: expires_at.map(Into::into),
            approver: None,
        };
        self.db()?.execute("INSERT INTO consent_requests(id,project_id,kind,payload_json,manifest_hash,status,created_at,expires_at) VALUES(?1,?2,?3,?4,?5,?6,?7,?8)",params![request.id,request.project_id,request.kind,serde_json::to_string(&request.payload)?,request.manifest_hash,request.status,request.created_at,request.expires_at])?;
        self.append_project_event(project_id, "consent.requested", json!({"consent_id":request.id,"kind":request.kind,"manifest_hash":request.manifest_hash,"expires_at":request.expires_at}))?;
        Ok(request)
    }
    pub fn list_consents(&self, project_id: &str) -> Result<Vec<ConsentRequest>> {
        let db = self.db()?;
        let mut statement=db.prepare("SELECT id,project_id,kind,payload_json,manifest_hash,status,created_at,resolved_at,expires_at,approver FROM consent_requests WHERE project_id=?1 ORDER BY created_at DESC")?;
        let rows = statement.query_map([project_id], consent_from_row)?;
        rows.collect::<rusqlite::Result<Vec<_>>>()
            .map_err(Into::into)
    }
    pub fn resolve_consent(
        &self,
        project_id: &str,
        id: &str,
        approved: bool,
        approver: &str,
    ) -> Result<Option<ConsentRequest>> {
        let status = if approved { "approved" } else { "rejected" };
        let changed=self.db()?.execute("UPDATE consent_requests SET status=?3,resolved_at=?4,approver=?5 WHERE id=?1 AND project_id=?2 AND status='pending' AND (expires_at IS NULL OR expires_at > ?4)",params![id,project_id,status,now(),approver])?;
        if changed == 0 {
            return Ok(None);
        };
        let db = self.db()?;
        let result = db.query_row("SELECT id,project_id,kind,payload_json,manifest_hash,status,created_at,resolved_at,expires_at,approver FROM consent_requests WHERE id=?1",[id],consent_from_row).optional().map_err(anyhow::Error::from)?;
        drop(db);
        if let Some(ref request) = result {
            self.append_project_event(project_id, "consent.resolved", json!({"consent_id":request.id,"status":request.status,"manifest_hash":request.manifest_hash,"approver":request.approver}))?;
        }
        Ok(result)
    }
    pub fn propose_memory(
        &self,
        project_id: &str,
        job_id: Option<&str>,
        category: &str,
        content: &str,
        source: &str,
    ) -> Result<MemoryCandidate> {
        let candidate = MemoryCandidate {
            id: Uuid::new_v4().to_string(),
            project_id: project_id.into(),
            job_id: job_id.map(Into::into),
            category: category.into(),
            content: content.into(),
            source: source.into(),
            status: "pending".into(),
            created_at: now(),
            resolved_at: None,
        };
        self.db()?.execute("INSERT INTO memory_candidates(id,project_id,job_id,category,content,source,status,created_at) VALUES(?1,?2,?3,?4,?5,?6,?7,?8)",params![candidate.id,candidate.project_id,candidate.job_id,candidate.category,candidate.content,candidate.source,candidate.status,candidate.created_at])?;
        self.append_project_event(project_id, "memory.candidate", json!({"candidate_id":candidate.id,"job_id":candidate.job_id,"category":candidate.category,"source":candidate.source}))?;
        Ok(candidate)
    }
    pub fn list_memory_candidates(&self, project_id: &str) -> Result<Vec<MemoryCandidate>> {
        let db = self.db()?;
        let mut statement=db.prepare("SELECT id,project_id,job_id,category,content,source,status,created_at,resolved_at FROM memory_candidates WHERE project_id=?1 ORDER BY created_at DESC")?;
        let rows = statement.query_map([project_id], candidate_from_row)?;
        rows.collect::<rusqlite::Result<Vec<_>>>()
            .map_err(Into::into)
    }
    pub fn approve_memory_candidate(
        &self,
        project_id: &str,
        id: &str,
    ) -> Result<Option<ProjectMemoryEntry>> {
        let db = self.db()?;
        let candidate:Option<MemoryCandidate>=db.query_row("SELECT id,project_id,job_id,category,content,source,status,created_at,resolved_at FROM memory_candidates WHERE id=?1 AND project_id=?2 AND status='pending'",params![id,project_id],candidate_from_row).optional()?;
        drop(db);
        let Some(candidate) = candidate else {
            return Ok(None);
        };
        let entry = self.record_memory(
            project_id,
            &candidate.category,
            &candidate.content,
            &candidate.source,
        )?;
        self.db()?.execute(
            "UPDATE memory_candidates SET status='approved',resolved_at=?2 WHERE id=?1",
            params![id, now()],
        )?;
        self.append_project_event(
            project_id,
            "memory.approved",
            json!({"candidate_id":id,"memory_id":entry.id}),
        )?;
        Ok(Some(entry))
    }
}
fn sha256_json(value: &Value) -> String {
    let bytes = serde_json::to_vec(value).unwrap_or_default();
    hex::encode(Sha256::digest(bytes))
}
fn job_from_row(row: &rusqlite::Row<'_>) -> rusqlite::Result<Job> {
    let status_string: String = row.get(2)?;
    let status = match status_string.as_str() {
        "pending_approval" => JobStatus::PendingApproval,
        "queued" => JobStatus::Queued,
        "leased" => JobStatus::Leased,
        "succeeded" => JobStatus::Succeeded,
        "failed" => JobStatus::Failed,
        "cancelled" => JobStatus::Cancelled,
        _ => {
            return Err(rusqlite::Error::InvalidColumnType(
                2,
                "status".into(),
                rusqlite::types::Type::Text,
            ));
        }
    };
    Ok(Job {
        id: row.get(0)?,
        project_id: row.get(1)?,
        status,
        input: serde_json::from_str(&row.get::<_, String>(3)?).unwrap_or(json!({})),
        policy: serde_json::from_str(&row.get::<_, String>(4)?).unwrap_or_default(),
        requires_approval: row.get::<_, i64>(5)? != 0,
        attempts: row.get::<_, i64>(6)? as u32,
        max_attempts: row.get::<_, i64>(7)? as u32,
        result: row
            .get::<_, Option<String>>(8)?
            .and_then(|v| serde_json::from_str(&v).ok()),
        created_at: row.get(9)?,
        updated_at: row.get(10)?,
    })
}
fn project_from_row(row: &rusqlite::Row<'_>) -> rusqlite::Result<Project> {
    Ok(Project {
        id: row.get(0)?,
        name: row.get(1)?,
        workspace_path: row.get(2)?,
        created_at: row.get(3)?,
    })
}
fn agent_from_row(row: &rusqlite::Row<'_>) -> rusqlite::Result<Agent> {
    let persistence = match row.get::<_, String>(5)?.as_str() {
        "temporal" => AgentPersistence::Temporal,
        "permanent" => AgentPersistence::Permanent,
        _ => {
            return Err(rusqlite::Error::InvalidColumnType(
                5,
                "persistence".into(),
                rusqlite::types::Type::Text,
            ));
        }
    };
    Ok(Agent {
        id: row.get(0)?,
        project_id: row.get(1)?,
        name: row.get(2)?,
        role: row.get(3)?,
        description: row.get(4)?,
        persistence,
        profile_path: row.get(6)?,
        created_at: row.get(7)?,
    })
}
fn memory_from_row(row: &rusqlite::Row<'_>) -> rusqlite::Result<ProjectMemoryEntry> {
    Ok(ProjectMemoryEntry {
        id: row.get(0)?,
        project_id: row.get(1)?,
        category: row.get(2)?,
        content: row.get(3)?,
        source: row.get(4)?,
        created_at: row.get(5)?,
    })
}
fn artifact_from_row(row: &rusqlite::Row<'_>) -> rusqlite::Result<Artifact> {
    Ok(Artifact {
        id: row.get(0)?,
        job_id: row.get(1)?,
        sha256: row.get(2)?,
        content_type: row.get(3)?,
        byte_len: row.get::<_, i64>(4)? as u64,
        created_at: row.get(5)?,
    })
}
fn consent_from_row(row: &rusqlite::Row<'_>) -> rusqlite::Result<ConsentRequest> {
    Ok(ConsentRequest {
        id: row.get(0)?,
        project_id: row.get(1)?,
        kind: row.get(2)?,
        payload: serde_json::from_str(&row.get::<_, String>(3)?).unwrap_or(json!({})),
        manifest_hash: row.get(4)?,
        status: row.get(5)?,
        created_at: row.get(6)?,
        resolved_at: row.get(7)?,
        expires_at: row.get(8)?,
        approver: row.get(9)?,
    })
}
fn candidate_from_row(row: &rusqlite::Row<'_>) -> rusqlite::Result<MemoryCandidate> {
    Ok(MemoryCandidate {
        id: row.get(0)?,
        project_id: row.get(1)?,
        job_id: row.get(2)?,
        category: row.get(3)?,
        content: row.get(4)?,
        source: row.get(5)?,
        status: row.get(6)?,
        created_at: row.get(7)?,
        resolved_at: row.get(8)?,
    })
}
fn append_event(
    conn: &Connection,
    project_id: &str,
    job_id: Option<&str>,
    kind: &str,
    payload: Value,
) -> Result<()> {
    conn.execute("INSERT INTO events(project_id,job_id,kind,payload_json,occurred_at) VALUES(?1,?2,?3,?4,?5)",params![project_id,job_id,kind,serde_json::to_string(&payload)?,now()])?;
    Ok(())
}
fn now() -> String {
    Utc::now().to_rfc3339()
}
fn hash(token: &str) -> String {
    hex::encode(Sha256::digest(token.as_bytes()))
}
fn status_text(status: &JobStatus) -> &'static str {
    match status {
        JobStatus::PendingApproval => "pending_approval",
        JobStatus::Queued => "queued",
        JobStatus::Leased => "leased",
        JobStatus::Succeeded => "succeeded",
        JobStatus::Failed => "failed",
        JobStatus::Cancelled => "cancelled",
    }
}
fn persistence_text(persistence: &AgentPersistence) -> &'static str {
    match persistence {
        AgentPersistence::Temporal => "temporal",
        AgentPersistence::Permanent => "permanent",
    }
}
fn redact(value: Value) -> Value {
    match value {
        Value::Object(map) => Value::Object(
            map.into_iter()
                .map(|(k, v)| {
                    (
                        k.clone(),
                        if is_sensitive_key(&k) {
                            Value::String("[REDACTED]".into())
                        } else {
                            redact(v)
                        },
                    )
                })
                .collect(),
        ),
        Value::Array(a) => Value::Array(a.into_iter().map(redact).collect()),
        v => v,
    }
}
fn is_sensitive_key(key: &str) -> bool {
    let key = key.to_ascii_lowercase();
    [
        "secret",
        "token",
        "password",
        "authorization",
        "api_key",
        "apikey",
        "credential",
    ]
    .iter()
    .any(|marker| key.contains(marker))
}
