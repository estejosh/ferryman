//! Telegram approval gate: lets the configured operator (`approver_id`) approve or deny
//! a `pending_approval` job from their phone over a Telegram bot, without the bridge or
//! any worker ever holding an approval credential.
//!
//! Security model: the bot token is the only secret here, and it never leaves this
//! process — it is read from env/keyring by the caller and handed to `TelegramGate::
//! from_config`, which is the last place it is held before being folded into outbound
//! request URLs. **The token must never be logged.** Because `reqwest::Error`'s Display
//! impl includes the request URL (and thus the token embedded in it), every error path in
//! this module logs a fixed message only — never the error value itself.
//!
//! Fails closed by construction: `from_config` returns `None` unless both a bot token and
//! an approver id are configured, and the caller (`main.rs`) simply does not spawn the
//! gate in that case. No approval path opens; jobs stay parked.

use std::time::Duration;

use orchestrator_core::SqliteStore;
use serde::Deserialize;
use serde_json::{Value, json};
use tokio::task::JoinHandle;

const DEFAULT_POLL_TIMEOUT_SECONDS: i64 = 25;
const DEFAULT_NOTIFY_INTERVAL: Duration = Duration::from_secs(2);
const DEFAULT_POLL_IDLE_BACKOFF: Duration = Duration::from_millis(200);
const POLL_ERROR_BACKOFF: Duration = Duration::from_secs(5);

pub struct TelegramGate {
    client: reqwest::Client,
    api_base: String,
    bot_token: String,
    approver_id: i64,
    chat_id: i64,
    notify_interval: Duration,
    poll_timeout_secs: i64,
    poll_idle_backoff: Duration,
}

impl TelegramGate {
    /// Only returns `Some` when both a bot token and an approver id are configured —
    /// see the module-level fail-closed note. `chat_id` defaults to `approver_id` (a DM).
    pub fn from_config(
        bot_token: Option<String>,
        approver_id: Option<i64>,
        chat_id: Option<i64>,
    ) -> Option<Self> {
        let bot_token = bot_token.filter(|token| !token.is_empty())?;
        let approver_id = approver_id?;
        Some(Self {
            client: reqwest::Client::new(),
            api_base: "https://api.telegram.org".to_string(),
            bot_token,
            approver_id,
            chat_id: chat_id.unwrap_or(approver_id),
            notify_interval: DEFAULT_NOTIFY_INTERVAL,
            poll_timeout_secs: DEFAULT_POLL_TIMEOUT_SECONDS,
            poll_idle_backoff: DEFAULT_POLL_IDLE_BACKOFF,
        })
    }

    #[cfg(test)]
    fn with_test_tuning(mut self, api_base: String) -> Self {
        self.api_base = api_base;
        self.notify_interval = Duration::from_millis(20);
        self.poll_timeout_secs = 1;
        self.poll_idle_backoff = Duration::from_millis(20);
        self
    }

    /// Spawns the two independent background loops: notify-on-park and the getUpdates
    /// long-poll receiver. They share the store and the Telegram HTTP client but run on
    /// their own schedules so a slow long-poll never delays notifying a newly parked job.
    pub fn spawn(self, store: SqliteStore) -> (JoinHandle<()>, JoinHandle<()>) {
        let telegram = TelegramClient {
            client: self.client,
            api_base: self.api_base,
            bot_token: self.bot_token,
            chat_id: self.chat_id,
        };
        let approver_id = self.approver_id;
        let notify_telegram = telegram.clone();
        let notify_store = store.clone();
        let notify_interval = self.notify_interval;
        let notify_handle = tokio::spawn(async move {
            notify_loop(notify_telegram, notify_store, notify_interval).await;
        });
        let poll_timeout_secs = self.poll_timeout_secs;
        let poll_idle_backoff = self.poll_idle_backoff;
        let poll_handle = tokio::spawn(async move {
            poll_loop(
                telegram,
                store,
                approver_id,
                poll_timeout_secs,
                poll_idle_backoff,
            )
            .await;
        });
        (notify_handle, poll_handle)
    }
}

#[derive(Clone)]
struct TelegramClient {
    client: reqwest::Client,
    api_base: String,
    bot_token: String,
    chat_id: i64,
}

impl TelegramClient {
    fn url(&self, method: &str) -> String {
        format!("{}/bot{}/{method}", self.api_base, self.bot_token)
    }

    async fn send_message(&self, text: &str) -> anyhow::Result<()> {
        self.client
            .post(self.url("sendMessage"))
            .json(&json!({"chat_id": self.chat_id, "text": text}))
            .send()
            .await?
            .error_for_status()?;
        Ok(())
    }

    async fn get_updates(&self, offset: i64, timeout_secs: i64) -> anyhow::Result<Vec<TgUpdate>> {
        let response = self
            .client
            .get(self.url("getUpdates"))
            .query(&[
                ("offset", offset.to_string()),
                ("timeout", timeout_secs.to_string()),
            ])
            .timeout(Duration::from_secs(
                u64::try_from(timeout_secs + 10).unwrap_or(35),
            ))
            .send()
            .await?
            .error_for_status()?
            .json::<TgGetUpdatesResponse>()
            .await?;
        if !response.ok {
            anyhow::bail!("telegram getUpdates responded ok=false");
        }
        Ok(response.result)
    }
}

#[derive(Deserialize)]
struct TgGetUpdatesResponse {
    ok: bool,
    #[serde(default)]
    result: Vec<TgUpdate>,
}
#[derive(Deserialize)]
struct TgUpdate {
    update_id: i64,
    #[serde(default)]
    message: Option<TgMessage>,
}
#[derive(Deserialize)]
struct TgMessage {
    #[serde(default)]
    text: Option<String>,
    from: TgUser,
    chat: TgChat,
}
#[derive(Deserialize)]
struct TgUser {
    id: i64,
}
#[derive(Deserialize)]
struct TgChat {
    id: i64,
}

async fn notify_loop(client: TelegramClient, store: SqliteStore, interval: Duration) {
    let mut ticker = tokio::time::interval(interval);
    loop {
        ticker.tick().await;
        let pending = match store.jobs_pending_telegram_notification() {
            Ok(jobs) => jobs,
            Err(_) => {
                tracing::warn!("telegram: failed to query pending-approval jobs");
                continue;
            }
        };
        for job in pending {
            let text = format!(
                "Approval requested\nproject: {}\njob: {}\naction: {}\n\n/approve_{} to approve\n/deny_{} to deny",
                job.project_id,
                job.id,
                describe_action(&job.input),
                job.id,
                job.id
            );
            match client.send_message(&text).await {
                Ok(()) => {
                    if store
                        .mark_telegram_notified(&job.project_id, &job.id)
                        .is_err()
                    {
                        tracing::warn!(job_id = %job.id, "telegram: sent DM but failed to record telegram.notified event");
                    }
                }
                Err(_) => {
                    tracing::warn!(job_id = %job.id, "telegram: failed to send approval DM, will retry next tick");
                }
            }
        }
    }
}

fn describe_action(input: &Value) -> String {
    if let Some(description) = input.get("description").and_then(Value::as_str) {
        return description.to_string();
    }
    let compact = serde_json::to_string(input).unwrap_or_default();
    compact.chars().take(300).collect()
}

enum GateAction {
    Approve,
    Deny,
}

fn parse_command(text: &str) -> Option<(GateAction, String)> {
    let first_token = text.split_whitespace().next()?;
    let first_token = first_token.split('@').next()?;
    let body = first_token.strip_prefix('/')?;
    if let Some(job_id) = body.strip_prefix("approve_") {
        return Some((GateAction::Approve, job_id.to_string()));
    }
    if let Some(job_id) = body.strip_prefix("deny_") {
        return Some((GateAction::Deny, job_id.to_string()));
    }
    None
}

async fn poll_loop(
    client: TelegramClient,
    store: SqliteStore,
    approver_id: i64,
    timeout_secs: i64,
    idle_backoff: Duration,
) {
    let mut offset: i64 = 0;
    loop {
        let updates = match client.get_updates(offset, timeout_secs).await {
            Ok(updates) => updates,
            Err(_) => {
                tracing::warn!("telegram: getUpdates failed, backing off");
                tokio::time::sleep(POLL_ERROR_BACKOFF).await;
                continue;
            }
        };
        if updates.is_empty() {
            tokio::time::sleep(idle_backoff).await;
            continue;
        }
        for update in updates {
            offset = offset.max(update.update_id + 1);
            let Some(message) = update.message else {
                continue;
            };
            let Some(text) = message.text.as_deref() else {
                continue;
            };
            if message.from.id != approver_id || message.chat.id != client.chat_id {
                tracing::warn!(
                    from_id = message.from.id,
                    chat_id = message.chat.id,
                    "telegram: rejected non-approver command"
                );
                continue;
            }
            let Some((action, job_id)) = parse_command(text) else {
                continue;
            };
            let outcome = match action {
                GateAction::Approve => store.telegram_approve(&job_id, approver_id),
                GateAction::Deny => store.telegram_deny(&job_id, approver_id),
            };
            let reply = match (action, outcome) {
                (GateAction::Approve, Ok(Some(job))) => {
                    format!("approved — job {} is now queued", job.id)
                }
                (GateAction::Deny, Ok(Some(job))) => {
                    format!("denied — job {} will not run", job.id)
                }
                (_, Ok(None)) => "no such pending gate".to_string(),
                (_, Err(_)) => {
                    tracing::warn!(job_id = %job_id, "telegram: store error resolving gate command");
                    "internal error processing gate command".to_string()
                }
            };
            if client.send_message(&reply).await.is_err() {
                tracing::warn!("telegram: failed to send gate-command reply");
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use axum::{
        Json, Router,
        extract::{Path, State},
        routing::{get, post},
    };
    use orchestrator_core::{JobStatus, NewJob, PolicyEnvelope};
    use std::sync::{Arc, Mutex};
    use tokio::net::TcpListener;

    #[derive(Clone, Default)]
    struct FakeTelegram {
        sent: Arc<Mutex<Vec<Value>>>,
        pending_updates: Arc<Mutex<Vec<Value>>>,
    }

    async fn fake_get_updates(
        State(fake): State<FakeTelegram>,
        Path(_token): Path<String>,
    ) -> Json<Value> {
        let mut pending = fake.pending_updates.lock().unwrap();
        let drained: Vec<Value> = pending.drain(..).collect();
        Json(json!({"ok": true, "result": drained}))
    }
    async fn fake_send_message(
        State(fake): State<FakeTelegram>,
        Path(_token): Path<String>,
        Json(body): Json<Value>,
    ) -> Json<Value> {
        fake.sent.lock().unwrap().push(body);
        Json(json!({"ok": true, "result": {"message_id": 1}}))
    }

    async fn start_fake_server() -> (String, FakeTelegram) {
        let fake = FakeTelegram::default();
        let app = Router::new()
            .route("/bot{token}/getUpdates", get(fake_get_updates))
            .route("/bot{token}/sendMessage", post(fake_send_message))
            .with_state(fake.clone());
        let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let address = listener.local_addr().unwrap();
        tokio::spawn(async move {
            axum::serve(listener, app).await.unwrap();
        });
        (format!("http://{address}"), fake)
    }

    fn test_store() -> SqliteStore {
        let dir = std::env::temp_dir().join(format!("telegram-gate-test-{}", uuid::Uuid::new_v4()));
        std::fs::create_dir_all(&dir).unwrap();
        let store = SqliteStore::open(dir.join("bridge.db")).unwrap();
        store.create_project("p", "Project", "token", "").unwrap();
        store
    }

    fn gated_job(store: &SqliteStore, description: &str) -> orchestrator_core::Job {
        store
            .submit_job(
                "p",
                NewJob {
                    input: json!({"description": description}),
                    policy: PolicyEnvelope::default(),
                    requires_approval: true,
                    max_attempts: 1,
                    idempotency_key: None,
                    approval_ttl_seconds: None,
                },
            )
            .unwrap()
    }

    async fn wait_until(mut check: impl FnMut() -> bool, timeout: Duration) -> bool {
        let start = tokio::time::Instant::now();
        while start.elapsed() < timeout {
            if check() {
                return true;
            }
            tokio::time::sleep(Duration::from_millis(20)).await;
        }
        check()
    }

    #[test]
    fn from_config_fails_closed_without_token_or_approver_id() {
        assert!(TelegramGate::from_config(None, Some(1), None).is_none());
        assert!(TelegramGate::from_config(Some("tok".into()), None, None).is_none());
        assert!(TelegramGate::from_config(Some(String::new()), Some(1), None).is_none());
        assert!(TelegramGate::from_config(None, None, None).is_none());
        assert!(TelegramGate::from_config(Some("tok".into()), Some(1), None).is_some());
    }

    #[tokio::test]
    async fn notify_loop_dms_once_per_parked_job() {
        let (base, fake) = start_fake_server().await;
        let store = test_store();
        let job = gated_job(&store, "dry-run smoke test");
        let gate = TelegramGate::from_config(Some("t".into()), Some(999), None)
            .unwrap()
            .with_test_tuning(base);
        let (notify, poll) = gate.spawn(store.clone());

        let notified = wait_until(
            || {
                fake.sent
                    .lock()
                    .unwrap()
                    .iter()
                    .any(|m| m["text"].as_str().unwrap_or("").contains(&job.id))
            },
            Duration::from_secs(3),
        )
        .await;
        assert!(notified, "expected an approval DM mentioning the job id");
        assert_eq!(
            store.get_job("p", &job.id).unwrap().unwrap().status,
            JobStatus::PendingApproval
        );
        notify.abort();
        poll.abort();
    }

    #[tokio::test]
    async fn authorized_approve_command_queues_the_job() {
        let (base, fake) = start_fake_server().await;
        let store = test_store();
        let job = gated_job(&store, "dry-run smoke test");
        fake.pending_updates.lock().unwrap().push(json!({
            "update_id": 1,
            "message": {"text": format!("/approve_{}", job.id), "from": {"id": 999}, "chat": {"id": 999}}
        }));
        let gate = TelegramGate::from_config(Some("t".into()), Some(999), None)
            .unwrap()
            .with_test_tuning(base);
        let (notify, poll) = gate.spawn(store.clone());

        let approved = wait_until(
            || {
                matches!(
                    store.get_job("p", &job.id).unwrap().map(|j| j.status),
                    Some(JobStatus::Queued)
                )
            },
            Duration::from_secs(3),
        )
        .await;
        assert!(approved, "authorized /approve_<id> must queue the job");
        let events = store
            .timeline("p", 0, 50, Some(&job.id), Some("job.approved"))
            .unwrap();
        assert_eq!(events.len(), 1);
        assert_eq!(events[0].payload["approver_telegram_id"], json!(999));
        notify.abort();
        poll.abort();
    }

    #[tokio::test]
    async fn deny_command_cancels_the_job() {
        let (base, fake) = start_fake_server().await;
        let store = test_store();
        let job = gated_job(&store, "dry-run smoke test");
        fake.pending_updates.lock().unwrap().push(json!({
            "update_id": 1,
            "message": {"text": format!("/deny_{}", job.id), "from": {"id": 999}, "chat": {"id": 999}}
        }));
        let gate = TelegramGate::from_config(Some("t".into()), Some(999), None)
            .unwrap()
            .with_test_tuning(base);
        let (notify, poll) = gate.spawn(store.clone());

        let denied = wait_until(
            || {
                matches!(
                    store.get_job("p", &job.id).unwrap().map(|j| j.status),
                    Some(JobStatus::Cancelled)
                )
            },
            Duration::from_secs(3),
        )
        .await;
        assert!(
            denied,
            "authorized /deny_<id> must cancel the job so it never runs"
        );
        notify.abort();
        poll.abort();
    }

    /// Negative test (dry-run acceptance criterion b): a command from ANY id other than
    /// the configured approver must be dropped — the job must not move.
    #[tokio::test]
    async fn command_from_a_different_telegram_user_is_ignored() {
        let (base, fake) = start_fake_server().await;
        let store = test_store();
        let job = gated_job(&store, "dry-run smoke test");
        fake.pending_updates.lock().unwrap().push(json!({
            "update_id": 1,
            "message": {"text": format!("/approve_{}", job.id), "from": {"id": 12345}, "chat": {"id": 12345}}
        }));
        let gate = TelegramGate::from_config(Some("t".into()), Some(999), None)
            .unwrap()
            .with_test_tuning(base);
        let (notify, poll) = gate.spawn(store.clone());

        // Give the poller several ticks to (wrongly) act, then assert it did not.
        tokio::time::sleep(Duration::from_millis(300)).await;
        assert_eq!(
            store.get_job("p", &job.id).unwrap().unwrap().status,
            JobStatus::PendingApproval,
            "a command from a non-approver id must never approve/deny a job"
        );
        assert!(
            fake.sent.lock().unwrap().iter().all(|m| !m["text"]
                .as_str()
                .unwrap_or("")
                .starts_with("approved")
                && !m["text"].as_str().unwrap_or("").starts_with("denied")),
            "must not reply as if the command were honored"
        );
        notify.abort();
        poll.abort();
    }
}
