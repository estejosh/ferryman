//! A tiny stand-in for a Hive API node: enough JSON-RPC for the rescue channel's tests and
//! for a drill before the fleet has a real Hive account.
//!
//! It speaks `condenser_api.get_account_history` (with `start`, `limit` and the operation
//! filter, as a node does), `get_accounts` (for accounts given to [`MockHive::authorize`]
//! or [`MockHive::set_account`]), `get_dynamic_global_properties` and
//! `broadcast_transaction`, keeps what is broadcast in memory, and records an operation
//! under every account in its `required_posting_auths`, as a real node does. It does NOT
//! validate signatures against account authorities (the readers do the real checking: a
//! record counts only if the master signed it), and it is not for the internet.

use std::collections::BTreeMap;
use std::net::SocketAddr;
use std::sync::atomic::{AtomicBool, AtomicU64, Ordering};
use std::sync::{Arc, Mutex};

use anyhow::{Context, Result};
use axum::extract::State;
use axum::routing::post;
use axum::{Json, Router};
use chrono::{DateTime, Utc};
use serde_json::{Value, json};

#[derive(Default)]
struct Inner {
    /// Each account's history, oldest first; an entry's index is its place in the list,
    /// as `get_account_history` returns it: `[index, {trx_id, block, ..., op}]`.
    history: BTreeMap<String, Vec<Value>>,
    /// Accounts `get_accounts` knows.
    accounts: BTreeMap<String, Value>,
    head: u64,
    broadcasts: u64,
}

struct Shared {
    inner: Mutex<Inner>,
    down: AtomicBool,
    /// Answer every call with a body larger than any reader should accept.
    oversize: AtomicBool,
    history_calls: AtomicU64,
}

/// A running mock node.
pub struct MockHive {
    addr: SocketAddr,
    shared: Arc<Shared>,
    task: tokio::task::JoinHandle<()>,
}

impl Drop for MockHive {
    fn drop(&mut self) {
        self.task.abort();
    }
}

impl MockHive {
    /// Listen on `bind` (`127.0.0.1:0` for any free port).
    ///
    /// # Errors
    /// The address cannot be bound.
    pub async fn start(bind: &str) -> Result<Self> {
        let shared = Arc::new(Shared {
            inner: Mutex::new(Inner {
                head: 90_000_000,
                ..Inner::default()
            }),
            down: AtomicBool::new(false),
            oversize: AtomicBool::new(false),
            history_calls: AtomicU64::new(0),
        });
        let listener = tokio::net::TcpListener::bind(bind)
            .await
            .with_context(|| format!("bind {bind}"))?;
        let addr = listener.local_addr()?;
        let app = Router::new()
            .route("/", post(rpc))
            .with_state(Arc::clone(&shared));
        let task = tokio::spawn(async move {
            let _ = axum::serve(listener, app).await;
        });
        Ok(Self { addr, shared, task })
    }

    /// `http://127.0.0.1:port`
    #[must_use]
    pub fn url(&self) -> String {
        format!("http://{}", self.addr)
    }

    #[must_use]
    pub fn addr(&self) -> SocketAddr {
        self.addr
    }

    /// Make the node answer every request with HTTP 503 (or stop doing so).
    pub fn set_down(&self, down: bool) {
        self.shared.down.store(down, Ordering::SeqCst);
    }

    /// Make the node answer every request with a body of several megabytes (or stop).
    pub fn set_oversize(&self, oversize: bool) {
        self.shared.oversize.store(oversize, Ordering::SeqCst);
    }

    /// How many `get_account_history` calls have been made.
    #[must_use]
    pub fn history_calls(&self) -> u64 {
        self.shared.history_calls.load(Ordering::SeqCst)
    }

    /// How many transactions have been broadcast to it.
    #[must_use]
    pub fn broadcasts(&self) -> u64 {
        self.lock().broadcasts
    }

    fn lock(&self) -> std::sync::MutexGuard<'_, Inner> {
        self.shared
            .inner
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner)
    }

    /// Put an operation in `account`'s history directly, as anyone on the chain could.
    pub fn inject(&self, account: &str, op_id: &str, json_str: &str) {
        self.inject_at(account, op_id, json_str, Utc::now());
    }

    /// As [`Self::inject`], dated `at`.
    pub fn inject_at(&self, account: &str, op_id: &str, json_str: &str, at: DateTime<Utc>) {
        let mut inner = self.lock();
        push_custom_json(&mut inner, account, op_id, json_str, "injected", at);
    }

    /// Put `count` dust transfers to `account` in its history: what anyone can do to bury
    /// the operations that matter.
    pub fn inject_transfers(&self, account: &str, count: usize) {
        let mut inner = self.lock();
        for _ in 0..count {
            inner.head += 1;
            let head = inner.head;
            let list = inner.history.entry(account.to_owned()).or_default();
            let index = list.len();
            list.push(json!([index, {
                "trx_id": format!("dust{index:036x}"),
                "block": head,
                "trx_in_block": 0,
                "op_in_trx": 0,
                "virtual_op": 0,
                "timestamp": Utc::now().format("%Y-%m-%dT%H:%M:%S").to_string(),
                "op": ["transfer", {
                    "from": "spammer", "to": account, "amount": "0.001 HIVE", "memo": ""
                }],
            }]));
        }
    }

    /// Say that `posting_key` (an `STM...` public key) is a posting key of `account`, and
    /// that `account` has other, different owner, active and memo keys.
    pub fn authorize(&self, account: &str, posting_key: &str) {
        let other = "STM5PAqRSn2vPZYfuqUQJJLs6QnMGUhgdbJP71QTpGS1aZWTpXDqa";
        self.set_account(
            account,
            json!({
                "name": account,
                "owner": {"weight_threshold": 1, "account_auths": [], "key_auths": [[other, 1]]},
                "active": {"weight_threshold": 1, "account_auths": [], "key_auths": [[other, 1]]},
                "posting": {"weight_threshold": 1, "account_auths": [],
                            "key_auths": [[posting_key, 1]]},
                "memo_key": other,
            }),
        );
    }

    /// As [`Self::authorize`] for a key held here (a drill's or a test's).
    pub fn authorize_key(&self, account: &str, key: &crate::tx::PostingKey) {
        self.authorize(account, &key.mock_public_key_string());
    }

    /// What `get_accounts` returns for `account`.
    pub fn set_account(&self, account: &str, value: Value) {
        self.lock().accounts.insert(account.to_owned(), value);
    }

    /// Every custom_json recorded under `account`: `(id, json)`.
    #[must_use]
    pub fn ops_for(&self, account: &str) -> Vec<(String, String)> {
        self.lock()
            .history
            .get(account)
            .into_iter()
            .flatten()
            .filter_map(|e| {
                let data = e.pointer("/1/op/1")?;
                e.pointer("/1/op/0")
                    .and_then(Value::as_str)
                    .filter(|n| *n == "custom_json")?;
                Some((
                    data.get("id")?.as_str()?.to_owned(),
                    data.get("json")?.as_str()?.to_owned(),
                ))
            })
            .collect()
    }

    /// Serve until the process ends (for `ferry rescue hive mock`).
    pub async fn forever(self) {
        std::future::pending::<()>().await;
        drop(self);
    }
}

fn push_custom_json(
    inner: &mut Inner,
    account: &str,
    op_id: &str,
    json_str: &str,
    trx: &str,
    at: DateTime<Utc>,
) {
    inner.head += 1;
    let head = inner.head;
    let list = inner.history.entry(account.to_owned()).or_default();
    let index = list.len();
    list.push(json!([index, {
        "trx_id": format!("{trx}{index:036x}"),
        "block": head,
        "trx_in_block": 0,
        "op_in_trx": 0,
        "virtual_op": 0,
        "timestamp": at.format("%Y-%m-%dT%H:%M:%S").to_string(),
        "op": ["custom_json", {
            "required_auths": [],
            "required_posting_auths": [account],
            "id": op_id,
            "json": json_str,
        }],
    }]));
}

/// A real node's operation numbers for the two kinds of operation the mock holds.
fn op_number(name: &str) -> u32 {
    match name {
        "transfer" => 2,
        "custom_json" => 18,
        _ => 63,
    }
}

async fn rpc(
    State(shared): State<Arc<Shared>>,
    Json(request): Json<Value>,
) -> (axum::http::StatusCode, Json<Value>) {
    use axum::http::StatusCode;
    if shared.down.load(Ordering::SeqCst) {
        return (StatusCode::SERVICE_UNAVAILABLE, Json(json!({})));
    }
    let id = request.get("id").cloned().unwrap_or(json!(1));
    if shared.oversize.load(Ordering::SeqCst) {
        let filler = "x".repeat(3 * 1024 * 1024);
        return (
            StatusCode::OK,
            Json(json!({ "jsonrpc": "2.0", "id": id, "result": [filler] })),
        );
    }
    let method = request.get("method").and_then(Value::as_str).unwrap_or("");
    let params = request.get("params").cloned().unwrap_or(json!([]));
    let mut inner = shared
        .inner
        .lock()
        .unwrap_or_else(std::sync::PoisonError::into_inner);
    let result: Result<Value, String> = match method {
        "condenser_api.get_account_history" => {
            shared.history_calls.fetch_add(1, Ordering::SeqCst);
            let account = params.get(0).and_then(Value::as_str).unwrap_or("");
            let all = inner.history.get(account).cloned().unwrap_or_default();
            let start = params.get(1).and_then(Value::as_i64).unwrap_or(-1);
            let limit = params.get(2).and_then(Value::as_u64).unwrap_or(10) as usize;
            let low = params.get(3).and_then(Value::as_u64);
            let high = params.get(4).and_then(Value::as_u64);
            if all.is_empty() {
                Ok(json!([]))
            } else if limit == 0 || limit > 1000 {
                Err("limit must be between 1 and 1000".to_owned())
            } else {
                let last = all.len() - 1;
                let start = usize::try_from(start).map_or(last, |s| s.min(last));
                if start + 1 < limit {
                    Err("start must be greater than or equal to limit-1".to_owned())
                } else {
                    // The range is by place in the history; the filter then picks from it.
                    let window = &all[start + 1 - limit..=start];
                    let filtering = low.is_some() || high.is_some();
                    let picked = window.iter().filter(|entry| {
                        if !filtering {
                            return true;
                        }
                        let number = op_number(
                            entry
                                .pointer("/1/op/0")
                                .and_then(Value::as_str)
                                .unwrap_or(""),
                        );
                        if number < 64 {
                            low.is_some_and(|bits| bits & (1 << number) != 0)
                        } else {
                            high.is_some_and(|bits| bits & (1 << (number - 64)) != 0)
                        }
                    });
                    Ok(Value::Array(picked.cloned().collect()))
                }
            }
        }
        "condenser_api.get_accounts" => {
            let names = params
                .get(0)
                .and_then(Value::as_array)
                .cloned()
                .unwrap_or_default();
            Ok(Value::Array(
                names
                    .iter()
                    .filter_map(Value::as_str)
                    .filter_map(|name| inner.accounts.get(name).cloned())
                    .collect(),
            ))
        }
        "condenser_api.get_dynamic_global_properties" => {
            let head = inner.head;
            Ok(json!({
                "head_block_number": head,
                "head_block_id": format!("{:08x}{}", head as u32, "ab".repeat(16)),
                "time": Utc::now().format("%Y-%m-%dT%H:%M:%S").to_string(),
            }))
        }
        "condenser_api.broadcast_transaction"
        | "condenser_api.broadcast_transaction_synchronous" => {
            let tx = params.get(0).cloned().unwrap_or(Value::Null);
            let signed = tx
                .get("signatures")
                .and_then(Value::as_array)
                .is_some_and(|s| {
                    !s.is_empty() && s.iter().all(|x| x.as_str().is_some_and(|x| x.len() == 130))
                });
            if !signed {
                Err("missing or malformed signature".to_owned())
            } else {
                let ops = tx
                    .get("operations")
                    .and_then(Value::as_array)
                    .cloned()
                    .unwrap_or_default();
                for op in ops {
                    let (Some("custom_json"), Some(data)) =
                        (op.get(0).and_then(Value::as_str), op.get(1))
                    else {
                        continue;
                    };
                    let op_id = data.get("id").and_then(Value::as_str).unwrap_or("");
                    let json_str = data.get("json").and_then(Value::as_str).unwrap_or("");
                    let accounts: Vec<String> = data
                        .get("required_posting_auths")
                        .and_then(Value::as_array)
                        .map(|a| {
                            a.iter()
                                .filter_map(|v| v.as_str().map(str::to_owned))
                                .collect()
                        })
                        .unwrap_or_default();
                    for account in accounts {
                        push_custom_json(&mut inner, &account, op_id, json_str, "tx", Utc::now());
                    }
                }
                inner.broadcasts += 1;
                Ok(json!({}))
            }
        }
        other => Err(format!("method {other} not found")),
    };
    drop(inner);
    let body = match result {
        Ok(value) => json!({ "jsonrpc": "2.0", "id": id, "result": value }),
        Err(message) => {
            json!({ "jsonrpc": "2.0", "id": id, "error": { "code": -32000, "message": message } })
        }
    };
    (StatusCode::OK, Json(body))
}
