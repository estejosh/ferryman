//! A tiny stand-in for a Hive API node: enough JSON-RPC for the rescue channel's tests and
//! for a drill before the fleet has a real Hive account.
//!
//! It speaks `condenser_api.get_account_history`, `get_dynamic_global_properties` and
//! `broadcast_transaction`, keeps what is broadcast in memory, and records an operation
//! under every account in its `required_posting_auths`, as a real node does. It does NOT
//! validate signatures against account authorities (the readers do the real checking: a
//! record counts only if the master signed it), and it is not for the internet.

use std::net::SocketAddr;
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::{Arc, Mutex};

use anyhow::{Context, Result};
use axum::extract::State;
use axum::routing::post;
use axum::{Json, Router};
use chrono::Utc;
use serde_json::{Value, json};

#[derive(Default)]
struct Inner {
    /// (account, entry as `get_account_history` returns it)
    entries: Vec<(String, Value)>,
    head: u64,
    broadcasts: u64,
}

struct Shared {
    inner: Mutex<Inner>,
    down: AtomicBool,
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

    /// How many transactions have been broadcast to it.
    #[must_use]
    pub fn broadcasts(&self) -> u64 {
        self.shared
            .inner
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner)
            .broadcasts
    }

    /// Put an operation in `account`'s history directly, as anyone on the chain could.
    pub fn inject(&self, account: &str, op_id: &str, json_str: &str) {
        let mut inner = self
            .shared
            .inner
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner);
        push(&mut inner, account, op_id, json_str, "injected");
    }

    /// Every custom_json recorded under `account`: `(id, json)`.
    #[must_use]
    pub fn ops_for(&self, account: &str) -> Vec<(String, String)> {
        self.shared
            .inner
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner)
            .entries
            .iter()
            .filter(|(a, _)| a == account)
            .filter_map(|(_, e)| {
                let data = e.pointer("/1/op/1")?;
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

fn push(inner: &mut Inner, account: &str, op_id: &str, json_str: &str, trx: &str) {
    inner.head += 1;
    let index = inner.entries.len() as u64 + 1;
    let entry = json!([index, {
        "trx_id": format!("{trx}{index:036x}"),
        "block": inner.head,
        "trx_in_block": 0,
        "op_in_trx": 0,
        "virtual_op": 0,
        "timestamp": Utc::now().format("%Y-%m-%dT%H:%M:%S").to_string(),
        "op": ["custom_json", {
            "required_auths": [],
            "required_posting_auths": [account],
            "id": op_id,
            "json": json_str,
        }],
    }]);
    inner.entries.push((account.to_owned(), entry));
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
    let method = request.get("method").and_then(Value::as_str).unwrap_or("");
    let params = request.get("params").cloned().unwrap_or(json!([]));
    let mut inner = shared
        .inner
        .lock()
        .unwrap_or_else(std::sync::PoisonError::into_inner);
    let result: Result<Value, String> = match method {
        "condenser_api.get_account_history" => {
            let account = params.get(0).and_then(Value::as_str).unwrap_or("");
            let limit = params.get(2).and_then(Value::as_u64).unwrap_or(10) as usize;
            let mine: Vec<&Value> = inner
                .entries
                .iter()
                .filter(|(a, _)| a == account)
                .map(|(_, e)| e)
                .collect();
            let from = mine.len().saturating_sub(limit);
            Ok(Value::Array(
                mine[from..].iter().map(|e| (*e).clone()).collect(),
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
                        push(&mut inner, &account, op_id, json_str, "tx");
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
