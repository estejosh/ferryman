//! Hive over JSON-RPC on HTTPS, the little of it this needs.
//!
//! Reads go to several public API nodes in turn and are merged: no node is trusted for
//! content (every record is signed and sealed), only used to find it. A node that is down,
//! slow or lagging costs one timeout, not the channel. Writes try nodes in turn until one
//! accepts the signed transaction.

use std::collections::BTreeMap;
use std::time::Duration;

use anyhow::{Context, Result, bail};
use chrono::{Duration as ChronoDuration, Utc};
use serde_json::{Value, json};

use crate::tx::{CustomJson, MAINNET_CHAIN_ID, PostingKey, Transaction, parse_hive_time};

/// One `custom_json` operation read from an account's history.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct HistoryOp {
    pub index: u64,
    pub trx_id: String,
    pub block: u64,
    pub timestamp: String,
    pub id: String,
    pub json: String,
    pub posting_auths: Vec<String>,
}

/// What a read found and how.
#[derive(Debug, Default)]
pub struct Read {
    pub ops: Vec<HistoryOp>,
    /// Nodes that answered.
    pub answered: Vec<String>,
    /// Nodes that did not, with why.
    pub failed: Vec<(String, String)>,
}

/// What a broadcast did.
#[derive(Debug)]
pub struct Broadcast {
    pub node: String,
    pub trx_id: String,
}

#[derive(Debug, Clone)]
pub struct HiveClient {
    nodes: Vec<String>,
    http: reqwest::Client,
    chain_id: String,
    /// Stop reading after this many nodes have answered (merge their results).
    min_ok: usize,
}

impl HiveClient {
    /// A client over `nodes`.
    ///
    /// # Panics
    /// The HTTP client cannot be built (no TLS backend), which is a build problem.
    #[must_use]
    pub fn new(nodes: Vec<String>) -> Self {
        let http = reqwest::Client::builder()
            .timeout(Duration::from_secs(10))
            .connect_timeout(Duration::from_secs(5))
            .user_agent(concat!("ferryman-hive-rescue/", env!("CARGO_PKG_VERSION")))
            .build()
            .expect("an HTTP client");
        Self {
            nodes,
            http,
            chain_id: MAINNET_CHAIN_ID.to_owned(),
            min_ok: 2,
        }
    }

    /// Use another chain id (a test chain).
    #[must_use]
    pub fn with_chain_id(mut self, chain_id: &str) -> Self {
        chain_id.clone_into(&mut self.chain_id);
        self
    }

    /// Stop after this many answering nodes (1 reads from the first that answers).
    #[must_use]
    pub fn with_min_ok(mut self, n: usize) -> Self {
        self.min_ok = n.max(1);
        self
    }

    #[must_use]
    pub fn nodes(&self) -> &[String] {
        &self.nodes
    }

    async fn call(&self, node: &str, method: &str, params: Value) -> Result<Value> {
        let response = self
            .http
            .post(node)
            .json(&json!({ "jsonrpc": "2.0", "method": method, "params": params, "id": 1 }))
            .send()
            .await
            .context("no answer")?;
        let status = response.status();
        if !status.is_success() {
            bail!("HTTP {status}");
        }
        let body: Value = response.json().await.context("not JSON")?;
        if let Some(error) = body.get("error") {
            let message = error
                .get("message")
                .and_then(Value::as_str)
                .unwrap_or("an error");
            bail!("{}", message.chars().take(200).collect::<String>());
        }
        body.get("result").cloned().context("no result")
    }

    /// The `custom_json` operations with id `op_id` in the last `limit` entries of
    /// `account`'s history, merged from the nodes that answer.
    pub async fn read_history(&self, account: &str, op_id: &str, limit: u32) -> Read {
        let mut merged: BTreeMap<(String, u64), HistoryOp> = BTreeMap::new();
        let mut read = Read::default();
        for node in &self.nodes {
            match self
                .call(
                    node,
                    "condenser_api.get_account_history",
                    json!([account, -1, limit.min(1000)]),
                )
                .await
            {
                Ok(result) => {
                    for op in parse_history(&result, op_id) {
                        merged.insert((op.trx_id.clone(), op.index), op);
                    }
                    read.answered.push(node.clone());
                    if read.answered.len() >= self.min_ok {
                        break;
                    }
                }
                Err(error) => read.failed.push((node.clone(), format!("{error:#}"))),
            }
        }
        read.ops = merged.into_values().collect();
        read.ops.sort_by_key(|op| op.index);
        read
    }

    /// Build the transaction for one `custom_json` from a node's current head block.
    ///
    /// # Errors
    /// No node answered with a head block.
    pub async fn build(&self, op: CustomJson) -> Result<Transaction> {
        let mut last = None;
        for node in &self.nodes {
            match self
                .call(
                    node,
                    "condenser_api.get_dynamic_global_properties",
                    json!([]),
                )
                .await
            {
                Ok(props) => match head_reference(&props) {
                    Ok((num, prefix, time)) => {
                        return Ok(Transaction {
                            ref_block_num: num,
                            ref_block_prefix: prefix,
                            expiration: time + ChronoDuration::seconds(60),
                            operations: vec![op],
                        });
                    }
                    Err(error) => last = Some(format!("{node}: {error:#}")),
                },
                Err(error) => last = Some(format!("{node}: {error:#}")),
            }
        }
        bail!(
            "no Hive node gave a head block ({})",
            last.unwrap_or_else(|| "no nodes configured".into())
        )
    }

    /// Sign and broadcast.
    ///
    /// # Errors
    /// No node accepted the transaction; the messages say why for each.
    pub async fn broadcast(&self, tx: &Transaction, key: &PostingKey) -> Result<Broadcast> {
        let signature = tx.sign(key, &self.chain_id)?;
        let rpc = tx.to_rpc(&[signature]);
        let mut failures = Vec::new();
        for node in &self.nodes {
            match self
                .call(node, "condenser_api.broadcast_transaction", json!([rpc]))
                .await
            {
                Ok(_) => {
                    return Ok(Broadcast {
                        node: node.clone(),
                        trx_id: tx.id(),
                    });
                }
                Err(error) => failures.push(format!("{node}: {error:#}")),
            }
        }
        bail!("no Hive node accepted the post: {}", failures.join("; "))
    }
}

/// `(ref_block_num, ref_block_prefix, head time)` from `get_dynamic_global_properties`.
fn head_reference(props: &Value) -> Result<(u16, u32, chrono::DateTime<Utc>)> {
    let number = props
        .get("head_block_number")
        .and_then(Value::as_u64)
        .context("no head_block_number")?;
    let id = props
        .get("head_block_id")
        .and_then(Value::as_str)
        .context("no head_block_id")?;
    let bytes = hex::decode(id).context("head_block_id is not hex")?;
    if bytes.len() < 8 {
        bail!("head_block_id is too short");
    }
    let prefix = u32::from_le_bytes(bytes[4..8].try_into()?);
    let time = parse_hive_time(
        props
            .get("time")
            .and_then(Value::as_str)
            .context("no time")?,
    )?;
    Ok(((number & 0xffff) as u16, prefix, time))
}

/// Pick the `custom_json` operations with `op_id` out of a `get_account_history` result.
fn parse_history(result: &Value, op_id: &str) -> Vec<HistoryOp> {
    let Some(entries) = result.as_array() else {
        return Vec::new();
    };
    entries
        .iter()
        .filter_map(|entry| {
            let index = entry.get(0)?.as_u64()?;
            let item = entry.get(1)?;
            let op = item.get("op")?;
            let (name, data) = match op {
                Value::Array(parts) => (parts.first()?.as_str()?, parts.get(1)?),
                Value::Object(map) => (map.get("type")?.as_str()?, map.get("value")?),
                _ => return None,
            };
            if name != "custom_json" && name != "custom_json_operation" {
                return None;
            }
            if data.get("id")?.as_str()? != op_id {
                return None;
            }
            Some(HistoryOp {
                index,
                trx_id: item.get("trx_id")?.as_str()?.to_owned(),
                block: item.get("block").and_then(Value::as_u64).unwrap_or(0),
                timestamp: item
                    .get("timestamp")
                    .and_then(Value::as_str)
                    .unwrap_or_default()
                    .to_owned(),
                id: op_id.to_owned(),
                json: data.get("json")?.as_str()?.to_owned(),
                posting_auths: data
                    .get("required_posting_auths")
                    .and_then(Value::as_array)
                    .map(|a| {
                        a.iter()
                            .filter_map(|v| v.as_str().map(str::to_owned))
                            .collect()
                    })
                    .unwrap_or_default(),
            })
        })
        .collect()
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn history_picks_only_custom_json_with_our_id() {
        let result = json!([
            [5, {"trx_id": "aa", "block": 10, "timestamp": "2026-10-21T10:00:00",
                 "op": ["custom_json", {"required_auths": [], "required_posting_auths": ["fleet"],
                                        "id": "ferryman-rescue", "json": "{}"}]}],
            [6, {"trx_id": "bb", "block": 11, "timestamp": "2026-10-21T10:00:03",
                 "op": ["custom_json", {"required_auths": [], "required_posting_auths": ["fleet"],
                                        "id": "other", "json": "{}"}]}],
            [7, {"trx_id": "cc", "block": 12, "timestamp": "2026-10-21T10:00:06",
                 "op": ["transfer", {"from": "a", "to": "b"}]}],
        ]);
        let ops = parse_history(&result, "ferryman-rescue");
        assert_eq!(ops.len(), 1);
        assert_eq!(ops[0].trx_id, "aa");
        assert_eq!(ops[0].posting_auths, ["fleet"]);
    }

    #[test]
    fn the_reference_block_comes_from_the_head_block_id() {
        let props = json!({
            "head_block_number": 0x0001_8685_u64,
            "head_block_id": "00018685ddea50c4000000000000000000000000",
            "time": "2026-10-21T22:00:00",
        });
        let (num, prefix, _) = head_reference(&props).unwrap();
        assert_eq!(num, 0x8685);
        assert_eq!(prefix, 0xc450_eadd);
    }
}
