//! Hive over JSON-RPC on HTTPS, the little of it this needs.
//!
//! Reads go to several public API nodes in turn and are merged: no node is trusted for
//! content (every record is signed and sealed), only used to find it. A node that is down,
//! slow or lagging costs one timeout, not the channel. Writes try nodes in turn until one
//! accepts the signed transaction.

use std::collections::BTreeMap;
use std::time::Duration;

use anyhow::{Context, Result, bail};
use chrono::{DateTime, Duration as ChronoDuration, Utc};
use serde_json::{Value, json};

use crate::record::MAX_OP_JSON;
use crate::tx::{CustomJson, MAINNET_CHAIN_ID, PostingKey, Transaction, parse_hive_time};

/// The most a node's answer may weigh before it is dropped unparsed.
pub const MAX_RESPONSE: usize = 1024 * 1024;
/// `operation_filter_low` bit for `custom_json` (operation 18).
const FILTER_CUSTOM_JSON: u64 = 1 << 18;

/// How far back, and how much, a read of an account's history goes.
///
/// Anyone can put entries in an account's history (a dust transfer, say), so the newest
/// entries are no place to look for a record and stop. A read asks the node for
/// `custom_json` operations only and pages back through the history until the caller has
/// what it wants or one of these bounds is reached.
#[derive(Debug, Clone, Copy)]
pub struct Bounds {
    /// Matching operations to look at, at most.
    pub max_ops: usize,
    /// Operations older than this are not looked at.
    pub max_age: ChronoDuration,
    /// History entries asked for per request.
    pub page: u64,
    /// Requests per node, at most (so a history of other things is not walked forever).
    pub max_pages: usize,
}

impl Default for Bounds {
    fn default() -> Self {
        Self {
            max_ops: 2000,
            max_age: ChronoDuration::days(7),
            page: 500,
            max_pages: 40,
        }
    }
}

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
    bounds: Bounds,
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
            bounds: Bounds::default(),
        }
    }

    /// Read history within other bounds.
    #[must_use]
    pub fn with_bounds(mut self, bounds: Bounds) -> Self {
        self.bounds = bounds;
        self
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
        let body: Value =
            serde_json::from_slice(&read_capped(response).await?).context("not JSON")?;
        if let Some(error) = body.get("error") {
            let message = error
                .get("message")
                .and_then(Value::as_str)
                .unwrap_or("an error");
            bail!("{}", message.chars().take(200).collect::<String>());
        }
        body.get("result").cloned().context("no result")
    }

    /// The `custom_json` operations with id `op_id` in `account`'s history (at most
    /// `limit` of them, within the client's bounds), merged from the nodes that answer.
    pub async fn read_history(&self, account: &str, op_id: &str, limit: u32) -> Read {
        let mut bounds = self.bounds;
        bounds.max_ops = bounds.max_ops.min(limit as usize);
        self.read_history_until(account, op_id, Utc::now(), bounds, &|_| false)
            .await
    }

    /// As [`Self::read_history`], paging back from the newest operation; after each page
    /// `done` is shown that page's operations (newest last within a page) and says whether
    /// that is enough, so a record found at once costs one request.
    pub async fn read_history_until(
        &self,
        account: &str,
        op_id: &str,
        now: DateTime<Utc>,
        bounds: Bounds,
        done: &(dyn Fn(&[HistoryOp]) -> bool + Sync),
    ) -> Read {
        let mut merged: BTreeMap<(String, u64), HistoryOp> = BTreeMap::new();
        let mut read = Read::default();
        for node in &self.nodes {
            match self
                .scan_node(node, account, op_id, now, bounds, done)
                .await
            {
                Ok(ops) => {
                    for op in ops {
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

    /// Page back through one node's history of `account`: `custom_json` operations only
    /// (filtered by the node), 500 entries of history per request, stopping when `done`
    /// says so, at a bound, or at the start of the history.
    async fn scan_node(
        &self,
        node: &str,
        account: &str,
        op_id: &str,
        now: DateTime<Utc>,
        bounds: Bounds,
        done: &(dyn Fn(&[HistoryOp]) -> bool + Sync),
    ) -> Result<Vec<HistoryOp>> {
        // The newest entry's index, from an unfiltered one-entry read: a filtered read of
        // the newest entries can come back empty when they are all something else, and
        // then there would be nothing to page back from.
        let head = self
            .call(
                node,
                "condenser_api.get_account_history",
                json!([account, -1, 1]),
            )
            .await?;
        let Some(mut start) = head
            .as_array()
            .and_then(|a| a.last())
            .and_then(|e| e.get(0))
            .and_then(Value::as_u64)
        else {
            return Ok(Vec::new());
        };
        let oldest_wanted = now - bounds.max_age;
        let mut found: Vec<HistoryOp> = Vec::new();
        for _ in 0..bounds.max_pages {
            let limit = bounds.page.min(start + 1).clamp(1, 1000);
            let result = self
                .call(
                    node,
                    "condenser_api.get_account_history",
                    json!([account, start, limit, FILTER_CUSTOM_JSON, 0]),
                )
                .await?;
            let (mut page, oldest) = parse_history(&result, op_id);
            page.retain(|op| match parse_hive_time(&op.timestamp) {
                Ok(time) => time >= oldest_wanted,
                Err(_) => true,
            });
            let enough = done(&page);
            found.extend(page);
            let too_old = oldest.is_some_and(|t| t < oldest_wanted);
            if enough || too_old || found.len() >= bounds.max_ops || limit > start {
                break;
            }
            start -= limit;
        }
        found.truncate(bounds.max_ops.max(1));
        Ok(found)
    }

    /// Whether `key` may post for `account` and is only a posting key.
    ///
    /// The key must be one of the posting keys of `poster` (the account whose key it is;
    /// `account` itself when `poster` is `None`), and must not also be an owner, active or
    /// memo key of it. When `poster` is another account, `account`'s posting authority must
    /// list it. This catches a wrong or too-powerful key being configured; the chain
    /// decides what it can actually do.
    ///
    /// # Errors
    /// The key is not a posting key of the account, or is a stronger key, or no node
    /// could say.
    pub async fn check_posting_key(
        &self,
        account: &str,
        poster: Option<&str>,
        key: &PostingKey,
    ) -> Result<()> {
        let keyholder = poster.filter(|p| !p.is_empty()).unwrap_or(account);
        let names = if keyholder == account {
            vec![account]
        } else {
            vec![account, keyholder]
        };
        let mut last = None;
        for node in &self.nodes {
            match self
                .call(node, "condenser_api.get_accounts", json!([names]))
                .await
            {
                Ok(result) => return posting_key_verdict(&result, account, keyholder, key),
                Err(error) => last = Some(format!("{node}: {error:#}")),
            }
        }
        bail!(
            "no Hive node could say which keys {keyholder} has ({})",
            last.unwrap_or_else(|| "no nodes configured".into())
        )
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

/// Read a response body, refusing one over [`MAX_RESPONSE`] (by its declared length, then
/// by what actually arrives) before it is parsed.
async fn read_capped(mut response: reqwest::Response) -> Result<Vec<u8>> {
    if response
        .content_length()
        .is_some_and(|n| n > MAX_RESPONSE as u64)
    {
        bail!("the answer is over {MAX_RESPONSE} bytes");
    }
    let mut body = Vec::new();
    while let Some(chunk) = response.chunk().await.context("the answer broke off")? {
        if body.len() + chunk.len() > MAX_RESPONSE {
            bail!("the answer is over {MAX_RESPONSE} bytes");
        }
        body.extend_from_slice(&chunk);
    }
    Ok(body)
}

fn key_strings(value: Option<&Value>) -> Vec<&str> {
    value
        .and_then(|auth| auth.get("key_auths"))
        .and_then(Value::as_array)
        .map(|pairs| {
            pairs
                .iter()
                .filter_map(|pair| pair.get(0).and_then(Value::as_str))
                .collect()
        })
        .unwrap_or_default()
}

fn posting_key_verdict(
    accounts: &Value,
    account: &str,
    keyholder: &str,
    key: &PostingKey,
) -> Result<()> {
    let find = |name: &str| {
        accounts
            .as_array()
            .and_then(|all| {
                all.iter()
                    .find(|a| a.get("name").and_then(Value::as_str) == Some(name))
            })
            .with_context(|| format!("no Hive account '{name}'"))
    };
    let holder = find(keyholder)?;
    let stronger = key_strings(holder.get("owner"))
        .into_iter()
        .chain(key_strings(holder.get("active")))
        .chain(holder.get("memo_key").and_then(Value::as_str))
        .any(|stm| key.is_public_key(stm));
    if stronger {
        bail!(
            "refusing to post: the configured key is an owner, active or memo key of {keyholder}, \
             not a posting key. Use a posting key only"
        );
    }
    if !key_strings(holder.get("posting"))
        .into_iter()
        .any(|stm| key.is_public_key(stm))
    {
        bail!("refusing to post: the configured key is not a posting key of {keyholder}");
    }
    if keyholder != account {
        let delegated = find(account)?
            .get("posting")
            .and_then(|p| p.get("account_auths"))
            .and_then(Value::as_array)
            .is_some_and(|pairs| {
                pairs
                    .iter()
                    .any(|pair| pair.get(0).and_then(Value::as_str) == Some(keyholder))
            });
        if !delegated {
            bail!("refusing to post: {account}'s posting authority does not list {keyholder}");
        }
    }
    Ok(())
}

/// Pick the `custom_json` operations with `op_id` out of a `get_account_history` result,
/// and the time of the oldest `custom_json` of any id in it. A `json` over
/// [`MAX_OP_JSON`] is dropped here, before anything copies or parses it.
fn parse_history(result: &Value, op_id: &str) -> (Vec<HistoryOp>, Option<DateTime<Utc>>) {
    let Some(entries) = result.as_array() else {
        return (Vec::new(), None);
    };
    let oldest = entries
        .iter()
        .filter_map(|entry| {
            let time = entry.get(1)?.get("timestamp")?.as_str()?;
            parse_hive_time(time).ok()
        })
        .min();
    let ops = entries
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
            if data.get("json")?.as_str()?.len() > MAX_OP_JSON {
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
        .collect();
    (ops, oldest)
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
        let (ops, oldest) = parse_history(&result, "ferryman-rescue");
        assert_eq!(ops.len(), 1);
        assert_eq!(ops[0].trx_id, "aa");
        assert_eq!(ops[0].posting_auths, ["fleet"]);
        assert_eq!(
            oldest,
            Some(parse_hive_time("2026-10-21T10:00:00").unwrap())
        );
    }

    #[test]
    fn an_oversized_json_is_dropped_before_it_is_copied() {
        let big = "x".repeat(MAX_OP_JSON + 1);
        let ok = "y".repeat(MAX_OP_JSON);
        let result = json!([
            [1, {"trx_id": "aa", "block": 1, "timestamp": "2026-10-21T10:00:00",
                 "op": ["custom_json", {"required_posting_auths": ["f"], "id": "r", "json": big}]}],
            [2, {"trx_id": "bb", "block": 2, "timestamp": "2026-10-21T10:00:01",
                 "op": ["custom_json", {"required_posting_auths": ["f"], "id": "r", "json": ok}]}],
        ]);
        let (ops, _) = parse_history(&result, "r");
        assert_eq!(ops.len(), 1);
        assert_eq!(ops[0].trx_id, "bb");
    }

    #[test]
    fn posting_key_checks() {
        let key =
            PostingKey::from_wif("5K2r4ZRQ9HUu1Y1Sfon55LSe5jLwKiwcB7wAEi61cHKDjZ3LrGY").unwrap();
        let mine = "STM7bGV7CAYHXWm1hyPvhRZJYo3SNmMhuArHcLPSELgQhWM2Bk49F";
        let other = "STM5PAqRSn2vPZYfuqUQJJLs6QnMGUhgdbJP71QTpGS1aZWTpXDqa";
        let account = |posting: &str, active: &str, memo: &str| {
            json!([{
                "name": "fleet",
                "owner": {"key_auths": [[other, 1]]},
                "active": {"key_auths": [[active, 1]]},
                "posting": {"key_auths": [[posting, 1]], "account_auths": [["helper", 1]]},
                "memo_key": memo,
            }])
        };
        assert!(posting_key_verdict(&account(mine, other, other), "fleet", "fleet", &key).is_ok());
        let not_posting =
            posting_key_verdict(&account(other, other, other), "fleet", "fleet", &key);
        assert!(format!("{:#}", not_posting.unwrap_err()).contains("not a posting key"));
        let active = posting_key_verdict(&account(mine, mine, other), "fleet", "fleet", &key);
        assert!(format!("{:#}", active.unwrap_err()).contains("owner, active or memo"));
        let memo = posting_key_verdict(&account(mine, other, mine), "fleet", "fleet", &key);
        assert!(format!("{:#}", memo.unwrap_err()).contains("owner, active or memo"));
        assert!(posting_key_verdict(&json!([]), "fleet", "fleet", &key).is_err());
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
