//! The agent surface of `ferry mcp serve` (ADR 0028, beta).
//!
//! Six core tools, a thin facade over the same library calls the `ferry channel ...`
//! commands use, so permission checks, signing and ledger entries are the ones the CLI has.
//! Opt-in groups: `--tools admin` (search, get, status, update) and `--tools legacy` (the
//! eight read tools `ferry mcp serve` always had; they live in `mcp.rs`).
//!
//! What it will not do, by construction: read `secrets/`, accept a passphrase, sign a
//! release, mint a grant, approve anything, or carry work content. It takes references
//! (commit sha, hand-in id) and short summaries.
//!
//! Token rules T1-T10 are enforced by the `mcp_budget` test in `mcp_agent_tests.rs`.

use std::hash::{Hash, Hasher};

use anyhow::{Result, anyhow, bail};
use chrono::{DateTime, Utc};
use serde_json::{Map, Value, json};

use ferryman_channel::access::{self, Level};
use ferryman_channel::marvin;
use ferryman_channel::{
    Acknowledgement, AgentIdentity, Message, ProjectRoute, Review, SignatureCheck, Task,
    TaskResult, TaskState,
};

/// The guide: the server instructions, `ferry_help`, and the first `ferry_join` reply (T3: at
/// most 650 tokens, enforced in CI). Written for an agent that has only this server and
/// nobody to ask: nothing in it needs a command line except what it tells the human.
pub const INSTRUCTIONS: &str = "Ferryman: people (the master) own projects; AI agents share the work as signed orders in a shared channel, so many agents on many machines can work one project without clashing. Nothing needs to be running.
Levels, per project (join shows yours): worker = read, claim an order, report progress, submit work, message agents. member = also create orders, review changes, ask the human. orchestrator = also takes over as primary. Only the master approves, and the master is a human: agents never approve; use ferry_ask_human.
Loop: ferry_join, ferry_catchup, ferry_orders list (scope open), claim one, do the work in the work repo that ferry_orders show names (a branch there, never the channel), commit, ferry_orders submit with ref = the commit sha, then wait for review (ferry_catchup shows it). With several seats, pass project on every call after join.
Give work: ferry_orders create (member and up; a worker asks a member with ferry_talk, or the human with ferry_ask_human). Ask the human: ferry_ask_human raise, with a recommendation. Message an agent: ferry_talk post.
Words: primary = the agent leading a project (ferry_primary). seat = your place in a project. swarm = the agents working one project. order = one signed unit of work. hand-in = your finished work, named by ref.
Never put secrets or file contents in messages or notes. Messages travel peer to peer (iroh) with a relay as fallback; you never handle transport. No tool here changes the folder layout: that takes a master-signed fleet order (ferry fleet order migrate), so tell the human.
When something needs the human, tell them in plain words what to do. If join shows an update, tell the human; never update mid-order.";

/// What each level may do, said once in a join reply for the levels it lists.
fn can(level: Level) -> &'static str {
    match level {
        Level::Worker => "claim, progress, submit orders; read; message agents",
        Level::Member => "worker things, and create orders, review changes, ask the human",
        Level::Orchestrator => "member things, and take over as primary",
    }
}

/// Said when a call tries to change the folder layout.
const LAYOUT_REFUSAL: &str = "no MCP tool changes the folder layout. A layout change is applied only from a fleet order signed by the master (ferry fleet order migrate), never on anyone else's say-so. Tell the human";

/// Words that name a layout change, as a tool name or an `action`.
const LAYOUT_WORDS: &[&str] = &["migrate", "layout", "relocate", "restructure"];

fn layout_guard(name: &str, args: &Value) -> Result<()> {
    let action = args.get("action").and_then(Value::as_str).unwrap_or("");
    let hit = |text: &str| {
        let text = text.to_ascii_lowercase();
        LAYOUT_WORDS.iter().any(|w| text.contains(w))
    };
    if hit(name) || hit(action) {
        return Err(denied(LAYOUT_REFUSAL));
    }
    Ok(())
}

/// T4: the most items any response carries, and the most characters of structured data.
pub const MAX_ITEMS: usize = 20;
pub const MAX_CHARS: usize = 4000;

/// Minutes without a word from the primary before it reads as `quiet`. `silent` is the
/// quiet period Marvin already uses (`marvin::HOLDING_GOES_QUIET_AFTER_MINUTES`).
pub const QUIET_AFTER_MINUTES: i64 = 10;

/// The kind a question raised by `ferry_ask_human` carries.
pub const ASK_KIND: &str = "ask";
/// The option strings a question raised by `ferry_ask_human` offers.
const ASK_APPROVE: &str = "approve";
const ASK_REJECT: &str = "reject";

/// Per-response cap in tokens, T4/T10.
#[must_use]
pub fn cap_tokens(tool: &str) -> usize {
    match tool {
        "ferry_catchup" => 1000,
        "ferry_join" => 1100,
        "ferry_help" => 750,
        "ferry_primary" | "ferry_ask_human" => 300,
        _ => 600,
    }
}

/// Tokens in `chars` characters of JSON or prose, deliberately pessimistic: 3.3 characters
/// to a token, where chars / 4 undercounts symbol-dense JSON.
#[cfg(test)]
#[must_use]
pub fn est_tokens(chars: usize) -> usize {
    (chars * 10).div_ceil(33)
}

/// The most characters a response may spend under `tokens`.
const fn chars_for(tokens: usize) -> usize {
    tokens * 33 / 10
}

// ---------------------------------------------------------------------------------------
// Refusals

/// A refusal the model should read and act on, as opposed to a fault.
#[derive(Debug)]
pub struct Refusal {
    pub kind: &'static str,
    pub why: String,
}

impl std::fmt::Display for Refusal {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "{}: {}", self.kind, self.why)
    }
}

impl std::error::Error for Refusal {}

pub(crate) fn refusal(kind: &'static str, why: impl Into<String>) -> anyhow::Error {
    anyhow::Error::new(Refusal {
        kind,
        why: why.into(),
    })
}

pub(crate) fn denied(why: impl Into<String>) -> anyhow::Error {
    refusal("denied", why)
}

pub(crate) fn bad(why: impl Into<String>) -> anyhow::Error {
    refusal("bad_request", why)
}

// ---------------------------------------------------------------------------------------
// Replies

/// What a tool produced, before the response envelope and caps are applied.
pub struct Reply {
    /// One line. Not a second copy of the data (T9).
    pub text: String,
    pub data: Value,
    /// Bodies come back as links (T7), fetched with `resources/read`.
    pub links: Vec<Value>,
}

impl Reply {
    pub(crate) fn new(text: impl Into<String>, data: Value) -> Self {
        Self {
            text: text.into(),
            data,
            links: Vec::new(),
        }
    }
}

fn len_of(value: &Value) -> usize {
    serde_json::to_string(value).map_or(0, |text| text.len())
}

/// Shorten `text` to `max` characters on one line.
#[must_use]
pub fn short(text: &str, max: usize) -> String {
    let flat: String = text.split_whitespace().collect::<Vec<_>>().join(" ");
    if flat.chars().count() <= max {
        return flat;
    }
    let mut out: String = flat.chars().take(max.saturating_sub(1)).collect();
    out.push('~');
    out
}

/// Drop the last item of the first non-empty array named in `order` (searching nested
/// objects one level down), returning whether anything was dropped.
fn drop_one(data: &mut Value, order: &[&str]) -> bool {
    for key in order {
        if let Some(Value::Array(items)) = data.get_mut(*key)
            && !items.is_empty()
        {
            items.pop();
            return true;
        }
    }
    // Anything else that is an array, largest first.
    let Some(map) = data.as_object_mut() else {
        return false;
    };
    let biggest = map
        .iter()
        .filter_map(|(key, value)| value.as_array().map(|a| (key.clone(), a.len())))
        .filter(|(_, len)| *len > 0)
        .max_by_key(|(_, len)| *len);
    if let Some((key, _)) = biggest
        && let Some(Value::Array(items)) = map.get_mut(&key)
    {
        items.pop();
        return true;
    }
    false
}

/// Enforce T4 (20 items, 4,000 chars) and the tool's own cap, marking `truncated`.
fn fit(reply: &mut Reply, tool: &str, order: &[&str]) {
    let mut truncated = false;
    if let Some(map) = reply.data.as_object_mut() {
        for value in map.values_mut() {
            if let Value::Array(items) = value
                && items.len() > MAX_ITEMS
            {
                items.truncate(MAX_ITEMS);
                truncated = true;
            }
        }
    }
    let cap = chars_for(cap_tokens(tool));
    let extra =
        |reply: &Reply| reply.text.len() + reply.links.iter().map(len_of).sum::<usize>() + 130;
    while len_of(&reply.data) + extra(reply) > cap || len_of(&reply.data) > MAX_CHARS {
        if !drop_one(&mut reply.data, order) {
            break;
        }
        truncated = true;
    }
    if truncated && let Some(map) = reply.data.as_object_mut() {
        map.insert("truncated".into(), json!(true));
    }
}

/// A legacy tool's result, put through the same redaction and caps as the agent tools.
#[must_use]
pub(crate) fn finish_legacy(value: Value, tool: &str) -> Value {
    let data = if value.is_object() {
        value
    } else {
        json!({ "items": value })
    };
    finish(Reply::new(tool.to_string(), data), tool)
}

pub(crate) fn finish(mut reply: Reply, tool: &str) -> Value {
    // What is dropped first when a catch-up has to shrink: the recent chatter, then the
    // open queue. Decisions, asks and what waits on you go last.
    let order: &[&str] = match tool {
        "ferry_catchup" => &[
            "recent",
            "open",
            "mine",
            "decisions",
            "asks",
            "waiting_on_you",
        ],
        _ => &[],
    };
    // Nothing that looks like a secret leaves, whoever put it in the channel.
    let mut redacted = redact_value(&mut reply.data);
    if let Some(text) = redact_text(&reply.text) {
        reply.text = text;
        redacted = true;
    }
    if redacted && let Some(map) = reply.data.as_object_mut() {
        map.insert("redacted".into(), json!(true));
    }
    fit(&mut reply, tool, order);
    let mut content = vec![json!({ "type": "text", "text": reply.text })];
    content.extend(reply.links);
    json!({
        "content": content,
        "structuredContent": reply.data,
        "isError": false,
    })
}

/// The kind of the operating-system error underneath `error`, if there is one.
fn io_kind(error: &anyhow::Error) -> Option<std::io::ErrorKind> {
    error
        .chain()
        .find_map(|cause| cause.downcast_ref::<std::io::Error>())
        .map(std::io::Error::kind)
}

/// The order `id`, or a plain "no such order" where the file system would say os error 2.
fn read_order(route: &ProjectRoute, id: &str) -> Result<Task> {
    safe_id(id)?;
    ferryman_channel::read_task(route, id).map_err(|error| {
        if io_kind(&error) == Some(std::io::ErrorKind::NotFound) {
            bad(format!(
                "no such order '{id}'. ferry_orders list shows the ids you can use"
            ))
        } else {
            error
        }
    })
}

/// The result for a failed call: one line of text, plus a machine-readable reason.
#[must_use]
pub fn error_result(error: &anyhow::Error) -> Value {
    let (kind, why) = match error.downcast_ref::<Refusal>() {
        Some(r) => (r.kind, r.why.clone()),
        None => match io_kind(error) {
            Some(std::io::ErrorKind::NotFound) => (
                "not_found",
                "something this call needs is not on this machine. Check the id or project (ferry_join, ferry_orders list)".to_string(),
            ),
            Some(std::io::ErrorKind::PermissionDenied) => (
                "denied",
                "this machine does not allow that. Tell the human".to_string(),
            ),
            _ => ("error", format!("{error:#}")),
        },
    };
    json!({
        "content": [{ "type": "text", "text": short(&format!("{kind}: {why}"), 400) }],
        "structuredContent": { "error": kind, "reason": short(&why, 400) },
        "isError": true,
    })
}

// ---------------------------------------------------------------------------------------
// Tool definitions (T1, T2, T8): static strings, no version, time or agent name.

fn tool(name: &str, description: &str, input: &Value, output: &[&str]) -> Value {
    let props: Map<String, Value> = output
        .iter()
        .map(|k| ((*k).to_string(), json!({})))
        .collect();
    json!({
        "name": name,
        "description": description,
        "inputSchema": input,
        "outputSchema": { "type": "object", "properties": props },
    })
}

/// The seven core tools, sorted by name. Every argument is explained where it is declared.
#[must_use]
pub fn core_tools() -> Vec<Value> {
    let text = |what: &str| json!({ "type": "string", "description": what });
    let mut tools = vec![
        tool(
            "ferry_ask_human",
            "Ask the human to decide something. You can ask, never approve. raise needs title, recommendation and reasoning; status shows one ask (id) or your recent ones.",
            &json!({"type":"object","properties":{
                "action":{"enum":["raise","status"]},
                "title":text("the question in one line, at most 120 characters"),
                "recommendation":text("what you suggest they decide, at most 300 characters"),
                "reasoning":text("why, at most 1200 characters"),
                "id":text("an ask id from raise, for status")},"required":["action"]}),
            &["id", "state", "note", "asks"],
        ),
        tool(
            "ferry_catchup",
            "Resume in one call: who leads (and if that is stale), the project brief, decisions, open orders, yours, your asks and what waits on you. Use the returned next as since to get only what changed.",
            &json!({"type":"object","properties":{
                "since":text("the next value from your last catchup; returns only what changed"),
                "detail":{"type":"boolean","description":"true for longer lines and more rows"}}}),
            &[
                "primary",
                "brief",
                "decisions",
                "open",
                "mine",
                "asks",
                "waiting_on_you",
                "update",
                "next",
            ],
        ),
        tool(
            "ferry_help",
            "The short guide: what Ferryman is, what your level may do, the work loop, how to give work or ask the human, and the glossary. Call it whenever unsure.",
            &json!({"type":"object","properties":{}}),
            &["guide", "agent", "levels"],
        ),
        tool(
            "ferry_join",
            "Start here. Returns your name, level, your seats (projects, with what each is about), who leads and, on the first call, the guide. More than fit: call again with since = next.",
            &json!({"type":"object","properties":{
                "since":text("the next cursor from the last join, for the next page of projects")}}),
            &[
                "agent",
                "level",
                "granted",
                "primary",
                "alive",
                "mine_open",
                "queue",
                "update",
                "how",
                "projects",
                "total",
                "can",
                "guide",
                "next",
            ],
        ),
        tool(
            "ferry_orders",
            "Orders (units of work). list: scope mine|claimable|open|all (default open), page with since. show/claim (id). progress (id, note). submit (id, ref, note). review (id, verdict, notes; member+). create (title, task; member+).",
            &json!({"type":"object","properties":{
                "action":{"enum":["list","show","claim","progress","submit","review","create"]},
                "id":text("an order id, from list"),
                "scope":{"enum":["mine","claimable","open","all"],"description":"list: mine = yours, claimable = you may claim now, open = not finished (default), all = also finished"},
                "since":text("list: the next cursor from the last list, for the next page"),
                "note":text("progress: one line of status; submit: a short summary (the work itself is a commit)"),
                "ref":text("submit: the commit sha or hand-in id of the finished work"),
                "verdict":{"enum":["accept","changes"],"description":"review: accept, or send back with changes (then notes says what)"},
                "notes":text("review: what to change"),
                "title":text("create: the order in one line"),
                "task":text("create: what to do and how it is judged done"),
                "to":text("create: an agent or machine name; leave out for open to anyone"),
                "kind":text("create: code-change, docs, tests, review, plan, chore, research"),
                "size":{"enum":["small","medium","large"],"description":"create: how big"},
                "priority":{"enum":["low","normal","high"],"description":"create: queue order"},
                "depends_on":{"type":"array","items":{"type":"string"},"description":"create: order ids that must be done first"}},
                "required":["action"]}),
            &[
                "orders", "id", "state", "run_via", "scope", "total", "hidden", "next",
            ],
        ),
        tool(
            "ferry_primary",
            "Who leads this project and whether it is alive. status or standby look; takeover (orchestrator, only when the primary is silent) leads; release gives the lead up.",
            &json!({"type":"object","properties":{"action":{"enum":["status","standby","takeover","release"]}},"required":["action"]}),
            &["primary", "age_s", "state", "rule", "stale", "fix"],
        ),
        tool(
            "ferry_talk",
            "Messages between agents. read returns only new ones; post sends text to the agent named in to.",
            &json!({"type":"object","properties":{
                "action":{"enum":["read","post"]},
                "to":text("post: the agent's name, from the alive list in join"),
                "text":text("post: the message, at most 1500 characters; no secrets, no files"),
                "since":text("read: the next cursor from the last read"),
                "peek":{"type":"boolean","description":"read: true to look without marking messages read"}},"required":["action"]}),
            &["messages", "id", "next"],
        ),
    ];
    tools.sort_by(|a, b| a["name"].as_str().cmp(&b["name"].as_str()));
    tools
}

/// The opt-in admin group (`--tools admin`), sorted by name.
#[must_use]
pub fn admin_tools() -> Vec<Value> {
    let text = |what: &str| json!({ "type": "string", "description": what });
    let mut tools = vec![
        tool(
            "ferry_get",
            "Fetch one ferry:// resource (an order, message or brief) as text.",
            &json!({"type":"object","properties":{"uri":text("a ferry://<project>/<order|msg|brief>/<id> link")},"required":["uri"]}),
            &["uri", "text"],
        ),
        tool(
            "ferry_search",
            "Search the channel's memory, ledger, learnings and results. Paged.",
            &json!({"type":"object","properties":{"query":text("words to look for"),"since":text("the next cursor from the last search")},"required":["query"]}),
            &["hits", "next"],
        ),
        tool(
            "ferry_status",
            "Channel summary: task counts by state, agents, ledger length.",
            &json!({"type":"object","properties":{}}),
            &["project", "tasks", "agents", "ledger"],
        ),
        tool(
            "ferry_update",
            "check: is a signed, approved release available. apply: install it (orchestrator only).",
            &json!({"type":"object","properties":{"action":{"enum":["check","apply"]}},"required":["action"]}),
            &["current", "latest", "available", "installed"],
        ),
    ];
    tools.sort_by(|a, b| a["name"].as_str().cmp(&b["name"].as_str()));
    tools
}

// ---------------------------------------------------------------------------------------
// Secret-shape guard

/// Why `text` looks like a secret, if it does. The same file-level check order files use,
/// plus the shapes people paste into messages: provider tokens, `NAME_TOKEN=value`, a
/// password after the word, and long unbroken base64.
#[must_use]
pub fn secret_shape(text: &str) -> Option<String> {
    if let Some(reason) =
        ferryman_channel::order_files::secret_reason("message.txt", text.as_bytes())
    {
        return Some(reason);
    }
    let lower_words: Vec<String> = text
        .split(|c: char| c.is_whitespace() || "\"'`,;()[]{}<>".contains(c))
        .filter(|w| !w.is_empty())
        .map(str::to_string)
        .collect();
    const PREFIXES: &[(&str, usize)] = &[
        ("ghp_", 20),
        ("gho_", 20),
        ("ghu_", 20),
        ("ghs_", 20),
        ("ghr_", 20),
        ("github_pat_", 20),
        ("glpat-", 16),
        ("xoxb-", 12),
        ("xoxp-", 12),
        ("xoxa-", 12),
        ("xoxr-", 12),
        ("sk-", 20),
        ("sk_live_", 12),
        ("rk_live_", 12),
        ("AKIA", 16),
        ("AIza", 30),
        ("npm_", 24),
        ("hf_", 24),
    ];
    for (index, word) in lower_words.iter().enumerate() {
        if let Some((_, min)) = PREFIXES.iter().find(|(p, _)| word.starts_with(p))
            && word.len() >= *min
        {
            return Some("it contains a token".to_string());
        }
        if word.starts_with("eyJ") && word.len() > 30 && word.matches('.').count() >= 2 {
            return Some("it contains a signed token".to_string());
        }
        // NAME_TOKEN=value, password: value
        if let Some((key, value)) = word.split_once(['=', ':']) {
            let key_up = key.to_ascii_uppercase();
            let sensitive = ["KEY", "TOKEN", "SECRET", "PASSWORD", "PASSPHRASE", "PWD"]
                .iter()
                .any(|s| key_up.contains(s));
            let value = value.trim_start_matches(['=', ':', '/']);
            if sensitive && value.len() >= 8 && !value.starts_with("http") {
                return Some("it assigns a value to a key, token or password".to_string());
            }
            if sensitive
                && value.is_empty()
                && let Some(next) = lower_words.get(index + 1)
                && next.len() >= 8
                && !next.contains(' ')
                && ["PASSWORD", "PASSPHRASE", "SECRET", "TOKEN"]
                    .iter()
                    .any(|s| key_up == *s)
            {
                return Some("it states a password or token".to_string());
            }
        }
        let blob = word.len() >= 40
            && word
                .chars()
                .all(|c| c.is_ascii_alphanumeric() || matches!(c, '+' | '=' | '_' | '-'));
        if blob {
            let hex = word.chars().all(|c| c.is_ascii_hexdigit());
            let classes = [
                word.chars().any(|c| c.is_ascii_uppercase()),
                word.chars().any(|c| c.is_ascii_lowercase()),
                word.chars().any(|c| c.is_ascii_digit()),
            ]
            .iter()
            .filter(|b| **b)
            .count();
            if (hex && word.len() > 40) || (!hex && classes >= 3) {
                return Some("it contains a long key-like string".to_string());
            }
        }
    }
    None
}

fn guard(field: &str, text: &str) -> Result<()> {
    match secret_shape(text) {
        Some(reason) => Err(refusal(
            "secret",
            format!(
                "{field} looks like a secret ({reason}). Messages are not the place for one. Tell the human to seal it to the machines that need it"
            ),
        )),
        None => Ok(()),
    }
}

/// Keys whose values are identifiers or cursors, never prose: a hash or a long id in one
/// of them is not a secret and is not redacted. Agent names are validated identifiers.
/// Free-text keys (`name`, `how`, `order`, ...) are not here and are redacted.
const ID_KEYS: &[&str] = &[
    "id", "next", "since", "uri", "ref", "hash", "sha", "commit", "agent", "to", "from", "by",
    "holder", "project", "machine", "current", "latest",
];

/// `text` with every secret-shaped word replaced by `[redacted]`, or `None` when nothing
/// needed replacing. Whitespace and the punctuation around a word stay, so JSON survives.
#[must_use]
pub fn redact_text(text: &str) -> Option<String> {
    // Word spans: runs of non-whitespace.
    let mut spans: Vec<(usize, usize)> = Vec::new();
    let mut start: Option<usize> = None;
    for (i, c) in text.char_indices() {
        match (c.is_whitespace(), start) {
            (false, None) => start = Some(i),
            (true, Some(s)) => {
                spans.push((s, i));
                start = None;
            }
            _ => {}
        }
    }
    if let Some(s) = start {
        spans.push((s, text.len()));
    }
    let mut flagged: Vec<bool> = spans
        .iter()
        .map(|&(s, e)| secret_shape(&text[s..e]).is_some())
        .collect();
    for i in 0..spans.len() {
        let word = &text[spans[i].0..spans[i].1];
        if !flagged[i]
            && let Some(&(ns, ne)) = spans.get(i + 1)
            && !flagged[i + 1]
            && secret_shape(&format!("{word} {}", &text[ns..ne])).is_some()
        {
            // `password: hunter2hunter2`: the word and the value after it.
            flagged[i] = true;
            flagged[i + 1] = true;
        }
    }
    if !flagged.iter().any(|f| *f) {
        // A secret that is no single word (a key block) condemns the whole text.
        return secret_shape(text).map(|_| "[redacted]".to_string());
    }
    let mut out = String::with_capacity(text.len());
    let mut at = 0;
    for (i, (s, e)) in spans.iter().enumerate() {
        out.push_str(&text[at..*s]);
        let word = &text[*s..*e];
        if flagged[i] {
            let lead = word.len()
                - word
                    .trim_start_matches(['"', '\'', '(', '[', '{', '`'])
                    .len();
            let trail = word.len()
                - word
                    .trim_end_matches(['"', '\'', ')', ']', '}', ',', ';', '`'])
                    .len();
            out.push_str(&word[..lead.min(word.len())]);
            out.push_str("[redacted]");
            if trail > 0 && word.len() >= lead + trail {
                out.push_str(&word[word.len() - trail..]);
            }
        } else {
            out.push_str(word);
        }
        at = *e;
    }
    out.push_str(&text[at..]);
    Some(out)
}

/// [`redact_text`] over every string in `value` (skipping identifier fields), in place.
/// True when anything was replaced.
pub fn redact_value(value: &mut Value) -> bool {
    match value {
        Value::String(text) => {
            if let Some(clean) = redact_text(text) {
                *text = clean;
                true
            } else {
                false
            }
        }
        Value::Array(items) => items.iter_mut().fold(false, |any, v| redact_value(v) | any),
        Value::Object(map) => map.iter_mut().fold(false, |any, (key, v)| {
            if ID_KEYS.contains(&key.as_str()) && v.is_string() {
                any
            } else {
                redact_value(v) | any
            }
        }),
        _ => false,
    }
}

/// A reference (commit sha, hand-in id) is hex or a short path-safe word, never a token.
fn guard_ref(field: &str, text: &str) -> Result<()> {
    if text.len() <= 64 && text.chars().all(|c| c.is_ascii_hexdigit()) {
        return Ok(());
    }
    guard(field, text)
}

/// Lines that read as source code, not prose: dense in `{}();=<>` and the like, or
/// opening with a keyword, or a path header over several lines.
fn looks_like_code(text: &str) -> bool {
    const KEYWORDS: &[&str] = &[
        "fn ", "pub ", "def ", "class ", "import ", "from ", "use ", "let ", "const ", "return ",
        "#include", "package ", "func ", "impl ", "struct ",
    ];
    let mut lines = 0usize;
    let mut codeish = 0usize;
    let mut header = false;
    for line in text.lines() {
        let t = line.trim();
        if t.is_empty() {
            continue;
        }
        lines += 1;
        let lower = t.to_ascii_lowercase();
        if (lower.starts_with("file:")
            || lower.starts_with("path:")
            || lower.starts_with("// ")
            || lower.starts_with("# ")
            || lower.starts_with("--- ")
            || lower.starts_with("+++ "))
            && (t.contains('/') || t.contains('\\'))
            && t.rsplit('.')
                .next()
                .is_some_and(|ext| (1..=5).contains(&ext.len()))
            && t.len() <= 160
        {
            header = true;
        }
        let symbols = t.chars().filter(|c| "{}();=<>[]|&$\\".contains(*c)).count();
        let dense = symbols * 100 >= t.chars().count() * 12;
        let indented = line.starts_with("    ") || line.starts_with('\t');
        if (dense && t.chars().count() >= 8)
            || KEYWORDS.iter().any(|k| t.starts_with(k)) && symbols > 0
            || (indented && symbols * 100 >= t.chars().count() * 8)
        {
            codeish += 1;
        }
    }
    codeish >= 5 || (header && lines >= 4)
}

/// Work content does not travel through the channel: refuse fenced code, diffs, path-headed
/// file bodies and long runs of code-like lines.
fn not_work(field: &str, text: &str) -> Result<()> {
    if text.contains("```")
        || text.contains("diff --git")
        || text.contains("\n+++ ")
        || text.contains("\n--- a/")
        || text.contains("*** Begin Patch")
        || looks_like_code(text)
    {
        return Err(bad(format!(
            "{field} looks like work content. Commit it in the work repo and pass the commit or hand-in as ref"
        )));
    }
    Ok(())
}

// ---------------------------------------------------------------------------------------
// Cursors (T5): opaque strings.

fn msg_cursor(message: &Message) -> String {
    format!("t{}.{}", message.created_at.timestamp_millis(), message.id)
}

fn parse_msg_cursor(cursor: &str) -> Result<(i64, String)> {
    let rest = cursor
        .strip_prefix('t')
        .ok_or_else(|| bad("unrecognised cursor"))?;
    let (ms, id) = rest
        .split_once('.')
        .ok_or_else(|| bad("unrecognised cursor"))?;
    Ok((
        ms.parse().map_err(|_| bad("unrecognised cursor"))?,
        id.to_string(),
    ))
}

fn parse_offset(cursor: Option<&str>) -> Result<usize> {
    match cursor {
        None | Some("") => Ok(0),
        Some(text) => text
            .strip_prefix('o')
            .and_then(|n| n.parse().ok())
            .ok_or_else(|| bad("unrecognised cursor")),
    }
}

fn arg_str<'a>(args: &'a Value, key: &str) -> Option<&'a str> {
    args.get(key)
        .and_then(Value::as_str)
        .map(str::trim)
        .filter(|s| !s.is_empty())
}

fn need<'a>(args: &'a Value, key: &str, action: &str) -> Result<&'a str> {
    arg_str(args, key).ok_or_else(|| bad(format!("{action} needs '{key}'")))
}

pub(crate) fn safe_id(id: &str) -> Result<()> {
    if ferryman_channel::is_safe_component(id) {
        Ok(())
    } else {
        Err(bad("an id is letters, digits, '.', '-' and '_'"))
    }
}

fn finished(state: &TaskState) -> bool {
    matches!(
        state,
        TaskState::Accepted
            | TaskState::Done
            | TaskState::Killed { .. }
            | TaskState::Refuted { .. }
    )
}

fn is_me(a: &str, b: &str) -> bool {
    ferryman_channel::canonical_agent_name(a) == ferryman_channel::canonical_agent_name(b)
}

/// The order's first line, shortened only when it is longer than `max`.
fn title_of(task: &Task, max: usize) -> String {
    let text = task
        .order
        .payload
        .get("task")
        .and_then(Value::as_str)
        .unwrap_or("(structured)");
    let first = text
        .lines()
        .map(str::trim)
        .find(|line| !line.is_empty())
        .unwrap_or(text);
    short(first, max)
}

/// How long a title is shown in full.
const TITLE_CHARS: usize = 80;

fn message_text(message: &Message) -> String {
    match message.payload.get("text").and_then(Value::as_str) {
        Some(text) => text.to_string(),
        None => message.payload.to_string(),
    }
}

fn age_s(at: DateTime<Utc>) -> i64 {
    (Utc::now() - at).num_seconds().max(0)
}

/// One line about a project for `ferry_join`: its id, your level, and what it is about (the
/// first line of its brief, when it has one).
fn project_row(route: &ProjectRoute, level: Level) -> Value {
    let about = marvin::list_briefs(route)
        .ok()
        .and_then(|briefs| briefs.into_iter().next())
        .map(|brief| short(&brief.objective, 60))
        .unwrap_or_default();
    let mut row = json!({ "project": route.project_id, "level": level.as_str() });
    if !about.is_empty() {
        row["about"] = json!(about);
    }
    row
}

/// "17 days", "5 h", "12 min".
fn how_long(minutes: i64) -> String {
    if minutes >= 48 * 60 {
        format!("{} days", minutes / (24 * 60))
    } else if minutes >= 120 {
        format!("{} h", minutes / 60)
    } else {
        format!("{minutes} min")
    }
}

// ---------------------------------------------------------------------------------------
// The agent

/// One MCP process: one agent identity, one project.
pub struct Agent {
    pub route: ProjectRoute,
    pub me: String,
    /// `--tools admin`.
    pub admin: bool,
    /// The guide has been sent with a `ferry_join` already.
    pub guided: std::sync::atomic::AtomicBool,
}

impl Agent {
    pub fn new(route: ProjectRoute, me: &str, admin: bool) -> Result<Self> {
        let me = ferryman_channel::canonical_agent_name(me);
        let is_master = ferryman_channel::master::read_master(&route)
            .ok()
            .flatten()
            .is_some_and(|m| is_me(&m.master, &me));
        if is_master {
            bail!(
                "--as {me} is the master identity. Agents ask and never approve, so the master does not run this server; use an agent identity, and decide in the dashboard or with `ferry channel review`"
            );
        }
        Ok(Self {
            route,
            me,
            admin,
            guided: std::sync::atomic::AtomicBool::new(false),
        })
    }

    /// Is `--as <name>` an agent this machine actually holds the key for, seated on the
    /// roster with that same key? A name alone proves nothing: anyone can type one. Until
    /// this is true every tool but `ferry_join` refuses, and nothing is registered here.
    #[must_use]
    pub fn seated(&self) -> bool {
        let Ok(Some(identity)) = AgentIdentity::load_existing(&self.me, &self.route.attachment)
        else {
            return false;
        };
        self.route().agents.iter().any(|a| {
            is_me(&a.name, &self.me)
                && a.public_key.as_deref() == Some(identity.public_key_hex().as_str())
        })
    }

    pub(crate) fn require_seated(&self) -> Result<()> {
        if self.seated() {
            Ok(())
        } else {
            Err(refusal(
                "locked",
                format!(
                    "'{}' is not seated on this machine, so this app is read-only here. Ask the person who runs this machine to seat it (dashboard, Agents), then restart the app",
                    self.me
                ),
            ))
        }
    }

    /// The route with the roster as it is now.
    fn route(&self) -> ProjectRoute {
        let mut route = self.route.clone();
        if let Ok(agents) = ferryman_channel::read_agent_roster(&route.communications) {
            route.agents = agents;
        }
        route
    }

    #[must_use]
    pub fn level(&self) -> Level {
        access::level_of(&self.route.communications, &self.route.project_id, &self.me)
    }

    /// The human who owns this project, for messages that tell a worker whom to ask.
    fn master_name(&self) -> String {
        ferryman_channel::master::read_master(&self.route())
            .ok()
            .flatten()
            .map_or_else(|| "the project owner".to_string(), |m| m.master)
    }

    /// What every level may do: claim, report progress, submit, message. A worker's files
    /// land in its own hand-ins folder, which the readers honour (ADR 0024).
    fn require_work(&self, what: &str) -> Result<Level> {
        if let Some(note) = self.paused(&self.route()) {
            return Err(denied(format!(
                "cannot {what} while paused ({}). Tell the human",
                short(&note, 120)
            )));
        }
        Ok(self.level())
    }

    /// What a member and up may do: review, create orders, ask the human.
    fn require_write(&self, what: &str) -> Result<Level> {
        let level = self.require_work(what)?;
        if level.writes_channel() {
            Ok(level)
        } else {
            Err(denied(format!(
                "your level is worker, which cannot {what}. Ask instead: ferry_talk post to {} (the human who owns this project) or to a member agent, saying what you need; they can do it or raise your level",
                self.master_name()
            )))
        }
    }

    fn identity(&self) -> Result<AgentIdentity> {
        match AgentIdentity::load_existing(&self.me, &self.route.attachment) {
            Ok(Some(identity)) => Ok(identity),
            _ => Err(refusal(
                "locked",
                format!(
                    "no usable key for '{}' on this machine. Ask the owner to seat it: dashboard, Agents",
                    self.me
                ),
            )),
        }
    }

    /// Dispatch one `tools/call`.
    pub fn call(&self, name: &str, args: &Value) -> Value {
        match self.call_raw(name, args) {
            Ok(reply) => finish(reply, name),
            Err(error) => error_result(&error),
        }
    }

    /// The reply before redaction and truncation, so a test can measure what a tool
    /// produced against its cap and not only what survived the cut.
    pub fn call_raw(&self, name: &str, args: &Value) -> Result<Reply> {
        layout_guard(name, args)?;
        if name != "ferry_join" && name != "ferry_help" {
            // Only a seated key reads or writes the channel through this server.
            if name.starts_with("ferry_") {
                self.require_seated()?;
            }
            // Every string the caller sends is checked for secrets, whichever tool it is
            // for. Ids, cursors and refs have shapes of their own and are checked there.
            if let Some(map) = args.as_object() {
                for (key, value) in map {
                    if let Some(text) = value.as_str()
                        && !matches!(
                            key.as_str(),
                            "action" | "id" | "since" | "uri" | "to" | "ref"
                        )
                    {
                        guard(key, text)?;
                    }
                }
            }
        }
        match name {
            "ferry_join" => self.join(args),
            "ferry_help" => self.help(),
            "ferry_catchup" => self.catchup(args),
            "ferry_orders" => self.orders(args),
            "ferry_talk" => self.talk(args),
            "ferry_primary" => self.primary(args),
            "ferry_ask_human" => self.ask_human(args),
            "ferry_get" if self.admin => self.get(args),
            "ferry_search" if self.admin => self.search(args),
            "ferry_status" if self.admin => self.status(),
            "ferry_update" if self.admin => self.update(args),
            other => Err(bad(format!("unknown tool: {other}"))),
        }
    }

    // -- primary ----------------------------------------------------------------------

    /// `(view, state)` for the holder of Marvin. State is alive, quiet, silent or none.
    fn primary_view(&self, route: &ProjectRoute) -> (Value, &'static str, Option<marvin::Holding>) {
        let now = Utc::now();
        match marvin::current_holder(route).ok().flatten() {
            Some(holder) => {
                let minutes = holder.quiet_minutes(now);
                let state = if holder.has_gone_quiet(now) {
                    "silent"
                } else if minutes >= QUIET_AFTER_MINUTES {
                    "quiet"
                } else {
                    "alive"
                };
                (
                    json!({
                        "name": holder.agent,
                        "age_s": age_s(holder.touched_at),
                        "alive": state != "silent",
                    }),
                    state,
                    Some(holder),
                )
            }
            None => (json!({ "name": null, "alive": false }), "none", None),
        }
    }

    /// The primary is silent and nothing answers to its name (a retired machine name, say):
    /// how long it has been quiet, and what the master should do. The channel's holder stays
    /// where it was left; only the master or an orchestrator can move it.
    fn stale_primary(
        &self,
        route: &ProjectRoute,
        state: &str,
        holder: Option<&marvin::Holding>,
    ) -> Option<(String, String)> {
        let holder = holder?;
        if state != "silent" {
            return None;
        }
        let answering = ferryman_channel::receipts::list_presence(route)
            .unwrap_or_default()
            .iter()
            .any(|(p, _)| {
                is_me(&p.agent, &holder.agent)
                    && age_s(p.seen_at) < ferryman_channel::receipts::PRESENCE_ABSENT_AFTER_SECS
            });
        if answering {
            return None;
        }
        let quiet = how_long(holder.quiet_minutes(Utc::now()));
        let fix = format!(
            "No live worker answers to '{}' (it may be a retired name). The master should choose a new primary: in the dashboard (Agents), or ask an orchestrator agent to run ferry_primary takeover",
            holder.agent
        );
        Some((quiet, fix))
    }

    /// Raise one ask to the human about a stale primary. The id is the primary's name, so
    /// however many agents see it, and however often, there is one ask.
    fn raise_stale_ask(&self, route: &ProjectRoute, name: &str, quiet: &str) {
        if !self.level().writes_channel() || self.paused(route).is_some() {
            return;
        }
        let Ok(identity) = self.identity() else {
            return;
        };
        let id = format!(
            "ask-stale-primary-{}",
            ferryman_channel::canonical_agent_name(name)
        );
        let text = format!(
            "Primary '{name}' has been silent for {quiet} and no worker answers to that name.\nRecommendation: choose a new primary (dashboard, Agents).\nWhy: until then nobody leads this project, and a takeover is waiting on you."
        );
        let options = [
            ASK_APPROVE.to_string(),
            ASK_REJECT.to_string(),
            "send back".to_string(),
        ];
        let _ = ferryman_channel::questions::ask(
            route, &identity, &id, ASK_KIND, &text, &options, None,
        );
    }

    /// While this agent is the primary, every call it makes is a word from it. Without
    /// this the holder would go quiet while very much at work.
    fn touch(&self, route: &ProjectRoute) {
        if let Ok(Some(holder)) = marvin::current_holder(route)
            && is_me(&holder.agent, &self.me)
            && self.level() >= Level::Orchestrator
            && let Ok(identity) = self.identity()
        {
            let _ = marvin::take(route, &identity, &holder.note, false);
        }
    }

    fn paused(&self, route: &ProjectRoute) -> Option<String> {
        if let Some(note) = ferryman_ops::governor::paused() {
            return Some(note);
        }
        ferryman_channel::receipts::list_presence(route)
            .ok()?
            .into_iter()
            .find(|(presence, _)| is_me(&presence.agent, &self.me) && presence.paused)
            .map(|_| "this machine is paused (ferry pause)".to_string())
    }

    fn primary(&self, args: &Value) -> Result<Reply> {
        let route = self.route();
        let action = need(args, "action", "ferry_primary")?;
        let (view, state, holder) = self.primary_view(&route);
        let rule = match state {
            "none" => "no primary: an Orchestrator on a machine that is not paused may take over",
            "silent" => {
                "primary is silent: an Orchestrator on a machine that is not paused may take over"
            }
            _ => {
                "primary is heard from: stand by and poll ferry_catchup; takeover is refused until it is silent"
            }
        };
        let me_primary = holder.as_ref().is_some_and(|h| is_me(&h.agent, &self.me));
        let stale = self.stale_primary(&route, state, holder.as_ref());
        if let (Some((quiet, _)), Some(h)) = (&stale, &holder) {
            self.raise_stale_ask(&route, &h.agent, quiet);
        }
        let status = |extra: Option<(&str, Value)>| {
            let mut data = json!({
                "primary": view["name"],
                "age_s": view["age_s"],
                "state": state,
                "rule": rule,
            });
            if let Some((quiet, fix)) = &stale {
                data["stale"] = json!(true);
                data["silent_for"] = json!(quiet);
                data["fix"] = json!(fix);
            }
            if me_primary {
                data["you_are_primary"] = json!(true);
            }
            if let Some((k, v)) = extra {
                data[k] = v;
            }
            data
        };
        match action {
            "status" | "standby" => {
                let who = view["name"].as_str().unwrap_or("nobody");
                let note = if stale.is_some() {
                    " (stale: tell the master)"
                } else {
                    ""
                };
                Ok(Reply::new(
                    format!("primary {who}, {state}{note}"),
                    status(None),
                ))
            }
            "takeover" => {
                let level = self.level();
                if level < Level::Orchestrator {
                    return Err(denied(format!(
                        "level {} cannot take over; only an Orchestrator can. Use ferry_ask_human with a recommendation",
                        level.as_str()
                    )));
                }
                if let Some(why) = self.paused(&route) {
                    return Err(denied(format!("{why}, so it cannot take over")));
                }
                if !me_primary && !matches!(state, "silent" | "none") {
                    return Err(refusal(
                        "refused",
                        format!(
                            "the primary is {state}, heard from {} min ago; takeover needs {} min of silence. Stand by",
                            view["age_s"].as_i64().unwrap_or(0) / 60,
                            marvin::HOLDING_GOES_QUIET_AFTER_MINUTES
                        ),
                    ));
                }
                let identity = self.identity()?;
                let from = view["name"].as_str().map(str::to_string);
                // force is never set here: marvin::take itself refuses while the holder
                // is still heard from.
                let holding = marvin::take(&route, &identity, "taken over through MCP", false)?;
                // Tell the one who held it; there is no broadcast address on the channel.
                if let Some(old) = from.as_deref().filter(|old| !is_me(old, &self.me)) {
                    let _ = self.send(&route, &identity, old, &format!("taking over from {old}"));
                }
                let mut data = status(None);
                data["primary"] = json!(holding.agent);
                data["state"] = json!("alive");
                data["you_are_primary"] = json!(true);
                data["next"] = json!("ferry_catchup");
                Ok(Reply::new("you are primary".to_string(), data))
            }
            "release" => {
                self.require_write("release")?;
                let identity = self.identity()?;
                marvin::release(&route, &identity, "released through MCP")?;
                Ok(Reply::new(
                    "released",
                    json!({ "released": true, "state": "silent" }),
                ))
            }
            other => Err(bad(format!("unknown action '{other}'"))),
        }
    }

    // -- join -------------------------------------------------------------------------

    fn join(&self, _args: &Value) -> Result<Reply> {
        // A name is a claim, not a credential. Joining registers nothing and mints no key:
        // the key must already be on this machine and seated on the roster.
        let route = self.route();
        let granted = self.seated();
        if !granted {
            let note = match AgentIdentity::load_existing(&self.me, &self.route.attachment) {
                Ok(Some(_)) => format!(
                    "'{}' is not seated: it has a key here but is not on this project's roster. Tell the human: ask the owner to seat it in the Ferryman dashboard (Agents)",
                    self.me
                ),
                _ => format!(
                    "'{}' is not seated: it has no key on this machine yet. Restart this server (it seats itself on start), or tell the human to seat it in the Ferryman dashboard (Agents). Until then this app can read nothing and write nothing",
                    self.me
                ),
            };
            let data = json!({
                "agent": self.me,
                "project": route.project_id,
                "level": "none",
                "granted": false,
                "note": note,
            });
            return Ok(Reply::new(
                format!(
                    "Ferryman MCP (beta): {} is not seated on {}; read-only, nothing else",
                    self.me, route.project_id
                ),
                data,
            ));
        }
        let level = self.level();
        let (primary, state, _) = self.primary_view(&route);
        let tasks = ferryman_channel::list_tasks(&route).unwrap_or_default();
        let mine_open = tasks
            .iter()
            .filter(|t| self.is_mine(t) && !finished(&t.state()))
            .count();
        let alive = self.alive(&route, &tasks);
        let mut data = json!({
            "agent": self.me,
            "project": route.project_id,
            "machine": ferryman_channel::receipts::machine_label(),
            "level": level.as_str(),
            "granted": granted,
            "total": 1,
            "projects": [project_row(&route, level)],
            "can": { level.as_str(): can(level) },
            "primary": primary,
            "alive": alive,
            "mine_open": mine_open,
            "queue": { "snifrig": ferryman_ops::heavy::snifrig_on_path().is_some() },
            "next": "ferry_catchup",
        });
        if let Some(update) = self.update_field(&route) {
            data["update"] = update;
        }
        if !self.guided.swap(true, std::sync::atomic::Ordering::Relaxed) {
            data["guide"] = json!(INSTRUCTIONS);
        }
        let who = data["primary"]["name"]
            .as_str()
            .unwrap_or("nobody")
            .to_string();
        Ok(Reply::new(
            format!(
                "Ferryman MCP (beta): {} on {}, level {}, primary {who} ({state})",
                self.me,
                route.project_id,
                level.as_str(),
            ),
            data,
        ))
    }

    fn help(&self) -> Result<Reply> {
        let level = self.level();
        Ok(Reply::new(
            "the Ferryman guide",
            json!({
                "guide": INSTRUCTIONS,
                "agent": self.me,
                "levels": { self.route.project_id.clone(): level.as_str() },
                "can": { level.as_str(): can(level) },
            }),
        ))
    }

    fn alive(&self, route: &ProjectRoute, tasks: &[Task]) -> Vec<Value> {
        let mut seen: Vec<(i64, Value)> = ferryman_channel::receipts::list_presence(route)
            .unwrap_or_default()
            .into_iter()
            .filter(|(p, _)| {
                age_s(p.seen_at) < ferryman_channel::receipts::PRESENCE_ABSENT_AFTER_SECS
            })
            .map(|(p, _)| {
                let doing = tasks
                    .iter()
                    .find(|t| {
                        t.holder().is_some_and(|h| is_me(h, &p.agent)) && !finished(&t.state())
                    })
                    .map(|t| t.order.id.clone())
                    .or(p.held.clone().map(|h| short(&h, 40)))
                    .unwrap_or_else(|| "idle".into());
                let age = age_s(p.seen_at);
                (
                    age,
                    json!({ "name": p.agent, "doing": doing, "age_s": age }),
                )
            })
            .collect();
        seen.sort_by_key(|(age, _)| *age);
        seen.into_iter().map(|(_, v)| v).take(10).collect()
    }

    fn is_mine(&self, task: &Task) -> bool {
        task.holder().is_some_and(|h| is_me(h, &self.me))
            || task
                .order
                .assigned_to
                .as_deref()
                .is_some_and(|a| ferryman_channel::addressed_to(a, &self.me))
    }

    // -- catchup ----------------------------------------------------------------------

    fn catchup(&self, args: &Value) -> Result<Reply> {
        let route = self.route();
        self.touch(&route);
        let detail = args.get("detail").and_then(Value::as_bool).unwrap_or(false);
        let since = arg_str(args, "since");
        let (open_cap, decision_cap, line) = if detail { (20, 16, 200) } else { (6, 4, 80) };

        let tasks = ferryman_channel::list_tasks(&route)?;
        let ledger = ferryman_channel::ledger::read_ledger(&route)
            .map(|log| log.entries)
            .unwrap_or_default();
        let (primary, state, holder) = self.primary_view(&route);
        let stale = self.stale_primary(&route, state, holder.as_ref());
        if let (Some((quiet, _)), Some(h)) = (&stale, &holder) {
            self.raise_stale_ask(&route, &h.agent, quiet);
        }
        let brief = match &holder {
            Some(h) => marvin::read_brief(&route, &h.agent).ok().flatten(),
            None => None,
        }
        .or_else(|| {
            marvin::list_briefs(&route)
                .ok()
                .and_then(|b| b.into_iter().next())
        });

        let mut hasher = std::collections::hash_map::DefaultHasher::new();
        for task in &tasks {
            task.order.id.hash(&mut hasher);
            state_name(&task.state()).hash(&mut hasher);
            task.holder().hash(&mut hasher);
        }
        let digest = hasher.finish();
        let brief_ms = brief
            .as_ref()
            .map_or(0, |b| b.updated_at.timestamp_millis());
        let next = format!("c.{}.{}.{:x}", ledger.len(), brief_ms, digest);

        let mut ledger_before = None;
        if let Some(cursor) = since {
            if cursor == next {
                return Ok(Reply::new(
                    "nothing new since your cursor",
                    json!({ "unchanged": true, "next": next }),
                ));
            }
            let parts: Vec<&str> = cursor.split('.').collect();
            if parts.len() != 4 || parts[0] != "c" {
                return Err(bad("unrecognised cursor"));
            }
            ledger_before = parts[1].parse::<usize>().ok();
        }

        let people = ferryman_channel::people(&route);
        let mut open: Vec<&Task> = tasks.iter().filter(|t| !finished(&t.state())).collect();
        open.sort_by(|a, b| {
            b.order
                .effective_priority(&people)
                .cmp(&a.order.effective_priority(&people))
                .then(a.order.created_at.cmp(&b.order.created_at))
        });
        let open_total = open.len();
        let row = |t: &Task| {
            let mut r = json!({
                "id": t.order.id,
                "title": title_of(t, TITLE_CHARS),
                "state": state_name(&t.state()),
            });
            if let Some(h) = t.holder().or(t.order.assigned_to.as_deref()) {
                r["assignee"] = json!(h);
            }
            r
        };
        let open_rows: Vec<Value> = open.iter().take(open_cap).map(|t| row(t)).collect();
        let mine: Vec<Value> = tasks
            .iter()
            .filter(|t| self.is_mine(t) && !finished(&t.state()))
            .take(3)
            .map(|t| json!({ "id": t.order.id, "title": title_of(t, TITLE_CHARS), "state": state_name(&t.state()) }))
            .collect();

        let decisions: Vec<Value> = brief
            .as_ref()
            .map(|b| {
                let lines: Vec<&str> = b
                    .decided
                    .lines()
                    .map(|l| l.trim().trim_start_matches(['-', '*', ' ']))
                    .filter(|l| !l.is_empty())
                    .collect();
                let skip = lines.len().saturating_sub(decision_cap);
                lines
                    .iter()
                    .enumerate()
                    .skip(skip)
                    .rev()
                    .map(|(i, l)| {
                        json!({ "id": format!("d{}", i + 1), "line": short(l, line), "at": b.updated_at.format("%m-%d").to_string() })
                    })
                    .collect()
            })
            .unwrap_or_default();

        let asks: Vec<Value> = self
            .my_asks(&route)
            .into_iter()
            .rev()
            .take(3)
            .map(|(id, state, _)| json!({ "id": id, "state": state }))
            .collect();

        let mut waiting: Vec<Value> = Vec::new();
        if self.level().writes_channel() {
            // Only what this agent could actually decide: not an order that needs the
            // master, and not a result it submitted itself.
            for t in tasks
                .iter()
                .filter(|t| matches!(t.state(), TaskState::AwaitingReview { .. }))
                .filter(|t| !t.order.requires_approval)
                .filter(|t| {
                    let revision = t.latest_revision();
                    !t.results
                        .iter()
                        .any(|r| Some(r.revision) == revision && is_me(&r.agent, &self.me))
                })
                .take(3)
            {
                waiting.push(json!(format!("review {}", t.order.id)));
            }
        }
        let unread = self.unread_count(&route);
        if unread > 0 {
            waiting.push(json!(format!("{unread} unread: ferry_talk read")));
        }

        let mut brief_view = Value::Null;
        if let Some(b) = &brief {
            let constraints: Vec<Value> = b
                .constraints
                .lines()
                .map(str::trim)
                .filter(|l| !l.is_empty())
                .take(3)
                .map(|l| json!(short(l, 80)))
                .collect();
            brief_view = json!({
                "objective": short(&b.objective, if detail { 300 } else { 160 }),
                "constraints": constraints,
                "now": short(&b.in_flight, if detail { 300 } else { 140 }),
                "next_up": short(&b.next, if detail { 300 } else { 100 }),
            });
        }
        let mut primary_view = json!({ "name": primary["name"], "state": state });
        if let Some((quiet, fix)) = &stale {
            primary_view["stale"] = json!(true);
            primary_view["silent_for"] = json!(quiet);
            primary_view["fix"] = json!(fix);
        }
        let mut data = json!({
            "primary": primary_view,
            "brief": brief_view,
            "decisions": decisions,
            "open": open_rows,
            "mine": mine,
            "asks": asks,
            "waiting_on_you": waiting,
            "next": next,
        });
        if open_total > open_cap {
            data["open_total"] = json!(open_total);
        }
        if let Some(before) = ledger_before {
            let recent: Vec<Value> = ledger
                .iter()
                .skip(before.min(ledger.len()))
                .rev()
                .take(3)
                .map(|e| json!({ "kind": e.kind, "by": e.actor, "line": short(&e.summary, 50) }))
                .collect();
            data["recent"] = json!(recent);
        }
        if let Some(update) = self.update_field(&route) {
            data["update"] = update;
        }
        let mut reply = Reply::new(
            format!(
                "{} open, {} yours; primary {} ({state}{})",
                open_total,
                mine.len(),
                primary["name"].as_str().unwrap_or("nobody"),
                if stale.is_some() { ", stale" } else { "" }
            ),
            data,
        );
        if brief.is_some()
            && let Some(h) = &holder
        {
            reply.links.push(json!({
                "type": "resource_link",
                "uri": format!("ferry://{}/brief/{}", route.project_id, h.agent),
                "name": "full brief",
                "mimeType": "text/plain",
            }));
        }
        Ok(reply)
    }

    fn unread_count(&self, route: &ProjectRoute) -> usize {
        ferryman_channel::list_messages(route)
            .map(|messages| {
                messages
                    .iter()
                    .filter(|m| m.recipient.eq_ignore_ascii_case(&self.me))
                    .filter(|m| !ferryman_channel::is_acknowledged(route, &m.id))
                    .count()
            })
            .unwrap_or(0)
    }

    // -- orders -----------------------------------------------------------------------

    fn orders(&self, args: &Value) -> Result<Reply> {
        let route = self.route();
        let action = need(args, "action", "ferry_orders")?;
        self.touch(&route);
        match action {
            "list" => self.orders_list(&route, arg_str(args, "scope"), arg_str(args, "since")),
            "create" => self.orders_create(&route, args),
            "show" => self.orders_show(&route, need(args, "id", "show")?),
            "claim" => {
                self.require_work("claim orders")?;
                let id = need(args, "id", "claim")?;
                safe_id(id)?;
                // The checks the worker makes before it takes an order, in the same
                // order: is it signed and unblocked and addressed to this agent, then
                // the holds (interface, file overlap, fleet width, project tier, order
                // files). Only then the claim.
                let task = read_order(&route, id)?;
                if !task.holder().is_some_and(|h| is_me(h, &self.me)) {
                    let open = ferryman_channel::work_among(&route, &self.me, vec![task.clone()])?
                        .into_iter()
                        .any(|t| matches!(t.state(), TaskState::Open | TaskState::Offered { .. }));
                    if !open {
                        return Err(refusal(
                            "refused",
                            format!(
                                "{id} is not open to you: it is taken, finished, addressed to someone else, waiting on other orders, or not validly signed"
                            ),
                        ));
                    }
                    if let Some(reason) =
                        ferryman_ops::agent::start_hold(&route, &self.me, &task.order)
                    {
                        return Err(refusal(
                            "refused",
                            format!("hold off {id}: {}", short(&reason, 200)),
                        ));
                    }
                }
                ferryman_channel::claim_order(&route, id, &self.me)?;
                let task = read_order(&route, id)?;
                let holder = task.holder().unwrap_or("nobody").to_string();
                let ok = is_me(&holder, &self.me);
                Ok(Reply::new(
                    if ok {
                        format!("you hold {id}")
                    } else {
                        format!("{holder} holds {id}; claimed first")
                    },
                    json!({ "id": id, "state": state_name(&task.state()), "holder": holder, "ok": ok }),
                ))
            }
            "progress" => {
                self.require_work("report progress")?;
                let id = need(args, "id", "progress")?;
                safe_id(id)?;
                let note = need(args, "note", "progress")?;
                guard("note", note)?;
                not_work("note", note)?;
                if note.len() > 500 {
                    return Err(bad("a progress note is at most 500 characters"));
                }
                self.holding(&route, id)?;
                let identity = self.identity()?;
                ferryman_channel::ledger::append_ledger_entry(
                    &route,
                    &identity,
                    "progress",
                    &self.me,
                    &short(note, 500),
                    Some(id),
                )?;
                Ok(Reply::new(
                    format!("progress noted on {id}"),
                    json!({ "id": id, "ok": true }),
                ))
            }
            "submit" => {
                self.require_work("submit results")?;
                let id = need(args, "id", "submit")?;
                safe_id(id)?;
                let reference = need(args, "ref", "submit")?;
                guard_ref("ref", reference)?;
                if reference.len() > 128
                    || !reference
                        .chars()
                        .all(|c| c.is_ascii_alphanumeric() || "._-/:@#".contains(c))
                {
                    return Err(bad(
                        "ref is a commit sha or hand-in id, at most 128 characters",
                    ));
                }
                let note = arg_str(args, "note").unwrap_or("");
                guard("note", note)?;
                not_work("note", note)?;
                if note.len() > 1000 {
                    return Err(bad(
                        "the summary is at most 1000 characters; commit the detail in the work repo",
                    ));
                }
                let task = self.holding(&route, id)?;
                let identity = self.identity()?;
                let revision = task.latest_revision().unwrap_or(0) + 1;
                let mut result = TaskResult {
                    order_id: id.to_string(),
                    agent: self.me.clone(),
                    revision,
                    submitted_at: Utc::now(),
                    payload: json!({ "text": note, "ref": reference }),
                    signed_by: None,
                    signature: None,
                };
                identity.sign_result(&mut result);
                ferryman_channel::submit_result(&route, &result)?;
                let after = read_order(&route, id)?;
                Ok(Reply::new(
                    format!("submitted revision {revision} of {id}"),
                    json!({ "id": id, "revision": revision, "state": state_name(&after.state()) }),
                ))
            }
            "review" => {
                let id = need(args, "id", "review")?;
                // A missing order is said first, in words, whoever asks.
                read_order(&route, id)?;
                self.require_review()?;
                let accept = match need(args, "verdict", "review")? {
                    "accept" => true,
                    "changes" => false,
                    other => {
                        return Err(bad(format!("verdict is accept or changes, not '{other}'")));
                    }
                };
                let notes = arg_str(args, "notes").map(str::to_string);
                if let Some(n) = &notes {
                    guard("notes", n)?;
                    if n.len() > 1000 {
                        return Err(bad("review notes are at most 1000 characters"));
                    }
                }
                let task = read_order(&route, id)?;
                let revision = task
                    .latest_revision()
                    .ok_or_else(|| bad("there is no result to review yet"))?;
                if task
                    .results
                    .iter()
                    .any(|r| r.revision == revision && is_me(&r.agent, &self.me))
                {
                    return Err(denied(
                        "you submitted this result; another agent reviews it",
                    ));
                }
                if task.order.requires_approval {
                    return Err(denied(
                        "agents never approve: this order needs the master's approval. Use ferry_ask_human with a recommendation; the master decides in the Ferryman dashboard",
                    ));
                }
                if accept
                    && let Some(missing) = task.contract_violations_in(&route)
                    && !missing.is_empty()
                {
                    return Err(bad(format!(
                        "the result does not satisfy the order's contract: {}",
                        short(&missing.join("; "), 200)
                    )));
                }
                let identity = self.identity()?;
                let mut verdict = Review {
                    order_id: id.to_string(),
                    revision,
                    reviewer: self.me.clone(),
                    reviewed_at: Utc::now(),
                    accepted: accept,
                    notes,
                    signed_by: None,
                    signature: None,
                };
                identity.sign_review(&mut verdict);
                ferryman_channel::submit_review(&route, &verdict)?;
                Ok(Reply::new(
                    if accept {
                        format!("accepted revision {revision} of {id}")
                    } else {
                        format!("sent {id} back")
                    },
                    json!({ "id": id, "revision": revision, "accepted": accept }),
                ))
            }
            other => Err(bad(format!("unknown action '{other}'"))),
        }
    }

    /// Review is a member's job, and never an approval: a worker is told who decides.
    fn require_review(&self) -> Result<()> {
        let level = self.require_work("review")?;
        if level.writes_channel() {
            return Ok(());
        }
        Err(denied(format!(
            "agents never approve, and a worker cannot review. If a decision is needed, ask the human: ferry_talk post to {} (a member uses ferry_ask_human)",
            self.master_name()
        )))
    }

    /// The task, if this agent holds it.
    fn holding(&self, route: &ProjectRoute, id: &str) -> Result<Task> {
        let task = read_order(route, id)?;
        if task.holder().is_some_and(|h| is_me(h, &self.me)) {
            Ok(task)
        } else {
            Err(refusal(
                "refused",
                format!(
                    "you do not hold {id} (holder: {}). Claim it first",
                    task.holder().unwrap_or("nobody")
                ),
            ))
        }
    }

    fn orders_list(
        &self,
        route: &ProjectRoute,
        scope: Option<&str>,
        since: Option<&str>,
    ) -> Result<Reply> {
        let scope = scope.unwrap_or("open");
        if !matches!(scope, "mine" | "claimable" | "open" | "all") {
            return Err(bad(format!(
                "scope is mine, claimable, open or all, not '{scope}'"
            )));
        }
        let offset = parse_offset(since)?;
        let mut tasks: Vec<Task> = Vec::new();
        for task in ferryman_channel::list_tasks(route)? {
            let done = finished(&task.state());
            let keep = match scope {
                "all" => true,
                "open" => !done,
                "mine" => !done && self.is_mine(&task),
                // Claimable is the costly one: it checks signatures and dependencies.
                _ => {
                    !done
                        && ferryman_channel::work_among(route, &self.me, vec![task.clone()])
                            .map(|w| !w.is_empty())
                            .unwrap_or(false)
                }
            };
            if keep {
                tasks.push(task);
            }
        }
        let total = tasks.len();
        let identity = self.identity().ok();
        let page: Vec<&Task> = tasks.iter().skip(offset).take(MAX_ITEMS).collect();
        let mut shown: Vec<Value> = Vec::new();
        for task in &page {
            if let Some(identity) = &identity {
                let _ = ferryman_channel::receipts::record_read(route, &task.order.id, identity);
            }
            let mut r = json!({ "id": task.order.id, "title": title_of(task, TITLE_CHARS), "state": state_name(&task.state()) });
            if let Some(h) = task.holder() {
                r["holder"] = json!(h);
            }
            shown.push(r);
        }
        let mut data = json!({ "orders": shown, "scope": scope, "total": total });
        // Fit to the cap before deciding where the cursor points, so `next` names the
        // first order the caller has not been shown.
        let mut reply = Reply::new(String::new(), json!({}));
        let cap = cap_tokens("ferry_orders") * 4 - 260;
        while len_of(&data) > cap.min(MAX_CHARS - 200) {
            match data.get_mut("orders") {
                Some(Value::Array(rows)) if !rows.is_empty() => {
                    rows.pop();
                }
                _ => break,
            }
        }
        let count = data["orders"].as_array().map_or(0, Vec::len);
        let hidden = total.saturating_sub(offset + count);
        data["shown"] = json!(count);
        data["hidden"] = json!(hidden);
        if hidden > 0 {
            data["next"] = json!(format!("o{}", offset + count));
            data["truncated"] = json!(true);
        }
        reply.text = format!(
            "{total} order(s), scope {scope}; showing {count}, {hidden} not shown{}",
            if hidden > 0 {
                ". More: list again with since = next"
            } else {
                ""
            }
        );
        reply.data = data;
        Ok(reply)
    }

    fn orders_create(&self, route: &ProjectRoute, args: &Value) -> Result<Reply> {
        self.require_write("create orders")?;
        let title = need(args, "title", "create")?;
        if title.chars().count() > 120 {
            return Err(bad(
                "a title is at most 120 characters; the detail goes in task",
            ));
        }
        let detail = arg_str(args, "task").unwrap_or("");
        if detail.chars().count() > 3000 {
            return Err(bad(
                "task is at most 3000 characters; put the long brief in the work repo and name the file",
            ));
        }
        let to = match arg_str(args, "to") {
            None => None,
            Some(who) if matches!(who.to_ascii_lowercase().as_str(), "open" | "anyone" | "all") => {
                None
            }
            Some(who) => {
                if !ferryman_channel::is_safe_component(who) {
                    return Err(bad(
                        "to is an agent or machine name: letters, digits, '.', '-' and '_'",
                    ));
                }
                let known = self
                    .route()
                    .agents
                    .iter()
                    .any(|a| ferryman_channel::addressed_to(who, &a.name));
                if !known {
                    return Err(bad(format!(
                        "nobody called '{who}' is on this project. ferry_join shows who is alive; leave to out for an order open to anyone"
                    )));
                }
                Some(who.to_ascii_lowercase())
            }
        };
        let kind = match arg_str(args, "kind") {
            Some(kind) => Some(
                serde_json::from_value::<ferryman_channel::work::WorkKind>(json!(
                    kind.to_ascii_lowercase()
                ))
                .map_err(|_| bad(format!("kind '{kind}' is not one this server knows")))?,
            ),
            None => None,
        };
        let size = match arg_str(args, "size") {
            Some(size) => {
                Some(ferryman_channel::work::Size::parse(size).map_err(|e| bad(format!("{e}")))?)
            }
            None => None,
        };
        let priority = match arg_str(args, "priority") {
            Some(p) => Some(ferryman_channel::Priority::parse(p).map_err(|e| bad(format!("{e}")))?),
            None => None,
        };
        let mut depends_on = Vec::new();
        for dep in args
            .get("depends_on")
            .and_then(Value::as_array)
            .into_iter()
            .flatten()
            .filter_map(Value::as_str)
        {
            read_order(route, dep).map_err(|_| {
                bad(format!(
                    "depends_on names '{dep}', which is not an order here"
                ))
            })?;
            depends_on.push(dep.to_string());
        }
        let identity = self.identity()?;
        let id = format!("o-{}-{}", self.me, Utc::now().timestamp_millis());
        let text = if detail.is_empty() {
            title.to_string()
        } else {
            format!("{title}\n\n{detail}")
        };
        let needs = Some(ferryman_channel::work::ExplicitNeeds {
            kind,
            size,
            ..ferryman_channel::work::ExplicitNeeds::default()
        })
        .filter(|needs| !needs.is_empty());
        let mut order = ferryman_channel::Order {
            id: id.clone(),
            project_id: route.project_id.clone(),
            issued_by: self.me.clone(),
            assigned_to: to.clone(),
            created_at: Utc::now(),
            payload: json!({ "task": text }),
            // What an agent hands out comes back reviewed.
            requires_review: true,
            requires_approval: false,
            depends_on,
            signed_by: None,
            signature: None,
            result_contract: None,
            interface: None,
            touches: Vec::new(),
            needs,
            allow_overlap: false,
            priority,
        };
        identity.sign_order(&mut order);
        ferryman_channel::issue_order(route, &order)?;
        let _ = ferryman_channel::ledger::append_ledger_entry(
            route,
            &identity,
            "order",
            &self.me,
            &format!("issued order {id}"),
            Some(&id),
        );
        Ok(Reply::new(
            format!(
                "created {id}, {}",
                match &to {
                    Some(who) => format!("addressed to {who}"),
                    None => "open to anyone".to_string(),
                }
            ),
            json!({ "id": id, "state": "open", "to": to, "next": "ferry_orders list" }),
        ))
    }

    fn orders_show(&self, route: &ProjectRoute, id: &str) -> Result<Reply> {
        safe_id(id)?;
        let task = read_order(route, id)?;
        let needs = task.order.needs.clone();
        let mut data = json!({
            "id": id,
            "title": title_of(&task, 120),
            "state": state_name(&task.state()),
            "issued_by": task.order.issued_by,
            "work_repo": route.workspace.display().to_string(),
            "results": task.results.len(),
            "run_via": ferryman_ops::heavy::run_via(route, needs.as_ref()).as_str(),
        });
        if let Some(h) = task.holder() {
            data["holder"] = json!(h);
        }
        if let Some(a) = &task.order.assigned_to {
            data["assigned_to"] = json!(a);
        }
        if task.order.requires_review {
            data["review"] = json!(true);
        }
        if task.order.requires_approval {
            data["approval"] = json!(true);
        }
        if let Some(needs) = &needs {
            if needs.heavy {
                data["heavy"] = json!(true);
            }
            if let Some(hints) = &needs.hints {
                data["hints"] = serde_json::to_value(hints).unwrap_or(Value::Null);
            }
        }
        let mut reply = Reply::new(format!("{id}: {}", state_name(&task.state())), data);
        reply.links.push(json!({
            "type": "resource_link",
            "uri": format!("ferry://{}/order/{id}", route.project_id),
            "name": id,
            "mimeType": "text/plain",
        }));
        Ok(reply)
    }

    // -- talk -------------------------------------------------------------------------

    fn send(
        &self,
        route: &ProjectRoute,
        identity: &AgentIdentity,
        to: &str,
        text: &str,
    ) -> Result<String> {
        let mut message = Message::new(
            route.project_id.clone(),
            self.me.clone(),
            to,
            "text/plain",
            json!({ "text": text }),
            false,
            None,
        );
        identity.sign(&mut message);
        let id = message.id.clone();
        let mut engine = match crate::lane::carried_by_iroh(route) {
            Some(_) => ferryman_channel::system_delivery_engine_carried("iroh"),
            None => ferryman_channel::system_delivery_engine(),
        };
        engine.send(route, &message)?;
        Ok(id)
    }

    fn talk(&self, args: &Value) -> Result<Reply> {
        let route = self.route();
        match need(args, "action", "ferry_talk")? {
            "read" => self.talk_read(
                &route,
                arg_str(args, "since"),
                args.get("peek").and_then(Value::as_bool).unwrap_or(false),
            ),
            "post" => {
                self.require_work("post")?;
                let to = need(args, "to", "post")?.to_ascii_lowercase();
                let text = need(args, "text", "post")?;
                if text.chars().count() > 1500 {
                    return Err(bad(
                        "a message is at most 1500 characters; put detail in the work repo",
                    ));
                }
                guard("text", text)?;
                not_work("text", text)?;
                if to.contains("telegram") {
                    return Err(bad("Telegram is never a target"));
                }
                let Some(target) = route.agents.iter().find(|a| is_me(&a.name, &to)) else {
                    return Err(bad(format!("no agent called '{to}' on this channel")));
                };
                if target.role == "bridge" || target.name.contains("telegram") {
                    return Err(bad("Telegram is never a target"));
                }
                let identity = self.identity()?;
                let id = self.send(&route, &identity, &to, text)?;
                Ok(Reply::new(format!("sent to {to}"), json!({ "id": id })))
            }
            other => Err(bad(format!("unknown action '{other}'"))),
        }
    }

    fn talk_read(&self, route: &ProjectRoute, since: Option<&str>, peek: bool) -> Result<Reply> {
        let cursor = match since {
            Some(c) => Some(parse_msg_cursor(c)?),
            None => None,
        };
        let now = Utc::now();
        let mut mine: Vec<Message> = ferryman_channel::list_messages(route)?
            .into_iter()
            .filter(|m| !m.sender.eq_ignore_ascii_case(&self.me))
            .filter(|m| {
                let direct = m.recipient.eq_ignore_ascii_case(&self.me);
                let broadcast = m.recipient == "all";
                if !(direct || broadcast) {
                    return false;
                }
                match &cursor {
                    Some((ms, id)) => {
                        (m.created_at.timestamp_millis(), m.id.clone()) > (*ms, id.clone())
                    }
                    None if direct => !ferryman_channel::is_acknowledged(route, &m.id),
                    None => (now - m.created_at).num_hours() < 6,
                }
            })
            .collect();
        mine.sort_by_key(|m| (m.created_at, m.id.clone()));
        let total = mine.len();
        let cap = cap_tokens("ferry_talk") * 4 - 200;
        let mut count = mine.len().min(MAX_ITEMS);
        let (rows, links) = loop {
            let mut rows = Vec::new();
            let mut links = Vec::new();
            for m in mine.iter().take(count) {
                let body = message_text(m);
                let mut row = json!({
                    "id": m.id,
                    "from": m.sender,
                    "at": m.created_at.format("%m-%d %H:%M").to_string(),
                    "text": short(&body, 300),
                });
                if m.recipient == "all" {
                    row["to"] = json!("all");
                }
                if !matches!(
                    ferryman_channel::verify_message(m, &route.agents),
                    SignatureCheck::Valid
                ) {
                    row["unverified"] = json!(true);
                }
                if body.chars().count() > 300 {
                    row["more"] = json!(true);
                    links.push(json!({
                        "type": "resource_link",
                        "uri": format!("ferry://{}/msg/{}", route.project_id, m.id),
                        "name": "full message",
                        "mimeType": "text/plain",
                    }));
                }
                rows.push(row);
            }
            let size = len_of(&json!(rows)) + links.iter().map(len_of).sum::<usize>();
            if size <= cap || count <= 1 {
                break (rows, links);
            }
            count -= 1;
        };
        let returned = &mine[..rows.len().min(mine.len())];
        if !peek {
            for m in returned
                .iter()
                .filter(|m| m.recipient.eq_ignore_ascii_case(&self.me))
            {
                let _ = ferryman_channel::record_acknowledgement(
                    route,
                    &Acknowledgement {
                        message_id: m.id.clone(),
                        project_id: route.project_id.clone(),
                        recipient: m.recipient.clone(),
                        processed_at: Utc::now(),
                        idempotency_key: m.idempotency_key.clone(),
                    },
                );
            }
        }
        let next = returned
            .last()
            .map(msg_cursor)
            .or_else(|| since.map(str::to_string))
            .unwrap_or_else(|| format!("t{}.", now.timestamp_millis()));
        let mut data = json!({ "messages": rows, "next": next });
        if returned.len() < total {
            data["truncated"] = json!(true);
            data["left"] = json!(total - returned.len());
        }
        let mut reply = Reply::new(format!("{} new message(s)", returned.len()), data);
        reply.links = links;
        Ok(reply)
    }

    // -- ask_human --------------------------------------------------------------------

    /// This agent's asks, oldest first: `(id, state, note)`.
    fn my_asks(&self, route: &ProjectRoute) -> Vec<(String, &'static str, Option<String>)> {
        ferryman_channel::questions::list(route)
            .into_iter()
            .filter(|(q, _)| q.kind == ASK_KIND && is_me(&q.asked_by, &self.me))
            .map(|(q, answer)| {
                let (state, note) = ask_state(answer.as_ref().map(|a| a.answer.as_str()));
                (q.id, state, note)
            })
            .collect()
    }

    fn ask_human(&self, args: &Value) -> Result<Reply> {
        let route = self.route();
        match need(args, "action", "ferry_ask_human")? {
            "raise" => {
                self.require_write("ask the human")?;
                let title = need(args, "title", "raise")?;
                let recommendation = need(args, "recommendation", "raise")?;
                let reasoning = need(args, "reasoning", "raise")?;
                if title.chars().count() > 120 || recommendation.chars().count() > 300 {
                    return Err(bad("title is at most 120 characters, recommendation 300"));
                }
                if reasoning.chars().count() > 1200 {
                    return Err(bad("reasoning is at most 1200 characters"));
                }
                for (field, text) in [
                    ("title", title),
                    ("recommendation", recommendation),
                    ("reasoning", reasoning),
                ] {
                    guard(field, text)?;
                }
                let identity = self.identity()?;
                let id = format!("ask-{}-{}", self.me, Utc::now().timestamp_millis());
                let text = format!("{title}\nRecommendation: {recommendation}\nWhy: {reasoning}");
                let options = [
                    ASK_APPROVE.to_string(),
                    ASK_REJECT.to_string(),
                    "send back".to_string(),
                ];
                ferryman_channel::questions::ask(
                    &route, &identity, &id, ASK_KIND, &text, &options, None,
                )?;
                Ok(Reply::new(
                    format!("asked the human ({id})"),
                    json!({ "id": id, "state": "pending" }),
                ))
            }
            "status" => {
                let asks = self.my_asks(&route);
                match arg_str(args, "id") {
                    Some(id) => {
                        let Some((id, state, note)) = asks.into_iter().find(|(i, _, _)| i == id)
                        else {
                            return Err(bad(format!("you have no ask '{id}'")));
                        };
                        let mut data = json!({ "id": id, "state": state });
                        if let Some(n) = note {
                            data["note"] = json!(short(&n, 300));
                        }
                        Ok(Reply::new(format!("{id}: {state}"), data))
                    }
                    None => {
                        let list: Vec<Value> = asks
                            .iter()
                            .rev()
                            .take(5)
                            .map(|(id, state, _)| json!({ "id": id, "state": state }))
                            .collect();
                        Ok(Reply::new(
                            format!("{} ask(s)", asks.len()),
                            json!({ "asks": list }),
                        ))
                    }
                }
            }
            other => Err(bad(format!("unknown action '{other}'"))),
        }
    }

    // -- resources --------------------------------------------------------------------

    /// `resources/read` for `ferry://<project>/{order,msg,brief}/<id>`. Nothing here takes
    /// a path from the caller, so nothing outside the channel's records can be reached.
    pub fn read_resource(&self, uri: &str) -> Result<Value> {
        self.require_seated()?;
        let route = self.route();
        let rest = uri
            .strip_prefix("ferry://")
            .ok_or_else(|| bad("a ferry:// uri"))?;
        let parts: Vec<&str> = rest.split('/').collect();
        let [project, kind, id] = parts.as_slice() else {
            return Err(bad("ferry://<project>/<order|msg|brief>/<id>"));
        };
        if *project != route.project_id {
            return Err(bad("that is another project"));
        }
        safe_id(id)?;
        let text = match *kind {
            "order" => {
                let task = read_order(&route, id)?;
                let mut out = format!(
                    "{}\n\nstate: {}\nissued by: {}\n",
                    task.order
                        .payload
                        .get("task")
                        .and_then(Value::as_str)
                        .map_or_else(|| task.order.payload.to_string(), str::to_string),
                    state_name(&task.state()),
                    task.order.issued_by
                );
                for r in &task.results {
                    out.push_str(&format!(
                        "\nresult r{} by {}:\n{}\n",
                        r.revision,
                        r.agent,
                        result_text(&r.payload)
                    ));
                }
                for r in &task.reviews {
                    out.push_str(&format!(
                        "\nreview r{} by {}: {} {}\n",
                        r.revision,
                        r.reviewer,
                        if r.accepted { "accepted" } else { "changes" },
                        r.notes.clone().unwrap_or_default()
                    ));
                }
                out
            }
            "msg" => {
                let message = ferryman_channel::read_message(&route, id)?;
                let mine = message.recipient == "all"
                    || message.recipient.eq_ignore_ascii_case(&self.me)
                    || message.sender.eq_ignore_ascii_case(&self.me);
                if !mine {
                    return Err(denied("that message is not yours"));
                }
                message_text(&message)
            }
            "brief" => {
                let brief = marvin::read_brief(&route, id)?.ok_or_else(|| bad("no such brief"))?;
                format!(
                    "{}\n\nconstraints:\n{}\n\nin flight:\n{}\n\ndecided:\n{}\n\nrejected:\n{}\n\nwaiting on human:\n{}\n\nnext:\n{}\n",
                    brief.objective,
                    brief.constraints,
                    brief.in_flight,
                    brief.decided,
                    brief.rejected,
                    brief.waiting_on_human,
                    brief.next
                )
            }
            other => return Err(bad(format!("unknown resource kind '{other}'"))),
        };
        let text: String = text.chars().take(16_000).collect();
        let (text, redacted) = match redact_text(&text) {
            Some(clean) => (clean, true),
            None => (text, false),
        };
        let mut content = json!({ "uri": uri, "mimeType": "text/plain", "text": text });
        if redacted {
            content["redacted"] = json!(true);
        }
        Ok(json!({ "contents": [content] }))
    }

    // -- admin ------------------------------------------------------------------------

    fn get(&self, args: &Value) -> Result<Reply> {
        let uri = need(args, "uri", "ferry_get")?;
        let read = self.read_resource(uri)?;
        let text = read["contents"][0]["text"]
            .as_str()
            .unwrap_or("")
            .to_string();
        let capped: String = text.chars().take(3000).collect();
        let mut data =
            json!({ "uri": uri, "text": capped, "truncated": text.chars().count() > 3000 });
        if read["contents"][0]["redacted"] == json!(true) {
            data["redacted"] = json!(true);
        }
        Ok(Reply::new(format!("{} chars", text.chars().count()), data))
    }

    fn search(&self, args: &Value) -> Result<Reply> {
        let route = self.route();
        let query = need(args, "query", "ferry_search")?;
        let offset = parse_offset(arg_str(args, "since"))?;
        let claims = ferryman_channel::ask::ask(&route, query)?;
        let total = claims.len();
        let hits: Vec<Value> = claims
            .iter()
            .skip(offset)
            .take(8)
            .map(
                |c| json!({ "source": c.source, "at": c.location, "text": short(&c.excerpt, 140) }),
            )
            .collect();
        let shown = hits.len();
        let mut data = json!({ "hits": hits });
        if offset + shown < total {
            data["next"] = json!(format!("o{}", offset + shown));
        }
        Ok(Reply::new(format!("{total} hit(s)"), data))
    }

    fn status(&self) -> Result<Reply> {
        let route = self.route();
        let tasks = ferryman_channel::list_tasks(&route)?;
        let mut counts = std::collections::BTreeMap::new();
        for task in &tasks {
            *counts.entry(state_name(&task.state())).or_insert(0usize) += 1;
        }
        let ledger = ferryman_channel::ledger::read_ledger(&route).map_or(0, |l| l.entries.len());
        Ok(Reply::new(
            format!("{} task(s)", tasks.len()),
            json!({ "project": route.project_id, "tasks": counts, "agents": route.agents.len(), "ledger": ledger }),
        ))
    }

    // -- updates ----------------------------------------------------------------------

    /// The newest release the master signed an approval for, if any verifies. This is the
    /// only source of "an update exists": a public tag or a release page is not consent.
    fn approved_release(
        &self,
        route: &ProjectRoute,
    ) -> Option<ferryman_channel::release::ReleaseApproval> {
        let master = ferryman_channel::master::read_master(route)
            .ok()
            .flatten()?;
        ferryman_channel::release::list_approvals(route)
            .into_iter()
            .filter(|a| is_me(&a.approved_by, &master.master))
            .filter(|a| is_me(a.signed_by.as_deref().unwrap_or(""), &master.master))
            .filter(|a| {
                ferryman_channel::release::verify_approval(a, &route.agents)
                    == SignatureCheck::Valid
            })
            .max_by_key(|a| crate::update::parts(&a.version))
    }

    /// The master-approved release newer than what is running.
    fn newer_release(
        &self,
        route: &ProjectRoute,
    ) -> Option<ferryman_channel::release::ReleaseApproval> {
        self.approved_release(route)
            .filter(|a| crate::update::is_newer(&a.version))
    }

    /// The compact `update` field (about 40 tokens). Absent when the master has approved
    /// nothing newer than what runs here.
    fn update_field(&self, route: &ProjectRoute) -> Option<Value> {
        let latest = self.newer_release(route)?.version;
        let fleet = route.attachment.join("agent.toml").is_file();
        let auto = fleet
            && !std::env::var("FERRYMAN_NO_AUTO_UPDATE").is_ok_and(|v| !v.is_empty() && v != "0");
        let how = if fleet {
            "ferry update".to_string()
        } else {
            format!(
                "download ferry-{} from github.com/estejosh/ferryman/releases/latest",
                crate::update::target_triple().unwrap_or("<your platform>")
            )
        };
        Some(json!({
            "current": env!("CARGO_PKG_VERSION"),
            "latest": latest.trim_start_matches('v'),
            "auto": auto,
            "how": how,
        }))
    }

    fn update(&self, args: &Value) -> Result<Reply> {
        let route = self.route();
        let action = need(args, "action", "ferry_update")?;
        match action {
            "check" => {
                let view = self.newer_release(&route);
                let mut data =
                    json!({ "current": env!("CARGO_PKG_VERSION"), "available": view.is_some() });
                if let Some(latest) = &view {
                    data["latest"] = json!(latest.version.trim_start_matches('v'));
                    if let Some(field) = self.update_field(&route) {
                        data["how"] = field["how"].clone();
                        data["auto"] = field["auto"].clone();
                    }
                }
                Ok(Reply::new(
                    match &view {
                        Some(a) => {
                            format!("update available: {}", a.version.trim_start_matches('v'))
                        }
                        None => "up to date".to_string(),
                    },
                    data,
                ))
            }
            "apply" => {
                let level = self.level();
                if level < Level::Orchestrator {
                    return Err(denied(format!(
                        "level {} cannot update this machine; only an Orchestrator can. Tell the human",
                        level.as_str()
                    )));
                }
                if let Some(note) = self.paused(&route) {
                    return Err(denied(format!(
                        "cannot update while paused ({}). Tell the human",
                        short(&note, 120)
                    )));
                }
                let Some(approval) = self.newer_release(&route) else {
                    return Ok(Reply::new(
                        "already current",
                        json!({ "current": env!("CARGO_PKG_VERSION"), "available": false }),
                    ));
                };
                // The download is checked against the hash inside the master's signed
                // approval, not a checksum file next to the release. No hash for this
                // platform, no install.
                let Some(target) = crate::update::target_triple() else {
                    return Err(refusal(
                        "refused",
                        "there is no published build for this platform; build from source",
                    ));
                };
                let Some(sha256) = approval.artifacts.get(target).cloned() else {
                    return Err(refusal(
                        "refused",
                        format!(
                            "the master's approval of {} pins no checksum for {target}, so it cannot be verified here. Ask the master to approve it with checksums, or run `ferry update`",
                            approval.version
                        ),
                    ));
                };
                let tag = format!("v{}", approval.version.trim_start_matches('v'));
                let installed = run_blocking({
                    let tag = tag.clone();
                    async move {
                        crate::update::apply_pinned(&tag, &sha256)
                            .await
                            .map_err(|e| format!("{e:#}"))
                    }
                })
                .ok_or_else(|| anyhow!("the update did not run"))?
                .map_err(|e| anyhow!("{e}"))?;
                Ok(Reply::new(
                    format!("installed {installed}; it takes effect when the worker restarts"),
                    json!({ "installed": installed, "available": false }),
                ))
            }
            other => Err(bad(format!("unknown action '{other}'"))),
        }
    }
}
// ---------------------------------------------------------------------------------------
// Pieces shared with mcp.rs

#[must_use]
pub fn state_name(state: &TaskState) -> &'static str {
    match state {
        TaskState::Open => "open",
        TaskState::Offered { .. } => "offered",
        TaskState::Claimed { .. } => "claimed",
        TaskState::Stale { .. } => "stale",
        TaskState::AwaitingReview { .. } => "awaiting_review",
        TaskState::ChangesRequested { .. } => "changes_requested",
        TaskState::Accepted => "accepted",
        TaskState::Done => "done",
        TaskState::Refuted { .. } => "refuted",
        TaskState::Killed { .. } => "killed",
    }
}

/// The readable text of a result payload, whatever shape the agent chose.
#[must_use]
pub fn result_text(payload: &Value) -> String {
    match payload {
        Value::String(text) => text.clone(),
        other => match (
            other
                .get("output")
                .or_else(|| other.get("result"))
                .or_else(|| other.get("text"))
                .and_then(Value::as_str),
            other.get("ref").and_then(Value::as_str),
        ) {
            (Some(text), Some(r)) => format!("{text} (ref {r})"),
            (Some(text), None) => text.to_string(),
            (None, _) => serde_json::to_string(other).unwrap_or_default(),
        },
    }
}

/// A human's signed answer to an ask, as a state and note. The agent only ever reads it.
#[must_use]
pub fn ask_state(answer: Option<&str>) -> (&'static str, Option<String>) {
    match answer.map(str::trim) {
        None => ("pending", None),
        Some(text) => {
            // Only the exact option strings count; "approve only if X" is a send back.
            if text == ASK_APPROVE {
                ("approved", None)
            } else if text == ASK_REJECT {
                ("rejected", None)
            } else {
                ("sent_back", Some(text.to_string()))
            }
        }
    }
}

/// Run a future to completion on its own thread and runtime: this server is synchronous
/// stdio and may be called from inside an async main.
fn run_blocking<F>(future: F) -> Option<F::Output>
where
    F: std::future::Future + Send + 'static,
    F::Output: Send + 'static,
{
    std::thread::spawn(move || {
        tokio::runtime::Builder::new_current_thread()
            .enable_all()
            .build()
            .ok()
            .map(|runtime| runtime.block_on(future))
    })
    .join()
    .ok()
    .flatten()
}

/// Fail early with a clear message when `--as` names something that cannot be an agent.
pub fn check_agent_name(name: &str) -> Result<()> {
    if name.trim().is_empty() || !ferryman_channel::is_safe_component(name) {
        bail!("--as takes an agent name: letters, digits, '.', '-' and '_'");
    }
    Ok(())
}

// ---------------------------------------------------------------------------------------
// Zero-config identities: an app seats itself as a Worker.

/// The identity an app gets on this machine: `<client>-<machine>`, from the name the client
/// announced in `initialize` (`codex`, `claude-code`, ...) and this machine's name.
#[must_use]
pub fn app_name(client: Option<&str>) -> String {
    let words = |text: &str| -> String {
        let mut out = String::new();
        for c in text.to_ascii_lowercase().chars() {
            if c.is_ascii_alphanumeric() {
                out.push(c);
            } else if !out.ends_with('-') && !out.is_empty() {
                out.push('-');
            }
        }
        out.trim_end_matches('-').chars().take(24).collect()
    };
    let client = client.map(words).filter(|c| !c.is_empty());
    let machine =
        Some(words(&ferryman_channel::receipts::machine_label())).filter(|m| !m.is_empty());
    match (client, machine) {
        (Some(c), Some(m)) if c.ends_with(&format!("-{m}")) => c,
        (Some(c), Some(m)) => format!("{c}-{m}"),
        (Some(c), None) => c,
        (None, Some(m)) => format!("app-{m}"),
        (None, None) => "app".to_string(),
    }
}

/// Seat `name` in `route` as an app: its key from the machine keystore (made if this is
/// the first time), published on the roster under [`access::APP_ROLE`], which makes it a
/// Worker. Never the master, and never over a name another key already holds. Idempotent.
pub fn seat_app(route: &ProjectRoute, name: &str) -> Result<()> {
    let name = ferryman_channel::canonical_agent_name(name);
    let master = ferryman_channel::master::read_master(route).ok().flatten();
    if master.is_some_and(|m| is_me(&m.master, &name)) {
        bail!(
            "'{name}' is the master of {}; the master is never an app",
            route.project_id
        );
    }
    let identity = AgentIdentity::load_or_create(&name, &route.attachment)?;
    let key = identity.public_key_hex();
    // The project's own roster file, not the merged view: that one also lists the
    // machine-wide fleet roster, which would say "seated" for every project after the first.
    let on_roster = std::fs::read_to_string(
        route
            .communications
            .join("agents")
            .join(format!("{name}.json")),
    )
    .ok()
    .and_then(|text| serde_json::from_str::<ferryman_channel::AgentRoute>(&text).ok())
    .is_some_and(|entry| {
        entry.public_key.as_deref() == Some(key.as_str()) && entry.role == access::APP_ROLE
    });
    if on_roster {
        return Ok(());
    }
    let encryption =
        ferryman_channel::secrets::EncryptionIdentity::load_or_create(&name, &route.attachment)?;
    ferryman_channel::register_agent_key(
        route,
        &ferryman_channel::AgentRoute {
            name,
            role: access::APP_ROLE.to_string(),
            capabilities: vec!["messages.receive".to_string()],
            public_key: None,
            encryption_key: Some(encryption.public_key_hex()),
        },
        &identity,
    )?;
    Ok(())
}

/// The projects `name` is, or would be, seated in, with the level it has or would get (a
/// Worker). For showing a person what they are connecting before anything is written.
#[must_use]
pub fn app_seats(name: &str, source: &RouteSource) -> Vec<(String, Level)> {
    source()
        .into_iter()
        .filter(|route| {
            let master = ferryman_channel::master::read_master(route).ok().flatten();
            !master.is_some_and(|m| is_me(&m.master, name))
        })
        .map(|route| {
            let level = match Agent::new(route.clone(), name, false) {
                Ok(agent) if agent.seated() => agent.level(),
                _ => Level::Worker,
            };
            (route.project_id, level)
        })
        .filter(|(_, level)| *level != Level::Orchestrator)
        .collect()
}

/// Seat `name` in every project `source` offers. Returns how many it is now seated in.
pub fn seat_everywhere(name: &str, source: &RouteSource) -> usize {
    source()
        .iter()
        .filter(|route| seat_app(route, name).is_ok())
        .count()
}

// ---------------------------------------------------------------------------------------
// All-projects mode: one connection, every live project (ADR 0031, "Decision" 2).

/// How many seats are at each level, `{"worker": 24, "member": 1}`.
fn level_counts(open: &[(ProjectRoute, Level)]) -> Value {
    let mut counts = std::collections::BTreeMap::new();
    for (_, level) in open {
        *counts.entry(level.as_str()).or_insert(0usize) += 1;
    }
    json!(counts)
}

/// What each level present among `open` may do, said once.
fn can_map(open: &[(ProjectRoute, Level)]) -> Value {
    let mut map = Map::new();
    for (_, level) in open {
        map.insert(level.as_str().to_string(), json!(can(*level)));
    }
    Value::Object(map)
}

/// "Your seats: a, b, c ..." for a message that tells the caller where it can act.
fn seats(open: &[(ProjectRoute, Level)]) -> String {
    if open.is_empty() {
        return "You have no seats on this machine.".to_string();
    }
    let names: Vec<&str> = open
        .iter()
        .map(|(route, _)| route.project_id.as_str())
        .take(8)
        .collect();
    format!(
        "Your seats: {}{} (ferry_join lists them all)",
        names.join(", "),
        if open.len() > 8 { ", ..." } else { "" }
    )
}

/// Where an all-projects server finds its projects. Asked again on every call, so a project
/// that is archived or added shows up without a restart.
pub type RouteSource = std::sync::Arc<dyn Fn() -> Vec<ProjectRoute> + Send + Sync>;

/// Every live, non-archived project in the ferry root, as `ferry agent run --all-projects`
/// counts them: archived ones are left out, and so is any whose checkout or channel cannot
/// be read here.
#[must_use]
pub fn root_routes() -> Vec<ProjectRoute> {
    let Some(root) = ferryman_channel::ferry::find_root() else {
        return Vec::new();
    };
    root.read()
        .projects
        .iter()
        .filter(|entry| !entry.is_archived())
        .filter_map(|entry| entry.route(&root).ok().map(|(route, _)| route))
        .collect()
}

/// One identity across many projects. The per-project checks are the single-project
/// [`Agent`]'s, built fresh for the project a call names: the level comes from the
/// master-signed grants of that project, and a project where the identity is not seated is
/// not offered.
pub struct AllProjects {
    pub me: String,
    pub admin: bool,
    /// Served over HTTP to a cloud app: only Worker and Member seats are offered.
    pub remote: bool,
    source: RouteSource,
    /// The guide has been sent with a join already.
    guided: std::sync::atomic::AtomicBool,
}

impl AllProjects {
    pub fn new(me: &str, admin: bool, remote: bool, source: RouteSource) -> Result<Self> {
        check_agent_name(me)?;
        Ok(Self {
            me: ferryman_channel::canonical_agent_name(me),
            admin,
            remote,
            source,
            guided: std::sync::atomic::AtomicBool::new(false),
        })
    }

    /// The projects this identity is seated in, with its level in each.
    #[must_use]
    pub fn open(&self) -> Vec<(ProjectRoute, Level)> {
        (self.source)()
            .into_iter()
            .filter_map(|route| {
                // The master identity is refused here too (Agent::new).
                let agent = Agent::new(route.clone(), &self.me, self.admin).ok()?;
                if !agent.seated() {
                    return None;
                }
                let level = agent.level();
                if self.remote && level == Level::Orchestrator {
                    return None;
                }
                Some((route, level))
            })
            .collect()
    }

    /// The core tools with a `project` argument added to each.
    #[must_use]
    pub fn tools(&self) -> Vec<Value> {
        let mut all = core_tools();
        if self.admin {
            all.extend(admin_tools());
        }
        for tool in &mut all {
            if let Some(props) = tool["inputSchema"]["properties"].as_object_mut() {
                props.insert(
                    "project".into(),
                    json!({ "type": "string", "description": "which project, from ferry_join" }),
                );
            }
        }
        all
    }

    pub fn call(&self, name: &str, args: &Value) -> Value {
        match self.call_inner(name, args) {
            Ok(result) => result,
            Err(error) => error_result(&error),
        }
    }

    fn call_inner(&self, name: &str, args: &Value) -> Result<Value> {
        layout_guard(name, args)?;
        let mut args = args.clone();
        let project = args
            .as_object_mut()
            .and_then(|map| map.remove("project"))
            .and_then(|v| v.as_str().map(String::from));
        let open = self.open();
        if name == "ferry_join" && project.is_none() {
            return self.join_all(&open, arg_str(&args, "since"));
        }
        if name == "ferry_help" && project.is_none() {
            return Ok(self.help_all(&open));
        }
        if !name.starts_with("ferry_") {
            return Err(bad(format!("unknown tool: {name}")));
        }
        let (route, _) = self.pick(&open, project.as_deref())?;
        let agent = Agent::new(route, &self.me, self.admin)?;
        // The guide goes out once per connection, not once per project.
        if self.guided.load(std::sync::atomic::Ordering::Relaxed) {
            agent
                .guided
                .store(true, std::sync::atomic::Ordering::Relaxed);
        } else if name == "ferry_join" {
            self.guided
                .store(true, std::sync::atomic::Ordering::Relaxed);
        }
        Ok(agent.call(name, &args))
    }

    fn pick(
        &self,
        open: &[(ProjectRoute, Level)],
        project: Option<&str>,
    ) -> Result<(ProjectRoute, Level)> {
        match project {
            Some(id) => open
                .iter()
                .find(|(route, _)| route.project_id == id)
                .cloned()
                .ok_or_else(|| {
                    bad(format!(
                        "you are not seated in project '{id}'. {}",
                        seats(open)
                    ))
                }),
            None if open.len() == 1 => Ok(open[0].clone()),
            None if open.is_empty() => Err(bad(
                "you are not seated in any project on this machine. Tell the human to run `ferry enable` in a project folder, or to seat you in the Ferryman dashboard (Agents)",
            )),
            None => Err(bad(format!("pass project on this call. {}", seats(open)))),
        }
    }

    /// The guide with this identity's levels, for `ferry_help` with no project.
    fn help_all(&self, open: &[(ProjectRoute, Level)]) -> Value {
        let mut data = json!({
            "guide": INSTRUCTIONS,
            "agent": self.me,
            "levels": level_counts(open),
        });
        data["can"] = can_map(open);
        finish(Reply::new("the Ferryman guide", data), "ferry_help")
    }

    /// Every seat, a page at a time: what fits under the cap, then `next`. Nothing is
    /// dropped without a cursor to the rest.
    fn join_all(&self, open: &[(ProjectRoute, Level)], since: Option<&str>) -> Result<Value> {
        let offset = parse_offset(since)?.min(open.len());
        let total = open.len();
        let counts = level_counts(open);
        let level = match counts.as_object() {
            Some(map) if map.len() == 1 => map.keys().next().cloned().unwrap_or_default(),
            Some(map) if map.is_empty() => "none".to_string(),
            _ => "varies".to_string(),
        };
        let mut data = json!({
            "agent": self.me,
            "granted": !open.is_empty(),
            "level": level,
            "levels": counts,
            "total": total,
            "can": can_map(open),
        });
        if open.is_empty() {
            data["note"] = json!(format!(
                "'{}' is not seated in any live project on this machine. Tell the human to run `ferry enable` in a project folder, or to seat this app in the Ferryman dashboard (Agents)",
                self.me
            ));
        }
        if offset == 0 {
            if let Some((route, _)) = open.first()
                && let Ok(agent) = Agent::new(route.clone(), &self.me, self.admin)
                && let Some(update) = agent.update_field(route)
            {
                data["update"] = update;
            }
            if !self.guided.swap(true, std::sync::atomic::Ordering::Relaxed) {
                data["guide"] = json!(INSTRUCTIONS);
            }
        }
        let rows: Vec<Value> = open
            .iter()
            .skip(offset)
            .take(MAX_ITEMS)
            .map(|(route, level)| project_row(route, *level))
            .collect();
        let text = format!(
            "Ferryman MCP (beta): {} seated in {total} project(s), level {level}",
            self.me
        );
        // Leave room for the envelope and the paging fields, then take as many rows as fit.
        let budget = chars_for(cap_tokens("ferry_join")).min(MAX_CHARS) - text.len() - 330;
        let mut count = rows.len();
        data["projects"] = json!(rows);
        while count > 1 && len_of(&data) > budget {
            count -= 1;
            if let Some(Value::Array(rows)) = data.get_mut("projects") {
                rows.truncate(count);
            }
        }
        data["shown"] = json!(count);
        if offset + count < total {
            data["hidden"] = json!(total - offset - count);
            data["next"] = json!(format!("o{}", offset + count));
            data["more"] =
                json!("call ferry_join again with since = next for the rest of your projects");
        } else {
            data["next"] = json!("ferry_catchup with project");
        }
        Ok(finish(Reply::new(text, data), "ferry_join"))
    }

    /// `resources/read` for a `ferry://<project>/...` uri: the project in it picks the seat.
    pub fn read_resource(&self, uri: &str) -> Result<Value> {
        let project = uri
            .strip_prefix("ferry://")
            .and_then(|rest| rest.split('/').next())
            .unwrap_or("");
        let (route, _) = self.pick(&self.open(), Some(project))?;
        Agent::new(route, &self.me, self.admin)?.read_resource(uri)
    }
}

#[cfg(test)]
#[path = "mcp_agent_tests.rs"]
mod tests;
