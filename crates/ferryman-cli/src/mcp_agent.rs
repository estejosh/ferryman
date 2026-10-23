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

use std::collections::BTreeSet;
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

/// Server instructions (T3: at most 250 tokens, enforced in CI).
pub const INSTRUCTIONS: &str = "\
Ferryman channel. Files are the channel; nothing needs to be running.
1. Call ferry_join first, then ferry_catchup. Never read full history or the comms folder.
2. ferry_orders: claim, progress, submit, review. ferry_talk: read only what is new.
3. Heavy orders run through this machine's queue (snifrig) when present.
4. Work in the work repo; commit and push there. Never put work, code or files in the channel.
5. Never send secrets in messages. Use the vault flow (ferry channel secret).
6. If the primary is silent, ferry_primary status and follow its rule. The primary keeps its brief with the CLI: ferry marvin brief. Need a human: ferry_ask_human with a recommendation.
7. If join shows an update, tell the human. Never update mid-order.
More tools: start with --tools admin or --tools legacy.";

/// T4: the most items any response carries, and the most characters of structured data.
pub const MAX_ITEMS: usize = 20;
pub const MAX_CHARS: usize = 4000;

/// Minutes without a word from the primary before it reads as `quiet`. `silent` is the
/// quiet period Marvin already uses (`marvin::HOLDING_GOES_QUIET_AFTER_MINUTES`).
pub const QUIET_AFTER_MINUTES: i64 = 10;

/// The kind a question raised by `ferry_ask_human` carries.
pub const ASK_KIND: &str = "ask";

/// Per-response cap in tokens, T4/T10.
#[must_use]
pub fn cap_tokens(tool: &str) -> usize {
    match tool {
        "ferry_catchup" => 800,
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

fn refusal(kind: &'static str, why: impl Into<String>) -> anyhow::Error {
    anyhow::Error::new(Refusal {
        kind,
        why: why.into(),
    })
}

fn denied(why: impl Into<String>) -> anyhow::Error {
    refusal("denied", why)
}

fn bad(why: impl Into<String>) -> anyhow::Error {
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
    fn new(text: impl Into<String>, data: Value) -> Self {
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

fn finish(mut reply: Reply, tool: &str) -> Value {
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

/// The result for a failed call: one line of text, plus a machine-readable reason.
#[must_use]
pub fn error_result(error: &anyhow::Error) -> Value {
    let (kind, why) = match error.downcast_ref::<Refusal>() {
        Some(r) => (r.kind, r.why.clone()),
        None => ("error", format!("{error:#}")),
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

/// The six core tools, sorted by name.
#[must_use]
pub fn core_tools() -> Vec<Value> {
    let mut tools = vec![
        tool(
            "ferry_ask_human",
            "Ask the human to decide. raise needs title, recommendation, reasoning; status takes id. You can ask, never approve.",
            &json!({"type":"object","properties":{"action":{"enum":["raise","status"]},"title":{"type":"string"},"recommendation":{"type":"string"},"reasoning":{"type":"string"},"id":{"type":"string"}},"required":["action"]}),
            &["id", "state", "note"],
        ),
        tool(
            "ferry_catchup",
            "Resume in one call: primary, brief, decisions, open orders, yours, asks. Pass since for only what changed.",
            &json!({"type":"object","properties":{"since":{"type":"string"},"detail":{"type":"boolean"}}}),
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
            "ferry_join",
            "Announce yourself. Returns your level, who is primary and who is alive. Call first.",
            &json!({"type":"object","properties":{}}),
            &[
                "agent",
                "level",
                "granted",
                "primary",
                "alive",
                "mine_open",
                "queue",
                "update",
                "next",
            ],
        ),
        tool(
            "ferry_orders",
            "Orders. list, show, claim, progress (note), submit (ref = commit or hand-in id, note), review (verdict accept|changes).",
            &json!({"type":"object","properties":{"action":{"enum":["list","show","claim","progress","submit","review"]},"id":{"type":"string"},"note":{"type":"string"},"ref":{"type":"string"},"verdict":{"enum":["accept","changes"]},"notes":{"type":"string"},"since":{"type":"string"}},"required":["action"]}),
            &["orders", "id", "state", "run_via", "next"],
        ),
        tool(
            "ferry_primary",
            "Who leads. status, standby, takeover (only when the primary is silent), release.",
            &json!({"type":"object","properties":{"action":{"enum":["status","standby","takeover","release"]}},"required":["action"]}),
            &["primary", "age_s", "state", "rule"],
        ),
        tool(
            "ferry_talk",
            "Messages. read gives only new ones; post sends to an agent name.",
            &json!({"type":"object","properties":{"action":{"enum":["read","post"]},"to":{"type":"string"},"text":{"type":"string"},"since":{"type":"string"},"peek":{"type":"boolean"}},"required":["action"]}),
            &["messages", "id", "next"],
        ),
    ];
    tools.sort_by(|a, b| a["name"].as_str().cmp(&b["name"].as_str()));
    tools
}

/// The opt-in admin group (`--tools admin`), sorted by name.
#[must_use]
pub fn admin_tools() -> Vec<Value> {
    let mut tools = vec![
        tool(
            "ferry_get",
            "Fetch one ferry:// resource (order, msg, brief) as text.",
            &json!({"type":"object","properties":{"uri":{"type":"string"}},"required":["uri"]}),
            &["uri", "text"],
        ),
        tool(
            "ferry_search",
            "Search the channel's memory, ledger, learnings and results. Paged.",
            &json!({"type":"object","properties":{"query":{"type":"string"},"since":{"type":"string"}},"required":["query"]}),
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
            "check: is a signed, approved release available. apply: install it (Orchestrator only; same path as ferry update).",
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
                "{field} looks like a secret ({reason}). Messages are not the place for one; seal it to the machines that need it with `ferry channel secret set`"
            ),
        )),
        None => Ok(()),
    }
}

/// Keys whose values are identifiers or cursors, never prose: a hash or a long id in one
/// of them is not a secret and is not redacted.
const ID_KEYS: &[&str] = &[
    "id", "next", "since", "uri", "ref", "hash", "sha", "commit", "agent", "name", "to", "from",
    "by", "holder", "project", "machine", "current", "latest", "how", "order",
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

fn safe_id(id: &str) -> Result<()> {
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

fn title_of(task: &Task, max: usize) -> String {
    short(
        task.order
            .payload
            .get("task")
            .and_then(Value::as_str)
            .unwrap_or("(structured)"),
        max,
    )
}

fn message_text(message: &Message) -> String {
    match message.payload.get("text").and_then(Value::as_str) {
        Some(text) => text.to_string(),
        None => message.payload.to_string(),
    }
}

fn age_s(at: DateTime<Utc>) -> i64 {
    (Utc::now() - at).num_seconds().max(0)
}

// ---------------------------------------------------------------------------------------
// The agent

/// One MCP process: one agent identity, one project.
pub struct Agent {
    pub route: ProjectRoute,
    pub me: String,
    /// `--tools admin`.
    pub admin: bool,
}

impl Agent {
    #[must_use]
    pub fn new(route: ProjectRoute, me: &str, admin: bool) -> Self {
        Self {
            route,
            me: ferryman_channel::canonical_agent_name(me),
            admin,
        }
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

    fn require_seated(&self) -> Result<()> {
        if self.seated() {
            Ok(())
        } else {
            Err(refusal(
                "locked",
                format!(
                    "'{}' is not a seated agent on this machine, so this app is read-only here. Seat it first: run `ferry channel join --as {}` here, or ask the owner (dashboard, Agents), then restart the app",
                    self.me, self.me
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

    fn require_write(&self, what: &str) -> Result<Level> {
        let level = self.level();
        if level.writes_channel() {
            if let Some(note) = self.paused(&self.route()) {
                return Err(denied(format!(
                    "cannot {what} while paused ({}). Tell the human",
                    short(&note, 120)
                )));
            }
            Ok(level)
        } else {
            Err(denied(format!(
                "level worker cannot {what}. Workers hand work in with `ferry work hand-in`; they do not write the channel"
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
        if name != "ferry_join" {
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
            "ferry_join" => self.join(),
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
        let status = |extra: Option<(&str, Value)>| {
            let mut data = json!({
                "primary": view["name"],
                "age_s": view["age_s"],
                "state": state,
                "rule": rule,
            });
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
                Ok(Reply::new(format!("primary {who}, {state}"), status(None)))
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

    fn join(&self) -> Result<Reply> {
        // A name is a claim, not a credential. Joining registers nothing and mints no key:
        // the key must already be on this machine and seated on the roster.
        let route = self.route();
        let granted = self.seated();
        let note = if granted {
            None
        } else {
            Some(
                match AgentIdentity::load_existing(&self.me, &self.route.attachment) {
                    Ok(Some(_)) => format!(
                        "'{}' has a key here but is not seated on the roster. Ask the owner (dashboard, Agents)",
                        self.me
                    ),
                    _ => format!(
                        "no key for '{}' on this machine. Run `ferry channel join --as {}` here or ask the owner (dashboard, Agents), then restart the app. Until then this app can read nothing and write nothing",
                        self.me, self.me
                    ),
                },
            )
        };
        if !granted {
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
            "primary": primary,
            "alive": alive,
            "mine_open": mine_open,
            "queue": { "snifrig": ferryman_ops::heavy::snifrig_on_path().is_some() },
            "next": "ferry_catchup",
        });
        if let Some(update) = self.update_field(&route) {
            data["update"] = update;
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
                "title": title_of(t, 48),
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
            .map(|t| json!({ "id": t.order.id, "title": title_of(t, 48), "state": state_name(&t.state()) }))
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
            for t in tasks
                .iter()
                .filter(|t| matches!(t.state(), TaskState::AwaitingReview { .. }))
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
                "objective": short(&b.objective, if detail { 300 } else { 120 }),
                "constraints": constraints,
            });
        }
        let mut data = json!({
            "primary": { "name": primary["name"], "state": state },
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
                "{} open, {} yours; primary {} ({state})",
                open_total,
                mine.len(),
                primary["name"].as_str().unwrap_or("nobody")
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
            "list" => self.orders_list(&route, arg_str(args, "since")),
            "show" => self.orders_show(&route, need(args, "id", "show")?),
            "claim" => {
                self.require_write("claim orders")?;
                let id = need(args, "id", "claim")?;
                safe_id(id)?;
                // The checks the worker makes before it takes an order, in the same
                // order: is it signed and unblocked and addressed to this agent, then
                // the holds (interface, file overlap, fleet width, project tier, order
                // files). Only then the claim.
                let task = ferryman_channel::read_task(&route, id)?;
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
                let task = ferryman_channel::read_task(&route, id)?;
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
                self.require_write("report progress")?;
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
                self.require_write("submit results")?;
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
                let after = ferryman_channel::read_task(&route, id)?;
                Ok(Reply::new(
                    format!("submitted revision {revision} of {id}"),
                    json!({ "id": id, "revision": revision, "state": state_name(&after.state()) }),
                ))
            }
            "review" => {
                self.require_write("review")?;
                let id = need(args, "id", "review")?;
                safe_id(id)?;
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
                let task = ferryman_channel::read_task(&route, id)?;
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
                if task.order.requires_approval && !self.is_master(&route) {
                    return Err(denied(
                        "this order needs the master's approval, not an agent's. Use ferry_ask_human with a recommendation",
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

    fn is_master(&self, route: &ProjectRoute) -> bool {
        ferryman_channel::master::read_master(route)
            .ok()
            .flatten()
            .is_some_and(|m| is_me(&m.master, &self.me))
    }

    /// The task, if this agent holds it.
    fn holding(&self, route: &ProjectRoute, id: &str) -> Result<Task> {
        let task = ferryman_channel::read_task(route, id)?;
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

    fn orders_list(&self, route: &ProjectRoute, since: Option<&str>) -> Result<Reply> {
        let offset = parse_offset(since)?;
        let mut seen = BTreeSet::new();
        let mut tasks: Vec<Task> = Vec::new();
        for task in ferryman_channel::list_tasks(route)? {
            if finished(&task.state()) {
                continue;
            }
            let claimable = ferryman_channel::work_among(route, &self.me, vec![task.clone()])
                .map(|w| !w.is_empty())
                .unwrap_or(false);
            if (self.is_mine(&task) || claimable) && seen.insert(task.order.id.clone()) {
                tasks.push(task);
            }
        }
        let total = tasks.len();
        let identity = if self.level().writes_channel() {
            self.identity().ok()
        } else {
            None
        };
        let page: Vec<&Task> = tasks.iter().skip(offset).take(MAX_ITEMS).collect();
        let mut shown: Vec<Value> = Vec::new();
        for task in &page {
            if let Some(identity) = &identity {
                let _ = ferryman_channel::receipts::record_read(route, &task.order.id, identity);
            }
            let mut r = json!({ "id": task.order.id, "title": title_of(task, 50), "state": state_name(&task.state()) });
            if let Some(h) = task.holder() {
                r["holder"] = json!(h);
            }
            shown.push(r);
        }
        let mut data = json!({ "orders": shown });
        // Fit to the cap before deciding where the cursor points, so `next` names the
        // first order the caller has not been shown.
        let mut reply = Reply::new(format!("{total} order(s) for you or claimable"), json!({}));
        let cap = cap_tokens("ferry_orders") * 4 - reply.text.len() - 160;
        while len_of(&data) > cap.min(MAX_CHARS - 200) {
            match data.get_mut("orders") {
                Some(Value::Array(rows)) if !rows.is_empty() => {
                    rows.pop();
                }
                _ => break,
            }
        }
        let count = data["orders"].as_array().map_or(0, Vec::len);
        if offset + count < total {
            data["next"] = json!(format!("o{}", offset + count));
            data["truncated"] = json!(true);
        }
        reply.data = data;
        Ok(reply)
    }

    fn orders_show(&self, route: &ProjectRoute, id: &str) -> Result<Reply> {
        safe_id(id)?;
        let task = ferryman_channel::read_task(route, id)?;
        let needs = task.order.needs.clone();
        let mut data = json!({
            "id": id,
            "title": title_of(&task, 100),
            "state": state_name(&task.state()),
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
                self.require_write("post")?;
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
                    "approve".to_string(),
                    "reject".to_string(),
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
                let task = ferryman_channel::read_task(&route, id)?;
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
            let lower = text.to_ascii_lowercase();
            if lower.starts_with("approve") {
                ("approved", None)
            } else if lower.starts_with("reject") {
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

#[cfg(test)]
#[path = "mcp_agent_tests.rs"]
mod tests;
