//! Telegram v2: every project from one chat, by buttons, acting by identity.
//!
//! `ferry telegram` serves every channel under the ferry root from one Telegram chat - a
//! private chat with the bot, or a group - so a person away from their machines can see
//! what the fleet is doing and direct it. It is driven by inline buttons: a main menu
//! (Projects, Engines, Tasks, Self-improve), Approve / Send back / Details on every task
//! that needs the person, option buttons on the improve loop's questions. `/start` and
//! `/menu` only show the menu; there are no other commands. Plain text is an order to the
//! project picked in the chat, or to the default project.
//!
//! # Identity, not a password
//!
//! The bridge signs with its own key, `telegram-<machine>`. The project's master delegates
//! to that key once (`ferry team delegate`, or the dashboard), for orders, review and
//! improve. Every order, verdict, switch and answer it writes carries the master's name
//! and the bridge's signature - "josh via telegram-grouchly" - and counts only while that
//! delegation does. No password is read, held or needed; see
//! [`ferryman_channel::delegation`].
//!
//! # Who may use it
//!
//! Only the Telegram user ids in `TELEGRAM_APPROVERS`, and only in their private chat
//! with the bot or in the one group named by `TELEGRAM_CHAT_ID`. Anything else is logged
//! and not answered, so a stranger learns nothing about the bot.
//!
//! # Not a path for secrets
//!
//! A Telegram chat is not end-to-end encrypted. Nothing here accepts, carries or echoes a
//! credential; secrets are sealed from the dashboard's Secrets tab.
//!
//! # Shape
//!
//! [`Bridge`] is the whole of the behaviour and does no I/O with Telegram: it takes an
//! update and returns [`Action`]s, and [`Bridge::tick`] returns what progress to report.
//! The loop at the bottom performs them over HTTP. The tests drive the same `Bridge` with
//! a fake that assigns message ids, so nothing here needs the network to be tested.

use anyhow::{Context, Result, bail};
use chrono::{DateTime, Utc};
use ferryman_channel::policy::{self, Policy};
use ferryman_channel::{AgentIdentity, ProjectRoute, TaskState, delegation, questions};
use serde::{Deserialize, Serialize};
use serde_json::{Value, json};
use std::collections::BTreeMap;
use std::path::PathBuf;
use std::time::Duration;

/// How long `getUpdates` waits with nothing to say. Short enough that progress edits,
/// which are made between polls, keep up with the work.
const LONG_POLL_SECS: u64 = 10;
/// Telegram refuses messages over 4096 characters.
const MESSAGE_CHARS: usize = 3500;
/// A result is summarised, not pasted: the whole of it is in the channel.
const EXCERPT_CHARS: usize = 700;
/// How much bookkeeping to keep: enough that a restart does not repeat itself.
const KEEP: usize = 500;
/// An engine inventory older than this is a worker that has stopped reporting.
const INVENTORY_FRESH_MINS: i64 = 60;
/// How often to look for projects added to the ferry root while the bridge runs.
const RELOAD_SECS: u64 = 600;

/// One row of inline buttons: (label, callback data).
pub type Row = Vec<(String, String)>;

/// Something to do in Telegram.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Action {
    Send {
        chat: i64,
        text: String,
        buttons: Vec<Row>,
        /// Ask Telegram to open a reply to this message, for a note or an answer.
        force_reply: bool,
        /// What to remember about the message once Telegram says which id it has.
        track: Option<Track>,
    },
    Edit {
        chat: i64,
        message_id: i64,
        text: String,
        buttons: Vec<Row>,
    },
    /// Stop a pressed button spinning, with a short toast.
    Answer { callback_id: String, text: String },
}

/// What a sent message is for, so a later reply or edit can find it.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Track {
    /// The one status message edited as an order moves.
    Status { project: String, order: String },
    /// Waiting for the note that sends a result back.
    SendBack { project: String, order: String },
    /// Waiting for an answer in words.
    Answer { project: String, question: String },
}

/// Who may use the bridge, and where.
#[derive(Debug, Clone)]
pub struct Config {
    pub approvers: Vec<i64>,
    /// The group chat, when the bridge is used in one. Private chats with an approver
    /// always work.
    pub group: Option<i64>,
    pub default_project: String,
}

impl Config {
    fn from_env(default_project: String) -> Result<Self> {
        let raw = std::env::var("TELEGRAM_APPROVERS")
            .ok()
            .filter(|raw| !raw.trim().is_empty())
            .or_else(|| std::env::var("TELEGRAM_APPROVER_ID").ok())
            .unwrap_or_default();
        let approvers = parse_ids(&raw)?;
        if approvers.is_empty() {
            bail!(
                "TELEGRAM_APPROVERS must list the numeric Telegram user ids allowed to use the \
                 bot, comma separated (ask @userinfobot). Without it anyone who finds the bot \
                 could direct the fleet, so the bridge will not start."
            );
        }
        let group = match std::env::var("TELEGRAM_CHAT_ID") {
            Ok(raw) if !raw.trim().is_empty() => Some(
                raw.trim()
                    .parse::<i64>()
                    .context("TELEGRAM_CHAT_ID must be the group's numeric id")?,
            ),
            _ => None,
        };
        Ok(Self {
            approvers,
            group,
            default_project,
        })
    }
}

fn parse_ids(raw: &str) -> Result<Vec<i64>> {
    raw.split(',')
        .map(str::trim)
        .filter(|id| !id.is_empty())
        .map(|id| {
            id.parse::<i64>()
                .with_context(|| format!("'{id}' is not a numeric Telegram user id"))
        })
        .collect()
}

/// An order the bridge issued, and where its status message is.
#[derive(Debug, Clone, Default, Serialize, Deserialize)]
struct Watched {
    project: String,
    order: String,
    chat: i64,
    #[serde(default)]
    message_id: Option<i64>,
    #[serde(default)]
    shown: String,
    #[serde(default)]
    finished: bool,
    /// Said "no engine can run this"; say so again when one comes back.
    #[serde(default)]
    no_engine: bool,
}

/// A message waiting for a reply: a send-back note or an answer in words.
#[derive(Debug, Clone, Serialize, Deserialize)]
struct Prompt {
    chat: i64,
    message_id: i64,
    kind: String,
    project: String,
    id: String,
}

/// What the bridge keeps between restarts, on this machine only.
#[derive(Debug, Default, Serialize, Deserialize)]
struct State {
    #[serde(default)]
    offset: i64,
    /// The project each chat has picked.
    #[serde(default)]
    current: BTreeMap<String, String>,
    #[serde(default)]
    watched: Vec<Watched>,
    #[serde(default)]
    prompts: Vec<Prompt>,
    /// Things already put in front of the person: `q:<project>:<id>`,
    /// `r:<project>:<order>:<revision>`.
    #[serde(default)]
    posted: Vec<String>,
    /// Whether what was already waiting at first start has been noted, so starting the
    /// bridge does not replay every old review.
    #[serde(default)]
    seeded: bool,
    /// Callback data too long for Telegram's 64 bytes, by index.
    #[serde(default)]
    keys: Vec<String>,
}

fn bound<T>(list: &mut Vec<T>) {
    if list.len() > KEEP {
        let excess = list.len() - KEEP;
        list.drain(..excess);
    }
}

/// Cut to `limit` characters, marking the cut.
fn excerpt(text: &str, limit: usize) -> String {
    let text = text.trim();
    if text.chars().count() <= limit {
        return text.to_string();
    }
    format!("{}...", text.chars().take(limit).collect::<String>())
}

/// The parts of a Telegram update the bridge reads.
#[derive(Debug, Clone, Default, Deserialize)]
pub struct Update {
    pub update_id: i64,
    #[serde(default)]
    pub message: Option<Msg>,
    #[serde(default)]
    pub callback_query: Option<Callback>,
}

#[derive(Debug, Clone, Default, Deserialize)]
pub struct Msg {
    #[serde(default)]
    pub message_id: i64,
    #[serde(default)]
    pub from: Option<User>,
    #[serde(default)]
    pub chat: Chat,
    #[serde(default)]
    pub text: Option<String>,
    #[serde(default)]
    pub reply_to_message: Option<Box<Msg>>,
}

#[derive(Debug, Clone, Default, Deserialize)]
pub struct User {
    pub id: i64,
}

#[derive(Debug, Clone, Default, Deserialize)]
pub struct Chat {
    pub id: i64,
}

#[derive(Debug, Clone, Default, Deserialize)]
pub struct Callback {
    pub id: String,
    pub from: User,
    #[serde(default)]
    pub message: Option<Msg>,
    #[serde(default)]
    pub data: Option<String>,
}

/// The bridge: every project, one chat, one identity.
pub struct Bridge {
    config: Config,
    agent: AgentIdentity,
    routes: Vec<ProjectRoute>,
    state: State,
    state_path: Option<PathBuf>,
}

fn button(label: impl Into<String>, data: impl Into<String>) -> (String, String) {
    (label.into(), data.into())
}

fn menu_row() -> Row {
    vec![button("Menu", "menu")]
}

impl Bridge {
    fn new(
        config: Config,
        agent: AgentIdentity,
        routes: Vec<ProjectRoute>,
        state_path: Option<PathBuf>,
    ) -> Self {
        let state = state_path
            .as_ref()
            .and_then(|path| std::fs::read(path).ok())
            .and_then(|bytes| serde_json::from_slice(&bytes).ok())
            .unwrap_or_default();
        Self {
            config,
            agent,
            routes,
            state,
            state_path,
        }
    }

    fn save(&self) {
        let Some(path) = &self.state_path else {
            return;
        };
        if let Some(parent) = path.parent() {
            let _ = std::fs::create_dir_all(parent);
        }
        if let Ok(text) = serde_json::to_vec_pretty(&self.state)
            && let Err(error) = std::fs::write(path, text)
        {
            eprintln!("telegram: could not save {}: {error}", path.display());
        }
    }

    fn route(&self, project: &str) -> Option<&ProjectRoute> {
        self.routes.iter().find(|route| route.project_id == project)
    }

    /// The project a chat is working in: the one it picked, else the default, else the
    /// first there is.
    fn current(&self, chat: i64) -> String {
        self.state
            .current
            .get(&chat.to_string())
            .filter(|project| self.route(project).is_some())
            .cloned()
            .or_else(|| {
                self.route(&self.config.default_project)
                    .map(|route| route.project_id.clone())
            })
            .or_else(|| self.routes.first().map(|route| route.project_id.clone()))
            .unwrap_or_else(|| self.config.default_project.clone())
    }

    /// Where the bridge speaks on its own initiative: the group, or the first approver.
    fn home(&self) -> i64 {
        self.config
            .group
            .or_else(|| self.config.approvers.first().copied())
            .unwrap_or_default()
    }

    /// Whether this person, in this chat, may use the bridge.
    fn allowed(&self, from: i64, chat: i64) -> bool {
        self.config.approvers.contains(&from) && (chat == from || Some(chat) == self.config.group)
    }

    /// Whom the bridge acts for in this project: the principal of its active delegation.
    fn principal(&self, route: &ProjectRoute) -> std::result::Result<String, String> {
        match delegation::active(
            &route.communications,
            &route.project_id,
            self.agent.name(),
            Utc::now(),
        ) {
            Some(granted) => Ok(granted.principal),
            None => Err(format!(
                "I cannot act in {project} yet: its master has not delegated to {me}, or \
                 the delegation has ended. Delegate on the dashboard (Teammates, \"Let ... act \
                 for me\") or run: ferry team delegate {me}",
                project = route.project_id,
                me = self.agent.name()
            )),
        }
    }

    fn by(&self, principal: &str) -> String {
        delegation::label(principal, self.agent.name())
    }

    /// Callback data, kept within Telegram's 64 bytes.
    fn data(&mut self, data: String) -> String {
        if data.len() <= 64 {
            return data;
        }
        if let Some(index) = self.state.keys.iter().position(|key| *key == data) {
            return format!("k:{index}");
        }
        if self.state.keys.len() >= KEEP {
            self.state.keys.clear();
        }
        self.state.keys.push(data);
        format!("k:{}", self.state.keys.len() - 1)
    }

    /// The Override button for an improvement's Block: it names the finding on the card
    /// (`<revision>.<digest prefix>`), so pressing it after the finding changed is refused
    /// rather than applied to something the master did not read.
    fn override_data(&mut self, route: &ProjectRoute, order: &str, revision: u32) -> String {
        let seen = found_seen(route, order, revision);
        self.data(format!(
            "aov:{}:{order}:{revision}.{}",
            route.project_id,
            digest_prefix(&seen)
        ))
    }

    fn resolve(&self, data: &str) -> String {
        data.strip_prefix("k:")
            .and_then(|index| index.parse::<usize>().ok())
            .and_then(|index| self.state.keys.get(index).cloned())
            .unwrap_or_else(|| data.to_string())
    }

    /// Act on one update from Telegram.
    pub fn handle(&mut self, update: Update, now: DateTime<Utc>) -> Vec<Action> {
        self.state.offset = self.state.offset.max(update.update_id + 1);
        let actions = if let Some(callback) = update.callback_query {
            self.on_callback(callback, now)
        } else if let Some(message) = update.message {
            self.on_message(message, now)
        } else {
            Vec::new()
        };
        self.save();
        actions
    }

    fn on_message(&mut self, message: Msg, now: DateTime<Utc>) -> Vec<Action> {
        let from = message.from.as_ref().map_or(0, |user| user.id);
        let chat = message.chat.id;
        if !self.allowed(from, chat) {
            // Not answered: a reply would confirm the bot exists to whoever is probing it.
            eprintln!("telegram: ignored a message from {from} in chat {chat}");
            return Vec::new();
        }
        let Some(text) = message
            .text
            .as_deref()
            .map(str::trim)
            .filter(|t| !t.is_empty())
        else {
            return Vec::new();
        };
        // A reply to one of the bridge's own questions is the answer to it.
        if let Some(replied) = message.reply_to_message.as_ref().map(|m| m.message_id)
            && let Some(index) = self
                .state
                .prompts
                .iter()
                .position(|prompt| prompt.chat == chat && prompt.message_id == replied)
        {
            let prompt = self.state.prompts.remove(index);
            return self.on_reply(chat, &prompt, text);
        }
        if text.starts_with('/') {
            let command = text
                .split_whitespace()
                .next()
                .unwrap_or_default()
                .split('@')
                .next()
                .unwrap_or_default()
                .to_ascii_lowercase();
            let (body, buttons) = self.menu(chat);
            let body = if matches!(command.as_str(), "/start" | "/menu") {
                body
            } else {
                format!("Use the buttons - there are no other commands.\n\n{body}")
            };
            return vec![send(chat, body, buttons)];
        }
        self.order(chat, message.message_id, from, text, now)
    }
    /// Free text: a signed order to the chat's project, in the master's name.
    fn order(
        &mut self,
        chat: i64,
        message_id: i64,
        from: i64,
        text: &str,
        now: DateTime<Utc>,
    ) -> Vec<Action> {
        let project = self.current(chat);
        let Some(route) = self.route(&project).cloned() else {
            return vec![send(
                chat,
                format!("There is no project called {project} here."),
                vec![menu_row()],
            )];
        };
        let principal = match self.principal(&route) {
            Ok(principal) => principal,
            Err(why) => return vec![send(chat, why, vec![menu_row()])],
        };
        let id = format!("tg-{}-{message_id}", chat.unsigned_abs());
        let mut order = ferryman_channel::Order {
            id: id.clone(),
            project_id: route.project_id.clone(),
            issued_by: principal.clone(),
            assigned_to: None,
            created_at: now,
            payload: json!({
                "task": text,
                "via": self.agent.name(),
                "telegram_user": from,
            }),
            requires_review: false,
            requires_approval: false,
            depends_on: Vec::new(),
            signed_by: None,
            signature: None,
            result_contract: None,
            interface: None,
            touches: Vec::new(),
            needs: None,
            allow_overlap: false,
        };
        self.agent.sign_order(&mut order);
        if let Err(error) = ferryman_channel::issue_order(&route, &order) {
            return vec![send(
                chat,
                format!("Could not send that: {error:#}"),
                vec![menu_row()],
            )];
        }
        let by = self.by(&principal);
        let _ = ferryman_channel::ledger::append_ledger_entry(
            &route,
            &self.agent,
            "order",
            self.agent.name(),
            &format!("issued order {id} from Telegram, as {by}"),
            Some(&id),
        );
        // What was said, kept as said and signed, the way every statement in a channel is.
        let _ = ferryman_channel::head::record_said_via(
            &route.communications,
            &route.project_id,
            &principal,
            &self.agent,
            text,
        );
        let engine = self.engine_up(now);
        let no_engine = matches!(engine, Some(None));
        self.state.watched.push(Watched {
            project: project.clone(),
            order: id.clone(),
            chat,
            message_id: None,
            shown: "sent".to_string(),
            finished: false,
            no_engine,
        });
        bound(&mut self.state.watched);
        let mut actions = vec![Action::Send {
            chat,
            text: status_text(&id, &project, &by, "sent", None),
            buttons: Vec::new(),
            force_reply: false,
            track: Some(Track::Status { project, order: id }),
        }];
        if no_engine {
            actions.push(send(
                chat,
                "No engine anywhere can run this right now: every worker reports its engines \
                 down or out of credit. It waits in the channel, and I will say when one is back."
                    .to_string(),
                Vec::new(),
            ));
        }
        actions
    }

    /// A reply to a prompt: the note that sends work back, or an answer in words.
    fn on_reply(&mut self, chat: i64, prompt: &Prompt, text: &str) -> Vec<Action> {
        let Some(route) = self.route(&prompt.project).cloned() else {
            return Vec::new();
        };
        let principal = match self.principal(&route) {
            Ok(principal) => principal,
            Err(why) => return vec![send(chat, why, Vec::new())],
        };
        let said = match prompt.kind.as_str() {
            "sendback" => self
                .review(&route, &prompt.id, &principal, false, Some(text))
                .map(|revision| format!("Sent {} r{revision} back: {text}", prompt.id)),
            _ => {
                let answered = match questions::read(&route, &prompt.id) {
                    Some(asked) if asked.kind == questions::CONTRACT => {
                        decide_contract(&route, &asked, text.trim(), &principal, &self.agent)
                    }
                    _ => questions::answer(&route, &prompt.id, text, &principal, &self.agent),
                };
                answered.map(|answer| {
                    format!(
                        "Answered {} as {}: {}",
                        prompt.id,
                        answer.from(),
                        answer.answer
                    )
                })
            }
        };
        vec![send(
            chat,
            said.unwrap_or_else(|error| format!("Could not record that: {error:#}")),
            Vec::new(),
        )]
    }

    /// Approve or send back the latest result, as the principal, signed by the bridge.
    fn review(
        &self,
        route: &ProjectRoute,
        order: &str,
        principal: &str,
        accept: bool,
        notes: Option<&str>,
    ) -> Result<u32> {
        let task = ferryman_channel::read_task(route, order)?;
        let revision = task
            .latest_revision()
            .context("there is no result to review yet")?;
        let mut review = ferryman_channel::Review {
            order_id: order.to_string(),
            revision,
            reviewer: principal.to_string(),
            reviewed_at: Utc::now(),
            accepted: accept,
            notes: notes.map(str::to_string),
            signed_by: None,
            signature: None,
        };
        self.agent.sign_review(&mut review);
        ferryman_channel::submit_review(route, &review)?;
        Ok(revision)
    }

    /// `Some(Some(name))` when an engine is up somewhere, `Some(None)` when every fresh
    /// inventory says none is, `None` when no worker has reported at all.
    fn engine_up(&self, now: DateTime<Utc>) -> Option<Option<String>> {
        let mut reported = false;
        for route in &self.routes {
            for (inventory, check) in
                ferryman_channel::receipts::list_engines(route).unwrap_or_default()
            {
                if check != ferryman_channel::SignatureCheck::Valid
                    || now.signed_duration_since(inventory.updated_at)
                        > chrono::Duration::minutes(INVENTORY_FRESH_MINS)
                {
                    continue;
                }
                reported = true;
                if let Some(engine) = inventory.engines.iter().find(|e| e.state == "up") {
                    return Some(Some(format!("{} on {}", engine.name, inventory.machine)));
                }
            }
        }
        reported.then_some(None)
    }

    fn menu(&self, chat: i64) -> (String, Vec<Row>) {
        (
            format!(
                "Ferryman - working in {}.\nSend any message to give it an order. Do not send \
                 credentials here.",
                self.current(chat)
            ),
            vec![
                vec![button("Projects", "projects"), button("Engines", "engines")],
                vec![button("Tasks", "tasks"), button("Self-improve", "improve")],
                vec![button("Focus", "focus")],
            ],
        )
    }

    fn projects_view(&mut self, chat: i64) -> (String, Vec<Row>) {
        let current = self.current(chat);
        let names: Vec<String> = self.routes.iter().map(|r| r.project_id.clone()).collect();
        let mut rows: Vec<Row> = Vec::new();
        for pair in names.chunks(2) {
            let mut row = Row::new();
            for name in pair {
                let label = if *name == current {
                    format!("{name} (current)")
                } else {
                    name.clone()
                };
                let data = self.data(format!("pick:{name}"));
                row.push(button(label, data));
            }
            rows.push(row);
        }
        rows.push(menu_row());
        (format!("Pick a project. Now: {current}."), rows)
    }

    fn engines_view(&mut self, chat: i64, now: DateTime<Utc>) -> (String, Vec<Row>) {
        let mut seen: BTreeMap<(String, String), ferryman_channel::receipts::EngineInventory> =
            BTreeMap::new();
        for route in &self.routes {
            for (inventory, check) in
                ferryman_channel::receipts::list_engines(route).unwrap_or_default()
            {
                if check != ferryman_channel::SignatureCheck::Valid {
                    continue;
                }
                let key = (
                    inventory.agent.to_ascii_lowercase(),
                    inventory.machine.to_ascii_lowercase(),
                );
                if seen
                    .get(&key)
                    .is_none_or(|known| known.updated_at < inventory.updated_at)
                {
                    seen.insert(key, inventory);
                }
            }
        }
        if seen.is_empty() {
            return (
                "No worker has published its engines yet.".to_string(),
                vec![menu_row()],
            );
        }
        let mut lines = Vec::new();
        for inventory in seen.values() {
            lines.push(format!(
                "{} on {} ({} ago)",
                inventory.agent,
                inventory.machine,
                ferryman_channel::receipts::short_age(now - inventory.updated_at)
            ));
            for engine in &inventory.engines {
                let state = match (engine.state.as_str(), engine.until) {
                    ("exhausted", Some(until)) => {
                        format!("out until {}", until.format("%a %H:%M UTC"))
                    }
                    (state, _) => state.to_string(),
                };
                lines.push(format!(
                    "  {} ({}, {}): {state}",
                    engine.name, engine.tier, engine.paid
                ));
            }
        }
        let (policy_lines, mut rows) = self.policy_part(chat, now);
        lines.push(String::new());
        lines.extend(policy_lines);
        rows.push(menu_row());
        (excerpt(&lines.join("\n"), MESSAGE_CHARS), rows)
    }

    /// The engine policy of the chat's project, as it falls on its fleet, with buttons
    /// to accept the recommendation, block an engine, or move one to the top.
    fn policy_part(&mut self, chat: i64, now: DateTime<Utc>) -> (Vec<String>, Vec<Row>) {
        let project = self.current(chat);
        let Some(route) = self.route(&project).cloned() else {
            return (Vec::new(), Vec::new());
        };
        let (current, setting) = policy::effective(&route.communications, &project);
        let fleet = policy::fleet(&route, now);
        let mut lines = vec![format!(
            "Engine policy for {project} (background work: self-improve plans, builds, \
             reviews): {}",
            match &setting {
                Some(setting) if setting.policy.is_some() => format!("set by {}", setting.set_by()),
                _ => "auto - subscriptions never".to_string(),
            }
        )];
        lines.extend(current.describe());
        lines.push(
            "The adversary's terms (mode, engine, agents, cap) are the master's own signature: \
             here they are shown, not changed - use `ferry engines policy set` or the dashboard."
                .to_string(),
        );
        lines.extend(policy::summary(&current, &fleet));
        let shown = |selector: Option<&str>| {
            selector
                .map(|s| s.trim_start_matches("name:").to_string())
                .unwrap_or_else(|| "auto".to_string())
        };
        let mut rows = vec![
            vec![
                button(
                    format!(
                        "Improvement engine: {}",
                        shown(current.improvement_engine())
                    ),
                    self.data(format!("pim:{project}")),
                ),
                button(
                    format!("Review engine: {}", shown(current.review_engine())),
                    self.data(format!("pre:{project}")),
                ),
            ],
            vec![
                button("Use recommended", self.data(format!("prec:{project}"))),
                button("Accept recommended", self.data(format!("pacc:{project}"))),
            ],
            vec![if current.auto_merge == policy::AutoMerge::LowRisk {
                button(
                    "Auto-merge docs/tests/deps: on - turn off",
                    self.data(format!("pam:{project}:none")),
                )
            } else {
                button(
                    "Auto-merge docs/tests/deps after both approvals",
                    self.data(format!("pam:{project}:low-risk")),
                )
            }],
            vec![button(
                "Use team preset",
                self.data(format!("ptm:{project}")),
            )],
        ];
        let mut names: Vec<String> = Vec::new();
        for engine in &fleet {
            if !names.iter().any(|n| n.eq_ignore_ascii_case(&engine.name)) {
                names.push(engine.name.clone());
            }
        }
        for name in names.into_iter().take(6) {
            rows.push(vec![
                button(
                    format!("Block {name}"),
                    self.data(format!("pblk:{project}:{name}")),
                ),
                button(
                    format!("Move {name} to top"),
                    self.data(format!("ptop:{project}:{name}")),
                ),
            ]);
        }
        (lines, rows)
    }

    /// The simple pick: one button per engine that can improve (or, for `review`, that
    /// can review), with how it is paid for and whether auto recommends it.
    fn pick_view(&mut self, project: &str, review: bool, now: DateTime<Utc>) -> (String, Vec<Row>) {
        let Some(route) = self.route(project).cloned() else {
            return (format!("{project} is not here."), vec![menu_row()]);
        };
        let (current, _) = policy::effective(&route.communications, project);
        let fleet = policy::fleet(&route, now);
        let recommended = policy::recommend(&fleet, &[]).policy;
        let picks = policy::choices(&current, &fleet, &recommended);
        let list = picks[if review { "review" } else { "improve" }]
            .as_array()
            .cloned()
            .unwrap_or_default();
        let mut rows = Vec::new();
        for option in &list {
            let selector = option["selector"].as_str().unwrap_or_default().to_string();
            let name = selector.trim_start_matches("name:").to_string();
            let label = format!(
                "{}{} - {}{}",
                if option["recommended"].as_bool() == Some(true) {
                    "Recommended: "
                } else {
                    ""
                },
                option["label"].as_str().unwrap_or_default(),
                option["paid"].as_str().unwrap_or_default(),
                if option["blocked"].is_string() {
                    " (blocked)"
                } else {
                    ""
                }
            );
            let verb = if review { "sre" } else { "sim" };
            rows.push(vec![button(
                label,
                self.data(format!("{verb}:{project}:{name}")),
            )]);
        }
        rows.push(vec![button("Back to engines", "engines")]);
        let text = if list.is_empty() {
            format!("No engine in {project}'s fleet can do this yet.")
        } else if review {
            format!(
                "Pick {project}'s review engine. Every improvement needs its verdict, then yours, \
                 before it can go live."
            )
        } else {
            format!("Pick {project}'s improvement engine: it plans and builds self-improvements.")
        };
        (text, rows)
    }

    /// The team preset for `project`: plan on high, build on medium, swarm the cheap work.
    /// Roles already opened to a capped subscription stay open; nothing else is assumed.
    fn team_proposal(
        &self,
        project: &str,
        now: DateTime<Utc>,
    ) -> std::result::Result<(policy::Recommendation, Vec<String>), String> {
        let route = self
            .route(project)
            .ok_or_else(|| format!("{project} is not here"))?;
        let (current, _) = policy::effective(&route.communications, &route.project_id);
        let options = policy::TeamOptions {
            subscription_roles: current.subscription_roles.clone(),
            ..policy::TeamOptions::default()
        };
        let mut proposal = policy::team_for(route, now, &options);
        // What accepting signs is the preset laid over the policy in force: the master's
        // `never`, caps, auto-merge, adversary mode and `where` are theirs to change, not
        // the preset's.
        // The adversary's terms are the master's own signature, so the phone shows and signs
        // the preset with the adversary part as it is.
        proposal.policy =
            policy::apply_team(&current, &proposal.policy).keeping_adversary_of(&current);
        let warnings = policy::subscription_warnings(&proposal.policy, &policy::fleet(route, now));
        Ok((proposal, warnings))
    }

    /// What the team preset would sign, with a reason per choice and an Accept button.
    fn team_view(&mut self, project: &str, now: DateTime<Utc>) -> (String, Vec<Row>) {
        let (proposal, warnings) = match self.team_proposal(project, now) {
            Ok(found) => found,
            Err(why) => return (why, vec![menu_row()]),
        };
        let mut lines = vec![format!(
            "Team preset for {project}: plan on high, build on medium, swarm the cheap work. \
             Nothing changes until you accept."
        )];
        lines.extend(proposal.policy.describe());
        lines.push("Why:".to_string());
        lines.extend(proposal.reasons.iter().map(|reason| format!("- {reason}")));
        lines.extend(warnings.iter().map(|warning| format!("Warning: {warning}")));
        let rows = vec![
            vec![button(
                "Accept team preset",
                self.data(format!("ptma:{project}")),
            )],
            vec![button("Back to engines", "engines")],
        ];
        (excerpt(&lines.join("\n"), MESSAGE_CHARS), rows)
    }

    /// Change a project's engine policy as its master, signed by the bridge under the
    /// `improve` delegation. `change` gets the policy in force and the recommendation,
    /// and returns the new one, or `None` for no change.
    fn change_policy(
        &self,
        project: &str,
        change: impl FnOnce(Policy, Policy) -> Option<Policy>,
    ) -> std::result::Result<bool, String> {
        let route = self
            .route(project)
            .ok_or_else(|| format!("{project} is not here"))?;
        let principal = self.principal(route)?;
        let (current, _) = policy::effective(&route.communications, &route.project_id);
        let recommended = policy::recommend_for(route, Utc::now()).policy;
        let Some(next) = change(current.clone(), recommended) else {
            return Ok(false);
        };
        // The bridge signs as a delegate, and a delegate never signs the adversary's terms:
        // whatever the change carries, they stay as the master left them.
        let next = next.keeping_adversary_of(&current);
        policy::set_policy_as(
            &route.communications,
            &route.project_id,
            Some(next),
            &self.agent,
            Some(&principal),
        )
        .map_err(|error| format!("{error:#}"))
    }
    fn tasks_view(&mut self, chat: i64, now: DateTime<Utc>) -> (String, Vec<Row>) {
        let project = self.current(chat);
        let Some(route) = self.route(&project).cloned() else {
            return (format!("{project} is not here."), vec![menu_row()]);
        };
        let mut tasks = ferryman_channel::list_tasks(&route).unwrap_or_default();
        tasks.sort_by_key(|task| std::cmp::Reverse(task.order.created_at));
        if tasks.is_empty() {
            return (format!("{project} has no tasks yet."), vec![menu_row()]);
        }
        let mut lines = vec![format!("{project}, newest first:")];
        let mut rows = Vec::new();
        for task in tasks.iter().take(10) {
            lines.push(format!(
                "{}  {}  {}",
                task.order.id,
                where_it_is(&route, task, now),
                excerpt(&title(task), 60)
            ));
            if matches!(task.state_at(now), TaskState::AwaitingReview { .. }) {
                let data = self.data(format!("det:{project}:{}", task.order.id));
                rows.push(vec![button(format!("Review {}", task.order.id), data)]);
            }
        }
        rows.push(menu_row());
        (lines.join("\n"), rows)
    }

    fn details(&mut self, project: &str, order: &str, now: DateTime<Utc>) -> (String, Vec<Row>) {
        let Some(route) = self.route(project).cloned() else {
            return (format!("{project} is not here."), vec![menu_row()]);
        };
        let task = match ferryman_channel::read_task(&route, order) {
            Ok(task) => task,
            Err(error) => {
                return (
                    format!("Could not read {order}: {error:#}"),
                    vec![menu_row()],
                );
            }
        };
        let mut lines = vec![
            format!("{order} in {project}"),
            format!(
                "From {}, {}",
                delegation::label(
                    &task.order.issued_by,
                    task.order.signed_by.as_deref().unwrap_or_default()
                ),
                where_it_is(&route, &task, now)
            ),
            String::new(),
            excerpt(&title_full(&task), 400),
        ];
        if let Some(result) = task.results.iter().max_by_key(|result| result.revision) {
            lines.push(String::new());
            lines.push(format!("Result r{} by {}:", result.revision, result.agent));
            lines.push(excerpt(&result_text(&result.payload), EXCERPT_CHARS));
        }
        if let Some(advice) = task.pending_recommendation() {
            lines.push(String::new());
            lines.push(format!(
                "{} recommends {}: {}",
                advice.reviewer,
                if advice.accept {
                    "keeping it"
                } else {
                    "sending it back"
                },
                excerpt(&advice.reasoning, 300)
            ));
        }
        for review in &task.reviews {
            lines.push(format!(
                "r{} {} by {}{}",
                review.revision,
                if review.accepted {
                    "approved"
                } else {
                    "sent back"
                },
                delegation::label(
                    &review.reviewer,
                    review.signed_by.as_deref().unwrap_or_default()
                ),
                review
                    .notes
                    .as_deref()
                    .map(|n| format!(": {n}"))
                    .unwrap_or_default()
            ));
        }
        let mut rows = Vec::new();
        if matches!(task.state_at(now), TaskState::AwaitingReview { .. }) {
            rows.push(self.review_buttons(project, order, false));
        }
        rows.push(menu_row());
        (excerpt(&lines.join("\n"), MESSAGE_CHARS), rows)
    }

    fn review_buttons(&mut self, project: &str, order: &str, with_details: bool) -> Row {
        let mut row = vec![
            button("Approve", self.data(format!("ok:{project}:{order}"))),
            button("Send back", self.data(format!("back:{project}:{order}"))),
        ];
        if with_details {
            row.push(button(
                "Details",
                self.data(format!("det:{project}:{order}")),
            ));
        }
        row
    }

    fn improve_view(&mut self) -> (String, Vec<Row>) {
        let mut lines = vec![
            "Self-improve, per project. The weekly loop plans, builds and reviews; nothing \
             merges without you."
                .to_string(),
        ];
        let mut rows = Vec::new();
        let projects: Vec<(String, bool, Option<String>)> = self
            .routes
            .iter()
            .map(|route| {
                let setting = ferryman_channel::ferry::self_improve_setting(
                    &route.communications,
                    &route.project_id,
                );
                (
                    route.project_id.clone(),
                    setting.as_ref().is_some_and(|s| s.enabled),
                    setting.map(|s| s.set_by()),
                )
            })
            .collect();
        for (project, on, set_by) in projects {
            lines.push(format!(
                "{project}: {}{}",
                if on { "on" } else { "off" },
                set_by
                    .map(|by| format!(" (set by {by})"))
                    .unwrap_or_default()
            ));
            let data = self.data(format!("imp:{project}:{}", if on { "off" } else { "on" }));
            rows.push(vec![button(
                format!(
                    "{project}: {} - turn {}",
                    if on { "on" } else { "off" },
                    if on { "off" } else { "on" }
                ),
                data,
            )]);
            // Switched on with no engine policy of its own: say what auto would choose,
            // and offer to sign it.
            if on
                && let Some(route) = self.route(&project).cloned()
                && !policy::is_set(&route.communications, &project)
            {
                let proposal = policy::recommend_for(&route, Utc::now());
                lines.push(format!(
                    "  no engine policy yet - runs on auto. Recommended: {}",
                    proposal.policy.describe().join("; ")
                ));
                let data = self.data(format!("pacc:{project}:imp"));
                rows.push(vec![button(
                    format!("Accept recommended engines for {project}"),
                    data,
                )]);
            }
        }
        rows.push(vec![button("On for all my repos", "impall")]);
        rows.push(menu_row());
        (excerpt(&lines.join("\n"), MESSAGE_CHARS), rows)
    }

    /// Switch self-improve for one project as its master, signed by the bridge.
    fn switch_improve(&self, project: &str, enabled: bool) -> std::result::Result<bool, String> {
        let route = self
            .route(project)
            .ok_or_else(|| format!("{project} is not here"))?;
        let principal = self.principal(route)?;
        ferryman_channel::ferry::set_self_improve_as(
            &route.communications,
            &route.project_id,
            enabled,
            &self.agent,
            Some(&principal),
        )
        .map_err(|error| format!("{error:#}"))
    }

    /// The focus screen: every project with its tier, and the way to change it. The record
    /// is signed in the home project's channel; the bridge signs as the master's delegate.
    fn focus_view(&mut self, now: DateTime<Utc>) -> (String, Vec<Row>) {
        let home = ferryman_channel::focus::home_project();
        let Some(home_route) = self.route(&home).cloned() else {
            return (
                format!(
                    "The focus is signed in {home}'s channel, which this bridge does not serve, \
                     so it cannot change it from here. Use the dashboard, or run: ferry focus show"
                ),
                vec![menu_row()],
            );
        };
        let focus =
            ferryman_channel::focus::in_force(&home_route.communications, &home_route.project_id);
        let mut lines = vec![
            "Focus: which projects the swarm gives its time to. Focus work goes first and gets \
             most of the weekly improve budget; paused gets none. Nothing changes until you \
             press a project and a tier."
                .to_string(),
        ];
        if !focus.is_set() {
            lines.push("No focus is set: every project is normal.".to_string());
        }
        if let Some(notice) = &focus.notice {
            lines.push(format!("Warning: {notice}"));
        }
        let routes = self.routes.clone();
        let mut rows: Vec<Row> = Vec::new();
        for route in &routes {
            let project = &route.project_id;
            if ferryman_channel::ferry::is_archived(&route.communications, project) {
                lines.push(format!("{project}: archived, gets nothing"));
                continue;
            }
            let entry = focus.pin(project, now).map_or_else(
                || "normal".to_string(),
                ferryman_channel::focus::Pin::describe,
            );
            lines.push(format!("{project}: {entry}"));
            let data = self.data(format!("fsel:{project}"));
            rows.push(vec![button(format!("{project}: {entry}"), data)]);
        }
        if focus.is_set() {
            rows.push(vec![button("Clear the focus", "fclr")]);
        }
        rows.push(menu_row());
        (excerpt(&lines.join("\n"), MESSAGE_CHARS), rows)
    }

    /// The tiers one project can be put in.
    fn focus_pick_view(&mut self, project: &str, now: DateTime<Utc>) -> (String, Vec<Row>) {
        let tier = self.route(&ferryman_channel::focus::home_project()).map_or(
            ferryman_channel::focus::Tier::Normal,
            |home| {
                ferryman_channel::focus::in_force(&home.communications, &home.project_id)
                    .tier(project, now)
            },
        );
        let mut lines = vec![format!("{project} is {tier} now. What should it be?")];
        for each in ferryman_channel::focus::Tier::ALL {
            lines.push(format!("{each}: {}", each.describe()));
        }
        let mut rows: Vec<Row> = Vec::new();
        for (label, tier, days) in [
            ("Focus for 30 days", "focus", 30),
            ("Focus until I change it", "focus", 0),
            ("Normal", "normal", 0),
            ("Background for 30 days", "background", 30),
            ("Paused for 30 days", "paused", 30),
        ] {
            let data = self.data(format!("fset:{project}:{tier}:{days}"));
            rows.push(vec![button(label, data)]);
        }
        rows.push(vec![button("Back to the focus", "focus")]);
        rows.push(menu_row());
        (excerpt(&lines.join("\n"), MESSAGE_CHARS), rows)
    }

    /// Change the focus as the home project's master, signed by the bridge.
    fn change_focus(
        &self,
        change: impl FnOnce(&mut BTreeMap<String, ferryman_channel::focus::Pin>) -> anyhow::Result<()>,
    ) -> std::result::Result<bool, String> {
        let home = ferryman_channel::focus::home_project();
        let route = self
            .route(&home)
            .ok_or_else(|| format!("{home}'s channel is not served here"))?;
        let principal = self.principal(route)?;
        ferryman_channel::focus::set(
            &route.communications,
            &route.project_id,
            &self.agent,
            Some(&principal),
            change,
            Utc::now(),
        )
        .map_err(|error| format!("{error:#}"))
    }

    /// Put one project in a tier (`days` of 0 or none: until changed). Normal is no entry.
    fn switch_focus(
        &self,
        project: &str,
        tier: &str,
        days: Option<i64>,
    ) -> std::result::Result<bool, String> {
        let target = self
            .route(project)
            .ok_or_else(|| format!("{project} is not here"))?;
        if ferryman_channel::ferry::is_archived(&target.communications, project) {
            return Err(format!("{project} is archived, and gets nothing"));
        }
        let tier =
            ferryman_channel::focus::Tier::parse(tier).map_err(|error| format!("{error:#}"))?;
        let now = Utc::now();
        self.change_focus(|entries| {
            if tier == ferryman_channel::focus::Tier::Normal {
                entries.remove(project);
                Ok(())
            } else {
                ferryman_channel::focus::pin_project(entries, project, tier, days, now)
            }
        })
    }
    fn on_callback(&mut self, callback: Callback, now: DateTime<Utc>) -> Vec<Action> {
        let chat = callback.message.as_ref().map_or(0, |m| m.chat.id);
        if !self.allowed(callback.from.id, chat) {
            eprintln!(
                "telegram: ignored a button press from {} in chat {chat}",
                callback.from.id
            );
            return Vec::new();
        }
        let message_id = callback.message.as_ref().map(|m| m.message_id);
        let data = self.resolve(callback.data.as_deref().unwrap_or_default());
        let mut parts = data.splitn(4, ':');
        let verb = parts.next().unwrap_or_default().to_string();
        let project = parts.next().unwrap_or_default().to_string();
        let id = parts.next().unwrap_or_default().to_string();
        let extra = parts.next().unwrap_or_default().to_string();
        let mut toast = String::new();
        let view: Option<(String, Vec<Row>)> = match verb.as_str() {
            "menu" => Some(self.menu(chat)),
            "projects" => Some(self.projects_view(chat)),
            "engines" => Some(self.engines_view(chat, now)),
            "pim" | "pre" => Some(self.pick_view(&project, verb == "pre", now)),
            "sim" | "sre" | "prec" => {
                let engine = id.clone();
                let outcome = match verb.as_str() {
                    "sim" => self.change_policy(&project, |mut current, _| {
                        current.set_improvement_engine(&format!("name:{engine}"));
                        Some(current)
                    }),
                    "sre" => self.change_policy(&project, |mut current, _| {
                        current.set_review_engine(&format!("name:{engine}"));
                        Some(current)
                    }),
                    _ => self.change_policy(&project, |mut current, recommended| {
                        if let Some(improve) = recommended.improvement_engine() {
                            current.set_improvement_engine(improve);
                        }
                        if let Some(review) = recommended.review_engine() {
                            current.set_review_engine(review);
                        }
                        Some(current)
                    }),
                };
                toast = match outcome {
                    Ok(true) => match verb.as_str() {
                        "sim" => format!("{engine} improves {project}"),
                        "sre" => format!("{engine} reviews {project}"),
                        _ => format!("Recommended engines set for {project}"),
                    },
                    Ok(false) => "Already so".to_string(),
                    Err(why) => excerpt(&why, 190),
                };
                Some(self.engines_view(chat, now))
            }
            "ptm" => Some(self.team_view(&project, now)),
            "ptma" => {
                // The proposal is made again from the channel as it is now, and the
                // policy's own checks run before it is signed.
                let outcome = self.team_proposal(&project, now).and_then(|(proposal, _)| {
                    self.change_policy(&project, move |_, _| Some(proposal.policy))
                });
                toast = match outcome {
                    Ok(true) => format!("Team preset signed for {project}"),
                    Ok(false) => "Already so".to_string(),
                    Err(why) => excerpt(&why, 190),
                };
                Some(self.engines_view(chat, now))
            }
            "pam" => {
                let outcome = match policy::AutoMerge::parse(&id) {
                    Ok(mode) => self
                        .change_policy(&project, |mut current, _| {
                            current.auto_merge = mode;
                            Some(current)
                        })
                        .map(|changed| (changed, mode)),
                    Err(error) => Err(format!("{error:#}")),
                };
                toast = match outcome {
                    Ok((true, policy::AutoMerge::LowRisk)) => format!(
                        "{project}: docs, tests and dependency bumps merge on their own after both approvals"
                    ),
                    Ok((true, policy::AutoMerge::None)) => {
                        format!("{project}: nothing merges on its own")
                    }
                    Ok((false, _)) => "Already so".to_string(),
                    Err(why) => excerpt(&why, 190),
                };
                Some(self.engines_view(chat, now))
            }
            "pacc" | "pblk" | "ptop" => {
                let engine = id.clone();
                let outcome = match verb.as_str() {
                    "pacc" => self.change_policy(&project, |current, recommended| {
                        Some(policy::apply_recommendation(&current, &recommended))
                    }),
                    "pblk" => self.change_policy(&project, |mut current, _| {
                        current.block(&engine).then_some(current)
                    }),
                    _ => self.change_policy(&project, |mut current, _| {
                        current.move_to_top(&engine);
                        Some(current)
                    }),
                };
                toast = match outcome {
                    Ok(true) => match verb.as_str() {
                        "pacc" => format!("Recommended engine policy signed for {project}"),
                        "pblk" => format!("{engine} blocked for background work in {project}"),
                        _ => format!("{engine} first for every role in {project}"),
                    },
                    Ok(false) => "Already so".to_string(),
                    Err(why) => excerpt(&why, 190),
                };
                // Accepted from the self-improve screen: stay there.
                Some(if extra == "imp" || id == "imp" {
                    self.improve_view()
                } else {
                    self.engines_view(chat, now)
                })
            }
            "focus" => Some(self.focus_view(now)),
            "fsel" => Some(self.focus_pick_view(&project, now)),
            "fset" | "fclr" => {
                let outcome = if verb == "fclr" {
                    self.change_focus(|entries| {
                        entries.clear();
                        Ok(())
                    })
                } else {
                    let days = extra.parse::<i64>().ok().filter(|days| *days > 0);
                    self.switch_focus(&project, &id, days)
                };
                toast = match outcome {
                    Ok(true) if verb == "fclr" => {
                        "Focus cleared: every project is normal".to_string()
                    }
                    Ok(true) => format!("{project} is now {id}"),
                    Ok(false) => "Already so".to_string(),
                    Err(why) => excerpt(&why, 190),
                };
                Some(self.focus_view(now))
            }
            "tasks" => Some(self.tasks_view(chat, now)),
            "improve" => Some(self.improve_view()),
            "pick" if self.route(&project).is_some() => {
                self.state.current.insert(chat.to_string(), project.clone());
                toast = format!("Working in {project}");
                Some(self.menu(chat))
            }
            "det" => Some(self.details(&project, &id, now)),
            "imp" => {
                toast = match self.switch_improve(&project, id == "on") {
                    Ok(true) => format!("Self-improve {id} for {project}"),
                    Ok(false) => format!("Already {id}"),
                    Err(why) => excerpt(&why, 190),
                };
                Some(self.improve_view())
            }
            "impall" => {
                // An archived project is left alone: switching it on is refused anyway,
                // and it is not offered.
                let projects: Vec<String> = self
                    .routes
                    .iter()
                    .filter(|r| {
                        !ferryman_channel::ferry::is_archived(&r.communications, &r.project_id)
                    })
                    .map(|r| r.project_id.clone())
                    .collect();
                let switched = projects
                    .iter()
                    .filter(|project| {
                        self.switch_improve(project, true)
                            .is_ok_and(|changed| changed)
                    })
                    .count();
                toast = format!("Switched on in {switched} project(s)");
                Some(self.improve_view())
            }
            "ok" | "back" => {
                return self.on_verdict(
                    &callback.id,
                    chat,
                    message_id,
                    &project,
                    &id,
                    verb == "ok",
                );
            }
            "aov" | "clk" | "cov" | "crj" => {
                return self.on_adversary(
                    &callback.id,
                    chat,
                    message_id,
                    (verb.as_str(), &project, &id, &extra),
                );
            }
            "ans" | "ansx" => {
                return self.on_answer(
                    &callback.id,
                    chat,
                    message_id,
                    &project,
                    &id,
                    (verb == "ans").then_some(extra),
                );
            }
            _ => None,
        };
        let mut actions = vec![Action::Answer {
            callback_id: callback.id,
            text: toast,
        }];
        if let Some((text, buttons)) = view {
            actions.push(match message_id {
                Some(message_id) => Action::Edit {
                    chat,
                    message_id,
                    text,
                    buttons,
                },
                None => send(chat, text, buttons),
            });
        }
        actions
    }
    fn on_verdict(
        &mut self,
        callback_id: &str,
        chat: i64,
        message_id: Option<i64>,
        project: &str,
        order: &str,
        accept: bool,
    ) -> Vec<Action> {
        let Some(route) = self.route(project).cloned() else {
            return vec![toast(callback_id, format!("{project} is not here"))];
        };
        let principal = match self.principal(&route) {
            Ok(principal) => principal,
            Err(why) => {
                return vec![
                    toast(callback_id, "Not delegated"),
                    send(chat, why, Vec::new()),
                ];
            }
        };
        if !accept {
            // The note is what sends work back; ask for it as a reply to this message.
            return vec![
                toast(callback_id, ""),
                Action::Send {
                    chat,
                    text: format!("What should change in {order}? Reply to this message."),
                    buttons: Vec::new(),
                    force_reply: true,
                    track: Some(Track::SendBack {
                        project: project.to_string(),
                        order: order.to_string(),
                    }),
                },
            ];
        }
        match self.review(&route, order, &principal, true, None) {
            Ok(revision) => {
                let done = format!("{order} r{revision} approved by {}.", self.by(&principal));
                let mut actions = vec![toast(callback_id, "Approved")];
                if let Some(message_id) = message_id {
                    actions.push(Action::Edit {
                        chat,
                        message_id,
                        text: done,
                        buttons: vec![menu_row()],
                    });
                } else {
                    actions.push(send(chat, done, Vec::new()));
                }
                actions
            }
            Err(error) => vec![
                toast(callback_id, "Not approved"),
                send(
                    chat,
                    format!("Could not approve {order}: {error:#}"),
                    Vec::new(),
                ),
            ],
        }
    }

    fn on_answer(
        &mut self,
        callback_id: &str,
        chat: i64,
        message_id: Option<i64>,
        project: &str,
        question: &str,
        option: Option<String>,
    ) -> Vec<Action> {
        let Some(route) = self.route(project).cloned() else {
            return vec![toast(callback_id, format!("{project} is not here"))];
        };
        let Some(asked) = questions::read(&route, question) else {
            return vec![toast(callback_id, "That question is gone")];
        };
        let Some(option) = option else {
            return vec![
                toast(callback_id, ""),
                Action::Send {
                    chat,
                    text: format!(
                        "Your answer to: {}\nReply to this message.",
                        excerpt(&asked.text, 300)
                    ),
                    buttons: Vec::new(),
                    force_reply: true,
                    track: Some(Track::Answer {
                        project: project.to_string(),
                        question: question.to_string(),
                    }),
                },
            ];
        };
        let Some(choice) = option
            .parse::<usize>()
            .ok()
            .and_then(|index| asked.options.get(index).cloned())
        else {
            return vec![toast(callback_id, "That option is gone")];
        };
        let principal = match self.principal(&route) {
            Ok(principal) => principal,
            Err(why) => {
                return vec![
                    toast(callback_id, "Not delegated"),
                    send(chat, why, Vec::new()),
                ];
            }
        };
        // A contract question is not answered, it is decided: Lock freezes the contract and
        // Reject declines it, each signed for the master, and the answer follows from that.
        let outcome = if asked.kind == questions::CONTRACT {
            decide_contract(&route, &asked, &choice, &principal, &self.agent)
        } else {
            questions::answer(&route, question, &choice, &principal, &self.agent)
        };
        match outcome {
            Ok(answer) => {
                // An engine-policy question's buttons do what they say: accept the
                // recommended policy, or block the engine - signed for the master.
                let changed = if asked.kind == questions::POLICY {
                    match self.change_policy(project, |current, recommended| {
                        policy::answer_changes(&choice, &current, &recommended)
                    }) {
                        Ok(true) => " The engine policy is changed.".to_string(),
                        Ok(false) => String::new(),
                        Err(why) => format!(" The policy was not changed: {why}"),
                    }
                } else {
                    String::new()
                };
                let text = format!(
                    "{}\n\nAnswered \"{}\" - {}.{changed}",
                    excerpt(&asked.text, 1500),
                    answer.answer,
                    answer.from()
                );
                let mut actions = vec![toast(callback_id, "Answered")];
                actions.push(match message_id {
                    Some(message_id) => Action::Edit {
                        chat,
                        message_id,
                        text,
                        buttons: Vec::new(),
                    },
                    None => send(chat, text, Vec::new()),
                });
                actions
            }
            Err(error) => vec![toast(callback_id, excerpt(&format!("{error:#}"), 190))],
        }
    }

    /// Telegram said which id a sent message got; remember it where it matters.
    pub fn sent(&mut self, track: Track, chat: i64, message_id: i64) {
        match track {
            Track::Status { project, order } => {
                if let Some(watched) = self
                    .state
                    .watched
                    .iter_mut()
                    .find(|w| w.project == project && w.order == order)
                {
                    watched.message_id = Some(message_id);
                }
            }
            Track::SendBack { project, order } => self.state.prompts.push(Prompt {
                chat,
                message_id,
                kind: "sendback".to_string(),
                project,
                id: order,
            }),
            Track::Answer { project, question } => self.state.prompts.push(Prompt {
                chat,
                message_id,
                kind: "answer".to_string(),
                project,
                id: question,
            }),
        }
        bound(&mut self.state.prompts);
        self.save();
    }

    /// Everything that has changed since the last look: orders moving, results, work
    /// waiting for the person, the improve loop's questions, an engine coming back.
    pub fn tick(&mut self, now: DateTime<Utc>) -> Vec<Action> {
        let mut actions = Vec::new();
        let engine = self.engine_up(now);
        let watched = std::mem::take(&mut self.state.watched);
        let mut kept = Vec::new();
        for mut w in watched {
            if w.finished {
                kept.push(w);
                continue;
            }
            let Some(route) = self.route(&w.project).cloned() else {
                kept.push(w);
                continue;
            };
            let Ok(task) = ferryman_channel::read_task(&route, &w.order) else {
                kept.push(w);
                continue;
            };
            let stage = stage_of(&route, &task, now);
            if stage != w.shown {
                w.shown.clone_from(&stage);
                if let Some(message_id) = w.message_id {
                    let by = delegation::label(
                        &task.order.issued_by,
                        task.order.signed_by.as_deref().unwrap_or_default(),
                    );
                    let holder = task.holder().map(str::to_string);
                    actions.push(Action::Edit {
                        chat: w.chat,
                        message_id,
                        text: status_text(&w.order, &w.project, &by, &stage, holder.as_deref()),
                        buttons: Vec::new(),
                    });
                }
            }
            if w.no_engine
                && let Some(Some(up)) = &engine
            {
                w.no_engine = false;
                actions.push(send(
                    w.chat,
                    format!("An engine is back: {up}. {} will be picked up.", w.order),
                    Vec::new(),
                ));
            }
            if let Some(result) = task.results.iter().max_by_key(|r| r.revision) {
                w.finished = true;
                self.state
                    .posted
                    .push(format!("r:{}:{}:{}", w.project, w.order, result.revision));
                let mut buttons = Vec::new();
                if matches!(task.state_at(now), TaskState::AwaitingReview { .. }) {
                    buttons.push(self.review_buttons(&w.project, &w.order, true));
                }
                // A refuted result is never reported as done.
                let found = ferryman_channel::evidence::classify(&task.order.payload, result);
                let headline = if found.status == ferryman_channel::evidence::Status::Refuted {
                    format!(
                        "{} came back REFUTED, not done - r{} by {}: {}",
                        w.order,
                        result.revision,
                        result.agent,
                        found.reasons.join("; ")
                    )
                } else {
                    format!(
                        "{} is done - r{} by {}:",
                        w.order, result.revision, result.agent
                    )
                };
                actions.push(send(
                    w.chat,
                    format!(
                        "{headline}\n\n{}",
                        excerpt(&result_text(&result.payload), EXCERPT_CHARS)
                    ),
                    buttons,
                ));
            }
            if matches!(task.state_at(now), TaskState::Killed { .. }) {
                w.finished = true;
            }
            kept.push(w);
        }
        self.state.watched = kept;
        bound(&mut self.state.watched);
        actions.extend(self.waiting_on_you(now));
        self.state.seeded = true;
        bound(&mut self.state.posted);
        self.save();
        actions
    }
    /// Results waiting on the person, and the improve loop's questions, each put in front
    /// of them once. At first start, results already waiting are noted rather than
    /// replayed; the Tasks view still lists them.
    fn waiting_on_you(&mut self, now: DateTime<Utc>) -> Vec<Action> {
        let home = self.home();
        let mut actions = Vec::new();
        for route in self.routes.clone() {
            let project = route.project_id.clone();
            let principal =
                delegation::active(&route.communications, &project, self.agent.name(), now)
                    .map(|granted| granted.principal);
            for task in ferryman_channel::list_tasks(&route).unwrap_or_default() {
                // An improvement comes to the person below, once the review engine has
                // given the first key - never before.
                if ferryman_channel::gate::gated(&task.order.payload) {
                    continue;
                }
                let TaskState::AwaitingReview { by, revision } = task.state_at(now) else {
                    continue;
                };
                // Work the person asked for, or work only they may approve.
                let theirs = task.order.requires_approval
                    || principal
                        .as_deref()
                        .is_some_and(|p| p.eq_ignore_ascii_case(&task.order.issued_by));
                let key = format!("r:{project}:{}:{revision}", task.order.id);
                if !theirs || self.state.posted.contains(&key) {
                    continue;
                }
                self.state.posted.push(key);
                if !self.state.seeded {
                    continue;
                }
                let result = task
                    .results
                    .iter()
                    .find(|r| r.revision == revision)
                    .map(|r| excerpt(&result_text(&r.payload), EXCERPT_CHARS))
                    .unwrap_or_default();
                let mut buttons = vec![self.review_buttons(&project, &task.order.id, true)];
                let (adversary, blocked) = adversary_card(&route, &task.order.id, revision);
                if blocked {
                    let data = self.override_data(&route, &task.order.id, revision);
                    buttons.push(vec![button("Override the Block", data)]);
                }
                actions.push(send(
                    home,
                    format!(
                        "{} in {project} needs you - r{revision} by {by}:\n{}{}\n\n{result}{adversary}",
                        task.order.id,
                        excerpt(&title(&task), 200),
                        routing_line(Some(&task), revision)
                    ),
                    buttons,
                ));
            }
            for waiting in ferryman_channel::gate::waiting(&route) {
                let key = format!("g:{project}:{}:{}", waiting.order_id, waiting.revision);
                if !waiting.ready_for_you || self.state.posted.contains(&key) {
                    continue;
                }
                self.state.posted.push(key);
                if !self.state.seeded {
                    continue;
                }
                let mut lines = vec![
                    format!(
                        "{project} - waiting for your approval: {} r{} by {}",
                        waiting.order_id, waiting.revision, waiting.worker
                    ),
                    excerpt(&waiting.title, 200),
                    String::new(),
                ];
                if let Some(stat) = &waiting.diff_stat {
                    lines.push(format!("Diff: {stat}"));
                }
                lines.push(format!("Evidence: {}", waiting.evidence));
                let routed = routing_line(
                    ferryman_channel::read_task(&route, &waiting.order_id)
                        .ok()
                        .as_ref(),
                    waiting.revision,
                );
                if let Some(routed) = routed.strip_prefix('\n') {
                    lines.push(routed.to_string());
                }
                if let Some(engine) = &waiting.engine {
                    lines.push(format!(
                        "Review engine: {}",
                        excerpt(&engine.describe(), 600)
                    ));
                }
                // The adversary's word sits beside the two keys; a Block gets its own button.
                if let Some(finding) = &waiting.adversary {
                    lines.extend(finding_lines(finding));
                }
                let auto = policy::effective(&route.communications, &project)
                    .0
                    .auto_merge
                    == policy::AutoMerge::LowRisk;
                lines.push(if auto {
                    "Approving is the second key. Then docs, tests and dependency bumps merge \
                     on their own; anything else becomes approved, ready to merge."
                        .to_string()
                } else {
                    "Approving is the second key. Nothing merges on its own: it becomes \
                     approved, ready to merge."
                        .to_string()
                });
                let mut buttons = vec![self.review_buttons(&project, &waiting.order_id, true)];
                if waiting.adversary_blocked {
                    let data = self.override_data(&route, &waiting.order_id, waiting.revision);
                    buttons.push(vec![button("Override the Block", data)]);
                }
                actions.push(send(home, lines.join("\n"), buttons));
            }
            // What fm merged on its own - low-risk work, after both keys - said once each.
            for merged in ferryman_channel::automerge::merged(&route) {
                let key = format!("m:{project}:{}:{}", merged.order_id, merged.revision);
                if self.state.posted.contains(&key) {
                    continue;
                }
                self.state.posted.push(key);
                if !self.state.seeded {
                    continue;
                }
                actions.push(send(
                    home,
                    format!(
                        "{project} - merged on its own after both approvals:\n{}",
                        excerpt(&merged.describe(), 1500)
                    ),
                    Vec::new(),
                ));
            }
            for question in questions::pending(&route) {
                let key = format!("q:{project}:{}", question.id);
                if self.state.posted.contains(&key) {
                    continue;
                }
                self.state.posted.push(key);
                let mut buttons: Vec<Row> = Vec::new();
                for (index, option) in question.options.iter().enumerate() {
                    let data = self.data(format!("ans:{project}:{}:{index}", question.id));
                    buttons.push(vec![button(option.clone(), data)]);
                }
                let data = self.data(format!("ansx:{project}:{}", question.id));
                buttons.push(vec![button("Answer in words", data)]);
                let heading = if question.kind == questions::MERGE {
                    format!("{project} - ready to merge, waiting for you")
                } else if question.kind == questions::POLICY {
                    format!("{project} - engine policy")
                } else if question.kind == questions::CONTRACT {
                    format!("{project} - interface contract, waiting for your lock")
                } else if question.kind == questions::SUGGESTION {
                    // The buttons are Accept, Decline and Ask more: the same signed answer
                    // `ferry suggestions accept` gives. Everything below the heading is the
                    // contributor's words, shown as plain text.
                    format!("{project} - a suggestion from outside, waiting for your decision")
                } else {
                    format!("{project} - a question from {}", question.asked_by)
                };
                actions.push(send(
                    home,
                    format!("{heading}\n\n{}", excerpt(&question.text, 1500)),
                    buttons,
                ));
            }
            actions.extend(self.adversary_cards(&route, &project, home));
        }
        actions
    }

    /// What the adversary found, put on the phone once each. A contract still waiting for
    /// its lock gets the finding with Lock and Reject beside it (the contract's own card
    /// went out before the adversary had read it), and an Override only for a Block; an
    /// improvement's Block gets an Override too, since in `blocking` mode no review card is
    /// posted while it stands. Other findings on improvements ride on the review card.
    fn adversary_cards(&mut self, route: &ProjectRoute, project: &str, home: i64) -> Vec<Action> {
        use ferryman_channel::adversary::{self as found, Trigger};
        use ferryman_channel::interface;
        let (policy, _) = policy::effective(&route.communications, project);
        if policy.adversary == policy::AdversaryMode::Off {
            return Vec::new();
        }
        let mut actions = Vec::new();
        // Only what counts: a finding by someone who built the work, or has no signed
        // inventory listing its engine, never puts a card on the phone.
        for standing in found::list_standings(route).standings {
            let finding = &standing.finding;
            let block = standing.unresolved_block();
            let seen = standing.digest();
            let (buttons, text) =
                match finding.trigger {
                    Trigger::ContractLock => {
                        let Some(contract) = interface::parse_ref(&finding.subject).ok().and_then(
                            |(name, version)| interface::read_contract(route, &name, &version),
                        ) else {
                            continue;
                        };
                        // Only the finding on the revision the lock is decided on, while pending.
                        if interface::status(route, &contract) != interface::Status::Proposed
                            || found::contract_revision(route, &contract) != finding.revision
                        {
                            continue;
                        }
                        let subject = finding.subject.clone();
                        let contract_digest = interface::digest(&route.project_id, &contract);
                        let looked = digest_prefix(&contract_digest);
                        let mut rows: Vec<Row> = vec![vec![
                            button(
                                "Lock",
                                self.data(format!("clk:{project}:{subject}:{looked}")),
                            ),
                            button("Reject", self.data(format!("crj:{project}:{subject}"))),
                        ]];
                        if block {
                            rows.push(vec![button(
                                "Override the Block and lock",
                                self.data(format!(
                                    "cov:{project}:{subject}:{looked}.{}",
                                    digest_prefix(&seen)
                                )),
                            )]);
                        }
                        (
                            rows,
                            format!("{project} - the adversary read contract {subject}"),
                        )
                    }
                    Trigger::PreDone => {
                        // Advisory: the review card carries the Override itself.
                        if policy.adversary != policy::AdversaryMode::Blocking || !block {
                            continue;
                        }
                        let data = self.data(format!(
                            "aov:{project}:{}:{}.{}",
                            finding.subject,
                            finding.revision,
                            digest_prefix(&seen)
                        ));
                        (
                            vec![vec![button("Override the Block", data)]],
                            format!(
                                "{project} - the adversary blocked {} r{}",
                                finding.subject, finding.revision
                            ),
                        )
                    }
                    Trigger::RepeatFailure => continue,
                };
            // A different finding on the same revision is a new card, with its own buttons.
            let key = format!("a:{project}:{}:{}", finding.stem(), digest_prefix(&seen));
            if self.state.posted.contains(&key) {
                continue;
            }
            self.state.posted.push(key);
            if !self.state.seeded {
                continue;
            }
            let body: Vec<String> = finding_lines(finding);
            actions.push(send(home, format!("{text}\n{}", body.join("\n")), buttons));
        }
        actions
    }
    /// Refuse a digest prefix that does not name exactly one contract in the project: a
    /// button carries a prefix, not the whole digest, and a prefix that two contracts share
    /// could be pressed against the wrong one.
    fn named_contract(route: &ProjectRoute, name: &str, version: &str, prefix: &str) -> Result<()> {
        use ferryman_channel::interface;
        let prefix = prefix.trim().to_ascii_lowercase();
        if prefix.len() < interface::DIGEST_MIN {
            bail!("the contract changed since you looked: this button names no contract");
        }
        let sharing = interface::list_contracts(route)
            .into_iter()
            .filter(|contract| interface::digest(&route.project_id, contract).starts_with(&prefix))
            .count();
        let named = interface::read_contract(route, name, version).is_some_and(|contract| {
            interface::digest(&route.project_id, &contract).starts_with(&prefix)
        });
        match (named, sharing) {
            (true, 1) => Ok(()),
            (true, _) => bail!("that button's digest names more than one contract; use the CLI"),
            (false, _) => bail!(
                "the contract changed since you looked: {name}@{version} is not what that card showed"
            ),
        }
    }

    /// The buttons on an adversary card, each signed for the master under the bridge's
    /// delegation: Lock or Reject a contract, Override a Block (and lock, for a contract).
    /// Overriding takes the scope for that moment - `improve` for a contract, `review` for
    /// an improvement - exactly as it does anywhere else.
    fn on_adversary(
        &mut self,
        callback_id: &str,
        chat: i64,
        message_id: Option<i64>,
        (verb, project, id, extra): (&str, &str, &str, &str),
    ) -> Vec<Action> {
        use ferryman_channel::adversary::{self as found, Trigger};
        use ferryman_channel::interface;
        let Some(route) = self.route(project).cloned() else {
            return vec![toast(callback_id, format!("{project} is not here"))];
        };
        let principal = match self.principal(&route) {
            Ok(principal) => principal,
            Err(why) => {
                return vec![
                    toast(callback_id, "Not delegated"),
                    send(chat, why, Vec::new()),
                ];
            }
        };
        let why = "overridden from Telegram";
        let outcome: Result<String> = match verb {
            // `<revision>.<finding digest prefix or none>`: the finding on the card.
            "aov" => extra
                .split_once('.')
                .context("this button is from before overrides named what you read; ask again")
                .and_then(|(revision, finding)| {
                    let revision = revision.parse::<u32>().context("which revision?")?;
                    found::override_or_waive(
                        &route,
                        id,
                        revision,
                        Trigger::PreDone,
                        finding,
                        Some(why),
                        &principal,
                        &self.agent,
                    )
                    .map(|given| {
                        format!(
                            "{id} r{revision}: the adversary is answered, signed by {}. The \
                             review engine's key can be granted now.",
                            given.from()
                        )
                    })
                }),
            _ => interface::parse_ref(id).and_then(|(name, version)| match verb {
                // `<contract digest prefix>`: the contract on the card.
                "clk" => Self::named_contract(&route, &name, &version, extra)
                    .and_then(|()| {
                        interface::lock(&route, &name, &version, extra, &principal, &self.agent)
                    })
                    .map(|_| format!("{id} locked by {}.", self.by(&principal))),
                // `<contract digest prefix>.<finding digest prefix or none>`.
                "cov" => extra
                    .split_once('.')
                    .context("this button is from before overrides named what you read; ask again")
                    .and_then(|(contract, finding)| {
                        Self::named_contract(&route, &name, &version, contract)?;
                        interface::lock_overriding(
                            &route,
                            &name,
                            &version,
                            contract,
                            finding,
                            &principal,
                            &self.agent,
                            Some(why),
                        )
                    })
                    .map(|_| {
                        format!(
                            "{id} locked by {}, over the adversary's Block.",
                            self.by(&principal)
                        )
                    }),
                _ => interface::reject(&route, &name, &version, &principal, &self.agent)
                    .map(|_| format!("{id} rejected by {}.", self.by(&principal))),
            }),
        };
        match outcome {
            Ok(text) => {
                let mut actions = vec![toast(callback_id, "Done")];
                actions.push(match message_id {
                    Some(message_id) => Action::Edit {
                        chat,
                        message_id,
                        text,
                        buttons: vec![menu_row()],
                    },
                    None => send(chat, text, Vec::new()),
                });
                actions
            }
            Err(error) => vec![
                toast(callback_id, excerpt(&format!("{error:#}"), 190)),
                send(chat, format!("{error:#}"), Vec::new()),
            ],
        }
    }
}

/// The first 16 characters of a digest - what a button carries - or `none` whole.
fn digest_prefix(digest: &str) -> &str {
    digest.get(..16).unwrap_or(digest)
}

/// What the adversary's word on `order` r`revision` comes to, as an override must name it.
fn found_seen(route: &ProjectRoute, order: &str, revision: u32) -> String {
    ferryman_channel::adversary::finding_seen(
        route,
        order,
        revision,
        ferryman_channel::adversary::Trigger::PreDone,
    )
}

/// The smart router's one-line reason on an order's card: a newline and `Routed: nvidia:
/// free, p 0.81 for docs >= 0.75, cheapest sufficient`, from what the worker recorded with
/// that revision. Empty when it recorded none, so work done before the router reads as it did.
fn routing_line(task: Option<&ferryman_channel::Task>, revision: u32) -> String {
    task.and_then(|task| task.results.iter().find(|r| r.revision == revision))
        .and_then(|result| ferryman_channel::router::reason_of(&result.payload))
        .map(|why| format!("\nRouted: {}", excerpt(&why, 300)))
        .unwrap_or_default()
}

/// The adversary's finding as card lines: the headline, then its worst issues.
fn finding_lines(finding: &ferryman_channel::adversary::AdversaryFinding) -> Vec<String> {
    finding
        .lines(3)
        .iter()
        .map(|line| excerpt(line, 400))
        .collect()
}

/// A review card's adversary paragraph (empty when it has nothing to say) for `order` at
/// `revision`, and whether a Block still stands there.
fn adversary_card(route: &ProjectRoute, order: &str, revision: u32) -> (String, bool) {
    use ferryman_channel::adversary as found;
    let (policy, _) = policy::effective(&route.communications, &route.project_id);
    if policy.adversary == policy::AdversaryMode::Off {
        return (String::new(), false);
    }
    let Some(standing) = found::standing(route, order, revision, found::Trigger::PreDone) else {
        return (String::new(), false);
    };
    let mut lines = finding_lines(&standing.finding);
    if let Some(over) = &standing.overridden {
        lines.push(format!("The Block was overridden by {}.", over.from()));
    }
    (
        format!("\n\n{}", lines.join("\n")),
        standing.unresolved_block(),
    )
}

/// Lock or reject the interface contract a question is about, as the master, signed by the
/// bridge under their delegation; the question's answer is the result. Anything but Lock or
/// Reject is refused: a contract is frozen or declined, not discussed in a free reply.
fn decide_contract(
    route: &ProjectRoute,
    asked: &questions::Question,
    choice: &str,
    principal: &str,
    signer: &AgentIdentity,
) -> Result<questions::Answer> {
    use ferryman_channel::interface;
    let Some(contract) = interface::contract_for_question(route, &asked.id) else {
        bail!("that contract is gone, or no longer verifies");
    };
    if choice.eq_ignore_ascii_case(interface::LOCK) {
        // The question's id names the contract it was asked about (a digest prefix is in
        // it), so the contract found by it is the one the master was shown.
        let looked = interface::digest(&route.project_id, &contract);
        interface::lock(
            route,
            &contract.name,
            &contract.version,
            &looked,
            principal,
            signer,
        )?;
    } else if choice.eq_ignore_ascii_case(interface::REJECT) {
        interface::reject(route, &contract.name, &contract.version, principal, signer)?;
    } else {
        bail!("answer {} or {}", interface::LOCK, interface::REJECT);
    }
    questions::answer_to(route, asked)
        .context("the decision was recorded but its answer does not verify")
}

fn send(chat: i64, text: String, buttons: Vec<Row>) -> Action {
    Action::Send {
        chat,
        text,
        buttons,
        force_reply: false,
        track: None,
    }
}

fn toast(callback_id: &str, text: impl Into<String>) -> Action {
    Action::Answer {
        callback_id: callback_id.to_string(),
        text: text.into(),
    }
}

/// The one status line an order's message shows, rewritten as it moves.
fn status_text(order: &str, project: &str, by: &str, stage: &str, holder: Option<&str>) -> String {
    let steps = ["sent", "delivered", "read", "claimed", "done"];
    let reached = steps.iter().position(|step| *step == stage);
    let trail: Vec<String> = steps
        .iter()
        .enumerate()
        .map(|(index, step)| match reached {
            Some(at) if index == at => format!("[{step}]"),
            Some(at) if index < at => (*step).to_string(),
            _ => format!("({step})"),
        })
        .collect();
    let mut text = format!("{order} to {project}, as {by}\n{}", trail.join(" > "));
    if reached.is_none() {
        text.push_str(&format!("\n{stage}"));
    }
    if let Some(holder) = holder {
        text.push_str(&format!("\nworking on it: {holder}"));
    }
    text
}

/// Where an order has got to, as one word the status line knows.
fn stage_of(route: &ProjectRoute, task: &ferryman_channel::Task, now: DateTime<Utc>) -> String {
    match task.state_at(now) {
        TaskState::Killed { by, .. } => format!("stopped by {by}"),
        TaskState::Accepted | TaskState::Done | TaskState::AwaitingReview { .. } => {
            "done".to_string()
        }
        TaskState::Refuted { .. } => "refuted - not done".to_string(),
        _ => ferryman_channel::receipts::progress(route, task, now)
            .map_or_else(|| "sent".to_string(), |p| p.stage.as_str().to_string()),
    }
}

fn where_it_is(route: &ProjectRoute, task: &ferryman_channel::Task, now: DateTime<Utc>) -> String {
    match task.state_at(now) {
        TaskState::AwaitingReview { .. } => "waiting for review".to_string(),
        TaskState::Accepted => "approved".to_string(),
        TaskState::ChangesRequested { revision } => format!("sent back (r{revision})"),
        TaskState::Done => "done".to_string(),
        TaskState::Refuted { revision, .. } => format!("refuted (r{revision}) - not done"),
        TaskState::Killed { by, .. } => format!("stopped by {by}"),
        _ => stage_of(route, task, now),
    }
}

fn title_full(task: &ferryman_channel::Task) -> String {
    task.order
        .payload
        .get("task")
        .and_then(Value::as_str)
        .map_or_else(|| task.order.payload.to_string(), str::to_string)
}

fn title(task: &ferryman_channel::Task) -> String {
    task.order
        .payload
        .get("improvement")
        .and_then(|improvement| improvement.get("title"))
        .and_then(Value::as_str)
        .map(str::to_string)
        .unwrap_or_else(|| {
            title_full(task)
                .lines()
                .find(|line| !line.trim().is_empty())
                .unwrap_or_default()
                .to_string()
        })
}

fn result_text(payload: &Value) -> String {
    payload
        .get("output")
        .and_then(Value::as_str)
        .map_or_else(|| payload.to_string(), str::to_string)
}
// --- the loop --------------------------------------------------------------------------

#[derive(Debug, Deserialize)]
struct TgResponse {
    ok: bool,
    #[serde(default)]
    result: Value,
    #[serde(default)]
    description: Option<String>,
}

/// Telegram's Bot API over HTTPS. The token is in the URL and never printed.
struct Http {
    client: reqwest::Client,
    token: String,
}

impl Http {
    async fn call(&self, method: &str, body: &Value) -> Result<Value> {
        let response: TgResponse = self
            .client
            .post(format!(
                "https://api.telegram.org/bot{}/{method}",
                self.token
            ))
            .json(body)
            .timeout(Duration::from_secs(LONG_POLL_SECS + 20))
            .send()
            .await
            .with_context(|| format!("call Telegram's {method}"))?
            .json()
            .await
            .with_context(|| format!("read Telegram's reply to {method}"))?;
        if !response.ok {
            bail!(
                "telegram {method}: {}",
                response
                    .description
                    .unwrap_or_else(|| "refused".to_string())
            );
        }
        Ok(response.result)
    }

    async fn updates(&self, offset: i64) -> Result<Vec<Update>> {
        let result = self
            .call(
                "getUpdates",
                &json!({
                    "offset": offset,
                    "timeout": LONG_POLL_SECS,
                    "allowed_updates": ["message", "callback_query"],
                }),
            )
            .await?;
        Ok(serde_json::from_value(result).unwrap_or_default())
    }
}

fn keyboard(buttons: &[Row]) -> Value {
    json!({
        "inline_keyboard": buttons
            .iter()
            .map(|row| row
                .iter()
                .map(|(text, data)| json!({ "text": text, "callback_data": data }))
                .collect::<Vec<_>>())
            .collect::<Vec<_>>()
    })
}

async fn perform(http: &Http, bridge: &mut Bridge, actions: Vec<Action>) {
    for action in actions {
        let outcome = match action {
            Action::Send {
                chat,
                text,
                buttons,
                force_reply,
                track,
            } => {
                let mut body = json!({ "chat_id": chat, "text": excerpt(&text, MESSAGE_CHARS) });
                if force_reply {
                    body["reply_markup"] = json!({ "force_reply": true, "selective": true });
                } else if !buttons.is_empty() {
                    body["reply_markup"] = keyboard(&buttons);
                }
                http.call("sendMessage", &body).await.map(|sent| {
                    if let (Some(track), Some(id)) = (track, sent["message_id"].as_i64()) {
                        bridge.sent(track, chat, id);
                    }
                })
            }
            Action::Edit {
                chat,
                message_id,
                text,
                buttons,
            } => {
                let body = json!({
                    "chat_id": chat,
                    "message_id": message_id,
                    "text": excerpt(&text, MESSAGE_CHARS),
                    "reply_markup": keyboard(&buttons),
                });
                match http.call("editMessageText", &body).await {
                    // Pressing the button that shows what is already shown.
                    Err(error) if format!("{error}").contains("not modified") => Ok(()),
                    other => other.map(|_| ()),
                }
            }
            Action::Answer { callback_id, text } => http
                .call(
                    "answerCallbackQuery",
                    &json!({ "callback_query_id": callback_id, "text": text }),
                )
                .await
                .map(|_| ()),
        };
        if let Err(error) = outcome {
            eprintln!("telegram: {error:#}");
        }
    }
}

/// Every channel the bridge serves: those under `comms`, or the ferry root's projects.
fn load_routes(comms: Option<&PathBuf>) -> Result<Vec<ProjectRoute>> {
    let mut routes = crate::target_routes(&crate::Targets {
        workspace: None,
        comms: comms.cloned(),
    })?;
    routes.sort_by(|a, b| a.project_id.cmp(&b.project_id));
    routes.dedup_by(|a, b| a.project_id == b.project_id);
    Ok(routes)
}

/// The bridge's own key, seated in every project and published to every roster, so the
/// master can delegate to it and every machine can check what it signs.
fn seat(name: &str, routes: &[ProjectRoute]) -> Result<AgentIdentity> {
    let found = routes.iter().find_map(|route| {
        AgentIdentity::load_existing(name, &route.attachment)
            .ok()
            .flatten()
    });
    let identity = match found {
        Some(identity) => identity,
        None => AgentIdentity::load_or_create(
            name,
            &routes
                .first()
                .context("there are no projects here for the bridge to serve")?
                .attachment,
        )?,
    };
    for route in routes {
        let seated = match AgentIdentity::load_existing(name, &route.attachment) {
            Ok(Some(_)) => Ok(()),
            _ => identity.seat_in(&route.attachment),
        };
        let published = seated.and_then(|()| {
            ferryman_channel::register_agent_key(
                route,
                &ferryman_channel::AgentRoute {
                    name: name.to_string(),
                    role: "delegate".to_string(),
                    capabilities: Vec::new(),
                    public_key: None,
                    encryption_key: None,
                },
                &identity,
            )
        });
        if let Err(error) = published {
            eprintln!(
                "telegram: {name} cannot sign in {}: {error:#}",
                route.project_id
            );
        }
    }
    Ok(identity)
}

fn state_file(name: &str, routes: &[ProjectRoute]) -> Option<PathBuf> {
    ferryman_channel::licensing::machine_state_dir()
        .or_else(|| routes.first().map(|route| route.attachment.clone()))
        .map(|dir: PathBuf| dir.join(format!("telegram-{name}.json")))
}

/// Run the bridge until it is stopped.
pub async fn run(
    agent: Option<String>,
    comms: Option<PathBuf>,
    default_project: String,
) -> Result<()> {
    let token = match std::env::var("TELEGRAM_BOT_TOKEN") {
        Ok(token) if !token.trim().is_empty() => token.trim().to_string(),
        _ => bail!(
            "TELEGRAM_BOT_TOKEN is not set. Create a bot with @BotFather and put the token in \
             this process's environment - a systemd EnvironmentFile with mode 600 - never in \
             the channel, which syncs."
        ),
    };
    let config = Config::from_env(default_project)?;
    let name = match agent {
        Some(name) => name,
        None => ferryman_channel::canonical_agent_name(&format!(
            "telegram-{}",
            ferryman_ops::identity::machine_name()?
        )),
    };
    let mut routes = load_routes(comms.as_ref())?;
    let identity = seat(&name, &routes)?;
    let state_path = state_file(&name, &routes);
    println!("telegram: signing as {name}, {} project(s)", routes.len());
    let mut missing = Vec::new();
    for route in &routes {
        match delegation::active(&route.communications, &route.project_id, &name, Utc::now()) {
            Some(granted) => println!(
                "  {}: acts for {} ({})",
                route.project_id,
                granted.principal,
                granted.scopes.join(", ")
            ),
            None => missing.push(route.project_id.clone()),
        }
    }
    if !missing.is_empty() {
        println!(
            "  not delegated yet in: {}\n  the master delegates once with 'ferry team delegate {name}' \
             or the dashboard's Teammates page; until then the bridge shows these projects but cannot act",
            missing.join(", ")
        );
    }
    let mut bridge = Bridge::new(config, identity, routes.clone(), state_path);
    let http = Http {
        client: reqwest::Client::new(),
        token,
    };
    let mut reloaded = std::time::Instant::now();
    loop {
        match http.updates(bridge.state.offset).await {
            Ok(updates) => {
                for update in updates {
                    let actions = bridge.handle(update, Utc::now());
                    perform(&http, &mut bridge, actions).await;
                }
            }
            Err(error) => {
                eprintln!("telegram: {error:#}; retrying");
                tokio::time::sleep(Duration::from_secs(10)).await;
            }
        }
        let actions = bridge.tick(Utc::now());
        perform(&http, &mut bridge, actions).await;
        if reloaded.elapsed() > Duration::from_secs(RELOAD_SECS) {
            reloaded = std::time::Instant::now();
            if let Ok(fresh) = load_routes(comms.as_ref())
                && fresh.len() != routes.len()
            {
                let _ = seat(&name, &fresh);
                routes.clone_from(&fresh);
                bridge.routes = fresh;
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use ferryman_channel::AgentRoute;
    use std::path::Path;

    const JOSH_TG: i64 = 42;
    const GROUP: i64 = -1001;
    const BRIDGE: &str = "telegram-grouchly";

    fn person(name: &str, seed: u8) -> AgentIdentity {
        AgentIdentity::from_seed(name, [seed; 32])
    }

    fn josh() -> AgentIdentity {
        person("josh", 1)
    }

    fn wisp() -> AgentIdentity {
        person("wisp", 3)
    }

    /// An adversary: not the builder, and (once it has published an inventory) allowed to
    /// say what counts.
    fn scout() -> AgentIdentity {
        person("scout", 7)
    }

    /// A second adversary, on another machine.
    fn ranger() -> AgentIdentity {
        person("ranger", 8)
    }

    /// Publish `who`'s signed engine inventory: deepseek, on `machine`. Asking twice is
    /// harmless: the first inventory stands.
    fn inventory(route: &ProjectRoute, who: &AgentIdentity, machine: &str) {
        let _ = ferryman_channel::receipts::refresh_engines(
            route,
            who,
            machine,
            "0.0.0",
            vec![ferryman_channel::receipts::EngineReport {
                name: "deepseek".into(),
                kind: "http".into(),
                model: None,
                tier: "judge".into(),
                paid: "prepaid".into(),
                state: "up".into(),
                until: None,
                reason: None,
                latency_ms: None,
                balance: None,
                checked_at: None,
                trust: None,
                billing: None,
                class: None,
                capabilities: None,
            }],
            Utc::now(),
        );
    }

    /// Record `finding` as `scout`, whose inventory is published first.
    fn scout_says(route: &ProjectRoute, finding: ferryman_channel::adversary::AdversaryFinding) {
        inventory(route, &scout(), "grouchly");
        ferryman_channel::adversary::record(route, &scout(), finding).unwrap();
    }

    /// Record `finding` as `ranger`, a second adversary.
    fn ranger_says(route: &ProjectRoute, finding: ferryman_channel::adversary::AdversaryFinding) {
        inventory(route, &ranger(), "beastly");
        ferryman_channel::adversary::record(route, &ranger(), finding).unwrap();
    }
    /// A channel mastered by josh, with the bridge and a worker on its roster.
    fn project(dir: &Path, id: &str) -> ProjectRoute {
        let communications = dir.join(format!("{id}-ferryman"));
        std::fs::create_dir_all(&communications).unwrap();
        let mut route = ProjectRoute {
            project_id: id.into(),
            workspace: dir.join(id),
            attachment: dir.join(format!("{id}-attachment")),
            communications,
            shared_remote: String::new(),
            git_remote: String::new(),
            git_visibility: String::new(),
            agents: Vec::new(),
        };
        for member in [josh(), person(BRIDGE, 2), wisp(), scout(), ranger()] {
            let agent = AgentRoute {
                name: member.name().into(),
                role: "operator".into(),
                capabilities: Vec::new(),
                public_key: Some(member.public_key_hex()),
                encryption_key: None,
            };
            ferryman_channel::register_agent(&route, &agent).unwrap();
            route.agents.push(agent);
        }
        ferryman_channel::master::initialize_master(&route, &josh(), "josh").unwrap();
        route
    }

    fn delegate(route: &ProjectRoute, scopes: &[&str]) {
        ferryman_channel::delegation::grant(
            &route.communications,
            &route.project_id,
            &josh(),
            BRIDGE,
            &scopes.iter().map(ToString::to_string).collect::<Vec<_>>(),
            None,
        )
        .unwrap();
    }

    fn bridge(dir: &Path) -> (Bridge, ProjectRoute, ProjectRoute) {
        let ferryman = project(dir, "ferryman");
        let bullship = project(dir, "bullship");
        let bridge = Bridge::new(
            Config {
                approvers: vec![JOSH_TG],
                group: Some(GROUP),
                default_project: "ferryman".into(),
            },
            person(BRIDGE, 2),
            vec![bullship.clone(), ferryman.clone()],
            None,
        );
        (bridge, ferryman, bullship)
    }

    fn text(from: i64, chat: i64, id: i64, words: &str) -> Update {
        Update {
            update_id: id,
            message: Some(Msg {
                message_id: id,
                from: Some(User { id: from }),
                chat: Chat { id: chat },
                text: Some(words.into()),
                reply_to_message: None,
            }),
            callback_query: None,
        }
    }

    fn reply(chat: i64, id: i64, to: i64, words: &str) -> Update {
        let mut update = text(JOSH_TG, chat, id, words);
        if let Some(message) = update.message.as_mut() {
            message.reply_to_message = Some(Box::new(Msg {
                message_id: to,
                ..Msg::default()
            }));
        }
        update
    }

    fn press(from: i64, chat: i64, message_id: i64, data: &str) -> Update {
        Update {
            update_id: message_id,
            message: None,
            callback_query: Some(Callback {
                id: format!("cb-{message_id}"),
                from: User { id: from },
                message: Some(Msg {
                    message_id,
                    chat: Chat { id: chat },
                    ..Msg::default()
                }),
                data: Some(data.into()),
            }),
        }
    }

    /// The fake Telegram: hands out message ids and remembers what each send was for.
    fn deliver(bridge: &mut Bridge, actions: &[Action], next_id: &mut i64) {
        for action in actions {
            if let Action::Send {
                chat,
                track: Some(track),
                ..
            } = action
            {
                *next_id += 1;
                bridge.sent(track.clone(), *chat, *next_id);
            }
        }
    }

    fn texts(actions: &[Action]) -> Vec<String> {
        actions
            .iter()
            .filter_map(|action| match action {
                Action::Send { text, .. } | Action::Edit { text, .. } => Some(text.clone()),
                Action::Answer { .. } => None,
            })
            .collect()
    }

    fn buttons(actions: &[Action]) -> Vec<(String, String)> {
        actions
            .iter()
            .flat_map(|action| match action {
                Action::Send { buttons, .. } | Action::Edit { buttons, .. } => buttons.concat(),
                Action::Answer { .. } => Vec::new(),
            })
            .collect()
    }
    #[test]
    fn strangers_and_other_chats_get_nothing_at_all() {
        let dir = tempfile::tempdir().unwrap();
        let (mut bridge, ferryman, _) = bridge(dir.path());
        delegate(&ferryman, &["orders"]);
        let now = Utc::now();
        assert!(
            bridge
                .handle(text(99, GROUP, 1, "delete everything"), now)
                .is_empty()
        );
        assert!(
            bridge
                .handle(text(JOSH_TG, -555, 2, "wrong group"), now)
                .is_empty()
        );
        assert!(
            bridge
                .handle(text(99, 99, 3, "private stranger"), now)
                .is_empty()
        );
        assert!(bridge.handle(press(99, GROUP, 4, "impall"), now).is_empty());
        assert!(ferryman_channel::list_tasks(&ferryman).unwrap().is_empty());
        // The approver, in their private chat and in the group, is answered.
        assert!(
            !bridge
                .handle(text(JOSH_TG, JOSH_TG, 5, "/start"), now)
                .is_empty()
        );
        assert!(
            !bridge
                .handle(text(JOSH_TG, GROUP, 6, "/menu@FerrymanBot"), now)
                .is_empty()
        );
    }

    #[test]
    fn start_shows_the_menu_and_there_are_no_other_commands() {
        let dir = tempfile::tempdir().unwrap();
        let (mut bridge, _, _) = bridge(dir.path());
        let now = Utc::now();
        let menu = bridge.handle(text(JOSH_TG, GROUP, 1, "/start"), now);
        let labels: Vec<String> = buttons(&menu).into_iter().map(|(label, _)| label).collect();
        assert_eq!(
            labels,
            ["Projects", "Engines", "Tasks", "Self-improve", "Focus"]
        );
        let other = bridge.handle(text(JOSH_TG, GROUP, 2, "/status"), now);
        assert!(texts(&other)[0].starts_with("Use the buttons"));
        assert_eq!(buttons(&other).len(), 5, "and the menu with it");
    }

    #[test]
    fn without_a_delegation_nothing_is_signed_and_the_way_to_fix_it_is_said() {
        let dir = tempfile::tempdir().unwrap();
        let (mut bridge, ferryman, _) = bridge(dir.path());
        let said = bridge.handle(text(JOSH_TG, GROUP, 1, "tidy the README"), Utc::now());
        assert!(texts(&said)[0].contains("ferry team delegate telegram-grouchly"));
        assert!(ferryman_channel::list_tasks(&ferryman).unwrap().is_empty());
    }

    /// A message becomes a signed order in josh's name, and one status message follows it
    /// from sent to done, then the result is posted.
    #[test]
    fn free_text_is_a_delegated_order_whose_status_message_follows_it() {
        let dir = tempfile::tempdir().unwrap();
        let (mut bridge, ferryman, _) = bridge(dir.path());
        delegate(&ferryman, &["orders"]);
        let mut ids = 1000;
        let now = Utc::now();
        let actions = bridge.handle(text(JOSH_TG, GROUP, 7, "tidy the README"), now);
        assert!(texts(&actions)[0].contains("as josh via telegram-grouchly"));
        deliver(&mut bridge, &actions, &mut ids);

        let order_id = format!("tg-{}-7", GROUP.unsigned_abs());
        let task = ferryman_channel::read_task(&ferryman, &order_id).unwrap();
        assert_eq!(task.order.issued_by, "josh");
        assert_eq!(task.order.signed_by.as_deref(), Some(BRIDGE));
        assert_eq!(
            ferryman_channel::verify_order_in(&ferryman, &task.order),
            ferryman_channel::SignatureCheck::Valid
        );
        assert!(ferryman_channel::work_for(&ferryman, "wisp").unwrap().len() == 1);

        ferryman_channel::receipts::record_delivered(&ferryman, &order_id, &wisp(), "m", "0")
            .unwrap();
        let moved = bridge.tick(Utc::now());
        assert!(
            matches!(&moved[0], Action::Edit { message_id: 1001, text, .. } if text.contains("[delivered]")),
            "{moved:?}"
        );
        ferryman_channel::claim_order(&ferryman, &order_id, "wisp").unwrap();
        assert!(texts(&bridge.tick(Utc::now()))[0].contains("[claimed]"));
        assert!(
            bridge.tick(Utc::now()).is_empty(),
            "nothing changed, nothing said"
        );

        let mut result = ferryman_channel::TaskResult {
            order_id: order_id.clone(),
            agent: "wisp".into(),
            revision: 1,
            submitted_at: Utc::now(),
            payload: json!({ "output": "README tidied" }),
            signed_by: None,
            signature: None,
        };
        wisp().sign_result(&mut result);
        ferryman_channel::submit_result(&ferryman, &result).unwrap();
        let done = texts(&bridge.tick(Utc::now()));
        assert!(done[0].contains("[done]"), "{done:?}");
        assert!(done[1].contains("README tidied"), "{done:?}");
        assert!(bridge.tick(Utc::now()).is_empty(), "said once");
    }

    #[test]
    fn picking_a_project_sends_the_next_message_there() {
        let dir = tempfile::tempdir().unwrap();
        let (mut bridge, ferryman, bullship) = bridge(dir.path());
        delegate(&bullship, &["orders"]);
        let picked = bridge.handle(press(JOSH_TG, GROUP, 50, "pick:bullship"), Utc::now());
        assert!(matches!(&picked[0], Action::Answer { text, .. } if text == "Working in bullship"));
        bridge.handle(text(JOSH_TG, GROUP, 8, "add a leaderboard"), Utc::now());
        assert_eq!(ferryman_channel::list_tasks(&bullship).unwrap().len(), 1);
        assert!(ferryman_channel::list_tasks(&ferryman).unwrap().is_empty());
        // The private chat still has the default.
        assert_eq!(bridge.current(JOSH_TG), "ferryman");
    }
    /// An order of josh's that needs him, with a result in: its message carries Approve /
    /// Send back / Details, and each writes a verdict in his name through the delegation.
    fn awaiting_review(route: &ProjectRoute, id: &str) {
        awaiting_review_with(route, id, json!({ "output": "renamed" }));
    }

    fn awaiting_review_with(route: &ProjectRoute, id: &str, payload: Value) {
        let mut order = ferryman_channel::Order {
            id: id.into(),
            project_id: route.project_id.clone(),
            issued_by: "josh".into(),
            assigned_to: None,
            created_at: Utc::now(),
            payload: json!({ "task": "rename the flag" }),
            requires_review: true,
            requires_approval: true,
            depends_on: Vec::new(),
            signed_by: None,
            signature: None,
            result_contract: None,
            interface: None,
            touches: Vec::new(),
            needs: None,
            allow_overlap: false,
        };
        josh().sign_order(&mut order);
        ferryman_channel::issue_order(route, &order).unwrap();
        let mut result = ferryman_channel::TaskResult {
            order_id: id.into(),
            agent: "wisp".into(),
            revision: 1,
            submitted_at: Utc::now(),
            payload,
            signed_by: None,
            signature: None,
        };
        wisp().sign_result(&mut result);
        ferryman_channel::claim_order(route, id, "wisp").unwrap();
        ferryman_channel::submit_result(route, &result).unwrap();
    }

    #[test]
    fn approve_and_send_back_are_buttons_and_verdicts_in_the_masters_name() {
        let dir = tempfile::tempdir().unwrap();
        let (mut bridge, ferryman, _) = bridge(dir.path());
        delegate(&ferryman, &["orders", "review"]);
        assert!(
            bridge.tick(Utc::now()).is_empty(),
            "nothing waiting at first start"
        );
        awaiting_review(&ferryman, "t-1");
        let posted = bridge.tick(Utc::now());
        assert!(texts(&posted)[0].contains("t-1 in ferryman needs you"));
        let data: Vec<String> = buttons(&posted).into_iter().map(|(_, data)| data).collect();
        assert_eq!(
            data,
            ["ok:ferryman:t-1", "back:ferryman:t-1", "det:ferryman:t-1"]
        );
        assert!(bridge.tick(Utc::now()).is_empty(), "posted once");

        let details = bridge.handle(press(JOSH_TG, GROUP, 60, "det:ferryman:t-1"), Utc::now());
        assert!(texts(&details)[0].contains("renamed"));

        let approved = bridge.handle(press(JOSH_TG, GROUP, 61, "ok:ferryman:t-1"), Utc::now());
        assert!(texts(&approved)[0].contains("approved by josh via telegram-grouchly"));
        assert_eq!(
            ferryman_channel::read_task(&ferryman, "t-1")
                .unwrap()
                .state(),
            TaskState::Accepted
        );

        // Send back asks for the note as a reply, and the reply sends it back.
        awaiting_review(&ferryman, "t-2");
        let mut ids = 2000;
        let asked = bridge.handle(press(JOSH_TG, GROUP, 62, "back:ferryman:t-2"), Utc::now());
        assert!(matches!(
            &asked[1],
            Action::Send {
                force_reply: true,
                ..
            }
        ));
        deliver(&mut bridge, &asked, &mut ids);
        let sent_back = bridge.handle(
            reply(GROUP, 63, 2001, "keep the old name as an alias"),
            Utc::now(),
        );
        assert!(texts(&sent_back)[0].starts_with("Sent t-2 r1 back"));
        let task = ferryman_channel::read_task(&ferryman, "t-2").unwrap();
        assert_eq!(task.state(), TaskState::ChangesRequested { revision: 2 });
        assert_eq!(task.reviews[0].reviewer, "josh");
        assert_eq!(task.reviews[0].signed_by.as_deref(), Some(BRIDGE));
    }

    #[test]
    fn the_card_says_why_that_engine_when_the_worker_recorded_it() {
        let dir = tempfile::tempdir().unwrap();
        let (mut bridge, ferryman, _) = bridge(dir.path());
        delegate(&ferryman, &["orders", "review"]);
        assert!(bridge.tick(Utc::now()).is_empty());
        awaiting_review_with(
            &ferryman,
            "t-9",
            json!({
                "output": "renamed",
                "routing": { "reason": "nvidia: free, p 0.81 for docs >= 0.75, cheapest sufficient" }
            }),
        );
        awaiting_review(&ferryman, "t-8");
        let posted = bridge.tick(Utc::now());
        let cards = texts(&posted);
        let routed = cards.iter().find(|t| t.contains("t-9 in")).unwrap();
        assert!(
            routed.contains("\nRouted: nvidia: free, p 0.81 for docs >= 0.75, cheapest sufficient"),
            "{routed}"
        );
        let plain = cards.iter().find(|t| t.contains("t-8 in")).unwrap();
        assert!(
            !plain.contains("Routed:"),
            "work with no recorded decision reads as it did: {plain}"
        );
    }

    #[test]
    fn a_verdict_without_the_review_scope_is_refused() {
        let dir = tempfile::tempdir().unwrap();
        let (mut bridge, ferryman, _) = bridge(dir.path());
        delegate(&ferryman, &["orders"]);
        awaiting_review(&ferryman, "t-3");
        let refused = bridge.handle(press(JOSH_TG, GROUP, 70, "ok:ferryman:t-3"), Utc::now());
        assert!(
            texts(&refused)[0].contains("not delegated 'review'"),
            "{refused:?}"
        );
        assert!(matches!(
            ferryman_channel::read_task(&ferryman, "t-3")
                .unwrap()
                .state(),
            TaskState::AwaitingReview { .. }
        ));
    }

    #[test]
    fn the_improve_loops_questions_arrive_with_buttons_and_the_answer_is_signed_for_josh() {
        let dir = tempfile::tempdir().unwrap();
        let (mut bridge, ferryman, _) = bridge(dir.path());
        delegate(&ferryman, &["improve"]);
        questions::ask(
            &ferryman,
            &wisp(),
            "clarify-2026-w39-1",
            questions::CLARIFY,
            "Keep Windows 7 support?",
            &["Yes".to_string(), "No".to_string()],
            None,
        )
        .unwrap();
        let posted = bridge.tick(Utc::now());
        assert!(texts(&posted)[0].contains("Keep Windows 7 support?"));
        let choices = buttons(&posted);
        assert_eq!(
            choices[0],
            (
                "Yes".to_string(),
                "ans:ferryman:clarify-2026-w39-1:0".to_string()
            )
        );
        assert_eq!(choices[2].0, "Answer in words");
        let answered = bridge.handle(press(JOSH_TG, GROUP, 80, &choices[1].1), Utc::now());
        assert!(texts(&answered)[0].contains("Answered \"No\" - josh via telegram-grouchly"));
        let (question, answer) = questions::list(&ferryman).remove(0);
        assert_eq!(question.id, "clarify-2026-w39-1");
        assert_eq!(answer.unwrap().answer, "No");
        assert!(bridge.tick(Utc::now()).is_empty());
    }

    /// An outsider's suggestion that triage sent up arrives once, with Accept, Decline and
    /// Ask more, and the button is the same signed answer the owner's worker then reads.
    #[test]
    fn a_suggestion_from_outside_is_asked_with_three_buttons_and_the_answer_parses() {
        use ferryman_channel::suggestions::{QUESTION_KIND, flow::Choice};
        let dir = tempfile::tempdir().unwrap();
        let (mut bridge, ferryman, _) = bridge(dir.path());
        delegate(&ferryman, &["improve"]);
        let options = ["Accept", "Decline", "Ask more"].map(String::from);
        questions::ask(
            &ferryman,
            &wisp(),
            "sugg-1",
            QUESTION_KIND,
            "#4 [idea] Offline timer from @octo (typed)\nTriage: accept",
            &options,
            None,
        )
        .unwrap();
        let posted = bridge.tick(Utc::now());
        let shown = texts(&posted);
        assert!(
            shown[0].starts_with("ferryman - a suggestion from outside"),
            "{shown:?}"
        );
        assert!(shown[0].contains("Offline timer"), "{shown:?}");
        let choices = buttons(&posted);
        let labels: Vec<&str> = choices.iter().map(|(label, _)| label.as_str()).collect();
        assert_eq!(labels, ["Accept", "Decline", "Ask more", "Answer in words"]);
        assert!(bridge.tick(Utc::now()).is_empty(), "posted once");
        bridge.handle(press(JOSH_TG, GROUP, 81, &choices[0].1), Utc::now());
        let (_, answer) = questions::list(&ferryman).remove(0);
        let answer = answer.unwrap();
        assert_eq!(Choice::parse(&answer.answer), Some(Choice::Accept));
    }

    /// A proposed interface contract reaches the phone once, however often it is asked
    /// about, with Lock and Reject buttons; Lock freezes it signed for josh by the bridge,
    /// and a free-text reply cannot stand in for the decision.
    #[test]
    fn a_proposed_contract_is_asked_once_and_lock_or_reject_decides_it() {
        use ferryman_channel::contract::Shape;
        use ferryman_channel::interface;
        let dir = tempfile::tempdir().unwrap();
        let (mut bridge, ferryman, _) = bridge(dir.path());
        delegate(&ferryman, &["improve"]);
        let shape = Shape::parse(&json!({
            "type": "object",
            "required": ["id"],
            "properties": { "id": { "type": "integer" } }
        }))
        .unwrap();
        let first = interface::propose(
            &ferryman,
            &wisp(),
            "user-api",
            "1",
            "GET /users/:id",
            None,
            shape.clone(),
        )
        .unwrap();
        assert!(
            !interface::ensure_question(&ferryman, &wisp(), &first).unwrap(),
            "asking again is asking once"
        );

        let posted = bridge.tick(Utc::now());
        let shown = texts(&posted);
        assert_eq!(shown.len(), 1, "{shown:?}");
        assert!(
            shown[0].starts_with("ferryman - interface contract"),
            "{shown:?}"
        );
        assert!(shown[0].contains("user-api@1"), "{shown:?}");
        let labels: Vec<String> = buttons(&posted)
            .into_iter()
            .map(|(label, _)| label)
            .collect();
        assert_eq!(labels, ["Lock", "Reject", "Answer in words"]);
        assert!(bridge.tick(Utc::now()).is_empty(), "posted once");

        // Not a decision: the question stays open and nothing is locked.
        let asked =
            questions::read(&ferryman, &interface::question_id("ferryman", &first)).unwrap();
        let error = decide_contract(
            &ferryman,
            &asked,
            "sure, why not",
            "josh",
            &person(BRIDGE, 2),
        )
        .unwrap_err();
        assert!(error.to_string().contains("Lock or Reject"), "{error}");
        assert!(interface::locked(&ferryman, "user-api", "1").is_none());
        assert_eq!(questions::pending(&ferryman).len(), 1);

        let answered = press_labelled(&mut bridge, &posted, "Lock", 83);
        assert!(
            texts(&answered)
                .iter()
                .any(|t| t.contains("Answered \"Lock\" - josh via telegram-grouchly")),
            "{answered:?}"
        );
        let locked = interface::locked(&ferryman, "user-api", "1").expect("locked from the phone");
        let lock = locked.lock.unwrap();
        assert_eq!(lock.by, "josh");
        assert_eq!(lock.signed_by, "telegram-grouchly");
        assert!(questions::pending(&ferryman).is_empty());

        // Reject declines a second proposal; it can no longer be locked.
        let second =
            interface::propose(&ferryman, &wisp(), "user-api", "2", "", None, shape).unwrap();
        let posted = bridge.tick(Utc::now());
        press_labelled(&mut bridge, &posted, "Reject", 84);
        assert_eq!(
            interface::status(&ferryman, &second),
            interface::Status::Rejected
        );
        assert!(interface::locked(&ferryman, "user-api", "2").is_none());
    }

    #[test]
    fn a_contract_cannot_be_locked_from_the_phone_without_the_improve_delegation() {
        use ferryman_channel::contract::Shape;
        use ferryman_channel::interface;
        let dir = tempfile::tempdir().unwrap();
        let (mut bridge, ferryman, _) = bridge(dir.path());
        let shape = Shape::parse(&json!({ "type": "object" })).unwrap();
        interface::propose(&ferryman, &wisp(), "user-api", "1", "", None, shape).unwrap();
        let posted = bridge.tick(Utc::now());
        let refused = press_labelled(&mut bridge, &posted, "Lock", 85);
        assert!(
            matches!(&refused[0], Action::Answer { text, .. } if text.contains("Not delegated")),
            "{refused:?}"
        );
        assert!(interface::locked(&ferryman, "user-api", "1").is_none());
    }

    #[test]
    fn self_improve_toggles_per_project_and_on_for_all_only_where_delegated() {
        let dir = tempfile::tempdir().unwrap();
        let (mut bridge, ferryman, bullship) = bridge(dir.path());
        delegate(&ferryman, &["improve"]);
        let view = bridge.handle(press(JOSH_TG, GROUP, 90, "improve"), Utc::now());
        assert!(
            buttons(&view)
                .iter()
                .any(|(_, data)| data == "imp:ferryman:on")
        );
        let switched = bridge.handle(press(JOSH_TG, GROUP, 90, "imp:ferryman:on"), Utc::now());
        assert!(
            matches!(&switched[0], Action::Answer { text, .. } if text == "Self-improve on for ferryman")
        );
        let setting =
            ferryman_channel::ferry::self_improve_setting(&ferryman.communications, "ferryman")
                .unwrap();
        assert_eq!(setting.set_by(), "josh via telegram-grouchly");

        bridge.handle(press(JOSH_TG, GROUP, 90, "imp:ferryman:off"), Utc::now());
        let all = bridge.handle(press(JOSH_TG, GROUP, 90, "impall"), Utc::now());
        assert!(
            matches!(&all[0], Action::Answer { text, .. } if text == "Switched on in 1 project(s)")
        );
        assert!(ferryman_channel::ferry::self_improve_enabled(
            &ferryman.communications,
            "ferryman"
        ));
        assert!(!ferryman_channel::ferry::self_improve_enabled(
            &bullship.communications,
            "bullship"
        ));
    }

    #[test]
    fn the_focus_is_viewed_and_changed_from_buttons_signed_for_the_master() {
        use ferryman_channel::focus::{Tier, in_force};
        let dir = tempfile::tempdir().unwrap();
        ferryman_channel::licensing::use_machine_state_dir_per_thread(dir.path().join("state"));
        let (mut bridge, ferryman, bullship) = bridge(dir.path());
        delegate(&ferryman, &["improve"]);
        let tier = |project: &str| {
            in_force(&ferryman.communications, "ferryman").tier(project, Utc::now())
        };
        let answer = |actions: &[Action]| match &actions[0] {
            Action::Answer { text, .. } => text.clone(),
            other => panic!("expected an answer, got {other:?}"),
        };
        let push = |bridge: &mut Bridge, data: &str| {
            bridge.handle(press(JOSH_TG, GROUP, 91, data), Utc::now())
        };

        let view = push(&mut bridge, "focus");
        let data: Vec<String> = buttons(&view).into_iter().map(|(_, data)| data).collect();
        assert!(data.contains(&"fsel:ferryman".to_string()), "{data:?}");
        assert!(data.contains(&"fsel:bullship".to_string()), "{data:?}");
        assert!(!data.contains(&"fclr".to_string()), "nothing to clear yet");
        assert!(texts(&view)[0].contains("No focus is set"), "{view:?}");

        // A project's tiers.
        let pick = push(&mut bridge, "fsel:bullship");
        let data: Vec<String> = buttons(&pick).into_iter().map(|(_, data)| data).collect();
        for want in [
            "fset:bullship:focus:30",
            "fset:bullship:focus:0",
            "fset:bullship:normal:0",
            "fset:bullship:background:30",
            "fset:bullship:paused:30",
        ] {
            assert!(data.contains(&want.to_string()), "{want} in {data:?}");
        }

        // Choosing one signs it as the master, through the delegation.
        let set = push(&mut bridge, "fset:bullship:focus:30");
        assert_eq!(answer(&set), "bullship is now focus");
        assert_eq!(tier("bullship"), Tier::Focus);
        assert_eq!(tier("ferryman"), Tier::Normal);
        let record = in_force(&ferryman.communications, "ferryman")
            .setting
            .unwrap();
        assert_eq!(record.set_by(), "josh via telegram-grouchly");
        assert!(record.projects["bullship"].until.is_some(), "30 days");
        // The view that follows shows it, and offers to clear.
        let shown = buttons(&set);
        assert!(
            shown.iter().any(
                |(label, data)| data == "fsel:bullship" && label.starts_with("bullship: focus")
            ),
            "{shown:?}"
        );
        assert!(shown.iter().any(|(_, data)| data == "fclr"));

        // Until changed, pressed again: nothing to sign.
        push(&mut bridge, "fset:bullship:focus:0");
        let again = push(&mut bridge, "fset:bullship:focus:0");
        assert_eq!(answer(&again), "Already so");
        push(&mut bridge, "fset:ferryman:paused:0");
        assert_eq!(tier("ferryman"), Tier::Paused);
        // Normal is no entry at all.
        push(&mut bridge, "fset:bullship:normal:0");
        assert_eq!(tier("bullship"), Tier::Normal);
        assert!(
            !in_force(&ferryman.communications, "ferryman")
                .setting
                .unwrap()
                .projects
                .contains_key("bullship")
        );

        let cleared = push(&mut bridge, "fclr");
        assert!(answer(&cleared).starts_with("Focus cleared"), "{cleared:?}");
        assert!(!in_force(&ferryman.communications, "ferryman").is_set());

        // An archived project is refused: it gets nothing.
        ferryman_channel::ferry::set_archived(&bullship.communications, "bullship", true, &josh())
            .unwrap();
        let refused = push(&mut bridge, "fset:bullship:focus:30");
        assert!(answer(&refused).contains("archived"), "{refused:?}");
        assert!(!in_force(&ferryman.communications, "ferryman").is_set());
        let view = push(&mut bridge, "focus");
        assert!(
            !buttons(&view)
                .iter()
                .any(|(_, data)| data == "fsel:bullship"),
            "an archived project is not offered"
        );
    }

    #[test]
    fn the_focus_cannot_be_changed_from_the_phone_without_the_improve_delegation() {
        let dir = tempfile::tempdir().unwrap();
        ferryman_channel::licensing::use_machine_state_dir_per_thread(dir.path().join("state"));
        let (mut bridge, ferryman, _) = bridge(dir.path());
        // Delegated for orders only.
        delegate(&ferryman, &["orders"]);
        let refused = bridge.handle(
            press(JOSH_TG, GROUP, 92, "fset:bullship:focus:30"),
            Utc::now(),
        );
        assert!(
            matches!(&refused[0], Action::Answer { text, .. } if !text.contains("is now")),
            "{refused:?}"
        );
        assert!(!ferryman.communications.join("FOCUS").exists());
        // Nobody but an approver may press the buttons at all.
        let stranger = bridge.handle(press(777, GROUP, 93, "fset:bullship:focus:30"), Utc::now());
        assert!(stranger.is_empty());
        assert!(!ferryman.communications.join("FOCUS").exists());
    }
    /// "On for all" from the phone passes over an archived project, even one the bridge
    /// may switch.
    #[test]
    fn on_for_all_from_the_phone_leaves_an_archived_project_alone() {
        let dir = tempfile::tempdir().unwrap();
        let (mut bridge, ferryman, bullship) = bridge(dir.path());
        delegate(&ferryman, &["improve"]);
        delegate(&bullship, &["improve"]);
        assert!(
            ferryman_channel::ferry::set_archived(
                &bullship.communications,
                "bullship",
                true,
                &josh()
            )
            .unwrap()
        );
        let all = bridge.handle(press(JOSH_TG, GROUP, 90, "impall"), Utc::now());
        assert!(
            matches!(&all[0], Action::Answer { text, .. } if text == "Switched on in 1 project(s)"),
            "{all:?}"
        );
        assert!(ferryman_channel::ferry::self_improve_enabled(
            &ferryman.communications,
            "ferryman"
        ));
        assert!(
            ferryman_channel::ferry::self_improve_setting(&bullship.communications, "bullship")
                .is_none(),
            "nothing was signed for the archived project"
        );
    }

    /// A result its own words refute is announced as refuted, never as done.
    #[test]
    fn a_refuted_result_is_never_announced_as_done() {
        let dir = tempfile::tempdir().unwrap();
        let (_bridge, ferryman, _) = bridge(dir.path());
        let mut order = ferryman_channel::Order {
            id: "archcheck".into(),
            project_id: "ferryman".into(),
            issued_by: "josh".into(),
            assigned_to: Some("wisp".into()),
            created_at: Utc::now(),
            payload: json!({ "task": "Run these and paste the raw output" }),
            requires_review: false,
            requires_approval: false,
            depends_on: Vec::new(),
            signed_by: None,
            signature: None,
            result_contract: None,
            interface: None,
            touches: Vec::new(),
            needs: None,
            allow_overlap: false,
        };
        josh().sign_order(&mut order);
        ferryman_channel::issue_order(&ferryman, &order).unwrap();
        ferryman_channel::claim_order(&ferryman, "archcheck", "wisp").unwrap();
        let mut result = ferryman_channel::TaskResult {
            order_id: "archcheck".into(),
            agent: "wisp".into(),
            revision: 1,
            submitted_at: Utc::now(),
            payload: json!({ "output": "better suited to 'claw'\n1. no output\n2. no output" }),
            signed_by: None,
            signature: None,
        };
        wisp().sign_result(&mut result);
        ferryman_channel::submit_result(&ferryman, &result).unwrap();
        let task = ferryman_channel::read_task(&ferryman, "archcheck").unwrap();
        let now = Utc::now();
        assert_eq!(stage_of(&ferryman, &task, now), "refuted - not done");
        assert_eq!(
            where_it_is(&ferryman, &task, now),
            "refuted (r1) - not done"
        );
    }

    #[test]
    fn with_every_engine_down_it_says_so_and_speaks_up_when_one_is_back() {
        let dir = tempfile::tempdir().unwrap();
        let (mut bridge, ferryman, _) = bridge(dir.path());
        delegate(&ferryman, &["orders"]);
        let engine = |state: &str| ferryman_channel::receipts::EngineReport {
            name: "claude".into(),
            kind: "cli".into(),
            model: None,
            tier: "judge".into(),
            paid: "subscription".into(),
            state: state.into(),
            until: None,
            reason: None,
            latency_ms: None,
            balance: None,
            checked_at: None,
            trust: None,
            billing: None,
            class: None,
            capabilities: None,
        };
        let now = Utc::now();
        ferryman_channel::receipts::refresh_engines(
            &ferryman,
            &wisp(),
            "beastly",
            "0",
            vec![engine("exhausted")],
            now - chrono::Duration::minutes(10),
        )
        .unwrap();
        let said = texts(&bridge.handle(text(JOSH_TG, GROUP, 9, "ship it"), now));
        assert!(
            said[1].starts_with("No engine anywhere can run this"),
            "{said:?}"
        );
        let _ = bridge.tick(now);
        ferryman_channel::receipts::refresh_engines(
            &ferryman,
            &wisp(),
            "beastly",
            "0",
            vec![engine("up")],
            now,
        )
        .unwrap();
        let back = texts(&bridge.tick(now));
        assert!(
            back.iter()
                .any(|t| t.starts_with("An engine is back: claude on beastly")),
            "{back:?}"
        );
    }

    /// Publish, as wisp on beastly, a subscription, a free tier and a prepaid engine.
    fn three_engines(route: &ProjectRoute) {
        let engine =
            |name: &str, tier: &str, paid: &str| ferryman_channel::receipts::EngineReport {
                name: name.into(),
                kind: "http".into(),
                model: None,
                tier: tier.into(),
                paid: paid.into(),
                state: "up".into(),
                until: None,
                reason: None,
                latency_ms: None,
                balance: None,
                checked_at: None,
                trust: None,
                billing: None,
                class: None,
                capabilities: None,
            };
        ferryman_channel::receipts::refresh_engines(
            route,
            &wisp(),
            "beastly",
            "0",
            vec![
                engine("claude", "judge", "subscription"),
                engine("nemotron", "build", "free-tier"),
                engine("deepseek", "judge", "prepaid"),
            ],
            Utc::now(),
        )
        .unwrap();
    }

    fn press_labelled(bridge: &mut Bridge, view: &[Action], label: &str, id: i64) -> Vec<Action> {
        let (_, data) = buttons(view)
            .into_iter()
            .find(|(text, _)| text == label)
            .unwrap_or_else(|| panic!("no button '{label}' in {:?}", buttons(view)));
        bridge.handle(press(JOSH_TG, GROUP, id, &data), Utc::now())
    }

    /// The Engines menu shows the policy in force and who it blocks, and its buttons
    /// sign changes for josh - only under the improve delegation.
    #[test]
    fn the_engines_menu_shows_the_policy_and_its_buttons_act_for_josh() {
        let dir = tempfile::tempdir().unwrap();
        let (mut bridge, ferryman, _) = bridge(dir.path());
        three_engines(&ferryman);
        let view = bridge.handle(press(JOSH_TG, GROUP, 80, "engines"), Utc::now());
        let shown = texts(&view).join("\n");
        assert!(shown.contains("Engine policy for ferryman"), "{shown}");
        assert!(
            shown.contains("blocked claude on beastly: a subscription"),
            "{shown}"
        );
        assert!(
            shown.contains("build  nemotron on beastly > deepseek on beastly"),
            "{shown}"
        );

        // Not delegated: refused, nothing signed.
        let refused = press_labelled(&mut bridge, &view, "Block nemotron", 80);
        assert!(
            matches!(&refused[0], Action::Answer { text, .. } if text.contains("delegated")),
            "{refused:?}"
        );
        assert!(policy::setting(&ferryman.communications, "ferryman").is_none());

        delegate(&ferryman, &["improve"]);
        press_labelled(&mut bridge, &view, "Block nemotron", 80);
        let set = policy::setting(&ferryman.communications, "ferryman").unwrap();
        assert_eq!(set.set_by(), "josh via telegram-grouchly");
        assert_eq!(set.policy.as_ref().unwrap().never, ["name:nemotron"]);
        press_labelled(&mut bridge, &view, "Move deepseek to top", 80);
        let (now_in_force, _) = policy::effective(&ferryman.communications, "ferryman");
        assert_eq!(
            now_in_force.preferences(policy::Role::Build)[0],
            "name:deepseek"
        );
        let accepted = press_labelled(&mut bridge, &view, "Accept recommended", 80);
        assert!(
            matches!(&accepted[0], Action::Answer { text, .. } if text.starts_with("Recommended engine policy signed")),
            "{accepted:?}"
        );
        let (now_in_force, _) = policy::effective(&ferryman.communications, "ferryman");
        assert_eq!(
            now_in_force.preferences(policy::Role::Build),
            ["name:nemotron", "name:deepseek"]
        );
    }

    /// "Use team preset" shows what the preset would sign, with a reason per choice, and
    /// changes nothing until Accept - which needs the improve delegation like every other
    /// policy button.
    #[test]
    fn the_team_preset_is_shown_with_reasons_and_signed_only_on_accept() {
        let dir = tempfile::tempdir().unwrap();
        let (mut bridge, ferryman, _) = bridge(dir.path());
        three_engines(&ferryman);
        let view = bridge.handle(press(JOSH_TG, GROUP, 100, "engines"), Utc::now());
        let proposal = press_labelled(&mut bridge, &view, "Use team preset", 100);
        let shown = texts(&proposal).join("\n");
        assert!(shown.contains("Team preset for ferryman"), "{shown}");
        assert!(shown.contains("Why:"), "{shown}");
        assert!(shown.contains("build: effort medium, width 3"), "{shown}");
        assert!(shown.contains("up to 3 at once"), "{shown}");
        assert!(
            policy::setting(&ferryman.communications, "ferryman").is_none(),
            "looking signs nothing"
        );

        // Not delegated: refused, nothing signed.
        let refused = press_labelled(&mut bridge, &proposal, "Accept team preset", 100);
        assert!(
            matches!(&refused[0], Action::Answer { text, .. } if text.contains("delegated")),
            "{refused:?}"
        );
        assert!(policy::setting(&ferryman.communications, "ferryman").is_none());

        delegate(&ferryman, &["improve"]);
        let accepted = press_labelled(&mut bridge, &proposal, "Accept team preset", 100);
        assert!(
            matches!(&accepted[0], Action::Answer { text, .. } if text.starts_with("Team preset signed")),
            "{accepted:?}"
        );
        let (set, setting) = policy::effective(&ferryman.communications, "ferryman");
        assert_eq!(setting.unwrap().set_by(), "josh via telegram-grouchly");
        assert_eq!(set.width_for(policy::Role::Build), Some(3));
        assert_eq!(set.width_for(policy::Role::Chore), Some(4));
        assert_eq!(set.effort_for(policy::Role::Plan), policy::Effort::High);
        assert!(set.subscription_roles.is_empty(), "subscriptions stay out");
    }

    /// The preset is for engines, effort and width. Accepting it from the phone must not
    /// quietly drop what the master chose for security: `never`, caps, auto-merge and the
    /// adversary's mode.
    #[test]
    fn accepting_the_team_preset_from_the_phone_keeps_the_masters_security_settings() {
        let dir = tempfile::tempdir().unwrap();
        let (mut bridge, ferryman, _) = bridge(dir.path());
        three_engines(&ferryman);
        let mut mine = policy::Policy {
            never: vec!["name:claude".into()],
            caps_usd: std::collections::BTreeMap::from([("build".to_string(), 5.0)]),
            auto_merge: policy::AutoMerge::LowRisk,
            adversary: policy::AdversaryMode::Blocking,
            protect_subscriptions: true,
            ..policy::Policy::default()
        };
        mine.set_adversary_engine("name:deepseek");
        mine.adversary_agents = vec!["wisp".into()];
        policy::set_policy(
            &ferryman.communications,
            "ferryman",
            Some(mine.clone()),
            &josh(),
        )
        .unwrap();
        delegate(&ferryman, &["improve"]);
        let view = bridge.handle(press(JOSH_TG, GROUP, 100, "engines"), Utc::now());
        let proposal = press_labelled(&mut bridge, &view, "Use team preset", 100);
        let shown = texts(&proposal).join("\n");
        assert!(
            shown.contains("never: name:claude"),
            "the card shows what is signed: {shown}"
        );
        let accepted = press_labelled(&mut bridge, &proposal, "Accept team preset", 100);
        assert!(
            matches!(&accepted[0], Action::Answer { text, .. } if text.starts_with("Team preset signed")),
            "{accepted:?}"
        );
        let (set, setting) = policy::effective(&ferryman.communications, "ferryman");
        assert_eq!(setting.unwrap().set_by(), "josh via telegram-grouchly");
        assert_eq!(
            set.width_for(policy::Role::Build),
            Some(3),
            "the preset applied"
        );
        assert_eq!(set.never, mine.never);
        assert_eq!(set.caps_usd, mine.caps_usd);
        assert_eq!(set.auto_merge, policy::AutoMerge::LowRisk);
        assert_eq!(set.adversary, policy::AdversaryMode::Blocking);
        // The adversary's terms are the master's own signature: the phone's delegation does
        // not carry them, so the preset's adversary choice is not applied from here and the
        // file is still the master's.
        assert_eq!(set.adversary_engine(), Some("name:deepseek"));
        assert_eq!(set.adversary_agents, ["wisp"]);
        let adversary = policy::adversary_setting(&ferryman.communications, "ferryman").unwrap();
        assert_eq!(adversary.signed_by, "josh");
        assert_eq!(adversary.seq, 1, "never re-signed from the phone");
    }

    /// Held work's question arrives with buttons; "Accept recommended" answers it and
    /// signs the recommended policy for josh. Switching self-improve on with no policy
    /// offers the same.
    #[test]
    fn a_hold_question_accepted_from_the_phone_signs_the_recommended_policy() {
        let dir = tempfile::tempdir().unwrap();
        let (mut bridge, ferryman, _) = bridge(dir.path());
        delegate(&ferryman, &["improve"]);
        three_engines(&ferryman);
        let _ = bridge.tick(Utc::now());
        assert!(
            policy::ask_hold(
                &ferryman,
                &wisp(),
                policy::Role::Build,
                "2026-W40",
                "all blocked"
            )
            .unwrap()
        );
        let posted = bridge.tick(Utc::now());
        assert!(
            texts(&posted)
                .iter()
                .any(|t| t.starts_with("ferryman - engine policy")),
            "{posted:?}"
        );
        let answered = press_labelled(&mut bridge, &posted, policy::ACCEPT_RECOMMENDED, 81);
        assert!(
            texts(&answered)
                .iter()
                .any(|t| t.contains("The engine policy is changed")),
            "{answered:?}"
        );
        assert!(policy::is_set(&ferryman.communications, "ferryman"));

        // Onboarding: on, with no policy - the self-improve screen offers one.
        policy::set_policy(&ferryman.communications, "ferryman", None, &josh()).unwrap();
        bridge.handle(press(JOSH_TG, GROUP, 82, "imp:ferryman:on"), Utc::now());
        let view = bridge.handle(press(JOSH_TG, GROUP, 82, "improve"), Utc::now());
        assert!(
            texts(&view).join("\n").contains("no engine policy yet"),
            "{view:?}"
        );
        press_labelled(
            &mut bridge,
            &view,
            "Accept recommended engines for ferryman",
            82,
        );
        assert!(policy::is_set(&ferryman.communications, "ferryman"));
    }

    /// The two-button pick: improvement engine and review engine, signed for josh.
    #[test]
    fn the_improvement_and_review_engines_are_picked_with_two_buttons() {
        let dir = tempfile::tempdir().unwrap();
        let (mut bridge, ferryman, _) = bridge(dir.path());
        delegate(&ferryman, &["improve"]);
        three_engines(&ferryman);
        let view = bridge.handle(press(JOSH_TG, GROUP, 90, "engines"), Utc::now());
        let picker = press_labelled(&mut bridge, &view, "Improvement engine: auto", 90);
        let options = buttons(&picker);
        assert!(
            options
                .iter()
                .any(|(label, _)| label.starts_with("Recommended: nemotron")),
            "{options:?}"
        );
        assert!(
            options
                .iter()
                .any(|(label, _)| label.contains("claude") && label.ends_with("(blocked)")),
            "{options:?}"
        );
        let label = options
            .iter()
            .find(|(label, _)| label.starts_with("Recommended: nemotron"))
            .unwrap()
            .0
            .clone();
        press_labelled(&mut bridge, &picker, &label, 90);
        let view = bridge.handle(press(JOSH_TG, GROUP, 90, "engines"), Utc::now());
        let picker = press_labelled(&mut bridge, &view, "Review engine: auto", 90);
        let label = buttons(&picker)
            .into_iter()
            .find(|(label, _)| label.contains("deepseek"))
            .unwrap()
            .0;
        press_labelled(&mut bridge, &picker, &label, 90);
        let (chosen, setting) = policy::effective(&ferryman.communications, "ferryman");
        assert_eq!(chosen.improvement_engine(), Some("name:nemotron"));
        assert_eq!(chosen.review_engine(), Some("name:deepseek"));
        assert_eq!(setting.unwrap().set_by(), "josh via telegram-grouchly");
        assert_eq!(
            chosen.auto_merge,
            policy::AutoMerge::None,
            "off unless asked"
        );

        // The auto-merge toggle, one button.
        let view = bridge.handle(press(JOSH_TG, GROUP, 90, "engines"), Utc::now());
        press_labelled(
            &mut bridge,
            &view,
            "Auto-merge docs/tests/deps after both approvals",
            90,
        );
        let (chosen, _) = policy::effective(&ferryman.communications, "ferryman");
        assert_eq!(chosen.auto_merge, policy::AutoMerge::LowRisk);
        assert_eq!(
            chosen.review_engine(),
            Some("name:deepseek"),
            "the rest is kept"
        );
        let view = bridge.handle(press(JOSH_TG, GROUP, 90, "engines"), Utc::now());
        press_labelled(
            &mut bridge,
            &view,
            "Auto-merge docs/tests/deps: on - turn off",
            90,
        );
        let (chosen, _) = policy::effective(&ferryman.communications, "ferryman");
        assert_eq!(chosen.auto_merge, policy::AutoMerge::None);
    }

    /// An improvement reaches the phone only after the review engine's key, and the
    /// Approve button there is the master's key; before it, approval is refused.
    #[test]
    fn an_improvement_is_approved_from_the_phone_only_after_the_review_engine() {
        let dir = tempfile::tempdir().unwrap();
        let (mut bridge, ferryman, _) = bridge(dir.path());
        delegate(&ferryman, &["review"]);
        let _ = bridge.tick(Utc::now());
        let mut order = ferryman_channel::Order {
            id: "improve-2026-w40-1".into(),
            project_id: "ferryman".into(),
            issued_by: "wisp".into(),
            assigned_to: None,
            created_at: Utc::now(),
            payload: json!({ "task": "better", "tags": ["improvement"], "improvement": { "title": "Better errors" } }),
            requires_review: true,
            requires_approval: false,
            depends_on: Vec::new(),
            signed_by: None,
            signature: None,
            result_contract: None,
            interface: None,
            touches: Vec::new(),
            needs: None,
            allow_overlap: false,
        };
        wisp().sign_order(&mut order);
        ferryman_channel::issue_order(&ferryman, &order).unwrap();
        ferryman_channel::claim_order(&ferryman, &order.id, "wisp").unwrap();
        let mut result = ferryman_channel::TaskResult {
            order_id: order.id.clone(),
            agent: "wisp".into(),
            revision: 1,
            submitted_at: Utc::now(),
            payload: json!({ "output": "done", "evidence": { "recorded_by": "worker", "git": true, "commits": ["abc1234 better"], "diff_stat": "2 files changed" } }),
            signed_by: None,
            signature: None,
        };
        wisp().sign_result(&mut result);
        ferryman_channel::submit_result(&ferryman, &result).unwrap();
        assert!(
            bridge.tick(Utc::now()).is_empty(),
            "nothing for the person before the review engine"
        );
        let early = bridge.handle(
            press(JOSH_TG, GROUP, 91, &format!("ok:ferryman:{}", order.id)),
            Utc::now(),
        );
        assert!(
            texts(&early)
                .iter()
                .any(|t| t.contains("review engine has not reviewed it")),
            "{early:?}"
        );
        ferryman_channel::gate::record_engine_review(
            &ferryman,
            &wisp(),
            ferryman_channel::gate::EngineReview {
                order_id: order.id.clone(),
                revision: 1,
                reviewer: "wisp".into(),
                machine: "grouchly".into(),
                engine: "deepseek".into(),
                model: None,
                tier: "judge".into(),
                paid: "prepaid".into(),
                host: None,
                route: Vec::new(),
                accept: true,
                summary: "clear and tested".into(),
                reviewed_at: Utc::now(),
                signed_by: None,
                signature: None,
            },
        )
        .unwrap();
        let posted = bridge.tick(Utc::now());
        let said = texts(&posted).join("\n");
        assert!(said.contains("waiting for your approval"), "{said}");
        assert!(said.contains("Diff: 2 files changed") && said.contains("clear and tested"));
        press_labelled(&mut bridge, &posted, "Approve", 92);
        let task = ferryman_channel::read_task(&ferryman, &order.id).unwrap();
        assert!(ferryman_channel::gate::approved_for_live(&ferryman, &task));
    }

    #[test]
    fn long_button_data_is_kept_short_and_resolves_back() {
        let dir = tempfile::tempdir().unwrap();
        let (mut bridge, _, _) = bridge(dir.path());
        let long = format!("ans:ferryman:{}:0", "x".repeat(80));
        let short = bridge.data(long.clone());
        assert!(short.len() <= 64);
        assert_eq!(bridge.resolve(&short), long);
        assert_eq!(bridge.data("menu".into()), "menu");
    }

    #[test]
    fn approvers_parse_from_a_list() {
        assert_eq!(parse_ids(" 42, 7 ,").unwrap(), vec![42, 7]);
        assert!(parse_ids("josh").is_err());
    }

    // --- the adversary on the phone -----------------------------------------------------------

    fn adversary_finding(
        subject: &str,
        revision: u32,
        trigger: ferryman_channel::adversary::Trigger,
        verdict: ferryman_channel::adversary::Verdict,
    ) -> ferryman_channel::adversary::AdversaryFinding {
        use ferryman_channel::adversary::{AdversaryFinding, Issue, Severity};
        AdversaryFinding {
            order_id: subject.split('@').next().unwrap_or_default().to_string(),
            revision,
            trigger,
            subject: subject.to_string(),
            engine: "deepseek".into(),
            model: None,
            machine: "grouchly".into(),
            same_engine: false,
            verdict,
            findings: vec![Issue {
                severity: Severity::High,
                title: "the consumer reads `name`, the provider sends `username`".into(),
                detail: "the two halves disagree".into(),
                location: Some("user.name".into()),
            }],
            created_at: Utc::now(),
            result_digest: String::new(),
            signed_by: String::new(),
            signature: String::new(),
        }
    }

    fn set_adversary(route: &ProjectRoute, mode: ferryman_channel::policy::AdversaryMode) {
        ferryman_channel::policy::set_policy(
            &route.communications,
            &route.project_id,
            Some(Policy {
                adversary: mode,
                ..Policy::default()
            }),
            &josh(),
        )
        .unwrap();
    }

    fn proposed_user_api(route: &ProjectRoute) {
        let shape = ferryman_channel::contract::Shape::parse(&json!({
            "type": "object",
            "required": ["id"],
            "properties": { "id": { "type": "integer" } }
        }))
        .unwrap();
        ferryman_channel::interface::propose(route, &wisp(), "user-api", "1", "users", None, shape)
            .unwrap();
    }

    #[test]
    fn a_contract_finding_comes_beside_lock_and_reject_with_an_override_only_for_a_block() {
        use ferryman_channel::adversary::{self as found, Trigger, Verdict};
        use ferryman_channel::interface;
        let dir = tempfile::tempdir().unwrap();
        let (mut bridge, ferryman, _) = bridge(dir.path());
        delegate(&ferryman, &["improve"]);
        let _ = bridge.tick(Utc::now());
        proposed_user_api(&ferryman);
        let first = bridge.tick(Utc::now());
        assert_eq!(texts(&first).len(), 1, "the contract's own card: {first:?}");

        // A Concern: the finding is shown with Lock and Reject, and nothing to override.
        scout_says(
            &ferryman,
            adversary_finding("user-api@1", 0, Trigger::ContractLock, Verdict::Concern),
        );
        let concern = bridge.tick(Utc::now());
        let shown = texts(&concern).join("\n");
        assert!(
            shown.contains("the adversary read contract user-api@1"),
            "{shown}"
        );
        assert!(shown.contains("concern by deepseek"), "{shown}");
        assert!(shown.contains("the consumer reads `name`"), "{shown}");
        let labels: Vec<String> = buttons(&concern)
            .into_iter()
            .map(|(label, _)| label)
            .collect();
        assert_eq!(labels, ["Lock", "Reject"]);
        assert!(
            bridge.tick(Utc::now()).is_empty(),
            "each finding is posted once"
        );

        // A Block: an Override beside them, and only then.
        // (A second adversary: one signer says one thing per moment, and a contract nobody has
        // built yet has only its shapes, revision 0.)
        ranger_says(
            &ferryman,
            adversary_finding("user-api@1", 0, Trigger::ContractLock, Verdict::Block),
        );
        let block = bridge.tick(Utc::now());
        let labels: Vec<String> = buttons(&block)
            .into_iter()
            .map(|(label, _)| label)
            .collect();
        assert_eq!(labels, ["Lock", "Reject", "Override the Block and lock"]);
        assert!(texts(&block).join("\n").contains("block by deepseek"));

        // Blocking mode: Lock is refused with the reason; the override locks, signed for josh.
        set_adversary(&ferryman, ferryman_channel::policy::AdversaryMode::Blocking);
        let refused = press_labelled(&mut bridge, &block, "Lock", 120);
        assert!(
            refused.iter().any(|action| matches!(action,
                Action::Answer { text, .. } if text.contains("blocks locking user-api@1"))),
            "{refused:?}"
        );
        assert!(interface::locked(&ferryman, "user-api", "1").is_none());
        let overridden = press_labelled(&mut bridge, &block, "Override the Block and lock", 121);
        assert!(
            texts(&overridden)
                .iter()
                .any(|t| t
                    .contains("locked by josh via telegram-grouchly, over the adversary's Block")),
            "{overridden:?}"
        );
        let locked = interface::locked(&ferryman, "user-api", "1").expect("locked");
        assert_eq!(locked.lock.unwrap().signed_by, "telegram-grouchly");
        let standing = found::standing(&ferryman, "user-api@1", 0, Trigger::ContractLock).unwrap();
        assert_eq!(
            standing.overridden.unwrap().from(),
            "josh via telegram-grouchly"
        );
    }

    #[test]
    fn a_contract_override_needs_the_improve_delegation_and_off_shows_nothing() {
        use ferryman_channel::adversary::{self as found, Trigger, Verdict};
        use ferryman_channel::interface;
        let dir = tempfile::tempdir().unwrap();
        let (mut bridge, ferryman, _) = bridge(dir.path());
        delegate(&ferryman, &["review"]);
        let _ = bridge.tick(Utc::now());
        proposed_user_api(&ferryman);
        let _ = bridge.tick(Utc::now());
        scout_says(
            &ferryman,
            adversary_finding("user-api@1", 0, Trigger::ContractLock, Verdict::Block),
        );
        set_adversary(&ferryman, ferryman_channel::policy::AdversaryMode::Blocking);
        let block = bridge.tick(Utc::now());
        let refused = press_labelled(&mut bridge, &block, "Override the Block and lock", 122);
        assert!(
            refused
                .iter()
                .any(|action| matches!(action, Action::Answer { text, .. } if !text.is_empty())),
            "{refused:?}"
        );
        assert!(interface::locked(&ferryman, "user-api", "1").is_none());
        assert!(
            found::standing(&ferryman, "user-api@1", 0, Trigger::ContractLock)
                .unwrap()
                .unresolved_block()
        );

        // With the adversary off, a finding on file is not put on the phone.
        let dir = tempfile::tempdir().unwrap();
        let (mut bridge, ferryman, _) = self::bridge(dir.path());
        set_adversary(&ferryman, ferryman_channel::policy::AdversaryMode::Off);
        let _ = bridge.tick(Utc::now());
        proposed_user_api(&ferryman);
        let _ = bridge.tick(Utc::now());
        scout_says(
            &ferryman,
            adversary_finding("user-api@1", 0, Trigger::ContractLock, Verdict::Block),
        );
        assert!(bridge.tick(Utc::now()).is_empty());
    }

    /// The text of every toast and message in `actions`, in one string.
    fn said(actions: &[Action]) -> String {
        actions
            .iter()
            .map(|action| match action {
                Action::Send { text, .. }
                | Action::Edit { text, .. }
                | Action::Answer { text, .. } => text.clone(),
            })
            .collect::<Vec<_>>()
            .join("\n")
    }

    /// A lock button decides on the contract its card showed: a button whose digest is not
    /// the contract's (the proposal was replaced after the card was posted), or that names
    /// none, locks nothing - and the one that names it does.
    #[test]
    fn a_lock_button_names_the_contract_it_was_shown_and_goes_stale_when_it_changes() {
        use ferryman_channel::interface;
        let dir = tempfile::tempdir().unwrap();
        let (mut bridge, ferryman, _) = bridge(dir.path());
        delegate(&ferryman, &["improve"]);
        let _ = bridge.tick(Utc::now());
        proposed_user_api(&ferryman);
        let digest = interface::current_digest(&ferryman, "user-api", "1").unwrap();

        for data in [
            "clk:ferryman:user-api@1:0000000000000000".to_string(),
            "clk:ferryman:user-api@1:".to_string(),
            format!("clk:ferryman:user-api@1:{}", &digest[..4]),
        ] {
            let refused = bridge.handle(press(JOSH_TG, GROUP, 150, &data), Utc::now());
            assert!(
                said(&refused).contains("changed since you looked"),
                "{data}: {refused:?}"
            );
            assert!(
                interface::locked(&ferryman, "user-api", "1").is_none(),
                "{data}"
            );
        }
        let locked = bridge.handle(
            press(
                JOSH_TG,
                GROUP,
                151,
                &format!("clk:ferryman:user-api@1:{}", &digest[..16]),
            ),
            Utc::now(),
        );
        assert!(
            said(&locked).contains("user-api@1 locked by josh"),
            "{locked:?}"
        );
        assert!(interface::locked(&ferryman, "user-api", "1").is_some());
    }

    /// An override button names the adversary's word as its card showed it: when another
    /// adversary speaks after the card went out, pressing it overrides and locks nothing,
    /// and the card posted for the new word works.
    #[test]
    fn an_override_button_goes_stale_when_another_adversary_speaks_after_its_card() {
        use ferryman_channel::adversary::{self as found, Trigger, Verdict};
        use ferryman_channel::interface;
        let dir = tempfile::tempdir().unwrap();
        let (mut bridge, ferryman, _) = bridge(dir.path());
        delegate(&ferryman, &["improve"]);
        set_adversary(&ferryman, ferryman_channel::policy::AdversaryMode::Blocking);
        let _ = bridge.tick(Utc::now());
        proposed_user_api(&ferryman);
        let _ = bridge.tick(Utc::now());
        scout_says(
            &ferryman,
            adversary_finding("user-api@1", 0, Trigger::ContractLock, Verdict::Block),
        );
        let card = bridge.tick(Utc::now());
        ranger_says(
            &ferryman,
            adversary_finding("user-api@1", 0, Trigger::ContractLock, Verdict::Block),
        );
        let stale = press_labelled(&mut bridge, &card, "Override the Block and lock", 160);
        assert!(
            said(&stale).contains("changed since you looked"),
            "{stale:?}"
        );
        assert!(interface::locked(&ferryman, "user-api", "1").is_none());
        assert!(
            found::standing(&ferryman, "user-api@1", 0, Trigger::ContractLock)
                .unwrap()
                .unresolved_block(),
            "a refused override overrides nothing"
        );

        let fresh = bridge.tick(Utc::now());
        assert!(!fresh.is_empty(), "the new word gets its own card");
        press_labelled(&mut bridge, &fresh, "Override the Block and lock", 161);
        assert!(interface::locked(&ferryman, "user-api", "1").is_some());
    }

    /// The phone's Approve is held to the order's contract like every other way to accept:
    /// a result that lacks what the order requires is refused with the reason, and the
    /// revision that carries it is approved.
    #[test]
    fn approving_from_the_phone_a_result_that_breaks_the_orders_contract_is_refused() {
        let dir = tempfile::tempdir().unwrap();
        let (mut bridge, ferryman, _) = bridge(dir.path());
        delegate(&ferryman, &["review"]);
        let _ = bridge.tick(Utc::now());
        let mut order = ferryman_channel::Order {
            id: "t-ctr".into(),
            project_id: "ferryman".into(),
            issued_by: "wisp".into(),
            assigned_to: None,
            created_at: Utc::now(),
            payload: json!({ "task": "write the summary" }),
            requires_review: true,
            requires_approval: false,
            depends_on: Vec::new(),
            signed_by: None,
            signature: None,
            result_contract: Some(ferryman_channel::contract::ResultContract {
                required: vec!["summary".into()],
                schema: None,
            }),
            interface: None,
            touches: Vec::new(),
            needs: None,
            allow_overlap: false,
        };
        wisp().sign_order(&mut order);
        ferryman_channel::issue_order(&ferryman, &order).unwrap();
        ferryman_channel::claim_order(&ferryman, "t-ctr", "wisp").unwrap();
        let submit = |revision: u32, payload: Value| {
            let mut result = ferryman_channel::TaskResult {
                order_id: "t-ctr".into(),
                agent: "wisp".into(),
                revision,
                submitted_at: Utc::now(),
                payload,
                signed_by: None,
                signature: None,
            };
            wisp().sign_result(&mut result);
            ferryman_channel::submit_result(&ferryman, &result).unwrap();
        };
        submit(1, json!({ "output": "done" }));
        let refused = bridge.handle(press(JOSH_TG, GROUP, 170, "ok:ferryman:t-ctr"), Utc::now());
        let shown = said(&refused);
        assert!(shown.contains("Could not approve t-ctr"), "{shown}");
        assert!(shown.contains("breaks the order's contract"), "{shown}");
        assert!(
            ferryman_channel::read_task(&ferryman, "t-ctr")
                .unwrap()
                .reviews
                .is_empty(),
            "nothing was recorded"
        );

        submit(2, json!({ "output": "done", "summary": "wrote it" }));
        let approved = bridge.handle(press(JOSH_TG, GROUP, 171, "ok:ferryman:t-ctr"), Utc::now());
        assert!(
            said(&approved).contains("t-ctr r2 approved"),
            "{approved:?}"
        );
    }

    /// An improvement the worker finished, waiting for the review engine.
    fn finished_improvement(route: &ProjectRoute, id: &str) {
        let mut order = ferryman_channel::Order {
            id: id.into(),
            project_id: "ferryman".into(),
            issued_by: "wisp".into(),
            assigned_to: None,
            created_at: Utc::now(),
            payload: json!({ "task": "better", "tags": ["improvement"], "improvement": { "title": "Better errors" } }),
            requires_review: true,
            requires_approval: false,
            depends_on: Vec::new(),
            signed_by: None,
            signature: None,
            result_contract: None,
            interface: None,
            touches: Vec::new(),
            needs: None,
            allow_overlap: false,
        };
        wisp().sign_order(&mut order);
        ferryman_channel::issue_order(route, &order).unwrap();
        ferryman_channel::claim_order(route, id, "wisp").unwrap();
        let mut result = ferryman_channel::TaskResult {
            order_id: id.into(),
            agent: "wisp".into(),
            revision: 1,
            submitted_at: Utc::now(),
            payload: json!({ "output": "done", "evidence": { "recorded_by": "worker", "git": true, "commits": ["abc1234 better"], "diff_stat": "2 files changed" } }),
            signed_by: None,
            signature: None,
        };
        wisp().sign_result(&mut result);
        ferryman_channel::submit_result(route, &result).unwrap();
    }

    fn engine_key(route: &ProjectRoute, id: &str) {
        ferryman_channel::gate::record_engine_review(
            route,
            &wisp(),
            ferryman_channel::gate::EngineReview {
                order_id: id.into(),
                revision: 1,
                reviewer: "wisp".into(),
                machine: "grouchly".into(),
                engine: "deepseek".into(),
                model: None,
                tier: "judge".into(),
                paid: "prepaid".into(),
                host: None,
                route: Vec::new(),
                accept: true,
                summary: "clear and tested".into(),
                reviewed_at: Utc::now(),
                signed_by: None,
                signature: None,
            },
        )
        .unwrap();
    }

    #[test]
    fn the_review_card_shows_the_adversary_beside_the_two_keys_and_a_block_can_be_overridden() {
        use ferryman_channel::adversary::{self as found, Trigger, Verdict};
        let dir = tempfile::tempdir().unwrap();
        let (mut bridge, ferryman, _) = bridge(dir.path());
        delegate(&ferryman, &["review"]);
        let _ = bridge.tick(Utc::now());
        finished_improvement(&ferryman, "improve-2026-w40-1");
        scout_says(
            &ferryman,
            adversary_finding("improve-2026-w40-1", 1, Trigger::PreDone, Verdict::Block),
        );
        engine_key(&ferryman, "improve-2026-w40-1");

        // Advisory: both keys are there, so the card is too - with the finding and an
        // Override, and Approve still works.
        let posted = bridge.tick(Utc::now());
        let said = texts(&posted).join("\n");
        assert!(said.contains("waiting for your approval"), "{said}");
        assert!(
            said.contains("clear and tested"),
            "the engine's key: {said}"
        );
        assert!(said.contains("adversary BLOCK"), "{said}");
        assert!(said.contains("the consumer reads `name`"), "{said}");
        let labels: Vec<String> = buttons(&posted)
            .into_iter()
            .map(|(label, _)| label)
            .collect();
        assert_eq!(
            labels,
            ["Approve", "Send back", "Details", "Override the Block"]
        );
        let overridden = press_labelled(&mut bridge, &posted, "Override the Block", 123);
        assert!(
            texts(&overridden)
                .iter()
                .any(|t| t.contains("answered, signed by josh via telegram-grouchly")),
            "{overridden:?}"
        );
        assert!(
            !found::standing(&ferryman, "improve-2026-w40-1", 1, Trigger::PreDone)
                .unwrap()
                .unresolved_block()
        );
    }

    #[test]
    fn in_blocking_mode_a_standing_block_has_its_own_card_because_no_review_card_can_come() {
        use ferryman_channel::adversary::{self as found, Trigger, Verdict};
        let dir = tempfile::tempdir().unwrap();
        let (mut bridge, ferryman, _) = bridge(dir.path());
        delegate(&ferryman, &["improve"]);
        set_adversary(&ferryman, ferryman_channel::policy::AdversaryMode::Blocking);
        let _ = bridge.tick(Utc::now());
        finished_improvement(&ferryman, "improve-2026-w40-2");
        scout_says(
            &ferryman,
            adversary_finding("improve-2026-w40-2", 1, Trigger::PreDone, Verdict::Block),
        );
        engine_key(&ferryman, "improve-2026-w40-2");
        let task = ferryman_channel::read_task(&ferryman, "improve-2026-w40-2").unwrap();
        assert!(
            ferryman_channel::gate::gate(
                &ferryman,
                &task,
                &policy::effective(&ferryman.communications, "ferryman").0
            )
            .engine
            .as_ref()
            .is_err_and(|why| why.contains("adversary")),
            "blocking: the engine's key does not count while the Block stands"
        );
        let posted = bridge.tick(Utc::now());
        let said = texts(&posted).join("\n");
        assert!(
            said.contains("the adversary blocked improve-2026-w40-2 r1"),
            "{said}"
        );
        assert!(!said.contains("waiting for your approval"), "{said}");
        let labels: Vec<String> = buttons(&posted)
            .into_iter()
            .map(|(label, _)| label)
            .collect();
        assert_eq!(labels, ["Override the Block"]);

        // `improve` is not the scope that approves a result: refused, still standing.
        let refused = press_labelled(&mut bridge, &posted, "Override the Block", 124);
        assert!(
            refused
                .iter()
                .any(|action| matches!(action, Action::Answer { text, .. } if !text.is_empty() && text != "Done")),
            "{refused:?}"
        );
        assert!(
            found::standing(&ferryman, "improve-2026-w40-2", 1, Trigger::PreDone)
                .unwrap()
                .unresolved_block()
        );
        delegate(&ferryman, &["improve", "review"]);
        press_labelled(&mut bridge, &posted, "Override the Block", 125);
        assert!(
            !found::standing(&ferryman, "improve-2026-w40-2", 1, Trigger::PreDone)
                .unwrap()
                .unresolved_block()
        );
        // And with the Block answered, the review card comes.
        let after = bridge.tick(Utc::now());
        assert!(
            texts(&after)
                .join("\n")
                .contains("waiting for your approval"),
            "{after:?}"
        );
    }
}
