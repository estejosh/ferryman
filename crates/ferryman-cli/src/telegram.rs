//! Issue work from a phone.
//!
//! Everything Ferryman does is already reachable from a terminal, which is exactly where
//! an operator is not when the fleet has a question. This is a long-poll bridge between one
//! Telegram chat and one project's channel: a message becomes a signed order, and a result
//! comes back to the same chat when a worker submits it.
//!
//! It is deliberately *not* a second control plane. It writes the same signed artifacts
//! `ferry channel order` writes, into the same folder, and reads state the same way every
//! other reader does - so a bridge that dies loses nothing but its own notifications, and a
//! fleet that never sees one behaves identically.
//!
//! # Not a path for secrets
//!
//! Orders, yes. Credentials, never. A Telegram cloud chat is not end-to-end encrypted: a
//! token typed into one is stored on Telegram's servers and syncs to every device signed
//! into that account, and it stays in that history long after whoever sent it has forgotten.
//! Losing an order to a leak costs nothing - it was going into a shared folder anyway.
//! Losing a repository token costs the repository.
//!
//! So the bridge carries instructions and results, and secrets travel by a path that is
//! encrypted to a specific recipient. This is a rule about what to send, not something the
//! code can enforce - it cannot tell a task from a token - which is exactly why it is
//! written down here and in the README rather than left to be worked out later.
//!
//! # Authorization
//!
//! One numeric Telegram user id may command it, and the bridge refuses to start without one.
//! Telegram authenticates `from.id` server-side, so it is the one field in an update that a
//! stranger cannot forge - but it is only meaningful if something checks it, and a bridge
//! that starts with the check unset would take orders from whoever finds the bot.

use anyhow::{Context, Result, bail};
use serde::Deserialize;
use serde_json::{Value, json};
use std::path::{Path, PathBuf};
use std::time::Duration;

/// How long Telegram holds a `getUpdates` request open with nothing to say. Long-polling
/// rather than a timer: a message arrives in the second it was sent, and an idle bridge
/// costs one open connection instead of a request every few seconds.
const LONG_POLL_SECS: u64 = 25;

/// Telegram rejects anything over 4096 characters, and a wall of engine output is not what
/// a phone is for. The whole result is in the channel either way.
const EXCERPT_CHARS: usize = 600;

/// How many announced results to remember. Enough that a restart does not repeat itself,
/// bounded so the state file cannot grow without limit on a long-lived fleet.
const SEEN_LIMIT: usize = 500;

/// What a chat message asked for.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Instruction {
    Help,
    Agents,
    Status,
    /// Put work into the channel. `to` addresses one machine; `None` is open to anyone.
    Order {
        to: Option<String>,
        task: String,
    },
}

/// Read one chat message as an instruction.
///
/// Bare text is an open order, because that is what an operator reaching for their phone
/// almost always means, and making them remember a verb to do the common thing is how a
/// tool stops getting used.
#[must_use]
pub fn parse_instruction(text: &str) -> Option<Instruction> {
    let text = text.trim();
    if text.is_empty() {
        return None;
    }
    // `/help@ferrymanbot` is what Telegram sends in a group; the suffix is addressing, not
    // part of the command.
    let (head, rest) = text.split_once(char::is_whitespace).unwrap_or((text, ""));
    let command = head.split('@').next().unwrap_or(head).to_ascii_lowercase();
    let rest = rest.trim();
    match command.as_str() {
        "/help" | "/start" => Some(Instruction::Help),
        "/agents" | "/roster" => Some(Instruction::Agents),
        "/status" | "/tasks" => Some(Instruction::Status),
        "/order" => (!rest.is_empty()).then(|| Instruction::Order {
            to: None,
            task: rest.to_string(),
        }),
        "/to" => {
            let (who, task) = rest.split_once(char::is_whitespace)?;
            let who = ferryman_channel::canonical_agent_name(who);
            let task = task.trim();
            (!who.is_empty() && !task.is_empty()).then_some(Instruction::Order {
                to: Some(who),
                task: task.to_string(),
            })
        }
        // An unrecognised slash command is a typo, not a task. Turning `/stauts` into an
        // order for the fleet to carry out is the kind of helpfulness nobody wants.
        _ if command.starts_with('/') => None,
        _ => Some(Instruction::Order {
            to: None,
            task: text.to_string(),
        }),
    }
}

/// The identity of one submitted result, for "have I already said this".
#[must_use]
pub fn result_key(order_id: &str, agent: &str, revision: u32) -> String {
    format!("{order_id}:{agent}:{revision}")
}

/// Cut a string to `limit` characters on a character boundary, marking that it was cut.
#[must_use]
pub fn excerpt(text: &str, limit: usize) -> String {
    let text = text.trim();
    if text.chars().count() <= limit {
        return text.to_string();
    }
    let kept: String = text.chars().take(limit).collect();
    format!("{kept}...")
}

/// What the bridge remembers between restarts: which updates it has consumed, and which
/// results it has already reported.
#[derive(Debug, Default, serde::Serialize, Deserialize)]
struct BridgeState {
    /// Telegram's own cursor. Acknowledging by offset is what stops a restart replaying
    /// the last 24 hours of messages as fresh orders.
    #[serde(default)]
    offset: i64,
    #[serde(default)]
    seen: Vec<String>,
}

impl BridgeState {
    fn remember(&mut self, key: String) {
        self.seen.push(key);
        if self.seen.len() > SEEN_LIMIT {
            let excess = self.seen.len() - SEEN_LIMIT;
            self.seen.drain(..excess);
        }
    }

    fn knows(&self, key: &str) -> bool {
        self.seen.iter().any(|seen| seen == key)
    }
}

/// Where this bridge's state lives: beside the key store in the attachment, which is local
/// to this machine - the synced folder is the `communications` directory inside it. A cursor
/// that synced would be a cursor two machines fought over. Named after the signing agent so
/// that even two bridges on one machine keep their own.
fn state_path(attachment: &Path, agent: &str) -> PathBuf {
    attachment.join(format!("telegram-{agent}.json"))
}

/// One project the bridge serves, and the topic it serves it in.
///
/// A bridge used to be one chat and one project. A fleet is not shaped like that: an
/// operator runs several projects and wants one place to talk to all of them, with the
/// answers kept apart. A forum group gives that shape - a topic per project - and a desk is
/// one seat at it: the topic on the Telegram side, the channel on the Ferryman side, and
/// the identity orders raised here are signed with.
struct Desk {
    /// The topic's name, for what the bridge says about itself.
    name: String,
    /// Where this desk answers on its own initiative. The topic id is `None` for a private
    /// chat and for a group's General, both of which take a plain message.
    chat_id: i64,
    thread: Option<i64>,
    route: ferryman_channel::ProjectRoute,
    issuer: String,
    default_to: Option<String>,
    state: BridgeState,
    state_path: PathBuf,
}

/// Telegram's cursor, kept beside the map rather than in a channel.
///
/// `getUpdates` is per bot token, not per project, so one bridge has exactly one cursor no
/// matter how many desks it keeps. Putting it in any one project's attachment would make
/// that project's folder quietly load-bearing for all the others.
#[derive(Debug, Default, serde::Serialize, Deserialize)]
struct Cursor {
    #[serde(default)]
    offset: i64,
}

fn cursor_path(dir: &Path) -> PathBuf {
    dir.join(".tgferryman-cursor.json")
}

#[derive(Debug, Deserialize)]
struct TgResponse<T> {
    ok: bool,
    #[serde(default)]
    result: Option<T>,
    #[serde(default)]
    description: Option<String>,
}

#[derive(Debug, Deserialize)]
struct TgUpdate {
    update_id: i64,
    #[serde(default)]
    message: Option<TgMessage>,
}

#[derive(Debug, Deserialize)]
struct TgMessage {
    #[serde(default)]
    message_id: i64,
    #[serde(default)]
    from: Option<TgUser>,
    #[serde(default)]
    text: Option<String>,
    /// Which chat it arrived in. A bridge that only knows its configured chat answers a
    /// group in a private message, which is how you end up talking past someone.
    #[serde(default)]
    chat: Option<TgChat>,
    /// The forum topic, in a group that has them. Absent in a private chat and in a
    /// group's General topic. A reply without it lands in General rather than in the
    /// conversation it belongs to.
    #[serde(default)]
    message_thread_id: Option<i64>,
}

#[derive(Debug, Deserialize)]
struct TgChat {
    id: i64,
}

#[derive(Debug, Deserialize)]
struct TgUser {
    id: i64,
}

/// The bot's side of one chat.
struct Chat {
    http: reqwest::Client,
    token: String,
    chat_id: i64,
}

impl Chat {
    /// Send to the configured chat. For anything the bridge says on its own initiative -
    /// the greeting, a result arriving - because there is no incoming message to answer.
    async fn send(&self, text: &str) -> Result<()> {
        self.send_to(self.chat_id, None, text).await
    }

    /// Answer where the question was asked.
    ///
    /// The bridge used to reply only to the chat it was configured with, so a message sent
    /// in a group was answered in a private chat, and the group looked like it was being
    /// ignored. `message_thread_id` carries the same rule one level down: in a group with
    /// forum topics, omitting it drops the reply into General instead of the topic the
    /// conversation is in.
    async fn send_to(&self, chat_id: i64, thread: Option<i64>, text: &str) -> Result<()> {
        let mut body = json!({ "chat_id": chat_id, "text": excerpt(text, 3900) });
        if let Some(thread) = thread {
            body["message_thread_id"] = json!(thread);
        }
        let response = self
            .http
            .post(format!(
                "https://api.telegram.org/bot{}/sendMessage",
                self.token
            ))
            .json(&body)
            .send()
            .await
            .context("send a Telegram message")?;
        if !response.status().is_success() {
            // The body of a Telegram error carries the reason ("chat not found"), and the
            // status alone sends an operator hunting. The token is in the URL, never here.
            let status = response.status();
            let body = response.text().await.unwrap_or_default();
            bail!(
                "telegram sendMessage returned {status}: {}",
                excerpt(&body, 200)
            );
        }
        Ok(())
    }

    /// Make a topic, and take the only copy of its id.
    ///
    /// `createForumTopic` is the whole of Telegram's topic API that matters here: there is
    /// no call that lists topics, so the `message_thread_id` this returns is not
    /// recoverable from Telegram afterwards. It goes straight into `.tgferryman`, and if
    /// that write is lost the topic is still there in the group and Ferryman can never
    /// speak into it again.
    ///
    /// Needs the bot to be an administrator of the group with "Manage topics".
    async fn create_forum_topic(&self, chat_id: i64, name: &str) -> Result<i64> {
        #[derive(Default, Deserialize)]
        struct ForumTopic {
            message_thread_id: i64,
        }
        let response: TgResponse<ForumTopic> = self
            .http
            .post(format!(
                "https://api.telegram.org/bot{}/createForumTopic",
                self.token
            ))
            .json(&json!({ "chat_id": chat_id, "name": name }))
            .send()
            .await
            .context("ask Telegram to create a forum topic")?
            .json()
            .await
            .context("parse Telegram's reply to createForumTopic")?;
        match (response.ok, response.result) {
            (true, Some(topic)) => Ok(topic.message_thread_id),
            _ => bail!(
                "telegram refused to create the topic '{name}': {}. The bot must be an \
                 administrator of the group with the \"Manage topics\" right, and the group \
                 must have topics turned on",
                response
                    .description
                    .unwrap_or_else(|| "no reason given".to_string())
            ),
        }
    }

    async fn updates(&self, offset: i64) -> Result<Vec<TgUpdate>> {
        let response: TgResponse<Vec<TgUpdate>> = self
            .http
            .get(format!(
                "https://api.telegram.org/bot{}/getUpdates",
                self.token
            ))
            .query(&[
                ("offset", offset.to_string()),
                ("timeout", LONG_POLL_SECS.to_string()),
                ("allowed_updates", "[\"message\"]".to_string()),
            ])
            .timeout(Duration::from_secs(LONG_POLL_SECS + 15))
            .send()
            .await
            .context("poll Telegram for updates")?
            .json()
            .await
            .context("parse Telegram's reply to getUpdates")?;
        if !response.ok {
            bail!(
                "telegram getUpdates refused: {}",
                response
                    .description
                    .unwrap_or_else(|| "no reason given".to_string())
            );
        }
        Ok(response.result.unwrap_or_default())
    }
}

/// Read the bot token. The token is a password for the bot: it stays in the environment,
/// never in a config file the channel syncs and never on a command line `ps` can read.
fn bot_token() -> Result<String> {
    match std::env::var("TELEGRAM_BOT_TOKEN") {
        Ok(token) if !token.trim().is_empty() => Ok(token),
        _ => bail!(
            "TELEGRAM_BOT_TOKEN is not set. Create a bot with @BotFather, then put the token \
             in this process's environment - a systemd EnvironmentFile with mode 600, or your \
             shell's own secrets file. Not in the channel: it syncs."
        ),
    }
}

/// Read the one user id allowed to command the fleet.
fn approver_id() -> Result<i64> {
    let raw = std::env::var("TELEGRAM_APPROVER_ID").unwrap_or_default();
    match raw.trim().parse::<i64>() {
        Ok(id) => Ok(id),
        Err(_) => bail!(
            "TELEGRAM_APPROVER_ID must be your numeric Telegram user id (ask @userinfobot). \
             Without it every message reaching this bot would be an order, so the bridge \
             refuses to start rather than opening the fleet to whoever finds it."
        ),
    }
}

/// Run the bridge until it is stopped.
///
/// Two shapes, one loop. With a [`crate::tgmap`] map it keeps a desk per topic and serves
/// several projects from one group; without one it is what it always was - one chat, one
/// project - so an existing install keeps working with no file and no flag.
///
/// `agent` is the identity orders are signed with, which is the operator, not a worker: a
/// bridge that signed as a machine would put that machine's name on work a human asked for.
pub async fn bridge(
    workspace: Option<PathBuf>,
    agent: Option<String>,
    default_to: Option<String>,
    map: Option<PathBuf>,
) -> Result<()> {
    let start = match workspace {
        Some(path) => path,
        None => std::env::current_dir().context("read the current directory")?,
    };
    let token = bot_token()?;
    let approver = approver_id()?;
    let http = reqwest::Client::new();

    // An explicit --map is a promise the file is there; a discovered one is a convenience,
    // and its absence just means the older single-project shape.
    let map_file = match map {
        Some(path) => {
            if !path.is_file() {
                // Asked for a map that is not there. Rather than an error telling the
                // operator to go and write TOML, write the one the machine already implies:
                // every channel beside it, listed and waiting for a group id. One restart
                // after that builds the whole group.
                let dir = path.parent().unwrap_or(Path::new("."));
                let starter = crate::tgmap::starter(dir);
                starter.save(&path)?;
                bail!(
                    "wrote a starter map at {} listing {} channel{} found in {}.\n\n\
                     Add your bot to your Telegram group as an administrator with \"Manage \
                     topics\", turn Topics on in the group's settings, and start me again. \
                     Say anything in the group and I will take it from there.",
                    path.display(),
                    starter.topics.len(),
                    if starter.topics.len() == 1 { "" } else { "s" },
                    dir.display()
                );
            }
            Some(path)
        }
        None => crate::tgmap::discover(&start),
    };

    match map_file {
        Some(path) => group_bridge(http, token, approver, agent, default_to, &path).await,
        None => single_bridge(http, token, approver, start, agent, default_to).await,
    }
}

/// One group, a topic per project.
async fn group_bridge(
    http: reqwest::Client,
    token: String,
    approver: i64,
    agent: Option<String>,
    default_to: Option<String>,
    map_path: &Path,
) -> Result<()> {
    let mut map = crate::tgmap::TopicMap::load(map_path)?;
    let base = map_path.parent().unwrap_or(Path::new(".")).to_path_buf();
    let cursor_file = cursor_path(&base);
    let mut cursor: Cursor = match std::fs::read_to_string(&cursor_file) {
        Ok(raw) => serde_json::from_str(&raw).unwrap_or_default(),
        Err(_) => Cursor::default(),
    };
    let known_group = map.group.is_some();
    let group = match map.group {
        Some(group) => group,
        None => {
            let mut chat = Chat {
                http: http.clone(),
                token: token.clone(),
                // Nothing to answer in yet, so anything said before the group is known goes
                // to the operator directly.
                chat_id: approver,
            };
            let group = learn_group(&chat, approver, &mut cursor, &cursor_file).await?;
            map.group = Some(group);
            map.save(map_path)?;
            chat.chat_id = group;
            group
        }
    };
    let chat = Chat {
        http,
        token,
        chat_id: group,
    };
    if !known_group {
        chat.send(&format!(
            "Got it - this group is {group}, written into {}.",
            crate::tgmap::FILE
        ))
        .await
        .ok();
    }

    // Build out the group to match the file. Saved after each one: an id Telegram has
    // handed out and Ferryman has not written down belongs to a topic nothing can ever
    // speak into again, so losing four of them to one failed write is not acceptable.
    let unmade: Vec<String> = map
        .unmade()
        .into_iter()
        .map(|topic| topic.name.clone())
        .collect();
    let mut created = Vec::new();
    for name in unmade {
        let thread = chat.create_forum_topic(group, &name).await?;
        map.record_thread(&name, thread);
        map.save(map_path)?;
        println!("telegram: created topic {name} ({thread})");
        created.push(name);
    }

    let mut desks = Vec::new();
    for topic in &map.topics {
        let workspace = topic.resolved_workspace(&base);
        // One unreachable project must not silence the others. A channel that has not been
        // cloned onto this machine yet is the ordinary case on a new box.
        let route = match ferryman_channel::route_for(&workspace) {
            Ok(route) => route,
            Err(error) => {
                eprintln!(
                    "telegram: topic '{}' has no channel at {}: {error}",
                    topic.name,
                    workspace.display()
                );
                continue;
            }
        };
        let issuer = ferryman_ops::identity::resolve(agent.clone(), &route.attachment)?;
        let state_path = state_path(&route.attachment, &issuer);
        let (state, first_run) = load_state(&state_path, &route)?;
        desks.push(Desk {
            name: topic.name.clone(),
            chat_id: group,
            thread: topic.thread,
            route,
            issuer,
            default_to: topic.default_to.clone().or_else(|| default_to.clone()),
            state,
            state_path,
        });
        let _ = first_run;
    }
    if desks.is_empty() {
        bail!(
            "{} lists {} topics and none of them has a Ferryman channel on this machine",
            map_path.display(),
            map.topics.len()
        );
    }

    if !known_group || !created.is_empty() {
        // A topic appearing in a group with no explanation is alarming rather than useful,
        // and a bridge that has just built the place should say what it built.
        let hello = group_opening(&desks, &created);
        let general = desks.iter().find(|desk| desk.thread.is_none());
        chat.send_to(group, general.and_then(|desk| desk.thread), &hello)
            .await
            .ok();
    }

    println!("telegram bridge: {} desks in group {group}", desks.len());
    for desk in &desks {
        println!(
            "  {} -> {} as {}{}",
            desk.name,
            desk.route.project_id,
            desk.issuer,
            match desk.thread {
                Some(thread) => format!(" (topic {thread})"),
                None => " (general)".to_string(),
            }
        );
    }

    serve(&chat, &mut desks, approver, &mut cursor, &cursor_file).await
}

/// Wait to be spoken to, and take the group's id from the message.
///
/// A chat id is not something a person has. Telegram does not show it anywhere in the app,
/// and the usual answer - "ask @userinfobot, then paste the number into a config file" - is
/// three steps of clerical work to tell a program something it can see for itself the
/// moment anyone types in the group.
///
/// So it watches instead. The first message from the approver in a group becomes the
/// group, and is written into the map. A message in a private chat is not: the whole point
/// of the map is topics, and a private chat has none, so it says so and keeps waiting
/// rather than wiring itself to the wrong place and being hard to unpick later.
async fn learn_group(
    chat: &Chat,
    approver: i64,
    cursor: &mut Cursor,
    cursor_file: &Path,
) -> Result<i64> {
    println!("telegram: waiting to be added - say anything in the group you want me to use");
    chat.send(
        "I do not know which group to use yet. Say anything in the group you want me to \
         work in, and I will take it from there.\n\nI need to be an administrator there \
         with \"Manage topics\", and the group needs Topics turned on.",
    )
    .await
    .ok();
    loop {
        let updates = match chat.updates(cursor.offset).await {
            Ok(updates) => updates,
            Err(error) => {
                eprintln!("telegram: {error}; retrying");
                tokio::time::sleep(Duration::from_secs(10)).await;
                continue;
            }
        };
        for update in updates {
            cursor.offset = cursor.offset.max(update.update_id + 1);
            write_cursor(cursor_file, cursor)?;
            let Some(message) = update.message else {
                continue;
            };
            if message.from.as_ref().map(|user| user.id) != Some(approver) {
                continue;
            }
            let Some(chat_id) = message.chat.as_ref().map(|c| c.id) else {
                continue;
            };
            // Group and supergroup ids are negative; a positive id is a person.
            if chat_id < 0 {
                return Ok(chat_id);
            }
            chat.send_to(
                chat_id,
                None,
                "That is our private chat, and it has no topics. Say it in the group instead.",
            )
            .await
            .ok();
        }
    }
}

/// The older shape: one chat, one project, no map.
async fn single_bridge(
    http: reqwest::Client,
    token: String,
    approver: i64,
    start: PathBuf,
    agent: Option<String>,
    default_to: Option<String>,
) -> Result<()> {
    let route = ferryman_channel::route_for(&start)?;
    let issuer = ferryman_ops::identity::resolve(agent, &route.attachment)?;
    let chat_id = match std::env::var("TELEGRAM_CHAT_ID") {
        Ok(raw) if !raw.trim().is_empty() => raw
            .trim()
            .parse::<i64>()
            .context("TELEGRAM_CHAT_ID must be numeric")?,
        // A direct message to the approver is the common case and needs no configuration.
        _ => approver,
    };
    let chat = Chat {
        http,
        token,
        chat_id,
    };

    let state_path = state_path(&route.attachment, &issuer);
    let (state, first_run) = load_state(&state_path, &route)?;
    if first_run {
        // A greeting that only says "up" tells the operator nothing they could not have
        // assumed. What they actually need to know is where their next message will land,
        // who is available to do it, and whether anything is already in flight.
        chat.send(&opening(&route, &issuer, default_to.as_deref()))
            .await?;
    }
    println!(
        "telegram bridge: project {} as {issuer}, chat {chat_id}",
        route.project_id
    );

    // The cursor lived in this file before there were maps, and still does here.
    let mut cursor = Cursor {
        offset: state.offset,
    };
    let cursor_file = state_path.clone();
    let mut desks = vec![Desk {
        name: route.project_id.clone(),
        chat_id,
        thread: None,
        route,
        issuer,
        default_to,
        state,
        state_path,
    }];
    serve(&chat, &mut desks, approver, &mut cursor, &cursor_file).await
}

/// Read a desk's memory, seeding it on first sight.
///
/// Everything already in the channel is history, not news. Announcing it would greet a new
/// operator with every result the project has ever produced.
fn load_state(path: &Path, route: &ferryman_channel::ProjectRoute) -> Result<(BridgeState, bool)> {
    let first_run = !path.exists();
    let mut state: BridgeState = match std::fs::read_to_string(path) {
        Ok(raw) => serde_json::from_str(&raw).unwrap_or_default(),
        Err(_) => BridgeState::default(),
    };
    if first_run {
        for task in ferryman_channel::list_tasks(route)? {
            for result in &task.results {
                state.remember(result_key(&task.order.id, &result.agent, result.revision));
            }
        }
        save(path, &state)?;
    }
    Ok((state, first_run))
}

/// Poll, act, report - the same loop whatever the desks are.
async fn serve(
    chat: &Chat,
    desks: &mut [Desk],
    approver: i64,
    cursor: &mut Cursor,
    cursor_file: &Path,
) -> Result<()> {
    loop {
        match chat.updates(cursor.offset).await {
            Ok(updates) => {
                for update in updates {
                    // Acknowledge before acting. A message that makes the bridge panic
                    // would otherwise be redelivered forever, and a crash loop that reissues
                    // the same order every restart is worse than a lost message.
                    cursor.offset = cursor.offset.max(update.update_id + 1);
                    save_cursor(cursor_file, cursor, desks)?;
                    let Some(message) = update.message else {
                        continue;
                    };
                    match desk_for(desks, &message) {
                        Some(index) => handle(chat, &desks[index], approver, &message).await,
                        None => unmapped(chat, desks, &message).await,
                    }
                }
            }
            Err(error) => {
                // A phone with no signal, Telegram rate-limiting, a laptop lid: none of
                // these are reasons to stop being the fleet's ear.
                eprintln!("telegram: {error}; retrying");
                tokio::time::sleep(Duration::from_secs(10)).await;
            }
        }

        for desk in desks.iter_mut() {
            if let Err(error) = announce(chat, desk).await {
                eprintln!("telegram: could not report {} results: {error}", desk.name);
            }
        }
    }
}

/// Which desk a message belongs to.
///
/// Matched on the topic it arrived in. A message with no topic - a private chat, or the
/// group's General - goes to the desk that has no topic of its own, if there is one.
fn desk_for(desks: &[Desk], message: &TgMessage) -> Option<usize> {
    let threads: Vec<Option<i64>> = desks.iter().map(|desk| desk.thread).collect();
    crate::tgmap::index_for(&threads, message.message_thread_id)
}

/// Answer a message from a topic that is not in the map.
///
/// Not silence: the operator is standing in a topic that looks like every other one, and
/// the reason it does nothing is a line missing from a file they can edit. But not a guess
/// either - putting the order in some other project's channel would sign work into a
/// project nobody asked about.
async fn unmapped(chat: &Chat, desks: &[Desk], message: &TgMessage) {
    let from = message
        .from
        .as_ref()
        .map(|user| user.id)
        .unwrap_or_default();
    let known: Vec<&str> = desks.iter().map(|desk| desk.name.as_str()).collect();
    let text = format!(
        "This topic is not in {}, so I do not know which project it is for.\n\n\
         Add a [[topic]] for it with the thread id {}, then restart me.\n\n\
         I am serving: {}",
        crate::tgmap::FILE,
        message
            .message_thread_id
            .map_or_else(|| "(none)".to_string(), |id| id.to_string()),
        if known.is_empty() {
            "nothing".to_string()
        } else {
            known.join(", ")
        }
    );
    eprintln!(
        "telegram: a message from {from} in unmapped topic {:?}",
        message.message_thread_id
    );
    let where_from = message.chat.as_ref().map_or(chat.chat_id, |c| c.id);
    if let Err(error) = chat
        .send_to(where_from, message.message_thread_id, &text)
        .await
    {
        eprintln!("telegram: could not reply: {error}");
    }
}

fn save_cursor(path: &Path, cursor: &Cursor, desks: &mut [Desk]) -> Result<()> {
    // Without a map the cursor shares a file with the one desk's memory, which is where it
    // has always lived; rewriting that file as a bare cursor would drop what it has already
    // announced and repeat every result on the next restart.
    if let Some(desk) = desks
        .iter_mut()
        .find(|desk| desk.state_path.as_path() == path)
    {
        desk.state.offset = cursor.offset;
        return save(path, &desk.state);
    }
    write_cursor(path, cursor)
}

fn write_cursor(path: &Path, cursor: &Cursor) -> Result<()> {
    if let Some(parent) = path.parent() {
        std::fs::create_dir_all(parent).ok();
    }
    std::fs::write(path, serde_json::to_string_pretty(cursor)?)
        .with_context(|| format!("write {}", path.display()))
}

/// What to say when a group bridge starts for the first time.
fn group_opening(desks: &[Desk], created: &[String]) -> String {
    let mut lines = vec![format!(
        "Ferryman bridge up, serving {} topic{}.",
        desks.len(),
        if desks.len() == 1 { "" } else { "s" }
    )];
    if !created.is_empty() {
        lines.push(format!("Created: {}.", created.join(", ")));
    }
    lines.push(String::new());
    for desk in desks {
        let lands = match &desk.default_to {
            Some(who) => who.clone(),
            None => "whoever claims it first".to_string(),
        };
        lines.push(format!(
            "{} -> {} (signed {}, goes to {lands})",
            desk.name, desk.route.project_id, desk.issuer
        ));
    }
    lines.push(String::new());
    lines.push("Say anything in a topic to put work in that project's channel.".to_string());
    lines.push("/help for the rest. Do not send credentials here.".to_string());
    lines.join("\n")
}

fn save(path: &Path, state: &BridgeState) -> Result<()> {
    if let Some(parent) = path.parent() {
        std::fs::create_dir_all(parent).ok();
    }
    std::fs::write(path, serde_json::to_string_pretty(state)?)
        .with_context(|| format!("write {}", path.display()))
}

/// Act on one message. Errors are reported into the chat rather than returned: the operator
/// is holding the only screen that will show them, and a bridge that exits on a bad order
/// stops answering the good ones.
async fn handle(chat: &Chat, desk: &Desk, approver: i64, message: &TgMessage) {
    let route = &desk.route;
    let issuer = desk.issuer.as_str();
    let default_to = desk.default_to.as_deref();
    let from = message
        .from
        .as_ref()
        .map(|user| user.id)
        .unwrap_or_default();
    if from != approver {
        // Not an error worth answering: replying would confirm the bot exists to whoever
        // is probing it.
        eprintln!("telegram: ignored a message from {from}, who is not the approver");
        return;
    }
    let Some(text) = message.text.as_deref() else {
        return;
    };
    let reply = match parse_instruction(text) {
        None => help_text(default_to),
        Some(Instruction::Help) => help_text(default_to),
        Some(Instruction::Agents) => {
            match ferryman_channel::read_agent_roster(&route.communications) {
                Ok(roster) if roster.is_empty() => {
                    "no agents have joined this channel yet".to_string()
                }
                Ok(roster) => {
                    let mut lines = vec![format!("{} agents:", roster.len())];
                    for agent in roster {
                        let keyed = agent.public_key.as_ref().is_some_and(|key| !key.is_empty());
                        lines.push(format!(
                            "  {} {}",
                            agent.name,
                            if keyed { "" } else { "(no key yet)" }
                        ));
                    }
                    lines.join("\n")
                }
                Err(error) => format!("could not read the roster: {error}"),
            }
        }
        Some(Instruction::Status) => status_text(route),
        Some(Instruction::Order { to, task }) => {
            // An unaddressed order goes to whichever machine claims it first, which is the
            // wrong default when machines are not interchangeable: they differ in what they
            // cost to run, and the fastest poller wins rather than the cheapest engine. So a
            // configured default decides, and `/to` still overrides it per message.
            let target = to.clone().or_else(|| default_to.map(str::to_string));
            match issue(route, issuer, message.message_id, target.clone(), &task) {
                Ok(id) => match (target, to.is_some()) {
                    (Some(who), true) => format!("issued {id} to {who}"),
                    (Some(who), false) => format!("issued {id} to {who} (default)"),
                    (None, _) => format!("issued {id}, open to whoever claims it first"),
                },
                Err(error) => format!("could not issue that: {error}"),
            }
        }
    };
    // Answer in the chat and topic the message came from, falling back to the configured
    // chat only when Telegram did not tell us where it was.
    let where_from = message.chat.as_ref().map_or(chat.chat_id, |c| c.id);
    if let Err(error) = chat
        .send_to(where_from, message.message_thread_id, &reply)
        .await
    {
        eprintln!("telegram: could not reply: {error}");
    }
}

fn help_text(default_to: Option<&str>) -> String {
    let lands = match default_to {
        Some(who) => format!("Send any line to make it an order. It goes to {who}."),
        None => "Send any line to make it an order, open to whichever machine claims it first."
            .to_string(),
    };
    format!(
        "{lands}\n\
         /to <agent> <task>  send it to one machine instead\n\
         /order <task>       the same as sending the line alone\n\
         /status             every task and where it has got to\n\
         /agents             who is in this channel\n\
         \n\
         Do not send credentials here. This chat is not end-to-end encrypted."
    )
}

/// What to say on first contact.
///
/// "Bridge up" is not news to whoever just started it. The useful facts are where the next
/// message will land, who could pick it up, and whether the channel is already busy - all of
/// which are one roster read away and none of which the operator can see from a phone.
fn opening(
    route: &ferryman_channel::ProjectRoute,
    issuer: &str,
    default_to: Option<&str>,
) -> String {
    let roster = ferryman_channel::read_agent_roster(&route.communications).unwrap_or_default();
    let names: Vec<String> = roster
        .iter()
        .filter(|agent| agent.name != issuer)
        .map(|agent| agent.name.clone())
        .collect();

    let (open, running) = match ferryman_channel::list_tasks(route) {
        Ok(tasks) => tasks
            .iter()
            .fold((0, 0), |(open, running), task| match task.state() {
                // Offered counts as waiting, not running. An order addressed to a
                // machine that has not picked it up is exactly as un-started as an open
                // one, and counting it as in-progress is how a stalled fleet looks busy.
                ferryman_channel::TaskState::Open | ferryman_channel::TaskState::Offered { .. } => {
                    (open + 1, running)
                }
                ferryman_channel::TaskState::Claimed { .. }
                | ferryman_channel::TaskState::ChangesRequested { .. } => (open, running + 1),
                _ => (open, running),
            }),
        Err(_) => (0, 0),
    };

    let lands = match default_to {
        Some(who) => format!("Anything you send goes to {who}."),
        None => "Anything you send is open to whichever machine claims it first.".to_string(),
    };

    format!(
        "Ferryman bridge up on {project}, signing as {issuer}.\n\
         {lands} /to <agent> to pick one.\n\
         \n\
         Fleet: {fleet}\n\
         Now: {open} waiting, {running} in progress\n\
         \n\
         /help for the rest. Do not send credentials here.",
        project = route.project_id,
        fleet = if names.is_empty() {
            "nobody has joined yet".to_string()
        } else {
            names.join(", ")
        },
    )
}

fn status_text(route: &ferryman_channel::ProjectRoute) -> String {
    let tasks = match ferryman_channel::list_tasks(route) {
        Ok(tasks) => tasks,
        Err(error) => return format!("could not read the channel: {error}"),
    };
    if tasks.is_empty() {
        return "no tasks yet".to_string();
    }
    let mut lines = Vec::new();
    // Newest first: the phone is for what is happening now, and the oldest task in a long
    // project is rarely the one being asked about.
    let mut tasks = tasks;
    tasks.sort_by(|a, b| b.order.created_at.cmp(&a.order.created_at));
    for task in tasks.iter().take(12) {
        lines.push(format!(
            "{}  {}  {:?}",
            task.order.id,
            task.holder().unwrap_or("-"),
            task.state()
        ));
    }
    if tasks.len() > 12 {
        lines.push(format!("... and {} older", tasks.len() - 12));
    }
    lines.join("\n")
}

/// Turn a message into a signed order.
///
/// The order id carries the Telegram message id, so an order can be traced back to the
/// message that asked for it - and a redelivered update cannot mint a second order, because
/// the id is already taken.
fn issue(
    route: &ferryman_channel::ProjectRoute,
    issuer: &str,
    message_id: i64,
    to: Option<String>,
    task: &str,
) -> Result<String> {
    let id = format!("tg-{message_id}");
    let mut order = ferryman_channel::Order {
        id: id.clone(),
        project_id: route.project_id.clone(),
        issued_by: issuer.to_string(),
        assigned_to: to,
        created_at: chrono::Utc::now(),
        payload: json!({ "task": task }),
        requires_review: false,
        requires_approval: false,
        depends_on: Vec::new(),
        signed_by: None,
        signature: None,
        result_contract: None,
    };
    // Unsigned work is work nobody can attribute. If this identity can sign, it does.
    if let Some(identity) = crate::sign_as(route, issuer)? {
        identity.sign_order(&mut order);
        ferryman_channel::issue_order(route, &order)?;
        let _ = ferryman_channel::ledger::append_ledger_entry(
            route,
            &identity,
            "order",
            issuer,
            &format!("issued order {id} from Telegram"),
            Some(&id),
        );
    } else {
        ferryman_channel::issue_order(route, &order)?;
    }
    Ok(id)
}

/// Report results that have arrived since the last look.
async fn announce(chat: &Chat, desk: &mut Desk) -> Result<()> {
    let route = &desk.route;
    let mut fresh: Vec<(String, String)> = Vec::new();
    for task in ferryman_channel::list_tasks(route)? {
        for result in &task.results {
            let key = result_key(&task.order.id, &result.agent, result.revision);
            if desk.state.knows(&key) {
                continue;
            }
            let output = result
                .payload
                .get("output")
                .and_then(Value::as_str)
                .map(str::to_string)
                .unwrap_or_else(|| result.payload.to_string());
            let signature = ferryman_channel::verify_result(result, &route.agents);
            fresh.push((
                key,
                format!(
                    "{} r{} by {} ({signature:?})\n\n{}",
                    task.order.id,
                    result.revision,
                    result.agent,
                    excerpt(&output, EXCERPT_CHARS)
                ),
            ));
        }
    }
    // Remember first, then speak. The other order repeats an announcement every restart if
    // the send is what failed, and a phone that buzzes with yesterday's results twice is a
    // bridge an operator turns off.
    for (key, text) in fresh {
        desk.state.remember(key);
        save(&desk.state_path, &desk.state)?;
        // Into this project's topic, not into whatever chat the bridge was started with.
        // A result that lands in the wrong topic is a result the operator has to work out
        // the owner of, which is the whole thing the topics were for.
        chat.send_to(desk.chat_id, desk.thread, &text).await?;
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn a_bare_line_is_an_open_order() {
        assert_eq!(
            parse_instruction("check the README opening"),
            Some(Instruction::Order {
                to: None,
                task: "check the README opening".to_string()
            })
        );
    }

    #[test]
    fn an_addressed_order_folds_the_agent_name() {
        // The same folding every other entry point uses, or `/to BEASTLYWSL` addresses a
        // machine the roster does not have.
        assert_eq!(
            parse_instruction("/to BeastlyWSL  run the tests"),
            Some(Instruction::Order {
                to: Some("beastlywsl".to_string()),
                task: "run the tests".to_string()
            })
        );
    }

    #[test]
    fn a_group_suffix_is_addressing_not_part_of_the_command() {
        assert_eq!(
            parse_instruction("/status@ferrymanbot"),
            Some(Instruction::Status)
        );
    }

    #[test]
    fn a_mistyped_command_is_not_quietly_turned_into_work() {
        // `/stauts` becoming an order for the fleet to carry out is the kind of
        // helpfulness that wastes an engine run and confuses the person who typed it.
        assert_eq!(parse_instruction("/stauts"), None);
    }

    #[test]
    fn an_order_verb_with_nothing_after_it_is_not_an_order() {
        assert_eq!(parse_instruction("/order   "), None);
        assert_eq!(parse_instruction("/to beastlywsl"), None);
    }

    /// The default recipient is the difference between "the fleet does this" and "whichever
    /// machine polls fastest does this", and those machines do not cost the same to run.
    #[test]
    fn an_unaddressed_message_goes_to_the_default_and_to_overrides_it() {
        let bare = parse_instruction("run the tests").unwrap();
        let Instruction::Order { to, .. } = bare else {
            panic!("a bare line is an order")
        };
        assert_eq!(to, None, "parsing does not know about the default");

        // The default is applied where the order is issued, not where it is parsed, so
        // `/to` keeps overriding it and a fleet with no default still races as before.
        let applied = to.clone().or_else(|| Some("grouchly".to_string()));
        assert_eq!(applied.as_deref(), Some("grouchly"));

        let addressed = parse_instruction("/to beastlywsl run the tests").unwrap();
        let Instruction::Order { to, .. } = addressed else {
            panic!("addressed order")
        };
        assert_eq!(
            to.clone()
                .or_else(|| Some("grouchly".to_string()))
                .as_deref(),
            Some("beastlywsl"),
            "an explicit target wins over the default"
        );
    }

    #[test]
    fn help_says_where_a_bare_line_actually_goes() {
        // Telling someone their message is "open to whoever claims it first" when it is in
        // fact pinned to one machine is worse than saying nothing.
        assert!(help_text(Some("grouchly")).contains("goes to grouchly"));
        assert!(help_text(None).contains("claims it first"));
        for text in [help_text(Some("grouchly")), help_text(None)] {
            assert!(
                text.contains("Do not send credentials"),
                "the warning belongs on the surface an operator actually reads"
            );
        }
    }

    #[test]
    fn seen_results_are_remembered_but_bounded() {
        let mut state = BridgeState::default();
        for index in 0..(SEEN_LIMIT + 10) {
            state.remember(result_key("t", "a", u32::try_from(index).unwrap()));
        }
        assert_eq!(state.seen.len(), SEEN_LIMIT);
        // The oldest fall off, not the newest: a restart must not re-announce what just
        // happened.
        assert!(!state.knows(&result_key("t", "a", 0)));
        assert!(state.knows(&result_key(
            "t",
            "a",
            u32::try_from(SEEN_LIMIT + 9).unwrap()
        )));
    }

    #[test]
    fn an_excerpt_cuts_on_a_character_boundary() {
        let text = "e\u{301}".repeat(400);
        let cut = excerpt(&text, 10);
        assert!(cut.ends_with("..."));
        assert_eq!(cut.chars().count(), 13);
    }

    #[test]
    fn state_is_named_for_the_agent_that_writes_it() {
        // One writer per path is what makes the synced folder conflict-free; two bridges
        // sharing a cursor file would fight over it.
        let path = state_path(Path::new("/w/.ferryman"), "beastlywsl");
        assert!(path.ends_with("telegram-beastlywsl.json"));
    }
}
