//! The email lane in the worker: a store-and-forward fallback through the fleet's AgentMail
//! inbox (ADR 0032).
//!
//! ```text
//! <ferry root>/ferry.toml  [email]       inbox, after_minutes, key (the variable's name)
//! <ferry root>/secrets/.env               this machine's own AgentMail key, owner-only
//! <machine state>/mail-state.json         bundle ids taken, what was mailed to whom
//! ```
//!
//! Every [`EVERY`] the worker:
//!
//! - **sends** to each iroh peer the lane has not reached for `after_minutes` the channel
//!   files changed since the lane last did, in sealed, signed bundles
//!   ([`ferryman_channel::maillane`]), one per peer agent and project, a few hundred KB each;
//! - **receives** every lane mail in the inbox addressed to an agent of this machine, opens
//!   it with that agent's own key, and lets each file in under exactly the rules a file
//!   arriving over iroh meets ([`ferryman_iroh::lane::channel_share`]).
//!
//! A mail is taken once by its bundle id, whatever happened to it. A mail that is not a lane
//! bundle is left alone: an email is never an order. The key is this machine's own, narrowed
//! to read and send in the one inbox; it is never written to a log or a channel.

use std::collections::{BTreeMap, BTreeSet};
use std::path::{Path, PathBuf};
use std::time::{Duration, Instant};

use anyhow::{Context, Result, bail};
use chrono::{DateTime, Utc};
use ferryman_channel::{
    ProjectRoute,
    maillane::{self, Bundle, MailFile},
    secrets::EncryptionIdentity,
};
use ferryman_ops::Progress;
use serde::{Deserialize, Serialize};
use serde_json::{Value, json};

/// How often the lane looks.
pub(crate) const EVERY: Duration = Duration::from_secs(120);
/// The most file bytes one bundle carries before it is sealed. A sealed, compressed bundle
/// is sent as hex in the mail's body, and AgentMail takes 6 MB a request.
const BUNDLE_BYTES: usize = 1_500_000;
/// How far back a peer the lane never reached is caught up from.
const FIRST_CATCH_UP_DAYS: i64 = 7;
/// Mails looked at each pass, newest first.
const LIST_LIMIT: usize = 50;
/// Bundle ids remembered as taken.
const TAKEN_KEPT: usize = 5_000;
const BODY_START: &str = "FERRYMAN-MAIL v1";
const BODY_END: &str = "END";
const API: &str = "https://api.agentmail.to/v0";

/// `[email]` in `ferry.toml`.
#[derive(Debug, Clone, PartialEq, Eq, Deserialize)]
pub(crate) struct EmailConfig {
    pub inbox: String,
    #[serde(default = "default_after")]
    pub after_minutes: i64,
    /// The name of the variable that holds this machine's key, in the environment or in
    /// `<root>/secrets/.env`.
    #[serde(default = "default_key")]
    pub key: String,
    #[serde(default = "yes")]
    pub enabled: bool,
}

fn default_after() -> i64 {
    15
}
fn default_key() -> String {
    "AGENTMAIL_FERRYMAN_MACHINE_KEY".to_string()
}
fn yes() -> bool {
    true
}

impl EmailConfig {
    /// `[email]` from the root's `ferry.toml`, when it has one and it is on.
    pub(crate) fn load(root: &Path) -> Option<Self> {
        let text = std::fs::read_to_string(root.join("ferry.toml")).ok()?;
        let table: toml::Table = toml::from_str(&text).ok()?;
        let config: Self = table.get("email")?.clone().try_into().ok()?;
        config.enabled.then_some(config)
    }
}

/// The value of `name` from the environment, else from a `NAME=value` line in `env_file`.
fn secret(name: &str, env_file: &Path) -> Option<String> {
    if let Ok(value) = std::env::var(name)
        && !value.trim().is_empty()
    {
        return Some(value.trim().to_string());
    }
    let text = std::fs::read_to_string(env_file).ok()?;
    text.lines().find_map(|line| {
        let line = line.trim_start_matches('\u{feff}').trim();
        let (key, value) = line.split_once('=')?;
        (key.trim() == name).then(|| value.trim().trim_matches('"').to_string())
    })
}

#[derive(Debug, Default, Serialize, Deserialize)]
struct State {
    /// Bundle ids already taken, oldest first.
    #[serde(default)]
    taken: Vec<String>,
    /// `<agent>|<project>` to the newest modification time (ms) mailed to it.
    #[serde(default)]
    mailed: BTreeMap<String, i64>,
    #[serde(default)]
    sent: u64,
    #[serde(default)]
    received: u64,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    last_error: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    last_pass: Option<DateTime<Utc>>,
}

impl State {
    fn load(path: &Path) -> Self {
        std::fs::read(path)
            .ok()
            .and_then(|bytes| serde_json::from_slice(&bytes).ok())
            .unwrap_or_default()
    }

    fn save(&self, path: &Path) {
        if let Ok(bytes) = serde_json::to_vec_pretty(self) {
            let _ = std::fs::write(path, bytes);
        }
    }

    fn take(&mut self, id: &str) {
        if !self.taken.iter().any(|seen| seen == id) {
            self.taken.push(id.to_string());
            let extra = self.taken.len().saturating_sub(TAKEN_KEPT);
            self.taken.drain(..extra);
        }
    }
}

/// The body of a lane mail: the bundle as JSON, compressed, hex, in lines of 76.
pub(crate) fn encode_body(bundle: &Bundle) -> Result<String> {
    let json = serde_json::to_vec(bundle)?;
    let packed = zstd::encode_all(json.as_slice(), 9)?;
    let hex = hex::encode(packed);
    let mut body = String::with_capacity(hex.len() + hex.len() / 76 + 64);
    body.push_str(BODY_START);
    body.push('\n');
    for chunk in hex.as_bytes().chunks(76) {
        body.push_str(std::str::from_utf8(chunk).unwrap_or_default());
        body.push('\n');
    }
    body.push_str(BODY_END);
    body.push('\n');
    Ok(body)
}

/// The bundle in a lane mail's body. Anything between the markers that is not hex - a
/// line break a mail system added, a space - is ignored.
pub(crate) fn decode_body(body: &str) -> Result<Bundle> {
    let start = body
        .find(BODY_START)
        .context("not a lane mail: no start marker")?
        + BODY_START.len();
    let rest = &body[start..];
    let end = rest
        .rfind(BODY_END)
        .context("not a lane mail: no end marker")?;
    let hex: String = rest[..end]
        .chars()
        .filter(char::is_ascii_hexdigit)
        .collect();
    let packed = hex::decode(hex).context("the body is not hex")?;
    let json = zstd::decode_all(packed.as_slice()).context("the body does not decompress")?;
    Ok(serde_json::from_slice(&json)?)
}

/// The files of `route`'s channel, under `rules`, changed after `since_ms`, newest last,
/// cut into bundles of about [`BUNDLE_BYTES`].
fn changed_files(
    route: &ProjectRoute,
    rules: &ferryman_iroh::manifest::Rules,
    since_ms: i64,
) -> Vec<Vec<MailFile>> {
    let mut cache = ferryman_iroh::manifest::HashCache::default();
    let scanned = ferryman_iroh::manifest::scan(&route.communications, rules, &mut cache);
    let mut entries: Vec<_> = scanned
        .values()
        .filter(|entry| entry.mtime > since_ms)
        .cloned()
        .collect();
    entries.sort_by_key(|entry| entry.mtime);
    let mut bundles = Vec::new();
    let mut current: Vec<MailFile> = Vec::new();
    let mut size = 0usize;
    for entry in entries {
        let Some((entry, bytes)) =
            ferryman_iroh::manifest::read_for_send(&route.communications, rules, &entry.path)
        else {
            continue;
        };
        if bytes.len() > BUNDLE_BYTES {
            // Waits for a live lane: one file over a mail's budget is not split.
            continue;
        }
        if size + bytes.len() > BUNDLE_BYTES && !current.is_empty() {
            bundles.push(std::mem::take(&mut current));
            size = 0;
        }
        size += bytes.len();
        current.push(MailFile {
            path: entry.path,
            mtime_ms: entry.mtime,
            data_hex: hex::encode(bytes),
        });
    }
    if !current.is_empty() {
        bundles.push(current);
    }
    bundles
}

/// A peer the iroh lane has not reached: its agents, the projects the lane shared with it,
/// and when it last reached it.
type StalePeer = (Vec<String>, Vec<String>, Option<DateTime<Utc>>);

/// The email lane, ready to run inside the worker.
pub(crate) struct MailLane {
    config: EmailConfig,
    key: String,
    /// The machine's worker: what it mails is signed with its key in each project's
    /// attachment, and what is addressed to it is opened with its encryption key there.
    agent: String,
    state_path: PathBuf,
    iroh_status: PathBuf,
    http: reqwest::Client,
    last: Option<Instant>,
}

impl std::fmt::Debug for MailLane {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("MailLane")
            .field("inbox", &self.config.inbox)
            .field("agent", &self.agent)
            .finish_non_exhaustive()
    }
}

impl MailLane {
    /// The lane, when `[email]` is set and this machine has its key. Says why not when it
    /// was meant to run.
    pub(crate) fn for_worker(
        root: &ferryman_channel::ferry::Root,
        agent: &str,
        report: &impl Progress,
    ) -> Option<Self> {
        let config = EmailConfig::load(&root.path)?;
        let Some(key) = secret(&config.key, &root.path.join("secrets").join(".env")) else {
            report.warn(&format!(
                "email lane: [email] is set, but this machine has no {} (in the environment or \
                 the root's secrets/.env); it is off here",
                config.key
            ));
            return None;
        };
        let machine = ferryman_iroh::machine_dir().ok()?;
        let http = reqwest::Client::builder()
            .timeout(Duration::from_secs(60))
            .build()
            .ok()?;
        report.info(&format!(
            "email lane on through {}, for peers the iroh lane has not reached for {} min",
            config.inbox, config.after_minutes
        ));
        Some(Self {
            config,
            key,
            agent: agent.to_string(),
            state_path: machine.join("mail-state.json"),
            iroh_status: machine.join(ferryman_iroh::STATUS_FILE),
            http,
            last: None,
        })
    }

    /// One pass, at most every [`EVERY`]. Never a reason for the worker to stop.
    pub(crate) async fn pass(&mut self, routes: &[ProjectRoute], report: &impl Progress) {
        if self.last.is_some_and(|at| at.elapsed() < EVERY) {
            return;
        }
        self.last = Some(Instant::now());
        let mut state = State::load(&self.state_path);
        let mut errors = Vec::new();
        match self.receive(routes, &mut state, report).await {
            Ok(()) => {}
            Err(error) => errors.push(format!("receive: {error:#}")),
        }
        match self.send(routes, &mut state, report).await {
            Ok(()) => {}
            Err(error) => errors.push(format!("send: {error:#}")),
        }
        if !errors.is_empty() {
            report.warn(&format!("email lane: {}", errors.join("; ")));
        }
        state.last_error = (!errors.is_empty()).then(|| errors.join("; "));
        state.last_pass = Some(Utc::now());
        state.save(&self.state_path);
    }

    fn auth(&self, request: reqwest::RequestBuilder) -> reqwest::RequestBuilder {
        request.bearer_auth(&self.key)
    }

    fn inbox_url(&self, rest: &str) -> String {
        format!("{API}/inboxes/{}{rest}", self.config.inbox)
    }

    /// Peers of the iroh lane it has not reached for `after_minutes`: (their agents, the
    /// projects the lane shared with them, the last time it reached them).
    fn stale_peers(&self) -> Vec<StalePeer> {
        let Some(status) = ferryman_iroh::lane::Status::read(&self.iroh_status) else {
            return Vec::new();
        };
        let cutoff = Utc::now() - chrono::Duration::minutes(self.config.after_minutes);
        status
            .peers
            .values()
            .filter(|peer| peer.last_sync.is_none_or(|at| at < cutoff))
            .filter(|peer| {
                // A peer that is new to the lane gets the lane's own chance first.
                peer.failing_since.is_some_and(|since| since < cutoff)
                    || peer.last_sync.is_some_and(|at| at < cutoff)
            })
            .map(|peer| (peer.agents.clone(), peer.projects.clone(), peer.last_sync))
            .collect()
    }

    async fn send(
        &self,
        routes: &[ProjectRoute],
        state: &mut State,
        report: &impl Progress,
    ) -> Result<()> {
        let local = vec![self.agent.as_str().to_string()];
        for (agents, projects, last_sync) in self.stale_peers() {
            for route in routes
                .iter()
                .filter(|route| projects.contains(&route.project_id))
            {
                let roster =
                    ferryman_channel::read_agent_roster(&route.communications).unwrap_or_default();
                // One agent of the peer's machine that can open a bundle: it has a key to
                // open with, and is not this machine's.
                let Some(to) = agents.iter().find(|agent| {
                    !agent.eq_ignore_ascii_case(self.agent.as_str())
                        && roster.iter().any(|entry| {
                            entry.name.eq_ignore_ascii_case(agent)
                                && entry.encryption_key.as_ref().is_some_and(|k| !k.is_empty())
                        })
                }) else {
                    continue;
                };
                let Some((rules, sends)) =
                    ferryman_iroh::lane::channel_share(route, &local, &agents)
                else {
                    continue;
                };
                if !sends {
                    continue;
                }
                let mark = format!("{to}|{}", route.project_id);
                let since = state.mailed.get(&mark).copied().unwrap_or_else(|| {
                    last_sync.map_or_else(
                        || {
                            (Utc::now() - chrono::Duration::days(FIRST_CATCH_UP_DAYS))
                                .timestamp_millis()
                        },
                        |at| at.timestamp_millis(),
                    )
                });
                for files in changed_files(route, &rules, since) {
                    let newest = files
                        .iter()
                        .map(|file| file.mtime_ms)
                        .max()
                        .unwrap_or(since);
                    let count = files.len();
                    let identity = ferryman_channel::AgentIdentity::load_existing(
                        &self.agent,
                        &route.attachment,
                    )?
                    .with_context(|| {
                        format!("no key for {} in {}", self.agent, route.project_id)
                    })?;
                    let bundle = maillane::seal(route, &identity, to, files)?;
                    self.send_bundle(&bundle).await?;
                    state.mailed.insert(mark.clone(), newest);
                    state.sent += 1;
                    report.info(&format!(
                        "email lane: mailed {count} file(s) of {} to {to} (the iroh lane has not \
                         reached it)",
                        route.project_id
                    ));
                }
            }
        }
        Ok(())
    }

    async fn send_bundle(&self, bundle: &Bundle) -> Result<()> {
        let body = encode_body(bundle)?;
        let response = self
            .auth(self.http.post(self.inbox_url("/messages/send")))
            .json(&json!({
                "to": [self.config.inbox],
                "subject": bundle.subject(),
                "text": body,
            }))
            .send()
            .await
            .context("AgentMail did not answer")?;
        if !response.status().is_success() {
            bail!("AgentMail refused the mail: HTTP {}", response.status())
        }
        Ok(())
    }

    async fn receive(
        &self,
        routes: &[ProjectRoute],
        state: &mut State,
        report: &impl Progress,
    ) -> Result<()> {
        let response = self
            .auth(self.http.get(self.inbox_url("/messages")))
            .query(&[
                ("limit", LIST_LIMIT.to_string()),
                ("subject", maillane::SUBJECT_PREFIX.to_string()),
            ])
            .send()
            .await
            .context("AgentMail did not answer")?;
        if !response.status().is_success() {
            bail!(
                "AgentMail refused to list the inbox: HTTP {}",
                response.status()
            )
        }
        let listed: Value = response.json().await?;
        let taken: BTreeSet<String> = state.taken.iter().cloned().collect();
        for message in listed["messages"].as_array().into_iter().flatten() {
            let subject = message["subject"].as_str().unwrap_or_default();
            let Some(id) = subject.strip_prefix(maillane::SUBJECT_PREFIX) else {
                continue;
            };
            if taken.contains(id) || !ferryman_channel::is_safe_component(id) {
                continue;
            }
            let Some(message_id) = message["message_id"].as_str() else {
                continue;
            };
            let full: Value = self
                .auth(
                    self.http
                        .get(self.inbox_url(&format!("/messages/{}", urlencode(message_id)))),
                )
                .send()
                .await?
                .json()
                .await?;
            let body = full["text"].as_str().unwrap_or_default();
            let outcome = decode_body(body).and_then(|bundle| self.take_bundle(routes, &bundle));
            match outcome {
                Ok(Some((project, written, offered))) => {
                    state.received += 1;
                    report.info(&format!(
                        "email lane: {project}: {written} of {offered} file(s) let in from a \
                         bundle by mail"
                    ));
                }
                // Not for an agent of this machine: another machine's mail.
                Ok(None) => {}
                Err(error) => report.warn(&format!("email lane: mail {id} refused: {error:#}")),
            }
            state.take(id);
        }
        Ok(())
    }

    /// Open `bundle` if it is for an agent of this machine and let its files in. `None` when
    /// it is addressed to another machine's agent.
    fn take_bundle(
        &self,
        routes: &[ProjectRoute],
        bundle: &Bundle,
    ) -> Result<Option<(String, usize, usize)>> {
        if !bundle.to.eq_ignore_ascii_case(self.agent.as_str()) {
            return Ok(None);
        }
        let Some(route) = routes
            .iter()
            .find(|route| route.project_id == bundle.project_id)
        else {
            bail!("project {} is not served here", bundle.project_id)
        };
        let key = EncryptionIdentity::load_existing(&bundle.to, &route.attachment)?
            .with_context(|| format!("no encryption key for {} here", bundle.to))?;
        let files = maillane::open(route, &key, bundle)?;
        let local = vec![self.agent.as_str().to_string()];
        let Some((rules, _)) =
            ferryman_iroh::lane::channel_share(route, &local, std::slice::from_ref(&bundle.from))
        else {
            bail!("{}'s channel is not exchanged", route.project_id)
        };
        let offered = files.len();
        let mut written = 0;
        for file in files {
            let Ok(bytes) = hex::decode(&file.data_hex) else {
                continue;
            };
            let entry = ferryman_iroh::manifest::entry_for(&file.path, file.mtime_ms, &bytes);
            if let Ok(true) = ferryman_iroh::manifest::write_received(
                &route.communications,
                &rules,
                &entry,
                &bytes,
            ) {
                written += 1;
            }
        }
        Ok(Some((route.project_id.clone(), written, offered)))
    }
}

/// Percent-encode a message id for a URL path (they look like `<abc@agentmail.to>`).
fn urlencode(text: &str) -> String {
    text.bytes()
        .map(|byte| match byte {
            b'A'..=b'Z' | b'a'..=b'z' | b'0'..=b'9' | b'-' | b'.' | b'_' | b'~' => {
                (byte as char).to_string()
            }
            other => format!("%{other:02X}"),
        })
        .collect()
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn a_body_survives_the_line_breaks_and_spaces_a_mail_system_adds() {
        let bundle = Bundle {
            format: maillane::FORMAT.into(),
            id: "abc".into(),
            project_id: "demo".into(),
            from: "grouchly".into(),
            to: "beastly".into(),
            created_at: Utc::now(),
            slot: ferryman_channel::secrets::RecipientSlot {
                recipient: "beastly".into(),
                ephemeral_public_hex: "00".repeat(32),
                nonce_hex: "11".repeat(24),
                ciphertext_hex: "22".repeat(500),
            },
            signature: "33".repeat(64),
        };
        let body = encode_body(&bundle).unwrap();
        assert!(body.lines().all(|line| line.len() <= 76), "short lines");
        // A mail system re-wraps and indents it, and adds a footer.
        let mangled = format!(
            "{}\r\n\r\n--\r\nSent by AgentMail",
            body.replace('\n', "\r\n  ")
        );
        assert_eq!(decode_body(&mangled).unwrap(), bundle);
        assert!(decode_body("hello, please do the thing").is_err());
    }

    #[test]
    fn the_key_comes_from_the_environment_or_the_secrets_file_and_a_bom_does_not_hide_it() {
        let dir = tempfile::tempdir().unwrap();
        let file = dir.path().join(".env");
        std::fs::write(
            &file,
            "\u{feff}OTHER=1\n#agentmail\nFM_TEST_MAIL_KEY = \"am_us_inbox_x\"\n",
        )
        .unwrap();
        assert_eq!(
            secret("FM_TEST_MAIL_KEY", &file).as_deref(),
            Some("am_us_inbox_x")
        );
        assert_eq!(secret("FM_TEST_MISSING", &file), None);
    }

    #[test]
    fn email_config_is_read_from_ferry_toml_with_its_defaults() {
        let dir = tempfile::tempdir().unwrap();
        std::fs::write(
            dir.path().join("ferry.toml"),
            "[email]\ninbox = \"ferryman@agentmail.to\"\n",
        )
        .unwrap();
        let config = EmailConfig::load(dir.path()).unwrap();
        assert_eq!(config.inbox, "ferryman@agentmail.to");
        assert_eq!(config.after_minutes, 15);
        assert_eq!(config.key, "AGENTMAIL_FERRYMAN_MACHINE_KEY");
        std::fs::write(
            dir.path().join("ferry.toml"),
            "[email]\ninbox = \"x@agentmail.to\"\nenabled = false\n",
        )
        .unwrap();
        assert!(EmailConfig::load(dir.path()).is_none());
    }

    #[test]
    fn a_taken_list_stays_bounded_and_takes_each_id_once() {
        let mut state = State::default();
        for n in 0..(TAKEN_KEPT + 10) {
            state.take(&format!("id{n}"));
        }
        assert_eq!(state.taken.len(), TAKEN_KEPT);
        assert_eq!(state.taken.first().map(String::as_str), Some("id10"));
        // Taking one already taken changes nothing.
        state.take("id20");
        assert_eq!(state.taken.first().map(String::as_str), Some("id10"));
    }
}
