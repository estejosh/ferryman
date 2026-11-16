//! `ferry notify` and the worker's notices pass: tools hand the operator's news to
//! Ferryman, and Ferryman decides what reaches the operator's chat
//! ([`ferryman_channel::notices`]).
//!
//! The chat is the Telegram bot the root is set up with: `TELEGRAM_BOT_TOKEN`, and
//! `TELEGRAM_CHAT_ID` (else the first of `TELEGRAM_APPROVERS` / `TELEGRAM_APPROVER_ID`),
//! from the worker's environment or `<root>/secrets/.env`. Without them nothing is sent:
//! everything goes into the digest and `ferry notify status` says so. The token is never
//! logged; errors from the HTTP client are stripped of the URL, which carries it.

use std::path::{Path, PathBuf};
use std::time::{Duration, Instant};

use anyhow::{Context, Result};
use chrono::Utc;
use clap::Subcommand;
use ferryman_channel::notices::{self, Action, Ledger, Level, Notice, Rules};
use serde_json::{Value, json};

use ferryman_ops::Progress;

#[derive(Subcommand, Debug, Clone)]
pub enum NotifyCommand {
    /// Hand Ferryman a notice for the operator. `info` goes into the day's digest; `act`
    /// and `urgent` go to the operator's chat once, and a new state for the same subject
    /// updates the message already sent.
    Send {
        /// Who is telling: `gpu-queue`, `reports/nightly`.
        #[arg(long)]
        source: String,
        /// What it is about, the same every time: `card`, `order 42`.
        #[arg(long)]
        subject: String,
        /// Where it stands now: `waiting`, `failed`, `done`.
        #[arg(long)]
        state: String,
        /// info, act or urgent.
        #[arg(long, default_value = "info")]
        level: String,
        /// One line for a person.
        #[arg(long)]
        text: String,
    },
    /// What each source handed in and what became of it, and today's digest.
    Status,
}

/// `ferry notify ...`.
///
/// # Errors
/// No machine state directory, an invalid notice, or the inbox could not be written.
pub fn command(command: NotifyCommand) -> Result<()> {
    let dir = notices::dir().context("no per-user state directory on this machine")?;
    match command {
        NotifyCommand::Send {
            source,
            subject,
            state,
            level,
            text,
        } => {
            let notice = Notice {
                source,
                subject,
                state,
                level: Level::parse(&level)?,
                text,
                at: Utc::now(),
            };
            notices::submit(&dir, &notice)?;
            println!(
                "handed in ({}); the worker decides on its next pass whether it goes out",
                notice.level.as_str()
            );
        }
        NotifyCommand::Status => {
            let ledger = Ledger::load(&dir);
            let chat = Chat::from_root(root().as_deref());
            println!(
                "operator chat: {}",
                if chat.is_some() {
                    "Telegram"
                } else {
                    "none set up (TELEGRAM_BOT_TOKEN and a chat id): everything goes to the digest"
                }
            );
            if ledger.sources.is_empty() {
                println!("no notices yet");
            }
            for (source, count) in &ledger.sources {
                println!(
                    "{source}: {} handed in, {} sent, {} updated, {} to the digest, {} repeats dropped",
                    count.received, count.sent, count.updated, count.digest, count.repeats
                );
            }
            let today = notices::read_digest(&dir, Utc::now().date_naive());
            println!("today's digest: {} line(s)", today.len());
            for notice in today.iter().rev().take(10) {
                println!("  {} {}", notice.at.format("%H:%M"), notice.line());
            }
        }
    }
    Ok(())
}

fn root() -> Option<PathBuf> {
    ferryman_channel::ferry::find_root().map(|root| root.path)
}

/// The operator's chat.
struct Chat {
    http: reqwest::Client,
    token: String,
    chat: i64,
}

impl Chat {
    fn from_root(root: Option<&Path>) -> Option<Self> {
        let env_file = root.map(|root| root.join("secrets").join(".env"));
        let get = |name: &str| setting(name, env_file.as_deref());
        let token = get("TELEGRAM_BOT_TOKEN")?;
        let chat = get("TELEGRAM_CHAT_ID")
            .or_else(|| get("TELEGRAM_APPROVERS"))
            .or_else(|| get("TELEGRAM_APPROVER_ID"))?
            .split(',')
            .find_map(|id| id.trim().parse::<i64>().ok())?;
        let http = reqwest::Client::builder()
            .timeout(Duration::from_secs(20))
            .build()
            .ok()?;
        Some(Self { http, token, chat })
    }

    async fn call(&self, method: &str, body: &Value) -> Result<Value> {
        let reply: Value = self
            .http
            .post(format!(
                "https://api.telegram.org/bot{}/{method}",
                self.token
            ))
            .json(body)
            .send()
            .await
            // The URL holds the token: never into an error.
            .map_err(|e| anyhow::anyhow!("telegram {method}: {}", e.without_url()))?
            .json()
            .await
            .map_err(|e| anyhow::anyhow!("telegram {method}: {}", e.without_url()))?;
        if reply["ok"] != true {
            anyhow::bail!(
                "telegram {method}: {}",
                reply["description"].as_str().unwrap_or("refused")
            );
        }
        Ok(reply["result"].clone())
    }

    async fn send(&self, text: &str) -> Result<i64> {
        let result = self
            .call(
                "sendMessage",
                &json!({ "chat_id": self.chat, "text": text, "disable_web_page_preview": true }),
            )
            .await?;
        result["message_id"]
            .as_i64()
            .context("telegram sendMessage: no message id")
    }

    async fn update(&self, message: i64, text: &str) -> Result<()> {
        self.call(
            "editMessageText",
            &json!({ "chat_id": self.chat, "message_id": message, "text": text }),
        )
        .await
        .map(|_| ())
    }
}

/// `name` from the environment, else a `NAME=value` line in `env_file`.
fn setting(name: &str, env_file: Option<&Path>) -> Option<String> {
    if let Ok(value) = std::env::var(name)
        && !value.trim().is_empty()
    {
        return Some(value.trim().to_string());
    }
    let text = std::fs::read_to_string(env_file?).ok()?;
    text.lines().find_map(|line| {
        let line = line.trim_start_matches('\u{feff}').trim();
        let (key, value) = line.split_once('=')?;
        (key.trim() == name)
            .then(|| {
                value
                    .trim()
                    .trim_matches('"')
                    .trim_matches('\'')
                    .to_string()
            })
            .filter(|value| !value.is_empty())
    })
}

/// The worker's notices pass: at most every 30 seconds, take what was handed in and
/// deliver what the rules say. Never a reason for the worker to stop.
pub struct NoticesPass {
    dir: PathBuf,
    rules: Rules,
    chat: Option<Chat>,
    last: Option<Instant>,
}

impl NoticesPass {
    pub fn for_worker(report: &impl Progress) -> Option<Self> {
        let dir = notices::dir()?;
        let root = root();
        let chat = Chat::from_root(root.as_deref());
        if chat.is_none() {
            report.info(
                "notices: no operator chat set up (TELEGRAM_BOT_TOKEN and a chat id); notices go to the digest",
            );
        }
        Some(Self {
            dir,
            rules: root.as_deref().map(Rules::load).unwrap_or_default(),
            chat,
            last: None,
        })
    }

    pub async fn pass(&mut self, report: &impl Progress) {
        if self
            .last
            .is_some_and(|at| at.elapsed() < Duration::from_secs(30))
        {
            return;
        }
        self.last = Some(Instant::now());
        let (taken, bad) = notices::take_inbox(&self.dir);
        for path in bad {
            report.warn(&format!("notices: dropped {path}: not a notice"));
        }
        if taken.is_empty() {
            return;
        }
        let mut ledger = Ledger::load(&self.dir);
        for notice in taken {
            let now = Utc::now();
            let action = ledger.decide(&notice, &self.rules, now);
            let delivered = match (&action, &self.chat) {
                (Action::Repeat, _) => continue,
                (Action::Digest, _) | (_, None) => {
                    if let Err(error) = notices::append_digest(&self.dir, &notice) {
                        report.warn(&format!("notices: digest not written: {error:#}"));
                    }
                    continue;
                }
                (Action::Send { text }, Some(chat)) => chat.send(text).await.map(Some),
                (Action::Update { message, text }, Some(chat)) => {
                    match chat.update(*message, text).await {
                        Ok(()) => Ok(None),
                        // Too old to edit, or deleted: say it fresh.
                        Err(_) => chat.send(text).await.map(Some),
                    }
                }
            };
            match delivered {
                Ok(message) => ledger.sent(&notice, message, now),
                Err(error) => {
                    report.warn(&format!(
                        "notices: {} not delivered ({error:#}); kept in the digest",
                        notice.source
                    ));
                    let _ = notices::append_digest(&self.dir, &notice);
                }
            }
        }
        if let Err(error) = ledger.save(&self.dir) {
            report.warn(&format!("notices: ledger not saved: {error:#}"));
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[tokio::test]
    async fn with_no_chat_set_up_everything_lands_in_the_digest() {
        let dir = tempfile::tempdir().unwrap();
        let mut pass = NoticesPass {
            dir: dir.path().to_path_buf(),
            rules: Rules::default(),
            chat: None,
            last: None,
        };
        let notice = Notice {
            source: "renders".into(),
            subject: "batch 7".into(),
            state: "failed".into(),
            level: Level::Act,
            text: "batch 7 failed: disk full".into(),
            at: Utc::now(),
        };
        notices::submit(dir.path(), &notice).unwrap();
        pass.pass(&ferryman_ops::Silent).await;
        assert_eq!(
            notices::read_digest(dir.path(), notice.at.date_naive()),
            vec![notice]
        );
        assert_eq!(Ledger::load(dir.path()).sources["renders"].received, 1);
        assert!(notices::take_inbox(dir.path()).0.is_empty());
    }

    #[test]
    fn the_chat_comes_from_the_secrets_file() {
        let dir = tempfile::tempdir().unwrap();
        std::fs::create_dir_all(dir.path().join("secrets")).unwrap();
        // Names only this test uses, so the real environment cannot answer for the file.
        let file = dir.path().join("secrets").join(".env");
        std::fs::write(
            &file,
            "\u{feff}FM_TEST_NOTIFY_TOKEN=\"abc\"\nFM_TEST_NOTIFY_IDS= 12, 34\n",
        )
        .unwrap();
        assert_eq!(
            setting("FM_TEST_NOTIFY_TOKEN", Some(&file)).as_deref(),
            Some("abc")
        );
        assert_eq!(
            setting("FM_TEST_NOTIFY_IDS", Some(&file)).as_deref(),
            Some("12, 34")
        );
        assert!(setting("FM_TEST_NOTIFY_NONE", Some(&file)).is_none());
    }
}
