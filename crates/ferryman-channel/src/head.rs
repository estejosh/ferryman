//! Who the head agent is, in the master's own words.
//!
//! The master says it the way they say anything - "grouchly, you're head agent for now" -
//! in the dashboard or in a message. What makes it an appointment is that the words are
//! signed by the project's master and name the agent. The agent records that it heard them
//! by claiming: `head/<agent>.json` carries the master's signed words whole, so every
//! machine can check them without trusting the agent that wrote the file. The newest words
//! win, so "for now" ends when the master names someone else.
//!
//! The trade, made on purpose: the words are not parsed. Any statement of the master's that
//! names an agent can back a claim, so an agent that wanted to could claim on "thanks,
//! grouchly". Every claim carries the words it rests on for anyone to read, the master can
//! revoke it from the dashboard, and naming someone else supersedes it.

use std::{fs, path::Path};

use anyhow::{Context, Result, bail};
use chrono::{DateTime, Duration, Utc};
use ed25519_dalek::Signer;
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};

use crate::{AgentIdentity, AgentRoute, Message, SignatureCheck};

/// How far back `claim` looks for the master's words when it is not told which ones.
const LOOKBACK_DAYS: i64 = 7;

/// Something a person said, signed by them: one statement per file under `said/`.
///
/// A conversation is signed as a whole file by whoever wrote to it last - often the bridge,
/// on the person's behalf - so one turn inside it proves nothing about who said it. The
/// dashboard holds the person's unlocked key, so it signs each turn on its own as well.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct Said {
    pub id: String,
    pub project_id: String,
    pub who: String,
    pub said: String,
    pub at: DateTime<Utc>,
    pub signature: String,
}

fn said_payload(said: &Said) -> String {
    format!(
        "ferryman-said-v1\n{}\n{}\n{}\n{}\n{}",
        said.id,
        said.project_id,
        said.who,
        said.at.to_rfc3339(),
        said.said
    )
}

/// Keep a signed copy of one thing a person said, where every agent can read it.
pub fn record_said(
    channel: &Path,
    project_id: &str,
    person: &AgentIdentity,
    said: &str,
) -> Result<Said> {
    let mut record = Said {
        id: uuid::Uuid::new_v4().to_string(),
        project_id: project_id.to_owned(),
        who: person.name().to_owned(),
        said: said.to_owned(),
        at: Utc::now(),
        signature: String::new(),
    };
    record.signature = hex::encode(
        person
            .signing
            .sign(said_payload(&record).as_bytes())
            .to_bytes(),
    );
    let dir = channel.join("said");
    fs::create_dir_all(&dir)?;
    crate::atomic_json(&dir.join(format!("{}.json", record.id)), &record)?;
    Ok(record)
}

/// The words an appointment rests on.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
#[serde(tag = "kind", rename_all = "snake_case")]
pub enum Order {
    Said(Said),
    Message(Box<Message>),
}

impl Order {
    #[must_use]
    pub fn id(&self) -> &str {
        match self {
            Self::Said(said) => &said.id,
            Self::Message(message) => &message.id,
        }
    }

    #[must_use]
    pub fn at(&self) -> DateTime<Utc> {
        match self {
            Self::Said(said) => said.at,
            Self::Message(message) => message.created_at,
        }
    }

    /// Who said it, as signed.
    #[must_use]
    pub fn by(&self) -> Option<&str> {
        match self {
            Self::Said(said) => Some(&said.who),
            Self::Message(message) => message.signed_by.as_deref(),
        }
    }

    /// The words themselves, for a person to read.
    #[must_use]
    pub fn words(&self) -> String {
        match self {
            Self::Said(said) => said.said.clone(),
            Self::Message(message) => match &message.payload {
                serde_json::Value::String(text) => text.clone(),
                payload => ["text", "body", "message"]
                    .iter()
                    .find_map(|key| payload.get(key).and_then(|v| v.as_str()))
                    .map_or_else(|| payload.to_string(), str::to_owned),
            },
        }
    }

    fn project_id(&self) -> &str {
        match self {
            Self::Said(said) => &said.project_id,
            Self::Message(message) => &message.project_id,
        }
    }

    /// Signed by `master`, by the key the channel knows them by, for this project.
    fn is_the_masters(&self, master: &str, project_id: &str, roster: &[AgentRoute]) -> bool {
        if self.project_id() != project_id
            || !self.by().is_some_and(|by| by.eq_ignore_ascii_case(master))
        {
            return false;
        }
        let check = match self {
            Self::Said(said) => crate::check_signature(
                Some(&said.who),
                Some(&said.signature),
                &said_payload(said),
                roster,
            ),
            Self::Message(message) => crate::verify_message(message, roster),
        };
        check == SignatureCheck::Valid
    }

    /// Whether these words are about `agent`: addressed to it, or naming it.
    fn names(&self, agent: &str) -> bool {
        if let Self::Message(message) = self
            && message.recipient.eq_ignore_ascii_case(agent)
        {
            return true;
        }
        mentions(&self.words(), agent)
    }
}

/// Whether `name` appears in `text` as a word of its own.
fn mentions(text: &str, name: &str) -> bool {
    text.split(|c: char| !(c.is_alphanumeric() || c == '-' || c == '_'))
        .any(|word| word.eq_ignore_ascii_case(name))
}
/// An appointment: the master's words, carried whole by the agent they named.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
pub struct Head {
    pub project_id: String,
    pub agent: String,
    pub claimed_at: DateTime<Utc>,
    pub order: Order,
    /// The agent's signature: it heard the words and took the role.
    pub signature: String,
}

fn head_payload(head: &Head) -> String {
    let order = serde_json::to_vec(&head.order).unwrap_or_default();
    format!(
        "ferryman-head-v1\n{}\n{}\n{}\n{}",
        head.project_id,
        head.agent,
        head.claimed_at.to_rfc3339(),
        hex::encode(Sha256::digest(&order))
    )
}

fn holds(head: &Head, project_id: &str, master: &str, roster: &[AgentRoute]) -> bool {
    head.project_id == project_id
        && head.order.is_the_masters(master, project_id, roster)
        && head.order.names(&head.agent)
        && crate::check_signature(
            Some(&head.agent),
            Some(&head.signature),
            &head_payload(head),
            roster,
        ) == SignatureCheck::Valid
}

fn master_of(channel: &Path, project_id: &str) -> Result<Option<(String, Vec<AgentRoute>)>> {
    let roster = crate::read_agent_roster(channel)?;
    Ok(crate::master::read_master_at(channel, &roster)?
        .filter(|declaration| declaration.project_id == project_id)
        .map(|declaration| (declaration.master, roster)))
}

/// The head agent of this project: the newest appointment that checks out, if any.
///
/// Anything that does not check out - not the master's words, not naming the agent, not
/// signed by it - is passed over as though it were not there.
pub fn current(channel: &Path, project_id: &str) -> Result<Option<Head>> {
    let dir = channel.join("head");
    if !dir.is_dir() {
        return Ok(None);
    }
    let Some((master, roster)) = master_of(channel, project_id)? else {
        return Ok(None);
    };
    let mut best: Option<Head> = None;
    for entry in fs::read_dir(&dir)?.flatten() {
        let path = entry.path();
        if path.extension().is_none_or(|ext| ext != "json") {
            continue;
        }
        let Ok(head) = serde_json::from_slice::<Head>(&fs::read(&path)?) else {
            continue;
        };
        if holds(&head, project_id, &master, &roster)
            && best
                .as_ref()
                .is_none_or(|best| head.order.at() > best.order.at())
        {
            best = Some(head);
        }
    }
    Ok(best)
}

fn json_files(dir: &Path) -> Vec<Vec<u8>> {
    fs::read_dir(dir)
        .map(|entries| {
            entries
                .flatten()
                .map(|entry| entry.path())
                .filter(|path| path.extension().is_some_and(|ext| ext == "json"))
                .filter_map(|path| fs::read(path).ok())
                .collect()
        })
        .unwrap_or_default()
}

/// Every statement and message in the channel that could back a claim.
fn orders(channel: &Path, project_id: &str) -> Vec<Order> {
    let said = json_files(&channel.join("said"))
        .into_iter()
        .filter_map(|bytes| serde_json::from_slice::<Said>(&bytes).ok())
        .map(Order::Said);
    let messages = json_files(&channel.join("messages").join(project_id))
        .into_iter()
        .filter_map(|bytes| serde_json::from_slice::<Message>(&bytes).ok())
        .map(|message| Order::Message(Box::new(message)));
    said.chain(messages).collect()
}

/// Take the role the master gave this agent.
///
/// With no `order_id`, the newest words of the master's from the last week that name this
/// agent. With one, exactly those words - a `said/` statement or a message id.
pub fn claim(
    channel: &Path,
    project_id: &str,
    agent: &AgentIdentity,
    order_id: Option<&str>,
) -> Result<Head> {
    let Some((master, roster)) = master_of(channel, project_id)? else {
        bail!(
            "{project_id} has no master, so nobody can name a head agent. The master claims it \
             with `ferry root master`, or by opening the dashboard."
        );
    };
    let name = agent.name();
    let candidates = orders(channel, project_id);
    let order = match order_id {
        Some(id) => candidates
            .into_iter()
            .find(|order| order.id() == id)
            .with_context(|| format!("no statement or message '{id}' in {project_id}'s channel"))?,
        None => candidates
            .into_iter()
            .filter(|order| {
                order.at() > Utc::now() - Duration::days(LOOKBACK_DAYS)
                    && order.is_the_masters(&master, project_id, &roster)
                    && order.names(name)
            })
            .max_by_key(Order::at)
            .with_context(|| {
                format!(
                    "{master} has not named {name} in anything signed in the last \
                     {LOOKBACK_DAYS} days, so there is nothing to claim on"
                )
            })?,
    };
    if !order.is_the_masters(&master, project_id, &roster) {
        bail!("those words were not signed by {master}, {project_id}'s master");
    }
    if !order.names(name) {
        bail!("those words do not name {name}");
    }
    let mut head = Head {
        project_id: project_id.to_owned(),
        agent: name.to_owned(),
        claimed_at: Utc::now(),
        order,
        signature: String::new(),
    };
    head.signature = hex::encode(
        agent
            .signing
            .sign(head_payload(&head).as_bytes())
            .to_bytes(),
    );
    if !holds(&head, project_id, &master, &roster) {
        bail!(
            "{name}'s key is not the one {project_id}'s channel knows it by, so no machine \
             would honour this claim"
        );
    }
    let dir = channel.join("head");
    fs::create_dir_all(&dir)?;
    crate::atomic_json(
        &dir.join(format!("{}.json", crate::canonical_agent_name(name))),
        &head,
    )?;
    Ok(head)
}

/// Give the role up. Returns whether there was anything to give up.
pub fn step_down(channel: &Path, agent: &str) -> Result<bool> {
    let path = channel
        .join("head")
        .join(format!("{}.json", crate::canonical_agent_name(agent)));
    if !path.is_file() {
        return Ok(false);
    }
    fs::remove_file(&path).with_context(|| format!("removing {}", path.display()))?;
    Ok(true)
}

/// Clear every appointment in the channel: the master's revoke. Returns how many went.
pub fn revoke_all(channel: &Path) -> Result<usize> {
    let dir = channel.join("head");
    if !dir.is_dir() {
        return Ok(0);
    }
    let mut removed = 0;
    for entry in fs::read_dir(&dir)?.flatten() {
        let path = entry.path();
        if path.extension().is_some_and(|ext| ext == "json") {
            fs::remove_file(&path)?;
            removed += 1;
        }
    }
    Ok(removed)
}
#[cfg(test)]
mod tests {
    use super::*;

    struct Fleet {
        _dir: tempfile::TempDir,
        channel: std::path::PathBuf,
        josh: AgentIdentity,
        grouchly: AgentIdentity,
        beastly: AgentIdentity,
    }

    /// A channel whose master is josh, with two agents on the roster.
    fn fleet() -> Fleet {
        let dir = tempfile::tempdir().unwrap();
        crate::licensing::use_machine_state_dir_per_thread(dir.path().join("state"));
        let channel = dir.path().join("comms").join("proj-ferryman");
        fs::create_dir_all(&channel).unwrap();
        let josh = AgentIdentity::from_seed("josh", [7u8; 32]);
        let grouchly = AgentIdentity::from_seed("grouchly", [8u8; 32]);
        let beastly = AgentIdentity::from_seed("beastly", [9u8; 32]);
        let mut route = crate::ProjectRoute {
            project_id: "proj".into(),
            workspace: dir.path().join("proj"),
            attachment: dir.path().join("attachment"),
            communications: channel.clone(),
            shared_remote: "proj-ferryman".into(),
            git_remote: String::new(),
            git_visibility: String::new(),
            agents: Vec::new(),
        };
        for member in [&josh, &grouchly, &beastly] {
            let agent = AgentRoute {
                name: member.name().into(),
                role: "worker".into(),
                capabilities: Vec::new(),
                public_key: Some(member.public_key_hex()),
                encryption_key: None,
            };
            crate::register_agent(&route, &agent).unwrap();
            route.agents.push(agent);
        }
        crate::master::initialize_master(&route, &josh, "josh").unwrap();
        Fleet {
            _dir: dir,
            channel,
            josh,
            grouchly,
            beastly,
        }
    }

    fn head_of(fleet: &Fleet) -> Option<String> {
        current(&fleet.channel, "proj")
            .unwrap()
            .map(|head| head.agent)
    }

    /// Said in plain words, claimed by the agent named, seen by everyone.
    #[test]
    fn the_master_names_a_head_in_plain_words_and_it_holds() {
        let fleet = fleet();
        assert_eq!(head_of(&fleet), None);
        record_said(
            &fleet.channel,
            "proj",
            &fleet.josh,
            "grouchly, you're head agent for now",
        )
        .unwrap();

        let head = claim(&fleet.channel, "proj", &fleet.grouchly, None).unwrap();
        assert_eq!(head.order.words(), "grouchly, you're head agent for now");
        assert_eq!(head_of(&fleet).as_deref(), Some("grouchly"));
    }

    /// "For now" ends when the master names someone else.
    #[test]
    fn newer_words_replace_the_head() {
        let fleet = fleet();
        record_said(&fleet.channel, "proj", &fleet.josh, "grouchly is head").unwrap();
        claim(&fleet.channel, "proj", &fleet.grouchly, None).unwrap();
        std::thread::sleep(std::time::Duration::from_millis(20));
        record_said(
            &fleet.channel,
            "proj",
            &fleet.josh,
            "beastly, take over as head agent",
        )
        .unwrap();
        claim(&fleet.channel, "proj", &fleet.beastly, None).unwrap();
        assert_eq!(head_of(&fleet).as_deref(), Some("beastly"));
    }

    /// Nobody claims on words that do not name them, or that the master did not say.
    #[test]
    fn only_the_masters_words_naming_you_count() {
        let fleet = fleet();
        record_said(
            &fleet.channel,
            "proj",
            &fleet.josh,
            "grouchly, you're head agent",
        )
        .unwrap();
        let error = claim(&fleet.channel, "proj", &fleet.beastly, None)
            .expect_err("beastly was not named")
            .to_string();
        assert!(error.contains("has not named beastly"), "{error}");

        record_said(
            &fleet.channel,
            "proj",
            &fleet.beastly,
            "beastly is head agent now",
        )
        .unwrap();
        assert!(
            claim(&fleet.channel, "proj", &fleet.beastly, None).is_err(),
            "an agent naming itself is not the master naming it"
        );
        assert_eq!(head_of(&fleet), None);
    }

    /// A file written by hand, re-using the master's words for someone they did not name,
    /// is passed over by every reader.
    #[test]
    fn a_planted_appointment_is_ignored() {
        let fleet = fleet();
        record_said(&fleet.channel, "proj", &fleet.josh, "grouchly leads").unwrap();
        let real = claim(&fleet.channel, "proj", &fleet.grouchly, None).unwrap();
        let mut planted = Head {
            agent: "beastly".into(),
            claimed_at: Utc::now() + Duration::days(1),
            signature: String::new(),
            ..real
        };
        planted.signature = hex::encode(
            fleet
                .beastly
                .signing
                .sign(head_payload(&planted).as_bytes())
                .to_bytes(),
        );
        crate::atomic_json(&fleet.channel.join("head").join("beastly.json"), &planted).unwrap();
        assert_eq!(head_of(&fleet).as_deref(), Some("grouchly"));
    }

    /// A signed message addressed to the agent is words enough, whatever it says.
    #[test]
    fn a_message_to_the_agent_can_name_it() {
        let fleet = fleet();
        let mut message = Message::new(
            "proj",
            "josh",
            "grouchly",
            "text/plain",
            serde_json::json!({ "text": "you're head agent for now" }),
            false,
            None,
        );
        fleet.josh.sign(&mut message);
        let dir = fleet.channel.join("messages").join("proj");
        fs::create_dir_all(&dir).unwrap();
        crate::atomic_json(&dir.join(format!("{}.json", message.id)), &message).unwrap();

        claim(&fleet.channel, "proj", &fleet.grouchly, Some(&message.id)).unwrap();
        assert_eq!(head_of(&fleet).as_deref(), Some("grouchly"));
    }

    #[test]
    fn stepping_down_and_revoking_clear_it() {
        let fleet = fleet();
        record_said(&fleet.channel, "proj", &fleet.josh, "grouchly is head").unwrap();
        claim(&fleet.channel, "proj", &fleet.grouchly, None).unwrap();
        assert!(step_down(&fleet.channel, "grouchly").unwrap());
        assert_eq!(head_of(&fleet), None);

        claim(&fleet.channel, "proj", &fleet.grouchly, None).unwrap();
        assert_eq!(revoke_all(&fleet.channel).unwrap(), 1);
        assert_eq!(head_of(&fleet), None);
    }
}
