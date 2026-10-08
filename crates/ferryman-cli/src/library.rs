//! `ferry remember`, `ferry ask --library` and `ferry library ...`: the fleet's memory and
//! front desk.
//!
//! See [`ferryman_channel::library`]. The library lives in the home project's channel (the
//! same one the focus lives in) and reaches every machine by sync. Anyone on the roster may
//! write a fact; it is unconfirmed until the master confirms it. Confirm, retract and the
//! mail tag map are the master's. Nothing here stores a secret: a fact that looks like one
//! is refused, and the message says to store a pointer.

use std::io::Read;
use std::path::PathBuf;

use anyhow::{Context, Result, bail};
use chrono::Utc;
use ferryman_channel::library::ask::{self as lask, Found};
use ferryman_channel::library::mail;
use ferryman_channel::library::{self, Fact, Library, NewFact, Status, store, views};
use ferryman_channel::{AgentIdentity, ProjectRoute};
use ferryman_ops::agent::AgentConfig;
use ferryman_ops::library::{self as ops, Reader};
use serde_json::{Value, json};

use super::signing_identity_in;

#[derive(clap::Subcommand, Clone)]
pub(crate) enum LibraryCommand {
    /// What the library holds: facts by standing, what waits for the master, contradictions,
    /// the mail tag map, and a warning when this machine is holding on to an earlier copy.
    Show {
        #[arg(long)]
        json: bool,
    },
    /// Find facts (and generated rows) by the words of a question. No model; full-text.
    Search {
        query: String,
        /// Only this project's facts and the fleet-wide ones.
        #[arg(long)]
        project: Option<String>,
        #[arg(long, default_value_t = 10)]
        limit: usize,
        #[arg(long)]
        json: bool,
    },
    /// Ask a question: the best facts, put in words by a cheap model with no tools, citing
    /// fact ids and dates; "I don't know" when the library has nothing. Same as `ferry ask
    /// --library`.
    Ask {
        question: String,
        #[arg(long)]
        project: Option<String>,
        /// Return the matching facts only; ask no model.
        #[arg(long)]
        no_model: bool,
        #[arg(long)]
        json: bool,
    },
    /// One fact, with who wrote it, its standing and its chain of replacements.
    Fact {
        id: String,
        #[arg(long)]
        json: bool,
    },
    /// Confirm a fact, signed as the master: it is true. Master only.
    Confirm { id: String },
    /// Retract a fact, signed as the master: it stays in the history and is no longer an
    /// answer. Master only.
    Retract {
        id: String,
        #[arg(long)]
        reason: Option<String>,
    },
    /// Everything ever said about a subject, oldest first: replaced and retracted too.
    History {
        subject: String,
        #[arg(long)]
        json: bool,
    },
    /// The generated pages (machines, engines, projects, inboxes, where each secret lives).
    /// `--refresh` regenerates them from this machine's live state and signs them.
    Views {
        #[arg(long)]
        refresh: bool,
        #[arg(long)]
        json: bool,
    },
    /// The mail tag map: which subject tag (`[REDAKTLY]`) goes to which project. Master only
    /// to change.
    Tags {
        #[command(subcommand)]
        command: TagsCommand,
    },
    /// The shared agent inbox: take in mail n8n dropped, see the queue, see the replies.
    Mail {
        #[command(subcommand)]
        command: MailCommand,
    },
    /// Run the librarian's loop here: refresh the views, put contradictions to the master and
    /// run the mail desk. The same step the worker loop takes with FERRYMAN_LIBRARIAN=1.
    Serve {
        /// One pass and stop.
        #[arg(long)]
        once: bool,
        /// Seconds between passes.
        #[arg(long, default_value_t = 60)]
        interval: u64,
    },
}

#[derive(clap::Subcommand, Clone)]
pub(crate) enum TagsCommand {
    Show {
        #[arg(long)]
        json: bool,
    },
    /// Route `[TAG]` in a subject to a project.
    Set {
        tag: String,
        project: String,
    },
    Remove {
        tag: String,
    },
}

#[derive(clap::Subcommand, Clone)]
pub(crate) enum MailCommand {
    /// Check a mail file (JSON: message_id, thread_id, from, subject, text, html) and put it
    /// in the desk's `in/` folder for the librarian. `-` reads stdin. Nothing in the file is
    /// believed; a bad one is refused and not kept.
    Ingest {
        #[arg(long)]
        file: String,
    },
    /// Every mail on the desk, and what the master has been asked.
    Queue {
        #[arg(long)]
        json: bool,
    },
    /// The replies waiting for n8n to send.
    Outbox {
        #[arg(long)]
        json: bool,
    },
    /// Say a reply was sent (what n8n does by writing `ack/<reply id>`).
    Ack { reply: String },
    /// Run the desk once, now.
    Run,
}

/// What `ferry remember` takes.
#[derive(clap::Args, Clone)]
pub(crate) struct RememberArgs {
    /// The fact, in a sentence or two (at most 1000 characters). Never a secret: write where
    /// it lives instead ("NVIDIA key: Custodly, name nvidiaapi").
    pub text: String,
    /// What it is about. Defaults to the first words of the text.
    #[arg(long)]
    pub subject: Option<String>,
    /// The project it is about; leave off for a fleet-wide fact.
    #[arg(long)]
    pub project: Option<String>,
    /// Tags, comma separated.
    #[arg(long, value_delimiter = ',')]
    pub tags: Vec<String>,
    /// The fact this one replaces. A fact is never edited: say the new thing and name the old.
    #[arg(long, value_delimiter = ',')]
    pub supersedes: Vec<String>,
    /// Where it came from, in your words.
    #[arg(long)]
    pub source: Option<String>,
    /// Sign as this identity (the master's name makes the fact confirmed). By default: this
    /// machine's own agent, whose facts wait for the master.
    #[arg(long = "as")]
    pub as_name: Option<String>,
    #[arg(long)]
    pub json: bool,
}

// --- the home ----------------------------------------------------------------------------

#[cfg(test)]
thread_local! {
    /// Tests name the home project themselves: the real one is found through a ferry root,
    /// and a test must not touch the machine's.
    pub(crate) static TEST_HOME: std::cell::RefCell<Option<library::Home>> =
        const { std::cell::RefCell::new(None) };
}

fn home() -> Result<library::Home> {
    #[cfg(test)]
    if let Some(home) = TEST_HOME.with(|home| home.borrow().clone()) {
        return Ok(home);
    }
    library::home()
}

fn load(home: &library::Home) -> Library {
    Library::load(&home.channel, &home.project)
}

/// The master's identity on this machine, for the actions only the master takes.
fn master_identity(home: &library::Home) -> Result<(String, AgentIdentity)> {
    let Some(master) = ferryman_channel::ferry::master_of(&home.channel)? else {
        bail!(
            "{} has no master, and only its master does that.\n\n\
             Claim every project that has none:  ferry root master",
            home.project
        );
    };
    let identity = signing_identity_in(&home.attachment, &master)?;
    Ok((master, identity))
}

/// Who a fact is signed by: `--as`, else this machine's own agent.
fn author_identity(home: &library::Home, as_name: Option<&str>) -> Result<AgentIdentity> {
    let name = match as_name {
        Some(name) => name.to_string(),
        None => AgentConfig::load(&home.attachment)
            .map(|config| config.agent)
            .context(
                "this machine has no worker identity to sign as: say who you are with --as <name>",
            )?,
    };
    signing_identity_in(&home.attachment, &name)
}

fn config_for(home: &library::Home) -> Result<AgentConfig> {
    AgentConfig::load(&home.attachment).context("this machine has no worker configuration")
}

// --- showing -----------------------------------------------------------------------------

fn when(fact: &Fact) -> String {
    fact.created_at.format("%Y-%m-%d").to_string()
}

fn print_fact(fact: &Fact) {
    let mark = match fact.status {
        Status::Confirmed => String::new(),
        Status::Unconfirmed => " (UNCONFIRMED: waits for the master)".to_string(),
        Status::Retracted => format!(" (RETRACTED{})", {
            if fact.retract_reason.is_empty() {
                String::new()
            } else {
                format!(": {}", fact.retract_reason)
            }
        }),
        Status::Generated => String::new(),
    };
    let replaced = if fact.superseded_by.is_empty() {
        String::new()
    } else {
        format!(" (replaced by {})", fact.superseded_by.join(", "))
    };
    println!(
        "{} {} [{}] {}{mark}{replaced}",
        fact.id,
        when(fact),
        fact.written_by(),
        fact.subject
    );
    println!("    {}", fact.text);
    if fact.project.is_some() || !fact.tags.is_empty() {
        println!(
            "    project: {}  tags: {}",
            fact.project.as_deref().unwrap_or("-"),
            if fact.tags.is_empty() {
                "-".to_string()
            } else {
                fact.tags.join(", ")
            }
        );
    }
}

fn print_found(found: &[Found]) {
    for fact in found {
        print!("{}", lask::render_fact(fact));
    }
}

fn show(as_json: bool) -> Result<()> {
    let home = home()?;
    let library = load(&home);
    let (confirmed, unconfirmed, retracted, replaced) = library.counts();
    let conflicts = library.conflicts();
    if as_json {
        println!(
            "{}",
            serde_json::to_string_pretty(&json!({
                "home": library.home,
                "master": library.master,
                "confirmed": confirmed,
                "unconfirmed": unconfirmed,
                "retracted": retracted,
                "replaced": replaced,
                "waiting": library.unconfirmed().collect::<Vec<_>>(),
                "conflicts": conflicts,
                "tag_map": library.tag_map,
                "notices": library.notices,
                "rejected": library.rejected,
            }))?
        );
        return Ok(());
    }
    println!(
        "library in {}'s channel (master {}): {confirmed} confirmed, {unconfirmed} waiting for \
         the master, {replaced} replaced, {retracted} retracted",
        library.home,
        library.master.as_deref().unwrap_or("none yet")
    );
    for notice in &library.notices {
        println!("  warning: {notice}");
    }
    if !library.notices.is_empty() {
        println!("  this machine is using what it saw before; the master can settle it");
    }
    for reason in &library.rejected {
        println!("  not believed: {reason}");
    }
    for fact in library.unconfirmed() {
        print_fact(fact);
    }
    if unconfirmed == 0 {
        println!("  nothing waits for the master");
    } else {
        println!("  to settle: ferry library confirm <id> | ferry library retract <id>");
    }
    for conflict in &conflicts {
        println!(
            "  contradiction about \"{}\": {}",
            conflict.subject,
            conflict.facts.join(" vs ")
        );
    }
    if !library.tag_map.map.is_empty() {
        let tags: Vec<String> = library
            .tag_map
            .map
            .iter()
            .map(|(tag, project)| format!("[{tag}] -> {project}"))
            .collect();
        println!("  mail tags: {}", tags.join(", "));
    }
    Ok(())
}

fn search(query: &str, project: Option<&str>, limit: usize, as_json: bool) -> Result<()> {
    let home = home()?;
    let reader = Reader::load(&home.channel, &home.project);
    let found = reader.search(query, project, limit.clamp(1, 50));
    if as_json {
        println!("{}", serde_json::to_string_pretty(&found)?);
    } else if found.is_empty() {
        println!("{}", lask::DONT_KNOW);
    } else {
        print_found(&found);
    }
    Ok(())
}

pub(crate) async fn ask(
    question: &str,
    project: Option<&str>,
    no_model: bool,
    as_json: bool,
) -> Result<()> {
    let home = home()?;
    let reader = Reader::load(&home.channel, &home.project);
    let answer = match (no_model, config_for(&home)) {
        (false, Ok(config)) => {
            ops::ask_live(&home.route(), &config, &reader, question, project, false).await
        }
        _ => ops::facts_only(&reader, question, project),
    };
    if as_json {
        println!("{}", serde_json::to_string_pretty(&answer)?);
    } else {
        print!("{}", lask::render(&answer));
    }
    Ok(())
}

fn fact_detail(id: &str, as_json: bool) -> Result<()> {
    let home = home()?;
    let library = load(&home);
    let Some(fact) = library.fact(id) else {
        bail!("there is no fact {id}");
    };
    if as_json {
        println!("{}", serde_json::to_string_pretty(fact)?);
    } else {
        print_fact(fact);
        if let Some(by) = &fact.confirmed_by {
            println!(
                "    confirmed by {by}{}",
                fact.confirmed_at
                    .map_or(String::new(), |at| format!(" on {}", at.format("%Y-%m-%d")))
            );
        }
        if !fact.supersedes.is_empty() {
            println!("    replaces: {}", fact.supersedes.join(", "));
        }
        if !fact.source.is_empty() {
            println!("    source: {}", fact.source);
        }
    }
    Ok(())
}

fn history(subject: &str, as_json: bool) -> Result<()> {
    let home = home()?;
    let library = load(&home);
    let facts = library.history(subject);
    if as_json {
        println!("{}", serde_json::to_string_pretty(&facts)?);
    } else if facts.is_empty() {
        println!("nothing has been said about \"{subject}\"");
    } else {
        for fact in facts {
            print_fact(fact);
        }
    }
    Ok(())
}

// --- writing -----------------------------------------------------------------------------

pub(crate) fn remember(args: RememberArgs) -> Result<()> {
    let home = home()?;
    let identity = author_identity(&home, args.as_name.as_deref())?;
    let subject = args.subject.clone().unwrap_or_else(|| {
        args.text
            .split_whitespace()
            .take(8)
            .collect::<Vec<_>>()
            .join(" ")
    });
    let source = args.source.clone().unwrap_or_else(|| {
        format!(
            "{} via ferry remember on {}",
            identity.name(),
            store::machine_name()
        )
    });
    let written = library::remember(
        &home.channel,
        &home.project,
        &identity,
        None,
        NewFact {
            subject,
            text: args.text.clone(),
            tags: args.tags.clone(),
            project: args.project.clone(),
            source,
            supersedes: args.supersedes.clone(),
        },
    )?;
    if args.json {
        println!(
            "{}",
            serde_json::to_string_pretty(&json!({
                "id": written.event.id,
                "status": written.status.as_str(),
            }))?
        );
    } else if written.status == Status::Confirmed {
        println!(
            "remembered {} (confirmed, signed by {})",
            written.event.id,
            identity.name()
        );
    } else {
        println!(
            "remembered {} (unconfirmed: it waits for the master; they confirm it with `ferry \
             library confirm {}`)",
            written.event.id, written.event.id
        );
    }
    Ok(())
}

fn confirm(id: &str) -> Result<()> {
    let home = home()?;
    let (_, identity) = master_identity(&home)?;
    library::confirm(&home.channel, &home.project, &identity, None, id)?;
    println!("{id} confirmed");
    Ok(())
}

fn retract(id: &str, reason: Option<&str>) -> Result<()> {
    let home = home()?;
    let (_, identity) = master_identity(&home)?;
    library::retract(
        &home.channel,
        &home.project,
        &identity,
        None,
        id,
        reason.unwrap_or_default(),
    )?;
    println!("{id} retracted (it stays in the history)");
    Ok(())
}

fn tags(command: TagsCommand) -> Result<()> {
    let home = home()?;
    let library = load(&home);
    match command {
        TagsCommand::Show { json } => {
            if json {
                println!("{}", serde_json::to_string_pretty(&library.tag_map)?);
            } else if library.tag_map.map.is_empty() {
                println!(
                    "no mail tags: every mail goes to the master. Add one: ferry library tags set redaktly redaktly"
                );
            } else {
                for (tag, project) in &library.tag_map.map {
                    println!("[{tag}] -> {project}");
                }
            }
            Ok(())
        }
        TagsCommand::Set { tag, project } => {
            let mut map = library.tag_map.map.clone();
            map.insert(tag.trim().trim_matches(['[', ']']).to_lowercase(), project);
            let (_, identity) = master_identity(&home)?;
            library::set_tag_map(&home.channel, &home.project, &identity, None, map)?;
            println!("mail tag map signed");
            Ok(())
        }
        TagsCommand::Remove { tag } => {
            let mut map = library.tag_map.map.clone();
            if map
                .remove(tag.trim().trim_matches(['[', ']']).to_lowercase().as_str())
                .is_none()
            {
                bail!("no tag [{tag}] is mapped");
            }
            let (_, identity) = master_identity(&home)?;
            library::set_tag_map(&home.channel, &home.project, &identity, None, map)?;
            println!("mail tag map signed");
            Ok(())
        }
    }
}

// --- views and the mail desk -------------------------------------------------------------

fn print_views(rows: &[views::GeneratedRow]) {
    let mut last = String::new();
    for row in rows {
        if row.view != last {
            println!(
                "{} (generated {} by {} on {})",
                row.view,
                row.generated_at.format("%Y-%m-%d %H:%M UTC"),
                row.generated_by,
                row.machine
            );
            last.clone_from(&row.view);
        }
        println!("  {}: {}", row.row.id, row.row.text);
    }
}

fn views_command(refresh: bool, as_json: bool) -> Result<()> {
    let home = home()?;
    if refresh {
        let root = ferryman_channel::ferry::find_root().context("no ferry root here")?;
        let config = config_for(&home)?;
        let identity = signing_identity_in(&home.attachment, &config.agent)?;
        let focus = ferryman_channel::focus::in_force(&home.channel, &home.project);
        let generated = views::generate(&root, &focus, Utc::now());
        views::write(
            &home.channel,
            &home.project,
            &identity,
            generated,
            Utc::now(),
        )?;
        println!("views refreshed and signed by {}", identity.name());
    }
    let rows = views::read(&home.channel, &home.project);
    if as_json {
        println!("{}", serde_json::to_string_pretty(&rows)?);
    } else if rows.is_empty() {
        println!("no generated views yet: `ferry library views --refresh`, or run the librarian");
    } else {
        print_views(&rows);
    }
    Ok(())
}

fn read_input(file: &str) -> Result<Vec<u8>> {
    let mut bytes = Vec::new();
    if file == "-" {
        std::io::stdin()
            .take(mail::MAX_FILE + 1)
            .read_to_end(&mut bytes)
            .context("read the mail from stdin")?;
    } else {
        let path = PathBuf::from(file);
        if std::fs::metadata(&path)
            .context("read the mail file")?
            .len()
            > mail::MAX_FILE
        {
            bail!("refused: larger than {} bytes", mail::MAX_FILE);
        }
        bytes = std::fs::read(&path).context("read the mail file")?;
    }
    Ok(bytes)
}

async fn mail_command(command: MailCommand) -> Result<()> {
    let desk = mail::desk()?;
    match command {
        MailCommand::Ingest { file } => {
            let bytes = read_input(&file)?;
            let tags = home()
                .map(|home| load(&home).tag_map.map)
                .unwrap_or_default();
            let mail = desk.drop_mail(&bytes, &tags, Utc::now())?;
            println!(
                "{} taken in{}",
                mail.id,
                mail.project
                    .map_or(String::new(), |project| format!(" for {project}"))
            );
        }
        MailCommand::Queue { json } => {
            let items = desk.items();
            let route = library::home_route().ok();
            let waiting: Vec<_> = route
                .as_ref()
                .map(ferryman_channel::questions::pending)
                .unwrap_or_default()
                .into_iter()
                .filter(|question| question.kind == ferryman_channel::questions::LIBRARY)
                .collect();
            if json {
                println!(
                    "{}",
                    serde_json::to_string_pretty(&json!({"items": items, "asking": waiting}))?
                );
            } else if items.is_empty() {
                println!("the mail desk is empty");
            }
            if !json {
                for item in &items {
                    println!(
                        "{} {:?} {} {} {}",
                        item.mail.id,
                        item.stage,
                        item.mail.project.as_deref().unwrap_or("-"),
                        item.decision.map_or("-".to_string(), |d| format!("{d:?}")),
                        ferryman_channel::suggestions::plain(&item.mail.subject, 70)
                    );
                }
                for question in &waiting {
                    println!(
                        "  needs the master: {} ({})",
                        question.id,
                        question.asked_at.format("%Y-%m-%d")
                    );
                }
            }
        }
        MailCommand::Outbox { json } => {
            let drafts = desk.outbox();
            if json {
                println!("{}", serde_json::to_string_pretty(&drafts)?);
            } else if drafts.is_empty() {
                println!("no replies waiting");
            } else {
                for draft in drafts {
                    println!(
                        "{} ({}) for mail {}",
                        draft.reply_id,
                        draft.kind.as_str(),
                        draft.mail_id
                    );
                }
            }
        }
        MailCommand::Ack { reply } => {
            if !reply
                .chars()
                .all(|c| c.is_ascii_alphanumeric() || matches!(c, '-' | '_'))
            {
                bail!("that is not a reply id");
            }
            desk.ensure()?;
            std::fs::write(desk.dir().join("ack").join(&reply), b"")?;
            println!("{reply} acknowledged; the next pass moves it to sent/");
        }
        MailCommand::Run => serve(true, 0).await?,
    }
    Ok(())
}

/// The loop: one pass, or one every `interval` seconds.
async fn serve(once: bool, interval: u64) -> Result<()> {
    let home = home()?;
    let config = config_for(&home)?;
    loop {
        let outcome = ops::pass(&config, Utc::now()).await;
        for line in &outcome.lines {
            println!("{line}");
        }
        for warning in &outcome.warnings {
            eprintln!("warning: {warning}");
        }
        if once {
            return Ok(());
        }
        tokio::time::sleep(std::time::Duration::from_secs(interval.clamp(5, 3600))).await;
    }
}

pub(crate) async fn command(command: LibraryCommand) -> Result<()> {
    match command {
        LibraryCommand::Show { json } => show(json),
        LibraryCommand::Search {
            query,
            project,
            limit,
            json,
        } => search(&query, project.as_deref(), limit, json),
        LibraryCommand::Ask {
            question,
            project,
            no_model,
            json,
        } => ask(&question, project.as_deref(), no_model, json).await,
        LibraryCommand::Fact { id, json } => fact_detail(&id, json),
        LibraryCommand::Confirm { id } => confirm(&id),
        LibraryCommand::Retract { id, reason } => retract(&id, reason.as_deref()),
        LibraryCommand::History { subject, json } => history(&subject, json),
        LibraryCommand::Views { refresh, json } => views_command(refresh, json),
        LibraryCommand::Tags { command } => tags(command),
        LibraryCommand::Mail { command } => mail_command(command).await,
        LibraryCommand::Serve { once, interval } => serve(once, interval).await,
    }
}

// --- MCP ---------------------------------------------------------------------------------

/// The library's MCP tools. `library_remember` is the one write, and it is the weakest: it
/// adds an unconfirmed fact, signed as the agent whose keys this server holds. An MCP
/// connection is a stranger to the master, so it can never write as them.
pub(crate) fn mcp_tools() -> Vec<Value> {
    vec![
        json!({
            "name": "library_ask",
            "description": "Ask the fleet's library a question. Returns an answer put in words by a cheap model with no tools, citing fact ids and dates, or \"I don't know\" when the library has nothing. Facts marked unconfirmed have not been confirmed by the owner. Advice only.",
            "inputSchema": {
                "type": "object",
                "properties": {
                    "question": { "type": "string" },
                    "project": { "type": "string", "description": "Only this project's facts and the fleet-wide ones." },
                    "no_model": { "type": "boolean", "description": "Return the matching facts only." }
                },
                "required": ["question"],
                "additionalProperties": false,
            },
        }),
        json!({
            "name": "library_search",
            "description": "Full-text search of the library's live facts and generated pages. No model. Each hit has its id, date, standing (confirmed, unconfirmed, generated) and source.",
            "inputSchema": {
                "type": "object",
                "properties": {
                    "query": { "type": "string" },
                    "project": { "type": "string" },
                    "limit": { "type": "integer", "minimum": 1, "maximum": 50 }
                },
                "required": ["query"],
                "additionalProperties": false,
            },
        }),
        json!({
            "name": "library_remember",
            "description": "Write a fact into the library for the whole fleet. It is signed as this agent and waits as UNCONFIRMED until the owner confirms it. A fact is never edited: to correct one, name it in supersedes. Never include a secret; say where it lives instead (\"NVIDIA key: Custodly, name nvidiaapi\"). Anything that looks like a secret is refused.",
            "inputSchema": {
                "type": "object",
                "properties": {
                    "text": { "type": "string", "description": "At most 1000 characters." },
                    "subject": { "type": "string" },
                    "project": { "type": "string" },
                    "tags": { "type": "array", "items": { "type": "string" } },
                    "supersedes": { "type": "array", "items": { "type": "string" }, "description": "Fact ids this replaces." },
                    "source": { "type": "string", "description": "Where it came from, in your words. Recorded as a claim, not verified." }
                },
                "required": ["text"],
                "additionalProperties": false,
            },
        }),
        json!({
            "name": "library_fact",
            "description": "One fact (or generated page row) by id, with who wrote it, whether it is confirmed, what it replaced and what replaced it, and the history of its subject.",
            "inputSchema": {
                "type": "object",
                "properties": { "id": { "type": "string" } },
                "required": ["id"],
                "additionalProperties": false,
            },
        }),
    ]
}

pub(crate) fn is_mcp_tool(name: &str) -> bool {
    matches!(
        name,
        "library_ask" | "library_search" | "library_remember" | "library_fact"
    )
}

fn text_arg<'a>(args: &'a Value, key: &str) -> Result<&'a str> {
    args.get(key)
        .and_then(Value::as_str)
        .map(str::trim)
        .filter(|text| !text.is_empty())
        .with_context(|| format!("the '{key}' argument is needed"))
}

fn strings_arg(args: &Value, key: &str) -> Vec<String> {
    args.get(key)
        .and_then(Value::as_array)
        .map(|list| {
            list.iter()
                .filter_map(Value::as_str)
                .map(str::to_string)
                .collect()
        })
        .unwrap_or_default()
}

/// The identity an MCP connection writes as: the worker identity whose keys this server's
/// workspace (or the home project's) holds. Nothing in a tool call can name another.
fn mcp_identity(route: &ProjectRoute, home: &library::Home) -> Result<AgentIdentity> {
    for attachment in [&route.attachment, &home.attachment] {
        if let Ok(config) = AgentConfig::load(attachment)
            && let Ok(Some(identity)) = AgentIdentity::load_existing(&config.agent, attachment)
        {
            return Ok(identity);
        }
    }
    bail!("this MCP server holds no agent key to sign a fact with")
}

/// Run `future` to the end on a thread of its own, for the stdio server, which is not async.
fn blocking<T: Send>(future: impl FnOnce() -> Result<T> + Send) -> Result<T> {
    std::thread::scope(|scope| {
        scope
            .spawn(future)
            .join()
            .map_err(|_| anyhow::anyhow!("the librarian stopped unexpectedly"))?
    })
}

fn mcp_ask(home: &library::Home, args: &Value) -> Result<Value> {
    let question = text_arg(args, "question")?.to_string();
    let project = args
        .get("project")
        .and_then(Value::as_str)
        .map(str::to_string);
    let no_model = args
        .get("no_model")
        .and_then(Value::as_bool)
        .unwrap_or(false);
    let reader = Reader::load(&home.channel, &home.project);
    let answer = match config_for(home) {
        Ok(config) if !no_model => {
            let route = home.route();
            blocking(|| {
                let runtime = tokio::runtime::Builder::new_current_thread()
                    .enable_all()
                    .build()
                    .context("start the librarian's runtime")?;
                Ok(runtime.block_on(ops::ask_live(
                    &route,
                    &config,
                    &reader,
                    &question,
                    project.as_deref(),
                    false,
                )))
            })?
        }
        _ => ops::facts_only(&reader, &question, project.as_deref()),
    };
    Ok(serde_json::to_value(answer)?)
}

fn mcp_remember(route: &ProjectRoute, home: &library::Home, args: &Value) -> Result<Value> {
    let identity = mcp_identity(route, home)?;
    if load(home)
        .master
        .as_deref()
        .is_some_and(|master| master.eq_ignore_ascii_case(identity.name()))
    {
        bail!("an MCP connection never writes as the master: use `ferry remember --as` there");
    }
    let text = text_arg(args, "text")?.to_string();
    let subject = args
        .get("subject")
        .and_then(Value::as_str)
        .map(str::to_string)
        .unwrap_or_else(|| {
            text.split_whitespace()
                .take(8)
                .collect::<Vec<_>>()
                .join(" ")
        });
    let claimed = args
        .get("source")
        .and_then(Value::as_str)
        .map(|source| ferryman_channel::suggestions::plain(source, 80))
        .filter(|source| !source.is_empty());
    let source = format!(
        "{} via MCP on {}{}",
        identity.name(),
        store::machine_name(),
        claimed.map_or(String::new(), |claimed| format!("; says: {claimed}"))
    );
    let written = library::remember(
        &home.channel,
        &home.project,
        &identity,
        None,
        NewFact {
            subject,
            text,
            tags: strings_arg(args, "tags"),
            project: args
                .get("project")
                .and_then(Value::as_str)
                .map(str::to_string),
            source,
            supersedes: strings_arg(args, "supersedes"),
        },
    )?;
    Ok(json!({
        "id": written.event.id,
        "status": written.status.as_str(),
        "signed_by": identity.name(),
        "note": "unconfirmed until the owner confirms it; a fact is never edited, only superseded",
    }))
}

fn mcp_fact(home: &library::Home, args: &Value) -> Result<Value> {
    let id = text_arg(args, "id")?;
    let reader = Reader::load(&home.channel, &home.project);
    if let Some(row) = reader.rows.iter().find(|row| row.row.id == id) {
        return Ok(json!({
            "id": row.row.id,
            "status": "generated",
            "subject": row.row.subject,
            "text": row.row.text,
            "generated_at": row.generated_at,
            "generated_by": row.generated_by,
            "machine": row.machine,
            "note": "read from live state when it was generated; nobody confirms it",
        }));
    }
    let Some(fact) = reader.library.fact(id) else {
        bail!("there is no fact {id}");
    };
    let named = |ids: &[String]| -> Vec<&Fact> {
        ids.iter()
            .filter_map(|id| reader.library.fact(id))
            .collect()
    };
    Ok(json!({
        "fact": fact,
        "replaces": named(&fact.supersedes),
        "replaced_by": named(&fact.superseded_by),
        "history": reader.library.history(&fact.subject),
    }))
}

/// Run one of the library's MCP tools. `route` is the workspace the server runs in.
pub(crate) fn mcp_call(route: &ProjectRoute, name: &str, args: &Value) -> Result<Value> {
    let home = home()?;
    match name {
        "library_ask" => mcp_ask(&home, args),
        "library_search" => {
            let reader = Reader::load(&home.channel, &home.project);
            let limit = args
                .get("limit")
                .and_then(Value::as_u64)
                .map_or(10, |limit| {
                    usize::try_from(limit).unwrap_or(10).clamp(1, 50)
                });
            let found = reader.search(
                text_arg(args, "query")?,
                args.get("project").and_then(Value::as_str),
                limit,
            );
            Ok(serde_json::to_value(found)?)
        }
        "library_remember" => mcp_remember(route, &home, args),
        "library_fact" => mcp_fact(&home, args),
        other => bail!("unknown tool: {other}"),
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use clap::Parser;

    #[derive(Parser)]
    struct Cli {
        #[command(subcommand)]
        command: LibraryCommand,
    }

    #[derive(Parser)]
    struct Remember {
        #[command(flatten)]
        args: RememberArgs,
    }

    #[test]
    fn the_documented_commands_parse() {
        for line in [
            "library show --json",
            "library search nvidia --project bullship --limit 3",
            "library ask where is the key --no-model",
            "library fact f-0123456789",
            "library confirm f-0123456789",
            "library retract f-0123456789 --reason moved",
            "library history grouchly",
            "library views --refresh",
            "library tags set redaktly redaktly",
            "library tags remove redaktly",
            "library mail ingest --file mail.json",
            "library mail queue --json",
            "library mail outbox",
            "library mail ack r-0123456789-1",
            "library mail run",
            "library serve --once --interval 30",
        ] {
            let words: Vec<&str> = line.split_whitespace().collect();
            let mut argv = vec!["ferry"];
            argv.extend(&words[1..]);
            // `ask` takes the question as one argument.
            if line.starts_with("library ask") {
                argv = vec!["ferry", "ask", "where is the key", "--no-model"];
            }
            assert!(Cli::try_parse_from(argv).is_ok(), "{line}");
        }
        let parsed = Remember::try_parse_from([
            "remember",
            "grouchly is always on",
            "--subject",
            "grouchly",
            "--project",
            "bullship",
            "--tags",
            "machines,ops",
            "--supersedes",
            "f-0123456789",
            "--as",
            "josh",
        ])
        .unwrap();
        assert_eq!(parsed.args.tags, ["machines", "ops"]);
        assert_eq!(parsed.args.as_name.as_deref(), Some("josh"));
    }
}
