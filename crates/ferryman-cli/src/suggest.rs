//! `ferry suggest` (a contributor, or their agent) and `ferry suggestions` (the owner).
//!
//! See [`ferryman_channel::suggestions`]. Strangers never join the private channel: a
//! suggestion is a signed record in an issue on a public GitHub repository the owner names,
//! and everything here that touches GitHub uses the credentials of whoever runs it
//! (`GITHUB_TOKEN`, or `gh auth token`), which are never stored or printed.
//!
//! Consent is the point of `join`: on a terminal the person types `I agree` after the terms
//! are shown; a person's own script may pass `--agree <sha256-of-the-terms>`, which is the
//! same agreement signed with the same key and recorded as having been given by flag. An
//! agent must show the terms to the person it acts for and have them agree: the flag is a
//! record that the person did, not a way round them.

use std::io::{BufRead, IsTerminal, Write};
use std::path::{Path, PathBuf};

use anyhow::{Context, Result, bail};
use chrono::Utc;
use ferryman_channel::{
    ProjectRoute,
    suggestions::{
        client::{self, Joined},
        contributor::{ACCEPT_PHRASE, Consent, ContributorStore, acceptance_current},
        flow::{self, Card, Choice, Stage},
        inbox::{Inbox, InboxRef},
        invite::Invite,
        plain, publish,
        record::{self, Limits, OpenArgs, SuggestionsRecord, TEMPLATE, TriageConfig},
    },
};
use ferryman_ops::suggest::GithubInbox;
use serde_json::json;

use super::signing_identity_in;

// --- the contributor ----------------------------------------------------------------------

#[derive(clap::Subcommand, Clone)]
pub(crate) enum SuggestCommand {
    /// Read a project's invite, show its terms and agree to them. Nothing can be sent
    /// until you have.
    ///
    ///   ferry suggest join ferry-suggest:eyJ2...
    ///   ferry suggest join ferry-suggest:eyJ2... --agree <sha256 of the terms>
    ///
    /// On a terminal the terms are shown and you type `I agree`. Without one the terms and
    /// their sha256 are printed and nothing is agreed. An agent shows them to the person it
    /// acts for, and only once that person has read and accepted them is it run again with
    /// --agree and that sha256. An agent never agrees for its person.
    Join {
        /// The `ferry-suggest:...` text from the project's README or ferryman-suggest.json.
        invite: String,
        /// Agree without typing: the sha256 of the terms, which must match exactly.
        #[arg(long, value_name = "SHA256")]
        agree: Option<String>,
    },
    /// What a joined project takes: its kinds of suggestion, each field and its limit.
    Types {
        #[arg(long)]
        json: bool,
    },
    /// Send a suggestion. On a terminal it asks for each field and shows a preview; from a
    /// script give `--file` (JSON, `-` for stdin) or `--title/--pitch/--why`.
    ///
    ///   ferry suggest new
    ///   ferry suggest new --type idea --title "Offline timer" --pitch "..." --why "..." --yes
    ///   echo '{"type":"idea","title":"..","pitch":"..","why":".."}' | ferry suggest new --file - --json
    New {
        /// Which kind (see `ferry suggest types`). Defaults to the first the project lists.
        #[arg(long = "type")]
        kind: Option<String>,
        #[arg(long)]
        title: Option<String>,
        #[arg(long)]
        pitch: Option<String>,
        #[arg(long)]
        why: Option<String>,
        /// Another field of the kind, as NAME=TEXT. May be repeated.
        #[arg(long = "field", value_name = "NAME=TEXT")]
        fields: Vec<String>,
        /// A JSON object with "type" and the fields, or `-` to read it from stdin.
        #[arg(long)]
        file: Option<String>,
        /// Send without the final question.
        #[arg(long, short = 'y')]
        yes: bool,
        /// Print one JSON object: {"ok":true,"issue":N,"url":".."} or {"ok":false,"errors":[..]}.
        #[arg(long)]
        json: bool,
    },
    /// Where each suggestion you sent stands, and any question waiting for you.
    Status {
        #[arg(long)]
        json: bool,
    },
    /// Answer the owner's question on one of your suggestions.
    Reply {
        /// The issue number (or the start of the suggestion's id).
        issue: String,
        /// Your answer; or use --file.
        text: Option<String>,
        /// Read the answer from a file, or `-` for stdin.
        #[arg(long)]
        file: Option<String>,
    },
    /// Take a suggestion back.
    Withdraw {
        issue: String,
        #[arg(long)]
        reason: Option<String>,
    },
}

fn is_terminal() -> bool {
    std::io::stdin().is_terminal()
}

fn read_line() -> Result<String> {
    let mut line = String::new();
    std::io::stdin()
        .lock()
        .read_line(&mut line)
        .context("read your answer")?;
    Ok(line.trim_end_matches(['\r', '\n']).to_string())
}

fn prompt(text: &str) -> Result<String> {
    print!("{text}");
    std::io::stdout().flush().ok();
    read_line()
}

fn store() -> Result<ContributorStore> {
    Ok(ContributorStore::open(&ContributorStore::default_dir()?))
}

/// The inbox a joined project names, with this person's credentials.
fn inbox_of(store: &ContributorStore, project: &str) -> Result<GithubInbox> {
    let offer = store.offer(project).with_context(|| {
        format!("you have not joined {project}: run `ferry suggest join <invite>`")
    })?;
    Ok(GithubInbox::new(&client::inbox_ref(&offer)?))
}

fn read_text(source: &str) -> Result<String> {
    if source == "-" {
        let mut text = String::new();
        std::io::Read::read_to_string(&mut std::io::stdin(), &mut text).context("read stdin")?;
        Ok(text)
    } else {
        std::fs::read_to_string(source).with_context(|| format!("read {source}"))
    }
}

fn print_terms_summary(joined: &Joined) {
    let offer = &joined.offer;
    println!(
        "{} takes suggestions in {}",
        plain(&offer.display_name, 200),
        plain(&offer.inbox, 200)
    );
    println!(
        "  from the owner {} (key {}), terms version {}",
        plain(&offer.owner, 200),
        offer.fingerprint(),
        offer.terms.version
    );
    println!("  terms sha256 {}", offer.terms.sha256);
    let limits = &offer.limits;
    println!(
        "  limits: {} open at once, {} new a day, {} clarification round(s), {} days to answer",
        limits.open_per_contributor,
        limits.new_per_day,
        limits.clarification_rounds,
        limits.answer_days
    );
}

async fn join(invite_text: &str, agree: Option<&str>) -> Result<()> {
    let store = store()?;
    let invite = Invite::decode(invite_text)?;
    let inbox = GithubInbox::new(&client::inbox_ref(&invite.offer)?);
    let joined = client::prepare_join(&store, &inbox, invite_text)?;
    let project = joined.offer.project_id.clone();
    if let Some(existing) = store.acceptance(&project)
        && acceptance_current(&existing, &joined.offer)
        && agree.is_none()
    {
        println!(
            "You already agreed to {}'s terms (version {}) as @{}. Nothing to do: ferry suggest new",
            plain(&joined.offer.display_name, 200),
            joined.offer.terms.version,
            existing.contributor_login
        );
        return Ok(());
    }
    print_terms_summary(&joined);
    let typed;
    let consent = if let Some(sha) = agree {
        Consent::Flag(sha)
    } else if is_terminal() {
        println!(
            "\n----- the terms -----\n{}\n----- end of the terms -----\n",
            joined.terms_text.trim_end()
        );
        println!(
            "By agreeing you accept these terms for everything you send to this project, and \
             your agreement is signed with this machine's contributor key."
        );
        typed = prompt(&format!(
            "Type exactly `{ACCEPT_PHRASE}` to agree, anything else to stop: "
        ))?;
        Consent::Typed(&typed)
    } else {
        println!(
            "\n----- the terms -----\n{}\n----- end of the terms -----\n",
            joined.terms_text.trim_end()
        );
        bail!(
            "this is not a terminal, so nothing was agreed. Once the person you act for has read \
             the terms above, run:\n  ferry suggest join {invite_text} --agree {}",
            joined.offer.terms.sha256
        );
    };
    let login = inbox.whoami()?;
    let agreed = client::agree(&store, &inbox, &joined, &login, consent, Utc::now())?;
    println!(
        "Agreed as @{login} to terms version {} ({}).",
        agreed.acceptance.terms_version, agreed.acceptance.accepted_via
    );
    for issue in agreed.reposted {
        println!(
            "  also posted on your earlier suggestion #{issue}, which was sent under older terms"
        );
    }
    println!("Next: ferry suggest types, then ferry suggest new");
    Ok(())
}

fn types(project: Option<&str>, as_json: bool) -> Result<()> {
    let store = store()?;
    let project = client::pick_project(&store, project)?;
    let inbox = inbox_of(&store, &project)?;
    let offer = client::current_offer(&store, &inbox, &project)?;
    if as_json {
        println!(
            "{}",
            serde_json::to_string_pretty(
                &json!({ "project": project, "types": offer.types, "limits": offer.limits })
            )?
        );
        return Ok(());
    }
    println!("{} takes:", plain(&offer.display_name, 200));
    for spec in &offer.types {
        println!("  {}", spec.id);
        for (id, label, max, required) in client::describe_fields(&offer, &spec.id) {
            println!(
                "    {id:<10} {label} (up to {max} characters{})",
                if required { ", required" } else { "" }
            );
        }
    }
    Ok(())
}

/// Ask for each field of `kind`, with its limit, until each fits.
fn ask_fields(
    offer: &record::Offer,
    kind: &str,
) -> Result<std::collections::BTreeMap<String, String>> {
    let mut fields = std::collections::BTreeMap::new();
    for (id, label, max, required) in client::describe_fields(offer, kind) {
        loop {
            let hint = if required {
                "required"
            } else {
                "optional, Enter to skip"
            };
            let value = prompt(&format!("{label} (up to {max} characters, {hint}): "))?;
            let used = value.chars().count();
            if used > max {
                println!(
                    "  that is {used} characters and the limit is {max}: shorten it by {}",
                    used - max
                );
                continue;
            }
            if required && value.trim().is_empty() {
                println!("  this one is required");
                continue;
            }
            println!("  {used}/{max}");
            if !value.trim().is_empty() {
                fields.insert(id.clone(), value);
            }
            break;
        }
    }
    Ok(fields)
}

async fn new(project: Option<&str>, args: NewArgs) -> Result<()> {
    let store = store()?;
    let project = client::pick_project(&store, project)?;
    let inbox = inbox_of(&store, &project)?;
    let offer = client::current_offer(&store, &inbox, &project)?;
    let given = args.title.is_some()
        || args.pitch.is_some()
        || args.why.is_some()
        || !args.fields.is_empty();
    let (kind, fields, confirm) = if let Some(file) = &args.file {
        let (kind, fields) = client::parse_submission(&read_text(file)?, args.kind.as_deref())?;
        (kind, fields, false)
    } else if given {
        let mut fields = std::collections::BTreeMap::new();
        for (name, value) in [
            ("title", &args.title),
            ("pitch", &args.pitch),
            ("why", &args.why),
        ] {
            if let Some(value) = value {
                fields.insert(name.to_string(), value.clone());
            }
        }
        for item in &args.fields {
            let (name, value) = item
                .split_once('=')
                .with_context(|| format!("--field is NAME=TEXT, not '{item}'"))?;
            fields.insert(name.trim().to_string(), value.to_string());
        }
        let kind = args
            .kind
            .clone()
            .or_else(|| offer.types.first().map(|spec| spec.id.clone()))
            .context("this project lists no kinds of suggestion")?;
        (kind, fields, false)
    } else if is_terminal() {
        let names: Vec<&str> = offer.types.iter().map(|spec| spec.id.as_str()).collect();
        let kind = match &args.kind {
            Some(kind) => kind.clone(),
            None => {
                let default = names.first().copied().unwrap_or("idea");
                let answer = prompt(&format!("What kind? ({}) [{default}]: ", names.join(", ")))?;
                if answer.trim().is_empty() {
                    default.to_string()
                } else {
                    answer.trim().to_string()
                }
            }
        };
        let fields = ask_fields(&offer, &kind)?;
        (kind, fields, true)
    } else {
        bail!(
            "nothing to send: give --file (JSON, or - for stdin) or --title/--pitch/--why. \
             `ferry suggest types` lists the fields."
        );
    };
    if confirm && !args.yes {
        println!("\nTo {}: [{kind}]", plain(&offer.display_name, 200));
        for (id, label, ..) in client::describe_fields(&offer, &kind) {
            if let Some(value) = fields.get(&id) {
                println!("  {label}: {value}");
            }
        }
        let answer = prompt("Send this? [y/N] ")?;
        if !matches!(answer.trim().to_ascii_lowercase().as_str(), "y" | "yes") {
            println!("Not sent.");
            return Ok(());
        }
    }
    match client::send(&store, &inbox, &project, &kind, &fields, Utc::now()) {
        Ok(sent) => {
            if args.json {
                println!(
                    "{}",
                    json!({ "ok": true, "project": project, "issue": sent.issue, "url": sent.url })
                );
            } else {
                println!("Sent: {}\nFollow it with: ferry suggest status", sent.url);
            }
            Ok(())
        }
        Err(error) if args.json => {
            let errors: Vec<String> = format!("{error:#}")
                .lines()
                .map(str::trim)
                .filter(|line| !line.is_empty())
                .map(str::to_string)
                .collect();
            println!("{}", json!({ "ok": false, "errors": errors }));
            std::process::exit(1);
        }
        Err(error) => Err(error),
    }
}

pub(crate) struct NewArgs {
    pub kind: Option<String>,
    pub title: Option<String>,
    pub pitch: Option<String>,
    pub why: Option<String>,
    pub fields: Vec<String>,
    pub file: Option<String>,
    pub yes: bool,
    pub json: bool,
}

fn status(project: Option<&str>, as_json: bool) -> Result<()> {
    let store = store()?;
    let project = client::pick_project(&store, project)?;
    let inbox = inbox_of(&store, &project)?;
    let rows = client::status(&store, &inbox, &project)?;
    if as_json {
        println!("{}", serde_json::to_string_pretty(&rows)?);
        return Ok(());
    }
    if rows.is_empty() {
        println!("You have not sent {project} anything from this machine.");
        return Ok(());
    }
    for row in &rows {
        println!(
            "#{:<5} {:<20} [{}] {}",
            row.issue, row.state, row.kind, row.title
        );
        println!("       {}", row.url);
        if let Some(question) = &row.question {
            println!("       the owner asks: {question}");
            println!(
                "       answer with: ferry suggest reply {} \"your answer\"",
                row.issue
            );
        }
    }
    Ok(())
}

fn reply(project: Option<&str>, issue: &str, text: Option<&str>, file: Option<&str>) -> Result<()> {
    let text = match (text, file) {
        (Some(text), None) => text.to_string(),
        (None, Some(file)) => read_text(file)?,
        _ => bail!("give the answer as text, or with --file (- for stdin)"),
    };
    let store = store()?;
    let project = client::pick_project(&store, project)?;
    let inbox = inbox_of(&store, &project)?;
    let number = client::reply(&store, &inbox, &project, issue, text.trim(), Utc::now())?;
    println!("Answered on #{number}.");
    Ok(())
}

fn withdraw(project: Option<&str>, issue: &str, reason: Option<&str>) -> Result<()> {
    let store = store()?;
    let project = client::pick_project(&store, project)?;
    let inbox = inbox_of(&store, &project)?;
    let number = client::withdraw(
        &store,
        &inbox,
        &project,
        issue,
        reason.unwrap_or(""),
        Utc::now(),
    )?;
    println!("Withdrawn: #{number}.");
    Ok(())
}

pub(crate) async fn suggest(project: Option<String>, command: SuggestCommand) -> Result<()> {
    let project = project.as_deref();
    match command {
        SuggestCommand::Join { invite, agree } => join(&invite, agree.as_deref()).await,
        SuggestCommand::Types { json } => types(project, json),
        SuggestCommand::New {
            kind,
            title,
            pitch,
            why,
            fields,
            file,
            yes,
            json,
        } => {
            new(
                project,
                NewArgs {
                    kind,
                    title,
                    pitch,
                    why,
                    fields,
                    file,
                    yes,
                    json,
                },
            )
            .await
        }
        SuggestCommand::Status { json } => status(project, json),
        SuggestCommand::Reply { issue, text, file } => {
            reply(project, &issue, text.as_deref(), file.as_deref())
        }
        SuggestCommand::Withdraw { issue, reason } => withdraw(project, &issue, reason.as_deref()),
    }
}

// --- the owner ----------------------------------------------------------------------------

#[derive(clap::Subcommand, Clone)]
pub(crate) enum SuggestionsCommand {
    /// Open a project to suggestions from outsiders and their agents, signed as its master.
    ///
    ///   ferry suggestions open --inbox github:estejosh/idle-ish-ideas --terms TERMS.md --publish
    ///
    /// The inbox is a public GitHub repository you own; strangers never join your channel.
    /// Ferryman does not write your terms (docs/templates/SUGGESTION_TERMS.md is a draft, and
    /// `ferry suggestions terms template` prints it): `open` refuses the untouched draft
    /// unless you pass --accept-draft-terms. With --publish the join page (README section,
    /// AGENTS.md, TERMS.md, ferryman-suggest.json, schemas) is committed to the inbox with
    /// your GitHub credentials; without it the files are written to a local folder.
    Open {
        /// github:owner/repo
        #[arg(long)]
        inbox: String,
        /// What the project is called on the page. Defaults to the project id.
        #[arg(long)]
        name: Option<String>,
        /// Your terms, as a Markdown file.
        #[arg(long)]
        terms: Option<PathBuf>,
        /// Kinds and their fields: idea,bug:steps=500!+expected=300,content:where=200
        #[arg(long)]
        types: Option<String>,
        /// Limits: open=3,per-day=1,rounds=2,days=14,title=80,pitch=1000,why=500
        #[arg(long)]
        limits: Option<String>,
        /// A file in the project's repository that says what the product is (read by triage).
        #[arg(long)]
        canon: Option<String>,
        /// A file in the project's repository that says what a good suggestion is.
        #[arg(long)]
        rubric: Option<String>,
        /// Commit the join page to the inbox now.
        #[arg(long)]
        publish: bool,
        /// Publish the draft terms template as it is.
        #[arg(long)]
        accept_draft_terms: bool,
        /// Where to write the page when not publishing (default ./ferryman-suggest-page).
        #[arg(long)]
        out: Option<PathBuf>,
    },
    /// Stop taking new suggestions, signed. What is in flight is still decided and built.
    Close,
    /// What is in force: the terms version, the limits, and what the suggestions stand at.
    Show {
        #[arg(long)]
        json: bool,
    },
    /// The terms.
    Terms {
        #[command(subcommand)]
        command: TermsCommand,
    },
    /// Print the invite: the one line a contributor passes to `ferry suggest join`.
    Invite,
    /// Commit the join page to the inbox with your GitHub credentials, or with --out write
    /// it to a folder instead.
    Publish {
        #[arg(long)]
        out: Option<PathBuf>,
    },
    /// The suggestions waiting for your decision ("needs me"), with what triage made of each.
    Pending {
        /// Every suggestion, not only the ones waiting for you.
        #[arg(long)]
        all: bool,
        #[arg(long)]
        json: bool,
    },
    /// Accept a pending suggestion: it becomes a normal signed order for the workers.
    Accept { issue: u64 },
    /// Decline a pending suggestion; the reason is shown to the contributor.
    Decline {
        issue: u64,
        #[arg(long)]
        reason: Option<String>,
    },
    /// Ask the contributor more about a pending suggestion (the model's question, or yours).
    Ask {
        issue: u64,
        question: Option<String>,
    },
    /// Look at the inbox now instead of waiting for the next worker pass.
    Sync,
}

#[derive(clap::Subcommand, Clone)]
pub(crate) enum TermsCommand {
    /// Print the draft template. It is a starting point, not legal advice.
    Template,
    /// Replace the terms: a new version. Suggestions already in flight keep the terms they
    /// were sent under, and an accepted one waits for its sender to agree to the new terms.
    Set {
        file: PathBuf,
        #[arg(long)]
        accept_draft_terms: bool,
        #[arg(long)]
        publish: bool,
        #[arg(long)]
        out: Option<PathBuf>,
    },
}

/// The routes this machine has: the ferry root's projects, and the project the current
/// directory is in.
fn routes() -> Vec<ProjectRoute> {
    let mut routes: Vec<ProjectRoute> = Vec::new();
    if let Some(root) = ferryman_channel::ferry::find_root() {
        routes.extend(
            root.projects()
                .iter()
                .filter_map(|entry| ferryman_channel::route_for(&entry.channel).ok()),
        );
    }
    routes
}

fn route_of(project: Option<&str>) -> Result<ProjectRoute> {
    let here = std::env::current_dir()
        .ok()
        .and_then(|dir| ferryman_channel::route_for(&dir).ok());
    let mut all = routes();
    match project {
        Some(name) => {
            if let Some(route) = here.filter(|route| route.project_id.eq_ignore_ascii_case(name)) {
                return Ok(route);
            }
            let known: Vec<String> = all.iter().map(|route| route.project_id.clone()).collect();
            all.into_iter()
                .find(|route| route.project_id.eq_ignore_ascii_case(name))
                .with_context(|| {
                    format!(
                        "no project '{name}' on this machine (have: {})",
                        known.join(", ")
                    )
                })
        }
        None => match (here, all.len()) {
            (Some(route), _) => Ok(route),
            (None, 1) => Ok(all.remove(0)),
            _ => bail!("say which project with --project (run inside its folder, or name it)"),
        },
    }
}

fn master_identity(route: &ProjectRoute) -> Result<(String, ferryman_channel::AgentIdentity)> {
    let Some(master) = ferryman_channel::ferry::master_of(&route.communications)? else {
        bail!(
            "{} has no master, and only its master opens it to suggestions or decides them.\n\n\
             Claim every project that has none:  ferry root master",
            route.project_id
        );
    };
    let identity = signing_identity_in(&route.attachment, &master)?;
    Ok((master, identity))
}

fn record_of(route: &ProjectRoute) -> Result<SuggestionsRecord> {
    record::current(&route.communications, &route.project_id).with_context(|| {
        format!(
            "{} is not open to suggestions: ferry suggestions open --inbox github:owner/repo --terms TERMS.md",
            route.project_id
        )
    })
}

fn safe_relative(label: &str, path: &str) -> Result<()> {
    let candidate = Path::new(path);
    if path.trim().is_empty()
        || candidate.is_absolute()
        || candidate
            .components()
            .any(|part| !matches!(part, std::path::Component::Normal(_)))
    {
        bail!(
            "--{label} is a path inside the project's repository, like docs/CANON.md, not '{path}'"
        );
    }
    Ok(())
}

/// Put the join page where the owner said: the inbox, or a folder.
fn put_page(record: &SuggestionsRecord, publish_now: bool, out: Option<&Path>) -> Result<()> {
    let invite = Invite::new(&record.offer).encode();
    if publish_now && out.is_none() {
        let inbox = GithubInbox::new(&InboxRef::parse(&record.offer.inbox)?);
        let written = publish::publish(&inbox, &record.offer, &record.terms_text)
            .context("the join page was signed but could not be published; fix the credentials and run `ferry suggestions publish`")?;
        let changed = written.iter().filter(|file| file.changed).count();
        println!(
            "Published to {}: {changed} file(s) changed, {} already up to date.",
            record.offer.inbox,
            written.len() - changed
        );
    } else {
        let dir = out.map_or_else(|| PathBuf::from("ferryman-suggest-page"), Path::to_path_buf);
        let files = publish::files(&record.offer, &record.terms_text, None);
        publish::write_folder(&dir, &files)?;
        println!(
            "Wrote the join page to {}. Commit its files to {}, or run `ferry suggestions publish`.",
            dir.display(),
            record.offer.inbox
        );
    }
    println!("Invite: {invite}");
    Ok(())
}

fn open(project: Option<&str>, args: OpenOptions) -> Result<()> {
    let route = route_of(project)?;
    let (_, identity) = master_identity(&route)?;
    for (label, value) in [("canon", &args.canon), ("rubric", &args.rubric)] {
        if let Some(value) = value {
            safe_relative(label, value)?;
        }
    }
    let terms_text = match &args.terms {
        Some(path) => {
            std::fs::read_to_string(path).with_context(|| format!("read {}", path.display()))?
        }
        None => TEMPLATE.to_string(),
    };
    let existing = record::current(&route.communications, &route.project_id);
    let types = match &args.types {
        Some(spec) => record::parse_types(spec)?,
        None => existing
            .as_ref()
            .map_or_else(record::default_types, |record| record.offer.types.clone()),
    };
    let limits = match &args.limits {
        Some(spec) => record::parse_limits(spec, Limits::default())?,
        None => existing
            .as_ref()
            .map_or_else(Limits::default, |record| record.offer.limits.clone()),
    };
    let triage = TriageConfig {
        rubric: args.rubric.clone().or_else(|| {
            existing
                .as_ref()
                .and_then(|record| record.triage.rubric.clone())
        }),
        canon: args.canon.clone().or_else(|| {
            existing
                .as_ref()
                .and_then(|record| record.triage.canon.clone())
        }),
    };
    let record = record::open(
        &route.communications,
        &route.project_id,
        &identity,
        OpenArgs {
            display_name: args.name.clone().unwrap_or_else(|| {
                existing.as_ref().map_or_else(
                    || route.project_id.clone(),
                    |record| record.offer.display_name.clone(),
                )
            }),
            inbox: args.inbox.clone(),
            terms_text,
            types,
            limits,
            triage,
            accept_draft_terms: args.accept_draft_terms,
        },
        Utc::now(),
    )?;
    println!(
        "{} is open to suggestions at {} (terms version {}, sha256 {}), signed by {}.",
        record.offer.display_name,
        record.offer.inbox,
        record.offer.terms.version,
        record.offer.terms.sha256,
        record.signed_by
    );
    put_page(&record, args.publish, args.out.as_deref())?;
    println!("Your workers read the inbox on their next pass; to look now: ferry suggestions sync");
    Ok(())
}

pub(crate) struct OpenOptions {
    pub inbox: String,
    pub name: Option<String>,
    pub terms: Option<PathBuf>,
    pub types: Option<String>,
    pub limits: Option<String>,
    pub canon: Option<String>,
    pub rubric: Option<String>,
    pub publish: bool,
    pub accept_draft_terms: bool,
    pub out: Option<PathBuf>,
}

fn show(project: Option<&str>, as_json: bool) -> Result<()> {
    let route = route_of(project)?;
    let record = record_of(&route)?;
    let cards = flow::cards(&route, Some(&record.offer));
    let count = |stage: Stage| cards.iter().filter(|card| card.stage == stage).count();
    let notice = record::rollback_notice(&route.communications, &route.project_id);
    if as_json {
        println!(
            "{}",
            serde_json::to_string_pretty(&json!({
                "project": route.project_id,
                "offer": record.offer,
                "signed_by": record.signed_by,
                "seq": record.seq,
                "notice": notice,
                "total": cards.len(),
                "waiting_for_you": count(Stage::Pending),
            }))?
        );
        return Ok(());
    }
    let offer = &record.offer;
    println!(
        "{}: {} at {}, signed by {} (sequence {})",
        route.project_id,
        if offer.is_open() { "open" } else { "closed" },
        offer.inbox,
        record.signed_by,
        record.seq
    );
    if let Some(notice) = notice {
        println!("  warning: {notice}");
    }
    println!(
        "  terms version {}, sha256 {}",
        offer.terms.version, offer.terms.sha256
    );
    println!(
        "  kinds: {}",
        offer
            .types
            .iter()
            .map(|spec| spec.id.as_str())
            .collect::<Vec<_>>()
            .join(", ")
    );
    let limits = &offer.limits;
    println!(
        "  limits: {} open each, {} new a day, {} clarification round(s), {} days to answer; title {}, pitch {}, why {}",
        limits.open_per_contributor,
        limits.new_per_day,
        limits.clarification_rounds,
        limits.answer_days,
        limits.title_max,
        limits.pitch_max,
        limits.why_max
    );
    println!(
        "  {} suggestion(s): {} waiting for you, {} being asked, {} accepted or building, {} shipped, {} declined",
        cards.len(),
        count(Stage::Pending),
        count(Stage::Clarifying),
        count(Stage::Accepted) + count(Stage::Building),
        count(Stage::Shipped),
        count(Stage::Declined)
    );
    Ok(())
}

fn print_card(card: &Card) {
    println!(
        "#{} [{}] {} - @{} ({})",
        card.issue,
        card.kind,
        card.title,
        card.login,
        card.stage.as_str()
    );
    println!("   {}", card.url);
    if !card.terms_current {
        println!(
            "   sent under terms version {} (not the current ones)",
            card.terms_version
        );
    }
    if !card.pitch.is_empty() {
        println!("   pitch: {}", card.pitch);
    }
    if !card.why.is_empty() {
        println!("   why: {}", card.why);
    }
    if let Some(verdict) = &card.verdict {
        let decision = serde_json::to_value(verdict.decision)
            .ok()
            .and_then(|value| value.as_str().map(str::to_string))
            .unwrap_or_default();
        println!("   triage: {decision} - {}", verdict.reason);
        if !verdict.spec_draft.is_empty() {
            println!("   would build: {}", verdict.spec_draft);
        }
    }
    if card.stage == Stage::Pending {
        println!(
            "   decide: ferry suggestions accept {0} | decline {0} --reason \"..\" | ask {0} \"..\"",
            card.issue
        );
    }
}

fn pending(project: Option<&str>, all: bool, as_json: bool) -> Result<()> {
    let route = route_of(project)?;
    let record = record_of(&route)?;
    let cards: Vec<Card> = flow::cards(&route, Some(&record.offer))
        .into_iter()
        .filter(|card| all || card.stage == Stage::Pending)
        .collect();
    if as_json {
        println!("{}", serde_json::to_string_pretty(&cards)?);
        return Ok(());
    }
    if cards.is_empty() {
        println!("Nothing is waiting for your decision.");
    }
    for card in &cards {
        print_card(card);
    }
    Ok(())
}

fn decide(project: Option<&str>, issue: u64, choice: &Choice) -> Result<()> {
    let route = route_of(project)?;
    let (master, identity) = master_identity(&route)?;
    flow::decide(&route, issue, choice, &master, &identity)?;
    println!(
        "Recorded: {}. Your workers act on it on their next pass (to look now: ferry suggestions sync).",
        choice.text()
    );
    Ok(())
}

async fn sync(project: Option<&str>) -> Result<()> {
    let route = route_of(project)?;
    record_of(&route)?;
    let config = ferryman_ops::agent::AgentConfig::load(&route.attachment)?;
    let outcome = ferryman_ops::suggest::pass(&route, &config, Utc::now()).await;
    for line in &outcome.lines {
        println!("{line}");
    }
    for warning in &outcome.warnings {
        eprintln!("warning: {warning}");
    }
    if outcome.lines.is_empty() && outcome.warnings.is_empty() {
        println!("Nothing new in the inbox.");
    }
    Ok(())
}

pub(crate) async fn suggestions(
    project: Option<String>,
    command: SuggestionsCommand,
) -> Result<()> {
    let project = project.as_deref();
    match command {
        SuggestionsCommand::Open {
            inbox,
            name,
            terms,
            types,
            limits,
            canon,
            rubric,
            publish,
            accept_draft_terms,
            out,
        } => open(
            project,
            OpenOptions {
                inbox,
                name,
                terms,
                types,
                limits,
                canon,
                rubric,
                publish,
                accept_draft_terms,
                out,
            },
        ),
        SuggestionsCommand::Close => {
            let route = route_of(project)?;
            let (_, identity) = master_identity(&route)?;
            if record::close(
                &route.communications,
                &route.project_id,
                &identity,
                Utc::now(),
            )? {
                println!(
                    "{} no longer takes new suggestions. What is in flight is still decided.",
                    route.project_id
                );
            } else {
                println!("{} was already closed.", route.project_id);
            }
            Ok(())
        }
        SuggestionsCommand::Show { json } => show(project, json),
        SuggestionsCommand::Terms { command } => match command {
            TermsCommand::Template => {
                print!("{TEMPLATE}");
                Ok(())
            }
            TermsCommand::Set {
                file,
                accept_draft_terms,
                publish,
                out,
            } => {
                let route = route_of(project)?;
                let (_, identity) = master_identity(&route)?;
                let text = std::fs::read_to_string(&file)
                    .with_context(|| format!("read {}", file.display()))?;
                let record = record::set_terms(
                    &route.communications,
                    &route.project_id,
                    &identity,
                    &text,
                    accept_draft_terms,
                    Utc::now(),
                )?;
                println!(
                    "Terms are now version {} (sha256 {}). Contributors agree again before their next suggestion.",
                    record.offer.terms.version, record.offer.terms.sha256
                );
                put_page(&record, publish, out.as_deref())
            }
        },
        SuggestionsCommand::Invite => {
            let route = route_of(project)?;
            let record = record_of(&route)?;
            println!("{}", Invite::new(&record.offer).encode());
            Ok(())
        }
        SuggestionsCommand::Publish { out } => {
            let route = route_of(project)?;
            let record = record_of(&route)?;
            put_page(&record, true, out.as_deref())
        }
        SuggestionsCommand::Pending { all, json } => pending(project, all, json),
        SuggestionsCommand::Accept { issue } => decide(project, issue, &Choice::Accept),
        SuggestionsCommand::Decline { issue, reason } => decide(
            project,
            issue,
            &Choice::Decline(reason.filter(|reason| !reason.trim().is_empty())),
        ),
        SuggestionsCommand::Ask { issue, question } => decide(
            project,
            issue,
            &Choice::Ask(question.filter(|question| !question.trim().is_empty())),
        ),
        SuggestionsCommand::Sync => sync(project).await,
    }
}

#[cfg(test)]
mod tests {
    use clap::{CommandFactory, Parser};

    use super::*;

    fn parse(args: &[&str]) -> crate::Cli {
        let mut line = vec!["ferry"];
        line.extend_from_slice(args);
        crate::Cli::try_parse_from(line).unwrap()
    }

    #[test]
    fn the_command_lines_hold_together() {
        crate::Cli::command().debug_assert();
        let cli = parse(&[
            "suggest",
            "new",
            "--project",
            "idle-ish",
            "--type",
            "idea",
            "--title",
            "t",
            "--json",
            "-y",
        ]);
        let crate::Command::Suggest { project, command } = cli.command else {
            panic!("not a suggest command");
        };
        assert_eq!(project.as_deref(), Some("idle-ish"));
        assert!(matches!(
            command,
            SuggestCommand::New {
                json: true,
                yes: true,
                ..
            }
        ));
        let cli = parse(&[
            "suggest",
            "join",
            "ferry-suggest:abc",
            "--agree",
            "deadbeef",
        ]);
        assert!(matches!(
            cli.command,
            crate::Command::Suggest {
                command: SuggestCommand::Join { agree: Some(_), .. },
                ..
            }
        ));
        let cli = parse(&[
            "suggestions",
            "open",
            "--inbox",
            "github:o/r",
            "--publish",
            "--accept-draft-terms",
        ]);
        assert!(matches!(
            cli.command,
            crate::Command::Suggestions {
                command: SuggestionsCommand::Open {
                    publish: true,
                    accept_draft_terms: true,
                    ..
                },
                ..
            }
        ));
        let cli = parse(&["suggestions", "terms", "set", "TERMS.md", "--project", "p"]);
        assert!(matches!(
            cli.command,
            crate::Command::Suggestions {
                command: SuggestionsCommand::Terms { .. },
                project: Some(_)
            }
        ));
        for owner_words in [
            "accept 3",
            "decline 3 --reason no",
            "ask 3 why",
            "pending --all --json",
            "invite",
            "sync",
            "show",
            "close",
        ] {
            let mut args = vec!["suggestions"];
            args.extend(owner_words.split(' '));
            let _ = parse(&args);
        }
    }

    #[test]
    fn the_triage_files_must_be_inside_the_repository() {
        assert!(safe_relative("canon", "docs/design/CANON.md").is_ok());
        for bad in ["", "../CANON.md", "/etc/passwd", "docs/../../x", "C:\\x.md"] {
            assert!(safe_relative("canon", bad).is_err(), "{bad}");
        }
    }

    #[test]
    fn a_reply_comes_from_text_or_a_file_never_both_or_neither() {
        assert!(reply(Some("p"), "1", None, None).is_err());
        assert!(reply(Some("p"), "1", Some("a"), Some("b")).is_err());
    }
}
