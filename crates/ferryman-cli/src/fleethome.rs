//! `ferry where` and the fleet's own folder: `ferry fleet init | admit | publish | notices |
//! notice | order | orders | machines | write-hints` (ADR 0026).
//!
//! The folder, and what counts in it, is `ferryman_channel::fleethome`. What a machine does
//! with it is `ferryman_ops::fleethome`. This file is what is printed, and who signs.

use std::collections::BTreeSet;

use anyhow::{Context, Result, bail};
use clap::{Args, Subcommand};
use ferryman_channel::AgentIdentity;
use ferryman_channel::ferry::{self, Root};
use ferryman_channel::fleethome::{self as home, Kind, NoticeBody};
use ferryman_ops::Progress;
use ferryman_ops::fleethome::{self as ops, Publish, Snapshot};

// --- ferry where ---------------------------------------------------------------------------

#[derive(Args, Clone)]
pub struct WhereArgs {
    /// The project id. Not needed with --all.
    pub project: Option<String>,
    /// Another machine's place for the project (default: this machine).
    #[arg(long)]
    pub machine: Option<String>,
    /// All of it as JSON: every place, where it was learned from, and who signed it.
    #[arg(long)]
    pub json: bool,
    /// One place: code, channel, handins, data or env. Default: code.
    #[arg(long, value_parser = ["code", "channel", "handins", "data", "env"])]
    pub kind: Option<String>,
    /// Every project on every machine the fleet knows of.
    #[arg(long, conflicts_with_all = ["project", "machine", "session_hint"])]
    pub all: bool,
    /// Print a short block for a CLAUDE.md or AGENTS.md instead of a path.
    #[arg(long)]
    pub session_hint: bool,
}

/// `ferry where`.
pub fn where_command(args: &WhereArgs) -> Result<()> {
    let root = ferry::find_root().context(
        "no ferry root found here. Run it from inside the root, or set FERRYMAN_ROOT to it",
    )?;
    let own = ferryman_ops::identity::machine_name()?;
    if args.all {
        let rows = home::resolve_all(&root, &own);
        if args.json {
            println!("{}", serde_json::to_string_pretty(&rows)?);
            return Ok(());
        }
        let kind = Kind::parse(args.kind.as_deref().unwrap_or("code"))?;
        for row in rows {
            println!(
                "{}\t{}\t{}\t{}",
                row.project,
                row.machine,
                row.source,
                row.path(kind).unwrap_or("-")
            );
        }
        return Ok(());
    }
    let Some(project) = &args.project else {
        bail!("name a project (`ferry where <project>`), or use --all");
    };
    let found = home::resolve(&root, project, args.machine.as_deref(), &own)?;
    if args.session_hint {
        if found.source != "manifest" {
            bail!(
                "a session hint is for this machine; {project} is read from another machine's entry"
            );
        }
        print!("{}", home::hint_block(&found));
        return Ok(());
    }
    if args.json {
        println!("{}", serde_json::to_string_pretty(&found)?);
        return Ok(());
    }
    let kind = Kind::parse(args.kind.as_deref().unwrap_or("code"))?;
    match found.path(kind) {
        Some(path) => println!("{path}"),
        None => bail!(
            "{project} has no {} place on {}",
            args.kind.as_deref().unwrap_or("code"),
            found.machine
        ),
    }
    Ok(())
}

// --- ferry fleet ... -----------------------------------------------------------------------

#[derive(Subcommand, Clone)]
pub enum HomeCommand {
    /// Make the fleet's own folder, `<root>/fleet`, and register it (master).
    ///
    /// One synced channel, separate from every project, for what is true of the whole fleet:
    /// where each machine keeps each project, what each machine runs, notices, orders and
    /// release approvals. You are its master; nothing in it counts unless you or a machine you
    /// admitted signed it. Run once, on the master's machine. Safe to run again.
    Init {
        /// The master's name. Default: the person who masters most projects here.
        #[arg(long)]
        master: Option<String>,
        /// Do not register the folder with Syncthing (the iroh lane picks it up anyway).
        #[arg(long)]
        no_syncthing: bool,
    },
    /// Let a machine write its own entries into the fleet folder (master).
    Admit {
        /// The name the machine's key is on the fleet roster under (its machine name).
        name: String,
        /// The machine it may speak for. Default: the same name.
        #[arg(long)]
        machine: Option<String>,
    },
    /// Publish this machine's directory entries and machine record now.
    Publish,
    /// The fleet's notices: layout changes, deprecations, updates, migrations.
    Notices {
        /// Include expired ones.
        #[arg(long)]
        all: bool,
        #[arg(long)]
        json: bool,
    },
    /// Post a fleet-wide notice (master).
    Notice {
        /// layout-change, deprecation, update-available, migration or general.
        #[arg(value_parser = home::NOTICE_KINDS)]
        kind: String,
        /// One line.
        title: String,
        /// The detail.
        #[arg(long, default_value = "")]
        text: String,
        #[arg(long, default_value = "info", value_parser = home::SEVERITIES)]
        severity: String,
        /// For update-available: the release version it names.
        #[arg(long)]
        version: Option<String>,
        /// It stops being shown after this many days.
        #[arg(long)]
        expires_days: Option<i64>,
    },
    /// Give the fleet an order (master): update, migrate or restart-worker, to one machine
    /// or to all. A worker acts only on the master's signature.
    Order {
        #[arg(value_parser = home::ORDER_ACTIONS)]
        action: String,
        /// The machine it is for. Without it, every machine.
        #[arg(long)]
        machine: Option<String>,
    },
    /// The fleet orders waiting for this machine.
    Orders {
        #[arg(long)]
        json: bool,
    },
    /// The fleet's relay list: the relays every machine's iroh lane tries, in order, after
    /// any named in its own ferry.toml. Only the master changes it (signed); with no
    /// subcommand, shows it.
    Relays {
        #[command(subcommand)]
        action: Option<RelaysAction>,
        #[arg(long)]
        json: bool,
    },
    /// The machines in the fleet folder: version, layout, what they serve, when last seen.
    Machines {
        #[arg(long)]
        json: bool,
    },
    /// Write the "where this project lives" block into each clone's CLAUDE.md (and AGENTS.md
    /// where there is one). Shows what it would do unless you pass --apply. Touches only the
    /// text between its own `<!-- ferry:where begin/end -->` markers, and never commits.
    WriteHints {
        /// Write the files. Without it nothing is written.
        #[arg(long)]
        apply: bool,
        /// Only these projects.
        #[arg(long)]
        project: Vec<String>,
    },
}

#[derive(Subcommand, Clone)]
pub enum RelaysAction {
    /// Show the list.
    List,
    /// Replace the list. Each entry is `https://host[:port]/`, and `=<sha256>` after it
    /// when the relay's certificate is not one a public CA signed (a bare IP, say).
    Set {
        #[arg(required = true)]
        relays: Vec<String>,
    },
    /// Add one (at the end, or first with --first); an entry for the same URL is replaced.
    Add {
        relay: String,
        #[arg(long)]
        first: bool,
        /// What it is, for people.
        #[arg(long)]
        note: Option<String>,
    },
    /// Take one out, by its URL.
    Remove { url: String },
}

fn parse_relay(text: &str) -> Result<home::FleetRelay> {
    let (url, pin) = match text.split_once('=') {
        Some((url, pin)) => (url, Some(pin.to_ascii_lowercase())),
        None => (text, None),
    };
    let relay = home::FleetRelay {
        url: url.to_owned(),
        cert_sha256: pin,
        note: None,
    };
    relay.check().map_err(|why| anyhow::anyhow!(why))?;
    Ok(relay)
}

fn same_url(a: &str, b: &str) -> bool {
    a.trim_end_matches('/')
        .eq_ignore_ascii_case(b.trim_end_matches('/'))
}

fn print_relays(list: &home::RelayList) {
    if list.relays.is_empty() {
        println!("relay list: none (machines use only what their own ferry.toml names)");
    }
    for (n, relay) in list.relays.iter().enumerate() {
        println!(
            "  {}. {}{}{}",
            n + 1,
            relay.url,
            if relay.cert_sha256.is_some() {
                "  (certificate pinned)"
            } else {
                "  (public CA)"
            },
            relay
                .note
                .as_deref()
                .map(|note| format!("  {note}"))
                .unwrap_or_default()
        );
    }
    for rejection in &list.findings.rejected {
        println!("  ignored: {} - {}", rejection.path, rejection.why);
    }
}

fn relays(action: Option<RelaysAction>, json: bool) -> Result<()> {
    let root = root()?;
    need_fleet(&root)?;
    let current = home::read_relays(&root);
    let next = match action {
        None | Some(RelaysAction::List) => {
            if json {
                println!(
                    "{}",
                    serde_json::to_string_pretty(&serde_json::json!({
                        "relays": current.relays,
                        "written_at": current.written_at,
                        "ignored": current.findings.rejected.iter()
                            .map(|r| serde_json::json!({"path": r.path, "why": r.why}))
                            .collect::<Vec<_>>(),
                    }))?
                );
            } else {
                print_relays(&current);
            }
            return Ok(());
        }
        Some(RelaysAction::Set { relays }) => relays
            .iter()
            .map(|text| parse_relay(text))
            .collect::<Result<Vec<_>>>()?,
        Some(RelaysAction::Add { relay, first, note }) => {
            let mut added = parse_relay(&relay)?;
            added.note = note;
            let mut next: Vec<_> = current
                .relays
                .iter()
                .filter(|have| !same_url(&have.url, &added.url))
                .cloned()
                .collect();
            if first {
                next.insert(0, added);
            } else {
                next.push(added);
            }
            next
        }
        Some(RelaysAction::Remove { url }) => {
            let next: Vec<_> = current
                .relays
                .iter()
                .filter(|have| !same_url(&have.url, &url))
                .cloned()
                .collect();
            if next.len() == current.relays.len() {
                bail!("{url} is not in the relay list");
            }
            next
        }
    };
    let master = master_identity(&root)?;
    home::publish_relays(&root, &master, next)?;
    print_relays(&home::read_relays(&root));
    println!(
        "signed. A running worker keeps the relays it started with; \
         `ferry fleet order restart-worker` makes the fleet pick this up."
    );
    Ok(())
}

fn root() -> Result<Root> {
    ferry::find_root().context("no ferry root yet - make one with `ferry root init`")
}

fn need_fleet(root: &Root) -> Result<()> {
    if !home::exists(root) {
        bail!(
            "there is no fleet folder in {} yet; the master runs `ferry fleet init`",
            root.path.display()
        );
    }
    Ok(())
}

/// A person's identity, unlocked for this run, found in this root's attachments.
fn person_identity(root: &Root, name: &str) -> Result<AgentIdentity> {
    let mut places = vec![root.path.clone()];
    places.extend(
        root.read()
            .projects
            .iter()
            .filter_map(ferryman_channel::ferry::Entry::attachment),
    );
    for place in &places {
        if crate::held_operator().is_none() && crate::hold_operator(place, name)? {
            return crate::signing_identity_in(place, name);
        }
        if let Some(identity) = AgentIdentity::load_existing(name, place)? {
            return Ok(identity);
        }
    }
    if crate::held_operator().is_some_and(|held| held.name().eq_ignore_ascii_case(name)) {
        return crate::signing_identity_in(&places[0], name);
    }
    bail!(
        "this machine holds no key for '{name}', so it cannot sign as them. Run this on the \
         master's machine, where their identity is"
    )
}

fn master_identity(root: &Root) -> Result<AgentIdentity> {
    let master = ferry::master_of(&root.fleet_dir())?
        .context("the fleet folder has no master yet; run `ferry fleet init`")?;
    person_identity(root, &master)
}

fn say(outcome: &Publish) {
    match outcome {
        Publish::NoFleet => println!("fleet folder: none here yet"),
        Publish::Done {
            entries,
            machine_written,
        } => println!(
            "fleet folder: {entries} project entr{} current{}",
            if *entries == 1 { "y" } else { "ies" },
            if *machine_written {
                ", machine record written"
            } else {
                ""
            }
        ),
        Publish::Pending(why) => println!("fleet folder: not published yet - {why}"),
    }
}

pub fn run(command: HomeCommand) -> Result<()> {
    match command {
        HomeCommand::Init {
            master,
            no_syncthing,
        } => init(master, no_syncthing),
        HomeCommand::Admit { name, machine } => {
            let root = root()?;
            need_fleet(&root)?;
            let master = master_identity(&root)?;
            let machine = machine.unwrap_or_else(|| name.clone());
            home::admit(&root, &master, &name, &machine)?;
            println!("{name} may now write the fleet folder's entries for {machine}");
            Ok(())
        }
        HomeCommand::Relays { action, json } => relays(action, json),
        HomeCommand::Publish => {
            let root = root()?;
            need_fleet(&root)?;
            say(&ops::publish_here(&root));
            Ok(())
        }
        HomeCommand::Notices { all, json } => notices(all, json),
        HomeCommand::Notice {
            kind,
            title,
            text,
            severity,
            version,
            expires_days,
        } => {
            let root = root()?;
            need_fleet(&root)?;
            let master = master_identity(&root)?;
            let mut notice = NoticeBody::new(&kind, &severity, &title, &text);
            if let Some(days) = expires_days {
                notice.expires = Some(chrono::Utc::now() + chrono::Duration::days(days));
            }
            if let Some(version) = version {
                notice.details = serde_json::json!({ "version": version });
            }
            let id = home::post_notice(&root, &master, notice)?;
            println!("posted {id}");
            Ok(())
        }
        HomeCommand::Order { action, machine } => {
            let root = root()?;
            need_fleet(&root)?;
            let master = master_identity(&root)?;
            let order = home::issue_order(
                &root,
                &master,
                machine.as_deref(),
                &action,
                serde_json::json!({}),
            )?;
            println!(
                "ordered {action} for {}: {}",
                machine.as_deref().unwrap_or("every machine"),
                order.id
            );
            Ok(())
        }
        HomeCommand::Orders { json } => orders(json),
        HomeCommand::Machines { json } => machines(json),
        HomeCommand::WriteHints { apply, project } => write_hints(apply, &project),
    }
}

fn init(master: Option<String>, no_syncthing: bool) -> Result<()> {
    let root = root()?;
    let master = match master {
        Some(name) => name,
        None => ferryman_ops::fleet::dominant_master(&root)
            .context("who is the master? pass --master <name>")?,
    };
    let identity = person_identity(&root, &master)?;
    let report = home::init(&root, &identity)?;
    println!(
        "fleet folder {} (master {})",
        report.dir.display(),
        report.master
    );
    for made in &report.made {
        println!("  made {made}");
    }
    // What was loose in comms/ is copied forward, never moved: older binaries still read it.
    let pinned = home::copy_forward(
        &root.path.join("comms").join("agents-pinned"),
        &root.fleet_local().join("agents-pinned"),
    )?;
    if pinned > 0 {
        println!(
            "  copied {pinned} pinned key(s) into fleet/local (comms/agents-pinned is untouched)"
        );
    }
    // This machine joins as itself, admitted by the master that is here.
    let machine = ferryman_ops::identity::machine_name()?;
    let me = ops::machine_identity(&root)?;
    home::enrol(&root, &me)?;
    home::admit(&root, &identity, me.name(), &machine)?;
    say(&ops::publish(
        &root,
        &me,
        &machine,
        &ops::basic_facts(&root, Vec::new()),
    ));
    if no_syncthing {
        println!(
            "  not registered with Syncthing (--no-syncthing); the iroh lane carries it when it is on"
        );
    } else {
        let peers = ferryman_channel::syncthing_peers().unwrap_or_default();
        match ferryman_channel::syncthing_register_folder(&home::route(&root), &peers) {
            Ok(setup) if setup.available => println!(
                "  Syncthing folder {} shared with {} device(s)",
                setup.folder_id,
                setup.shared_with.len()
            ),
            Ok(setup) => println!("  Syncthing: {}", setup.note),
            Err(error) => println!("  Syncthing: not registered - {error:#}"),
        }
    }
    println!("  Other machines: their workers enrol themselves on start; admit each with");
    println!("    ferry fleet admit <machine-name>");
    Ok(())
}

fn notices(all: bool, json: bool) -> Result<()> {
    let root = root()?;
    need_fleet(&root)?;
    let (rows, findings) = home::read_notices(&root);
    let shown: Vec<_> = rows.iter().filter(|row| all || !row.expired).collect();
    if json {
        let list: Vec<_> = shown
            .iter()
            .map(|row| {
                serde_json::json!({
                    "id": row.body.id, "kind": row.body.kind, "severity": row.body.severity,
                    "title": row.body.title, "text": row.body.text, "issued": row.body.issued,
                    "expires": row.body.expires, "machine": row.body.machine,
                    "details": row.body.details, "signed_by": row.signed_by, "expired": row.expired,
                })
            })
            .collect();
        println!("{}", serde_json::to_string_pretty(&list)?);
    } else if shown.is_empty() {
        println!("no notices");
    }
    if !json {
        for row in &shown {
            println!(
                "[{}] {} {} - {} (by {}){}",
                row.body.severity,
                row.body.issued.format("%Y-%m-%d %H:%M"),
                row.body.kind,
                row.body.title,
                row.signed_by,
                if row.expired { " [expired]" } else { "" }
            );
            for line in row.body.text.lines().take(12) {
                println!("    {line}");
            }
        }
    }
    let ids: Vec<String> = shown
        .iter()
        .filter(|row| row.body.severity == "high")
        .map(|row| row.body.id.clone())
        .collect();
    let _ = home::mark_seen(&root, &ids);
    if !findings.rejected.is_empty() {
        eprintln!(
            "{} file(s) in notices/ were ignored (unsigned, forged or not admitted); `ferry doctor --layout` lists them",
            findings.rejected.len()
        );
    }
    Ok(())
}

fn orders(json: bool) -> Result<()> {
    let root = root()?;
    need_fleet(&root)?;
    let machine = ferryman_ops::identity::machine_name()?;
    let (orders, findings) = home::read_orders_for(&root, &machine);
    if json {
        println!("{}", serde_json::to_string_pretty(&orders)?);
    } else if orders.is_empty() {
        println!("no fleet orders waiting for {machine}");
    }
    if !json {
        for order in &orders {
            println!(
                "{}  {}  for {}",
                order.id,
                ops::order_action(order).unwrap_or("(an action this version does not know)"),
                order.assigned_to.as_deref().unwrap_or("every machine")
            );
        }
    }
    for item in &findings.rejected {
        eprintln!("ignored {}: {}", item.path, item.why);
    }
    Ok(())
}

fn machines(json: bool) -> Result<()> {
    let root = root()?;
    need_fleet(&root)?;
    let (rows, findings) = home::read_machines(&root);
    if json {
        let list: Vec<_> = rows
            .iter()
            .map(|row| serde_json::to_value(&row.body).unwrap_or_default())
            .collect();
        println!("{}", serde_json::to_string_pretty(&list)?);
        return Ok(());
    }
    if rows.is_empty() {
        println!("no machine has published yet");
    }
    let now = chrono::Utc::now();
    for row in &rows {
        let age = (now - row.body.last_seen).num_minutes();
        println!(
            "{:<14} ferry {:<8} layout {}  {}  {} project(s)  seen {} min ago{}",
            row.body.machine,
            row.body.version,
            row.body.layout,
            row.body.os,
            row.body.projects.len(),
            age,
            if age > 60 { "  [quiet]" } else { "" }
        );
    }
    for item in &findings.rejected {
        eprintln!("ignored {}: {}", item.path, item.why);
    }
    Ok(())
}

fn write_hints(apply: bool, only: &[String]) -> Result<()> {
    let root = root()?;
    let own = ferryman_ops::identity::machine_name()?;
    let plans: Vec<_> = home::hint_plan(&root, &own)
        .into_iter()
        .filter(|plan| only.is_empty() || only.contains(&plan.project))
        .collect();
    if plans.is_empty() {
        println!("no clone here to write a hint into");
        return Ok(());
    }
    let (mut wrote, mut refused) = (0, 0);
    for plan in &plans {
        let what = match &plan.action {
            home::HintAction::Create => "create".to_owned(),
            home::HintAction::Append => "add the block".to_owned(),
            home::HintAction::Update => "update the block".to_owned(),
            home::HintAction::Unchanged => "already current".to_owned(),
            home::HintAction::Refused(why) => {
                refused += 1;
                format!("REFUSED ({why})")
            }
        };
        let verb = match (&plan.action, apply) {
            (home::HintAction::Unchanged | home::HintAction::Refused(_), _) | (_, false) => {
                String::new()
            }
            (_, true) => match plan.apply() {
                Ok(true) => {
                    wrote += 1;
                    " - written".to_owned()
                }
                Ok(false) => String::new(),
                Err(error) => format!(" - FAILED: {error:#}"),
            },
        };
        println!("{:<22} {}: {what}{verb}", plan.project, plan.file.display());
    }
    if apply {
        println!(
            "wrote {wrote} file(s). Nothing was staged, committed or pushed; look at the diff and commit it yourself"
        );
    } else {
        println!("Nothing was written. Run it with --apply to do it.");
    }
    if refused > 0 {
        bail!("{refused} file(s) were refused and left exactly as they were");
    }
    Ok(())
}

// --- after a move --------------------------------------------------------------------------

/// After something moved (a migrate, a data path): publish this machine's directory and tell
/// the fleet, and say what happened. Never fails the command that moved things.
pub fn after_move(root: &Root, before: &Snapshot, why: &str, severity: &str) {
    let changed = ops::after_change(root, before, why, severity);
    match &changed.publish {
        Publish::NoFleet => {}
        other => say(other),
    }
    if let Some(id) = &changed.notice {
        println!(
            "fleet notice {id}: {} place(s) moved, old and new paths listed",
            changed.moved
        );
    } else if let Some(note) = &changed.notice_note
        && changed.moved > 0
    {
        println!("fleet notice: {note}");
    }
}

/// Publish this machine's directory after a command that changed what it files, saying
/// nothing unless there is a fleet folder and something to report.
pub fn publish_quiet(root: &Root) {
    match ops::publish_here(root) {
        Publish::NoFleet => {}
        Publish::Done { .. } => {}
        Publish::Pending(why) => eprintln!("fleet folder: not published yet - {why}"),
    }
}

// --- the worker ------------------------------------------------------------------------------

/// What a worker remembers between passes, so it says each thing once.
#[derive(Default)]
pub struct WorkerPass {
    told_pending: Option<String>,
    told_release: BTreeSet<String>,
    told_orders: BTreeSet<String>,
}

/// What the pass wants the worker to do.
#[derive(Debug, PartialEq, Eq)]
pub enum Next {
    Carry,
    /// Stop between passes so the supervisor starts it again (a master's order, or a new
    /// binary just installed).
    Stop(&'static str),
}

fn auto_update_off() -> bool {
    std::env::var("FERRYMAN_NO_AUTO_UPDATE").is_ok_and(|v| !v.is_empty() && v != "0")
}

impl WorkerPass {
    /// Add the worker's own identity to the fleet roster, so the iroh lane can publish its
    /// transports record there. It is not admitted by this: it still cannot write an entry.
    pub fn enrol_worker(root: &Root, worker: &AgentIdentity) {
        // A folder Syncthing has handed over may have no master.json yet; it still needs its
        // own `.stignore`.
        let _ = home::ensure_stignore(&root.fleet_dir());
        if home::exists(root) {
            let _ = home::enrol(root, worker);
        }
    }

    /// One pass: publish this machine's entries, say what the fleet has said, act on what the
    /// master ordered.
    pub async fn run(
        &mut self,
        engines: &[String],
        projects: &[String],
        report: &impl Progress,
    ) -> Next {
        let Some(root) = ferry::find_root() else {
            return Next::Carry;
        };
        if !home::exists(&root) {
            return Next::Carry;
        }
        let (Ok(machine), Ok(identity)) = (
            ferryman_ops::identity::machine_name(),
            ops::machine_identity(&root),
        ) else {
            return Next::Carry;
        };
        let facts = home::Facts {
            version: env!("CARGO_PKG_VERSION").to_owned(),
            engines: engines.to_vec(),
            projects: projects.to_vec(),
            ..home::Facts::default()
        };
        match ops::publish(&root, &identity, &machine, &facts) {
            Publish::Pending(why) => {
                if self.told_pending.as_deref() != Some(why.as_str()) {
                    report.warn(&format!("fleet folder: not publishing yet - {why}"));
                    self.told_pending = Some(why);
                }
            }
            Publish::Done { .. } | Publish::NoFleet => self.told_pending = None,
        }
        let running = env!("CARGO_PKG_VERSION");
        let heard = ops::listen(&root, &machine, running);
        for row in &heard.notices {
            report.warn(&format!(
                "fleet notice [{}] {}: {}",
                row.body.severity, row.body.kind, row.body.title
            ));
        }
        if let Some(version) = &heard.newer
            && self.told_release.insert(version.clone())
        {
            report.info(&format!(
                "fleet notice: release {version} is out (this is {running}); {}",
                if auto_update_off() {
                    "auto-update is off here (FERRYMAN_NO_AUTO_UPDATE), so run `ferry update` when you choose"
                } else {
                    "auto-update is on, so this worker takes it at its next check"
                }
            ));
        }
        for order in &heard.orders {
            let Some(action) = ops::order_action(order) else {
                if self.told_orders.insert(order.id.clone()) {
                    report.warn(&format!(
                        "fleet order {}: an action this version does not know; left alone",
                        order.id
                    ));
                }
                continue;
            };
            match action {
                "restart-worker" => {
                    let _ = home::mark_order_done(&root, &order.id);
                    report.info(&format!(
                        "fleet order {}: the master asked for a restart",
                        order.id
                    ));
                    return Next::Stop("restart ordered by the master");
                }
                "update" => {
                    if auto_update_off() {
                        if self.told_orders.insert(order.id.clone()) {
                            report.warn(&format!(
                                "fleet order {}: the master ordered an update, and this machine has \
                                 auto-update off (FERRYMAN_NO_AUTO_UPDATE). Not done; run `ferry update` yourself",
                                order.id
                            ));
                        }
                        continue;
                    }
                    match crate::update::latest_release().await {
                        Ok(latest) if crate::update::is_newer(&latest) => {
                            match crate::update::apply(&latest).await {
                                Ok(installed) => {
                                    let _ = home::mark_order_done(&root, &order.id);
                                    report.info(&format!(
                                        "fleet order {}: updated to {installed}",
                                        order.id
                                    ));
                                    return Next::Stop("updated by the master's order");
                                }
                                Err(error) => report.warn(&format!(
                                    "fleet order {}: could not update to {latest}: {error:#}",
                                    order.id
                                )),
                            }
                        }
                        Ok(_) => {
                            let _ = home::mark_order_done(&root, &order.id);
                        }
                        Err(error) => report.warn(&format!(
                            "fleet order {}: could not look for a release: {error:#}",
                            order.id
                        )),
                    }
                }
                _ => {
                    // A migrate moves the folders a running worker stands in, and refuses to
                    // while one runs. So a worker does not do it; it says so, once.
                    if self.told_orders.insert(order.id.clone()) {
                        report.warn(&format!(
                            "fleet order {}: the master ordered `{action}`. A running worker cannot \
                             do that to its own root: stop it and run `ferry root migrate --apply`",
                            order.id
                        ));
                    }
                }
            }
        }
        Next::Carry
    }
}
