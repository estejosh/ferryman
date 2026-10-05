//! `ferry focus`: which projects the swarm is spending itself on right now.
//!
//! See [`ferryman_channel::focus`]. Setting it takes the master's signature, as `ferry
//! improve on` does, and the signed record travels in the `ferryman` channel to every
//! machine. Nothing here signs on its own: `suggest` shows what the signals say and the
//! command that would sign it.

use std::path::PathBuf;

use anyhow::{Context, Result, bail};
use chrono::Utc;
use ferryman_channel::focus::{self, Focus, Overview, Tier};
use ferryman_channel::focus_suggest::{self, Suggestions};
use serde_json::json;

use super::signing_identity_in;

#[derive(clap::Subcommand, Clone)]
pub(crate) enum FocusCommand {
    /// The focus in force: who signed it, each project's tier and expiry, what that comes
    /// to this week (improvement orders planned, the width they may run at), and a warning
    /// when this machine is holding on to an earlier record.
    Show {
        /// Print JSON instead of text.
        #[arg(long)]
        json: bool,
    },
    /// Put projects in a tier, signed as the master: `focus` (most of the improve time and
    /// the first claim on workers), `normal`, `background` (a trickle) or `paused` (nothing
    /// of the swarm's own; a person's orders still run). Other projects keep their entries.
    ///
    ///   ferry focus set ferryman,redaktly,bullship focus --days 30
    ///   ferry focus set oddsports background
    Set {
        /// A project id, or several separated by commas.
        projects: String,
        /// focus, normal, background or paused.
        tier: String,
        /// The entry lasts this many days (1 to 366), then the project reads as normal
        /// again. Without it the entry holds until changed.
        #[arg(long)]
        days: Option<i64>,
    },
    /// What the fleet's own signals say each project's tier should be - recent git
    /// activity, open and failed orders, what the last `improve gather` found, how long
    /// it has been quiet - with one reason per project. With no record signed it starts
    /// from your seed list (FERRYMAN_FOCUS_SEED, or `focus-seed` in the ferry root).
    /// Nothing is signed.
    Suggest {
        #[arg(long)]
        json: bool,
    },
    /// Take entries off, signed: the named projects, or every entry with none named. Every
    /// project is then normal again.
    Clear {
        #[arg(value_delimiter = ',')]
        projects: Vec<String>,
    },
}

/// ,b, c as project ids.
fn split(list: &str) -> Vec<String> {
    list.split(',')
        .map(str::trim)
        .filter(|name| !name.is_empty())
        .map(str::to_string)
        .collect()
}

/// The home project's channel on this machine, and where its keys are.
struct Home {
    project: String,
    channel: PathBuf,
    attachment: PathBuf,
}

fn home() -> Result<Home> {
    let project = focus::home_project();
    let root = ferryman_channel::ferry::find_root()
        .context("no ferry root yet - make one with `ferry root init`")?;
    let entry = root
        .read()
        .projects
        .into_iter()
        .find(|entry| entry.project_id == project && entry.channel.is_dir())
        .with_context(|| {
            format!(
                "the focus lives in {project}'s channel, which is not on this machine \
                 (set FERRYMAN_FOCUS_HOME to name another home project)"
            )
        })?;
    let attachment = entry
        .repo
        .as_ref()
        .map(|repo| repo.join(".ferryman"))
        .filter(|attachment| attachment.is_dir())
        .unwrap_or_else(|| root.path.clone());
    Ok(Home {
        project,
        channel: entry.channel,
        attachment,
    })
}

/// Every project in the ferry root here, as (id, channel).
fn projects() -> Vec<(String, PathBuf)> {
    ferryman_channel::ferry::find_root()
        .map(|root| {
            root.read()
                .projects
                .into_iter()
                .filter(|entry| entry.channel.is_dir())
                .map(|entry| (entry.project_id, entry.channel))
                .collect()
        })
        .unwrap_or_default()
}

/// What `show` and `set` print: who signed it, and each project's line.
fn print_focus(focus: &Focus, rows: &[Overview]) {
    match &focus.setting {
        Some(setting) if !setting.projects.is_empty() => println!(
            "focus: signed by {}, {} UTC (sequence {}), in {}'s channel",
            setting.set_by(),
            setting.set_at.format("%Y-%m-%d %H:%M"),
            setting.seq,
            setting.home
        ),
        Some(setting) => println!(
            "focus: cleared by {}, {} UTC - every project is normal",
            setting.set_by(),
            setting.set_at.format("%Y-%m-%d %H:%M")
        ),
        None => println!("focus: none signed - every project is normal"),
    }
    if let Some(notice) = &focus.notice {
        println!("  warning: {notice}");
        println!("  this machine is using the last record it saw; sign again to settle it");
    }
    let now = Utc::now();
    for (project, pin) in focus.expired(now) {
        println!(
            "  {project}: {} ended, so it is normal again",
            pin.describe()
        );
    }
    if rows.is_empty() {
        return;
    }
    let width = rows
        .iter()
        .map(|row| row.project.chars().count())
        .max()
        .unwrap_or(0);
    println!(
        "  {:width$}  {:<11} {:<24} {:<14} width build/chore",
        "project", "tier", "entry", "orders a week"
    );
    for row in rows {
        let orders = match row.orders {
            Some(orders) => orders.to_string(),
            None => "self-improve off".to_string(),
        };
        let cap = |role: &str| {
            row.width
                .get(role)
                .copied()
                .flatten()
                .map_or("-".to_string(), |width| width.to_string())
        };
        println!(
            "  {:width$}  {:<11} {:<24} {:<14} {}/{}",
            row.project,
            row.tier.as_str(),
            row.entry.as_deref().unwrap_or("-"),
            orders,
            cap("build"),
            cap("chore")
        );
    }
}

fn show(as_json: bool) -> Result<()> {
    let focus = focus::current();
    let now = Utc::now();
    let rows = focus::overview(&projects(), &focus, focus::PER_PROJECT, now);
    if as_json {
        let setting = focus.setting.as_ref();
        println!(
            "{}",
            serde_json::to_string_pretty(&json!({
                "home": focus.home,
                "set_by": setting.map(ferryman_channel::focus::FocusSetting::set_by),
                "set_at": setting.map(|s| s.set_at),
                "seq": setting.map(|s| s.seq),
                "notice": focus.notice,
                "projects": rows,
            }))?
        );
        return Ok(());
    }
    print_focus(&focus, &rows);
    if !focus.is_set() {
        println!("  see what the signals suggest: ferry focus suggest");
    }
    Ok(())
}

/// Sign a change to the entries as the home channel's master.
fn sign(
    change: impl FnOnce(&mut std::collections::BTreeMap<String, focus::Pin>) -> Result<()>,
) -> Result<bool> {
    let home = home()?;
    let Some(master) = ferryman_channel::ferry::master_of(&home.channel)? else {
        bail!(
            "{} has no master, and only its master sets the focus.\n\
             \n\
             Claim every project that has none:  ferry root master",
            home.project
        );
    };
    let identity = signing_identity_in(&home.attachment, &master)?;
    focus::set(
        &home.channel,
        &home.project,
        &identity,
        None,
        change,
        Utc::now(),
    )
}

fn set(names: &[String], tier: &str, days: Option<i64>) -> Result<()> {
    let tier = Tier::parse(tier)?;
    if names.is_empty() {
        bail!("name a project, or several separated by commas");
    }
    let known = projects();
    for name in names {
        match known.iter().find(|(project, _)| project == name) {
            Some((project, channel)) if ferryman_channel::ferry::is_archived(channel, project) => {
                bail!(
                    "{project} is archived, and an archived project gets nothing; bring it \
                     back first with 'ferry root archive {project} --restore'"
                );
            }
            Some(_) => {}
            None => println!(
                "note: {name} is not in this machine's ferry root; it is recorded anyway and \
                 takes effect where the project is"
            ),
        }
    }
    let now = Utc::now();
    let changed = sign(|entries| {
        for name in names {
            focus::pin_project(entries, name, tier, days, now)?;
        }
        Ok(())
    })?;
    println!(
        "{}",
        if changed {
            format!(
                "{} set to {tier}{}, signed; every machine that syncs the channel follows it",
                names.join(", "),
                days.map_or(String::new(), |days| format!(" for {days} day(s)"))
            )
        } else {
            "already so".to_string()
        }
    );
    show(false)
}

fn clear(names: &[String]) -> Result<()> {
    let changed = sign(|entries| {
        if names.is_empty() {
            entries.clear();
        } else {
            for name in names {
                entries.remove(name);
            }
        }
        Ok(())
    })?;
    println!(
        "{}",
        match (changed, names.is_empty()) {
            (false, _) => "nothing to clear".to_string(),
            (true, true) => "focus cleared, signed: every project is normal".to_string(),
            (true, false) => format!("{} cleared, signed", names.join(", ")),
        }
    );
    Ok(())
}

/// The command that would sign `tier` for `projects`.
fn command_for(projects: &[&str], tier: Tier, days: bool) -> String {
    format!(
        "ferry focus set {} {tier}{}",
        projects.join(","),
        if days { " --days 30" } else { "" }
    )
}

fn suggest(as_json: bool) -> Result<()> {
    let focus = focus::current();
    let candidates = focus_suggest::candidates_from_root();
    if candidates.is_empty() {
        bail!("no projects in this machine's ferry root; see 'ferry root show'");
    }
    let seed = focus_suggest::seed_list();
    let suggestions = focus_suggest::suggest(&candidates, &focus, &seed, Utc::now());
    if as_json {
        println!("{}", serde_json::to_string_pretty(&suggestions)?);
        return Ok(());
    }
    print_suggestions(&suggestions);
    Ok(())
}

fn print_suggestions(suggestions: &Suggestions) {
    if suggestions.seeded {
        println!(
            "No focus is signed. Starting from your seed list ({}), the rest from the signals.",
            focus_suggest::SEED_FILE
        );
    }
    for name in &suggestions.seed_missing {
        println!("  note: {name} is in the seed list but is not a project in this ferry root");
    }
    let width = suggestions
        .rows
        .iter()
        .map(|row| row.project.chars().count())
        .max()
        .unwrap_or(0);
    println!(
        "  {:width$}  {:<11} {:<11} why",
        "project", "now", "suggested"
    );
    for row in &suggestions.rows {
        let mark = if row.tier == row.now { " " } else { "*" };
        println!(
            "{mark} {:width$}  {:<11} {:<11} {}",
            row.project,
            row.now.as_str(),
            row.tier.as_str(),
            row.reason
        );
    }
    let changes = suggestions.changes();
    if changes.is_empty() {
        println!("nothing to change: the focus already matches the signals");
        return;
    }
    println!("\nNothing is signed. To sign what is marked *, as the master:");
    for tier in Tier::ALL {
        let names: Vec<&str> = changes
            .iter()
            .filter(|(_, wanted)| *wanted == tier)
            .map(|(project, _)| *project)
            .collect();
        if !names.is_empty() {
            println!("  {}", command_for(&names, tier, tier != Tier::Normal));
        }
    }
}

pub(crate) fn command(command: FocusCommand) -> Result<()> {
    match command {
        FocusCommand::Show { json } => show(json),
        FocusCommand::Set {
            projects,
            tier,
            days,
        } => set(&split(&projects), &tier, days),
        FocusCommand::Suggest { json } => suggest(json),
        FocusCommand::Clear { projects } => clear(&projects),
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use clap::Parser;

    #[derive(Parser)]
    struct Cli {
        #[command(subcommand)]
        command: FocusCommand,
    }

    /// Josh's own initial command, as the docs give it, parses into one entry per project.
    #[test]
    fn the_documented_commands_parse() {
        let cli = Cli::try_parse_from([
            "focus",
            "set",
            "ferryman,redaktly,bullship",
            "focus",
            "--days",
            "30",
        ])
        .unwrap();
        let FocusCommand::Set {
            projects,
            tier,
            days,
        } = cli.command
        else {
            panic!("not set")
        };
        assert_eq!(split(&projects), ["ferryman", "redaktly", "bullship"]);
        assert_eq!(tier, "focus");
        assert_eq!(days, Some(30));
        assert!(Cli::try_parse_from(["focus", "show", "--json"]).is_ok());
        assert!(Cli::try_parse_from(["focus", "suggest"]).is_ok());
        assert!(Cli::try_parse_from(["focus", "clear"]).is_ok());
        assert!(Cli::try_parse_from(["focus", "clear", "a,b"]).is_ok());
        assert!(Cli::try_parse_from(["focus", "set", "oddsports", "background"]).is_ok());
        assert!(
            Cli::try_parse_from(["focus", "set", "oddsports"]).is_err(),
            "no tier"
        );
    }

    #[test]
    fn the_suggested_command_names_the_projects_and_the_tier() {
        assert_eq!(
            command_for(&["a", "b"], Tier::Focus, true),
            "ferry focus set a,b focus --days 30"
        );
        assert_eq!(
            command_for(&["c"], Tier::Normal, false),
            "ferry focus set c normal"
        );
    }
}
