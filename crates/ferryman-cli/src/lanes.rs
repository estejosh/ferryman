//! `ferry lanes ...` and `ferry counter ...`: several agents, one repository (ADR 0029).
//!
//! The logic is in `ferryman_channel::lanes` and `ferryman_channel::counters`; this file
//! is argument parsing, choosing the project and the agent, and saying what happened.
//! (`ferry lane iroh` is the transport lane and is unrelated; hence the plural.)

use std::path::PathBuf;
use std::time::Duration;

use anyhow::{Context, Result, bail};
use ferryman_channel::lanes::{self, LandOptions, LandOutcome};
use ferryman_channel::{AgentIdentity, ProjectRoute, counters, ferry};

#[derive(clap::Subcommand, Clone)]
pub(crate) enum LanesCommand {
    /// Make a lane: its own worktree and branch, the paths it owns, and a pre-commit hook.
    ///
    /// The worktree is <repo>/.lanes/<lane> on branch lane/<lane>. Work there; never in
    /// another lane's folder and never in the main checkout.
    New {
        /// The project (as `ferry root show` lists it).
        project: String,
        /// The lane's name: a task or role, e.g. game, art.
        lane: String,
        /// A glob this lane owns (repeatable): art/**, assets/*.png. Required.
        #[arg(long = "owns", required = true)]
        owns: Vec<String>,
        /// A shared file any lane may touch, beyond DECISIONS.md, README.md, CHANGELOG.md.
        #[arg(long = "shared")]
        shared: Vec<String>,
        /// A log only ever appended to (repeatable), e.g. DECISIONS.md: concurrent additions
        /// merge by union when the lane lands. Never name a file that is edited in place.
        #[arg(long = "append-only")]
        append_only: Vec<String>,
        /// The branch the lane lands on. Default: main (or master).
        #[arg(long)]
        base: Option<String>,
        /// Act as this agent (default: this machine's).
        #[arg(long)]
        agent: Option<String>,
    },
    /// The lanes of a project: owner, ownership, ahead/behind, dirty, live sessions.
    List {
        #[arg(long)]
        project: Option<String>,
        /// Include retired lanes.
        #[arg(long)]
        all: bool,
        #[arg(long)]
        json: bool,
    },
    /// Register this agent session in the current worktree and print its rules. Run it at
    /// the start of a session, inside your lane.
    Enter {
        /// Your session id. Default: $FERRY_SESSION, $CLAUDE_SESSION_ID, or a new one.
        #[arg(long)]
        session: Option<String>,
        #[arg(long)]
        pid: Option<u32>,
        #[arg(long)]
        agent: Option<String>,
    },
    /// Say this session has ended.
    Leave {
        #[arg(long)]
        session: Option<String>,
    },
    /// The pre-commit hook's check. Not for people.
    #[command(hide = true)]
    Check,
    /// Land a lane: rebase onto its base and fast-forward it, one landing at a time.
    ///
    /// On a conflict nothing is touched: the files are listed and the lane's owner is
    /// told. Run it from anywhere in the project.
    Land {
        lane: String,
        #[arg(long)]
        project: Option<String>,
        /// Push the base to the remote afterwards, with the sealed token.
        #[arg(long)]
        push: bool,
        /// Do not fetch the remote first.
        #[arg(long)]
        no_fetch: bool,
        /// Land even though the lane touched paths another lane owns. Logged.
        #[arg(long, value_name = "REASON")]
        allow_foreign: Option<String>,
        /// Seconds to wait for another landing to finish.
        #[arg(long, default_value_t = 60)]
        wait: u64,
        /// Milliseconds to wait after claiming the landing lock, for a peer's claim to show.
        /// Default: 1000 when only this machine uses the project, 8000 when others do.
        #[arg(long)]
        settle_ms: Option<u64>,
        /// The sealed secret holding the push token (see `ferry channel secret`).
        #[arg(long, default_value = "GH_TOKEN")]
        secret: String,
        #[arg(long, default_value = "origin")]
        remote: String,
        #[arg(long)]
        agent: Option<String>,
    },
    /// Remove a lane's worktree and branch, and free the paths it owns.
    Retire {
        lane: String,
        #[arg(long)]
        project: Option<String>,
        /// Retire even with uncommitted files, a live session or unlanded commits (the branch
        /// tip is first saved under refs/ferry/retired/<lane>/).
        #[arg(long)]
        force: bool,
        #[arg(long)]
        agent: Option<String>,
    },
}

#[derive(clap::Subcommand, Clone)]
pub(crate) enum CounterCommand {
    /// Take the next number of a counter and print it (and nothing else).
    Next {
        name: String,
        #[arg(long)]
        project: Option<String>,
        /// The first number of a counter that has none yet, and a floor for later ones.
        #[arg(long, default_value_t = 1)]
        start: u64,
        /// Seconds to wait for a peer's earlier claim to arrive. Default: 0 when only this
        /// machine has used the counter, 8 when others have.
        #[arg(long)]
        settle: Option<u64>,
        /// Take a number although the policy names a different allocator.
        #[arg(long)]
        provisional: bool,
        #[arg(long)]
        agent: Option<String>,
    },
    /// Every number taken, and by whom.
    List {
        name: String,
        #[arg(long)]
        project: Option<String>,
        #[arg(long)]
        json: bool,
    },
    /// Find numbers more than one agent claimed, and who won each.
    Check {
        name: String,
        #[arg(long)]
        project: Option<String>,
    },
    /// Master only: name the single allocator and/or give agents disjoint ranges.
    Policy {
        name: String,
        #[arg(long)]
        project: Option<String>,
        #[arg(long)]
        allocator: Option<String>,
        /// agent=START-END, e.g. ash=1000-1999 (repeatable).
        #[arg(long = "range")]
        ranges: Vec<String>,
        #[arg(long)]
        agent: Option<String>,
    },
}

fn route_of(project: Option<&str>) -> Result<ProjectRoute> {
    let cwd = std::env::current_dir().context("read the current directory")?;
    if let Some(project) = project {
        if let Ok(route) = ferryman_channel::route_for(&cwd)
            && route.project_id == project
        {
            return Ok(route);
        }
        let root = ferry::find_root()
            .context("no ferry root here; run this from the project's checkout")?;
        let entry = root
            .projects()
            .into_iter()
            .find(|e| e.project_id == project)
            .with_context(|| {
                format!(
                    "no project '{project}' in {}",
                    root.manifest_path().display()
                )
            })?;
        return Ok(entry.route(&root)?.0);
    }
    ferryman_channel::route_for(&cwd)
}

fn me(route: &ProjectRoute, agent: Option<String>) -> Result<AgentIdentity> {
    let name = ferryman_ops::identity::resolve(agent, &route.attachment)?;
    crate::signing_identity(route, &name)
}

fn token(route: &ProjectRoute, secret: &str) -> Result<String> {
    let agent = ferryman_ops::identity::resolve(None, &route.attachment)?;
    let Some(identity) =
        ferryman_channel::secrets::EncryptionIdentity::load_existing(&agent, &route.attachment)?
    else {
        bail!(
            "this machine's agent ('{agent}') has no encryption key; run 'ferry channel join' first"
        );
    };
    ferryman_channel::secrets::open_secret(route, secret, &identity)
        .with_context(|| format!("open the sealed secret '{secret}' (see `ferry channel secret`)"))
}

pub(crate) fn command(command: LanesCommand) -> Result<()> {
    match command {
        LanesCommand::New {
            project,
            lane,
            owns,
            shared,
            append_only,
            base,
            agent,
        } => {
            let route = route_of(Some(&project))?;
            let identity = me(&route, agent)?;
            let exe = std::env::current_exe().context("find this ferry binary")?;
            let (record, dir) = lanes::new_lane(
                &route,
                &identity,
                lanes::NewLane {
                    lane: &lane,
                    owns,
                    shared,
                    append_only,
                    base,
                    exe,
                },
            )?;
            println!("lane {} is ready", record.lane);
            println!("  worktree  {}", dir.display());
            println!("  branch    {}  (lands on {})", record.branch, record.base);
            println!("  owns      {}", record.owns.join(", "));
            println!("  owner     {} on {}", record.owner, record.machine);
            println!();
            println!(
                "  Work only inside the worktree. Commit there; land with `ferry lanes land {}`.",
                record.lane
            );
        }
        LanesCommand::List { project, all, json } => {
            let route = route_of(project.as_deref())?;
            let lines = lanes::summary(&route, all)?;
            let loaded = lanes::load(&route)?;
            if json {
                println!("{}", serde_json::to_string_pretty(&lines)?);
                return Ok(());
            }
            if lines.is_empty() {
                println!(
                    "no lanes in {}.  ferry lanes new {} <lane> --owns <glob>",
                    route.project_id, route.project_id
                );
            }
            for l in &lines {
                let state = match (&l.path, l.dirty) {
                    (None, _) => "not on this machine".to_string(),
                    (Some(_), d) => format!(
                        "+{} -{}{}",
                        l.ahead.unwrap_or(0),
                        l.behind.unwrap_or(0),
                        if d == Some(true) { " dirty" } else { "" }
                    ),
                };
                println!(
                    "{:<12} {:<8} {:<8} {}  owns {}  [{}{}]",
                    l.lane,
                    l.status,
                    l.owner,
                    l.branch,
                    l.owns.join(","),
                    state,
                    if l.live_sessions > 0 {
                        format!(", {} live", l.live_sessions)
                    } else {
                        String::new()
                    }
                );
            }
            for problem in loaded.problems {
                println!("warning: {problem}");
            }
        }
        LanesCommand::Enter {
            session,
            pid,
            agent,
        } => {
            let cwd = std::env::current_dir()?;
            let gitdir = PathBuf::from(
                String::from_utf8_lossy(
                    &std::process::Command::new("git")
                        .arg("-C")
                        .arg(&cwd)
                        .args(["rev-parse", "--absolute-git-dir"])
                        .output()
                        .context("run git")?
                        .stdout,
                )
                .trim(),
            );
            if !gitdir.is_dir() {
                bail!("{} is not inside a git worktree", cwd.display());
            }
            let route = ferryman_channel::route_for(&cwd).ok();
            let agent = match (&route, agent) {
                (Some(r), a) => ferryman_ops::identity::resolve(a, &r.attachment)?,
                (None, Some(a)) => a,
                (None, None) => ferryman_ops::identity::machine_name()?,
            };
            let id = session
                .or_else(lanes::current_session_id)
                .unwrap_or_else(|| lanes::stable_session_id(&agent, &cwd));
            let others: Vec<_> = lanes::live_sessions(&gitdir, chrono::Utc::now())
                .into_iter()
                .filter(|m| m.session != id)
                .collect();
            lanes::register_session(&gitdir, &id, &agent, pid)?;
            println!("session {id} registered as {agent} in {}", cwd.display());
            println!(
                "  keep it alive by committing here, or run this again; set FERRY_SESSION={id} to reuse it"
            );
            match lanes::read_marker(&gitdir) {
                Some(m) => {
                    println!(
                        "  you are in lane '{}'. The pre-commit hook refuses paths another lane owns.",
                        m.lane
                    );
                    println!(
                        "  Land with `ferry lanes land {}`; take numbers with `ferry counter next <name>`.",
                        m.lane
                    );
                }
                None => println!(
                    "  this is NOT a lane. Do not share it: `ferry lanes new <project> <lane> --owns <glob>` gives you your own."
                ),
            }
            if !others.is_empty() {
                println!(
                    "warning: {} other live session(s) work in this same tree ({}). One index, one HEAD: move to a lane.",
                    others.len(),
                    others
                        .iter()
                        .map(|m| format!("{}:{}", m.agent, m.session))
                        .collect::<Vec<_>>()
                        .join(", ")
                );
            }
        }
        LanesCommand::Leave { session } => {
            let cwd = std::env::current_dir()?;
            let out = std::process::Command::new("git")
                .arg("-C")
                .arg(&cwd)
                .args(["rev-parse", "--absolute-git-dir"])
                .output()
                .context("run git")?;
            let gitdir = PathBuf::from(String::from_utf8_lossy(&out.stdout).trim());
            let id = session
                .or_else(lanes::current_session_id)
                .context("which session? pass --session or set FERRY_SESSION")?;
            lanes::release_session(&gitdir, &id);
            println!("session {id} released");
        }
        LanesCommand::Check => {
            let cwd = std::env::current_dir()?;
            let reason = std::env::var("FERRY_LANE_OVERRIDE").ok();
            let Some(outcome) = lanes::check_staged(&cwd, reason.as_deref(), |route, owner| {
                AgentIdentity::load_existing(owner, &route.attachment)
                    .ok()
                    .flatten()
            })?
            else {
                return Ok(());
            };
            if let Some(note) = &outcome.offline {
                eprintln!("ferry lanes: warning: {note}");
            }
            for problem in &outcome.problems {
                eprintln!("ferry lanes: warning: {problem}");
            }
            let r = &outcome.report;
            if !r.unowned.is_empty() {
                eprintln!(
                    "ferry lanes: note: {} path(s) nobody owns: {}",
                    r.unowned.len(),
                    r.unowned.join(", ")
                );
            }
            if !r.shared.is_empty() {
                eprintln!(
                    "ferry lanes: note: shared file(s) {}: allowed; append only, and they reach main through `ferry lanes land`",
                    r.shared.join(", ")
                );
            }
            if r.refused.is_empty() {
                return Ok(());
            }
            let list = r
                .refused
                .iter()
                .map(|(p, o)| format!("  {p}  (lane {o})"))
                .collect::<Vec<_>>()
                .join("\n");
            if let Some(reason) = outcome.overridden {
                eprintln!("ferry lanes: OVERRIDE logged ({reason}) for:\n{list}");
                return Ok(());
            }
            bail!(
                "lane '{}' may not commit paths another lane owns:\n{list}\n\
                 Unstage them (git restore --staged <path>) and hand the change to the owning lane. \
                 If it really must go in: FERRY_LANE_OVERRIDE=\"why\" git commit ... (logged in the channel)",
                r.lane
            )
        }
        LanesCommand::Land {
            lane,
            project,
            push,
            no_fetch,
            allow_foreign,
            wait,
            settle_ms,
            secret,
            remote,
            agent,
        } => {
            let route = route_of(project.as_deref())?;
            let identity = me(&route, agent)?;
            let token = if push {
                Some(token(&route, &secret)?)
            } else {
                None
            };
            // Fetching a private https remote needs the token too; take it if it is there.
            let token = token.or_else(|| {
                if no_fetch {
                    None
                } else {
                    self::token(&route, &secret).ok()
                }
            });
            let opts = LandOptions {
                remote,
                fetch: !no_fetch,
                push,
                allow_foreign,
                wait_secs: wait,
                settle_ms: settle_ms.unwrap_or_else(|| {
                    let d = counters::default_settle(&route).as_millis();
                    u64::try_from(d).unwrap_or(8000).max(1000)
                }),
                token,
            };
            match lanes::land(&route, &identity, &lane, &opts)? {
                LandOutcome::Landed {
                    base,
                    commits,
                    old_tip,
                    new_tip,
                    pushed,
                    push_note,
                    lane_note,
                } => {
                    println!(
                        "landed {commits} commit(s) of lane '{lane}' on {base}: {} -> {}",
                        &old_tip[..8],
                        &new_tip[..8]
                    );
                    println!(
                        "  the lane now sits on the new {base}; the old tip is kept at refs/ferry/landed/{lane}/*"
                    );
                    if let Some(note) = lane_note {
                        eprintln!("warning: {note}");
                    }
                    if pushed {
                        println!("  pushed {base}");
                    }
                    if let Some(note) = push_note {
                        bail!("{note}");
                    }
                }
                LandOutcome::NothingToLand => {
                    println!("lane '{lane}' has nothing that is not already on its base")
                }
                LandOutcome::Conflict { files, notified } => {
                    bail!(
                        "landing lane '{lane}' stopped: conflicts in {}.\n\
                         Nothing was changed; the lane is as you left it{}. \
                         Rebase it in its worktree, resolve, commit, and land again.",
                        files.join(", "),
                        if notified {
                            " and its owner has been told"
                        } else {
                            ""
                        }
                    );
                }
                LandOutcome::Refused(why) => bail!("not landed: {why}"),
            }
        }
        LanesCommand::Retire {
            lane,
            project,
            force,
            agent,
        } => {
            let route = route_of(project.as_deref())?;
            let identity = me(&route, agent)?;
            let branch = lanes::retire_lane(&route, &identity, &lane, force)?;
            println!("lane '{lane}' retired; worktree and {branch} removed, its paths are free");
        }
    }
    Ok(())
}

fn parse_range(text: &str) -> Result<(String, (u64, u64))> {
    let (agent, span) = text
        .split_once('=')
        .with_context(|| format!("'{text}' is not agent=START-END"))?;
    let (start, end) = span
        .split_once('-')
        .with_context(|| format!("'{text}' is not agent=START-END"))?;
    Ok((
        agent.trim().to_lowercase(),
        (start.trim().parse()?, end.trim().parse()?),
    ))
}

pub(crate) fn counter_command(command: CounterCommand) -> Result<()> {
    match command {
        CounterCommand::Next {
            name,
            project,
            start,
            settle,
            provisional,
            agent,
        } => {
            let route = route_of(project.as_deref())?;
            let identity = me(&route, agent)?;
            let machine = lanes::this_machine();
            let settle = settle.unwrap_or_else(|| counters::default_settle(&route).as_secs());
            let n = counters::next(
                &route,
                &identity,
                &name,
                &counters::NextOptions {
                    start,
                    settle: Duration::from_secs(settle),
                    provisional,
                    machine,
                },
            )?;
            println!("{n}");
        }
        CounterCommand::List {
            name,
            project,
            json,
        } => {
            let route = route_of(project.as_deref())?;
            let held = counters::held(&route, &name)?;
            if json {
                println!("{}", serde_json::to_string_pretty(&held)?);
                return Ok(());
            }
            for h in held {
                println!(
                    "{:>6}  {} on {}  {}{}",
                    h.n,
                    h.winner.agent,
                    h.winner.machine,
                    h.winner.claimed_at.to_rfc3339(),
                    if h.losers.is_empty() {
                        String::new()
                    } else {
                        format!("  (contested by {})", h.losers.len())
                    }
                );
            }
        }
        CounterCommand::Check { name, project } => {
            let route = route_of(project.as_deref())?;
            let contested: Vec<_> = counters::held(&route, &name)?
                .into_iter()
                .filter(|h| !h.losers.is_empty())
                .collect();
            if contested.is_empty() {
                println!("{name}: every number has one claim");
                return Ok(());
            }
            for h in &contested {
                println!(
                    "{} goes to {} on {}; also claimed by {}",
                    h.n,
                    h.winner.agent,
                    h.winner.machine,
                    h.losers
                        .iter()
                        .map(|l| format!("{} on {}", l.agent, l.machine))
                        .collect::<Vec<_>>()
                        .join(", ")
                );
            }
            bail!(
                "{} number(s) were claimed twice; the losers must take another number",
                contested.len()
            );
        }
        CounterCommand::Policy {
            name,
            project,
            allocator,
            ranges,
            agent,
        } => {
            let route = route_of(project.as_deref())?;
            let identity = me(&route, agent)?;
            let ranges = ranges
                .iter()
                .map(|r| parse_range(r))
                .collect::<Result<_>>()?;
            let policy = counters::set_policy(&route, &identity, &name, allocator, ranges)?;
            println!("{}", serde_json::to_string_pretty(&policy)?);
        }
    }
    Ok(())
}

/// The lane lines of `ferry doctor`, for the workspace it was run in.
pub(crate) fn doctor_findings(start: &std::path::Path) -> Vec<lanes::Finding> {
    let Ok(route) = ferryman_channel::route_for(start) else {
        return Vec::new();
    };
    let days = std::env::var("FERRY_LANE_STALE_DAYS")
        .ok()
        .and_then(|v| v.parse().ok())
        .unwrap_or(7);
    lanes::doctor(&route, days, 100)
}
