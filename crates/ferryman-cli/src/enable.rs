//! `ferry enable` - point a project at Ferryman in one non-interactive step.
//!
//! # The caller is usually not a person
//!
//! This is written to be run by an agent that has just been told to put a project on
//! Ferryman, with nobody watching. Everything that follows from that:
//!
//! - **It never prompts.** No terminal, no confirmation, no editor. Every decision is a
//!   flag with a defensible default.
//! - **It is idempotent.** Running it twice is not an error and does not clobber an
//!   edited config. An agent that cannot remember whether it already ran can simply run
//!   it again, which is the normal state of affairs for an agent.
//! - **It reports in JSON on request**, including exactly which files it created versus
//!   found, so a caller can tell "I set this up" from "it was already set up" without
//!   parsing prose.
//! - **It verifies itself.** Before returning success it re-reads the channel through
//!   the same code path everything else uses. Writing files that happen to be wrong is
//!   the failure mode that would waste the most of an unattended agent's time.
//!
//! It deliberately does NOT touch the work repository: no commits, no hooks, no
//! modified build. Everything it writes lives under `.ferryman/`, which is the whole
//! separation Ferryman is built on.

use anyhow::{Context, Result, bail};
use ferryman_channel::{AgentRoute, ProjectRoute};
use serde_json::json;
use std::fs;
use std::path::PathBuf;

use crate::agent::{AgentConfig, ReviewMode};

pub struct Request {
    pub workspace: Option<PathBuf>,
    pub project: Option<String>,
    pub agent: Option<String>,
    pub role: String,
    pub command: String,
    pub review: String,
    pub as_json: bool,
}

/// A file this run created, or found already correct.
struct Step {
    what: &'static str,
    path: PathBuf,
    created: bool,
}

/// Everything the caller needs to know, separated from how it is printed so the same
/// facts drive the human output, the JSON and the tests.
struct Outcome {
    project: String,
    agent: String,
    workspace: PathBuf,
    route: ProjectRoute,
    public_key: String,
    config: AgentConfig,
    steps: Vec<Step>,
}

pub fn run(request: Request) -> Result<()> {
    let as_json = request.as_json;
    let outcome = perform(request)?;
    if as_json {
        report_json(&outcome)
    } else {
        report_human(&outcome)
    }
}

fn perform(request: Request) -> Result<Outcome> {
    let workspace = match request.workspace {
        Some(path) => path,
        None => std::env::current_dir().context("read the current directory")?,
    };
    let workspace = workspace
        .canonicalize()
        .with_context(|| format!("{} does not exist", workspace.display()))?;

    let project = match request.project {
        Some(id) => id,
        None => workspace
            .file_name()
            .and_then(|n| n.to_str())
            .map(slug)
            .filter(|s| !s.is_empty())
            .context("could not name the project from the directory; pass --project")?,
    };
    if !ferryman_channel::is_safe_component(&project) {
        bail!("project id '{project}' is not a path-safe identifier")
    }
    let agent_name = match request.agent {
        Some(name) => slug(&name),
        None => default_agent_name(),
    };
    if !ferryman_channel::is_safe_component(&agent_name) {
        bail!("agent name '{agent_name}' is not a path-safe identifier")
    }
    let review = ReviewMode::parse(&request.review)?;

    let attachment = workspace.join(".ferryman");
    let communications = attachment.join("ferryman");
    let shared_remote = format!("{project}-ferryman");
    let mut steps = Vec::new();

    fs::create_dir_all(&communications)
        .with_context(|| format!("create {}", communications.display()))?;

    // bridge.toml is what every other command discovers the project through, so it is
    // written first and never rewritten: an operator who edited it means it.
    let bridge = attachment.join("bridge.toml");
    let bridge_created = !bridge.exists();
    if bridge_created {
        fs::write(
            &bridge,
            format!(
                "project = \"{project}\"\n\
                 workspace = \"{}\"\n\
                 attachment = \"{}\"\n\
                 communications = \"{}\"\n\
                 shared_remote = \"{shared_remote}\"\n",
                workspace.display(),
                attachment.display(),
                communications.display(),
            ),
        )
        .with_context(|| format!("write {}", bridge.display()))?;
    }
    steps.push(Step {
        what: "channel config",
        path: bridge.clone(),
        created: bridge_created,
    });

    // Keep the private half out of the synced folder. Written before any key exists, so
    // there is no window in which a key could be carried away.
    let ignore = communications.join(".stignore");
    let ignore_created = !ignore.exists();
    if ignore_created {
        fs::write(&ignore, "keys\n*.tmp\n*.key\n")
            .with_context(|| format!("write {}", ignore.display()))?;
    }
    steps.push(Step {
        what: "sync exclusions",
        path: ignore.clone(),
        created: ignore_created,
    });

    let config_path = AgentConfig::path(&attachment);
    let config_created = !config_path.exists();
    if config_created {
        fs::write(
            &config_path,
            AgentConfig::render(
                &agent_name,
                &request.role,
                &request.command,
                &["-p".to_string(), "{prompt}".to_string()],
                review,
            ),
        )
        .with_context(|| format!("write {}", config_path.display()))?;
    }
    steps.push(Step {
        what: "agent config",
        path: config_path.clone(),
        created: config_created,
    });

    // Read the route back through the same discovery every other command uses, rather
    // than trusting the values just written.
    let route: ProjectRoute = ferryman_channel::route_for(&workspace)
        .context("the channel was written but cannot be discovered; this is a bug")?;

    let key_path = attachment.join("keys").join(format!("{agent_name}.key"));
    let key_created = !key_path.exists();
    let identity = ferryman_channel::AgentIdentity::load_or_create(&agent_name, &route.attachment)?;
    let roster_entry = AgentRoute {
        name: agent_name.clone(),
        role: request.role.clone(),
        capabilities: vec!["messages.receive".to_string()],
        public_key: None,
    };
    // Checked before the write, not after: registering is safe to repeat, but reporting
    // "created" every time would make `already_configured` permanently false and tell a
    // re-running agent it had just done setup it had not.
    let roster_existed = route
        .communications
        .join("agents")
        .join(format!("{agent_name}.json"))
        .exists();
    let roster_path = ferryman_channel::register_agent_key(&route, &roster_entry, &identity)?;
    steps.push(Step {
        what: "signing key",
        path: key_path,
        created: key_created,
    });
    steps.push(Step {
        what: "roster entry",
        path: roster_path,
        created: !roster_existed,
    });

    // Prove it, rather than assert it: load the config the way the loops will, and read
    // the roster back the way a peer will.
    let loaded = AgentConfig::load(&route.attachment).context("the agent config is unreadable")?;
    let roster = ferryman_channel::read_agent_roster(&route.communications)?;
    if !roster.iter().any(|a| a.name == agent_name) {
        bail!("the agent was registered but is not in the roster; this is a bug")
    }

    Ok(Outcome {
        project,
        agent: agent_name,
        workspace,
        route,
        public_key: identity.public_key_hex(),
        config: loaded,
        steps,
    })
}

fn report_json(outcome: &Outcome) -> Result<()> {
    println!(
        "{}",
        serde_json::to_string_pretty(&json!({
            "enabled": true,
            "project": outcome.project,
            "agent": outcome.agent,
            "workspace": outcome.workspace.display().to_string(),
            "channel": outcome.route.communications.display().to_string(),
            "syncthing_folder_id": format!("{}-ferryman", outcome.project),
            "agent_command": outcome.config.command,
            "review": outcome.config.review.as_str(),
            "public_key": outcome.public_key,
            "already_configured": outcome.steps.iter().all(|s| !s.created),
            "files": outcome.steps.iter().map(|s| json!({
                "what": s.what,
                "path": s.path.display().to_string(),
                "created": s.created,
            })).collect::<Vec<_>>(),
            "next": {
                "share_this_folder": outcome.route.communications.display().to_string(),
                "with_folder_id": format!("{}-ferryman", outcome.project),
                "then_run": ["ferry agent run", "ferry agent review"],
            },
        }))?
    );
    Ok(())
}

fn report_human(outcome: &Outcome) -> Result<()> {
    println!("ferryman enabled for '{}'", outcome.project);
    for step in &outcome.steps {
        println!(
            "  {:<16} {}  {}",
            step.what,
            if step.created { "created" } else { "present" },
            step.path.display()
        );
    }
    println!();
    println!("  agent      {}", outcome.agent);
    println!("  runs       {}", outcome.config.command);
    println!("  review     {}", outcome.config.review.as_str());
    println!("  public key {}", outcome.public_key);
    println!();
    println!("To bring another machine in, share this folder over Syncthing:");
    println!("  {}", outcome.route.communications.display());
    println!("  folder id: {}-ferryman", outcome.project);
    println!();
    println!("Then, on each machine:");
    println!("  ferry agent run        # does work");
    println!("  ferry agent review     # judges results");
    Ok(())
}

/// This machine's name, lowercased and made path-safe.
fn default_agent_name() -> String {
    let raw = std::env::var("FERRYMAN_AGENT")
        .ok()
        .filter(|v| !v.trim().is_empty())
        .or_else(|| std::env::var("HOSTNAME").ok())
        .or_else(|| std::env::var("COMPUTERNAME").ok())
        .unwrap_or_else(|| "agent".into());
    let slugged = slug(&raw);
    if slugged.is_empty() {
        "agent".to_string()
    } else {
        slugged
    }
}

/// Make an arbitrary name usable as a path component.
///
/// A project directory can be called anything at all, and an unattended caller has no
/// way to fix a rejected name. Mapping it is better than failing on it - but the result
/// is still checked by `is_safe_component`, so this loosens nothing.
fn slug(value: &str) -> String {
    let mapped: String = value
        .trim()
        .to_lowercase()
        .chars()
        .map(|c| {
            if c.is_ascii_alphanumeric() || c == '-' || c == '_' {
                c
            } else {
                '-'
            }
        })
        .collect();
    mapped.trim_matches('-').to_string()
}

#[cfg(test)]
mod tests {
    use super::*;

    fn enable_in(dir: &std::path::Path) -> Result<()> {
        run(Request {
            workspace: Some(dir.to_path_buf()),
            project: Some("demo".into()),
            agent: Some("tester".into()),
            role: "worker".into(),
            command: "true".into(),
            review: "confirm".into(),
            as_json: false,
        })
    }

    #[test]
    fn enabling_twice_is_not_an_error_and_keeps_your_edits() {
        let dir = tempdir();
        enable_in(&dir).unwrap();
        let config = AgentConfig::path(&dir.join(".ferryman"));
        // Stand in for an operator editing the file after setup.
        let edited = fs::read_to_string(&config)
            .unwrap()
            .replace("review = \"confirm\"", "review = \"auto\"");
        fs::write(&config, edited).unwrap();

        enable_in(&dir).unwrap();

        let after = AgentConfig::load(&dir.join(".ferryman")).unwrap();
        assert_eq!(
            after.review,
            ReviewMode::Auto,
            "re-running enable overwrote a config the operator had changed"
        );
    }

    #[test]
    fn the_signing_key_survives_a_second_run() {
        let dir = tempdir();
        enable_in(&dir).unwrap();
        let key = fs::read_to_string(dir.join(".ferryman/keys/tester.key")).unwrap();
        enable_in(&dir).unwrap();
        let again = fs::read_to_string(dir.join(".ferryman/keys/tester.key")).unwrap();
        // A new key would silently orphan every signature this agent had already made.
        assert_eq!(key, again, "re-running enable rotated the signing key");
    }

    #[test]
    fn the_private_key_is_excluded_from_the_synced_folder() {
        let dir = tempdir();
        enable_in(&dir).unwrap();
        let ignore = fs::read_to_string(dir.join(".ferryman/ferryman/.stignore")).unwrap();
        assert!(ignore.lines().any(|line| line.trim() == "keys"));
    }

    #[test]
    fn a_second_run_reports_that_it_changed_nothing() {
        // An agent re-runs enable because it cannot remember whether it already did.
        // The answer has to be honest, or it learns nothing from asking.
        let dir = tempdir();
        enable_in(&dir).unwrap();
        let request = Request {
            workspace: Some(dir.clone()),
            project: Some("demo".into()),
            agent: Some("tester".into()),
            role: "worker".into(),
            command: "true".into(),
            review: "confirm".into(),
            as_json: false,
        };
        let outcome = perform(request).unwrap();
        assert!(
            outcome.steps.iter().all(|step| !step.created),
            "a repeat run claimed to create something"
        );
    }

    #[test]
    fn an_enabled_project_is_immediately_usable() {
        let dir = tempdir();
        enable_in(&dir).unwrap();
        // The point of enable: everything after it works with no further setup.
        let route = ferryman_channel::route_for(&dir).unwrap();
        assert_eq!(route.project_id, "demo");
        assert!(ferryman_channel::list_tasks(&route).unwrap().is_empty());
    }

    #[test]
    fn awkward_directory_names_are_mapped_rather_than_rejected() {
        // An unattended caller cannot rename someone's project directory.
        assert_eq!(slug("My Project (v2)!"), "my-project--v2");
        assert_eq!(slug("  trailing--  "), "trailing");
    }

    fn tempdir() -> PathBuf {
        let base = std::env::temp_dir().join(format!(
            "ferryman-enable-{}-{}",
            std::process::id(),
            std::time::SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)
                .unwrap()
                .as_nanos()
        ));
        fs::create_dir_all(&base).unwrap();
        base
    }
}
