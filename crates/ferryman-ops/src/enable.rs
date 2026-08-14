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
use std::fs;
use std::path::PathBuf;

use crate::agent::{AgentConfig, ReviewMode};
use crate::identity::{machine_name, slug};

pub struct Request {
    pub workspace: Option<PathBuf>,
    pub project: Option<String>,
    pub agent: Option<String>,
    pub role: String,
    pub email: String,
    pub command: String,
    pub review: String,
    /// Leave the local Syncthing alone. For a machine where the folder is managed by
    /// something else, or where touching a running service is not wanted.
    pub no_syncthing: bool,
    pub as_json: bool,
}

/// A file this run created, or found already correct.
pub struct Step {
    pub what: &'static str,
    pub path: PathBuf,
    pub created: bool,
}

/// Everything the caller needs to know, separated from how it is printed so the same
/// facts drive the human output, the JSON and the tests.
pub struct Outcome {
    pub project: String,
    pub syncthing: Option<ferryman_channel::SyncthingSetup>,
    pub counted: ferryman_channel::licensing::FleetCount,
    pub agent: String,
    pub workspace: PathBuf,
    pub route: ProjectRoute,
    pub public_key: String,
    pub config: AgentConfig,
    pub steps: Vec<Step>,
}

pub fn perform(request: Request) -> Result<Outcome> {
    let workspace = match request.workspace {
        Some(path) => path,
        None => std::env::current_dir().context("read the current directory")?,
    };
    let workspace = workspace
        .canonicalize()
        .with_context(|| format!("{} does not exist", workspace.display()))?;
    // Windows canonicalisation yields \\?\X:\... , which then appeared in bridge.toml,
    // in every path in --json, and in the folder path given to Syncthing.
    let workspace = ferryman_channel::real_path(&workspace);

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
        None => machine_name()?,
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
        fs::write(
            &ignore,
            // A 6 MB `ferry` binary turned up in a real channel. It was put there by an
            // operator rather than by Ferryman, but a coordination channel has no reason
            // to carry executables at all, and one that does is a way to hand every
            // machine in a fleet a program to run. Refusing the whole class is cheap.
            "keys\n\
             *.tmp\n\
             *.key\n\
             *.exe\n\
             *.dll\n\
             *.so\n\
             *.dylib\n\
             *.msi\n\
             *.bat\n\
             *.cmd\n\
             *.ps1\n\
             *.sh\n\
             local\n",
        )
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

    // The operator who first set the project up is its master by default, unless
    // they later disclaim the role to someone else. Written automatically and
    // signed by this agent's key, so a team never has to remember a separate
    // "choose the master" step. Best-effort: a machine that cannot write it
    // still gets a working channel.
    if bridge_created
        && let Ok(declaration) =
            ferryman_channel::master::initialize_master(&route, &identity, &agent_name)
    {
        steps.push(Step {
            what: "master declaration",
            path: route.communications.join("master.json"),
            created: true,
        });
        let _ = declaration;
    }

    // Register this machine so the fleet can be counted. Done here rather than in a
    // separate step because a registration an operator has to remember is a
    // registration that does not happen.
    let device_id = ferryman_channel::licensing::device_id(&route.attachment)?;
    let device = ferryman_channel::licensing::DeviceRecord {
        id: device_id.clone(),
        kind: ferryman_channel::licensing::DeviceKind::Computer,
        operator_email: request.email.trim().to_string(),
        registered_at: chrono::Utc::now(),
    };
    let device_existed = route
        .communications
        .join("devices")
        .join(format!("{device_id}.json"))
        .exists();
    let device_path = ferryman_channel::licensing::register_device(&route, &device)?;
    steps.push(Step {
        what: "device record",
        path: device_path,
        created: !device_existed,
    });

    // Prove it, rather than assert it: load the config the way the loops will, and read
    // the roster back the way a peer will.
    let loaded = AgentConfig::load(&route.attachment).context("the agent config is unreadable")?;
    let roster = ferryman_channel::read_agent_roster(&route.communications)?;
    if !roster.iter().any(|a| a.name == agent_name) {
        bail!("the agent was registered but is not in the roster; this is a bug")
    }

    let counted =
        ferryman_channel::licensing::count(&ferryman_channel::licensing::read_devices(&route)?);

    // Wire Syncthing here rather than telling the operator to do it in a web UI. An
    // agent cannot click a web UI, and this was the one step that kept adding a second
    // machine a manual job while everything else was a single command.
    //
    // Shares with every device this Syncthing already trusts. That is the right default
    // for a fleet someone has already paired: it never adds a device, so it cannot widen
    // trust - it only uses trust that already exists.
    let syncthing = if request.no_syncthing {
        None
    } else {
        let peers = ferryman_channel::syncthing_peers().unwrap_or_default();
        // The fleet channel first: it is what makes identity and the device count mean
        // the same thing on every machine. Best-effort, because a machine that cannot
        // host one must still be able to join a project.
        let _ = ferryman_channel::syncthing_register_fleet(&peers);
        Some(ferryman_channel::syncthing_register_folder(&route, &peers)?)
    };

    Ok(Outcome {
        project,
        syncthing,
        counted,
        agent: agent_name,
        workspace,
        route,
        public_key: identity.public_key_hex(),
        config: loaded,
        steps,
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    /// Keep this test binary's machine state out of the developer's home.
    ///
    /// `cfg(test)` is per crate, so a dependent crate's tests link ferryman-channel
    /// compiled without it - which is how the suite came to write real signing keys into
    /// ~/.local/state. First call wins, so every test here shares one temporary machine.
    fn hermetic_machine() {
        let dir = std::env::temp_dir().join(format!(
            "ferryman-test-machine-{}-{}",
            env!("CARGO_CRATE_NAME"),
            std::process::id()
        ));
        let _ = std::fs::create_dir_all(&dir);
        ferryman_channel::licensing::use_machine_state_dir_per_thread(dir);
    }

    fn enable_in(dir: &std::path::Path) -> Result<()> {
        hermetic_machine();
        perform(Request {
            workspace: Some(dir.to_path_buf()),
            project: Some("demo".into()),
            agent: Some("tester".into()),
            role: "worker".into(),
            email: "tester@example.com".into(),
            no_syncthing: true,
            command: "true".into(),
            review: "confirm".into(),
            as_json: false,
        })?;
        Ok(())
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
            email: "tester@example.com".into(),
            no_syncthing: true,
            command: "true".into(),
            review: "confirm".into(),
            as_json: false,
        };
        let outcome = perform(request).unwrap();
        let created: Vec<&str> = outcome
            .steps
            .iter()
            .filter(|step| step.created)
            .map(|step| step.what)
            .collect();
        assert!(
            created.is_empty(),
            "a repeat run claimed to create: {created:?}"
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
