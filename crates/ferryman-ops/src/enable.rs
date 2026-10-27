//! `ferry enable` - point a project at Ferryman in one non-interactive step.
//!
//! # The caller is usually not a person
//!
//! This is written to be run by an agent that has just been told to put a project on
//! Ferryman, with nobody watching. Everything that follows from that:
//!
//! - **It never prompts under `--json`, or when stdin is not a terminal.** Every
//!   decision is a flag with a defensible default, so the unattended path never
//!   blocks on a question nobody is there to answer. The CLI does ask one thing of a
//!   human at a terminal - whether to set up the web dashboard, at
//!   `ferryman-cli/src/main.rs` - because it leads to an operator name and a password
//!   an agent must not choose. That prompt lives in the CLI, not here: this module
//!   has never prompted and must not start.
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
//! It writes almost nothing into the work repository: no commits, no hooks, no
//! modified build. Everything it configures lives under `.ferryman/`, which is the
//! whole separation Ferryman is built on.
//!
//! The two exceptions are both one file each, both idempotent, and both there because
//! leaving them out costs the operator more than writing them:
//!
//! - `.gitignore` gains `/.ferryman/`, because committing the private signing key
//!   inside it would publish an identity every machine in the fleet trusts.
//! - `FERRYMAN.md` is written, because LICENSE section 6 requires it of every project
//!   that uses Ferryman. It was documented as automatic long before it was, which put
//!   everyone who followed the README in technical breach of a licence term they had
//!   been told the tooling handled. Writing the file is cheaper than the trap.

use anyhow::{Context, Result, bail};
use ferryman_channel::{AgentRoute, ProjectRoute};
use std::fs;
use std::path::{Path, PathBuf};

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
    /// Share the channel folder with only these device ids, instead of every device
    /// Syncthing already trusts. Lets one project go to one person.
    pub share_with: Vec<String>,
    pub as_json: bool,
    /// Become this project's master: write the signed master declaration. Explicit,
    /// never silent — the caller should ask the user first.
    pub master: bool,
    /// Container image to sandbox the agent CLI in; empty means run it bare.
    pub sandbox: Option<String>,
    /// Run each task in its own git worktree when the workspace is a git repo.
    pub worktree: bool,
    /// This machine is joining a channel that already exists elsewhere (an invitation).
    /// Its copy of the folder is empty only because nothing has synced yet, so the
    /// "first machine" reasoning must not apply: never declare a master here.
    pub joining: bool,
    /// Make a new channel even though the ferry root already files this project with a
    /// different one, or Syncthing already syncs the project's folder id somewhere else.
    /// Without it `enable` refuses and points at `ferry root attach`.
    pub force_new_channel: bool,
    /// Create the key and the config, and do not make the identity a member anywhere: no
    /// roster entry, no master declaration. For a key made ahead of the master's
    /// `ferry team approve <name> --all`.
    pub no_enrol: bool,
    /// Place the project by hand instead of in the ferry root's layout. Each is optional
    /// and recorded in the root's manifest as a custom placement, which Ferryman then
    /// respects: it neither moves nor assumes anything about those paths.
    pub channel: Option<PathBuf>,
    pub repo: Option<PathBuf>,
    pub handins: Option<PathBuf>,
    pub env: Option<PathBuf>,
    /// Where this project keeps its own data (machine-local, never synced). Recorded in the
    /// root's manifest; the default is `projects/<id>/data`.
    pub data: Option<PathBuf>,
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
    /// Whether the configured engine resolves on this machine's PATH right now.
    ///
    /// Checked at enable time because a missing engine is the most common
    /// first-task failure and the current failure mode - the loop claiming a
    /// task, failing to start the command, and reporting it only then - wastes
    /// the operator's time in exactly the way setup exists to prevent. Not an
    /// error: the engine may legitimately be installed after enabling, on
    /// another machine of the fleet, or inside the sandbox image.
    pub command_found: bool,
    /// OmniRoute answers on this machine and no engine here goes through it yet: worth
    /// suggesting, since its free combos make a strong improvement engine.
    pub omniroute_unused: bool,
    pub steps: Vec<Step>,
}

/// Make sure git will not carry `.ferryman/` — above all the signing key inside it.
///
/// Returns the path written, or `None` when the workspace is not a git repository or the
/// entry was already there. Idempotent: running enable twice must not append twice.
///
/// Deliberately additive. The operator's `.gitignore` is theirs, so this appends one entry
/// with a comment saying why, and never rewrites or reorders what is already there.
fn ensure_git_ignores_attachment(workspace: &Path) -> Result<Option<PathBuf>> {
    // Only in a git repository. Writing a .gitignore into a directory that has nothing to
    // do with git would be litter.
    if !workspace.join(".git").exists() {
        return Ok(None);
    }
    let path = workspace.join(".gitignore");
    let existing = fs::read_to_string(&path).unwrap_or_default();
    // Match how anyone would actually have written it, so we do not add a duplicate to a
    // repository that already handled this.
    let already = existing.lines().map(str::trim).any(|line| {
        matches!(
            line,
            ".ferryman" | ".ferryman/" | "/.ferryman" | "/.ferryman/" | ".ferryman/**"
        )
    });
    if already {
        return Ok(None);
    }
    let mut updated = existing;
    if !updated.is_empty() && !updated.ends_with('\n') {
        updated.push('\n');
    }
    if !updated.is_empty() {
        updated.push('\n');
    }
    updated.push_str(
        "# Ferryman's attachment: this machine's config, its synced channel, and its\n\
         # PRIVATE SIGNING KEY. None of it belongs in the work repository - committing\n\
         # .ferryman/keys would publish an identity every machine in your fleet trusts.\n\
         /.ferryman/\n",
    );
    fs::write(&path, updated).with_context(|| format!("write {}", path.display()))?;
    Ok(Some(path))
}

/// Write the attribution file LICENSE section 6 requires, into the work repository.
///
/// Returns the path written, or `None` when it was already there. Idempotent, and
/// deliberately non-destructive: a `FERRYMAN.md` the operator has edited - to add their
/// own text, or because their project attributes several things in one file - is left
/// exactly as it is. Presence is what the licence asks for, not particular bytes.
///
/// Unlike the `.gitignore` entry, this is written whether or not the workspace is a git
/// repository. Section 6 applies to "any project that uses the Software", and a project
/// that is not under git is still a project.
fn ensure_attribution_file(workspace: &Path) -> Result<Option<PathBuf>> {
    let path = workspace.join("FERRYMAN.md");
    if path.exists() {
        return Ok(None);
    }
    fs::write(
        &path,
        "This project uses Ferryman (https://github.com/estejosh/ferryman),\n\
         licensed under the Ferryman Source-Available License.\n\
         \n\
         Ferryman coordinates the AI agents that work on this project. It is not part\n\
         of what this project ships, and it reads nothing here that you do not point it\n\
         at. This file is here because the licence asks any project using Ferryman to\n\
         say so - see section 6 of\n\
         https://github.com/estejosh/ferryman/blob/main/LICENSE\n\
         \n\
         You may edit this file freely. Ferryman writes it once and never rewrites it.\n",
    )
    .with_context(|| format!("write {}", path.display()))?;
    Ok(Some(path))
}

/// Does a person have an identity on this machine? Operator keys live in the machine
/// state directory; one there means a human can sign, and the machine must not take a
/// role that belongs to them.
fn person_identity_exists() -> bool {
    let Some(dir) = ferryman_channel::licensing::machine_state_dir() else {
        return false;
    };
    std::fs::read_dir(dir.join("operators"))
        .map(|entries| {
            entries
                .flatten()
                .any(|e| e.path().is_file() && e.path().extension().is_some_and(|x| x == "json"))
        })
        .unwrap_or(false)
}

/// Why `workspace` is not a place to enable: the user's home folder (a stray `.git` there
/// makes it look like a project), or a folder inside a git repository that is not the top
/// of it. `None` for a repository's top and for a folder under no repository at all.
#[must_use]
pub fn not_a_project_top(workspace: &Path) -> Option<String> {
    let home = std::env::var_os(if cfg!(windows) { "USERPROFILE" } else { "HOME" });
    if home.is_some_and(|home| crate::attach::same_path(Path::new(&home), workspace)) {
        return Some(format!(
            "{} is your home folder, not a project. Run this in a project's own folder, or              pass --workspace <folder>.",
            workspace.display()
        ));
    }
    let output = std::process::Command::new("git")
        .arg("-C")
        .arg(workspace)
        .args(["rev-parse", "--show-toplevel"])
        .output()
        .ok()
        .filter(|o| o.status.success())?;
    let top = PathBuf::from(String::from_utf8_lossy(&output.stdout).trim());
    (!crate::attach::same_path(&top, workspace)).then(|| {
        format!(
            "{} is inside the git repository at {} but is not its top, so enabling here would              make a channel for a folder that is not a project. Run it in {}, or pass              --workspace.",
            workspace.display(),
            top.display(),
            top.display()
        )
    })
}

/// Why making a channel at `communications` for `project` would split it from the one it
/// already has, or `None` when nothing is in the way.
///
/// Two things say a project has a channel somewhere else: the ferry root files it under a
/// different folder that is on this machine, or Syncthing already syncs the project's folder
/// id at another path. Either way a second channel means the folder is deleted and made
/// again where the new one is, and an identity enrolled where nothing else reads it. The
/// remedy is `ferry root attach`, which names the channel that exists.
#[must_use]
pub fn split_risk(
    project: &str,
    filed: Option<&ferryman_channel::ferry::Entry>,
    communications: &Path,
    synced: Option<&ferryman_channel::SyncthingFolderState>,
) -> Option<String> {
    let remedy = format!(
        "To use the channel that exists, attach this checkout to it:\n\
         \x20   ferry root attach <this folder> --project {project}\n\
         To really make a second channel (it will not be the one the fleet reads):\n\
         \x20   ferry enable --force-new-channel"
    );
    if let Some(entry) = filed
        && entry.channel.is_dir()
        && !crate::attach::same_path(&entry.channel, communications)
    {
        return Some(format!(
            "this machine already files '{project}' with a channel at {}, and this folder has \
             no .ferryman/bridge.toml reading it. Enabling here would make a second, empty \
             channel beside the real one.\n{remedy}",
            entry.channel.display()
        ));
    }
    if let Some(state) = synced
        && !state.registered_path.is_empty()
        && !state.syncs(communications)
    {
        return Some(format!(
            "Syncthing already syncs the folder '{project}-ferryman' at {}. Enabling here would \
             delete it and make it again at {}, which stops the real channel syncing.\n{remedy}",
            state.registered_path,
            communications.display()
        ));
    }
    None
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

    if let Some(why) = not_a_project_top(&workspace) {
        bail!("{why}");
    }

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
    // Both arms already fold case - `slug` lowercases, and `machine_name` slugs the
    // hostname - so this wrapper changes nothing today. It is here because those are two
    // functions in another crate that happen to agree, and the guarantee this line needs
    // is that the name is canonical, not that two helpers stay in step forever. The
    // channel folds again on write; this keeps the local `agent.toml` and key file
    // agreeing with what gets published.
    let agent_name = ferryman_channel::canonical_agent_name(&match request.agent {
        Some(name) => slug(&name),
        None => machine_name()?,
    });
    if !ferryman_channel::is_safe_component(&agent_name) {
        bail!("agent name '{agent_name}' is not a path-safe identifier")
    }
    let review = ReviewMode::parse(&request.review)?;
    if request.no_enrol && request.master {
        bail!(
            "--master and --no-enrol contradict each other: a master is on the roster. \
             Drop one of them"
        );
    }

    let attachment = workspace.join(".ferryman");
    let bridge_exists = attachment.join("bridge.toml").exists();
    // Where the channel goes. A path the caller chose is theirs. Otherwise a layout-2 ferry
    // root has a place for it (projects/<id>/comms), used for a project that has no channel
    // yet; an existing project keeps the one it has.
    let communications = if let Some(chosen) = &request.channel {
        chosen.clone()
    } else if !bridge_exists
        && let Some(root) = ferryman_channel::ferry::find_root()
        && root.layout_version() >= 2
    {
        root.comms_home(&project)
    } else {
        attachment.join("ferryman")
    };
    let custom = request.channel.is_some()
        || request.repo.is_some()
        || request.handins.is_some()
        || request.env.is_some();
    let shared_remote = format!("{project}-ferryman");
    let mut steps = Vec::new();

    // A clone with no bridge.toml is about to get a channel of its own. If this project
    // already has one, that is a second, empty channel with the same name: the project's
    // Syncthing folder is re-registered at the new path (deleted and recreated) and the
    // identity is put on a roster nobody else reads. Refuse before anything is written.
    let bridge = attachment.join("bridge.toml");
    if !request.force_new_channel && !bridge.exists() {
        let root = ferryman_channel::ferry::find_root();
        let filed = root.as_ref().and_then(|root| {
            root.read()
                .projects
                .into_iter()
                .find(|e| e.project_id == project)
        });
        let synced = if request.no_syncthing {
            None
        } else {
            ferryman_channel::syncthing_folder_state(&shared_remote)
        };
        // Judged against the channel this clone would have made for itself, not the
        // layout's default: a root that already files the project has put its channel at
        // that default, and "it is the same place" must not read as "nothing to refuse".
        let would_make = if request.channel.is_some() {
            communications.clone()
        } else {
            attachment.join("ferryman")
        };
        if let Some(why) = split_risk(&project, filed.as_ref(), &would_make, synced.as_ref()) {
            bail!("{why}");
        }
    }

    fs::create_dir_all(&communications)
        .with_context(|| format!("create {}", communications.display()))?;
    // The channel may sit anywhere (a layout-2 root files it under projects/<id>/comms), so
    // the checkout's own `.ferryman/` is made on its own.
    fs::create_dir_all(&attachment).with_context(|| format!("create {}", attachment.display()))?;

    // bridge.toml is what every other command discovers the project through, so it is
    // written first and never rewritten: an operator who edited it means it.
    let bridge_created = !bridge.exists();
    if bridge_created {
        fs::write(
            &bridge,
            format!(
                "project = \"{project}\"\n\
                 workspace = \"{}\"\n\
                 attachment = \"{}\"\n\
                 communications = \"{}\"\n\
                 shared_remote = \"{shared_remote}\"\n\
                 grants = \"open\"\n",
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

    // Keep the private half out of GIT, which is a different exit than Syncthing and was
    // not covered.
    //
    // `.stignore` below stops keys leaving through the synced channel, and the threat
    // model talks about that at length. But `ferry enable` runs inside the operator's work
    // repository, and it created `.ferryman/keys/<agent>.key` as an ordinary untracked
    // file. One `git add -A` - which is what agents and humans both type - and a private
    // signing key is committed. If that repository is public, the key is public, and every
    // artifact that agent ever signs is forgeable by anyone who read it.
    //
    // Verified on this project's own repository: `.gitignore` had no `.ferryman` entry,
    // and nothing in enable had ever written one.
    //
    // The whole directory, not just `keys/`: none of it belongs in the work repository.
    // `.ferryman/ferryman` is the synced channel, which is the point of "two repositories,
    // on purpose", and the rest is machine-local config that would only cause conflicts if
    // shared.
    let gitignore_updated = ensure_git_ignores_attachment(&workspace)?;
    if let Some(path) = gitignore_updated {
        steps.push(Step {
            what: "git exclusion",
            path,
            created: true,
        });
    }

    // LICENSE section 6. Reported as a step like everything else, so a caller reading
    // --json can see the file appear rather than discovering it in a later diff.
    if let Some(path) = ensure_attribution_file(&workspace)? {
        steps.push(Step {
            what: "attribution",
            path,
            created: true,
        });
    }

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
             *.seed\n\
             operator.seed\n\
             operator.seed.*\n\
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
                // Chosen from the engine named, not one shape for everyone: a
                // worker pointed at OpenCode must be started as `opencode run`
                // or it fails on every task. See [`AgentConfig::default_args`].
                &AgentConfig::default_args(&request.command),
                review,
                request.sandbox.as_deref(),
                request.worktree,
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
    // The encryption key is the recipient half of sealed secrets: X25519, kept
    // beside the signing key, never synced. Generated at enable so this machine
    // is a valid recipient the moment it can do work.
    let encryption = ferryman_channel::secrets::EncryptionIdentity::load_or_create(
        &agent_name,
        &route.attachment,
    )?;
    let roster_entry = AgentRoute {
        name: agent_name.clone(),
        role: request.role.clone(),
        capabilities: vec!["messages.receive".to_string()],
        public_key: None,
        encryption_key: Some(encryption.public_key_hex()),
    };
    // Checked before the write, not after: registering is safe to repeat, but reporting
    // "created" every time would make `already_configured` permanently false and tell a
    // re-running agent it had just done setup it had not.
    let roster_existed = route
        .communications
        .join("agents")
        .join(format!("{agent_name}.json"))
        .exists();
    steps.push(Step {
        what: "signing key",
        path: key_path,
        created: key_created,
    });
    // `--no-enrol`: the key exists, and nobody has been told. The master's
    // `ferry team approve <name> --all` is what puts it on a roster.
    if request.no_enrol {
        steps.push(Step {
            what: "roster entry skipped (--no-enrol): the master enrols this identity with \
                   `ferry team approve <name> --all`",
            path: route.communications.join("agents"),
            created: false,
        });
    } else {
        let roster_path = ferryman_channel::register_agent_key(&route, &roster_entry, &identity)?;
        steps.push(Step {
            what: "roster entry",
            path: roster_path,
            created: !roster_existed,
        });
    }

    // Becoming the master is an explicit choice, not a silent default: the caller
    // asks "do you want to be master of this project?" and sets `master` from the
    // answer. The declaration is signed by this agent's key, so the choice is
    // verifiable.
    //
    // Two cases are not a choice, and asking would only teach people to say yes
    // without reading: a channel nobody else is on yet (first machine, first run), and
    // a channel whose only orchestrator is this machine. In both, "who is master" has
    // one answer. On any other machine it stays explicit.
    let implicit_master = !request.master
        && !request.joining
        && !request.no_enrol
        && ferryman_channel::master::read_master(&route)
            .ok()
            .flatten()
            .is_none()
        && {
            let others: Vec<_> = ferryman_channel::read_agent_roster(&route.communications)
                .unwrap_or_default()
                .into_iter()
                .filter(|a| !a.name.eq_ignore_ascii_case(&agent_name))
                .collect();
            others.is_empty()
                || (request.role == "orchestrator"
                    && !others.iter().any(|a| a.role == "orchestrator"))
        };
    // A master is a person. This machine can only sign with its own key, so where a
    // person already has an identity here, declaring the machine master would put the
    // wrong kind of actor in charge - and the person cannot be signed in from a flag,
    // because only they have their password. Leave it undeclared and say where to
    // claim it. Found declaring `beastly` master of a project Josh was enabling.
    let person_here = person_identity_exists();
    if (request.master || implicit_master) && person_here {
        steps.push(Step {
            what: "master left undeclared: a person on this machine claims it with \
                   `ferry root master` (one password, every project)",
            path: route.communications.join("master.json"),
            created: false,
        });
    } else if request.master || implicit_master {
        let declaration =
            ferryman_channel::master::initialize_master(&route, &identity, &agent_name)?;
        steps.push(Step {
            what: if implicit_master {
                "master declaration (this machine is the first, so it is the master)"
            } else {
                "master declaration"
            },
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
        ferry_version: Some(env!("CARGO_PKG_VERSION").to_string()),
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
    if !request.no_enrol && !roster.iter().any(|a| a.name == agent_name) {
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
        // Start the managed Syncthing if it is not answering.
        //
        // Ferryman runs its own instance and has always known how to start it - `ferry
        // syncthing start` - but `enable` did not, so a machine whose Syncthing was
        // simply not running got `"available": false` and a note, and carried on. For a
        // person that is a puzzle; for the agent this command is written for, it is a
        // dead end, because the whole point of the one-command install is that there is
        // nobody to hand the remaining job to.
        //
        // Best-effort and never fatal: a machine that cannot run Syncthing still gets a
        // working local channel, which is exactly what the `available: false` path is
        // for. This only removes the case where it would have worked all along.
        if !crate::syncthing::managed_running() {
            let _ = crate::syncthing::start();
        }
        // Shares with every device this Syncthing already trusts by default; a
        // caller that wants one project to reach one person instead passes
        // `share_with`, which narrows the share list to exactly those devices.
        let peers = ferryman_channel::syncthing_peers().unwrap_or_default();
        // A project can be shared with a machine Syncthing does not trust yet:
        // add any `--share-with` device it has not seen, so the folder reaches it.
        for id in &request.share_with {
            if !peers.iter().any(|peer| &peer.device_id == id) {
                ferryman_channel::syncthing_add_device(id, "")?;
            }
        }
        // The fleet channel first: it is what makes identity and the device count mean
        // the same thing on every machine. Best-effort, because a machine that cannot
        // host one must still be able to join a project.
        let _ = ferryman_channel::syncthing_register_fleet(&peers);
        let share = if request.share_with.is_empty() {
            peers
        } else {
            ferryman_channel::peers_for_ids(&request.share_with)?
        };
        Some(ferryman_channel::syncthing_register_folder(&route, &share)?)
    };

    // The first `enable` on a machine makes the one place everything lives, beside the
    // project being enabled. After this nobody runs a filing command again: using a
    // project is what files it (see `known::remember`).
    //
    // Only when there is no root already, and best-effort: a filing convenience must
    // never be the reason enabling a project fails. Nothing of the user's is moved into
    // it - see ADR 0019 - so creating it costs them nothing but a directory.
    if ferryman_channel::ferry::find_root().is_none()
        && let Some(beside) = workspace.parent()
    {
        let _ = ferryman_channel::ferry::Root::create(&beside.join("ferry"));
    }
    // A hand-placed project is recorded as such, so the root never assumes it lives under
    // projects/<id> and erry root migrate leaves it where it is.
    if custom && let Some(root) = ferryman_channel::ferry::find_root() {
        let places = ferryman_channel::ferry::CustomPlaces {
            channel: route.communications.clone(),
            repo: request.repo.clone(),
            handins: request.handins.clone(),
            env: request.env.clone(),
            work: None,
            data: None,
        };
        root.record_custom(&project, &places)?;
        steps.push(Step {
            what: "custom placement recorded in the ferry root",
            path: root.manifest_path(),
            created: true,
        });
    }
    // The project's own data (ADR 0026): machine-local, recorded here, never synced.
    if let Some(data) = &request.data {
        let Some(root) = ferryman_channel::ferry::find_root() else {
            bail!(
                "--data is recorded in the ferry root, and there is none yet - make one with `ferry root init`"
            );
        };
        let repo = request
            .repo
            .clone()
            .or_else(|| workspace.join(".git").exists().then(|| workspace.clone()));
        root.adopt(&project, &route.communications, repo.as_deref())?;
        root.set_data(&project, Some(data))?;
        steps.push(Step {
            what: "data folder recorded in the ferry root (machine-local, never synced)",
            path: data.clone(),
            created: true,
        });
    }

    // A test must not depend on what happens to listen on this machine.
    let omniroute_unused = !cfg!(test)
        && crate::omniroute::listening()
        && !loaded.engines.iter().any(crate::omniroute::is_omniroute);
    Ok(Outcome {
        project,
        syncthing,
        counted,
        agent: agent_name,
        workspace,
        route,
        public_key: identity.public_key_hex(),
        config: loaded,
        command_found: crate::doctor::find_on_path(&request.command).is_some(),
        omniroute_unused,
        steps,
    })
}

/// Keep this test binary's machine state out of the developer's home.
///
/// `cfg(test)` is per crate, so a dependent crate's tests link ferryman-channel
/// compiled without it - which is how the suite came to write real signing keys into
/// ~/.local/state. First call wins, so every test here shares one temporary machine.
#[cfg(test)]
fn hermetic_machine() {
    // The checkout may sit inside a real ferry root; a test finds only the one it makes.
    ferryman_channel::ferry::isolate_root_search_for_this_thread();
    let dir = std::env::temp_dir().join(format!(
        "ferryman-test-machine-{}-{}",
        env!("CARGO_CRATE_NAME"),
        std::process::id()
    ));
    let _ = std::fs::create_dir_all(&dir);
    ferryman_channel::licensing::use_machine_state_dir_per_thread(dir);
}

/// A real enabled project for other test modules in this crate.
///
/// Doctor's checks need something enabled to examine, and its own module should
/// not have to restate the request shape. Uses the same hermetic machine state
/// as the tests above; first call wins, which is fine because every caller wants
/// the same isolation.
#[cfg(test)]
pub(crate) mod tests_support {
    use super::*;

    /// Enable a project in a fresh temporary directory whose engine is
    /// `command`, and return the workspace path.
    pub(crate) fn enabled_project(command: &str) -> PathBuf {
        // See `agent.rs::unique`: the clock alone does not separate two tests that
        // start in the same tick, and macOS ticks more coarsely than Linux.
        static NEXT: std::sync::atomic::AtomicU64 = std::sync::atomic::AtomicU64::new(0);
        let dir = std::env::temp_dir().join(format!(
            "ferryman-enable-support-{}-{}-{}",
            std::process::id(),
            NEXT.fetch_add(1, std::sync::atomic::Ordering::Relaxed),
            std::time::SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)
                .unwrap()
                .as_nanos()
        ));
        // Its own folder, with the workspace inside it: the first enable makes a ferry root
        // beside the workspace, which must not be a folder other tests share.
        let dir = dir.join("ws");
        fs::create_dir_all(&dir).unwrap();
        hermetic_machine();
        perform(Request {
            workspace: Some(dir.clone()),
            project: Some("demo".into()),
            agent: Some("tester".into()),
            role: "worker".into(),
            email: "tester@example.com".into(),
            no_syncthing: true,
            share_with: vec![],
            command: command.into(),
            review: "confirm".into(),
            as_json: false,
            master: false,
            sandbox: None,
            worktree: false,
            joining: false,
            force_new_channel: false,
            no_enrol: false,
            channel: None,
            repo: None,
            handins: None,
            env: None,
            data: None,
        })
        .unwrap();
        dir
    }
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
        // The checkout may sit inside a real ferry root; a test finds only the one it makes.
        ferryman_channel::ferry::isolate_root_search_for_this_thread();
        // One machine per test thread, not per process: enable files a project in the ferry
        // root it finds through this directory's pointer, and the project guard refuses to file
        // one name under two channels, so tests that share a pointer refuse each other.
        let dir = std::env::temp_dir().join(format!(
            "ferryman-test-machine-{}-{}-{:?}",
            env!("CARGO_CRATE_NAME"),
            std::process::id(),
            std::thread::current().id()
        ));
        let _ = std::fs::create_dir_all(&dir);
        ferryman_channel::licensing::use_machine_state_dir_per_thread(dir);
    }

    fn enable_in(dir: &std::path::Path) -> Result<()> {
        enable_named(dir, "demo")
    }

    /// As `enable_in`, under another project name: the root now refuses a second clone of one
    /// project that has no `bridge.toml`, so a test enabling several folders needs several names.
    fn enable_named(dir: &std::path::Path, project: &str) -> Result<()> {
        hermetic_machine();
        perform(Request {
            workspace: Some(dir.to_path_buf()),
            project: Some(project.into()),
            agent: Some("tester".into()),
            role: "worker".into(),
            email: "tester@example.com".into(),
            no_syncthing: true,
            share_with: vec![],
            command: "true".into(),
            review: "confirm".into(),
            as_json: false,
            master: false,
            sandbox: None,
            worktree: false,
            joining: false,
            force_new_channel: false,
            no_enrol: false,
            channel: None,
            repo: None,
            handins: None,
            env: None,
            data: None,
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
        // The seed never lands in the channel in the first place, but the one secret
        // that has to survive gets belt-and-braces exclusions all the same.
        assert!(ignore.lines().any(|line| line.trim() == "*.seed"));
        assert!(ignore.lines().any(|line| line.trim() == "operator.seed"));
    }

    /// Enabling inside a git repository must put `.ferryman/` beyond git's reach.
    ///
    /// The key lives at `.ferryman/keys/<agent>.key` as an ordinary untracked file, so one
    /// `git add -A` - which agents and humans both type - would commit a private signing
    /// key. On a public repository that publishes an identity the whole fleet trusts.
    #[test]
    fn enabling_in_a_git_repository_keeps_the_signing_key_out_of_git() {
        let dir = tempdir();
        // Enough for the check: it looks for a .git entry, not a valid repository.
        fs::create_dir_all(dir.join(".git")).unwrap();
        enable_in(&dir).unwrap();

        let key = dir.join(".ferryman/keys/tester.key");
        assert!(
            key.is_file(),
            "the test is meaningless without a key present"
        );

        let ignored = fs::read_to_string(dir.join(".gitignore")).unwrap();
        assert!(
            ignored.lines().any(|line| line.trim() == "/.ferryman/"),
            "enable must exclude the attachment from git, got:\n{ignored}"
        );

        // Idempotent: enable is safe to run twice, so it must not append twice.
        enable_in(&dir).unwrap();
        let again = fs::read_to_string(dir.join(".gitignore")).unwrap();
        assert_eq!(
            again.matches("/.ferryman/").count(),
            1,
            "a second run duplicated the entry"
        );
    }

    /// An operator who already excluded it, in any of the usual spellings, is left alone.
    #[test]
    fn an_existing_exclusion_is_respected_rather_than_duplicated() {
        for (n, spelling) in [".ferryman", ".ferryman/", "/.ferryman"]
            .into_iter()
            .enumerate()
        {
            let dir = tempdir();
            fs::create_dir_all(dir.join(".git")).unwrap();
            fs::write(dir.join(".gitignore"), format!("target/\n{spelling}\n")).unwrap();
            enable_named(&dir, &format!("demo{n}")).unwrap();
            let ignored = fs::read_to_string(dir.join(".gitignore")).unwrap();
            assert!(
                !ignored.contains("Ferryman's attachment"),
                "'{spelling}' already covers it; enable should not add another entry"
            );
        }
    }

    /// Outside a git repository there is nothing to protect and nothing to write.
    #[test]
    fn enabling_outside_git_writes_no_gitignore() {
        let dir = tempdir();
        enable_in(&dir).unwrap();
        assert!(
            !dir.join(".gitignore").exists(),
            "a .gitignore in a non-git directory is litter"
        );
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
            share_with: vec![],
            command: "true".into(),
            review: "confirm".into(),
            as_json: false,
            master: false,
            sandbox: None,
            worktree: false,
            joining: false,
            force_new_channel: false,
            no_enrol: false,
            channel: None,
            repo: None,
            handins: None,
            env: None,
            data: None,
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

    /// Enable must write the arg contract of the engine it was pointed at, not
    /// Claude's args with a different command name in front of them.
    #[test]
    fn the_written_args_match_the_engine_named() {
        let dir = tempdir();
        perform(Request {
            workspace: Some(dir.clone()),
            project: Some("demo".into()),
            agent: Some("tester".into()),
            role: "worker".into(),
            email: "tester@example.com".into(),
            no_syncthing: true,
            share_with: vec![],
            command: "opencode".into(),
            review: "confirm".into(),
            as_json: false,
            master: false,
            sandbox: None,
            worktree: false,
            joining: false,
            force_new_channel: false,
            no_enrol: false,
            channel: None,
            repo: None,
            handins: None,
            env: None,
            data: None,
        })
        .unwrap();
        let config = fs::read_to_string(AgentConfig::path(&dir.join(".ferryman"))).unwrap();
        assert!(
            config.contains(r#"args = ["run","--auto","{prompt}"]"#),
            "an opencode worker must be started as 'opencode run', got:\n{config}"
        );
    }

    /// A missing engine is discovered at enable time, not at first-task time.
    #[test]
    fn a_missing_engine_is_reported_at_enable_time_not_at_first_task_time() {
        let dir = tempdir();
        let outcome = perform(Request {
            workspace: Some(dir),
            project: Some("demo".into()),
            agent: Some("tester".into()),
            role: "worker".into(),
            email: "tester@example.com".into(),
            no_syncthing: true,
            share_with: vec![],
            command: "definitely-not-an-engine-9x7".into(),
            review: "confirm".into(),
            as_json: false,
            master: false,
            sandbox: None,
            worktree: false,
            joining: false,
            force_new_channel: false,
            no_enrol: false,
            channel: None,
            repo: None,
            handins: None,
            env: None,
            data: None,
        })
        .unwrap();
        assert!(
            !outcome.command_found,
            "enable must admit when the engine is not on this machine"
        );
    }

    #[test]
    fn enable_writes_the_attribution_file_the_licence_asks_for() {
        // LICENSE section 6 requires a FERRYMAN.md in any project that uses Ferryman,
        // and two documents said the tooling wrote it long before the tooling did.
        // Everyone who followed the README was in technical breach of a term they had
        // been told was handled.
        let dir = tempdir();
        hermetic_machine();
        perform(request_in(&dir)).unwrap();
        let written = fs::read_to_string(dir.join("FERRYMAN.md")).unwrap();
        assert!(written.contains("uses Ferryman"), "{written}");
        assert!(
            written.contains("Ferryman Source-Available License"),
            "the licence has to be named, not merely linked: {written}"
        );
    }

    #[test]
    fn an_edited_attribution_file_is_left_alone() {
        // The licence asks for presence, not for particular bytes. A project that
        // attributes several things in one file, or that worded it themselves, must not
        // have that overwritten by running enable again.
        let dir = tempdir();
        hermetic_machine();
        let mine = "This project uses Ferryman, and three other things I wrote about.\n";
        fs::write(dir.join("FERRYMAN.md"), mine).unwrap();
        perform(request_in(&dir)).unwrap();
        assert_eq!(fs::read_to_string(dir.join("FERRYMAN.md")).unwrap(), mine);
    }

    /// The mistake this exists for: a clone with no bridge.toml, of a project the root
    /// already files with a real channel, gets a second empty channel beside it.
    #[test]
    fn enabling_a_clone_of_a_filed_project_is_refused_and_points_at_attach() {
        let dir = tempdir();
        hermetic_machine();
        let root = ferryman_channel::ferry::Root::create(&dir.join("ferry")).unwrap();
        let real = root.comms_home("demo");
        fs::create_dir_all(&real).unwrap();
        root.adopt("demo", &real, None).unwrap();
        let clone = dir.join("clone");
        fs::create_dir_all(&clone).unwrap();

        let error = perform(request_in(&clone)).err().expect("refused");
        let said = format!("{error:#}");
        assert!(said.contains("ferry root attach"), "{said}");
        assert!(said.contains("--force-new-channel"), "{said}");
        assert!(said.contains(&real.display().to_string()), "{said}");
        assert!(
            !clone.join(".ferryman").exists(),
            "refused before anything was written"
        );
        assert!(
            fs::read_dir(&real).unwrap().next().is_none(),
            "and the real channel was not touched"
        );

        // The explicit opt-out makes the second channel anyway.
        perform(Request {
            force_new_channel: true,
            ..request_in(&clone)
        })
        .unwrap();
        assert!(clone.join(".ferryman/bridge.toml").is_file());
    }

    #[test]
    fn enabling_a_clone_already_attached_to_the_filed_channel_is_not_refused() {
        let dir = tempdir();
        hermetic_machine();
        let root = ferryman_channel::ferry::Root::create(&dir.join("ferry")).unwrap();
        let real = root.comms_home("demo");
        fs::create_dir_all(&real).unwrap();
        root.adopt("demo", &real, None).unwrap();
        let clone = dir.join("clone");
        fs::create_dir_all(clone.join(".git")).unwrap();
        crate::attach::attach(&root, &clone, Some("demo"), false).unwrap();

        // With a bridge.toml the channel is the one it names, so enable has nothing to split.
        perform(request_in(&clone)).unwrap();
        assert!(
            !clone.join(".ferryman/ferryman/agents").exists(),
            "the roster entry went to the filed channel, not a new one"
        );
        assert!(real.join("agents/tester.json").is_file());
    }

    #[test]
    fn enable_refuses_a_folder_that_is_not_the_top_of_its_repository() {
        let dir = tempdir();
        hermetic_machine();
        let git = |args: &[&str], at: &Path| {
            assert!(
                std::process::Command::new("git")
                    .arg("-C")
                    .arg(at)
                    .args(args)
                    .status()
                    .unwrap()
                    .success()
            );
        };
        git(&["init", "-q"], &dir);
        let sub = dir.join("sub");
        fs::create_dir_all(&sub).unwrap();
        let said = format!("{:#}", perform(request_in(&sub)).err().expect("refused"));
        assert!(said.contains("not its top"), "{said}");
        assert!(!sub.join(".ferryman").exists(), "nothing was written");
        // The top itself is fine.
        perform(request_in(&dir)).unwrap();
    }

    #[test]
    fn syncthing_already_syncing_the_folder_elsewhere_is_a_reason_to_refuse() {
        let here = Path::new("/work/clone/.ferryman/ferryman");
        let state = |path: &str| ferryman_channel::SyncthingFolderState {
            folder_id: "demo-ferryman".into(),
            state: "idle".into(),
            error: String::new(),
            registered_path: path.into(),
        };
        let said = split_risk(
            "demo",
            None,
            here,
            Some(&state("/ferry/comms/demo-ferryman")),
        )
        .expect("a folder synced elsewhere is a split");
        assert!(said.contains("/ferry/comms/demo-ferryman"), "{said}");
        assert!(said.contains("ferry root attach"), "{said}");
        // The same folder, a folder Syncthing does not report a path for, nothing at all.
        assert!(
            split_risk(
                "demo",
                None,
                here,
                Some(&state("/work/clone/.ferryman/ferryman"))
            )
            .is_none()
        );
        assert!(split_risk("demo", None, here, Some(&state(""))).is_none());
        assert!(split_risk("demo", None, here, None).is_none());
    }

    #[test]
    fn no_enrol_makes_the_key_and_tells_nobody() {
        let dir = tempdir();
        hermetic_machine();
        perform(Request {
            no_enrol: true,
            channel: None,
            repo: None,
            handins: None,
            env: None,
            data: None,
            ..request_in(&dir)
        })
        .unwrap();
        assert!(dir.join(".ferryman/keys/tester.key").is_file(), "the key");
        assert!(dir.join(".ferryman/agent.toml").is_file(), "and its config");
        let agents = dir.join(".ferryman/ferryman/agents");
        assert!(
            !agents.join("tester.json").exists(),
            "but the identity is on no roster"
        );
        assert!(
            !dir.join(".ferryman/ferryman/master.json").exists(),
            "and is nobody's master"
        );
        // The master enrolling it later is what makes it a member.
        perform(request_in(&dir)).unwrap();
        assert!(agents.join("tester.json").is_file());

        let error = perform(Request {
            no_enrol: true,
            channel: None,
            repo: None,
            handins: None,
            env: None,
            data: None,
            master: true,
            ..request_in(&dir)
        })
        .err()
        .expect("contradiction");
        assert!(format!("{error:#}").contains("contradict"), "{error:#}");
    }

    #[test]
    fn a_layout_two_root_gets_the_channel_in_the_project_folder() {
        let dir = tempdir();
        hermetic_machine();
        // The root sits beside the workspace, as it does for real; inside it the channel
        // would be refused as work in a synced folder.
        let beside = dir.parent().unwrap().to_path_buf();
        let root = ferryman_channel::ferry::Root::create(&beside.join("ferry")).unwrap();
        assert_eq!(root.layout_version(), 2);
        let done = perform(request_in(&dir)).unwrap();
        let home = root.comms_home("demo");
        assert!(ferryman_channel::ferry::same_place(
            &done.route.communications,
            &home
        ));
        assert!(
            home.join("agents").is_dir(),
            "the roster is in projects/demo/comms"
        );
        assert!(dir.join(".ferryman").join("bridge.toml").is_file());
    }

    #[test]
    fn a_channel_placed_by_hand_is_recorded_as_custom_and_respected() {
        let dir = tempdir();
        hermetic_machine();
        let beside = dir.parent().unwrap().to_path_buf();
        let root = ferryman_channel::ferry::Root::create(&beside.join("ferry")).unwrap();
        let chosen = beside.join("my-channel");
        let handins = beside.join("my-handins");
        perform(Request {
            channel: Some(chosen.clone()),
            handins: Some(handins.clone()),
            ..request_in(&dir)
        })
        .unwrap();
        let entry = root
            .read()
            .projects
            .into_iter()
            .find(|e| e.project_id == "demo")
            .unwrap();
        assert_eq!(entry.placement, ferryman_channel::ferry::Placement::Custom);
        assert!(ferryman_channel::ferry::same_place(&entry.channel, &chosen));
        assert_eq!(entry.handins, Some(handins));
        assert!(chosen.join("agents").is_dir());
        assert!(
            !root.project_dir("demo").join("comms").exists(),
            "nothing was put in projects/demo: the person decided"
        );
    }

    /// The plain request the attribution tests share: no engine that exists, no
    /// Syncthing, nothing that reaches off this machine.
    fn request_in(dir: &Path) -> Request {
        Request {
            workspace: Some(dir.to_path_buf()),
            project: Some("demo".into()),
            agent: Some("tester".into()),
            role: "worker".into(),
            email: "tester@example.com".into(),
            no_syncthing: true,
            share_with: vec![],
            command: "definitely-not-an-engine-9x7".into(),
            review: "confirm".into(),
            as_json: false,
            master: false,
            sandbox: None,
            worktree: false,
            joining: false,
            force_new_channel: false,
            no_enrol: false,
            channel: None,
            repo: None,
            handins: None,
            env: None,
            data: None,
        }
    }

    fn tempdir() -> PathBuf {
        // See `agent.rs::unique`: the clock alone does not separate two tests that
        // start in the same tick, and macOS ticks more coarsely than Linux.
        static NEXT: std::sync::atomic::AtomicU64 = std::sync::atomic::AtomicU64::new(0);
        let base = std::env::temp_dir().join(format!(
            "ferryman-enable-{}-{}-{}",
            std::process::id(),
            NEXT.fetch_add(1, std::sync::atomic::Ordering::Relaxed),
            std::time::SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)
                .unwrap()
                .as_nanos()
        ));
        // A workspace of its own inside a folder of its own: the first enable on a machine
        // makes a ferry root beside the workspace, and beside TEMP itself that root would be
        // one folder every test, and every earlier run, shared.
        let workspace = base.join("ws");
        fs::create_dir_all(&workspace).unwrap();
        workspace
    }
}
