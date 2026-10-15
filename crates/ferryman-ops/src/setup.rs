//! `ferry fleet setup` - put a machine into the one layout, with the one worker.
//!
//! The principle is that Ferryman must work by fixed structure, not by agents remembering
//! paths or steps. Every machine has the same layout, one command puts it there, and
//! `ferry doctor --layout` plus the watchdog verify and repair it. This is that command.
//!
//! # What it does
//!
//! 1. Makes the folders: `comms/`, `repos/`, `work/` under the ferry root.
//! 2. Runs `repos sync`: every live project gets `repos/<project>`, Ferryman's own clone,
//!    attached to the channel the root already files. Human working copies are not touched.
//! 3. Picks or makes the machine's one worker identity (an explicit `--identity`, else the
//!    one a worker on this machine already runs as, else `ichabod-<machine>-swarm`) and
//!    gives it a home: `repos/<project>/.ferryman` with an `agent.toml` and a key. An
//!    `agent.toml` or key found in a person's checkout is copied, never moved. The identity
//!    is not enrolled anywhere: that is the master's signature.
//! 4. With `--service`, writes ONE service that runs `ferry agent run --all-projects`
//!    (a systemd user unit with restart and resource limits on Linux; a Scheduled Task and
//!    a PowerShell wrapper on Windows, with the environment loaded from a file beside it and
//!    never written inline), turns every other worker's service or task off - disabled, never
//!    deleted, and backed up first - and makes Syncthing a service of its own so it outlives
//!    the worker.
//! 5. Prints the lines only the master can run, exactly: `team approve <id> --all`,
//!    `team revoke --name <old> --all` for each retired identity, `root swarm off` for
//!    each project this machine keeps out of the swarm, and `order reoffer` for orders still
//!    addressed to a retired identity. It never signs anything.
//!
//! `--dry-run` shows all of it and writes nothing. A step that needs more rights than the
//! user has (a system-wide unit, a task another account owns) is printed as a command to
//! run, not attempted again with more force.
//!
//! Safe to run again: each step looks before it writes, and a file it would replace is
//! copied to `service/backup/<time>/` first.

use std::fs;
use std::path::{Path, PathBuf};
use std::process::Command;

use anyhow::{Context, Result, bail};
use ferryman_channel::ferry::Root;

use crate::agent::AgentConfig;
use crate::machine::{Kind, Scan, Worker};
use crate::{repos, rootconfig};

/// The systemd user unit that runs the worker.
pub const UNIT: &str = "ferryman-worker.service";
/// The systemd user unit that runs Syncthing on its own.
pub const SYNCTHING_UNIT: &str = "ferryman-syncthing.service";
/// The Windows scheduled task that runs the worker.
pub const TASK: &str = "Ferryman Worker";
/// The Windows scheduled task that runs Syncthing on its own.
pub const SYNCTHING_TASK: &str = "Ferryman Syncthing";

/// Which service manager the machine has.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Platform {
    Linux,
    Windows,
}

impl Platform {
    /// The platform this binary is running on.
    #[must_use]
    pub fn current() -> Self {
        if cfg!(windows) {
            Self::Windows
        } else {
            Self::Linux
        }
    }
}

/// How `ferry fleet setup` is asked to run.
#[derive(Debug, Clone)]
pub struct Options {
    /// The worker identity. Without it: the one a worker here already uses, else the default.
    pub identity: Option<String>,
    /// The project whose clone holds the worker's `agent.toml` and key.
    pub home: Option<String>,
    /// Identities this machine used to run as, to be revoked by the master.
    pub retire: Vec<String>,
    /// Projects this machine keeps out of the swarm (the root's `ferry.toml`).
    pub exclude: Vec<String>,
    /// Where to clone projects from, written to the root's `ferry.toml` when given.
    pub remote_template: Option<String>,
    pub dry_run: bool,
    /// Write and enable the service, and turn the others off.
    pub service: bool,
    /// Run Syncthing as a service of its own too.
    pub with_syncthing: bool,
    /// Do not fetch (no network).
    pub no_fetch: bool,
    /// The `ferry` binary the service runs.
    pub ferry: PathBuf,
    pub platform: Platform,
    /// The user's home directory (where a systemd user unit goes).
    pub user_home: PathBuf,
    /// Who the service runs as, for the task's principal and `loginctl enable-linger`.
    pub user: String,
}

impl Options {
    /// The defaults for the machine this runs on.
    #[must_use]
    pub fn here() -> Self {
        let user_home = std::env::var_os(if cfg!(windows) { "USERPROFILE" } else { "HOME" })
            .map(PathBuf::from)
            .unwrap_or_default();
        let user = if cfg!(windows) {
            match (std::env::var("USERDOMAIN"), std::env::var("USERNAME")) {
                (Ok(domain), Ok(name)) => format!("{domain}\\{name}"),
                (_, Ok(name)) => name,
                _ => String::new(),
            }
        } else {
            std::env::var("USER").unwrap_or_default()
        };
        Self {
            identity: None,
            home: None,
            retire: Vec::new(),
            exclude: Vec::new(),
            remote_template: None,
            dry_run: false,
            service: false,
            with_syncthing: crate::syncthing::managed_home_exists(),
            no_fetch: false,
            ferry: std::env::current_exe().unwrap_or_else(|_| PathBuf::from("ferry")),
            platform: Platform::current(),
            user_home,
            user,
        }
    }
}

/// What a run did, or in a dry run would do, section by section.
#[derive(Debug, Clone, Default)]
pub struct Report {
    pub dry_run: bool,
    pub folders: Vec<String>,
    pub repos: Vec<repos::Row>,
    /// The identity the worker runs as.
    pub identity: String,
    pub identity_lines: Vec<String>,
    pub service: Vec<String>,
    pub disabled: Vec<String>,
    pub excluded: Vec<String>,
    /// What only the master can run, exact.
    pub signing: Vec<String>,
    /// What this user has to run themselves: elevation, or stopping a running process.
    pub manual: Vec<String>,
    pub notes: Vec<String>,
}

impl Report {
    /// The report as text for a terminal.
    #[must_use]
    pub fn render(&self) -> String {
        let mut out = String::new();
        let mut section = |title: &str, lines: &[String]| {
            if lines.is_empty() {
                return;
            }
            out.push_str(&format!("{title}\n"));
            for line in lines {
                out.push_str(&format!("  {line}\n"));
            }
            out.push('\n');
        };
        section(
            if self.dry_run {
                "layout (would)"
            } else {
                "layout"
            },
            &self.folders,
        );
        let rows: Vec<String> = self
            .repos
            .iter()
            .map(|row| match &row.status {
                repos::Status::Skipped(why) => {
                    format!("{:<18} skipped: {}", row.project, why.reason())
                }
                _ => format!("{:<18} {}", row.project, row.word()),
            })
            .collect();
        section("repos", &rows);
        section(
            &format!("identity: {}", self.identity),
            &self.identity_lines,
        );
        section("this machine keeps out of the swarm", &self.excluded);
        section("service", &self.service);
        section("other workers turned off (never deleted)", &self.disabled);
        section("notes", &self.notes);
        section(
            "run these yourself (this command never runs them)",
            &self.manual,
        );
        section(
            "the master signs these (this command never signs)",
            &self.signing,
        );
        if self.dry_run {
            out.push_str("dry run: nothing was written\n");
        }
        out
    }
}

/// Run a program quietly; its standard output when it succeeded.
pub fn run_quietly(program: &str, args: &[String]) -> Option<String> {
    let mut command = Command::new(program);
    command.args(args);
    #[cfg(windows)]
    {
        use std::os::windows::process::CommandExt;
        command.creation_flags(0x0800_0000);
    }
    let output = command.output().ok()?;
    output
        .status
        .success()
        .then(|| String::from_utf8_lossy(&output.stdout).into_owned())
}

/// The command runner: program and arguments in, standard output out when it worked.
pub type Run<'a> = dyn FnMut(&str, &[String]) -> Option<String> + 'a;

fn strings(items: &[&str]) -> Vec<String> {
    items.iter().map(|item| (*item).to_string()).collect()
}

// --- text of the service files ---------------------------------------------------------

/// What the service files are written from.
#[derive(Debug, Clone)]
pub struct Spec {
    pub ferry: PathBuf,
    /// The worker's workspace: the clone holding its `agent.toml`.
    pub workspace: PathBuf,
    /// `KEY=VALUE` lines the service loads. Ferryman writes none of the values.
    pub env_file: PathBuf,
    pub user: String,
}

fn unit_quote(path: &Path) -> String {
    format!(
        "\"{}\"",
        path.display()
            .to_string()
            .replace('\\', "\\\\")
            .replace('"', "\\\"")
            .replace('%', "%%")
            .replace('$', "$$")
    )
}

/// A path as the `EnvironmentFile=` line takes it: `%` would start a specifier.
fn unit_path(path: &Path) -> String {
    path.display().to_string().replace('%', "%%")
}

/// Refuse a path that could break out of a line or a quote in a unit, a script or a task:
/// a control character (a newline above all) has no business in a path Ferryman writes
/// into a service file.
fn plain_path(path: &Path) -> Result<()> {
    if path.display().to_string().chars().any(char::is_control) {
        bail!(
            "{:?} has a control character in it, so it cannot be written into a service file",
            path.display().to_string()
        );
    }
    Ok(())
}

/// The systemd user unit for the worker.
///
/// Restart on failure with a pause, so a crash loop is slow rather than a spin. The limits
/// are the machine's, not the model's: memory high-water at 70 percent and a hard stop at
/// 85, four cores, a bounded process count. A worker that runs engines is the thing most
/// able to take a machine down, and a limit here is how it is only the worker that goes.
#[must_use]
pub fn systemd_unit(spec: &Spec, with_syncthing: bool) -> String {
    let after = if with_syncthing {
        format!(
            "After=network-online.target {SYNCTHING_UNIT}\nWants=network-online.target {SYNCTHING_UNIT}\n"
        )
    } else {
        "After=network-online.target\nWants=network-online.target\n".to_string()
    };
    format!(
        "# Written by `ferry fleet setup`. The one Ferryman worker on this machine: it serves\n\
         # every project under the ferry root. Edit freely; setup keeps a copy of any unit it\n\
         # replaces in service/backup/.\n\
         [Unit]\n\
         Description=Ferryman worker (every project, one per machine)\n\
         {after}\
         \n\
         [Service]\n\
         Type=simple\n\
         WorkingDirectory={workdir}\n\
         # KEY=VALUE lines for the engines. Ferryman never writes a value into this file.\n\
         EnvironmentFile=-{env}\n\
         Environment=GIT_TERMINAL_PROMPT=0\n\
         ExecStart={ferry} agent run --all-projects --workspace {workspace}\n\
         Restart=on-failure\n\
         RestartSec=30\n\
         Nice=10\n\
         MemoryHigh=70%\n\
         MemoryMax=85%\n\
         CPUQuota=400%\n\
         TasksMax=4096\n\
         KillMode=control-group\n\
         TimeoutStopSec=60\n\
         \n\
         [Install]\n\
         WantedBy=default.target\n",
        workdir = unit_quote(&spec.workspace),
        env = unit_path(&spec.env_file),
        ferry = unit_quote(&spec.ferry),
        workspace = unit_quote(&spec.workspace),
    )
}

/// The systemd user unit for the managed Syncthing, separate from the worker so that
/// stopping or restarting the worker never stops the sync.
#[must_use]
pub fn systemd_syncthing_unit(spec: &Spec) -> String {
    format!(
        "# Written by `ferry fleet setup`. Syncthing, supervised on its own: the worker's\n\
         # restarts do not reach it.\n\
         [Unit]\n\
         Description=Ferryman-managed Syncthing\n\
         After=network-online.target\n\
         \n\
         [Service]\n\
         Type=simple\n\
         ExecStart={ferry} syncthing run\n\
         Restart=on-failure\n\
         RestartSec=15\n\
         Nice=10\n\
         \n\
         [Install]\n\
         WantedBy=default.target\n",
        ferry = unit_quote(&spec.ferry),
    )
}

/// A PowerShell single-quoted string. PowerShell reads the typographic single quotes as
/// quotes too, so each of them is doubled the same way a plain one is.
fn ps_quote(text: &str) -> String {
    let mut out = String::from("'");
    for c in text.chars() {
        out.push(c);
        if matches!(c, '\'' | '\u{2018}' | '\u{2019}' | '\u{201A}' | '\u{201B}') {
            out.push(c);
        }
    }
    out.push('\'');
    out
}

/// The bytes of a PowerShell script: UTF-8 with a byte-order mark, because Windows
/// PowerShell 5 reads a script without one as the ANSI code page and garbles any path
/// with an accent in it.
fn ps_bytes(text: &str) -> Vec<u8> {
    let mut out = vec![0xEF, 0xBB, 0xBF];
    out.extend_from_slice(text.as_bytes());
    out
}

/// The PowerShell wrapper a scheduled task runs. It reads `KEY=VALUE` lines from the env
/// file at start (so no value is ever inline in a task, a script or a command line) and
/// then runs the worker, passing its exit code on so the task's restart policy sees it.
///
/// `command` is the tail of the ferry command line, for the worker or for Syncthing.
#[must_use]
pub fn windows_wrapper(spec: &Spec, command: &str) -> String {
    format!(
        "# Written by `ferry fleet setup`. Loads the environment from a file, then runs Ferryman.\r\n\
         # Put KEY=VALUE lines in the env file; Ferryman never writes a value into it.\r\n\
         $ErrorActionPreference = 'Stop'\r\n\
         $envFile = {env}\r\n\
         if (Test-Path -LiteralPath $envFile) {{\r\n\
         \x20 Get-Content -LiteralPath $envFile | ForEach-Object {{\r\n\
         \x20   $line = $_.Trim()\r\n\
         \x20   if ($line -eq '' -or $line.StartsWith('#')) {{ return }}\r\n\
         \x20   $at = $line.IndexOf('=')\r\n\
         \x20   if ($at -lt 1) {{ return }}\r\n\
         \x20   $value = $line.Substring($at + 1).Trim()\r\n\
         \x20   if ($value.Length -ge 2 -and $value.StartsWith('\"') -and $value.EndsWith('\"')) {{ $value = $value.Substring(1, $value.Length - 2) }}\r\n\
         \x20   [Environment]::SetEnvironmentVariable($line.Substring(0, $at).Trim(), $value, 'Process')\r\n\
         \x20 }}\r\n\
         }}\r\n\
         $env:GIT_TERMINAL_PROMPT = '0'\r\n\
         $env:GCM_INTERACTIVE = 'never'\r\n\
         Set-Location -LiteralPath {workspace}\r\n\
         & {ferry} {command}\r\n\
         exit $LASTEXITCODE\r\n",
        env = ps_quote(&spec.env_file.display().to_string()),
        workspace = ps_quote(&spec.workspace.display().to_string()),
        ferry = ps_quote(&spec.ferry.display().to_string()),
    )
}

fn xml_escape(text: &str) -> String {
    text.replace('&', "&amp;")
        .replace('<', "&lt;")
        .replace('>', "&gt;")
        .replace('"', "&quot;")
}

/// The scheduled-task definition: at logon of the user, no time limit, restarted every
/// minute on failure, one instance at a time. Interactive token, so the user's own
/// credential helper (git over https) is available to it.
#[must_use]
pub fn task_xml(spec: &Spec, description: &str, wrapper: &Path) -> String {
    let user = if spec.user.is_empty() {
        String::new()
    } else {
        format!("<UserId>{}</UserId>", xml_escape(&spec.user))
    };
    format!(
        "<?xml version=\"1.0\" encoding=\"UTF-16\"?>\r\n\
         <Task version=\"1.4\" xmlns=\"http://schemas.microsoft.com/windows/2004/02/mit/task\">\r\n\
         \x20 <RegistrationInfo><Description>{description}</Description></RegistrationInfo>\r\n\
         \x20 <Triggers><LogonTrigger><Enabled>true</Enabled>{user}</LogonTrigger></Triggers>\r\n\
         \x20 <Principals><Principal id=\"Author\">{user}<LogonType>InteractiveToken</LogonType><RunLevel>LeastPrivilege</RunLevel></Principal></Principals>\r\n\
         \x20 <Settings>\r\n\
         \x20   <MultipleInstancesPolicy>IgnoreNew</MultipleInstancesPolicy>\r\n\
         \x20   <DisallowStartIfOnBatteries>false</DisallowStartIfOnBatteries>\r\n\
         \x20   <StopIfGoingOnBatteries>false</StopIfGoingOnBatteries>\r\n\
         \x20   <AllowHardTerminate>true</AllowHardTerminate>\r\n\
         \x20   <StartWhenAvailable>true</StartWhenAvailable>\r\n\
         \x20   <RunOnlyIfNetworkAvailable>false</RunOnlyIfNetworkAvailable>\r\n\
         \x20   <AllowStartOnDemand>true</AllowStartOnDemand>\r\n\
         \x20   <Enabled>true</Enabled>\r\n\
         \x20   <Hidden>false</Hidden>\r\n\
         \x20   <ExecutionTimeLimit>PT0S</ExecutionTimeLimit>\r\n\
         \x20   <Priority>7</Priority>\r\n\
         \x20   <RestartOnFailure><Interval>PT1M</Interval><Count>999</Count></RestartOnFailure>\r\n\
         \x20 </Settings>\r\n\
         \x20 <Actions Context=\"Author\"><Exec>\r\n\
         \x20   <Command>powershell.exe</Command>\r\n\
         \x20   <Arguments>-NoProfile -NonInteractive -WindowStyle Hidden -ExecutionPolicy Bypass -File \"{wrapper}\"</Arguments>\r\n\
         \x20   <WorkingDirectory>{workdir}</WorkingDirectory>\r\n\
         \x20 </Exec></Actions>\r\n\
         </Task>\r\n",
        description = xml_escape(description),
        wrapper = xml_escape(&wrapper.display().to_string()),
        workdir = xml_escape(&spec.workspace.display().to_string()),
    )
}

/// UTF-16 little-endian with a byte-order mark: what `schtasks /Create /XML` reads.
#[must_use]
pub fn utf16_le(text: &str) -> Vec<u8> {
    let mut out = vec![0xFF, 0xFE];
    for unit in text.encode_utf16() {
        out.extend_from_slice(&unit.to_le_bytes());
    }
    out
}

/// The env file stub: comments only.
#[must_use]
pub fn env_stub() -> &'static str {
    "# Environment for the Ferryman worker service, one KEY=VALUE per line.\n\
     # Put the engines' API keys here and nowhere else: a service unit, a scheduled task and a\n\
     # wrapper script are all readable by more people than this file should be.\n\
     # Ferryman never writes a value into this file and `ferry fleet setup` never overwrites it.\n\
     #\n\
     # ANTHROPIC_API_KEY=\n\
     # OPENROUTER_API_KEY=\n"
}

// --- the run ---------------------------------------------------------------------------

struct Found {
    agent: String,
    attachment: PathBuf,
    project: String,
}

/// Every `agent.toml` in the checkouts the root knows (managed clones and human ones).
fn found_configs(root: &Root) -> Vec<Found> {
    let mut found: Vec<Found> = Vec::new();
    for entry in root.read().projects {
        let mut places = vec![root.managed_clone(&entry.project_id)];
        places.extend(entry.repo.iter().cloned());
        places.extend(entry.human_checkouts.iter().cloned());
        for place in places {
            let attachment = place.join(".ferryman");
            if !AgentConfig::path(&attachment).is_file() {
                continue;
            }
            if found.iter().any(|f| f.attachment == attachment) {
                continue;
            }
            if let Ok(config) = AgentConfig::load(&attachment) {
                found.push(Found {
                    agent: config.agent,
                    attachment,
                    project: entry.project_id.clone(),
                });
            }
        }
    }
    found
}

/// The identity the worker runs as, and why. The name ends up in file names, in an
/// `agent.toml` and in commands printed for the master to paste, so whatever it came from
/// (a process command line, a unit file, a checkout) it must be a plain name.
fn choose_identity(options: &Options, scan: &Scan, found: &[Found]) -> Result<(String, String)> {
    let (name, why) = choose_identity_raw(options, scan, found)?;
    if !ferryman_channel::is_safe_component(&name) {
        bail!(
            "'{name}' is not a name: use letters, digits, '.', '-' and '_' (name one with --identity)"
        );
    }
    Ok((name, why))
}

fn choose_identity_raw(
    options: &Options,
    scan: &Scan,
    found: &[Found],
) -> Result<(String, String)> {
    if let Some(name) = &options.identity {
        let name = ferryman_channel::canonical_agent_name(name);
        if !ferryman_channel::is_safe_component(&name) {
            bail!("'{name}' is not a name: use letters, digits, '.', '-' and '_'");
        }
        return Ok((name, "named with --identity".into()));
    }
    let mut running: Vec<String> = scan
        .live()
        .iter()
        .filter_map(|worker| worker.identity.clone())
        .map(|name| ferryman_channel::canonical_agent_name(&name))
        .filter(|name| ferryman_channel::is_safe_component(name))
        .collect();
    running.sort();
    running.dedup();
    if let [only] = running.as_slice() {
        return Ok((
            only.clone(),
            "the identity the worker here already runs as".into(),
        ));
    }
    let mut swarm: Vec<String> = found
        .iter()
        .map(|f| ferryman_channel::canonical_agent_name(&f.agent))
        .filter(|name| name.ends_with("-swarm") && ferryman_channel::is_safe_component(name))
        .collect();
    swarm.sort();
    swarm.dedup();
    if let [only] = swarm.as_slice() {
        return Ok((
            only.clone(),
            "the swarm identity an agent.toml here already names".into(),
        ));
    }
    let machine = crate::identity::machine_name()?;
    Ok((
        format!("ichabod-{machine}-swarm"),
        "the default, ichabod-<machine>-swarm".into(),
    ))
}

fn stamp() -> String {
    chrono::Utc::now().format("%Y%m%dT%H%M%SZ").to_string()
}

/// Copy `from` into `dir` (created), returning where it went.
fn backup_file(dir: &Path, from: &Path) -> Result<PathBuf> {
    fs::create_dir_all(dir).with_context(|| format!("create {}", dir.display()))?;
    let name = from
        .file_name()
        .map(|n| n.to_string_lossy().into_owned())
        .unwrap_or_else(|| "file".into());
    let to = dir.join(name);
    fs::copy(from, &to).with_context(|| format!("copy {} to {}", from.display(), to.display()))?;
    Ok(to)
}

fn file_safe(name: &str) -> String {
    name.chars()
        .map(|c| {
            if c.is_ascii_alphanumeric() || c == '-' || c == '_' {
                c
            } else {
                '_'
            }
        })
        .collect()
}

fn write_if_changed(path: &Path, bytes: &[u8], backup_dir: &Path) -> Result<bool> {
    if fs::read(path).ok().as_deref() == Some(bytes) {
        return Ok(false);
    }
    if path.exists() {
        backup_file(backup_dir, path)?;
    }
    if let Some(parent) = path.parent() {
        fs::create_dir_all(parent).with_context(|| format!("create {}", parent.display()))?;
    }
    fs::write(path, bytes).with_context(|| format!("write {}", path.display()))?;
    Ok(true)
}

fn is_ours(worker: &Worker) -> bool {
    match &worker.kind {
        Kind::Unit { unit, .. } => unit == UNIT,
        Kind::Task { name, .. } => name.trim_start_matches('\\') == TASK,
        Kind::Process { .. } => false,
    }
}

/// Run setup.
///
/// # Errors
/// A step that must work for the rest to make sense failed (the folders cannot be made,
/// the clone's `.ferryman` cannot be written). Steps that need rights the user lacks are
/// not errors: they are in [`Report::manual`].
pub fn setup(root: &Root, options: &Options, scan: &Scan, run: &mut Run<'_>) -> Result<Report> {
    let mut report = Report {
        dry_run: options.dry_run,
        ..Report::default()
    };
    let dry = options.dry_run;

    // 1. folders
    for (name, path) in [
        ("comms", root.comms()),
        ("repos", root.repos()),
        ("work", root.work()),
    ] {
        if path.is_dir() {
            report
                .folders
                .push(format!("{name}/ is there ({})", path.display()));
        } else {
            if !dry {
                fs::create_dir_all(&path).with_context(|| format!("create {}", path.display()))?;
            }
            report
                .folders
                .push(format!("{name}/ made ({})", path.display()));
        }
    }

    // 2. the machine's own settings in the root's ferry.toml
    if let Some(template) = &options.remote_template {
        let current = rootconfig::RootConfig::load(root).remote_template;
        if current.as_deref() == Some(template.as_str()) {
            report
                .notes
                .push(format!("clone URL template already {template}"));
        } else {
            rootconfig::check_remote(&template.replace("{project}", "x"))
                .with_context(|| format!("--remote-template '{template}'"))?;
            if !dry {
                rootconfig::set_remote_template(root, template)?;
            }
            report
                .notes
                .push(format!("clone URL template set to {template}"));
        }
    }
    for name in &options.retire {
        if !ferryman_channel::is_safe_component(&ferryman_channel::canonical_agent_name(name)) {
            bail!("--retire '{name}' is not a name: use letters, digits, '.', '-' and '_'");
        }
    }
    for project in &options.exclude {
        if !ferryman_channel::is_safe_component(project) {
            bail!("'{project}' is not a project id");
        }
        let was = rootconfig::RootConfig::load(root).excluded(project);
        if !was && !dry {
            rootconfig::set_excluded(root, project, true)?;
        }
        report.excluded.push(if was {
            format!("{project} (already excluded)")
        } else {
            format!("{project} excluded in {}", rootconfig::path(root).display())
        });
    }

    // 3. every live project gets its clone
    let sync_options = repos::Options {
        only: None,
        dry_run: dry,
        no_fetch: options.no_fetch,
        ..repos::Options::default()
    };
    report.repos = repos::sync(root, &sync_options)?;

    // 4. identity
    let found = found_configs(root);
    let (identity, why) = choose_identity(options, scan, &found)?;
    report.identity.clone_from(&identity);
    report.identity_lines.push(format!("chosen: {why}"));
    let config = rootconfig::RootConfig::load(root);
    let live: Vec<_> = root
        .read()
        .projects
        .into_iter()
        .filter(|entry| {
            !entry.is_archived()
                && entry.channel.is_dir()
                && !entry.swarm_off()
                && !config.excluded(&entry.project_id)
        })
        .collect();
    let home_project = options
        .home
        .clone()
        .or_else(|| {
            found
                .iter()
                .find(|f| f.agent == identity)
                .map(|f| f.project.clone())
        })
        .or_else(|| {
            live.iter()
                .find(|entry| entry.project_id == "ferryman")
                .map(|entry| entry.project_id.clone())
        })
        .or_else(|| live.first().map(|entry| entry.project_id.clone()));
    let mut workspace: Option<PathBuf> = None;
    match home_project {
        None => report
            .identity_lines
            .push("no live project to hold the worker's home; nothing more to do for it".into()),
        Some(project) => {
            let clone = root.managed_clone(&project);
            let attachment = clone.join(".ferryman");
            report
                .identity_lines
                .push(format!("home: {}", clone.display()));
            if attachment.join("bridge.toml").is_file() {
                workspace = Some(clone.clone());
                home_files(&identity, &attachment, &found, dry, &mut report)?;
            } else {
                report.identity_lines.push(format!(
                    "{} is not attached yet, so its agent.toml and key wait for `ferry repos sync`{}",
                    clone.display(),
                    if dry { " (a dry run does not clone)" } else { "" }
                ));
            }
        }
    }

    // 5. the service
    let retired = retired_identities(options, scan, &identity, &found, &mut report);
    service(
        root,
        options,
        scan,
        &identity,
        workspace.as_deref(),
        run,
        &mut report,
    )?;

    // 6. what the master signs
    signing_lines(root, options, &identity, &retired, &mut report);
    Ok(report)
}

/// The agent.toml and the key in the worker's home.
fn home_files(
    identity: &str,
    attachment: &Path,
    found: &[Found],
    dry: bool,
    report: &mut Report,
) -> Result<()> {
    let config_path = AgentConfig::path(attachment);
    if config_path.is_file() {
        report
            .identity_lines
            .push(format!("agent.toml is there ({})", config_path.display()));
    } else {
        let source = found
            .iter()
            .find(|f| f.agent == identity)
            .or_else(|| found.iter().find(|f| f.agent.ends_with("-swarm")));
        let text = if let Some(source) = source {
            let text = fs::read_to_string(AgentConfig::path(&source.attachment))?;
            report.identity_lines.push(format!(
                "agent.toml copied from {} (the original stays where it is)",
                source.attachment.display()
            ));
            if source.agent == identity {
                text
            } else {
                rename_agent(&text, identity)
            }
        } else {
            report.identity_lines.push(
                "agent.toml written with the defaults: engine `claude`, one order at a time. \
                 Edit it for your engines"
                    .into(),
            );
            AgentConfig::render(
                identity,
                "worker",
                "claude",
                &AgentConfig::default_args("claude"),
                crate::agent::ReviewMode::Confirm,
                None,
                true,
            )
        };
        if !dry {
            fs::create_dir_all(attachment)?;
            fs::write(&config_path, text)
                .with_context(|| format!("write {}", config_path.display()))?;
            if let Some(source) = source
                && let Ok(config) = AgentConfig::load(&source.attachment)
                && let Some(preamble) = config.preamble_file
                && Path::new(&preamble)
                    .components()
                    .all(|part| matches!(part, std::path::Component::Normal(_)))
            {
                let from = source.attachment.join(&preamble);
                let to = attachment.join(&preamble);
                if from.is_file()
                    && !to.exists()
                    && let Some(parent) = to.parent()
                {
                    fs::create_dir_all(parent)?;
                    fs::copy(&from, &to)?;
                }
            }
        }
    }
    // The key.
    let held = ferryman_channel::AgentIdentity::load_existing(identity, attachment)?;
    if let Some(key) = held {
        report.identity_lines.push(format!(
            "key is there (public key {})",
            key.public_key_hex()
        ));
        return Ok(());
    }
    let source = found.iter().find(|f| {
        f.agent == identity
            && f.attachment != attachment
            && ferryman_channel::AgentIdentity::load_existing(identity, &f.attachment)
                .ok()
                .flatten()
                .is_some()
    });
    if dry {
        report.identity_lines.push(match source {
            Some(source) => format!(
                "would copy the key between two folders of this machine, from {}",
                source.attachment.display()
            ),
            None => "would make a new key (nothing here holds one for this name)".into(),
        });
    } else if let Some(source) = source {
        copy_key_files(identity, &source.attachment, attachment)?;
        report.identity_lines.push(format!(
            "key copied from {} (the original stays where it is)",
            source.attachment.display()
        ));
    } else {
        let key = ferryman_channel::AgentIdentity::load_or_create(identity, attachment)?;
        ferryman_channel::secrets::EncryptionIdentity::load_or_create(identity, attachment)?;
        report.identity_lines.push(format!(
            "new key made; public key {} - the master enrols it (below)",
            key.public_key_hex()
        ));
    }
    Ok(())
}

/// Set the `agent = "..."` line of an agent.toml to `identity`.
fn rename_agent(text: &str, identity: &str) -> String {
    let mut out = String::new();
    let mut done = false;
    for line in text.lines() {
        if !done && line.contains('=') && line.split('=').next().unwrap_or("").trim() == "agent" {
            out.push_str(&format!("agent = \"{identity}\"\n"));
            done = true;
            continue;
        }
        out.push_str(line);
        out.push('\n');
    }
    out
}

/// Copy the files of `keys/` named for the identity from one attachment to another, when
/// the destination has none. Two directories of one machine: a key never travels.
fn copy_key_files(identity: &str, from: &Path, to: &Path) -> Result<()> {
    let source = from.join("keys");
    let destination = to.join("keys");
    fs::create_dir_all(&destination)?;
    for entry in fs::read_dir(&source)?.flatten() {
        let name = entry.file_name().to_string_lossy().into_owned();
        if !(name == identity || name.starts_with(&format!("{identity}."))) {
            continue;
        }
        let target = destination.join(&name);
        if !target.exists() && entry.path().is_file() {
            fs::copy(entry.path(), &target)?;
        }
    }
    Ok(())
}

/// Identities this machine ran as and no longer will.
fn retired_identities(
    options: &Options,
    scan: &Scan,
    chosen: &str,
    found: &[Found],
    report: &mut Report,
) -> Vec<String> {
    let mut names: Vec<String> = options
        .retire
        .iter()
        .cloned()
        .chain(
            scan.live()
                .iter()
                .filter(|worker| !is_ours(worker))
                .filter_map(|worker| worker.identity.clone()),
        )
        .map(|name| ferryman_channel::canonical_agent_name(&name))
        .filter(|name| name != chosen)
        .collect();
    names.sort();
    names.dedup();
    // These go into commands the master pastes, so only plain names get through.
    let (names, odd): (Vec<String>, Vec<String>) = names
        .into_iter()
        .partition(|name| ferryman_channel::is_safe_component(name));
    if !odd.is_empty() {
        report.notes.push(format!(
            "{} worker name(s) here are not plain names (letters, digits, '.', '-', '_') and \
             were left out of the lines the master signs; revoke them by hand if they are real",
            odd.len()
        ));
    }
    let mut others: Vec<String> = found
        .iter()
        .map(|f| ferryman_channel::canonical_agent_name(&f.agent))
        .filter(|name| name != chosen && !names.contains(name))
        .collect();
    others.sort();
    others.dedup();
    if !others.is_empty() {
        report.notes.push(format!(
            "agent.toml files here also name {}. They are not workers this machine runs, so \
             they are left alone; if one is retired, run setup again with --retire <name>",
            others.join(", ")
        ));
    }
    names
}

fn service(
    root: &Root,
    options: &Options,
    scan: &Scan,
    identity: &str,
    workspace: Option<&Path>,
    run: &mut Run<'_>,
    report: &mut Report,
) -> Result<()> {
    let dry = options.dry_run;
    let others: Vec<&Worker> = scan.live().into_iter().filter(|w| !is_ours(w)).collect();
    if !options.service {
        report.service.push(
            "not installed: add --service to write the one service and turn the others off".into(),
        );
        for worker in &others {
            report
                .service
                .push(format!("would turn off: {}", worker.describe()));
        }
        return Ok(());
    }
    let Some(workspace) = workspace else {
        report.service.push(
            "not installed: the worker's home is not attached yet. Run `ferry repos sync`, then \
             this again"
                .into(),
        );
        return Ok(());
    };
    let service_dir = root.path.join("service");
    let backup_dir = service_dir.join("backup").join(stamp());
    let env_file = service_dir.join("worker.env");
    let spec = Spec {
        ferry: options.ferry.clone(),
        workspace: workspace.to_path_buf(),
        env_file: env_file.clone(),
        user: options.user.clone(),
    };
    for path in [&spec.ferry, &spec.workspace, &spec.env_file] {
        plain_path(path)?;
    }
    if env_file.exists() {
        report.service.push(format!(
            "env file {} is there, untouched",
            env_file.display()
        ));
    } else {
        if !dry {
            fs::create_dir_all(&service_dir)?;
            fs::write(&env_file, env_stub())?;
            #[cfg(unix)]
            {
                use std::os::unix::fs::PermissionsExt;
                let _ = fs::set_permissions(&env_file, fs::Permissions::from_mode(0o600));
            }
        }
        report.service.push(format!(
            "env file {} {} (put engine keys there; Ferryman writes no values)",
            env_file.display(),
            if dry { "would be made" } else { "made" }
        ));
    }

    // Other workers first: the service must not start beside them.
    let mut running_elsewhere = false;
    for worker in &others {
        match &worker.kind {
            Kind::Process { .. } => {
                running_elsewhere = true;
                report.manual.push(format!(
                    "{} (a running process is never stopped by setup): {}",
                    worker.describe(),
                    worker.stop_commands().join("   then   ")
                ));
            }
            Kind::Unit {
                unit, file, user, ..
            } => {
                if !*user {
                    report.manual.push(format!(
                        "{}: needs elevation: {}",
                        worker.name(),
                        worker.stop_commands().join(" ; ")
                    ));
                    continue;
                }
                if dry {
                    report.disabled.push(format!(
                        "would back up {} and disable {unit}",
                        file.display()
                    ));
                    continue;
                }
                let kept = backup_file(&backup_dir, file)?;
                if run("systemctl", &strings(&["--user", "disable", "--now", unit])).is_some() {
                    report.disabled.push(format!(
                        "{unit} disabled and stopped; its file is unchanged and copied to {}",
                        kept.display()
                    ));
                } else {
                    report.manual.push(format!(
                        "{unit} could not be disabled: {}",
                        worker.stop_commands().join(" ; ")
                    ));
                }
            }
            Kind::Task { name, .. } => {
                if dry {
                    report.disabled.push(format!(
                        "would export {name} to {} and disable it",
                        backup_dir.display()
                    ));
                    continue;
                }
                let Some(xml) = run(
                    "schtasks",
                    &strings(&["/Query", "/TN", name.as_str(), "/XML"]),
                ) else {
                    report.manual.push(format!(
                        "{name}: its definition could not be saved, so it is left as it is. \
                         Disable it yourself: schtasks /Change /TN \"{name}\" /DISABLE"
                    ));
                    continue;
                };
                fs::create_dir_all(&backup_dir)?;
                let saved = backup_dir.join(format!("{}.xml", file_safe(name)));
                fs::write(&saved, xml)?;
                let _ = run("schtasks", &strings(&["/End", "/TN", name.as_str()]));
                if run(
                    "schtasks",
                    &strings(&["/Change", "/TN", name.as_str(), "/DISABLE"]),
                )
                .is_some()
                {
                    report.disabled.push(format!(
                        "{name}: disabled; definition saved to {} (the task and its scripts are not deleted)",
                        saved.display()
                    ));
                } else {
                    report.manual.push(format!(
                        "{name} could not be disabled (another account owns it, or it needs \
                         elevation): schtasks /Change /TN \"{name}\" /DISABLE"
                    ));
                }
            }
        }
    }

    match options.platform {
        Platform::Linux => install_linux(
            options,
            &spec,
            identity,
            &backup_dir,
            running_elsewhere,
            run,
            report,
        ),
        Platform::Windows => install_windows(
            options,
            &spec,
            &service_dir,
            &backup_dir,
            running_elsewhere,
            run,
            report,
        ),
    }
}

fn install_linux(
    options: &Options,
    spec: &Spec,
    identity: &str,
    backup_dir: &Path,
    running_elsewhere: bool,
    run: &mut Run<'_>,
    report: &mut Report,
) -> Result<()> {
    let dry = options.dry_run;
    let folder = options.user_home.join(".config/systemd/user");
    let mut units: Vec<(&str, String)> = vec![(UNIT, systemd_unit(spec, options.with_syncthing))];
    if options.with_syncthing {
        units.insert(0, (SYNCTHING_UNIT, systemd_syncthing_unit(spec)));
    }
    for (name, text) in &units {
        let path = folder.join(name);
        if dry {
            report.service.push(format!(
                "would write {} (runs as {identity})",
                path.display()
            ));
            continue;
        }
        let changed = write_if_changed(&path, text.as_bytes(), backup_dir)?;
        report.service.push(format!(
            "{} {}",
            path.display(),
            if changed {
                "written"
            } else {
                "already correct"
            }
        ));
    }
    if dry {
        report
            .service
            .push("would run: systemctl --user daemon-reload, then enable the units".into());
        return Ok(());
    }
    if run("systemctl", &strings(&["--user", "daemon-reload"])).is_none() {
        report.manual.push("systemctl --user daemon-reload".into());
    }
    for (name, _) in &units {
        // The worker is not started beside one that is still running: it would refuse,
        // and restart on failure forever. Enabled now, started once the other has stopped.
        let hold = *name == UNIT && running_elsewhere;
        let args: Vec<&str> = if hold {
            vec!["--user", "enable", name]
        } else {
            vec!["--user", "enable", "--now", name]
        };
        if run("systemctl", &strings(&args)).is_some() {
            report.service.push(format!(
                "{name} enabled{}",
                if hold {
                    "; start it after stopping the other worker"
                } else {
                    " and started"
                }
            ));
        } else {
            report.manual.push(format!("systemctl {}", args.join(" ")));
        }
    }
    if running_elsewhere {
        report.manual.push(
            "systemctl --user start ferryman-worker.service   (after the process above has stopped)"
                .into(),
        );
    }
    if !options.user.is_empty()
        && run("loginctl", &strings(&["enable-linger", &options.user])).is_none()
    {
        report.manual.push(format!(
            "loginctl enable-linger {}   (so the service runs without a login session)",
            options.user
        ));
    }
    Ok(())
}

fn install_windows(
    options: &Options,
    spec: &Spec,
    service_dir: &Path,
    backup_dir: &Path,
    running_elsewhere: bool,
    run: &mut Run<'_>,
    report: &mut Report,
) -> Result<()> {
    let dry = options.dry_run;
    let mut tasks: Vec<(&str, &str, String, &str)> = vec![(
        TASK,
        "ferryman-worker.ps1",
        format!(
            "agent run --all-projects --workspace {}",
            ps_quote(&spec.workspace.display().to_string())
        ),
        "The one Ferryman worker on this machine; serves every project",
    )];
    if options.with_syncthing {
        tasks.insert(
            0,
            (
                SYNCTHING_TASK,
                "ferryman-syncthing.ps1",
                "syncthing run".to_string(),
                "Ferryman-managed Syncthing, supervised apart from the worker",
            ),
        );
    }
    for (name, script, command, description) in &tasks {
        let wrapper = service_dir.join(script);
        let xml_path = service_dir.join(format!("{}.xml", file_safe(name)));
        if dry {
            report.service.push(format!(
                "would write {} and the task \"{name}\" ({description})",
                wrapper.display(),
            ));
            continue;
        }
        if let Some(xml) = run("schtasks", &strings(&["/Query", "/TN", name, "/XML"])) {
            fs::create_dir_all(backup_dir)?;
            fs::write(backup_dir.join(format!("{}.xml", file_safe(name))), xml)?;
        }
        let changed = write_if_changed(
            &wrapper,
            &ps_bytes(&windows_wrapper(spec, command)),
            backup_dir,
        )?;
        report.service.push(format!(
            "{} {}",
            wrapper.display(),
            if changed {
                "written"
            } else {
                "already correct"
            }
        ));
        fs::write(&xml_path, utf16_le(&task_xml(spec, description, &wrapper)))?;
        let xml_arg = xml_path.display().to_string();
        if run(
            "schtasks",
            &strings(&["/Create", "/TN", name, "/XML", xml_arg.as_str(), "/F"]),
        )
        .is_none()
        {
            report.manual.push(format!(
                "schtasks /Create /TN \"{name}\" /XML \"{xml_arg}\" /F   (needs the same user, or elevation)"
            ));
            continue;
        }
        report.service.push(format!(
            "task \"{name}\" created (at logon, restarted on failure)"
        ));
        if *name == TASK && running_elsewhere {
            report.service.push(format!(
                "task \"{name}\" not started: another worker is still running. Stop it, then: \
                 schtasks /Run /TN \"{name}\""
            ));
        } else if run("schtasks", &strings(&["/Run", "/TN", name])).is_some() {
            report.service.push(format!("task \"{name}\" started"));
        } else {
            report.manual.push(format!("schtasks /Run /TN \"{name}\""));
        }
    }
    if dry {
        report
            .service
            .push("would create and start the tasks".into());
    }
    Ok(())
}

/// What the master runs.
fn signing_lines(
    root: &Root,
    options: &Options,
    identity: &str,
    retired: &[String],
    report: &mut Report,
) {
    let master = crate::fleet::dominant_master(root);
    let as_flag = master
        .as_deref()
        .filter(|master| ferryman_channel::is_safe_component(master))
        .map(|master| format!(" --as {master}"))
        .unwrap_or_default();
    report
        .signing
        .push(format!("ferry team approve {identity} --all{as_flag}"));
    for name in retired {
        report
            .signing
            .push(format!("ferry team revoke --name {name} --all{as_flag}"));
        report.signing.push(format!(
            "ferry order release --held-by {name} --all{as_flag}   (returns its unfinished claims to the queue)"
        ));
    }
    let config = rootconfig::RootConfig::load(root);
    let mut kept_out: Vec<String> = config.swarm_exclude.clone();
    kept_out.extend(options.exclude.iter().cloned());
    kept_out.sort();
    kept_out.dedup();
    let projects = root.read().projects;
    for project in kept_out {
        if !ferryman_channel::is_safe_component(&project) {
            continue;
        }
        if let Some(entry) = projects.iter().find(|entry| entry.project_id == project)
            && !entry.swarm_off()
        {
            report.signing.push(format!(
                "ferry root swarm off --project {project}{as_flag}   (so every machine keeps it out, not only this one)"
            ));
        }
    }
    // Orders still addressed to a name that will not claim them.
    for name in retired {
        let mut addressed: Vec<(String, String)> = Vec::new();
        for entry in &projects {
            if entry.is_archived() || !ferryman_channel::is_safe_component(&entry.project_id) {
                continue;
            }
            let Ok((route, _)) = entry.route(root) else {
                continue;
            };
            let Ok(tasks) = ferryman_channel::list_tasks(&route) else {
                continue;
            };
            for task in tasks {
                if let ferryman_channel::TaskState::Offered { to } = task.state()
                    && to.eq_ignore_ascii_case(name)
                    && ferryman_channel::is_safe_component(&task.order.id)
                {
                    addressed.push((entry.project_id.clone(), task.order.id.clone()));
                }
            }
        }
        for (project, order) in addressed.iter().take(20) {
            report.signing.push(format!(
                "ferry order reoffer {order} --to {identity} --project {project}{as_flag}"
            ));
        }
        if addressed.len() > 20 {
            report.signing.push(format!(
                "... and {} more orders addressed to {name}: `ferry order reoffer <id> --to {identity} --project <p>`",
                addressed.len() - 20
            ));
        }
    }
}

#[cfg(test)]
mod tests;
