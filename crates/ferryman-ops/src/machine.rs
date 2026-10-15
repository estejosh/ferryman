//! One worker per machine, and the check that says so.
//!
//! # What went wrong
//!
//! `ferry agent run --all-projects` exists so one process serves every repo on a machine. It
//! did not stop anything else from serving them too. A machine accumulated a systemd unit
//! per engine, a scheduled task from an older install and a terminal someone left open, all
//! as different identities, and the worker lock (which is per identity per channel) let every
//! one of them in. Each polled every channel and each ran its own engines: the same project
//! worked by several workers at several times the cost, and nothing said so.
//!
//! This module finds them. It looks at the process table, at the service manager's unit files
//! on Linux and at the task scheduler on Windows, names each worker it finds (any identity)
//! and says how to stop it. `ferry doctor` reports what it finds, `ferry agent run` warns
//! and `ferry agent run --all-projects` refuses to be the second all-projects worker unless
//! told `--allow-second-worker`.
//!
//! # What counts
//!
//! A worker is something whose command line is `ferry agent run` (not `--dry-run`). A
//! service or task counts while it is enabled, because an enabled one starts a worker whether
//! or not one is running right now. A disabled one is exactly what `ferry fleet setup` leaves
//! behind and is ignored. The process this check runs in, and the service or task it was
//! started by, are never counted as "another" worker.

#[cfg(any(target_os = "linux", windows))]
use std::fs;
use std::path::{Path, PathBuf};
#[cfg(any(target_os = "linux", windows))]
use std::process::Command;

/// How a worker was found.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Kind {
    /// A running process.
    Process { pid: u32 },
    /// A systemd unit file that runs a worker.
    Unit {
        unit: String,
        file: PathBuf,
        /// Whether `--user` or the system manager owns it.
        user: bool,
        enabled: bool,
        active: bool,
        /// The service's main process, when it is running.
        pid: Option<u32>,
    },
    /// A Windows scheduled task that runs a worker.
    Task {
        name: String,
        enabled: bool,
        running: bool,
        /// Wrapper scripts the task runs, which hold the real command line.
        scripts: Vec<PathBuf>,
    },
}

/// One worker found on this machine.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Worker {
    pub kind: Kind,
    /// `--all-projects`: serves every project in the ferry root.
    pub all_projects: bool,
    /// The identity it works as, when it could be read from the config it runs against.
    pub identity: Option<String>,
    /// The command line, shortened for a sentence.
    pub command: String,
}

impl Worker {
    /// Whether this worker is, or would be, working: a process always; a service or task
    /// while it is enabled or running.
    #[must_use]
    pub fn live(&self) -> bool {
        match &self.kind {
            Kind::Process { .. } => true,
            Kind::Unit {
                enabled, active, ..
            } => *enabled || *active,
            Kind::Task {
                enabled, running, ..
            } => *enabled || *running,
        }
    }

    /// What to call it in a sentence.
    #[must_use]
    pub fn name(&self) -> String {
        match &self.kind {
            Kind::Process { pid } => format!("process {pid}"),
            Kind::Unit { unit, .. } => format!("systemd unit {unit}"),
            Kind::Task { name, .. } => format!("scheduled task {name}"),
        }
    }

    /// One line: what it is, whose it is, what it serves, what it runs.
    #[must_use]
    pub fn describe(&self) -> String {
        let state = match &self.kind {
            Kind::Process { .. } => "running".to_string(),
            Kind::Unit {
                enabled, active, ..
            } => format!(
                "{}, {}",
                if *active { "running" } else { "not running" },
                if *enabled { "enabled" } else { "disabled" }
            ),
            Kind::Task {
                enabled, running, ..
            } => format!(
                "{}, {}",
                if *running { "running" } else { "not running" },
                if *enabled { "enabled" } else { "disabled" }
            ),
        };
        format!(
            "{} ({state}) as {}, serving {}: {}",
            self.name(),
            self.identity
                .as_deref()
                .unwrap_or("an identity it did not say"),
            if self.all_projects {
                "every project"
            } else {
                "one project or one folder"
            },
            self.command
        )
    }

    /// The commands that stop it for good, short of deleting anything.
    #[must_use]
    pub fn stop_commands(&self) -> Vec<String> {
        match &self.kind {
            Kind::Process { pid } => {
                if cfg!(windows) {
                    vec![format!("taskkill /PID {pid}")]
                } else {
                    vec![format!("kill {pid}")]
                }
            }
            Kind::Unit { unit, user, .. } => {
                let unit = shell_word(unit);
                vec![if *user {
                    format!("systemctl --user disable --now {unit}")
                } else {
                    format!("sudo systemctl disable --now {unit}")
                }]
            }
            Kind::Task { name, .. } => {
                // A task name is a path-like string the machine gave us; it is quoted, and a
                // quote or a control character in it cannot end the quote.
                let name: String = name
                    .chars()
                    .filter(|c| *c != '"' && !c.is_control())
                    .collect();
                vec![
                    format!("schtasks /End /TN \"{name}\""),
                    format!("schtasks /Change /TN \"{name}\" /DISABLE"),
                ]
            }
        }
    }
}

/// A word for a POSIX shell: as it is when it is plain, else single-quoted (with control
/// characters dropped), so a unit file named `x; rm -rf ~.service` prints as one argument.
fn shell_word(text: &str) -> String {
    let plain = !text.is_empty()
        && text
            .chars()
            .all(|c| c.is_ascii_alphanumeric() || matches!(c, '-' | '_' | '.' | '@' | ':'));
    if plain {
        return text.to_owned();
    }
    let kept: String = text.chars().filter(|c| !c.is_control()).collect();
    format!("'{}'", kept.replace('\'', "'\\''"))
}

/// What a `ferry agent run` command line asks for.
#[derive(Debug, Clone, PartialEq, Eq, Default)]
pub struct Invocation {
    pub all_projects: bool,
    pub workspace: Option<String>,
    pub comms: Option<String>,
    pub dry_run: bool,
    pub once: bool,
}

/// Split a command line into words, honouring double and single quotes. Not a shell; enough
/// to read `ExecStart=` and a `Task To Run`.
#[must_use]
pub fn words(text: &str) -> Vec<String> {
    let mut out = Vec::new();
    let mut current = String::new();
    let mut quote: Option<char> = None;
    let mut started = false;
    for ch in text.chars() {
        match (quote, ch) {
            (Some(q), c) if c == q => quote = None,
            (Some(_), c) => current.push(c),
            (None, '"' | '\'') => {
                quote = Some(ch);
                started = true;
            }
            (None, c) if c.is_whitespace() => {
                if started || !current.is_empty() {
                    out.push(std::mem::take(&mut current));
                    started = false;
                }
            }
            (None, c) => current.push(c),
        }
    }
    if started || !current.is_empty() {
        out.push(current);
    }
    out
}

fn is_ferry(token: &str) -> bool {
    let name = token
        .rsplit(['/', '\\'])
        .next()
        .unwrap_or(token)
        .to_ascii_lowercase();
    let stem = name.strip_suffix(".exe").unwrap_or(&name);
    stem == "ferry" || stem == "ferryman" || stem.starts_with("ferry-")
}

/// Read `ferry agent run ...` out of a command line, or `None` when it is not one.
#[must_use]
pub fn invocation(tokens: &[String]) -> Option<Invocation> {
    let at = tokens
        .windows(2)
        .position(|pair| pair[0] == "agent" && pair[1] == "run")?;
    if !tokens[..at].iter().any(|token| is_ferry(token)) {
        return None;
    }
    let rest = &tokens[at + 2..];
    let value_of = |flag: &str| -> Option<String> {
        let prefix = format!("{flag}=");
        rest.iter().enumerate().find_map(|(i, token)| {
            token
                .strip_prefix(&prefix)
                .map(str::to_string)
                .or_else(|| (token == flag).then(|| rest.get(i + 1).cloned()).flatten())
        })
    };
    Some(Invocation {
        all_projects: rest.iter().any(|token| token == "--all-projects"),
        workspace: value_of("--workspace"),
        comms: value_of("--comms"),
        dry_run: rest.iter().any(|token| token == "--dry-run"),
        once: rest.iter().any(|token| token == "--once"),
    })
}

/// The first `ferry agent run` in a block of text (a unit file, a wrapper script), line by
/// line, so a comment that mentions the command does not count: a line must begin with the
/// program, or with a shell word that runs one.
#[must_use]
pub fn invocation_in_text(text: &str) -> Option<(Invocation, String)> {
    for line in text.lines() {
        let trimmed = line.trim();
        if trimmed.starts_with('#')
            || trimmed.starts_with("::")
            || trimmed.to_ascii_lowercase().starts_with("rem ")
        {
            continue;
        }
        let body = trimmed
            .strip_prefix("ExecStart=")
            .unwrap_or(trimmed)
            .trim_start_matches(['-', '@', '+', '!', '&', ' ']);
        let tokens = words(body);
        if let Some(found) = invocation(&tokens) {
            return Some((found, body.to_string()));
        }
    }
    None
}

/// A unit file's worker command, or `None` when the unit runs something else.
#[must_use]
pub fn unit_worker(text: &str) -> Option<(Invocation, String)> {
    let exec: String = text
        .lines()
        .filter(|line| line.trim_start().starts_with("ExecStart="))
        .collect::<Vec<_>>()
        .join("\n");
    invocation_in_text(&exec)
}

/// One row of `schtasks /query /fo csv /v`.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct TaskRow {
    pub name: String,
    pub status: String,
    pub run: String,
    pub start_in: String,
    pub state: String,
}

/// Split one CSV line (the scheduler quotes every field and doubles any quote inside).
fn csv_fields(line: &str) -> Vec<String> {
    let mut out = Vec::new();
    let mut current = String::new();
    let mut in_quotes = false;
    let mut chars = line.chars().peekable();
    while let Some(ch) = chars.next() {
        match ch {
            '"' if in_quotes && chars.peek() == Some(&'"') => {
                current.push('"');
                chars.next();
            }
            '"' => in_quotes = !in_quotes,
            ',' if !in_quotes => out.push(std::mem::take(&mut current)),
            c => current.push(c),
        }
    }
    out.push(current);
    out
}

/// The tasks in `schtasks /query /fo csv /v` output. The header is repeated for each folder
/// of tasks and its words depend on the display language, so columns are found by name where
/// the name is English and by their usual position otherwise.
#[must_use]
pub fn parse_schtasks(text: &str) -> Vec<TaskRow> {
    let mut rows = Vec::new();
    let mut columns = (1usize, 3usize, 8usize, 9usize, 11usize);
    for line in text.lines() {
        let line = line.trim_start_matches('\u{feff}');
        if line.trim().is_empty() {
            continue;
        }
        let fields = csv_fields(line);
        if fields.len() < 9 {
            continue;
        }
        if fields.iter().any(|field| field == "TaskName") {
            let at = |name: &str, fallback: usize| {
                fields
                    .iter()
                    .position(|field| field == name)
                    .unwrap_or(fallback)
            };
            columns = (
                at("TaskName", 1),
                at("Status", 3),
                at("Task To Run", 8),
                at("Start In", 9),
                at("Scheduled Task State", 11),
            );
            continue;
        }
        let get = |i: usize| fields.get(i).cloned().unwrap_or_default();
        rows.push(TaskRow {
            name: get(columns.0),
            status: get(columns.1),
            run: get(columns.2),
            start_in: get(columns.3),
            state: get(columns.4),
        });
    }
    rows
}

/// Paths in a command that name a script the scheduler runs.
#[must_use]
pub fn scripts_in(command: &str) -> Vec<PathBuf> {
    words(command)
        .into_iter()
        .map(|word| word.trim_matches(|c| c == '"' || c == '\'').to_string())
        .filter(|word| {
            let lower = word.to_ascii_lowercase();
            [".cmd", ".bat", ".ps1"]
                .iter()
                .any(|extension| lower.ends_with(extension))
        })
        .map(PathBuf::from)
        .collect()
}

/// The task as a worker, or `None` when it is not one. `read` reads a script's text (a
/// parameter so the rule can be tested without a disk).
pub fn task_worker(row: &TaskRow, read: &mut dyn FnMut(&Path) -> Option<String>) -> Option<Worker> {
    let mut found = invocation_in_text(&row.run);
    let scripts = scripts_in(&row.run);
    if found.is_none() {
        found = scripts
            .iter()
            .filter_map(|script| read(script))
            .find_map(|text| invocation_in_text(&text));
    }
    let (invocation, command) = found?;
    (!invocation.dry_run).then(|| Worker {
        kind: Kind::Task {
            name: row.name.clone(),
            enabled: !row.state.eq_ignore_ascii_case("disabled"),
            running: row.status.eq_ignore_ascii_case("running"),
            scripts,
        },
        all_projects: invocation.all_projects,
        identity: None,
        command: shorten(&command),
    })
}

fn shorten(command: &str) -> String {
    const LONGEST: usize = 140;
    let one_line = command.split_whitespace().collect::<Vec<_>>().join(" ");
    if one_line.chars().count() <= LONGEST {
        return one_line;
    }
    let cut: String = one_line.chars().take(LONGEST).collect();
    format!("{cut}...")
}

/// The identity configured for the project at `dir`, when there is one.
fn identity_at(dir: &Path) -> Option<String> {
    let route = ferryman_channel::route_for(dir).ok()?;
    crate::agent::AgentConfig::load(&route.attachment)
        .ok()
        .map(|config| config.agent)
}

/// What the start of a worker should do about the others.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Start {
    /// Nothing else is running or enabled.
    Clear,
    /// Go on, and say these.
    Warn(Vec<String>),
    /// Do not start, and say why.
    Refuse(String),
}

/// The workers on this machine other than this process and whatever started it.
#[derive(Debug, Clone, Default)]
pub struct Scan {
    pub workers: Vec<Worker>,
    /// Places that could not be looked at, so a quiet scan is not read as a clean one.
    pub notes: Vec<String>,
}

impl Scan {
    /// The workers that are, or would be, working.
    #[must_use]
    pub fn live(&self) -> Vec<&Worker> {
        self.workers.iter().filter(|worker| worker.live()).collect()
    }
}

fn fix_lines(workers: &[&Worker]) -> String {
    let mut out = String::from(
        "  one worker per machine serves every repo: `ferry fleet setup` writes it and turns \
         the others off. Or stop these yourself:",
    );
    for worker in workers {
        for command in worker.stop_commands() {
            out.push_str(&format!("\n      {command}"));
        }
    }
    out
}

/// The rule for starting a worker, given what else is here.
///
/// `--all-projects` is the one worker a machine is meant to have, so a second one is refused:
/// it would poll every channel again and run the same orders under another name. Any other
/// worker starting beside one that is already live is allowed, with a warning that names
/// what is already there.
#[must_use]
pub fn judge_start(scan: &Scan, all_projects: bool, allow_second: bool) -> Start {
    let live = scan.live();
    if live.is_empty() {
        return Start::Clear;
    }
    let listing = live
        .iter()
        .map(|worker| format!("  {}", worker.describe()))
        .collect::<Vec<_>>()
        .join("\n");
    let rivals: Vec<&Worker> = live
        .iter()
        .copied()
        .filter(|worker| worker.all_projects)
        .collect();
    if all_projects && !rivals.is_empty() && !allow_second {
        return Start::Refuse(format!(
            "another worker already serves every project on this machine:\n{listing}\n\
             A second all-projects worker polls every channel again and runs the same orders \
             as another identity.\n{}\n  To run both on purpose: --allow-second-worker",
            fix_lines(&rivals)
        ));
    }
    let mut lines = vec![format!(
        "another ferry worker is {} on this machine:\n{listing}\n{}",
        if live
            .iter()
            .any(|worker| matches!(worker.kind, Kind::Process { .. }))
        {
            "running"
        } else {
            "set to run"
        },
        fix_lines(&live)
    )];
    if all_projects && !rivals.is_empty() {
        lines.push(
            "starting a second all-projects worker because --allow-second-worker was given".into(),
        );
    }
    Start::Warn(lines)
}

/// `ferry doctor`'s reading: whether this machine has the one worker it should.
#[must_use]
pub fn doctor_line(scan: &Scan) -> (bool, String) {
    let live = scan.live();
    let mut detail = match live.as_slice() {
        [] => "no worker running or enabled on this machine".to_string(),
        [one] => format!("one worker: {}", one.describe()),
        many => format!(
            "{} workers on this machine, each polling and spending on its own:\n{}\n{}",
            many.len(),
            many.iter()
                .map(|worker| format!("  {}", worker.describe()))
                .collect::<Vec<_>>()
                .join("\n"),
            fix_lines(many)
        ),
    };
    if !scan.notes.is_empty() {
        detail.push_str(&format!("\n  not looked at: {}", scan.notes.join("; ")));
    }
    (live.len() <= 1, detail)
}

/// A command run quietly, its standard output when it succeeded.
#[cfg(any(target_os = "linux", windows))]
fn quietly(program: &str, args: &[&str]) -> Option<String> {
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

/// The process table, with each command line and working directory.
fn process_table() -> sysinfo::System {
    use sysinfo::{ProcessRefreshKind, ProcessesToUpdate, System, UpdateKind};
    let mut system = System::new();
    system.refresh_processes_specifics(
        ProcessesToUpdate::All,
        true,
        ProcessRefreshKind::nothing()
            .with_cmd(UpdateKind::Always)
            .with_cwd(UpdateKind::Always),
    );
    system
}

/// Look at the process table, the unit files and the scheduler.
#[must_use]
pub fn scan() -> Scan {
    let system = process_table();
    let me = sysinfo::get_current_pid().ok();
    // This process and everything that started it: a service's worker is not "another".
    let mut family: Vec<sysinfo::Pid> = Vec::new();
    let mut at = me;
    while let Some(pid) = at {
        if family.contains(&pid) {
            break;
        }
        family.push(pid);
        at = system.process(pid).and_then(sysinfo::Process::parent);
    }
    let family_cmds: Vec<String> = family
        .iter()
        .filter_map(|pid| system.process(*pid))
        .map(|process| {
            process
                .cmd()
                .iter()
                .map(|part| part.to_string_lossy().to_ascii_lowercase())
                .collect::<Vec<_>>()
                .join(" ")
        })
        .collect();
    let my_command = family_cmds.first().cloned().unwrap_or_default();

    let mut scan = Scan::default();
    let mut service_pids: Vec<u32> = Vec::new();

    // Only Linux (systemd units) and Windows (scheduled tasks) have services to list; elsewhere
    // this stays empty.
    #[cfg_attr(not(any(target_os = "linux", windows)), allow(unused_mut))]
    let mut services: Vec<Worker> = Vec::new();
    #[cfg(target_os = "linux")]
    services_linux(&mut services, &mut scan.notes);
    #[cfg(windows)]
    tasks_windows(&mut services, &mut scan.notes);
    for worker in services {
        let ours = match &worker.kind {
            Kind::Unit { pid, .. } => {
                pid.is_some_and(|pid| family.iter().any(|f| f.as_u32() == pid))
            }
            Kind::Task {
                running, scripts, ..
            } => {
                *running
                    && (scripts.iter().any(|script| {
                        let needle = script.to_string_lossy().to_ascii_lowercase();
                        family_cmds.iter().any(|cmd| cmd.contains(&needle))
                    }) || words(&worker.command).join(" ").to_ascii_lowercase() == my_command)
            }
            Kind::Process { .. } => false,
        };
        if ours {
            continue;
        }
        if let Kind::Unit { pid: Some(pid), .. } = &worker.kind {
            service_pids.push(*pid);
        }
        scan.workers.push(worker);
    }

    let scripts: Vec<String> = scan
        .workers
        .iter()
        .filter_map(|worker| match &worker.kind {
            Kind::Task {
                scripts, running, ..
            } if *running => Some(scripts.clone()),
            _ => None,
        })
        .flatten()
        .map(|script| script.to_string_lossy().to_ascii_lowercase())
        .collect();
    for (pid, process) in system.processes() {
        if family.contains(pid) || service_pids.contains(&pid.as_u32()) {
            continue;
        }
        // On Linux the table also lists every thread, under its own id and with its
        // process's command line. A worker's threads are not more workers: v0.5.28 read
        // its own threads as rivals and refused to start.
        if process.thread_kind().is_some() {
            continue;
        }
        let tokens: Vec<String> = process
            .cmd()
            .iter()
            .map(|part| part.to_string_lossy().into_owned())
            .collect();
        let Some(found) = invocation(&tokens) else {
            continue;
        };
        if found.dry_run {
            continue;
        }
        // The worker a scheduled task's wrapper started is the task, already listed.
        let mut parent = process.parent();
        let mut under_task = false;
        for _ in 0..4 {
            let Some(up) = parent.and_then(|p| system.process(p)) else {
                break;
            };
            let cmd = up
                .cmd()
                .iter()
                .map(|part| part.to_string_lossy().to_ascii_lowercase())
                .collect::<Vec<_>>()
                .join(" ");
            if scripts.iter().any(|script| cmd.contains(script)) {
                under_task = true;
                break;
            }
            parent = up.parent();
        }
        if under_task {
            continue;
        }
        let home = found
            .workspace
            .as_deref()
            .map(PathBuf::from)
            .or_else(|| process.cwd().map(Path::to_path_buf));
        scan.workers.push(Worker {
            kind: Kind::Process { pid: pid.as_u32() },
            all_projects: found.all_projects,
            identity: home.as_deref().and_then(identity_at),
            command: shorten(&tokens.join(" ")),
        });
    }
    scan.workers.sort_by_key(Worker::name);
    scan
}

#[cfg(target_os = "linux")]
fn services_linux(out: &mut Vec<Worker>, notes: &mut Vec<String>) {
    let mut folders: Vec<(PathBuf, bool)> = Vec::new();
    if let Some(home) = std::env::var_os("HOME").map(PathBuf::from) {
        folders.push((home.join(".config/systemd/user"), true));
    }
    folders.push((PathBuf::from("/etc/systemd/user"), true));
    folders.push((PathBuf::from("/etc/systemd/system"), false));
    let mut looked = false;
    for (folder, user) in folders {
        let Ok(entries) = fs::read_dir(&folder) else {
            continue;
        };
        looked = true;
        for entry in entries.flatten() {
            let path = entry.path();
            let Some(unit) = path
                .file_name()
                .and_then(|n| n.to_str())
                .map(str::to_string)
            else {
                continue;
            };
            if !unit.ends_with(".service") {
                continue;
            }
            let Ok(text) = fs::read_to_string(&path) else {
                continue;
            };
            let Some((found, command)) = unit_worker(&text) else {
                continue;
            };
            if found.dry_run {
                continue;
            }
            let scope: &[&str] = if user { &["--user"] } else { &[] };
            let ask = |verb: &str| -> Option<String> {
                let mut args: Vec<&str> = scope.to_vec();
                args.push(verb);
                args.push(&unit);
                quietly("systemctl", &args)
            };
            let enabled = ask("is-enabled").is_some_and(|s| {
                matches!(s.trim(), "enabled" | "enabled-runtime" | "static" | "alias")
            });
            let active = ask("is-active").is_some_and(|s| s.trim() == "active");
            let pid = {
                let mut args: Vec<&str> = scope.to_vec();
                args.extend(["show", "-p", "MainPID", "--value", &unit]);
                quietly("systemctl", &args)
                    .and_then(|s| s.trim().parse::<u32>().ok())
                    .filter(|pid| *pid > 0)
            };
            let home = found.workspace.as_deref().map(PathBuf::from);
            out.push(Worker {
                kind: Kind::Unit {
                    unit,
                    file: path,
                    user,
                    enabled,
                    active,
                    pid,
                },
                all_projects: found.all_projects,
                identity: home.as_deref().and_then(identity_at),
                command: shorten(&command),
            });
        }
    }
    if !looked {
        notes.push("no systemd unit folder could be read".into());
    }
}

#[cfg(windows)]
fn tasks_windows(out: &mut Vec<Worker>, notes: &mut Vec<String>) {
    let Some(text) = quietly("schtasks", &["/Query", "/FO", "CSV", "/V"]) else {
        notes.push("the task scheduler could not be queried".into());
        return;
    };
    let mut read = |path: &Path| -> Option<String> {
        let bytes = fs::read(path).ok()?;
        Some(String::from_utf8_lossy(&bytes[..bytes.len().min(64 * 1024)]).into_owned())
    };
    for row in parse_schtasks(&text) {
        let lower = row.run.to_ascii_lowercase();
        // Cheap filters before reading any script: a worker's task names ferry or runs a
        // script, and most of a machine's tasks are neither.
        if !lower.contains("ferry") && scripts_in(&row.run).is_empty() {
            continue;
        }
        let Some(mut worker) = task_worker(&row, &mut read) else {
            continue;
        };
        let home = PathBuf::from(&row.start_in);
        if row.start_in != "N/A" && home.is_dir() {
            worker.identity = identity_at(&home);
        }
        out.push(worker);
    }
}

#[cfg(test)]
mod tests;
