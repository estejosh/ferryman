//! `ferry doctor --layout`: is this machine laid out the way Ferryman expects?
//!
//! The principle is that nothing may depend on an agent remembering a path or a step, so the
//! layout is fixed and this is the check that it is still there. It reads; the only thing it
//! ever changes is a stale lock, and only when the process in it is proven dead, and then by
//! renaming, never deleting. The watchdog runs it, and its repair is `repos sync`, which
//! never signs.
//!
//! Eight checks, each with the command that fixes it:
//!
//! 1. the top folders exist under the ferry root (`comms/`, `repos/`, `work/` in layout 1;
//!    `projects/`, `secrets/`, `logs/` in layout 2);
//! 2. every live project has its managed clone (`repos/<project>`, or `projects/<project>/repo`),
//!    attached to its channel; a project placed by hand (custom) is left as recorded;
//! 3. exactly one worker is running or enabled on the machine;
//! 4. that worker runs as a service (an enabled unit or scheduled task), so a reboot does not
//!    end the swarm;
//! 5. no worker lock names a process that is no longer running;
//! 6. Syncthing shares only channels: no configured folder is the root, above it, or under
//!    repos/, work/, secrets/ or a project's repo, work or tmp, and none of Ferryman's own
//!    folders sits outside the places the layout or the manifest gives it;
//! 7. layout 2 only: each managed project has repo, comms, handins and work, and each custom
//!    project's recorded paths exist (a custom project is not a failure);
//! 8. keys stay home: no `secrets/` or `.env` is inside a synced folder, and a Worker-level
//!    agent on this machine has no write path into the channel (ADR 0024).

use std::fs;
use std::path::{Path, PathBuf};

use ferryman_channel::access;
use ferryman_channel::ferry::{Entry, Placement, Root};
use ferryman_channel::syncscope::{self, Folder};

use crate::machine::{self, Kind, Scan};

/// One line of the report.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Check {
    pub name: &'static str,
    pub ok: bool,
    pub detail: String,
    /// What to run when it is not ok.
    pub fix: Option<String>,
}

/// A worker lock found on disk.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct StaleLock {
    pub project: String,
    pub path: PathBuf,
    /// The pid it names; `None` when the file does not hold one.
    pub pid: Option<u32>,
}

impl StaleLock {
    /// Dead is proven only for a pid that parsed and is not running.
    #[must_use]
    pub fn proven_dead(&self) -> bool {
        self.pid
            .is_some_and(|pid| !crate::agent::process_alive(pid))
    }
}

/// Everything the layout check found.
#[derive(Debug, Clone, Default)]
pub struct Report {
    pub checks: Vec<Check>,
    pub stale: Vec<StaleLock>,
}

impl Report {
    #[must_use]
    pub fn ok(&self) -> bool {
        self.checks.iter().all(|check| check.ok)
    }

    /// The report as lines for a terminal.
    #[must_use]
    pub fn render(&self) -> String {
        let mut out = String::new();
        for check in &self.checks {
            out.push_str(&format!(
                "{} {}: {}\n",
                if check.ok { "ok  " } else { "FAIL" },
                check.name,
                check.detail
            ));
            if !check.ok
                && let Some(fix) = &check.fix
            {
                out.push_str(&format!("      fix: {fix}\n"));
            }
        }
        out
    }
}

/// Every worker lock under the root's checkouts whose process is gone (or whose content is
/// not a pid), so a person can see what a crash left behind.
#[must_use]
pub fn stale_locks(root: &Root) -> Vec<StaleLock> {
    let mut found = Vec::new();
    let mut seen: Vec<PathBuf> = Vec::new();
    for entry in root.read().projects {
        if entry.is_archived() {
            continue;
        }
        let mut places: Vec<PathBuf> = Vec::new();
        places.push(entry.managed_clone_path(root));
        places.extend(entry.repo.iter().cloned());
        places.extend(entry.human_checkouts.iter().cloned());
        for place in places {
            let folder = place.join(".ferryman");
            let Ok(entries) = fs::read_dir(&folder) else {
                continue;
            };
            for file in entries.flatten() {
                let path = file.path();
                let name = file.file_name().to_string_lossy().into_owned();
                if !(name.starts_with("worker-") && name.ends_with(".lock")) || seen.contains(&path)
                {
                    continue;
                }
                seen.push(path.clone());
                let pid = fs::read_to_string(&path)
                    .ok()
                    .and_then(|text| text.trim().parse::<u32>().ok());
                let lock = StaleLock {
                    project: entry.project_id.clone(),
                    path,
                    pid,
                };
                let alive = pid.is_some_and(crate::agent::process_alive);
                if !alive {
                    found.push(lock);
                }
            }
        }
    }
    found
}

/// Move aside the locks whose process is proven dead. Renamed to `<name>.stale-<pid>`, never
/// deleted, and the pid is looked at again just before the rename. Returns what was done.
pub fn archive_stale(locks: &[StaleLock]) -> Vec<String> {
    let mut done = Vec::new();
    for lock in locks {
        if !lock.proven_dead() {
            continue;
        }
        let Some(pid) = lock.pid else { continue };
        let mut name = lock
            .path
            .file_name()
            .map(|n| n.to_string_lossy().into_owned())
            .unwrap_or_default();
        name.push_str(&format!(".stale-{pid}"));
        let mut target = lock.path.with_file_name(&name);
        // A pid is reused, so the same name can already be taken by an earlier archive.
        // Nothing is ever overwritten or deleted: this one gets a number.
        let mut number = 1;
        while target.exists() && number < 1000 {
            target = lock.path.with_file_name(format!("{name}-{number}"));
            number += 1;
        }
        if target.exists() {
            continue;
        }
        if fs::rename(&lock.path, &target).is_ok() {
            done.push(format!(
                "{} -> {}",
                lock.path.display(),
                target
                    .file_name()
                    .map(|n| n.to_string_lossy().into_owned())
                    .unwrap_or_default()
            ));
        }
    }
    done
}

fn folders_check(root: &Root) -> Check {
    let tops = root.top_folders();
    let missing: Vec<String> = tops
        .iter()
        .filter(|(_, path)| !path.is_dir())
        .map(|(name, _)| format!("{name}/"))
        .collect();
    Check {
        name: "folders",
        ok: missing.is_empty(),
        detail: if missing.is_empty() {
            format!(
                "{} are under {}",
                tops.iter()
                    .map(|(name, _)| format!("{name}/"))
                    .collect::<Vec<_>>()
                    .join(", "),
                root.path.display()
            )
        } else {
            format!(
                "missing under {}: {}",
                root.path.display(),
                missing.join(", ")
            )
        },
        fix: Some("ferry fleet setup".into()),
    }
}

fn clones(root: &Root) -> Check {
    let missing = crate::repos::unsynced(root);
    let live = root
        .read()
        .projects
        .iter()
        .filter(|entry| !entry.is_archived())
        .count();
    let home = if root.layout_version() >= 2 {
        "projects/<project>/repo"
    } else {
        "repos/<project>"
    };
    Check {
        name: "repos",
        ok: missing.is_empty(),
        detail: if missing.is_empty() {
            format!("every live project has its clone at {home} ({live} filed)")
        } else {
            format!(
                "{} project(s) without an attached {home}: {}",
                missing.len(),
                missing
                    .iter()
                    .map(|(project, why)| format!("{project} ({why})"))
                    .collect::<Vec<_>>()
                    .join("; ")
            )
        },
        fix: Some("ferry repos sync".into()),
    }
}

fn workers(scan: &Scan) -> Check {
    let (ok, detail) = machine::doctor_line(scan);
    let live = scan.live();
    Check {
        name: "one worker",
        // None is not "one": a machine with no worker is not serving anything.
        ok: ok && live.len() == 1,
        detail,
        fix: Some(if live.is_empty() {
            "ferry fleet setup --service".into()
        } else {
            "ferry fleet setup (turns the others off, deletes nothing)".into()
        }),
    }
}

fn service(scan: &Scan) -> Check {
    let live = scan.live();
    let managed = live.iter().find(|worker| {
        matches!(
            &worker.kind,
            Kind::Unit { enabled: true, .. } | Kind::Task { enabled: true, .. }
        )
    });
    Check {
        name: "service",
        ok: managed.is_some(),
        detail: managed.map_or_else(
            || {
                "the worker is not a service: a reboot, a closed terminal or a logout ends it"
                    .into()
            },
            |worker| format!("{} is enabled", worker.name()),
        ),
        fix: Some("ferry fleet setup --service".into()),
    }
}

fn locks(root: &Root) -> (Check, Vec<StaleLock>) {
    let stale = stale_locks(root);
    let check = Check {
        name: "locks",
        ok: stale.is_empty(),
        detail: if stale.is_empty() {
            "no worker lock names a dead process".into()
        } else {
            format!(
                "{} lock(s) name a process that is gone: {}",
                stale.len(),
                stale
                    .iter()
                    .map(|lock| format!(
                        "{} ({})",
                        lock.path.display(),
                        lock.pid
                            .map_or_else(|| "no pid in it".to_owned(), |pid| format!("pid {pid}"))
                    ))
                    .collect::<Vec<_>>()
                    .join("; ")
            )
        },
        fix: Some("ferry doctor --layout --fix (renames them aside; deletes nothing)".into()),
    };
    (check, stale)
}

/// The Syncthing scope check. `folders` is what Syncthing has configured, or `None` when it
/// was not asked or could not be reached; that is not a failure, only a check not made.
fn syncthing_scope(root: &Root, folders: Option<&[Folder]>) -> Check {
    let fix = Some(
        "ferry doctor --layout --fix (stops Syncthing sharing the folder; deletes no file)"
            .to_owned(),
    );
    let Some(folders) = folders else {
        return Check {
            name: "syncthing",
            ok: true,
            detail: "Syncthing's folders were not read (it is not running or not asked)".into(),
            fix: None,
        };
    };
    let strays = syncscope::strays(&root.path, folders);
    Check {
        name: "syncthing",
        ok: strays.is_empty(),
        detail: if strays.is_empty() {
            format!(
                "Syncthing shares nothing but channels and hand-ins ({} folder(s) configured under {})",
                folders.len(),
                root.path.display()
            )
        } else {
            format!(
                "{} Syncthing folder(s) sit where nothing is shared: {}. Only channels and hand-ins are shared; git carries the code",
                strays.len(),
                strays
                    .iter()
                    .map(|folder| format!("{} at {}", folder.id, folder.path))
                    .collect::<Vec<_>>()
                    .join("; ")
            )
        },
        fix,
    }
}

/// Stop Syncthing sharing the folders Ferryman itself registered in a place the scope guard
/// forbids (an old `<project>-work`, say). Only the Syncthing registration goes. No file does.
/// Folders it cannot vouch for as its own are left, and show in the check.
pub fn unshare_strays(root: &Root) -> Vec<String> {
    let Some(folders) = syncscope::configured_folders() else {
        return Vec::new();
    };
    let mut done = Vec::new();
    for folder in syncscope::strays(&root.path, &folders) {
        if syncscope::is_ours_to_unshare(&root.path, folder)
            && ferryman_channel::syncthing_remove_folder(&folder.id).is_ok()
        {
            done.push(format!("stopped sharing {} ({})", folder.id, folder.path));
        }
    }
    done
}

/// The live (not archived) projects filed in the root.
fn live(root: &Root) -> Vec<Entry> {
    root.read()
        .projects
        .into_iter()
        .filter(|entry| !entry.is_archived())
        .collect()
}

/// Layout 2: each managed project has `repo`, `comms`, `handins` and `work`; each custom
/// project (placed by hand) has the paths recorded for it. Being custom is not a failure;
/// a recorded path that is not there is.
fn project_folders(root: &Root) -> Check {
    let mut problems = Vec::new();
    let (mut managed, mut custom) = (0_usize, 0_usize);
    let whole = root.layout_version() >= 2;
    for entry in live(root) {
        let id = &entry.project_id;
        // Part-way through `root migrate` only the projects that moved have this shape.
        if !whole && !entry.is_v2_placed(root) {
            continue;
        }
        let mut wanted: Vec<(&str, PathBuf)> = vec![("comms", entry.channel.clone())];
        match entry.placement_in(root) {
            Placement::Managed => {
                managed += 1;
                wanted.push(("repo", entry.managed_clone_path(root)));
                wanted.push(("handins", entry.handins_path(root)));
                wanted.push(("work", entry.work_path(root)));
            }
            Placement::Custom => {
                custom += 1;
                if let Some(repo) = &entry.repo {
                    wanted.push(("repo", repo.clone()));
                }
                if let Some(handins) = &entry.handins {
                    wanted.push(("handins", handins.clone()));
                }
                if let Some(work) = &entry.work {
                    wanted.push(("work", work.clone()));
                }
            }
        }
        let missing: Vec<String> = wanted
            .iter()
            .filter(|(_, path)| !path.is_dir())
            .map(|(name, path)| format!("{name} {}", path.display()))
            .collect();
        if !missing.is_empty() {
            problems.push(format!("{id}: missing {}", missing.join(", ")));
        }
    }
    let custom_note = if custom == 0 {
        String::new()
    } else {
        format!("; {custom} placed by hand (custom), left where they were recorded")
    };
    Check {
        name: "projects",
        ok: problems.is_empty(),
        detail: if problems.is_empty() {
            format!("{managed} managed project(s) have repo, comms, handins and work{custom_note}")
        } else {
            format!("{}{custom_note}", problems.join("; "))
        },
        fix: Some(
            "ferry doctor --layout --fix (makes handins/work/tmp), ferry repos sync (the clone)"
                .into(),
        ),
    }
}

/// Make the per-project folders a managed project is meant to have (`handins`, `work`,
/// `tmp`) when they are missing. Only ever makes a folder; touches nothing in a custom
/// project. Returns what was made.
pub fn make_project_folders(root: &Root) -> Vec<String> {
    let mut made = Vec::new();
    let whole = root.layout_version() >= 2;
    for entry in live(root) {
        if entry.placement_in(root) != Placement::Managed {
            continue;
        }
        // A root part-way through `root migrate` is still layout 1 as a whole; the
        // projects that moved already have their folders and get any that are missing.
        if !whole && !entry.is_v2_placed(root) {
            continue;
        }
        for path in [
            entry.handins_path(root),
            entry.work_path(root),
            root.project_tmp(&entry.project_id),
        ] {
            if !path.is_dir() && fs::create_dir_all(&path).is_ok() {
                made.push(format!("made {}", path.display()));
            }
        }
    }
    made
}

/// `.env` files (and `*.env`) inside `dir`, to a few levels, without following links.
fn env_files_in(dir: &Path, depth: usize, found: &mut Vec<PathBuf>) {
    let Ok(entries) = fs::read_dir(dir) else {
        return;
    };
    for entry in entries.flatten() {
        let path = entry.path();
        let Ok(meta) = fs::symlink_metadata(&path) else {
            continue;
        };
        if meta.is_file() && access::looks_like_env_file(&path) {
            found.push(path);
        } else if meta.is_dir() && depth > 0 && entry.file_name() != ".stfolder" {
            env_files_in(&path, depth - 1, found);
        }
    }
}

/// Keys stay home, and a Worker has no way into the channel.
///
/// For every live project, whatever its placement: no `secrets/`, project `.env` or other
/// `.env` file sits inside a folder that is synced (the channel, the hand-ins); and for a
/// Worker-level agent that runs here, the project keeps hand-ins apart from the channel (its
/// own writes have somewhere to go), no file of its is sitting in the channel, and Syncthing,
/// if it has the channel, has it receive-only.
fn keys_and_levels(root: &Root, ask_syncthing: bool) -> Check {
    let mut problems = Vec::new();
    let secrets = root.secrets();
    for entry in live(root) {
        let id = &entry.project_id;
        let mut synced = vec![entry.channel.clone()];
        let handins = entry.handins_path(root);
        if !handins.starts_with(&entry.channel) {
            synced.push(handins);
        }
        let env = entry.env_path(root);
        for dir in &synced {
            if access::path_within(dir, &secrets) || access::path_within(&secrets, dir) {
                problems.push(format!("{id}: {} holds or sits in secrets/", dir.display()));
            }
            if access::path_within(&env, dir) {
                problems.push(format!(
                    "{id}: its environment file {} is inside the synced folder {}",
                    env.display(),
                    dir.display()
                ));
            }
            let mut found = Vec::new();
            env_files_in(dir, 3, &mut found);
            for file in found {
                problems.push(format!(
                    "{id}: {} is an environment file inside a synced folder",
                    file.display()
                ));
            }
        }
        let workers = access::worker_agents(&entry.channel, id);
        if workers.is_empty() {
            continue;
        }
        let local: Option<String> = entry
            .attachment()
            .and_then(|attachment| crate::agent::AgentConfig::load(&attachment).ok())
            .map(|config| ferryman_channel::canonical_agent_name(&config.agent))
            .filter(|name| workers.contains(name));
        let Some(local) = local else { continue };
        if !access::enforced(&entry.channel, id) {
            problems.push(format!(
                "{id}: {local} is a Worker here but the project keeps hand-ins inside the channel, so it has nowhere else to write"
            ));
            continue;
        }
        let stray = stray_worker_files(&entry.channel, &local);
        if !stray.is_empty() {
            problems.push(format!(
                "{id}: {} file(s) by {local} sit in the channel, e.g. {}",
                stray.len(),
                stray[0]
            ));
        }
        if ask_syncthing {
            let folder = format!("{id}-ferryman");
            if let Some(kind) = ferryman_channel::syncthing_folder_type(&folder)
                && kind != "receiveonly"
            {
                problems.push(format!(
                    "{id}: {local} is a Worker here but Syncthing has the channel as {kind}, not receiveonly"
                ));
            }
        }
    }
    Check {
        name: "keys",
        ok: problems.is_empty(),
        detail: if problems.is_empty() {
            "no secrets/ or .env is inside a synced folder, and no Worker here can write a channel"
                .into()
        } else {
            problems.join("; ")
        },
        fix: Some(
            "move the .env out of the synced folder; ferry doctor --layout --fix moves a Worker's stray channel files into its handins; ferry access set <project> <agent> worker re-applies receive-only"
                .into(),
        ),
    }
}

/// Channel-relative paths of files `agent` authored in `channel` (what a Worker must not
/// have there).
fn stray_worker_files(channel: &Path, agent: &str) -> Vec<String> {
    let workers: std::collections::BTreeSet<String> = std::iter::once(agent.to_owned()).collect();
    let mut found = Vec::new();
    let mut pending = vec![(channel.to_path_buf(), String::new())];
    while let Some((dir, prefix)) = pending.pop() {
        let Ok(entries) = fs::read_dir(&dir) else {
            continue;
        };
        for entry in entries.flatten() {
            let name = entry.file_name().to_string_lossy().into_owned();
            let relative = if prefix.is_empty() {
                name.clone()
            } else {
                format!("{prefix}/{name}")
            };
            let Ok(meta) = fs::symlink_metadata(entry.path()) else {
                continue;
            };
            if meta.is_dir() {
                if !matches!(name.as_str(), ".stfolder" | ".stversions" | "keys") {
                    pending.push((entry.path(), relative));
                }
            } else if meta.is_file()
                && access::comms_author_refused(&relative, None, &workers).is_some()
            {
                found.push(relative);
            }
        }
    }
    found.sort();
    found
}

/// Move the channel files a Worker-level agent running here left in the channel into its
/// hand-ins folder. Moves, never deletes. Returns what was done.
pub fn sweep_worker_strays(root: &Root) -> Vec<String> {
    let mut done = Vec::new();
    for entry in live(root) {
        let Some(attachment) = entry.attachment() else {
            continue;
        };
        let Ok(config) = crate::agent::AgentConfig::load(&attachment) else {
            continue;
        };
        let Ok(route) =
            ferryman_channel::route_for(entry.repo.as_deref().unwrap_or(&entry.channel))
        else {
            continue;
        };
        for moved in access::sweep_worker_writes(&route, &config.agent) {
            done.push(format!(
                "moved {}'s {moved} out of the channel of {} into its handins",
                config.agent, entry.project_id
            ));
        }
    }
    done
}

/// Run the checks. `scan` is the machine's workers (see [`machine::scan`]); passing it
/// in keeps the rule testable without a process table. Syncthing is not asked here: see
/// [`inspect_live`] and [`inspect_with`].
#[must_use]
pub fn inspect(root: &Root, scan: &Scan) -> Report {
    inspect_with(root, scan, None)
}

/// [`inspect`], reading the folders from the machine's own Syncthing.
#[must_use]
pub fn inspect_live(root: &Root, scan: &Scan) -> Report {
    inspect_with(root, scan, syncscope::configured_folders().as_deref())
}

/// [`inspect`], with Syncthing's configured folders given.
#[must_use]
pub fn inspect_with(root: &Root, scan: &Scan, folders: Option<&[Folder]>) -> Report {
    let (lock_check, stale) = locks(root);
    let mut checks = vec![
        folders_check(root),
        clones(root),
        workers(scan),
        service(scan),
        lock_check,
        syncthing_scope(root, folders),
    ];
    // Also for a root part-way through `root migrate`: the projects that moved are in
    // layout 2 already, whatever the manifest as a whole says.
    if root.layout_version() >= 2
        || root
            .read()
            .projects
            .iter()
            .any(|entry| !entry.is_archived() && entry.is_v2_placed(root))
    {
        checks.push(project_folders(root));
    }
    checks.push(keys_and_levels(root, folders.is_some()));
    Report { checks, stale }
}
#[cfg(test)]
mod tests;
