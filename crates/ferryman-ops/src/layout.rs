//! `ferry doctor --layout`: is this machine laid out the way Ferryman expects?
//!
//! The principle is that nothing may depend on an agent remembering a path or a step, so the
//! layout is fixed and this is the check that it is still there. It reads; the only thing it
//! ever changes is a stale lock, and only when the process in it is proven dead, and then by
//! renaming, never deleting. The watchdog runs it, and its repair is `repos sync`, which
//! never signs.
//!
//! Six checks, each with the command that fixes it:
//!
//! 1. the three folders (`comms/`, `repos/`, `work/`) exist under the ferry root;
//! 2. every live project has `repos/<project>`, a clone attached to its channel;
//! 3. exactly one worker is running or enabled on the machine;
//! 4. that worker runs as a service (an enabled unit or scheduled task), so a reboot does not
//!    end the swarm;
//! 5. no worker lock names a process that is no longer running;
//! 6. Syncthing shares only channels: no configured folder is the root, above it, or under
//!    repos/ or work/, and none of Ferryman's own folders sits outside comms/.

use std::fs;
use std::path::PathBuf;

use ferryman_channel::ferry::Root;
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
        places.push(root.managed_clone(&entry.project_id));
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
    let missing: Vec<String> = [
        ("comms", root.comms()),
        ("repos", root.repos()),
        ("work", root.work()),
    ]
    .into_iter()
    .filter(|(_, path)| !path.is_dir())
    .map(|(name, _)| format!("{name}/"))
    .collect();
    Check {
        name: "folders",
        ok: missing.is_empty(),
        detail: if missing.is_empty() {
            format!("comms/, repos/ and work/ are under {}", root.path.display())
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
    Check {
        name: "repos",
        ok: missing.is_empty(),
        detail: if missing.is_empty() {
            format!("every live project has its clone under repos/ ({live} filed)")
        } else {
            format!(
                "{} project(s) without an attached repos/<project>: {}",
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
                "Syncthing shares nothing outside {}/comms ({} folder(s) configured)",
                root.path.display(),
                folders.len()
            )
        } else {
            format!(
                "{} Syncthing folder(s) sit outside comms/: {}. Only channels are shared; git carries the code",
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

/// Run the six checks. `scan` is the machine's workers (see [`machine::scan`]); passing it
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
    Report {
        checks: vec![
            folders_check(root),
            clones(root),
            workers(scan),
            service(scan),
            lock_check,
            syncthing_scope(root, folders),
        ],
        stale,
    }
}
#[cfg(test)]
mod tests;
