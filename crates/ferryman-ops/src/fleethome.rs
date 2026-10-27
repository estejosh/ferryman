//! Keeping this machine's part of the fleet folder current (ADR 0026).
//!
//! The folder and what counts in it are `ferryman_channel::fleethome`. This is what a machine
//! does with it: publish what it has, say what it moved, and hear what the fleet says.
//!
//! Everything here is best-effort and quiet. A machine the master has not admitted, or a root
//! with no fleet folder yet, is told so and carries on: the fleet folder is additive, and
//! nothing a project does waits on it.

use std::collections::BTreeMap;

use anyhow::{Context, Result};
use ferryman_channel::AgentIdentity;
use ferryman_channel::ferry::Root;
use ferryman_channel::fleethome::{self as home, Facts, NoticeBody, NoticeRow, Paths};
use serde_json::json;

/// This machine's own identity in the fleet folder: its name, and the key it already holds
/// for that name. Never a person's.
///
/// # Errors
/// The machine has no usable name, or its key cannot be read or made.
pub fn machine_identity(root: &Root) -> Result<AgentIdentity> {
    let name = crate::identity::machine_name()?;
    AgentIdentity::load_or_create(&name, &root.fleet_local())
        .with_context(|| format!("this machine's key for '{name}'"))
}

/// What a publish came to.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Publish {
    /// There is no fleet folder in this root. Nothing to do.
    NoFleet,
    /// Written (or already current).
    Done {
        entries: usize,
        machine_written: bool,
    },
    /// Not yet: the reason, in words for a person. Usually that the master has not admitted
    /// this machine.
    Pending(String),
}

/// Publish this machine's directory entries and its machine record.
#[must_use]
pub fn publish(root: &Root, identity: &AgentIdentity, machine: &str, facts: &Facts) -> Publish {
    if !home::exists(root) {
        return Publish::NoFleet;
    }
    if let Err(error) = home::enrol(root, identity) {
        return Publish::Pending(format!("{error:#}"));
    }
    // What lets another machine take a project up (ADR 0030): where its clone came from and
    // who masters it, on each directory entry; which worker this machine runs and what it
    // keeps out of its swarm, on the machine record. Filled in here, whoever publishes, so a
    // publish by `ferry enable` does not take back what the worker said.
    let directory = match home::publish_directory_with(
        root,
        machine,
        identity,
        &crate::propagate::adverts(root),
    ) {
        Ok(done) => done.written.len() + done.unchanged,
        Err(error) => return Publish::Pending(format!("{error:#}")),
    };
    let mut facts = facts.clone();
    if facts.worker.is_none() {
        facts.worker = crate::propagate::own_worker(root);
    }
    facts.excludes = crate::rootconfig::RootConfig::load(root).swarm_exclude;
    facts
        .excludes
        .retain(|project| ferryman_channel::is_safe_component(project));
    match home::publish_machine(root, machine, identity, &facts) {
        Ok(machine_written) => Publish::Done {
            entries: directory,
            machine_written,
        },
        Err(error) => Publish::Pending(format!("{error:#}")),
    }
}

/// What this machine can say about itself without a worker: the version, and the projects
/// the root files. A worker adds its engines.
#[must_use]
pub fn basic_facts(root: &Root, engines: Vec<String>) -> Facts {
    Facts {
        version: env!("CARGO_PKG_VERSION").to_owned(),
        worker: crate::propagate::own_worker(root),
        engines,
        projects: root
            .projects()
            .into_iter()
            .map(|entry| entry.project_id)
            .collect(),
        excludes: Vec::new(),
    }
}

/// [`publish`] as this machine, for a command that has just changed where things are
/// (`enable`, `adopt`, `root data`). Says nothing unless there is something to say.
#[must_use]
pub fn publish_here(root: &Root) -> Publish {
    if !home::exists(root) {
        return Publish::NoFleet;
    }
    let Ok(machine) = crate::identity::machine_name() else {
        return Publish::NoFleet;
    };
    let Ok(identity) = machine_identity(root) else {
        return Publish::NoFleet;
    };
    publish(root, &identity, &machine, &basic_facts(root, Vec::new()))
}

// ---------------------------------------------------------------------------------------
// What moved

/// Where every project's places were, and the layout, at one moment.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Snapshot {
    pub layout: u32,
    pub paths: BTreeMap<String, Paths>,
}

/// Take a [`Snapshot`] of `root` as its manifest says now.
#[must_use]
pub fn snapshot(root: &Root) -> Snapshot {
    Snapshot {
        layout: root.layout_version(),
        paths: root
            .read()
            .projects
            .iter()
            .map(|entry| {
                (
                    entry.project_id.clone(),
                    home::dir_body(root, entry, "-").paths,
                )
            })
            .collect(),
    }
}

/// One place that is not where it was.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Moved {
    pub project: String,
    pub kind: &'static str,
    pub old: String,
    pub new: String,
}

/// What differs between two snapshots, place by place. A project that is new, or gone, is
/// not a move.
#[must_use]
pub fn moved(before: &Snapshot, after: &Snapshot) -> Vec<Moved> {
    let mut out = Vec::new();
    for (project, old) in &before.paths {
        let Some(new) = after.paths.get(project) else {
            continue;
        };
        let pairs = [
            ("code", &old.code, &new.code),
            ("channel", &old.channel, &new.channel),
            ("handins", &old.handins, &new.handins),
            ("data", &old.data, &new.data),
            ("env", &old.env, &new.env),
            ("work", &old.work, &new.work),
        ];
        for (kind, was, now) in pairs {
            if let (Some(was), Some(now)) = (was, now)
                && was != now
            {
                out.push(Moved {
                    project: project.clone(),
                    kind,
                    old: was.clone(),
                    new: now.clone(),
                });
            }
        }
    }
    out
}

/// What `after_change` did.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Changed {
    pub moved: usize,
    pub publish: Publish,
    /// The id of the notice posted, when there was a move to tell the fleet about.
    pub notice: Option<String>,
    /// Why no notice was posted, when there was a move and it could not be.
    pub notice_note: Option<String>,
}

/// After a move: publish this machine's directory, then post a signed `layout-change`
/// notice that lists every old and new path. The directory comes first, so a reader who
/// sees the notice finds the entry already saying the same.
#[must_use]
pub fn after_change(root: &Root, before: &Snapshot, why: &str, severity: &str) -> Changed {
    let after = snapshot(root);
    let moves = moved(before, &after);
    let publish_result = publish_here(root);
    let mut changed = Changed {
        moved: moves.len(),
        publish: publish_result.clone(),
        notice: None,
        notice_note: None,
    };
    if moves.is_empty() && before.layout == after.layout {
        return changed;
    }
    match publish_result {
        Publish::NoFleet => {
            changed.notice_note = Some("there is no fleet folder, so nobody was told".into());
            return changed;
        }
        Publish::Pending(why) => {
            changed.notice_note = Some(format!("not posted: {why}"));
            return changed;
        }
        Publish::Done { .. } => {}
    }
    let (Ok(machine), Ok(identity)) = (crate::identity::machine_name(), machine_identity(root))
    else {
        changed.notice_note = Some("this machine has no identity to sign with".into());
        return changed;
    };
    let layouts = (before.layout, after.layout);
    match post_layout_notice(root, &identity, &machine, layouts, &moves, why, severity) {
        Ok(id) => changed.notice = Some(id),
        Err(error) => changed.notice_note = Some(format!("{error:#}")),
    }
    changed
}

fn post_layout_notice(
    root: &Root,
    identity: &AgentIdentity,
    machine: &str,
    layouts: (u32, u32),
    moves: &[Moved],
    why: &str,
    severity: &str,
) -> Result<String> {
    let mut text = format!(
        "{machine}: {why}. Layout {} to {}. {} place(s) moved.\n",
        layouts.0,
        layouts.1,
        moves.len()
    );
    for item in moves.iter().take(40) {
        text.push_str(&format!(
            "{} {}: {} -> {}\n",
            item.project, item.kind, item.old, item.new
        ));
    }
    if moves.len() > 40 {
        text.push_str(&format!(
            "... and {} more (see details)\n",
            moves.len() - 40
        ));
    }
    while text.len() > 3900 {
        match text.rfind('\n') {
            Some(at) if at > 0 => text.truncate(at),
            _ => break,
        }
    }
    let mut notice = NoticeBody::new(
        "layout-change",
        severity,
        &format!("{machine} moved {} place(s): {why}", moves.len()),
        &text,
    );
    notice.id = format!("{}-{machine}", notice.id);
    notice.machine = Some(machine.to_owned());
    notice.details = json!({
        "why": why,
        "layout": { "from": layouts.0, "to": layouts.1 },
        "moved": moves
            .iter()
            .map(|item| json!({
                "project": item.project,
                "kind": item.kind,
                "old": item.old,
                "new": item.new,
            }))
            .collect::<Vec<_>>(),
    });
    home::post_notice(root, identity, notice)
}

// ---------------------------------------------------------------------------------------
// Hearing the fleet

/// What a worker hears from the fleet folder in one pass.
#[derive(Debug, Clone, Default)]
pub struct Heard {
    /// High-severity notices not shown on this machine yet.
    pub notices: Vec<NoticeRow>,
    /// A release newer than this build that a live notice names.
    pub newer: Option<String>,
    /// Fleet orders for this machine from the master that are not yet acted on.
    pub orders: Vec<ferryman_channel::Order>,
}

/// Read the fleet folder as `machine`. Marks the notices it returns as shown, so a worker
/// says each once.
#[must_use]
pub fn listen(root: &Root, machine: &str, running: &str) -> Heard {
    if !home::exists(root) {
        return Heard::default();
    }
    let notices = home::unread_high(root);
    let ids: Vec<String> = notices.iter().map(|row| row.body.id.clone()).collect();
    let _ = home::mark_seen(root, &ids);
    let (all, _) = home::read_notices(root);
    Heard {
        notices,
        newer: home::newer_release(&all, running),
        orders: home::read_orders_for(root, machine).0,
    }
}

/// The action of a fleet order, when it is one this build knows.
#[must_use]
pub fn order_action(order: &ferryman_channel::Order) -> Option<&str> {
    order
        .payload
        .get("action")
        .and_then(serde_json::Value::as_str)
        .filter(|action| home::ORDER_ACTIONS.contains(action))
}

#[cfg(test)]
mod tests {
    use super::*;

    struct Fleet {
        _dir: tempfile::TempDir,
        root: Root,
        josh: AgentIdentity,
    }

    fn fleet() -> Fleet {
        ferryman_channel::ferry::isolate_root_search_for_this_thread();
        let dir = tempfile::tempdir().unwrap();
        ferryman_channel::licensing::use_machine_state_dir_per_thread(dir.path().join("state"));
        let root = Root::create_with_layout(&dir.path().join("ferry"), 1).unwrap();
        let channel = root.comms_home("demo");
        std::fs::create_dir_all(&channel).unwrap();
        let repo = root.repos().join("demo");
        std::fs::create_dir_all(&repo).unwrap();
        root.adopt("demo", &channel, Some(&repo)).unwrap();
        let josh = AgentIdentity::from_seed("josh", [7u8; 32]);
        home::init(&root, &josh).unwrap();
        Fleet {
            _dir: dir,
            root,
            josh,
        }
    }

    #[test]
    fn a_machine_that_is_not_admitted_is_told_why_and_the_folder_is_untouched() {
        let f = fleet();
        let me = AgentIdentity::from_seed("beastly", [11u8; 32]);
        let outcome = publish(&f.root, &me, "beastly", &basic_facts(&f.root, Vec::new()));
        let Publish::Pending(why) = outcome else {
            panic!("{outcome:?}");
        };
        assert!(why.contains("not admitted"), "{why}");
        assert!(home::read_directory(&f.root).projects.is_empty());
        // Admitted, it publishes.
        home::admit(&f.root, &f.josh, "beastly", "beastly").unwrap();
        let outcome = publish(
            &f.root,
            &me,
            "beastly",
            &basic_facts(&f.root, vec!["claude".into()]),
        );
        assert!(
            matches!(
                outcome,
                Publish::Done {
                    entries: 1,
                    machine_written: true
                }
            ),
            "{outcome:?}"
        );
    }

    #[test]
    fn a_migrate_updates_the_directory_then_posts_a_notice_listing_old_and_new() {
        let f = fleet();
        let me = AgentIdentity::from_seed("beastly", [11u8; 32]);
        home::enrol(&f.root, &me).unwrap();
        home::admit(&f.root, &f.josh, "beastly", "beastly").unwrap();
        let machine = "beastly";
        assert!(matches!(
            publish(&f.root, &me, machine, &basic_facts(&f.root, Vec::new())),
            Publish::Done { .. }
        ));
        let before = snapshot(&f.root);

        // A migrate moves the clone and the channel; the manifest says so.
        let new_repo = f.root.path.join("projects").join("demo").join("repo");
        let new_comms = f.root.path.join("projects").join("demo").join("comms");
        f.root
            .update_entry("demo", |entry| {
                entry.repo = Some(new_repo.clone());
                entry.channel = new_comms.clone();
            })
            .unwrap();
        let after = snapshot(&f.root);
        let moves = moved(&before, &after);
        assert!(
            moves
                .iter()
                .any(|m| m.kind == "code" && m.new.ends_with("repo"))
        );
        assert!(moves.iter().any(|m| m.kind == "channel"));

        // The same steps `after_change` takes, with this test's machine identity (the real
        // one is read from the OS and the machine's key store).
        let published = home::publish_directory(&f.root, machine, &me).unwrap();
        assert_eq!(published.written, vec!["demo/beastly".to_owned()]);
        let id = post_layout_notice(
            &f.root,
            &me,
            machine,
            (before.layout, after.layout),
            &moves,
            "root migrate",
            "high",
        )
        .unwrap();

        let directory = home::read_directory(&f.root);
        assert_eq!(
            directory.projects["demo"]["beastly"]
                .body
                .paths
                .code
                .as_deref(),
            Some(new_repo.display().to_string().as_str())
        );
        let (notices, findings) = home::read_notices(&f.root);
        assert!(findings.rejected.is_empty(), "{:?}", findings.rejected);
        assert_eq!(notices.len(), 1);
        let notice = &notices[0].body;
        assert_eq!(notice.id, id);
        assert_eq!(notice.kind, "layout-change");
        assert_eq!(notice.severity, "high");
        assert_eq!(notice.machine.as_deref(), Some("beastly"));
        assert!(notice.text.contains(&new_repo.display().to_string()));
        let listed = notice.details["moved"].as_array().unwrap();
        assert!(listed.iter().any(|m| m["project"] == "demo"
            && m["kind"] == "code"
            && m["new"] == new_repo.display().to_string()
            && m["old"] != m["new"]));
        assert_eq!(notices[0].signed_by, "beastly");

        // Heard once, and not again.
        let heard = listen(&f.root, "tiny", "0.6.1");
        assert_eq!(heard.notices.len(), 1);
        assert!(listen(&f.root, "tiny", "0.6.1").notices.is_empty());
    }

    #[test]
    fn nothing_moved_posts_nothing() {
        let f = fleet();
        let before = snapshot(&f.root);
        assert!(moved(&before, &snapshot(&f.root)).is_empty());
        let changed = after_change(&f.root, &before, "no change", "info");
        assert_eq!(changed.moved, 0);
        assert!(changed.notice.is_none());
        assert!(home::read_notices(&f.root).0.is_empty());
    }
}
