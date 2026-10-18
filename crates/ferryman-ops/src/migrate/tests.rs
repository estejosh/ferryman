use super::*;
use crate::machine::{Kind, Worker};
use ferryman_channel::ferry::Root;

fn hermetic() {
    ferryman_channel::licensing::use_machine_state_dir_per_thread(
        std::env::temp_dir().join(format!("ferryman-migrate-selftest-{}", std::process::id())),
    );
}

fn write(path: &Path, text: &str) {
    fs::create_dir_all(path.parent().unwrap()).unwrap();
    fs::write(path, text).unwrap();
}

struct Fixture {
    dir: tempfile::TempDir,
    root: Root,
}

/// A layout-1 root with one managed project (`alpha`) and one placed by hand (`mine`).
fn fixture() -> Fixture {
    hermetic();
    let dir = tempfile::tempdir().unwrap();
    let root = Root::create_with_layout(&dir.path().join("ferry"), 1).unwrap();

    let channel = root.comms().join("alpha-ferryman");
    write(&channel.join("agents").join("wisp.json"), "{}");
    write(
        &channel
            .join("handins")
            .join("wisp")
            .join("o1")
            .join("handin.json"),
        "{}",
    );
    let repo = root.repos().join("alpha");
    write(
        &repo.join(".ferryman").join("bridge.toml"),
        &format!(
            "project = \"alpha\"\nworkspace = \"{}\"\nattachment = \"{}\"\ncommunications = \"{}\"\n",
            repo.display(),
            repo.join(".ferryman").display(),
            channel.display()
        ),
    );
    assert!(root.adopt("alpha", &channel, Some(&repo)).unwrap());

    let mine = dir.path().join("elsewhere").join("mine-comms");
    write(&mine.join("agents").join("fang.json"), "{}");
    let mine_repo = dir.path().join("elsewhere").join("mine-repo");
    fs::create_dir_all(&mine_repo).unwrap();
    assert!(root.adopt("mine", &mine, Some(&mine_repo)).unwrap());
    Fixture { dir, root }
}

fn snapshot(path: &Path) -> Vec<(PathBuf, u64)> {
    fn walk(path: &Path, out: &mut Vec<(PathBuf, u64)>) {
        let Ok(entries) = fs::read_dir(path) else {
            return;
        };
        for entry in entries.flatten() {
            let p = entry.path();
            let meta = entry.metadata().unwrap();
            out.push((p.clone(), if meta.is_file() { meta.len() } else { 0 }));
            if meta.is_dir() {
                walk(&p, out);
            }
        }
    }
    let mut out = Vec::new();
    walk(path, &mut out);
    out.sort();
    out
}

fn status<'a>(report: &'a Report, id: &str) -> &'a Status {
    &report
        .projects
        .iter()
        .find(|p| p.project == id)
        .unwrap()
        .status
}

fn options(apply: bool) -> Options {
    Options {
        apply,
        syncthing: false,
        backend: None,
        prune_stale_worktrees: false,
        machine_blockers: Vec::new(),
    }
}

/// A Syncthing stand-in that records the calls it gets and, when the folder is resumed,
/// whether the hand-ins had already left the channel and `handins` was already ignored.
#[derive(Debug)]
struct Mock {
    comms: PathBuf,
    calls: std::sync::Mutex<Vec<String>>,
    move_ok: bool,
}

impl Mock {
    fn new(comms: PathBuf) -> std::sync::Arc<Self> {
        std::sync::Arc::new(Self {
            comms,
            calls: std::sync::Mutex::new(Vec::new()),
            move_ok: true,
        })
    }
    fn note(&self, call: &str) {
        self.calls.lock().unwrap().push(call.to_string());
    }
    fn calls(&self) -> Vec<String> {
        self.calls.lock().unwrap().clone()
    }
    /// Whether a resume now would announce no deletion.
    fn safe_to_resume(&self) -> bool {
        !self.comms.join("handins").exists()
            && fs::read_to_string(self.comms.join(".stignore"))
                .is_ok_and(|text| text.lines().any(|line| line.trim() == "/handins"))
    }
}

impl Syncthing for Mock {
    fn has_folder(&self, _: &str) -> bool {
        true
    }
    fn pause(&self, _: &str, paused: bool) -> Result<()> {
        if paused {
            self.note("pause");
        } else {
            self.note(if self.safe_to_resume() {
                "resume (safe)"
            } else {
                "resume (EARLY)"
            });
        }
        Ok(())
    }
    fn move_folder(&self, _: &str, _: &Path) -> Result<bool> {
        self.note(if self.safe_to_resume() {
            "move+resume (safe)"
        } else {
            "move+resume (EARLY)"
        });
        Ok(self.move_ok)
    }
    fn register_handins(&self, _: &ferryman_channel::ProjectRoute, _: &Path) -> Result<()> {
        self.note("register");
        Ok(())
    }
}

#[test]
fn a_dry_run_writes_nothing_at_all() {
    let f = fixture();
    let before = snapshot(f.dir.path());
    let manifest = fs::read(f.root.manifest_path()).unwrap();
    let report = run(&f.root, &options(false)).unwrap();
    assert_eq!(status(&report, "alpha"), &Status::Planned);
    assert_eq!(status(&report, "mine"), &Status::Custom);
    assert!(!report.applied && report.log.is_none());
    assert_eq!(
        snapshot(f.dir.path()),
        before,
        "the dry run changed the disk"
    );
    assert_eq!(fs::read(f.root.manifest_path()).unwrap(), manifest);
    assert!(report.render().contains("left in place (custom)"));
    assert!(!f.root.path.join("_to_delete").exists());
    assert!(!f.root.logs().exists());
}

#[test]
fn apply_moves_a_managed_project_and_leaves_a_custom_one_alone() {
    let f = fixture();
    let custom_before = snapshot(&f.dir.path().join("elsewhere"));
    let report = run(&f.root, &options(true)).unwrap();
    assert_eq!(
        status(&report, "alpha"),
        &Status::Migrated,
        "{}",
        report.render()
    );
    assert_eq!(status(&report, "mine"), &Status::Custom);

    let home = f.root.project_dir("alpha");
    assert!(
        home.join("comms")
            .join("agents")
            .join("wisp.json")
            .is_file()
    );
    assert!(
        home.join("handins")
            .join("wisp")
            .join("o1")
            .join("handin.json")
            .is_file(),
        "hand-ins get their own folder"
    );
    assert!(!home.join("comms").join("handins").exists());
    assert!(
        home.join("repo")
            .join(".ferryman")
            .join("bridge.toml")
            .is_file()
    );
    assert!(!f.root.comms().join("alpha-ferryman").exists());
    assert!(!f.root.repos().join("alpha").exists());

    let bridge =
        fs::read_to_string(home.join("repo").join(".ferryman").join("bridge.toml")).unwrap();
    assert!(
        bridge.contains(&home.join("comms").display().to_string()),
        "{bridge}"
    );
    assert!(bridge.contains(&format!("workspace = \"{}\"", home.join("repo").display())));

    let entry = f
        .root
        .read()
        .projects
        .into_iter()
        .find(|e| e.project_id == "alpha")
        .unwrap();
    assert_eq!(entry.channel, home.join("comms"));
    assert_eq!(entry.repo, Some(home.join("repo")));

    assert_eq!(snapshot(&f.dir.path().join("elsewhere")), custom_before);
    assert_eq!(f.root.layout_version(), 2, "every managed project moved");
    assert!(report.log.as_ref().is_some_and(|log| log.is_file()));
    // The old manifest is kept, not deleted.
    assert!(report.to_delete.iter().any(|p| p.is_file()));
}

#[test]
fn a_second_run_has_nothing_to_do() {
    let f = fixture();
    run(&f.root, &options(true)).unwrap();
    let again = run(&f.root, &options(true)).unwrap();
    assert_eq!(status(&again, "alpha"), &Status::AlreadyDone);
    assert_eq!(status(&again, "mine"), &Status::Custom);
}

#[test]
fn a_running_worker_blocks_the_move_and_says_so() {
    let f = fixture();
    let worker = Worker {
        kind: Kind::Process { pid: 4242 },
        all_projects: true,
        identity: None,
        command: "ferry agent run --all-projects".into(),
    };
    let blockers = blockers_from_scan(&Scan {
        workers: vec![worker],
        notes: Vec::new(),
    });
    assert_eq!(blockers.len(), 1);
    let report = run(
        &f.root,
        &Options {
            machine_blockers: blockers,
            ..options(true)
        },
    )
    .unwrap();
    assert!(matches!(status(&report, "alpha"), Status::Blocked(why) if why[0].contains("running")));
    assert_eq!(
        f.root.layout_version(),
        1,
        "not bumped while a project is left behind"
    );
    let alpha = report
        .projects
        .iter()
        .find(|p| p.project == "alpha")
        .unwrap();
    assert!(
        alpha.steps.iter().any(|step| step.starts_with("channel ")),
        "a blocked project still shows what would move: {:?}",
        alpha.steps
    );
    assert!(
        f.root
            .comms()
            .join("alpha-ferryman")
            .join("agents")
            .exists()
    );
    assert!(f.root.repos().join("alpha").exists());
}

#[test]
fn doctor_accepts_a_custom_project_in_a_migrated_root() {
    let f = fixture();
    run(&f.root, &options(true)).unwrap();
    let report = crate::layout::inspect(&f.root, &Scan::default());
    let projects = report.checks.iter().find(|c| c.name == "projects").unwrap();
    assert!(projects.ok, "{}", report.render());
    assert!(projects.detail.contains("custom"), "{}", projects.detail);
}

#[test]
fn syncthing_is_held_paused_until_the_hand_ins_are_out_and_ignored() {
    let f = fixture();
    let mock = Mock::new(f.root.project_dir("alpha").join("comms"));
    let report = run(
        &f.root,
        &Options {
            backend: Some(mock.clone()),
            ..options(true)
        },
    )
    .unwrap();
    assert_eq!(
        status(&report, "alpha"),
        &Status::Migrated,
        "{}",
        report.render()
    );
    assert_eq!(
        mock.calls(),
        vec!["pause", "register", "move+resume (safe)"],
        "paused first; hand-ins registered and out before the folder is given back"
    );
    let stignore = fs::read_to_string(f.root.project_dir("alpha").join("comms/.stignore")).unwrap();
    assert!(stignore.lines().any(|l| l.trim() == "/handins"));
}

#[test]
fn a_failure_after_the_move_resumes_syncthing_and_a_rerun_finishes_the_job() {
    let f = fixture();
    // Make the step after the move fail: `.stignore` cannot be written over a directory.
    let channel = f.root.comms().join("alpha-ferryman");
    fs::create_dir_all(channel.join(".stignore")).unwrap();
    let comms = f.root.project_dir("alpha").join("comms");
    let mock = Mock::new(comms.clone());
    let failing = Options {
        backend: Some(mock.clone()),
        ..options(true)
    };
    let report = run(&f.root, &failing).unwrap();
    assert!(
        matches!(status(&report, "alpha"), Status::Failed(_)),
        "{}",
        report.render()
    );
    // Syncthing was given back (pointed at the channel's new place), not left paused.
    let calls = mock.calls();
    assert_eq!(
        calls.first().map(String::as_str),
        Some("pause"),
        "{calls:?}"
    );
    assert!(
        calls.iter().any(|c| c.starts_with("move+resume")),
        "resumed on the way out: {calls:?}"
    );
    // The manifest and the bridge already say where the channel is.
    let entry = f
        .root
        .read()
        .projects
        .into_iter()
        .find(|e| e.project_id == "alpha")
        .unwrap();
    assert_eq!(entry.channel, comms);
    assert!(comms.join("agents/wisp.json").is_file());
    assert_eq!(
        f.root.layout_version(),
        1,
        "not bumped while a project failed"
    );

    // Fix what was in the way; a rerun finishes the hand-ins and the clone.
    fs::remove_dir(comms.join(".stignore")).unwrap();
    let again = run(
        &f.root,
        &Options {
            backend: Some(Mock::new(comms.clone())),
            ..options(true)
        },
    )
    .unwrap();
    assert_eq!(
        status(&again, "alpha"),
        &Status::Migrated,
        "{}",
        again.render()
    );
    assert!(
        f.root
            .project_dir("alpha")
            .join("handins/wisp/o1/handin.json")
            .is_file()
    );
    assert!(!comms.join("handins").exists());
    assert_eq!(f.root.layout_version(), 2);
}

#[test]
fn a_rerun_finishes_a_move_that_stopped_before_the_manifest_was_told() {
    let f = fixture();
    let channel = f.root.comms().join("alpha-ferryman");
    let comms = f.root.project_dir("alpha").join("comms");
    // The earlier run died right after the rename.
    fs::create_dir_all(comms.parent().unwrap()).unwrap();
    fs::rename(&channel, &comms).unwrap();
    let report = run(&f.root, &options(true)).unwrap();
    assert_eq!(
        status(&report, "alpha"),
        &Status::Migrated,
        "{}",
        report.render()
    );
    let entry = f
        .root
        .read()
        .projects
        .into_iter()
        .find(|e| e.project_id == "alpha")
        .unwrap();
    assert_eq!(entry.channel, comms);
    assert!(
        f.root
            .project_dir("alpha")
            .join("handins/wisp/o1/handin.json")
            .is_file()
    );
    let bridge = fs::read_to_string(
        f.root
            .project_dir("alpha")
            .join("repo/.ferryman/bridge.toml"),
    )
    .unwrap();
    assert!(bridge.contains(&comms.display().to_string()), "{bridge}");
}

#[test]
fn a_park_that_fails_is_an_error_not_a_silent_duplicate() {
    let dir = tempfile::tempdir().unwrap();
    let blocker = dir.path().join("_to_delete");
    fs::write(&blocker, "a file where the folder should be").unwrap();
    let victim = dir.path().join("old");
    fs::create_dir_all(&victim).unwrap();
    let mut ctx = Ctx {
        apply: true,
        stamp: "t".into(),
        park: blocker,
        parked: Vec::new(),
        backed_up: false,
    };
    assert!(park(&victim, &mut ctx).is_err());
    assert!(victim.is_dir(), "nothing was lost");
}

#[test]
fn copy_tree_keeps_modified_times_and_refuses_a_linked_directory() {
    let dir = tempfile::tempdir().unwrap();
    let from = dir.path().join("from");
    write(&from.join("a/b.txt"), "x");
    let old = std::time::SystemTime::now() - std::time::Duration::from_secs(86_400 * 30);
    fs::OpenOptions::new()
        .write(true)
        .open(from.join("a/b.txt"))
        .unwrap()
        .set_modified(old)
        .unwrap();
    let to = dir.path().join("to");
    ferry::copy_tree(&from, &to).unwrap();
    let copied = fs::metadata(to.join("a/b.txt"))
        .unwrap()
        .modified()
        .unwrap();
    let drift = copied
        .duration_since(old)
        .unwrap_or_else(|e| e.duration())
        .as_secs();
    assert!(drift < 3, "the copy kept the file's time (off by {drift}s)");

    let elsewhere = dir.path().join("elsewhere");
    fs::create_dir_all(&elsewhere).unwrap();
    let link = from.join("link");
    let made = {
        #[cfg(unix)]
        {
            std::os::unix::fs::symlink(&elsewhere, &link).is_ok()
        }
        #[cfg(windows)]
        {
            std::os::windows::fs::symlink_dir(&elsewhere, &link).is_ok()
        }
    };
    if made {
        let refused = ferry::copy_tree(&from, &dir.path().join("to2")).unwrap_err();
        assert!(
            format!("{refused:#}").contains("link to a directory"),
            "{refused:#}"
        );
    }
}

#[test]
fn a_stale_bridge_does_not_drag_a_migrated_entry_back_to_the_old_channel() {
    let f = fixture();
    let old = f.root.comms().join("alpha-ferryman");
    run(&f.root, &options(true)).unwrap();
    let home = f.root.project_dir("alpha");
    // A checkout whose bridge.toml still names the old place is filed again.
    assert!(
        f.root
            .adopt("alpha", &old, Some(&home.join("repo")))
            .unwrap()
    );
    let entry = f
        .root
        .read()
        .projects
        .into_iter()
        .find(|e| e.project_id == "alpha")
        .unwrap();
    assert_eq!(entry.channel, home.join("comms"));
}
