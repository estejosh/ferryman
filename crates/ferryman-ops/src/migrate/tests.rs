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

/// What the stand-in does when asked.
#[derive(Debug, Clone, Default)]
struct Behaviour {
    pause_fails: bool,
    move_result: Move,
    /// The folder was already paused by its owner.
    paused_before: bool,
    /// Where it says Syncthing has the folder.
    old_path: Option<PathBuf>,
}

#[derive(Debug, Clone, Copy, Default, PartialEq, Eq)]
enum Move {
    #[default]
    Works,
    Declined,
    Errors,
}

/// A Syncthing stand-in that records the calls it gets and, when the folder is resumed,
/// whether the hand-ins had already left the channel and `handins` was already ignored.
#[derive(Debug)]
struct Mock {
    comms: PathBuf,
    calls: std::sync::Mutex<Vec<String>>,
    behaviour: Behaviour,
}

impl Mock {
    fn new(comms: PathBuf) -> std::sync::Arc<Self> {
        Self::behaving(comms, Behaviour::default())
    }
    fn behaving(comms: PathBuf, behaviour: Behaviour) -> std::sync::Arc<Self> {
        std::sync::Arc::new(Self {
            comms,
            calls: std::sync::Mutex::new(Vec::new()),
            behaviour,
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
    fn label(&self, what: &str) -> String {
        format!(
            "{what} ({})",
            if self.safe_to_resume() {
                "safe"
            } else {
                "EARLY"
            }
        )
    }
}

impl Syncthing for Mock {
    fn has_folder(&self, _: &str) -> bool {
        true
    }
    fn is_paused(&self, _: &str) -> bool {
        self.behaviour.paused_before
    }
    fn path_of(&self, _: &str) -> Option<PathBuf> {
        self.behaviour.old_path.clone()
    }
    fn pause(&self, _: &str, paused: bool) -> Result<()> {
        if paused {
            self.note("pause");
            if self.behaviour.pause_fails {
                bail!("syncthing refused");
            }
        } else {
            self.note(&self.label("resume"));
        }
        Ok(())
    }
    fn move_folder(&self, _: &str, _: &Path) -> Result<bool> {
        self.note(&self.label("move+resume"));
        match self.behaviour.move_result {
            Move::Works => Ok(true),
            Move::Declined => Ok(false),
            Move::Errors => bail!("syncthing is gone"),
        }
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
    // Paused, then given back in one call, at the channel's new place; the hand-ins were never
    // touched, so resuming before they were ignored announced nothing.
    assert_eq!(mock.calls(), vec!["pause", "move+resume (EARLY)"]);
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

fn entry_of(f: &Fixture, id: &str) -> Entry {
    f.root
        .read()
        .projects
        .into_iter()
        .find(|e| e.project_id == id)
        .unwrap()
}

#[test]
fn a_pause_that_fails_changes_nothing_and_resumes_nothing() {
    let f = fixture();
    let old = f.root.comms().join("alpha-ferryman");
    let comms = f.root.project_dir("alpha").join("comms");
    let mock = Mock::behaving(
        comms,
        Behaviour {
            pause_fails: true,
            ..Behaviour::default()
        },
    );
    let report = run(
        &f.root,
        &Options {
            backend: Some(mock.clone()),
            ..options(true)
        },
    )
    .unwrap();
    assert!(matches!(status(&report, "alpha"), Status::Failed(_)));
    assert_eq!(
        mock.calls(),
        vec!["pause"],
        "no resume of what it never paused"
    );
    assert!(
        old.join("agents/wisp.json").is_file(),
        "the channel did not move"
    );
    assert!(!f.root.project_dir("alpha").join(MARKER).exists());
    assert_eq!(entry_of(&f, "alpha").channel, old);
}

#[test]
fn a_folder_syncthing_will_not_repoint_is_left_paused_and_a_rerun_gives_it_back() {
    for how in [Move::Declined, Move::Errors] {
        let f = fixture();
        let comms = f.root.project_dir("alpha").join("comms");
        let mock = Mock::behaving(
            comms.clone(),
            Behaviour {
                move_result: how,
                ..Behaviour::default()
            },
        );
        let report = run(
            &f.root,
            &Options {
                backend: Some(mock.clone()),
                ..options(true)
            },
        )
        .unwrap();
        let Status::Failed(why) = status(&report, "alpha") else {
            panic!("{}", report.render());
        };
        assert!(why.contains("left paused"), "{why}");
        // The old place is empty now: resuming there would sync nothing and look healthy.
        assert_eq!(
            mock.calls(),
            vec!["pause", "register", "move+resume (safe)"],
            "{how:?}"
        );
        assert!(f.root.project_dir("alpha").join(MARKER).is_file());

        let again = Mock::new(comms.clone());
        let report = run(
            &f.root,
            &Options {
                backend: Some(again.clone()),
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
            again.calls(),
            vec!["pause", "register", "move+resume (safe)"]
        );
        assert!(!f.root.project_dir("alpha").join(MARKER).exists());
    }
}

#[test]
fn a_folder_syncthing_will_not_repoint_resumes_at_its_old_path_only_if_the_channel_is_there() {
    let f = fixture();
    let comms = f.root.project_dir("alpha").join("comms");
    // Syncthing says it still has the folder at a place that holds a channel.
    let still_there = f.dir.path().join("elsewhere").join("mine-comms");
    let mock = Mock::behaving(
        comms,
        Behaviour {
            move_result: Move::Declined,
            old_path: Some(still_there),
            ..Behaviour::default()
        },
    );
    let report = run(
        &f.root,
        &Options {
            backend: Some(mock.clone()),
            ..options(true)
        },
    )
    .unwrap();
    assert!(matches!(status(&report, "alpha"), Status::Failed(_)));
    assert_eq!(
        mock.calls().last().map(String::as_str),
        Some("resume (safe)"),
        "{:?}",
        mock.calls()
    );
}

#[test]
fn a_failure_while_moving_the_hand_ins_is_finished_by_a_rerun() {
    let f = fixture();
    let dir = f.root.project_dir("alpha");
    let comms = dir.join("comms");
    // A file where the hand-ins folder should go.
    write(&dir.join("handins"), "in the way");
    let mock = Mock::new(comms.clone());
    let report = run(
        &f.root,
        &Options {
            backend: Some(mock.clone()),
            ..options(true)
        },
    )
    .unwrap();
    assert!(
        matches!(status(&report, "alpha"), Status::Failed(_)),
        "{}",
        report.render()
    );
    // `handins` was already ignored when the move stopped, so giving the folder back
    // announces nothing.
    assert_eq!(mock.calls(), vec!["pause", "move+resume (EARLY)"]);
    assert_eq!(entry_of(&f, "alpha").channel, comms);
    assert!(
        comms.join("handins/wisp/o1/handin.json").is_file(),
        "nothing was lost"
    );
    assert!(
        fs::read_to_string(comms.join(".stignore"))
            .unwrap()
            .lines()
            .any(|l| l.trim() == "/handins")
    );

    fs::remove_file(dir.join("handins")).unwrap();
    let report = run(
        &f.root,
        &Options {
            backend: Some(Mock::new(comms.clone())),
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
    assert!(dir.join("handins/wisp/o1/handin.json").is_file());
    assert!(!comms.join("handins").exists());
    assert!(!dir.join(MARKER).exists());
}

#[test]
fn a_rerun_ignores_and_registers_the_hand_ins_even_when_there_were_none() {
    let f = fixture();
    let channel = f.root.comms().join("alpha-ferryman");
    fs::remove_dir_all(channel.join("handins")).unwrap();
    // The step after the move cannot write `.stignore` over a directory.
    fs::create_dir_all(channel.join(".stignore")).unwrap();
    let comms = f.root.project_dir("alpha").join("comms");
    let report = run(
        &f.root,
        &Options {
            backend: Some(Mock::new(comms.clone())),
            ..options(true)
        },
    )
    .unwrap();
    assert!(matches!(status(&report, "alpha"), Status::Failed(_)));
    assert_eq!(entry_of(&f, "alpha").channel, comms);

    fs::remove_dir(comms.join(".stignore")).unwrap();
    let mock = Mock::new(comms.clone());
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
        vec!["pause", "register", "move+resume (safe)"]
    );
    assert!(
        fs::read_to_string(comms.join(".stignore"))
            .unwrap()
            .lines()
            .any(|l| l.trim() == "/handins")
    );
}

#[test]
fn a_folder_its_owner_had_paused_is_given_back_paused() {
    let f = fixture();
    let comms = f.root.project_dir("alpha").join("comms");
    let mock = Mock::behaving(
        comms,
        Behaviour {
            paused_before: true,
            ..Behaviour::default()
        },
    );
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
        vec!["pause", "register", "move+resume (safe)", "pause"],
        "paused again after the move, as the person had it"
    );
}

#[test]
fn a_peer_still_on_the_old_layout_is_named_in_the_plan() {
    let f = fixture();
    let channel = f.root.comms().join("alpha-ferryman");
    write(
        &channel.join("presence").join("bob.json"),
        &format!(
            r#"{{"agent":"bob","machine":"b","seen_at":"{}","ferry_version":"0.5.30","paused":false}}"#,
            chrono::Utc::now().to_rfc3339()
        ),
    );
    let report = run(&f.root, &options(false)).unwrap();
    let text = report.render();
    assert!(
        text.contains("peers still on the old layout (bob)"),
        "{text}"
    );
    assert!(text.contains("same window"), "{text}");
}

fn git(dir: &Path, args: &[&str]) -> String {
    let out = Command::new("git")
        .arg("-C")
        .arg(dir)
        .args(args)
        .output()
        .unwrap();
    assert!(
        out.status.success(),
        "git {args:?}: {}",
        String::from_utf8_lossy(&out.stderr)
    );
    String::from_utf8_lossy(&out.stdout).trim().to_string()
}

/// Ferryman's clone of `alpha` as a git repo whose only commit is on a remote.
fn pushed_clone(f: &Fixture) -> PathBuf {
    let repo = f.root.repos().join("alpha");
    git(&repo, &["init", "-q", "-b", "main"]);
    git(&repo, &["config", "user.email", "t@example.com"]);
    git(&repo, &["config", "user.name", "tester"]);
    git(&repo, &["config", "commit.gpgsign", "false"]);
    write(&repo.join("f.txt"), "x\n");
    git(&repo, &["add", "f.txt"]);
    git(&repo, &["commit", "-q", "-m", "init"]);
    let bare = f.dir.path().join("remote.git");
    fs::create_dir_all(&bare).unwrap();
    git(&bare, &["init", "-q", "--bare"]);
    git(
        &repo,
        &["remote", "add", "origin", &bare.display().to_string()],
    );
    git(&repo, &["push", "-q", "-u", "origin", "main"]);
    repo
}

fn parked(f: &Fixture) -> Vec<String> {
    fs::read_dir(f.root.path.join("_to_delete"))
        .map(|entries| {
            entries
                .flatten()
                .map(|e| e.file_name().to_string_lossy().into_owned())
                .collect()
        })
        .unwrap_or_default()
}

#[test]
fn pruning_moves_only_clean_pushed_worktrees_under_work_and_leaves_the_rest() {
    let f = fixture();
    let repo = pushed_clone(&f);
    let stale = f.root.work().join("stale");
    let dirty = f.root.work().join("dirty");
    let human = f.dir.path().join("elsewhere").join("my-worktree");
    for (branch, path) in [("stale", &stale), ("dirty", &dirty), ("mine", &human)] {
        git(
            &repo,
            &[
                "worktree",
                "add",
                "-q",
                "-b",
                branch,
                &path.display().to_string(),
            ],
        );
    }
    write(&dirty.join("scratch.txt"), "not committed\n");

    let options = Options {
        prune_stale_worktrees: true,
        ..options(false)
    };
    // The plan names exactly what would move, and why the rest stays.
    let plan = run(&f.root, &options).unwrap().render();
    assert!(plan.contains("stale: would move"), "{plan}");
    assert!(
        plan.contains("dirty") && plan.contains("uncommitted changes"),
        "{plan}"
    );
    assert!(
        plan.contains("my-worktree") && plan.contains("not under work/"),
        "{plan}"
    );
    assert!(!plan.contains("my-worktree: would"), "{plan}");

    let report = run(
        &f.root,
        &Options {
            apply: true,
            ..options
        },
    )
    .unwrap();
    assert_eq!(
        status(&report, "alpha"),
        &Status::Migrated,
        "{}",
        report.render()
    );
    let moved = parked(&f);
    assert!(moved.iter().any(|n| n.starts_with("stale-")), "{moved:?}");
    assert!(
        !moved
            .iter()
            .any(|n| n.starts_with("dirty-") || n.starts_with("my-worktree")),
        "{moved:?}"
    );
    assert!(dirty.join("scratch.txt").is_file());
    assert!(human.is_dir());
}

#[test]
fn pruning_also_reaches_a_project_that_was_already_migrated() {
    let f = fixture();
    pushed_clone(&f);
    let report = run(&f.root, &options(true)).unwrap();
    assert_eq!(
        status(&report, "alpha"),
        &Status::Migrated,
        "{}",
        report.render()
    );
    let repo = entry_of(&f, "alpha").repo.unwrap();
    let stale = f.root.project_dir("alpha").join("work").join("old");
    git(
        &repo,
        &[
            "worktree",
            "add",
            "-q",
            "-b",
            "old",
            &stale.display().to_string(),
        ],
    );

    let again = run(
        &f.root,
        &Options {
            prune_stale_worktrees: true,
            ..options(true)
        },
    )
    .unwrap();
    assert_eq!(
        status(&again, "alpha"),
        &Status::AlreadyDone,
        "{}",
        again.render()
    );
    assert!(
        parked(&f).iter().any(|n| n.starts_with("old-")),
        "{:?}",
        parked(&f)
    );
}
