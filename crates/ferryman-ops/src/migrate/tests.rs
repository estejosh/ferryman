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
        machine_blockers: Vec::new(),
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
            apply: true,
            syncthing: false,
            machine_blockers: blockers,
        },
    )
    .unwrap();
    assert!(matches!(status(&report, "alpha"), Status::Blocked(why) if why[0].contains("running")));
    assert_eq!(
        f.root.layout_version(),
        1,
        "not bumped while a project is left behind"
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
