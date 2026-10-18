use super::*;
use crate::machine::{Kind, Worker};
use std::path::Path;

fn hermetic() {
    ferryman_channel::licensing::use_machine_state_dir_per_thread(
        std::env::temp_dir().join(format!("ferryman-layout-selftest-{}", std::process::id())),
    );
}

fn setup() -> (tempfile::TempDir, Root) {
    hermetic();
    let dir = tempfile::tempdir().unwrap();
    let root = Root::create_with_layout(&dir.path().join("ferry"), 1).unwrap();
    for folder in [root.comms(), root.repos(), root.work()] {
        fs::create_dir_all(folder).unwrap();
    }
    (dir, root)
}

fn unit(enabled: bool) -> Worker {
    Worker {
        kind: Kind::Unit {
            unit: "ferryman-worker.service".into(),
            file: PathBuf::from("/home/u/.config/systemd/user/ferryman-worker.service"),
            user: true,
            enabled,
            active: enabled,
            pid: None,
        },
        all_projects: true,
        identity: None,
        command: "ferry agent run --all-projects".into(),
    }
}

fn process(pid: u32) -> Worker {
    Worker {
        kind: Kind::Process { pid },
        all_projects: true,
        identity: None,
        command: "ferry agent run --all-projects".into(),
    }
}

fn scan_of(workers: Vec<Worker>) -> Scan {
    Scan {
        workers,
        notes: Vec::new(),
    }
}

fn check<'a>(report: &'a Report, name: &str) -> &'a Check {
    report.checks.iter().find(|c| c.name == name).unwrap()
}

#[test]
fn a_machine_with_the_layout_and_one_enabled_service_passes() {
    let (_dir, root) = setup();
    let report = inspect(&root, &scan_of(vec![unit(true)]));
    assert!(report.ok(), "{}", report.render());
}

#[test]
fn a_missing_folder_is_named_with_its_fix() {
    let (_dir, root) = setup();
    fs::remove_dir_all(root.work()).unwrap();
    let report = inspect(&root, &scan_of(vec![unit(true)]));
    let folders = check(&report, "folders");
    assert!(!folders.ok);
    assert!(folders.detail.contains("work/"), "{}", folders.detail);
    assert_eq!(folders.fix.as_deref(), Some("ferry fleet setup"));
}

#[test]
fn no_worker_and_two_workers_both_fail_the_one_worker_check() {
    let (_dir, root) = setup();
    let none = inspect(&root, &scan_of(Vec::new()));
    assert!(!check(&none, "one worker").ok);
    assert!(!check(&none, "service").ok);
    let two = inspect(&root, &scan_of(vec![unit(true), process(4242)]));
    assert!(!check(&two, "one worker").ok);
    assert!(check(&two, "one worker").detail.contains("2 workers"));
}

#[test]
fn a_worker_that_is_only_a_process_is_not_a_service() {
    let (_dir, root) = setup();
    let report = inspect(&root, &scan_of(vec![process(4242)]));
    assert!(check(&report, "one worker").ok);
    assert!(!check(&report, "service").ok);
    assert!(check(&report, "service").detail.contains("reboot"));
}

#[test]
fn a_disabled_unit_does_not_count_as_a_worker() {
    let (_dir, root) = setup();
    let report = inspect(&root, &scan_of(vec![unit(false), unit(true)]));
    assert!(check(&report, "one worker").ok);
    assert!(check(&report, "service").ok);
}

fn with_lock(root: &Root, dir: &Path, project: &str, pid: &str) -> PathBuf {
    let channel = root.comms_home(project);
    fs::create_dir_all(&channel).unwrap();
    let repo = dir.join("clones").join(project);
    fs::create_dir_all(repo.join(".ferryman")).unwrap();
    root.adopt(project, &channel, Some(&repo)).unwrap();
    let lock = repo.join(".ferryman").join("worker-fang.lock");
    fs::write(&lock, pid).unwrap();
    lock
}

#[test]
fn a_lock_naming_a_dead_process_is_reported_and_renamed_never_deleted() {
    let (dir, root) = setup();
    let lock = with_lock(&root, dir.path(), "quantly", "999999999");
    let found = stale_locks(&root);
    assert_eq!(found.len(), 1, "{found:?}");
    assert_eq!(found[0].pid, Some(999_999_999));
    assert!(found[0].proven_dead());
    let report = inspect(&root, &scan_of(vec![unit(true)]));
    assert!(!check(&report, "locks").ok);
    assert!(check(&report, "locks").detail.contains("999999999"));

    let done = archive_stale(&found);
    assert_eq!(done.len(), 1, "{done:?}");
    assert!(!lock.exists());
    let kept = lock.with_file_name("worker-fang.lock.stale-999999999");
    assert_eq!(fs::read_to_string(kept).unwrap(), "999999999");
    assert!(stale_locks(&root).is_empty());
}

#[test]
fn a_second_lock_from_a_reused_pid_is_kept_beside_the_first_not_deleted() {
    let (dir, root) = setup();
    let lock = with_lock(&root, dir.path(), "quantly", "999999999");
    archive_stale(&stale_locks(&root));
    // The same pid again: the first archive is still there and nothing is overwritten.
    fs::write(&lock, "999999999").unwrap();
    let done = archive_stale(&stale_locks(&root));
    assert_eq!(done.len(), 1, "{done:?}");
    assert!(!lock.exists());
    assert!(
        lock.with_file_name("worker-fang.lock.stale-999999999")
            .is_file()
    );
    assert!(
        lock.with_file_name("worker-fang.lock.stale-999999999-1")
            .is_file()
    );
}

#[test]
fn a_lock_naming_a_live_process_is_left_alone() {
    let (dir, root) = setup();
    let lock = with_lock(
        &root,
        dir.path(),
        "quantly",
        &std::process::id().to_string(),
    );
    assert!(stale_locks(&root).is_empty());
    assert!(lock.exists());
}

#[test]
fn a_lock_with_no_pid_in_it_is_reported_but_never_moved() {
    let (dir, root) = setup();
    let lock = with_lock(&root, dir.path(), "quantly", "not a pid");
    let found = stale_locks(&root);
    assert_eq!(found.len(), 1);
    assert!(!found[0].proven_dead());
    assert!(archive_stale(&found).is_empty());
    assert!(lock.exists());
}

#[test]
fn a_live_project_without_a_clone_fails_the_repos_check() {
    let (_dir, root) = setup();
    let channel = root.comms_home("quantly");
    fs::create_dir_all(&channel).unwrap();
    root.adopt("quantly", &channel, None).unwrap();
    let report = inspect(&root, &scan_of(vec![unit(true)]));
    let repos = check(&report, "repos");
    assert!(!repos.ok, "{}", repos.detail);
    assert!(repos.detail.contains("quantly"));
    assert_eq!(repos.fix.as_deref(), Some("ferry repos sync"));
}

fn folder(id: &str, path: &Path) -> Folder {
    Folder {
        id: id.into(),
        label: String::new(),
        path: path.display().to_string(),
    }
}

#[test]
fn a_syncthing_folder_outside_comms_is_flagged_and_channels_are_not() {
    let (_dir, root) = setup();
    let scan = scan_of(vec![unit(true)]);
    let good = vec![
        folder("p-ferryman", &root.comms().join("p-ferryman")),
        folder("holiday-photos", Path::new("/srv/photos")),
    ];
    let report = inspect_with(&root, &scan, Some(&good));
    assert!(check(&report, "syncthing").ok, "{}", report.render());

    let bad = vec![
        folder("p-ferryman", &root.comms().join("p-ferryman")),
        folder("p-work", &root.work().join("p")),
        folder("by-hand", &root.repos().join("p")),
        folder("whole", &root.path),
    ];
    let report = inspect_with(&root, &scan, Some(&bad));
    let found = check(&report, "syncthing");
    assert!(!found.ok);
    for id in ["p-work", "by-hand", "whole"] {
        assert!(found.detail.contains(id), "{}", found.detail);
    }
    assert!(!found.detail.contains("p-ferryman at"), "{}", found.detail);
    assert!(
        found
            .fix
            .as_deref()
            .is_some_and(|fix| fix.contains("--layout --fix"))
    );
    assert!(!report.ok());
}

#[test]
fn not_reaching_syncthing_is_a_check_not_made_and_not_a_failure() {
    let (_dir, root) = setup();
    let report = inspect_with(&root, &scan_of(vec![unit(true)]), None);
    assert!(check(&report, "syncthing").ok);
    assert!(report.ok(), "{}", report.render());
}
