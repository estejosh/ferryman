use super::*;
use ferryman_channel::{AgentIdentity, AgentRoute, ProjectRoute};

fn hermetic() {
    ferryman_channel::licensing::use_machine_state_dir_per_thread(
        std::env::temp_dir().join(format!("ferryman-repos-selftest-{}", std::process::id())),
    );
}

fn josh() -> AgentIdentity {
    AgentIdentity::from_seed("josh", [7u8; 32])
}

/// A project the root files as a channel with a master: no checkout anywhere.
fn filed(root: &Root, id: &str) -> PathBuf {
    let channel = root.comms_home(id);
    fs::create_dir_all(&channel).unwrap();
    let master = josh();
    let route = ProjectRoute {
        project_id: id.into(),
        workspace: channel.clone(),
        attachment: channel.clone(),
        communications: channel.clone(),
        shared_remote: format!("{id}-ferryman"),
        git_remote: String::new(),
        git_visibility: String::new(),
        agents: Vec::new(),
    };
    ferryman_channel::register_agent(
        &route,
        &AgentRoute {
            name: "josh".into(),
            role: "operator".into(),
            capabilities: Vec::new(),
            public_key: Some(master.public_key_hex()),
            encryption_key: None,
        },
    )
    .unwrap();
    let route = ProjectRoute {
        agents: ferryman_channel::read_agent_roster(&channel).unwrap(),
        ..route
    };
    ferryman_channel::master::initialize_master(&route, &master, "josh").unwrap();
    root.adopt(id, &channel, None).unwrap();
    channel
}

fn run(dir: &Path, args: &[&str]) {
    let output = Command::new("git")
        .arg("-C")
        .arg(dir)
        .args(["-c", "user.name=t", "-c", "user.email=t@example.com"])
        .args(args)
        .output()
        .unwrap();
    assert!(
        output.status.success(),
        "git {args:?}: {}",
        String::from_utf8_lossy(&output.stderr)
    );
}

/// A bare repository `<dir>/origins/<name>.git` with one commit on main, and the working
/// repository it was pushed from (to make more commits).
fn origin(dir: &Path, name: &str) -> (PathBuf, PathBuf) {
    let bare = dir.join("origins").join(format!("{name}.git"));
    fs::create_dir_all(&bare).unwrap();
    run(&bare, &["init", "--bare", "-q", "-b", "main"]);
    let seed = dir.join("seeds").join(name);
    fs::create_dir_all(&seed).unwrap();
    run(&seed, &["init", "-q", "-b", "main"]);
    fs::write(seed.join("README.md"), "hello").unwrap();
    run(&seed, &["add", "-A"]);
    run(&seed, &["commit", "-q", "-m", "first"]);
    run(&seed, &["push", "-q", bare.to_str().unwrap(), "main"]);
    (bare, seed)
}

fn setup() -> (tempfile::TempDir, Root) {
    hermetic();
    let dir = tempfile::tempdir().unwrap();
    let root = Root::create(&dir.path().join("ferry")).unwrap();
    (dir, root)
}

fn with_template(root: &Root, dir: &Path) {
    let template = format!("{}/{{project}}.git", dir.join("origins").display());
    rootconfig::set_remote_template(root, &template).unwrap();
}

fn row<'a>(rows: &'a [Row], id: &str) -> &'a Row {
    rows.iter().find(|row| row.project == id).unwrap()
}

fn snapshot(dir: &Path) -> Vec<(PathBuf, Vec<u8>)> {
    fn walk(dir: &Path, out: &mut Vec<(PathBuf, Vec<u8>)>) {
        for entry in fs::read_dir(dir).unwrap().flatten() {
            let path = entry.path();
            if path.is_dir() {
                walk(&path, out);
            } else {
                out.push((path.clone(), fs::read(&path).unwrap()));
            }
        }
    }
    let mut out = Vec::new();
    walk(dir, &mut out);
    out.sort();
    out
}

#[test]
fn a_project_with_a_channel_and_a_remote_gets_a_clone_attached_to_its_channel() {
    let (dir, root) = setup();
    let channel = filed(&root, "quantly");
    origin(dir.path(), "quantly");
    with_template(&root, dir.path());
    let before = snapshot(&channel);

    let rows = sync(&root, &Options::default()).unwrap();
    let r = row(&rows, "quantly");
    assert_eq!(r.status, Status::Done(vec!["cloned", "attached"]), "{r:?}");
    assert_eq!(r.word(), "cloned, attached");

    let managed = root.managed_clone("quantly");
    assert!(managed.join(".git").exists() && managed.join("README.md").is_file());
    // Filed as the worker's checkout, reading the channel the root already had.
    let entry = &root.read().projects[0];
    assert_eq!(entry.repo.as_deref(), Some(managed.as_path()));
    assert!(!entry.adopted);
    let (route, has_checkout) = entry.route(&root).unwrap();
    assert!(has_checkout);
    assert!(attach::same_path(&route.communications, &channel));
    // The key-bearing folder is ignored by git, through the clone's own exclude file.
    let ignored = Command::new("git")
        .arg("-C")
        .arg(&managed)
        .args(["check-ignore", "-q", ".ferryman/keys/x.key"])
        .status()
        .unwrap();
    assert!(ignored.success(), ".ferryman is kept out of git");
    assert!(
        !managed.join(".gitignore").exists(),
        "no tracked file written"
    );
    // The channel is untouched: no roster, key or device was written.
    assert_eq!(snapshot(&channel), before);
}

#[test]
fn syncing_again_changes_nothing_and_a_new_commit_is_fetched() {
    let (dir, root) = setup();
    filed(&root, "quantly");
    let (bare, seed) = origin(dir.path(), "quantly");
    with_template(&root, dir.path());
    sync(&root, &Options::default()).unwrap();
    let managed = root.managed_clone("quantly");
    let manifest = fs::read(root.manifest_path()).unwrap();
    let files = snapshot(&managed.join(".ferryman"));

    let again = sync(&root, &Options::default()).unwrap();
    assert_eq!(
        row(&again, "quantly").status,
        Status::AlreadyOk,
        "{again:?}"
    );
    assert_eq!(fs::read(root.manifest_path()).unwrap(), manifest);
    assert_eq!(snapshot(&managed.join(".ferryman")), files);

    fs::write(seed.join("more.md"), "more").unwrap();
    run(&seed, &["add", "-A"]);
    run(&seed, &["commit", "-q", "-m", "second"]);
    run(&seed, &["push", "-q", bare.to_str().unwrap(), "main"]);
    let fetched = sync(&root, &Options::default()).unwrap();
    assert_eq!(
        row(&fetched, "quantly").status,
        Status::Done(vec!["fetched"]),
        "{fetched:?}"
    );
    // A fetch is all it does: the clone's own branch and files were not moved.
    assert!(!managed.join("more.md").exists());
    let log = git_ok(Some(&managed), &["log", "--oneline", "origin/main"]).unwrap();
    assert_eq!(log.lines().count(), 2);
}

#[test]
fn a_persons_working_copy_is_never_touched_and_is_remembered() {
    let (dir, root) = setup();
    let channel = filed(&root, "quantly");
    let (_, seed) = origin(dir.path(), "quantly");
    // The person's checkout is where the worker used to work: attached, filed, with
    // uncommitted work in it.
    let human = dir.path().join("work").join("quantly");
    fs::create_dir_all(human.parent().unwrap()).unwrap();
    run(
        dir.path(),
        &[
            "clone",
            "-q",
            seed.to_str().unwrap(),
            human.to_str().unwrap(),
        ],
    );
    fs::write(human.join("wip.rs"), "uncommitted").unwrap();
    attach::attach(&root, &human, Some("quantly"), false).unwrap();
    assert_eq!(
        root.read().projects[0].repo.as_deref(),
        Some(human.as_path())
    );
    with_template(&root, dir.path());
    let theirs = snapshot(&human);

    let rows = sync(&root, &Options::default()).unwrap();
    assert_eq!(
        row(&rows, "quantly").status,
        Status::Done(vec!["cloned", "attached"]),
        "{rows:?}"
    );
    assert_eq!(
        snapshot(&human),
        theirs,
        "not one byte of the working copy changed"
    );
    let entry = &root.read().projects[0];
    let managed = root.managed_clone("quantly");
    assert_eq!(
        entry.repo.as_deref(),
        Some(managed.as_path()),
        "workers use the clone"
    );
    assert_eq!(
        entry.human_checkouts,
        vec![human.clone()],
        "and the copy is remembered"
    );
    assert!(attach::same_path(
        &entry.route(&root).unwrap().0.communications,
        &channel
    ));

    // Filing the person's copy again (an `enable`, an `attach`) does not take it back.
    root.adopt("quantly", &channel, Some(&human)).unwrap();
    let entry = &root.read().projects[0];
    assert_eq!(entry.repo.as_deref(), Some(managed.as_path()));
    assert_eq!(entry.human_checkouts, vec![human]);
}

#[cfg(unix)]
#[test]
fn a_link_left_by_adopt_is_replaced_and_what_it_pointed_at_is_not_touched() {
    let (dir, root) = setup();
    filed(&root, "quantly");
    let (_, seed) = origin(dir.path(), "quantly");
    with_template(&root, dir.path());
    let human = dir.path().join("human");
    run(
        dir.path(),
        &[
            "clone",
            "-q",
            seed.to_str().unwrap(),
            human.to_str().unwrap(),
        ],
    );
    fs::write(human.join("wip.rs"), "uncommitted").unwrap();
    fs::create_dir_all(root.repos()).unwrap();
    std::os::unix::fs::symlink(&human, root.managed_clone("quantly")).unwrap();
    let theirs = snapshot(&human);

    let rows = sync(&root, &Options::default()).unwrap();
    assert_eq!(
        row(&rows, "quantly").status,
        Status::Done(vec!["cloned", "attached"]),
        "{rows:?}"
    );
    let managed = root.managed_clone("quantly");
    assert!(link_at(&managed).is_none(), "now a real clone");
    assert!(managed.join(".git").is_dir());
    assert_eq!(snapshot(&human), theirs);
    assert!(
        root.read().projects[0].human_checkouts.contains(&human),
        "the checkout the link pointed at is remembered"
    );
}

#[test]
fn what_is_not_synced_is_named() {
    let (dir, root) = setup();
    for id in ["archived", "off", "secret", "orphan", "gone"] {
        filed(&root, id);
        origin(dir.path(), id);
    }
    root.archive("archived", true, &josh()).unwrap();
    ferryman_channel::ferry::set_swarm(&root.comms_home("off"), "off", false, &josh()).unwrap();
    rootconfig::set_excluded(&root, "secret", true).unwrap();
    with_template(&root, dir.path());
    // "gone" lost its channel folder; "orphan" has a remote that does not answer.
    fs::remove_dir_all(root.comms_home("gone")).unwrap();
    fs::remove_dir_all(dir.path().join("origins").join("orphan.git")).unwrap();

    let rows = sync(&root, &Options::default()).unwrap();
    assert_eq!(
        row(&rows, "archived").status,
        Status::Skipped(Skip::Archived)
    );
    assert_eq!(row(&rows, "off").status, Status::Skipped(Skip::SwarmOff));
    assert_eq!(row(&rows, "secret").status, Status::Skipped(Skip::Excluded));
    assert_eq!(row(&rows, "gone").status, Status::Skipped(Skip::NoChannel));
    assert!(
        matches!(&row(&rows, "orphan").status, Status::Skipped(Skip::Failed(why)) if why.contains("could not clone")),
        "{rows:?}"
    );
    for id in ["archived", "off", "secret", "gone", "orphan"] {
        assert!(
            !root.managed_clone(id).exists(),
            "{id}: nothing was cloned for a project that is skipped"
        );
    }
    assert!(
        root.read().projects.iter().all(|e| e.repo.is_none()),
        "nothing was filed for them either"
    );
}

#[test]
fn a_project_with_no_remote_known_is_skipped_not_guessed() {
    let (_dir, root) = setup();
    filed(&root, "noremote");
    let rows = sync(&root, &Options::default()).unwrap();
    assert_eq!(
        row(&rows, "noremote").status,
        Status::Skipped(Skip::NoRemote)
    );
    assert!(Skip::NoRemote.reason().contains("remote_template"));
}

#[test]
fn a_dry_run_changes_nothing_and_says_what_it_would_do() {
    let (dir, root) = setup();
    filed(&root, "quantly");
    origin(dir.path(), "quantly");
    with_template(&root, dir.path());
    let (before, manifest) = (
        snapshot(&root.path),
        fs::read(root.manifest_path()).unwrap(),
    );

    let rows = sync(
        &root,
        &Options {
            dry_run: true,
            ..Options::default()
        },
    )
    .unwrap();
    let r = row(&rows, "quantly");
    assert_eq!(r.status, Status::Done(vec!["cloned", "attached"]));
    assert!(
        r.details.iter().any(|d| d.starts_with("would clone")),
        "{r:?}"
    );
    assert!(!root.managed_clone("quantly").exists());
    assert_eq!(snapshot(&root.path), before);
    assert_eq!(fs::read(root.manifest_path()).unwrap(), manifest);
}

#[test]
fn only_one_project_when_asked_and_an_unknown_one_is_an_error() {
    let (dir, root) = setup();
    filed(&root, "alpha");
    filed(&root, "beta");
    origin(dir.path(), "alpha");
    origin(dir.path(), "beta");
    with_template(&root, dir.path());
    let rows = sync(
        &root,
        &Options {
            only: Some("alpha".into()),
            ..Options::default()
        },
    )
    .unwrap();
    assert_eq!(rows.len(), 1);
    assert!(root.managed_clone("alpha").exists());
    assert!(!root.managed_clone("beta").exists());
    let error = sync(
        &root,
        &Options {
            only: Some("nope".into()),
            ..Options::default()
        },
    )
    .expect_err("an unknown project");
    assert!(format!("{error:#}").contains("nope"));
}

#[test]
fn something_that_is_not_a_clone_is_left_exactly_as_it_is() {
    let (dir, root) = setup();
    filed(&root, "quantly");
    origin(dir.path(), "quantly");
    with_template(&root, dir.path());
    let squatter = root.managed_clone("quantly");
    fs::create_dir_all(&squatter).unwrap();
    fs::write(squatter.join("notes.txt"), "mine").unwrap();
    let rows = sync(&root, &Options::default()).unwrap();
    assert!(matches!(
        row(&rows, "quantly").status,
        Status::Skipped(Skip::NotAClone(_))
    ));
    assert_eq!(
        fs::read_to_string(squatter.join("notes.txt")).unwrap(),
        "mine"
    );
}

#[test]
fn the_origin_of_a_working_copy_is_a_last_resort_and_loses_its_credentials() {
    let (dir, root) = setup();
    filed(&root, "quantly");
    let human = dir.path().join("human");
    fs::create_dir_all(&human).unwrap();
    run(&human, &["init", "-q", "-b", "main"]);
    run(
        &human,
        &[
            "remote",
            "add",
            "origin",
            "https://someone:secrettoken@example.invalid/estejosh/quantly.git",
        ],
    );
    root.adopt("quantly", &root.comms_home("quantly"), Some(&human))
        .unwrap();
    let entry = root.read().projects[0].clone();
    let found = candidates(&entry, &RootConfig::default(), &root);
    assert_eq!(found, vec!["https://example.invalid/estejosh/quantly.git"]);
    assert!(!found.concat().contains("secrettoken"));

    // The machine's own template comes first.
    let config = RootConfig {
        remote_template: Some("git@github-estejosh:estejosh/{project}.git".into()),
        ..RootConfig::default()
    };
    assert_eq!(
        candidates(&entry, &config, &root),
        vec![
            "git@github-estejosh:estejosh/quantly.git".to_owned(),
            "https://example.invalid/estejosh/quantly.git".to_owned()
        ]
    );
}

#[test]
fn unsynced_lists_what_a_sync_would_fix_and_nothing_once_it_has() {
    let (dir, root) = setup();
    filed(&root, "alpha");
    filed(&root, "excluded");
    origin(dir.path(), "alpha");
    with_template(&root, dir.path());
    rootconfig::set_excluded(&root, "excluded", true).unwrap();
    let missing = unsynced(&root);
    assert_eq!(missing.len(), 1, "{missing:?}");
    assert_eq!(missing[0].0, "alpha");
    sync(&root, &Options::default()).unwrap();
    assert!(unsynced(&root).is_empty(), "{:?}", unsynced(&root));
}
