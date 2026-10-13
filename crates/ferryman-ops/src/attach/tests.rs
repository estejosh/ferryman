use super::*;
use ferryman_channel::{AgentIdentity, AgentRoute, ProjectRoute};

fn hermetic() {
    ferryman_channel::licensing::use_machine_state_dir_per_thread(
        std::env::temp_dir().join(format!("ferryman-attach-selftest-{}", std::process::id())),
    );
}

fn josh() -> AgentIdentity {
    AgentIdentity::from_seed("josh", [7u8; 32])
}

/// A project the root files as a channel only: the channel folder, a roster and a master.
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

/// A clone of `id` beside the root: a directory with a `.git`.
fn clone_of(dir: &Path, name: &str) -> PathBuf {
    let clone = dir.join("clones").join(name);
    fs::create_dir_all(clone.join(".git").join("info")).unwrap();
    clone
}

/// Every file under `dir` with its contents, so a test can say nothing in it changed.
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

fn setup() -> (tempfile::TempDir, Root) {
    hermetic();
    let dir = tempfile::tempdir().unwrap();
    let root = Root::create(&dir.path().join("ferry")).unwrap();
    (dir, root)
}

#[test]
fn attaching_names_the_existing_channel_and_touches_nothing_in_it() {
    let (dir, root) = setup();
    let channel = filed(&root, "quantly");
    let before = snapshot(&channel);
    let clone = clone_of(dir.path(), "quantly");

    let done = attach(&root, &clone, None, false).unwrap();
    let Attach::Attached { actions } = done else {
        panic!("{done:?}")
    };
    assert_eq!(actions.len(), 3, "{actions:?}");

    // The checkout reads the channel the root files, not a new one.
    let (route, has_checkout) = root.read().projects[0].route(&root).unwrap();
    assert!(has_checkout);
    assert!(same_path(&route.communications, &channel));
    assert_eq!(route.project_id, "quantly");
    assert!(same_path(&route.workspace, &clone));
    assert!(
        !clone.join(".ferryman").join("ferryman").exists(),
        "no second channel was made inside the repository"
    );
    assert!(!clone.join(".ferryman").join("keys").exists(), "no key");
    // Git keeps it out, and only through the clone's own untracked exclude file.
    let exclude = fs::read_to_string(clone.join(".git").join("info").join("exclude")).unwrap();
    assert!(covers_attachment(&exclude), "{exclude}");
    assert!(
        !clone.join(".gitignore").exists(),
        "no tracked file was written"
    );
    // And the channel is byte for byte what it was: no roster, device or grant was written.
    assert_eq!(snapshot(&channel), before);
}

#[test]
fn attaching_twice_is_already_and_writes_nothing() {
    let (dir, root) = setup();
    filed(&root, "quantly");
    let clone = clone_of(dir.path(), "quantly");
    attach(&root, &clone, None, false).unwrap();
    let before = snapshot(&clone);
    let manifest = fs::read(root.manifest_path()).unwrap();

    assert_eq!(attach(&root, &clone, None, false).unwrap(), Attach::Already);
    assert_eq!(snapshot(&clone), before);
    assert_eq!(fs::read(root.manifest_path()).unwrap(), manifest);
    let exclude = fs::read_to_string(clone.join(".git").join("info").join("exclude")).unwrap();
    assert_eq!(exclude.matches("/.ferryman/").count(), 1, "added once");
}

#[test]
fn a_dry_run_says_what_it_would_do_and_writes_nothing() {
    let (dir, root) = setup();
    let channel = filed(&root, "quantly");
    let clone = clone_of(dir.path(), "quantly");
    let (before, manifest) = (
        snapshot(dir.path()),
        fs::read(root.manifest_path()).unwrap(),
    );

    let Attach::Attached { actions } = attach(&root, &clone, None, true).unwrap() else {
        panic!("a dry run reports what it would attach")
    };
    assert!(
        actions.iter().any(|a| a.contains("bridge.toml")),
        "{actions:?}"
    );
    assert!(
        actions
            .iter()
            .any(|a| a.contains(&channel.display().to_string())),
        "{actions:?}"
    );
    assert_eq!(snapshot(dir.path()), before);
    assert_eq!(fs::read(root.manifest_path()).unwrap(), manifest);
}

#[test]
fn a_tracked_gitignore_that_already_covers_it_is_enough() {
    let (dir, root) = setup();
    filed(&root, "quantly");
    let clone = clone_of(dir.path(), "quantly");
    fs::write(clone.join(".gitignore"), "target/\n/.ferryman/\n").unwrap();

    attach(&root, &clone, None, false).unwrap();
    let exclude =
        fs::read_to_string(clone.join(".git").join("info").join("exclude")).unwrap_or_default();
    assert!(!covers_attachment(&exclude), "nothing was added: {exclude}");
}

#[test]
fn what_it_will_not_attach_is_named() {
    let (dir, root) = setup();
    filed(&root, "archived");
    filed(&root, "gone");
    filed(&root, "plain");
    let archived = clone_of(dir.path(), "archived");
    let gone = clone_of(dir.path(), "gone");
    root.archive("archived", true, &josh()).unwrap();
    // The channel folder vanished from this machine.
    fs::remove_dir_all(root.comms_home("gone")).unwrap();
    let not_git = dir.path().join("clones").join("plain");
    fs::create_dir_all(&not_git).unwrap();

    assert_eq!(
        attach(&root, &archived, None, false).unwrap(),
        Attach::Skipped(Skip::Archived)
    );
    assert_eq!(
        attach(&root, &gone, None, false).unwrap(),
        Attach::Skipped(Skip::NoChannel)
    );
    assert_eq!(
        attach(&root, &not_git, None, false).unwrap(),
        Attach::Skipped(Skip::NotGit)
    );
    let stranger = clone_of(dir.path(), "stranger");
    assert_eq!(
        attach(&root, &stranger, None, false).unwrap(),
        Attach::Skipped(Skip::NotFiled("stranger".into()))
    );
    for left_alone in [&archived, &gone, &stranger] {
        assert!(!left_alone.join(".ferryman").exists());
    }
}

#[test]
fn a_project_flag_names_the_project_when_the_folder_does_not() {
    let (dir, root) = setup();
    filed(&root, "quantly");
    let clone = clone_of(dir.path(), "quantly-old-clone");
    assert!(matches!(
        attach(&root, &clone, None, false).unwrap(),
        Attach::Skipped(Skip::NotFiled(_))
    ));
    assert!(matches!(
        attach(&root, &clone, Some("quantly"), false).unwrap(),
        Attach::Attached { .. }
    ));
}

#[test]
fn a_checkout_with_its_own_channel_is_left_exactly_as_it_is() {
    let (dir, root) = setup();
    let filed_channel = filed(&root, "quantly");
    let clone = clone_of(dir.path(), "quantly");
    // What `ferry enable` makes in a clone it cannot find a bridge for.
    let attachment = clone.join(".ferryman");
    let second = attachment.join("ferryman");
    fs::create_dir_all(&second).unwrap();
    let theirs = bridge_text("quantly", &clone, &attachment, &second);
    fs::write(attachment.join("bridge.toml"), &theirs).unwrap();

    let done = attach(&root, &clone, None, false).unwrap();
    let Attach::Skipped(Skip::OtherChannel { reads, files }) = done else {
        panic!("{done:?}")
    };
    assert!(same_path(&reads, &second));
    assert!(same_path(&files, &filed_channel));
    assert_eq!(
        fs::read_to_string(attachment.join("bridge.toml")).unwrap(),
        theirs
    );
    assert!(
        root.read().projects[0].repo.is_none(),
        "the root was not pointed at it either"
    );
}

#[test]
fn a_second_clone_does_not_take_the_place_of_the_one_the_root_files() {
    let (dir, root) = setup();
    filed(&root, "quantly");
    let first = clone_of(dir.path(), "quantly");
    attach(&root, &first, None, false).unwrap();
    let second = dir.path().join("elsewhere").join("quantly");
    fs::create_dir_all(second.join(".git")).unwrap();

    let done = attach(&root, &second, None, false).unwrap();
    let Attach::Skipped(Skip::AttachedElsewhere(other)) = done else {
        panic!("{done:?}")
    };
    assert!(same_path(&other, &first));
    assert!(!second.join(".ferryman").exists());
    assert!(same_path(
        root.read().projects[0].repo.as_ref().unwrap(),
        &first
    ));
}

#[test]
fn attach_all_reports_every_clone_it_finds_and_ignores_the_rest() {
    let (dir, root) = setup();
    for id in ["alpha", "beta", "gamma", "delta"] {
        filed(&root, id);
    }
    root.archive("delta", true, &josh()).unwrap();
    let folder = dir.path().join("clones");
    for name in ["alpha", "beta", "gamma", "delta"] {
        clone_of(dir.path(), name);
    }
    // Not named for any filed project: not this command's business, and not listed.
    clone_of(dir.path(), "notes");
    fs::create_dir_all(folder.join("loose-files")).unwrap();
    // Already attached by hand.
    attach(&root, &folder.join("alpha"), None, false).unwrap();

    let skip = vec!["gamma".to_owned()];
    let reports = attach_all(&root, &folder, &skip, false).unwrap();
    let outcome = |name: &str| {
        &reports
            .iter()
            .find(|report| report.name == name)
            .unwrap_or_else(|| panic!("{name} is in {reports:?}"))
            .outcome
    };
    assert_eq!(reports.len(), 4, "{reports:?}");
    assert_eq!(outcome("alpha"), &Attach::Already);
    assert!(matches!(outcome("beta"), Attach::Attached { .. }));
    assert_eq!(outcome("gamma"), &Attach::Skipped(Skip::ByName));
    assert_eq!(outcome("delta"), &Attach::Skipped(Skip::Archived));
    assert!(!folder.join("gamma").join(".ferryman").exists());
    assert!(
        folder
            .join("beta")
            .join(".ferryman")
            .join("bridge.toml")
            .is_file()
    );

    let dry = attach_all(&root, &folder, &[], true).unwrap();
    assert!(
        dry.iter()
            .filter(|report| report.name == "gamma")
            .all(|report| matches!(report.outcome, Attach::Attached { .. })),
        "left out only while the list says so"
    );
    assert!(without_clone(&root, &reports).is_empty());
}
