use super::*;
use crate::AgentRoute;

fn run(dir: &Path, args: &[&str]) -> String {
    git(dir, args).unwrap_or_else(|e| panic!("{e:#}"))
}

struct World {
    _tmp: tempfile::TempDir,
    repo: PathBuf,
    route: ProjectRoute,
    ash: AgentIdentity,
    rf: AgentIdentity,
}

fn world() -> World {
    let tmp = tempfile::tempdir().unwrap();
    let repo = tmp.path().join("idle-ish");
    fs::create_dir_all(repo.join("game")).unwrap();
    fs::create_dir_all(repo.join("art")).unwrap();
    run(
        tmp.path(),
        &["init", "-q", "-b", "main", repo.to_str().unwrap()],
    );
    for (k, v) in [
        ("user.name", "t"),
        ("user.email", "t@example.com"),
        ("commit.gpgsign", "false"),
    ] {
        run(&repo, &["config", k, v]);
    }
    fs::write(repo.join("game/main.rs"), "fn main() {}\n").unwrap();
    fs::write(repo.join("art/hero.txt"), "hero\n").unwrap();
    fs::write(repo.join("DECISIONS.md"), "# Decisions\n\nD1 first\n").unwrap();
    fs::write(repo.join("README.md"), "title\nbody\n").unwrap();
    run(&repo, &["add", "-A"]);
    run(&repo, &["commit", "-q", "-n", "-m", "start"]);
    let ash = AgentIdentity::from_seed("ash", [1; 32]);
    let rf = AgentIdentity::from_seed("rf", [2; 32]);
    let attachment = tmp.path().join("attach");
    let communications = tmp.path().join("channel");
    fs::create_dir_all(&attachment).unwrap();
    fs::create_dir_all(&communications).unwrap();
    let route = ProjectRoute {
        project_id: "idle-ish".into(),
        workspace: repo.clone(),
        attachment,
        communications: communications.clone(),
        shared_remote: String::new(),
        git_remote: String::new(),
        git_visibility: String::new(),
        agents: Vec::new(),
    };
    for who in [&ash, &rf] {
        crate::register_agent(
            &route,
            &AgentRoute {
                name: who.name().into(),
                role: "worker".into(),
                capabilities: Vec::new(),
                public_key: Some(who.public_key_hex()),
                encryption_key: None,
            },
        )
        .unwrap();
    }
    let route = ProjectRoute {
        agents: crate::read_agent_roster(&communications).unwrap(),
        ..route
    };
    World {
        _tmp: tmp,
        repo,
        route,
        ash,
        rf,
    }
}

fn spec<'a>(lane: &'a str, owns: &[&str]) -> NewLane<'a> {
    NewLane {
        lane,
        owns: owns.iter().map(|s| (*s).to_owned()).collect(),
        shared: Vec::new(),
        append_only: vec!["DECISIONS.md".into()],
        base: None,
        exe: PathBuf::from("ferry"),
    }
}

fn commit(dir: &Path, files: &[(&str, &str)], message: &str) {
    for (path, text) in files {
        let full = dir.join(path);
        fs::create_dir_all(full.parent().unwrap()).unwrap();
        fs::write(full, text).unwrap();
    }
    run(dir, &["add", "-A"]);
    run(dir, &["commit", "-q", "-n", "-m", message]);
}

#[test]
fn globs_match_the_way_people_write_them() {
    assert!(path_matches("art/**", "art/hero/a.png"));
    assert!(path_matches("art", "art/hero/a.png"));
    assert!(path_matches("art/", "art/a.png"));
    assert!(path_matches("*.md", "README.md"));
    assert!(!path_matches("*.md", "docs/a.md"));
    assert!(path_matches("**/*.png", "a.png"));
    assert!(path_matches("**/*.png", "x/y/a.png"));
    assert!(!path_matches("art/**", "game/art/a.png"));
    assert!(path_matches("game/*.rs", "game/main.rs"));
    assert!(!path_matches("game/*.rs", "game/sub/main.rs"));
    assert!(!path_matches("", "anything"));
}

#[test]
fn a_lane_is_its_own_worktree_hidden_from_the_main_checkout() {
    let w = world();
    let (record, dir) = new_lane(&w.route, &w.ash, spec("game", &["game/**"])).unwrap();
    assert_eq!(record.branch, "lane/game");
    assert!(
        same_path(&dir, &w.repo.join(".lanes").join("game")),
        "{} vs {}",
        dir.display(),
        w.repo.display()
    );
    // git lists the worktree with forward slashes and long names; it is found all the same.
    assert!(
        worktrees(&w.repo)
            .unwrap()
            .iter()
            .any(|t| same_path(&t.path, &dir) && t.branch.as_deref() == Some("lane/game"))
    );
    assert_eq!(
        run(&dir, &["rev-parse", "--abbrev-ref", "HEAD"]),
        "lane/game"
    );
    assert_eq!(run(&w.repo, &["rev-parse", "--abbrev-ref", "HEAD"]), "main");
    assert_eq!(
        run(&w.repo, &["status", "--porcelain"]),
        "",
        "the lanes folder is excluded"
    );
    // The hook is this worktree's alone.
    assert!(!run(&dir, &["config", "--worktree", "core.hooksPath"]).is_empty());
    assert!(!git_ok(&w.repo, &["config", "--get", "core.hooksPath"]));
    let marker = read_marker(&git_dir_of(&dir).unwrap()).unwrap();
    assert_eq!(marker.lane, "game");
    assert!(
        git_dir_of(&dir)
            .unwrap()
            .join("ferry-hooks/pre-commit")
            .is_file()
    );
    // Idempotent, and the record is signed and verifies.
    new_lane(&w.route, &w.ash, spec("game", &["game/**"])).unwrap();
    let loaded = load(&w.route).unwrap();
    assert_eq!(loaded.lanes.len(), 1);
    assert!(loaded.problems.is_empty());
    // A second lane cannot take the same glob; nor can a forged record count.
    assert!(new_lane(&w.route, &w.rf, spec("art", &["game/**"])).is_err());
    let mut forged = loaded.lanes[0].clone();
    forged.owns = vec!["**".into()];
    crate::atomic_json(&record_path(&w.route, "game"), &forged).unwrap();
    let after = load(&w.route).unwrap();
    assert!(after.lanes.is_empty(), "a tampered record grants nothing");
    assert_eq!(after.problems.len(), 1);
}

#[test]
fn ownership_refuses_what_another_lane_owns_and_reports_the_rest() {
    let w = world();
    new_lane(&w.route, &w.ash, spec("game", &["game/**"])).unwrap();
    new_lane(&w.route, &w.rf, spec("art", &["art/**"])).unwrap();
    let lanes = load(&w.route).unwrap().lanes;
    let paths: Vec<String> = ["game/a.rs", "art/hero.png", "tools/x.sh", "DECISIONS.md"]
        .iter()
        .map(|s| (*s).to_owned())
        .collect();
    let report = classify(&lanes, "game", &paths);
    assert_eq!(report.owned, vec!["game/a.rs"]);
    assert_eq!(
        report.refused,
        vec![("art/hero.png".to_string(), "art".to_string())]
    );
    assert_eq!(report.unowned, vec!["tools/x.sh"]);
    assert_eq!(report.shared, vec!["DECISIONS.md"]);
}

#[test]
fn two_lanes_land_in_turn_and_decisions_appended_in_both_survive() {
    let w = world();
    let (_, game) = new_lane(&w.route, &w.ash, spec("game", &["game/**"])).unwrap();
    let (_, art) = new_lane(&w.route, &w.rf, spec("art", &["art/**"])).unwrap();
    commit(
        &game,
        &[
            ("game/a.rs", "a\n"),
            ("DECISIONS.md", "# Decisions\n\nD1 first\nD2 from game\n"),
        ],
        "game work",
    );
    commit(
        &art,
        &[
            ("art/b.txt", "b\n"),
            ("DECISIONS.md", "# Decisions\n\nD1 first\nD3 from art\n"),
        ],
        "art work",
    );

    let opts = LandOptions::default();
    let LandOutcome::Landed { commits, .. } = land(&w.route, &w.ash, "game", &opts).unwrap() else {
        panic!("game should land")
    };
    assert_eq!(commits, 1);
    // The lane now sits on the new main, and the main checkout has the files.
    assert_eq!(
        run(&game, &["rev-parse", "HEAD"]),
        run(&w.repo, &["rev-parse", "main"])
    );
    assert!(w.repo.join("game/a.rs").is_file());

    let LandOutcome::Landed { .. } = land(&w.route, &w.rf, "art", &opts).unwrap() else {
        panic!("art should land after the rebase")
    };
    let decisions = fs::read_to_string(w.repo.join("DECISIONS.md")).unwrap();
    assert!(
        decisions.contains("D2 from game") && decisions.contains("D3 from art"),
        "{decisions}"
    );
    assert_eq!(
        run(&w.repo, &["rev-list", "--count", "main"]),
        "3",
        "history is linear"
    );
    assert_eq!(
        run(&w.repo, &["rev-list", "--merges", "--count", "main"]),
        "0"
    );
    assert!(matches!(
        land(&w.route, &w.rf, "art", &opts).unwrap(),
        LandOutcome::NothingToLand
    ));
}

#[test]
fn a_conflict_aborts_leaves_the_lane_alone_and_tells_its_owner() {
    let w = world();
    let (_, game) = new_lane(&w.route, &w.ash, spec("game", &["game/**"])).unwrap();
    let (_, art) = new_lane(&w.route, &w.rf, spec("art", &["art/**"])).unwrap();
    commit(&game, &[("README.md", "title\nfrom game\n")], "game readme");
    commit(&art, &[("README.md", "title\nfrom art\n")], "art readme");
    let opts = LandOptions::default();
    assert!(matches!(
        land(&w.route, &w.ash, "game", &opts).unwrap(),
        LandOutcome::Landed { .. }
    ));
    let main_before = run(&w.repo, &["rev-parse", "main"]);
    let art_before = run(&art, &["rev-parse", "HEAD"]);
    let LandOutcome::Conflict { files, notified } = land(&w.route, &w.ash, "art", &opts).unwrap()
    else {
        panic!("art must conflict")
    };
    assert_eq!(files, vec!["README.md"]);
    assert!(notified);
    assert_eq!(run(&w.repo, &["rev-parse", "main"]), main_before);
    assert_eq!(
        run(&art, &["rev-parse", "HEAD"]),
        art_before,
        "the lane is untouched"
    );
    assert_eq!(run(&art, &["status", "--porcelain"]), "");
    assert!(!git_dir_of(&art).unwrap().join("rebase-merge").exists());
    assert!(
        !w.repo.join(".lanes/.land-art").exists(),
        "the scratch worktree is gone"
    );
}

#[test]
fn landing_refuses_work_in_a_path_another_lane_owns_unless_overridden() {
    let w = world();
    new_lane(&w.route, &w.ash, spec("game", &["game/**"])).unwrap();
    let (_, art) = new_lane(&w.route, &w.rf, spec("art", &["art/**"])).unwrap();
    commit(&art, &[("game/sneaky.rs", "x\n")], "art touches game");
    let LandOutcome::Refused(why) = land(&w.route, &w.rf, "art", &LandOptions::default()).unwrap()
    else {
        panic!("must refuse")
    };
    assert!(
        why.contains("game/sneaky.rs") && why.contains("lane game"),
        "{why}"
    );
    let opts = LandOptions {
        allow_foreign: Some("shared helper".into()),
        ..LandOptions::default()
    };
    assert!(matches!(
        land(&w.route, &w.rf, "art", &opts).unwrap(),
        LandOutcome::Landed { .. }
    ));
    let log = fs::read_to_string(lanes_dir(&w.route).join("overrides/art.jsonl")).unwrap();
    assert!(
        log.contains("shared helper")
            && log.contains("game/sneaky.rs")
            && log.contains("signature")
    );
}

#[test]
fn only_one_landing_at_a_time_and_a_dead_holders_claim_expires() {
    let w = world();
    let (_, game) = new_lane(&w.route, &w.ash, spec("game", &["game/**"])).unwrap();
    new_lane(&w.route, &w.rf, spec("art", &["art/**"])).unwrap();
    commit(&game, &[("game/a.rs", "a\n")], "game work");
    // Another machine holds the landing claim, and its file has synced here.
    let other = AgentIdentity::from_seed("rf", [2; 32]);
    LandingClaim::signed(
        &w.route,
        &other,
        "art",
        "grouchly",
        Utc::now() - Duration::seconds(30),
    )
    .publish(&w.route)
    .unwrap();
    let busy = LandOptions {
        wait_secs: 0,
        ..LandOptions::default()
    };
    let err = land(&w.route, &w.ash, "game", &busy)
        .unwrap_err()
        .to_string();
    assert!(err.contains("rf on grouchly is landing"), "{err}");
    // It finished (the claim is withdrawn): the landing goes through.
    fs::remove_file(claim_path(&w.route, "rf", "grouchly")).unwrap();
    assert!(matches!(
        land(&w.route, &w.ash, "game", &busy).unwrap(),
        LandOutcome::Landed { .. }
    ));
    assert!(
        !claim_path(&w.route, "ash", &this_machine()).exists(),
        "the claim is released"
    );
}

#[test]
fn simultaneous_landings_serialize_into_one_linear_history() {
    let w = world();
    let (_, game) = new_lane(&w.route, &w.ash, spec("game", &["game/**"])).unwrap();
    let (_, art) = new_lane(&w.route, &w.rf, spec("art", &["art/**"])).unwrap();
    commit(&game, &[("game/a.rs", "a\n")], "game work");
    commit(&art, &[("art/b.txt", "b\n")], "art work");
    let mut handles = Vec::new();
    for (lane, seed, name) in [("game", 1u8, "ash"), ("art", 2u8, "rf")] {
        let route = w.route.clone();
        handles.push(std::thread::spawn(move || {
            let who = AgentIdentity::from_seed(name, [seed; 32]);
            land(
                &route,
                &who,
                lane,
                &LandOptions {
                    wait_secs: 60,
                    ..LandOptions::default()
                },
            )
        }));
    }
    for h in handles {
        assert!(matches!(
            h.join().unwrap().unwrap(),
            LandOutcome::Landed { .. }
        ));
    }
    assert_eq!(run(&w.repo, &["rev-list", "--count", "main"]), "3");
    assert_eq!(
        run(&w.repo, &["rev-list", "--merges", "--count", "main"]),
        "0"
    );
    assert!(w.repo.join("game/a.rs").is_file() && w.repo.join("art/b.txt").is_file());
}

#[test]
fn a_lane_can_land_on_a_remote_without_the_token_touching_disk() {
    let w = world();
    let remote = w._tmp.path().join("remote.git");
    run(
        w._tmp.path(),
        &[
            "init",
            "-q",
            "--bare",
            "-b",
            "main",
            remote.to_str().unwrap(),
        ],
    );
    run(
        &w.repo,
        &["remote", "add", "origin", remote.to_str().unwrap()],
    );
    run(&w.repo, &["push", "-q", "origin", "main"]);
    let (_, game) = new_lane(&w.route, &w.ash, spec("game", &["game/**"])).unwrap();
    commit(&game, &[("game/a.rs", "a\n")], "game work");
    let opts = LandOptions {
        push: true,
        fetch: true,
        token: Some("sekrit-token".into()),
        ..LandOptions::default()
    };
    let LandOutcome::Landed { pushed, .. } = land(&w.route, &w.ash, "game", &opts).unwrap() else {
        panic!("should land")
    };
    assert!(pushed);
    assert_eq!(
        run(&remote, &["rev-parse", "main"]),
        run(&w.repo, &["rev-parse", "main"])
    );
    // A file remote takes no header, and nothing on disk mentions the token.
    let config = fs::read_to_string(w.repo.join(".git/config")).unwrap();
    assert!(!config.contains("sekrit") && !config.contains("extraheader"));
}

#[test]
fn the_credential_reaches_git_only_as_environment_for_the_one_remote() {
    let env = auth_env_at(0, "https://github.com/estejosh/idle-ish.git", Some("tok"));
    assert_eq!(env[0], ("GIT_CONFIG_COUNT".to_string(), "1".to_string()));
    assert_eq!(env[1].1, "http.https://github.com/.extraheader");
    assert_eq!(env[2].1, "AUTHORIZATION: basic eC1hY2Nlc3MtdG9rZW46dG9r");
    // It appends to entries already present rather than clobbering them.
    let env = auth_env_at(2, "https://github.com/x.git", Some("tok"));
    assert_eq!(env[0].1, "3");
    assert_eq!(env[1].0, "GIT_CONFIG_KEY_2");
    assert_eq!(env[2].0, "GIT_CONFIG_VALUE_2");
    assert!(auth_env("git@github.com:estejosh/x.git", Some("tok")).is_empty());
    assert!(auth_env("https://github.com/x.git", None).is_empty());
    assert_eq!(
        auth_env("https://user@host.example/x.git", Some("t"))[1].1,
        "http.https://host.example/.extraheader"
    );
}

#[test]
fn doctor_warns_about_two_agents_in_one_tree_and_about_stale_lanes() {
    let w = world();
    let (_, game) = new_lane(&w.route, &w.ash, spec("game", &["game/**"])).unwrap();
    assert!(doctor(&w.route, 7, 50).is_empty());
    let gitdir = git_dir_of(&game).unwrap();
    register_session(&gitdir, "sess-a", "ash", None).unwrap();
    assert!(
        doctor(&w.route, 7, 50).is_empty(),
        "one live session is normal"
    );
    register_session(&gitdir, "sess-b", "rf", None).unwrap();
    let found = doctor(&w.route, 7, 50);
    assert!(
        found
            .iter()
            .any(|f| f.level == "warn" && f.what.contains("2 agents share")),
        "{found:?}"
    );
    release_session(&gitdir, "sess-b");
    assert_eq!(live_sessions(&gitdir, Utc::now()).len(), 1);
    // Stale: nothing has happened for longer than the threshold.
    let found = doctor(&w.route, 0, 50);
    assert!(
        found.iter().any(|f| f.what.contains("is stale")),
        "{found:?}"
    );
    // And far behind main.
    commit(&w.repo, &[("tools/x.txt", "x\n")], "main moves");
    let found = doctor(&w.route, 7, 1);
    assert!(
        found.iter().any(|f| f.what.contains("behind main")),
        "{found:?}"
    );
}

#[test]
fn retiring_a_lane_frees_its_globs_and_refuses_unlanded_work() {
    let w = world();
    let (_, game) = new_lane(&w.route, &w.ash, spec("game", &["game/**"])).unwrap();
    commit(&game, &[("game/a.rs", "a\n")], "work");
    assert!(retire_lane(&w.route, &w.ash, "game", false).is_err());
    assert!(matches!(
        land(&w.route, &w.ash, "game", &LandOptions::default()).unwrap(),
        LandOutcome::Landed { .. }
    ));
    retire_lane(&w.route, &w.ash, "game", false).unwrap();
    assert!(!game.exists());
    assert!(!branch_exists(&w.repo, "lane/game"));
    assert!(summary(&w.route, false).unwrap().is_empty());
    assert_eq!(summary(&w.route, true).unwrap()[0].status, "retired");
    // The globs are free again.
    new_lane(&w.route, &w.rf, spec("game2", &["game/**"])).unwrap();
}

#[test]
fn retire_never_loses_work() {
    let w = world();
    let (_, game) = new_lane(&w.route, &w.ash, spec("game", &["game/**"])).unwrap();
    // An untracked file alone blocks a retire.
    fs::write(game.join("game/scratch.txt"), "notes\n").unwrap();
    let err = retire_lane(&w.route, &w.ash, "game", false)
        .unwrap_err()
        .to_string();
    assert!(err.contains("uncommitted or untracked"), "{err}");
    assert!(game.join("game/scratch.txt").is_file());
    fs::remove_file(game.join("game/scratch.txt")).unwrap();
    // A live session blocks it.
    let gitdir = git_dir_of(&game).unwrap();
    register_session(&gitdir, "sess-a", "ash", None).unwrap();
    let err = retire_lane(&w.route, &w.ash, "game", false)
        .unwrap_err()
        .to_string();
    assert!(err.contains("live session"), "{err}");
    release_session(&gitdir, "sess-a");
    // Unlanded commits block it, and --force keeps them under refs/ferry/retired.
    commit(&game, &[("game/a.rs", "a\n")], "work");
    let tip = run(&game, &["rev-parse", "HEAD"]);
    assert!(retire_lane(&w.route, &w.ash, "game", false).is_err());
    assert!(branch_exists(&w.repo, "lane/game"));
    retire_lane(&w.route, &w.ash, "game", true).unwrap();
    assert!(!branch_exists(&w.repo, "lane/game"));
    let saved = run(
        &w.repo,
        &[
            "for-each-ref",
            "--format=%(objectname)",
            "refs/ferry/retired/game/",
        ],
    );
    assert_eq!(saved, tip, "the forced retire left a way back");
}

#[test]
fn retire_with_a_missing_worktree_still_counts_unlanded_commits() {
    let w = world();
    let (_, game) = new_lane(&w.route, &w.ash, spec("game", &["game/**"])).unwrap();
    commit(&game, &[("game/a.rs", "a\n")], "work");
    // The folder is deleted behind git's back.
    run(
        &w.repo,
        &["worktree", "remove", "--force", game.to_str().unwrap()],
    );
    assert!(!game.exists());
    let err = retire_lane(&w.route, &w.ash, "game", false)
        .unwrap_err()
        .to_string();
    assert!(err.contains("1 commit"), "{err}");
    assert!(branch_exists(&w.repo, "lane/game"), "the branch is kept");
    retire_lane(&w.route, &w.ash, "game", true).unwrap();
    assert!(
        !run(&w.repo, &["for-each-ref", "refs/ferry/retired/game/"]).is_empty(),
        "saved before deleting"
    );
}

#[test]
fn landing_stops_if_an_untracked_file_is_in_the_way_and_changes_nothing() {
    let w = world();
    let (_, game) = new_lane(&w.route, &w.ash, spec("game", &["game/**"])).unwrap();
    let (_, art) = new_lane(&w.route, &w.rf, spec("art", &["art/**"])).unwrap();
    commit(&game, &[("game/a.rs", "a\n")], "game work");
    commit(&art, &[("art/b.txt", "b\n")], "art work");
    assert!(matches!(
        land(&w.route, &w.ash, "game", &LandOptions::default()).unwrap(),
        LandOutcome::Landed { .. }
    ));
    // art has an untracked file where game's landed file would arrive.
    fs::create_dir_all(art.join("game")).unwrap();
    fs::write(art.join("game/a.rs"), "mine, not committed\n").unwrap();
    let main_before = run(&w.repo, &["rev-parse", "main"]);
    let art_before = run(&art, &["rev-parse", "HEAD"]);
    let LandOutcome::Refused(why) = land(&w.route, &w.rf, "art", &LandOptions::default()).unwrap()
    else {
        panic!("must refuse")
    };
    assert!(why.contains("game/a.rs"), "{why}");
    assert_eq!(run(&w.repo, &["rev-parse", "main"]), main_before);
    assert_eq!(run(&art, &["rev-parse", "HEAD"]), art_before);
    assert_eq!(
        fs::read_to_string(art.join("game/a.rs")).unwrap(),
        "mine, not committed\n"
    );
}

#[test]
fn a_successful_landing_always_keeps_the_old_tip() {
    let w = world();
    let (_, game) = new_lane(&w.route, &w.ash, spec("game", &["game/**"])).unwrap();
    commit(&game, &[("game/a.rs", "a\n")], "work");
    let before = run(&game, &["rev-parse", "HEAD"]);
    let LandOutcome::Landed { old_tip, .. } =
        land(&w.route, &w.ash, "game", &LandOptions::default()).unwrap()
    else {
        panic!("should land")
    };
    assert_eq!(old_tip, before);
    let saved = run(
        &w.repo,
        &[
            "for-each-ref",
            "--format=%(objectname)",
            "refs/ferry/landed/game/",
        ],
    );
    assert_eq!(saved, before);
}

#[test]
fn lane_changed_notices_a_moved_tip_and_uncommitted_edits() {
    let w = world();
    let (_, game) = new_lane(&w.route, &w.ash, spec("game", &["game/**"])).unwrap();
    commit(&game, &[("game/a.rs", "a\n")], "one");
    let tip = run(&game, &["rev-parse", "HEAD"]);
    assert_eq!(lane_changed(&game, "lane/game", &tip, &tip).unwrap(), None);
    fs::write(game.join("game/main.rs"), "changed\n").unwrap();
    assert!(
        lane_changed(&game, "lane/game", &tip, &tip)
            .unwrap()
            .unwrap()
            .contains("uncommitted")
    );
    run(&game, &["checkout", "-q", "--", "game/main.rs"]);
    commit(&game, &[("game/b.rs", "b\n")], "two");
    assert!(
        lane_changed(&game, "lane/game", &tip, &tip)
            .unwrap()
            .unwrap()
            .contains("moved")
    );
}

#[test]
fn landing_catches_non_ascii_paths_and_renames_out_of_another_lane() {
    let w = world();
    new_lane(&w.route, &w.ash, spec("game", &["game/**"])).unwrap();
    let (_, art) = new_lane(&w.route, &w.rf, spec("art", &["art/**"])).unwrap();
    // A rename out of game's folder is a deletion there, and counts.
    run(&art, &["mv", "game/main.rs", "art/moved.rs"]);
    run(&art, &["commit", "-q", "-n", "-m", "move"]);
    let LandOutcome::Refused(why) = land(&w.route, &w.rf, "art", &LandOptions::default()).unwrap()
    else {
        panic!("must refuse")
    };
    assert!(why.contains("game/main.rs"), "{why}");
    // A non-ASCII name is reported as itself, not as a quoted escape.
    run(&art, &["reset", "-q", "--hard", "main"]);
    commit(&art, &[("game/h\u{e9}ro.rs", "x\n")], "accent");
    let LandOutcome::Refused(why) = land(&w.route, &w.rf, "art", &LandOptions::default()).unwrap()
    else {
        panic!("must refuse")
    };
    assert!(why.contains("h\u{e9}ro.rs"), "{why}");
}

#[test]
fn every_hook_chains_to_the_repos_own_hooks_dir() {
    let w = world();
    let custom = w._tmp.path().join("husky");
    fs::create_dir_all(&custom).unwrap();
    fs::write(
        custom.join("post-commit"),
        "#!/bin/sh\necho ran > \"$(git rev-parse --absolute-git-dir)/post-ran\"\n",
    )
    .unwrap();
    run(&w.repo, &["config", "core.hooksPath", &slashes(&custom)]);
    let (_, game) = new_lane(&w.route, &w.ash, spec("game", &["game/**"])).unwrap();
    let hooks = git_dir_of(&game).unwrap().join("ferry-hooks");
    for name in CLIENT_HOOKS {
        assert!(hooks.join(name).is_file(), "missing wrapper for {name}");
    }
    assert!(
        fs::read_to_string(hooks.join("post-commit"))
            .unwrap()
            .contains("husky")
    );
    commit(&game, &[("game/a.rs", "a\n")], "work");
    assert!(
        git_dir_of(&game).unwrap().join("post-ran").is_file(),
        "the repo's own post-commit ran through the wrapper"
    );
}

#[test]
fn append_only_files_union_merge_and_nothing_else_does() {
    let w = world();
    let (_, game) = new_lane(&w.route, &w.ash, spec("game", &["game/**"])).unwrap();
    assert!(
        !w.repo.join(".git/info/attributes").exists(),
        "shared attributes untouched"
    );
    let attributes =
        fs::read_to_string(git_dir_of(&game).unwrap().join("ferry-attributes")).unwrap();
    assert_eq!(attributes.trim(), "DECISIONS.md merge=union");
    assert!(!attributes.contains("README"));
}

#[test]
fn session_ids_are_stable_and_dead_processes_are_not_live() {
    let w = world();
    let (_, game) = new_lane(&w.route, &w.ash, spec("game", &["game/**"])).unwrap();
    assert_eq!(
        stable_session_id("ash", &game),
        stable_session_id("ash", &game)
    );
    assert_ne!(
        stable_session_id("ash", &game),
        stable_session_id("rf", &game)
    );
    let gitdir = git_dir_of(&game).unwrap();
    let id = stable_session_id("ash", &game);
    register_session(&gitdir, &id, "ash", None).unwrap();
    register_session(&gitdir, &id, "ash", None).unwrap();
    assert_eq!(live_sessions(&gitdir, Utc::now()).len(), 1);
    // A recorded pid that is not running drops the session.
    register_session(&gitdir, "gone", "rf", Some(u32::MAX - 1)).unwrap();
    assert_eq!(live_sessions(&gitdir, Utc::now()).len(), 1);
    register_session(&gitdir, "me", "rf", Some(std::process::id())).unwrap();
    assert_eq!(live_sessions(&gitdir, Utc::now()).len(), 2);
}

#[test]
fn the_same_agent_on_two_machines_has_two_landing_claims() {
    let w = world();
    let a = LandingClaim::signed(&w.route, &w.ash, "game", "grouchly", Utc::now());
    a.publish(&w.route).unwrap();
    let b = LandingClaim::signed(&w.route, &w.ash, "game", "beastly", Utc::now());
    b.publish(&w.route).unwrap();
    assert_ne!(
        claim_path(&w.route, "ash", "grouchly"),
        claim_path(&w.route, "ash", "beastly")
    );
    // From beastly's point of view only grouchly's claim is someone else's.
    let others = other_claims(&w.route, "ash", "beastly");
    assert_eq!(others.len(), 1);
    assert_eq!(others[0].machine, "grouchly");
    // A conflict copy is not a claim.
    let dir = lanes_dir(&w.route).join("landing");
    fs::copy(
        claim_path(&w.route, "ash", "grouchly"),
        dir.join("ash.grouchly.sync-conflict-20260101-000000-XYZ.json"),
    )
    .unwrap();
    assert_eq!(other_claims(&w.route, "ash", "beastly").len(), 1);
}

#[test]
fn the_commit_check_uses_a_cached_manifest_when_the_channel_is_gone() {
    let w = world();
    let (_, game) = new_lane(&w.route, &w.ash, spec("game", &["game/**"])).unwrap();
    new_lane(&w.route, &w.rf, spec("art", &["art/**"])).unwrap();
    // Point the marker at an attachment that is gone: the channel cannot be read. No cache
    // means allowed with a note; a cache means the owned path is still refused.
    let gitdir = git_dir_of(&game).unwrap();
    let mut marker = read_marker(&gitdir).unwrap();
    marker.attachment = w._tmp.path().join("nowhere");
    fs::write(marker_path(&gitdir), serde_json::to_vec(&marker).unwrap()).unwrap();
    fs::create_dir_all(game.join("art")).unwrap();
    fs::write(game.join("art/x.txt"), "x\n").unwrap();
    run(&game, &["add", "art/x.txt"]);
    let none = |_: &ProjectRoute, _: &str| None;
    let open = check_staged(&game, None, none).unwrap().unwrap();
    assert!(
        open.offline
            .as_deref()
            .unwrap()
            .contains("no manifest is cached")
    );
    assert!(open.report.refused.is_empty(), "nothing known, so allowed");
    assert!(gitdir.join("ferry-lanes-warnings.jsonl").is_file());
    // With a cache from an earlier online check, art/ is still protected.
    let lanes = load(&w.route).unwrap().lanes;
    fs::write(
        gitdir.join("ferry-lanes-cache.json"),
        serde_json::to_vec(&lanes).unwrap(),
    )
    .unwrap();
    let closed = check_staged(&game, None, none).unwrap().unwrap();
    assert!(closed.offline.as_deref().unwrap().contains("cached"));
    assert_eq!(
        closed.report.refused,
        vec![("art/x.txt".to_string(), "art".to_string())]
    );
}

#[test]
fn old_git_is_refused_up_front() {
    assert!(require_git((1, 0), "x").is_ok());
    assert!(
        require_git((99, 0), "lanes")
            .unwrap_err()
            .to_string()
            .contains("needs git 99.0")
    );
}
