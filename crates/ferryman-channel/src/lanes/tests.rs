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
    assert_eq!(dir, w.repo.join(".lanes").join("game"));
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
    fs::remove_file(claim_path(&w.route, "rf")).unwrap();
    assert!(matches!(
        land(&w.route, &w.ash, "game", &busy).unwrap(),
        LandOutcome::Landed { .. }
    ));
    assert!(
        !claim_path(&w.route, "ash").exists(),
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
    let env = auth_env("https://github.com/estejosh/idle-ish.git", Some("tok"));
    assert_eq!(env[1].1, "http.https://github.com/.extraheader");
    assert_eq!(env[2].1, "AUTHORIZATION: basic eC1hY2Nlc3MtdG9rZW46dG9r");
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
