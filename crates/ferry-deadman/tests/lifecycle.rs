//! End-to-end lifecycle drills, fully offline via the simulation beacon.

mod common;

use std::time::Duration;

use ferry_deadman::commands::{self, ArmArgs, TestTriggerArgs};
use ferry_deadman::error::Error;
use ferry_deadman::state::{self, Mode};

use common::repo_fixture;

const SUCCESSOR_HEX: &str = "aabbccddeeff00112233445566778899";

/// Arm in simulate mode straight off CLI flags (no config file).
fn arm_sim(repo: &std::path::Path, window: &str) -> state::State {
    commands::arm(&ArmArgs {
        repo: repo.to_path_buf(),
        config: None,
        successors: vec![(Some("ada".into()), SUCCESSOR_HEX.into())],
        window: Some(window.into()),
        include_secrets: None,
        includes: vec![],
        beacon: None,
        simulate: true,
        archive_cmd: None,
    })
    .expect("arm should succeed");
    state::load(repo).unwrap()
}

fn trigger(repo: &std::path::Path, max_wait: Option<Duration>) -> Result<(), Error> {
    commands::test_trigger(&TestTriggerArgs {
        repo: repo.to_path_buf(),
        max_wait,
        keep: false,
    })
}

#[test]
fn full_lifecycle_recovers_identical_bundle_hash() {
    let fx = repo_fixture("lifecycle");
    let repo = fx.repo();
    let st = arm_sim(repo, "2s");

    assert_eq!(st.mode, Mode::Sim);
    assert!(st.unlock_round > 0);
    assert!(st.bundle_sha256.as_deref().is_some_and(|h| !h.is_empty()));
    let artifact = state::artifact_path(repo, &state::State::artifact_name_for(&st.successors[0]));
    assert!(artifact.is_file(), "artifact must exist");

    // "Refuses while locked" and "opens after the window" are two claims, and hanging
    // both on one two-second window makes the first depend on how fast the machine got
    // here. On Windows, with the repository on a network drive, arming took longer than
    // the window and this assertion failed - a true statement about the clock, not
    // about the code. One fixture per claim.
    let locked_fx = repo_fixture("lifecycle-locked");
    let locked_repo = locked_fx.repo();
    arm_sim(locked_repo, "30s");
    let err = trigger(locked_repo, Some(Duration::ZERO)).expect_err("must be locked");
    assert!(
        matches!(err, Error::Locked { .. }),
        "expected Locked, got {err:?}"
    );

    // After the window passes (sim rounds = seconds) the drill must succeed
    // and recover exactly the sealed bundle.
    std::thread::sleep(Duration::from_millis(2_600));
    trigger(repo, None).expect("test-trigger should succeed after unlock");
}

#[test]
fn heartbeat_moves_unlock_round_forward_and_prunes() {
    let fx = repo_fixture("heartbeat");
    let repo = fx.repo();
    let st1 = arm_sim(repo, "60s");
    let art = state::artifact_path(repo, &state::State::artifact_name_for(&st1.successors[0]));
    let before_bytes = std::fs::read(&art).unwrap();

    // Heartbeat re-arms at a NEW future round.
    std::thread::sleep(Duration::from_millis(1_100));
    commands::heartbeat(repo).expect("heartbeat");

    let st2 = state::load(repo).unwrap();
    assert!(
        st2.unlock_round > st1.unlock_round,
        "round must move forward"
    );
    assert!(st2.last_heartbeat_unix >= st2.armed_unix);
    assert_ne!(
        before_bytes,
        std::fs::read(&art).unwrap(),
        "artifact must be replaced"
    );

    // Old artifact pruned: only the canonical pair remains in .deadman/.
    let leftovers: Vec<_> = std::fs::read_dir(state::state_dir(repo))
        .unwrap()
        .map(|e| e.unwrap().file_name())
        .collect();
    assert_eq!(leftovers.len(), 2, "state.json + sealed-archive.tlock only");

    // Still time-locked after re-arm.
    let err = trigger(repo, Some(Duration::ZERO)).expect_err("must be locked again");
    assert!(matches!(err, Error::Locked { .. }));
}

#[test]
fn multiple_successors_each_get_their_own_sealed_copy() {
    let fx = repo_fixture("multi-succ");
    let repo = fx.repo();
    commands::arm(&ArmArgs {
        repo: repo.into(),
        config: None,
        successors: vec![
            (Some("ada".into()), "aabbccddeeff00112233".into()),
            (Some("grace".into()), "11223344556677889900".into()),
            (None, "fedcba98765432100123".into()), // unnamed -> legacy name
        ],
        window: Some("2s".into()),
        include_secrets: None,
        includes: vec![],
        beacon: None,
        simulate: true,
        archive_cmd: None,
    })
    .expect("arm with three successors");

    let names = [
        format!("sealed-{}.tlock", state::slug("ada")),
        format!("sealed-{}.tlock", state::slug("grace")),
        state::ARTIFACT_NAME.to_string(),
    ];
    let mut blobs = Vec::new();
    for n in &names {
        let p = state::artifact_path(repo, n);
        let b = std::fs::read(&p).unwrap_or_else(|e| panic!("{n}: {e}"));
        assert!(!blobs.contains(&b), "{n} must be an independent copy");
        blobs.push(b);
    }

    // The drill opens EVERY copy.
    std::thread::sleep(Duration::from_millis(2_600));
    commands::test_trigger(&TestTriggerArgs {
        repo: repo.into(),
        max_wait: None,
        keep: false,
    })
    .expect("trigger verifies every successor copy");
}

#[test]
fn re_arm_prunes_copies_of_removed_successors() {
    let fx = repo_fixture("prune");
    let repo = fx.repo();
    arm_sim(repo, "30s"); // one successor "ada"
    let st_first = state::load(repo).unwrap();
    let gone = state::artifact_path(
        repo,
        &state::State::artifact_name_for(&st_first.successors[0]),
    );
    assert!(gone.is_file());

    // Re-arm with a differently named successor: ada's copy must vanish.
    commands::arm(&ArmArgs {
        repo: repo.into(),
        config: None,
        successors: vec![(Some("grace".into()), SUCCESSOR_HEX.into())],
        window: Some("30s".into()),
        include_secrets: None,
        includes: vec![],
        beacon: None,
        simulate: true,
        archive_cmd: None,
    })
    .expect("re-arm as grace");
    assert!(!gone.exists(), "stale copy must be pruned");
    assert!(state::artifact_path(repo, "sealed-grace.tlock").is_file());
    let st = state::load(repo).unwrap();
    assert_eq!(st.successors.len(), 1);
    assert_eq!(st.successors[0].name, "grace");
}

#[test]
fn disarm_removes_state_artifacts_and_config() {
    let fx = repo_fixture("disarm");
    let repo = fx.repo();
    std::fs::write(
        repo.join("deadman.toml"),
        "beacon = \"simulate\"\nwindow = \"30s\"\n[[successors]]\nname=\"ada\"\n",
    )
    .unwrap();
    commands::arm(&ArmArgs {
        repo: repo.into(),
        config: None, // picks up deadman.toml
        successors: vec![],
        window: None,
        include_secrets: None,
        includes: vec![],
        beacon: None,
        simulate: false, // config says simulate
        archive_cmd: None,
    })
    .expect("arm driven purely by config");
    assert!(state::state_dir(repo).exists());
    assert!(repo.join("deadman.toml").is_file());

    commands::disarm(repo).expect("disarm");
    assert!(!state::state_dir(repo).exists(), ".deadman must be gone");
    assert!(!repo.join("deadman.toml").exists(), "config must be gone");

    let err = state::load(repo).expect_err("must be unarmed");
    assert!(matches!(err, Error::NotArmed(_)));
    assert!(commands::disarm(repo).is_err(), "second disarm is an error");
}

#[test]
fn malformed_inputs_are_rejected_cleanly() {
    let fx = repo_fixture("malformed");
    let repo = fx.repo();
    let base = || ArmArgs {
        repo: repo.to_path_buf(),
        config: None,
        successors: vec![(Some("ada".into()), SUCCESSOR_HEX.into())],
        window: Some("5s".into()),
        include_secrets: None,
        includes: vec![],
        beacon: None,
        simulate: true,
        archive_cmd: None,
    };

    // bad window
    let err = commands::arm(&ArmArgs {
        window: Some("banana".into()),
        ..base()
    })
    .err()
    .unwrap();
    assert!(matches!(err, Error::BadInput(_)));

    // bad successor key (neither file nor hex)
    let err = commands::arm(&ArmArgs {
        successors: vec![(None, "definitely not a key".into())],
        ..base()
    })
    .err()
    .unwrap();
    assert!(matches!(err, Error::BadInput(_)));

    // empty successor
    let err = commands::arm(&ArmArgs {
        successors: vec![(None, "   ".into())],
        ..base()
    })
    .err()
    .unwrap();
    assert!(matches!(err, Error::BadInput(_)));

    // no successors at all
    let err = commands::arm(&ArmArgs {
        successors: vec![],
        ..base()
    })
    .err()
    .unwrap();
    assert!(matches!(err, Error::BadInput(_)));

    // CLI [NAME=]KEY syntax is validated by parse_successor
    assert!(commands::parse_successor("ada=aabbccdd").is_ok());
    assert!(commands::parse_successor("aabbccdd").is_ok());
    assert!(commands::parse_successor("=aabbccdd").is_err());
    assert!(commands::parse_successor("ada=").is_err());
    assert!(commands::parse_successor("bad name! = aabbccdd").is_err());

    // A directory that is genuinely outside any repository.
    //
    // `git rev-parse --git-dir` walks UPWARD, so a temp dir is only "not a repo" when
    // no ancestor is one. On a machine whose home directory is itself a git working
    // tree - a real configuration, and the one this was caught on - every temp dir is
    // inside a repository, and asserting otherwise tests the machine rather than the
    // code. So the precondition is established rather than assumed.
    let not_git = tempfile::tempdir().unwrap();
    let inside_some_repo = std::process::Command::new("git")
        .arg("-C")
        .arg(not_git.path())
        .args(["rev-parse", "--git-dir"])
        .output()
        .map(|o| o.status.success())
        .unwrap_or(false);
    if !inside_some_repo {
        let err = commands::arm(&ArmArgs {
            repo: not_git.path().into(),
            ..base()
        })
        .err()
        .unwrap();
        assert!(matches!(err, Error::NotAGitRepo(_)));
    }

    // nonexistent path
    let err = commands::status(&std::path::PathBuf::from("/nonexistent/fdm/xyz"))
        .err()
        .unwrap();
    assert!(matches!(err, Error::NotAGitRepo(_)));

    // heartbeat / status / trigger on unarmed repo
    assert!(matches!(
        commands::heartbeat(repo).unwrap_err(),
        Error::NotArmed(_)
    ));
    assert!(matches!(
        commands::status(repo).unwrap_err(),
        Error::NotArmed(_)
    ));

    // armed but still locked maps to exit code 3; bad input to 2
    arm_sim(repo, "10s");
    let locked = trigger(repo, Some(Duration::ZERO)).err().unwrap();
    assert_eq!(locked.exit_code(), 3);
    assert_eq!(Error::BadInput("x".into()).exit_code(), 2);
}

#[test]
fn tampered_artifact_is_detected() {
    let fx = repo_fixture("tamper");
    let repo = fx.repo();
    let st = arm_sim(repo, "1s");
    let art = state::artifact_path(repo, &state::State::artifact_name_for(&st.successors[0]));
    let mut bytes = std::fs::read(&art).unwrap();
    let last = bytes.len() - 3;
    bytes[last] ^= 0xff; // flip a payload byte
    std::fs::write(&art, &bytes).unwrap();

    std::thread::sleep(Duration::from_millis(1_400));
    let err =
        trigger(repo, Some(Duration::from_secs(10))).expect_err("tampered artifact must fail");
    match err {
        Error::Corrupt(_) | Error::Other(_) => {}
        other => panic!("expected corruption error, got {other:?}"),
    }
}

#[test]
fn status_and_state_consistency_after_arm_with_extras() {
    let fx = repo_fixture("statuscheck");
    let repo = fx.repo();
    std::fs::write(repo.join(".env"), "SECRET=1").unwrap();
    std::fs::create_dir_all(repo.join("docs")).unwrap();
    std::fs::write(repo.join("docs/runbook.md"), "# run").unwrap();

    let keyfile = fx.root.path().join("succ.key");
    std::fs::write(&keyfile, b"-----BEGIN PUBLIC KEY-----\nZm9v\n").unwrap();

    commands::arm(&ArmArgs {
        repo: repo.into(),
        config: None,
        successors: vec![(None, keyfile.display().to_string())],
        window: Some("45m".into()),
        include_secrets: Some(true),
        includes: vec!["docs/**".into()],
        beacon: None,
        simulate: true,
        archive_cmd: None,
    })
    .expect("arm with file successor key + secrets + globs");

    let st = state::load(repo).unwrap();
    assert!(st.include_secrets);
    assert_eq!(st.include_globs, vec!["docs/**".to_string()]);
    assert!(st.successors[0].fingerprint.starts_with("sha256:"));
    assert_eq!(st.window_display(), "45m");
    commands::status(repo).expect("status after arm");
}
