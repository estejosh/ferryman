//! End-to-end lifecycle tests, fully offline via the simulation beacon.

mod common;

use std::time::Duration;

use ferry_deadman::commands::{self, ArmArgs, TestTriggerArgs};
use ferry_deadman::error::Error;
use ferry_deadman::state::{self, Mode};

use common::repo_fixture;

const SUCCESSOR_HEX: &str = "aabbccddeeff00112233445566778899";

fn arm_sim(repo: &std::path::Path, window: &str) -> state::State {
    commands::arm(&ArmArgs {
        repo: repo.to_path_buf(),
        successor_pub: SUCCESSOR_HEX.into(),
        window: window.into(),
        include_secrets: false,
        beacon: None,
        simulate: true,
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
    assert!(!st.bundle_sha256.is_empty());
    assert!(state::artifact_path(repo).is_file(), "artifact must exist");

    // Immediately after arming the round has not passed: must refuse.
    let err = trigger(repo, Some(Duration::ZERO)).expect_err("must be locked");
    assert!(
        matches!(err, Error::Locked { .. }),
        "expected Locked, got {err:?}"
    );

    // After the window passes (sim rounds = seconds) the drill must succeed.
    std::thread::sleep(Duration::from_millis(2_600));
    trigger(repo, None).expect("test-trigger should succeed after unlock");
}

#[test]
fn heartbeat_moves_unlock_round_forward() {
    let fx = repo_fixture("heartbeat");
    let repo = fx.repo();
    let st1 = arm_sim(repo, "60s");
    let art = state::artifact_path(repo);
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

    // Old artifact is pruned: only the canonical file remains.
    let leftovers: Vec<_> = std::fs::read_dir(state::state_dir(repo))
        .unwrap()
        .map(|e| e.unwrap().file_name())
        .collect();
    assert_eq!(leftovers.len(), 2, "state.json + sealed-archive.tlock only");
}

#[test]
fn disarm_removes_config_and_artifacts() {
    let fx = repo_fixture("disarm");
    let repo = fx.repo();
    arm_sim(repo, "30s");
    assert!(state::state_dir(repo).exists());

    commands::disarm(repo).expect("disarm");
    assert!(!state::state_dir(repo).exists(), ".deadman must be gone");

    let err = state::load(repo).expect_err("must be unarmed");
    assert!(matches!(err, Error::NotArmed(_)));
    assert!(commands::disarm(repo).is_err(), "second disarm is an error");
}

#[test]
fn malformed_inputs_are_rejected_cleanly() {
    let fx = repo_fixture("malformed");
    let repo = fx.repo();

    // bad window
    let err = commands::arm(&ArmArgs {
        repo: repo.into(),
        successor_pub: SUCCESSOR_HEX.into(),
        window: "banana".into(),
        include_secrets: false,
        beacon: None,
        simulate: true,
    })
    .err()
    .unwrap();
    assert!(matches!(err, Error::BadInput(_)));

    // bad successor key (neither file nor hex)
    let err = commands::arm(&ArmArgs {
        repo: repo.into(),
        successor_pub: "definitely not a key".into(),
        window: "5s".into(),
        include_secrets: false,
        beacon: None,
        simulate: true,
    })
    .err()
    .unwrap();
    assert!(matches!(err, Error::BadInput(_)));

    // empty successor
    let err = commands::arm(&ArmArgs {
        repo: repo.into(),
        successor_pub: "  ".into(),
        window: "5s".into(),
        include_secrets: false,
        beacon: None,
        simulate: true,
    })
    .err()
    .unwrap();
    assert!(matches!(err, Error::BadInput(_)));

    // non-git directory
    let not_git = tempfile::tempdir().unwrap();
    let err = commands::arm(&ArmArgs {
        repo: not_git.path().into(),
        successor_pub: SUCCESSOR_HEX.into(),
        window: "5s".into(),
        include_secrets: false,
        beacon: None,
        simulate: true,
    })
    .err()
    .unwrap();
    assert!(matches!(err, Error::NotAGitRepo(_)));

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

    // armed but asking for exit codes
    arm_sim(repo, "10s");
    let locked = trigger(repo, Some(Duration::ZERO)).err().unwrap();
    assert_eq!(locked.exit_code(), 3);
    assert_eq!(Error::BadInput("x".into()).exit_code(), 2);
}

#[test]
fn tampered_artifact_is_detected() {
    let fx = repo_fixture("tamper");
    let repo = fx.repo();
    arm_sim(repo, "1s");
    let art = state::artifact_path(repo);
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
fn status_and_state_consistency_after_arm() {
    let fx = repo_fixture("statuscheck");
    let repo = fx.repo();
    std::fs::write(repo.join(".env"), "SECRET=1").unwrap();
    let mut args = ArmArgs {
        repo: repo.to_path_buf(),
        successor_pub: String::new(),
        window: "45m".into(),
        include_secrets: true,
        beacon: None,
        simulate: true,
    };
    // file-based successor key
    let keyfile = fx.root.path().join("succ.key");
    std::fs::write(&keyfile, b"-----BEGIN PUBLIC KEY-----\nZm9v\n").unwrap();
    args.successor_pub = keyfile.display().to_string();
    commands::arm(&args).expect("arm with file successor + secrets");

    let st = state::load(repo).unwrap();
    assert!(st.include_secrets);
    assert!(st.successor_fingerprint.starts_with("sha256:"));
    assert_eq!(st.window_display(), "45m");
    // status must run cleanly against armed repo
    commands::status(repo).expect("status after arm");
}
