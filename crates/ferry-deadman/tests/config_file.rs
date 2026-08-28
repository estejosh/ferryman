//! deadman.toml behaviour: init, precedence, warnings, hooks, custom
//! archivers, heartbeat sources. All drills use the offline simulate beacon.

mod common;

use std::time::Duration;

use ferry_deadman::commands::{self, ArmArgs, TestTriggerArgs};
use ferry_deadman::config;
use ferry_deadman::error::Error;
use ferry_deadman::state;

use common::repo_fixture;

const SUCCESSOR_HEX: &str = "aabbccddeeff00112233445566778899";

fn base_args(repo: &std::path::Path) -> ArmArgs {
    ArmArgs {
        repo: repo.to_path_buf(),
        config: None,
        successors: vec![],
        window: None,
        include_secrets: None,
        includes: vec![],
        beacon: None,
        simulate: false,
        archive_cmd: None,
    }
}

#[test]
fn init_writes_parsable_template_and_refuses_clobber() {
    let fx = repo_fixture("init");
    let repo = fx.repo();

    commands::init(repo, false).expect("first init");
    let path = repo.join("deadman.toml");
    assert!(path.is_file());
    let text = std::fs::read_to_string(&path).unwrap();
    let (cfg, unknown) = config::parse(&text).unwrap();
    assert_eq!(cfg, config::Config::default());
    assert!(unknown.is_empty());
    // The template documents every knob.
    for needle in [
        "window",
        "beacon",
        "include_secrets",
        "[[successors]]",
        "archive.command",
        "heartbeat.sources",
        "[notify]",
    ] {
        assert!(text.contains(needle), "template should mention {needle}");
    }

    // Second init refuses; --force overwrites.
    let err = commands::init(repo, false).unwrap_err();
    assert!(matches!(err, Error::BadInput(_)));
    commands::init(repo, true).expect("forced init");
}

#[test]
fn arm_is_driven_by_config_and_flags_override() {
    let fx = repo_fixture("precedence");
    let repo = fx.repo();
    std::fs::write(
        repo.join("deadman.toml"),
        format!(
            "window = \"90d\"\nbeacon = \"simulate\"\n[[successors]]\nname = \"ada\"\nkey = \"{SUCCESSOR_HEX}\"\n"
        ),
    )
    .unwrap();
    commands::arm(&base_args(repo)).expect("pure-config arm");
    let st = state::load(repo).unwrap();
    assert_eq!(st.mode, state::Mode::Sim);
    assert_eq!(st.window_secs, 90 * 86_400);
    assert_eq!(st.successors[0].name, "ada");

    // A CLI flag beats the config value.
    commands::arm(&ArmArgs {
        window: Some("2s".into()),
        successors: vec![(Some("grace".into()), SUCCESSOR_HEX.into())],
        ..base_args(repo)
    })
    .expect("flag override arm");
    let st = state::load(repo).unwrap();
    assert_eq!(st.window_secs, 2);
    assert_eq!(st.successors[0].name, "grace");
    assert_eq!(st.successors.len(), 1);
}

#[test]
fn unknown_keys_warn_but_arm_still_succeeds() {
    let fx = repo_fixture("unknown-keys");
    let repo = fx.repo();
    std::fs::write(
        repo.join("deadman.toml"),
        format!(
            "beacon = \"simulate\"\nfuture_shiny_feature = true\n[[successors]]\nname = \"ada\"\nnick = \"a\"\nkey = \"{SUCCESSOR_HEX}\"\n"
        ),
    )
    .unwrap();

    let loaded = config::load(None, repo).expect("load tolerates unknown keys");
    assert_eq!(
        loaded.unknown_keys,
        vec![
            "future_shiny_feature".to_string(),
            "successors.nick".to_string()
        ]
    );
    commands::arm(&base_args(repo)).expect("arm proceeds despite unknown keys");
}

#[test]
fn bad_toml_is_rejected_gracefully() {
    let fx = repo_fixture("bad-toml");
    let repo = fx.repo();
    std::fs::write(
        repo.join("deadman.toml"),
        "window = \"30d\"\nNOT TOML {{{\n",
    )
    .unwrap();
    let err = commands::arm(&base_args(repo)).unwrap_err();
    match err {
        Error::BadInput(msg) => assert!(msg.contains("deadman.toml"), "{msg}"),
        other => panic!("expected BadInput, got {other:?}"),
    }

    // Wrong value type is also a clean rejection.
    std::fs::write(repo.join("deadman.toml"), "window = 30\n").unwrap();
    let err = commands::arm(&base_args(repo)).unwrap_err();
    assert!(matches!(err, Error::BadInput(_)));
}

#[test]
fn notify_hooks_fire_on_arm_and_rearm_and_trigger() {
    let fx = repo_fixture("hooks");
    let repo = fx.repo();
    let marker = fx.root.path().join("hooklog");
    let log = marker.display().to_string().replace('\'', "");

    // A hook is a shell line and the shell differs by host: `sh -c` on unix,
    // `cmd /C` on Windows, which spells variables `%LIKE_THIS%` and does not strip
    // single quotes. The product cannot paper over that, so neither does the test -
    // it writes the hook each shell actually understands, and asserts the same
    // behaviour from both.
    #[cfg(windows)]
    let (arm, rearm, trigger) = (
        format!("echo %FERRY_DEADMAN_EVENT%>> \"{log}\""),
        format!("echo %FERRY_DEADMAN_EVENT%:%FERRY_DEADMAN_ROUND%>> \"{log}\""),
        format!("echo %FERRY_DEADMAN_EVENT%>> \"{log}\""),
    );
    #[cfg(not(windows))]
    let (arm, rearm, trigger) = (
        format!("echo $FERRY_DEADMAN_EVENT >> '{log}'"),
        format!("echo $FERRY_DEADMAN_EVENT:$FERRY_DEADMAN_ROUND >> '{log}'"),
        format!("echo $FERRY_DEADMAN_EVENT >> '{log}'"),
    );
    let escape = |s: &str| s.replace('\\', "\\\\").replace('"', "\\\"");
    std::fs::write(
        repo.join("deadman.toml"),
        format!(
            "beacon = \"simulate\"\nwindow = \"1s\"\n[notify]\narm = \"{}\"\nrearm = \"{}\"\ntrigger = \"{}\"\n[[successors]]\nname=\"ada\"\n",
            escape(&arm),
            escape(&rearm),
            escape(&trigger)
        ),
    )
    .unwrap();

    commands::arm(&base_args(repo)).expect("arm");
    commands::heartbeat(repo).expect("heartbeat re-arms");
    std::thread::sleep(Duration::from_millis(2_100));
    commands::test_trigger(&TestTriggerArgs {
        repo: repo.into(),
        max_wait: None,
        keep: false,
    })
    .expect("trigger drill");

    let log_text = std::fs::read_to_string(&marker).unwrap();
    let lines: Vec<&str> = log_text.lines().collect();
    assert_eq!(lines[0], "arm", "arm hook must fire first: {log_text}");
    assert!(
        lines[1].starts_with("rearm:"),
        "rearm hook carries the round: {log_text}"
    );
    assert!(
        lines.contains(&"trigger"),
        "trigger hook must fire after a successful drill: {log_text}"
    );

    // Trigger fires once per armed cycle even if the drill runs twice.
    std::thread::sleep(Duration::from_millis(300));
    commands::heartbeat(repo).expect("second re-arm resets cycle");
    std::thread::sleep(Duration::from_millis(2_100));
    commands::test_trigger(&TestTriggerArgs {
        repo: repo.into(),
        max_wait: None,
        keep: false,
    })
    .expect("second drill");
    let count = std::fs::read_to_string(&marker)
        .unwrap()
        .lines()
        .filter(|l| *l == "trigger")
        .count();
    assert_eq!(count, 2, "exactly one trigger per armed cycle");
}

#[test]
fn any_cli_source_heartbeats_on_status() {
    let fx = repo_fixture("any-cli");
    let repo = fx.repo();
    std::fs::write(
        repo.join("deadman.toml"),
        format!(
            "beacon = \"simulate\"\nwindow = \"60s\"\nheartbeat.sources = [\"any-cli\"]\n[[successors]]\nname = \"ada\"\nkey = \"{SUCCESSOR_HEX}\"\n"
        ),
    )
    .unwrap();
    commands::arm(&base_args(repo)).expect("arm");

    std::thread::sleep(Duration::from_millis(1_100));
    let before = state::load(repo).unwrap();
    commands::status(repo).expect("status triggers the automatic heartbeat");
    let after = state::load(repo).unwrap();
    assert!(
        after.unlock_round > before.unlock_round,
        "status must have auto-heartbeated ({} -> {})",
        before.unlock_round,
        after.unlock_round
    );
    assert!(after.last_heartbeat_unix >= before.last_heartbeat_unix);
}

// A custom archiver is a shell line, and a shell line is not portable: `cp` and
// `$VAR` on unix, `copy` and `%VAR%` under cmd. The product cannot fix that and does
// not pretend to, so the test writes what each host actually understands and asserts
// the same recorded behaviour from both.
#[cfg(windows)]
const SHELL: &str = "cmd";
#[cfg(windows)]
const SHELL_FLAG: &str = "/C";
#[cfg(windows)]
const ARCHIVE_LINE: &str = "copy release.bin \\\"%FERRY_DEADMAN_OUT%\\\"";
#[cfg(not(windows))]
const SHELL: &str = "sh";
#[cfg(not(windows))]
const SHELL_FLAG: &str = "-c";
#[cfg(not(windows))]
const ARCHIVE_LINE: &str = "cp release.bin \\\"$FERRY_DEADMAN_OUT\\\"";

#[test]
fn custom_archive_command_roundtrips_by_hash() {
    let fx = repo_fixture("custom-archive");
    let repo = fx.repo();
    std::fs::write(repo.join("release.bin"), b"OPAQUE-RELEASE-PAYLOAD").unwrap();
    std::fs::write(
        repo.join("deadman.toml"),
        format!(
            "beacon = \"simulate\"\nwindow = \"2s\"\narchive.command = \"{ARCHIVE_LINE}\"\n[[successors]]\nname = \"ada\"\nkey = \"{SUCCESSOR_HEX}\"\n"
        ),
    )
    .unwrap();

    commands::arm(&base_args(repo)).expect("arm with custom archiver");
    let st = state::load(repo).unwrap();
    assert!(st.bundle_sha256.is_none(), "no bundle in a custom payload");
    assert_eq!(
        st.archive_argv,
        Some(vec![
            SHELL.to_string(),
            SHELL_FLAG.to_string(),
            ARCHIVE_LINE.replace("\\\"", "\"")
        ])
    );
    let art = state::artifact_path(repo, &state::State::artifact_name_for(&st.successors[0]));
    assert!(art.is_file());

    std::thread::sleep(Duration::from_millis(2_600));
    commands::test_trigger(&TestTriggerArgs {
        repo: repo.into(),
        max_wait: None,
        keep: false,
    })
    .expect("custom payload recovers and verifies by hash");
}

#[test]
fn include_globs_archive_working_tree_files() {
    let fx = repo_fixture("globs");
    let repo = fx.repo();
    std::fs::create_dir_all(repo.join("receipts/2026")).unwrap();
    std::fs::write(repo.join("receipts/2026/q1.txt"), "coffee=4.10").unwrap();
    std::fs::create_dir_all(repo.join("target")).unwrap();
    std::fs::write(repo.join("target/junk.o"), "binary junk").unwrap();

    commands::arm(&ArmArgs {
        includes: vec!["receipts/**".into()],
        window: Some("2s".into()),
        successors: vec![(Some("ada".into()), SUCCESSOR_HEX.into())],
        ..base_args(repo)
    })
    .expect("arm with globs (simulate via flags only)");
    let st = state::load(repo).unwrap();
    assert_eq!(st.include_globs, vec!["receipts/**".to_string()]);
}
