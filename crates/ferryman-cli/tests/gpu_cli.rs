//! `ferry gpu run | acquire | release | status | bump` through the real binary, against a
//! temp root and a temp machine-state folder. The card is not needed: the lane is state.

use std::fs;
use std::path::PathBuf;
use std::process::{Command, Output};

struct World {
    _dir: tempfile::TempDir,
    root: PathBuf,
    state: PathBuf,
}

fn world() -> World {
    let dir = tempfile::tempdir().unwrap();
    let root = ferryman_channel::ferry::Root::create_with_layout(&dir.path().join("ferry"), 1)
        .unwrap()
        .path;
    let state = dir.path().join("state");
    fs::create_dir_all(&state).unwrap();
    fs::write(
        root.join("ferry.toml"),
        "[gpu]\nwidth = 1\nvram_mb = 24000\n",
    )
    .unwrap();
    World {
        _dir: dir,
        root,
        state,
    }
}

impl World {
    fn ferry(&self, args: &[&str]) -> Output {
        Command::new(env!("CARGO_BIN_EXE_ferry"))
            .args(args)
            .env("FERRYMAN_ROOT", &self.root)
            .env("FERRYMAN_STATE_DIR", &self.state)
            .env("LOCALAPPDATA", &self.state)
            .output()
            .unwrap()
    }
}

fn out(o: &Output) -> String {
    String::from_utf8_lossy(&o.stdout).to_string()
}

fn err(o: &Output) -> String {
    String::from_utf8_lossy(&o.stderr).to_string()
}

#[test]
fn run_holds_the_card_for_the_command_and_gives_it_back() {
    let w = world();
    let ferry = env!("CARGO_BIN_EXE_ferry");
    let run = w.ferry(&[
        "gpu", "run", "--tenant", "render", "--vram", "4000", "--", ferry, "gpu", "status",
    ]);
    assert!(run.status.success(), "{}", err(&run));
    // The command saw itself holding the card, with its memory.
    let seen = out(&run);
    assert!(seen.contains("holds") && seen.contains("render-"), "{seen}");
    assert!(seen.contains("4000 MB"), "{seen}");
    let after = out(&w.ferry(&["gpu", "status"]));
    assert!(after.contains("nobody holds the card"), "{after}");
}

#[test]
fn run_passes_the_commands_exit_code_through() {
    let w = world();
    let ferry = env!("CARGO_BIN_EXE_ferry");
    let run = w.ferry(&[
        "gpu", "run", "--tenant", "x", "--", ferry, "gpu", "bump", "nobody",
    ]);
    assert_eq!(run.status.code(), Some(1), "{}", err(&run));
    assert!(err(&run).contains("not waiting"), "{}", err(&run));
}

#[test]
fn acquire_holds_until_released_and_the_next_asker_waits_its_turn() {
    let w = world();
    let me = std::process::id().to_string();
    let first = w.ferry(&["gpu", "acquire", "--tenant", "script", "--pid", &me]);
    assert!(first.status.success(), "{}", err(&first));
    let id = out(&first).trim().to_string();
    assert!(id.starts_with("script-"), "{id}");

    let status = out(&w.ferry(&["gpu", "status"]));
    assert!(status.contains(&id) && status.contains("holds"), "{status}");

    // The card is taken: a second asker gives up after its wait instead of stealing it.
    let second = w.ferry(&["gpu", "acquire", "--tenant", "other", "--wait", "1"]);
    assert!(!second.status.success());
    assert!(err(&second).contains("timed out"), "{}", err(&second));
    assert!(!out(&w.ferry(&["gpu", "status"])).contains("other-"));

    assert!(w.ferry(&["gpu", "release", &id]).status.success());
    let third = w.ferry(&["gpu", "acquire", "--tenant", "other", "--pid", &me]);
    assert!(third.status.success(), "{}", err(&third));
}

#[test]
fn a_request_bigger_than_the_budget_is_refused_up_front() {
    let w = world();
    let big = w.ferry(&["gpu", "acquire", "--tenant", "huge", "--vram", "99999"]);
    assert!(!big.status.success());
    assert!(err(&big).contains("budget"), "{}", err(&big));
}

#[test]
fn status_json_lists_rows_tenants_and_unmanaged_holders() {
    let w = world();
    let me = std::process::id().to_string();
    let id = out(&w.ferry(&["gpu", "acquire", "--tenant", "j", "--pid", &me]));
    let json: serde_json::Value =
        serde_json::from_str(&out(&w.ferry(&["gpu", "status", "--json"]))).unwrap();
    assert_eq!(json["rows"][0]["id"].as_str(), Some(id.trim()));
    assert_eq!(json["rows"][0]["holder"], true);
    assert!(json["tenants"].is_array() && json["unmanaged"].is_array());
}
