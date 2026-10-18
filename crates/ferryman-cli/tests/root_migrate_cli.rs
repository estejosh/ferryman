//! `ferry root migrate` through the real binary: the dry run changes nothing on disk.
//!
//! The library test of the same name calls `migrate::run` directly, which cannot see what
//! the command does around it (resolving a worker's route files the project in the root and
//! writes the usage index unless `known::read_only()` was called first). This runs the
//! entry point.

use ferryman_channel::ferry::Root;
use std::collections::BTreeMap;
use std::fs;
use std::path::{Path, PathBuf};
use std::process::Command;
use std::time::SystemTime;

type Snapshot = BTreeMap<PathBuf, Option<(Vec<u8>, SystemTime)>>;

fn write(path: &Path, text: &str) {
    fs::create_dir_all(path.parent().unwrap()).unwrap();
    fs::write(path, text).unwrap();
}

/// Files by content and modified time, directories by name only (a directory's own
/// modified time is updated lazily by some filesystems and says nothing about content).
fn snapshot(path: &Path) -> Snapshot {
    fn walk(path: &Path, out: &mut Snapshot) {
        let Ok(entries) = fs::read_dir(path) else {
            return;
        };
        for entry in entries.flatten() {
            let p = entry.path();
            let meta = entry.metadata().unwrap();
            if meta.is_dir() {
                out.insert(p.clone(), None);
                walk(&p, out);
            } else {
                out.insert(
                    p.clone(),
                    Some((fs::read(&p).unwrap(), meta.modified().unwrap())),
                );
            }
        }
    }
    let mut out = BTreeMap::new();
    walk(path, &mut out);
    out
}

#[test]
fn the_dry_run_changes_nothing_through_the_command() {
    let dir = tempfile::tempdir().unwrap();
    let base = dir.path();
    let root = Root::create_with_layout(&base.join("ferry"), 1).unwrap();
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
    let outside = base.join("elsewhere");
    fs::create_dir_all(&outside).unwrap();
    let state = base.join("state");
    fs::create_dir_all(&state).unwrap();

    let before = snapshot(base);
    let output = Command::new(env!("CARGO_BIN_EXE_ferry"))
        .args(["root", "migrate"])
        .current_dir(&outside)
        .env("FERRYMAN_ROOT", &root.path)
        .env("FERRYMAN_STATE_DIR", &state)
        .env("LOCALAPPDATA", &state)
        .env("HOME", base)
        .env("USERPROFILE", base)
        .output()
        .unwrap();
    let text = String::from_utf8_lossy(&output.stdout);
    assert!(
        output.status.success(),
        "{text}\n{}",
        String::from_utf8_lossy(&output.stderr)
    );
    assert!(text.contains("dry run, nothing was changed"), "{text}");
    assert!(text.contains("alpha"), "{text}");
    assert_eq!(
        snapshot(base),
        before,
        "the dry run changed the disk:\n{text}"
    );
}

#[test]
fn access_show_changes_nothing_through_the_command() {
    use ferryman_channel::{AgentIdentity, AgentRoute, ProjectRoute, access};

    let dir = tempfile::tempdir().unwrap();
    let base = dir.path().join("world");
    let mine = dir.path().join("my-state");
    ferryman_channel::licensing::use_machine_state_dir_per_thread(mine);
    let root = Root::create_with_layout(&base.join("ferry"), 1).unwrap();
    let channel = root.comms().join("alpha-ferryman");
    fs::create_dir_all(&channel).unwrap();
    let route = ProjectRoute {
        project_id: "alpha".into(),
        workspace: channel.clone(),
        attachment: channel.clone(),
        communications: channel.clone(),
        shared_remote: "alpha-ferryman".into(),
        git_remote: String::new(),
        git_visibility: String::new(),
        agents: Vec::new(),
    };
    let master = AgentIdentity::from_seed("josh", [7u8; 32]);
    let worker = AgentIdentity::from_seed("wisp", [8u8; 32]);
    for who in [&master, &worker] {
        ferryman_channel::register_agent(
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
        agents: ferryman_channel::read_agent_roster(&channel).unwrap(),
        ..route
    };
    ferryman_channel::master::initialize_master(&route, &master, "josh").unwrap();
    access::set_level(&route, &master, "wisp", access::Level::Worker).unwrap();
    assert!(root.adopt("alpha", &channel, None).unwrap());

    // The CLI's own machine state is empty: showing must leave it that way.
    let state = base.join("state");
    fs::create_dir_all(&state).unwrap();
    let outside = base.join("elsewhere");
    fs::create_dir_all(&outside).unwrap();
    let before = snapshot(&base);
    let output = Command::new(env!("CARGO_BIN_EXE_ferry"))
        .args(["access", "show", "--project", "alpha"])
        .current_dir(&outside)
        .env("FERRYMAN_ROOT", &root.path)
        .env("FERRYMAN_STATE_DIR", &state)
        .env("LOCALAPPDATA", &state)
        .env("HOME", &base)
        .env("USERPROFILE", &base)
        .output()
        .unwrap();
    let text = String::from_utf8_lossy(&output.stdout);
    assert!(
        output.status.success(),
        "{text}\n{}",
        String::from_utf8_lossy(&output.stderr)
    );
    assert!(text.contains("wisp") && text.contains("worker"), "{text}");
    assert_eq!(snapshot(&base), before, "showing changed the disk:\n{text}");
}
