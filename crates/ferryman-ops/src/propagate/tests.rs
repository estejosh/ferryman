use super::*;
use crate::agent::AgentConfig;
use crate::fleet;
use ferryman_channel::fleethome::{DIRECTORY, MACHINES};
use ferryman_channel::{ProjectRoute, read_agent_roster};
use std::path::{Path, PathBuf};
use std::process::Command;

fn hermetic() {
    ferryman_channel::ferry::isolate_root_search_for_this_thread();
    ferryman_channel::licensing::use_machine_state_dir_per_thread(std::env::temp_dir().join(
        format!("ferryman-propagate-selftest-{}", std::process::id()),
    ));
}

fn josh() -> AgentIdentity {
    AgentIdentity::from_seed("josh", [7u8; 32])
}

/// One machine of the test fleet: its own root, the identity it signs fleet files as, and the
/// all-projects worker it runs.
struct Side {
    name: &'static str,
    root: Root,
    machine: AgentIdentity,
    worker: AgentIdentity,
}

struct Fleet {
    dir: tempfile::TempDir,
    b: Side,
    g: Side,
}

fn side(dir: &Path, name: &'static str, seed: u8) -> Side {
    let root = Root::create(&dir.join(name).join("ferry")).unwrap();
    Side {
        name,
        root,
        machine: AgentIdentity::from_seed(&format!("{name}-ferry"), [seed; 32]),
        worker: AgentIdentity::from_seed(&format!("{name}-worker"), [seed + 1; 32]),
    }
}

/// Copy a fleet folder the way Syncthing or the lane would: everything but this machine's own
/// part, newer or missing files only.
fn sync_fleet(from: &Side, to: &Side) {
    fn walk(src: &Path, dst: &Path) {
        for entry in fs::read_dir(src).into_iter().flatten().flatten() {
            let path = entry.path();
            let name = entry.file_name();
            if name == "local" || name == ".stignore" {
                continue;
            }
            let target = dst.join(&name);
            if path.is_dir() {
                fs::create_dir_all(&target).unwrap();
                walk(&path, &target);
            } else {
                fs::create_dir_all(dst).unwrap();
                fs::copy(&path, &target).unwrap();
            }
        }
    }
    fs::create_dir_all(to.root.fleet_dir()).unwrap();
    walk(&from.root.fleet_dir(), &to.root.fleet_dir());
}

/// Two machines in one fleet, josh master, both admitted, the fleet folder on both. beastly
/// is the one projects are made on; grouchly is the one they arrive at.
fn fleet() -> Fleet {
    hermetic();
    let dir = tempfile::tempdir().unwrap();
    let (b, g) = (
        side(dir.path(), "beastly", 11),
        side(dir.path(), "grouchly", 21),
    );
    home::init(&b.root, &josh()).unwrap();
    for side in [&b, &g] {
        home::enrol(&b.root, &side.machine).unwrap();
        home::admit(&b.root, &josh(), side.machine.name(), side.name).unwrap();
    }
    sync_fleet(&b, &g);
    Fleet { dir, b, g }
}

/// A project on `side`: a channel with a roster and a master, a repository with an origin,
/// and the entry in the root's manifest.
fn project(side: &Side, id: &str, master: &AgentIdentity, origin: &str) -> PathBuf {
    let channel = side.root.comms_home(id);
    fs::create_dir_all(&channel).unwrap();
    let workspace = side.root.path.parent().unwrap().join("work").join(id);
    fs::create_dir_all(&workspace).unwrap();
    run(&workspace, &["init", "-q", "-b", "main"]);
    run(&workspace, &["remote", "add", "origin", origin]);
    let route = ProjectRoute {
        project_id: id.into(),
        workspace: workspace.clone(),
        attachment: workspace.join(".ferryman"),
        communications: channel.clone(),
        shared_remote: format!("{id}-ferryman"),
        git_remote: String::new(),
        git_visibility: String::new(),
        agents: Vec::new(),
    };
    let entry = AgentRoute {
        name: master.name().into(),
        role: "operator".into(),
        capabilities: Vec::new(),
        public_key: Some(master.public_key_hex()),
        encryption_key: None,
    };
    ferryman_channel::register_agent(&route, &entry).unwrap();
    let route = ProjectRoute {
        agents: vec![entry],
        ..route
    };
    ferryman_channel::master::initialize_master(&route, master, master.name()).unwrap();
    side.root.adopt(id, &channel, Some(&workspace)).unwrap();
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

/// A bare repository `<dir>/origins/<name>.git` with one commit on main.
fn origin(dir: &Path, name: &str) -> PathBuf {
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
    bare
}

/// What `side` says about itself in the fleet folder, as its worker would.
fn publish(side: &Side) {
    remember_worker(&side.root, &side.worker);
    let outcome = crate::fleethome::publish(
        &side.root,
        &side.machine,
        side.name,
        &crate::fleethome::basic_facts(&side.root, vec!["claude".into()]),
    );
    assert!(
        matches!(outcome, crate::fleethome::Publish::Done { .. }),
        "{outcome:?}"
    );
}

fn lines(events: &[Event]) -> Vec<&str> {
    events.iter().map(|event| event.line.as_str()).collect()
}

fn roster_key(channel: &Path, name: &str) -> Option<String> {
    crate::fleet::listed(channel, name).and_then(|agent| agent.public_key)
}

// --- the remote that is advertised --------------------------------------------------------

#[test]
fn a_remote_with_a_credential_in_it_is_never_published() {
    assert_eq!(
        publishable_remote("https://user:hunter2@github.com/estejosh/x.git").as_deref(),
        Some("https://github.com/estejosh/x.git"),
        "an http(s) credential is stripped"
    );
    assert_eq!(
        publishable_remote("https://token@github.com/estejosh/x.git").as_deref(),
        Some("https://github.com/estejosh/x.git")
    );
    assert_eq!(
        publishable_remote("git@github.com:estejosh/x.git").as_deref(),
        Some("git@github.com:estejosh/x.git"),
        "an scp-like address has no secret in it"
    );
    // Anything with userinfo that cannot be stripped is not advertised at all.
    assert_eq!(publishable_remote("ssh://git:pw@host/x.git"), None);
    assert_eq!(publishable_remote("ssh://git@host/x.git"), None);
    // Not remotes another machine can use.
    assert_eq!(publishable_remote("/home/josh/x.git"), None);
    assert_eq!(publishable_remote("C:\\repos\\x"), None);
    assert_eq!(publishable_remote("file:///srv/x.git"), None);
    assert_eq!(publishable_remote("ext::sh -c id"), None);
    assert_eq!(publishable_remote("--upload-pack=evil"), None);
}

#[test]
fn what_a_machine_advertises_is_in_its_directory_entry_and_never_carries_a_credential() {
    let f = fleet();
    project(
        &f.b,
        "snifrig",
        &josh(),
        "https://user:hunter2@github.com/estejosh/snifrig.git",
    );
    publish(&f.b);
    let directory = home::read_directory(&f.b.root);
    let body = &directory.projects["snifrig"]["beastly"].body;
    assert_eq!(
        body.git_remote.as_deref(),
        Some("https://github.com/estejosh/snifrig.git")
    );
    assert_eq!(body.master.as_deref(), Some("josh"));
    let on_disk = fs::read_to_string(
        f.b.root
            .fleet_dir()
            .join(DIRECTORY)
            .join("snifrig")
            .join("beastly.json"),
    )
    .unwrap();
    assert!(
        !on_disk.contains("hunter2") && !on_disk.contains("user:"),
        "{on_disk}"
    );
}

#[test]
fn a_project_its_master_took_out_of_the_swarm_advertises_nothing() {
    let f = fleet();
    let channel = project(
        &f.b,
        "secret",
        &josh(),
        "https://github.com/estejosh/secret.git",
    );
    ferryman_channel::ferry::set_swarm(&channel, "secret", false, &josh()).unwrap();
    let adverts = adverts(&f.b.root);
    assert!(!adverts.contains_key("secret"), "{adverts:?}");
    publish(&f.b);
    let entry = &home::read_directory(&f.b.root).projects["secret"]["beastly"];
    assert!(entry.body.master.is_none() && entry.body.git_remote.is_none());
}

#[test]
fn the_machine_record_names_the_worker_and_what_the_machine_excludes() {
    let f = fleet();
    fs::write(
        rootconfig::path(&f.g.root),
        "[swarm]\nexclude = [\"phonehome\"]\n",
    )
    .unwrap();
    publish(&f.g);
    let (rows, findings) = home::read_machines(&f.g.root);
    assert!(findings.rejected.is_empty(), "{:?}", findings.rejected);
    let record = rows
        .iter()
        .find(|row| row.body.machine == "grouchly")
        .unwrap();
    assert_eq!(
        record.body.worker,
        Some(WorkerId {
            name: "grouchly-worker".into(),
            public_key: f.g.worker.public_key_hex()
        })
    );
    assert_eq!(record.body.excludes, vec!["phonehome".to_owned()]);
    // A publish by something that is not the worker (`ferry enable`) does not take it back.
    let outcome = crate::fleethome::publish(
        &f.g.root,
        &f.g.machine,
        "grouchly",
        &crate::fleethome::basic_facts(&f.g.root, Vec::new()),
    );
    assert!(matches!(outcome, crate::fleethome::Publish::Done { .. }));
    let (rows, _) = home::read_machines(&f.g.root);
    assert!(rows[0].body.worker.is_some());
}

// --- making room for the peers' workers ---------------------------------------------------

/// beastly has `snifrig`; grouchly's machine record names its worker and is synced over.
fn room_fixture() -> (Fleet, PathBuf) {
    let f = fleet();
    let channel = project(
        &f.b,
        "snifrig",
        &josh(),
        "https://github.com/estejosh/snifrig.git",
    );
    publish(&f.g);
    sync_fleet(&f.g, &f.b);
    publish(&f.b);
    (f, channel)
}

#[test]
fn a_peers_worker_is_put_on_the_roster_of_each_project_this_machine_serves() {
    let (f, channel) = room_fixture();
    let events = make_room(&f.b.root, "beastly");
    assert_eq!(
        roster_key(&channel, "grouchly-worker"),
        Some(f.g.worker.public_key_hex())
    );
    let entry = crate::fleet::listed(&channel, "grouchly-worker").unwrap();
    assert_eq!(entry.role, "worker", "the floor, and no grant");
    assert!(
        events
            .iter()
            .any(|e| !e.warn && e.line.contains("made room")),
        "{:?}",
        lines(&events)
    );
    // Again changes nothing and says nothing.
    assert!(make_room(&f.b.root, "beastly").is_empty());
    // Its own worker is not put there by this: a machine makes room for OTHERS.
    assert_eq!(roster_key(&channel, "beastly-worker"), None);
}

#[test]
fn a_machine_the_master_never_admitted_gets_no_room() {
    let (f, channel) = room_fixture();
    // A third machine enrols (anyone can) and writes a record naming a worker. Nobody admitted it.
    let rogue = AgentIdentity::from_seed("rogue-ferry", [31u8; 32]);
    home::enrol(&f.b.root, &rogue).unwrap();
    let mut body = serde_json::to_value(
        home::read_machines(&f.b.root)
            .0
            .iter()
            .find(|row| row.body.machine == "grouchly")
            .unwrap()
            .body
            .clone(),
    )
    .unwrap();
    body["machine"] = "rogue".into();
    body["worker"] = serde_json::json!({
        "name": "rogue-worker",
        "public_key": AgentIdentity::from_seed("rogue-worker", [32u8; 32]).public_key_hex()
    });
    let doc = home::sign("machine", "rogue", body, &rogue);
    fs::write(
        f.b.root.fleet_dir().join(MACHINES).join("rogue.json"),
        serde_json::to_vec(&doc).unwrap(),
    )
    .unwrap();
    let (_, findings) = home::read_machines(&f.b.root);
    assert!(
        findings
            .rejected
            .iter()
            .any(|r| r.why.contains("not admitted")),
        "{:?}",
        findings.rejected
    );

    let _ = make_room(&f.b.root, "beastly");
    assert_eq!(roster_key(&channel, "rogue-worker"), None);
    assert!(roster_key(&channel, "grouchly-worker").is_some());
}

#[test]
fn no_room_is_made_for_a_machine_that_keeps_the_project_out() {
    let f = fleet();
    let kept = project(
        &f.b,
        "phonehome",
        &josh(),
        "https://github.com/estejosh/phonehome.git",
    );
    let open = project(
        &f.b,
        "snifrig",
        &josh(),
        "https://github.com/estejosh/snifrig.git",
    );
    fs::write(
        rootconfig::path(&f.g.root),
        "[swarm]\nexclude = [\"phonehome\"]\n",
    )
    .unwrap();
    publish(&f.g);
    sync_fleet(&f.g, &f.b);
    let _ = make_room(&f.b.root, "beastly");
    assert_eq!(roster_key(&kept, "grouchly-worker"), None);
    assert!(roster_key(&open, "grouchly-worker").is_some());
}

#[test]
fn no_room_is_made_for_a_project_this_machine_does_not_serve_or_another_master_owns() {
    let f = fleet();
    let other = AgentIdentity::from_seed("someone-else", [41u8; 32]);
    let theirs = project(&f.b, "theirs", &other, "https://github.com/x/theirs.git");
    let off = project(&f.b, "off", &josh(), "https://github.com/x/off.git");
    ferryman_channel::ferry::set_swarm(&off, "off", false, &josh()).unwrap();
    let mine = project(&f.b, "mine", &josh(), "https://github.com/x/mine.git");
    fs::write(
        rootconfig::path(&f.b.root),
        "[swarm]\nexclude = [\"here\"]\n",
    )
    .unwrap();
    let here = project(&f.b, "here", &josh(), "https://github.com/x/here.git");
    publish(&f.g);
    sync_fleet(&f.g, &f.b);
    let _ = make_room(&f.b.root, "beastly");
    assert!(roster_key(&mine, "grouchly-worker").is_some());
    for (id, channel) in [("theirs", &theirs), ("off", &off), ("here", &here)] {
        assert_eq!(roster_key(channel, "grouchly-worker"), None, "{id}");
    }
}

#[test]
fn a_roster_that_holds_a_different_key_for_the_name_is_never_overwritten() {
    let (f, channel) = room_fixture();
    let squatter = AgentIdentity::from_seed("grouchly-worker", [99u8; 32]);
    let route = Entry {
        project_id: "snifrig".into(),
        channel: channel.clone(),
        ..Entry::default()
    }
    .route(&f.b.root)
    .unwrap()
    .0;
    ferryman_channel::register_agent_key(
        &route,
        &AgentRoute {
            name: "grouchly-worker".into(),
            role: "worker".into(),
            capabilities: Vec::new(),
            public_key: None,
            encryption_key: None,
        },
        &squatter,
    )
    .unwrap();
    let events = make_room(&f.b.root, "beastly");
    assert_eq!(
        roster_key(&channel, "grouchly-worker"),
        Some(squatter.public_key_hex()),
        "first key wins"
    );
    assert!(
        events
            .iter()
            .any(|e| e.warn && e.line.contains("different key")),
        "{:?}",
        lines(&events)
    );
}

// --- receiving what was advertised --------------------------------------------------------

/// beastly made `snifrig`; both machines have said their piece; grouchly has the fleet folder.
fn arrival_fixture(remote: &str) -> Fleet {
    let f = fleet();
    project(&f.b, "snifrig", &josh(), remote);
    publish(&f.b);
    sync_fleet(&f.b, &f.g);
    publish(&f.g);
    sync_fleet(&f.g, &f.b);
    f
}

fn receive_on_g(f: &Fleet) -> Vec<Event> {
    receive(&f.g.root, "grouchly", &f.g.worker)
}

fn filed_on(side: &Side, id: &str) -> bool {
    side.root.read().projects.iter().any(|e| e.project_id == id)
}

#[test]
fn an_advertised_project_is_filed_with_both_workers_on_its_roster_and_its_remote_kept() {
    let f = arrival_fixture("https://github.com/estejosh/snifrig.git");
    assert!(!filed_on(&f.g, "snifrig"));
    let events = receive_on_g(&f);
    assert_eq!(
        lines(&events),
        vec!["snifrig arrived from beastly: filed, cloning"]
    );

    let entry = f.g.root.read().projects.into_iter().next().unwrap();
    assert_eq!(entry.project_id, "snifrig");
    assert_eq!(entry.channel, f.g.root.comms_home("snifrig"));
    assert!(entry.repo.is_none(), "channel only until it is cloned");
    // This worker, and the advertiser's, by public key; nothing else.
    assert_eq!(
        roster_key(&entry.channel, "grouchly-worker"),
        Some(f.g.worker.public_key_hex())
    );
    assert_eq!(
        roster_key(&entry.channel, "beastly-worker"),
        Some(f.b.worker.public_key_hex())
    );
    // The remote is held for `repos sync` and is not in the person's ferry.toml.
    assert_eq!(
        arrival_remote(&f.g.root, "snifrig").as_deref(),
        Some("https://github.com/estejosh/snifrig.git")
    );
    assert!(!rootconfig::path(&f.g.root).exists());
    assert!(
        RootConfig::load(&f.g.root).remote_for("snifrig").is_none(),
        "not a [git.remotes] entry"
    );
    // No key crossed: the keys this machine holds are its own.
    let keys = f.g.root.comms_home("snifrig").join("keys");
    assert!(!keys.exists());
    // Once filed it is not filed again, and nothing is said.
    assert!(receive_on_g(&f).is_empty());
}

#[test]
fn a_project_advertised_by_a_machine_the_master_never_admitted_is_not_filed() {
    let f = fleet();
    let rogue = AgentIdentity::from_seed("rogue-ferry", [31u8; 32]);
    home::enrol(&f.b.root, &rogue).unwrap();
    sync_fleet(&f.b, &f.g);
    let body = serde_json::json!({
        "project": "snifrig", "machine": "rogue", "root": "/r", "placement": "managed",
        "layout": 2, "lifecycle": "live",
        "paths": { "code": "/r/x", "checkouts": [] },
        "git_remote": "https://github.com/estejosh/snifrig.git", "master": "josh"
    });
    let doc = home::sign("entry", "snifrig/rogue", body, &rogue);
    let path = f.g.root.fleet_dir().join(DIRECTORY).join("snifrig");
    fs::create_dir_all(&path).unwrap();
    fs::write(path.join("rogue.json"), serde_json::to_vec(&doc).unwrap()).unwrap();
    assert!(receive_on_g(&f).is_empty());
    assert!(!filed_on(&f.g, "snifrig"));
    assert!(!f.g.root.comms_home("snifrig").exists());
}

#[test]
fn a_project_whose_master_is_not_the_fleets_is_not_filed() {
    let f = fleet();
    let other = AgentIdentity::from_seed("someone-else", [41u8; 32]);
    project(&f.b, "theirs", &other, "https://github.com/x/theirs.git");
    publish(&f.b);
    sync_fleet(&f.b, &f.g);
    publish(&f.g);
    let entry = &home::read_directory(&f.g.root).projects["theirs"]["beastly"];
    assert_eq!(entry.body.master.as_deref(), Some("someone-else"));
    assert!(receive_on_g(&f).is_empty());
    assert!(!filed_on(&f.g, "theirs"));
}

#[test]
fn an_entry_from_before_this_existed_names_no_master_and_files_nothing() {
    let f = fleet();
    // Written the old way: no git_remote, no master.
    let body = serde_json::json!({
        "project": "old", "machine": "beastly", "root": "/r", "placement": "managed",
        "layout": 2, "lifecycle": "live",
        "paths": { "code": "/r/x", "checkouts": [] }
    });
    let doc = home::sign("entry", "old/beastly", body, &f.b.machine);
    let path = f.g.root.fleet_dir().join(DIRECTORY).join("old");
    fs::create_dir_all(&path).unwrap();
    fs::write(path.join("beastly.json"), serde_json::to_vec(&doc).unwrap()).unwrap();
    let directory = home::read_directory(&f.g.root);
    assert!(
        directory.findings.rejected.is_empty(),
        "{:?}",
        directory.findings.rejected
    );
    assert!(directory.projects["old"]["beastly"].body.master.is_none());
    assert!(receive_on_g(&f).is_empty());
}

#[test]
fn a_project_this_machine_excludes_is_not_filed() {
    let f = arrival_fixture("https://github.com/estejosh/snifrig.git");
    rootconfig::set_excluded(&f.g.root, "snifrig", true).unwrap();
    assert!(receive_on_g(&f).is_empty());
    assert!(!filed_on(&f.g, "snifrig"));
    assert!(!f.g.root.comms_home("snifrig").exists());
}

#[test]
fn an_archived_project_is_not_filed() {
    let f = fleet();
    let channel = project(&f.b, "done", &josh(), "https://github.com/x/done.git");
    f.b.root.archive("done", true, &josh()).unwrap();
    assert!(ferryman_channel::ferry::is_archived(&channel, "done"));
    publish(&f.b);
    sync_fleet(&f.b, &f.g);
    let entry = &home::read_directory(&f.g.root).projects["done"]["beastly"];
    assert_eq!(entry.body.lifecycle, "archived");
    assert!(receive_on_g(&f).is_empty());
    assert!(!filed_on(&f.g, "done"));
}

#[test]
fn a_project_id_that_is_not_safe_is_not_filed() {
    let f = fleet();
    // An entry filed under a folder whose name is not a project id is dropped by the reader.
    let body = serde_json::json!({
        "project": "../escape", "machine": "beastly", "root": "/r", "placement": "managed",
        "layout": 2, "lifecycle": "live", "paths": { "checkouts": [] }, "master": "josh"
    });
    let doc = home::sign("entry", "../escape/beastly", body, &f.b.machine);
    let path = f.g.root.fleet_dir().join(DIRECTORY).join("bad id");
    fs::create_dir_all(&path).unwrap();
    fs::write(path.join("beastly.json"), serde_json::to_vec(&doc).unwrap()).unwrap();
    assert!(!home::read_directory(&f.g.root).findings.rejected.is_empty());
    assert!(receive_on_g(&f).is_empty());
    assert!(f.g.root.read().projects.is_empty());
    assert!(!f.g.root.path.join("escape").exists());
}

#[test]
fn a_worker_name_the_roster_already_knows_under_another_key_stops_the_arrival() {
    let f = arrival_fixture("https://github.com/estejosh/snifrig.git");
    // The channel folder is already there (it arrived some other way) and lists the name
    // under a different key.
    let comms = f.g.root.comms_home("snifrig");
    fs::create_dir_all(&comms).unwrap();
    let squatter = AgentIdentity::from_seed("grouchly-worker", [99u8; 32]);
    let route = Entry {
        project_id: "snifrig".into(),
        channel: comms.clone(),
        ..Entry::default()
    }
    .route(&f.g.root)
    .unwrap()
    .0;
    ferryman_channel::register_agent_key(
        &route,
        &AgentRoute {
            name: "grouchly-worker".into(),
            role: "worker".into(),
            capabilities: Vec::new(),
            public_key: None,
            encryption_key: None,
        },
        &squatter,
    )
    .unwrap();
    let events = receive_on_g(&f);
    assert!(events.iter().all(|e| e.warn), "{:?}", lines(&events));
    assert!(
        !filed_on(&f.g, "snifrig"),
        "nothing is filed on a roster that refuses"
    );
    assert_eq!(
        roster_key(&comms, "grouchly-worker"),
        Some(squatter.public_key_hex())
    );
}

// --- cloning what arrived -----------------------------------------------------------------

/// The same fixture, with beastly advertising a remote grouchly can actually reach.
fn reachable(f: &Fleet) -> PathBuf {
    let bare = origin(f.dir.path(), "snifrig");
    let mut adverts = adverts(&f.b.root);
    adverts.get_mut("snifrig").unwrap().git_remote = Some(bare.display().to_string());
    home::publish_directory_with(&f.b.root, "beastly", &f.b.machine, &adverts).unwrap();
    sync_fleet(&f.b, &f.g);
    bare
}

#[test]
fn an_arrived_project_is_cloned_from_the_advertised_remote_and_attached() {
    let f = arrival_fixture("https://github.com/estejosh/snifrig.git");
    reachable(&f);
    receive_on_g(&f);
    assert_eq!(unattached(&f.g.root), vec!["snifrig".to_owned()]);

    let mut state = SyncState::default();
    let events = sync_arrivals(
        &f.g.root,
        &mut state,
        2,
        Duration::from_secs(60),
        Instant::now(),
    );
    assert!(events.iter().all(|e| !e.warn), "{:?}", lines(&events));
    let entry = f.g.root.read().projects.into_iter().next().unwrap();
    let managed = f.g.root.managed_clone_of("snifrig");
    assert_eq!(entry.repo.as_deref(), Some(managed.as_path()));
    assert!(managed.join("README.md").is_file());
    assert!(entry.attachment().is_some());
    assert!(unattached(&f.g.root).is_empty());
}

#[test]
fn a_template_of_this_machines_own_is_tried_before_the_advertised_remote() {
    let f = arrival_fixture("https://github.com/estejosh/snifrig.git");
    let advertised = reachable(&f);
    receive_on_g(&f);
    // The machine's own way of forming a remote comes first.
    let mine = f.dir.path().join("mine").join("snifrig.git");
    fs::create_dir_all(mine.parent().unwrap()).unwrap();
    run(
        f.dir.path(),
        &[
            "clone",
            "-q",
            "--bare",
            advertised.to_str().unwrap(),
            mine.to_str().unwrap(),
        ],
    );
    let base = mine.parent().unwrap().display().to_string();
    rootconfig::set_remote_template(&f.g.root, &format!("{base}/{{project}}.git")).unwrap();
    let entry = f.g.root.read().projects.into_iter().next().unwrap();
    let candidates = repos::candidates(&entry, &RootConfig::load(&f.g.root), &f.g.root);
    // The template joins with '/', which git accepts on every platform.
    assert_eq!(candidates[0], format!("{base}/snifrig.git"));
    assert_eq!(candidates[1], advertised.display().to_string());
}

#[test]
fn a_project_nobody_can_clone_does_not_use_up_the_pass_and_is_retried_later() {
    let f = fleet();
    // Three projects arrive; the first two have no remote anywhere.
    for id in ["aaa", "bbb", "ccc"] {
        project(&f.b, id, &josh(), "https://github.com/estejosh/x.git");
    }
    publish(&f.b);
    let bare = origin(f.dir.path(), "ccc");
    let mut ads = adverts(&f.b.root);
    for id in ["aaa", "bbb"] {
        ads.get_mut(id).unwrap().git_remote = None;
    }
    ads.get_mut("ccc").unwrap().git_remote = Some(bare.display().to_string());
    home::publish_directory_with(&f.b.root, "beastly", &f.b.machine, &ads).unwrap();
    sync_fleet(&f.b, &f.g);
    publish(&f.g);
    receive_on_g(&f);
    assert_eq!(unattached(&f.g.root).len(), 3);

    let mut state = SyncState::default();
    let start = Instant::now();
    let first = sync_arrivals(&f.g.root, &mut state, 2, Duration::from_secs(60), start);
    assert_eq!(
        first.iter().filter(|e| e.warn).count(),
        2,
        "{:?}",
        lines(&first)
    );
    assert_eq!(unattached(&f.g.root).len(), 3);
    // The two that failed are left alone for a while, so the one behind them is taken now.
    let second = sync_arrivals(&f.g.root, &mut state, 2, Duration::from_secs(60), start);
    assert!(second.iter().all(|e| !e.warn), "{:?}", lines(&second));
    assert_eq!(
        unattached(&f.g.root),
        vec!["aaa".to_owned(), "bbb".to_owned()]
    );
    // After the wait they are tried again.
    let later = sync_arrivals(
        &f.g.root,
        &mut state,
        2,
        Duration::from_secs(60),
        start + RETRY_AFTER,
    );
    assert_eq!(later.iter().filter(|e| e.warn).count(), 2);
}

#[test]
fn a_person_s_checkout_is_never_taken_over_by_an_arrival_sync() {
    let f = fleet();
    // A project filed here with a person's working copy attached: not "unattached".
    project(&f.g, "mine", &josh(), "https://github.com/x/mine.git");
    let workspace = f.g.root.path.parent().unwrap().join("work").join("mine");
    fs::create_dir_all(workspace.join(".ferryman")).unwrap();
    fs::write(
        workspace.join(".ferryman").join("bridge.toml"),
        format!(
            "project = \"mine\"\nworkspace = \"{}\"\nattachment = \"{}\"\ncommunications = \"{}\"\n",
            workspace.display(),
            workspace.join(".ferryman").display(),
            f.g.root.comms_home("mine").display()
        ),
    )
    .unwrap();
    assert!(unattached(&f.g.root).is_empty());
}

// --- the worker picks it up while it runs -------------------------------------------------

fn worker_home(f: &Fleet) -> (PathBuf, AgentConfig) {
    let home =
        f.g.root
            .path
            .parent()
            .unwrap()
            .join("home")
            .join(".ferryman");
    fs::create_dir_all(&home).unwrap();
    f.g.worker.seat_in(&home).unwrap();
    fs::write(
        AgentConfig::path(&home),
        format!(
            "agent = \"{}\"\ncommand = \"claude\"\nmax_parallel = \"2\"\n",
            f.g.worker.name()
        ),
    )
    .unwrap();
    let config = AgentConfig::load(&home).unwrap();
    (home, config)
}

#[test]
fn a_project_created_on_another_machine_is_served_here_on_the_next_pass_with_no_restart() {
    let f = arrival_fixture("https://github.com/estejosh/snifrig.git");
    // A project grouchly already serves, so there is a running worker.
    project(&f.g, "old", &josh(), "https://github.com/x/old.git");
    let (home_dir, config) = worker_home(&f);
    let old_route = Entry {
        project_id: "old".into(),
        ..f.g.root.read().projects[0].clone()
    };
    drop(old_route);
    let old_workspace = f.g.root.path.parent().unwrap().join("work").join("old");
    fs::create_dir_all(old_workspace.join(".ferryman")).unwrap();
    fs::write(old_workspace.join(".gitignore"), "/.ferryman/\n").unwrap();
    fs::write(
        old_workspace.join(".ferryman").join("bridge.toml"),
        format!(
            "project = \"old\"\nworkspace = \"{}\"\nattachment = \"{}\"\ncommunications = \"{}\"\n",
            old_workspace.display(),
            old_workspace.join(".ferryman").display(),
            f.g.root.comms_home("old").display()
        ),
    )
    .unwrap();
    let route = Entry {
        project_id: "old".into(),
        channel: f.g.root.comms_home("old"),
        ..Entry::default()
    }
    .route(&f.g.root)
    .unwrap()
    .0;
    ferryman_channel::register_agent_key(
        &route,
        &AgentRoute {
            name: f.g.worker.name().into(),
            role: "worker".into(),
            capabilities: Vec::new(),
            public_key: None,
            encryption_key: None,
        },
        &f.g.worker,
    )
    .unwrap();
    f.g.root
        .adopt("old", &f.g.root.comms_home("old"), Some(&old_workspace))
        .unwrap();

    let (plan, identity) = fleet::plan_worker(&f.g.root, &home_dir, &config).unwrap();
    let running = fleet::serve(plan, &identity, &config);
    assert_eq!(
        running
            .served
            .iter()
            .map(|(r, _)| r.project_id.as_str())
            .collect::<Vec<_>>(),
        vec!["old"]
    );

    // beastly's project is advertised and reachable; the worker is already running.
    reachable(&f);
    // Pass 1: the arrival is filed and cloned, and the same pass's re-plan serves it.
    let mut state = SyncState::default();
    let events = receive_on_g(&f);
    assert_eq!(
        lines(&events),
        vec!["snifrig arrived from beastly: filed, cloning"]
    );
    let cloned = sync_arrivals(
        &f.g.root,
        &mut state,
        2,
        Duration::from_secs(60),
        Instant::now(),
    );
    assert!(cloned.iter().all(|e| !e.warn), "{:?}", lines(&cloned));
    let pass = fleet::newly_served(&f.g.root, &home_dir, &config, &running.served).unwrap();
    assert_eq!(
        pass.served
            .iter()
            .map(|(r, _)| r.project_id.as_str())
            .collect::<Vec<_>>(),
        vec!["snifrig"],
        "skipped: {:?}",
        pass.skipped
    );
    // Its key is in the clone, put there from the machine's own copy.
    let route = &pass.served[0].0;
    assert!(
        AgentIdentity::load_existing(f.g.worker.name(), &route.attachment)
            .unwrap()
            .is_some()
    );
    // The roster the worker serves lists both workers and the master, once the channel arrives.
    assert!(
        read_agent_roster(&route.communications)
            .unwrap()
            .iter()
            .any(|a| a.name == "beastly-worker")
    );
}

#[test]
fn a_channel_only_project_is_not_served_until_it_has_a_checkout_and_then_it_is() {
    // The reason a project filed by hand "was not picked up while the worker ran": the
    // re-plan skipped it for want of a checkout and nothing cloned one.
    let f = arrival_fixture("https://github.com/estejosh/snifrig.git");
    reachable(&f);
    receive_on_g(&f);
    let (home_dir, config) = worker_home(&f);
    let (plan, identity) = fleet::plan_worker(&f.g.root, &home_dir, &config).unwrap();
    let running = fleet::serve(plan, &identity, &config);
    assert!(running.served.is_empty());
    let pass = fleet::newly_served(&f.g.root, &home_dir, &config, &running.served).unwrap();
    assert!(pass.served.is_empty());
    assert!(
        pass.skipped[0].1.contains("no checkout"),
        "{:?}",
        pass.skipped
    );
    let _ = sync_arrivals(
        &f.g.root,
        &mut SyncState::default(),
        2,
        Duration::from_secs(60),
        Instant::now(),
    );
    let pass = fleet::newly_served(&f.g.root, &home_dir, &config, &running.served).unwrap();
    assert_eq!(pass.served.len(), 1, "{:?}", pass.skipped);
}
