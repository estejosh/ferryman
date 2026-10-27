use super::*;
use crate::agent::AgentConfig;
use crate::fleet;
use crate::rootconfig;
use std::fs;
use std::path::Path;

fn hermetic() {
    ferryman_channel::ferry::isolate_root_search_for_this_thread();
    ferryman_channel::licensing::use_machine_state_dir_per_thread(
        std::env::temp_dir().join(format!("ferryman-seat-selftest-{}", std::process::id())),
    );
}

fn josh() -> AgentIdentity {
    AgentIdentity::from_seed("josh", [7u8; 32])
}

fn connector() -> AgentIdentity {
    AgentIdentity::from_seed("claude-ai-josh", [61u8; 32])
}

fn store() -> PathBuf {
    ferryman_channel::licensing::machine_state_dir().unwrap()
}

/// A served project: a channel with a roster and a master, a checkout whose `.ferryman` is
/// git-ignored, and the manifest entry.
fn project(dir: &Path, root: &Root, id: &str) -> PathBuf {
    let channel = root.comms_home(id);
    fs::create_dir_all(&channel).unwrap();
    let workspace = dir.join("repos").join(id);
    let attachment = workspace.join(".ferryman");
    fs::create_dir_all(&attachment).unwrap();
    fs::write(workspace.join(".gitignore"), "/.ferryman/\n").unwrap();
    let route = ProjectRoute {
        project_id: id.into(),
        workspace: workspace.clone(),
        attachment: attachment.clone(),
        communications: channel.clone(),
        shared_remote: format!("{id}-ferryman"),
        git_remote: String::new(),
        git_visibility: String::new(),
        agents: Vec::new(),
    };
    let master = josh();
    let entry = AgentRoute {
        name: "josh".into(),
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
    ferryman_channel::master::initialize_master(&route, &master, "josh").unwrap();
    fs::write(
        attachment.join("bridge.toml"),
        format!(
            "project = \"{id}\"\nworkspace = \"{}\"\nattachment = \"{}\"\ncommunications = \"{}\"\n",
            workspace.display(),
            attachment.display(),
            channel.display()
        ),
    )
    .unwrap();
    root.adopt(id, &channel, Some(&workspace)).unwrap();
    attachment
}

fn setup() -> (tempfile::TempDir, Root) {
    hermetic();
    let dir = tempfile::tempdir().unwrap();
    let root = Root::create(&dir.path().join("ferry")).unwrap();
    (dir, root)
}

fn names() -> Vec<String> {
    vec!["claude-ai-josh".to_owned()]
}

fn outcome(seats: &[Seat], project: &str) -> Outcome {
    seats
        .iter()
        .find(|seat| seat.project == project)
        .unwrap()
        .outcome
        .clone()
}

fn key_file(attachment: &Path) -> PathBuf {
    attachment.join("keys").join("claude-ai-josh.key")
}

fn listed_key(root: &Root, id: &str) -> Option<String> {
    crate::fleet::listed(&root.comms_home(id), "claude-ai-josh").and_then(|agent| agent.public_key)
}

#[test]
fn a_connector_is_seated_from_the_key_another_project_already_holds() {
    let (dir, root) = setup();
    let alpha = project(dir.path(), &root, "alpha");
    let beta = project(dir.path(), &root, "beta");
    connector().seat_in(&alpha).unwrap();

    let seats = seat_everywhere(&root, &names());
    assert_eq!(outcome(&seats, "beta"), Outcome::Seated);
    assert_eq!(
        fs::read_to_string(key_file(&beta)).unwrap(),
        fs::read_to_string(key_file(&alpha)).unwrap(),
        "the same key, copied between two directories of this one machine"
    );
    assert_eq!(
        listed_key(&root, "beta"),
        Some(connector().public_key_hex())
    );
    assert_eq!(
        crate::fleet::listed(&root.comms_home("beta"), "claude-ai-josh")
            .unwrap()
            .role,
        "member",
        "a role nobody gave it elsewhere is a member"
    );
    // Seating gave a key file and a roster line, not authority: no grant was written.
    let (route, _) = root.read().projects[1].route(&root).unwrap();
    assert!(
        ferryman_channel::master::member_grants(&route)
            .unwrap()
            .iter()
            .all(|(grant, _)| grant.grantee != "claude-ai-josh")
    );
    // The key is not in the channel.
    assert!(!root.comms_home("beta").join("keys").exists());
    // Again changes nothing.
    let again = seat_everywhere(&root, &names());
    assert_eq!(outcome(&again, "beta"), Outcome::Already);
}

#[test]
fn the_role_the_name_already_has_on_another_roster_is_the_one_it_is_given() {
    let (dir, root) = setup();
    let alpha = project(dir.path(), &root, "alpha");
    project(dir.path(), &root, "beta");
    connector().seat_in(&alpha).unwrap();
    let route = root.read().projects[0].route(&root).unwrap().0;
    ferryman_channel::register_agent_key(
        &route,
        &AgentRoute {
            name: "claude-ai-josh".into(),
            role: "operator".into(),
            capabilities: Vec::new(),
            public_key: None,
            encryption_key: None,
        },
        &connector(),
    )
    .unwrap();
    let _ = seat_everywhere(&root, &names());
    assert_eq!(
        crate::fleet::listed(&root.comms_home("beta"), "claude-ai-josh")
            .unwrap()
            .role,
        "operator"
    );
}

#[test]
fn a_connector_is_seated_from_the_machines_own_key_store() {
    let (dir, root) = setup();
    let alpha = project(dir.path(), &root, "alpha");
    connector().seat_in(&store()).unwrap();
    let seats = seat_everywhere(&root, &names());
    assert_eq!(outcome(&seats, "alpha"), Outcome::Seated);
    assert!(key_file(&alpha).is_file());
}

#[test]
fn two_different_keys_under_one_name_refuse_everywhere_and_write_nothing() {
    let (dir, root) = setup();
    let alpha = project(dir.path(), &root, "alpha");
    let beta = project(dir.path(), &root, "beta");
    let gamma = project(dir.path(), &root, "gamma");
    connector().seat_in(&alpha).unwrap();
    AgentIdentity::from_seed("claude-ai-josh", [62u8; 32])
        .seat_in(&beta)
        .unwrap();
    let error = held(&root, "claude-ai-josh").unwrap_err();
    assert!(
        format!("{error:#}").contains("2 different keys"),
        "{error:#}"
    );

    let seats = seat_everywhere(&root, &names());
    assert!(
        seats
            .iter()
            .all(|seat| matches!(seat.outcome, Outcome::Refused(_))),
        "{seats:?}"
    );
    assert!(!key_file(&gamma).exists());
    assert_eq!(listed_key(&root, "gamma"), None);
}

#[test]
fn a_name_this_machine_holds_no_key_for_is_never_given_one() {
    let (dir, root) = setup();
    let alpha = project(dir.path(), &root, "alpha");
    let seats = seat_everywhere(&root, &names());
    assert_eq!(outcome(&seats, "alpha"), Outcome::NoKey);
    assert!(!key_file(&alpha).exists());
    assert!(!alpha.join("keys").exists(), "not even the folder");
    assert!(!store().join("keys").join("claude-ai-josh.key").exists());
    assert_eq!(listed_key(&root, "alpha"), None);
}

#[test]
fn a_key_is_not_seated_where_git_would_commit_it() {
    let (dir, root) = setup();
    let alpha = project(dir.path(), &root, "alpha");
    let beta = project(dir.path(), &root, "beta");
    connector().seat_in(&alpha).unwrap();
    // beta's checkout is a git repository that does not ignore `.ferryman`.
    let workspace = dir.path().join("repos").join("beta");
    fs::remove_file(workspace.join(".gitignore")).unwrap();
    let status = std::process::Command::new("git")
        .arg("-C")
        .arg(&workspace)
        .args(["init", "-q"])
        .status()
        .unwrap();
    assert!(status.success());
    let seats = seat_everywhere(&root, &names());
    let Outcome::Refused(why) = outcome(&seats, "beta") else {
        panic!("{seats:?}")
    };
    assert!(why.contains("does not git-ignore .ferryman"), "{why}");
    assert!(!key_file(&beta).exists());
    assert_eq!(listed_key(&root, "beta"), None);

    fs::write(workspace.join(".gitignore"), "/.ferryman/\n").unwrap();
    let seats = seat_everywhere(&root, &names());
    assert_eq!(outcome(&seats, "beta"), Outcome::Seated);
    assert!(key_file(&beta).is_file());
}

#[test]
fn a_different_key_on_the_roster_or_in_the_checkout_is_never_replaced() {
    let (dir, root) = setup();
    let alpha = project(dir.path(), &root, "alpha");
    let beta = project(dir.path(), &root, "beta");
    let gamma = project(dir.path(), &root, "gamma");
    connector().seat_in(&alpha).unwrap();
    // beta's roster knows the name under another key.
    let other = AgentIdentity::from_seed("claude-ai-josh", [63u8; 32]);
    let route = root.read().projects[1].route(&root).unwrap().0;
    ferryman_channel::register_peer_key(
        &route,
        &AgentRoute {
            name: "claude-ai-josh".into(),
            role: "member".into(),
            capabilities: Vec::new(),
            public_key: None,
            encryption_key: None,
        },
        &other.public_key_hex(),
    )
    .unwrap();
    // gamma's checkout holds another key under the name... which makes two keys on this
    // machine, so the whole thing refuses. Take that away to test beta on its own.
    drop(gamma);
    let seats = seat_everywhere(&root, &names());
    let Outcome::Refused(why) = outcome(&seats, "beta") else {
        panic!("{seats:?}")
    };
    assert!(why.contains("different key"), "{why}");
    assert!(!key_file(&beta).exists());
    assert_eq!(listed_key(&root, "beta"), Some(other.public_key_hex()));
}

#[test]
fn the_worker_seats_the_configured_connectors_where_it_seats_itself() {
    let (dir, root) = setup();
    let alpha = project(dir.path(), &root, "alpha");
    let beta = project(dir.path(), &root, "beta");
    connector().seat_in(&store()).unwrap();
    let worker = AgentIdentity::from_seed("ichabod-test", [9u8; 32]);
    for id in ["alpha", "beta"] {
        let route = root
            .read()
            .projects
            .into_iter()
            .find(|e| e.project_id == id)
            .unwrap()
            .route(&root)
            .unwrap()
            .0;
        ferryman_channel::register_agent_key(
            &route,
            &AgentRoute {
                name: "ichabod-test".into(),
                role: "worker".into(),
                capabilities: Vec::new(),
                public_key: None,
                encryption_key: None,
            },
            &worker,
        )
        .unwrap();
    }
    let home = dir.path().join("home").join(".ferryman");
    fs::create_dir_all(&home).unwrap();
    worker.seat_in(&home).unwrap();
    fs::write(
        AgentConfig::path(&home),
        "agent = \"ichabod-test\"\ncommand = \"claude\"\nmax_parallel = \"2\"\n",
    )
    .unwrap();
    let config = AgentConfig::load(&home).unwrap();

    // Nothing listed in [seat]: nothing seated.
    let (plan, identity) = fleet::plan_worker(&root, &home, &config).unwrap();
    let served = fleet::serve(plan, &identity, &config);
    assert_eq!(served.served.len(), 2);
    assert!(served.notes.is_empty());
    assert!(!key_file(&alpha).exists() && !key_file(&beta).exists());

    // Listed: it is seated in both as the worker starts serving them.
    rootconfig::set_seat(&root, "Claude-AI-Josh", true).unwrap();
    let (plan, identity) = fleet::plan_worker(&root, &home, &config).unwrap();
    let served = fleet::serve(plan, &identity, &config);
    assert_eq!(served.served.len(), 2);
    assert!(key_file(&alpha).is_file() && key_file(&beta).is_file());
    assert_eq!(served.notes.len(), 2, "{:?}", served.notes);
    // Said once: the next start has nothing to say.
    let (plan, identity) = fleet::plan_worker(&root, &home, &config).unwrap();
    assert!(fleet::serve(plan, &identity, &config).notes.is_empty());
}

#[test]
fn seat_config_is_read_validated_and_edited_without_touching_the_rest() {
    let (_dir, root) = setup();
    fs::write(
        rootconfig::path(&root),
        "[swarm]\nexclude = [\"a\"]\n[seat]\nagents = [\"Claude-AI-Josh\", \"../evil\", \"claude-ai-josh\"]\n",
    )
    .unwrap();
    let config = RootConfig::load(&root);
    assert_eq!(config.seat_agents, vec!["claude-ai-josh".to_owned()]);
    assert_eq!(config.notes.len(), 1, "{:?}", config.notes);
    assert!(config.notes[0].contains("../evil"));
    assert!(config.excluded("a"));

    assert!(!rootconfig::set_seat(&root, "claude-ai-josh", true).unwrap());
    assert!(rootconfig::set_seat(&root, "wisp", true).unwrap());
    assert_eq!(
        RootConfig::load(&root).seat_agents,
        vec!["claude-ai-josh".to_owned(), "wisp".to_owned()]
    );
    assert!(RootConfig::load(&root).excluded("a"), "the rest is kept");
    assert!(rootconfig::set_seat(&root, "wisp", false).unwrap());
    assert!(!rootconfig::set_seat(&root, "wisp", false).unwrap());
    assert!(rootconfig::set_seat(&root, "../x", true).is_err());
}
