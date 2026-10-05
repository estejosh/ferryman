use super::*;
use std::cell::Cell;

fn hermetic() {
    ferryman_channel::licensing::use_machine_state_dir_per_thread(
        std::env::temp_dir().join(format!("ferryman-fleet-selftest-{}", std::process::id())),
    );
}

fn josh() -> AgentIdentity {
    AgentIdentity::from_seed("josh", [7u8; 32])
}

fn worker() -> AgentIdentity {
    AgentIdentity::from_seed("ichabod-test", [9u8; 32])
}

/// A project in the root, mastered by `master`: the channel, its roster, its master
/// declaration, and - when `checkout` - a repository with the attachment `ferry enable`
/// leaves in it.
fn project(dir: &Path, root: &Root, id: &str, master: &AgentIdentity, checkout: bool) {
    let channel = root.comms_home(id);
    fs::create_dir_all(&channel).unwrap();
    let workspace = dir.join("repos").join(id);
    let attachment = workspace.join(".ferryman");
    fs::create_dir_all(&attachment).unwrap();
    let mut route = ProjectRoute {
        project_id: id.into(),
        workspace: workspace.clone(),
        attachment: attachment.clone(),
        communications: channel.clone(),
        shared_remote: format!("{id}-ferryman"),
        git_remote: String::new(),
        git_visibility: String::new(),
        agents: Vec::new(),
    };
    let master_entry = AgentRoute {
        name: master.name().into(),
        role: "operator".into(),
        capabilities: Vec::new(),
        public_key: Some(master.public_key_hex()),
        encryption_key: None,
    };
    ferryman_channel::register_agent(&route, &master_entry).unwrap();
    route.agents.push(master_entry);
    ferryman_channel::master::initialize_master(&route, master, master.name()).unwrap();
    if checkout {
        fs::write(
            attachment.join("bridge.toml"),
            format!(
                "project = \"{id}\"\nworkspace = \"{}\"\nattachment = \"{}\"\n\
                 communications = \"{}\"\n",
                workspace.display(),
                attachment.display(),
                channel.display()
            ),
        )
        .unwrap();
        root.adopt(id, &channel, Some(&workspace)).unwrap();
    } else {
        root.adopt(id, &channel, None).unwrap();
    }
}

fn attachment_of(dir: &Path, id: &str) -> PathBuf {
    dir.join("repos").join(id).join(".ferryman")
}

/// The worker's own home: its key, and the agent.toml it was started next to.
fn home(dir: &Path, extra: &str) -> (PathBuf, AgentConfig) {
    let home = dir.join("home").join(".ferryman");
    fs::create_dir_all(&home).unwrap();
    worker().seat_in(&home).unwrap();
    fs::write(
        AgentConfig::path(&home),
        format!("agent = \"ichabod-test\"\ncommand = \"claude\"\nmax_parallel = \"4\"\n{extra}"),
    )
    .unwrap();
    let config = AgentConfig::load(&home).unwrap();
    (home, config)
}

fn as_josh(count: &Cell<usize>) -> impl FnMut(&Entry, &str) -> Result<AgentIdentity> + '_ {
    move |_, master| {
        count.set(count.get() + 1);
        assert_eq!(master, "josh");
        Ok(josh())
    }
}

fn outcome<'a>(done: &'a [(String, Enrolment)], id: &str) -> &'a Enrolment {
    &done.iter().find(|(project, _)| project == id).unwrap().1
}

fn enrolled_everywhere(root: &Root) {
    let asked = Cell::new(0);
    enrol(
        root,
        "ichabod-test",
        "worker",
        &worker().public_key_hex(),
        "josh",
        &mut as_josh(&asked),
    );
}

#[test]
fn enrolling_writes_the_roster_entry_and_the_masters_grant_once() {
    hermetic();
    let dir = tempfile::tempdir().unwrap();
    let root = Root::create(&dir.path().join("ferry")).unwrap();
    project(dir.path(), &root, "alpha", &josh(), true);
    project(dir.path(), &root, "beta", &josh(), false);
    let key = worker().public_key_hex();

    let asked = Cell::new(0);
    let done = enrol(
        &root,
        "ichabod-test",
        "worker",
        &key,
        "josh",
        &mut as_josh(&asked),
    );
    let both = Enrolment::Added {
        roster: true,
        grant: true,
    };
    assert_eq!(outcome(&done, "alpha"), &both);
    // A project with no checkout here is enrolled all the same: it takes the master's
    // signature, not a repository.
    assert_eq!(outcome(&done, "beta"), &both);
    assert_eq!(asked.get(), 2);

    let entry = listed(&root.comms_home("alpha"), "ichabod-test").unwrap();
    assert_eq!(entry.role, "worker");
    assert_eq!(entry.public_key.as_deref(), Some(key.as_str()));
    let (route, _) = root.read().projects[0].route(&root).unwrap();
    let grants = ferryman_channel::master::member_grants(&route).unwrap();
    let grant = grants
        .iter()
        .find(|(grant, _)| grant.grantee == "ichabod-test")
        .expect("a grant was written");
    assert!(grant.1 == SignatureCheck::Valid, "signed by the master");
    assert_eq!(grant.0.public_key, key);
    assert_eq!(grant.0.roles, ["worker"]);

    // Again: nothing to write, so nobody is asked to sign.
    let asked = Cell::new(0);
    let again = enrol(
        &root,
        "ichabod-test",
        "worker",
        &key,
        "josh",
        &mut as_josh(&asked),
    );
    assert_eq!(outcome(&again, "alpha"), &Enrolment::AlreadyThere);
    assert_eq!(outcome(&again, "beta"), &Enrolment::AlreadyThere);
    assert_eq!(
        asked.get(),
        0,
        "an enrolled project does not ask for a password"
    );
}

#[test]
fn a_project_somebody_else_masters_is_left_alone_and_never_asks_for_their_key() {
    hermetic();
    let dir = tempfile::tempdir().unwrap();
    let root = Root::create(&dir.path().join("ferry")).unwrap();
    let bob = AgentIdentity::from_seed("bob", [5u8; 32]);
    project(dir.path(), &root, "mine", &josh(), false);
    project(dir.path(), &root, "theirs", &bob, false);

    let asked = Cell::new(0);
    let done = enrol(
        &root,
        "ichabod-test",
        "worker",
        &worker().public_key_hex(),
        "josh",
        &mut as_josh(&asked),
    );
    assert_eq!(
        outcome(&done, "theirs"),
        &Enrolment::NotMaster {
            master: "bob".into()
        }
    );
    assert_eq!(asked.get(), 1, "only the project josh masters asked");
    assert!(
        listed(&root.comms_home("theirs"), "ichabod-test").is_none(),
        "nothing was written into it, not even a roster entry"
    );
    assert!(!root.comms_home("theirs").join("grants").exists());
    assert_eq!(
        dominant_master(&root).as_deref(),
        Some("bob"),
        "a tie goes alphabetical"
    );
}

#[test]
fn a_signature_that_cannot_be_made_writes_nothing() {
    hermetic();
    let dir = tempfile::tempdir().unwrap();
    let root = Root::create(&dir.path().join("ferry")).unwrap();
    project(dir.path(), &root, "alpha", &josh(), false);

    let mut locked = |_: &Entry, _: &str| -> Result<AgentIdentity> { bail!("wrong password") };
    let done = enrol(
        &root,
        "ichabod-test",
        "worker",
        &worker().public_key_hex(),
        "josh",
        &mut locked,
    );
    let Enrolment::Skipped(why) = outcome(&done, "alpha") else {
        panic!("{done:?}")
    };
    assert!(why.contains("wrong password"), "{why}");
    assert!(listed(&root.comms_home("alpha"), "ichabod-test").is_none());
    assert!(!root.comms_home("alpha").join("grants").exists());
}

#[test]
fn a_name_a_master_revoked_stays_revoked_and_a_different_key_is_not_replaced() {
    hermetic();
    let dir = tempfile::tempdir().unwrap();
    let root = Root::create(&dir.path().join("ferry")).unwrap();
    project(dir.path(), &root, "alpha", &josh(), false);
    project(dir.path(), &root, "clash", &josh(), false);
    enrolled_everywhere(&root);

    let (route, _) = root.read().projects[0].route(&root).unwrap();
    ferryman_channel::master::revoke_member(&route, &josh(), "ichabod-test", "retired").unwrap();
    // Another channel already knows the name under somebody else's key.
    let clash = root.comms_home("clash");
    fs::write(
        clash.join("agents").join("ichabod-test.json"),
        r#"{"name":"ichabod-test","role":"worker","capabilities":[],"public_key":"aa"}"#,
    )
    .unwrap();

    let asked = Cell::new(0);
    let done = enrol(
        &root,
        "ichabod-test",
        "worker",
        &worker().public_key_hex(),
        "josh",
        &mut as_josh(&asked),
    );
    let Enrolment::Skipped(revoked) = outcome(&done, "alpha") else {
        panic!("{done:?}")
    };
    assert!(revoked.contains("revoked"), "{revoked}");
    let Enrolment::Skipped(clashing) = outcome(&done, "clash") else {
        panic!("{done:?}")
    };
    assert!(clashing.contains("different key"), "{clashing}");
    assert_eq!(
        listed(&clash, "ichabod-test")
            .unwrap()
            .public_key
            .as_deref(),
        Some("aa"),
        "first key wins"
    );
}

#[test]
fn a_project_with_no_master_has_nobody_to_sign() {
    hermetic();
    let dir = tempfile::tempdir().unwrap();
    let root = Root::create(&dir.path().join("ferry")).unwrap();
    fs::create_dir_all(root.comms_home("bare")).unwrap();
    root.adopt("bare", &root.comms_home("bare"), None).unwrap();
    let asked = Cell::new(0);
    let done = enrol(
        &root,
        "ichabod-test",
        "worker",
        &worker().public_key_hex(),
        "josh",
        &mut as_josh(&asked),
    );
    assert_eq!(outcome(&done, "bare"), &Enrolment::NoMaster);
    assert_eq!(asked.get(), 0);
}

/// The point of it: one worker, started with its own config, serves every project it
/// is enrolled in, says why for the rest, and is the same identity with the same
/// engines in all of them.
#[test]
fn one_worker_serves_every_project_it_is_enrolled_in_under_its_own_config() {
    hermetic();
    let dir = tempfile::tempdir().unwrap();
    let root = Root::create(&dir.path().join("ferry")).unwrap();
    project(dir.path(), &root, "alpha", &josh(), true);
    project(dir.path(), &root, "delta", &josh(), true);
    project(dir.path(), &root, "gamma", &josh(), false);
    enrolled_everywhere(&root);
    let (route, _) = root.read().projects[1].route(&root).unwrap();
    assert_eq!(route.project_id, "delta");
    ferryman_channel::master::revoke_member(&route, &josh(), "ichabod-test", "gone").unwrap();
    // Enrolled nowhere.
    project(dir.path(), &root, "beta", &josh(), true);

    let (home, config) = home(
        dir.path(),
        "engines = [\"big\", \"small\"]\n\
         engine.big.command = \"claude\"\nengine.big.tier = \"build\"\n\
         engine.small.command = \"claude\"\nengine.small.tier = \"chore\"\n",
    );
    // A project's own agent.toml is not what this worker runs as.
    fs::write(
        AgentConfig::path(&attachment_of(dir.path(), "alpha")),
        "agent = \"someone-else\"\ncommand = \"other\"\n",
    )
    .unwrap();

    let (plan, identity) = plan_worker(&root, &home, &config).unwrap();
    let why = |id: &str| match &plan
        .rows
        .iter()
        .find(|row| row.project == id)
        .unwrap()
        .standing
    {
        Standing::Skips(why) => why.clone(),
        Standing::Serves { .. } => String::new(),
    };
    assert_eq!(plan.serving(), 1, "only alpha");
    assert!(why("beta").contains("not on its roster"), "{}", why("beta"));
    assert!(why("beta").contains("ferry team approve ichabod-test --all"));
    assert!(
        why("delta").contains("has not let 'ichabod-test' work"),
        "{}",
        why("delta")
    );
    assert!(
        why("gamma").contains("no checkout of gamma"),
        "{}",
        why("gamma")
    );
    assert_eq!(
        plan.rows[0].describe(&config),
        "would serve as ichabod-test with engines big (build) > small (chore)"
    );
    assert!(plan.rows[1].describe(&config).starts_with("not serving: "));
    // Planning wrote nothing: the checkout has no key yet.
    assert!(
        AgentIdentity::load_existing("ichabod-test", &attachment_of(dir.path(), "alpha"))
            .unwrap()
            .is_none()
    );

    let fleet = serve(plan, &identity, &config);
    assert_eq!(fleet.served.len(), 1);
    assert_eq!(fleet.skipped.len(), 3);
    let (served, used) = &fleet.served[0];
    assert_eq!(served.project_id, "alpha");
    assert_eq!(used.agent, "ichabod-test");
    assert_eq!(used.command, "claude");
    assert_eq!(used.engines.len(), 2);
    assert_eq!(used.max_parallel, 4);
    let seated = AgentIdentity::load_existing("ichabod-test", &attachment_of(dir.path(), "alpha"))
        .unwrap()
        .expect("the machine's own key was put in the checkout");
    assert_eq!(seated.public_key_hex(), worker().public_key_hex());
}

#[test]
fn a_worker_with_no_key_here_is_refused_before_anything_is_planned() {
    hermetic();
    let dir = tempfile::tempdir().unwrap();
    let root = Root::create(&dir.path().join("ferry")).unwrap();
    let (home, config) = home(dir.path(), "");
    fs::remove_file(home.join("keys").join("ichabod-test.key")).unwrap();
    let why = plan_worker(&root, &home, &config)
        .err()
        .unwrap()
        .to_string();
    assert!(why.contains("holds no key for 'ichabod-test'"), "{why}");
}

#[test]
fn a_checkout_holding_a_different_key_is_not_overwritten() {
    hermetic();
    let dir = tempfile::tempdir().unwrap();
    let root = Root::create(&dir.path().join("ferry")).unwrap();
    project(dir.path(), &root, "alpha", &josh(), true);
    enrolled_everywhere(&root);
    AgentIdentity::from_seed("ichabod-test", [1u8; 32])
        .seat_in(&attachment_of(dir.path(), "alpha"))
        .unwrap();
    let (home, config) = home(dir.path(), "");
    let (plan, _) = plan_worker(&root, &home, &config).unwrap();
    assert_eq!(plan.serving(), 0);
    let Standing::Skips(why) = &plan.rows[0].standing else {
        panic!("served")
    };
    assert!(why.contains("holds a different key"), "{why}");
}

#[test]
fn channels_with_no_checkout_beside_them_are_counted_for_the_hint() {
    let dir = tempfile::tempdir().unwrap();
    let channel = dir.path().join("a-ferryman");
    fs::create_dir_all(channel.join("agents")).unwrap();
    // A checkout, which `--comms` does watch.
    fs::create_dir_all(dir.path().join("b").join(".ferryman")).unwrap();
    // Neither.
    fs::create_dir_all(dir.path().join("notes")).unwrap();
    assert_eq!(bare_channels(dir.path()), 1);
}

fn route_of(root: &Root, id: &str) -> ProjectRoute {
    root.read()
        .projects
        .iter()
        .find(|entry| entry.project_id == id)
        .unwrap()
        .route(root)
        .unwrap()
        .0
}

/// A roster is a folder anyone in the project can write, so it is never where an
/// enrolment finds a key. The only key it takes unasked is this machine's own.
#[test]
fn the_only_key_taken_unasked_is_this_machines_own() {
    hermetic();
    let dir = tempfile::tempdir().unwrap();
    let root = Root::create(&dir.path().join("ferry")).unwrap();
    project(dir.path(), &root, "alpha", &josh(), true);
    project(dir.path(), &root, "beta", &josh(), true);
    enrolled_everywhere(&root);
    // A member of beta rewrites the entry to a key of their own.
    fs::write(
        root.comms_home("beta")
            .join("agents")
            .join("ichabod-test.json"),
        r#"{"name":"ichabod-test","role":"worker","capabilities":[],"public_key":"bb"}"#,
    )
    .unwrap();
    assert_eq!(
        machine_key(&root, None, "ichabod-test").unwrap(),
        None,
        "listed on rosters is not held here"
    );

    worker()
        .seat_in(&attachment_of(dir.path(), "alpha"))
        .unwrap();
    assert_eq!(
        machine_key(&root, None, "ichabod-test").unwrap(),
        Some(worker().public_key_hex())
    );
    assert_eq!(
        machine_key(
            &root,
            Some(&attachment_of(dir.path(), "beta")),
            "ichabod-test"
        )
        .unwrap(),
        Some(worker().public_key_hex())
    );

    AgentIdentity::from_seed("ichabod-test", [1u8; 32])
        .seat_in(&attachment_of(dir.path(), "beta"))
        .unwrap();
    let why = machine_key(&root, None, "ichabod-test")
        .unwrap_err()
        .to_string();
    assert!(why.contains("2 different keys"), "{why}");
}

#[test]
fn a_key_or_role_that_would_corrupt_a_grant_is_refused_before_anything_is_written() {
    hermetic();
    let key = worker().public_key_hex();
    assert!(check_enrolment("ichabod-test", "worker", &key).is_ok());
    assert!(check_enrolment("ichabod-test", "worker,orchestrator", &key).is_err());
    assert!(check_enrolment("ichabod-test", "worker\nx", &key).is_err());
    assert!(check_enrolment("../x", "worker", &key).is_err());
    assert!(check_enrolment("ichabod-test", "worker", "bb").is_err());
    assert!(check_enrolment("ichabod-test", "worker", &format!("{key}\nroles")).is_err());

    let dir = tempfile::tempdir().unwrap();
    let root = Root::create(&dir.path().join("ferry")).unwrap();
    project(dir.path(), &root, "alpha", &josh(), false);
    let asked = Cell::new(0);
    let done = enrol(
        &root,
        "ichabod-test",
        "worker,orchestrator",
        &key,
        "josh",
        &mut as_josh(&asked),
    );
    assert!(matches!(outcome(&done, "alpha"), Enrolment::Skipped(_)));
    assert_eq!(asked.get(), 0);
    assert!(!root.comms_home("alpha").join("grants").exists());
}

/// The master's name is not what authorises a grant; their key is. An identity called
/// `josh` that is not the key the project's roster knows `josh` by writes nothing.
#[test]
fn a_signer_that_is_not_the_masters_key_in_that_project_writes_nothing() {
    hermetic();
    let dir = tempfile::tempdir().unwrap();
    let root = Root::create(&dir.path().join("ferry")).unwrap();
    project(dir.path(), &root, "alpha", &josh(), false);
    let mut impostor = |_: &Entry, _: &str| -> Result<AgentIdentity> {
        Ok(AgentIdentity::from_seed("josh", [8u8; 32]))
    };
    let done = enrol(
        &root,
        "ichabod-test",
        "worker",
        &worker().public_key_hex(),
        "josh",
        &mut impostor,
    );
    let Enrolment::Skipped(why) = outcome(&done, "alpha") else {
        panic!("{done:?}")
    };
    assert!(why.contains("not the key"), "{why}");
    assert!(listed(&root.comms_home("alpha"), "ichabod-test").is_none());
    assert!(!root.comms_home("alpha").join("grants").exists());
}

/// A machine whose owner the master revoked is as revoked as the owner. A grant for it
/// would be honoured over that for any role but worker, so it is not written.
#[test]
fn a_machine_whose_owner_was_revoked_is_not_enrolled() {
    hermetic();
    let dir = tempfile::tempdir().unwrap();
    let root = Root::create(&dir.path().join("ferry")).unwrap();
    project(dir.path(), &root, "beta", &josh(), false);
    enrolled_everywhere(&root);
    let olive = AgentIdentity::from_seed("olive", [4u8; 32]);
    let route = route_of(&root, "beta");
    ferryman_channel::register_agent(
        &route,
        &AgentRoute {
            name: "olive".into(),
            role: "operator".into(),
            capabilities: Vec::new(),
            public_key: Some(olive.public_key_hex()),
            encryption_key: None,
        },
    )
    .unwrap();
    let route = route_of(&root, "beta");
    ferryman_channel::owner::attest_owner(
        &route,
        &olive,
        "ichabod-test",
        &worker().public_key_hex(),
    )
    .unwrap();
    ferryman_channel::master::revoke_member(&route, &josh(), "olive", "left").unwrap();

    let asked = Cell::new(0);
    let done = enrol(
        &root,
        "ichabod-test",
        "orchestrator",
        &worker().public_key_hex(),
        "josh",
        &mut as_josh(&asked),
    );
    let Enrolment::Skipped(why) = outcome(&done, "beta") else {
        panic!("{done:?}")
    };
    assert!(why.contains("its owner"), "{why}");
    assert_eq!(asked.get(), 0);
    let (route, _) = root.read().projects[0].route(&root).unwrap();
    assert!(
        !ferryman_channel::master::member_grants(&route)
            .unwrap()
            .iter()
            .any(|(grant, _)| grant.roles.iter().any(|role| role == "orchestrator")),
        "no grant for the revoked owner's machine"
    );
}

fn git(workspace: &Path, args: &[&str]) {
    let status = std::process::Command::new("git")
        .arg("-C")
        .arg(workspace)
        .args(args)
        .status()
        .unwrap();
    assert!(status.success(), "git {args:?}");
}

/// Seating puts a private key under the checkout. Where git would carry it into a
/// commit, it is not put there.
#[test]
fn a_key_is_not_seated_where_git_would_commit_it() {
    hermetic();
    let dir = tempfile::tempdir().unwrap();
    let root = Root::create(&dir.path().join("ferry")).unwrap();
    project(dir.path(), &root, "alpha", &josh(), true);
    enrolled_everywhere(&root);
    let workspace = dir.path().join("repos").join("alpha");
    git(&workspace, &["init", "-q"]);
    let (home, config) = home(dir.path(), "");

    let (plan, identity) = plan_worker(&root, &home, &config).unwrap();
    let Standing::Skips(why) = &plan.rows[0].standing else {
        panic!("served")
    };
    assert!(why.contains("does not git-ignore .ferryman"), "{why}");
    let fleet = serve(plan, &identity, &config);
    assert!(fleet.served.is_empty());
    assert!(
        AgentIdentity::load_existing("ichabod-test", &attachment_of(dir.path(), "alpha"))
            .unwrap()
            .is_none(),
        "no key was written"
    );

    fs::write(workspace.join(".gitignore"), "/.ferryman/\n").unwrap();
    let (plan, identity) = plan_worker(&root, &home, &config).unwrap();
    assert_eq!(plan.serving(), 1);
    let fleet = serve(plan, &identity, &config);
    assert_eq!(fleet.served.len(), 1);
    assert!(
        AgentIdentity::load_existing("ichabod-test", &attachment_of(dir.path(), "alpha"))
            .unwrap()
            .is_some()
    );
}

#[test]
fn a_name_that_cannot_be_a_file_name_is_refused_before_a_key_is_written_through_it() {
    hermetic();
    let dir = tempfile::tempdir().unwrap();
    let root = Root::create(&dir.path().join("ferry")).unwrap();
    let (home, mut config) = home(dir.path(), "");
    config.agent = "../../x".into();
    let why = plan_worker(&root, &home, &config)
        .err()
        .unwrap()
        .to_string();
    assert!(why.contains("not a name"), "{why}");
}

/// The manifest and the checkout must agree where the channel is, or a project is judged
/// in one folder and written to in the other.
#[test]
fn a_checkout_that_reads_a_different_channel_than_the_manifest_is_not_served() {
    hermetic();
    let dir = tempfile::tempdir().unwrap();
    let root = Root::create(&dir.path().join("ferry")).unwrap();
    project(dir.path(), &root, "alpha", &josh(), true);
    enrolled_everywhere(&root);
    let elsewhere = dir.path().join("elsewhere");
    fs::create_dir_all(&elsewhere).unwrap();
    let attachment = attachment_of(dir.path(), "alpha");
    fs::write(
        attachment.join("bridge.toml"),
        format!(
            "project = \"alpha\"\nworkspace = \"{}\"\nattachment = \"{}\"\n\
             communications = \"{}\"\n",
            attachment.parent().unwrap().display(),
            attachment.display(),
            elsewhere.display()
        ),
    )
    .unwrap();
    let (home, config) = home(dir.path(), "");
    let (plan, _) = plan_worker(&root, &home, &config).unwrap();
    let Standing::Skips(why) = &plan.rows[0].standing else {
        panic!("served")
    };
    assert!(why.contains("reads its channel from"), "{why}");
}

/// What was true when the worker started is not what is true weeks later.
#[test]
fn a_project_revoked_or_archived_after_the_worker_started_stops_being_served() {
    hermetic();
    let dir = tempfile::tempdir().unwrap();
    let root = Root::create(&dir.path().join("ferry")).unwrap();
    project(dir.path(), &root, "alpha", &josh(), true);
    project(dir.path(), &root, "delta", &josh(), true);
    enrolled_everywhere(&root);
    let (home, config) = home(dir.path(), "");
    let (plan, identity) = plan_worker(&root, &home, &config).unwrap();
    let fleet = serve(plan, &identity, &config);
    assert_eq!(fleet.served.len(), 2);
    for (route, config) in &fleet.served {
        assert_eq!(no_longer_served(route, config), None);
    }

    let (alpha, config) = &fleet.served[0];
    assert_eq!(alpha.project_id, "alpha");
    ferryman_channel::master::revoke_member(alpha, &josh(), "ichabod-test", "gone").unwrap();
    let why = no_longer_served(alpha, config).expect("revoked");
    assert!(why.contains("has not let"), "{why}");

    let (delta, config) = &fleet.served[1];
    root.archive("delta", true, &josh()).unwrap();
    assert_eq!(
        no_longer_served(delta, config).as_deref(),
        Some("it has been archived")
    );
}
