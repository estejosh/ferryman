//! A worker that is already running takes up a project another machine of the fleet created,
//! on the next pass, with no restart (ADR 0030). The loop's own steps, run the way the loop
//! runs them, against a root and a fleet folder built in a temporary directory.

use std::cell::RefCell;
use std::fs;
use std::path::Path;
use std::process::Command;

use ferryman_channel::ferry::Root;
use ferryman_channel::fleethome::{self as home, Advert, Facts, WorkerId};
use ferryman_channel::{AgentIdentity, AgentRoute, ProjectRoute};
use ferryman_ops::Progress;
use ferryman_ops::agent::AgentConfig;

use super::{Propagation, Reevaluate, take_newly_approved, told_at_startup};

/// Collects what the worker would say.
#[derive(Default)]
struct Said(RefCell<Vec<String>>);

impl Progress for Said {
    fn info(&self, message: &str) {
        self.0.borrow_mut().push(message.to_owned());
    }
    fn warn(&self, message: &str) {
        self.0.borrow_mut().push(format!("WARN {message}"));
    }
}

impl Said {
    fn has(&self, part: &str) -> bool {
        self.0.borrow().iter().any(|line| line.contains(part))
    }
}

fn git(dir: &Path, args: &[&str]) {
    let output = Command::new("git")
        .arg("-C")
        .arg(dir)
        .args(["-c", "user.name=t", "-c", "user.email=t@example.com"])
        .args(args)
        .output()
        .unwrap();
    assert!(output.status.success(), "git {args:?}");
}

fn copy_fleet(from: &Root, to: &Root) {
    fn walk(src: &Path, dst: &Path) {
        for entry in fs::read_dir(src).into_iter().flatten().flatten() {
            let name = entry.file_name();
            if name == "local" {
                continue;
            }
            let path = entry.path();
            if path.is_dir() {
                fs::create_dir_all(dst.join(&name)).unwrap();
                walk(&path, &dst.join(&name));
            } else {
                fs::create_dir_all(dst).unwrap();
                fs::copy(&path, dst.join(&name)).unwrap();
            }
        }
    }
    walk(&from.fleet_dir(), &to.fleet_dir());
}

#[tokio::test]
async fn a_project_another_machine_made_is_served_by_the_running_worker_on_the_next_pass() {
    ferryman_channel::ferry::isolate_root_search_for_this_thread();
    ferryman_channel::licensing::use_machine_state_dir_per_thread(
        std::env::temp_dir().join(format!("ferryman-cli-pickup-{}", std::process::id())),
    );
    let dir = tempfile::tempdir().unwrap();
    let josh = AgentIdentity::from_seed("josh", [7u8; 32]);
    let beastly_machine = AgentIdentity::from_seed("beastly-ferry", [11u8; 32]);
    let beastly_worker = AgentIdentity::from_seed("beastly-worker", [12u8; 32]);
    let worker = AgentIdentity::from_seed("grouchly-worker", [22u8; 32]);

    // beastly: the fleet's master made the fleet folder, admitted beastly, and a project
    // was made there.
    let b = Root::create(&dir.path().join("beastly").join("ferry")).unwrap();
    home::init(&b, &josh).unwrap();
    home::enrol(&b, &beastly_machine).unwrap();
    home::admit(&b, &josh, "beastly-ferry", "beastly").unwrap();
    let channel = b.comms_home("snifrig");
    fs::create_dir_all(&channel).unwrap();
    let workspace = dir.path().join("beastly").join("snifrig");
    fs::create_dir_all(&workspace).unwrap();
    git(&workspace, &["init", "-q", "-b", "main"]);
    let master_entry = AgentRoute {
        name: "josh".into(),
        role: "operator".into(),
        capabilities: Vec::new(),
        public_key: Some(josh.public_key_hex()),
        encryption_key: None,
    };
    let route = ProjectRoute {
        project_id: "snifrig".into(),
        workspace: workspace.clone(),
        attachment: workspace.join(".ferryman"),
        communications: channel.clone(),
        shared_remote: "snifrig-ferryman".into(),
        git_remote: String::new(),
        git_visibility: String::new(),
        agents: vec![master_entry.clone()],
    };
    ferryman_channel::register_agent(&route, &master_entry).unwrap();
    ferryman_channel::master::initialize_master(&route, &josh, "josh").unwrap();
    b.adopt("snifrig", &channel, Some(&workspace)).unwrap();
    // The remote beastly's clone came from, where grouchly can reach it.
    let seed = dir.path().join("seed");
    fs::create_dir_all(&seed).unwrap();
    git(&seed, &["init", "-q", "-b", "main"]);
    fs::write(seed.join("README.md"), "hi").unwrap();
    git(&seed, &["add", "-A"]);
    git(&seed, &["commit", "-q", "-m", "first"]);
    let adverts = std::collections::BTreeMap::from([(
        "snifrig".to_owned(),
        Advert {
            git_remote: Some(seed.display().to_string()),
            master: Some("josh".into()),
        },
    )]);
    home::publish_directory_with(&b, "beastly", &beastly_machine, &adverts).unwrap();
    home::publish_machine(
        &b,
        "beastly",
        &beastly_machine,
        &Facts {
            version: "0.6.2".into(),
            worker: Some(WorkerId {
                name: beastly_worker.name().into(),
                public_key: beastly_worker.public_key_hex(),
            }),
            ..Facts::default()
        },
    )
    .unwrap();

    // grouchly: the same fleet folder arrived by sync; its all-projects worker is running
    // and serves nothing yet.
    let g = Root::create(&dir.path().join("grouchly").join("ferry")).unwrap();
    copy_fleet(&b, &g);
    let home_dir = dir.path().join("grouchly").join("home").join(".ferryman");
    fs::create_dir_all(&home_dir).unwrap();
    worker.seat_in(&home_dir).unwrap();
    fs::write(
        AgentConfig::path(&home_dir),
        "agent = \"grouchly-worker\"\ncommand = \"claude\"\nmax_parallel = \"2\"\n",
    )
    .unwrap();
    let config = AgentConfig::load(&home_dir).unwrap();
    let (plan, identity) = ferryman_ops::fleet::plan_worker(&g, &home_dir, &config).unwrap();
    let mut fleet = ferryman_ops::fleet::serve(plan, &identity, &config);
    assert!(fleet.served.is_empty());
    let reevaluate = Reevaluate {
        root: g.clone(),
        home: home_dir.clone(),
        config: config.clone(),
    };
    let mut told = told_at_startup(&reevaluate, &fleet);
    let mut locks = Vec::new();
    let mut propagation = Propagation::default();
    let said = Said::default();

    // One pass of the loop's own steps: the arrival is filed and cloned, then the re-plan
    // serves it. The worker is not restarted anywhere in this.
    ferryman_ops::fleet::refresh_rosters(&mut fleet.served);
    propagation.run(&reevaluate, &said).await;
    take_newly_approved(&reevaluate, &mut fleet, &mut locks, &mut told, None, &said);

    let served: Vec<&str> = fleet
        .served
        .iter()
        .map(|(route, _)| route.project_id.as_str())
        .collect();
    assert_eq!(served, vec!["snifrig"], "said: {:?}", said.0.borrow());
    assert_eq!(locks.len(), 1);
    assert!(said.has("snifrig arrived from beastly: filed, cloning"));
    assert!(said.has("now serving snifrig"));
    let entry = g.read().projects.into_iter().next().unwrap();
    assert_eq!(entry.repo, Some(g.managed_clone_of("snifrig")));
    assert!(g.managed_clone_of("snifrig").join("README.md").is_file());

    // A pass later there is nothing new to say, and nothing is done twice.
    let before = said.0.borrow().len();
    propagation.run(&reevaluate, &said).await;
    take_newly_approved(&reevaluate, &mut fleet, &mut locks, &mut told, None, &said);
    assert_eq!(fleet.served.len(), 1);
    assert_eq!(said.0.borrow().len(), before, "{:?}", said.0.borrow());
}

/// A project that appears after the worker started and is not open to it is SAID, once. It
/// used to be recorded without a word, so a project the worker was not serving looked like one
/// it had not noticed.
#[test]
fn a_project_that_appears_after_the_worker_started_and_is_not_open_yet_is_named_once() {
    ferryman_channel::ferry::isolate_root_search_for_this_thread();
    ferryman_channel::licensing::use_machine_state_dir_per_thread(
        std::env::temp_dir().join(format!("ferryman-cli-pickup-said-{}", std::process::id())),
    );
    let dir = tempfile::tempdir().unwrap();
    let root = Root::create(&dir.path().join("ferry")).unwrap();
    let worker = AgentIdentity::from_seed("w-worker", [22u8; 32]);
    let home_dir = dir.path().join("home").join(".ferryman");
    fs::create_dir_all(&home_dir).unwrap();
    worker.seat_in(&home_dir).unwrap();
    fs::write(
        AgentConfig::path(&home_dir),
        "agent = \"w-worker\"\ncommand = \"claude\"\nmax_parallel = \"2\"\n",
    )
    .unwrap();
    let config = AgentConfig::load(&home_dir).unwrap();
    let (plan, identity) = ferryman_ops::fleet::plan_worker(&root, &home_dir, &config).unwrap();
    let mut fleet = ferryman_ops::fleet::serve(plan, &identity, &config);
    let reevaluate = Reevaluate {
        root: root.clone(),
        home: home_dir,
        config,
    };
    let mut told = told_at_startup(&reevaluate, &fleet);
    assert!(told.is_empty());

    // A channel is filed with no checkout.
    let channel = root.comms_home("late");
    fs::create_dir_all(&channel).unwrap();
    root.adopt("late", &channel, None).unwrap();
    let said = Said::default();
    let mut locks = Vec::new();
    take_newly_approved(&reevaluate, &mut fleet, &mut locks, &mut told, None, &said);
    assert!(
        said.has("late: not serving yet - no checkout of late"),
        "{:?}",
        said.0.borrow()
    );
    take_newly_approved(&reevaluate, &mut fleet, &mut locks, &mut told, None, &said);
    assert_eq!(said.0.borrow().len(), 1, "once: {:?}", said.0.borrow());
}
