use super::*;
use crate::machine::{self, Worker};
use ferryman_channel::{AgentIdentity, AgentRoute, ProjectRoute};

fn hermetic() {
    ferryman_channel::licensing::use_machine_state_dir_per_thread(
        std::env::temp_dir().join(format!("ferryman-setup-selftest-{}", std::process::id())),
    );
}

fn josh() -> AgentIdentity {
    AgentIdentity::from_seed("josh", [7u8; 32])
}

fn filed(root: &Root, id: &str) -> PathBuf {
    let channel = root.comms_home(id);
    fs::create_dir_all(&channel).unwrap();
    let master = josh();
    let route = ProjectRoute {
        project_id: id.into(),
        workspace: channel.clone(),
        attachment: channel.clone(),
        communications: channel.clone(),
        shared_remote: format!("{id}-ferryman"),
        git_remote: String::new(),
        git_visibility: String::new(),
        agents: Vec::new(),
    };
    ferryman_channel::register_agent(
        &route,
        &AgentRoute {
            name: "josh".into(),
            role: "operator".into(),
            capabilities: Vec::new(),
            public_key: Some(master.public_key_hex()),
            encryption_key: None,
        },
    )
    .unwrap();
    let route = ProjectRoute {
        agents: ferryman_channel::read_agent_roster(&channel).unwrap(),
        ..route
    };
    ferryman_channel::master::initialize_master(&route, &master, "josh").unwrap();
    root.adopt(id, &channel, None).unwrap();
    channel
}

fn git(dir: &Path, args: &[&str]) {
    let output = Command::new("git")
        .arg("-C")
        .arg(dir)
        .args(["-c", "user.name=t", "-c", "user.email=t@example.com"])
        // No background maintenance: after a push, git can start `maintenance run
        // --auto` detached in the bare repo, and the lock it later removes made the
        // dry-run snapshot differ by a file Ferryman never touched (flaky on Linux/macOS).
        .args(["-c", "maintenance.auto=false", "-c", "gc.auto=0"])
        .args(["-c", "receive.autoGc=false"])
        .args(args)
        .output()
        .unwrap();
    assert!(
        output.status.success(),
        "git {args:?}: {}",
        String::from_utf8_lossy(&output.stderr)
    );
}

fn origin(dir: &Path, name: &str) -> PathBuf {
    let bare = dir.join("origins").join(format!("{name}.git"));
    fs::create_dir_all(&bare).unwrap();
    git(&bare, &["init", "--bare", "-q", "-b", "main"]);
    let seed = dir.join("seeds").join(name);
    fs::create_dir_all(&seed).unwrap();
    git(&seed, &["init", "-q", "-b", "main"]);
    fs::write(seed.join("README.md"), "hello").unwrap();
    git(&seed, &["add", "-A"]);
    git(&seed, &["commit", "-q", "-m", "first"]);
    git(&seed, &["push", "-q", bare.to_str().unwrap(), "main"]);
    bare
}

fn template(dir: &Path) -> String {
    format!("{}/{{project}}.git", dir.join("origins").display())
}

struct Machine {
    dir: tempfile::TempDir,
    root: Root,
}

fn machine_with(projects: &[&str]) -> Machine {
    hermetic();
    let dir = tempfile::tempdir().unwrap();
    let root = Root::create_with_layout(&dir.path().join("ferry"), 1).unwrap();
    for project in projects {
        filed(&root, project);
        origin(dir.path(), project);
    }
    Machine { dir, root }
}

fn options(machine: &Machine) -> Options {
    Options {
        identity: Some("ichabod-test-swarm".into()),
        home: None,
        retire: Vec::new(),
        exclude: Vec::new(),
        remote_template: Some(template(machine.dir.path())),
        seat: Vec::new(),
        dry_run: false,
        service: false,
        with_syncthing: false,
        no_fetch: false,
        ferry: PathBuf::from("/opt/ferry/ferry"),
        platform: Platform::Linux,
        user_home: machine.dir.path().join("home"),
        user: "josh".into(),
    }
}

fn spec() -> Spec {
    Spec {
        ferry: PathBuf::from("/opt/ferry/ferry"),
        workspace: PathBuf::from("/srv/ferry/repos/ferryman"),
        env_file: PathBuf::from("/srv/ferry/service/worker.env"),
        user: "josh".into(),
    }
}

type Log = std::rc::Rc<std::cell::RefCell<Vec<String>>>;

fn recorder() -> (Log, impl FnMut(&str, &[String]) -> Option<String>) {
    let log = std::rc::Rc::new(std::cell::RefCell::new(Vec::new()));
    let inner = log.clone();
    (log, move |program: &str, args: &[String]| {
        inner
            .borrow_mut()
            .push(format!("{program} {}", args.join(" ")));
        Some(String::new())
    })
}

fn unit_worker(name: &str, user: bool, identity: &str) -> Worker {
    Worker {
        kind: machine::Kind::Unit {
            unit: name.into(),
            file: PathBuf::from(format!("/nonexistent/{name}")),
            user,
            enabled: true,
            active: true,
            pid: Some(1),
        },
        all_projects: true,
        identity: Some(identity.into()),
        command: "ferry agent run --all-projects".into(),
    }
}

fn snapshot(dir: &Path) -> Vec<(PathBuf, Vec<u8>)> {
    fn walk(dir: &Path, out: &mut Vec<(PathBuf, Vec<u8>)>) {
        let Ok(entries) = fs::read_dir(dir) else {
            return;
        };
        for entry in entries.flatten() {
            let path = entry.path();
            if path.is_dir() {
                walk(&path, out);
            } else {
                out.push((path.clone(), fs::read(&path).unwrap_or_default()));
            }
        }
    }
    let mut out = Vec::new();
    walk(dir, &mut out);
    out.sort();
    out
}

#[test]
fn the_systemd_unit_is_one_worker_with_limits_and_no_inline_secrets() {
    let text = systemd_unit(&spec(), true);
    for needle in [
        "Restart=on-failure",
        "MemoryMax=",
        "CPUQuota=",
        "TasksMax=",
        "EnvironmentFile=-/srv/ferry/service/worker.env",
        "\nWorkingDirectory=/srv/ferry/repos/ferryman\n",
        "agent run --all-projects --workspace",
        "ferryman-syncthing.service",
    ] {
        assert!(text.contains(needle), "missing {needle}:\n{text}");
    }
    assert!(!text.contains("API_KEY"), "{text}");
    // Doctor reads it back as the one all-projects worker.
    let (found, _) = machine::unit_worker(&text).expect("the unit runs a worker");
    assert!(found.all_projects);
    assert_eq!(
        found.workspace.as_deref(),
        Some("/srv/ferry/repos/ferryman")
    );
}

#[test]
fn syncthing_has_a_unit_of_its_own_that_is_not_a_worker() {
    let text = systemd_syncthing_unit(&spec());
    assert!(text.contains("syncthing run"));
    assert!(text.contains("Restart=on-failure"));
    assert!(machine::unit_worker(&text).is_none());
}

#[test]
fn the_windows_wrapper_loads_its_environment_from_a_file_and_is_read_as_the_worker() {
    let mut spec = spec();
    spec.ferry = PathBuf::from(r"C:\Program Files\ferry\ferry.exe");
    spec.workspace = PathBuf::from(r"X:\ferry\repos\ferryman");
    spec.env_file = PathBuf::from(r"X:\ferry\service\worker.env");
    let text = windows_wrapper(
        &spec,
        "agent run --all-projects --workspace 'X:\\ferry\\repos\\ferryman'",
    );
    assert!(
        text.contains(r"$envFile = 'X:\ferry\service\worker.env'"),
        "{text}"
    );
    assert!(text.contains("SetEnvironmentVariable"));
    assert!(text.contains("exit $LASTEXITCODE"));
    // The worker reads this to know a failing exit will be restarted (the update restart).
    assert!(text.contains("$env:FERRYMAN_SUPERVISED"), "{text}");
    assert!(!text.contains("API_KEY"));
    let (found, _) = machine::invocation_in_text(&text).expect("the wrapper runs a worker");
    assert!(found.all_projects);
}

fn wrapper_before_0_6_2() -> String {
    let current = windows_wrapper(&spec(), "agent run --all-projects");
    let old: String = current
        .split_inclusive("\r\n")
        .filter(|line| !line.contains("FERRYMAN_SUPERVISED") && !line.contains("EX_TEMPFAIL"))
        .filter(|line| !line.contains("The task restarts a failing exit"))
        .collect();
    assert!(!old.contains("FERRYMAN_SUPERVISED"));
    old
}

#[test]
fn a_wrapper_written_before_the_worker_could_ask_to_restart_is_marked_in_place() {
    let old = wrapper_before_0_6_2();
    let marked = mark_wrapper(&old).expect("an old wrapper is marked");
    assert!(
        marked.contains("$env:FERRYMAN_SUPERVISED = 'task'\r\n"),
        "{marked}"
    );
    // Exactly one line added after the git prompt line; the rest is byte for byte.
    let without: String = marked
        .split_inclusive("\r\n")
        .filter(|line| {
            !line.contains("FERRYMAN_SUPERVISED") && !line.starts_with("# The worker stops")
        })
        .collect();
    assert_eq!(without, old);
    // Marking is idempotent, and still reads as the worker.
    assert_eq!(mark_wrapper(&marked), None);
    assert!(machine::invocation_in_text(&marked).is_some());
    // Something that is not our wrapper is left alone.
    assert_eq!(mark_wrapper("Write-Host hello\r\n"), None);
}

#[test]
fn the_existing_wrapper_on_disk_is_refreshed_once_and_the_old_one_kept() {
    let dir = tempfile::tempdir().unwrap();
    let root = Root::create_with_layout(&dir.path().join("ferry"), 1).unwrap();
    assert!(
        !refresh_worker_wrapper(&root).unwrap(),
        "no wrapper, nothing to do"
    );
    let service = root.path.join("service");
    fs::create_dir_all(&service).unwrap();
    let path = service.join(WORKER_WRAPPER);
    fs::write(&path, ps_bytes(&wrapper_before_0_6_2())).unwrap();
    assert!(refresh_worker_wrapper(&root).unwrap());
    let bytes = fs::read(&path).unwrap();
    assert!(
        bytes.starts_with(&[0xEF, 0xBB, 0xBF]),
        "the byte-order mark stays"
    );
    assert!(
        String::from_utf8(bytes)
            .unwrap()
            .contains("FERRYMAN_SUPERVISED")
    );
    assert!(
        service
            .join("ferryman-worker.ps1.before-supervised")
            .is_file()
    );
    assert!(
        !refresh_worker_wrapper(&root).unwrap(),
        "the second time changes nothing"
    );
}

#[test]
fn the_task_wrapper_is_recognised_among_a_processs_ancestors_by_its_command_line() {
    let args = |parts: &[&str]| parts.iter().map(|p| (*p).to_owned()).collect::<Vec<_>>();
    assert!(is_worker_wrapper_cmd(&args(&[
        "powershell.exe",
        "-NoProfile",
        "-File",
        r"X:\ferry\service\ferryman-worker.ps1"
    ])));
    assert!(is_worker_wrapper_cmd(&args(&[
        r#""X:\ferry\service\FERRYMAN-WORKER.PS1""#
    ])));
    // The Syncthing task's wrapper, a person's shell and an editor are not it.
    assert!(!is_worker_wrapper_cmd(&args(&[
        "powershell.exe",
        "-File",
        r"X:\ferry\service\ferryman-syncthing.ps1"
    ])));
    assert!(!is_worker_wrapper_cmd(&args(&["pwsh.exe"])));
    // This test process's parents are cargo and a shell, never the wrapper.
    assert!(!under_worker_wrapper());
}

#[test]
fn the_task_restarts_on_failure_and_runs_the_wrapper_not_ferry_directly() {
    let xml = task_xml(
        &spec(),
        "worker",
        Path::new(r"X:\ferry\service\ferryman-worker.ps1"),
    );
    assert!(xml.contains("<RestartOnFailure>"));
    assert!(xml.contains("<ExecutionTimeLimit>PT0S</ExecutionTimeLimit>"));
    assert!(xml.contains("-File \"X:\\ferry\\service\\ferryman-worker.ps1\""));
    assert!(xml.contains("<MultipleInstancesPolicy>IgnoreNew</MultipleInstancesPolicy>"));
    assert!(
        !xml.contains("--all-projects"),
        "no command line, and so no secret, inline"
    );
    let bytes = utf16_le(&xml);
    assert_eq!(&bytes[..2], &[0xFF, 0xFE]);
}

#[test]
fn a_dry_run_changes_nothing_and_still_prints_the_masters_lines() {
    let machine = machine_with(&["quantly"]);
    let mut opts = options(&machine);
    opts.dry_run = true;
    opts.service = true;
    let before = snapshot(machine.dir.path());
    let (log, mut run) = recorder();
    let report = setup(&machine.root, &opts, &machine::Scan::default(), &mut run).unwrap();
    assert_eq!(
        before,
        snapshot(machine.dir.path()),
        "a dry run writes nothing"
    );
    assert!(
        log.borrow().is_empty(),
        "and runs nothing: {:?}",
        log.borrow()
    );
    assert!(
        report
            .signing
            .iter()
            .any(|line| line.starts_with("ferry team approve ichabod-test-swarm --all")),
        "{:?}",
        report.signing
    );
    assert!(report.render().contains("dry run: nothing was written"));
}

#[test]
fn setup_makes_the_layout_the_clone_and_the_identity_and_is_safe_to_repeat() {
    let machine = machine_with(&["quantly"]);
    let opts = options(&machine);
    let mut run = |_: &str, _: &[String]| None;
    let report = setup(&machine.root, &opts, &machine::Scan::default(), &mut run).unwrap();
    for folder in [
        machine.root.comms(),
        machine.root.repos(),
        machine.root.work(),
    ] {
        assert!(folder.is_dir(), "{}", folder.display());
    }
    let clone = machine.root.managed_clone("quantly");
    assert!(clone.join(".git").exists());
    let attachment = clone.join(".ferryman");
    assert!(
        attachment.join("agent.toml").is_file(),
        "{:?}",
        report.identity_lines
    );
    let first = AgentIdentity::load_existing("ichabod-test-swarm", &attachment)
        .unwrap()
        .expect("a key")
        .public_key_hex();
    let config = AgentConfig::load(&attachment).unwrap();
    assert_eq!(config.agent, "ichabod-test-swarm");
    // Nothing was enrolled: the roster of the channel does not know the new name.
    let roster = ferryman_channel::read_agent_roster(&machine.root.comms_home("quantly")).unwrap();
    assert!(
        !roster.iter().any(|a| a.name == "ichabod-test-swarm"),
        "{roster:?}"
    );

    let text = fs::read_to_string(attachment.join("agent.toml")).unwrap();
    setup(&machine.root, &opts, &machine::Scan::default(), &mut run).unwrap();
    assert_eq!(
        text,
        fs::read_to_string(attachment.join("agent.toml")).unwrap()
    );
    let again = AgentIdentity::load_existing("ichabod-test-swarm", &attachment)
        .unwrap()
        .unwrap()
        .public_key_hex();
    assert_eq!(first, again, "the key is reused, never replaced");
}

#[test]
fn a_seat_option_lists_the_connector_and_seats_it_where_the_machine_holds_its_key() {
    let machine = machine_with(&["quantly"]);
    let store = ferryman_channel::licensing::machine_state_dir().unwrap();
    let connector = AgentIdentity::from_seed("claude-ai-josh", [61u8; 32]);
    connector.seat_in(&store).unwrap();
    let mut opts = options(&machine);
    opts.seat = vec!["claude-ai-josh".into(), "claude-ai-nobody".into()];
    let mut run = |_: &str, _: &[String]| None;

    // A dry run says what it would do and writes neither the list nor a key.
    opts.dry_run = true;
    let dry = setup(&machine.root, &opts, &machine::Scan::default(), &mut run).unwrap();
    assert!(
        dry.seated.iter().any(|line| line.contains("would seat")),
        "{:?}",
        dry.seated
    );
    assert!(
        rootconfig::RootConfig::load(&machine.root)
            .seat_agents
            .is_empty()
    );

    opts.dry_run = false;
    let report = setup(&machine.root, &opts, &machine::Scan::default(), &mut run).unwrap();
    assert_eq!(
        rootconfig::RootConfig::load(&machine.root).seat_agents,
        vec!["claude-ai-josh".to_owned(), "claude-ai-nobody".to_owned()]
    );
    let attachment = machine.root.managed_clone("quantly").join(".ferryman");
    let seated = AgentIdentity::load_existing("claude-ai-josh", &attachment)
        .unwrap()
        .expect("seated from the machine key store");
    assert_eq!(seated.public_key_hex(), connector.public_key_hex());
    // A name with no key here is said so, and nothing is made for it.
    assert!(
        AgentIdentity::load_existing("claude-ai-nobody", &attachment)
            .unwrap()
            .is_none()
    );
    assert!(
        report
            .seated
            .iter()
            .any(|line| line.contains("claude-ai-nobody") && line.contains("no key")),
        "{:?}",
        report.seated
    );
}

#[test]
fn without_service_nothing_is_installed_or_turned_off() {
    let machine = machine_with(&["quantly"]);
    let opts = options(&machine);
    let (log, mut run) = recorder();
    let scan = machine::Scan {
        workers: vec![unit_worker("ferryman-ichabod.service", true, "old-swarm")],
        notes: Vec::new(),
    };
    let report = setup(&machine.root, &opts, &scan, &mut run).unwrap();
    assert!(log.borrow().is_empty(), "{:?}", log.borrow());
    assert!(!opts.user_home.join(".config/systemd/user").exists());
    assert!(report.service.iter().any(|l| l.contains("--service")));
}

#[test]
fn the_service_replaces_the_others_by_disabling_them_and_keeping_a_copy() {
    let machine = machine_with(&["quantly"]);
    let mut opts = options(&machine);
    opts.service = true;
    // The old unit exists on disk, so it can be backed up.
    let old = machine
        .dir
        .path()
        .join("home/.config/systemd/user/ferryman-ichabod.service");
    fs::create_dir_all(old.parent().unwrap()).unwrap();
    fs::write(
        &old,
        "[Service]\nExecStart=/x/ferry agent run --all-projects\n",
    )
    .unwrap();
    let mut old_worker = unit_worker("ferryman-ichabod.service", true, "old-swarm");
    if let machine::Kind::Unit { file, .. } = &mut old_worker.kind {
        file.clone_from(&old);
    }
    let system = unit_worker("ferryman-system.service", false, "sys-swarm");
    let scan = machine::Scan {
        workers: vec![old_worker, system],
        notes: Vec::new(),
    };
    let (log, mut run) = recorder();
    let report = setup(&machine.root, &opts, &scan, &mut run).unwrap();
    let log = log.borrow().clone();

    assert!(old.is_file(), "the old unit is disabled, never deleted");
    let backups = machine.root.path.join("service/backup");
    assert!(
        snapshot(&backups)
            .iter()
            .any(|(path, bytes)| path.ends_with("ferryman-ichabod.service") && !bytes.is_empty()),
        "a copy was kept"
    );
    assert!(
        log.contains(&"systemctl --user disable --now ferryman-ichabod.service".to_string()),
        "{log:?}"
    );
    assert!(
        log.contains(&"systemctl --user enable --now ferryman-worker.service".to_string()),
        "{log:?}"
    );
    // The system-wide unit needs elevation: printed, not attempted.
    assert!(
        !log.iter().any(|l| l.contains("ferryman-system.service")),
        "{log:?}"
    );
    assert!(
        report
            .manual
            .iter()
            .any(|l| l.contains("sudo systemctl disable --now ferryman-system.service")),
        "{:?}",
        report.manual
    );
    let unit = opts
        .user_home
        .join(".config/systemd/user/ferryman-worker.service");
    let text = fs::read_to_string(unit).unwrap();
    assert!(
        text.contains("repos/quantly") || text.contains("repos\\\\quantly"),
        "{text}"
    );
    // The master's lines name both retired identities.
    for name in ["old-swarm", "sys-swarm"] {
        assert!(
            report
                .signing
                .iter()
                .any(|l| l.starts_with(&format!("ferry team revoke --name {name} --all"))),
            "{:?}",
            report.signing
        );
    }
}

#[test]
fn a_running_process_is_never_stopped_and_holds_the_service_back() {
    let machine = machine_with(&["quantly"]);
    let mut opts = options(&machine);
    opts.service = true;
    let scan = machine::Scan {
        workers: vec![Worker {
            kind: machine::Kind::Process { pid: 4242 },
            all_projects: true,
            identity: Some("old-swarm".into()),
            command: "ferry agent run --all-projects".into(),
        }],
        notes: Vec::new(),
    };
    let (log, mut run) = recorder();
    let report = setup(&machine.root, &opts, &scan, &mut run).unwrap();
    let log = log.borrow().clone();
    assert!(!log.iter().any(|l| l.contains("kill")), "{log:?}");
    assert!(
        log.contains(&"systemctl --user enable ferryman-worker.service".to_string()),
        "{log:?}"
    );
    assert!(!log.contains(&"systemctl --user enable --now ferryman-worker.service".to_string()));
    assert!(
        report
            .manual
            .iter()
            .any(|l| l.contains("kill 4242") || l.contains("taskkill")),
        "{:?}",
        report.manual
    );
}

#[test]
fn the_env_file_is_made_once_and_never_overwritten() {
    let machine = machine_with(&["quantly"]);
    let mut opts = options(&machine);
    opts.service = true;
    let (_log, mut run) = recorder();
    setup(&machine.root, &opts, &machine::Scan::default(), &mut run).unwrap();
    let env = machine.root.path.join("service/worker.env");
    let stub = fs::read_to_string(&env).unwrap();
    assert!(
        stub.lines()
            .all(|l| l.starts_with('#') || l.trim().is_empty()),
        "{stub}"
    );
    fs::write(&env, "OPENROUTER_API_KEY=placeholder\n").unwrap();
    setup(&machine.root, &opts, &machine::Scan::default(), &mut run).unwrap();
    assert_eq!(
        fs::read_to_string(&env).unwrap(),
        "OPENROUTER_API_KEY=placeholder\n"
    );
}

#[test]
fn on_windows_it_writes_a_wrapper_and_a_task_and_disables_the_old_task() {
    let machine = machine_with(&["quantly"]);
    let mut opts = options(&machine);
    opts.service = true;
    opts.platform = Platform::Windows;
    opts.ferry = PathBuf::from(r"C:\ferry\ferry.exe");
    let scan = machine::Scan {
        workers: vec![Worker {
            kind: machine::Kind::Task {
                name: r"\Ferry Ichabod".into(),
                enabled: true,
                running: false,
                scripts: Vec::new(),
            },
            all_projects: true,
            identity: Some("old-swarm".into()),
            command: "ferry agent run --all-projects".into(),
        }],
        notes: Vec::new(),
    };
    let (log, mut run) = recorder();
    let report = setup(&machine.root, &opts, &scan, &mut run).unwrap();
    let log = log.borrow().clone();
    let service = machine.root.path.join("service");
    assert!(service.join("ferryman-worker.ps1").is_file());
    assert!(service.join("Ferryman_Worker.xml").is_file());
    let xml = fs::read(service.join("Ferryman_Worker.xml")).unwrap();
    assert_eq!(&xml[..2], &[0xFF, 0xFE]);
    assert!(
        log.iter()
            .any(|l| l.starts_with("schtasks /Change /TN \\Ferry Ichabod /DISABLE")),
        "{log:?}"
    );
    assert!(
        log.iter()
            .any(|l| l.starts_with("schtasks /Create /TN Ferryman Worker /XML")),
        "{log:?}"
    );
    assert!(
        log.iter().any(|l| l == "schtasks /Run /TN Ferryman Worker"),
        "{log:?}"
    );
    assert!(
        report.disabled.iter().any(|l| l.contains("not deleted")),
        "{:?}",
        report.disabled
    );
    assert!(
        fs::read_to_string(service.join("ferryman-worker.ps1"))
            .unwrap()
            .contains("repos"),
        "the wrapper runs in the managed clone"
    );
}

#[test]
fn an_exclusion_is_written_locally_and_the_signed_flag_is_printed_not_signed() {
    let machine = machine_with(&["quantly", "pc-secrets"]);
    let mut opts = options(&machine);
    opts.exclude = vec!["pc-secrets".into()];
    let mut run = |_: &str, _: &[String]| None;
    let report = setup(&machine.root, &opts, &machine::Scan::default(), &mut run).unwrap();
    assert!(rootconfig::RootConfig::load(&machine.root).excluded("pc-secrets"));
    assert!(
        !machine.root.managed_clone("pc-secrets").exists(),
        "an excluded project is not cloned"
    );
    assert!(machine.root.managed_clone("quantly").join(".git").exists());
    assert!(
        report
            .signing
            .iter()
            .any(|l| l.starts_with("ferry root swarm off --project pc-secrets")),
        "{:?}",
        report.signing
    );
    // Not signed: the channel has no SWARM file.
    assert!(!machine.root.comms_home("pc-secrets").join("SWARM").exists());
}

#[test]
fn an_agent_config_and_key_in_a_persons_checkout_are_copied_not_moved() {
    let machine = machine_with(&["quantly"]);
    // A person's working copy of the project, with the swarm's config and key in it.
    let human = machine.dir.path().join("human/quantly");
    fs::create_dir_all(human.parent().unwrap()).unwrap();
    let bare = machine.dir.path().join("origins/quantly.git");
    git(
        machine.dir.path(),
        &[
            "clone",
            "-q",
            bare.to_str().unwrap(),
            human.to_str().unwrap(),
        ],
    );
    let attachment = human.join(".ferryman");
    fs::create_dir_all(&attachment).unwrap();
    fs::write(
        attachment.join("agent.toml"),
        AgentConfig::render(
            "old-swarm",
            "worker",
            "claude",
            &AgentConfig::default_args("claude"),
            crate::agent::ReviewMode::Confirm,
            None,
            true,
        ),
    )
    .unwrap();
    let held = AgentIdentity::load_or_create("old-swarm", &attachment).unwrap();
    machine
        .root
        .adopt("quantly", &machine.root.comms_home("quantly"), Some(&human))
        .unwrap();
    let mut opts = options(&machine);
    opts.identity = None;
    opts.remote_template = None;
    let mut run = |_: &str, _: &[String]| None;
    let report = setup(&machine.root, &opts, &machine::Scan::default(), &mut run).unwrap();
    assert_eq!(report.identity, "old-swarm", "{:?}", report.identity_lines);
    let managed = machine.root.managed_clone("quantly").join(".ferryman");
    let copied = AgentIdentity::load_existing("old-swarm", &managed)
        .unwrap()
        .expect("seated");
    assert_eq!(copied.public_key_hex(), held.public_key_hex());
    assert!(
        attachment.join("agent.toml").is_file(),
        "the original stays"
    );
    assert!(
        AgentIdentity::load_existing("old-swarm", &attachment)
            .unwrap()
            .is_some()
    );
    assert_eq!(machine.root.read().projects[0].human_checkouts.len(), 1);
}

#[test]
fn quoting_keeps_a_path_inside_its_quotes_in_a_unit_and_in_a_script() {
    // systemd: `$` and `%` would otherwise expand; a quote or a backslash would end the string.
    let quoted = unit_quote(Path::new("/srv/a$HOME/b%h/c\"d\\e"));
    assert_eq!(quoted, "\"/srv/a$$HOME/b%%h/c\\\"d\\\\e\"");
    assert_eq!(unit_path(Path::new("/srv/50%/x")), "/srv/50%%/x");
    // PowerShell: the typographic single quotes end a string too.
    assert_eq!(ps_quote("it's"), "'it''s'");
    assert_eq!(
        ps_quote("a\u{2019}; calc; \u{2018}b"),
        "'a\u{2019}\u{2019}; calc; \u{2018}\u{2018}b'"
    );
    // The script carries a byte-order mark so a path with an accent survives.
    assert_eq!(&ps_bytes("x")[..3], &[0xEF, 0xBB, 0xBF]);
}

#[test]
fn a_path_with_a_newline_in_it_is_not_written_into_a_service_file() {
    assert!(plain_path(Path::new("/srv/ferry/repos/ok")).is_ok());
    assert!(plain_path(Path::new("/srv/ferry\nExecStartPre=/bin/evil")).is_err());
    assert!(plain_path(Path::new("C:\\a\r\nb")).is_err());
}

#[test]
fn a_worker_name_that_is_not_a_plain_name_never_reaches_the_masters_lines() {
    let machine = machine_with(&["quantly"]);
    let mut opts = options(&machine);
    opts.identity = None;
    let scan = machine::Scan {
        workers: vec![
            unit_worker("ferryman-a.service", true, "good-old-swarm"),
            unit_worker("ferryman-b.service", true, "evil; rm -rf ~"),
        ],
        notes: Vec::new(),
    };
    let mut run = |_: &str, _: &[String]| None;
    let report = setup(&machine.root, &opts, &scan, &mut run).unwrap();
    // The odd name cannot be the identity either: there are not two live names to choose from.
    assert!(
        ferryman_channel::is_safe_component(&report.identity),
        "{}",
        report.identity
    );
    for line in &report.signing {
        assert!(!line.contains("rm -rf"), "{line}");
        assert!(!line.contains(';'), "{line}");
    }
    assert!(
        report.notes.iter().any(|n| n.contains("not plain names")),
        "{:?}",
        report.notes
    );
    let mut bad = options(&machine);
    bad.retire = vec!["x y".into()];
    assert!(setup(&machine.root, &bad, &machine::Scan::default(), &mut run).is_err());
}

#[test]
fn a_preamble_path_that_climbs_out_of_the_checkout_is_not_followed() {
    let machine = machine_with(&["quantly"]);
    let human = machine.dir.path().join("human/quantly");
    fs::create_dir_all(human.parent().unwrap()).unwrap();
    let bare = machine.dir.path().join("origins/quantly.git");
    git(
        machine.dir.path(),
        &[
            "clone",
            "-q",
            bare.to_str().unwrap(),
            human.to_str().unwrap(),
        ],
    );
    let attachment = human.join(".ferryman");
    fs::create_dir_all(&attachment).unwrap();
    let secret = machine.dir.path().join("human/secret.txt");
    fs::write(&secret, "not for the clone").unwrap();
    let mut text = AgentConfig::render(
        "old-swarm",
        "worker",
        "claude",
        &AgentConfig::default_args("claude"),
        crate::agent::ReviewMode::Confirm,
        None,
        true,
    );
    text.push_str("preamble_file = \"../../secret.txt\"\n");
    fs::write(attachment.join("agent.toml"), text).unwrap();
    machine
        .root
        .adopt("quantly", &machine.root.comms_home("quantly"), Some(&human))
        .unwrap();
    let mut opts = options(&machine);
    opts.identity = None;
    opts.remote_template = None;
    let mut run = |_: &str, _: &[String]| None;
    setup(&machine.root, &opts, &machine::Scan::default(), &mut run).unwrap();
    let managed = machine.root.managed_clone("quantly");
    let leaked = snapshot(&managed)
        .iter()
        .any(|(path, bytes)| bytes == b"not for the clone" && path != &secret);
    assert!(!leaked, "the file outside the checkout was copied in");
}
