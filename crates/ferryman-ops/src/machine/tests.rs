use super::*;

fn tokens(text: &str) -> Vec<String> {
    words(text)
}

fn unit(name: &str, all: bool, enabled: bool, active: bool) -> Worker {
    Worker {
        kind: Kind::Unit {
            unit: name.into(),
            file: PathBuf::from(format!("/home/u/.config/systemd/user/{name}")),
            user: true,
            enabled,
            active,
            pid: active.then_some(4242),
        },
        all_projects: all,
        identity: Some("ichabod-grouchly-swarm".into()),
        command: "ferry agent run --all-projects".into(),
    }
}

fn process(pid: u32, all: bool) -> Worker {
    Worker {
        kind: Kind::Process { pid },
        all_projects: all,
        identity: None,
        command: "ferry agent run".into(),
    }
}

#[test]
fn a_command_line_is_read_the_way_a_shell_would_split_it() {
    assert_eq!(
        tokens(
            r#""C:\Program Files\ferry\ferry.exe" agent run --workspace "X:\a b" --all-projects"#
        ),
        [
            r"C:\Program Files\ferry\ferry.exe",
            "agent",
            "run",
            "--workspace",
            r"X:\a b",
            "--all-projects"
        ]
    );
    assert_eq!(tokens("a 'b c' d"), ["a", "b c", "d"]);
    assert_eq!(tokens(""), Vec::<String>::new());
}

#[test]
fn only_ferry_agent_run_is_a_worker() {
    let run = invocation(&tokens(
        "/usr/local/bin/ferry agent run --all-projects --once",
    ))
    .unwrap();
    assert!(run.all_projects && run.once && !run.dry_run);
    let single = invocation(&tokens("ferry agent run --workspace=/srv/x")).unwrap();
    assert_eq!(single.workspace.as_deref(), Some("/srv/x"));
    assert!(!single.all_projects);
    let dry = invocation(&tokens("ferry agent run --dry-run --all-projects")).unwrap();
    assert!(dry.dry_run);
    // Other commands, other programs, and a mention in prose are not workers.
    assert!(invocation(&tokens("ferry agent status")).is_none());
    assert!(invocation(&tokens("ferry doctor")).is_none());
    assert!(invocation(&tokens("grep agent run file.txt")).is_none());
    assert!(invocation(&tokens("echo ferry")).is_none());
    assert!(invocation(&tokens("ferry-updater agent run")).is_some());
}

#[test]
fn a_unit_file_is_a_worker_only_through_its_exec_line() {
    let unit_text = "[Unit]\nDescription=ferry agent run (the swarm)\n\n[Service]\n\
        ExecStart=/usr/local/bin/ferry agent run --all-projects\nRestart=on-failure\n";
    let (found, command) = unit_worker(unit_text).unwrap();
    assert!(found.all_projects);
    assert!(command.contains("agent run"));
    let other = "[Unit]\nDescription=ferry agent run\n[Service]\nExecStart=/usr/bin/sleep 10\n";
    assert!(
        unit_worker(other).is_none(),
        "a description that mentions it is not a command"
    );
}

#[test]
fn a_script_comment_is_not_a_command() {
    let script = "@echo off\r\nrem ferry agent run --all-projects was here\r\n:: ferry agent run\r\n\
        \"C:\\ferry\\ferry.exe\" agent run --all-projects\r\n";
    let (found, _) = invocation_in_text(script).unwrap();
    assert!(found.all_projects);
    assert!(invocation_in_text("# ferry agent run\n").is_none());
}

const SCHTASKS: &str = "\"HostName\",\"TaskName\",\"Next Run Time\",\"Status\",\"Logon Mode\",\"Last Run Time\",\"Last Result\",\"Author\",\"Task To Run\",\"Start In\",\"Comment\",\"Scheduled Task State\"\r\n\
\"BEASTLY\",\"\\Ferryman Swarm\",\"N/A\",\"Running\",\"Interactive only\",\"N/A\",\"0\",\"u\",\"C:\\ferry\\run-swarm.cmd\",\"X:\\ferryman\",\"\",\"Enabled\"\r\n\
\"BEASTLY\",\"\\Ferryman Old\",\"N/A\",\"Ready\",\"Interactive only\",\"N/A\",\"0\",\"u\",\"\"\"C:\\ferry\\ferry.exe\"\" agent run --workspace X:\\fructly\",\"N/A\",\"\",\"Disabled\"\r\n\
\"BEASTLY\",\"\\Backup\",\"N/A\",\"Ready\",\"Interactive only\",\"N/A\",\"0\",\"u\",\"C:\\tools\\backup.exe\",\"N/A\",\"\",\"Enabled\"\r\n";

#[test]
fn the_task_scheduler_listing_is_parsed_and_wrapper_scripts_are_followed() {
    let rows = parse_schtasks(SCHTASKS);
    assert_eq!(rows.len(), 3, "{rows:?}");
    assert_eq!(rows[0].name, "\\Ferryman Swarm");
    assert_eq!(rows[0].state, "Enabled");
    assert_eq!(rows[0].status, "Running");
    assert_eq!(rows[0].start_in, "X:\\ferryman");

    let mut read = |path: &Path| -> Option<String> {
        (path == Path::new("C:\\ferry\\run-swarm.cmd")).then(|| {
            "@echo off\r\ncall env.cmd\r\nC:\\ferry\\ferry.exe agent run --all-projects\r\n"
                .to_string()
        })
    };
    let swarm = task_worker(&rows[0], &mut read).unwrap();
    assert!(swarm.all_projects && swarm.live());
    let old = task_worker(&rows[1], &mut read).unwrap();
    assert!(!old.all_projects);
    assert!(
        !old.live(),
        "a disabled task is exactly what fleet setup leaves behind"
    );
    assert!(
        task_worker(&rows[2], &mut read).is_none(),
        "an unrelated task"
    );
}

#[test]
fn a_dry_run_task_is_not_a_worker() {
    let row = TaskRow {
        name: "\\check".into(),
        status: "Ready".into(),
        run: "ferry agent run --dry-run".into(),
        start_in: "N/A".into(),
        state: "Enabled".into(),
    };
    assert!(task_worker(&row, &mut |_| None).is_none());
}

#[test]
fn a_disabled_unit_is_ignored_and_an_enabled_or_running_one_counts() {
    assert!(!unit("a.service", true, false, false).live());
    assert!(unit("a.service", true, true, false).live());
    assert!(unit("a.service", true, false, true).live());
    assert!(process(1, false).live());
}

#[test]
fn a_clear_machine_starts_freely() {
    assert_eq!(judge_start(&Scan::default(), true, false), Start::Clear);
    let disabled = Scan {
        workers: vec![unit("old.service", true, false, false)],
        notes: Vec::new(),
    };
    assert_eq!(judge_start(&disabled, true, false), Start::Clear);
}

#[test]
fn a_second_all_projects_worker_is_refused_unless_told_otherwise() {
    let scan = Scan {
        workers: vec![unit("ferryman-swarm.service", true, true, true)],
        notes: Vec::new(),
    };
    let Start::Refuse(why) = judge_start(&scan, true, false) else {
        panic!("a second all-projects worker must be refused")
    };
    assert!(why.contains("ferryman-swarm.service"), "{why}");
    assert!(why.contains("--allow-second-worker"), "{why}");
    assert!(
        why.contains("systemctl --user disable --now ferryman-swarm.service"),
        "{why}"
    );
    assert!(why.contains("ferry fleet setup"), "{why}");

    match judge_start(&scan, true, true) {
        Start::Warn(lines) => assert!(
            lines.iter().any(|l| l.contains("--allow-second-worker")),
            "{lines:?}"
        ),
        other => panic!("{other:?}"),
    }
}

#[test]
fn a_single_project_worker_beside_another_is_warned_about_not_refused() {
    let scan = Scan {
        workers: vec![process(77, true)],
        notes: Vec::new(),
    };
    let Start::Warn(lines) = judge_start(&scan, false, false) else {
        panic!("a warning, not a refusal")
    };
    assert!(lines[0].contains("process 77"), "{lines:?}");
    assert!(
        lines[0].contains("kill 77") || lines[0].contains("taskkill /PID 77"),
        "{lines:?}"
    );
    // Another single-project worker does not stop an all-projects one starting.
    let single = Scan {
        workers: vec![process(78, false)],
        notes: Vec::new(),
    };
    assert!(matches!(judge_start(&single, true, false), Start::Warn(_)));
}

#[test]
fn doctor_says_plainly_how_many_workers_there_are_and_how_to_fix_it() {
    let (ok, line) = doctor_line(&Scan::default());
    assert!(ok);
    assert!(line.contains("no worker"), "{line}");

    let one = Scan {
        workers: vec![unit("ferryman-swarm.service", true, true, true)],
        notes: Vec::new(),
    };
    let (ok, line) = doctor_line(&one);
    assert!(ok, "{line}");
    assert!(line.starts_with("one worker"), "{line}");

    let three = Scan {
        workers: vec![
            unit("a.service", true, true, true),
            unit("b.service", false, true, false),
            process(9, false),
        ],
        notes: vec!["no systemd unit folder could be read".into()],
    };
    let (ok, line) = doctor_line(&three);
    assert!(!ok);
    assert!(line.contains("3 workers"), "{line}");
    assert!(line.contains("ferry fleet setup"), "{line}");
    assert!(line.contains("not looked at: no systemd"), "{line}");
}

#[test]
fn the_stop_commands_disable_and_never_delete() {
    for worker in [
        unit("x.service", true, true, true),
        process(5, false),
        Worker {
            kind: Kind::Task {
                name: "\\Old".into(),
                enabled: true,
                running: false,
                scripts: Vec::new(),
            },
            all_projects: false,
            identity: None,
            command: "c".into(),
        },
    ] {
        for command in worker.stop_commands() {
            assert!(
                !command.contains("rm ")
                    && !command.contains("/Delete")
                    && !command.contains("del "),
                "{command}"
            );
        }
    }
}

#[test]
fn a_long_command_is_shortened_for_a_sentence() {
    let long = format!("ferry agent run {}", "--x ".repeat(100));
    assert!(shorten(&long).chars().count() < 160);
    assert!(shorten(&long).ends_with("..."));
    assert_eq!(shorten("ferry   agent\nrun"), "ferry agent run");
}

#[test]
fn the_stop_commands_print_an_odd_unit_or_task_name_as_one_argument() {
    let odd = unit("x; rm -rf ~.service", true, true, true);
    let commands = odd.stop_commands();
    assert_eq!(
        commands,
        ["systemctl --user disable --now 'x; rm -rf ~.service'"]
    );
    let quote = unit("it's.service", true, true, true);
    assert_eq!(
        quote.stop_commands(),
        ["systemctl --user disable --now 'it'\\''s.service'"]
    );
    let plain = unit("ferryman-ichabod.service", true, true, true);
    assert_eq!(
        plain.stop_commands(),
        ["systemctl --user disable --now ferryman-ichabod.service"]
    );
    let task = Worker {
        kind: Kind::Task {
            name: "\\Evil\" & calc \"x\n".into(),
            enabled: true,
            running: false,
            scripts: Vec::new(),
        },
        all_projects: true,
        identity: None,
        command: String::new(),
    };
    for line in task.stop_commands() {
        assert_eq!(line.matches('"').count(), 2, "{line}");
        assert!(!line.contains('\n'), "{line:?}");
    }
}
