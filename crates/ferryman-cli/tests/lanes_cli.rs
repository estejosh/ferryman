//! Two agents, two lanes, one repository, through the real `ferry` binary and real git
//! hooks: ownership refusal, an override that is logged, shared counters, serialized
//! landing and a landing conflict. Everything happens in a temp directory.

use ferryman_channel::ferry::Root;
use ferryman_channel::{AgentIdentity, AgentRoute, ProjectRoute};
use std::fs;
use std::path::{Path, PathBuf};
use std::process::{Command, Output};

struct World {
    _dir: tempfile::TempDir,
    base: PathBuf,
    state: PathBuf,
    root: Root,
    repo: PathBuf,
    channel: PathBuf,
}

fn text(o: &Output) -> String {
    format!(
        "{}\n{}",
        String::from_utf8_lossy(&o.stdout),
        String::from_utf8_lossy(&o.stderr)
    )
}

impl World {
    fn env(&self, c: &mut Command, agent: &str) {
        c.env("FERRYMAN_ROOT", &self.root.path)
            .env("FERRYMAN_STATE_DIR", &self.state)
            .env("LOCALAPPDATA", &self.state)
            .env("HOME", &self.base)
            .env("USERPROFILE", &self.base)
            .env("FERRYMAN_AGENT", agent)
            .env_remove("FERRY_LANE_OVERRIDE");
    }

    fn ferry(&self, cwd: &Path, agent: &str, args: &[&str]) -> Output {
        let mut c = Command::new(env!("CARGO_BIN_EXE_ferry"));
        c.args(args).current_dir(cwd);
        self.env(&mut c, agent);
        c.output().unwrap()
    }

    fn git(&self, cwd: &Path, agent: &str, args: &[&str]) -> Output {
        self.git_with(cwd, agent, args, &[])
    }

    fn git_with(&self, cwd: &Path, agent: &str, args: &[&str], extra: &[(&str, &str)]) -> Output {
        let mut c = Command::new("git");
        c.args(args).current_dir(cwd);
        self.env(&mut c, agent);
        for (k, v) in extra {
            c.env(k, v);
        }
        c.output().unwrap()
    }

    fn ok(&self, o: Output) -> String {
        assert!(o.status.success(), "{}", text(&o));
        String::from_utf8_lossy(&o.stdout).trim().to_string()
    }
}

fn world() -> World {
    let dir = tempfile::tempdir().unwrap();
    let base = dir.path().join("world");
    let state = base.join("state");
    fs::create_dir_all(&state).unwrap();
    ferryman_channel::licensing::use_machine_state_dir_per_thread(state.clone());
    let root = Root::create_with_layout(&base.join("ferry"), 1).unwrap();
    let channel = root.comms().join("idle-ish-ferryman");
    let repo = root.repos().join("idle-ish");
    let attachment = repo.join(".ferryman");
    fs::create_dir_all(&channel).unwrap();
    fs::create_dir_all(&attachment).unwrap();
    fs::write(
        attachment.join("bridge.toml"),
        format!(
            "project = \"idle-ish\"\nworkspace = \"{}\"\nattachment = \"{}\"\ncommunications = \"{}\"\n",
            repo.display().to_string().replace('\\', "/"),
            attachment.display().to_string().replace('\\', "/"),
            channel.display().to_string().replace('\\', "/")
        ),
    )
    .unwrap();
    let w = World {
        _dir: dir,
        base,
        state,
        root,
        repo: repo.clone(),
        channel: channel.clone(),
    };
    let route = ProjectRoute {
        project_id: "idle-ish".into(),
        workspace: repo.clone(),
        attachment: attachment.clone(),
        communications: channel.clone(),
        shared_remote: String::new(),
        git_remote: String::new(),
        git_visibility: String::new(),
        agents: Vec::new(),
    };
    for name in ["ash", "rf"] {
        let identity = AgentIdentity::load_or_create(name, &attachment).unwrap();
        ferryman_channel::register_agent(
            &route,
            &AgentRoute {
                name: name.into(),
                role: "worker".into(),
                capabilities: Vec::new(),
                public_key: Some(identity.public_key_hex()),
                encryption_key: None,
            },
        )
        .unwrap();
    }
    // The repository: a game and its art, as on idle-ish.
    w.ok(w.git(
        &w.base,
        "ash",
        &["init", "-q", "-b", "main", repo.to_str().unwrap()],
    ));
    for (k, v) in [
        ("user.name", "t"),
        ("user.email", "t@example.com"),
        ("commit.gpgsign", "false"),
    ] {
        w.ok(w.git(&repo, "ash", &["config", k, v]));
    }
    fs::create_dir_all(repo.join("game")).unwrap();
    fs::create_dir_all(repo.join("art")).unwrap();
    fs::write(repo.join("game/main.rs"), "fn main() {}\n").unwrap();
    fs::write(repo.join("art/hero.txt"), "hero\n").unwrap();
    fs::write(repo.join("README.md"), "title\nbody\n").unwrap();
    fs::write(repo.join("DECISIONS.md"), "# Decisions\n\nD1 first\n").unwrap();
    fs::write(repo.join(".git/info/exclude"), "/.ferryman/\n").unwrap();
    w.ok(w.git(&repo, "ash", &["add", "-A"]));
    w.ok(w.git(&repo, "ash", &["commit", "-q", "-m", "start"]));
    assert!(w.root.adopt("idle-ish", &channel, Some(&repo)).unwrap());
    w
}

#[test]
fn two_agents_in_two_lanes_of_one_repo() {
    let w = world();
    let repo = w.repo.clone();

    // Each agent gets a lane of its own.
    w.ok(w.ferry(
        &repo,
        "ash",
        &[
            "lanes", "new", "idle-ish", "game", "--owns", "game/**", "--agent", "ash",
        ],
    ));
    w.ok(w.ferry(
        &repo,
        "rf",
        &[
            "lanes", "new", "idle-ish", "art", "--owns", "art/**", "--agent", "rf",
        ],
    ));
    let game = repo.join(".lanes/game");
    let art = repo.join(".lanes/art");
    assert!(game.is_dir() && art.is_dir());
    assert_eq!(
        w.ok(w.git(&repo, "ash", &["status", "--porcelain"])),
        "",
        "lanes are invisible to the main checkout"
    );

    // `ferry root show` lists them.
    let shown = w.ok(w.ferry(&w.base, "ash", &["root", "show"]));
    assert!(
        shown.contains("lane game") && shown.contains("lane art"),
        "{shown}"
    );
    let listed = w.ok(w.ferry(&repo, "ash", &["lanes", "list"]));
    assert!(
        listed.contains("game") && listed.contains("art"),
        "{listed}"
    );

    // Two sessions committing at the same moment, each in its own lane.
    fs::create_dir_all(game.join("game")).unwrap();
    fs::write(game.join("game/a.rs"), "a\n").unwrap();
    fs::create_dir_all(art.join("art")).unwrap();
    fs::write(art.join("art/b.png"), "png\n").unwrap();
    // The game agent also, by mistake, has an art file staged: `git add -A` in its tree.
    fs::write(game.join("art/stray.png"), "stray\n").unwrap();
    let (w_ref, game_ref, art_ref) = (&w, &game, &art);
    let (game_commit, art_commit) = std::thread::scope(|s| {
        let g = s.spawn(move || {
            w_ref.ok(w_ref.git(game_ref, "ash", &["add", "-A"]));
            w_ref.git(game_ref, "ash", &["commit", "-q", "-m", "game work"])
        });
        let a = s.spawn(move || {
            w_ref.ok(w_ref.git(art_ref, "rf", &["add", "-A"]));
            w_ref.git(art_ref, "rf", &["commit", "-q", "-m", "art work"])
        });
        (g.join().unwrap(), a.join().unwrap())
    });
    // Ownership: the game lane's commit is refused over the art file; the art lane's goes.
    assert!(!game_commit.status.success(), "{}", text(&game_commit));
    let refusal = text(&game_commit);
    assert!(
        refusal.contains("art/stray.png") && refusal.contains("lane art"),
        "{refusal}"
    );
    assert!(art_commit.status.success(), "{}", text(&art_commit));
    let art_files = w.ok(w.git(&art, "rf", &["show", "--name-only", "--format=", "HEAD"]));
    assert_eq!(
        art_files, "art/b.png",
        "no game file rode along in the art commit"
    );

    // Unstage the stray, and add an unowned file: allowed, reported.
    w.ok(w.git(&game, "ash", &["rm", "-q", "--cached", "art/stray.png"]));
    fs::write(game.join("tools.sh"), "echo\n").unwrap();
    w.ok(w.git(&game, "ash", &["add", "tools.sh"]));
    let c = w.git(&game, "ash", &["commit", "-q", "-m", "game work"]);
    assert!(c.status.success(), "{}", text(&c));
    assert!(
        text(&c).contains("nobody owns") && text(&c).contains("tools.sh"),
        "{}",
        text(&c)
    );

    // An explicit override goes through and is logged in the channel.
    fs::write(game.join("art/shared.png"), "s\n").unwrap();
    w.ok(w.git(&game, "ash", &["add", "art/shared.png"]));
    let c = w.git_with(
        &game,
        "ash",
        &["commit", "-q", "-m", "needs the art helper"],
        &[("FERRY_LANE_OVERRIDE", "art handed it over")],
    );
    assert!(c.status.success(), "{}", text(&c));
    let log = fs::read_to_string(w.channel.join("lanes/overrides/game.jsonl")).unwrap();
    assert!(
        log.contains("art handed it over") && log.contains("art/shared.png"),
        "{log}"
    );

    // Counters: six allocations from two agents at once, no number twice.
    let numbers: Vec<u64> = std::thread::scope(|s| {
        let handles: Vec<_> = (0..6)
            .map(|i| {
                let w = &w;
                let repo = &repo;
                s.spawn(move || {
                    let agent = if i % 2 == 0 { "ash" } else { "rf" };
                    w.ok(w.ferry(
                        repo,
                        agent,
                        &[
                            "counter", "next", "decision", "--start", "30", "--agent", agent,
                        ],
                    ))
                    .parse::<u64>()
                    .unwrap()
                })
            })
            .collect();
        handles.into_iter().map(|h| h.join().unwrap()).collect()
    });
    let mut sorted = numbers.clone();
    sorted.sort_unstable();
    assert_eq!(sorted, vec![30, 31, 32, 33, 34, 35], "{numbers:?}");
    let checked = w.ferry(&repo, "ash", &["counter", "check", "decision"]);
    assert!(checked.status.success(), "{}", text(&checked));

    // Landing: both at once. The override commit touched art/shared.png (the art lane's),
    // so the game lane's landing needs the same override; the art lane lands plainly.
    let (landed_game, landed_art) = std::thread::scope(|s| {
        let g = s.spawn(|| {
            w.ferry(
                &repo,
                "ash",
                &[
                    "lanes",
                    "land",
                    "game",
                    "--agent",
                    "ash",
                    "--no-fetch",
                    "--allow-foreign",
                    "art handed it over",
                ],
            )
        });
        let a = s.spawn(|| {
            w.ferry(
                &repo,
                "rf",
                &["lanes", "land", "art", "--agent", "rf", "--no-fetch"],
            )
        });
        (g.join().unwrap(), a.join().unwrap())
    });
    assert!(landed_game.status.success(), "{}", text(&landed_game));
    assert!(landed_art.status.success(), "{}", text(&landed_art));
    assert_eq!(
        w.ok(w.git(&repo, "ash", &["rev-list", "--merges", "--count", "main"])),
        "0"
    );
    for file in ["game/a.rs", "art/b.png", "tools.sh"] {
        assert!(repo.join(file).is_file(), "{file} is on main");
    }

    // A landing conflict: both lanes rewrite the same README line.
    fs::write(game.join("README.md"), "title\nfrom game\n").unwrap();
    w.ok(w.git(&game, "ash", &["add", "README.md"]));
    let c = w.git(&game, "ash", &["commit", "-q", "-m", "game readme"]);
    assert!(c.status.success(), "{}", text(&c));
    fs::write(art.join("README.md"), "title\nfrom art\n").unwrap();
    w.ok(w.git(&art, "rf", &["add", "README.md"]));
    let c = w.git(&art, "rf", &["commit", "-q", "-m", "art readme"]);
    assert!(c.status.success(), "{}", text(&c));
    w.ok(w.ferry(
        &repo,
        "ash",
        &["lanes", "land", "game", "--agent", "ash", "--no-fetch"],
    ));
    let art_tip = w.ok(w.git(&art, "rf", &["rev-parse", "HEAD"]));
    let main_tip = w.ok(w.git(&repo, "rf", &["rev-parse", "main"]));
    let conflict = w.ferry(
        &repo,
        "rf",
        &["lanes", "land", "art", "--agent", "rf", "--no-fetch"],
    );
    assert!(!conflict.status.success());
    assert!(
        text(&conflict).contains("conflicts in README.md"),
        "{}",
        text(&conflict)
    );
    assert_eq!(
        w.ok(w.git(&art, "rf", &["rev-parse", "HEAD"])),
        art_tip,
        "the lane is untouched"
    );
    assert_eq!(
        w.ok(w.git(&repo, "rf", &["rev-parse", "main"])),
        main_tip,
        "main is untouched"
    );
    assert_eq!(w.ok(w.git(&art, "rf", &["status", "--porcelain"])), "");
}
