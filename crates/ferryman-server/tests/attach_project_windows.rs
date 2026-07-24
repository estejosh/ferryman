#![cfg(windows)]

use std::{
    fs,
    path::Path,
    process::{Command, Output},
};

fn git(directory: &Path, arguments: &[&str]) -> Output {
    Command::new("git")
        .arg("-C")
        .arg(directory)
        .args(arguments)
        .output()
        .expect("run git")
}

fn assert_success(output: &Output) {
    assert!(
        output.status.success(),
        "command failed\nstdout: {}\nstderr: {}",
        String::from_utf8_lossy(&output.stdout),
        String::from_utf8_lossy(&output.stderr)
    );
}

#[test]
fn attachment_adopts_history_is_idempotent_and_preserves_main_remote() {
    let fixture = tempfile::tempdir().unwrap();
    let workspace = fixture.path().join("alpha");
    let source = fixture.path().join("alpha-old-communications");
    let remote = fixture.path().join("alpha-bridge.git");
    let tools = fixture.path().join("tools");
    fs::create_dir_all(&workspace).unwrap();
    fs::create_dir_all(&source).unwrap();
    fs::create_dir_all(&tools).unwrap();
    fs::create_dir_all(workspace.join(".ferryman")).unwrap();
    fs::write(
        workspace.join(".ferryman/bridge.toml"),
        "endpoint = \"http://127.0.0.1:8796\"\nproject  = \"alpha\"\n",
    )
    .unwrap();
    assert_success(&git(
        fixture.path(),
        &["init", "--bare", remote.to_str().unwrap()],
    ));

    assert_success(&git(&workspace, &["init", "-q"]));
    assert_success(&git(
        &workspace,
        &[
            "remote",
            "add",
            "origin",
            "https://example.invalid/main-project.git",
        ],
    ));
    assert_success(&git(&source, &["init", "-q"]));
    assert_success(&git(&source, &["config", "user.name", "Ferryman Test"]));
    assert_success(&git(
        &source,
        &["config", "user.email", "ferryman-test@example.invalid"],
    ));
    fs::write(source.join("history.txt"), "preserve this history\n").unwrap();
    assert_success(&git(&source, &["add", "history.txt"]));
    assert_success(&git(&source, &["commit", "-q", "-m", "existing history"]));
    assert_success(&git(&source, &["branch", "-M", "main"]));
    assert_success(&git(
        &source,
        &[
            "remote",
            "add",
            "origin",
            "https://github.com/estejosh/alpha-bridge.git",
        ],
    ));

    fs::write(
        tools.join("gh.cmd"),
        "@echo off\r\necho {\"nameWithOwner\":\"estejosh/alpha-bridge\",\"visibility\":\"PRIVATE\"}\r\n",
    )
    .unwrap();
    let script = Path::new(env!("CARGO_MANIFEST_DIR"))
        .join("../..")
        .join("scripts/attach-project.ps1");
    let inherited_path = std::env::var_os("PATH").unwrap_or_default();
    let child_path = format!("{};{}", tools.display(), inherited_path.to_string_lossy());
    let remote_text = remote.to_string_lossy().replace('\\', "/");
    let remote_url = if remote_text.as_bytes().get(1) == Some(&b':') {
        format!("file:///{remote_text}")
    } else {
        format!("file://{remote_text}")
    };

    for _ in 0..2 {
        let output = Command::new("powershell.exe")
            .args(["-NoProfile", "-File"])
            .arg(&script)
            .arg("-Workspace")
            .arg(&workspace)
            .args([
                "-Project",
                "alpha",
                "-SharedRemote",
                "/beastly-bridges/alpha",
                "-GitRemote",
                "https://github.com/estejosh/alpha-bridge.git",
                "-IntegrationMode",
                "single-agent",
                "-Participant",
                "alpha-builder|builder|code,test",
                "-AdoptFrom",
            ])
            .arg(&source)
            .args([
                "-UpdateStandard",
                "-SkipMegaRegistration",
                "-SkipHubRegistration",
            ])
            .env("PATH", &child_path)
            .env("GIT_CONFIG_COUNT", "1")
            .env("GIT_CONFIG_KEY_0", format!("url.{remote_url}.insteadOf"))
            .env(
                "GIT_CONFIG_VALUE_0",
                "https://github.com/estejosh/alpha-bridge.git",
            )
            .output()
            .expect("run attachment script");
        assert_success(&output);
        let current_origin = git(
            &workspace.join(".ferryman/ferryman"),
            &["remote", "get-url", "origin"],
        );
        assert_success(&current_origin);
        assert_eq!(
            String::from_utf8_lossy(&current_origin.stdout).trim(),
            "https://github.com/estejosh/alpha-bridge.git"
        );
    }

    let inner = workspace.join(".ferryman/ferryman");
    let source_head = git(&source, &["rev-parse", "HEAD"]);
    assert_success(&source_head);
    let source_head = String::from_utf8_lossy(&source_head.stdout)
        .trim()
        .to_owned();
    assert_success(&git(
        &inner,
        &["merge-base", "--is-ancestor", &source_head, "HEAD"],
    ));
    assert_eq!(
        String::from_utf8_lossy(&git(&inner, &["remote", "get-url", "origin"]).stdout).trim(),
        "https://github.com/estejosh/alpha-bridge.git"
    );
    assert_eq!(
        String::from_utf8_lossy(&git(&workspace, &["remote", "get-url", "origin"]).stdout).trim(),
        "https://example.invalid/main-project.git"
    );
    assert!(workspace.join(".ferryman/bridge.toml").is_file());
    assert!(
        fs::read_to_string(workspace.join(".ferryman/bridge.toml"))
            .unwrap()
            .contains("communications = ")
    );
    assert!(inner.join("PROTOCOL.md").is_file());
    let adoption = fs::read_to_string(inner.join("ADOPTION.md")).unwrap();
    assert!(adoption.contains("single-agent"));
    assert!(adoption.contains("project-inbox"));
    assert!(adoption.contains("alpha-builder"));
    let remote_adoption = git(
        fixture.path(),
        &[
            "--git-dir",
            remote.to_str().unwrap(),
            "show",
            "main:ADOPTION.md",
        ],
    );
    assert_success(&remote_adoption);
    assert!(String::from_utf8_lossy(&remote_adoption.stdout).contains("alpha-builder"));
    assert!(inner.join(".megaignore").is_file());
    assert!(!inner.join("token").exists());
    assert!(!inner.join("runtime").exists());

    let scanner = Path::new(env!("CARGO_MANIFEST_DIR"))
        .join("../..")
        .join("scripts/scan-project-safety.ps1");
    let scan = Command::new("powershell.exe")
        .args(["-NoProfile", "-File"])
        .arg(scanner)
        .arg("-Workspace")
        .arg(&workspace)
        .output()
        .expect("run attachment safety scanner");
    assert_success(&scan);
    assert!(String::from_utf8_lossy(&scan.stdout).contains("standard_revision"));
}
