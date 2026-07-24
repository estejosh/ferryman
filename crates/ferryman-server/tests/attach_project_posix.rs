use std::{
    fs,
    path::{Path, PathBuf},
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

#[cfg(windows)]
fn posix_path(path: &Path) -> String {
    let text = path.to_string_lossy().replace('\\', "/");
    let bytes = text.as_bytes();
    assert_eq!(bytes.get(1), Some(&b':'), "expected a drive path: {text}");
    format!(
        "/mnt/{}/{}",
        (bytes[0] as char).to_ascii_lowercase(),
        &text[3..]
    )
}

#[cfg(not(windows))]
fn posix_path(path: &Path) -> String {
    path.to_string_lossy().into_owned()
}

#[test]
fn posix_attachment_dry_run_is_framework_neutral_and_non_mutating() {
    let fixture = tempfile::tempdir().unwrap();
    let workspace = fixture.path().join("alpha");
    fs::create_dir_all(&workspace).unwrap();
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
    let remote_before = git(&workspace, &["remote", "-v"]).stdout;

    let script = PathBuf::from(env!("CARGO_MANIFEST_DIR"))
        .join("../..")
        .join("scripts/attach-project.sh");
    let mut command = if cfg!(windows) {
        let mut command = Command::new("wsl.exe");
        command.args(["-d", "Ubuntu", "--", "bash"]);
        command
    } else {
        Command::new("bash")
    };
    let participant = if cfg!(windows) {
        r"alpha-builder\|builder\|code,test"
    } else {
        "alpha-builder|builder|code,test"
    };
    let output = command
        .arg(posix_path(&script))
        .args(["--workspace", &posix_path(&workspace)])
        .args(["--project", "alpha"])
        .args(["--shared-remote", "/beastly-bridges/alpha"])
        .args([
            "--git-remote",
            "https://github.com/estejosh/alpha-bridge.git",
        ])
        .args(["--integration-mode", "multi-agent"])
        .args(["--participant", participant])
        .args([
            "--dry-run",
            "--skip-mega-registration",
            "--skip-hub-registration",
        ])
        .output()
        .expect("run POSIX attachment dry run");
    assert_success(&output);
    let stdout = String::from_utf8_lossy(&output.stdout);
    assert!(stdout.contains("Integration:    multi-agent"));
    assert!(stdout.contains("commit portable protocol/adoption/ignore metadata"));
    assert!(stdout.contains("No token was created, changed, copied, or printed"));
    assert!(!workspace.join(".ferryman").exists());
    assert_eq!(git(&workspace, &["remote", "-v"]).stdout, remote_before);
}

#[test]
fn posix_attachment_apply_is_idempotent_and_pushes_only_portable_bootstrap() {
    let fixture = tempfile::tempdir().unwrap();
    let workspace = fixture.path().join("beta");
    let remote = fixture.path().join("beta-bridge.git");
    let tools = fixture.path().join("tools");
    fs::create_dir_all(&workspace).unwrap();
    fs::create_dir_all(&tools).unwrap();
    fs::create_dir_all(workspace.join(".ferryman")).unwrap();
    fs::write(
        workspace.join(".ferryman/bridge.toml"),
        "endpoint = \"http://127.0.0.1:8796\"\nproject  = \"beta\"\n",
    )
    .unwrap();
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
    let remote_before = git(&workspace, &["remote", "-v"]).stdout;
    assert_success(&git(
        fixture.path(),
        &["init", "--bare", remote.to_str().unwrap()],
    ));

    let fake_gh = tools.join("gh");
    fs::write(
        &fake_gh,
        "#!/bin/sh\nprintf '%s\\n' 'estejosh/beta-bridge|PRIVATE'\n",
    )
    .unwrap();
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        fs::set_permissions(&fake_gh, fs::Permissions::from_mode(0o755)).unwrap();
    }
    #[cfg(windows)]
    {
        let output = Command::new("wsl.exe")
            .args(["-d", "Ubuntu", "--", "chmod", "+x"])
            .arg(posix_path(&fake_gh))
            .output()
            .expect("make fake gh executable");
        assert_success(&output);
    }

    let script = PathBuf::from(env!("CARGO_MANIFEST_DIR"))
        .join("../..")
        .join("scripts/attach-project.sh");
    let remote_url = format!("file://{}", posix_path(&remote));
    let path = format!("{}:/usr/local/bin:/usr/bin:/bin", posix_path(&tools));
    let participant = if cfg!(windows) {
        r"beta-builder\|builder\|code,test"
    } else {
        "beta-builder|builder|code,test"
    };

    for _ in 0..2 {
        let mut command = if cfg!(windows) {
            let mut command = Command::new("wsl.exe");
            command.args(["-d", "Ubuntu", "--"]);
            command
        } else {
            Command::new("env")
        };
        if cfg!(windows) {
            command.arg("env");
        }
        let output = command
            .arg(format!("PATH={path}"))
            .arg("GIT_CONFIG_COUNT=1")
            .arg(format!("GIT_CONFIG_KEY_0=url.{remote_url}.insteadOf"))
            .arg("GIT_CONFIG_VALUE_0=https://github.com/estejosh/beta-bridge.git")
            .arg("bash")
            .arg(posix_path(&script))
            .args(["--workspace", &posix_path(&workspace)])
            .args(["--project", "beta"])
            .args(["--shared-remote", "/beastly-bridges/beta"])
            .args([
                "--git-remote",
                "https://github.com/estejosh/beta-bridge.git",
            ])
            .args(["--integration-mode", "single-agent"])
            .args(["--participant", participant])
            .args([
                "--update-standard",
                "--skip-mega-registration",
                "--skip-hub-registration",
            ])
            .output()
            .expect("run POSIX attachment apply");
        assert_success(&output);
    }

    let inner = workspace.join(".ferryman/ferryman");
    let adoption = fs::read_to_string(inner.join("ADOPTION.md")).unwrap();
    assert!(adoption.contains("project-inbox"));
    assert!(adoption.contains("beta-builder"));
    assert!(!inner.join("token").exists());
    assert!(!inner.join("runtime").exists());
    assert!(workspace.join(".ferryman/runtime").is_dir());
    assert!(
        fs::read_to_string(workspace.join(".ferryman/bridge.toml"))
            .unwrap()
            .contains("communications = ")
    );
    assert_eq!(git(&workspace, &["remote", "-v"]).stdout, remote_before);

    let branch = git(&inner, &["symbolic-ref", "--short", "HEAD"]);
    assert_success(&branch);
    let branch = String::from_utf8_lossy(&branch.stdout).trim().to_owned();
    let remote_adoption = git(
        fixture.path(),
        &[
            "--git-dir",
            remote.to_str().unwrap(),
            "show",
            &format!("{branch}:ADOPTION.md"),
        ],
    );
    assert_success(&remote_adoption);
    assert!(String::from_utf8_lossy(&remote_adoption.stdout).contains("beta-builder"));

    let scanner = PathBuf::from(env!("CARGO_MANIFEST_DIR"))
        .join("../..")
        .join("scripts/scan-project-safety.sh");
    let mut scan = if cfg!(windows) {
        let mut command = Command::new("wsl.exe");
        command.args(["-d", "Ubuntu", "--", "bash"]);
        command
    } else {
        Command::new("bash")
    };
    let scan = scan
        .arg(posix_path(&scanner))
        .args(["--workspace", &posix_path(&workspace)])
        .output()
        .expect("run POSIX attachment safety scanner");
    assert_success(&scan);
    assert!(String::from_utf8_lossy(&scan.stdout).contains("standard_revision"));
}
