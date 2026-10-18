//! Phase A: sandbox profile, named-CLI fail-closed, canary (detection only), protect picker.

use std::fs;
use std::os::unix::fs::PermissionsExt;
use std::path::PathBuf;
use std::process::Command as StdCommand;
use std::time::Duration;

use assert_cmd::Command;
use predicates::prelude::*;

struct Sandbox {
    _temp: tempfile::TempDir,
    home: PathBuf,
    cwd: PathBuf,
    state: PathBuf,
    fake_bin: PathBuf,
}

impl Sandbox {
    fn new() -> Self {
        let temp = tempfile::tempdir().unwrap();
        let home = temp.path().join("home");
        let cwd = temp.path().join("cwd");
        let state = temp.path().join("state");
        let fake_bin = temp.path().join("fake-bin");
        fs::create_dir_all(&home).unwrap();
        fs::create_dir_all(&cwd).unwrap();
        fs::create_dir_all(&state).unwrap();
        fs::create_dir_all(&fake_bin).unwrap();
        Self {
            _temp: temp,
            home,
            cwd,
            state,
            fake_bin,
        }
    }

    fn cmd(&self) -> Command {
        let mut command = Command::cargo_bin("agent-shield").unwrap();
        command
            .env_clear()
            .env("HOME", &self.home)
            .env("PATH", std::env::var_os("PATH").unwrap_or_default())
            .env("AGENT_SHIELD_STATE_DIR", &self.state)
            .env("AGENT_SHIELD_SOCK", self.home.join("no-daemon.sock"))
            .current_dir(&self.cwd)
            .timeout(Duration::from_secs(10));
        command
    }

    fn write_fake(&self, name: &str, script: &str) -> PathBuf {
        let path = self.fake_bin.join(name);
        fs::write(&path, script).unwrap();
        fs::set_permissions(&path, fs::Permissions::from_mode(0o755)).unwrap();
        path
    }
}

#[test]
fn print_sandbox_profile_denies_secret_trees() {
    let sandbox = Sandbox::new();
    sandbox
        .cmd()
        .args(["run", "--print-sandbox-profile", "--", "echo", "ok"])
        .assert()
        .success()
        .stdout(
            predicate::str::contains("(version 1)")
                .and(predicate::str::contains(".ssh"))
                .and(predicate::str::contains(".aws"))
                .and(predicate::str::contains("Keychains"))
                .and(predicate::str::contains("Google/Chrome"))
                .and(predicate::str::contains("/usr/bin/security")),
        );
}

#[test]
fn named_cli_without_sandbox_exec_fails_closed() {
    let sandbox = Sandbox::new();
    sandbox.write_fake("claude", "#!/bin/sh\necho unsandboxed\n");
    let path = std::env::join_paths([&sandbox.fake_bin, std::path::Path::new("/bin")]).unwrap();
    sandbox
        .cmd()
        .env("PATH", &path)
        .env(
            "AGENT_SHIELD_SANDBOX_EXEC",
            sandbox.home.join("missing-sandbox-exec"),
        )
        .args(["run", "claude"])
        .assert()
        .code(1)
        .stderr(
            predicate::str::contains("Refusing to start")
                .and(predicate::str::contains("Partly protected"))
                .and(predicate::str::contains("unsandboxed").not()),
        )
        .stdout(predicate::str::contains("unsandboxed").not());
}

#[test]
fn run_double_dash_still_runs_arbitrary_commands() {
    let sandbox = Sandbox::new();
    sandbox
        .cmd()
        .args(["run", "--", "/bin/echo", "shim-ok"])
        .assert()
        .success()
        .stdout(predicate::str::contains("shim-ok"));
}

#[test]
fn canary_ensure_and_trip_are_detection_only() {
    let sandbox = Sandbox::new();
    sandbox.cmd().args(["canary", "ensure"]).assert().success();
    let canary = sandbox.state.join("canary/CANARY");
    assert!(fs::read_to_string(&canary)
        .unwrap()
        .contains("CANARY-DO-NOT-USE detection-only"));
    sandbox
        .cmd()
        .args(["canary", "trip", canary.to_str().unwrap()])
        .assert()
        .success()
        .stdout(
            predicate::str::contains("Detection only")
                .and(predicate::str::contains("did not block")),
        );
    let log = fs::read_to_string(sandbox.state.join("audit.jsonl")).unwrap();
    assert!(log.contains("canary.trip"));
    assert!(log.contains("\"decision\":\"allow\""));
    assert!(!log.to_ascii_lowercase().contains("blocked every"));
}

#[test]
fn protect_list_and_set_honour_temp_home() {
    let sandbox = Sandbox::new();
    sandbox
        .cmd()
        .args(["protect", "list", "--json"])
        .assert()
        .success()
        .stdout(
            predicate::str::contains("claude-code")
                .and(predicate::str::contains("aider"))
                .and(predicate::str::contains("@github/copilot/npm-loader.js"))
                .and(predicate::str::contains("TODO after 23 Oct")),
        );
    sandbox
        .cmd()
        .args(["protect", "set", "aider", "--off"])
        .assert()
        .success();
    let saved = fs::read_to_string(
        sandbox
            .home
            .join(".config/privaku/agent-shield/protected-apps.yaml"),
    )
    .unwrap();
    assert!(saved.contains("aider"));
    assert!(saved.contains("false"));
}

#[cfg(target_os = "macos")]
#[test]
fn sandbox_exec_denies_ssh_tree_on_macos() {
    let sandbox = Sandbox::new();
    let ssh = sandbox.home.join(".ssh");
    fs::create_dir_all(&ssh).unwrap();
    let key = ssh.join("id_rsa");
    fs::write(&key, "CANARY-DO-NOT-USE\n").unwrap();
    let profile = sandbox
        .cmd()
        .args(["run", "--print-sandbox-profile", "--", "true"])
        .output()
        .unwrap();
    assert!(profile.status.success());
    let profile_path = sandbox.state.join("test.sb");
    fs::write(&profile_path, &profile.stdout).unwrap();
    fs::set_permissions(&profile_path, fs::Permissions::from_mode(0o600)).unwrap();
    let denied = StdCommand::new("/usr/bin/sandbox-exec")
        .args(["-f", profile_path.to_str().unwrap(), "--", "/bin/cat"])
        .arg(&key)
        .output()
        .unwrap();
    assert!(
        !denied.status.success(),
        "cat of denied ssh key should fail: {}",
        String::from_utf8_lossy(&denied.stderr)
    );
    let allowed = StdCommand::new("/usr/bin/sandbox-exec")
        .args([
            "-f",
            profile_path.to_str().unwrap(),
            "--",
            "/bin/echo",
            "ok",
        ])
        .output()
        .unwrap();
    assert!(allowed.status.success());
    assert_eq!(String::from_utf8_lossy(&allowed.stdout).trim(), "ok");
}
