use std::fs;
use std::path::PathBuf;

use assert_cmd::Command;
use predicates::prelude::*;

struct Sandbox {
    _tmp: tempfile::TempDir,
    home: PathBuf,
    repo: PathBuf,
}

impl Sandbox {
    fn new() -> Self {
        let tmp = tempfile::tempdir().unwrap();
        let home = tmp.path().join("home");
        let repo = tmp.path().join("repo");
        fs::create_dir_all(&home).unwrap();
        fs::create_dir_all(&repo).unwrap();
        Self {
            _tmp: tmp,
            home,
            repo,
        }
    }

    fn cmd(&self) -> Command {
        let mut command = Command::cargo_bin("agent-shield").unwrap();
        command
            .env_clear()
            .env("HOME", &self.home)
            .env("PATH", std::env::var_os("PATH").unwrap_or_default())
            .current_dir(&self.repo);
        command
    }

    fn write_user_policy(&self, text: &str) {
        let path = self.home.join(".config/privaku/agent-shield/policy.yaml");
        fs::create_dir_all(path.parent().unwrap()).unwrap();
        fs::write(path, text).unwrap();
    }
}

#[test]
fn shell_private_key_is_denied_as_json() {
    let sandbox = Sandbox::new();
    let output = sandbox
        .cmd()
        .args(["check", "--shell", "cat ~/.ssh/id_rsa", "--json"])
        .assert()
        .code(20)
        .get_output()
        .stdout
        .clone();
    let decision: serde_json::Value = serde_json::from_slice(&output).unwrap();
    let schema: serde_json::Value =
        serde_json::from_str(include_str!("../../../protocol/decision.schema.json")).unwrap();
    let validator = jsonschema::draft202012::new(&schema).unwrap();
    let errors: Vec<_> = validator
        .iter_errors(&decision)
        .map(|error| error.to_string())
        .collect();
    assert!(
        errors.is_empty(),
        "check JSON does not match protocol/decision.schema.json: {errors:?}"
    );
    assert_eq!(decision["outcome"], "deny");
    assert_eq!(decision["rule_id"], "secrets.ssh_private_key");
    assert_eq!(
        decision["matched_rule_ids"],
        serde_json::json!(["secrets.ssh_private_key"])
    );
}

#[test]
fn allow_ask_and_plain_output_use_decision_exit_codes() {
    let sandbox = Sandbox::new();
    sandbox.write_user_policy(
        "version: 1\nrules:\n  - id: user.ask_deploy\n    severity: medium\n    decision: ask\n    match: { program: deploy }\n",
    );
    sandbox
        .cmd()
        .args(["check", "--shell", "cargo test"])
        .assert()
        .success()
        .stdout(predicate::str::starts_with("ALLOW"));
    sandbox
        .cmd()
        .args(["check", "--shell", "deploy"])
        .assert()
        .code(10)
        .stdout(predicate::str::contains("ASK [user.ask_deploy]"));
}

#[test]
fn read_and_mcp_actions_are_evaluated() {
    let sandbox = Sandbox::new();
    sandbox
        .cmd()
        .args(["check", "--read", "~/.ssh/id_ed25519"])
        .assert()
        .code(20)
        .stdout(predicate::str::contains("secrets.ssh_private_key"));

    sandbox.write_user_policy(
        r#"
version: 1
rules:
  - id: user.mcp_secret
    severity: critical
    decision: deny
    match:
      access: [read]
      paths: ["~/.ssh/id_*"]
      mcp: { server: "file*", tool: "read_*", arg: /path }
"#,
    );
    sandbox
        .cmd()
        .args([
            "check",
            "--mcp",
            "filesystem",
            "read_file",
            r#"{"path":"~/.ssh/id_rsa"}"#,
            "--json",
        ])
        .assert()
        .code(20)
        .stdout(predicate::str::contains(r#""user.mcp_secret""#));
}

#[test]
fn malformed_shell_is_ask_and_bad_mcp_json_fails_closed() {
    let sandbox = Sandbox::new();
    sandbox
        .cmd()
        .args(["check", "--shell", "if then", "--json"])
        .assert()
        .code(10)
        .stdout(predicate::str::contains(r#""rule_id":"parse_error""#));
    sandbox
        .cmd()
        .args([
            "check",
            "--mcp",
            "filesystem",
            "read_file",
            "{bad",
            "--json",
        ])
        .assert()
        .code(20)
        .stdout(predicate::str::contains(r#""rule_id":"internal_error""#));
}

#[test]
fn check_requires_exactly_one_action_and_valid_agent() {
    let sandbox = Sandbox::new();
    sandbox.cmd().arg("check").assert().code(2);
    sandbox
        .cmd()
        .args(["check", "--shell", "ls", "--read", "x"])
        .assert()
        .code(2);
    sandbox
        .cmd()
        .args(["check", "--shell", "ls", "--agent", "unknown"])
        .assert()
        .code(2);
}

#[test]
fn policy_errors_fail_closed() {
    let sandbox = Sandbox::new();
    sandbox.write_user_policy("version: 1\nrules: [");
    sandbox
        .cmd()
        .args(["check", "--shell", "ls", "--json"])
        .assert()
        .code(20)
        .stdout(predicate::str::contains("cannot load policy"))
        .stdout(predicate::str::contains(r#""outcome":"deny""#));
}

#[test]
fn matcher_compilation_errors_fail_closed() {
    let sandbox = Sandbox::new();
    sandbox.write_user_policy(
        "version: 1\nrules:\n  - id: user.invalid_glob\n    severity: high\n    decision: deny\n    match: { program: '[' }\n",
    );
    sandbox
        .cmd()
        .args(["check", "--shell", "ls", "--json"])
        .assert()
        .code(20)
        .stdout(predicate::str::contains("cannot compile policy"))
        .stdout(predicate::str::contains(r#""outcome":"deny""#));
}
