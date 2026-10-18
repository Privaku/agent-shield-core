use std::fs;
use std::path::{Path, PathBuf};

use assert_cmd::Command;
use predicates::prelude::*;
use serde_json::Value;

const CASES: &[(&str, &str, &str)] = &[
    ("claude", "claude/bash_cat_ssh_key.json", "deny"),
    ("claude", "claude/bash_rm_home.json", "deny"),
    ("claude", "claude/bash_git_status.json", "allow"),
    ("claude", "claude/read_source.json", "allow"),
    ("claude", "claude/read_dotenv.json", "deny"),
    ("claude", "claude/write_zshrc.json", "deny"),
    ("claude", "claude/web_fetch.json", "allow"),
    ("claude", "claude/mcp_cloud_credentials.json", "deny"),
    ("claude", "claude/unknown_tool.json", "deny"),
    ("codex", "codex/apply_patch.json", "allow"),
    ("codex", "codex/bash_variant.json", "allow"),
];

struct Sandbox {
    _tmp: tempfile::TempDir,
    home: PathBuf,
    state: PathBuf,
}

impl Sandbox {
    fn new() -> Self {
        let tmp = tempfile::tempdir().unwrap();
        let home = tmp.path().join("home");
        let state = tmp.path().join("state");
        fs::create_dir_all(&home).unwrap();
        Self {
            _tmp: tmp,
            home,
            state,
        }
    }

    fn command(&self) -> Command {
        let mut command = Command::cargo_bin("agent-shield").unwrap();
        command
            .env_clear()
            .env("HOME", &self.home)
            .env("AGENT_SHIELD_STATE_DIR", &self.state)
            .env("AGENT_SHIELD_SOCK", self.home.join("no-daemon.sock"))
            .env("PATH", std::env::var_os("PATH").unwrap_or_default());
        command
    }

    fn audit_entries(&self) -> Vec<Value> {
        fs::read_to_string(self.state.join("audit.jsonl"))
            .unwrap()
            .lines()
            .map(|line| serde_json::from_str(line).unwrap())
            .collect()
    }
}

fn fixtures_root() -> PathBuf {
    Path::new(env!("CARGO_MANIFEST_DIR")).join("../../tests/fixtures")
}

fn fixture(relative: &str) -> Vec<u8> {
    fs::read(fixtures_root().join(relative)).unwrap()
}

fn parse_response(bytes: &[u8]) -> Value {
    let response: Value = serde_json::from_slice(bytes).unwrap();
    assert_eq!(
        response["hookSpecificOutput"]["hookEventName"],
        "PreToolUse"
    );
    assert!(response
        .as_object()
        .unwrap()
        .keys()
        .eq(["hookSpecificOutput"]));
    response
}

#[test]
fn every_valid_fixture_returns_native_decision_and_is_audited() {
    let sandbox = Sandbox::new();
    for (agent, path, expected) in CASES {
        let output = sandbox
            .command()
            .args(["hook", agent])
            .write_stdin(fixture(path))
            .assert()
            .success()
            .stderr(predicate::str::is_empty())
            .get_output()
            .stdout
            .clone();
        let response = parse_response(&output);
        assert_eq!(
            response["hookSpecificOutput"]["permissionDecision"], *expected,
            "fixture {path}"
        );
        let reason = response["hookSpecificOutput"]["permissionDecisionReason"]
            .as_str()
            .unwrap();
        if matches!(*expected, "deny" | "ask") {
            assert!(
                reason.to_ascii_lowercase().contains("do not retry"),
                "fixture {path} did not tell the agent not to retry: {reason}"
            );
        }
    }

    let entries = sandbox.audit_entries();
    assert_eq!(entries.len(), CASES.len());
    assert_eq!(entries[0]["agent"], "claude");
    assert_eq!(entries.last().unwrap()["agent"], "codex");
    assert_eq!(
        entries
            .iter()
            .find(|entry| entry["session"] == "claude-ask-unknown")
            .unwrap()["rule_id"],
        "hook.unknown_tool"
    );
}

#[test]
fn fixture_inventory_is_complete_and_garbage_fails_closed() {
    let root = fixtures_root();
    let fixture_count = ["claude", "codex"]
        .into_iter()
        .map(|directory| fs::read_dir(root.join(directory)).unwrap().count())
        .sum::<usize>();
    assert_eq!(fixture_count, CASES.len() + 1);

    Sandbox::new()
        .command()
        .args(["hook", "claude"])
        .write_stdin(fixture("claude/garbage.json"))
        .assert()
        .code(2)
        .stdout(predicate::str::is_empty())
        .stderr(predicate::str::contains("invalid hook input"));
}

#[test]
fn missing_fields_policy_errors_and_audit_errors_exit_two() {
    let missing = Sandbox::new();
    missing
        .command()
        .args(["hook", "claude"])
        .write_stdin("{}")
        .assert()
        .code(2)
        .stdout(predicate::str::is_empty())
        .stderr(predicate::str::contains("invalid hook input"));

    let invalid_policy = Sandbox::new();
    let policy = invalid_policy
        .home
        .join(".config/privaku/agent-shield/policy.yaml");
    fs::create_dir_all(policy.parent().unwrap()).unwrap();
    fs::write(policy, "version: 1\nrules: [").unwrap();
    invalid_policy
        .command()
        .args(["hook", "claude"])
        .write_stdin(fixture("claude/bash_git_status.json"))
        .assert()
        .code(2)
        .stdout(predicate::str::is_empty())
        .stderr(predicate::str::contains("cannot load policy"));

    let audit_failure = Sandbox::new();
    fs::write(&audit_failure.state, "not a directory").unwrap();
    audit_failure
        .command()
        .args(["hook", "codex"])
        .write_stdin(fixture("codex/bash_variant.json"))
        .assert()
        .code(2)
        .stdout(predicate::str::is_empty())
        .stderr(predicate::str::contains("cannot write audit log"));
}

#[test]
fn autonomous_environment_and_flag_reach_agent_context() {
    let environment = Sandbox::new();
    environment
        .command()
        .env("AGENT_SHIELD_AUTONOMOUS", "true")
        .args(["hook", "claude"])
        .write_stdin(fixture("claude/bash_git_status.json"))
        .assert()
        .success();
    assert_eq!(
        environment.audit_entries()[0]["action"]["context"]["autonomous"],
        true
    );

    let flag = Sandbox::new();
    flag.command()
        .args(["hook", "codex", "--autonomous"])
        .write_stdin(fixture("codex/bash_variant.json"))
        .assert()
        .success();
    assert_eq!(
        flag.audit_entries()[0]["action"]["context"]["autonomous"],
        true
    );
}
