use std::fs;
use std::path::{Path, PathBuf};

use assert_cmd::Command;
use predicates::prelude::*;
use serde_json::Value;

const CASES: &[(&str, &str)] = &[
    ("shell_cat_ssh_key.json", "deny"),
    ("shell_dotenv_upload.json", "deny"),
    ("shell_npm_test.json", "allow"),
    ("read_dotenv.json", "deny"),
    ("read_source.json", "allow"),
    ("read_secret_content.json", "deny"),
    ("mcp_cloud_credentials.json", "deny"),
    ("mcp_echo.json", "allow"),
    ("mcp_missing_server.json", "deny"),
    ("event_conflict.json", "deny"),
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
    Path::new(env!("CARGO_MANIFEST_DIR")).join("../../tests/fixtures/cursor")
}

fn fixture(name: &str) -> Vec<u8> {
    fs::read(fixtures_root().join(name)).unwrap()
}

fn parse_response(bytes: &[u8]) -> Value {
    let response: Value = serde_json::from_slice(bytes).unwrap();
    let object = response.as_object().unwrap();
    assert_eq!(object.len(), 3);
    assert!(object.contains_key("permission"));
    assert!(object.contains_key("user_message"));
    assert!(object.contains_key("agent_message"));
    response
}

#[test]
fn every_valid_fixture_returns_cursor_decision_and_is_audited() {
    let sandbox = Sandbox::new();
    for (name, expected) in CASES {
        let output = sandbox
            .command()
            .args(["hook", "cursor"])
            .write_stdin(fixture(name))
            .assert()
            .success()
            .stderr(predicate::str::is_empty())
            .get_output()
            .stdout
            .clone();
        let response = parse_response(&output);
        assert_eq!(response["permission"], *expected, "fixture {name}");
        assert!(response["user_message"]
            .as_str()
            .is_some_and(|s| !s.is_empty()));
        let agent_message = response["agent_message"].as_str().unwrap();
        if matches!(*expected, "ask" | "deny") {
            assert!(
                agent_message.to_ascii_lowercase().contains("do not retry"),
                "fixture {name} did not tell the agent not to retry: {agent_message}"
            );
        }
    }

    let entries = sandbox.audit_entries();
    assert_eq!(entries.len(), CASES.len());
    assert!(entries.iter().all(|entry| entry["agent"] == "cursor"));
    assert_eq!(
        entries
            .iter()
            .find(|entry| entry["session"] == "cursor-event-conflict")
            .unwrap()["rule_id"],
        "hook.cursor_event_conflict"
    );
}

#[test]
fn explicit_event_wins_conflicts_and_is_logged_fail_closed() {
    let sandbox = Sandbox::new();
    let response = sandbox
        .command()
        .args(["hook", "cursor", "--event", "beforeShellExecution"])
        .write_stdin(fixture("event_conflict.json"))
        .assert()
        .success()
        .stderr(predicate::str::is_empty())
        .get_output()
        .stdout
        .clone();
    assert_eq!(parse_response(&response)["permission"], "deny");
    let entry = sandbox.audit_entries().pop().unwrap();
    assert_eq!(entry["action"]["kind"], "shell");
    assert_eq!(entry["rule_id"], "hook.cursor_event_conflict");
}

#[test]
fn autonomous_mode_turns_adapter_asks_into_denials() {
    for (arguments, fixture_name) in [
        (
            vec!["hook", "cursor", "--autonomous"],
            "mcp_missing_server.json",
        ),
        (vec!["hook", "cursor"], "read_secret_content.json"),
    ] {
        let sandbox = Sandbox::new();
        let mut command = sandbox.command();
        command.args(arguments);
        if fixture_name == "read_secret_content.json" {
            command.env("AGENT_SHIELD_AUTONOMOUS", "true");
        }
        let response = command
            .write_stdin(fixture(fixture_name))
            .assert()
            .success()
            .get_output()
            .stdout
            .clone();
        let response = parse_response(&response);
        assert_eq!(response["permission"], "deny");
        assert!(response["agent_message"]
            .as_str()
            .unwrap()
            .contains("autonomous mode"));
    }
}

#[test]
fn malformed_json_and_invalid_tool_input_exit_two() {
    for (fixture_name, error) in [
        ("invalid.json", "invalid Cursor hook input"),
        (
            "mcp_invalid_tool_input.json",
            "tool_input is not valid JSON",
        ),
    ] {
        Sandbox::new()
            .command()
            .args(["hook", "cursor"])
            .write_stdin(fixture(fixture_name))
            .assert()
            .code(2)
            .stdout(predicate::str::is_empty())
            .stderr(predicate::str::contains(error));
    }
}

#[test]
fn fixture_inventory_is_complete_and_file_content_is_never_audited() {
    assert_eq!(fs::read_dir(fixtures_root()).unwrap().count(), 12);

    let sandbox = Sandbox::new();
    sandbox
        .command()
        .args(["hook", "cursor"])
        .write_stdin(fixture("read_secret_content.json"))
        .assert()
        .success();
    let audit = fs::read_to_string(sandbox.state.join("audit.jsonl")).unwrap();
    assert!(!audit.contains("AKIAIOSFODNN7EXAMPLE"));
    assert!(!audit.contains("AWS_ACCESS_KEY_ID"));
}
