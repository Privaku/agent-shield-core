use std::fs;
use std::path::{Path, PathBuf};

use assert_cmd::Command;
use predicates::prelude::*;
use shield_audit::{AuditWriter, FixedPaths, ACTIVE_LOG_NAME};
use shield_core::model::{
    Action, ActionKind, AgentContext, AgentKind, ArgvTree, Decision, Outcome, RiskScore, Severity,
};

fn append(directory: &Path, outcome: Outcome, index: usize) {
    append_agent(directory, outcome, index, AgentKind::Claude);
}

fn append_agent(directory: &Path, outcome: Outcome, index: usize, agent: AgentKind) {
    let raw = format!("echo {index}");
    let context = AgentContext {
        agent,
        session_id: "cli-test".into(),
        cwd: PathBuf::from("/workspace"),
        autonomous: false,
    };
    let action = Action::new(
        context,
        ActionKind::Shell {
            argv_tree: ArgvTree::Unparsed { raw: raw.clone() },
            raw,
            cwd: PathBuf::from("/workspace"),
            obfuscation: Vec::new(),
        },
    );
    let decision = Decision {
        outcome,
        rule_id: (outcome != Outcome::Allow).then(|| format!("test.{index}")),
        matched_rule_ids: Vec::new(),
        severity: if outcome == Outcome::Allow {
            Severity::Info
        } else {
            Severity::High
        },
        reason_user: "test".into(),
        reason_agent: "test".into(),
        risk_score: RiskScore::MIN,
    };
    AuditWriter::new(&FixedPaths::new(directory))
        .unwrap()
        .append(
            &action,
            &decision,
            (outcome != Outcome::Ask).then_some("policy"),
        )
        .unwrap();
}

fn command(directory: &Path) -> Command {
    let mut command = Command::cargo_bin("agent-shield").unwrap();
    command
        .env_clear()
        .env("HOME", directory)
        .env("AGENT_SHIELD_STATE_DIR", directory)
        .env("PATH", std::env::var_os("PATH").unwrap_or_default());
    command
}

#[test]
fn tail_filters_by_agent_kind() {
    let temp = tempfile::tempdir().unwrap();
    let agents = [
        AgentKind::Claude,
        AgentKind::Cursor,
        AgentKind::Codex,
        AgentKind::Mcp,
        AgentKind::Shim,
    ];
    for (index, agent) in agents.into_iter().enumerate() {
        append_agent(temp.path(), Outcome::Allow, index, agent);
    }
    for agent in ["claude", "cursor", "codex", "mcp", "shim"] {
        let output = command(temp.path())
            .args(["log", "tail", "-n", "20", "--agent", agent])
            .assert()
            .success()
            .get_output()
            .stdout
            .clone();
        let lines = String::from_utf8(output).unwrap();
        assert_eq!(lines.lines().count(), 1, "{agent}");
        let entry: serde_json::Value = serde_json::from_str(lines.trim()).unwrap();
        assert_eq!(entry["agent"], agent);
    }
}

#[test]
fn tail_limits_and_filters_entries() {
    let temp = tempfile::tempdir().unwrap();
    append(temp.path(), Outcome::Allow, 0);
    append(temp.path(), Outcome::Deny, 1);
    append(temp.path(), Outcome::Deny, 2);
    let output = command(temp.path())
        .args(["log", "tail", "-n", "1", "--decision", "deny"])
        .assert()
        .success()
        .get_output()
        .stdout
        .clone();
    let lines = String::from_utf8(output).unwrap();
    assert_eq!(lines.lines().count(), 1);
    let entry: serde_json::Value = serde_json::from_str(lines.trim()).unwrap();
    assert_eq!(entry["decision"], "deny");
    assert_eq!(entry["rule_id"], "test.2");
}

#[test]
fn verify_reports_the_first_bad_file_and_line() {
    let temp = tempfile::tempdir().unwrap();
    append(temp.path(), Outcome::Allow, 0);
    append(temp.path(), Outcome::Deny, 1);
    let path = temp.path().join(ACTIVE_LOG_NAME);
    let mut lines = fs::read_to_string(&path)
        .unwrap()
        .lines()
        .map(str::to_owned)
        .collect::<Vec<_>>();
    let mut value: serde_json::Value = serde_json::from_str(&lines[1]).unwrap();
    value["risk"] = serde_json::json!(0.5);
    lines[1] = serde_json::to_string(&value).unwrap();
    fs::write(&path, format!("{}\n", lines.join("\n"))).unwrap();

    command(temp.path())
        .args(["log", "verify"])
        .assert()
        .failure()
        .stderr(
            predicate::str::contains("audit.jsonl: line 2")
                .and(predicate::str::contains("hash mismatch")),
        );
}

#[test]
fn export_accepts_duration_and_rfc3339_since_values() {
    let temp = tempfile::tempdir().unwrap();
    append(temp.path(), Outcome::Allow, 0);
    append(temp.path(), Outcome::Ask, 1);
    append(temp.path(), Outcome::Deny, 2);

    for since in ["1h", "2000-01-01T00:00:00Z"] {
        let output = command(temp.path())
            .args(["log", "export", "--since", since])
            .assert()
            .success()
            .get_output()
            .stdout
            .clone();
        assert_eq!(String::from_utf8(output).unwrap().lines().count(), 3);
    }

    command(temp.path())
        .args(["log", "export", "--since", "yesterday"])
        .assert()
        .failure()
        .stderr(predicate::str::contains("invalid --since value"));
}

#[test]
fn verify_accepts_an_empty_log_directory() {
    let temp = tempfile::tempdir().unwrap();
    command(temp.path())
        .args(["log", "verify"])
        .assert()
        .success()
        .stdout(predicate::str::contains("OK: 0 entries"));
}

#[test]
fn check_logs_allow_deny_and_pending_ask_with_redaction() {
    let temp = tempfile::tempdir().unwrap();
    command(temp.path())
        .args(["check", "--shell", "echo safe"])
        .assert()
        .code(0);
    command(temp.path())
        .args(["check", "--shell", "cat ~/.ssh/id_rsa"])
        .assert()
        .code(20);
    let canary = "AKIAIOSFODNN7EXAMPLE";
    command(temp.path())
        .args(["check", "--shell", &format!("echo {canary}")])
        .assert()
        .code(10);

    command(temp.path())
        .args(["log", "verify"])
        .assert()
        .success()
        .stdout(predicate::str::contains("OK: 3 entries"));

    let contents = fs::read_to_string(temp.path().join(ACTIVE_LOG_NAME)).unwrap();
    assert!(!contents.contains(canary));
    assert!(contents.contains("[REDACTED:aws_access_key_id]"));
    let entries = contents
        .lines()
        .map(|line| serde_json::from_str::<serde_json::Value>(line).unwrap())
        .collect::<Vec<_>>();
    assert_eq!(entries[0]["decision"], "allow");
    assert_eq!(entries[0]["approver"], "policy");
    assert_eq!(entries[1]["decision"], "deny");
    assert_eq!(entries[1]["approver"], "policy");
    assert_eq!(entries[2]["decision"], "ask");
    assert!(entries[2]["approver"].is_null());
}
