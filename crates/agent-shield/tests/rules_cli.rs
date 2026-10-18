//! M3 acceptance for the CLI: `rules list` and `rules validate` exit codes
//! and messages. Every test runs with `HOME` and the working directory
//! pointed at a fresh temp dir, so the developer's own policy files never
//! take part.

use std::fs;
use std::path::{Path, PathBuf};

use assert_cmd::Command;
use predicates::prelude::*;
use predicates::str::contains;

const USER_POLICY_RELATIVE: &str = ".config/privaku/agent-shield/policy.yaml";

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
        Sandbox {
            _tmp: tmp,
            home,
            repo,
        }
    }

    fn cmd(&self) -> Command {
        let mut cmd = Command::cargo_bin("agent-shield").unwrap();
        cmd.env_clear()
            .env("HOME", &self.home)
            .env("PATH", std::env::var_os("PATH").unwrap_or_default())
            .current_dir(&self.repo);
        cmd
    }

    fn write_user(&self, text: &str) -> PathBuf {
        let path = self.home.join(USER_POLICY_RELATIVE);
        write(&path, text);
        path
    }

    fn write_project(&self, text: &str) -> PathBuf {
        let path = self.repo.join(".agent-shield.yaml");
        write(&path, text);
        path
    }

    fn write_file(&self, name: &str, text: &str) -> PathBuf {
        let path = self.repo.join(name);
        write(&path, text);
        path
    }
}

fn write(path: &Path, text: &str) {
    fs::create_dir_all(path.parent().unwrap()).unwrap();
    fs::write(path, text).unwrap();
}

const USER_RULE: &str = "version: 1\ndefaults:\n  ask_threshold: 0.5\nrules:\n  - id: user.ask_scp\n    description: Ask before scp\n    severity: medium\n    decision: ask\n    match: { program: scp }\n";

// --- rules list -------------------------------------------------------------

#[test]
fn list_shows_the_embedded_default_when_no_files_exist() {
    let sb = Sandbox::new();
    sb.cmd()
        .args(["rules", "list"])
        .assert()
        .success()
        .stdout(contains("Policy v1:"))
        .stdout(contains("embedded"))
        .stdout(contains("secrets.ssh_private_key"))
        .stdout(contains("rce.pipe_to_shell"))
        .stdout(contains("ask_threshold=0.70"))
        .stdout(contains("Disabled:").not());
}

#[test]
fn list_merges_user_and_project_files_from_home_and_cwd() {
    let sb = Sandbox::new();
    let user = sb.write_user(USER_RULE);
    let project = sb.write_project(
        "version: 1\ndisable: [user.ask_scp]\nrules:\n  - id: project.block_sudo\n    severity: high\n    decision: deny\n    match: { program: sudo }\n",
    );
    sb.cmd()
        .args(["rules", "list"])
        .assert()
        .success()
        .stdout(contains(user.display().to_string()))
        .stdout(contains(project.display().to_string()))
        .stdout(contains("ask_threshold=0.50"))
        .stdout(contains("project.block_sudo"))
        .stdout(contains("Disabled:"))
        .stdout(contains("user.ask_scp  (by project file"))
        .stdout(contains("21 rules enabled, 1 disabled"));
}

#[test]
fn list_json_is_machine_readable() {
    let sb = Sandbox::new();
    sb.write_user(USER_RULE);
    let out = sb
        .cmd()
        .args(["rules", "list", "--json"])
        .assert()
        .success()
        .get_output()
        .stdout
        .clone();
    let json: serde_json::Value = serde_json::from_slice(&out).expect("valid JSON");
    assert_eq!(json["version"], 1);
    assert_eq!(json["defaults"]["ask_threshold"], 0.5);
    assert_eq!(json["defaults"]["on_no_ui"], "deny");
    let rules = json["rules"].as_array().unwrap();
    assert!(rules
        .iter()
        .any(|r| r["id"] == "user.ask_scp" && r["layer"] == "user"));
    assert!(rules
        .iter()
        .any(|r| r["id"] == "secrets.ssh_private_key" && r["layer"] == "embedded"));
    assert_eq!(json["sources"].as_array().unwrap().len(), 2);
}

#[test]
fn list_fails_closed_when_a_layer_is_invalid() {
    let sb = Sandbox::new();
    let project = sb.write_project(
        "version: 1\nrules:\n  - id: a.b\n    severity: high\n    decision: block\n    match: { program: x }\n",
    );
    sb.cmd()
        .args(["rules", "list"])
        .assert()
        .code(1)
        .stdout(predicate::str::is_empty())
        .stderr(contains(format!(
            "error: {}:5: rule `a.b`:",
            fs::canonicalize(&project).unwrap_or(project).display()
        )))
        .stderr(contains(
            "unknown variant `block`, expected one of `allow`, `ask`, `deny`",
        ))
        .stderr(contains("every action is denied"));
}

#[test]
fn list_rejects_a_project_file_that_weakens_a_critical_rule() {
    let sb = Sandbox::new();
    sb.write_project("version: 1\ndisable: [secrets.ssh_private_key]\n");
    sb.cmd()
        .args(["rules", "list"])
        .assert()
        .code(1)
        .stderr(contains(
            "rule `secrets.ssh_private_key`: disabling a critical rule",
        ))
        .stderr(contains("project files can never do this"));
}

// --- rules validate ---------------------------------------------------------

#[test]
fn validate_accepts_a_valid_file() {
    let sb = Sandbox::new();
    let file = sb.write_file("policy.yaml", USER_RULE);
    sb.cmd()
        .args(["rules", "validate"])
        .arg(&file)
        .assert()
        .success()
        .stdout(contains(format!("OK: {} is valid", file.display())))
        .stdout(contains("1 rule in file, 21 enabled after merge"))
        .stdout(contains("as the user policy"))
        .stderr(predicate::str::is_empty());
}

#[test]
fn validate_exits_non_zero_on_duplicate_ids() {
    let sb = Sandbox::new();
    let file = sb.write_file(
        "dup.yaml",
        "version: 1\nrules:\n  - id: a.b\n    severity: low\n    decision: ask\n    match: { program: x }\n  - id: a.b\n    severity: low\n    decision: ask\n    match: { program: y }\n",
    );
    sb.cmd()
        .args(["rules", "validate"])
        .arg(&file)
        .assert()
        .code(1)
        .stdout(predicate::str::is_empty())
        .stderr(contains(format!(
            "error: {}:7: rule `a.b`: duplicate rule id; first defined at line 3",
            file.display()
        )));
}

#[test]
fn validate_exits_non_zero_on_unknown_fields() {
    let sb = Sandbox::new();
    let file = sb.write_file(
        "typo.yaml",
        "version: 1\nrules:\n  - id: a.b\n    severity: low\n    decision: ask\n    match: { programs: x }\n",
    );
    sb.cmd()
        .args(["rules", "validate"])
        .arg(&file)
        .assert()
        .code(1)
        .stderr(contains(":6: rule `a.b`:"))
        .stderr(contains("unknown field `programs`"));

    let file = sb.write_file("top.yaml", "version: 1\nrulez: []\n");
    sb.cmd()
        .args(["rules", "validate"])
        .arg(&file)
        .assert()
        .code(1)
        .stderr(contains(":2: unknown field `rulez`"));
}

#[test]
fn validate_exits_non_zero_on_bad_decision_severity_and_syntax() {
    let sb = Sandbox::new();
    let file = sb.write_file(
        "decision.yaml",
        "version: 1\nrules:\n  - id: a.b\n    severity: low\n    decision: Deny\n    match: { program: x }\n",
    );
    sb.cmd()
        .args(["rules", "validate"])
        .arg(&file)
        .assert()
        .code(1)
        .stderr(contains(":5: rule `a.b`:"))
        .stderr(contains("unknown variant `Deny`"));

    let file = sb.write_file(
        "severity.yaml",
        "version: 1\nrules:\n  - id: a.b\n    severity: fatal\n    decision: deny\n    match: { program: x }\n",
    );
    sb.cmd()
        .args(["rules", "validate"])
        .arg(&file)
        .assert()
        .code(1)
        .stderr(contains(":4: rule `a.b`:"))
        .stderr(contains("unknown variant `fatal`"));

    let file = sb.write_file("broken.yaml", "version: 1\nrules:\n  - id: [\n");
    sb.cmd()
        .args(["rules", "validate"])
        .arg(&file)
        .assert()
        .code(1)
        .stderr(contains("error: "));

    let file = sb.write_file("v2.yaml", "version: 2\n");
    sb.cmd()
        .args(["rules", "validate"])
        .arg(&file)
        .assert()
        .code(1)
        .stderr(contains(":1: unsupported policy version 2"));
}

#[test]
fn validate_infers_the_project_layer_from_the_file_name() {
    let sb = Sandbox::new();
    let project = sb.write_project("version: 1\ndisable: [rce.pipe_to_shell]\n");
    sb.cmd()
        .args(["rules", "validate"])
        .arg(&project)
        .assert()
        .code(1)
        .stderr(contains(
            "rule `rce.pipe_to_shell`: disabling a critical rule",
        ))
        .stderr(contains("project files can never do this"));

    // Validating as the user layer without the flag is also rejected...
    sb.cmd()
        .args(["rules", "validate", "--as", "user"])
        .arg(&project)
        .assert()
        .code(1)
        .stderr(contains("set `allow_override_critical: true`"));

    // ...and allowed with it, but only as a user file.
    let flagged = sb.write_file(
        "policy.yaml",
        "version: 1\nallow_override_critical: true\ndisable: [rce.pipe_to_shell]\n",
    );
    sb.cmd()
        .args(["rules", "validate"])
        .arg(&flagged)
        .assert()
        .success()
        .stdout(contains("19 enabled after merge"));
    sb.cmd()
        .args(["rules", "validate", "--as", "project"])
        .arg(&flagged)
        .assert()
        .code(1)
        .stderr(contains(
            ":2: `allow_override_critical` is only honoured in the user policy file",
        ));
}

#[test]
fn validate_project_file_uses_the_real_user_file_as_its_base() {
    let sb = Sandbox::new();
    let project = sb.write_project("version: 1\ndisable: [user.ask_scp]\n");
    sb.cmd()
        .args(["rules", "validate"])
        .arg(&project)
        .assert()
        .code(1)
        .stderr(contains(
            "rule `user.ask_scp`: `disable` names a rule no earlier policy layer defines",
        ))
        .stdout(predicate::str::is_empty());

    sb.write_user(USER_RULE);
    sb.cmd()
        .args(["rules", "validate"])
        .arg(&project)
        .assert()
        .success()
        .stdout(contains(
            "as a project policy over the embedded default and the user policy",
        ));
}

#[test]
fn validate_fails_on_missing_files_and_bad_flags() {
    let sb = Sandbox::new();
    sb.cmd()
        .args(["rules", "validate", "does-not-exist.yaml"])
        .assert()
        .code(1)
        .stderr(contains(
            "does-not-exist.yaml: cannot read policy file: no such file",
        ));

    let file = sb.write_file("policy.yaml", "version: 1\n");
    sb.cmd()
        .args(["rules", "validate", "--as", "bogus"])
        .arg(&file)
        .assert()
        .code(2);

    sb.cmd().args(["rules", "validate"]).assert().code(2);
}

#[test]
fn validate_accepts_the_embedded_default_as_itself() {
    let sb = Sandbox::new();
    let file = sb.write_file("default.yaml", shield_core::policy::EMBEDDED_DEFAULT);
    sb.cmd()
        .args(["rules", "validate", "--as", "embedded"])
        .arg(&file)
        .assert()
        .success()
        .stdout(contains("as the embedded default"));
}

#[test]
fn version_still_prints() {
    Sandbox::new()
        .cmd()
        .arg("--version")
        .assert()
        .success()
        .stdout(predicate::str::is_match(r"^agent-shield 0\.1\.0").unwrap());
}
