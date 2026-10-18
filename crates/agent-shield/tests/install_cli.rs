use std::fs;
use std::path::{Path, PathBuf};

use assert_cmd::Command;
use serde_json::{json, Value};

struct Sandbox {
    _temp: tempfile::TempDir,
    home: PathBuf,
    repo: PathBuf,
}

impl Sandbox {
    fn new() -> Self {
        let temp = tempfile::tempdir().unwrap();
        let home = temp.path().join("home");
        let repo = temp.path().join("repo");
        fs::create_dir_all(&home).unwrap();
        fs::create_dir_all(&repo).unwrap();
        Self {
            _temp: temp,
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

    fn create_agent_dirs(&self) {
        for directory in [".claude", ".cursor", ".codex"] {
            fs::create_dir_all(self.home.join(directory)).unwrap();
        }
    }

    fn write(&self, relative: &str, contents: &str) {
        let path = self.home.join(relative);
        fs::create_dir_all(path.parent().unwrap()).unwrap();
        fs::write(path, contents).unwrap();
    }

    fn read_json(&self, relative: &str) -> Value {
        serde_json::from_slice(&fs::read(self.home.join(relative)).unwrap()).unwrap()
    }
}

fn owned_pre_tool_command(document: &Value) -> &str {
    document["hooks"]["PreToolUse"]
        .as_array()
        .unwrap()
        .iter()
        .flat_map(|entry| entry["hooks"].as_array().unwrap())
        .find_map(|hook| {
            hook["command"].as_str().filter(|command| {
                command.ends_with("agent-shield hook claude")
                    || command.ends_with("agent-shield hook codex")
            })
        })
        .unwrap()
}

fn backup_count(path: &Path) -> usize {
    let filename = path.file_name().unwrap().to_string_lossy();
    let prefix = format!("{filename}.agent-shield.");
    fs::read_dir(path.parent().unwrap())
        .unwrap()
        .filter_map(Result::ok)
        .filter(|entry| entry.file_name().to_string_lossy().starts_with(&prefix))
        .count()
}

#[test]
fn install_into_empty_configs_uses_absolute_binary_and_all_native_events() {
    let sandbox = Sandbox::new();
    sandbox.create_agent_dirs();
    sandbox.cmd().args(["install", "--all"]).assert().success();

    for relative in [".claude/settings.json", ".codex/hooks.json"] {
        let document = sandbox.read_json(relative);
        let command = owned_pre_tool_command(&document);
        let binary = command
            .strip_suffix(if relative.contains("claude") {
                " hook claude"
            } else {
                " hook codex"
            })
            .unwrap();
        assert!(Path::new(binary).is_absolute(), "{command}");
        assert!(Path::new(binary).is_file(), "{command}");
    }

    let cursor = sandbox.read_json(".cursor/hooks.json");
    for event in [
        "beforeShellExecution",
        "beforeMCPExecution",
        "beforeReadFile",
    ] {
        let entries = cursor["hooks"][event].as_array().unwrap();
        assert_eq!(entries.len(), 1);
        assert_eq!(entries[0]["failClosed"], true);
        assert!(entries[0]["command"]
            .as_str()
            .unwrap()
            .ends_with(&format!("agent-shield hook cursor --event {event}")));
    }
}

#[test]
fn install_preserves_existing_user_hooks_and_is_byte_idempotent() {
    let sandbox = Sandbox::new();
    sandbox.write(
        ".claude/settings.json",
        "{\"theme\":\"dark\",\"hooks\":{\"PreToolUse\":[{\"matcher\":\"Bash\",\"hooks\":[{\"type\":\"command\",\"command\":\"user-claude\"}]}]}}\n",
    );
    sandbox.write(
        ".cursor/hooks.json",
        "{\"version\":1,\"hooks\":{\"beforeShellExecution\":[{\"command\":\"user-cursor\",\"failClosed\":false}]}}\n",
    );
    sandbox.write(
        ".codex/hooks.json",
        "{\"hooks\":{\"PreToolUse\":[{\"matcher\":\"*\",\"hooks\":[{\"type\":\"command\",\"command\":\"user-codex\"}]}]}}\n",
    );
    sandbox.cmd().args(["install", "--all"]).assert().success();

    let claude = sandbox.read_json(".claude/settings.json");
    assert!(claude.to_string().contains("user-claude"));
    assert_eq!(claude["theme"], "dark");
    let cursor = sandbox.read_json(".cursor/hooks.json");
    assert!(cursor.to_string().contains("user-cursor"));
    let codex = sandbox.read_json(".codex/hooks.json");
    assert!(codex.to_string().contains("user-codex"));

    let paths = [
        sandbox.home.join(".claude/settings.json"),
        sandbox.home.join(".cursor/hooks.json"),
        sandbox.home.join(".codex/hooks.json"),
    ];
    let once = paths
        .iter()
        .map(|path| fs::read(path).unwrap())
        .collect::<Vec<_>>();
    let backups = paths
        .iter()
        .map(|path| backup_count(path))
        .collect::<Vec<_>>();
    sandbox.cmd().args(["install", "--all"]).assert().success();
    for (index, path) in paths.iter().enumerate() {
        assert_eq!(fs::read(path).unwrap(), once[index]);
        assert_eq!(backup_count(path), backups[index]);
    }
}

#[test]
fn install_then_uninstall_restores_original_files_byte_for_byte() {
    let sandbox = Sandbox::new();
    let originals = [
        (
            ".claude/settings.json",
            "{\n \"theme\" : \"dark\", \"hooks\": {\"PreToolUse\": []}\n}\n",
        ),
        (
            ".cursor/hooks.json",
            "{\"version\": 1, \"hooks\": {\"beforeReadFile\": [{\"command\":\"mine\"}]}}\n",
        ),
        (
            ".codex/hooks.json",
            "{\n  \"custom\": [1, 2, 3],\n  \"hooks\": {\"PreToolUse\": []}\n}\n",
        ),
    ];
    for (relative, contents) in originals {
        sandbox.write(relative, contents);
    }
    sandbox.cmd().args(["install", "--all"]).assert().success();
    sandbox.cmd().arg("uninstall").assert().success();
    for (relative, contents) in originals {
        assert_eq!(
            fs::read(sandbox.home.join(relative)).unwrap(),
            contents.as_bytes()
        );
    }
}

#[test]
fn uninstall_one_agent_leaves_the_others() {
    let sandbox = Sandbox::new();
    sandbox.create_agent_dirs();
    sandbox.cmd().args(["install", "--all"]).assert().success();
    sandbox
        .cmd()
        .args(["uninstall", "--cursor"])
        .assert()
        .success();
    let claude = sandbox.read_json(".claude/settings.json");
    assert!(claude.to_string().contains("hook claude"));
    let cursor = fs::read_to_string(sandbox.home.join(".cursor/hooks.json")).unwrap_or_default();
    assert!(!cursor.contains("agent-shield hook cursor"), "{cursor}");
    let codex = sandbox.read_json(".codex/hooks.json");
    assert!(codex.to_string().contains("hook codex"));
}

#[test]
fn doctor_json_flags_removed_hook_and_cursor_fail_open() {
    let sandbox = Sandbox::new();
    sandbox.create_agent_dirs();
    sandbox.cmd().args(["install", "--all"]).assert().success();

    let mut claude = sandbox.read_json(".claude/settings.json");
    claude["hooks"]["PreToolUse"] = json!([]);
    fs::write(
        sandbox.home.join(".claude/settings.json"),
        serde_json::to_vec_pretty(&claude).unwrap(),
    )
    .unwrap();
    let mut cursor = sandbox.read_json(".cursor/hooks.json");
    cursor["hooks"]["beforeMCPExecution"][0]["failClosed"] = json!(false);
    fs::write(
        sandbox.home.join(".cursor/hooks.json"),
        serde_json::to_vec_pretty(&cursor).unwrap(),
    )
    .unwrap();

    let output = sandbox
        .cmd()
        .args(["doctor", "--json"])
        .assert()
        .code(1)
        .get_output()
        .stdout
        .clone();
    let report: Value = serde_json::from_slice(&output).unwrap();
    assert_eq!(report["schema_version"], 1);
    assert_eq!(report["status"], "error");
    let hooks = report["hooks"].as_array().unwrap();
    let claude = hooks.iter().find(|hook| hook["agent"] == "claude").unwrap();
    assert!(claude["message"].as_str().unwrap().contains("missing"));
    let cursor = hooks.iter().find(|hook| hook["agent"] == "cursor").unwrap();
    assert!(cursor["message"]
        .as_str()
        .unwrap()
        .contains("failClosed to true"));
    assert_eq!(report["daemon"]["status"], "warning");
    assert!(report["daemon"]["message"]
        .as_str()
        .unwrap()
        .contains("daemon is not running"));
}

#[test]
fn healthy_doctor_json_has_stable_parseable_shape() {
    let sandbox = Sandbox::new();
    sandbox.create_agent_dirs();
    sandbox.cmd().args(["install", "--all"]).assert().success();
    let output = sandbox
        .cmd()
        .args(["doctor", "--json"])
        .assert()
        .success()
        .get_output()
        .stdout
        .clone();
    let report: Value = serde_json::from_slice(&output).unwrap();
    assert_eq!(report["schema_version"], 1);
    assert_eq!(report["status"], "warning");
    assert_eq!(report["binary"]["status"], "ok");
    assert_eq!(report["policy"]["status"], "ok");
    assert_eq!(report["hooks"].as_array().unwrap().len(), 3);
}
