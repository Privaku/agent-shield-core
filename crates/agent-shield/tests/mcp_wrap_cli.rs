use std::fs;
use std::path::{Path, PathBuf};

use assert_cmd::Command;
use serde_json::Value;

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

    fn write_home(&self, relative: &str, contents: &str) -> PathBuf {
        write_file(&self.home.join(relative), contents)
    }

    fn write_repo(&self, relative: &str, contents: &str) -> PathBuf {
        write_file(&self.repo.join(relative), contents)
    }
}

fn claude_desktop_config_relative() -> &'static str {
    if cfg!(target_os = "macos") {
        "Library/Application Support/Claude/claude_desktop_config.json"
    } else {
        ".config/Claude/claude_desktop_config.json"
    }
}

fn write_file(path: &Path, contents: &str) -> PathBuf {
    fs::create_dir_all(path.parent().unwrap()).unwrap();
    fs::write(path, contents).unwrap();
    path.to_path_buf()
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

fn read_json(path: &Path) -> Value {
    serde_json::from_slice(&fs::read(path).unwrap()).unwrap()
}

fn assert_wrapped_json(path: &Path, name: &str, command: &str, args: &[&str]) {
    let document = read_json(path);
    let entry = &document["mcpServers"][name];
    let wrapped_command = entry["command"].as_str().unwrap();
    assert!(
        Path::new(wrapped_command)
            .file_name()
            .and_then(|value| value.to_str())
            .is_some_and(|value| value == "agent-shield"),
        "{wrapped_command}"
    );
    assert!(
        Path::new(wrapped_command).is_absolute(),
        "{wrapped_command}"
    );
    let mut expected = vec!["mcp-proxy", "--name", name, "--", command];
    expected.extend(args);
    let actual: Vec<&str> = entry["args"]
        .as_array()
        .unwrap()
        .iter()
        .map(|value| value.as_str().unwrap())
        .collect();
    assert_eq!(actual, expected);
}

#[test]
fn install_mcp_wraps_rewraps_and_unwraps_each_config_format() {
    let sandbox = Sandbox::new();
    let originals = [
        sandbox.write_home(
            claude_desktop_config_relative(),
            "{\n  \"mcpServers\": {\n    \"desktop\": {\n      \"command\": \"npx\",\n      \"args\": [\"-y\", \"desktop\"],\n      \"env\": {\"TOKEN\": \"keep\"}\n    }\n  }\n}\n",
        ),
        sandbox.write_home(
            ".claude.json",
            "{\"theme\":\"dark\",\"mcpServers\":{\"docs\":{\"command\":\"uvx\",\"args\":[\"mcp-docs\"]}}}\n",
        ),
        sandbox.write_repo(
            ".mcp.json",
            "{\n  \"mcpServers\": { \"local\": { \"command\": \"node\", \"args\": [\"server.js\"] } }\n}\n",
        ),
        sandbox.write_home(
            ".cursor/mcp.json",
            "{\"mcpServers\":{\"fs\":{\"command\":\"npx\",\"args\":[\"-y\",\"pkg\"],\"env\":{\"TOKEN\":\"keep\"}}}}\n",
        ),
        sandbox.write_repo(
            ".cursor/mcp.json",
            "{\"mcpServers\":{\"stdio\":{\"command\":\"python\",\"args\":[\"-m\",\"mcp\"]}}}\n",
        ),
        sandbox.write_home(
            ".codex/config.toml",
            "# header\n[mcp_servers.docs]\ncommand = \"uvx\"\nargs = [\"mcp-docs\"]\n\n[mcp_servers.docs.env]\nTOKEN = \"keep\"\n",
        ),
    ];
    let original_bytes: Vec<Vec<u8>> = originals
        .iter()
        .map(|path| fs::read(path).unwrap())
        .collect();

    sandbox.cmd().args(["install", "--mcp"]).assert().success();
    assert_wrapped_json(&originals[0], "desktop", "npx", &["-y", "desktop"]);
    assert_eq!(
        read_json(&originals[0])["mcpServers"]["desktop"]["env"]["TOKEN"],
        "keep"
    );
    assert_wrapped_json(&originals[1], "docs", "uvx", &["mcp-docs"]);
    assert_eq!(read_json(&originals[1])["theme"], "dark");
    assert_wrapped_json(&originals[2], "local", "node", &["server.js"]);
    assert_wrapped_json(&originals[3], "fs", "npx", &["-y", "pkg"]);
    assert_eq!(
        read_json(&originals[3])["mcpServers"]["fs"]["env"]["TOKEN"],
        "keep"
    );
    assert_wrapped_json(&originals[4], "stdio", "python", &["-m", "mcp"]);
    let toml = String::from_utf8(fs::read(&originals[5]).unwrap()).unwrap();
    assert!(toml.contains("# header"));
    assert!(toml.contains("TOKEN = \"keep\""));
    assert!(toml.contains("mcp-proxy"));
    assert!(toml.contains("--name"));

    let wrapped: Vec<Vec<u8>> = originals
        .iter()
        .map(|path| fs::read(path).unwrap())
        .collect();
    let backups: Vec<usize> = originals.iter().map(|path| backup_count(path)).collect();
    sandbox.cmd().args(["install", "--mcp"]).assert().success();
    for (index, path) in originals.iter().enumerate() {
        assert_eq!(
            fs::read(path).unwrap(),
            wrapped[index],
            "{}",
            path.display()
        );
        assert_eq!(backup_count(path), backups[index], "{}", path.display());
    }

    sandbox
        .cmd()
        .args(["uninstall", "--mcp"])
        .assert()
        .success();
    for (index, path) in originals.iter().enumerate() {
        assert_eq!(
            fs::read(path).unwrap(),
            original_bytes[index],
            "{}",
            path.display()
        );
    }
}

#[test]
fn install_mcp_dry_run_shows_a_diff_and_writes_nothing() {
    let sandbox = Sandbox::new();
    let path = sandbox.write_home(
        ".cursor/mcp.json",
        "{\n  \"mcpServers\": {\n    \"fs\": {\n      \"command\": \"npx\",\n      \"args\": [\"-y\", \"pkg\"]\n    }\n  }\n}\n",
    );
    let original = fs::read(&path).unwrap();
    let output = sandbox
        .cmd()
        .args(["install", "--mcp", "--dry-run"])
        .assert()
        .success()
        .get_output()
        .stdout
        .clone();
    let stdout = String::from_utf8(output).unwrap();
    assert!(stdout.contains("--- "));
    assert!(stdout.contains("+++ "));
    assert!(stdout.contains("mcp-proxy"));
    assert!(stdout.contains("Dry-run: no files were written."));
    assert_eq!(fs::read(&path).unwrap(), original);
    assert_eq!(backup_count(&path), 0);
}

#[test]
fn install_mcp_skips_http_sse_servers() {
    let sandbox = Sandbox::new();
    let path = sandbox.write_home(
        ".cursor/mcp.json",
        r#"{"mcpServers":{"remote":{"type":"sse","url":"https://example.com/mcp"},"fs":{"command":"npx","args":["-y","pkg"]}}}"#,
    );
    let output = sandbox
        .cmd()
        .args(["install", "--mcp"])
        .assert()
        .success()
        .get_output()
        .stdout
        .clone();
    let stdout = String::from_utf8(output).unwrap();
    assert!(stdout.contains("Skipping HTTP/SSE MCP server 'remote'"));
    assert!(stdout.contains("Wrapped stdio MCP server 'fs'"));
    assert_eq!(
        read_json(&path)["mcpServers"]["remote"]["url"],
        "https://example.com/mcp"
    );
    assert_wrapped_json(&path, "fs", "npx", &["-y", "pkg"]);
}
