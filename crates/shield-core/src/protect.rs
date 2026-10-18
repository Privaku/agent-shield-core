//! Protect-this-app catalog and process-tree matching (Phase A).
//!
//! Match GUI agents by **bundle ID** and **executable path**. Match Node and
//! Python CLIs by **script path in exec args**, never by the `node` /
//! `python` interpreter name. Team ID pinning is a TODO for after 23 Oct 2026.

use std::collections::{BTreeMap, BTreeSet};
use std::path::{Path, PathBuf};

use serde::{Deserialize, Serialize};

/// Do not guess Apple Team IDs. Fill from `codesign -dv` on 23 Oct 2026.
pub const TEAM_ID_TODO: &str =
    "TODO after 23 Oct 2026: record TeamIdentifier with codesign -dv; do not guess from Homebrew.";

/// One row in the R&D agent catalog.
#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
pub struct AgentSpec {
    pub id: &'static str,
    pub display_name: &'static str,
    /// GUI bundle identifiers. Empty for CLI-only agents.
    pub bundle_ids: &'static [&'static str],
    /// CLI names on PATH (`claude`, `copilot`, …).
    pub cli_names: &'static [&'static str],
    /// Substrings of argv that identify a Node/Python launcher script.
    pub script_markers: &'static [&'static str],
    /// Host bundle IDs when the agent runs inside another app (VS Code).
    pub host_bundle_ids: &'static [&'static str],
    /// Always `None` until the 23 Oct Mac session.
    pub team_id: Option<&'static str>,
}

/// Known coding-agent process identities. Team IDs stay unset.
pub fn catalog() -> &'static [AgentSpec] {
    CATALOG
}

const CATALOG: &[AgentSpec] = &[
    AgentSpec {
        id: "github-copilot-vscode",
        display_name: "GitHub Copilot (VS Code)",
        bundle_ids: &[],
        cli_names: &[],
        script_markers: &[],
        host_bundle_ids: &["com.microsoft.VSCode"],
        team_id: None,
    },
    AgentSpec {
        id: "github-copilot-cli",
        display_name: "GitHub Copilot CLI",
        bundle_ids: &[],
        cli_names: &["copilot"],
        script_markers: &["@github/copilot/npm-loader.js"],
        host_bundle_ids: &[],
        team_id: None,
    },
    AgentSpec {
        id: "chatgpt-codex-app",
        display_name: "ChatGPT / Codex app",
        bundle_ids: &[
            "com.openai.codex",
            "com.openai.chat",
            "com.openai.sky.CUAService",
        ],
        cli_names: &[],
        script_markers: &[],
        host_bundle_ids: &[],
        team_id: None,
    },
    AgentSpec {
        id: "codex-cli",
        display_name: "Codex CLI",
        bundle_ids: &[],
        cli_names: &["codex"],
        script_markers: &["@openai/codex/bin/codex.js"],
        host_bundle_ids: &[],
        team_id: None,
    },
    AgentSpec {
        id: "claude-desktop",
        display_name: "Claude Desktop",
        bundle_ids: &["com.anthropic.claudefordesktop"],
        cli_names: &[],
        script_markers: &[],
        host_bundle_ids: &[],
        team_id: None,
    },
    AgentSpec {
        id: "claude-code",
        display_name: "Claude Code",
        bundle_ids: &[],
        cli_names: &["claude"],
        script_markers: &[],
        host_bundle_ids: &[],
        team_id: None,
    },
    AgentSpec {
        id: "gemini-cli",
        display_name: "Gemini CLI",
        bundle_ids: &[],
        cli_names: &["gemini"],
        script_markers: &["@google/gemini-cli/bundle/gemini.js"],
        host_bundle_ids: &[],
        team_id: None,
    },
    AgentSpec {
        id: "windsurf",
        display_name: "Windsurf",
        bundle_ids: &["com.exafunction.windsurf"],
        cli_names: &[],
        script_markers: &[],
        host_bundle_ids: &[],
        team_id: None,
    },
    AgentSpec {
        id: "opencode",
        display_name: "OpenCode",
        bundle_ids: &["ai.opencode.desktop"],
        cli_names: &["opencode"],
        script_markers: &[],
        host_bundle_ids: &[],
        team_id: None,
    },
    AgentSpec {
        id: "cline",
        display_name: "Cline",
        bundle_ids: &[],
        cli_names: &["cline"],
        script_markers: &[],
        host_bundle_ids: &["com.microsoft.VSCode"],
        team_id: None,
    },
    AgentSpec {
        id: "zed",
        display_name: "Zed",
        bundle_ids: &["dev.zed.Zed"],
        cli_names: &["zed"],
        script_markers: &[],
        host_bundle_ids: &[],
        team_id: None,
    },
    AgentSpec {
        id: "kiro-ide",
        display_name: "Kiro IDE",
        bundle_ids: &["dev.kiro.desktop"],
        cli_names: &["kiro"],
        script_markers: &[],
        host_bundle_ids: &[],
        team_id: None,
    },
    AgentSpec {
        id: "kiro-cli",
        display_name: "Kiro CLI",
        bundle_ids: &["dev.kiro.cli", "com.amazon.codewhisperer"],
        cli_names: &["kiro-cli", "q"],
        script_markers: &[],
        host_bundle_ids: &[],
        team_id: None,
    },
    AgentSpec {
        id: "aider",
        display_name: "Aider",
        bundle_ids: &[],
        cli_names: &["aider"],
        script_markers: &["/bin/aider"],
        host_bundle_ids: &[],
        team_id: None,
    },
    AgentSpec {
        id: "continue-cli",
        display_name: "Continue CLI",
        bundle_ids: &[],
        cli_names: &["cn"],
        script_markers: &["@continuedev/cli/dist/cn.js"],
        host_bundle_ids: &["com.microsoft.VSCode"],
        team_id: None,
    },
    AgentSpec {
        id: "grok-cli",
        display_name: "Grok Build CLI",
        bundle_ids: &[],
        cli_names: &["grok"],
        script_markers: &[],
        host_bundle_ids: &[],
        team_id: None,
    },
    AgentSpec {
        id: "junie",
        display_name: "JetBrains Junie",
        bundle_ids: &["com.jetbrains.intellij"],
        cli_names: &["junie"],
        script_markers: &["@jetbrains/junie-cli/bin/index.js"],
        host_bundle_ids: &[],
        team_id: None,
    },
    AgentSpec {
        id: "roo-code",
        display_name: "Roo Code",
        bundle_ids: &[],
        cli_names: &[],
        script_markers: &[],
        host_bundle_ids: &["com.microsoft.VSCode"],
        team_id: None,
    },
    AgentSpec {
        id: "muse",
        display_name: "Meta Muse Code",
        bundle_ids: &[],
        cli_names: &["muse"],
        script_markers: &[],
        host_bundle_ids: &[],
        team_id: None,
    },
    AgentSpec {
        id: "grok-bot",
        display_name: "Grok Bot",
        bundle_ids: &["com.anysphere.sand"],
        cli_names: &[],
        script_markers: &[],
        host_bundle_ids: &[],
        team_id: None,
    },
];

/// Observed process used for attribution until Endpoint Security FORK/EXIT.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ProcessIdentity {
    pub pid: u32,
    pub ppid: u32,
    pub pgid: u32,
    pub path: PathBuf,
    pub bundle_id: Option<String>,
    pub argv: Vec<String>,
}

/// Which catalog row a process belongs to, if any.
pub fn match_process<'a>(
    proc: &ProcessIdentity,
    catalog: &'a [AgentSpec],
) -> Option<&'a AgentSpec> {
    for spec in catalog {
        if let Some(bundle) = proc.bundle_id.as_deref() {
            if spec.bundle_ids.contains(&bundle) || spec.host_bundle_ids.contains(&bundle) {
                return Some(spec);
            }
        }
        let file_name = proc
            .path
            .file_name()
            .and_then(|name| name.to_str())
            .unwrap_or("");
        if spec.cli_names.contains(&file_name) {
            return Some(spec);
        }
        if matches_script_marker(proc, spec) {
            return Some(spec);
        }
    }
    None
}

fn matches_script_marker(proc: &ProcessIdentity, spec: &AgentSpec) -> bool {
    if spec.script_markers.is_empty() {
        return false;
    }
    let interpreter = proc
        .path
        .file_name()
        .and_then(|name| name.to_str())
        .unwrap_or("");
    let is_node_or_python = interpreter.starts_with("node")
        || interpreter.starts_with("python")
        || interpreter == "bun"
        || interpreter == "deno";
    if !is_node_or_python && spec.cli_names.is_empty() {
        // Still allow marker matches on argv for wrapped launchers.
    }
    spec.script_markers.iter().any(|marker| {
        proc.argv.iter().any(|arg| {
            let normalised = arg.replace('\\', "/");
            normalised.contains(marker)
        })
    })
}

/// True when `child` shares the sandbox session process group, or is a
/// descendant of `root` via `ppid` in `by_pid`.
pub fn in_process_tree(
    child: &ProcessIdentity,
    root_pid: u32,
    root_pgid: u32,
    by_pid: &BTreeMap<u32, ProcessIdentity>,
) -> bool {
    if child.pid == root_pid || child.pgid == root_pgid {
        return true;
    }
    let mut pid = child.ppid;
    let mut seen = BTreeSet::new();
    while pid != 0 && seen.insert(pid) {
        if pid == root_pid {
            return true;
        }
        match by_pid.get(&pid) {
            Some(parent) => pid = parent.ppid,
            None => break,
        }
    }
    false
}

/// User choices: protect or ignore each catalog id. Missing ids default on.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct ProtectedApps {
    pub version: u32,
    pub apps: BTreeMap<String, bool>,
}

impl Default for ProtectedApps {
    fn default() -> Self {
        Self {
            version: 1,
            apps: BTreeMap::new(),
        }
    }
}

impl ProtectedApps {
    pub fn is_protected(&self, id: &str) -> bool {
        self.apps.get(id).copied().unwrap_or(true)
    }

    pub fn set(&mut self, id: String, protect: bool) {
        self.apps.insert(id, protect);
    }

    pub fn path(config_dir: &Path) -> PathBuf {
        config_dir.join("protected-apps.yaml")
    }

    pub fn load(config_dir: &Path) -> Self {
        let path = Self::path(config_dir);
        let Ok(text) = std::fs::read_to_string(path) else {
            return Self::default();
        };
        serde_yaml_ng::from_str(&text).unwrap_or_default()
    }

    pub fn save(&self, config_dir: &Path) -> std::io::Result<()> {
        std::fs::create_dir_all(config_dir)?;
        let text = serde_yaml_ng::to_string(self)
            .map_err(|error| std::io::Error::other(error.to_string()))?;
        std::fs::write(Self::path(config_dir), text)
    }
}

/// Match a process only if the user left that catalog row protected.
pub fn match_protected<'a>(
    proc: &ProcessIdentity,
    catalog: &'a [AgentSpec],
    prefs: &ProtectedApps,
) -> Option<&'a AgentSpec> {
    match_process(proc, catalog).filter(|spec| prefs.is_protected(spec.id))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn team_ids_are_unset_until_codesign_session() {
        assert!(TEAM_ID_TODO.contains("23 Oct"));
        for spec in catalog() {
            assert!(
                spec.team_id.is_none(),
                "{} must not guess a Team ID",
                spec.id
            );
        }
    }

    #[test]
    fn node_python_match_on_script_path_not_interpreter_name() {
        let node = ProcessIdentity {
            pid: 10,
            ppid: 1,
            pgid: 10,
            path: PathBuf::from("/usr/local/bin/node"),
            bundle_id: None,
            argv: vec![
                "node".into(),
                "/Users/x/.npm/_npx/@github/copilot/npm-loader.js".into(),
            ],
        };
        let python = ProcessIdentity {
            pid: 11,
            ppid: 1,
            pgid: 11,
            path: PathBuf::from("/opt/homebrew/bin/python3"),
            bundle_id: None,
            argv: vec![
                "python3".into(),
                "/Users/x/.local/pipx/venvs/aider-chat/bin/aider".into(),
            ],
        };
        let bare_node = ProcessIdentity {
            pid: 12,
            ppid: 1,
            pgid: 12,
            path: PathBuf::from("/usr/local/bin/node"),
            bundle_id: None,
            argv: vec!["node".into(), "app.js".into()],
        };
        assert_eq!(
            match_process(&node, catalog()).map(|s| s.id),
            Some("github-copilot-cli")
        );
        assert_eq!(
            match_process(&python, catalog()).map(|s| s.id),
            Some("aider")
        );
        assert_eq!(match_process(&bare_node, catalog()), None);
    }

    #[test]
    fn bundle_id_and_cli_path_match() {
        let gui = ProcessIdentity {
            pid: 20,
            ppid: 1,
            pgid: 20,
            path: PathBuf::from("/Applications/Claude.app/Contents/MacOS/Claude"),
            bundle_id: Some("com.anthropic.claudefordesktop".into()),
            argv: vec!["Claude".into()],
        };
        let cli = ProcessIdentity {
            pid: 21,
            ppid: 1,
            pgid: 21,
            path: PathBuf::from("/Users/x/.local/bin/claude"),
            bundle_id: None,
            argv: vec!["claude".into()],
        };
        assert_eq!(
            match_process(&gui, catalog()).map(|s| s.id),
            Some("claude-desktop")
        );
        assert_eq!(
            match_process(&cli, catalog()).map(|s| s.id),
            Some("claude-code")
        );
    }

    #[test]
    fn process_group_and_ppid_chain_attribute_children() {
        let root = ProcessIdentity {
            pid: 100,
            ppid: 1,
            pgid: 100,
            path: PathBuf::from("/bin/claude"),
            bundle_id: None,
            argv: vec!["claude".into()],
        };
        let child = ProcessIdentity {
            pid: 101,
            ppid: 100,
            pgid: 100,
            path: PathBuf::from("/bin/bash"),
            bundle_id: None,
            argv: vec!["bash".into()],
        };
        let grandchild = ProcessIdentity {
            pid: 102,
            ppid: 101,
            pgid: 100,
            path: PathBuf::from("/usr/bin/curl"),
            bundle_id: None,
            argv: vec!["curl".into()],
        };
        let outsider = ProcessIdentity {
            pid: 200,
            ppid: 1,
            pgid: 200,
            path: PathBuf::from("/usr/bin/curl"),
            bundle_id: None,
            argv: vec!["curl".into()],
        };
        let mut by_pid = BTreeMap::new();
        by_pid.insert(100, root.clone());
        by_pid.insert(101, child.clone());
        by_pid.insert(102, grandchild.clone());
        by_pid.insert(200, outsider.clone());
        assert!(in_process_tree(&child, 100, 100, &by_pid));
        assert!(in_process_tree(&grandchild, 100, 100, &by_pid));
        assert!(!in_process_tree(&outsider, 100, 100, &by_pid));
    }

    #[test]
    fn ignored_app_is_not_protected() {
        let proc = ProcessIdentity {
            pid: 1,
            ppid: 1,
            pgid: 1,
            path: PathBuf::from("/bin/claude"),
            bundle_id: None,
            argv: vec!["claude".into()],
        };
        let mut prefs = ProtectedApps::default();
        assert!(match_protected(&proc, catalog(), &prefs).is_some());
        prefs.set("claude-code".into(), false);
        assert!(match_protected(&proc, catalog(), &prefs).is_none());
    }
}
