//! Generated Seatbelt profiles for `sandbox-exec` (Phase A).
//!
//! The profile allows the rest of the session and **denies** SSH private
//! keys, Keychain, cloud credentials, and browser login data. Linux tests
//! cover profile text only; macOS applies it with `sandbox-exec`.

use std::fs;
use std::path::{Path, PathBuf};

/// CLI names launched with `agent-shield run <cli-agent>` under Seatbelt.
pub const SANDBOXED_CLIS: &[&str] = &[
    "claude", "codex", "gemini", "grok", "muse", "copilot", "aider", "opencode", "cn", "junie",
    "cline", "kiro", "kiro-cli",
];

/// True when `name` (a file name or argv0 basename) is a sandboxed CLI.
pub fn is_sandboxed_cli(name: &str) -> bool {
    let base = Path::new(name)
        .file_name()
        .and_then(|value| value.to_str())
        .unwrap_or(name);
    SANDBOXED_CLIS.contains(&base)
}

/// Absolute paths the generated profile must deny (directories use `subpath`).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct DeniedPath {
    pub path: PathBuf,
    pub kind: DeniedKind,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum DeniedKind {
    /// Deny the whole tree.
    Subpath,
    /// Deny one file.
    Literal,
}

/// User-policy protected folders and files (`user.protected.folder.*` /
/// `user.protected.file.*`) denied by the generated Seatbelt profile.
pub fn user_protected_denied_paths(home: &Path) -> Vec<DeniedPath> {
    let paths = crate::policy::Paths::new(Some(home), None);
    let Ok(policy) = crate::policy::load(&paths) else {
        return Vec::new();
    };
    let mut extra = Vec::new();
    for policy_rule in &policy.rules {
        let id = policy_rule.rule.id.as_str();
        if !(id.starts_with("user.protected.folder.") || id.starts_with("user.protected.file.")) {
            continue;
        }
        let Some(patterns) = policy_rule.rule.matcher.paths.as_ref() else {
            continue;
        };
        for pattern in patterns {
            let trimmed = pattern.trim();
            if trimmed.is_empty() || trimmed.contains('*') && !trimmed.ends_with("/**") {
                continue;
            }
            let root = trimmed.trim_end_matches("/**");
            if root.is_empty() || root.contains('*') {
                continue;
            }
            let path = fs::canonicalize(root).unwrap_or_else(|_| PathBuf::from(root));
            let kind = if trimmed.ends_with("/**") || id.starts_with("user.protected.folder.") {
                DeniedKind::Subpath
            } else {
                DeniedKind::Literal
            };
            if !extra
                .iter()
                .any(|existing: &DeniedPath| existing.path == path)
            {
                extra.push(DeniedPath { path, kind });
            }
        }
    }
    extra
}

/// Sensitive locations denied for a given home directory.
pub fn denied_paths(home: &Path) -> Vec<DeniedPath> {
    let home = fs::canonicalize(home).unwrap_or_else(|_| home.to_path_buf());
    let mut paths = vec![
        DeniedPath {
            path: home.join(".ssh"),
            kind: DeniedKind::Subpath,
        },
        DeniedPath {
            path: home.join("Library/Keychains"),
            kind: DeniedKind::Subpath,
        },
        DeniedPath {
            path: PathBuf::from("/Library/Keychains"),
            kind: DeniedKind::Subpath,
        },
        DeniedPath {
            path: PathBuf::from("/System/Library/Keychains"),
            kind: DeniedKind::Subpath,
        },
        DeniedPath {
            path: home.join(".aws"),
            kind: DeniedKind::Subpath,
        },
        DeniedPath {
            path: home.join(".config/gcloud"),
            kind: DeniedKind::Subpath,
        },
        DeniedPath {
            path: home.join(".azure"),
            kind: DeniedKind::Subpath,
        },
        DeniedPath {
            path: home.join(".kube"),
            kind: DeniedKind::Subpath,
        },
        DeniedPath {
            path: home.join(".docker/config.json"),
            kind: DeniedKind::Literal,
        },
        DeniedPath {
            path: home.join(".oci"),
            kind: DeniedKind::Subpath,
        },
        DeniedPath {
            path: home.join("Library/Cookies"),
            kind: DeniedKind::Subpath,
        },
        DeniedPath {
            path: home.join("Library/Application Support/Google/Chrome"),
            kind: DeniedKind::Subpath,
        },
        DeniedPath {
            path: home.join("Library/Application Support/Firefox"),
            kind: DeniedKind::Subpath,
        },
        DeniedPath {
            path: home.join("Library/Application Support/BraveSoftware"),
            kind: DeniedKind::Subpath,
        },
    ];
    paths.extend(user_protected_denied_paths(&home));
    paths.sort_by(|a, b| a.path.cmp(&b.path));
    paths
}

/// Seatbelt profile text for `sandbox-exec -f`.
///
/// `(allow default)` then deny the secret trees. The `security` binary is
/// denied as `process-exec` so Keychain CLI access fails closed too.
pub fn seatbelt_profile(home: &Path) -> String {
    let mut out = String::from("(version 1)\n(allow default)\n");
    for denied in denied_paths(home) {
        let filter = match denied.kind {
            DeniedKind::Subpath => format!("(subpath \"{}\")", sb_escape(&denied.path)),
            DeniedKind::Literal => format!("(literal \"{}\")", sb_escape(&denied.path)),
        };
        out.push_str("(deny file-read* file-write*\n  ");
        out.push_str(&filter);
        out.push_str(")\n");
    }
    out.push_str("(deny process-exec\n  (literal \"/usr/bin/security\"))\n");
    out.push_str("(deny process-exec\n  (literal \"/usr/bin/security-sysdelegate\"))\n");
    out
}

fn sb_escape(path: &Path) -> String {
    path.display()
        .to_string()
        .replace('\\', "\\\\")
        .replace('"', "\\\"")
}

/// Message when `sandbox-exec` is missing or the profile cannot be applied.
pub fn fail_closed_message(cli: &str) -> String {
    format!(
        "Refusing to start `{cli}` without sandbox-exec. Use hooks-only protection (Partly protected) on this Mac."
    )
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::path::PathBuf;

    #[test]
    fn known_clis_are_sandboxed_by_basename() {
        assert!(is_sandboxed_cli("claude"));
        assert!(is_sandboxed_cli("/opt/homebrew/bin/kiro-cli"));
        assert!(is_sandboxed_cli("aider"));
        assert!(!is_sandboxed_cli("sh"));
        assert!(!is_sandboxed_cli("git"));
        assert!(!is_sandboxed_cli("node"));
        assert!(!is_sandboxed_cli("python"));
    }

    #[test]
    fn profile_denies_ssh_keychain_cloud_and_browser_trees() {
        let home = PathBuf::from("/tmp/as-home");
        let profile = seatbelt_profile(&home);
        assert!(profile.starts_with("(version 1)\n(allow default)\n"));
        for needle in [
            "/tmp/as-home/.ssh",
            "/tmp/as-home/Library/Keychains",
            "/Library/Keychains",
            "/tmp/as-home/.aws",
            "/tmp/as-home/.config/gcloud",
            "/tmp/as-home/.azure",
            "/tmp/as-home/.kube",
            "/tmp/as-home/.docker/config.json",
            "/tmp/as-home/.oci",
            "/tmp/as-home/Library/Application Support/Google/Chrome",
            "/tmp/as-home/Library/Application Support/Firefox",
            "/tmp/as-home/Library/Application Support/BraveSoftware",
            "/usr/bin/security",
        ] {
            assert!(profile.contains(needle), "missing {needle}\n{profile}");
        }
        assert!(profile.contains("(deny file-read* file-write*"));
        assert!(!profile.contains("blocks every file"));
    }

    #[test]
    fn profile_includes_user_protected_folder() {
        let temp = tempfile::tempdir().unwrap();
        let home = temp.path().join("home");
        let vault = home.join("AgentShield-TestVault");
        std::fs::create_dir_all(vault.join("nested")).unwrap();
        let policy = home.join(".config/privaku/agent-shield/policy.yaml");
        std::fs::create_dir_all(policy.parent().unwrap()).unwrap();
        std::fs::write(
            &policy,
            format!(
                "version: 1\nrules:\n  - id: user.protected.folder.agentshield-testvault\n    severity: critical\n    decision: deny\n    match:\n      paths:\n        - \"{}\"\n        - \"{}/**\"\n",
                vault.display(),
                vault.display()
            ),
        )
        .unwrap();
        let profile = seatbelt_profile(&home);
        let vault_canon = std::fs::canonicalize(&vault).unwrap_or(vault);
        assert!(
            profile.contains(&vault_canon.to_string_lossy().into_owned())
                || profile.contains("AgentShield-TestVault"),
            "missing TestVault in profile\n{profile}"
        );
    }
}
