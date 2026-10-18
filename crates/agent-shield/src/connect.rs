//! First-run consent and auto-connect for installed AI agents.

use std::collections::BTreeSet;
use std::fs;
use std::path::{Path, PathBuf};
use std::process::ExitCode;

use anyhow::{anyhow, Result};
use serde::{Deserialize, Serialize};
use serde_json::json;
use shield_core::policy::Paths as PolicyPaths;
use shield_core::protect::{catalog, ProtectedApps};

use crate::install::Installer;
use crate::mcp_wrap::McpWrapper;

const PREFS_NAME: &str = "auto-connect.json";

#[derive(Debug, Clone, Serialize, Deserialize)]
struct Prefs {
    version: u32,
    consented: bool,
    auto_protect_new: bool,
    disconnected: BTreeSet<String>,
    known: BTreeSet<String>,
}

impl Default for Prefs {
    fn default() -> Self {
        Self {
            version: 1,
            consented: false,
            auto_protect_new: true,
            disconnected: BTreeSet::new(),
            known: BTreeSet::new(),
        }
    }
}

#[derive(Debug, Clone, Serialize)]
struct Found {
    id: String,
    name: String,
    kind: &'static str,
}

#[derive(Debug, Serialize)]
struct Report {
    consented: bool,
    auto_protect_new: bool,
    need_consent: bool,
    connected: Vec<Found>,
    notifications: Vec<String>,
}

pub fn run(
    consent: bool,
    auto_protect: Option<String>,
    disconnect: Option<String>,
    status: bool,
    json: bool,
) -> ExitCode {
    match run_inner(consent, auto_protect, disconnect, status, json) {
        Ok(()) => ExitCode::SUCCESS,
        Err(error) => {
            eprintln!("error: {error:#}");
            ExitCode::from(1)
        }
    }
}

fn run_inner(
    consent: bool,
    auto_protect: Option<String>,
    disconnect: Option<String>,
    status: bool,
    json: bool,
) -> Result<()> {
    let home = home_dir()?;
    let mut prefs = load_prefs(&home);
    if consent {
        prefs.consented = true;
    }
    if let Some(raw) = auto_protect {
        prefs.auto_protect_new = parse_on_off(&raw)?;
        if prefs.auto_protect_new {
            prefs.consented = true;
        }
    }
    if let Some(id) = disconnect {
        disconnect_one(&home, &id)?;
        prefs.disconnected.insert(id);
        save_prefs(&home, &prefs)?;
        if json {
            println!(
                "{}",
                serde_json::to_string_pretty(&json!({
                    "disconnected": true,
                    "consented": prefs.consented,
                    "auto_protect_new": prefs.auto_protect_new
                }))?
            );
        } else {
            println!("Disconnected and restored.");
        }
        return Ok(());
    }
    if status {
        save_prefs(&home, &prefs)?;
        return print_report(&report_status(&home, &prefs)?, json);
    }
    let report = scan_and_connect(&home, &mut prefs)?;
    save_prefs(&home, &prefs)?;
    print_report(&report, json)
}

fn scan_and_connect(home: &Path, prefs: &mut Prefs) -> Result<Report> {
    forget_missing(home, prefs)?;
    let found = detect(home)?;
    let mut connected = Vec::new();
    let mut notifications = Vec::new();
    if !prefs.consented {
        return Ok(Report {
            consented: false,
            auto_protect_new: prefs.auto_protect_new,
            need_consent: true,
            connected,
            notifications,
        });
    }
    let first_pass = prefs.known.is_empty();
    for agent in found {
        if prefs.disconnected.contains(&agent.id) {
            continue;
        }
        if prefs.known.contains(&agent.id) {
            continue;
        }
        if !first_pass && !prefs.auto_protect_new {
            continue;
        }
        let newly = connect_agent(home, &agent)?;
        prefs.known.insert(agent.id.clone());
        if newly {
            notifications.push(format!("Now protecting {}", agent.name));
            connected.push(agent);
        }
    }
    Ok(Report {
        consented: true,
        auto_protect_new: prefs.auto_protect_new,
        need_consent: false,
        connected,
        notifications,
    })
}

fn report_status(home: &Path, prefs: &Prefs) -> Result<Report> {
    Ok(Report {
        consented: prefs.consented,
        auto_protect_new: prefs.auto_protect_new,
        need_consent: !prefs.consented,
        connected: detect(home)?
            .into_iter()
            .filter(|agent| {
                prefs.known.contains(&agent.id) && !prefs.disconnected.contains(&agent.id)
            })
            .collect(),
        notifications: Vec::new(),
    })
}

fn detect(home: &Path) -> Result<Vec<Found>> {
    let mut out = Vec::new();
    let installer = Installer::from_env()?;
    for row in installer.inspect_hooks() {
        if row.detected {
            out.push(Found {
                id: row.agent.as_str().to_string(),
                name: row.agent.display_name().to_string(),
                kind: "hook",
            });
        }
    }
    if mcp_present(home) {
        out.push(Found {
            id: "mcp".into(),
            name: "AI tools".into(),
            kind: "mcp",
        });
    }
    for spec in catalog() {
        if catalog_present(
            home,
            spec.id,
            spec.bundle_ids,
            spec.host_bundle_ids,
            spec.cli_names,
        ) {
            if out.iter().any(|row| row.id == spec.id) {
                continue;
            }
            out.push(Found {
                id: spec.id.to_string(),
                name: spec.display_name.to_string(),
                kind: "app",
            });
        }
    }
    Ok(out)
}

fn connect_agent(home: &Path, agent: &Found) -> Result<bool> {
    match agent.kind {
        "hook" => {
            let installer = Installer::from_env()?;
            let before = hook_installed(&installer, &agent.id);
            let (claude, cursor, codex) = match agent.id.as_str() {
                "claude" => (true, false, false),
                "cursor" => (false, true, false),
                "codex" => (false, false, true),
                _ => (false, false, false),
            };
            installer.install(claude, cursor, codex, false)?;
            Ok(!before)
        }
        "mcp" => {
            let wrapper = McpWrapper::from_env()?;
            let outcomes = wrapper.wrap_with(false)?;
            Ok(outcomes
                .iter()
                .any(|row| row.changed || !row.wrapped.is_empty()))
        }
        "app" => {
            let dir = config_dir(home)?;
            let mut prefs = ProtectedApps::load(&dir);
            let already = prefs.apps.get(&agent.id).copied() == Some(true);
            prefs.set(agent.id.clone(), true);
            prefs.save(&dir)?;
            Ok(!already)
        }
        _ => Ok(false),
    }
}

fn disconnect_one(home: &Path, id: &str) -> Result<()> {
    match id {
        "claude" => {
            Installer::from_env()?.uninstall_selected(true, false, false)?;
        }
        "cursor" => {
            Installer::from_env()?.uninstall_selected(false, true, false)?;
        }
        "codex" => {
            Installer::from_env()?.uninstall_selected(false, false, true)?;
        }
        "mcp" => {
            McpWrapper::from_env()?.unwrap_with(false)?;
        }
        other => {
            let dir = config_dir(home)?;
            let mut prefs = ProtectedApps::load(&dir);
            prefs.set(other.to_string(), false);
            prefs.save(&dir)?;
        }
    }
    Ok(())
}

fn hook_installed(installer: &Installer, id: &str) -> bool {
    installer
        .inspect_hooks()
        .iter()
        .any(|row| row.agent.as_str() == id && row.detected && row.issues.is_empty())
}

fn forget_missing(home: &Path, prefs: &mut Prefs) -> Result<()> {
    let present: BTreeSet<String> = detect(home)?.into_iter().map(|row| row.id).collect();
    prefs.known.retain(|id| present.contains(id));
    prefs.disconnected.retain(|id| present.contains(id));
    Ok(())
}

fn mcp_present(home: &Path) -> bool {
    [
        home.join("Library/Application Support/Claude/claude_desktop_config.json"),
        home.join(".claude.json"),
        home.join(".cursor/mcp.json"),
        home.join(".codex/config.toml"),
    ]
    .iter()
    .any(|path| path.exists())
}

fn catalog_present(
    home: &Path,
    id: &str,
    bundle_ids: &[&str],
    host_bundle_ids: &[&str],
    cli_names: &[&str],
) -> bool {
    let wanted: BTreeSet<&str> = bundle_ids.iter().chain(host_bundle_ids).copied().collect();
    if !wanted.is_empty() {
        for root in application_roots(home) {
            if let Ok(entries) = fs::read_dir(&root) {
                for entry in entries.flatten() {
                    let path = entry.path();
                    if path.extension().and_then(|ext| ext.to_str()) != Some("app") {
                        continue;
                    }
                    if let Some(found) = read_bundle_id(&path) {
                        if wanted.contains(found.as_str()) {
                            return true;
                        }
                    }
                }
            }
        }
    }
    let isolated = std::env::var_os("AGENT_SHIELD_APPS_ROOT").is_some();
    if isolated {
        return id_hint_present(home, id);
    }
    cli_names.iter().any(|name| command_exists(name)) || id_hint_present(home, id)
}

fn id_hint_present(home: &Path, id: &str) -> bool {
    match id {
        "windsurf" => application_roots(home)
            .iter()
            .any(|root| root.join("Windsurf.app").exists()),
        "github-copilot-vscode" => application_roots(home).iter().any(|root| {
            root.join("Visual Studio Code.app").exists() || root.join("Code.app").exists()
        }),
        _ => false,
    }
}

fn application_roots(home: &Path) -> Vec<PathBuf> {
    if let Ok(extra) = std::env::var("AGENT_SHIELD_APPS_ROOT") {
        if !extra.is_empty() {
            return vec![PathBuf::from(extra)];
        }
    }
    vec![PathBuf::from("/Applications"), home.join("Applications")]
}

fn read_bundle_id(app: &Path) -> Option<String> {
    let text = fs::read_to_string(app.join("Contents/Info.plist")).ok()?;
    let key = "<key>CFBundleIdentifier</key>";
    let start = text.find(key)? + key.len();
    let after = &text[start..];
    let open = after.find("<string>")? + "<string>".len();
    let rest = &after[open..];
    let close = rest.find("</string>")?;
    Some(rest[..close].trim().to_string())
}

fn command_exists(name: &str) -> bool {
    let mut dirs = vec![
        PathBuf::from("/opt/homebrew/bin"),
        PathBuf::from("/usr/local/bin"),
        PathBuf::from("/usr/bin"),
        PathBuf::from("/bin"),
    ];
    if let Ok(path) = std::env::var("PATH") {
        dirs.extend(path.split(':').map(PathBuf::from));
    }
    let mut seen = BTreeSet::new();
    for dir in dirs {
        if !seen.insert(dir.clone()) {
            continue;
        }
        let candidate = dir.join(name);
        if candidate.is_file() {
            return true;
        }
    }
    false
}

fn home_dir() -> Result<PathBuf> {
    std::env::var_os("HOME")
        .filter(|value| !value.is_empty())
        .map(PathBuf::from)
        .ok_or_else(|| anyhow!("HOME is not set"))
}

fn config_dir(home: &Path) -> Result<PathBuf> {
    let cwd = std::env::current_dir().unwrap_or_else(|_| PathBuf::from("."));
    let paths = PolicyPaths::new(Some(home), Some(&cwd));
    Ok(paths
        .user_policy
        .as_ref()
        .and_then(|policy| policy.parent().map(Path::to_path_buf))
        .unwrap_or_else(|| home.join(".config/privaku/agent-shield")))
}

fn prefs_path(home: &Path) -> PathBuf {
    config_dir(home)
        .unwrap_or_else(|_| home.join(".config/privaku/agent-shield"))
        .join(PREFS_NAME)
}

fn load_prefs(home: &Path) -> Prefs {
    let path = prefs_path(home);
    let Ok(bytes) = fs::read(&path) else {
        return Prefs::default();
    };
    serde_json::from_slice(&bytes).unwrap_or_default()
}

fn save_prefs(home: &Path, prefs: &Prefs) -> Result<()> {
    let path = prefs_path(home);
    if let Some(parent) = path.parent() {
        fs::create_dir_all(parent)?;
    }
    fs::write(path, serde_json::to_vec_pretty(prefs)?)?;
    Ok(())
}

fn parse_on_off(raw: &str) -> Result<bool> {
    match raw.trim().to_ascii_lowercase().as_str() {
        "on" | "true" | "1" => Ok(true),
        "off" | "false" | "0" => Ok(false),
        other => Err(anyhow!("expected on or off, got {other}")),
    }
}

fn print_report(report: &Report, json: bool) -> Result<()> {
    if json {
        println!("{}", serde_json::to_string_pretty(report)?);
    } else if report.need_consent {
        println!("Agent Shield will connect to your AI agents");
    } else if report.connected.is_empty() {
        println!("No new agents to protect.");
    } else {
        for note in &report.notifications {
            println!("{note}");
        }
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn prefs_default_auto_protect_on() {
        let prefs = Prefs::default();
        assert!(prefs.auto_protect_new);
        assert!(!prefs.consented);
    }

    #[test]
    fn parse_toggle() {
        assert!(parse_on_off("on").unwrap());
        assert!(!parse_on_off("off").unwrap());
    }
}
