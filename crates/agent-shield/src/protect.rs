//! `agent-shield protect` — list and toggle Protect this app rows.

use std::path::PathBuf;
use std::process::ExitCode;

use anyhow::{anyhow, Result};
use serde::Serialize;
use shield_core::policy::Paths as PolicyPaths;
use shield_core::protect::{catalog, match_process, ProcessIdentity, ProtectedApps, TEAM_ID_TODO};

#[derive(Debug, Serialize)]
struct Row {
    id: String,
    display_name: String,
    bundle_ids: Vec<String>,
    cli_names: Vec<String>,
    script_markers: Vec<String>,
    protect: bool,
    team_id: Option<String>,
    team_id_todo: String,
}

fn config_dir() -> Result<PathBuf> {
    let home = std::env::var_os("HOME")
        .filter(|value| !value.is_empty())
        .map(PathBuf::from)
        .ok_or_else(|| anyhow!("HOME is not set"))?;
    let cwd = std::env::current_dir().unwrap_or_else(|_| PathBuf::from("."));
    let paths = PolicyPaths::new(Some(&home), Some(&cwd));
    Ok(paths
        .user_policy
        .as_ref()
        .and_then(|policy| policy.parent().map(Path::to_path_buf))
        .unwrap_or_else(|| home.join(".config/privaku/agent-shield")))
}

use std::path::Path;

pub fn list(json: bool) -> ExitCode {
    match list_inner(json) {
        Ok(()) => ExitCode::SUCCESS,
        Err(error) => {
            eprintln!("error: {error:#}");
            ExitCode::from(1)
        }
    }
}

fn list_inner(json: bool) -> Result<()> {
    let prefs = ProtectedApps::load(&config_dir()?);
    let rows: Vec<Row> = catalog()
        .iter()
        .map(|spec| Row {
            id: spec.id.into(),
            display_name: spec.display_name.into(),
            bundle_ids: spec.bundle_ids.iter().map(|s| (*s).to_string()).collect(),
            cli_names: spec.cli_names.iter().map(|s| (*s).to_string()).collect(),
            script_markers: spec
                .script_markers
                .iter()
                .map(|s| (*s).to_string())
                .collect(),
            protect: prefs.is_protected(spec.id),
            team_id: spec.team_id.map(str::to_string),
            team_id_todo: TEAM_ID_TODO.into(),
        })
        .collect();
    if json {
        println!("{}", serde_json::to_string_pretty(&rows)?);
    } else {
        println!("Protect this app  (Team IDs: {TEAM_ID_TODO})");
        for row in rows {
            let mark = if row.protect { "on" } else { "off" };
            println!("  [{mark}] {}  {}", row.id, row.display_name);
        }
    }
    Ok(())
}

pub fn set(id: String, protect: bool) -> ExitCode {
    match set_inner(id, protect) {
        Ok(()) => ExitCode::SUCCESS,
        Err(error) => {
            eprintln!("error: {error:#}");
            ExitCode::from(1)
        }
    }
}

fn set_inner(id: String, protect: bool) -> Result<()> {
    if !catalog().iter().any(|spec| spec.id == id) {
        anyhow::bail!("unknown app id `{id}`");
    }
    let dir = config_dir()?;
    let mut prefs = ProtectedApps::load(&dir);
    prefs.set(id, protect);
    prefs.save(&dir)?;
    Ok(())
}

/// Best-effort snapshot for tests and the NE scaffold.
#[allow(dead_code)]
pub fn identity_from_parts(
    pid: u32,
    ppid: u32,
    pgid: u32,
    path: PathBuf,
    bundle_id: Option<String>,
    argv: Vec<String>,
) -> ProcessIdentity {
    ProcessIdentity {
        pid,
        ppid,
        pgid,
        path,
        bundle_id,
        argv,
    }
}

#[allow(dead_code)]
pub fn describe_process(proc: &ProcessIdentity) -> Option<&'static str> {
    match_process(proc, catalog()).map(|spec| spec.id)
}
