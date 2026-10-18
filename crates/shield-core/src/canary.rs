//! Canary tripwire files. **Detection only** — a trip never denies I/O.
//!
//! Files live under the Agent Shield state directory (and `DEMO_HOME` when
//! set), never under a test's idea of the login user's real `~/.ssh`.

use std::fs;
use std::io;
use std::path::{Path, PathBuf};

/// Marker written at the top of every canary file.
pub const LABEL: &str = "CANARY-DO-NOT-USE detection-only";

/// Audit / UI rule id. Not a block.
pub const RULE_ID: &str = "canary.trip";

/// Relative paths under the canary directory.
pub const RELATIVE_FILES: &[&str] = &["CANARY", "id_rsa", "credentials"];

/// Directory that holds labelled canary files.
pub fn canary_dir(state_dir: &Path) -> PathBuf {
    state_dir.join("canary")
}

/// All canary file paths for a state directory.
pub fn canary_files(state_dir: &Path) -> Vec<PathBuf> {
    let dir = canary_dir(state_dir);
    RELATIVE_FILES.iter().map(|name| dir.join(name)).collect()
}

/// Extra canary paths from an isolated `DEMO_HOME` (demo `~/.ssh/CANARY`).
pub fn demo_canary_files(demo_home: &Path) -> Vec<PathBuf> {
    vec![
        demo_home.join(".ssh/CANARY"),
        demo_home.join(".ssh/id_rsa"),
        demo_home.join(".aws/credentials"),
        demo_home.join(".env"),
    ]
}

/// Create labelled canary files (0600) under `state_dir`.
pub fn ensure_files(state_dir: &Path) -> io::Result<Vec<PathBuf>> {
    let dir = canary_dir(state_dir);
    fs::create_dir_all(&dir)?;
    let mut created = Vec::new();
    for name in RELATIVE_FILES {
        let path = dir.join(name);
        if !path.exists() {
            fs::write(
                &path,
                format!("{LABEL}\nthrowaway canary for Agent Shield\n"),
            )?;
            #[cfg(unix)]
            {
                use std::os::unix::fs::PermissionsExt;
                fs::set_permissions(&path, fs::Permissions::from_mode(0o600))?;
            }
        }
        created.push(path);
    }
    Ok(created)
}

/// True when `path` is one of the watched canary files.
pub fn is_canary_path(path: &Path, watched: &[PathBuf]) -> bool {
    watched.iter().any(|candidate| {
        paths_equal(candidate, path)
            || candidate.file_name() == path.file_name() && candidate.parent() == path.parent()
    })
}

fn paths_equal(a: &Path, b: &Path) -> bool {
    if a == b {
        return true;
    }
    match (fs::canonicalize(a), fs::canonicalize(b)) {
        (Ok(left), Ok(right)) => left == right,
        _ => false,
    }
}

/// One detection-only trip. Never a deny.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Trip {
    pub path: PathBuf,
    pub reason_user: String,
}

impl Trip {
    pub fn new(path: PathBuf) -> Self {
        Self {
            reason_user: format!(
                "Detection only: a canary file was touched at {}. Agent Shield did not block the file action.",
                path.display()
            ),
            path,
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use tempfile::TempDir;

    #[test]
    fn ensure_writes_labelled_files_under_state_not_ssh() {
        let temp = TempDir::new().unwrap();
        let state = temp.path().join("state");
        let files = ensure_files(&state).unwrap();
        assert_eq!(files.len(), 3);
        for path in &files {
            let text = fs::read_to_string(path).unwrap();
            assert!(text.starts_with(LABEL), "{text}");
            assert!(path.starts_with(state.join("canary")));
            assert!(!path.to_string_lossy().contains("/.ssh/"));
        }
    }

    #[test]
    fn trip_copy_is_detection_only() {
        let trip = Trip::new(PathBuf::from("/tmp/canary/CANARY"));
        let lower = trip.reason_user.to_ascii_lowercase();
        assert!(lower.contains("detection only"));
        assert!(!lower.contains("blocked"));
        assert!(!lower.contains("denied"));
        assert_eq!(RULE_ID, "canary.trip");
    }
}
