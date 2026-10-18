use std::path::{Path, PathBuf};

use thiserror::Error;

pub const STATE_DIR_ENV: &str = "AGENT_SHIELD_STATE_DIR";
pub const ACTIVE_LOG_NAME: &str = "audit.jsonl";
pub const LOCK_FILE_NAME: &str = "audit.lock";
pub const HEAD_FILE_NAME: &str = "audit.head";

#[derive(Debug, Error)]
pub enum PathError {
    #[error("cannot locate the audit log because HOME is not set")]
    MissingHome,
}

/// Supplies the audit directory. Tests can inject [`FixedPaths`].
pub trait Paths {
    fn directory(&self) -> Result<PathBuf, PathError>;

    fn active_log(&self) -> Result<PathBuf, PathError> {
        Ok(self.directory()?.join(ACTIVE_LOG_NAME))
    }

    fn lock_file(&self) -> Result<PathBuf, PathError> {
        Ok(self.directory()?.join(LOCK_FILE_NAME))
    }

    fn head_file(&self) -> Result<PathBuf, PathError> {
        Ok(self.directory()?.join(HEAD_FILE_NAME))
    }
}

/// Native audit paths with an optional environment override.
#[derive(Debug, Clone)]
pub struct PlatformPaths {
    home: Option<PathBuf>,
    #[allow(dead_code)]
    xdg_state_home: Option<PathBuf>,
    override_directory: Option<PathBuf>,
}

impl PlatformPaths {
    pub fn from_env() -> Self {
        Self {
            home: std::env::var_os("HOME").map(PathBuf::from),
            xdg_state_home: std::env::var_os("XDG_STATE_HOME").map(PathBuf::from),
            override_directory: std::env::var_os(STATE_DIR_ENV).map(PathBuf::from),
        }
    }

    pub fn new(
        home: Option<PathBuf>,
        xdg_state_home: Option<PathBuf>,
        override_directory: Option<PathBuf>,
    ) -> Self {
        Self {
            home,
            xdg_state_home,
            override_directory,
        }
    }
}

impl Paths for PlatformPaths {
    fn directory(&self) -> Result<PathBuf, PathError> {
        if let Some(directory) = &self.override_directory {
            return Ok(directory.clone());
        }

        #[cfg(target_os = "macos")]
        {
            let home = self.home.as_ref().ok_or(PathError::MissingHome)?;
            Ok(home.join("Library/Logs/Privaku/agent-shield"))
        }

        #[cfg(not(target_os = "macos"))]
        {
            if let Some(directory) = &self.xdg_state_home {
                return Ok(directory.join("privaku"));
            }
            let home = self.home.as_ref().ok_or(PathError::MissingHome)?;
            Ok(home.join(".local/state/privaku"))
        }
    }
}

/// A direct directory override for tests and embedding applications.
#[derive(Debug, Clone)]
pub struct FixedPaths {
    directory: PathBuf,
}

impl FixedPaths {
    pub fn new(directory: impl AsRef<Path>) -> Self {
        Self {
            directory: directory.as_ref().to_path_buf(),
        }
    }
}

impl Paths for FixedPaths {
    fn directory(&self) -> Result<PathBuf, PathError> {
        Ok(self.directory.clone())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn explicit_override_wins() {
        let paths = PlatformPaths::new(
            Some(PathBuf::from("/home/me")),
            Some(PathBuf::from("/state")),
            Some(PathBuf::from("/override")),
        );
        assert_eq!(paths.directory().unwrap(), PathBuf::from("/override"));
    }

    #[cfg(not(target_os = "macos"))]
    #[test]
    fn linux_uses_xdg_then_home_fallback() {
        let xdg = PlatformPaths::new(
            Some(PathBuf::from("/home/me")),
            Some(PathBuf::from("/state")),
            None,
        );
        assert_eq!(xdg.directory().unwrap(), PathBuf::from("/state/privaku"));

        let fallback = PlatformPaths::new(Some(PathBuf::from("/home/me")), None, None);
        assert_eq!(
            fallback.directory().unwrap(),
            PathBuf::from("/home/me/.local/state/privaku")
        );
    }

    #[test]
    fn fixed_paths_exposes_standard_file_names() {
        let paths = FixedPaths::new("/tmp/audit-test");
        assert_eq!(
            paths.active_log().unwrap(),
            PathBuf::from("/tmp/audit-test/audit.jsonl")
        );
        assert_eq!(
            paths.lock_file().unwrap(),
            PathBuf::from("/tmp/audit-test/audit.lock")
        );
        assert_eq!(
            paths.head_file().unwrap(),
            PathBuf::from("/tmp/audit-test/audit.head")
        );
    }
}
