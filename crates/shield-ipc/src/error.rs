use std::io;
use std::path::PathBuf;

use thiserror::Error;

/// Fail-closed IPC errors. Callers must treat every variant as Deny.
#[derive(Debug, Error)]
pub enum IpcError {
    #[error("cannot {op} {path}: {source}")]
    Io {
        op: &'static str,
        path: PathBuf,
        #[source]
        source: io::Error,
    },
    #[error("{0}")]
    Protocol(String),
    #[error("approval request `{id}` timed out waiting for a UI")]
    Timeout { id: String },
    #[error("socket {path} has mode {mode:#o}; Agent Shield requires 0600")]
    BadPermissions { path: PathBuf, mode: u32 },
    #[error("peer uid {peer} does not match daemon uid {expected}")]
    PeerUid { peer: u32, expected: u32 },
    #[error("unsupported IPC protocol version {0}; this build speaks version 1")]
    UnsupportedVersion(u32),
    #[error("an approval daemon is already listening on {0}")]
    AlreadyRunning(PathBuf),
    #[error("always_allow could not write a user rule: {0}")]
    AlwaysAllow(String),
    #[error("HOME is not set; cannot locate the Agent Shield socket")]
    MissingHome,
}

impl IpcError {
    pub fn io(op: &'static str, path: impl Into<PathBuf>, source: io::Error) -> Self {
        IpcError::Io {
            op,
            path: path.into(),
            source,
        }
    }

    pub fn protocol(message: impl Into<String>) -> Self {
        IpcError::Protocol(message.into())
    }
}

impl From<serde_json::Error> for IpcError {
    fn from(error: serde_json::Error) -> Self {
        IpcError::Protocol(error.to_string())
    }
}

impl From<io::Error> for IpcError {
    fn from(error: io::Error) -> Self {
        IpcError::Io {
            op: "ipc",
            path: PathBuf::from("<socket>"),
            source: error,
        }
    }
}
