//! Portable IPC transport seam.
//!
//! UNIX sockets are the MVP implementation. A later Windows port can supply
//! a named-pipe `IpcTransport` without changing daemon or client logic.
//! `cfg(target_os = "macos")` lives only in this file's implementations.

use std::fs;
use std::io;
use std::os::fd::AsRawFd;
use std::os::unix::fs::PermissionsExt;
use std::os::unix::net::UnixStream as StdUnixStream;
use std::path::{Path, PathBuf};

use tokio::net::{UnixListener, UnixStream};

use crate::error::IpcError;

/// Required socket file mode: owner read/write only.
pub const SOCKET_MODE: u32 = 0o600;

/// Peer identity of a connected process.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct PeerCredentials {
    pub uid: u32,
    pub gid: u32,
    pub pid: Option<u32>,
}

/// Abstracts the byte transport so UNIX sockets now (and named pipes later)
/// share the same daemon and client.
pub trait IpcTransport: Send + Sync {
    /// Bind a listener at `path` with mode [`SOCKET_MODE`]. A stale socket
    /// file is replaced; a live daemon is an error.
    fn bind(&self, path: &Path) -> Result<UnixListener, IpcError>;

    /// Connect after refusing sockets whose mode is not [`SOCKET_MODE`].
    fn connect(&self, path: &Path) -> Result<UnixStream, IpcError>;

    /// Blocking connect used by the synchronous client.
    fn connect_std(&self, path: &Path) -> Result<StdUnixStream, IpcError>;

    /// Peer uid/gid of an accepted or connected stream.
    fn peer_credentials<S: AsRawFd>(&self, stream: &S) -> Result<PeerCredentials, IpcError>;

    /// Socket file mode bits (`st_mode & 0o777`).
    fn socket_mode(&self, path: &Path) -> Result<u32, IpcError>;

    /// Refuse a socket whose mode is not exactly [`SOCKET_MODE`].
    fn require_owner_only(&self, path: &Path) -> Result<(), IpcError> {
        let mode = self.socket_mode(path)?;
        if mode != SOCKET_MODE {
            return Err(IpcError::BadPermissions {
                path: path.to_path_buf(),
                mode,
            });
        }
        Ok(())
    }
}

/// UNIX-domain socket transport. Linux CI exercises this implementation.
#[derive(Debug, Clone, Copy, Default)]
pub struct UnixIpcTransport;

impl UnixIpcTransport {
    fn prepare_bind(path: &Path) -> Result<(), IpcError> {
        if let Some(parent) = path.parent() {
            fs::create_dir_all(parent).map_err(|source| IpcError::io("create", parent, source))?;
            let mut permissions = fs::metadata(parent)
                .map_err(|source| IpcError::io("stat", parent, source))?
                .permissions();
            permissions.set_mode(0o700);
            let _ = fs::set_permissions(parent, permissions);
        }
        if path.exists() {
            match StdUnixStream::connect(path) {
                Ok(_) => return Err(IpcError::AlreadyRunning(path.to_path_buf())),
                Err(_) => {
                    fs::remove_file(path).map_err(|source| IpcError::io("remove", path, source))?;
                }
            }
        }
        Ok(())
    }

    fn apply_mode(path: &Path) -> Result<(), IpcError> {
        let mut permissions = fs::metadata(path)
            .map_err(|source| IpcError::io("stat", path, source))?
            .permissions();
        permissions.set_mode(SOCKET_MODE);
        fs::set_permissions(path, permissions)
            .map_err(|source| IpcError::io("chmod", path, source))?;
        let mode = fs::metadata(path)
            .map_err(|source| IpcError::io("stat", path, source))?
            .permissions()
            .mode()
            & 0o777;
        if mode != SOCKET_MODE {
            return Err(IpcError::BadPermissions {
                path: path.to_path_buf(),
                mode,
            });
        }
        Ok(())
    }

    fn mode_of(path: &Path) -> Result<u32, IpcError> {
        let metadata = fs::metadata(path).map_err(|source| IpcError::io("stat", path, source))?;
        Ok(metadata.permissions().mode() & 0o777)
    }

    /// Platform socket path. macOS uses Application Support; Linux uses
    /// `$XDG_RUNTIME_DIR/privaku/` (or `/tmp/privaku-<uid>/` when unset).
    pub fn socket_path(
        home: Option<&Path>,
        xdg_runtime_dir: Option<&Path>,
        uid: u32,
    ) -> Result<PathBuf, IpcError> {
        #[cfg(target_os = "macos")]
        {
            let _ = (xdg_runtime_dir, uid);
            let home = home.ok_or(IpcError::MissingHome)?;
            Ok(home.join("Library/Application Support/Privaku/agent-shield.sock"))
        }

        #[cfg(not(target_os = "macos"))]
        {
            let _ = home;
            Ok(match xdg_runtime_dir {
                Some(dir) => dir.join("privaku/agent-shield.sock"),
                None => PathBuf::from(format!("/tmp/privaku-{uid}/agent-shield.sock")),
            })
        }
    }

    fn creds_of_fd(fd: i32) -> Result<PeerCredentials, IpcError> {
        #[cfg(target_os = "linux")]
        {
            let mut cred = libc::ucred {
                pid: 0,
                uid: 0,
                gid: 0,
            };
            let mut len = std::mem::size_of::<libc::ucred>() as libc::socklen_t;
            let result = unsafe {
                libc::getsockopt(
                    fd,
                    libc::SOL_SOCKET,
                    libc::SO_PEERCRED,
                    (&mut cred) as *mut libc::ucred as *mut libc::c_void,
                    &mut len,
                )
            };
            if result != 0 {
                return Err(IpcError::io(
                    "getsockopt",
                    "<peer>",
                    io::Error::last_os_error(),
                ));
            }
            Ok(PeerCredentials {
                uid: cred.uid,
                gid: cred.gid,
                pid: Some(cred.pid as u32),
            })
        }

        #[cfg(target_os = "macos")]
        {
            let mut uid: libc::uid_t = 0;
            let mut gid: libc::gid_t = 0;
            let result = unsafe { libc::getpeereid(fd, &mut uid, &mut gid) };
            if result != 0 {
                return Err(IpcError::io(
                    "getpeereid",
                    "<peer>",
                    io::Error::last_os_error(),
                ));
            }
            Ok(PeerCredentials {
                uid,
                gid,
                pid: None,
            })
        }

        #[cfg(not(any(target_os = "linux", target_os = "macos")))]
        {
            let _ = fd;
            Err(IpcError::protocol(
                "peer credentials are not implemented on this platform",
            ))
        }
    }
}

impl IpcTransport for UnixIpcTransport {
    fn bind(&self, path: &Path) -> Result<UnixListener, IpcError> {
        Self::prepare_bind(path)?;
        let listener = std::os::unix::net::UnixListener::bind(path)
            .map_err(|source| IpcError::io("bind", path, source))?;
        Self::apply_mode(path)?;
        listener
            .set_nonblocking(true)
            .map_err(|source| IpcError::io("bind", path, source))?;
        UnixListener::from_std(listener).map_err(|source| IpcError::io("bind", path, source))
    }

    fn connect(&self, path: &Path) -> Result<UnixStream, IpcError> {
        self.require_owner_only(path)?;
        let stream =
            StdUnixStream::connect(path).map_err(|source| IpcError::io("connect", path, source))?;
        stream
            .set_nonblocking(true)
            .map_err(|source| IpcError::io("connect", path, source))?;
        UnixStream::from_std(stream).map_err(|source| IpcError::io("connect", path, source))
    }

    fn connect_std(&self, path: &Path) -> Result<StdUnixStream, IpcError> {
        self.require_owner_only(path)?;
        StdUnixStream::connect(path).map_err(|source| IpcError::io("connect", path, source))
    }

    fn peer_credentials<S: AsRawFd>(&self, stream: &S) -> Result<PeerCredentials, IpcError> {
        Self::creds_of_fd(stream.as_raw_fd())
    }

    fn socket_mode(&self, path: &Path) -> Result<u32, IpcError> {
        Self::mode_of(path)
    }
}

/// Platform socket path used when `AGENT_SHIELD_SOCK` is unset.
pub fn platform_socket_path(
    home: Option<&Path>,
    xdg_runtime_dir: Option<&Path>,
    uid: u32,
) -> Result<PathBuf, IpcError> {
    UnixIpcTransport::socket_path(home, xdg_runtime_dir, uid)
}

/// Socket path from the process environment, honouring `AGENT_SHIELD_SOCK`.
pub fn socket_path_from_env() -> Result<PathBuf, IpcError> {
    if let Some(path) = std::env::var_os("AGENT_SHIELD_SOCK") {
        if !path.is_empty() {
            return Ok(PathBuf::from(path));
        }
    }
    let home = std::env::var_os("HOME").map(PathBuf::from);
    let xdg = std::env::var_os("XDG_RUNTIME_DIR").map(PathBuf::from);
    let uid = current_uid();
    platform_socket_path(home.as_deref(), xdg.as_deref(), uid)
}

pub fn current_uid() -> u32 {
    unsafe { libc::getuid() }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::os::unix::net::UnixListener as StdUnixListener;

    #[test]
    fn linux_platform_path_uses_xdg_then_tmp() {
        #[cfg(not(target_os = "macos"))]
        {
            let with_xdg = platform_socket_path(
                Some(Path::new("/home/me")),
                Some(Path::new("/run/user/1000")),
                1000,
            )
            .unwrap();
            assert_eq!(
                with_xdg,
                PathBuf::from("/run/user/1000/privaku/agent-shield.sock")
            );
            let fallback = platform_socket_path(Some(Path::new("/home/me")), None, 42).unwrap();
            assert_eq!(fallback, PathBuf::from("/tmp/privaku-42/agent-shield.sock"));
        }
    }

    #[test]
    fn wrong_permissions_are_refused() {
        let temp = tempfile::tempdir().unwrap();
        let path = temp.path().join("agent-shield.sock");
        let _listener = StdUnixListener::bind(&path).unwrap();
        let mut permissions = fs::metadata(&path).unwrap().permissions();
        permissions.set_mode(0o666);
        fs::set_permissions(&path, permissions).unwrap();

        let transport = UnixIpcTransport;
        let error = transport.require_owner_only(&path).unwrap_err();
        match error {
            IpcError::BadPermissions { mode, .. } => assert_eq!(mode, 0o666),
            other => panic!("expected BadPermissions, got {other}"),
        }
    }
}
