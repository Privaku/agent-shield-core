//! Synchronous client used by hooks, the proxy and the shim.
//!
//! Every error is fail-closed: the caller must treat it as Deny.

use std::io::{BufRead, BufReader, Write};
use std::os::unix::net::UnixStream;
use std::path::Path;
use std::time::{Duration, Instant};

fn map_timeout(id: &str, source: std::io::Error) -> IpcError {
    match source.kind() {
        std::io::ErrorKind::TimedOut | std::io::ErrorKind::WouldBlock => {
            IpcError::Timeout { id: id.to_string() }
        }
        _ => IpcError::io("read", "<socket>", source),
    }
}

use shield_core::model::{ApprovalRequest, ApprovalResponse, ApprovalVerdict};

use crate::error::IpcError;
use crate::protocol::{decode_line, encode_line, IpcMessage, IpcRole};
use crate::transport::{socket_path_from_env, IpcTransport, UnixIpcTransport};

/// Ask the daemon for a verdict. Errors (unreachable daemon, bad
/// permissions, protocol failures) must be treated as Deny.
pub fn request_approval(
    request: ApprovalRequest,
    timeout: Duration,
) -> Result<ApprovalVerdict, IpcError> {
    Ok(request_approval_at(&socket_path_from_env()?, request, timeout)?.verdict)
}

/// Full response, including `by`, against an explicit socket path.
pub fn request_approval_at(
    path: &Path,
    request: ApprovalRequest,
    timeout: Duration,
) -> Result<ApprovalResponse, IpcError> {
    let mut stream = UnixIpcTransport.connect_std(path)?;
    stream
        .set_read_timeout(Some(timeout))
        .map_err(|source| IpcError::io("timeout", path, source))?;
    stream
        .set_write_timeout(Some(timeout))
        .map_err(|source| IpcError::io("timeout", path, source))?;

    write_message(&mut stream, &IpcMessage::hello(IpcRole::Client))?;
    write_message(&mut stream, &IpcMessage::from_request(request.clone()))?;

    let deadline = Instant::now() + timeout;
    let mut reader = BufReader::new(stream);
    loop {
        if Instant::now() >= deadline {
            return Err(IpcError::Timeout { id: request.id });
        }
        let remaining = deadline.saturating_duration_since(Instant::now());
        reader
            .get_mut()
            .set_read_timeout(Some(remaining.max(Duration::from_millis(1))))
            .map_err(|source| IpcError::io("timeout", path, source))?;
        let message = read_message(&mut reader).map_err(|error| match error {
            IpcError::Io { source, .. } => map_timeout(&request.id, source),
            other => other,
        })?;
        match message {
            IpcMessage::Ping => continue,
            IpcMessage::ApprovalResponse { id, .. } if id != request.id => continue,
            IpcMessage::ApprovalResponse { .. } => {
                return Ok(message.as_response().expect("approval_response"));
            }
            IpcMessage::Event { .. } => continue,
            other => {
                return Err(IpcError::protocol(format!(
                    "unexpected message while waiting for a verdict: {other:?}"
                )));
            }
        }
    }
}

/// Send hello + ping and wait for ping. Used by `agent-shield doctor`.
pub fn ping(path: &Path, timeout: Duration) -> Result<(), IpcError> {
    let mut stream = UnixIpcTransport.connect_std(path)?;
    stream
        .set_read_timeout(Some(timeout))
        .map_err(|source| IpcError::io("timeout", path, source))?;
    stream
        .set_write_timeout(Some(timeout))
        .map_err(|source| IpcError::io("timeout", path, source))?;
    write_message(&mut stream, &IpcMessage::hello(IpcRole::Client))?;
    write_message(&mut stream, &IpcMessage::Ping)?;
    let mut reader = BufReader::new(stream);
    loop {
        match read_message(&mut reader)? {
            IpcMessage::Ping => return Ok(()),
            IpcMessage::Event { .. } => continue,
            other => {
                return Err(IpcError::protocol(format!(
                    "unexpected ping reply: {other:?}"
                )));
            }
        }
    }
}

fn write_message(stream: &mut UnixStream, message: &IpcMessage) -> Result<(), IpcError> {
    let line = encode_line(message)?;
    stream
        .write_all(line.as_bytes())
        .map_err(|source| IpcError::io("write", "<socket>", source))?;
    stream
        .flush()
        .map_err(|source| IpcError::io("flush", "<socket>", source))
}

fn read_message(reader: &mut BufReader<UnixStream>) -> Result<IpcMessage, IpcError> {
    let mut line = String::new();
    let n = reader
        .read_line(&mut line)
        .map_err(|source| IpcError::io("read", "<socket>", source))?;
    if n == 0 {
        return Err(IpcError::protocol("daemon closed the connection"));
    }
    Ok(decode_line(&line)?)
}
