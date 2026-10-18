use std::fs::{self, File, OpenOptions};
use std::io::{Read, Seek, SeekFrom, Write};
use std::path::{Path, PathBuf};

use fs2::FileExt;
use serde::{Deserialize, Serialize};
use shield_core::model::{Action, Decision};
use thiserror::Error;

use crate::entry::{AuditEntry, EntryError, GENESIS_HASH};
use crate::paths::{PathError, Paths, ACTIVE_LOG_NAME, HEAD_FILE_NAME};

pub const DEFAULT_ROTATION_BYTES: u64 = 10 * 1024 * 1024;

#[derive(Debug, Error)]
pub enum WriterError {
    #[error(transparent)]
    Path(#[from] PathError),
    #[error("audit log I/O failed: {0}")]
    Io(#[from] std::io::Error),
    #[error("audit entry creation failed: {0}")]
    Entry(#[from] EntryError),
    #[error("the last audit line is invalid JSON: {0}")]
    InvalidTail(#[from] serde_json::Error),
    #[error("audit head is missing for a non-empty log")]
    MissingHead,
    #[error("audit head hash {head} does not match the last log hash {log}")]
    HeadMismatch { head: String, log: String },
}

/// Cross-process, append-only audit writer.
///
/// A stable `audit.lock` file is locked before the active file is opened.
/// This avoids a process retaining a lock on a renamed inode during rotation.
#[derive(Debug, Clone)]
pub struct AuditWriter {
    directory: PathBuf,
    rotation_bytes: u64,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub(crate) struct AuditHead {
    pub entries: u64,
    pub hash: String,
}

impl AuditWriter {
    pub fn new(paths: &impl Paths) -> Result<Self, WriterError> {
        Ok(Self {
            directory: paths.directory()?,
            rotation_bytes: DEFAULT_ROTATION_BYTES,
        })
    }

    pub fn with_rotation_bytes(
        paths: &impl Paths,
        rotation_bytes: u64,
    ) -> Result<Self, WriterError> {
        Ok(Self {
            directory: paths.directory()?,
            rotation_bytes,
        })
    }

    pub fn directory(&self) -> &Path {
        &self.directory
    }

    pub fn append(
        &self,
        action: &Action,
        decision: &Decision,
        approver: Option<&str>,
    ) -> Result<AuditEntry, WriterError> {
        create_secure_directory(&self.directory)?;
        let lock_path = self.directory.join("audit.lock");
        let lock_file = secure_open(&lock_path, false)?;
        FileExt::lock_exclusive(&lock_file)?;

        let previous = last_hash(&self.directory)?;
        let head = read_head(&self.directory)?;
        let previous_entries = match head {
            Some(head) if head.hash == previous => head.entries,
            Some(head) => {
                return Err(WriterError::HeadMismatch {
                    head: head.hash,
                    log: previous,
                });
            }
            None if previous == GENESIS_HASH => 0,
            None => return Err(WriterError::MissingHead),
        };
        let entry = AuditEntry::now(action, decision, approver, &previous)?;
        let mut encoded = serde_json::to_vec(&entry)?;
        encoded.push(b'\n');

        let active = self.directory.join(ACTIVE_LOG_NAME);
        let active_size = match fs::metadata(&active) {
            Ok(metadata) => metadata.len(),
            Err(error) if error.kind() == std::io::ErrorKind::NotFound => 0,
            Err(error) => return Err(error.into()),
        };
        if active_size > 0 && active_size.saturating_add(encoded.len() as u64) > self.rotation_bytes
        {
            rotate(&self.directory, &active)?;
        }

        let mut file = secure_open(&active, true)?;
        file.write_all(&encoded)?;
        file.flush()?;
        write_head(
            &self.directory,
            &AuditHead {
                entries: previous_entries + 1,
                hash: entry.hash.clone(),
            },
        )?;
        Ok(entry)
    }
}

/// Rotated logs in oldest-first order, followed by the active log when it
/// exists.
pub fn ordered_log_files(directory: &Path) -> Result<Vec<PathBuf>, std::io::Error> {
    let mut rotated = Vec::new();
    match fs::read_dir(directory) {
        Ok(entries) => {
            for entry in entries {
                let entry = entry?;
                let name = entry.file_name();
                let Some(name) = name.to_str() else {
                    continue;
                };
                if let Some(index) = rotation_index(name) {
                    rotated.push((index, entry.path()));
                }
            }
        }
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => return Ok(Vec::new()),
        Err(error) => return Err(error),
    }
    rotated.sort_unstable_by_key(|(index, _)| *index);
    let mut files = rotated
        .into_iter()
        .map(|(_, path)| path)
        .collect::<Vec<_>>();
    let active = directory.join(ACTIVE_LOG_NAME);
    if active.is_file() {
        files.push(active);
    }
    Ok(files)
}

fn create_secure_directory(directory: &Path) -> Result<(), std::io::Error> {
    fs::create_dir_all(directory)?;
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        fs::set_permissions(directory, fs::Permissions::from_mode(0o700))?;
    }
    Ok(())
}

fn secure_open(path: &Path, append: bool) -> Result<File, std::io::Error> {
    let mut options = OpenOptions::new();
    options.create(true).read(true).write(true).append(append);
    let file = options.open(path)?;
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        file.set_permissions(fs::Permissions::from_mode(0o600))?;
    }
    Ok(file)
}

fn last_hash(directory: &Path) -> Result<String, WriterError> {
    let files = ordered_log_files(directory)?;
    for path in files.iter().rev() {
        if let Some(line) = read_last_line(path)? {
            let entry: AuditEntry = serde_json::from_str(&line)?;
            return Ok(entry.hash);
        }
    }
    Ok(GENESIS_HASH.to_string())
}

pub(crate) fn read_head(directory: &Path) -> Result<Option<AuditHead>, WriterError> {
    let path = directory.join(HEAD_FILE_NAME);
    match fs::read(&path) {
        Ok(bytes) => Ok(Some(serde_json::from_slice(&bytes)?)),
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => Ok(None),
        Err(error) => Err(error.into()),
    }
}

pub(crate) fn shared_lock(directory: &Path) -> Result<Option<File>, std::io::Error> {
    if !directory.is_dir() {
        return Ok(None);
    }
    let lock = secure_open(&directory.join("audit.lock"), false)?;
    FileExt::lock_shared(&lock)?;
    Ok(Some(lock))
}

fn write_head(directory: &Path, head: &AuditHead) -> Result<(), WriterError> {
    let temporary = directory.join(format!("{HEAD_FILE_NAME}.tmp-{}", std::process::id()));
    let final_path = directory.join(HEAD_FILE_NAME);
    let mut file = secure_open(&temporary, false)?;
    file.set_len(0)?;
    file.write_all(&serde_json::to_vec(head)?)?;
    file.flush()?;
    fs::rename(temporary, final_path)?;
    Ok(())
}

fn read_last_line(path: &Path) -> Result<Option<String>, std::io::Error> {
    let mut file = File::open(path)?;
    let mut position = file.metadata()?.len();
    if position == 0 {
        return Ok(None);
    }

    let mut reversed = Vec::new();
    let mut content_started = false;
    let mut chunk = vec![0_u8; 8192];
    while position > 0 {
        let amount = usize::try_from(position.min(chunk.len() as u64)).unwrap_or(chunk.len());
        position -= amount as u64;
        file.seek(SeekFrom::Start(position))?;
        file.read_exact(&mut chunk[..amount])?;
        for &byte in chunk[..amount].iter().rev() {
            if !content_started && matches!(byte, b'\n' | b'\r') {
                continue;
            }
            content_started = true;
            if byte == b'\n' {
                reversed.reverse();
                return String::from_utf8(reversed)
                    .map(Some)
                    .map_err(|error| std::io::Error::new(std::io::ErrorKind::InvalidData, error));
            }
            if byte != b'\r' {
                reversed.push(byte);
            }
        }
    }
    if !content_started {
        return Ok(None);
    }
    reversed.reverse();
    String::from_utf8(reversed)
        .map(Some)
        .map_err(|error| std::io::Error::new(std::io::ErrorKind::InvalidData, error))
}

fn rotate(directory: &Path, active: &Path) -> Result<(), std::io::Error> {
    let next = ordered_log_files(directory)?
        .iter()
        .filter_map(|path| path.file_name()?.to_str().and_then(rotation_index))
        .max()
        .unwrap_or(0)
        + 1;
    let rotated = directory.join(format!("audit.{next:06}.jsonl"));
    fs::rename(active, rotated)
}

fn rotation_index(name: &str) -> Option<u64> {
    name.strip_prefix("audit.")?
        .strip_suffix(".jsonl")?
        .parse()
        .ok()
}

#[cfg(test)]
mod tests {
    use std::io::{BufRead, BufReader};
    use std::sync::{Arc, Barrier};
    use std::thread;

    use shield_core::model::{
        ActionKind, AgentContext, AgentKind, ArgvTree, Outcome, RiskScore, Severity,
    };
    use tempfile::TempDir;

    use crate::paths::FixedPaths;

    use super::*;

    fn evaluation(thread: usize, item: usize) -> (Action, Decision) {
        let raw = format!("echo thread-{thread}-item-{item}");
        let context = AgentContext {
            agent: AgentKind::Claude,
            session_id: format!("session-{thread}"),
            cwd: PathBuf::from("/workspace"),
            autonomous: false,
        };
        let action = Action::new(
            context,
            ActionKind::Shell {
                argv_tree: ArgvTree::Unparsed { raw: raw.clone() },
                raw,
                cwd: PathBuf::from("/workspace"),
                obfuscation: Vec::new(),
            },
        );
        let decision = Decision {
            outcome: Outcome::Allow,
            rule_id: None,
            matched_rule_ids: Vec::new(),
            severity: Severity::Info,
            reason_user: "No rule matched".into(),
            reason_agent: "Allowed".into(),
            risk_score: RiskScore::MIN,
        };
        (action, decision)
    }

    fn assert_chain(directory: &Path) -> usize {
        let mut expected = GENESIS_HASH.to_string();
        let mut count = 0;
        for path in ordered_log_files(directory).unwrap() {
            for line in BufReader::new(File::open(path).unwrap()).lines() {
                let entry: AuditEntry = serde_json::from_str(&line.unwrap()).unwrap();
                assert_eq!(entry.prev_hash, expected);
                assert!(entry.has_valid_hash().unwrap());
                expected = entry.hash;
                count += 1;
            }
        }
        count
    }

    #[test]
    fn eight_threads_append_one_thousand_entries_each() {
        let temp = TempDir::new().unwrap();
        let writer = Arc::new(AuditWriter::new(&FixedPaths::new(temp.path())).unwrap());
        let barrier = Arc::new(Barrier::new(8));
        let threads = (0..8)
            .map(|thread_id| {
                let writer = Arc::clone(&writer);
                let barrier = Arc::clone(&barrier);
                thread::spawn(move || {
                    barrier.wait();
                    for item in 0..1_000 {
                        let (action, decision) = evaluation(thread_id, item);
                        writer.append(&action, &decision, Some("policy")).unwrap();
                    }
                })
            })
            .collect::<Vec<_>>();
        for handle in threads {
            handle.join().unwrap();
        }
        assert_eq!(assert_chain(temp.path()), 8_000);
    }

    #[test]
    fn rotation_carries_the_chain_into_the_new_file() {
        let temp = TempDir::new().unwrap();
        let writer = AuditWriter::with_rotation_bytes(&FixedPaths::new(temp.path()), 900).unwrap();
        for item in 0..12 {
            let (action, decision) = evaluation(0, item);
            writer.append(&action, &decision, Some("policy")).unwrap();
        }
        let files = ordered_log_files(temp.path()).unwrap();
        assert!(files.len() > 1);
        assert_eq!(assert_chain(temp.path()), 12);
    }

    #[test]
    fn canary_never_appears_on_disk() {
        let temp = TempDir::new().unwrap();
        let writer = AuditWriter::new(&FixedPaths::new(temp.path())).unwrap();
        let canary = "AKIAIOSFODNN7EXAMPLE";
        let (mut action, decision) = evaluation(0, 0);
        if let ActionKind::Shell { raw, .. } = &mut action.kind {
            *raw = format!("curl https://example.test/{canary}");
        }
        writer.append(&action, &decision, Some("policy")).unwrap();
        let bytes = fs::read(temp.path().join(ACTIVE_LOG_NAME)).unwrap();
        assert!(!String::from_utf8(bytes).unwrap().contains(canary));
    }
}
