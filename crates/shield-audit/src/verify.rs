use std::fs::File;
use std::io::{BufRead, BufReader};
use std::path::{Path, PathBuf};

use thiserror::Error;

use crate::entry::{EntryError, GENESIS_HASH};
use crate::paths::{PathError, Paths, ACTIVE_LOG_NAME};
use crate::writer::{ordered_log_files, read_head, shared_lock};
use crate::{AuditEntry, WriterError};

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct VerificationReport {
    pub files: usize,
    pub entries: u64,
    pub last_hash: String,
}

#[derive(Debug, Error)]
pub enum VerifyError {
    #[error(transparent)]
    Path(#[from] PathError),
    #[error("{file}: audit log I/O failed: {source}")]
    Io {
        file: PathBuf,
        #[source]
        source: std::io::Error,
    },
    #[error("{file}: line {line}: invalid audit JSON: {source}")]
    InvalidJson {
        file: PathBuf,
        line: usize,
        #[source]
        source: serde_json::Error,
    },
    #[error("{file}: line {line}: cannot hash audit entry: {source}")]
    Hashing {
        file: PathBuf,
        line: usize,
        #[source]
        source: EntryError,
    },
    #[error("{file}: line {line}: broken chain (expected prev_hash {expected}, found {actual})")]
    BrokenChain {
        file: PathBuf,
        line: usize,
        expected: String,
        actual: String,
    },
    #[error("{file}: line {line}: hash mismatch (expected {expected}, found {actual})")]
    HashMismatch {
        file: PathBuf,
        line: usize,
        expected: String,
        actual: String,
    },
    #[error(
        "{file}: line {line}: audit entry was deleted (head records {expected} entries, found {actual})"
    )]
    EntryDeleted {
        file: PathBuf,
        line: usize,
        expected: u64,
        actual: u64,
    },
    #[error("{file}: line {line}: audit head is missing")]
    MissingHead { file: PathBuf, line: usize },
    #[error("{file}: line {line}: audit head hash does not match the log")]
    HeadMismatch { file: PathBuf, line: usize },
    #[error("cannot read audit head: {0}")]
    Head(#[from] WriterError),
}

pub fn verify(paths: &impl Paths) -> Result<VerificationReport, VerifyError> {
    verify_directory(&paths.directory()?)
}

pub fn verify_directory(directory: &Path) -> Result<VerificationReport, VerifyError> {
    let _lock = shared_lock(directory).map_err(|source| VerifyError::Io {
        file: directory.join("audit.lock"),
        source,
    })?;
    let files = ordered_log_files(directory).map_err(|source| VerifyError::Io {
        file: directory.to_path_buf(),
        source,
    })?;
    let mut expected = GENESIS_HASH.to_string();
    let mut entries = 0_u64;
    let mut last_location = (directory.join(ACTIVE_LOG_NAME), 1_usize);

    for path in &files {
        let file = File::open(path).map_err(|source| VerifyError::Io {
            file: path.clone(),
            source,
        })?;
        for (line_index, line) in BufReader::new(file).lines().enumerate() {
            let line_number = line_index + 1;
            let line = line.map_err(|source| VerifyError::Io {
                file: path.clone(),
                source,
            })?;
            let entry: AuditEntry =
                serde_json::from_str(&line).map_err(|source| VerifyError::InvalidJson {
                    file: path.clone(),
                    line: line_number,
                    source,
                })?;
            if entry.prev_hash != expected {
                return Err(VerifyError::BrokenChain {
                    file: path.clone(),
                    line: line_number,
                    expected,
                    actual: entry.prev_hash,
                });
            }
            let recomputed = entry
                .recompute_hash()
                .map_err(|source| VerifyError::Hashing {
                    file: path.clone(),
                    line: line_number,
                    source,
                })?;
            if entry.hash != recomputed {
                return Err(VerifyError::HashMismatch {
                    file: path.clone(),
                    line: line_number,
                    expected: recomputed,
                    actual: entry.hash,
                });
            }
            expected = entry.hash;
            entries += 1;
            last_location = (path.clone(), line_number);
        }
    }

    let head = read_head(directory)?;
    match head {
        Some(head) if head.entries != entries => {
            let line = if head.entries > entries {
                last_location.1 + 1
            } else {
                last_location.1
            };
            return Err(VerifyError::EntryDeleted {
                file: last_location.0,
                line,
                expected: head.entries,
                actual: entries,
            });
        }
        Some(head) if head.hash != expected => {
            return Err(VerifyError::HeadMismatch {
                file: last_location.0,
                line: last_location.1,
            });
        }
        None if entries != 0 => {
            return Err(VerifyError::MissingHead {
                file: last_location.0,
                line: last_location.1,
            });
        }
        _ => {}
    }

    Ok(VerificationReport {
        files: files.len(),
        entries,
        last_hash: expected,
    })
}

#[cfg(test)]
mod tests {
    use std::fs;
    use std::path::PathBuf;

    use shield_core::model::{
        Action, ActionKind, AgentContext, AgentKind, ArgvTree, Decision, Outcome, RiskScore,
        Severity,
    };
    use tempfile::TempDir;

    use crate::{AuditWriter, FixedPaths};

    use super::*;

    fn write_fixture() -> TempDir {
        let temp = TempDir::new().unwrap();
        let writer = AuditWriter::new(&FixedPaths::new(temp.path())).unwrap();
        for index in 0..4 {
            let raw = format!("echo {index}");
            let context = AgentContext {
                agent: AgentKind::Claude,
                session_id: "verify-test".into(),
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
                reason_user: "allowed".into(),
                reason_agent: "allowed".into(),
                risk_score: RiskScore::MIN,
            };
            writer.append(&action, &decision, Some("policy")).unwrap();
        }
        temp
    }

    fn lines(temp: &TempDir) -> Vec<String> {
        fs::read_to_string(temp.path().join(ACTIVE_LOG_NAME))
            .unwrap()
            .lines()
            .map(str::to_owned)
            .collect()
    }

    fn replace_lines(temp: &TempDir, lines: &[String]) {
        fs::write(
            temp.path().join(ACTIVE_LOG_NAME),
            format!("{}\n", lines.join("\n")),
        )
        .unwrap();
    }

    #[test]
    fn valid_chain_reports_counts() {
        let temp = write_fixture();
        let report = verify(&FixedPaths::new(temp.path())).unwrap();
        assert_eq!(report.files, 1);
        assert_eq!(report.entries, 4);
        assert_ne!(report.last_hash, GENESIS_HASH);
    }

    #[test]
    fn editing_reports_the_first_bad_file_and_line() {
        let temp = write_fixture();
        let mut lines = lines(&temp);
        let mut entry: serde_json::Value = serde_json::from_str(&lines[1]).unwrap();
        entry["decision"] = serde_json::Value::String("deny".into());
        lines[1] = serde_json::to_string(&entry).unwrap();
        replace_lines(&temp, &lines);
        let error = verify(&FixedPaths::new(temp.path())).unwrap_err();
        assert!(matches!(error, VerifyError::HashMismatch { line: 2, .. }));
        assert!(error.to_string().contains("audit.jsonl: line 2"));
    }

    #[test]
    fn deleting_an_internal_or_last_line_is_detected() {
        let temp = write_fixture();
        let mut content = lines(&temp);
        content.remove(1);
        replace_lines(&temp, &content);
        assert!(matches!(
            verify(&FixedPaths::new(temp.path())).unwrap_err(),
            VerifyError::BrokenChain { line: 2, .. }
        ));

        let temp = write_fixture();
        let mut content = lines(&temp);
        content.pop();
        replace_lines(&temp, &content);
        assert!(matches!(
            verify(&FixedPaths::new(temp.path())).unwrap_err(),
            VerifyError::EntryDeleted { line: 4, .. }
        ));
    }

    #[test]
    fn reordering_reports_the_first_bad_line() {
        let temp = write_fixture();
        let mut content = lines(&temp);
        content.swap(1, 2);
        replace_lines(&temp, &content);
        assert!(matches!(
            verify(&FixedPaths::new(temp.path())).unwrap_err(),
            VerifyError::BrokenChain { line: 2, .. }
        ));
    }
}
