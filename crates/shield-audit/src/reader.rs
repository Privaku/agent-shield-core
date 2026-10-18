use std::fs::File;
use std::io::{BufRead, BufReader};
use std::path::{Path, PathBuf};

use thiserror::Error;
use time::{format_description::well_known::Rfc3339, Duration, OffsetDateTime};

use crate::writer::shared_lock;
use crate::{ordered_log_files, AuditEntry};

#[derive(Debug, Error)]
pub enum ReadError {
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
    #[error("invalid --since value {value:?}; use RFC3339 or a duration such as 30m, 24h, or 7d")]
    InvalidSince { value: String },
    #[error("{file}: line {line}: invalid RFC3339 audit timestamp {value:?}")]
    InvalidTimestamp {
        file: PathBuf,
        line: usize,
        value: String,
    },
}

pub fn read_entries(directory: &Path) -> Result<Vec<AuditEntry>, ReadError> {
    let _lock = shared_lock(directory).map_err(|source| ReadError::Io {
        file: directory.join("audit.lock"),
        source,
    })?;
    let files = ordered_log_files(directory).map_err(|source| ReadError::Io {
        file: directory.to_path_buf(),
        source,
    })?;
    let mut entries = Vec::new();
    for path in files {
        let file = File::open(&path).map_err(|source| ReadError::Io {
            file: path.clone(),
            source,
        })?;
        for (line_index, line) in BufReader::new(file).lines().enumerate() {
            let line_number = line_index + 1;
            let line = line.map_err(|source| ReadError::Io {
                file: path.clone(),
                source,
            })?;
            let entry = serde_json::from_str(&line).map_err(|source| ReadError::InvalidJson {
                file: path.clone(),
                line: line_number,
                source,
            })?;
            entries.push(entry);
        }
    }
    Ok(entries)
}

pub fn read_entries_since(
    directory: &Path,
    since: &str,
    now: OffsetDateTime,
) -> Result<Vec<AuditEntry>, ReadError> {
    let threshold = parse_since(since, now)?;
    let _lock = shared_lock(directory).map_err(|source| ReadError::Io {
        file: directory.join("audit.lock"),
        source,
    })?;
    let files = ordered_log_files(directory).map_err(|source| ReadError::Io {
        file: directory.to_path_buf(),
        source,
    })?;
    let mut entries = Vec::new();
    for path in files {
        let file = File::open(&path).map_err(|source| ReadError::Io {
            file: path.clone(),
            source,
        })?;
        for (line_index, line) in BufReader::new(file).lines().enumerate() {
            let line_number = line_index + 1;
            let line = line.map_err(|source| ReadError::Io {
                file: path.clone(),
                source,
            })?;
            let entry: AuditEntry =
                serde_json::from_str(&line).map_err(|source| ReadError::InvalidJson {
                    file: path.clone(),
                    line: line_number,
                    source,
                })?;
            let timestamp = OffsetDateTime::parse(&entry.ts, &Rfc3339).map_err(|_| {
                ReadError::InvalidTimestamp {
                    file: path.clone(),
                    line: line_number,
                    value: entry.ts.clone(),
                }
            })?;
            if timestamp >= threshold {
                entries.push(entry);
            }
        }
    }
    Ok(entries)
}

pub fn read_entries_since_now(directory: &Path, since: &str) -> Result<Vec<AuditEntry>, ReadError> {
    read_entries_since(directory, since, OffsetDateTime::now_utc())
}

fn parse_since(value: &str, now: OffsetDateTime) -> Result<OffsetDateTime, ReadError> {
    if let Ok(timestamp) = OffsetDateTime::parse(value, &Rfc3339) {
        return Ok(timestamp);
    }
    let (digits, unit) = value.split_at(value.len().saturating_sub(1));
    let amount = digits
        .parse::<i64>()
        .ok()
        .filter(|amount| *amount >= 0)
        .ok_or_else(|| ReadError::InvalidSince {
            value: value.to_string(),
        })?;
    let multiplier = match unit {
        "s" => 1,
        "m" => 60,
        "h" => 60 * 60,
        "d" => 24 * 60 * 60,
        "w" => 7 * 24 * 60 * 60,
        _ => {
            return Err(ReadError::InvalidSince {
                value: value.to_string(),
            });
        }
    };
    let seconds = amount
        .checked_mul(multiplier)
        .ok_or_else(|| ReadError::InvalidSince {
            value: value.to_string(),
        })?;
    let duration = Duration::seconds(seconds);
    now.checked_sub(duration)
        .ok_or_else(|| ReadError::InvalidSince {
            value: value.to_string(),
        })
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn since_accepts_rfc3339_and_simple_durations() {
        let now = OffsetDateTime::parse("2026-10-16T08:00:00Z", &Rfc3339).unwrap();
        assert_eq!(
            parse_since("2026-10-15T00:00:00Z", now).unwrap(),
            OffsetDateTime::parse("2026-10-15T00:00:00Z", &Rfc3339).unwrap()
        );
        assert_eq!(
            parse_since("30m", now).unwrap(),
            now - Duration::minutes(30)
        );
        assert_eq!(parse_since("24h", now).unwrap(), now - Duration::hours(24));
        assert_eq!(parse_since("7d", now).unwrap(), now - Duration::days(7));
        assert!(parse_since("yesterday", now).is_err());
        assert!(parse_since("-1h", now).is_err());
    }
}
