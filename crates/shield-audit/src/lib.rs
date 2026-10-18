//! Shield Audit - Hash-chained audit log
//!
//! Provides tamper-evident, privacy-safe logging:
//! - Append-only JSONL format
//! - SHA-256 hash chain for integrity verification
//! - Automatic secret redaction
//! - Log rotation at 10 MB
//!
//! Hashes sign `prev_hash || canonical_json(entry_without_hash)`. Canonical
//! JSON is compact UTF-8 JSON with object keys sorted lexicographically at
//! every depth and array order preserved.

mod entry;
mod paths;
mod reader;
mod verify;
mod writer;

pub use entry::{AuditEntry, EntryError, GENESIS_HASH};
pub use paths::{
    FixedPaths, PathError, Paths, PlatformPaths, ACTIVE_LOG_NAME, HEAD_FILE_NAME, LOCK_FILE_NAME,
    STATE_DIR_ENV,
};
pub use reader::{read_entries, read_entries_since, read_entries_since_now, ReadError};
pub use verify::{verify, verify_directory, VerificationReport, VerifyError};
pub use writer::{ordered_log_files, AuditWriter, WriterError, DEFAULT_ROTATION_BYTES};

pub fn version() -> &'static str {
    env!("CARGO_PKG_VERSION")
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_version() {
        assert!(version().starts_with("0.1"));
    }
}
