//! Per-session Ask rate limiter (threat T12).
//!
//! More than 5 Asks in a 60-second window from one session denies that Ask
//! and pauses further Asks for the rest of the window.

use std::collections::BTreeMap;
use std::fs;
use std::path::{Path, PathBuf};
use std::sync::Mutex;
use std::time::{Duration, SystemTime, UNIX_EPOCH};

use serde::{Deserialize, Serialize};

/// Maximum Asks accepted from one session in [`WINDOW`].
pub const MAX_ASKS_PER_WINDOW: usize = 5;
/// Sliding window used for T12 rate limiting.
pub const WINDOW: Duration = Duration::from_secs(60);

/// The session sent too many Asks and is paused.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct RateLimited {
    pub session: String,
}

/// File-backed or in-memory Ask counter, shared across hook/proxy/shim.
pub struct AskRateLimiter {
    inner: RateInner,
}

enum RateInner {
    File(PathBuf),
    Memory(Mutex<RateState>),
}

#[derive(Debug, Default, Clone, Serialize, Deserialize)]
struct RateState {
    sessions: BTreeMap<String, SessionRate>,
}

#[derive(Debug, Default, Clone, Serialize, Deserialize)]
struct SessionRate {
    asks: Vec<u64>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    paused_until: Option<u64>,
}

impl AskRateLimiter {
    pub fn file(path: impl Into<PathBuf>) -> Self {
        Self {
            inner: RateInner::File(path.into()),
        }
    }

    pub fn memory() -> Self {
        Self {
            inner: RateInner::Memory(Mutex::new(RateState::default())),
        }
    }

    /// Persist under `AGENT_SHIELD_RATE_DIR` or next to the daemon socket.
    pub fn from_env() -> Self {
        if let Ok(dir) = std::env::var("AGENT_SHIELD_RATE_DIR") {
            if !dir.is_empty() {
                let path = PathBuf::from(dir).join("ask-rate.json");
                return Self::file(path);
            }
        }
        match crate::transport::socket_path_from_env() {
            Ok(socket) => {
                let path = socket
                    .parent()
                    .unwrap_or(Path::new("."))
                    .join("ask-rate.json");
                Self::file(path)
            }
            Err(_) => Self::memory(),
        }
    }

    /// Record an Ask. `Err` means this session is over the limit (6th+).
    pub fn check_and_record(&self, session: &str) -> Result<(), RateLimited> {
        self.check_and_record_at(session, SystemTime::now())
    }

    pub fn check_and_record_at(&self, session: &str, now: SystemTime) -> Result<(), RateLimited> {
        let now_ms = millis(now);
        match &self.inner {
            RateInner::Memory(state) => {
                let mut state = state.lock().expect("ask rate limiter");
                apply(&mut state, session, now_ms)
            }
            RateInner::File(path) => {
                let mut state = load(path);
                let result = apply(&mut state, session, now_ms);
                save(path, &state);
                result
            }
        }
    }
}

fn apply(state: &mut RateState, session: &str, now_ms: u64) -> Result<(), RateLimited> {
    let window_start = now_ms.saturating_sub(WINDOW.as_millis() as u64);
    let entry = state.sessions.entry(session.to_string()).or_default();
    entry.asks.retain(|ts| *ts > window_start);
    if let Some(until) = entry.paused_until {
        if now_ms < until {
            return Err(RateLimited {
                session: session.to_string(),
            });
        }
        entry.paused_until = None;
    }
    if entry.asks.len() >= MAX_ASKS_PER_WINDOW {
        entry.paused_until = Some(now_ms.saturating_add(WINDOW.as_millis() as u64));
        return Err(RateLimited {
            session: session.to_string(),
        });
    }
    entry.asks.push(now_ms);
    Ok(())
}

fn load(path: &Path) -> RateState {
    let Ok(bytes) = fs::read(path) else {
        return RateState::default();
    };
    serde_json::from_slice(&bytes).unwrap_or_default()
}

fn save(path: &Path, state: &RateState) {
    if let Some(parent) = path.parent() {
        let _ = fs::create_dir_all(parent);
    }
    if let Ok(bytes) = serde_json::to_vec(state) {
        let tmp = path.with_extension("json.tmp");
        if fs::write(&tmp, bytes).is_ok() {
            let _ = fs::rename(&tmp, path);
        }
    }
}

fn millis(now: SystemTime) -> u64 {
    now.duration_since(UNIX_EPOCH)
        .unwrap_or_default()
        .as_millis() as u64
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn sixth_ask_from_one_session_is_denied() {
        let limiter = AskRateLimiter::memory();
        let start = UNIX_EPOCH + Duration::from_secs(1_000);
        for i in 0..MAX_ASKS_PER_WINDOW {
            limiter
                .check_and_record_at("sess", start + Duration::from_secs(i as u64))
                .expect("first five Asks are allowed");
        }
        let sixth = limiter
            .check_and_record_at("sess", start + Duration::from_secs(5))
            .unwrap_err();
        assert_eq!(sixth.session, "sess");
        limiter
            .check_and_record_at("sess", start + Duration::from_secs(6))
            .expect_err("paused session stays denied");
    }

    #[test]
    fn other_sessions_are_independent() {
        let limiter = AskRateLimiter::memory();
        let start = UNIX_EPOCH + Duration::from_secs(2_000);
        for _ in 0..MAX_ASKS_PER_WINDOW {
            limiter.check_and_record_at("a", start).unwrap();
        }
        limiter
            .check_and_record_at("a", start)
            .expect_err("session a is paused");
        limiter
            .check_and_record_at("b", start)
            .expect("session b is still open");
    }

    #[test]
    fn file_backed_limiter_survives_reload() {
        let temp = tempfile::tempdir().unwrap();
        let path = temp.path().join("ask-rate.json");
        let start = UNIX_EPOCH + Duration::from_secs(3_000);
        {
            let limiter = AskRateLimiter::file(&path);
            for _ in 0..MAX_ASKS_PER_WINDOW {
                limiter.check_and_record_at("s", start).unwrap();
            }
        }
        let limiter = AskRateLimiter::file(&path);
        limiter
            .check_and_record_at("s", start + Duration::from_secs(1))
            .expect_err("reloaded limiter still paused");
    }
}
