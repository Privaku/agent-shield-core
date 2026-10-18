//! Offline secret content detection and redaction.

use std::collections::HashMap;
use std::fmt;
use std::sync::OnceLock;

use regex::Regex;

const MIN_GENERIC_LENGTH: usize = 32;
const MIN_GENERIC_ENTROPY: f64 = 4.0;

/// Stable names used in redaction markers and audit records.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum SecretKind {
    AwsAccessKeyId,
    PemPrivateKey,
    GitHubToken,
    SkApiKey,
    SlackToken,
    StripeLiveKey,
    GoogleApiKey,
    Jwt,
    HighEntropyToken,
}

impl SecretKind {
    pub const ALL: [Self; 9] = [
        Self::AwsAccessKeyId,
        Self::PemPrivateKey,
        Self::GitHubToken,
        Self::SkApiKey,
        Self::SlackToken,
        Self::StripeLiveKey,
        Self::GoogleApiKey,
        Self::Jwt,
        Self::HighEntropyToken,
    ];

    pub const fn as_str(self) -> &'static str {
        match self {
            Self::AwsAccessKeyId => "aws_access_key_id",
            Self::PemPrivateKey => "pem_private_key",
            Self::GitHubToken => "github_token",
            Self::SkApiKey => "sk_api_key",
            Self::SlackToken => "slack_token",
            Self::StripeLiveKey => "stripe_live_key",
            Self::GoogleApiKey => "google_api_key",
            Self::Jwt => "jwt",
            Self::HighEntropyToken => "high_entropy_token",
        }
    }
}

impl fmt::Display for SecretKind {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str(self.as_str())
    }
}

/// One non-overlapping secret occurrence in the input.
#[derive(Debug, Clone, PartialEq)]
pub struct SecretMatch<'a> {
    pub kind: SecretKind,
    pub start: usize,
    pub end: usize,
    pub value: &'a str,
    /// Shannon entropy for the generic detector; absent for shaped tokens.
    pub entropy: Option<f64>,
}

/// Find every supported secret pattern, preferring shaped detectors over the
/// generic entropy detector when ranges overlap.
pub fn detect(text: &str) -> Vec<SecretMatch<'_>> {
    let mut shaped = Vec::new();
    for detector in detectors() {
        for found in detector.regex.find_iter(text) {
            if has_token_boundaries(text, found.start(), found.end(), detector.kind) {
                shaped.push(SecretMatch {
                    kind: detector.kind,
                    start: found.start(),
                    end: found.end(),
                    value: found.as_str(),
                    entropy: None,
                });
            }
        }
    }
    shaped.sort_by_key(|found| (found.start, usize::MAX - found.end));
    shaped = non_overlapping(shaped);

    let mut matches = shaped;
    for found in generic_regex().find_iter(text) {
        if matches.iter().any(|specific| {
            ranges_overlap(found.start(), found.end(), specific.start, specific.end)
        }) {
            continue;
        }
        if is_path_context(text, found.start(), found.end()) {
            continue;
        }
        let entropy = shannon_entropy(found.as_str());
        if found.as_str().len() >= MIN_GENERIC_LENGTH && entropy >= MIN_GENERIC_ENTROPY {
            matches.push(SecretMatch {
                kind: SecretKind::HighEntropyToken,
                start: found.start(),
                end: found.end(),
                value: found.as_str(),
                entropy: Some(entropy),
            });
        }
    }
    matches.sort_by_key(|found| found.start);
    non_overlapping(matches)
}

/// Replace every detected value with a stable marker.
pub fn redact(text: &str) -> String {
    let matches = detect(text);
    if matches.is_empty() {
        return text.to_string();
    }
    let mut redacted = String::with_capacity(text.len());
    let mut cursor = 0;
    for found in matches {
        redacted.push_str(&text[cursor..found.start]);
        redacted.push_str("[REDACTED:");
        redacted.push_str(found.kind.as_str());
        redacted.push(']');
        cursor = found.end;
    }
    redacted.push_str(&text[cursor..]);
    redacted
}

/// Shannon entropy in bits per character.
pub fn shannon_entropy(value: &str) -> f64 {
    if value.is_empty() {
        return 0.0;
    }
    let mut counts = HashMap::new();
    for byte in value.bytes() {
        *counts.entry(byte).or_insert(0usize) += 1;
    }
    let length = value.len() as f64;
    counts
        .values()
        .map(|count| {
            let probability = *count as f64 / length;
            -probability * probability.log2()
        })
        .sum()
}

struct Detector {
    kind: SecretKind,
    regex: Regex,
}

fn detectors() -> &'static [Detector] {
    static DETECTORS: OnceLock<Vec<Detector>> = OnceLock::new();
    DETECTORS.get_or_init(|| {
        [
            (SecretKind::AwsAccessKeyId, r"(?:AKIA|ASIA)[A-Z0-9]{16}"),
            (
                SecretKind::PemPrivateKey,
                r"-----BEGIN (?:RSA |EC |DSA |OPENSSH |ENCRYPTED )?PRIVATE KEY-----",
            ),
            (
                SecretKind::GitHubToken,
                r"(?:gh[pousr]_[A-Za-z0-9]{36,255}|github_pat_[A-Za-z0-9_]{30,255})",
            ),
            (
                SecretKind::SkApiKey,
                r"sk-(?:(?:proj|ant-api[0-9]{2})-)?[A-Za-z0-9_-]{20,}",
            ),
            (SecretKind::SlackToken, r"xox[baprs]-[A-Za-z0-9-]{10,}"),
            (SecretKind::StripeLiveKey, r"sk_live_[A-Za-z0-9]{16,}"),
            (SecretKind::GoogleApiKey, r"AIza[0-9A-Za-z_-]{35}"),
            (
                SecretKind::Jwt,
                r"eyJ[A-Za-z0-9_-]{5,}\.eyJ[A-Za-z0-9_-]{5,}\.[A-Za-z0-9_-]{8,}",
            ),
        ]
        .into_iter()
        .map(|(kind, pattern)| Detector {
            kind,
            regex: Regex::new(pattern).expect("built-in secret regex is valid"),
        })
        .collect()
    })
}

fn generic_regex() -> &'static Regex {
    static GENERIC: OnceLock<Regex> = OnceLock::new();
    GENERIC.get_or_init(|| {
        Regex::new(r"[A-Za-z0-9+/=_-]{32,}").expect("built-in entropy regex is valid")
    })
}

fn is_path_context(text: &str, start: usize, end: usize) -> bool {
    let window_start = start.saturating_sub(64);
    let window_end = (end + 64).min(text.len());
    let window = &text[window_start..window_end];
    if window.contains('/') || window.contains('\\') || window.contains('~') {
        return true;
    }
    let lower = window.to_ascii_lowercase();
    for ext in [
        ".dmg", ".app", ".pkg", ".zip", ".png", ".icns", ".json", ".yaml", ".yml", ".swift", ".rs",
        ".md", ".txt", ".log", ".dylib",
    ] {
        if lower.contains(ext) {
            return true;
        }
    }
    false
}

fn has_token_boundaries(text: &str, start: usize, end: usize, kind: SecretKind) -> bool {
    if kind == SecretKind::PemPrivateKey {
        return true;
    }
    let before = text[..start].chars().next_back();
    let after = text[end..].chars().next();
    !before.is_some_and(is_token_character) && !after.is_some_and(is_token_character)
}

fn is_token_character(character: char) -> bool {
    character.is_ascii_alphanumeric() || matches!(character, '_' | '-')
}

fn ranges_overlap(a_start: usize, a_end: usize, b_start: usize, b_end: usize) -> bool {
    a_start < b_end && b_start < a_end
}

fn non_overlapping(matches: Vec<SecretMatch<'_>>) -> Vec<SecretMatch<'_>> {
    let mut accepted: Vec<SecretMatch<'_>> = Vec::with_capacity(matches.len());
    for found in matches {
        if accepted
            .last()
            .is_none_or(|previous| found.start >= previous.end)
        {
            accepted.push(found);
        }
    }
    accepted
}
