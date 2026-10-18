//! Shield Core - Policy engine, action model, and security primitives
//!
//! This crate provides:
//! - Action model (Shell, FileRead, FileWrite, Network, McpToolCall)
//! - Policy engine with YAML rule evaluation
//! - Bash command parser and normalizer
//! - Path normalization and sensitive path detection
//! - Secret content detection and redaction
//! - Layer 2 feature risk scorer and Layer 3 explainer stub
//! - [`sandbox`] Seatbelt profile generation for `agent-shield run <cli>`
//! - [`protect`] Protect-this-app catalog and process-tree matching
//! - [`canary`] labelled tripwire files (detection only)

pub mod canary;
pub mod engine;
pub mod model;
pub mod paths;
pub mod policy;
pub mod protect;
pub mod sandbox;
pub mod score;
pub mod secrets;
pub mod shell;

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
