# Third-party licences

© 2026 Privaku

Direct dependencies of this core. Transitive crates stay inside the
allowlist in `deny.toml` (MIT, Apache-2.0, BSD-2-Clause, BSD-3-Clause,
ISC, Zlib, Unicode-3.0, Unlicense, CC0-1.0, and MPL-2.0 only as an
unmodified dependency).

## Rust dependencies

| Name | Version | Licence | URL | Purpose |
|---|---|---|---|---|
| `clap` | 4.4 | MIT OR Apache-2.0 | https://github.com/clap-rs/clap | Command-line argument parsing |
| `serde` | 1.0 | MIT OR Apache-2.0 | https://github.com/serde-rs/serde | Serialisation framework |
| `serde_json` | 1.0 | MIT OR Apache-2.0 | https://github.com/serde-rs/json | JSON wire format and audit log |
| `serde_yaml_ng` | 0.10 | MIT | https://github.com/acatton/serde-yaml-ng | YAML policy file parsing |
| `tokio` | 1.35 | MIT | https://github.com/tokio-rs/tokio | Async runtime for the daemon and IPC |
| `libc` | 0.2 | MIT OR Apache-2.0 | https://github.com/rust-lang/libc | Forwarding signals from the MCP proxy to its child |
| `anyhow` | 1.0 | MIT OR Apache-2.0 | https://github.com/dtolnay/anyhow | Error handling in the CLI |
| `thiserror` | 1.0 | MIT OR Apache-2.0 | https://github.com/dtolnay/thiserror | Error type derivation in libraries |
| `tracing` | 0.1 | MIT | https://github.com/tokio-rs/tracing | Structured diagnostics |
| `tracing-subscriber` | 0.3 | MIT | https://github.com/tokio-rs/tracing | Tracing output and filtering |
| `tree-sitter` | 0.25 | MIT | https://github.com/tree-sitter/tree-sitter | Parser runtime for the bash command parser |
| `tree-sitter-bash` | 0.25 | MIT | https://github.com/tree-sitter/tree-sitter-bash | Bash grammar |
| `globset` | 0.4 | MIT OR Apache-2.0 | https://github.com/BurntSushi/ripgrep/tree/master/crates/globset | Sensitive-path glob matching |
| `regex` | 1.13 | MIT OR Apache-2.0 | https://github.com/rust-lang/regex | Secret content detectors and redaction |
| `sha2` | 0.11 | MIT OR Apache-2.0 | https://github.com/RustCrypto/hashes | SHA-256 audit-log hash chain |
| `time` | 0.3 | MIT OR Apache-2.0 | https://github.com/time-rs/time | RFC 3339 audit timestamps |
| `fs2` | 0.4 | MIT OR Apache-2.0 | https://github.com/danburkert/fs2-rs | Cross-process audit-log file locking |
| `toml_edit` | 0.22 | MIT OR Apache-2.0 | https://github.com/toml-rs/toml | Preserve formatting while wrapping Codex MCP configs |
| `dialoguer` | 0.11 | MIT OR Apache-2.0 | https://github.com/console-rs/dialoguer | Terminal approval UI |

## Test dependencies

| Name | Version | Licence | URL | Purpose |
|---|---|---|---|---|
| `tempfile` | 3.10 | MIT OR Apache-2.0 | https://github.com/Stebalien/tempfile | Temporary directories in tests |
| `assert_cmd` | 2.0 | MIT OR Apache-2.0 | https://github.com/assert-rs/assert_cmd | CLI integration tests |
| `predicates` | 3.1 | MIT OR Apache-2.0 | https://github.com/assert-rs/predicates-rs | Test assertions |
| `jsonschema` | 0.58 | MIT | https://github.com/Stranger6667/jsonschema | Validates protocol fixtures |
| `proptest` | 1.12 | MIT OR Apache-2.0 | https://github.com/proptest-rs/proptest | Property tests for redaction |
