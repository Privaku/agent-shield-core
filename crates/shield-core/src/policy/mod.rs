//! YAML policy loader and validator.
//!
//! A policy is built from up to three layers, merged in this order:
//!
//! 1. the embedded default, `rules/default.yaml`, compiled in with
//!    `include_str!` ([`EMBEDDED_DEFAULT`]);
//! 2. the user file, `~/.config/privaku/agent-shield/policy.yaml`;
//! 3. the project file, `.agent-shield.yaml` in the working directory.
//!
//! Later layers overlay `defaults`, add rules, redefine rules by `id` and
//! switch rules off with `disable: [id, ...]`. A `critical` rule can only be
//! weakened or disabled by the user file, and only when that file sets
//! `allow_override_critical: true`; a project file can never do it.
//!
//! Every file is validated strictly: unknown keys, duplicate ids, bad
//! `decision`/`severity` values and empty `match` blocks are errors that name
//! the file, the line and the rule. A policy that fails to load must make the
//! caller deny, never allow.
//!
//! Matching semantics (what `match:` means for an action) are the M6 engine's
//! job; this module only guarantees the shape of the data.

mod error;
mod loader;
mod schema;

pub use error::{PolicyError, PolicyErrorKind};
pub use loader::{
    load, load_embedded, load_sources, merge, parse_source, validate_path, DisabledRule, Layer,
    LoadedSource, ParsedSource, Paths, Policy, PolicyRule, Source, EMBEDDED_DEFAULT, EMBEDDED_NAME,
};
pub use schema::{
    Access, Dataflow, Defaults, DefaultsPatch, Match, McpMatch, PolicyFile, Rule,
    DEFAULT_ASK_THRESHOLD, DEFAULT_ASK_TIMEOUT_SECONDS, SCHEMA_VERSION,
};
