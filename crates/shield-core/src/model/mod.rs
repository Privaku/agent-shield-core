//! Core data model shared by every Agent Shield component.
//!
//! The types here define the **wire format** used between the hook adapters,
//! the policy engine, the audit log, the approval daemon and the UIs. The JSON
//! encoding is fixed:
//!
//! - all field names and enum variants are `snake_case`;
//! - enums with payloads are internally tagged (`"kind"`, `"node"`, `"type"`);
//! - optional fields are omitted when absent, never written as `null`;
//! - unknown fields are rejected, so a malformed message fails closed.
//!
//! The matching JSON Schemas live in `protocol/*.schema.json` and the example
//! messages in `protocol/fixtures/`. Changing anything here means updating the
//! schemas and fixtures in the same commit.

mod action;
mod approval;
mod context;
mod decision;

pub use action::{
    Action, ActionKind, ArgvTree, BodySource, ListOp, ObfuscationFlag, Redirect, RedirectOp,
};
pub use approval::{ApprovalRequest, ApprovalResponse, ApprovalVerdict};
pub use context::{AgentContext, AgentKind};
pub use decision::{combine, Decision, Outcome, RiskScore, RiskScoreError, Severity};
