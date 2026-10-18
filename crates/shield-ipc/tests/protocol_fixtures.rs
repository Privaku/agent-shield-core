//! IPC protocol v1 fixture tests.
//!
//! Every `protocol/fixtures/ipc_*.json` file must validate against
//! `protocol/ipc.schema.json` and round-trip through [`IpcMessage`].

use std::fs;
use std::path::{Path, PathBuf};

use jsonschema::Validator;
use serde_json::Value;
use shield_ipc::{DecisionEvent, IpcMessage, IpcRole, PROTOCOL_VERSION};

fn protocol_dir() -> PathBuf {
    Path::new(env!("CARGO_MANIFEST_DIR"))
        .join("../../protocol")
        .canonicalize()
        .expect("protocol/ directory exists")
}

fn read_json(path: &Path) -> Value {
    let text = fs::read_to_string(path).unwrap_or_else(|e| panic!("read {}: {e}", path.display()));
    serde_json::from_str(&text).unwrap_or_else(|e| panic!("parse {}: {e}", path.display()))
}

fn ipc_fixtures() -> Vec<(String, Value)> {
    let dir = protocol_dir().join("fixtures");
    let mut files: Vec<PathBuf> = fs::read_dir(&dir)
        .expect("protocol/fixtures exists")
        .map(|e| e.unwrap().path())
        .filter(|p| {
            p.extension().is_some_and(|ext| ext == "json")
                && p.file_name()
                    .and_then(|name| name.to_str())
                    .is_some_and(|name| name.starts_with("ipc_"))
        })
        .collect();
    files.sort();
    files
        .into_iter()
        .map(|p| {
            let name = p.file_name().unwrap().to_string_lossy().into_owned();
            (name, read_json(&p))
        })
        .collect()
}

fn ipc_schema() -> Value {
    read_json(&protocol_dir().join("ipc.schema.json"))
}

fn ipc_validator() -> Validator {
    jsonschema::draft202012::new(&ipc_schema())
        .unwrap_or_else(|e| panic!("ipc.schema.json is not a valid schema: {e}"))
}

#[test]
fn ipc_schema_is_valid_2020_12() {
    let schema = ipc_schema();
    assert_eq!(
        schema["$schema"],
        "https://json-schema.org/draft/2020-12/schema"
    );
    assert_eq!(
        schema["$id"],
        "https://privaku.com/agent-shield/protocol/v1/ipc.schema.json"
    );
    jsonschema::meta::validate(&schema).unwrap();
}

#[test]
fn ipc_fixtures_validate_and_round_trip() {
    let validator = ipc_validator();
    let fixtures = ipc_fixtures();
    assert!(
        fixtures.len() >= 6,
        "need hello, subscribe, ping, request, response, event; found {}",
        fixtures.len()
    );
    for (name, value) in fixtures {
        let errors: Vec<String> = validator
            .iter_errors(&value)
            .map(|e| format!("  at {}: {e}", e.instance_path()))
            .collect();
        assert!(
            errors.is_empty(),
            "{name} fails ipc schema:\n{}",
            errors.join("\n")
        );
        let typed: IpcMessage = serde_json::from_value(value.clone())
            .unwrap_or_else(|e| panic!("{name}: deserialise: {e}"));
        let back = serde_json::to_value(&typed).unwrap();
        assert_eq!(&back, &value, "{name}: round-trip changed JSON");
    }
}

#[test]
fn event_decision_round_trips_attribution_fields() {
    let (_, value) = ipc_fixtures()
        .into_iter()
        .find(|(name, _)| name.contains("event_decision"))
        .expect("ipc_event_decision fixture");
    let message: IpcMessage = serde_json::from_value(value).unwrap();
    let IpcMessage::Event { decision } = message else {
        panic!("fixture is not an event");
    };
    let DecisionEvent {
        agent,
        session,
        rule_id,
        decision: outcome,
        ..
    } = decision;
    assert_eq!(agent.as_str(), "cursor");
    assert_eq!(session, "cur-01HZX4N8");
    assert_eq!(rule_id.as_deref(), Some("secrets.dotenv"));
    assert_eq!(outcome.as_str(), "ask");
}

#[test]
fn hello_roles_cover_client_and_ui() {
    let mut roles = Vec::new();
    for (name, value) in ipc_fixtures() {
        if !name.contains("hello") {
            continue;
        }
        let message: IpcMessage = serde_json::from_value(value).unwrap();
        match message {
            IpcMessage::Hello { role, version } => {
                assert_eq!(version, PROTOCOL_VERSION);
                roles.push(role);
            }
            other => panic!("{name}: {other:?}"),
        }
    }
    assert!(roles.contains(&IpcRole::Client));
    assert!(roles.contains(&IpcRole::Ui));
}
