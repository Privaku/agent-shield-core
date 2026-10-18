//! Protocol conformance tests.
//!
//! Every file in `protocol/fixtures/` must
//! 1. validate against its JSON Schema in `protocol/`,
//! 2. deserialise into the matching `shield_core::model` type, and
//! 3. serialise back to exactly the same JSON (the fixtures are canonical).
//!
//! The schemas and the Rust types are also checked against each other so the
//! wire format cannot drift silently.

use std::collections::BTreeSet;
use std::fs;
use std::path::{Path, PathBuf};

use jsonschema::Validator;
use serde::de::DeserializeOwned;
use serde::Serialize;
use serde_json::{json, Value};
use shield_core::model::{
    Action, ActionKind, AgentKind, ApprovalRequest, ApprovalResponse, ApprovalVerdict, ArgvTree,
    Decision, ListOp, ObfuscationFlag, Outcome, RedirectOp, Severity,
};

const MIN_FIXTURES: usize = 10;

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

fn schema(name: &str) -> Value {
    read_json(&protocol_dir().join(format!("{name}.schema.json")))
}

fn validator(name: &str) -> Validator {
    jsonschema::draft202012::new(&schema(name))
        .unwrap_or_else(|e| panic!("{name}.schema.json is not a valid schema: {e}"))
}

fn fixtures() -> Vec<(String, Value)> {
    let dir = protocol_dir().join("fixtures");
    let mut files: Vec<PathBuf> = fs::read_dir(&dir)
        .expect("protocol/fixtures exists")
        .map(|e| e.unwrap().path())
        .filter(|p| p.extension().is_some_and(|ext| ext == "json"))
        .filter(|p| {
            p.file_name()
                .and_then(|name| name.to_str())
                .is_some_and(|name| !name.starts_with("ipc_"))
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

/// Which schema and Rust type a fixture belongs to, derived from its file
/// name prefix.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord)]
enum Kind {
    Action,
    Decision,
    ApprovalRequest,
    ApprovalResponse,
}

impl Kind {
    fn of(file_name: &str) -> Kind {
        if file_name.starts_with("action_") {
            Kind::Action
        } else if file_name.starts_with("decision_") {
            Kind::Decision
        } else if file_name.starts_with("approval_request_") {
            Kind::ApprovalRequest
        } else if file_name.starts_with("approval_response_") {
            Kind::ApprovalResponse
        } else {
            panic!(
                "fixture {file_name} has no known prefix \
                 (action_, decision_, approval_request_, approval_response_)"
            )
        }
    }

    fn schema_name(self) -> &'static str {
        match self {
            Kind::Action => "action",
            Kind::Decision => "decision",
            Kind::ApprovalRequest | Kind::ApprovalResponse => "approval",
        }
    }
}

fn assert_valid(validator: &Validator, name: &str, value: &Value) {
    let errors: Vec<String> = validator
        .iter_errors(value)
        .map(|e| format!("  at {}: {e}", e.instance_path()))
        .collect();
    assert!(
        errors.is_empty(),
        "{name} fails schema validation:\n{}",
        errors.join("\n")
    );
}

fn assert_round_trip<T>(name: &str, value: &Value)
where
    T: Serialize + DeserializeOwned + PartialEq + std::fmt::Debug,
{
    let typed: T = serde_json::from_value(value.clone()).unwrap_or_else(|e| {
        panic!(
            "{name}: deserialise into {}: {e}",
            std::any::type_name::<T>()
        )
    });
    let back = serde_json::to_value(&typed).unwrap();
    assert_eq!(
        &back, value,
        "{name}: serialising the deserialised value changed the JSON (fixtures are canonical)"
    );
    let again: T = serde_json::from_value(back).unwrap();
    assert_eq!(again, typed, "{name}: second deserialisation differs");
}

#[test]
fn there_are_enough_fixtures() {
    let all = fixtures();
    assert!(
        all.len() >= MIN_FIXTURES,
        "expected at least {MIN_FIXTURES} fixtures, found {}",
        all.len()
    );
    let kinds: BTreeSet<_> = all.iter().map(|(n, _)| Kind::of(n)).collect();
    assert_eq!(
        kinds.len(),
        4,
        "every message type needs at least one fixture: {kinds:?}"
    );
}

#[test]
fn schemas_are_valid_2020_12_schemas() {
    for name in ["action", "decision", "approval"] {
        let s = schema(name);
        assert_eq!(
            s["$schema"], "https://json-schema.org/draft/2020-12/schema",
            "{name}"
        );
        assert_eq!(
            s["$id"],
            format!("https://privaku.com/agent-shield/protocol/v1/{name}.schema.json")
        );
        jsonschema::meta::validate(&s)
            .unwrap_or_else(|e| panic!("{name}.schema.json fails the metaschema: {e}"));
        validator(name);
    }
}

#[test]
fn every_fixture_validates_against_its_schema() {
    let validators = [
        ("action", validator("action")),
        ("decision", validator("decision")),
        ("approval", validator("approval")),
    ];
    for (name, value) in fixtures() {
        let schema_name = Kind::of(&name).schema_name();
        let (_, v) = validators.iter().find(|(n, _)| *n == schema_name).unwrap();
        assert_valid(v, &name, &value);
    }
}

#[test]
fn every_fixture_round_trips_through_the_model() {
    for (name, value) in fixtures() {
        match Kind::of(&name) {
            Kind::Action => assert_round_trip::<Action>(&name, &value),
            Kind::Decision => assert_round_trip::<Decision>(&name, &value),
            Kind::ApprovalRequest => assert_round_trip::<ApprovalRequest>(&name, &value),
            Kind::ApprovalResponse => assert_round_trip::<ApprovalResponse>(&name, &value),
        }
    }
}

#[test]
fn approval_fixtures_match_exactly_one_branch() {
    // The approval schema is a oneOf; a request must never also parse as a
    // response and vice versa.
    for (name, value) in fixtures() {
        match Kind::of(&name) {
            Kind::ApprovalRequest => {
                assert!(
                    serde_json::from_value::<ApprovalResponse>(value).is_err(),
                    "{name}"
                )
            }
            Kind::ApprovalResponse => {
                assert!(
                    serde_json::from_value::<ApprovalRequest>(value).is_err(),
                    "{name}"
                )
            }
            _ => {}
        }
    }
}

#[test]
fn fixtures_cover_every_action_kind_and_argv_node() {
    let mut kinds = BTreeSet::new();
    let mut nodes = BTreeSet::new();
    let mut agents = BTreeSet::new();

    fn walk(tree: &ArgvTree, nodes: &mut BTreeSet<&'static str>) {
        match tree {
            ArgvTree::Command { substitutions, .. } => {
                nodes.insert("command");
                substitutions.iter().for_each(|t| walk(t, nodes));
            }
            ArgvTree::Pipeline { commands } => {
                nodes.insert("pipeline");
                commands.iter().for_each(|t| walk(t, nodes));
            }
            ArgvTree::List { left, right, .. } => {
                nodes.insert("list");
                walk(left, nodes);
                walk(right, nodes);
            }
            ArgvTree::Group { body } => {
                nodes.insert("group");
                walk(body, nodes);
            }
            ArgvTree::Unparsed { .. } => {
                nodes.insert("unparsed");
            }
        }
    }

    for (name, value) in fixtures() {
        if Kind::of(&name) != Kind::Action {
            continue;
        }
        let action: Action = serde_json::from_value(value).unwrap();
        kinds.insert(action.kind.name());
        agents.insert(action.context.agent.as_str());
        if let ActionKind::Shell { argv_tree, .. } = &action.kind {
            walk(argv_tree, &mut nodes);
        }
    }

    let want_kinds: BTreeSet<_> = [
        "shell",
        "file_read",
        "file_write",
        "file_delete",
        "network",
        "mcp_tool_call",
    ]
    .into_iter()
    .collect();
    assert_eq!(kinds, want_kinds, "every ActionKind needs a fixture");
    let want_nodes: BTreeSet<_> = ["command", "pipeline", "list", "group", "unparsed"]
        .into_iter()
        .collect();
    assert_eq!(nodes, want_nodes, "every ArgvTree node needs a fixture");
    let want_agents: BTreeSet<_> = ["claude", "cursor", "codex", "mcp", "shim"]
        .into_iter()
        .collect();
    assert_eq!(agents, want_agents, "every AgentKind needs a fixture");
}

#[test]
fn fixtures_cover_every_outcome_and_verdict() {
    let mut outcomes = BTreeSet::new();
    let mut verdicts = BTreeSet::new();
    for (name, value) in fixtures() {
        match Kind::of(&name) {
            Kind::Decision => {
                let d: Decision = serde_json::from_value(value).unwrap();
                outcomes.insert(d.outcome.as_str());
            }
            Kind::ApprovalResponse => {
                let r: ApprovalResponse = serde_json::from_value(value).unwrap();
                verdicts.insert(serde_json::to_string(&r.verdict).unwrap());
            }
            _ => {}
        }
    }
    assert_eq!(outcomes, ["allow", "ask", "deny"].into_iter().collect());
    assert_eq!(
        verdicts,
        [
            "\"allow_once\"",
            "\"allow_session\"",
            "\"always_allow\"",
            "\"deny\""
        ]
        .into_iter()
        .map(String::from)
        .collect()
    );
}

/// Wire names of every enum variant, as serde writes them.
fn wire_names<T: Serialize>(variants: &[T]) -> Vec<Value> {
    variants
        .iter()
        .map(|v| serde_json::to_value(v).unwrap())
        .collect()
}

fn schema_enum(schema: &Value, pointer: &str) -> Vec<Value> {
    schema
        .pointer(pointer)
        .unwrap_or_else(|| panic!("schema pointer {pointer} missing"))
        .as_array()
        .unwrap_or_else(|| panic!("schema pointer {pointer} is not an enum array"))
        .clone()
}

#[test]
fn schema_enums_match_rust_wire_names() {
    let action = schema("action");
    let decision = schema("decision");
    let approval = schema("approval");

    let agent_kinds = wire_names(&[
        AgentKind::Claude,
        AgentKind::Cursor,
        AgentKind::Codex,
        AgentKind::Mcp,
        AgentKind::Shim,
    ]);
    assert_eq!(schema_enum(&action, "/$defs/agent_kind/enum"), agent_kinds);
    assert_eq!(
        schema_enum(&approval, "/$defs/agent_kind/enum"),
        agent_kinds
    );

    let severities = wire_names(&[
        Severity::Info,
        Severity::Low,
        Severity::Medium,
        Severity::High,
        Severity::Critical,
    ]);
    assert_eq!(schema_enum(&decision, "/$defs/severity/enum"), severities);
    assert_eq!(schema_enum(&approval, "/$defs/severity/enum"), severities);

    assert_eq!(
        schema_enum(&decision, "/$defs/outcome/enum"),
        wire_names(&[Outcome::Allow, Outcome::Ask, Outcome::Deny])
    );
    assert_eq!(
        schema_enum(&approval, "/$defs/verdict/enum"),
        wire_names(&[
            ApprovalVerdict::AllowOnce,
            ApprovalVerdict::AllowSession,
            ApprovalVerdict::AlwaysAllow,
            ApprovalVerdict::Deny,
        ])
    );
    assert_eq!(
        schema_enum(&action, "/$defs/argv_tree/oneOf/2/properties/op/enum"),
        wire_names(&[ListOp::And, ListOp::Or, ListOp::Then, ListOp::Background])
    );
    assert_eq!(
        schema_enum(&action, "/$defs/redirect/properties/op/enum"),
        wire_names(&[
            RedirectOp::Read,
            RedirectOp::Write,
            RedirectOp::Append,
            RedirectOp::ReadWrite,
            RedirectOp::HereDoc,
            RedirectOp::HereString,
            RedirectOp::Dup,
        ])
    );
    assert_eq!(
        schema_enum(&action, "/$defs/obfuscation_flag/enum"),
        wire_names(&ObfuscationFlag::ALL)
    );

    let kind_names: Vec<Value> = schema_enum(&action, "/$defs/action_kind/enum");
    let kind_branches: Vec<Value> = action["oneOf"]
        .as_array()
        .unwrap()
        .iter()
        .map(|r| {
            let def = r["$ref"].as_str().unwrap().trim_start_matches("#/$defs/");
            action["$defs"][def]["properties"]["kind"]["const"].clone()
        })
        .collect();
    assert_eq!(
        kind_names, kind_branches,
        "action kind enum and oneOf branches disagree"
    );
}

/// A mutation that must be rejected by the schema *and* by serde, so the two
/// never disagree about what is well-formed.
struct Rejected {
    fixture: &'static str,
    why: &'static str,
    mutate: fn(&mut Value),
}

#[test]
fn schema_and_serde_reject_the_same_malformed_messages() {
    let cases: Vec<Rejected> = vec![
        Rejected {
            fixture: "action_shell_ls.json",
            why: "unknown top-level field",
            mutate: |v| v["extra"] = json!(1),
        },
        Rejected {
            fixture: "action_shell_ls.json",
            why: "unknown action kind",
            mutate: |v| v["kind"] = json!("teleport"),
        },
        Rejected {
            fixture: "action_shell_ls.json",
            why: "CamelCase kind",
            mutate: |v| v["kind"] = json!("Shell"),
        },
        Rejected {
            fixture: "action_shell_ls.json",
            why: "missing context",
            mutate: |v| {
                v.as_object_mut().unwrap().remove("context");
            },
        },
        Rejected {
            fixture: "action_shell_ls.json",
            why: "unknown agent",
            mutate: |v| v["context"]["agent"] = json!("copilot"),
        },
        Rejected {
            fixture: "action_shell_ls.json",
            why: "autonomous must be a bool",
            mutate: |v| v["context"]["autonomous"] = json!("no"),
        },
        Rejected {
            fixture: "action_shell_ls.json",
            why: "unknown argv node",
            mutate: |v| v["argv_tree"] = json!({ "node": "loop", "body": [] }),
        },
        Rejected {
            fixture: "action_shell_ls.json",
            why: "unknown field inside argv node",
            mutate: |v| v["argv_tree"]["shell"] = json!("bash"),
        },
        Rejected {
            fixture: "action_shell_ls.json",
            why: "env must be a list of strings",
            mutate: |v| v["argv_tree"]["env"] = json!({}),
        },
        Rejected {
            fixture: "action_shell_ls.json",
            why: "wrappers must be a list of strings",
            mutate: |v| v["argv_tree"]["wrappers"] = json!("sudo"),
        },
        Rejected {
            fixture: "action_shell_ls.json",
            why: "unknown obfuscation flag",
            mutate: |v| v["obfuscation"] = json!(["rot13"]),
        },
        Rejected {
            fixture: "action_shell_reverse_shell.json",
            why: "heredoc body must be a string",
            mutate: |v| v["argv_tree"]["redirects"][0]["body"] = json!(1),
        },
        Rejected {
            fixture: "action_shell_rm_rf_home.json",
            why: "unknown list operator",
            mutate: |v| v["argv_tree"]["op"] = json!("pipe"),
        },
        Rejected {
            fixture: "action_shell_reverse_shell.json",
            why: "unknown redirect operator",
            mutate: |v| v["argv_tree"]["redirects"][0]["op"] = json!("tee"),
        },
        Rejected {
            fixture: "action_file_read_env.json",
            why: "path must be a string",
            mutate: |v| v["path"] = json!(["/etc/passwd"]),
        },
        Rejected {
            fixture: "action_file_read_env.json",
            why: "fields from another kind are rejected",
            mutate: |v| v["raw"] = json!("cat .env"),
        },
        Rejected {
            fixture: "action_network_upload_file.json",
            why: "unknown body source type",
            mutate: |v| v["body_source"] = json!({ "type": "memory" }),
        },
        Rejected {
            fixture: "action_network_upload_file.json",
            why: "file body source needs a path",
            mutate: |v| v["body_source"] = json!({ "type": "file" }),
        },
        Rejected {
            fixture: "action_mcp_read_file_secret.json",
            why: "mcp tool call needs args_json",
            mutate: |v| {
                v.as_object_mut().unwrap().remove("args_json");
            },
        },
        Rejected {
            fixture: "decision_deny_ssh_private_key.json",
            why: "unknown outcome",
            mutate: |v| v["outcome"] = json!("block"),
        },
        Rejected {
            fixture: "decision_deny_ssh_private_key.json",
            why: "unknown severity",
            mutate: |v| v["severity"] = json!("fatal"),
        },
        Rejected {
            fixture: "decision_deny_ssh_private_key.json",
            why: "risk score above 1",
            mutate: |v| v["risk_score"] = json!(1.5),
        },
        Rejected {
            fixture: "decision_deny_ssh_private_key.json",
            why: "negative risk score",
            mutate: |v| v["risk_score"] = json!(-0.1),
        },
        Rejected {
            fixture: "decision_deny_ssh_private_key.json",
            why: "risk score as string",
            mutate: |v| v["risk_score"] = json!("0.9"),
        },
        Rejected {
            fixture: "decision_deny_ssh_private_key.json",
            why: "unknown decision field",
            mutate: |v| v["verdict"] = json!("deny"),
        },
        Rejected {
            fixture: "decision_allow_unmatched.json",
            why: "missing reason_agent",
            mutate: |v| {
                v.as_object_mut().unwrap().remove("reason_agent");
            },
        },
        Rejected {
            fixture: "approval_request_dotenv.json",
            why: "unknown request field",
            mutate: |v| v["decision"] = json!("ask"),
        },
        Rejected {
            fixture: "approval_request_dotenv.json",
            why: "risk above 1",
            mutate: |v| v["risk"] = json!(2),
        },
        Rejected {
            fixture: "approval_request_dotenv.json",
            why: "missing agent context",
            mutate: |v| {
                v.as_object_mut().unwrap().remove("agent");
            },
        },
        Rejected {
            fixture: "approval_response_deny_timeout.json",
            why: "unknown verdict",
            mutate: |v| v["verdict"] = json!("allow"),
        },
        Rejected {
            fixture: "approval_response_deny_timeout.json",
            why: "CamelCase verdict",
            mutate: |v| v["verdict"] = json!("AllowOnce"),
        },
        Rejected {
            fixture: "approval_response_deny_timeout.json",
            why: "missing by",
            mutate: |v| {
                v.as_object_mut().unwrap().remove("by");
            },
        },
    ];

    let all = fixtures();
    for case in cases {
        let (_, original) = all
            .iter()
            .find(|(n, _)| n == case.fixture)
            .unwrap_or_else(|| panic!("fixture {} missing", case.fixture));
        let mut value = original.clone();
        (case.mutate)(&mut value);
        assert_ne!(
            &value, original,
            "{}: mutation '{}' changed nothing",
            case.fixture, case.why
        );

        let kind = Kind::of(case.fixture);
        let schema_ok = validator(kind.schema_name()).is_valid(&value);
        let serde_ok = match kind {
            Kind::Action => serde_json::from_value::<Action>(value.clone()).is_ok(),
            Kind::Decision => serde_json::from_value::<Decision>(value.clone()).is_ok(),
            Kind::ApprovalRequest => {
                serde_json::from_value::<ApprovalRequest>(value.clone()).is_ok()
            }
            Kind::ApprovalResponse => {
                serde_json::from_value::<ApprovalResponse>(value.clone()).is_ok()
            }
        };
        assert!(
            !schema_ok,
            "{}: schema accepted '{}'",
            case.fixture, case.why
        );
        assert!(!serde_ok, "{}: serde accepted '{}'", case.fixture, case.why);
    }
}

#[test]
fn schema_requires_url_or_host_for_network() {
    // serde cannot express "at least one of url/host"; the schema does, and
    // this test keeps that rule in place.
    let v = validator("action");
    let mut value = fixtures()
        .into_iter()
        .find(|(n, _)| n == "action_network_ssh_host.json")
        .unwrap()
        .1;
    assert!(v.is_valid(&value));
    value.as_object_mut().unwrap().remove("host");
    assert!(
        !v.is_valid(&value),
        "network action with neither url nor host must be invalid"
    );
}
