//! Match policy conditions against one normalized action.

use std::fmt;

use globset::Glob;

use crate::model::{Action, ActionKind, AgentContext};
use crate::paths::{
    extract_paths, CompiledSensitiveCatalog, ExtractedPath, PathAccess, PathContext, PathMatcher,
};
use crate::policy::{Access, Dataflow, Match, McpMatch};
use crate::secrets;
use crate::shell::{self, CommandTree, Node, SimpleCommand};

/// Facts extracted once and shared by every rule evaluated for an action.
#[derive(Debug)]
pub struct ActionFacts<'a> {
    action: &'a Action,
    context: &'a AgentContext,
    shell: Option<CommandTree>,
    paths: Vec<ExtractedPath>,
    network_sink: bool,
    secret_content: bool,
}

/// A matcher failure that must not silently turn into an Allow.
#[derive(Debug)]
pub struct MatchError(String);

impl fmt::Display for MatchError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str(&self.0)
    }
}

impl std::error::Error for MatchError {}

impl<'a> ActionFacts<'a> {
    /// Parse and extract the reusable facts for one action.
    pub fn new(action: &'a Action, context: &'a AgentContext) -> Result<Self, MatchError> {
        let shell = match &action.kind {
            ActionKind::Shell { raw, .. } => Some(
                shell::parse(raw)
                    .map_err(|error| MatchError(format!("cannot parse shell action: {error}")))?,
            ),
            _ => None,
        };
        let mut paths = shell.as_ref().map(extract_paths).unwrap_or_default();
        append_direct_paths(&action.kind, &mut paths);
        append_mcp_paths(&action.kind, &mut paths);
        let network_sink = action_has_network_sink(&action.kind, shell.as_ref());
        let secret_content = action_has_secret_content(&action.kind);
        Ok(Self {
            action,
            context,
            shell,
            paths,
            network_sink,
            secret_content,
        })
    }
}

/// Validate every non-path glob before an engine accepts a policy.
pub fn validate_globs(matcher: &Match, path_context: &PathContext) -> Result<(), MatchError> {
    for pattern in matcher
        .program
        .iter()
        .flatten()
        .chain(matcher.args_any.iter().flatten())
        .chain(matcher.args_all.iter().flatten())
        .chain(matcher.raw_any.iter().flatten())
    {
        Glob::new(pattern)
            .map_err(|error| MatchError(format!("invalid matcher glob `{pattern}`: {error}")))?;
    }
    if let Some(mcp) = &matcher.mcp {
        for pattern in [&mcp.server, &mcp.tool].into_iter().flatten() {
            Glob::new(pattern).map_err(|error| {
                MatchError(format!("invalid matcher glob `{pattern}`: {error}"))
            })?;
        }
    }
    if let Some(paths) = &matcher.paths {
        PathMatcher::new(
            path_context,
            paths,
            matcher.except_paths.as_deref().unwrap_or(&[]),
            cfg!(target_os = "macos"),
        )
        .map_err(|error| MatchError(error.to_string()))?;
    }
    if let Some(stages) = &matcher.pipeline {
        for stage in stages {
            validate_globs(stage, path_context)?;
        }
    }
    if let Some(alternatives) = &matcher.any {
        for alternative in alternatives {
            validate_globs(alternative, path_context)?;
        }
    }
    Ok(())
}

/// Return whether all populated keys in `matcher` hold for `facts`.
pub fn matches_rule(
    matcher: &Match,
    facts: &ActionFacts<'_>,
    path_context: &PathContext,
    sensitive: &CompiledSensitiveCatalog,
) -> Result<bool, MatchError> {
    if let Some(alternatives) = &matcher.any {
        let mut matched = false;
        for alternative in alternatives {
            if matches_rule(alternative, facts, path_context, sensitive)? {
                matched = true;
                break;
            }
        }
        if !matched {
            return Ok(false);
        }
    }
    if matcher
        .agent
        .as_ref()
        .is_some_and(|agents| !agents.contains(&facts.context.agent))
    {
        return Ok(false);
    }
    if let Some(mcp) = &matcher.mcp {
        if !matches_mcp(mcp, matcher, facts, path_context)? {
            return Ok(false);
        }
    }
    if has_command_conditions(matcher)
        && !facts
            .shell
            .as_ref()
            .is_some_and(|tree| command_conditions_match(matcher, &tree.simple_commands()))
    {
        return Ok(false);
    }
    if matcher.raw_any.as_ref().is_some_and(|patterns| {
        !facts.shell.as_ref().is_some_and(|tree| {
            patterns
                .iter()
                .any(|pattern| glob_matches(pattern, &tree.raw))
        })
    }) {
        return Ok(false);
    }
    if matcher.paths.is_some() || matcher.access.is_some() || matcher.outside_workspace.is_some() {
        let candidates = path_candidates(matcher, facts);
        if !matches_paths(matcher, &candidates, path_context)?
            && !string_path_globs(matcher, &candidates)
        {
            return Ok(false);
        }
    }
    if let Some(expected) = matcher.network_sink {
        if facts.network_sink != expected {
            return Ok(false);
        }
    }
    if let Some(expected) = matcher.secret_content {
        if facts.secret_content != expected {
            return Ok(false);
        }
    }
    if let Some(stages) = &matcher.pipeline {
        let Some(tree) = &facts.shell else {
            return Ok(false);
        };
        if !pipeline_matches(&tree.root, stages) {
            return Ok(false);
        }
    }
    if let Some(flow) = &matcher.dataflow {
        let Some(tree) = &facts.shell else {
            return Ok(false);
        };
        if !node_has_dataflow(&tree.root, flow, &facts.paths, path_context, sensitive)? {
            return Ok(false);
        }
    }
    Ok(true)
}

fn has_command_conditions(matcher: &Match) -> bool {
    matcher.program.is_some()
        || matcher.args_any.is_some()
        || matcher.args_all.is_some()
        || matcher.flags.is_some()
}

fn command_conditions_match(matcher: &Match, commands: &[&SimpleCommand]) -> bool {
    commands
        .iter()
        .any(|command| command_matches(matcher, command))
}

fn command_matches(matcher: &Match, command: &SimpleCommand) -> bool {
    if matcher.program.as_ref().is_some_and(|patterns| {
        !patterns.iter().any(|pattern| {
            glob_matches(pattern, &command.program.text)
                || command
                    .wrappers
                    .iter()
                    .any(|wrapper| glob_matches(pattern, wrapper))
        })
    }) {
        return false;
    }
    if matcher.args_any.as_ref().is_some_and(|patterns| {
        !command.args.iter().any(|argument| {
            patterns
                .iter()
                .any(|pattern| glob_matches(pattern, &argument.text))
        })
    }) {
        return false;
    }
    if matcher.args_all.as_ref().is_some_and(|patterns| {
        !patterns.iter().all(|pattern| {
            command
                .args
                .iter()
                .any(|argument| glob_matches(pattern, &argument.text))
        })
    }) {
        return false;
    }
    if matcher.flags.as_ref().is_some_and(|required| {
        let present = command.flags();
        !required.iter().all(|flag| present.contains(flag))
    }) {
        return false;
    }
    true
}

fn pipeline_matches(node: &Node, expected: &[Match]) -> bool {
    let matches_here = if let Node::Pipeline { stages } = node {
        ordered_stages_match(stages, expected)
    } else {
        false
    };
    matches_here
        || match node {
            Node::Pipeline { stages } => {
                stages.iter().any(|stage| pipeline_matches(stage, expected))
            }
            Node::List { left, right, .. } => {
                pipeline_matches(left, expected) || pipeline_matches(right, expected)
            }
            Node::Subshell { body, .. } | Node::Group { body, .. } => {
                pipeline_matches(body, expected)
            }
            Node::Compound { parts, .. } => {
                parts.iter().any(|part| pipeline_matches(part, expected))
            }
            Node::Simple(command) => command
                .substitutions
                .iter()
                .any(|substitution| pipeline_matches(&substitution.body, expected)),
            Node::Assignment(_) | Node::Empty => false,
        }
}

fn ordered_stages_match(stages: &[Node], expected: &[Match]) -> bool {
    let mut wanted = expected.iter();
    let Some(mut current) = wanted.next() else {
        return false;
    };
    for stage in stages {
        let commands = stage.simple_commands();
        if commands
            .iter()
            .any(|command| command_matches(current, command))
        {
            if let Some(next) = wanted.next() {
                current = next;
            } else {
                return true;
            }
        }
    }
    false
}

fn matches_paths(
    matcher: &Match,
    candidates: &[ExtractedPath],
    context: &PathContext,
) -> Result<bool, MatchError> {
    let path_matcher = matcher
        .paths
        .as_ref()
        .map(|includes| {
            PathMatcher::new(
                context,
                includes,
                matcher.except_paths.as_deref().unwrap_or(&[]),
                cfg!(target_os = "macos"),
            )
            .map_err(|error| MatchError(error.to_string()))
        })
        .transpose()?;
    for candidate in candidates {
        if matcher.access.as_ref().is_some_and(|accesses| {
            !accesses
                .iter()
                .any(|access| access_matches(*access, candidate.access))
        }) {
            continue;
        }
        if let Some(path_matcher) = &path_matcher {
            if !path_matcher
                .is_match(context, &candidate.path)
                .map_err(|error| MatchError(error.to_string()))?
            {
                continue;
            }
        }
        if let Some(expected) = matcher.outside_workspace {
            let normalized = context
                .normalize(&candidate.path)
                .map_err(|error| MatchError(error.to_string()))?;
            if (!normalized.starts_with(context.cwd())) != expected {
                continue;
            }
        }
        return Ok(true);
    }
    Ok(false)
}

fn string_path_globs(matcher: &Match, candidates: &[ExtractedPath]) -> bool {
    let Some(includes) = matcher.paths.as_ref() else {
        return false;
    };
    candidates.iter().any(|candidate| {
        let raw = &candidate.path;
        let looks_like_url = raw.contains("://") || raw.starts_with("http");
        looks_like_url && includes.iter().any(|pattern| glob_matches(pattern, raw))
    })
}

fn path_candidates(matcher: &Match, facts: &ActionFacts<'_>) -> Vec<ExtractedPath> {
    let mut candidates = facts.paths.clone();
    if let (
        Some(mcp),
        ActionKind::McpToolCall {
            tool, args_json, ..
        },
    ) = (&matcher.mcp, &facts.action.kind)
    {
        if let Some(pointer) = &mcp.arg {
            if let Some(path) = args_json
                .pointer(pointer)
                .and_then(serde_json::Value::as_str)
            {
                candidates.push(ExtractedPath {
                    path: path.to_string(),
                    access: infer_mcp_access(tool),
                    source: crate::paths::PathSource::Argument,
                    program: None,
                });
            }
        }
    }
    candidates
}

fn access_matches(policy: Access, actual: PathAccess) -> bool {
    matches!(
        (policy, actual),
        (Access::Read, PathAccess::Read)
            | (Access::Write, PathAccess::Write)
            | (Access::Delete, PathAccess::Delete)
            | (Access::Copy, PathAccess::Copy)
            | (Access::Send, PathAccess::Send)
            | (Access::Exec, PathAccess::Exec)
    )
}

fn matches_mcp(
    matcher: &McpMatch,
    whole: &Match,
    facts: &ActionFacts<'_>,
    path_context: &PathContext,
) -> Result<bool, MatchError> {
    let ActionKind::McpToolCall {
        server,
        tool,
        args_json,
    } = &facts.action.kind
    else {
        return Ok(false);
    };
    if matcher
        .server
        .as_ref()
        .is_some_and(|pattern| !glob_matches(pattern, server))
        || matcher
            .tool
            .as_ref()
            .is_some_and(|pattern| !glob_matches(pattern, tool))
    {
        return Ok(false);
    }
    if let Some(pointer) = &matcher.arg {
        let Some(value) = args_json.pointer(pointer) else {
            return Ok(false);
        };
        if let Some(paths) = &whole.paths {
            let Some(path) = value.as_str() else {
                return Ok(false);
            };
            let path_matcher = PathMatcher::new(
                path_context,
                paths,
                whole.except_paths.as_deref().unwrap_or(&[]),
                cfg!(target_os = "macos"),
            )
            .map_err(|error| MatchError(error.to_string()))?;
            if !path_matcher
                .is_match(path_context, path)
                .map_err(|error| MatchError(error.to_string()))?
                && !paths.iter().any(|pattern| glob_matches(pattern, path))
            {
                return Ok(false);
            }
        }
    }
    Ok(true)
}

fn node_has_dataflow(
    node: &Node,
    flow: &Dataflow,
    paths: &[ExtractedPath],
    context: &PathContext,
    sensitive: &CompiledSensitiveCatalog,
) -> Result<bool, MatchError> {
    if matches!(node, Node::Pipeline { .. } | Node::List { .. }) {
        let commands = node.simple_commands();
        for (source_index, command) in commands.iter().enumerate() {
            if !command_is_source(command, &flow.source, paths, context, sensitive)? {
                continue;
            }
            if commands[source_index + 1..]
                .iter()
                .any(|later| command_is_sink(later, &flow.sink, paths))
            {
                return Ok(true);
            }
        }
    }
    match node {
        Node::Pipeline { stages } => {
            for stage in stages {
                if node_has_dataflow(stage, flow, paths, context, sensitive)? {
                    return Ok(true);
                }
            }
        }
        Node::List { left, right, .. } => {
            if node_has_dataflow(left, flow, paths, context, sensitive)?
                || node_has_dataflow(right, flow, paths, context, sensitive)?
            {
                return Ok(true);
            }
        }
        Node::Subshell { body, .. } | Node::Group { body, .. } => {
            if node_has_dataflow(body, flow, paths, context, sensitive)? {
                return Ok(true);
            }
        }
        Node::Compound { parts, .. } => {
            for part in parts {
                if node_has_dataflow(part, flow, paths, context, sensitive)? {
                    return Ok(true);
                }
            }
        }
        Node::Simple(command) => {
            if command_is_source(command, &flow.source, paths, context, sensitive)?
                && command_is_sink(command, &flow.sink, paths)
            {
                return Ok(true);
            }
            for substitution in &command.substitutions {
                if node_has_dataflow(&substitution.body, flow, paths, context, sensitive)? {
                    return Ok(true);
                }
            }
        }
        Node::Assignment(_) | Node::Empty => {}
    }
    Ok(false)
}

fn command_is_source(
    command: &SimpleCommand,
    source: &str,
    paths: &[ExtractedPath],
    context: &PathContext,
    sensitive: &CompiledSensitiveCatalog,
) -> Result<bool, MatchError> {
    match source {
        "secret_content" => Ok(!secrets::detect(&command.argv().join(" ")).is_empty()),
        "any_file" => Ok(command_paths(command, paths).any(is_source_access)),
        "secret_file" => {
            for path in command_paths(command, paths).filter(|path| is_source_access(path)) {
                if sensitive
                    .is_sensitive(context, &path.path)
                    .map_err(|error| MatchError(error.to_string()))?
                {
                    return Ok(true);
                }
            }
            Ok(false)
        }
        _ => Ok(false),
    }
}

fn command_is_sink(command: &SimpleCommand, sink: &str, paths: &[ExtractedPath]) -> bool {
    match sink {
        "network" => command_is_network_sink(command),
        "shell" => is_shell_program(&command.program.text),
        "disk" => command_paths(command, paths)
            .any(|path| matches!(path.access, PathAccess::Write | PathAccess::Delete)),
        _ => false,
    }
}

fn command_paths<'a>(
    command: &'a SimpleCommand,
    paths: &'a [ExtractedPath],
) -> impl Iterator<Item = &'a ExtractedPath> {
    paths
        .iter()
        .filter(move |path| path.program.as_deref() == Some(command.program.text.as_str()))
}

fn is_source_access(path: &ExtractedPath) -> bool {
    matches!(
        path.access,
        PathAccess::Read | PathAccess::Copy | PathAccess::Send
    )
}

fn append_direct_paths(kind: &ActionKind, paths: &mut Vec<ExtractedPath>) {
    let direct = match kind {
        ActionKind::FileRead { path } => Some((path, PathAccess::Read)),
        ActionKind::FileWrite { path } => Some((path, PathAccess::Write)),
        ActionKind::FileDelete { path } => Some((path, PathAccess::Delete)),
        ActionKind::Network {
            body_source: Some(crate::model::BodySource::File { path }),
            ..
        } => Some((path, PathAccess::Send)),
        _ => None,
    };
    if let Some((path, access)) = direct {
        paths.push(ExtractedPath {
            path: path.to_string_lossy().into_owned(),
            access,
            source: crate::paths::PathSource::Argument,
            program: None,
        });
    }
}

fn append_mcp_paths(kind: &ActionKind, paths: &mut Vec<ExtractedPath>) {
    let ActionKind::McpToolCall {
        tool, args_json, ..
    } = kind
    else {
        return;
    };
    let access = infer_mcp_access(tool);
    for key in ["path", "file_path", "uri", "url", "target", "src", "dest"] {
        if let Some(value) = args_json.get(key).and_then(serde_json::Value::as_str) {
            if !value.is_empty() {
                paths.push(ExtractedPath {
                    path: value.to_string(),
                    access,
                    source: crate::paths::PathSource::Argument,
                    program: None,
                });
            }
        }
    }
}

fn action_has_network_sink(kind: &ActionKind, shell: Option<&CommandTree>) -> bool {
    match kind {
        ActionKind::Network { .. } => true,
        ActionKind::Shell { .. } => shell.is_some_and(|tree| {
            tree.simple_commands()
                .iter()
                .any(|command| command_is_network_sink(command))
                || tree.raw.contains("/dev/tcp/")
        }),
        ActionKind::McpToolCall { server, tool, .. } => {
            let name = format!("{server}/{tool}").to_ascii_lowercase();
            ["fetch", "http", "request", "download", "upload", "send"]
                .iter()
                .any(|needle| name.contains(needle))
        }
        _ => false,
    }
}

fn command_is_network_sink(command: &SimpleCommand) -> bool {
    matches!(
        command.program.text.as_str(),
        "curl"
            | "wget"
            | "fetch"
            | "nc"
            | "ncat"
            | "netcat"
            | "scp"
            | "rsync"
            | "ssh"
            | "sftp"
            | "ftp"
    )
}

fn action_has_secret_content(kind: &ActionKind) -> bool {
    match kind {
        ActionKind::Shell { raw, .. } => !secrets::detect(raw).is_empty(),
        ActionKind::Network {
            url,
            host,
            body_source,
            ..
        } => {
            url.iter()
                .chain(host.iter())
                .any(|value| !secrets::detect(value).is_empty())
                || body_source.as_ref().is_some_and(|source| match source {
                    crate::model::BodySource::Inline { text } => !secrets::detect(text).is_empty(),
                    _ => false,
                })
        }
        ActionKind::McpToolCall { args_json, .. } => {
            !secrets::detect(&args_json.to_string()).is_empty()
        }
        _ => false,
    }
}

fn infer_mcp_access(tool: &str) -> PathAccess {
    let tool = tool.to_ascii_lowercase();
    if tool.contains("delete") || tool.contains("remove") {
        PathAccess::Delete
    } else if tool.contains("write") || tool.contains("edit") || tool.contains("create") {
        PathAccess::Write
    } else if tool.contains("copy") {
        PathAccess::Copy
    } else if tool.contains("upload") || tool.contains("send") {
        PathAccess::Send
    } else if tool.contains("exec") || tool.contains("run") {
        PathAccess::Exec
    } else {
        PathAccess::Read
    }
}

fn is_shell_program(program: &str) -> bool {
    matches!(
        program,
        "sh" | "bash" | "zsh" | "dash" | "python" | "python3" | "perl" | "ruby" | "node"
    )
}

fn glob_matches(pattern: &str, value: &str) -> bool {
    Glob::new(pattern)
        .expect("matcher globs are validated when the engine is built")
        .compile_matcher()
        .is_match(value)
}
