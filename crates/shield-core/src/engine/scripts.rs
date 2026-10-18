//! Interpreter script-file scanning (amendment 002 item 1).
//!
//! When an agent runs `bash|sh|zsh`, `python`, `node`, `ruby`, `perl`, or
//! `deno` **on a file** (or an inline `-c`/`-e` body), Agent Shield reads that
//! source and evaluates it against the same path, secret and shell policy
//! before Allow. Unreadable or oversized files are **Ask**, never Allow.
//!
//! Missing files are not treated as unreadable: a corpus command such as
//! `python scripts/generate_schema.py` must stay Allow when the file is not
//! there. Write-then-exec in the **same** command line is recovered from
//! heredocs and `echo`/`printf` redirects.

use std::collections::{HashMap, HashSet};
use std::fs;
use std::io;
use std::path::{Path, PathBuf};

use crate::model::{Action, ActionKind, AgentContext, ArgvTree};
use crate::paths::PathContext;
use crate::shell::{self, CommandTree, RedirectKind, SimpleCommand, Word};

/// Files larger than this are Ask (documented in `docs/POLICY.md`).
pub const MAX_SCRIPT_BYTES: u64 = 256 * 1024;

/// Bound on interpreter → script → interpreter nesting.
pub const MAX_SCAN_DEPTH: usize = 4;

/// Why a script could not be evaluated as Allow.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum ScanError {
    Unreadable,
    Oversized { size: u64 },
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum Family {
    Shell,
    Python,
    Node,
    Deno,
    Ruby,
    Perl,
}

enum SourceKind {
    Inline(String),
    File(String),
}

struct Source {
    family: Family,
    kind: SourceKind,
}

/// Extra actions derived from interpreter script bodies. `Err` is fail-closed
/// Ask (unreadable or oversized). Missing files yield no extra actions.
pub fn derived_actions(
    action: &Action,
    context: &AgentContext,
    path_context: &PathContext,
    visited: &mut HashSet<PathBuf>,
) -> Result<Vec<Action>, ScanError> {
    let ActionKind::Shell { raw, cwd, .. } = &action.kind else {
        return Ok(Vec::new());
    };
    let Ok(tree) = shell::parse(raw) else {
        return Ok(Vec::new());
    };
    let writes = collect_pending_writes(&tree);
    let cwd = if cwd.as_os_str().is_empty() {
        &context.cwd
    } else {
        cwd
    };
    let mut extras = Vec::new();
    for command in tree.simple_commands() {
        let Some(source) = source_from_command(command) else {
            continue;
        };
        let Some(body) = load_source(&source, cwd, path_context, &writes, visited)? else {
            continue;
        };
        extras.extend(expand_body(source.family, &body, action, cwd));
    }
    Ok(extras)
}

/// Combine two decisions, keeping every matched rule id.
pub fn combine_keep_ids(
    a: crate::model::Decision,
    b: crate::model::Decision,
) -> crate::model::Decision {
    let mut ids = a.matched_rule_ids.clone();
    for id in &b.matched_rule_ids {
        if !ids.iter().any(|existing| existing == id) {
            ids.push(id.clone());
        }
    }
    let mut winner = crate::model::combine(a, b);
    winner.matched_rule_ids = ids;
    winner
}

fn load_source(
    source: &Source,
    cwd: &Path,
    path_context: &PathContext,
    writes: &HashMap<String, String>,
    visited: &mut HashSet<PathBuf>,
) -> Result<Option<String>, ScanError> {
    match &source.kind {
        SourceKind::Inline(text) => {
            if text.len() as u64 > MAX_SCRIPT_BYTES {
                return Err(ScanError::Oversized {
                    size: text.len() as u64,
                });
            }
            Ok(Some(text.clone()))
        }
        SourceKind::File(raw_path) => {
            if let Some(body) = writes.get(raw_path) {
                if body.len() as u64 > MAX_SCRIPT_BYTES {
                    return Err(ScanError::Oversized {
                        size: body.len() as u64,
                    });
                }
                return Ok(Some(body.clone()));
            }
            let path = resolve_path(raw_path, cwd, path_context);
            if !visited.insert(path.clone()) {
                return Ok(None);
            }
            try_read_file(&path)
        }
    }
}

fn try_read_file(path: &Path) -> Result<Option<String>, ScanError> {
    match fs::metadata(path) {
        Err(error) if error.kind() == io::ErrorKind::NotFound => Ok(None),
        Err(_) => Err(ScanError::Unreadable),
        Ok(metadata) if metadata.is_dir() => Err(ScanError::Unreadable),
        Ok(metadata) if metadata.len() > MAX_SCRIPT_BYTES => Err(ScanError::Oversized {
            size: metadata.len(),
        }),
        Ok(_) => match fs::read(path) {
            Err(error) if error.kind() == io::ErrorKind::NotFound => Ok(None),
            Err(_) => Err(ScanError::Unreadable),
            Ok(bytes) if bytes.len() as u64 > MAX_SCRIPT_BYTES => Err(ScanError::Oversized {
                size: bytes.len() as u64,
            }),
            Ok(bytes) => match String::from_utf8(bytes) {
                Ok(text) => Ok(Some(text)),
                Err(_) => Err(ScanError::Unreadable),
            },
        },
    }
}

fn resolve_path(raw: &str, cwd: &Path, path_context: &PathContext) -> PathBuf {
    path_context.normalize(raw).unwrap_or_else(|_| {
        let path = Path::new(raw);
        if path.is_absolute() {
            path.to_path_buf()
        } else {
            cwd.join(path)
        }
    })
}

fn expand_body(family: Family, body: &str, original: &Action, cwd: &Path) -> Vec<Action> {
    match family {
        Family::Shell => vec![shell_action(body, original, cwd)],
        Family::Python | Family::Node | Family::Deno | Family::Ruby | Family::Perl => {
            let mut extras = path_read_actions(body, original);
            extras.extend(network_actions(body, original));
            for snippet in inner_shell_snippets(family, body) {
                extras.push(shell_action(&snippet, original, cwd));
            }
            extras
        }
    }
}

fn shell_action(raw: &str, original: &Action, cwd: &Path) -> Action {
    let (argv_tree, obfuscation) = match shell::parse(raw) {
        Ok(tree) => (tree.to_argv_tree(), tree.obfuscation.to_vec()),
        Err(_) => (
            ArgvTree::Unparsed {
                raw: raw.to_string(),
            },
            Vec::new(),
        ),
    };
    Action::new(
        original.context.clone(),
        ActionKind::Shell {
            argv_tree,
            raw: raw.to_string(),
            cwd: cwd.to_path_buf(),
            obfuscation,
        },
    )
}

fn path_read_actions(body: &str, original: &Action) -> Vec<Action> {
    let mut seen = HashSet::new();
    let mut extras = Vec::new();
    for path in extract_paths(body) {
        if !seen.insert(path.clone()) {
            continue;
        }
        extras.push(Action::new(
            original.context.clone(),
            ActionKind::FileRead {
                path: PathBuf::from(path),
            },
        ));
    }
    extras
}

fn network_actions(body: &str, original: &Action) -> Vec<Action> {
    if !has_network_call(body) {
        return Vec::new();
    }
    let urls = extract_urls(body);
    if urls.is_empty() {
        return vec![Action::new(
            original.context.clone(),
            ActionKind::Network {
                url: None,
                host: Some("script-network".to_string()),
                method: Some("CONNECT".to_string()),
                body_source: None,
            },
        )];
    }
    urls.into_iter()
        .map(|url| {
            let host = url_host(&url);
            Action::new(
                original.context.clone(),
                ActionKind::Network {
                    url: Some(url),
                    host,
                    method: Some("GET".to_string()),
                    body_source: None,
                },
            )
        })
        .collect()
}

fn family_of(program: &str) -> Option<Family> {
    match program {
        "sh" | "bash" | "zsh" | "dash" | "ksh" | "ash" | "mksh" | "." | "source" => {
            Some(Family::Shell)
        }
        "python" | "python2" | "python3" => Some(Family::Python),
        "node" | "nodejs" => Some(Family::Node),
        "deno" => Some(Family::Deno),
        "ruby" => Some(Family::Ruby),
        "perl" => Some(Family::Perl),
        _ => None,
    }
}

fn source_from_command(command: &SimpleCommand) -> Option<Source> {
    let program = command.program.text.as_str();
    if program == "." || program == "source" {
        let file = command.args.first()?.text.as_str();
        if file.starts_with('-') && file != "-" {
            return None;
        }
        return Some(file_or_stdin(Family::Shell, file, command));
    }
    let family = family_of(program)?;
    match family {
        Family::Shell => shell_source(command),
        Family::Python => python_source(command),
        Family::Node => node_source(command),
        Family::Deno => deno_source(command),
        Family::Ruby => ruby_source(command),
        Family::Perl => perl_source(command),
    }
}

fn file_or_stdin(family: Family, file: &str, command: &SimpleCommand) -> Source {
    if file == "-" {
        if let Some(body) = heredoc_body(command) {
            return Source {
                family,
                kind: SourceKind::Inline(body),
            };
        }
    }
    Source {
        family,
        kind: SourceKind::File(file.to_string()),
    }
}

fn heredoc_body(command: &SimpleCommand) -> Option<String> {
    command.redirects.iter().find_map(|redirect| {
        (redirect.kind == RedirectKind::HereDoc)
            .then(|| redirect.body.clone())
            .flatten()
    })
}

fn stdin_file(command: &SimpleCommand) -> Option<String> {
    command.redirects.iter().find_map(|redirect| {
        (redirect.kind == RedirectKind::Read).then(|| redirect.target.text.clone())
    })
}

fn shell_source(command: &SimpleCommand) -> Option<Source> {
    if command.flags().iter().any(|flag| flag == "-c") {
        return None;
    }
    if let Some(file) = first_positional(&command.args, &[]) {
        return Some(file_or_stdin(Family::Shell, file, command));
    }
    if let Some(body) = heredoc_body(command) {
        return Some(Source {
            family: Family::Shell,
            kind: SourceKind::Inline(body),
        });
    }
    stdin_file(command).map(|file| Source {
        family: Family::Shell,
        kind: SourceKind::File(file),
    })
}

fn python_source(command: &SimpleCommand) -> Option<Source> {
    if let Some(inline) = take_option_value(&command.args, &["-c"]) {
        return Some(Source {
            family: Family::Python,
            kind: SourceKind::Inline(inline),
        });
    }
    if has_module_flag(&command.args) {
        return None;
    }
    first_positional(
        &command.args,
        &["-W", "-X", "--check-hash-based-pycs", "-Q"],
    )
    .map(|file| file_or_stdin(Family::Python, file, command))
    .or_else(|| {
        heredoc_body(command).map(|body| Source {
            family: Family::Python,
            kind: SourceKind::Inline(body),
        })
    })
}

fn node_source(command: &SimpleCommand) -> Option<Source> {
    if let Some(inline) = take_option_value(&command.args, &["-e", "--eval", "-p", "--print"]) {
        return Some(Source {
            family: Family::Node,
            kind: SourceKind::Inline(inline),
        });
    }
    first_positional(
        &command.args,
        &[
            "-r",
            "--require",
            "--title",
            "--eval",
            "-e",
            "-p",
            "--print",
        ],
    )
    .map(|file| file_or_stdin(Family::Node, file, command))
    .or_else(|| {
        heredoc_body(command).map(|body| Source {
            family: Family::Node,
            kind: SourceKind::Inline(body),
        })
    })
}

fn deno_source(command: &SimpleCommand) -> Option<Source> {
    let args: Vec<&str> = command.arg_texts();
    let sub = args.first().copied().unwrap_or("");
    if matches!(sub, "eval" | "repl") {
        let code = args.get(1).copied().unwrap_or("");
        if !code.is_empty() && !code.starts_with('-') {
            return Some(Source {
                family: Family::Deno,
                kind: SourceKind::Inline(code.to_string()),
            });
        }
        return heredoc_body(command).map(|body| Source {
            family: Family::Deno,
            kind: SourceKind::Inline(body),
        });
    }
    let rest = if matches!(
        sub,
        "run" | "check" | "compile" | "bundle" | "test" | "task"
    ) {
        &command.args[1..]
    } else {
        command.args.as_slice()
    };
    first_positional(rest, &[]).map(|file| file_or_stdin(Family::Deno, file, command))
}

fn ruby_source(command: &SimpleCommand) -> Option<Source> {
    if let Some(inline) = take_option_value(&command.args, &["-e"]) {
        return Some(Source {
            family: Family::Ruby,
            kind: SourceKind::Inline(inline),
        });
    }
    first_positional(
        &command.args,
        &["-r", "-I", "-C", "-E", "-F", "-i", "-W", "-x", "-e"],
    )
    .map(|file| file_or_stdin(Family::Ruby, file, command))
    .or_else(|| {
        heredoc_body(command).map(|body| Source {
            family: Family::Ruby,
            kind: SourceKind::Inline(body),
        })
    })
}

fn perl_source(command: &SimpleCommand) -> Option<Source> {
    if let Some(inline) = take_option_value(&command.args, &["-e", "-E"]) {
        return Some(Source {
            family: Family::Perl,
            kind: SourceKind::Inline(inline),
        });
    }
    first_positional(&command.args, &["-I", "-e", "-E", "-M"])
        .map(|file| file_or_stdin(Family::Perl, file, command))
        .or_else(|| {
            heredoc_body(command).map(|body| Source {
                family: Family::Perl,
                kind: SourceKind::Inline(body),
            })
        })
}

fn first_positional<'a>(args: &'a [Word], with_value: &[&str]) -> Option<&'a str> {
    let mut skip_next = false;
    let mut options = true;
    for arg in args {
        let text = arg.text.as_str();
        if skip_next {
            skip_next = false;
            continue;
        }
        if options && text == "--" {
            options = false;
            continue;
        }
        if options && with_value.contains(&text) {
            skip_next = true;
            continue;
        }
        if options && text.starts_with("--") && text.contains('=') {
            continue;
        }
        if options && text.starts_with('-') && text != "-" {
            continue;
        }
        return Some(text);
    }
    None
}

fn take_option_value(args: &[Word], flags: &[&str]) -> Option<String> {
    let mut expect = false;
    for arg in args {
        let text = arg.text.as_str();
        if expect {
            return Some(text.to_string());
        }
        for flag in flags {
            if text == *flag {
                expect = true;
                break;
            }
            let prefix = format!("{flag}=");
            if let Some(rest) = text.strip_prefix(&prefix) {
                return Some(rest.to_string());
            }
            if flag.len() == 2
                && !flag.starts_with("--")
                && text.starts_with(flag)
                && text.len() > 2
            {
                return Some(text[flag.len()..].to_string());
            }
        }
    }
    None
}

fn has_module_flag(args: &[Word]) -> bool {
    for arg in args {
        let text = arg.text.as_str();
        if text == "--" {
            break;
        }
        if text == "-m" || (text.starts_with('-') && !text.starts_with("--") && text.contains('m'))
        {
            return true;
        }
    }
    false
}

fn collect_pending_writes(tree: &CommandTree) -> HashMap<String, String> {
    let mut writes = HashMap::new();
    for command in tree.simple_commands() {
        let heredoc = heredoc_body(command);
        let echo_body = matches!(command.program.text.as_str(), "echo" | "printf")
            .then(|| command.arg_texts().join(" "));
        for redirect in &command.redirects {
            if !matches!(
                redirect.kind,
                RedirectKind::Write
                    | RedirectKind::Append
                    | RedirectKind::BothWrite
                    | RedirectKind::BothAppend
            ) {
                continue;
            }
            let path = redirect.target.text.clone();
            if let Some(body) = heredoc.clone().or_else(|| echo_body.clone()) {
                writes.insert(path, body);
            }
        }
    }
    writes
}

fn extract_paths(body: &str) -> Vec<String> {
    let mut paths = Vec::new();
    for candidate in quoted_strings(body)
        .into_iter()
        .chain(bare_path_tokens(body))
    {
        if looks_like_path(&candidate) {
            paths.push(candidate);
        }
    }
    paths
}

fn quoted_strings(body: &str) -> Vec<String> {
    let mut out = Vec::new();
    let bytes = body.as_bytes();
    let mut i = 0;
    while i < bytes.len() {
        let quote = bytes[i];
        if quote == b'\'' || quote == b'"' {
            i += 1;
            let start = i;
            while i < bytes.len() && bytes[i] != quote {
                if bytes[i] == b'\\' && i + 1 < bytes.len() {
                    i += 2;
                    continue;
                }
                i += 1;
            }
            if i <= bytes.len() {
                let slice = &body[start..i.min(body.len())];
                if !slice.is_empty() && slice.len() < 512 {
                    out.push(slice.replace('\\', ""));
                }
            }
            i += 1;
            continue;
        }
        i += 1;
    }
    out
}

fn bare_path_tokens(body: &str) -> Vec<String> {
    let mut out = Vec::new();
    for raw in body.split_whitespace() {
        let token = raw.trim_matches(|c: char| {
            matches!(c, '(' | ')' | '{' | '}' | '[' | ']' | ',' | ';' | ':')
        });
        if looks_like_path(token) {
            out.push(token.to_string());
        }
    }
    out
}

fn looks_like_path(value: &str) -> bool {
    let text = value.trim();
    if text.len() < 3 || text.len() > 512 || text.contains('\n') {
        return false;
    }
    if text.starts_with("http://") || text.starts_with("https://") || text.starts_with("ftp://") {
        return false;
    }
    let lower = text.to_ascii_lowercase();
    let markers = [
        "~/",
        "$home/",
        "${home}/",
        "/home/",
        "/users/",
        "/etc/",
        ".ssh",
        ".aws",
        ".env",
        ".npmrc",
        ".pypirc",
        ".netrc",
        ".git-credentials",
        "id_rsa",
        "id_ed25519",
        "id_ecdsa",
        "kube/config",
        "docker/config",
        "launchagents",
        ".zshrc",
        ".bashrc",
        ".profile",
        "credentials",
    ];
    markers.iter().any(|marker| lower.contains(marker))
        && (text.contains('/')
            || text.contains('\\')
            || text.starts_with('.')
            || text.starts_with('~'))
}

fn extract_urls(body: &str) -> Vec<String> {
    let mut urls = Vec::new();
    let mut remaining = body;
    loop {
        let https = remaining.find("https://");
        let http = remaining.find("http://");
        let (index, scheme_len) = match (https, http) {
            (Some(a), Some(b)) if b < a => (b, 7),
            (Some(a), _) => (a, 8),
            (None, Some(b)) => (b, 7),
            (None, None) => break,
        };
        let after = &remaining[index + scheme_len..];
        let end = after
            .find(|c: char| {
                c.is_whitespace() || matches!(c, '"' | '\'' | ')' | ']' | '}' | '<' | '>' | ',')
            })
            .unwrap_or(after.len());
        let url = format!("{}{}", &remaining[index..index + scheme_len], &after[..end]);
        if url.len() > scheme_len + 3 {
            urls.push(url.trim_end_matches('.').to_string());
        }
        remaining = &remaining[index + scheme_len + end..];
    }
    urls
}

fn url_host(url: &str) -> Option<String> {
    let rest = url
        .strip_prefix("https://")
        .or_else(|| url.strip_prefix("http://"))?;
    let host = rest.split(['/', '?', '#']).next().unwrap_or(rest);
    let host = host.split('@').next_back().unwrap_or(host);
    let host = host.split(':').next().unwrap_or(host);
    (!host.is_empty()).then(|| host.to_string())
}

fn has_network_call(body: &str) -> bool {
    let lower = body.to_ascii_lowercase();
    const CALLS: &[&str] = &[
        "urlopen(",
        "requests.get(",
        "requests.post(",
        "requests.put(",
        "requests.request(",
        "httpx.",
        "aiohttp.",
        "socket.socket(",
        "socket.connect(",
        ".connect((",
        "fetch(",
        "axios.",
        "net.createserver",
        "net.connect",
        "http.request",
        "https.request",
        "websocket",
        "xmlhttprequest",
        "net::http",
        "tcpsocket",
        "udpsocket",
        "httparty",
        "lwp::",
        "io::socket",
        "http::tiny",
        "curl_easy",
        "urllib.request",
    ];
    CALLS.iter().any(|needle| lower.contains(needle))
}

fn inner_shell_snippets(family: Family, body: &str) -> Vec<String> {
    let needles: &[&str] = match family {
        Family::Python => &[
            "os.system(",
            "os.popen(",
            "subprocess.run(",
            "subprocess.call(",
            "subprocess.popen(",
            "commands.getoutput(",
        ],
        Family::Node | Family::Deno => &[
            "execsync(",
            "child_process.exec(",
            "child_process.execsync(",
            "deno.run(",
        ],
        Family::Ruby => &["system(", "%x(", "exec("],
        Family::Perl => &["system(", "exec(", "qx("],
        Family::Shell => &[],
    };
    let mut snippets = Vec::new();
    let lower = body.to_ascii_lowercase();
    for needle in needles {
        let mut from = 0;
        while let Some(index) = lower[from..].find(needle) {
            let abs = from + index + needle.len();
            if let Some(snippet) = first_quoted_from(body, abs) {
                snippets.push(snippet);
            }
            from = abs + 1;
        }
    }
    snippets
}

fn first_quoted_from(body: &str, start: usize) -> Option<String> {
    let bytes = body.as_bytes();
    let mut i = start;
    while i < bytes.len() && bytes[i].is_ascii_whitespace() {
        i += 1;
    }
    if i >= bytes.len() {
        return None;
    }
    let quote = bytes[i];
    if quote != b'\'' && quote != b'"' {
        return None;
    }
    i += 1;
    let begin = i;
    while i < bytes.len() && bytes[i] != quote {
        if bytes[i] == b'\\' && i + 1 < bytes.len() {
            i += 2;
            continue;
        }
        i += 1;
    }
    Some(body[begin..i.min(body.len())].to_string())
}
