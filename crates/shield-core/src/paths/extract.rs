use crate::shell::{CommandTree, RedirectKind, SimpleCommand};

/// How a command uses a path.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum PathAccess {
    Read,
    Write,
    Delete,
    Copy,
    Send,
    Exec,
}

/// Where the path was found.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum PathSource {
    Argument,
    Redirect,
}

/// A path-bearing command argument or redirect.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ExtractedPath {
    pub path: String,
    pub access: PathAccess,
    pub source: PathSource,
    pub program: Option<String>,
}

impl ExtractedPath {
    fn argument(command: &SimpleCommand, path: &str, access: PathAccess) -> Option<Self> {
        is_local_file(path).then(|| Self {
            path: path.to_string(),
            access,
            source: PathSource::Argument,
            program: Some(command.program.text.clone()),
        })
    }
}

/// Extract path arguments from all simple commands and redirect targets in a
/// parsed M4 [`CommandTree`].
pub fn extract_paths(tree: &CommandTree) -> Vec<ExtractedPath> {
    let mut paths = Vec::new();
    for command in tree.simple_commands() {
        extract_command(command, &mut paths);
    }
    for redirect in tree.redirects() {
        let accesses: &[PathAccess] = match redirect.kind {
            RedirectKind::Read => &[PathAccess::Read],
            RedirectKind::Write
            | RedirectKind::Append
            | RedirectKind::BothWrite
            | RedirectKind::BothAppend => &[PathAccess::Write],
            RedirectKind::ReadWrite => &[PathAccess::Read, PathAccess::Write],
            RedirectKind::Dup | RedirectKind::HereDoc | RedirectKind::HereString => &[],
        };
        for access in accesses {
            if is_local_file(&redirect.target.text) {
                paths.push(ExtractedPath {
                    path: redirect.target.text.clone(),
                    access: *access,
                    source: PathSource::Redirect,
                    program: None,
                });
            }
        }
    }
    paths
}

fn extract_command(command: &SimpleCommand, out: &mut Vec<ExtractedPath>) {
    if command.program.raw.contains('/') {
        push_one(command, &command.program.raw, PathAccess::Exec, out);
    }
    match command.program.text.as_str() {
        "cat" | "less" | "ls" | "find" | "stat" | "tree" => {
            push_all(
                command,
                simple_positionals(command, &[]),
                PathAccess::Read,
                out,
            );
        }
        "head" | "tail" => {
            push_all(
                command,
                simple_positionals(command, &["-n", "--lines", "-c", "--bytes"]),
                PathAccess::Read,
                out,
            );
        }
        "cp" | "mv" => extract_copy(command, out),
        "ln" => extract_copy(command, out),
        "rm" | "rmdir" | "unlink" => {
            push_all(
                command,
                simple_positionals(command, &[]),
                PathAccess::Delete,
                out,
            );
        }
        "tar" => extract_tar(command, out),
        "zip" => extract_zip(command, out),
        "base64" => {
            push_all(
                command,
                simple_positionals(command, &["-w", "--wrap"]),
                PathAccess::Read,
                out,
            );
        }
        "xxd" => extract_xxd(command, out),
        "scp" => extract_remote_copy(command, true, out),
        "rsync" => extract_remote_copy(command, true, out),
        "curl" => extract_curl(command, out),
        _ => {}
    }
}

fn extract_copy(command: &SimpleCommand, out: &mut Vec<ExtractedPath>) {
    let positional = simple_positionals(
        command,
        &["-t", "--target-directory", "-S", "--suffix", "--backup"],
    );
    let Some((destination, sources)) = positional.split_last() else {
        return;
    };
    push_all(command, sources.iter().copied(), PathAccess::Copy, out);
    push_one(command, destination, PathAccess::Write, out);
}

fn extract_tar(command: &SimpleCommand, out: &mut Vec<ExtractedPath>) {
    let args = command.arg_texts();
    let mut create = false;
    let mut archive = None;
    let mut positional = Vec::new();
    let mut index = 0;
    let mut options = true;

    while index < args.len() {
        let arg = args[index];
        if options && arg == "--" {
            options = false;
        } else if options && (arg == "-f" || arg == "--file") {
            index += 1;
            archive = args.get(index).copied();
        } else if options && arg.starts_with("--file=") {
            archive = arg.split_once('=').map(|(_, value)| value);
        } else if options && (arg == "-C" || arg == "--directory") {
            index += 1;
            if let Some(directory) = args.get(index) {
                push_one(command, directory, PathAccess::Read, out);
            }
        } else if options && arg.starts_with('-') {
            let flags = arg.trim_start_matches('-');
            create |= flags.chars().any(|flag| matches!(flag, 'c' | 'r' | 'u'));
            if let Some(offset) = flags.find('f') {
                let attached = &flags[offset + 1..];
                if !attached.is_empty() {
                    archive = Some(attached);
                } else {
                    index += 1;
                    archive = args.get(index).copied();
                }
            }
        } else if options && index == 0 && arg.chars().all(|flag| flag.is_ascii_alphabetic()) {
            create |= arg.chars().any(|flag| matches!(flag, 'c' | 'r' | 'u'));
            if arg.contains('f') {
                index += 1;
                archive = args.get(index).copied();
            }
        } else {
            positional.push(arg);
        }
        index += 1;
    }

    if let Some(archive) = archive {
        push_one(
            command,
            archive,
            if create {
                PathAccess::Write
            } else {
                PathAccess::Read
            },
            out,
        );
    }
    if create {
        push_all(command, positional, PathAccess::Read, out);
    }
}

fn extract_zip(command: &SimpleCommand, out: &mut Vec<ExtractedPath>) {
    let positional = simple_positionals(
        command,
        &[
            "-b",
            "--temp-path",
            "-n",
            "--suffixes",
            "-t",
            "--before-date",
        ],
    );
    let Some((archive, inputs)) = positional.split_first() else {
        return;
    };
    push_one(command, archive, PathAccess::Write, out);
    push_all(command, inputs.iter().copied(), PathAccess::Read, out);
}

fn extract_xxd(command: &SimpleCommand, out: &mut Vec<ExtractedPath>) {
    let positional = simple_positionals(
        command,
        &["-c", "-g", "-l", "-o", "-s", "--cols", "--groupsize"],
    );
    if let Some(input) = positional.first() {
        push_one(command, input, PathAccess::Read, out);
    }
    if let Some(output) = positional.get(1) {
        push_one(command, output, PathAccess::Write, out);
    }
}

fn extract_remote_copy(
    command: &SimpleCommand,
    send_to_remote: bool,
    out: &mut Vec<ExtractedPath>,
) {
    let positional = simple_positionals(
        command,
        &[
            "-B",
            "--block-size",
            "-e",
            "--rsh",
            "-i",
            "--identity-file",
            "-o",
            "--option",
            "-P",
            "--port",
            "-S",
            "--rsync-path",
        ],
    );
    let Some((destination, sources)) = positional.split_last() else {
        return;
    };
    let destination_is_remote = is_remote(destination);
    for source in sources {
        if !is_remote(source) {
            push_one(
                command,
                source,
                if destination_is_remote && send_to_remote {
                    PathAccess::Send
                } else {
                    PathAccess::Copy
                },
                out,
            );
        }
    }
    if !destination_is_remote {
        push_one(command, destination, PathAccess::Write, out);
    }
}

fn extract_curl(command: &SimpleCommand, out: &mut Vec<ExtractedPath>) {
    let args = command.arg_texts();
    let mut index = 0;
    while index < args.len() {
        let arg = args[index];
        let value = if matches!(
            arg,
            "-F" | "--form"
                | "-T"
                | "--upload-file"
                | "--data-binary"
                | "--data"
                | "-d"
                | "--config"
                | "-K"
        ) {
            index += 1;
            args.get(index).copied()
        } else {
            None
        };

        if matches!(arg, "-T" | "--upload-file") {
            if let Some(path) = value {
                push_one(command, path, PathAccess::Send, out);
            }
        } else if matches!(arg, "-F" | "--form") {
            if let Some(path) = value.and_then(form_file) {
                push_one(command, path, PathAccess::Send, out);
            }
        } else if matches!(arg, "--data-binary" | "--data" | "-d") {
            if let Some(path) = value.and_then(at_file) {
                push_one(command, path, PathAccess::Send, out);
            }
        } else if matches!(arg, "--config" | "-K") {
            if let Some(path) = value {
                push_one(command, path, PathAccess::Read, out);
            }
        } else if let Some(path) = arg
            .strip_prefix("--upload-file=")
            .or_else(|| arg.strip_prefix("-T"))
            .filter(|path| !path.is_empty())
        {
            push_one(command, path, PathAccess::Send, out);
        } else if let Some(value) = arg
            .strip_prefix("--form=")
            .or_else(|| arg.strip_prefix("-F"))
            .filter(|value| !value.is_empty())
        {
            if let Some(path) = form_file(value) {
                push_one(command, path, PathAccess::Send, out);
            }
        } else if let Some(path) = at_file(arg) {
            push_one(command, path, PathAccess::Send, out);
        }
        index += 1;
    }
}

fn simple_positionals<'a>(command: &'a SimpleCommand, takes_value: &[&str]) -> Vec<&'a str> {
    let args = command.arg_texts();
    let mut positional = Vec::new();
    let mut index = 0;
    let mut options = true;
    while index < args.len() {
        let arg = args[index];
        if options && arg == "--" {
            options = false;
        } else if options && takes_value.contains(&arg) {
            index += 1;
        } else if options
            && takes_value
                .iter()
                .any(|option| arg.starts_with(&format!("{option}=")))
        {
        } else if !options || arg == "-" || !arg.starts_with('-') {
            positional.push(arg);
        }
        index += 1;
    }
    positional
}

fn form_file(value: &str) -> Option<&str> {
    let (_, file) = value.split_once("=@")?;
    let file = file.split(';').next().unwrap_or(file);
    is_local_file(file).then_some(file)
}

fn at_file(value: &str) -> Option<&str> {
    value.strip_prefix('@').filter(|path| is_local_file(path))
}

fn is_remote(value: &str) -> bool {
    value.starts_with("scp://")
        || value.starts_with("rsync://")
        || value
            .split_once(':')
            .is_some_and(|(host, path)| !host.contains('/') && !host.is_empty() && !path.is_empty())
}

fn is_local_file(value: &str) -> bool {
    !value.is_empty() && value != "-" && !is_remote(value) && !value.contains("://")
}

fn push_one(command: &SimpleCommand, path: &str, access: PathAccess, out: &mut Vec<ExtractedPath>) {
    if let Some(path) = ExtractedPath::argument(command, path, access) {
        out.push(path);
    }
}

fn push_all<'a>(
    command: &SimpleCommand,
    paths: impl IntoIterator<Item = &'a str>,
    access: PathAccess,
    out: &mut Vec<ExtractedPath>,
) {
    for path in paths {
        push_one(command, path, access, out);
    }
}
