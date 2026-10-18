//! Unwrapping of wrapper programs so the policy sees the command that really
//! runs: `sudo -E env X=1 rm -r /` is `rm -r /` with wrappers `sudo`, `env`.

use super::error::{ParseError, ParseErrorKind};
use super::lower::{Lower, LoweredWord};
use super::tree::{
    normalise_program, EnvAssign, Node, SimpleCommand, SubstKind, SubstOrigin, Substitution, Word,
};
use crate::model::ObfuscationFlag;

/// Deepest `sh -c` / `eval` nesting that is still unwrapped. Deeper strings
/// are left as the interpreter command they are.
pub const MAX_UNWRAP_DEPTH: usize = 5;

/// Upper bound on wrapper layers stripped from one simple command.
const MAX_WRAPPER_STEPS: usize = 64;

/// Interpreters whose `-c STRING` argument is bash-compatible enough to parse.
pub const SHELLS: &[&str] = &["sh", "bash", "zsh", "dash", "ksh", "ash", "mksh"];

/// Short options that take a value, per wrapper.
struct OptSpec {
    short_with_arg: &'static [char],
    long_with_arg: &'static [&'static str],
}

const SUDO: OptSpec = OptSpec {
    short_with_arg: &['u', 'g', 'p', 'C', 'h', 'r', 't', 'U', 'D', 'T', 'R'],
    long_with_arg: &[
        "user",
        "group",
        "prompt",
        "close-from",
        "host",
        "role",
        "type",
        "other-user",
        "chdir",
        "command-timeout",
        "chroot",
    ],
};
const ENV: OptSpec = OptSpec {
    short_with_arg: &['u', 'C', 'S'],
    long_with_arg: &[
        "unset",
        "chdir",
        "split-string",
        "default-signal",
        "ignore-signal",
        "block-signal",
    ],
};
const NICE: OptSpec = OptSpec {
    short_with_arg: &['n'],
    long_with_arg: &["adjustment"],
};
const TIME: OptSpec = OptSpec {
    short_with_arg: &['f', 'o'],
    long_with_arg: &["format", "output"],
};
const EXEC: OptSpec = OptSpec {
    short_with_arg: &['a'],
    long_with_arg: &[],
};
const XARGS: OptSpec = OptSpec {
    short_with_arg: &['a', 'd', 'E', 'I', 'L', 'n', 'P', 's', 'S'],
    long_with_arg: &[
        "arg-file",
        "delimiter",
        "eof",
        "max-args",
        "max-lines",
        "max-procs",
        "max-chars",
        "replace",
        "process-slot-var",
    ],
};
const NO_OPTS: OptSpec = OptSpec {
    short_with_arg: &[],
    long_with_arg: &[],
};

/// Skip leading options according to `spec`. Returns the index of the first
/// non-option word, or `None` when only options remain. `--` ends options
/// and is skipped.
fn skip_options(args: &[Word], spec: &OptSpec) -> Option<usize> {
    let mut i = 0;
    while i < args.len() {
        let t = args[i].text.as_str();
        if t == "--" {
            return (i + 1 < args.len()).then_some(i + 1);
        }
        if let Some(long) = t.strip_prefix("--") {
            if long.is_empty() {
                return Some(i);
            }
            let name = long.split('=').next().unwrap_or(long);
            if spec.long_with_arg.contains(&name) && !long.contains('=') {
                i += 2;
            } else {
                i += 1;
            }
            continue;
        }
        if t.starts_with('-') && t.len() > 1 {
            // A cluster like `-Eu root`: the first option that takes a value
            // consumes the rest of the cluster or the next word.
            let mut consumed_next = false;
            for (pos, ch) in t[1..].chars().enumerate() {
                if spec.short_with_arg.contains(&ch) {
                    consumed_next = pos + 2 == t.len();
                    break;
                }
            }
            i += if consumed_next { 2 } else { 1 };
            continue;
        }
        return Some(i);
    }
    None
}

/// `NAME=value` words at `args[start..]`; returns the assignments and the
/// index of the first other word.
fn take_assignments(args: &[Word], start: usize) -> (Vec<EnvAssign>, usize) {
    let mut assigns = Vec::new();
    let mut i = start;
    while i < args.len() {
        match split_assignment(&args[i]) {
            Some(assign) => {
                assigns.push(assign);
                i += 1;
            }
            None => break,
        }
    }
    (assigns, i)
}

fn split_assignment(word: &Word) -> Option<EnvAssign> {
    let (name, value) = word.text.split_once('=')?;
    let (name, append) = match name.strip_suffix('+') {
        Some(n) => (n, true),
        None => (name, false),
    };
    if name.is_empty()
        || !name
            .chars()
            .next()
            .map(|c| c.is_ascii_alphabetic() || c == '_')
            .unwrap_or(false)
        || !name.chars().all(|c| c.is_ascii_alphanumeric() || c == '_')
    {
        return None;
    }
    Some(EnvAssign {
        name: name.to_string(),
        value: Word {
            text: value.to_string(),
            raw: word.raw.clone(),
            dynamic: word.dynamic,
        },
        append,
        substitutions: vec![],
    })
}

enum Step {
    /// Keep unwrapping the returned command.
    Again(SimpleCommand),
    /// Finished.
    Done(Node),
}

impl Lower<'_> {
    /// Strip wrappers until the real command is reached.
    pub(crate) fn unwrap_command(&mut self, mut cmd: SimpleCommand) -> Result<Node, ParseError> {
        if super::lower::split_ifs_words(&mut cmd) {
            self.flags.set(ObfuscationFlag::VarIndirection);
        }
        // Every step but `xargs` → `echo` drops at least one word, so the
        // chain is bounded by the word count; the cap is a belt and braces.
        for _ in 0..MAX_WRAPPER_STEPS {
            match self.unwrap_step(cmd)? {
                Step::Again(next) => cmd = next,
                Step::Done(node) => return Ok(node),
            }
        }
        Ok(Node::Simple(cmd))
    }

    fn unwrap_step(&mut self, mut cmd: SimpleCommand) -> Result<Step, ParseError> {
        let program = cmd.program.text.clone();
        match program.as_str() {
            "sudo" | "doas" => {
                if cmd.has_any_flag(["-e", "--edit", "-l", "--list", "-v", "--validate", "-K"]) {
                    return Ok(Step::Done(Node::Simple(cmd)));
                }
                let spec = if program == "sudo" { &SUDO } else { &NO_OPTS };
                let Some(start) = skip_options(&cmd.args, spec) else {
                    return Ok(Step::Done(Node::Simple(cmd)));
                };
                let (assigns, next) = take_assignments(&cmd.args, start);
                if next >= cmd.args.len() {
                    return Ok(Step::Done(Node::Simple(cmd)));
                }
                cmd.env.extend(assigns);
                Ok(Step::Again(self.strip_wrapper(cmd, next, &program)))
            }
            "env" => {
                let Some(start) = skip_options(&cmd.args, &ENV) else {
                    return Ok(Step::Done(Node::Simple(cmd)));
                };
                if cmd.has_any_flag(["-S", "--split-string"]) {
                    // `-S` re-splits a string by its own rules; keep `env`.
                    return Ok(Step::Done(Node::Simple(cmd)));
                }
                let (assigns, next) = take_assignments(&cmd.args, start);
                if next >= cmd.args.len() {
                    return Ok(Step::Done(Node::Simple(cmd)));
                }
                cmd.env.extend(assigns);
                Ok(Step::Again(self.strip_wrapper(cmd, next, "env")))
            }
            "nice" | "nohup" | "time" | "builtin" | "exec" | "command" | "chronic" | "ionice"
            | "timeout" | "stdbuf" | "caffeinate" | "chroot" => {
                if program == "command" && cmd.has_any_flag(["-v", "-V"]) {
                    return Ok(Step::Done(Node::Simple(cmd)));
                }
                let spec = match program.as_str() {
                    "nice" => &NICE,
                    "time" => &TIME,
                    "exec" => &EXEC,
                    "timeout" => &TIMEOUT,
                    "ionice" => &IONICE,
                    "stdbuf" => &STDBUF,
                    "caffeinate" => &CAFFEINATE,
                    _ => &NO_OPTS,
                };
                let mut start = match skip_options(&cmd.args, spec) {
                    Some(s) => s,
                    None => return Ok(Step::Done(Node::Simple(cmd))),
                };
                if matches!(program.as_str(), "timeout" | "chroot") {
                    // `timeout [opts] DURATION cmd`, `chroot [opts] NEWROOT cmd`
                    start += 1;
                    if start >= cmd.args.len() {
                        return Ok(Step::Done(Node::Simple(cmd)));
                    }
                }
                Ok(Step::Again(self.strip_wrapper(cmd, start, &program)))
            }
            "su" => self.unwrap_su(cmd),
            "xargs" => {
                let start = skip_options(&cmd.args, &XARGS);
                let mut next = match start {
                    Some(s) => self.strip_wrapper(cmd, s, "xargs"),
                    None => {
                        // `xargs` alone runs `echo`.
                        let mut next = SimpleCommand {
                            program: Word::literal("echo"),
                            env: std::mem::take(&mut cmd.env),
                            redirects: std::mem::take(&mut cmd.redirects),
                            ..SimpleCommand::default()
                        };
                        next.wrappers = std::mem::take(&mut cmd.wrappers);
                        next.wrappers.push("xargs".to_string());
                        next
                    }
                };
                next.args_from_stdin = true;
                Ok(Step::Again(next))
            }
            p if SHELLS.contains(&p) => self.unwrap_shell(cmd),
            "eval" => self.unwrap_eval(cmd),
            "source" | "." => {
                if cmd
                    .substitutions
                    .iter()
                    .any(|s| matches!(s.kind, SubstKind::ProcessIn | SubstKind::Command))
                {
                    self.flags.set(ObfuscationFlag::EvalDynamic);
                }
                Ok(Step::Done(Node::Simple(cmd)))
            }
            "find" => {
                self.unwrap_find_exec(&mut cmd)?;
                Ok(Step::Done(Node::Simple(cmd)))
            }
            _ => Ok(Step::Done(Node::Simple(cmd))),
        }
    }

    /// Make `args[start]` the program and drop everything before it.
    fn strip_wrapper(&mut self, cmd: SimpleCommand, start: usize, wrapper: &str) -> SimpleCommand {
        let SimpleCommand {
            program: _,
            mut args,
            env,
            redirects,
            substitutions,
            mut wrappers,
            args_from_stdin,
        } = cmd;
        wrappers.push(normalise_program(wrapper));
        let rest = args.split_off(start);
        let mut iter = rest.into_iter();
        let program_word = iter.next().expect("start < args.len()");
        let mut next = SimpleCommand {
            program: Word::default(),
            args: iter.collect(),
            env,
            redirects,
            substitutions: Vec::new(),
            wrappers,
            args_from_stdin,
        };
        let mut program_subs = Vec::new();
        for mut sub in substitutions {
            match sub.origin {
                SubstOrigin::Arg(i) if i == start => program_subs.push((sub.kind, sub.body)),
                SubstOrigin::Arg(i) if i > start => {
                    sub.origin = SubstOrigin::Arg(i - start - 1);
                    next.substitutions.push(sub);
                }
                SubstOrigin::Arg(_) | SubstOrigin::Program => {
                    sub.origin = SubstOrigin::Wrapper;
                    next.substitutions.push(sub);
                }
                _ => next.substitutions.push(sub),
            }
        }
        self.set_program(
            &mut next,
            LoweredWord {
                word: program_word,
                subs: program_subs,
            },
        );
        next
    }

    /// `sh -c 'string' [name args...]`: parse `string` as a nested command
    /// line. Options before `-c` are skipped; a cluster containing `c`
    /// (`-ec`, `-xc`) counts. A non-literal string or one nested too deep is
    /// left as the interpreter command.
    fn unwrap_shell(&mut self, cmd: SimpleCommand) -> Result<Step, ParseError> {
        let mut i = 0;
        let mut script_index = None;
        while i < cmd.args.len() {
            let t = cmd.args[i].text.as_str();
            if t == "--" {
                break;
            }
            if t == "-o" || t == "+o" {
                i += 2;
                continue;
            }
            if (t.starts_with('-') || t.starts_with('+')) && t.len() > 1 && !t.starts_with("--") {
                if t[1..].contains('c') && !t.starts_with('+') {
                    script_index = Some(i + 1);
                    break;
                }
                i += 1;
                continue;
            }
            if t.starts_with("--") {
                i += 1;
                continue;
            }
            break;
        }
        let Some(script_index) = script_index else {
            if cmd
                .substitutions
                .iter()
                .any(|s| matches!(s.kind, SubstKind::ProcessIn))
            {
                // `bash <(curl ...)`
                self.flags.set(ObfuscationFlag::EvalDynamic);
            }
            return Ok(Step::Done(Node::Simple(cmd)));
        };
        let Some(script) = cmd.args.get(script_index) else {
            return Ok(Step::Done(Node::Simple(cmd)));
        };
        if script.dynamic {
            self.flags.set(ObfuscationFlag::EvalDynamic);
            return Ok(Step::Done(Node::Simple(cmd)));
        }
        let text = script.text.clone();
        let wrapper = cmd.program.text.clone();
        self.nested(cmd, &text, &wrapper)
    }

    /// `eval word...`: the words joined by spaces are a nested command line.
    fn unwrap_eval(&mut self, cmd: SimpleCommand) -> Result<Step, ParseError> {
        if cmd.args.is_empty() {
            return Ok(Step::Done(Node::Simple(cmd)));
        }
        if cmd.args.iter().any(|a| a.dynamic) {
            self.flags.set(ObfuscationFlag::EvalDynamic);
            return Ok(Step::Done(Node::Simple(cmd)));
        }
        let text = cmd
            .args
            .iter()
            .map(|a| a.text.as_str())
            .collect::<Vec<_>>()
            .join(" ");
        self.nested(cmd, &text, "eval")
    }

    fn nested(
        &mut self,
        cmd: SimpleCommand,
        text: &str,
        wrapper: &str,
    ) -> Result<Step, ParseError> {
        if self.depth + 1 > MAX_UNWRAP_DEPTH {
            return Ok(Step::Done(Node::Simple(cmd)));
        }
        let mut wrappers = cmd.wrappers.clone();
        wrappers.push(wrapper.to_string());
        let (mut body, flags) = match super::parse_depth(text, self.depth + 1, self.vars.clone()) {
            Ok(ok) => ok,
            Err(inner) => {
                return Err(ParseError::new(
                    ParseErrorKind::Nested,
                    self.src,
                    0,
                    format!("inside `{wrapper}`: {inner}"),
                ));
            }
        };
        self.flags.merge(flags);
        prefix_wrappers(&mut body, &wrappers);
        if !cmd.env.is_empty() {
            // `X=1 sh -c 'a; b'`: the interpreter's environment reaches
            // every command in the body.
            prefix_env(&mut body, &cmd.env);
        }
        if !cmd.redirects.is_empty() {
            // Redirects of the interpreter apply to the whole body.
            body = match body {
                Node::Simple(mut inner) => {
                    inner.redirects.extend(cmd.redirects);
                    Node::Simple(inner)
                }
                other => Node::Group {
                    body: Box::new(other),
                    redirects: cmd.redirects,
                },
            };
        }
        Ok(Step::Done(body))
    }

    /// `su [opts] [user] -c 'string'` / `--command=string`: the string runs
    /// in the target user's shell.
    fn unwrap_su(&mut self, cmd: SimpleCommand) -> Result<Step, ParseError> {
        let mut script: Option<Word> = None;
        let mut i = 0;
        while i < cmd.args.len() {
            let t = cmd.args[i].text.as_str();
            if t == "--" {
                break;
            }
            if let Some(rest) = t.strip_prefix("--command=") {
                script = Some(Word {
                    text: rest.to_string(),
                    raw: cmd.args[i].raw.clone(),
                    dynamic: cmd.args[i].dynamic,
                });
                break;
            }
            if t == "--command"
                || t == "-c"
                || (t.starts_with('-') && !t.starts_with("--") && t.ends_with('c') && t.len() > 1)
            {
                script = cmd.args.get(i + 1).cloned();
                break;
            }
            if matches!(
                t,
                "-s" | "--shell" | "-g" | "--group" | "-G" | "--supp-group"
            ) {
                i += 2;
                continue;
            }
            i += 1;
        }
        let Some(script) = script else {
            return Ok(Step::Done(Node::Simple(cmd)));
        };
        if script.dynamic {
            self.flags.set(ObfuscationFlag::EvalDynamic);
            return Ok(Step::Done(Node::Simple(cmd)));
        }
        let text = script.text.clone();
        self.nested(cmd, &text, "su")
    }

    /// `find ... -exec cmd {} \;` / `+`, also `-execdir`, `-ok`, `-okdir`.
    fn unwrap_find_exec(&mut self, cmd: &mut SimpleCommand) -> Result<(), ParseError> {
        let mut i = 0;
        while i < cmd.args.len() {
            let t = cmd.args[i].text.as_str();
            if matches!(t, "-exec" | "-execdir" | "-ok" | "-okdir") {
                let start = i + 1;
                let mut end = start;
                while end < cmd.args.len() && !matches!(cmd.args[end].text.as_str(), ";" | "+") {
                    end += 1;
                }
                if end > start {
                    let mut child = SimpleCommand {
                        program: Word::default(),
                        args: cmd.args[start + 1..end].to_vec(),
                        ..SimpleCommand::default()
                    };
                    let mut program_subs = Vec::new();
                    for sub in &cmd.substitutions {
                        match sub.origin {
                            SubstOrigin::Arg(k) if k == start => {
                                program_subs.push((sub.kind, sub.body.clone()))
                            }
                            SubstOrigin::Arg(k) if k > start && k < end => {
                                child.substitutions.push(Substitution {
                                    kind: sub.kind,
                                    origin: SubstOrigin::Arg(k - start - 1),
                                    body: sub.body.clone(),
                                })
                            }
                            _ => {}
                        }
                    }
                    child.wrappers = cmd.wrappers.clone();
                    child.wrappers.push("find".to_string());
                    self.set_program(
                        &mut child,
                        LoweredWord {
                            word: cmd.args[start].clone(),
                            subs: program_subs,
                        },
                    );
                    let body = self.unwrap_command(child)?;
                    cmd.substitutions.push(Substitution {
                        kind: SubstKind::Exec,
                        origin: SubstOrigin::Exec,
                        body,
                    });
                }
                i = end + 1;
            } else {
                i += 1;
            }
        }
        Ok(())
    }
}

const TIMEOUT: OptSpec = OptSpec {
    short_with_arg: &['k', 's'],
    long_with_arg: &["kill-after", "signal"],
};
const IONICE: OptSpec = OptSpec {
    short_with_arg: &['c', 'n', 'p', 'P', 'u'],
    long_with_arg: &["class", "classdata", "pid", "pgid", "uid"],
};
const STDBUF: OptSpec = OptSpec {
    short_with_arg: &['i', 'o', 'e'],
    long_with_arg: &["input", "output", "error"],
};
const CAFFEINATE: OptSpec = OptSpec {
    short_with_arg: &['t', 'w'],
    long_with_arg: &[],
};

/// Prepend `env` to the environment of every simple command under `node`
/// (substitution bodies excluded: they run before the assignment applies).
fn prefix_env(node: &mut Node, env: &[EnvAssign]) {
    match node {
        Node::Simple(cmd) => {
            let mut all = env.to_vec();
            all.append(&mut cmd.env);
            cmd.env = all;
        }
        Node::Pipeline { stages } => stages.iter_mut().for_each(|s| prefix_env(s, env)),
        Node::List { left, right, .. } => {
            prefix_env(left, env);
            prefix_env(right, env);
        }
        Node::Subshell { body, .. } | Node::Group { body, .. } => prefix_env(body, env),
        Node::Compound { parts, .. } => parts.iter_mut().for_each(|p| prefix_env(p, env)),
        Node::Assignment(_) | Node::Empty => {}
    }
}

/// Prepend `wrappers` to every simple command under `node`.
pub(crate) fn prefix_wrappers(node: &mut Node, wrappers: &[String]) {
    match node {
        Node::Simple(cmd) => {
            let mut all = wrappers.to_vec();
            all.append(&mut cmd.wrappers);
            cmd.wrappers = all;
            for sub in &mut cmd.substitutions {
                prefix_wrappers(&mut sub.body, wrappers);
            }
        }
        Node::Pipeline { stages } => stages.iter_mut().for_each(|s| prefix_wrappers(s, wrappers)),
        Node::List { left, right, .. } => {
            prefix_wrappers(left, wrappers);
            prefix_wrappers(right, wrappers);
        }
        Node::Subshell { body, .. } | Node::Group { body, .. } => prefix_wrappers(body, wrappers),
        Node::Compound { parts, .. } => parts.iter_mut().for_each(|p| prefix_wrappers(p, wrappers)),
        Node::Assignment(assigns) => {
            for a in assigns {
                for sub in &mut a.substitutions {
                    prefix_wrappers(&mut sub.body, wrappers);
                }
            }
        }
        Node::Empty => {}
    }
}
