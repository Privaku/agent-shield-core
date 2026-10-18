//! The normalised command tree produced by [`super::parse`].

use std::fmt;

use crate::model::{ArgvTree, ListOp, ObfuscationFlag, Redirect as WireRedirect, RedirectOp};

/// A parsed, normalised and unwrapped command line.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct CommandTree {
    /// The command line exactly as submitted.
    pub raw: String,
    /// The structure of the command line.
    pub root: Node,
    /// Obfuscation techniques noticed anywhere in the tree.
    pub obfuscation: ObfuscationFlags,
}

impl CommandTree {
    /// Every simple command in the tree in execution order: substitution
    /// bodies before the command that uses them, `find -exec` children after
    /// the `find`, unwrapped `sh -c` bodies in place of the interpreter.
    /// Redirect-only holders (`> file` with no program) are skipped; see
    /// [`Self::redirects`] for those.
    pub fn simple_commands(&self) -> Vec<&SimpleCommand> {
        let mut out = Vec::new();
        self.root.collect_simple(&mut out);
        out
    }

    /// Every redirect anywhere in the tree, including those on subshells,
    /// groups, compound statements and program-less holders.
    pub fn redirects(&self) -> Vec<&Redirect> {
        let mut out = Vec::new();
        self.root.collect_redirects(&mut out);
        out
    }

    /// Normalised program names of [`Self::simple_commands`].
    pub fn programs(&self) -> Vec<&str> {
        self.simple_commands()
            .into_iter()
            .map(|c| c.program.text.as_str())
            .collect()
    }

    /// Convert to the wire model used by `ActionKind::Shell`.
    pub fn to_argv_tree(&self) -> ArgvTree {
        self.root.to_argv_tree()
    }
}

/// One node of a [`CommandTree`].
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Node {
    /// A program with its arguments.
    Simple(SimpleCommand),
    /// `a | b | c` (also `|&`). Always at least two stages.
    Pipeline { stages: Vec<Node> },
    /// Two commands joined by `&&`, `||`, `;`/newline or `&`.
    List {
        op: ListOp,
        left: Box<Node>,
        right: Box<Node>,
    },
    /// `( ... )`: runs in a child shell.
    Subshell {
        body: Box<Node>,
        redirects: Vec<Redirect>,
    },
    /// `{ ...; }`: runs in the current shell.
    Group {
        body: Box<Node>,
        redirects: Vec<Redirect>,
    },
    /// `if`, `for`, `while`, `until`, `case`, `select` or a function
    /// definition. `parts` holds every statement inside (conditions and
    /// bodies alike) in source order; the control flow itself is not modelled
    /// because policy evaluates every command that *could* run.
    Compound {
        kind: CompoundKind,
        parts: Vec<Node>,
        redirects: Vec<Redirect>,
    },
    /// A bare variable assignment with no command (`X=1`, `export X=1` is a
    /// [`Node::Simple`] instead).
    Assignment(Vec<EnvAssign>),
    /// Nothing to run (only whitespace or comments).
    Empty,
}

impl Node {
    fn collect_simple<'a>(&'a self, out: &mut Vec<&'a SimpleCommand>) {
        enum Step<'a> {
            Visit(&'a Node),
            Emit(&'a SimpleCommand),
        }

        let mut stack = vec![Step::Visit(self)];
        while let Some(step) = stack.pop() {
            match step {
                Step::Emit(cmd) => {
                    if !cmd.program.text.is_empty() {
                        out.push(cmd);
                    }
                }
                Step::Visit(Node::Simple(cmd)) => {
                    for sub in cmd.substitutions.iter().rev() {
                        if sub.kind == SubstKind::Exec {
                            stack.push(Step::Visit(&sub.body));
                        }
                    }
                    stack.push(Step::Emit(cmd));
                    for sub in cmd.substitutions.iter().rev() {
                        if sub.kind != SubstKind::Exec {
                            stack.push(Step::Visit(&sub.body));
                        }
                    }
                }
                Step::Visit(Node::Pipeline { stages }) => {
                    stack.extend(stages.iter().rev().map(Step::Visit));
                }
                Step::Visit(Node::List { left, right, .. }) => {
                    stack.push(Step::Visit(right));
                    stack.push(Step::Visit(left));
                }
                Step::Visit(Node::Subshell { body, .. } | Node::Group { body, .. }) => {
                    stack.push(Step::Visit(body));
                }
                Step::Visit(Node::Compound { parts, .. }) => {
                    stack.extend(parts.iter().rev().map(Step::Visit));
                }
                Step::Visit(Node::Assignment(assigns)) => {
                    for assign in assigns.iter().rev() {
                        stack.extend(
                            assign
                                .substitutions
                                .iter()
                                .rev()
                                .map(|sub| Step::Visit(&sub.body)),
                        );
                    }
                }
                Step::Visit(Node::Empty) => {}
            }
        }
    }

    fn collect_redirects<'a>(&'a self, out: &mut Vec<&'a Redirect>) {
        enum Step<'a> {
            Visit(&'a Node),
            Emit(&'a [Redirect]),
        }

        let mut stack = vec![Step::Visit(self)];
        while let Some(step) = stack.pop() {
            match step {
                Step::Emit(redirects) => out.extend(redirects),
                Step::Visit(Node::Simple(cmd)) => {
                    stack.push(Step::Emit(&cmd.redirects));
                    stack.extend(
                        cmd.substitutions
                            .iter()
                            .rev()
                            .map(|sub| Step::Visit(&sub.body)),
                    );
                }
                Step::Visit(Node::Pipeline { stages }) => {
                    stack.extend(stages.iter().rev().map(Step::Visit));
                }
                Step::Visit(Node::List { left, right, .. }) => {
                    stack.push(Step::Visit(right));
                    stack.push(Step::Visit(left));
                }
                Step::Visit(
                    Node::Subshell { body, redirects } | Node::Group { body, redirects },
                ) => {
                    stack.push(Step::Emit(redirects));
                    stack.push(Step::Visit(body));
                }
                Step::Visit(Node::Compound {
                    parts, redirects, ..
                }) => {
                    stack.push(Step::Emit(redirects));
                    stack.extend(parts.iter().rev().map(Step::Visit));
                }
                Step::Visit(Node::Assignment(assigns)) => {
                    for assign in assigns.iter().rev() {
                        stack.extend(
                            assign
                                .substitutions
                                .iter()
                                .rev()
                                .map(|sub| Step::Visit(&sub.body)),
                        );
                    }
                }
                Step::Visit(Node::Empty) => {}
            }
        }
    }

    /// Every simple command under this node, in execution order.
    pub fn simple_commands(&self) -> Vec<&SimpleCommand> {
        let mut out = Vec::new();
        self.collect_simple(&mut out);
        out
    }

    /// The stages of a pipeline, or the node itself as a one-stage pipeline.
    pub fn stages(&self) -> Vec<&Node> {
        match self {
            Node::Pipeline { stages } => stages.iter().collect(),
            other => vec![other],
        }
    }

    /// Convert to the wire model. `Subshell`, `Group` and `Compound` become
    /// `ArgvTree::Group`; `Assignment` and `Empty` become a command with an
    /// empty `argv`; a `&>` redirect becomes two wire redirects (fd 1 and
    /// fd 2).
    pub fn to_argv_tree(&self) -> ArgvTree {
        match self {
            Node::Simple(cmd) => cmd.to_argv_tree(),
            Node::Pipeline { stages } => ArgvTree::Pipeline {
                commands: stages.iter().map(Node::to_argv_tree).collect(),
            },
            Node::List { op, left, right } => ArgvTree::List {
                op: *op,
                left: Box::new(left.to_argv_tree()),
                right: Box::new(right.to_argv_tree()),
            },
            Node::Subshell { body, redirects } | Node::Group { body, redirects } => {
                group_with_redirects(body.to_argv_tree(), redirects)
            }
            Node::Compound {
                parts, redirects, ..
            } => {
                let body = sequence(parts.iter().map(Node::to_argv_tree).collect());
                group_with_redirects(body, redirects)
            }
            Node::Assignment(assigns) => ArgvTree::Command {
                argv: vec![],
                redirects: vec![],
                substitutions: assigns
                    .iter()
                    .flat_map(|a| a.substitutions.iter())
                    .map(|s| s.body.to_argv_tree())
                    .collect(),
                env: assigns.iter().map(EnvAssign::to_string).collect(),
                wrappers: vec![],
            },
            Node::Empty => ArgvTree::Command {
                argv: vec![],
                redirects: vec![],
                substitutions: vec![],
                env: vec![],
                wrappers: vec![],
            },
        }
    }
}

fn group_with_redirects(body: ArgvTree, redirects: &[Redirect]) -> ArgvTree {
    // The wire `group` has no redirect slot; the redirects of `( ... ) > f`
    // belong to the whole group, so they are attached to a trailing empty
    // command only when present. That keeps the file path visible to M5.
    if redirects.is_empty() {
        return ArgvTree::Group {
            body: Box::new(body),
        };
    }
    ArgvTree::Group {
        body: Box::new(ArgvTree::List {
            op: ListOp::Then,
            left: Box::new(body),
            right: Box::new(ArgvTree::Command {
                argv: vec![],
                redirects: wire_redirects(redirects),
                substitutions: vec![],
                env: vec![],
                wrappers: vec![],
            }),
        }),
    }
}

/// Fold a list of trees into a right-nested `;` list.
pub(crate) fn sequence(mut trees: Vec<ArgvTree>) -> ArgvTree {
    match trees.len() {
        0 => ArgvTree::Command {
            argv: vec![],
            redirects: vec![],
            substitutions: vec![],
            env: vec![],
            wrappers: vec![],
        },
        1 => trees.pop().expect("one element"),
        _ => {
            let first = trees.remove(0);
            ArgvTree::List {
                op: ListOp::Then,
                left: Box::new(first),
                right: Box::new(sequence(trees)),
            }
        }
    }
}

fn wire_redirects(redirects: &[Redirect]) -> Vec<WireRedirect> {
    let mut out = Vec::with_capacity(redirects.len());
    for r in redirects {
        match r.kind {
            RedirectKind::BothWrite | RedirectKind::BothAppend => {
                let op = if r.kind == RedirectKind::BothWrite {
                    RedirectOp::Write
                } else {
                    RedirectOp::Append
                };
                for fd in [1, 2] {
                    out.push(WireRedirect {
                        fd: Some(fd),
                        op,
                        target: r.target.text.clone(),
                        body: None,
                    });
                }
            }
            kind => out.push(WireRedirect {
                fd: r.fd,
                op: kind.wire_op(),
                target: r.target.text.clone(),
                body: r.body.clone(),
            }),
        }
    }
    out
}

/// Which compound statement a [`Node::Compound`] came from.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum CompoundKind {
    If,
    For,
    While,
    Until,
    Case,
    Select,
    /// `name() { ... }` or `function name { ... }`.
    Function {
        name: String,
    },
}

/// A program and its arguments after quote removal, normalisation and
/// wrapper unwrapping.
#[derive(Debug, Clone, PartialEq, Eq, Default)]
pub struct SimpleCommand {
    /// The program. `text` is the normalised name (`/bin/rm`, `\rm`,
    /// `"r"m` and `$'\x72\x6d'` all give `rm`); `raw` is what was written.
    pub program: Word,
    /// Arguments after the program, in order.
    pub args: Vec<Word>,
    /// `NAME=value` prefixes, including those taken from `env` and `sudo`
    /// when unwrapping.
    pub env: Vec<EnvAssign>,
    /// Redirections attached to this command (heredocs included).
    pub redirects: Vec<Redirect>,
    /// Command and process substitutions in any word of this command, and
    /// commands this command runs itself (`find -exec`).
    pub substitutions: Vec<Substitution>,
    /// Normalised names of the wrappers stripped to reach this command,
    /// outermost first (`["sudo", "env"]`, `["bash"]`, `["xargs"]`, ...).
    pub wrappers: Vec<String>,
    /// `true` when the arguments come from standard input (`xargs`).
    pub args_from_stdin: bool,
}

impl SimpleCommand {
    /// `[program, arg, arg, ...]` as normalised strings. Empty when the
    /// command has no program (`> file` alone, a redirect holder).
    pub fn argv(&self) -> Vec<String> {
        if self.program.text.is_empty() && self.args.is_empty() {
            return Vec::new();
        }
        std::iter::once(self.program.text.clone())
            .chain(self.args.iter().map(|a| a.text.clone()))
            .collect()
    }

    /// Argument texts without the program.
    pub fn arg_texts(&self) -> Vec<&str> {
        self.args.iter().map(|a| a.text.as_str()).collect()
    }

    /// Option-like arguments before a `--` terminator, with short clusters
    /// split: `-rf` gives `-r` and `-f`; `--no-preserve-root=x` gives
    /// `--no-preserve-root`; `-n5` gives `-n` (the value is dropped at the
    /// first non-letter). A lone `-` is not a flag.
    pub fn flags(&self) -> Vec<String> {
        let mut out = Vec::new();
        for arg in &self.args {
            let t = arg.text.as_str();
            if t == "--" {
                break;
            }
            if let Some(long) = t.strip_prefix("--") {
                if long.is_empty() {
                    continue;
                }
                let name = long.split('=').next().unwrap_or(long);
                out.push(format!("--{name}"));
            } else if let Some(short) = t.strip_prefix('-') {
                for ch in short.chars() {
                    if !ch.is_ascii_alphabetic() {
                        break;
                    }
                    out.push(format!("-{ch}"));
                }
            }
        }
        out
    }

    /// `true` when [`Self::flags`] contains `flag` (`-r`, `--recursive`).
    pub fn has_flag(&self, flag: &str) -> bool {
        self.flags().iter().any(|f| f == flag)
    }

    /// `true` when any of `flags` is present.
    pub fn has_any_flag<'a, I: IntoIterator<Item = &'a str>>(&self, flags: I) -> bool {
        let have = self.flags();
        flags.into_iter().any(|f| have.iter().any(|h| h == f))
    }

    /// Arguments that are not options: everything after `--`, plus words not
    /// starting with `-` before it. `-` alone (stdin) is positional.
    pub fn positional(&self) -> Vec<&str> {
        let mut out = Vec::new();
        let mut after_dashdash = false;
        for arg in &self.args {
            let t = arg.text.as_str();
            if after_dashdash {
                out.push(t);
            } else if t == "--" {
                after_dashdash = true;
            } else if t == "-" || !t.starts_with('-') {
                out.push(t);
            }
        }
        out
    }

    /// Convert to the wire model.
    pub fn to_argv_tree(&self) -> ArgvTree {
        ArgvTree::Command {
            argv: self.argv(),
            redirects: wire_redirects(&self.redirects),
            substitutions: self
                .substitutions
                .iter()
                .map(|s| s.body.to_argv_tree())
                .collect(),
            env: self.env.iter().map(EnvAssign::to_string).collect(),
            wrappers: self.wrappers.clone(),
        }
    }
}

/// One shell word after quote removal.
#[derive(Debug, Clone, PartialEq, Eq, Default)]
pub struct Word {
    /// The word after quote removal, backslash unescaping, ANSI-C decoding
    /// and concatenation of adjacent parts. Variable references (`$HOME`,
    /// `${X}`), substitutions and arithmetic are kept as written because
    /// their value is unknown; `~` is kept for M5 to expand.
    pub text: String,
    /// The word exactly as written in the command line.
    pub raw: String,
    /// `true` when `text` still contains something the shell would expand
    /// (a variable, a substitution, arithmetic), so it is not the literal
    /// value the program will see.
    pub dynamic: bool,
}

impl Word {
    pub fn literal(text: impl Into<String>) -> Self {
        let text = text.into();
        Word {
            raw: text.clone(),
            text,
            dynamic: false,
        }
    }
}

impl fmt::Display for Word {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(&self.text)
    }
}

/// `NAME=value` or `NAME+=value`.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct EnvAssign {
    pub name: String,
    pub value: Word,
    /// `true` for `+=`.
    pub append: bool,
    /// Substitutions inside `value`.
    pub substitutions: Vec<Substitution>,
}

impl fmt::Display for EnvAssign {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(
            f,
            "{}{}={}",
            self.name,
            if self.append { "+" } else { "" },
            self.value.text
        )
    }
}

/// One I/O redirection.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Redirect {
    /// Descriptor written on the left (`2>`), if any.
    pub fd: Option<u32>,
    pub kind: RedirectKind,
    /// The word on the right: a path, a descriptor number, a here-string, or
    /// the heredoc delimiter.
    pub target: Word,
    /// Heredoc text (without the delimiter lines). `Some` only for
    /// [`RedirectKind::HereDoc`].
    pub body: Option<String>,
}

/// Redirection operator.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum RedirectKind {
    /// `<`
    Read,
    /// `>` and `>|`
    Write,
    /// `>>`
    Append,
    /// `<>`
    ReadWrite,
    /// `&>` and `>&file`: stdout and stderr to a file.
    BothWrite,
    /// `&>>`
    BothAppend,
    /// `>&N`, `<&N`, `>&-`, `<&-`: duplicate or close a descriptor.
    Dup,
    /// `<<` and `<<-`
    HereDoc,
    /// `<<<`
    HereString,
}

impl RedirectKind {
    /// Closest wire operator. `BothWrite`/`BothAppend` map to `Write`/
    /// `Append`; the bridge emits them twice (fd 1 and fd 2).
    pub fn wire_op(self) -> RedirectOp {
        match self {
            RedirectKind::Read => RedirectOp::Read,
            RedirectKind::Write | RedirectKind::BothWrite => RedirectOp::Write,
            RedirectKind::Append | RedirectKind::BothAppend => RedirectOp::Append,
            RedirectKind::ReadWrite => RedirectOp::ReadWrite,
            RedirectKind::Dup => RedirectOp::Dup,
            RedirectKind::HereDoc => RedirectOp::HereDoc,
            RedirectKind::HereString => RedirectOp::HereString,
        }
    }

    /// `true` when the operator creates or truncates/appends a file.
    pub fn writes_file(self) -> bool {
        matches!(
            self,
            RedirectKind::Write
                | RedirectKind::Append
                | RedirectKind::ReadWrite
                | RedirectKind::BothWrite
                | RedirectKind::BothAppend
        )
    }
}

/// A command nested inside another command.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Substitution {
    pub kind: SubstKind,
    /// Where in the enclosing command the substitution sits.
    pub origin: SubstOrigin,
    pub body: Node,
}

/// How a nested command is embedded.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum SubstKind {
    /// `$( ... )`
    Command,
    /// `` ` ... ` ``
    Backtick,
    /// `<( ... )`
    ProcessIn,
    /// `>( ... )`
    ProcessOut,
    /// `find ... -exec cmd {} \;` (also `-execdir`, `-ok`, `-okdir`).
    Exec,
}

/// Position of a [`Substitution`] in its command.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum SubstOrigin {
    /// The command name itself (`$(...) args`).
    Program,
    /// Argument at this index (0-based, program excluded).
    Arg(usize),
    /// Value of the environment prefix at this index.
    Env(usize),
    /// Target of the redirect at this index.
    Redirect(usize),
    /// The command is run by the enclosing program (`find -exec`).
    Exec,
    /// It sat in a word of a wrapper that was stripped
    /// (`sudo -u $(whoami) rm ...`).
    Wrapper,
}

/// Set of [`ObfuscationFlag`]s.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub struct ObfuscationFlags {
    pub base64_decode: bool,
    pub hex_escape: bool,
    pub var_indirection: bool,
    pub eval_dynamic: bool,
}

impl ObfuscationFlags {
    pub fn set(&mut self, flag: ObfuscationFlag) {
        match flag {
            ObfuscationFlag::Base64Decode => self.base64_decode = true,
            ObfuscationFlag::HexEscape => self.hex_escape = true,
            ObfuscationFlag::VarIndirection => self.var_indirection = true,
            ObfuscationFlag::EvalDynamic => self.eval_dynamic = true,
        }
    }

    pub fn contains(&self, flag: ObfuscationFlag) -> bool {
        match flag {
            ObfuscationFlag::Base64Decode => self.base64_decode,
            ObfuscationFlag::HexEscape => self.hex_escape,
            ObfuscationFlag::VarIndirection => self.var_indirection,
            ObfuscationFlag::EvalDynamic => self.eval_dynamic,
        }
    }

    pub fn is_empty(&self) -> bool {
        *self == ObfuscationFlags::default()
    }

    pub fn any(&self) -> bool {
        !self.is_empty()
    }

    /// The set flags in wire order, for `ActionKind::Shell::obfuscation`.
    pub fn to_vec(&self) -> Vec<ObfuscationFlag> {
        ObfuscationFlag::ALL
            .into_iter()
            .filter(|f| self.contains(*f))
            .collect()
    }

    pub fn merge(&mut self, other: ObfuscationFlags) {
        self.base64_decode |= other.base64_decode;
        self.hex_escape |= other.hex_escape;
        self.var_indirection |= other.var_indirection;
        self.eval_dynamic |= other.eval_dynamic;
    }
}

/// Normalise a program name: strip the directory part (`/bin/rm`, `./rm`,
/// `~/bin/rm` → `rm`). A name that is only slashes is kept as written.
pub fn normalise_program(name: &str) -> String {
    match name.rsplit('/').next() {
        Some(base) if !base.is_empty() => base.to_string(),
        _ => name.to_string(),
    }
}
