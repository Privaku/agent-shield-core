//! Lowering of the tree-sitter concrete syntax tree into [`Node`]s.

use std::collections::HashMap;

use tree_sitter::Node as TsNode;

use super::error::{ParseError, ParseErrorKind};
use super::tree::{
    CompoundKind, EnvAssign, Node, ObfuscationFlags, Redirect, RedirectKind, SimpleCommand,
    SubstKind, SubstOrigin, Substitution, Word,
};
use super::words;
use crate::model::{ListOp, ObfuscationFlag};

/// Statement node kinds of the tree-sitter-bash grammar.
const STATEMENT_KINDS: &[&str] = &[
    "redirected_statement",
    "variable_assignment",
    "variable_assignments",
    "command",
    "declaration_command",
    "unset_command",
    "test_command",
    "negated_command",
    "for_statement",
    "c_style_for_statement",
    "while_statement",
    "if_statement",
    "case_statement",
    "pipeline",
    "list",
    "compound_statement",
    "function_definition",
    "subshell",
];

/// Containers whose statement children belong to the enclosing compound.
const CONTAINER_KINDS: &[&str] = &["do_group", "elif_clause", "else_clause", "case_item"];

/// A word plus the substitutions found inside it (origin not yet known).
pub(crate) struct LoweredWord {
    pub word: Word,
    pub subs: Vec<(SubstKind, Node)>,
}

/// State shared while lowering one command text (and its nested `sh -c`
/// bodies, which get their own `Lower` with a deeper `depth`).
pub(crate) struct Lower<'s> {
    pub src: &'s str,
    pub depth: usize,
    pub flags: ObfuscationFlags,
    /// Literal variable assignments seen so far, for resolving `$c -rf ~`.
    pub vars: HashMap<String, String>,
}

impl<'s> Lower<'s> {
    pub fn new(src: &'s str, depth: usize, vars: HashMap<String, String>) -> Self {
        Lower {
            src,
            depth,
            flags: ObfuscationFlags::default(),
            vars,
        }
    }

    fn text(&self, n: TsNode) -> &'s str {
        &self.src[n.byte_range()]
    }

    fn syntax_error(&self, n: TsNode, detail: impl Into<String>) -> ParseError {
        ParseError::new(
            ParseErrorKind::Syntax,
            self.src,
            n.start_byte(),
            detail.into(),
        )
    }

    // --- statements -------------------------------------------------------

    /// Lower the children of `program`, `subshell`, `compound_statement`,
    /// ... into a right-nested `;`/`&` list.
    pub fn lower_statements(&mut self, parent: TsNode) -> Result<Node, ParseError> {
        let mut items: Vec<(Node, ListOp)> = Vec::new();
        let mut cursor = parent.walk();
        for child in parent.children(&mut cursor) {
            if child.is_error() || child.is_missing() {
                return Err(self.syntax_error(child, format!("unexpected `{}`", self.text(child))));
            }
            if !child.is_named() {
                if child.kind() == "&" {
                    if let Some(last) = items.last_mut() {
                        last.1 = ListOp::Background;
                    }
                }
                continue;
            }
            if child.kind() == "comment" {
                continue;
            }
            if STATEMENT_KINDS.contains(&child.kind()) {
                let node = self.lower_statement(child)?;
                items.push((node, ListOp::Then));
            }
        }
        Ok(fold_sequence(items))
    }

    pub fn lower_statement(&mut self, n: TsNode) -> Result<Node, ParseError> {
        if n.is_error() || n.is_missing() {
            return Err(self.syntax_error(n, format!("unexpected `{}`", self.text(n))));
        }
        match n.kind() {
            "command" => {
                let cmd = self.lower_command(n)?;
                self.unwrap_command(cmd)
            }
            "pipeline" => self.lower_pipeline(n),
            "list" => self.lower_list(n),
            "redirected_statement" => self.lower_redirected(n),
            "subshell" => Ok(Node::Subshell {
                body: Box::new(self.lower_statements(n)?),
                redirects: vec![],
            }),
            "compound_statement" => Ok(Node::Group {
                body: Box::new(self.lower_statements(n)?),
                redirects: vec![],
            }),
            "variable_assignment" => {
                let assign = self.lower_assignment(n)?;
                Ok(Node::Assignment(vec![assign]))
            }
            "variable_assignments" => {
                let mut assigns = Vec::new();
                let mut cursor = n.walk();
                for child in n.named_children(&mut cursor) {
                    if child.kind() == "variable_assignment" {
                        assigns.push(self.lower_assignment(child)?);
                    }
                }
                Ok(Node::Assignment(assigns))
            }
            "declaration_command" | "unset_command" => self.lower_declaration(n),
            "test_command" => self.lower_test(n),
            "negated_command" => {
                let mut cursor = n.walk();
                let inner = n
                    .named_children(&mut cursor)
                    .find(|c| STATEMENT_KINDS.contains(&c.kind()));
                match inner {
                    Some(inner) => self.lower_statement(inner),
                    None => Ok(Node::Empty),
                }
            }
            "for_statement" | "c_style_for_statement" => self.lower_compound(n, CompoundKind::For),
            "while_statement" => {
                let kind = if n.child(0).map(|c| c.kind()) == Some("until") {
                    CompoundKind::Until
                } else {
                    CompoundKind::While
                };
                self.lower_compound(n, kind)
            }
            "if_statement" => self.lower_compound(n, CompoundKind::If),
            "case_statement" => self.lower_compound(n, CompoundKind::Case),
            "function_definition" => {
                let name = n
                    .child_by_field_name("name")
                    .map(|c| self.text(c).to_string())
                    .unwrap_or_default();
                self.lower_compound(n, CompoundKind::Function { name })
            }
            other => Err(self.syntax_error(n, format!("unsupported statement `{other}`"))),
        }
    }

    fn lower_pipeline(&mut self, n: TsNode) -> Result<Node, ParseError> {
        let mut stages = Vec::new();
        let mut cursor = n.walk();
        for child in n.children(&mut cursor) {
            if child.is_error() || child.is_missing() {
                return Err(self.syntax_error(child, "incomplete pipeline"));
            }
            if child.is_named() && STATEMENT_KINDS.contains(&child.kind()) {
                stages.push(self.lower_statement(child)?);
            }
        }
        match stages.len() {
            0 => Ok(Node::Empty),
            1 => Ok(stages.pop().expect("one stage")),
            _ => Ok(Node::Pipeline { stages }),
        }
    }

    fn lower_list(&mut self, n: TsNode) -> Result<Node, ParseError> {
        enum Work<'tree> {
            Visit(TsNode<'tree>),
            Build(ListOp),
        }

        let mut work = vec![Work::Visit(n)];
        let mut values = Vec::new();
        while let Some(item) = work.pop() {
            match item {
                Work::Visit(node) if node.kind() == "list" => {
                    let mut op = None;
                    let mut sides = Vec::with_capacity(2);
                    let mut cursor = node.walk();
                    for child in node.children(&mut cursor) {
                        if child.is_error() || child.is_missing() {
                            return Err(self.syntax_error(child, "incomplete list"));
                        }
                        if !child.is_named() {
                            match child.kind() {
                                "&&" => op = Some(ListOp::And),
                                "||" => op = Some(ListOp::Or),
                                _ => {}
                            }
                        } else if STATEMENT_KINDS.contains(&child.kind()) {
                            sides.push(child);
                        }
                    }
                    if sides.len() != 2 {
                        return Err(self.syntax_error(node, "list needs two sides"));
                    }
                    let right = sides.pop().expect("two sides");
                    let left = sides.pop().expect("two sides");
                    work.push(Work::Build(op.unwrap_or(ListOp::Then)));
                    work.push(Work::Visit(right));
                    work.push(Work::Visit(left));
                }
                Work::Visit(node) => values.push(self.lower_statement(node)?),
                Work::Build(op) => {
                    let right = values.pop().expect("lowered right side");
                    let left = values.pop().expect("lowered left side");
                    values.push(Node::List {
                        op,
                        left: Box::new(left),
                        right: Box::new(right),
                    });
                }
            }
        }
        if values.len() == 1 {
            Ok(values.pop().expect("one lowered list"))
        } else {
            Err(self.syntax_error(n, "list needs two sides"))
        }
    }

    /// `body redirect...`. tree-sitter attaches trailing redirects of a
    /// pipeline to the whole pipeline; bash applies them to the last stage,
    /// so that is where they go. Heredoc redirects may also carry the rest of
    /// the line (`cat <<EOF | grep x`), which is re-attached here.
    fn lower_redirected(&mut self, n: TsNode) -> Result<Node, ParseError> {
        let body_node = n.child_by_field_name("body");
        let mut body = match body_node {
            Some(b) => self.lower_statement(b)?,
            None => Node::Empty,
        };
        let mut redirects: Vec<LoweredRedirect> = Vec::new();
        let mut extra_args: Vec<LoweredWord> = Vec::new();
        let mut continuation: Option<Continuation> = None;
        // A bare number glued to the next redirect (`cmd 0<x`, `>& f 0>&1`)
        // is that redirect's descriptor; tree-sitter leaves it as a `number`
        // argument of the command or of the previous redirect.
        let mut pending_fd: Option<(u32, usize)> = None;
        if let (Some(b), Node::Simple(cmd)) = (body_node, &mut body) {
            let count = b.named_child_count();
            if let Some(last) = count.checked_sub(1).and_then(|i| b.named_child(i)) {
                if last.kind() == "number" && !cmd.args.is_empty() {
                    if let Ok(fd) = self.text(last).parse::<u32>() {
                        pending_fd = Some((fd, last.end_byte()));
                        cmd.args.pop();
                    }
                }
            }
        }
        let mut cursor = n.walk();
        for child in n.children(&mut cursor) {
            if Some(child) == body_node {
                continue;
            }
            let adjacent_fd = match pending_fd.take() {
                Some((fd, end)) if end == child.start_byte() => Some(fd),
                Some((fd, _)) => {
                    extra_args.push(LoweredWord {
                        word: Word::literal(fd.to_string()),
                        subs: vec![],
                    });
                    None
                }
                None => None,
            };
            match child.kind() {
                "file_redirect" => {
                    let (mut lowered, trailing) = self.lower_file_redirect_with_extras(child)?;
                    if lowered.redirect.fd.is_none() {
                        lowered.redirect.fd = adjacent_fd;
                    }
                    redirects.push(lowered);
                    for (word, end) in trailing {
                        let digits = !word.word.text.is_empty()
                            && word.word.text.bytes().all(|b| b.is_ascii_digit());
                        match word.word.text.parse::<u32>() {
                            Ok(fd) if digits && pending_fd.is_none() && !word.word.dynamic => {
                                pending_fd = Some((fd, end));
                            }
                            _ => extra_args.push(word),
                        }
                    }
                }
                "herestring_redirect" => redirects.push(self.lower_herestring(child)?),
                "heredoc_redirect" => {
                    let lowered = self.lower_heredoc(child)?;
                    redirects.push(lowered.redirect);
                    redirects.extend(lowered.extra_redirects);
                    extra_args.extend(lowered.extra_args);
                    if lowered.continuation.is_some() {
                        continuation = lowered.continuation;
                    }
                }
                _ if child.is_error() || child.is_missing() => {
                    return Err(self.syntax_error(child, "bad redirect"));
                }
                _ => {}
            }
        }
        if let Some((fd, _)) = pending_fd {
            extra_args.push(LoweredWord {
                word: Word::literal(fd.to_string()),
                subs: vec![],
            });
        }
        attach_redirects(&mut body, redirects);
        if !extra_args.is_empty() {
            attach_args(&mut body, extra_args);
        }
        match continuation {
            None => Ok(body),
            Some(Continuation::Pipe(stage)) => {
                let mut stages = match body {
                    Node::Pipeline { stages } => stages,
                    other => vec![other],
                };
                match stage {
                    Node::Pipeline { stages: more } => stages.extend(more),
                    other => stages.push(other),
                }
                Ok(Node::Pipeline { stages })
            }
            Some(Continuation::List(op, right)) => Ok(Node::List {
                op,
                left: Box::new(body),
                right: Box::new(right),
            }),
        }
    }

    fn lower_compound(&mut self, n: TsNode, kind: CompoundKind) -> Result<Node, ParseError> {
        let mut parts = Vec::new();
        self.collect_parts(n, &mut parts)?;
        Ok(Node::Compound {
            kind,
            parts,
            redirects: vec![],
        })
    }

    /// Gather every statement (and every substitution in header words) of a
    /// compound statement, in source order.
    fn collect_parts(&mut self, n: TsNode, parts: &mut Vec<Node>) -> Result<(), ParseError> {
        let mut cursor = n.walk();
        for child in n.children(&mut cursor) {
            if child.is_error() || child.is_missing() {
                return Err(self.syntax_error(child, format!("unexpected `{}`", self.text(child))));
            }
            if !child.is_named() || child.kind() == "comment" {
                continue;
            }
            let kind = child.kind();
            if STATEMENT_KINDS.contains(&kind) {
                parts.push(self.lower_statement(child)?);
            } else if CONTAINER_KINDS.contains(&kind) {
                self.collect_parts(child, parts)?;
            } else if is_word_kind(kind) {
                let lowered = self.lower_word(child)?;
                for (_, body) in lowered.subs {
                    parts.push(body);
                }
            } else if kind == "file_redirect" || kind == "heredoc_redirect" {
                // `f() { ...; } > log` — recorded on the compound by the
                // caller when wrapped in a redirected_statement; a direct
                // redirect field here is rare and only names a file.
                let redirect = if kind == "file_redirect" {
                    self.lower_file_redirect(child)?
                } else {
                    self.lower_heredoc(child)?.redirect
                };
                let mut holder = SimpleCommand::default();
                self.push_redirect(&mut holder, redirect);
                parts.push(Node::Simple(holder));
            }
        }
        Ok(())
    }

    // --- simple commands --------------------------------------------------

    fn lower_command(&mut self, n: TsNode) -> Result<SimpleCommand, ParseError> {
        let mut cmd = SimpleCommand::default();
        let mut arg_index = 0usize;
        let mut cursor = n.walk();
        for child in n.children(&mut cursor) {
            if child.is_error() || child.is_missing() {
                return Err(self.syntax_error(child, format!("unexpected `{}`", self.text(child))));
            }
            match child.kind() {
                "variable_assignment" => {
                    let assign = self.lower_assignment(child)?;
                    let env_index = cmd.env.len();
                    let mut assign = assign;
                    for mut sub in assign.substitutions.drain(..) {
                        sub.origin = SubstOrigin::Env(env_index);
                        cmd.substitutions.push(sub);
                    }
                    cmd.env.push(assign);
                }
                "command_name" => {
                    let inner = child.named_child(0).unwrap_or(child);
                    let lowered = self.lower_word(inner)?;
                    self.set_program(&mut cmd, lowered);
                }
                "file_redirect" => {
                    let (r, extra) = self.lower_file_redirect_with_extras(child)?;
                    self.push_redirect(&mut cmd, r);
                    for (lowered, _) in extra {
                        for (kind, body) in lowered.subs {
                            cmd.substitutions.push(Substitution {
                                kind,
                                origin: SubstOrigin::Arg(arg_index),
                                body,
                            });
                        }
                        cmd.args.push(lowered.word);
                        arg_index += 1;
                    }
                }
                "herestring_redirect" => {
                    let r = self.lower_herestring(child)?;
                    self.push_redirect(&mut cmd, r);
                }
                "heredoc_redirect" => {
                    let lowered = self.lower_heredoc(child)?;
                    self.push_redirect(&mut cmd, lowered.redirect);
                    for r in lowered.extra_redirects {
                        self.push_redirect(&mut cmd, r);
                    }
                }
                "subshell" => {
                    // `cmd ( ... )` is not valid bash at run time; keep the
                    // inner commands visible.
                    let body = self.lower_statements(child)?;
                    cmd.substitutions.push(Substitution {
                        kind: SubstKind::Command,
                        origin: SubstOrigin::Arg(arg_index),
                        body,
                    });
                    cmd.args.push(Word {
                        text: self.text(child).to_string(),
                        raw: self.text(child).to_string(),
                        dynamic: true,
                    });
                    arg_index += 1;
                }
                _ if child.is_named() => {
                    if child.kind() == "regex" || is_word_kind(child.kind()) {
                        let lowered = self.lower_word(child)?;
                        for (kind, body) in lowered.subs {
                            cmd.substitutions.push(Substitution {
                                kind,
                                origin: SubstOrigin::Arg(arg_index),
                                body,
                            });
                        }
                        cmd.args.push(lowered.word);
                        arg_index += 1;
                    }
                }
                _ => {
                    // `=~`, `==` and `$` appear as anonymous argument tokens.
                    let t = self.text(child);
                    if matches!(t, "=~" | "==" | "$") {
                        cmd.args.push(Word::literal(t));
                        arg_index += 1;
                    }
                }
            }
        }
        Ok(cmd)
    }

    fn push_redirect(&mut self, cmd: &mut SimpleCommand, r: LoweredRedirect) {
        push_redirect(cmd, r);
    }

    /// Install the program word: resolve `$var` names, normalise the path,
    /// and raise the obfuscation flags for a dynamic command name.
    pub(crate) fn set_program(&mut self, cmd: &mut SimpleCommand, lowered: LoweredWord) {
        let LoweredWord { mut word, subs } = lowered;
        let has_subst = !subs.is_empty();
        for (kind, body) in subs {
            cmd.substitutions.push(Substitution {
                kind,
                origin: SubstOrigin::Program,
                body,
            });
        }
        if has_subst {
            self.flags.set(ObfuscationFlag::EvalDynamic);
        } else if word.dynamic {
            if let Some(value) = self.resolve_var(&word.text) {
                word.text = value;
                word.dynamic = false;
                self.flags.set(ObfuscationFlag::VarIndirection);
            }
        }
        word.text = super::tree::normalise_program(&word.text);
        if word.dynamic && !has_subst {
            // `$HOME/bin/tool` names a literal program in a variable
            // directory; only a dynamic *name* (`$c`, `${!x}`, `r${IFS}m`)
            // hides what runs.
            if is_dynamic_text(&word.text) {
                self.flags.set(ObfuscationFlag::VarIndirection);
            } else {
                word.dynamic = false;
            }
        }
        cmd.program = word;
    }

    /// `$name` / `${name}` → the literal value assigned earlier, if any.
    fn resolve_var(&self, text: &str) -> Option<String> {
        let name = text
            .strip_prefix("${")
            .and_then(|s| s.strip_suffix('}'))
            .or_else(|| text.strip_prefix('$'))?;
        if name.is_empty() || !name.chars().all(|c| c.is_ascii_alphanumeric() || c == '_') {
            return None;
        }
        self.vars.get(name).cloned()
    }

    fn lower_assignment(&mut self, n: TsNode) -> Result<EnvAssign, ParseError> {
        let name = n
            .child_by_field_name("name")
            .map(|c| self.text(c).to_string())
            .unwrap_or_default();
        let mut cursor = n.walk();
        let append = n.children(&mut cursor).any(|c| c.kind() == "+=");
        drop(cursor);
        let (value, subs) = match n.child_by_field_name("value") {
            Some(v) => {
                let lowered = self.lower_word(v)?;
                (lowered.word, lowered.subs)
            }
            None => (Word::literal(""), vec![]),
        };
        if !value.dynamic && !append {
            self.vars.insert(name.clone(), value.text.clone());
        } else {
            self.vars.remove(&name);
        }
        Ok(EnvAssign {
            name,
            value,
            append,
            substitutions: subs
                .into_iter()
                .map(|(kind, body)| Substitution {
                    kind,
                    origin: SubstOrigin::Env(0),
                    body,
                })
                .collect(),
        })
    }

    /// `export X=1 Y`, `declare -x A=b`, `local`, `readonly`, `typeset`,
    /// `unset X`: a simple command whose assignments become `NAME=value`
    /// arguments.
    fn lower_declaration(&mut self, n: TsNode) -> Result<Node, ParseError> {
        let mut cmd = SimpleCommand::default();
        let mut arg_index = 0usize;
        let mut cursor = n.walk();
        for child in n.children(&mut cursor) {
            if child.is_error() || child.is_missing() {
                return Err(self.syntax_error(child, format!("unexpected `{}`", self.text(child))));
            }
            if !child.is_named() {
                if cmd.program.text.is_empty() {
                    cmd.program = Word::literal(self.text(child));
                }
                continue;
            }
            match child.kind() {
                "variable_assignment" => {
                    let assign = self.lower_assignment(child)?;
                    for sub in assign.substitutions {
                        cmd.substitutions.push(Substitution {
                            kind: sub.kind,
                            origin: SubstOrigin::Arg(arg_index),
                            body: sub.body,
                        });
                    }
                    cmd.args.push(Word {
                        text: format!("{}={}", assign.name, assign.value.text),
                        raw: self.text(child).to_string(),
                        dynamic: assign.value.dynamic,
                    });
                    arg_index += 1;
                }
                "variable_name" => {
                    cmd.args.push(Word::literal(self.text(child)));
                    arg_index += 1;
                }
                _ => {
                    let lowered = self.lower_word(child)?;
                    for (kind, body) in lowered.subs {
                        cmd.substitutions.push(Substitution {
                            kind,
                            origin: SubstOrigin::Arg(arg_index),
                            body,
                        });
                    }
                    cmd.args.push(lowered.word);
                    arg_index += 1;
                }
            }
        }
        Ok(Node::Simple(cmd))
    }

    /// `[ ... ]`, `[[ ... ]]`, `(( ... ))`: the opening bracket is the
    /// program, the expression is one argument. Substitutions inside are
    /// kept visible.
    fn lower_test(&mut self, n: TsNode) -> Result<Node, ParseError> {
        let mut cmd = SimpleCommand::default();
        let open = n.child(0).map(|c| self.text(c)).unwrap_or("[");
        cmd.program = Word::literal(open);
        let mut inner = String::new();
        let mut subs = Vec::new();
        let mut cursor = n.walk();
        for child in n.named_children(&mut cursor) {
            if child.is_error() || child.is_missing() {
                return Err(self.syntax_error(child, "bad test expression"));
            }
            if !inner.is_empty() {
                inner.push(' ');
            }
            inner.push_str(self.text(child));
            self.collect_substitutions(child, &mut subs)?;
        }
        for (kind, body) in subs {
            cmd.substitutions.push(Substitution {
                kind,
                origin: SubstOrigin::Arg(0),
                body,
            });
        }
        if !inner.is_empty() {
            cmd.args.push(Word {
                text: inner.clone(),
                raw: inner,
                dynamic: true,
            });
        }
        Ok(Node::Simple(cmd))
    }

    // --- redirects --------------------------------------------------------

    fn lower_file_redirect(&mut self, n: TsNode) -> Result<LoweredRedirect, ParseError> {
        let (lowered, _extra) = self.lower_file_redirect_with_extras(n)?;
        Ok(lowered)
    }

    /// Lower a `file_redirect`. Only the first word after the operator is
    /// the target; tree-sitter sometimes parks the following words of the
    /// command line inside the redirect node (`cmd > x y`, `>& f 0>&1`), so
    /// those are returned separately with their end offsets.
    fn lower_file_redirect_with_extras(
        &mut self,
        n: TsNode,
    ) -> Result<(LoweredRedirect, Vec<(LoweredWord, usize)>), ParseError> {
        let mut fd = None;
        let mut op = "";
        let mut target = String::new();
        let mut raw = String::new();
        let mut dynamic = false;
        let mut subs = Vec::new();
        let mut extra = Vec::new();
        let mut have_target = false;
        let mut cursor = n.walk();
        for child in n.children(&mut cursor) {
            if child.is_error() || child.is_missing() {
                return Err(self.syntax_error(child, "bad redirect"));
            }
            if child.kind() == "file_descriptor" {
                fd = self.text(child).parse().ok();
            } else if !child.is_named() {
                op = self.text(child);
            } else if have_target {
                let lowered = self.lower_word(child)?;
                extra.push((lowered, child.end_byte()));
            } else {
                let lowered = self.lower_word(child)?;
                target.push_str(&lowered.word.text);
                raw.push_str(&lowered.word.raw);
                dynamic |= lowered.word.dynamic;
                subs.extend(lowered.subs);
                have_target = true;
            }
        }
        let kind = match op {
            "<" => RedirectKind::Read,
            "<>" => RedirectKind::ReadWrite,
            ">" | ">|" => RedirectKind::Write,
            ">>" => RedirectKind::Append,
            "&>" => RedirectKind::BothWrite,
            "&>>" => RedirectKind::BothAppend,
            "<&" | "<&-" => RedirectKind::Dup,
            ">&" | ">&-" => {
                if target.is_empty() || target == "-" || target.chars().all(|c| c.is_ascii_digit())
                {
                    RedirectKind::Dup
                } else {
                    RedirectKind::BothWrite
                }
            }
            other => return Err(self.syntax_error(n, format!("unknown redirect `{other}`"))),
        };
        if matches!(op, "<&-" | ">&-") && target.is_empty() {
            target.push('-');
            raw.push('-');
        }
        Ok((
            LoweredRedirect {
                redirect: Redirect {
                    fd,
                    kind,
                    target: Word {
                        text: target,
                        raw,
                        dynamic,
                    },
                    body: None,
                },
                subs,
            },
            extra,
        ))
    }

    fn lower_herestring(&mut self, n: TsNode) -> Result<LoweredRedirect, ParseError> {
        let mut fd = None;
        let mut word = None;
        let mut cursor = n.walk();
        for child in n.children(&mut cursor) {
            if child.is_error() || child.is_missing() {
                return Err(self.syntax_error(child, "bad here-string"));
            }
            if child.kind() == "file_descriptor" {
                fd = self.text(child).parse().ok();
            } else if child.is_named() {
                word = Some(self.lower_word(child)?);
            }
        }
        let LoweredWord { word, subs } = word.unwrap_or(LoweredWord {
            word: Word::literal(""),
            subs: vec![],
        });
        Ok(LoweredRedirect {
            redirect: Redirect {
                fd,
                kind: RedirectKind::HereString,
                target: word,
                body: None,
            },
            subs,
        })
    }

    fn lower_heredoc(&mut self, n: TsNode) -> Result<LoweredHeredoc, ParseError> {
        let mut fd = None;
        let mut delimiter = Word::literal("");
        let mut body = String::new();
        let mut subs = Vec::new();
        let mut extra_redirects = Vec::new();
        let mut extra_args = Vec::new();
        let mut continuation = None;
        let mut list_op = None;
        let mut cursor = n.walk();
        for child in n.children(&mut cursor) {
            if child.is_error() || child.is_missing() {
                return Err(self.syntax_error(child, "bad heredoc"));
            }
            match child.kind() {
                "file_descriptor" => fd = self.text(child).parse().ok(),
                "heredoc_start" => {
                    let (name, quoted) = words::heredoc_delimiter(self.text(child));
                    delimiter = Word {
                        text: name,
                        raw: self.text(child).to_string(),
                        dynamic: !quoted,
                    };
                }
                "heredoc_body" => {
                    body = self.text(child).to_string();
                    self.collect_substitutions(child, &mut subs)?;
                }
                "heredoc_end" => {}
                "file_redirect" => extra_redirects.push(self.lower_file_redirect(child)?),
                "herestring_redirect" => extra_redirects.push(self.lower_herestring(child)?),
                "pipeline" => {
                    // `cat <<EOF | grep x`: the grammar nests the rest of the
                    // pipeline inside the heredoc.
                    let mut stages = Vec::new();
                    let mut inner = child.walk();
                    for s in child.children(&mut inner) {
                        if s.is_named() && STATEMENT_KINDS.contains(&s.kind()) {
                            stages.push(self.lower_statement(s)?);
                        }
                    }
                    continuation = Some(Continuation::Pipe(match stages.len() {
                        1 => stages.pop().expect("one"),
                        _ => Node::Pipeline { stages },
                    }));
                }
                "&&" => list_op = Some(ListOp::And),
                "||" => list_op = Some(ListOp::Or),
                kind if STATEMENT_KINDS.contains(&kind) => {
                    let right = self.lower_statement(child)?;
                    continuation = Some(Continuation::List(list_op.unwrap_or(ListOp::Then), right));
                }
                kind if is_word_kind(kind) => extra_args.push(self.lower_word(child)?),
                _ => {}
            }
        }
        Ok(LoweredHeredoc {
            redirect: LoweredRedirect {
                redirect: Redirect {
                    fd,
                    kind: RedirectKind::HereDoc,
                    target: delimiter,
                    body: Some(body),
                },
                subs,
            },
            extra_redirects,
            extra_args,
            continuation,
        })
    }

    // --- words ------------------------------------------------------------

    pub(crate) fn lower_word(&mut self, n: TsNode) -> Result<LoweredWord, ParseError> {
        let raw = self.text(n).to_string();
        let mut subs = Vec::new();
        let mut dynamic = false;
        let text = self.word_text(n, &mut subs, &mut dynamic)?;
        Ok(LoweredWord {
            word: Word { text, raw, dynamic },
            subs,
        })
    }

    fn word_text(
        &mut self,
        n: TsNode,
        subs: &mut Vec<(SubstKind, Node)>,
        dynamic: &mut bool,
    ) -> Result<String, ParseError> {
        if n.is_error() || n.is_missing() {
            return Err(self.syntax_error(n, format!("unexpected `{}`", self.text(n))));
        }
        let raw = self.text(n);
        Ok(match n.kind() {
            "word"
            | "test_operator"
            | "extglob_pattern"
            | "regex"
            | "variable_name"
            | "special_variable_name"
            | "heredoc_start" => words::unescape_unquoted(raw),
            "number" | "brace_expression" | "array" => {
                self.collect_substitutions(n, subs)?;
                if n.named_child_count() > 0 && n.kind() == "number" {
                    *dynamic = true;
                }
                raw.to_string()
            }
            "raw_string" => raw
                .strip_prefix('\'')
                .and_then(|s| s.strip_suffix('\''))
                .unwrap_or(raw)
                .to_string(),
            "ansi_c_string" => {
                let body = raw
                    .strip_prefix("$'")
                    .and_then(|s| s.strip_suffix('\''))
                    .unwrap_or(raw);
                let decoded = words::decode_ansi_c(body);
                if decoded.numeric_escape {
                    self.flags.set(ObfuscationFlag::HexEscape);
                }
                decoded.text
            }
            "string" | "translated_string" => {
                let mut out = String::new();
                let mut cursor = n.walk();
                for child in n.children(&mut cursor) {
                    if child.is_error() || child.is_missing() {
                        return Err(self.syntax_error(child, "unterminated string"));
                    }
                    if !child.is_named() {
                        // A lone `$` (`"$'x'"`, `"a$"`) is literal text.
                        if child.kind() == "$" {
                            out.push('$');
                        }
                        continue;
                    }
                    match child.kind() {
                        "string_content" => {
                            out.push_str(&words::unescape_double_quoted(self.text(child)))
                        }
                        "string" => out.push_str(&self.word_text(child, subs, dynamic)?),
                        _ => out.push_str(&self.word_text(child, subs, dynamic)?),
                    }
                }
                out
            }
            "simple_expansion" => {
                *dynamic = true;
                raw.to_string()
            }
            "expansion" => {
                *dynamic = true;
                if n.child_by_field_name("operator")
                    .map(|op| self.text(op) == "!")
                    .unwrap_or(false)
                {
                    self.flags.set(ObfuscationFlag::VarIndirection);
                }
                self.collect_substitutions(n, subs)?;
                raw.to_string()
            }
            "arithmetic_expansion" => {
                *dynamic = true;
                self.collect_substitutions(n, subs)?;
                raw.to_string()
            }
            "command_substitution" => {
                *dynamic = true;
                let kind = if raw.starts_with("$(") {
                    SubstKind::Command
                } else {
                    SubstKind::Backtick
                };
                let body = self.lower_statements(n)?;
                subs.push((kind, body));
                raw.to_string()
            }
            "process_substitution" => {
                *dynamic = true;
                let kind = if raw.starts_with("<(") {
                    SubstKind::ProcessIn
                } else {
                    SubstKind::ProcessOut
                };
                let body = self.lower_statements(n)?;
                subs.push((kind, body));
                raw.to_string()
            }
            "concatenation" => {
                let mut out = String::new();
                let mut cursor = n.walk();
                for child in n.children(&mut cursor) {
                    if child.is_error() || child.is_missing() {
                        return Err(self.syntax_error(child, "bad word"));
                    }
                    if child.is_named() {
                        out.push_str(&self.word_text(child, subs, dynamic)?);
                    } else if child.kind() == "$" {
                        out.push('$');
                    }
                }
                out
            }
            _ => {
                self.collect_substitutions(n, subs)?;
                raw.to_string()
            }
        })
    }

    /// Find command and process substitutions anywhere below `n` (without
    /// descending into them) and lower their bodies.
    fn collect_substitutions(
        &mut self,
        n: TsNode,
        subs: &mut Vec<(SubstKind, Node)>,
    ) -> Result<(), ParseError> {
        let mut cursor = n.walk();
        let children: Vec<TsNode> = n.named_children(&mut cursor).collect();
        for child in children {
            if child.is_error() || child.is_missing() {
                return Err(self.syntax_error(child, format!("unexpected `{}`", self.text(child))));
            }
            match child.kind() {
                "command_substitution" | "process_substitution" => {
                    let mut dynamic = false;
                    self.word_text(child, subs, &mut dynamic)?;
                }
                "expansion" => {
                    if child
                        .child_by_field_name("operator")
                        .map(|op| self.text(op) == "!")
                        .unwrap_or(false)
                    {
                        self.flags.set(ObfuscationFlag::VarIndirection);
                    }
                    self.collect_substitutions(child, subs)?;
                }
                _ => self.collect_substitutions(child, subs)?,
            }
        }
        Ok(())
    }
}

pub(crate) struct LoweredRedirect {
    pub redirect: Redirect,
    pub subs: Vec<(SubstKind, Node)>,
}

fn push_redirect(cmd: &mut SimpleCommand, r: LoweredRedirect) {
    let index = cmd.redirects.len();
    for (kind, body) in r.subs {
        cmd.substitutions.push(Substitution {
            kind,
            origin: SubstOrigin::Redirect(index),
            body,
        });
    }
    cmd.redirects.push(r.redirect);
}

struct LoweredHeredoc {
    redirect: LoweredRedirect,
    extra_redirects: Vec<LoweredRedirect>,
    extra_args: Vec<LoweredWord>,
    continuation: Option<Continuation>,
}

enum Continuation {
    Pipe(Node),
    List(ListOp, Node),
}

/// `true` when `text` still holds a `$...` expansion or a backtick.
pub(crate) fn is_dynamic_text(text: &str) -> bool {
    text.contains('$') || text.contains('`')
}

/// Replace every unquoted `$IFS` / `${IFS}` in `text` with a space. Returns
/// `None` when the word has no IFS reference.
fn replace_ifs(text: &str) -> Option<String> {
    if !text.contains("$IFS") && !text.contains("${IFS}") {
        return None;
    }
    let mut out = String::with_capacity(text.len());
    let mut rest = text;
    let mut found = false;
    while let Some(pos) = rest.find('$') {
        let (head, tail) = rest.split_at(pos);
        out.push_str(head);
        if let Some(after) = tail.strip_prefix("${IFS}") {
            out.push(' ');
            rest = after;
            found = true;
        } else if let Some(after) = tail.strip_prefix("$IFS") {
            let next_is_name = after
                .chars()
                .next()
                .map(|c| c.is_ascii_alphanumeric() || c == '_')
                .unwrap_or(false);
            if next_is_name {
                out.push_str("$IFS");
            } else {
                out.push(' ');
                found = true;
            }
            rest = after;
        } else {
            out.push('$');
            rest = &tail[1..];
        }
    }
    out.push_str(rest);
    found.then_some(out)
}

/// `rm${IFS}-rf${IFS}~`: with the default `IFS`, each reference splits the
/// word like a space would. Words carrying substitutions are left alone.
/// Returns `true` when anything changed.
pub(crate) fn split_ifs_words(cmd: &mut SimpleCommand) -> bool {
    let has_sub_at = |cmd: &SimpleCommand, origin: SubstOrigin| {
        cmd.substitutions.iter().any(|s| s.origin == origin)
    };
    let pieces_of = |word: &Word| -> Option<Vec<Word>> {
        if !word.dynamic {
            return None;
        }
        let replaced = replace_ifs(&word.text)?;
        let pieces: Vec<Word> = replaced
            .split(' ')
            .filter(|p| !p.is_empty())
            .map(|p| Word {
                text: p.to_string(),
                raw: word.raw.clone(),
                dynamic: is_dynamic_text(p),
            })
            .collect();
        (!pieces.is_empty()).then_some(pieces)
    };

    let mut changed = false;
    let mut new_args: Vec<Word> = Vec::with_capacity(cmd.args.len());
    // Old argument index -> new index of its first piece.
    let mut index_map: Vec<usize> = Vec::with_capacity(cmd.args.len());

    if !has_sub_at(cmd, SubstOrigin::Program) {
        if let Some(mut pieces) = pieces_of(&cmd.program) {
            let mut program = pieces.remove(0);
            program.text = super::tree::normalise_program(&program.text);
            cmd.program = program;
            new_args.extend(pieces);
            changed = true;
        }
    }
    for (i, arg) in cmd.args.iter().enumerate() {
        index_map.push(new_args.len());
        match pieces_of(arg) {
            Some(pieces) if !has_sub_at(cmd, SubstOrigin::Arg(i)) => {
                new_args.extend(pieces);
                changed = true;
            }
            _ => new_args.push(arg.clone()),
        }
    }
    if !changed {
        return false;
    }
    for sub in &mut cmd.substitutions {
        if let SubstOrigin::Arg(i) = sub.origin {
            sub.origin = SubstOrigin::Arg(index_map[i]);
        }
    }
    cmd.args = new_args;
    true
}

fn is_word_kind(kind: &str) -> bool {
    matches!(
        kind,
        "word"
            | "string"
            | "raw_string"
            | "translated_string"
            | "ansi_c_string"
            | "number"
            | "expansion"
            | "simple_expansion"
            | "command_substitution"
            | "process_substitution"
            | "arithmetic_expansion"
            | "brace_expression"
            | "concatenation"
            | "array"
            | "extglob_pattern"
            | "test_operator"
    )
}

/// Right-nest `[(a, op_after_a), (b, op_after_b), (c, _)]` into
/// `List(op_a, a, List(op_b, b, c))`. The operator after the last statement
/// is dropped (`cmd &` alone is just `cmd`).
fn fold_sequence(mut items: Vec<(Node, ListOp)>) -> Node {
    let Some((last, _)) = items.pop() else {
        return Node::Empty;
    };
    items
        .into_iter()
        .rev()
        .fold(last, |right, (left, op)| Node::List {
            op,
            left: Box::new(left),
            right: Box::new(right),
        })
}

/// Attach redirects to the node they apply to: the last stage of a pipeline,
/// the command itself, or the group/subshell/compound.
fn attach_redirects(node: &mut Node, redirects: Vec<LoweredRedirect>) {
    if redirects.is_empty() {
        return;
    }
    match node {
        Node::Simple(cmd) => {
            for r in redirects {
                push_redirect(cmd, r);
            }
        }
        Node::Pipeline { stages } => {
            if let Some(last) = stages.last_mut() {
                attach_redirects(last, redirects);
            }
        }
        Node::List { right, .. } => attach_redirects(right, redirects),
        Node::Subshell { .. } | Node::Group { .. } | Node::Compound { .. } => {
            let mut holder = SimpleCommand::default();
            for r in redirects {
                push_redirect(&mut holder, r);
            }
            let subs = std::mem::take(&mut holder.substitutions);
            let plain = holder.redirects;
            match node {
                Node::Subshell { redirects: r, .. }
                | Node::Group { redirects: r, .. }
                | Node::Compound { redirects: r, .. } => r.extend(plain),
                _ => unreachable!(),
            }
            if !subs.is_empty() {
                // `( ... ) > $(x)`: keep the substitution visible.
                let holder = SimpleCommand {
                    substitutions: subs,
                    ..SimpleCommand::default()
                };
                let old = std::mem::replace(node, Node::Empty);
                *node = Node::List {
                    op: ListOp::Then,
                    left: Box::new(old),
                    right: Box::new(Node::Simple(holder)),
                };
            }
        }
        Node::Assignment(_) | Node::Empty => {
            let mut cmd = SimpleCommand::default();
            for r in redirects {
                push_redirect(&mut cmd, r);
            }
            let old = std::mem::replace(node, Node::Empty);
            *node = match old {
                Node::Empty => Node::Simple(cmd),
                other => Node::List {
                    op: ListOp::Then,
                    left: Box::new(other),
                    right: Box::new(Node::Simple(cmd)),
                },
            };
        }
    }
}

/// Arguments written after a heredoc operator (`cat <<EOF file`) belong to
/// the command.
fn attach_args(node: &mut Node, args: Vec<LoweredWord>) {
    match node {
        Node::Simple(cmd) => {
            for lowered in args {
                let index = cmd.args.len();
                for (kind, body) in lowered.subs {
                    cmd.substitutions.push(Substitution {
                        kind,
                        origin: SubstOrigin::Arg(index),
                        body,
                    });
                }
                cmd.args.push(lowered.word);
            }
        }
        Node::Pipeline { stages } => {
            if let Some(last) = stages.last_mut() {
                attach_args(last, args);
            }
        }
        _ => {}
    }
}
