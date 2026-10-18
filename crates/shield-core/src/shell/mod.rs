//! Bash command parser and normaliser (M4).
//!
//! [`parse`] turns a raw command line into a [`CommandTree`]: a tree of
//! pipelines, lists (`&&`, `||`, `;`, `&`), subshells, groups, compound
//! statements and [`SimpleCommand`]s, with command/process substitutions,
//! redirects (including heredocs) and environment prefixes attached to the
//! command they belong to. The grammar is `tree-sitter-bash`.
//!
//! On top of the syntax tree the parser:
//!
//! - **unwraps** `sudo`/`doas`, `env`, `nice`, `nohup`, `time`, `command`,
//!   `builtin`, `exec`, `xargs`, `timeout`, `chroot`, `sh`/`bash`/`zsh`
//!   `-c '...'` and `su -c '...'` (recursively, at most
//!   [`MAX_UNWRAP_DEPTH`] levels), `eval` and `find ... -exec`, recording
//!   the stripped names in [`SimpleCommand::wrappers`];
//! - **normalises** program names (`/bin/rm`, `\rm`, `"r"m`, `$'\x72\x6d'`
//!   all become `rm`), removes quotes, decodes ANSI-C strings, joins
//!   concatenated word parts and splits `rm${IFS}-rf` on `$IFS` as the
//!   default `IFS` would;
//! - **flags obfuscation** ([`ObfuscationFlags`]): `base64_decode`,
//!   `hex_escape`, `var_indirection`, `eval_dynamic`.
//!
//! # Failure is Ask
//!
//! When the text does not parse, [`parse`] returns a [`ParseError`].
//! **Callers must treat a `ParseError` as an Ask decision (Deny in
//! autonomous mode), never as an Allow.** The engine never guesses what an
//! unparsable command does; `model::ArgvTree::Unparsed { raw }` exists to
//! carry such a command through the rest of the pipeline.
//!
//! # Bridge to the wire model
//!
//! [`CommandTree::to_argv_tree`] converts the tree into
//! [`crate::model::ArgvTree`] and [`ObfuscationFlags::to_vec`] fills
//! `ActionKind::Shell::obfuscation`, so M6 can build `Action::Shell`
//! without knowing about tree-sitter.
//!
//! ```
//! use shield_core::shell::parse;
//!
//! let tree = parse("sudo -E env X=1 /bin/rm -r /").unwrap();
//! let cmds = tree.simple_commands();
//! assert_eq!(cmds.len(), 1);
//! assert_eq!(cmds[0].argv(), ["rm", "-r", "/"]);
//! assert_eq!(cmds[0].wrappers, ["sudo", "env"]);
//! assert_eq!(cmds[0].env[0].to_string(), "X=1");
//! ```

mod error;
mod lower;
mod obfuscation;
mod tree;
mod unwrap;
mod words;

use std::cell::RefCell;
use std::collections::HashMap;

pub use error::{ParseError, ParseErrorKind};
pub use tree::{
    normalise_program, CommandTree, CompoundKind, EnvAssign, Node, ObfuscationFlags, Redirect,
    RedirectKind, SimpleCommand, SubstKind, SubstOrigin, Substitution, Word,
};
pub use unwrap::{MAX_UNWRAP_DEPTH, SHELLS};

pub use crate::model::ObfuscationFlag;

thread_local! {
    static PARSER: RefCell<tree_sitter::Parser> = RefCell::new(new_parser());
}

fn new_parser() -> tree_sitter::Parser {
    let mut parser = tree_sitter::Parser::new();
    parser
        .set_language(&tree_sitter_bash::LANGUAGE.into())
        .expect("tree-sitter-bash grammar matches the tree-sitter runtime");
    parser
}

/// Parse a command line into a [`CommandTree`].
///
/// See the [module documentation](self) for what is normalised and why a
/// [`ParseError`] must be treated as **Ask**.
pub fn parse(raw: &str) -> Result<CommandTree, ParseError> {
    let (root, mut flags) = parse_depth(raw, 0, HashMap::new())?;
    let mut tree = CommandTree {
        raw: raw.to_string(),
        root,
        obfuscation: ObfuscationFlags::default(),
    };
    obfuscation::scan(&tree, &mut flags);
    tree.obfuscation = flags;
    Ok(tree)
}

/// Parse `src` at nesting level `depth` (0 for the command line itself,
/// 1 for the string inside `sh -c '...'`, ...).
pub(crate) fn parse_depth(
    src: &str,
    depth: usize,
    vars: HashMap<String, String>,
) -> Result<(Node, ObfuscationFlags), ParseError> {
    if let Some(offset) = src.find('\0') {
        return Err(ParseError::new(
            ParseErrorKind::NulByte,
            src,
            offset,
            "NUL byte in command text".to_string(),
        ));
    }
    let tree = PARSER.with(|p| {
        let mut parser = p.borrow_mut();
        let parsed = parser.parse(src, None);
        if src.contains("<>")
            && parsed
                .as_ref()
                .is_some_and(|tree| tree.root_node().has_error())
        {
            // tree-sitter-bash 0.25 omits Bash's `<>` read/write redirect.
            // Parse an equal-length supported token so byte ranges still
            // address the original source; lowering reads the real operator.
            let masked = src.replace("<>", ">>");
            if let Some(fallback) = parser.parse(&masked, None) {
                if !fallback.root_node().has_error() {
                    return Some(fallback);
                }
            }
        }
        parsed
    });
    let Some(tree) = tree else {
        return Err(ParseError::new(
            ParseErrorKind::Internal,
            src,
            0,
            "tree-sitter returned no tree".to_string(),
        ));
    };
    let root = tree.root_node();
    if root.has_error() {
        let (offset, detail) = first_error(root, src);
        return Err(ParseError::new(ParseErrorKind::Syntax, src, offset, detail));
    }
    let mut lower = lower::Lower::new(src, depth, vars);
    let node = lower.lower_statements(root)?;
    Ok((node, lower.flags))
}

/// Locate the first `ERROR` or missing node for the error message.
fn first_error(root: tree_sitter::Node, src: &str) -> (usize, String) {
    let mut stack = vec![root];
    while let Some(n) = stack.pop() {
        if n.is_missing() {
            return (n.start_byte(), format!("missing `{}`", n.kind()));
        }
        if n.is_error() {
            let text: String = src[n.byte_range()].chars().take(40).collect();
            return (
                n.start_byte(),
                if text.is_empty() {
                    "syntax error".to_string()
                } else {
                    format!("unexpected `{text}`")
                },
            );
        }
        if n.has_error() {
            let mut cursor = n.walk();
            let children: Vec<_> = n.children(&mut cursor).collect();
            stack.extend(children.into_iter().rev());
        }
    }
    (0, "syntax error".to_string())
}
