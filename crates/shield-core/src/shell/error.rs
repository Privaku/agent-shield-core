use std::fmt;

/// The command line could not be turned into a [`super::CommandTree`].
///
/// **Callers must treat this as an Ask, never as an Allow.** A command the
/// parser cannot understand is exactly the kind of input an attacker would
/// craft to slip past the rules, so the policy engine falls back to a human
/// (or to Deny in autonomous mode) instead of guessing.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ParseError {
    /// What went wrong.
    pub kind: ParseErrorKind,
    /// Byte offset into the (innermost) command text where the problem was
    /// detected.
    pub offset: usize,
    /// 1-based line of `offset`.
    pub line: usize,
    /// 1-based column of `offset` in characters.
    pub column: usize,
    /// Human-readable detail (the offending node kind, the depth reached, ...).
    pub detail: String,
}

/// Category of a [`ParseError`].
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum ParseErrorKind {
    /// The grammar rejected the text (unbalanced quotes, stray operator, ...).
    Syntax,
    /// A string inside `sh -c '...'` or `eval '...'` failed to parse.
    Nested,
    /// The text contains a NUL byte, which no shell accepts.
    NulByte,
    /// tree-sitter returned no tree at all (cancelled or out of memory).
    Internal,
}

impl ParseErrorKind {
    pub fn name(self) -> &'static str {
        match self {
            ParseErrorKind::Syntax => "syntax",
            ParseErrorKind::Nested => "nested",
            ParseErrorKind::NulByte => "nul_byte",
            ParseErrorKind::Internal => "internal",
        }
    }
}

impl ParseError {
    pub(crate) fn new(kind: ParseErrorKind, src: &str, offset: usize, detail: String) -> Self {
        let offset = offset.min(src.len());
        let before = &src[..offset];
        let line = before.matches('\n').count() + 1;
        let column = before
            .rsplit('\n')
            .next()
            .map(|l| l.chars().count())
            .unwrap_or(0)
            + 1;
        ParseError {
            kind,
            offset,
            line,
            column,
            detail,
        }
    }
}

impl fmt::Display for ParseError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(
            f,
            "shell parse error ({}) at {}:{}: {}",
            self.kind.name(),
            self.line,
            self.column,
            self.detail
        )
    }
}

impl std::error::Error for ParseError {}
