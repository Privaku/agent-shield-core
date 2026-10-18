//! Quote removal and escape decoding for single shell words.

/// Result of decoding one quoted or unquoted fragment.
#[derive(Debug, Default, PartialEq, Eq)]
pub(crate) struct Decoded {
    pub text: String,
    /// `true` when a numeric escape (`\xHH`, `\NNN`, `\uHHHH`) was decoded.
    pub numeric_escape: bool,
}

/// Unquoted word: a backslash removes itself and keeps the next character
/// literally (`\rm` → `rm`, `a\ b` → `a b`, `\;` → `;`).
pub(crate) fn unescape_unquoted(raw: &str) -> String {
    let mut out = String::with_capacity(raw.len());
    let mut chars = raw.chars();
    while let Some(c) = chars.next() {
        if c == '\\' {
            match chars.next() {
                Some('\n') => {}
                Some(next) => out.push(next),
                None => out.push('\\'),
            }
        } else {
            out.push(c);
        }
    }
    out
}

/// Inside `"..."` only `\$`, `` \` ``, `\"`, `\\` and `\<newline>` are
/// escapes; any other backslash is literal.
pub(crate) fn unescape_double_quoted(raw: &str) -> String {
    let mut out = String::with_capacity(raw.len());
    let mut chars = raw.chars().peekable();
    while let Some(c) = chars.next() {
        if c == '\\' {
            match chars.peek() {
                Some('$') | Some('`') | Some('"') | Some('\\') => {
                    out.push(chars.next().expect("peeked"));
                }
                Some('\n') => {
                    chars.next();
                }
                _ => out.push('\\'),
            }
        } else {
            out.push(c);
        }
    }
    out
}

/// Decode the body of an ANSI-C quoted string `$'...'` (the text between the
/// quotes).
pub(crate) fn decode_ansi_c(body: &str) -> Decoded {
    let mut out = Decoded::default();
    let mut bytes: Vec<u8> = Vec::with_capacity(body.len());
    let chars: Vec<char> = body.chars().collect();
    let mut i = 0;
    while i < chars.len() {
        let c = chars[i];
        if c != '\\' {
            push_char(&mut bytes, c);
            i += 1;
            continue;
        }
        i += 1;
        let Some(&e) = chars.get(i) else {
            bytes.push(b'\\');
            break;
        };
        i += 1;
        match e {
            'a' => bytes.push(0x07),
            'b' => bytes.push(0x08),
            'e' | 'E' => bytes.push(0x1b),
            'f' => bytes.push(0x0c),
            'n' => bytes.push(b'\n'),
            'r' => bytes.push(b'\r'),
            't' => bytes.push(b'\t'),
            'v' => bytes.push(0x0b),
            '\\' => bytes.push(b'\\'),
            '\'' => bytes.push(b'\''),
            '"' => bytes.push(b'"'),
            '?' => bytes.push(b'?'),
            'x' => {
                let (value, used) = take_radix(&chars[i..], 16, 2);
                if used == 0 {
                    bytes.extend_from_slice(b"\\x");
                } else {
                    out.numeric_escape = true;
                    bytes.push(value as u8);
                    i += used;
                }
            }
            '0'..='7' => {
                let (value, used) = take_radix(&chars[i - 1..], 8, 3);
                out.numeric_escape = true;
                bytes.push((value & 0xff) as u8);
                i += used - 1;
            }
            'u' | 'U' => {
                let max = if e == 'u' { 4 } else { 8 };
                let (value, used) = take_radix(&chars[i..], 16, max);
                if used == 0 {
                    bytes.push(b'\\');
                    push_char(&mut bytes, e);
                } else {
                    out.numeric_escape = true;
                    match char::from_u32(value) {
                        Some(ch) => push_char(&mut bytes, ch),
                        None => bytes.extend_from_slice("\u{fffd}".as_bytes()),
                    }
                    i += used;
                }
            }
            'c' => {
                if let Some(&ctrl) = chars.get(i) {
                    i += 1;
                    let upper = ctrl.to_ascii_uppercase() as u32;
                    bytes.push((upper ^ 0x40) as u8);
                } else {
                    bytes.extend_from_slice(b"\\c");
                }
            }
            other => {
                bytes.push(b'\\');
                push_char(&mut bytes, other);
            }
        }
    }
    out.text = String::from_utf8_lossy(&bytes).into_owned();
    out
}

fn push_char(bytes: &mut Vec<u8>, c: char) {
    let mut buf = [0u8; 4];
    bytes.extend_from_slice(c.encode_utf8(&mut buf).as_bytes());
}

/// Read up to `max` digits in `radix`; returns the value and digits used.
fn take_radix(chars: &[char], radix: u32, max: usize) -> (u32, usize) {
    let mut value: u32 = 0;
    let mut used = 0;
    for &c in chars.iter().take(max) {
        match c.to_digit(radix) {
            Some(d) => {
                value = value.wrapping_mul(radix).wrapping_add(d);
                used += 1;
            }
            None => break,
        }
    }
    (value, used)
}

/// Strip one layer of matching quotes from a heredoc delimiter
/// (`'EOF'`, `"EOF"`, `\EOF` → `EOF`). Returns the delimiter and whether it
/// was quoted (a quoted delimiter disables expansion in the body).
pub(crate) fn heredoc_delimiter(raw: &str) -> (String, bool) {
    let trimmed = raw.trim();
    if let Some(inner) = trimmed
        .strip_prefix('\'')
        .and_then(|s| s.strip_suffix('\''))
        .or_else(|| trimmed.strip_prefix('"').and_then(|s| s.strip_suffix('"')))
    {
        return (inner.to_string(), true);
    }
    if let Some(inner) = trimmed.strip_prefix('\\') {
        return (inner.to_string(), true);
    }
    (trimmed.to_string(), false)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn unquoted_backslash_is_removed() {
        assert_eq!(unescape_unquoted("\\rm"), "rm");
        assert_eq!(unescape_unquoted("a\\ b"), "a b");
        assert_eq!(unescape_unquoted("\\;"), ";");
        assert_eq!(unescape_unquoted("trailing\\"), "trailing\\");
        assert_eq!(unescape_unquoted("a\\\nb"), "ab");
    }

    #[test]
    fn double_quoted_keeps_unknown_escapes() {
        assert_eq!(unescape_double_quoted("a\\\"b"), "a\"b");
        assert_eq!(unescape_double_quoted("\\$HOME"), "$HOME");
        assert_eq!(unescape_double_quoted("\\n"), "\\n");
        assert_eq!(unescape_double_quoted("x\\\\y"), "x\\y");
    }

    #[test]
    fn ansi_c_decodes_hex_octal_unicode_and_controls() {
        let d = decode_ansi_c("\\x72\\x6d");
        assert_eq!(d.text, "rm");
        assert!(d.numeric_escape);

        let d = decode_ansi_c("\\162\\155");
        assert_eq!(d.text, "rm");
        assert!(d.numeric_escape);

        let d = decode_ansi_c("\\u0072m");
        assert_eq!(d.text, "rm");
        assert!(d.numeric_escape);

        let d = decode_ansi_c("a\\tb\\n\\'q\\'");
        assert_eq!(d.text, "a\tb\n'q'");
        assert!(!d.numeric_escape);

        assert_eq!(decode_ansi_c("\\cA").text, "\u{1}");
        assert_eq!(decode_ansi_c("\\q").text, "\\q");
        assert_eq!(decode_ansi_c("\\x").text, "\\x");
        assert_eq!(decode_ansi_c("tail\\").text, "tail\\");
    }

    #[test]
    fn heredoc_delimiters_lose_their_quotes() {
        assert_eq!(heredoc_delimiter("EOF"), ("EOF".into(), false));
        assert_eq!(heredoc_delimiter("'EOF'"), ("EOF".into(), true));
        assert_eq!(heredoc_delimiter("\"EOF\""), ("EOF".into(), true));
        assert_eq!(heredoc_delimiter("\\EOF"), ("EOF".into(), true));
    }
}
