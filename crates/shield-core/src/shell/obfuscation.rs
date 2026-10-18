//! Post-pass that raises obfuscation flags from the finished tree. Flags that
//! depend on how a word was *written* (ANSI-C escapes, `${!x}`, dynamic
//! command names) are raised during lowering; this pass looks at what the
//! commands *do*.

use super::tree::{CommandTree, ObfuscationFlags, SimpleCommand};
use crate::model::ObfuscationFlag;

const INTERPRETERS: &[&str] = &[
    "python", "python2", "python3", "perl", "ruby", "node", "nodejs", "php", "lua",
];

const BASE64_SNIPPETS: &[&str] = &[
    "b64decode",
    "base64.decode",
    "decode_base64",
    "base64_decode",
    "atob(",
    "Base64.decode",
    "Base64.strict_decode",
    "from('base64')",
    "from(\"base64\")",
    ", 'base64')",
    ", \"base64\")",
    "unpack('m",
    "unpack(\"m",
];

const EXEC_SNIPPETS: &[&str] = &["exec(", "eval(", "Function(", "vm.runIn"];

pub(crate) fn scan(tree: &CommandTree, flags: &mut ObfuscationFlags) {
    for cmd in tree.simple_commands() {
        scan_command(cmd, flags);
    }
}

fn scan_command(cmd: &SimpleCommand, flags: &mut ObfuscationFlags) {
    let program = cmd.program.text.as_str();
    let args = cmd.arg_texts();

    match program {
        "base64" | "basenc" => {
            if cmd.has_any_flag(["-d", "-D", "--decode"]) {
                flags.set(ObfuscationFlag::Base64Decode);
            }
        }
        "openssl" => {
            let base64_mode = args
                .iter()
                .any(|a| matches!(*a, "base64" | "enc" | "-base64" | "-a"));
            if base64_mode && cmd.has_any_flag(["-d", "-decode"]) {
                flags.set(ObfuscationFlag::Base64Decode);
            }
        }
        "xxd" => {
            if cmd.has_any_flag(["-r", "--revert"]) {
                flags.set(ObfuscationFlag::HexEscape);
            }
        }
        "echo" | "printf" => {
            let interprets = program == "printf" || cmd.has_flag("-e");
            if interprets && args.iter().any(|a| has_numeric_escape(a)) {
                flags.set(ObfuscationFlag::HexEscape);
            }
        }
        p if INTERPRETERS.contains(&p) || p.starts_with("python") => {
            let inline = cmd.has_any_flag(["-c", "-e", "-r", "-E", "-p"]);
            for a in &args {
                if BASE64_SNIPPETS.iter().any(|s| a.contains(s)) {
                    flags.set(ObfuscationFlag::Base64Decode);
                }
                if a.contains("fromhex(")
                    || a.contains("decode('hex')")
                    || a.contains("decode(\"hex\")")
                    || a.contains("pack('H")
                    || a.contains("pack(\"H")
                    || (inline && has_numeric_escape(a))
                {
                    flags.set(ObfuscationFlag::HexEscape);
                }
                if inline && EXEC_SNIPPETS.iter().any(|s| a.contains(s)) {
                    flags.set(ObfuscationFlag::EvalDynamic);
                }
            }
        }
        _ => {}
    }
}

/// `\xHH`, `\NNN` (octal), `\uHHHH` or `\0NNN` somewhere in `text`.
fn has_numeric_escape(text: &str) -> bool {
    let bytes = text.as_bytes();
    let mut i = 0;
    while i + 1 < bytes.len() {
        if bytes[i] == b'\\' {
            let next = bytes[i + 1];
            let hex_after = |n: usize| {
                bytes
                    .get(i + n)
                    .map(|b| b.is_ascii_hexdigit())
                    .unwrap_or(false)
            };
            if (next == b'x' && hex_after(2))
                || ((next == b'u' || next == b'U') && hex_after(2))
                || (next.is_ascii_digit() && (b'0'..=b'7').contains(&next) && {
                    bytes
                        .get(i + 2)
                        .map(|b| (b'0'..=b'7').contains(b))
                        .unwrap_or(false)
                })
            {
                return true;
            }
        }
        i += 1;
    }
    false
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn numeric_escape_detection() {
        assert!(has_numeric_escape("\\x72\\x6d"));
        assert!(has_numeric_escape("\\162\\155"));
        assert!(has_numeric_escape("a\\u0072"));
        assert!(!has_numeric_escape("\\n\\t"));
        assert!(!has_numeric_escape("plain"));
        assert!(!has_numeric_escape("\\x"));
        assert!(!has_numeric_escape("\\1"));
    }
}
