//! XML escaping shared by `-T pdml` and `-T psml`.
//!
//! The five XML metacharacters are escaped in both attribute values and
//! element text. Attribute strings that come from packet data first pass
//! through display escaping, which renders control characters as C
//! escapes (`\a`, `\t`, `\n`) or three-digit octal (`\033`, `\000`); the
//! frame interface name is the exception, using hexadecimal escapes
//! in its showname and show attributes.

/// Append `text` with the five XML metacharacters escaped.
pub fn escape(out: &mut String, text: &str) {
    for character in text.chars() {
        push_escaped(out, character);
    }
}

/// Escape a string as a field value is displayed in `showname` and
/// `show`, then apply XML escaping.
pub fn escape_display(out: &mut String, text: &str) {
    for character in text.chars() {
        match character {
            '\u{7}' => out.push_str("\\a"),
            '\u{8}' => out.push_str("\\b"),
            '\t' => out.push_str("\\t"),
            '\n' => out.push_str("\\n"),
            '\u{b}' => out.push_str("\\v"),
            '\u{c}' => out.push_str("\\f"),
            '\r' => out.push_str("\\r"),
            control if control.is_control() => {
                out.push_str(&format!("\\x{:02X}", u32::from(control)));
            }
            other => push_escaped(out, other),
        }
    }
}

/// Escape a DNS name for display: controls become
/// three-digit octal escapes and a literal backslash stays single.
pub fn escape_dns_name(out: &mut String, text: &str) {
    for character in text.chars() {
        match character {
            '\u{7}' => out.push_str("\\a"),
            '\u{8}' => out.push_str("\\b"),
            '\t' => out.push_str("\\t"),
            '\n' => out.push_str("\\n"),
            '\u{b}' => out.push_str("\\v"),
            '\u{c}' => out.push_str("\\f"),
            '\r' => out.push_str("\\r"),
            control if control.is_control() => {
                let code = u32::from(control);
                out.push('\\');
                for shift in [6, 3, 0] {
                    let digit = (code >> shift) & 0o7;
                    out.push(char::from(b'0' + u8::try_from(digit).unwrap_or(0)));
                }
            }
            other => push_escaped(out, other),
        }
    }
}

/// Escape a field's `show` value: tabs and newlines stay
/// raw, other controls use lowercase hexadecimal escapes, and a literal
/// backslash stays single.
pub fn escape_show(out: &mut String, text: &str) {
    for character in text.chars() {
        match character {
            '\t' | '\n' => out.push(character),
            control if control.is_control() => {
                out.push_str(&format!("\\x{:x}", u32::from(control)));
            }
            other => push_escaped(out, other),
        }
    }
}

/// Escape a frame interface name for a PDML `showname` attribute.
///
/// Interface names use uppercase hexadecimal escapes, unlike the octal
/// escapes of ordinary string fields.
pub fn escape_interface_showname(out: &mut String, text: &str) {
    for character in text.chars() {
        match character {
            '\u{7}' => out.push_str("\\a"),
            '\u{8}' => out.push_str("\\b"),
            '\t' => out.push_str("\\t"),
            '\n' => out.push_str("\\n"),
            '\u{b}' => out.push_str("\\v"),
            '\u{c}' => out.push_str("\\f"),
            '\r' => out.push_str("\\r"),
            control if control.is_control() => {
                out.push_str(&format!("\\x{:02X}", u32::from(control)));
            }
            other => push_escaped(out, other),
        }
    }
}

/// Escape a frame interface name for a PDML `show` attribute.
///
/// This form keeps tabs and newlines raw and uses lowercase
/// hexadecimal escapes for the remaining control characters.
pub fn escape_interface_show(out: &mut String, text: &str) {
    for character in text.chars() {
        match character {
            '\t' | '\n' => out.push(character),
            control if control.is_control() => {
                out.push_str(&format!("\\x{:x}", u32::from(control)));
            }
            other => push_escaped(out, other),
        }
    }
}

/// Escape a packet comment for a PDML `showname` attribute.
///
/// Comments use the frame dissector's hexadecimal escapes, but a literal
/// backslash is not doubled: the output keeps `\quote` as typed.
pub fn escape_comment_showname(out: &mut String, text: &str) {
    for character in text.chars() {
        match character {
            '\u{7}' => out.push_str("\\a"),
            '\u{8}' => out.push_str("\\b"),
            '\t' => out.push_str("\\t"),
            '\n' => out.push_str("\\n"),
            '\u{b}' => out.push_str("\\v"),
            '\u{c}' => out.push_str("\\f"),
            '\r' => out.push_str("\\r"),
            control if control.is_control() => {
                out.push_str(&format!("\\x{:02X}", u32::from(control)));
            }
            other => push_escaped(out, other),
        }
    }
}

/// Escape a packet comment for a PDML `show` attribute.
///
/// Tabs and newlines stay raw and the remaining control characters use
/// lowercase hexadecimal escapes; a literal backslash is not doubled.
pub fn escape_comment_show(out: &mut String, text: &str) {
    for character in text.chars() {
        match character {
            '\t' | '\n' => out.push(character),
            control if control.is_control() => {
                out.push_str(&format!("\\x{:x}", u32::from(control)));
            }
            other => push_escaped(out, other),
        }
    }
}

fn push_escaped(out: &mut String, character: char) {
    match character {
        '&' => out.push_str("&amp;"),
        '<' => out.push_str("&lt;"),
        '>' => out.push_str("&gt;"),
        '"' => out.push_str("&quot;"),
        '\'' => out.push_str("&#x27;"),
        other => out.push(other),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn escapes_the_five_xml_metacharacters() {
        let mut out = String::new();
        escape(&mut out, "a&b<c>d\"e'f");
        assert_eq!(out, "a&amp;b&lt;c&gt;d&quot;e&#x27;f");
    }

    #[test]
    fn display_escapes_control_characters() {
        let mut out = String::new();
        escape_display(&mut out, "a\u{1b}\u{7}\tb\nc\0d");
        assert_eq!(out, "a\\x1B\\a\\tb\\nc\\x00d");
    }

    #[test]
    fn dns_names_use_octal_and_keep_backslashes() {
        let mut out = String::new();
        escape_dns_name(&mut out, "a\\b\u{1b}\u{7}\u{7f}");
        assert_eq!(out, "a\\b\\033\\a\\177");
    }

    #[test]
    fn show_keeps_tabs_and_newlines_and_uses_lowercase_hex() {
        let mut out = String::new();
        escape_show(&mut out, "A\tB\nC\u{7f}D\u{1b}E\\");
        assert_eq!(out, "A\tB\nC\\x7fD\\x1bE\\");
    }

    #[test]
    fn interface_escapes_match_the_frame_form() {
        let mut showname = String::new();
        escape_interface_showname(&mut showname, "eth\u{1b}[\u{7}\tline\nnext");
        assert_eq!(showname, "eth\\x1B[\\a\\tline\\nnext");
        let mut show = String::new();
        escape_interface_show(&mut show, "eth\u{1b}[\u{7}\tline\nnext");
        assert_eq!(show, "eth\\x1b[\\x7\tline\nnext");
    }
}
