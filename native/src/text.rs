//! String helpers with the exact semantics of the Kotlin calls the ported
//! checks use, so both sides split and trim input the same way.

/// Java regex `\s`: space, `\t`, `\n`, `\x0B`, `\x0C`, `\r`.
pub fn is_regex_space(c: char) -> bool {
    matches!(c, ' ' | '\t' | '\n' | '\u{0B}' | '\u{0C}' | '\r')
}

/// Kotlin `Char.isWhitespace()` (used by `String.trim()` / `isBlank()`):
/// Java `Character.isWhitespace` or `isSpaceChar`.
pub fn is_kotlin_whitespace(c: char) -> bool {
    match c {
        '\t'..='\r' | '\u{1C}'..='\u{20}' => true,
        _ if c.is_ascii() => false,
        // NEL is a control character to Java, not whitespace.
        '\u{85}' => false,
        _ => c.is_whitespace() || matches!(c, '\u{A0}' | '\u{2007}' | '\u{202F}'),
    }
}

/// Kotlin `String.trim()`.
pub fn kotlin_trim(s: &str) -> &str {
    s.trim_matches(is_kotlin_whitespace)
}

/// Kotlin `CharSequence.isBlank()`.
pub fn is_blank(s: &str) -> bool {
    s.chars().all(is_kotlin_whitespace)
}

/// Kotlin `lineSequence()`: splits on `\r\n`, `\n` and `\r`; a trailing
/// separator yields a final empty line, an empty string one empty line.
pub fn lines(s: &str) -> Vec<&str> {
    let mut out = Vec::new();
    let bytes = s.as_bytes();
    let mut start = 0;
    let mut i = 0;
    while i < bytes.len() {
        match bytes[i] {
            b'\n' => {
                out.push(&s[start..i]);
                i += 1;
                start = i;
            }
            b'\r' => {
                out.push(&s[start..i]);
                i += if bytes.get(i + 1) == Some(&b'\n') { 2 } else { 1 };
                start = i;
            }
            _ => i += 1,
        }
    }
    out.push(&s[start..]);
    out
}

/// Kotlin `split(Regex("\\s+"))` (no limit): empty leading / trailing parts kept.
pub fn split_ws(s: &str) -> Vec<&str> {
    split_ws_limit(s, usize::MAX)
}

/// Kotlin `split(Regex("\\s+"), limit)`: at most [limit] parts, the last one
/// is the unsplit rest.
pub fn split_ws_limit(s: &str, limit: usize) -> Vec<&str> {
    let mut out = Vec::new();
    let mut start = 0;
    let mut chars = s.char_indices().peekable();
    while let Some((i, c)) = chars.next() {
        if out.len() + 1 >= limit {
            break;
        }
        if is_regex_space(c) {
            out.push(&s[start..i]);
            let mut end = i + c.len_utf8();
            while let Some(&(j, d)) = chars.peek() {
                if !is_regex_space(d) {
                    break;
                }
                end = j + d.len_utf8();
                chars.next();
            }
            start = end;
        }
    }
    out.push(&s[start..]);
    out
}

/// Kotlin `String.lowercase()` (locale-independent).
pub fn lowercase(s: &str) -> String {
    s.to_lowercase()
}

/// Truncates [s] to at most [max] characters (at a character boundary).
pub fn truncate_chars(s: &str, max: usize) -> &str {
    match s.char_indices().nth(max) {
        Some((i, _)) => &s[..i],
        None => s,
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn lines_match_kotlin_line_sequence() {
        assert_eq!(lines("a\nb\r\nc\rd"), vec!["a", "b", "c", "d"]);
        assert_eq!(lines("a\n"), vec!["a", ""]);
        assert_eq!(lines(""), vec![""]);
    }

    #[test]
    fn split_matches_kotlin_regex_split() {
        assert_eq!(split_ws("a  b\tc"), vec!["a", "b", "c"]);
        assert_eq!(split_ws(" a"), vec!["", "a"]);
        assert_eq!(split_ws("a "), vec!["a", ""]);
        assert_eq!(split_ws(""), vec![""]);
        assert_eq!(split_ws_limit("a b c d", 2), vec!["a", "b c d"]);
        assert_eq!(split_ws_limit("1 2 3 4 5 /x y", 6), vec!["1", "2", "3", "4", "5", "/x y"]);
    }

    #[test]
    fn trim_and_blank_match_kotlin() {
        assert_eq!(kotlin_trim("\u{1C} a \t"), "a");
        assert!(is_blank(" \t\n"));
        assert!(!is_blank(" x "));
        assert_eq!(truncate_chars("héllo", 2), "hé");
    }
}
