//! A minimal JSON writer for the results handed to Kotlin (parsed there by
//! `RaspJson`). Objects keep insertion order; callers list keys sorted so
//! the text equals Kotlin's `RaspCanonicalJson` (same escapes: `\"`, `\\`,
//! `\b`, `\f`, `\n`, `\r`, `\t`, other controls as `\u00xx`, the rest raw).

pub enum Value {
    Bool(bool),
    Int(i64),
    Str(String),
    Strs(Vec<String>),
}

#[derive(Default)]
pub struct Object(Vec<(&'static str, Value)>);

impl Object {
    pub fn new() -> Self {
        Self::default()
    }

    pub fn with(mut self, key: &'static str, value: Value) -> Self {
        self.0.push((key, value));
        self
    }

    pub fn encode(&self) -> String {
        let mut out = String::from("{");
        for (i, (key, value)) in self.0.iter().enumerate() {
            if i > 0 {
                out.push(',');
            }
            write_str(&mut out, key);
            out.push(':');
            match value {
                Value::Bool(b) => out.push_str(if *b { "true" } else { "false" }),
                Value::Int(n) => out.push_str(&n.to_string()),
                Value::Str(s) => write_str(&mut out, s),
                Value::Strs(list) => {
                    out.push('[');
                    for (j, s) in list.iter().enumerate() {
                        if j > 0 {
                            out.push(',');
                        }
                        write_str(&mut out, s);
                    }
                    out.push(']');
                }
            }
        }
        out.push('}');
        out
    }
}

/// Converts a count to the JSON integer type without a panicking cast.
pub fn int(n: usize) -> Value {
    Value::Int(i64::try_from(n).unwrap_or(i64::MAX))
}

fn write_str(out: &mut String, s: &str) {
    out.push('"');
    for c in s.chars() {
        match c {
            '"' => out.push_str("\\\""),
            '\\' => out.push_str("\\\\"),
            '\n' => out.push_str("\\n"),
            '\r' => out.push_str("\\r"),
            '\t' => out.push_str("\\t"),
            '\u{08}' => out.push_str("\\b"),
            '\u{0C}' => out.push_str("\\f"),
            c if (c as u32) < 0x20 => out.push_str(&format!("\\u{:04x}", c as u32)),
            c => out.push(c),
        }
    }
    out.push('"');
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn encodes_and_escapes() {
        let json = Object::new()
            .with("a", Value::Bool(true))
            .with("n", int(3))
            .with("s", Value::Str("q\"\\\n\u{1}…".into()))
            .with("l", Value::Strs(vec!["x".into(), "y".into()]))
            .encode();
        assert_eq!(json, "{\"a\":true,\"n\":3,\"s\":\"q\\\"\\\\\\n\\u0001…\",\"l\":[\"x\",\"y\"]}");
    }
}
