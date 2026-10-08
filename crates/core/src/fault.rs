//! Messages meant for a person.
//!
//! The daemon has no language of its own. A window in English and a window in
//! Russian ask the same socket, and the CLI may be piped into a log nobody
//! reads — so the daemon never phrases a sentence. It names what happened and
//! hands over the values that fill the blanks; the interface looks the name up
//! in its dictionary (`i18n/`, which the window reads as well) and writes the
//! sentence.
//!
//! The wire form is the key, optionally followed by a JSON object:
//!
//! ```text
//! err.badPassword
//! err.totpSeedBadAlphabet {"total":"16","outside":"3"}
//! ```
//!
//! A key the dictionary does not know is shown as it is, so a message never
//! disappears just because a translation is late.

use std::collections::BTreeMap;
use std::fmt;

/// A named failure with the values its sentence needs.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Fault {
    code: String,
    args: BTreeMap<String, String>,
}

impl Fault {
    /// Name the failure. The code is a dictionary key: `err.badPassword`.
    pub fn new(code: impl Into<String>) -> Self {
        Self { code: code.into(), args: BTreeMap::new() }
    }

    /// Add a value for the sentence to use as `{name}`.
    #[must_use]
    pub fn with(mut self, name: impl Into<String>, value: impl fmt::Display) -> Self {
        self.args.insert(name.into(), value.to_string());
        self
    }

    pub fn code(&self) -> &str {
        &self.code
    }
}

impl fmt::Display for Fault {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(&self.code)?;
        if self.args.is_empty() {
            return Ok(());
        }
        // Hand-rolled rather than serde: the values are short and escaping
        // them here keeps `keyward-core::fault` free of a JSON dependency in
        // the one place where the output has to be exact.
        f.write_str(" {")?;
        for (i, (name, value)) in self.args.iter().enumerate() {
            if i > 0 {
                f.write_str(",")?;
            }
            write!(f, "\"{}\":\"{}\"", escape(name), escape(value))?;
        }
        f.write_str("}")
    }
}

impl std::error::Error for Fault {}

fn escape(raw: &str) -> String {
    let mut out = String::with_capacity(raw.len());
    for c in raw.chars() {
        match c {
            '"' => out.push_str("\\\""),
            '\\' => out.push_str("\\\\"),
            '\n' => out.push_str("\\n"),
            '\r' => out.push_str("\\r"),
            '\t' => out.push_str("\\t"),
            c if (c as u32) < 0x20 => out.push_str(&format!("\\u{:04x}", c as u32)),
            c => out.push(c),
        }
    }
    out
}

/// Raise a named failure as an `anyhow` error.
#[macro_export]
macro_rules! fault {
    ($code:expr) => {
        anyhow::Error::new($crate::fault::Fault::new($code))
    };
    ($code:expr, $($name:expr => $value:expr),+ $(,)?) => {
        anyhow::Error::new($crate::fault::Fault::new($code)$(.with($name, $value))+)
    };
}

#[cfg(test)]
mod tests {
    use super::Fault;

    #[test]
    fn a_bare_code_stays_bare() {
        assert_eq!(Fault::new("err.badPassword").to_string(), "err.badPassword");
    }

    #[test]
    fn values_travel_as_json_in_a_stable_order() {
        let f = Fault::new("err.totpSeedBadAlphabet").with("outside", 3).with("total", 16);
        assert_eq!(f.to_string(), r#"err.totpSeedBadAlphabet {"outside":"3","total":"16"}"#);
    }

    /// A value is whatever the user typed, and it must not be able to end the
    /// JSON object early and turn the rest of itself into another key.
    #[test]
    fn a_quote_in_a_value_cannot_break_out() {
        let f = Fault::new("err.noSuchField").with("name", "he said \"hi\"\n");
        assert_eq!(f.to_string(), r#"err.noSuchField {"name":"he said \"hi\"\n"}"#);
    }
}
