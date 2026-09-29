//! Where entries come from. The vault is the destination; a file is the
//! bridge used in stages 1-2, while access to Bitwarden is not yet on the
//! `rbw` crate (see section 2.2 of the spec).
//!
//! What the `kw-*` fields mean is the business of whichever plugin reads them:
//! `kw-host` is a route to the ssh plugin and nothing at all to the core. The
//! core carries them as they are written.

use std::collections::BTreeMap;

use serde::{Deserialize, Serialize};

/// The prefix of the fields keyward passes to plugins. The namespace is the
/// core's; the meaning of a name inside it is not.
pub const FIELD_PREFIX: &str = "kw-";

/// A vault entry in the shape a plugin sees it.
///
/// `fields` holds the item's `kw-*` fields under their full names. The core
/// does not read them: it does not know which plugin is waiting for which name,
/// and a plugin that arrives tomorrow will bring a name nobody has heard of.
#[derive(Debug, Clone, Default, Serialize, Deserialize)]
#[derive(zeroize::ZeroizeOnDrop)]
pub struct VaultEntry {
    #[zeroize(skip)]
    pub id: String,
    pub name: String,
    /// The item's `kw-*` fields, by their full names.
    #[zeroize(skip)]
    #[serde(default, flatten)]
    pub fields: BTreeMap<String, String>,
    /// The public key in OpenSSH format.
    #[serde(default)]
    pub public_key: Option<String>,
    /// The private key in OpenSSH format. Allowed in a file source, but the
    /// real path is the vault: the daemon need not keep keys on disk.
    #[serde(default)]
    pub private_key: Option<String>,
}

impl VaultEntry {
    /// The value of one of the item's own fields, trimmed; `None` when it is
    /// absent or empty. An empty field is the same as none: that is how a
    /// binding is taken off.
    pub fn field(&self, name: &str) -> Option<&str> {
        self.fields.get(name).map(|v| v.trim()).filter(|v| !v.is_empty())
    }

    /// Put a field on, or take it off with an empty value.
    pub fn set_field(&mut self, name: &str, value: impl Into<String>) {
        let value = value.into();
        if value.trim().is_empty() {
            self.fields.remove(name);
        } else {
            self.fields.insert(name.to_string(), value);
        }
    }

    /// Whether the item carries any of keyward's own fields at all.
    pub fn is_tagged(&self) -> bool {
        self.fields.keys().any(|k| k.starts_with(FIELD_PREFIX))
    }
}

pub fn load_from_file(path: &std::path::Path) -> anyhow::Result<Vec<VaultEntry>> {
    if !path.exists() {
        return Ok(Vec::new());
    }
    let text = std::fs::read_to_string(path)?;
    if text.trim().is_empty() {
        return Ok(Vec::new());
    }
    let entries: Vec<VaultEntry> = serde_json::from_str(&text)?;
    Ok(entries)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn file_source_reads_entries() {
        let path = std::env::temp_dir().join(format!("kw-src-{}.json", std::process::id()));
        std::fs::write(&path, r#"[{"id":"1","name":"k","kw-host":"a.example.com"}]"#).unwrap();
        let entries = load_from_file(&path).unwrap();
        let _ = std::fs::remove_file(&path);
        assert_eq!(entries.len(), 1);
        assert_eq!(entries[0].field("kw-host"), Some("a.example.com"));
    }

    #[test]
    fn an_unknown_field_travels_as_it_is() {
        // The core must not lose a field because it has never heard of it: the
        // plugin that asked for it may be installed a minute from now.
        let raw = r#"[{"id":"1","name":"k","kw-host":"h","kw-tomorrow":"something"}]"#;
        let entry: Vec<VaultEntry> = serde_json::from_str(raw).unwrap();
        assert_eq!(entry[0].field("kw-tomorrow"), Some("something"));
        assert!(entry[0].is_tagged());
    }

    #[test]
    fn an_empty_field_is_the_same_as_none() {
        let mut e = VaultEntry::default();
        e.id = "1".into();
        e.name = "k".into();
        e.set_field("kw-host", "  ");
        assert_eq!(e.field("kw-host"), None, "an empty value is not a binding");
        e.set_field("kw-host", " a.example.com ");
        assert_eq!(e.field("kw-host"), Some("a.example.com"));
        e.set_field("kw-host", "");
        assert!(!e.is_tagged(), "an empty value takes the field off");
    }
}
