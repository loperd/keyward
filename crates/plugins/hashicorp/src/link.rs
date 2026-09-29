//! A connection to HashiCorp Vault as the interface sees it.
//!
//! The connection itself is kept as an item in the Bitwarden vault: the server
//! address and the credentials lie where the other secrets are rather than in a
//! separate file beside the application.

use serde::{Deserialize, Serialize};

/// The sign that a Vault is connected. The broker's tab is shown only when
/// such an item exists: an empty tab "for later" is of no use.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Link {
    pub entry_id: String,
    pub entry_name: String,
    pub addr: String,
    pub has_role_id: bool,
    /// Whether there is already a root token in the hidden item. Without this
    /// the interface cannot tell "no root was issued" from "one was issued, it
    /// is simply not in sight" — and drives a person to generate a second.
    pub has_root: bool,
    /// How many fields with unseal keys are chosen. A Vault with a threshold of
    /// three out of five cannot be unsealed without them, so the number is worth
    /// seeing.
    pub unseal_keys: usize,
    /// The names of those fields. The window reads their values itself — a
    /// plugin may read only its own `kw-` fields, and the shares lie in fields
    /// a person named — and hands them over with the call that needs them.
    #[serde(default)]
    pub unseal_fields: Vec<String>,
}

/// What a person filled in on the connection form.
#[derive(Debug, Clone, Default, Serialize, Deserialize)]
pub struct Form {
    /// The new item's name. Ignored when writing into an existing one.
    #[serde(default)]
    pub name: String,
    /// Write into one particular vault item instead of creating a new one.
    #[serde(default)]
    pub entry_id: Option<String>,
    pub addr: String,
    /// The names of the note's fields that hold the unseal keys.
    ///
    /// The names and not the values: the keys are already kept in that same
    /// vault item, and copying them into a second place doubles the surface
    /// they leak from for no good at all.
    #[serde(default)]
    pub unseal_fields: Vec<String>,
    #[serde(default)]
    pub role_id: String,
    #[serde(default)]
    pub secret_id: String,
    #[serde(default)]
    pub namespace: String,
}

impl Form {
    /// The chosen fields with the empty ones and the duplicates taken out: the
    /// same field offered twice will not make up the threshold.
    pub fn fields(&self) -> Vec<String> {
        let mut seen = Vec::new();
        for name in &self.unseal_fields {
            let name = name.trim();
            if name.is_empty() || seen.iter().any(|s: &String| s == name) {
                continue;
            }
            seen.push(name.to_string());
        }
        seen
    }

    /// A check before going to the network: an error one can act on beats a
    /// timeout.
    pub fn validate(&self) -> Result<(), String> {
        let addr = self.addr.trim();
        if addr.is_empty() {
            // The key travels as it is: the window translates it, and the plugin does
            // not know which language the window speaks.
            return Err("err.vaultAddrRequired".into());
        }
        if !addr.starts_with("http://") && !addr.starts_with("https://") {
            return Err("err.vaultAddrScheme".into());
        }
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn duplicate_and_empty_fields_are_dropped() {
        let f = Form {
            addr: "https://vault.example.net".into(),
            unseal_fields: vec![" share 1 ".into(), String::new(), "share 1".into(), "share 2".into()],
            ..Default::default()
        };
        // The same field twice will not make up the threshold: Vault counts it
        // as a repeat and the progress does not move.
        assert_eq!(f.fields(), vec!["share 1".to_string(), "share 2".to_string()]);
        assert!(Form::default().fields().is_empty());
    }

    #[test]
    fn address_is_required_and_must_have_scheme() {
        assert!(Form::default().validate().is_err());
        assert!(Form { addr: "vault.example.com".into(), ..Default::default() }.validate().is_err());
        assert!(Form { addr: "https://vault.example.com".into(), ..Default::default() }.validate().is_ok());
    }
}
