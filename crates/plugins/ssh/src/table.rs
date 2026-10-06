//! Building the table of routes out of the vault's items.
//!
//! It used to live in the core (`keyward_core::source::build_table`), but what
//! it parses are `kw-*` fields — that is, a plugin's agreement rather than the
//! core's: the core does not care what a plugin reads out of an item.

use keyward_plugin::VaultEntry;

use crate::mapping::{Mapping, MappingTable};

/// What counts as "yes" in a field a person typed by hand.
pub fn is_yes(v: Option<&str>) -> bool {
    matches!(v.map(str::trim).map(str::to_ascii_lowercase).as_deref(),
             Some("yes") | Some("true") | Some("1") | Some("on"))
}

/// The fields the ssh plugin reads off an item. The names live here, with the
/// plugin that gives them meaning: to the core they are `kw-*` and nothing
/// more.
pub const HOST: &str = "kw-host";
pub const CERT: &str = "kw-cert";
pub const CONFIRM: &str = "kw-confirm";
pub const HOSTKEY: &str = "kw-hostkey";
/// The login a key's hosts are entered with, when a route names none. Kept
/// apart from `kw-host`: a pattern's `user@` is a condition the agent matches
/// ssh's request against, while this is only what the terminal and the health
/// checks log in as.
pub const USER: &str = "kw-user";
/// The port the same way: what to connect to when a route names none.
pub const PORT: &str = "kw-port";

/// The item's `kw-port`. A value that is not a port is an error rather than
/// "no port": connecting to 22 instead of the port a person wrote is how a
/// shell ends up on the wrong service.
pub fn port_field(e: &VaultEntry) -> anyhow::Result<Option<u16>> {
    let Some(raw) = e.field(PORT) else { return Ok(None) };
    match raw.parse::<u16>() {
        Ok(p) if p > 0 => Ok(Some(p)),
        _ => Err(keyward_core::fault!("err.sshBadPortField", "port" => raw, "key" => e.name.as_str())),
    }
}

/// The item's `kw-user`, when it holds one.
pub fn user_field(e: &VaultEntry) -> Option<String> {
    e.field(USER).map(str::to_string)
}

/// Unfolds the items into a table of mappings. It also returns a list of
/// warnings: a broken pattern must not bring the whole agent down, but keeping
/// quiet about it is not allowed either — otherwise a person is left guessing
/// why a key is not offered.
pub fn build_table(entries: &[VaultEntry]) -> (MappingTable, Vec<String>) {
    let mut mappings = Vec::new();
    let mut warnings = Vec::new();

    for e in entries {
        let Some(spec) = e.field(HOST) else { continue };
        for raw in spec.split(',') {
            let raw = raw.trim();
            if raw.is_empty() {
                continue;
            }
            match Mapping::parse_pattern(&e.id, &e.name, raw) {
                Ok(mut m) => {
                    m.cert_role = e.field(CERT).map(str::to_string);
                    m.confirm = is_yes(e.field(CONFIRM));
                    m.hostkey = e.field(HOSTKEY).map(str::to_string);
                    mappings.push(m);
                }
                Err(err) => warnings.push(format!("{}: {err}", e.name)),
            }
        }
        if e.public_key.is_none() && e.field(CERT).is_none() {
            warnings.push(format!(
                "{}: there is a kw-host but neither a public key nor a kw-cert, so there will be nothing to sign with",
                e.name
            ));
        }
    }

    (MappingTable::new(mappings), warnings)
}

#[cfg(test)]
mod tests {
    use super::*;

    /// The fields are set one at a time rather than through
    /// `..Default::default()`.
    ///
    /// An item has a `Drop` — it wipes its fields after itself — and a
    /// struct-update expression will not move such a type: the old value would
    /// have to be dropped half taken apart.
    fn entry(name: &str, hosts: &str) -> VaultEntry {
        let mut e = VaultEntry::default();
        e.id = format!("id-{name}");
        e.name = name.to_string();
        e.set_field("kw-host", hosts);
        e.public_key = Some("ssh-ed25519 AAAA test".to_string());
        e
    }

    /// An item with nothing on it: only an identifier and a name.
    fn bare(id: &str, name: &str) -> VaultEntry {
        let mut e = VaultEntry::default();
        e.id = id.to_string();
        e.name = name.to_string();
        e
    }

    #[test]
    fn splits_comma_separated_patterns() {
        let (t, w) = build_table(&[entry("k", "*.example.net, git.example.com , admin@node1.*")]);
        assert_eq!(t.len(), 3);
        assert!(w.is_empty(), "unexpected warnings: {w:?}");
    }

    #[test]
    fn entries_without_kw_host_are_ignored() {
        let (t, w) = build_table(&[bare("1", "an ordinary password")]);
        assert!(t.is_empty());
        assert!(w.is_empty());
    }

    #[test]
    fn broken_pattern_warns_but_keeps_the_rest() {
        let (t, w) = build_table(&[entry("k", "good.example.com, bad:port")]);
        assert_eq!(t.len(), 1, "a sound pattern has to survive");
        assert_eq!(w.len(), 1);
        assert!(w[0].contains("bad:port"), "a warning has to name the culprit: {w:?}");
    }

    #[test]
    fn warns_when_there_is_nothing_to_sign_with() {
        let mut e = bare("1", "keyless");
        e.set_field("kw-host", "h");
        let (_, w) = build_table(&[e]);
        assert_eq!(w.len(), 1);
        assert!(w[0].contains("nothing to sign with"));
    }

    #[test]
    fn confirm_flag_is_parsed_loosely() {
        let mut e = entry("k", "h");
        e.set_field("kw-confirm", " YES ");
        let (t, _) = build_table(&[e]);
        assert!(t.mappings[0].confirm);
    }

    #[test]
    fn cert_role_and_hostkey_travel_from_entry_to_mapping() {
        // Empty strings in the fields mean "not set" rather than "set to
        // empty": otherwise the agent would forbid signing over a fingerprint
        // that does not exist.
        let mut e = entry("k", "h");
        e.set_field("kw-cert", "  ");
        e.set_field("kw-hostkey", "SHA256:abc");
        let (t, _) = build_table(&[e]);
        assert!(t.mappings[0].cert_role.is_none());
        assert_eq!(t.mappings[0].hostkey.as_deref(), Some("SHA256:abc"));
    }
}
