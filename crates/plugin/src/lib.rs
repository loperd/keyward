//! keyward's plugins: what a plugin is and what it is allowed.
//!
//! keyward's core is a Bitwarden account: items, secrets, a lock. Everything
//! else it has grown — the ssh agent, the HashiCorp Vault broker — has nothing
//! to do with storing passwords and lives in plugins of its own. The core
//! knows nothing about them: no types, no routes, no settings.
//!
//! An external plugin is a separate program, and the boundary here is a real
//! one: the daemon holds the vault's keys in memory, and somebody else's code
//! in its address space would read them directly — no signature check changes
//! that. A plugin gets exactly what [`Host`] lists and nothing beyond it.
//!
//! The conversation with the interface goes in one envelope,
//! `Request::Plugin { plugin, action, payload }`: adding a plugin does not
//! touch the protocol.

use std::path::PathBuf;

use serde::{Deserialize, Serialize};
use serde_json::Value;

pub use keyward_core::detail::{ItemDetail, SecretField};
pub use keyward_core::source::VaultEntry;

#[cfg(any(test, feature = "testing"))]
pub mod testing;

/// May an external plugin read this field of its own accord?
///
/// Only a custom field in keyward's own namespace — one a plugin wrote itself,
/// such as `kw-vault-addr`. Whatever a person named, and every password,
/// login, code and key, stays behind the window. The daemon decides with this,
/// and the plugins' tests run against a host that decides with it too, so that
/// the two cannot drift apart: a plugin that reaches for somebody else's field
/// fails its own tests rather than a person's screen.
pub fn external_may_read(field: &SecretField) -> bool {
    matches!(field, SecretField::Custom(name) if name.trim().to_ascii_lowercase().starts_with("kw-"))
}

/// Where a plugin came from.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum Origin {
    /// Built together with the daemon. It can be turned off, not removed.
    Builtin,
    /// Installed by a person: a separate program in
    /// `~/.keyward/plugins/<id>`.
    External,
}

/// What a plugin asks of the core. Permissions are asked for once, at
/// installation, and after that the daemon checks them on every call: what the
/// manifest says is a request, not a right.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum Permission {
    /// Read vault items with `kw-*` fields and keys.
    Entries,
    /// Read the values of secret fields.
    Secrets,
    /// Read the cards of items.
    Items,
    /// Create items and edit their fields.
    ItemsWrite,
    /// Show system notifications.
    Notices,
    /// Sign with the vault's ssh keys. The key itself does not leave: the
    /// core signs, and the plugin brings only the data and the flags. The
    /// permission exists because a signature is a way in: a plugin holding it
    /// gets in everywhere the vault's public key is installed.
    SshSign,
    /// Use the network. The core does not police this — a plugin's process
    /// goes out on its own — but a person is owed the request in plain sight: a
    /// plugin with access to secrets and to the network can carry them
    /// anywhere.
    Network,
    /// Keep secrets of its own in the macOS keychain — sealed with a key from
    /// the vault, read back behind Touch ID.
    Keychain,
    /// Put a value on the clipboard — through the core, which marks it
    /// concealed and clears it on time. A plugin that shows secrets copies
    /// them this way, so the window never holds the value.
    Clipboard,
}

impl Permission {
    /// The permission without which a [`Host`] method does not run. `None` is
    /// a method that gives nothing away: "is the vault open" and the plugin's
    /// own settings.
    ///
    /// The table lives next to the permissions themselves rather than in the
    /// daemon: it is part of the contract, and an external plugin is entitled
    /// to know it in advance. An unknown method is an error, not "allowed": a
    /// line forgotten here has to end in a refusal, or a new `Host` method
    /// would travel outwards unasked.
    pub fn required_for(method: &str) -> Result<Option<Self>> {
        Ok(match method {
            "unlocked" | "server" | "settings" | "set_settings" => None,
            "entries" => Some(Self::Entries),
            "item_detail" | "note_fields" | "tagged_items" => Some(Self::Items),
            "secret" => Some(Self::Secrets),
            "create_note" | "trash_item" | "set_fields" => Some(Self::ItemsWrite),
            "notice" => Some(Self::Notices),
            "sign_ssh" => Some(Self::SshSign),
            "keychain_has" | "keychain_get" | "keychain_set" | "keychain_forget" => Some(Self::Keychain),
            "copy_text" => Some(Self::Clipboard),
            other => anyhow::bail!("the core does not know the method \"{other}\""),
        })
    }

    /// The permission's name in the protocol: the same word that stands in
    /// `plugin.json` and, with a `plugin.perm.` prefix, in the dictionary.
    pub fn name(self) -> &'static str {
        match self {
            Self::Entries => "entries",
            Self::Secrets => "secrets",
            Self::Items => "items",
            Self::ItemsWrite => "items_write",
            Self::Notices => "notices",
            Self::SshSign => "ssh_sign",
            Self::Network => "network",
            Self::Keychain => "keychain",
            Self::Clipboard => "clipboard",
        }
    }

    /// A caption for a log and for a core with no dictionary. What a person
    /// sees is written by the window, out of `plugin.perm.<name>`.
    pub fn label(self) -> &'static str {
        match self {
            Self::Entries => "read ssh keys and items with keyward fields",
            Self::Secrets => "read passwords and other secret fields",
            Self::Items => "read the cards of items",
            Self::ItemsWrite => "create items and change their fields",
            Self::Notices => "show notifications",
            Self::SshSign => "sign with the vault's ssh keys",
            Self::Network => "use the network",
            Self::Keychain => "keep its own secrets in the keychain, behind Touch ID",
            Self::Clipboard => "put values on the clipboard, concealed and cleared on time",
        }
    }
}

/// A plugin's card: the interface draws its section and its row in the list
/// from it.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Manifest {
    /// The namespace in the protocol and the name of the settings file:
    /// `ssh`, `hashicorp`.
    pub id: String,
    /// A name for the case where the interface has no translation.
    pub title: String,
    /// The name of an icon from the interface's set.
    pub icon: String,
    /// Show a section in the rail on the left.
    pub section: bool,
    /// The plugin is of use only while the vault is open: with it locked the
    /// section is greyed.
    pub needs_unlocked: bool,
    /// A version, for external ones only; a built-in one has the
    /// application's.
    #[serde(default)]
    pub version: String,
    /// One line about what it is for.
    #[serde(default)]
    pub description: String,
    #[serde(default = "builtin")]
    pub origin: Origin,
    /// Is it on now? One that is off appears in no section, receives no
    /// events and answers no calls.
    #[serde(default = "yes")]
    pub enabled: bool,
    /// What the plugin asks of the core.
    #[serde(default)]
    pub permissions: Vec<Permission>,
    /// The section applies only where the plugin says so: the window asks it
    /// `available` and shows the section on a yes. The Vaultwarden panel, for
    /// one, exists only on a Vaultwarden server with `/admin` switched on.
    #[serde(default)]
    pub probe: bool,
}

fn builtin() -> Origin {
    Origin::Builtin
}

fn yes() -> bool {
    true
}

/// A vault item marked with a plugin's field. The values of hidden fields do
/// not arrive here: `secret` fetches those.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct TaggedItem {
    pub id: String,
    pub name: String,
    /// A plugin's hidden service item: keyward's list does not show it.
    pub hidden: bool,
    /// The item is personal rather than an organisation's. A plugin's service
    /// items have to be personal: in a shared folder anyone in the
    /// organisation could plant such a note, and the plugin would put somebody
    /// else's root token into it.
    pub owned: bool,
    /// The item's own fields: a name and a value. Hidden fields have an empty
    /// value — that the field exists is visible, and the value is fetched with
    /// `secret`, so it is not carried into a log by somebody who only needed to
    /// know whether it was there.
    pub fields: Vec<(String, String)>,
}

/// What happened in the core. A plugin is told so that it need not poll.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum HostEvent {
    /// The vault is open: the keys are there and items can be read.
    Unlocked,
    /// The vault is locked: everything that lived on the keys has to come
    /// down.
    Locked,
    /// The items were rebuilt: a sync, an edit, a change of account.
    EntriesChanged,
    /// The daemon's minute tick.
    Tick,
}

/// A plugin's error. The text reaches a person, so it is either a translation
/// key of the form `err.*` or a sentence.
pub type Error = anyhow::Error;
pub type Result<T> = anyhow::Result<T>;

/// The core as a plugin sees it. Everything a plugin is allowed is listed
/// here.
///
/// The master key, the account's tokens and raw ciphertexts are not here and
/// will not be: a plugin asks for the value of one field of one item, and the
/// core decides whether to hand it over — and asks Touch ID if the item calls
/// for it.
#[async_trait::async_trait]
pub trait Host: Send + Sync {
    /// Is the vault open?
    fn unlocked(&self) -> bool;

    /// Vault items with `kw-*` fields and with the public and private key.
    /// Empty while the vault is locked.
    fn entries(&self) -> Vec<VaultEntry>;

    /// An item's card: its name, its fields, its custom fields. There are no
    /// secrets in it.
    async fn item_detail(&self, entry_id: &str) -> Option<ItemDetail>;

    /// The value of a secret field. The core asks for confirmation itself if
    /// the item is marked "ask for the password again".
    async fn secret(&self, entry_id: &str, field: SecretField) -> Result<String>;

    /// The names of a note's fields: the HashiCorp plugin gathers the unseal
    /// keys by them.
    async fn note_fields(&self, entry_id: &str) -> Result<Vec<String>>;

    /// Items marked with the plugin's own field: this is how a plugin finds
    /// what it created itself. A plugin's connections and settings live as
    /// vault items rather than as files next to the application — otherwise
    /// they would not travel to another machine and would not be under the same
    /// lock as the other secrets.
    fn tagged_items(&self, field: &str) -> Vec<TaggedItem>;

    /// Create a note with fields of one's own. `hidden` makes it a plugin's
    /// service item: keyward's list does not show it, while in Bitwarden's web
    /// interface it is an ordinary secure note. Returns the item's
    /// identifier.
    async fn create_note(&self, name: &str, fields: Vec<(String, String)>, hidden: bool) -> Result<String>;

    /// Move an item into the trash.
    async fn trash_item(&self, entry_id: &str) -> Result<()>;

    /// Put values into one's own fields of an item. An empty value removes
    /// the field — "unbind" rests on that.
    async fn set_fields(&self, entry_id: &str, fields: Vec<(String, String)>) -> Result<()>;

    /// Sign with an item's ssh key.
    ///
    /// A plugin gets no private keys — not a built-in one, and an external one
    /// least of all: `entries` cuts them out. So the core signs, and the plugin
    /// brings what it knows itself: which item (`entry_id`), what (`data`),
    /// which variant of the hash (the ssh agent request's `flags`) and whether
    /// to ask the person (`confirm`).
    ///
    /// `confirm` is the plugin's request, not the last word: the core checks
    /// the `kw-confirm` mark on the item itself, and no argument from here
    /// takes it off.
    ///
    /// The signature comes back in ssh's wire form — the algorithm name and
    /// the bytes, exactly what the agent gives ssh.
    async fn sign_ssh(&self, _entry_id: &str, _data: &[u8], _flags: u32, _confirm: bool) -> Result<Vec<u8>> {
        // The default is a refusal: a core that cannot sign is obliged to say
        // so in words rather than hand back an empty signature.
        anyhow::bail!("this core cannot sign with ssh keys")
    }

    /// Whether the plugin keeps a secret of this name, without reading it.
    async fn keychain_has(&self, _name: &str) -> bool {
        false
    }

    /// A secret of the plugin's own, read back from the keychain; the core
    /// asks for the person's finger first. Per account: another account's
    /// secret of the same name is another secret.
    async fn keychain_get(&self, _name: &str) -> Result<String> {
        anyhow::bail!("this core keeps no secrets for plugins")
    }

    /// Keep a secret of the plugin's own. It never lies in the clear: the
    /// keychain holds a ciphertext under a key from the vault.
    async fn keychain_set(&self, _name: &str, _value: &str) -> Result<()> {
        anyhow::bail!("this core keeps no secrets for plugins")
    }

    async fn keychain_forget(&self, _name: &str) -> Result<()> {
        anyhow::bail!("this core keeps no secrets for plugins")
    }

    /// Put a value on the clipboard, concealed from clipboard managers and
    /// cleared on the settings' interval. Returns the seconds until then.
    async fn copy_text(&self, _value: &str) -> Result<u64> {
        anyhow::bail!("this core has no clipboard for plugins")
    }

    /// The address of the server the active account is on — what a plugin
    /// that manages that server starts from. None when there is no account.
    fn server(&self) -> Option<String> {
        None
    }

    /// A notification for a person. Whoever has a window shows it.
    fn notice(&self, title: &str, body: &str);

    /// A directory of one's own for state: `~/.keyward/plugins/<id>`, mode
    /// 0700.
    fn state_dir(&self) -> PathBuf;

    /// One's own settings. The core only keeps them in a file and gives them
    /// back as they are.
    fn settings(&self) -> Value;
    fn set_settings(&self, value: Value) -> Result<()>;
}

/// A plugin.
#[async_trait::async_trait]
pub trait Plugin: Send + Sync + 'static {
    fn manifest(&self) -> Manifest;

    /// A long-lived core, handed over once, at start-up.
    ///
    /// In `call` and `on_event` the core arrives as a reference and lives for
    /// exactly one call. That is enough for everyone except those who keep
    /// something of their own between calls: an ssh agent's socket answers a
    /// signature when ssh asks it, not when the daemon asks the plugin, and it
    /// needs the core at that minute. Whoever keeps nothing never notices this
    /// method.
    fn attach(&self, _host: std::sync::Arc<dyn Host>) {}

    /// The answer to a request from the interface. The names of operations are
    /// the plugin's own and the core does not read them; an unknown operation
    /// is the plugin's error, not the daemon's.
    async fn call(&self, host: &dyn Host, op: &str, payload: Value) -> Result<Value>;

    /// An event from the core. By default a plugin has nothing to do.
    async fn on_event(&self, _host: &dyn Host, _event: HostEvent) {}
}

/// Unpacking an envelope: `payload` into one's own type.
pub fn arg<T: serde::de::DeserializeOwned>(payload: Value) -> Result<T> {
    serde_json::from_value(payload).map_err(|e| anyhow::anyhow!("the plugin got something other than what it expected: {e}"))
}

/// A plugin's answer out of its own type.
pub fn out<T: Serialize>(value: T) -> Result<Value> {
    serde_json::to_value(value).map_err(|e| anyhow::anyhow!("the plugin's answer will not serialise: {e}"))
}

/// An answer with no contents.
pub fn ok() -> Result<Value> {
    Ok(Value::Null)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn permission_table_matches_the_spec() {
        let cases = [
            ("unlocked", None),
            ("settings", None),
            ("set_settings", None),
            ("entries", Some(Permission::Entries)),
            ("item_detail", Some(Permission::Items)),
            ("note_fields", Some(Permission::Items)),
            ("tagged_items", Some(Permission::Items)),
            ("secret", Some(Permission::Secrets)),
            ("create_note", Some(Permission::ItemsWrite)),
            ("trash_item", Some(Permission::ItemsWrite)),
            ("set_fields", Some(Permission::ItemsWrite)),
            ("notice", Some(Permission::Notices)),
            ("sign_ssh", Some(Permission::SshSign)),
        ];
        for (method, want) in cases {
            assert_eq!(Permission::required_for(method).unwrap(), want, "the method {method}");
        }
    }

    #[test]
    fn unknown_method_is_refused_not_allowed() {
        // A silent "allowed" for an unfamiliar name is a hole: any new `Host`
        // method would travel outwards unasked.
        assert!(Permission::required_for("state_dir").is_err());
        assert!(Permission::required_for("").is_err());
        assert!(Permission::required_for("secret ").is_err());
    }

    #[test]
    fn network_is_declared_but_never_enforced() {
        // The core does not police the network — a plugin's process goes out
        // on its own. The permission exists for the person: they are owed the
        // request before they install anything.
        assert!(Permission::required_for("network").is_err());
        assert_eq!(Permission::Network.label(), "use the network");
    }

    #[test]
    fn permissions_ride_the_wire_in_snake_case() {
        // The names in `plugin.json` are written by a plugin's author by
        // hand, and they have to match what the spec shows.
        let json = r#"["entries","items","items_write","secrets","notices","network","ssh_sign"]"#;
        let parsed: Vec<Permission> = serde_json::from_str(json).unwrap();
        assert_eq!(parsed.len(), 7);
        assert_eq!(serde_json::to_string(&Permission::ItemsWrite).unwrap(), "\"items_write\"");
        assert!(serde_json::from_str::<Permission>("\"vault\"").is_err());
    }

    #[test]
    fn external_manifest_fills_its_own_defaults() {
        // An external package writes `plugin.json` by hand: what is missing
        // takes its default, and the default has to be the safe one.
        let m: Manifest =
            serde_json::from_str(r#"{"id":"hello","title":"Hello","icon":"note","section":true,"needs_unlocked":false}"#)
                .unwrap();
        assert!(m.permissions.is_empty());
        assert_eq!(m.origin, Origin::Builtin);
        assert_eq!(m.version, "");
    }
}
