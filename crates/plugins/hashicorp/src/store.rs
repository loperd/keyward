//! Where the plugin keeps everything: connections, the ledger of issues, the
//! hidden items with root tokens.
//!
//! The plugin keeps nothing of its own on disk. A connection is not an
//! application setting but the fields of a vault item: that way it travels to
//! another machine with the vault and ends up under the same lock as the other
//! secrets. `keyward_vault::Vault` used to read these same fields; now `Host`
//! stands between the plugin and the items, and the field names are the
//! plugin's business — the core does not read them.

use anyhow::Result;
use keyward_plugin::{Host, SecretField, TaggedItem};
use serde_json::{json, Value};

use crate::link::{Form, Link};

/// The server's address. The plugin finds its own items by it too:
/// `Host::tagged_items` looks for exactly this field.
pub const ADDR: &str = "kw-vault-addr";
pub const ROLE_ID: &str = "kw-vault-role-id";
pub const SECRET_ID: &str = "kw-vault-secret-id";
pub const NAMESPACE: &str = "kw-vault-namespace";
/// The names of the item's fields that hold the shares of the unseal key. The
/// names and not the values: there is no reason to make a second copy of the
/// keys.
pub const UNSEAL_FIELDS: &str = "kw-vault-unseal-fields";
pub const TOKEN: &str = "kw-vault-token";
pub const ISSUED: &str = "kw-issued";
pub const ROOT_ISSUED: &str = "kw-root-issued";
pub const ROOT_REVOKED: &str = "kw-root-revoked";
/// The Vault address inside the hidden item that holds the root token. The
/// name differs from `kw-vault-addr` on purpose: otherwise the hidden item
/// would stand in for the connection itself.
pub const ROOT_ADDR: &str = "kw-root-addr";

/// The fields keyward marks an item as a connection with. Everything else in
/// the item belongs to a person and must not be touched.
const GONE: [&str; 5] = [ADDR, ROLE_ID, SECRET_ID, NAMESPACE, UNSEAL_FIELDS];

/// A connection's credentials, taken out of a vault item.
pub struct Creds {
    pub addr: String,
    pub namespace: Option<String>,
    pub role_id: Option<String>,
    pub secret_id: Option<String>,
    /// A direct token: the fallback when no AppRole has been set up.
    pub token: Option<String>,
    /// The unseal keys: with Shamir there are several and a threshold is
    /// needed.
    pub unseal_keys: Vec<String>,
}

/// The value of one of our own fields on an item.
///
/// In a list the core gives only the names of hidden fields, with the value
/// empty: the value itself has to be fetched separately, and rightly so,
/// because "is it there" is asked far more often than "show it".
async fn value(host: &dyn Host, item: &TaggedItem, name: &str) -> Option<String> {
    if let Some((_, v)) = item.fields.iter().find(|(k, _)| same(k, name)) {
        if !v.trim().is_empty() {
            return Some(v.clone());
        }
    }
    host.secret(&item.id, SecretField::Custom(name.to_string()))
        .await
        .ok()
        .filter(|v| !v.trim().is_empty())
}

/// Does the item have such a field, without reading the value?
fn has(item: &TaggedItem, name: &str) -> bool {
    item.fields.iter().any(|(k, _)| same(k, name))
}

fn same(a: &str, b: &str) -> bool {
    a.trim().eq_ignore_ascii_case(b)
}

/// The address in canonical form: the hidden item is looked up by it.
fn norm(addr: &str) -> &str {
    addr.trim().trim_end_matches('/')
}

// -- the plugin's settings -------------------------------------------------

/// The chosen connection. It lives in the plugin's settings rather than the
/// core's `Settings`: the core knows nothing of HashiCorp any more.
pub fn active_id(host: &dyn Host) -> Option<String> {
    host.settings()
        .get("active")
        .and_then(Value::as_str)
        .map(str::to_string)
        .filter(|s| !s.trim().is_empty())
}

/// Remembers the choice without losing the plugin's other settings.
pub fn set_active(host: &dyn Host, entry_id: &str) -> Result<()> {
    let mut settings = host.settings();
    if !settings.is_object() {
        settings = json!({});
    }
    settings["active"] = json!(entry_id);
    host.set_settings(settings)
}

/// Whether to give notice of issued tokens' deadlines. Yes by default: the
/// point of a broker is short access, and a person has to learn of its end
/// without a window on the screen.
pub fn expiry_notices(host: &dyn Host) -> bool {
    host.settings().get("expiry_notices").and_then(Value::as_bool).unwrap_or(true)
}

/// The settings as the interface shows them: always with both fields, even
/// when there is no file yet — otherwise a switch has nothing to start
/// from.
pub fn settings(host: &dyn Host) -> Value {
    json!({
        "active": active_id(host),
        "expiry_notices": expiry_notices(host),
    })
}

/// Save the settings whole. The chosen connection is not lost when the
/// interface sent only the switch.
pub fn set_settings(host: &dyn Host, incoming: Value) -> Result<()> {
    let mut settings = host.settings();
    if !settings.is_object() {
        settings = json!({});
    }
    if let Some(active) = incoming.get("active") {
        settings["active"] = active.clone();
    }
    if let Some(on) = incoming.get("expiry_notices").and_then(Value::as_bool) {
        settings["expiry_notices"] = json!(on);
    }
    host.set_settings(settings)?;
    Ok(())
}

// -- connections -------------------------------------------------------------

/// Every connected Vault.
///
/// There can be as many connections as one likes: each has its own item with
/// its own shares of the key. The order is by the item's name, so that the list
/// does not jump about from one sync to the next.
pub async fn connections(host: &dyn Host) -> Vec<Link> {
    let roots = hidden_notes(host);
    let mut links = Vec::new();
    for item in host.tagged_items(ADDR) {
        // keyward's own service item does not count as a connection: the root
        // token and the ledger lie in it, and it must not stand in for a
        // connection.
        if item.hidden {
            continue;
        }
        let Some(addr) = value(host, &item, ADDR).await else { continue };
        if addr.trim().is_empty() {
            continue;
        }
        let unseal_fields: Vec<String> = value(host, &item, UNSEAL_FIELDS)
            .await
            .map(|v| v.split(',').map(str::trim).filter(|l| !l.is_empty()).map(str::to_string).collect())
            .unwrap_or_default();
        let mut has_root = false;
        for note in &roots {
            if value(host, note, ROOT_ADDR).await.as_deref().map(norm) == Some(norm(&addr)) {
                has_root = true;
                break;
            }
        }
        links.push(Link {
            has_root,
            entry_id: item.id.clone(),
            entry_name: item.name.clone(),
            // The field's name is enough: the core does not give a hidden
            // field's value in a list, and an empty value removes the field
            // altogether — so "the field is there" means "the key is filled
            // in".
            has_role_id: has(&item, ROLE_ID),
            addr,
            unseal_keys: unseal_fields.len(),
            unseal_fields,
        });
    }
    links.sort_by_key(|l| l.entry_name.to_lowercase());
    links
}

/// The chosen connection: the one the broker works with.
pub async fn connection(host: &dyn Host) -> Option<Link> {
    let links = connections(host).await;
    active_id(host)
        .and_then(|id| links.iter().find(|l| l.entry_id == id).cloned())
        .or_else(|| links.first().cloned())
}

/// Why there is no connection: the vault is locked, no connection was chosen,
/// or the item vanished. Three different reasons and three different answers,
/// or a person mends the wrong thing.
pub fn why_no_credentials(host: &dyn Host) -> &'static str {
    if !host.unlocked() {
        return "err.vaultLockedUnlockIt";
    }
    if host.tagged_items(ADDR).is_empty() {
        return "err.noItemWithVaultAddr";
    }
    "err.connectionItemMissing"
}

/// Connects a HashiCorp Vault: puts the address and the keys into a vault
/// item.
pub async fn connect(host: &dyn Host, form: &Form) -> Result<()> {
    form.validate().map_err(|e| anyhow::anyhow!("{e}"))?;

    let mut fields: Vec<(String, String)> = vec![(ADDR.to_string(), form.addr.trim().to_string())];
    for (key, value) in [
        (ROLE_ID, &form.role_id),
        (SECRET_ID, &form.secret_id),
        (NAMESPACE, &form.namespace),
    ] {
        let v = value.trim();
        if !v.is_empty() {
            fields.push((key.to_string(), v.to_string()));
        }
    }
    let chosen = form.fields().join(", ");
    if !chosen.is_empty() {
        fields.push((UNSEAL_FIELDS.to_string(), chosen));
    }

    let target = match form.entry_id.clone() {
        Some(id) if !id.trim().is_empty() => Some(id),
        _ => connection(host).await.map(|l| l.entry_id),
    };
    match target {
        Some(id) => {
            host.set_fields(&id, fields).await?;
            tracing::info!(entry = %id, "a HashiCorp Vault was connected");
        }
        None => {
            // There is no item for the connection, so a note is created. The
            // name is asked for on the form: there are no nameless items in a
            // vault.
            let name = form.name.trim();
            if name.is_empty() {
                return Err(anyhow::anyhow!("err.chooseNoteForConnection"));
            }
            let id = host.create_note(name, fields, false).await?;
            tracing::info!(entry = %id, "a HashiCorp Vault was connected through a new note");
        }
    }
    Ok(())
}

/// Takes the connection out of an item.
///
/// The shares of the unseal key themselves are left alone: they are a person's
/// keys, not ours. Only what keyward counts an item a connection by goes: an
/// empty value removes the field.
pub async fn forget(host: &dyn Host, entry_id: &str) -> Result<()> {
    let fields = GONE.iter().map(|k| ((*k).to_string(), String::new())).collect();
    host.set_fields(entry_id, fields).await?;
    tracing::info!(entry = %entry_id, "the connection to Vault was taken away");
    Ok(())
}

/// The chosen connection's credentials.
pub async fn credentials(host: &dyn Host) -> Option<Creds> {
    let link = connection(host).await?;
    let item = host.tagged_items(ADDR).into_iter().find(|i| i.id == link.entry_id)?;

    // The keys' values are taken from the item's fields that were pointed at
    // when connecting: no second copy of the keys is made.
    let names: Vec<String> = value(host, &item, UNSEAL_FIELDS)
        .await
        .map(|v| v.split(',').map(str::trim).filter(|n| !n.is_empty()).map(str::to_string).collect())
        .unwrap_or_default();
    // Only fields the plugin may read of its own accord: the shares a person
    // named are refused by the daemon, and asking for them anyway filled its
    // log with refusals every minute. The window reads those and hands them
    // over with `unseal` and `generate_root`.
    let mut unseal_keys = Vec::new();
    for name in names {
        if !keyward_plugin::external_may_read(&SecretField::Custom(name.clone())) {
            continue;
        }
        if let Some(v) = value(host, &item, &name).await {
            unseal_keys.push(v);
        }
    }

    Some(Creds {
        namespace: value(host, &item, NAMESPACE).await,
        role_id: value(host, &item, ROLE_ID).await,
        secret_id: value(host, &item, SECRET_ID).await,
        token: root_token(host, &link.addr).await,
        unseal_keys,
        addr: link.addr,
    })
}

/// The values of the chosen fields of an item: the shares of the unseal key.
/// Empty ones are skipped: feeding an empty share loses a step of the
/// threshold.
pub async fn note_values(host: &dyn Host, entry_id: &str, names: &[String]) -> Vec<String> {
    let mut out = Vec::new();
    for name in names {
        // As in `credentials`: a person's own fields come from the window.
        if !keyward_plugin::external_may_read(&SecretField::Custom(name.clone())) {
            continue;
        }
        if let Ok(v) = host.secret(entry_id, SecretField::Custom(name.clone())).await {
            if !v.trim().is_empty() {
                out.push(v);
            }
        }
    }
    out
}

// -- the hidden items: the root token and the ledger -------------------------

/// keyward's own service items, holding root tokens and ledgers.
///
/// Hidden ones only: an ordinary item with the same field is somebody else's
/// forgery, not our ledger.
fn hidden_notes(host: &dyn Host) -> Vec<TaggedItem> {
    // Personal items only: a shared note with the same marks could be created
    // by anybody in the organisation, and a root token would travel into it.
    host.tagged_items(ROOT_ADDR).into_iter().filter(|i| i.hidden && i.owned).collect()
}

/// keyward's hidden item for this address.
async fn root_note(host: &dyn Host, addr: &str) -> Option<TaggedItem> {
    let addr = norm(addr);
    for note in hidden_notes(host) {
        if value(host, &note, ROOT_ADDR).await.as_deref().map(norm) == Some(addr) {
            return Some(note);
        }
    }
    None
}

/// The hidden item for an address: found or created.
async fn ensure_root_note(host: &dyn Host, addr: &str) -> Result<String> {
    let addr = norm(addr);
    if let Some(note) = root_note(host, addr).await {
        return Ok(note.id);
    }
    let server = addr.split("://").last().unwrap_or(addr).trim_end_matches('/');
    // A hidden service item: nobody needs a root token and a ledger in their
    // list, and in Bitwarden's web interface it is an ordinary secure note.
    host.create_note(
        &format!("keyward · vault · {server}"),
        vec![(ROOT_ADDR.to_string(), addr.to_string())],
        true,
    )
    .await
}

/// Puts a root token into a hidden item of its own.
///
/// Not into the same note where the shares of the key lie: a root token is
/// access to the whole Vault at once, and keeping it next to what it is
/// obtained with hands both ends to one pair of eyes. The item is marked
/// `kw-hidden`, so keyward's common list does not show it; in Bitwarden's web
/// interface it of course remains — an ordinary secure note.
pub async fn store_root_token(host: &dyn Host, addr: &str, token: &str) -> Result<()> {
    let id = ensure_root_note(host, addr).await?;
    host.set_fields(
        &id,
        vec![(TOKEN.to_string(), token.to_string()), (ROOT_ISSUED.to_string(), now_stamp())],
    )
    .await
}

/// The root token's value for this address, needed in order to revoke it with
/// itself.
pub async fn root_token(host: &dyn Host, addr: &str) -> Option<String> {
    let note = root_note(host, addr).await?;
    value(host, &note, TOKEN).await
}

/// Takes the token out of the hidden item, leaving a trace of when that
/// happened.
pub async fn forget_root(host: &dyn Host, addr: &str) -> Result<()> {
    let note = root_note(host, addr)
        .await
        .ok_or_else(|| anyhow::anyhow!(crate::model::key("err.noHiddenRootItem", &[("addr", addr)])))?;
    host.set_fields(
        &note.id,
        vec![(TOKEN.to_string(), String::new()), (ROOT_REVOKED.to_string(), now_stamp())],
    )
    .await
}

/// Every hidden item holding a live root token: the item, the address and the
/// time of issue. The token's value is not given out — only what it can be
/// recognised and revoked by.
pub async fn root_notes(host: &dyn Host) -> Vec<(String, String, u64)> {
    let mut out = Vec::new();
    for note in hidden_notes(host) {
        let Some(addr) = value(host, &note, ROOT_ADDR).await else { continue };
        // An empty value is what stays after a revocation: the item is kept
        // for the trail, but the token is no longer in it.
        if value(host, &note, TOKEN).await.is_none() {
            continue;
        }
        let issued = value(host, &note, ROOT_ISSUED)
            .await
            .and_then(|v| v.trim().parse::<u64>().ok())
            .unwrap_or(0);
        out.push((note.id.clone(), addr, issued));
    }
    out
}

/// The ledger of issues as it lies in an item.
pub async fn issued_json(host: &dyn Host, addr: &str) -> Option<String> {
    let note = root_note(host, addr).await?;
    value(host, &note, ISSUED).await
}

/// The ledger of issued tokens, in the vault item itself.
///
/// Not in a local file: then it lives on one machine and disappears on a
/// reinstall, while issued access has to be revocable from anywhere. There is
/// no reason to run a server of our own for it and Bitwarden's api cannot be
/// extended — so an ordinary field of an ordinary item, like everything else
/// here.
///
/// Only accessors lie there: with one a token can be looked at and revoked but
/// not used. The token itself is never saved.
pub async fn store_issued(host: &dyn Host, addr: &str, json: &str) -> Result<()> {
    let id = ensure_root_note(host, addr).await?;
    host.set_fields(&id, vec![(ISSUED.to_string(), json.to_string())]).await
}

/// A timestamp of the issue, so that the item shows how old a root token
/// is.
fn now_stamp() -> String {
    format!("{}", crate::api::now_secs())
}

/// A stand-in for the core in tests: items in memory instead of a vault.
#[cfg(test)]
pub mod testing {
    use std::collections::HashMap;
    use std::sync::Mutex;

    use keyward_plugin::{Host, ItemDetail, SecretField, TaggedItem, VaultEntry};
    use serde_json::Value;

    /// What was written: the item and its fields.
    type Written = Vec<(String, Vec<(String, String)>)>;

    #[derive(Default)]
    pub struct Fake {
        pub items: Mutex<Vec<TaggedItem>>,
        /// The values the core gives only on a request of their own.
        pub secrets: Mutex<HashMap<(String, String), String>>,
        pub settings: Mutex<Value>,
        /// What the plugin wrote.
        pub writes: Mutex<Written>,
        pub created: Mutex<Written>,
        pub notices: Mutex<Vec<(String, String)>>,
        pub locked: bool,
    }

    impl Fake {
        pub fn with(items: Vec<TaggedItem>) -> Self {
            Self { items: Mutex::new(items), ..Default::default() }
        }

        pub fn item(id: &str, name: &str, fields: &[(&str, &str)]) -> TaggedItem {
            TaggedItem {
                id: id.to_string(),
                name: name.to_string(),
                hidden: false,
                owned: true,
                fields: fields.iter().map(|(k, v)| (k.to_string(), v.to_string())).collect(),
            }
        }

        /// keyward's own service item: the root token and the ledger.
        pub fn hidden(id: &str, name: &str, fields: &[(&str, &str)]) -> TaggedItem {
            TaggedItem { hidden: true, ..Self::item(id, name, fields) }
        }
    }

    #[async_trait::async_trait]
    impl Host for Fake {
        fn unlocked(&self) -> bool {
            !self.locked
        }

        fn entries(&self) -> Vec<VaultEntry> {
            Vec::new()
        }

        async fn item_detail(&self, _entry_id: &str) -> Option<ItemDetail> {
            None
        }

        async fn secret(&self, entry_id: &str, field: SecretField) -> anyhow::Result<String> {
            let SecretField::Custom(name) = field else { anyhow::bail!("err.noSuchField") };
            if let Some(v) = self.secrets.lock().unwrap().get(&(entry_id.to_string(), name.clone())) {
                return Ok(v.clone());
            }
            self.items
                .lock()
                .unwrap()
                .iter()
                .find(|i| i.id == entry_id)
                .and_then(|i| i.fields.iter().find(|(k, _)| k.eq_ignore_ascii_case(&name)))
                .map(|(_, v)| v.clone())
                .ok_or_else(|| anyhow::anyhow!(crate::model::key("err.noField", &[("name", name.as_str())])))
        }

        async fn note_fields(&self, entry_id: &str) -> anyhow::Result<Vec<String>> {
            Ok(self
                .items
                .lock()
                .unwrap()
                .iter()
                .find(|i| i.id == entry_id)
                .map(|i| i.fields.iter().map(|(k, _)| k.clone()).collect())
                .unwrap_or_default())
        }

        fn tagged_items(&self, field: &str) -> Vec<TaggedItem> {
            self.items
                .lock()
                .unwrap()
                .iter()
                .filter(|i| i.fields.iter().any(|(k, _)| k.eq_ignore_ascii_case(field)))
                .map(|i| TaggedItem {
                    // As the core does: a hidden field's name is visible, its
                    // value is not.
                    fields: i
                        .fields
                        .iter()
                        .map(|(k, v)| {
                            let hidden = k.trim().to_lowercase().starts_with("kw-");
                            (k.clone(), if hidden { String::new() } else { v.clone() })
                        })
                        .collect(),
                    ..i.clone()
                })
                .collect()
        }

        async fn create_note(
            &self,
            name: &str,
            fields: Vec<(String, String)>,
            hidden: bool,
        ) -> anyhow::Result<String> {
            let id = format!("new-{}", self.created.lock().unwrap().len() + 1);
            self.created.lock().unwrap().push((name.to_string(), fields.clone()));
            self.items.lock().unwrap().push(TaggedItem {
                id: id.clone(),
                name: name.to_string(),
                hidden,
                owned: true,
                fields,
            });
            Ok(id)
        }

        async fn trash_item(&self, _entry_id: &str) -> anyhow::Result<()> {
            Ok(())
        }

        async fn set_fields(&self, entry_id: &str, fields: Vec<(String, String)>) -> anyhow::Result<()> {
            self.writes.lock().unwrap().push((entry_id.to_string(), fields.clone()));
            let mut items = self.items.lock().unwrap();
            let Some(item) = items.iter_mut().find(|i| i.id == entry_id) else {
                anyhow::bail!("err.itemNotFoundSync")
            };
            for (key, value) in fields {
                // An empty value removes the field: "unbind" rests on that.
                if value.trim().is_empty() {
                    item.fields.retain(|(k, _)| !k.eq_ignore_ascii_case(&key));
                    self.secrets.lock().unwrap().remove(&(entry_id.to_string(), key));
                    continue;
                }
                match item.fields.iter_mut().find(|(k, _)| k.eq_ignore_ascii_case(&key)) {
                    Some(slot) => slot.1 = value.clone(),
                    None => item.fields.push((key.clone(), value.clone())),
                }
                self.secrets.lock().unwrap().insert((entry_id.to_string(), key), value);
            }
            Ok(())
        }

        fn notice(&self, title: &str, body: &str) {
            self.notices.lock().unwrap().push((title.to_string(), body.to_string()));
        }

        fn state_dir(&self) -> std::path::PathBuf {
            std::env::temp_dir()
        }

        fn settings(&self) -> Value {
            self.settings.lock().unwrap().clone()
        }

        fn set_settings(&self, value: Value) -> anyhow::Result<()> {
            *self.settings.lock().unwrap() = value;
            Ok(())
        }
    }
}

#[cfg(test)]
mod tests {
    use super::testing::Fake;
    use super::*;
    use serde_json::json;

    fn vault() -> Fake {
        Fake::with(vec![
            Fake::item("b", "Prod", &[(ADDR, "https://vault.prod/"), (ROLE_ID, "r")]),
            Fake::item("a", "Dev", &[(ADDR, "https://vault.dev")]),
            // keyward's own service item: it also carries the root token for
            // prod.
            Fake::hidden(
                "hidden",
                "keyward · vault · vault.prod",
                &[(ROOT_ADDR, "https://vault.prod"), (TOKEN, "hvs.root")],
            ),
        ])
    }

    #[tokio::test]
    async fn connections_are_vault_items_and_not_a_setting() {
        let links = connections(&vault()).await;
        // keyward's hidden item takes no part in the list of connections, and
        // the order is by name so that the list does not jump about from one
        // sync to the next.
        assert_eq!(links.iter().map(|l| l.entry_id.as_str()).collect::<Vec<_>>(), ["a", "b"]);
        assert!(!links[0].has_role_id && links[1].has_role_id);
        // A root token is seen by the hidden item with the same address rather
        // than by the field itself.
        assert!(!links[0].has_root && links[1].has_root);
    }

    #[tokio::test]
    async fn the_chosen_connection_lives_in_the_plugins_settings() {
        let host = vault();
        // With nothing chosen, the first by name is taken.
        assert_eq!(connection(&host).await.unwrap().entry_id, "a");

        set_active(&host, "b").unwrap();
        assert_eq!(connection(&host).await.unwrap().entry_id, "b");

        // The choice must not write over the plugin's other settings.
        host.set_settings(json!({ "active": "b", "expiry_notices": false })).unwrap();
        set_active(&host, "a").unwrap();
        assert!(!expiry_notices(&host));
        assert_eq!(active_id(&host).as_deref(), Some("a"));

        // The item vanished: the connection does not disappear altogether but
        // falls back to the first, or a person sees an empty screen instead of
        // their Vaults.
        set_active(&host, "no-such-item").unwrap();
        assert_eq!(connection(&host).await.unwrap().entry_id, "a");
    }

    #[tokio::test]
    async fn hidden_fields_are_asked_for_separately() {
        // The core is entitled not to give the values of `kw-*` in a list: the
        // plugin then asks for each one separately, and the connection is
        // assembled all the same.
        let host = Fake::with(vec![Fake::item("a", "Dev", &[(ADDR, "")])]);
        host.secrets
            .lock()
            .unwrap()
            .insert(("a".into(), ADDR.into()), "https://vault.dev".into());
        let links = connections(&host).await;
        assert_eq!(links.len(), 1);
        assert_eq!(links[0].addr, "https://vault.dev");
    }

    #[tokio::test]
    async fn a_forgotten_connection_stops_being_a_connection() {
        let host = vault();
        forget(&host, "b").await.unwrap();
        let links = connections(&host).await;
        assert_eq!(links.iter().map(|l| l.entry_id.as_str()).collect::<Vec<_>>(), ["a"]);
        // The shares of the unseal key stay with the person: only our own is
        // taken away.
        let (_, written) = host.writes.lock().unwrap()[0].clone();
        assert!(written.iter().all(|(_, v)| v.is_empty()));
        assert_eq!(written.len(), GONE.len());
    }

    #[tokio::test]
    async fn the_ledger_creates_its_hidden_item_itself() {
        let host = Fake::with(vec![Fake::item("a", "Dev", &[(ADDR, "https://vault.dev")])]);
        store_issued(&host, "https://vault.dev/", "[]").await.unwrap();
        // The item is created for the address with no trailing slash, or it
        // would not be found on the next call.
        let (name, fields) = host.created.lock().unwrap()[0].clone();
        assert!(host.items.lock().unwrap().iter().any(|i| i.hidden), "the ledger is a service item");
        assert_eq!(name, "keyward · vault · vault.dev");
        assert!(fields.contains(&(ROOT_ADDR.to_string(), "https://vault.dev".to_string())));
        assert_eq!(issued_json(&host, "https://vault.dev").await.as_deref(), Some("[]"));
        // A second time no new item is created.
        store_issued(&host, "https://vault.dev", "[1]").await.unwrap();
        assert_eq!(host.created.lock().unwrap().len(), 1);
    }

    #[tokio::test]
    async fn a_revoked_root_leaves_the_list_and_the_item_stays() {
        let host = vault();
        assert_eq!(root_token(&host, "https://vault.prod/").await.as_deref(), Some("hvs.root"));
        assert_eq!(root_notes(&host).await.len(), 1);

        forget_root(&host, "https://vault.prod").await.unwrap();
        assert!(root_token(&host, "https://vault.prod").await.is_none());
        assert!(root_notes(&host).await.is_empty(), "there is no token, so there is nothing to show");
        // The trace of when that happened stays.
        let (_, written) = host.writes.lock().unwrap().last().cloned().unwrap();
        assert!(written.iter().any(|(k, v)| k == ROOT_REVOKED && !v.is_empty()));
    }

    #[tokio::test]
    async fn the_reason_there_is_no_connection_is_named() {
        let locked = Fake { locked: true, ..Default::default() };
        assert_eq!(why_no_credentials(&locked), "err.vaultLockedUnlockIt");
        assert_eq!(why_no_credentials(&Fake::default()), "err.noItemWithVaultAddr");
        // There are items, but the chosen one is not among them: the third
        // reason.
        assert!(why_no_credentials(&vault()).contains("err.connectionItemMissing"));
    }
}
