//! A host for the plugins' own tests: an in-memory vault that refuses a plugin
//! exactly as the daemon refuses an external one.
//!
//! A test that runs a plugin against a lenient fake proves nothing about the
//! daemon: the Vault plugin read a person's own fields for months, every test
//! passed, and the day the daemon started to refuse it the screen said "Vault
//! is not connected". Here every refusal is recorded, so a test can say "and it
//! reached for nothing it may not have".

use std::path::PathBuf;
use std::sync::Mutex;

use serde_json::Value;

use crate::{external_may_read, Host, ItemDetail, Result, SecretField, TaggedItem, VaultEntry};

/// One field of an item: its name, its value and whether it is hidden.
#[derive(Debug, Clone)]
struct Field {
    name: String,
    value: String,
    hidden: bool,
}

#[derive(Debug, Clone)]
struct Item {
    id: String,
    name: String,
    hidden: bool,
    owned: bool,
    fields: Vec<Field>,
}

/// The strict host. Build it with [`StrictHost::new`] and [`StrictHost::item`].
pub struct StrictHost {
    unlocked: bool,
    server: Option<String>,
    items: Mutex<Vec<Item>>,
    refused: Mutex<Vec<(String, String)>>,
    settings: Mutex<Value>,
    keychain: Mutex<std::collections::HashMap<String, String>>,
    dir: PathBuf,
    next: Mutex<u32>,
}

impl Default for StrictHost {
    fn default() -> Self {
        Self::new()
    }
}

impl StrictHost {
    /// An open, empty vault.
    pub fn new() -> Self {
        let dir = std::env::temp_dir().join(format!("kw-strict-{}-{}", std::process::id(), rand_suffix()));
        let _ = std::fs::create_dir_all(&dir);
        Self {
            unlocked: true,
            server: None,
            items: Mutex::new(Vec::new()),
            refused: Mutex::new(Vec::new()),
            settings: Mutex::new(Value::Null),
            keychain: Mutex::new(std::collections::HashMap::new()),
            dir,
            next: Mutex::new(0),
        }
    }

    /// The account's server.
    pub fn server(mut self, url: &str) -> Self {
        self.server = Some(url.to_string());
        self
    }

    /// A secret the plugin keeps in the keychain.
    pub fn keychain(self, name: &str, value: &str) -> Self {
        self.keychain.lock().unwrap().insert(name.to_string(), value.to_string());
        self
    }

    /// A locked vault: nothing can be read.
    pub fn locked(mut self) -> Self {
        self.unlocked = false;
        self
    }

    /// Add an item. `fields` are `(name, value, hidden)`.
    pub fn item(self, id: &str, name: &str, fields: &[(&str, &str, bool)]) -> Self {
        self.items.lock().unwrap().push(Item {
            id: id.to_string(),
            name: name.to_string(),
            hidden: false,
            owned: true,
            fields: fields
                .iter()
                .map(|(n, v, h)| Field { name: (*n).to_string(), value: (*v).to_string(), hidden: *h })
                .collect(),
        });
        self
    }

    /// Every field the plugin asked for and was refused, as `(item, field)`.
    pub fn refused(&self) -> Vec<(String, String)> {
        self.refused.lock().unwrap().clone()
    }

    /// An item's field as it is now, for checking what a plugin wrote.
    pub fn field(&self, entry_id: &str, name: &str) -> Option<String> {
        let items = self.items.lock().unwrap();
        let item = items.iter().find(|i| i.id == entry_id)?;
        item.fields.iter().find(|f| f.name.eq_ignore_ascii_case(name)).map(|f| f.value.clone())
    }
}

fn rand_suffix() -> u128 {
    std::time::SystemTime::now().duration_since(std::time::UNIX_EPOCH).map(|d| d.as_nanos()).unwrap_or(0)
}

#[async_trait::async_trait]
impl Host for StrictHost {
    fn unlocked(&self) -> bool {
        self.unlocked
    }

    fn entries(&self) -> Vec<VaultEntry> {
        if !self.unlocked {
            return Vec::new();
        }
        self.items
            .lock()
            .unwrap()
            .iter()
            .filter(|i| i.fields.iter().any(|f| f.name.to_ascii_lowercase().starts_with("kw-")))
            .map(|i| VaultEntry {
                id: i.id.clone(),
                name: i.name.clone(),
                fields: i
                    .fields
                    .iter()
                    .filter(|f| f.name.to_ascii_lowercase().starts_with("kw-"))
                    .map(|f| (f.name.clone(), f.value.clone()))
                    .collect(),
                public_key: None,
                private_key: None,
            })
            .collect()
    }

    async fn item_detail(&self, _entry_id: &str) -> Option<ItemDetail> {
        None
    }

    async fn secret(&self, entry_id: &str, field: SecretField) -> Result<String> {
        if !self.unlocked {
            anyhow::bail!("err.vaultLocked");
        }
        let name = match &field {
            SecretField::Custom(n) => n.clone(),
            other => format!("{other:?}"),
        };
        if !external_may_read(&field) {
            self.refused.lock().unwrap().push((entry_id.to_string(), name));
            anyhow::bail!("err.pluginForeignField");
        }
        self.field(entry_id, &name).ok_or_else(|| anyhow::anyhow!("err.noSuchField"))
    }

    async fn note_fields(&self, entry_id: &str) -> Result<Vec<String>> {
        let items = self.items.lock().unwrap();
        let item = items.iter().find(|i| i.id == entry_id).ok_or_else(|| anyhow::anyhow!("err.itemNotFound"))?;
        Ok(item.fields.iter().map(|f| f.name.clone()).collect())
    }

    fn tagged_items(&self, field: &str) -> Vec<TaggedItem> {
        if !self.unlocked {
            return Vec::new();
        }
        self.items
            .lock()
            .unwrap()
            .iter()
            .filter(|i| i.fields.iter().any(|f| f.name.eq_ignore_ascii_case(field)))
            .map(|i| TaggedItem {
                id: i.id.clone(),
                name: i.name.clone(),
                hidden: i.hidden,
                owned: i.owned,
                // Hidden values are not in a list, as in the daemon.
                fields: i
                    .fields
                    .iter()
                    .map(|f| (f.name.clone(), if f.hidden { String::new() } else { f.value.clone() }))
                    .collect(),
            })
            .collect()
    }

    async fn create_note(&self, name: &str, fields: Vec<(String, String)>, hidden: bool) -> Result<String> {
        let id = {
            let mut n = self.next.lock().unwrap();
            *n += 1;
            format!("note-{n}")
        };
        self.items.lock().unwrap().push(Item {
            id: id.clone(),
            name: name.to_string(),
            hidden,
            owned: true,
            fields: fields.into_iter().map(|(name, value)| Field { name, value, hidden: true }).collect(),
        });
        Ok(id)
    }

    async fn trash_item(&self, entry_id: &str) -> Result<()> {
        self.items.lock().unwrap().retain(|i| i.id != entry_id);
        Ok(())
    }

    async fn set_fields(&self, entry_id: &str, fields: Vec<(String, String)>) -> Result<()> {
        let mut items = self.items.lock().unwrap();
        let item = items.iter_mut().find(|i| i.id == entry_id).ok_or_else(|| anyhow::anyhow!("err.itemNotFound"))?;
        for (name, value) in fields {
            item.fields.retain(|f| !f.name.eq_ignore_ascii_case(&name));
            if !value.is_empty() {
                item.fields.push(Field { name, value, hidden: true });
            }
        }
        Ok(())
    }

    fn notice(&self, _title: &str, _body: &str) {}

    fn server(&self) -> Option<String> {
        self.server.clone()
    }

    async fn keychain_has(&self, name: &str) -> bool {
        self.keychain.lock().unwrap().contains_key(name)
    }

    async fn keychain_get(&self, name: &str) -> Result<String> {
        self.keychain.lock().unwrap().get(name).cloned().ok_or_else(|| anyhow::anyhow!("err.keychainNoSecret"))
    }

    async fn keychain_set(&self, name: &str, value: &str) -> Result<()> {
        self.keychain.lock().unwrap().insert(name.to_string(), value.to_string());
        Ok(())
    }

    async fn keychain_forget(&self, name: &str) -> Result<()> {
        self.keychain.lock().unwrap().remove(name);
        Ok(())
    }

    async fn copy_text(&self, _value: &str) -> Result<u64> {
        Ok(30)
    }

    fn state_dir(&self) -> PathBuf {
        self.dir.clone()
    }

    fn settings(&self) -> Value {
        self.settings.lock().unwrap().clone()
    }

    fn set_settings(&self, value: Value) -> Result<()> {
        *self.settings.lock().unwrap() = value;
        Ok(())
    }
}
