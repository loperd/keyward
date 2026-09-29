//! The ssh plugin: routes from a host to a vault item, and the ssh agent's
//! sockets.
//!
//! The core knows nothing of any of it. The table of routes, the socket
//! directory `~/.keyward/s`, the shared socket `~/.keyward/agent.sock` and the
//! plugin's own settings live here; what sticks out is one `call` method and
//! the `on_event` events.
//!
//! The main property has not gone anywhere: a socket of its own is raised for
//! every host, and **exactly one** key lies on it. There is no trying key after
//! key, and not by agreement but because there is nothing else to show ssh.

use std::collections::HashMap;
use std::sync::Arc;

use keyward_plugin::{arg, out, Host, HostEvent, Manifest, Origin, Permission, Plugin, Result, VaultEntry};
use serde::{Deserialize, Serialize};
use serde_json::Value;

pub mod agent;
pub mod glob;
pub mod mapping;
mod table;

pub use mapping::{Mapping, MappingTable, Resolution};
pub use table::build_table;

/// The shared socket's key in the table of live sockets: not a path, so as not
/// to collide with a host somebody named that way.
const SHARED_SLOT: &str = "\u{1}shared";

// -- The plugin's settings -------------------------------------------------

/// Whether to ask for confirmation when the ssh agent signs.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum Ask {
    /// Never, except for keys marked `kw-confirm` in the item itself.
    Never,
    /// Always, for any key.
    Always,
}

/// The plugin's own settings. These used to be three fields in the core's
/// `Settings`; the core has lost them, and the old values are carried over here
/// at the first call.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(default)]
pub struct SshSettings {
    pub agent_enabled: bool,
    pub ask: Ask,
    /// The shared agent socket with every key, for programs that do not read
    /// ssh_config and expect SSH_AUTH_SOCK. Off by default: it is the very
    /// trying of key after key that keyward walks away from.
    pub shared_socket: bool,
}

impl Default for SshSettings {
    fn default() -> Self {
        Self { agent_enabled: true, ask: Ask::Never, shared_socket: false }
    }
}

impl SshSettings {
    /// Fetches the settings from the core. An empty place means not
    /// "everything by default" but "the plugin is here for the first time": then
    /// the old shared settings file is looked into.
    fn read(host: &dyn Host) -> Self {
        let raw = host.settings();
        let untouched = raw.as_object().is_none_or(|o| {
            !o.contains_key("agent_enabled") && !o.contains_key("ask") && !o.contains_key("shared_socket")
        });
        if untouched {
            return Self::inherited();
        }
        serde_json::from_value(raw).unwrap_or_default()
    }

    /// Carrying over the old `ssh_agent_enabled`, `ssh_ask` and `ssh_socket`
    /// values out of `~/.keyward/settings.json`. Read as raw JSON rather than
    /// through the core's type: those fields are no longer in it, while in a
    /// person's file they still lie there.
    fn inherited() -> Self {
        let mut s = Self::default();
        let Ok(text) = std::fs::read_to_string(keyward_core::paths::settings_file()) else {
            return s;
        };
        let Ok(v) = serde_json::from_str::<Value>(&text) else { return s };
        if let Some(b) = v.get("ssh_agent_enabled").and_then(Value::as_bool) {
            s.agent_enabled = b;
        }
        if let Some(b) = v.get("ssh_socket").and_then(Value::as_bool) {
            s.shared_socket = b;
        }
        if v.get("ssh_ask").and_then(Value::as_str) == Some("always") {
            s.ask = Ask::Always;
        }
        s
    }
}

// -- The envelopes of the operations ---------------------------------------

/// A private key a person pasted into the editor, to be shown before it is
/// saved. Not `Debug`: it holds the key.
#[derive(Deserialize)]
struct InspectKeyArgs {
    private_key: String,
    #[serde(default)]
    passphrase: Option<String>,
}

#[derive(Debug, Deserialize)]
struct SetHostsArgs {
    entry_id: String,
    hosts: String,
}

#[derive(Debug, Deserialize)]
struct ResolveArgs {
    host: String,
    #[serde(default)]
    user: Option<String>,
    #[serde(default)]
    port: Option<u16>,
}

#[derive(Debug, Serialize)]
struct Resolved {
    resolution: Resolution,
    socket: String,
}

/// What used to lie in the core's `Status` as the `mappings`, `live_sockets`,
/// `warnings`, `unmapped_ssh_keys` and `ssh_socket` fields.
#[derive(Debug, Serialize)]
struct StatusOut {
    mappings: usize,
    live_sockets: usize,
    warnings: Vec<String>,
    /// The names of the vault's ssh keys that are bound to no host.
    unmapped: Vec<String>,
    /// The shared socket's path, if it is being served just now.
    socket: Option<String>,
}

// -- The plugin ------------------------------------------------------------

/// The live state: the table of routes and the sockets under it.
#[derive(Default)]
struct Inner {
    table: MappingTable,
    warnings: Vec<String>,
    /// The items with keys: `resolve` takes from them the one it raises a
    /// socket for. A locked vault has to clear them out of here.
    entries: Vec<VaultEntry>,
    live: HashMap<String, tokio::task::JoinHandle<()>>,
}

pub struct SshPlugin {
    inner: tokio::sync::Mutex<Inner>,
    /// The same items under a shared lock: the shared agent socket reads
    /// them.
    shared_entries: Arc<std::sync::RwLock<Vec<VaultEntry>>>,
    /// A core that outlives a call. The agent socket answers ssh when ssh asks
    /// it, and it needs a signature at that minute rather than inside somebody
    /// else's `call`. The runtime puts it here through `Plugin::attach`.
    core: std::sync::RwLock<Option<Arc<dyn Host>>>,
}

impl Default for SshPlugin {
    fn default() -> Self {
        Self::new()
    }
}

impl SshPlugin {
    pub fn new() -> Self {
        ensure_socket_dir();
        Self {
            inner: tokio::sync::Mutex::new(Inner::default()),
            shared_entries: Arc::new(std::sync::RwLock::new(Vec::new())),
            core: std::sync::RwLock::new(None),
        }
    }

    /// The core for the agent's sockets. Its absence means the plugin was
    /// started without being attached: there is nothing to raise a socket with
    /// and nobody to sign.
    fn core(&self) -> Result<Arc<dyn Host>> {
        self.core
            .read()
            .ok()
            .and_then(|c| c.clone())
            .ok_or_else(|| anyhow::anyhow!("the plugin is not attached to a core: there is nobody to sign"))
    }

    /// Catch up with the core when there is no table yet.
    ///
    /// A plugin's separate process comes up at the first call and knows
    /// nothing of the vault having been opened before it was born: the
    /// `Unlocked` and `EntriesChanged` events went past. So the very first
    /// request has to build the table itself — otherwise `resolve` on a cold
    /// process would honestly answer "no match" over a vault full of keys.
    async fn warm_up(&self, host: &dyn Host) {
        if !self.inner.lock().await.entries.is_empty() {
            return;
        }
        if host.entries().is_empty() {
            return;
        }
        self.rebuild(host).await;
    }

    /// Rebuilds the table of routes out of the core's items.
    async fn rebuild(&self, host: &dyn Host) {
        let entries = host.entries();
        let (table, warnings) = build_table(&entries);
        tracing::info!(mappings = table.len(), "the routes were rebuilt");
        if let Ok(mut shared) = self.shared_entries.write() {
            *shared = entries.clone();
        }
        let cfg = SshSettings::read(host);
        let mut inner = self.inner.lock().await;
        inner.table = table;
        inner.warnings = warnings;
        inner.entries = entries;
        self.ensure_shared_socket(&mut inner, &cfg);
    }

    /// The shared agent socket: up exactly when the setting has it on and at
    /// least one open vault holds keys. In every other case it is down, so that
    /// SSH_AUTH_SOCK does not silently point at nothing.
    fn ensure_shared_socket(&self, inner: &mut Inner, cfg: &SshSettings) {
        let path = keyward_core::paths::shared_agent_socket();
        let slot = SHARED_SLOT.to_string();
        let want = cfg.agent_enabled && cfg.shared_socket && !inner.entries.is_empty();
        let live = inner.live.get(&slot).is_some_and(|h| !h.is_finished());
        if want && !live {
            inner.live.remove(&slot);
            let confirm_all = cfg.ask == Ask::Always;
            let Ok(core) = self.core() else {
                tracing::warn!("the shared agent socket was not raised: the plugin is not attached to a core");
                return;
            };
            match agent::spawn_shared(&path, Arc::clone(&self.shared_entries), confirm_all, core) {
                Ok(handle) => {
                    inner.live.insert(slot, handle);
                }
                Err(e) => tracing::warn!(error = %e, "the shared agent socket was not raised"),
            }
        } else if !want && live {
            if let Some(h) = inner.live.remove(&slot) {
                h.abort();
            }
            let _ = std::fs::remove_file(&path);
        }
    }
}

/// The shared socket's path, if it is being served just now.
fn shared_socket(inner: &Inner) -> Option<String> {
    inner
        .live
        .get(SHARED_SLOT)
        .is_some_and(|h| !h.is_finished())
        .then(|| keyward_core::paths::shared_agent_socket().to_string_lossy().into_owned())
}

/// Takes every agent socket down. Needed whenever the keys stop being
/// available: otherwise ssh goes on signing with a "locked" key.
fn drop_sockets(inner: &mut Inner) {
    for (_, handle) in inner.live.drain() {
        handle.abort();
    }
    let _ = std::fs::remove_file(keyward_core::paths::shared_agent_socket());
    let dir = keyward_core::paths::agent_socket_dir();
    let _ = std::fs::remove_dir_all(&dir);
    let _ = std::fs::create_dir_all(&dir);
    // A directory created afresh takes its mode from umask, usually 0755. The
    // daemon set 0700 at start-up and then undid it itself.
    let _ = restrict(&dir);
}

/// Puts the public key next to the socket.
///
/// Without it, `IdentitiesOnly yes` stops ssh offering the agent's key at all:
/// under that flag only the keys named in `IdentityFile` are offered, and a
/// person may have no keys on disk whatsoever. Then ssh silently goes off to
/// its own and gets "Permission denied (publickey)" over a socket that is up
/// and working. With the file, exactly one key is offered — ours — and the
/// agent still does the signing: the private half never reaches the disk.
fn write_pubkey(socket: &std::path::Path, public_key: Option<&str>) {
    let path = socket.with_extension("pub");
    let Some(key) = public_key.map(str::trim).filter(|k| !k.is_empty()) else {
        let _ = std::fs::remove_file(&path);
        return;
    };
    if let Err(e) = std::fs::write(&path, format!("{key}\n")) {
        tracing::warn!(error = %e, path = %path.display(), "the public key was not written");
    }
}

/// The socket directory: we create it ourselves and close it to others
/// ourselves.
fn ensure_socket_dir() {
    let dir = keyward_core::paths::agent_socket_dir();
    if let Err(e) = std::fs::create_dir_all(&dir) {
        tracing::warn!(error = %e, dir = %dir.display(), "the agent socket directory was not created");
        return;
    }
    if let Err(e) = restrict(&dir) {
        tracing::warn!(error = %e, dir = %dir.display(), "the mode on the socket directory was not set");
    }
}

/// Mode 0700 on the directories and 0600 on the socket.
fn restrict(path: &std::path::Path) -> anyhow::Result<()> {
    use std::os::unix::fs::PermissionsExt as _;
    let meta = std::fs::metadata(path)?;
    let mode = if meta.is_dir() { 0o700 } else { 0o600 };
    std::fs::set_permissions(path, std::fs::Permissions::from_mode(mode))?;
    Ok(())
}

/// An ssh key of the vault as the plugin's screens show it: a name and what it
/// is bound to.
#[derive(Debug, Clone, serde::Serialize, serde::Deserialize)]
pub struct SshKeyEntry {
    pub id: String,
    pub name: String,
    /// The contents of `kw-host`; empty means the key is bound to no host yet.
    pub hosts: String,
}

/// The vault's ssh keys in the shape the interface shows them.
fn keys(host: &dyn Host) -> Vec<SshKeyEntry> {
    let mut out: Vec<SshKeyEntry> = host
        .entries()
        .iter()
        .filter(|e| e.public_key.is_some() || e.field(crate::table::HOST).is_some())
        .map(|e| SshKeyEntry {
            id: e.id.clone(),
            name: e.name.clone(),
            hosts: e.field(crate::table::HOST).unwrap_or_default().to_string(),
        })
        .collect();
    out.sort_by(|a, b| a.name.cmp(&b.name));
    out
}

#[async_trait::async_trait]
impl Plugin for SshPlugin {
    fn manifest(&self) -> Manifest {
        Manifest {
            id: "ssh".into(),
            title: "SSH".into(),
            icon: "route".into(),
            section: true,
            needs_unlocked: true,
            // A built-in plugin has the application's version: it is the
            // application.
            version: env!("CARGO_PKG_VERSION").into(),
            // The key, not the words: the showcase and the card are drawn by
            // the window, which knows its own language.
            description: "plugin.ssh.description".into(),
            origin: Origin::Builtin,
            // Whether the plugin is off is the daemon's register's business;
            // here is the card's initial state, which the register overrides.
            enabled: true,
            // Exactly what the plugin uses: items with `kw-*` fields, writing
            // `kw-host` when a host is bound, a notification about a signature,
            // and the signing itself — the plugin has no key, the core signs.
            permissions: vec![
                Permission::Entries,
                Permission::ItemsWrite,
                Permission::Notices,
                Permission::SshSign,
            ],
            probe: false,
        }
    }

    fn attach(&self, host: Arc<dyn Host>) {
        if let Ok(mut slot) = self.core.write() {
            *slot = Some(host);
        }
    }

    async fn call(&self, host: &dyn Host, op: &str, payload: Value) -> Result<Value> {
        self.warm_up(host).await;
        match op {
            "keys" => out(keys(host)),

            // What a pasted key is — its public half, fingerprint and kind —
            // for the editor to show before saving. The same parser the vault
            // saves with: whatever this accepts, the save accepts too. The
            // private key is read and dropped; it is not kept or answered.
            "inspect_key" => {
                let a: InspectKeyArgs = arg(payload)?;
                out(keyward_sshkey::import(&a.private_key, a.passphrase.as_deref())?.summary())
            }

            "set_hosts" => {
                let a: SetHostsArgs = arg(payload)?;
                // An empty value means "unbind"; the core decides, and the
                // item lies with it.
                host.set_fields(&a.entry_id, vec![(crate::table::HOST.to_string(), a.hosts.trim().to_string())])
                    .await?;
                self.rebuild(host).await;
                out(keys(host))
            }

            "hosts" => {
                let inner = self.inner.lock().await;
                out(inner.table.mappings.clone())
            }

            "resolve" => {
                let a: ResolveArgs = arg(payload)?;
                self.resolve(host, a).await
            }

            "status" => {
                let unmapped: Vec<String> = keys(host)
                    .into_iter()
                    .filter(|k| k.hosts.trim().is_empty())
                    .map(|k| k.name)
                    .collect();
                let inner = self.inner.lock().await;
                out(StatusOut {
                    mappings: inner.table.len(),
                    live_sockets: inner.live.len(),
                    warnings: inner.warnings.clone(),
                    unmapped,
                    socket: shared_socket(&inner),
                })
            }

            "settings" => out(SshSettings::read(host)),

            "set_settings" => {
                let was_on = SshSettings::read(host).agent_enabled;
                let cfg: SshSettings = arg(payload)?;
                host.set_settings(serde_json::to_value(&cfg)?)?;
                let mut inner = self.inner.lock().await;
                // An agent that was switched off has to stop serving
                // connections at once rather than after a restart.
                if was_on && !cfg.agent_enabled {
                    drop_sockets(&mut inner);
                }
                // The shared socket follows its own switch immediately.
                self.ensure_shared_socket(&mut inner, &cfg);
                out(cfg)
            }

            "snippet" => out(keyward_core::paths::ssh_config_snippet()),

            other => anyhow::bail!("the ssh plugin does not know the operation \"{other}\""),
        }
    }

    async fn on_event(&self, host: &dyn Host, event: HostEvent) {
        match event {
            // Locked means the keys are gone: the sockets come down and the
            // items are forgotten, or the agent goes on signing from memory.
            HostEvent::Locked => {
                let mut inner = self.inner.lock().await;
                drop_sockets(&mut inner);
                inner.entries.clear();
                inner.table = MappingTable::default();
                inner.warnings.clear();
                if let Ok(mut shared) = self.shared_entries.write() {
                    shared.clear();
                }
            }
            HostEvent::Unlocked | HostEvent::EntriesChanged => self.rebuild(host).await,
            // The agent has no use for the minute tick: the sockets live as
            // long as the tasks do.
            HostEvent::Tick => {}
        }
    }
}

impl SshPlugin {
    /// "Which socket to give ssh for this destination". The answer is the path
    /// of a socket holding exactly one key, raised right now.
    async fn resolve(&self, host: &dyn Host, a: ResolveArgs) -> Result<Value> {
        let cfg = SshSettings::read(host);
        if !cfg.agent_enabled {
            // An agent that is off has to behave as one that is not there: ssh
            // simply goes its ordinary way over key files.
            return Ok(Value::Null);
        }
        // An empty host name deserves no key: it used to match the pattern `*`
        // and raise a socket named `.sock`.
        if a.host.trim().is_empty() {
            return Ok(Value::Null);
        }

        let mut inner = self.inner.lock().await;
        let Some(resolution) = inner.table.resolve(&a.host, a.user.as_deref(), a.port) else {
            return Ok(Value::Null);
        };

        if !resolution.ambiguous_with.is_empty() {
            tracing::warn!(
                host = %a.host,
                winner = %resolution.mapping.entry_name,
                others = ?resolution.ambiguous_with,
                "ambiguous patterns; the winner was chosen by a tie-break"
            );
        }

        let entry = inner
            .entries
            .iter()
            .find(|e| e.id == resolution.mapping.entry_id)
            .cloned()
            .ok_or_else(|| {
                anyhow::anyhow!("the item {} vanished from the source", resolution.mapping.entry_name)
            })?;

        let path = keyward_core::paths::agent_socket(&a.host);
        // The ledger is kept by the socket's file name rather than the host's.
        //
        // The file name is sanitised: everything but latin letters, digits, a
        // dot, a hyphen and an underscore turns into `_`. So different hosts can
        // give one file — `münchen.example.com` and `mänchen.example.com` both
        // give `m_nchen.example.com.sock`. While the ledger was kept by the raw
        // host, the second resolve overwrote the first one's socket, and the
        // first was counted as live and got somebody else's key: ssh went to one
        // host with another one's key.
        let slot = path.to_string_lossy().into_owned();
        let already_live = inner.live.get(&slot).is_some_and(|h| !h.is_finished());

        if !already_live {
            inner.live.remove(&slot);
            let confirm = resolution.mapping.confirm || cfg.ask == Ask::Always;
            write_pubkey(&path, entry.public_key.as_deref());
            match agent::spawn(&path, entry, resolution.mapping.clone(), confirm, self.core()?) {
                Ok(handle) => {
                    inner.live.insert(slot, handle);
                }
                Err(e) => anyhow::bail!("the agent socket will not come up: {e}"),
            }
        }

        out(Resolved { resolution, socket: path.to_string_lossy().into_owned() })
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn pubkey_lands_next_to_the_socket_and_leaves_with_it() {
        // Without this file, ssh with `IdentitiesOnly yes` will not offer the
        // agent's key.
        let dir = std::env::temp_dir().join(format!("kw-pub-{}", std::process::id()));
        std::fs::create_dir_all(&dir).unwrap();
        let sock = dir.join("host.example.com.sock");
        let pubfile = dir.join("host.example.com.pub");

        write_pubkey(&sock, Some("ssh-ed25519 AAAA... kw"));
        assert_eq!(std::fs::read_to_string(&pubfile).unwrap(), "ssh-ed25519 AAAA... kw\n");

        // An item with no public key must be left with no file.
        write_pubkey(&sock, None);
        assert!(!pubfile.exists());
        let _ = std::fs::remove_dir_all(&dir);
    }

    use keyward_plugin::{ItemDetail, SecretField, TaggedItem};
    use std::path::PathBuf;
    use std::sync::Mutex;

    /// Every keyward path is read out of `KEYWARD_HOME` on each call, so they
    /// are led off into a directory of our own and the tests do not sweep real
    /// sockets away.
    fn sandbox() -> PathBuf {
        use std::sync::Once;
        static ONCE: Once = Once::new();
        let dir = std::env::temp_dir().join(format!("keyward-ssh-tests-{}", std::process::id()));
        ONCE.call_once(|| {
            let _ = std::fs::create_dir_all(&dir);
            std::env::set_var("KEYWARD_HOME", &dir);
        });
        dir
    }

    /// The core as a test sees it: items and settings in memory, everything
    /// else a stub.
    struct FakeHost {
        entries: Vec<VaultEntry>,
        settings: Mutex<Value>,
        written: Mutex<Vec<(String, Vec<(String, String)>)>>,
    }

    impl FakeHost {
        fn new(entries: Vec<VaultEntry>) -> Self {
            Self {
                entries,
                settings: Mutex::new(serde_json::to_value(SshSettings::default()).unwrap()),
                written: Mutex::new(Vec::new()),
            }
        }
    }

    #[async_trait::async_trait]
    impl Host for FakeHost {
        fn unlocked(&self) -> bool {
            true
        }
        fn entries(&self) -> Vec<VaultEntry> {
            self.entries.clone()
        }
        async fn item_detail(&self, _entry_id: &str) -> Option<ItemDetail> {
            None
        }
        async fn secret(&self, _entry_id: &str, _field: SecretField) -> Result<String> {
            anyhow::bail!("there are no secrets in the test")
        }
        async fn note_fields(&self, _entry_id: &str) -> Result<Vec<String>> {
            Ok(Vec::new())
        }
        fn tagged_items(&self, _field: &str) -> Vec<TaggedItem> {
            Vec::new()
        }
        async fn create_note(&self, _name: &str, _fields: Vec<(String, String)>, _hidden: bool) -> Result<String> {
            anyhow::bail!("the test creates no items")
        }
        async fn trash_item(&self, _entry_id: &str) -> Result<()> {
            Ok(())
        }
        async fn set_fields(&self, entry_id: &str, fields: Vec<(String, String)>) -> Result<()> {
            self.written.lock().unwrap().push((entry_id.to_string(), fields));
            Ok(())
        }
        fn notice(&self, _title: &str, _body: &str) {}
        fn state_dir(&self) -> PathBuf {
            sandbox()
        }
        fn settings(&self) -> Value {
            self.settings.lock().unwrap().clone()
        }
        fn set_settings(&self, value: Value) -> Result<()> {
            *self.settings.lock().unwrap() = value;
            Ok(())
        }
    }

    fn key(id: &str, name: &str, hosts: Option<&str>) -> VaultEntry {
        // The fields are set one at a time: an item has a `Drop`, and a
        // struct-update expression will not move such a type.
        let mut e = VaultEntry::default();
        e.id = id.to_string();
        e.name = name.to_string();
        e.set_field(crate::table::HOST, hosts.unwrap_or_default());
        e.public_key = Some("ssh-ed25519 AAAA test".to_string());
        e
    }

    fn host_with_keys() -> FakeHost {
        sandbox();
        FakeHost::new(vec![
            key("2", "prod", Some("*.prod.example.com")),
            key("1", "gitlab", Some("git.example.com")),
            key("3", "nobodys", None),
        ])
    }

    #[tokio::test]
    async fn unknown_op_is_the_plugins_own_error() {
        let host = host_with_keys();
        let err = SshPlugin::new().call(&host, "fly", Value::Null).await.unwrap_err();
        assert!(err.to_string().contains("fly"), "the error has to name the operation: {err}");
    }

    #[tokio::test]
    async fn a_pasted_key_is_shown_by_its_public_half_only() {
        let host = host_with_keys();
        let pem = include_str!("../../../sshkey/tests/fixtures/ssh/ed25519");
        let v = SshPlugin::new()
            .call(&host, "inspect_key", serde_json::json!({ "private_key": pem }))
            .await
            .unwrap();
        assert_eq!(v["fingerprint"], "SHA256:/isoPc4zsyI5eGGgBTllIrgXx/hHi7HWN3AqKBECz5w");
        assert_eq!(v["algorithm"], "ssh-ed25519");
        assert!(!v.to_string().contains("PRIVATE"), "the private key must not come back: {v}");
        let err = SshPlugin::new()
            .call(&host, "inspect_key", serde_json::json!({ "private_key": "ssh-ed25519 AAAA" }))
            .await
            .unwrap_err();
        assert!(err.to_string().starts_with("err.sshKeyIsPublic"), "{err}");
    }

    #[tokio::test]
    async fn keys_are_named_sorted_and_include_unbound_ones() {
        let host = host_with_keys();
        let v = SshPlugin::new().call(&host, "keys", Value::Null).await.unwrap();
        let list: Vec<SshKeyEntry> = serde_json::from_value(v).unwrap();
        assert_eq!(list.len(), 3);
        assert_eq!(list[0].name, "gitlab");
        assert_eq!(list[0].hosts, "git.example.com");
        let free = list.iter().find(|k| k.name == "nobodys").expect("an unbound key has to stay in the list");
        assert_eq!(free.hosts, "");
    }

    #[tokio::test]
    async fn set_hosts_writes_kw_host_and_rebuilds_the_table() {
        let host = host_with_keys();
        let p = SshPlugin::new();
        p.call(&host, "set_hosts", serde_json::json!({"entry_id": "3", "hosts": " a.example.com "}))
            .await
            .unwrap();
        let written = host.written.lock().unwrap().clone();
        assert_eq!(written.len(), 1);
        assert_eq!(written[0].0, "3");
        assert_eq!(written[0].1, vec![("kw-host".to_string(), "a.example.com".to_string())]);
        // The table is rebuilt in place: the interface need not call `hosts`
        // through a separate event.
        let v = p.call(&host, "hosts", Value::Null).await.unwrap();
        let hosts: Vec<Mapping> = serde_json::from_value(v).unwrap();
        assert_eq!(hosts.len(), 2, "FakeHost's items do not change, but the table has to be built");
    }

    #[tokio::test]
    async fn entries_changed_builds_the_table() {
        let host = host_with_keys();
        let p = SshPlugin::new();
        p.on_event(&host, HostEvent::EntriesChanged).await;
        let v = p.call(&host, "status", Value::Null).await.unwrap();
        assert_eq!(v["mappings"], 2);
        assert_eq!(v["live_sockets"], 0);
        assert_eq!(v["socket"], Value::Null);
        let unmapped: Vec<String> = serde_json::from_value(v["unmapped"].clone()).unwrap();
        assert_eq!(unmapped, vec!["nobodys".to_string()]);
    }

    #[tokio::test]
    async fn locking_forgets_the_keys() {
        let host = host_with_keys();
        let p = SshPlugin::new();
        p.on_event(&host, HostEvent::Unlocked).await;
        p.on_event(&host, HostEvent::Locked).await;
        let inner = p.inner.lock().await;
        assert!(inner.entries.is_empty(), "the items with keys have to vanish from memory");
        assert!(inner.table.is_empty());
        assert!(inner.live.is_empty());
    }

    #[tokio::test]
    async fn empty_host_gets_no_socket() {
        // An empty `%h` matched the pattern `*` and raised a `.sock` file.
        let host = host_with_keys();
        let p = SshPlugin::new();
        p.on_event(&host, HostEvent::EntriesChanged).await;
        let v = p.call(&host, "resolve", serde_json::json!({"host": "  "})).await.unwrap();
        assert_eq!(v, Value::Null);
    }

    #[tokio::test]
    async fn unknown_host_gets_no_socket() {
        let host = host_with_keys();
        let p = SshPlugin::new();
        p.on_event(&host, HostEvent::EntriesChanged).await;
        let v = p.call(&host, "resolve", serde_json::json!({"host": "no.such.host"})).await.unwrap();
        assert_eq!(v, Value::Null);
    }

    #[tokio::test]
    async fn switched_off_agent_behaves_as_an_absent_one() {
        let host = host_with_keys();
        let p = SshPlugin::new();
        p.on_event(&host, HostEvent::EntriesChanged).await;
        p.call(&host, "set_settings", serde_json::json!({"agent_enabled": false}))
            .await
            .unwrap();
        let v = p
            .call(&host, "resolve", serde_json::json!({"host": "git.example.com"}))
            .await
            .unwrap();
        assert_eq!(v, Value::Null, "with the agent off, resolve has to stay silent");
    }


    /// The showcase promises what the plugin does.
    ///
    /// The daemon reads `plugin.json` and draws the card and asks for consent
    /// by it; the `Manifest` in the code is what the plugin actually is. If they
    /// differ, a person consents to the wrong thing. There is no version in the
    /// file on purpose: the package build puts it there out of `Cargo.toml`.
    #[test]
    fn the_package_manifest_matches_the_code() {
        sandbox();
        let declared: Value = serde_json::from_str(include_str!("../plugin.json")).unwrap();
        let m = SshPlugin::new().manifest();

        assert_eq!(declared["id"], Value::String(m.id.clone()), "the id differs");
        assert_eq!(declared["title"], Value::String(m.title.clone()), "the title differs");
        assert_eq!(declared["icon"], Value::String(m.icon.clone()), "the icon differs");
        assert_eq!(declared["description"], Value::String(m.description.clone()), "the description differs");
        assert_eq!(declared["section"], Value::Bool(m.section), "the section differs");
        assert_eq!(declared["needs_unlocked"], Value::Bool(m.needs_unlocked), "\"needs an open vault\" differs");
        assert_eq!(declared["exec"], "keyward-plugin-ssh", "the wrong program");
        assert!(declared.get("version").is_none(), "a version does not live in plugin.json: the package build puts it there");

        let mut promised: Vec<String> = declared["permissions"]
            .as_array()
            .expect("plugin.json has no permissions")
            .iter()
            .map(|p| p.as_str().unwrap_or_default().to_string())
            .collect();
        let mut real: Vec<String> = m
            .permissions
            .iter()
            .map(|p| serde_json::to_value(p).unwrap().as_str().unwrap().to_string())
            .collect();
        promised.sort();
        real.sort();
        assert_eq!(promised, real, "the showcase promises the wrong permissions");
    }

    #[tokio::test]
    async fn settings_round_trip_through_the_host() {
        let host = host_with_keys();
        let p = SshPlugin::new();
        let v = p.call(&host, "settings", Value::Null).await.unwrap();
        assert_eq!(v["agent_enabled"], true);
        assert_eq!(v["ask"], "never");
        assert_eq!(v["shared_socket"], false);

        let v = p
            .call(&host, "set_settings", serde_json::json!({"agent_enabled": true, "ask": "always", "shared_socket": false}))
            .await
            .unwrap();
        assert_eq!(v["ask"], "always");
        assert_eq!(p.call(&host, "settings", Value::Null).await.unwrap()["ask"], "always");
    }

    #[tokio::test]
    async fn settings_defaults_match_what_the_core_had() {
        let s = SshSettings::default();
        assert!(s.agent_enabled);
        assert_eq!(s.ask, Ask::Never);
        assert!(!s.shared_socket, "the shared socket is a deliberate choice, not a default");
    }

    #[tokio::test]
    async fn snippet_names_the_socket_directory() {
        let host = host_with_keys();
        let v = SshPlugin::new().call(&host, "snippet", Value::Null).await.unwrap();
        let text = v.as_str().unwrap().to_string();
        assert!(text.contains("IdentityAgent"), "in the line for ssh_config: {text}");
        assert!(text.contains("resolve %h %r %p"));
    }

    #[tokio::test]
    async fn manifest_is_what_the_rail_draws() {
        let m = SshPlugin::new().manifest();
        assert_eq!(m.id, "ssh");
        assert_eq!(m.icon, "route");
        assert!(m.section && m.needs_unlocked);
    }
}

#[cfg(test)]
mod dictionary {
    /// The plugin's words live with the plugin, and the window merges them into
    /// the dictionary. They are held to the same rule as the core's: both
    /// languages cover the same keys, with the same values inside a sentence.
    #[test]
    fn both_languages_agree() {
        let ru = include_str!(concat!(env!("CARGO_MANIFEST_DIR"), "/i18n/ru.json"));
        let en = include_str!(concat!(env!("CARGO_MANIFEST_DIR"), "/i18n/en.json"));
        let wrong = keyward_core::text::audit(ru, en);
        assert!(wrong.is_empty(), "{wrong:#?}");
    }
}
