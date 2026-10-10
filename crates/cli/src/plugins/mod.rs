//! The register of plugins, and the core as they see it.
//!
//! There are no plugins built together with the daemon any more: both ssh and
//! HashiCorp arrive from the showcase as ordinary packages and run as separate
//! processes. Somebody else's code has no place next to the vault's keys, and
//! "install a plugin" would otherwise mean "hand over the vault". The kind
//! "built-in" stayed in the types: the daemon has to be able to show such a
//! plugin if it ever builds one into itself again.
//!
//! Hence the signing: private keys are not given to a plugin (`entries` cuts
//! them out), so the core itself signs with the vault's ssh key —
//! [`Host::sign_ssh`], the `ssh_sign` permission.
//!
//! The core, for its part, does not know what a plugin actually does: it passes
//! an envelope along and returns the answer.

mod archive;
mod catalog;
mod external;
mod net;
mod package;
mod publishers;
mod registry;
mod remote;
mod sources;
mod sshsign;

use std::path::PathBuf;
use std::sync::Arc;

use keyward_core::detail::{ItemDetail, SecretField};
use keyward_core::proto::Response;
use keyward_core::source::VaultEntry;
use keyward_plugin::{Host, HostEvent, TaggedItem};
use keyward_vault::Vault;
use serde_json::Value;

use crate::daemon::{Mirror, Shared};
use registry::Entry;

/// The separator between an account and an item in an identifier. Identifiers
/// are unique only within an account, and several accounts can be unlocked at
/// once.
const ACCOUNT_SEP: char = '\u{1}';

/// The plugins' cards: the interface draws its sections and the list of what
/// is installed from them.
pub fn manifests() -> Vec<Value> {
    registry::cards()
}

/// A request to a plugin. The state's mutex has been let go by this point: a
/// plugin goes out to the network and to sockets, and holding the whole daemon
/// on that is not allowed.
pub async fn call(
    shared: &Shared,
    plugin: &str,
    action: &str,
    payload: Value,
    peer: &crate::peer::Peer,
) -> Response {
    let Some(entry) = registry::find(plugin) else {
        return Response::error(keyward_core::fault!("err.noSuchPlugin", "plugin" => plugin));
    };
    // One that is off answers with an error rather than silence: the interface
    // has to be able to explain to a person why a section is empty.
    if !registry::is_enabled(plugin) {
        return Response::error(keyward_core::fault!("err.pluginDisabled", "plugin" => plugin));
    }
    // A built-in plugin runs inside this process: whatever it asks the core for
    // happens inside this call, and it asks on behalf of whoever called —
    // the application at the socket, and the sensor asks the person.
    //
    // An external one is a process that outlives the call. Its requests reach
    // the core from a reading task of its own, with nothing tying them to a
    // call, so they cannot be attributed to a caller: they are the plugin's
    // own, and the plugin is `Peer::External` — its own fields and nothing
    // else. Handing that task the caller's peer meant a process started by the
    // window kept the window's trust for good, and every later request — an
    // outsider's included — was served with it.
    let answer = match entry {
        Entry::Builtin(p) => {
            let host = host_for(shared, plugin, peer.clone()).await;
            p.call(host.as_ref(), action, payload).await
        }
        Entry::External(e) => {
            let host = host_for(shared, plugin, crate::peer::Peer::External).await;
            e.call(host, action, payload).await
        }
    };
    match answer {
        Ok(payload) => Response::Plugin { payload },
        Err(e) => Response::error(e),
    }
}

/// Send an event round. One that is off receives none: it has nothing to work
/// with either — no section, no process.
pub async fn notify(shared: &Shared, event: HostEvent) {
    for entry in registry::enabled_entries() {
        let id = entry.id();
        let host = host_for(shared, &id, peer_of(&entry)).await;
        match entry {
            Entry::Builtin(p) => p.on_event(host.as_ref(), event).await,
            Entry::External(e) => e.event(host, event).await,
        }
    }
}

/// The core as one plugin sees it.
async fn host_for(shared: &Shared, id: &str, peer: crate::peer::Peer) -> Arc<dyn Host> {
    let mirror = shared.lock().await.mirror();
    Arc::new(DaemonHost { shared: shared.clone(), mirror, id: id.to_string(), peer })
}

/// What to count a plugin as when it reaches for a secret.
///
/// A built-in one runs in this same process: the secret does not leave the
/// daemon, and asking the sensor on a minute timer when nobody is at the
/// machine would be a mockery. An external one is somebody else's process: it
/// gets its own `kw-*` fields and no more, whoever set it going.
fn peer_of(entry: &Entry) -> crate::peer::Peer {
    match entry {
        Entry::Builtin(_) => crate::peer::Peer::Builtin,
        Entry::External(_) => crate::peer::Peer::External,
    }
}

// -- Installing, removing, switching on ------------------------------------

/// Install a plugin: a directory, an archive or an address from the showcase.
/// It installs switched off: nobody has agreed to the permissions yet, and
/// consent is
/// `PluginEnable`.
pub async fn install(path: &str) -> Response {
    if remote::is_url(path) {
        return install_url(path).await;
    }
    let placed = match package::install(std::path::Path::new(path), &registry::taken) {
        Ok(placed) => placed,
        Err(e) => return Response::error(e),
    };
    // A path on disk is a developer's path: a directory has no signature and
    // nowhere to get one. Such a plugin is marked unverified, and the consent
    // dialogue is obliged to say so plainly.
    let id = placed.pkg.manifest.id.clone();
    let rec = registry::Record {
        version: placed.pkg.manifest.version.clone(),
        manifest_sha256: placed.manifest_sha.clone(),
        exec_sha256: placed.exec_sha.clone(),
        permissions: permission_names(&placed.pkg.manifest.permissions),
        unverified: true,
        ..registry::Record::default()
    };
    settle(placed, rec, &id).await
}

/// Installing from an address: revocation, signature, publisher, fingerprint —
/// and only then the ordinary installation from an archive.
async fn install_url(url: &str) -> Response {
    let dir = package::root();
    let list = sources::list();
    let fetched = match remote::fetch(&dir, &net::Net, &list, url, catalog::now(), &registry::record).await {
        Ok(f) => f,
        Err(e) => return Response::error(e),
    };
    // The showcase's promise — the version and the list of rights — is checked
    // before anything reaches the disk: a person agreed to what they saw on the
    // card, not to what turned out to be in the archive.
    let promised = package::Promise {
        version: fetched.version.clone(),
        permissions: fetched.permissions.clone(),
    };
    let placed = match package::install_or_update(
        &fetched.file,
        &registry::is_builtin,
        &registry::taken,
        Some(&promised),
    ) {
        Ok(placed) => placed,
        Err(e) => return Response::error(e),
    };
    let id = placed.pkg.manifest.id.clone();
    let rec = registry::Record {
        version: placed.pkg.manifest.version.clone(),
        publisher: fetched.publisher.clone(),
        package_sha256: fetched.sha256.clone(),
        manifest_sha256: placed.manifest_sha.clone(),
        exec_sha256: placed.exec_sha.clone(),
        permissions: permission_names(&placed.pkg.manifest.permissions),
        unverified: !fetched.verified,
    };
    tracing::info!(url, publisher = %fetched.publisher, verified = fetched.verified, "the plugin was downloaded");
    settle(placed, rec, &id).await
}

/// What was added to the rights, and whether the plugin stays on.
///
/// There is one rule and it is about consent: a person agreed to the list they
/// saw. A wider new list makes the consent void and the plugin waits switched
/// off. A narrower one, or the same, updates silently.
fn consent(before: Option<&registry::Record>, now: &[String], was_enabled: bool) -> (Vec<String>, bool) {
    let Some(old) = before else { return (Vec::new(), false) };
    let added: Vec<String> =
        now.iter().filter(|p| !old.permissions.contains(p)).cloned().collect();
    let keep = was_enabled && added.is_empty();
    (added, keep)
}

/// The names of permissions as the interface sees them and as they lie in the
/// register.
fn permission_names(perms: &[keyward_plugin::Permission]) -> Vec<String> {
    perms
        .iter()
        .filter_map(|p| serde_json::to_value(p).ok())
        .filter_map(|v| v.as_str().map(str::to_string))
        .collect()
}

/// The shared tail of an installation: decide whether the plugin stays on,
/// remember the installation, rebuild the register and hand back the card.
///
/// A new plugin is always off: there has been no consent to the permissions
/// yet. An update of one that is on stays on — **if** it does not ask for more
/// than before. If it asks for more, it goes off and is asked about again: a
/// person agreed to a different list.
async fn settle(placed: package::Placed, rec: registry::Record, id: &str) -> Response {
    let before = registry::record(id);
    let was_enabled = placed.updated && registry::is_enabled(id);
    let (added, keep_enabled) = consent(before.as_ref(), &rec.permissions, was_enabled);

    registry::remember(id, rec);
    registry::set_enabled(id, keep_enabled);
    // The old version's process has to die and its card to leave the register:
    // there is already another program and another manifest on disk.
    if let Some(old) = registry::drop_external(id) {
        old.stop().await;
    }
    for gone in registry::rescan() {
        gone.stop().await;
    }
    tracing::info!(plugin = id, updated = placed.updated, enabled = keep_enabled, "the plugin was installed");

    let Some(mut payload) = registry::card(id) else {
        return Response::error(keyward_core::fault!("err.pluginInstalledNotRegistered", "id" => id));
    };
    if let Some(obj) = payload.as_object_mut() {
        let rec = registry::record(id).unwrap_or_default();
        obj.insert("unverified".to_string(), Value::Bool(rec.unverified));
        obj.insert("publisher".to_string(), Value::String(rec.publisher.clone()));
        obj.insert(
            "fingerprint".to_string(),
            serde_json::to_value(fingerprint_of(&rec.publisher)).unwrap_or(Value::Null),
        );
        obj.insert("updated".to_string(), Value::Bool(placed.updated));
        // What exactly was added to the rights, so that the consent dialogue
        // does not make a person compare two lists by eye.
        obj.insert("added_permissions".to_string(), serde_json::to_value(&added).unwrap_or(Value::Null));
        obj.insert("consent_needed".to_string(), Value::Bool(!keep_enabled));
        // A revoked version is not installed at all, but an installed one may
        // have been revoked afterwards: then the card says so.
        if let Some(reason) =
            catalog::revoked_reason(&package::root(), &sources::list(), id, &rec.version)
        {
            obj.insert("revoked".to_string(), Value::Bool(true));
            obj.insert("revoked_reason".to_string(), Value::String(reason));
        }
    }
    Response::Plugin { payload }
}

fn fingerprint_of(publisher: &str) -> Vec<String> {
    if publisher.is_empty() {
        return Vec::new();
    }
    publishers::trusted(&package::root(), publisher)
        .map(|p| p.words())
        .unwrap_or_default()
}

/// The showcase: what can be installed. An unreachable source is not an error
/// on the screen: the entries arrive from the cache marked `stale`.
///
/// This is also the one moment when the daemon learns of a revocation: an
/// installed version that was revoked is switched off right here, with a
/// notification and the reason.
pub async fn catalog(shared: &Shared, refresh: bool) -> Response {
    let dir = package::root();
    let list = sources::list();
    let shelf = catalog::collect(&dir, &net::Net, &list, refresh, &catalog::target(), catalog::now()).await;
    disable_revoked(shared, &shelf.revoked).await;
    let installed = registry::installed_versions();
    let known = publishers::load_from(&dir);
    Response::PluginCatalog { entries: catalog::cards(&shelf.offers, &installed, &known) }
}

/// What was revoked is switched off. We will not remove it for anybody:
/// removing a plugin is their decision, but a revoked one has no business
/// running.
async fn disable_revoked(shared: &Shared, revoked: &[catalog::Revoked]) {
    let installed = registry::installed_versions();
    for r in revoked {
        let Some(have) = installed.get(&r.id) else { continue };
        if have != &r.version || registry::is_builtin(&r.id) || !registry::is_enabled(&r.id) {
            continue;
        }
        registry::set_enabled(&r.id, false);
        if let Some(plugin) = registry::external(&r.id) {
            plugin.stop().await;
        }
        let reason = if r.reason.is_empty() { keyward_core::text::t("plugin.revoked.noReason", &[]) } else { r.reason.clone() };
        tracing::warn!(plugin = %r.id, version = %r.version, reason = %reason, "the version was revoked; the plugin was switched off");
        crate::daemon::push_notice(
            shared,
            keyward_core::proto::Notice {
                title: keyward_core::text::message("notice.pluginDisabled.title", &[("plugin", &r.id)]),
                body: keyward_core::text::message("notice.pluginRevoked.body", &[("version", &r.version), ("reason", &reason)]),
            },
        )
        .await;
    }
}

/// Trust a publisher or strip them of trust. The key comes from the showcase —
/// the very one in which a person saw the plugin and checked the five words of
/// the fingerprint.
///
/// Stripping trust is not cosmetic: that publisher's packages can no longer be
/// checked, so the plugins they installed are switched off with a notification.
/// They are not entitled to go on running: the "I trust you" has just been
/// withdrawn.
pub async fn trust(shared: &Shared, publisher: &str, on: bool) -> Response {
    let dir = package::root();
    let list = sources::list();
    if on {
        let Some(key) = catalog::declared_key(&dir, &list, publisher) else {
            return Response::error(keyward_core::fault!(
                "err.publisherKeyUndeclared",
                "publisher" => publisher,
                "file" => publishers::PUBLISHERS_FILE,
            ));
        };
        if let Err(e) = publishers::add(&dir, publisher, &key) {
            return Response::error(e);
        }
    } else {
        if let Err(e) = publishers::remove(&dir, publisher) {
            return Response::error(e);
        }
        for (id, _) in registry::installed_versions() {
            let Some(rec) = registry::record(&id) else { continue };
            if rec.publisher != publisher || !registry::is_enabled(&id) {
                continue;
            }
            registry::set_enabled(&id, false);
            if let Some(plugin) = registry::external(&id) {
                plugin.stop().await;
            }
            tracing::warn!(plugin = %id, publisher, "the publisher was stripped of trust; the plugin was switched off");
            crate::daemon::push_notice(
                shared,
                keyward_core::proto::Notice {
                    title: keyward_core::text::message("notice.pluginDisabled.title", &[("plugin", &id)]),
                    body: keyward_core::text::message("notice.publisherUntrusted.body", &[("publisher", publisher)]),
                },
            )
            .await;
        }
    }
    // The list afresh: the window refreshes from one answer rather than two
    // requests.
    catalog(shared, false).await
}

/// The showcase addresses: show them or replace them.
pub fn source_list(set: Option<Vec<String>>) -> Response {
    match set {
        None => Response::PluginSources { sources: sources::list() },
        Some(list) => match sources::set(&list) {
            Ok(sources) => Response::PluginSources { sources },
            Err(e) => Response::error(e),
        },
    }
}

/// Remove a plugin: its process, its package directory, its settings and its
/// state.
pub async fn remove(id: &str) -> Response {
    if registry::is_builtin(id) {
        return Response::error(keyward_core::fault!("err.pluginBuiltinOnlyOff", "id" => id));
    }
    let Some(plugin) = registry::external(id) else {
        return Response::error(keyward_core::fault!("err.noSuchPlugin", "plugin" => id));
    };
    // The process first, the files after: otherwise the plugin would outlive
    // its own directory.
    plugin.stop().await;
    if let Err(e) = package::remove(id) {
        return Response::error(e);
    }
    registry::forget(id);
    for gone in registry::rescan() {
        gone.stop().await;
    }
    tracing::info!(plugin = id, "the plugin was removed");
    Response::Plugins { plugins: registry::cards() }
}

/// Switch on or off. A person's consent to the permissions is this.
pub async fn enable(shared: &Shared, id: &str, on: bool) -> Response {
    let Some(entry) = registry::find(id) else {
        return Response::error(keyward_core::fault!("err.noSuchPlugin", "plugin" => id));
    };
    registry::set_enabled(id, on);

    // Switching off is not just a line in the register: a plugin is left
    // holding live things. An external one loses its process; a built-in one is
    // told `Locked`, the same as when the vault is locked: take the sockets
    // down, put the timers out.
    let host = host_for(shared, id, peer_of(&entry)).await;
    match (&entry, on) {
        (Entry::External(e), false) => e.stop().await,
        (Entry::External(_), true) => {}
        (Entry::Builtin(p), false) => p.on_event(host.as_ref(), HostEvent::Locked).await,
        (Entry::Builtin(p), true) => p.on_event(host.as_ref(), HostEvent::EntriesChanged).await,
    }
    tracing::info!(plugin = id, on, "the plugin was switched");
    Response::Plugins { plugins: registry::cards() }
}

/// Carrying over settings that used to lie in the shared file. Done once:
/// `Settings::save` writes the file whole out of its own struct and will lose
/// these keys, so they have to be taken before the interface saves
/// anything.
pub fn migrate_settings() {
    let raw = std::fs::read_to_string(keyward_core::paths::settings_file()).unwrap_or_default();
    let Ok(old) = serde_json::from_str::<Value>(&raw) else { return };

    let ssh = keyward_core::paths::plugin_settings("ssh");
    if !ssh.exists() {
        let mut moved = serde_json::Map::new();
        if let Some(v) = old.get("ssh_agent_enabled") {
            moved.insert("agent_enabled".into(), v.clone());
        }
        if let Some(v) = old.get("ssh_ask") {
            moved.insert("ask".into(), v.clone());
        }
        if let Some(v) = old.get("ssh_socket") {
            moved.insert("shared_socket".into(), v.clone());
        }
        if !moved.is_empty() {
            write_settings("ssh", &Value::Object(moved));
            tracing::info!("the ssh agent's settings were carried over into the plugin");
        }
    }

    let hc = keyward_core::paths::plugin_settings("hashicorp");
    if !hc.exists() {
        let mut moved = serde_json::Map::new();
        if let Some(active) = old.get("hashicorp_active").filter(|v| !v.is_null()) {
            moved.insert("active".into(), active.clone());
        }
        // Notifications about expiring leases are the plugin's business too:
        // it alone knows what an issued lease is.
        if let Some(v) = old.get("expiry_notices") {
            moved.insert("expiry_notices".into(), v.clone());
        }
        if !moved.is_empty() {
            write_settings("hashicorp", &Value::Object(moved));
            tracing::info!("the HashiCorp settings were carried over into the plugin");
        }
    }
}

fn write_settings(id: &str, value: &Value) {
    let path = keyward_core::paths::plugin_settings(id);
    if let Some(dir) = path.parent() {
        let _ = std::fs::create_dir_all(dir);
        let _ = crate::daemon::restrict(dir);
    }
    if let Err(e) = std::fs::write(&path, serde_json::to_string_pretty(value).unwrap_or_default()) {
        tracing::warn!(error = %e, plugin = id, "the plugin's settings were not saved");
    }
}

struct DaemonHost {
    shared: Shared,
    /// A mirror of the state with no async lock: `Host` asks for items and for
    /// "is the vault open" from synchronous methods, and reaching into the
    /// daemon's mutex from there is not allowed.
    mirror: Arc<Mirror>,
    id: String,
    /// On whose behalf the plugin is working: the socket peer that called it,
    /// or the plugin itself when this is an event of the daemon's. This decides
    /// whether a password is handed over.
    peer: crate::peer::Peer,
}

impl DaemonHost {
    /// The vault the item belongs to and the item's own identifier. With no
    /// prefix it is the active account: that is how requests from the interface
    /// arrive.
    fn route<'a>(&self, st: &'a crate::daemon::State, entry_id: &str) -> Option<(&'a Vault, String)> {
        match entry_id.split_once(ACCOUNT_SEP) {
            Some((account, id)) => st.vaults.get(account).map(|v| (v, id.to_string())),
            None => st.active().map(|v| (v, entry_id.to_string())),
        }
    }
}

impl DaemonHost {
    /// The keychain item a plugin's secret lives in: the account, the plugin
    /// and the name, so that neither another account nor another plugin reads
    /// it. The vault must be open — the secret's key comes from it.
    fn keychain_item(&self, name: &str) -> keyward_plugin::Result<(Vault, String)> {
        if name.is_empty() || !name.chars().all(|c| c.is_ascii_alphanumeric() || matches!(c, '-' | '_')) {
            return Err(keyward_core::fault!("err.keychainBadName"));
        }
        let vault = self.mirror.active().ok_or_else(|| keyward_core::fault!("err.vaultLocked"))?;
        let item = format!("{}/{}/{}", vault.account().id, self.id, name);
        Ok((vault, item))
    }
}

#[async_trait::async_trait]
impl Host for DaemonHost {
    fn unlocked(&self) -> bool {
        self.mirror.unlocked()
    }

    fn server(&self) -> Option<String> {
        self.mirror.active().map(|v| v.account().base_url.clone())
    }

    async fn keychain_has(&self, name: &str) -> bool {
        let Ok((_, item)) = self.keychain_item(name) else { return false };
        tokio::task::spawn_blocking(move || keyward_vault::biometric::plugin_secret_exists(&item)).await.unwrap_or(false)
    }

    async fn keychain_get(&self, name: &str) -> keyward_plugin::Result<String> {
        let (vault, item) = self.keychain_item(name)?;
        let key = vault.plugin_secret_key()?;
        let reason = keyward_core::text::t("touch.pluginSecret", &[("plugin", self.id.as_str())]);
        tokio::task::spawn_blocking(move || keyward_vault::biometric::plugin_secret_load(&key, &item, &reason))
            .await
            .map_err(|e| anyhow::anyhow!("the keychain task fell over: {e}"))?
    }

    async fn keychain_set(&self, name: &str, value: &str) -> keyward_plugin::Result<()> {
        let (vault, item) = self.keychain_item(name)?;
        let key = vault.plugin_secret_key()?;
        let value = value.to_string();
        tokio::task::spawn_blocking(move || keyward_vault::biometric::plugin_secret_store(&key, &item, &value))
            .await
            .map_err(|e| anyhow::anyhow!("the keychain task fell over: {e}"))?
    }

    async fn copy_text(&self, value: &str) -> keyward_plugin::Result<u64> {
        let count = crate::clipboard::put(value)?;
        let settings = keyward_core::settings::Settings::load();
        Ok(match crate::clipboard::clear_after(&settings) {
            Some(after) => {
                crate::clipboard::clear_later(count, after);
                after.as_secs()
            }
            None => 0,
        })
    }

    async fn keychain_forget(&self, name: &str) -> keyward_plugin::Result<()> {
        let (_, item) = self.keychain_item(name)?;
        tokio::task::spawn_blocking(move || keyward_vault::biometric::plugin_secret_forget(&item))
            .await
            .map_err(|e| anyhow::anyhow!("the keychain task fell over: {e}"))?
    }

    fn entries(&self) -> Vec<VaultEntry> {
        self.mirror.entries()
    }

    async fn item_detail(&self, entry_id: &str) -> Option<ItemDetail> {
        let st = self.shared.lock().await;
        let (vault, id) = self.route(&st, entry_id)?;
        vault.item_detail(&id)
    }

    async fn secret(&self, entry_id: &str, field: SecretField) -> keyward_plugin::Result<String> {
        let (vault, id, grace, always_ask) = {
            let st = self.shared.lock().await;
            let grace = st.settings.biometric_grace_seconds;
            let always_ask = st.settings.touch_id_for_secrets;
            let (vault, id) = self
                .route(&st, entry_id)
                .ok_or_else(|| keyward_core::fault!("err.itemNotFoundSync"))?;
            (vault.clone(), id, grace, always_ask)
        };
        // The core asks for Touch ID on protected fields, not the plugin: a
        // plugin has no access to biometrics and never will. The core also
        // decides who gets a password at all, by the peer rather than by the
        // plugin.
        crate::daemon::guard_secret(&self.peer, &vault, &id, &field, grace, always_ask)?;
        // Taken afresh after the sensor: locking while the finger was on its
        // way must win (see `vault_after_touch`).
        let account = vault.account().id.clone();
        drop(vault);
        let vault = {
            let st = self.shared.lock().await;
            match self.route(&st, entry_id) {
                Some((v, again)) if v.account().id == account && again == id => v.clone(),
                _ => return Err(keyward_core::fault!("err.vaultLocked")),
            }
        };
        // The plugin's API hands out a plain string: it goes to the plugin's
        // own process over its pipe. The daemon's copy is wiped here.
        vault.secret(&id, &field).map(|s| String::clone(&s))
    }

    async fn note_fields(&self, entry_id: &str) -> keyward_plugin::Result<Vec<String>> {
        let st = self.shared.lock().await;
        let (vault, id) = self
            .route(&st, entry_id)
            .ok_or_else(|| keyward_core::fault!("err.itemNotFoundSync"))?;
        Ok(vault.note_field_names(&id))
    }

    fn tagged_items(&self, field: &str) -> Vec<TaggedItem> {
        let Some(vault) = self.mirror.active() else { return Vec::new() };
        vault
            .items_tagged(field)
            .into_iter()
            .map(|i| TaggedItem { id: i.id, name: i.name, hidden: i.hidden, owned: i.owned, fields: i.fields })
            .collect()
    }

    async fn create_note(
        &self,
        name: &str,
        fields: Vec<(String, String)>,
        hidden: bool,
    ) -> keyward_plugin::Result<String> {
        let vault = {
            let st = self.shared.lock().await;
            st.active().cloned().ok_or_else(|| keyward_core::fault!("err.noAccount"))?
        };
        let id = vault.create_plugin_note(name, &fields, hidden).await?;
        self.shared.lock().await.invalidate();
        Ok(id)
    }

    async fn trash_item(&self, entry_id: &str) -> keyward_plugin::Result<()> {
        let (vault, id) = {
            let st = self.shared.lock().await;
            let (vault, id) = self
                .route(&st, entry_id)
                .ok_or_else(|| keyward_core::fault!("err.itemNotFoundSync"))?;
            (vault.clone(), id)
        };
        vault.trash_item(&id).await?;
        self.shared.lock().await.invalidate();
        Ok(())
    }

    async fn set_fields(&self, entry_id: &str, fields: Vec<(String, String)>) -> keyward_plugin::Result<()> {
        let (vault, id) = {
            let st = self.shared.lock().await;
            let (vault, id) = self
                .route(&st, entry_id)
                .ok_or_else(|| keyward_core::fault!("err.itemNotFoundSync"))?;
            (vault.clone(), id)
        };
        vault.set_item_fields(&id, &fields).await?;
        self.shared.lock().await.invalidate();
        Ok(())
    }

    async fn sign_ssh(
        &self,
        entry_id: &str,
        data: &[u8],
        flags: u32,
        confirm: bool,
    ) -> keyward_plugin::Result<Vec<u8>> {
        // The items come from the mirror: they are whole there, private half
        // and all. A plugin gets none of it under any permission — `entries`
        // cuts it out on the way out — and it uses signing precisely because it
        // has no key.
        let entry = self
            .mirror
            .entries()
            .into_iter()
            .find(|e| e.id == entry_id)
            .ok_or_else(|| keyward_core::fault!("err.itemNotFoundSync"))?;
        let name = entry.name.clone();
        let private = entry
            .private_key
            .clone()
            .filter(|k| !k.trim().is_empty())
            .ok_or_else(|| keyward_core::fault!("err.itemNoPrivateKey", "name" => &name))?;

        // The agent showed the host the stored public half. A private key that
        // is not its pair signs what the host cannot check, and all the host
        // says is "Permission denied": it is said here instead, before the
        // finger is asked for anything.
        if !is_pair(entry.public_key.as_deref(), &private)? {
            tracing::warn!(entry = %name, "the item's private key is not the pair of its public key: the host accepts the public one and refuses the signature; open the item and work the public half out again");
            self.notice(&keyward_core::text::t("notice.sshKeyMismatchTitle", &[]), &keyward_core::text::t("err.sshKeyMismatch", &[("name", &name)]));
            return Err(keyward_core::fault!("err.sshKeyMismatch", "name" => &name));
        }

        // A `kw-confirm` mark on the item itself outweighs a plugin's
        // arguments: a person set it in the vault and a plugin is not entitled
        // to take it off. A plugin's argument can only add a prompt — it alone
        // knows that a setting says to ask every time.
        //
        // This is the one field the core reads by name, and it reads it because
        // it is the core that asks for the finger: leaving that to a plugin
        // would mean a plugin could decide not to ask.
        let pinned = entry
            .field("kw-confirm")
            .is_some_and(|v| matches!(v.to_ascii_lowercase().as_str(), "yes" | "true" | "1" | "on"));
        if confirm || pinned {
            let reason = keyward_core::text::t("touch.sshSign", &[("name", &name)]);
            // The sensor is a system dialogue's business, and it waits for a
            // person: a thread of its own, so that the whole daemon does not
            // stand still meanwhile.
            tokio::task::spawn_blocking(move || keyward_vault::biometric::confirm(&reason))
                .await
                .map_err(|e| keyward_core::fault!("err.confirmationBroke", "reason" => e))?
                .map_err(|e| keyward_core::fault!("err.signatureNotConfirmed", "reason" => e))?;
        }

        let data = data.to_vec();
        tokio::task::spawn_blocking(move || sshsign::sign(&private, &data, flags))
            .await
            .map_err(|e| keyward_core::fault!("err.signingFailed", "reason" => e))?
    }

    fn notice(&self, title: &str, body: &str) {
        let shared = self.shared.clone();
        let notice = keyward_core::proto::Notice { title: title.to_string(), body: body.to_string() };
        tokio::spawn(async move {
            crate::daemon::push_notice(&shared, notice).await;
        });
    }

    fn state_dir(&self) -> PathBuf {
        let dir = keyward_core::paths::plugin_dir(&self.id);
        let _ = std::fs::create_dir_all(&dir);
        let _ = crate::daemon::restrict(&dir);
        dir
    }

    fn settings(&self) -> Value {
        std::fs::read_to_string(keyward_core::paths::plugin_settings(&self.id))
            .ok()
            .and_then(|raw| serde_json::from_str(&raw).ok())
            .unwrap_or(Value::Null)
    }

    fn set_settings(&self, value: Value) -> keyward_plugin::Result<()> {
        write_settings(&self.id, &value);
        Ok(())
    }
}

/// Whether a stored public key is the pair of a private one: the kind and
/// the key itself, the comment aside.
fn is_pair(public: Option<&str>, private: &str) -> anyhow::Result<bool> {
    let derived = keyward_sshkey::import(private, None)
        .map_err(|e| keyward_core::fault!("err.signingFailed", "reason" => e))?
        .public_key;
    let body = |line: &str| line.split_whitespace().take(2).collect::<Vec<_>>().join(" ");
    Ok(public.map(body).is_some_and(|p| p == body(&derived)))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn a_private_key_signs_only_beside_its_own_public_half() {
        let a = keyward_sshkey::generate(keyward_core::edits::SshAlgorithm::Ed25519, "a").unwrap();
        let b = keyward_sshkey::generate(keyward_core::edits::SshAlgorithm::Ed25519, "b").unwrap();
        assert!(is_pair(Some(&a.public_key), &a.private_key).unwrap());
        let renamed = format!("{} another comment", a.public_key.split_whitespace().take(2).collect::<Vec<_>>().join(" "));
        assert!(is_pair(Some(&renamed), &a.private_key).unwrap(), "the comment is no part of the key");
        assert!(!is_pair(Some(&b.public_key), &a.private_key).unwrap(), "a stale public half after the private one was changed");
        assert!(!is_pair(None, &a.private_key).unwrap());
    }

    /// The full round of an installation against a real `~/.keyward/plugins`.
    ///
    /// Marked `ignore` on purpose: the test writes into a person's home
    /// directory and has no place in a general run. Run it by hand:
    /// `cargo test -p keyward-cli -- --ignored installing_the_example`.
    #[tokio::test]
    #[ignore = "writes into the real ~/.keyward/plugins"]
    async fn installing_the_example_leaves_it_off_until_asked() {
        let example = std::path::Path::new(env!("CARGO_MANIFEST_DIR")).join("tests/fixtures/probe");
        let card = match install(&example.to_string_lossy()).await {
            Response::Plugin { payload } => payload,
            other => panic!("the installation failed: {other:?}"),
        };
        assert_eq!(card["id"], "probe");
        assert_eq!(card["origin"], "external");
        assert_eq!(card["enabled"], false, "a new plugin installs switched off");
        assert_eq!(card["permissions"], serde_json::json!(["entries", "notices"]));

        // The same identifier is not taken a second time: an installation is
        // not entitled to overwrite somebody else's directory.
        assert!(matches!(install(&example.to_string_lossy()).await, Response::Error { .. }));

        // A person's consent is switching it on.
        registry::set_enabled("probe", true);
        let list = registry::cards();
        let probe = list.iter().find(|c| c["id"] == "probe").expect("the card is there");
        assert_eq!(probe["enabled"], true);

        match remove("probe").await {
            Response::Plugins { plugins } => {
                assert!(plugins.iter().all(|c| c["id"] != "probe"), "a removed plugin stayed in the list");
            }
            other => panic!("the removal failed: {other:?}"),
        }
        assert!(!package::root().join("probe").exists(), "the package directory stayed");
        assert!(!keyward_core::paths::plugin_settings("probe").exists(), "the settings stayed");
    }

    #[test]
    fn growing_permissions_take_the_consent_back() {
        let old = registry::Record {
            permissions: vec!["entries".into(), "notices".into()],
            ..registry::Record::default()
        };
        // The same number means a silent update and it stays on.
        let (added, keep) = consent(Some(&old), &["entries".into(), "notices".into()], true);
        assert!(added.is_empty());
        assert!(keep, "the same set of rights is no reason to ask again");

        // Fewer, all the more so.
        let (added, keep) = consent(Some(&old), &["entries".into()], true);
        assert!(added.is_empty() && keep);

        // More makes the consent void: a person agreed to something else.
        let (added, keep) = consent(Some(&old), &["entries".into(), "notices".into(), "secrets".into()], true);
        assert_eq!(added, vec!["secrets".to_string()]);
        assert!(!keep, "a plugin that asks for more has to wait switched off");

        // One that is off stays off.
        let (_, keep) = consent(Some(&old), &["entries".into()], false);
        assert!(!keep);

        // A new installation is always off: there has been no consent yet.
        let (added, keep) = consent(None, &["entries".into()], true);
        assert!(added.is_empty() && !keep);
    }

    #[tokio::test]
    async fn an_unknown_plugin_cannot_be_removed() {
        // Only what is installed can be removed. An unfamiliar name gets a
        // plain refusal rather than a silent "done".
        assert!(matches!(remove("no-such-plugin").await, Response::Error { .. }));
    }
}

#[cfg(test)]
mod peering {
    use crate::daemon::{decide, Step, REFUSED_ALIEN, REFUSED_PLUGIN};
    use crate::peer::{Peer, Trust};

    const FOREIGN: bool = false;
    const OWN: bool = true;

    /// An external plugin's process outlives the call that started it, and its
    /// requests arrive with nothing tying them to a caller. Judging them by
    /// whoever happened to start the process gave two wrong answers at once: a
    /// plugin started by the window kept the window's trust for every later
    /// request, and one started by an outsider could not read even its own
    /// fields — the Vault screens then said the item had no connection.
    #[test]
    fn a_plugins_own_requests_are_the_plugins_own() {
        assert_eq!(decide(&Peer::External, false, false, false, OWN), Step::Give);
        assert_eq!(decide(&Peer::External, false, false, false, FOREIGN), Step::Deny(REFUSED_PLUGIN));
    }

    /// And the trust of whoever called is not lent to it: an outsider at the
    /// socket is refused on its own account, not through a plugin.
    #[test]
    fn an_outsider_is_refused_whoever_it_asks_through() {
        let alien = Peer::Socket { pid: 1, path: None, trust: Trust::Alien };
        assert_eq!(decide(&alien, false, false, false, OWN), Step::Deny(REFUSED_ALIEN));
    }
}
