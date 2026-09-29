//! The register of plugins: the built-in ones plus those a person installed.
//!
//! This used to be a list of two lines of code. Now the list is assembled at
//! start-up: the built-in ones are known to the compiler, and external ones are
//! found by walking `~/.keyward/plugins/<id>/plugin.json`. Whether a plugin is
//! on is the only thing the register remembers on disk (`registry.json`), and
//! what it remembers is precisely the ones that are off: a new plugin has to be
//! off, and a line forgotten in the file must not switch anybody on by
//! accident.

use std::collections::{BTreeMap, BTreeSet};
use std::sync::{Arc, OnceLock, RwLock};

use keyward_plugin::Plugin;
use serde::{Deserialize, Serialize};
use serde_json::Value;

use super::external::External;
use super::package;

/// A plugin the daemon calls on.
pub enum Entry {
    Builtin(Arc<dyn Plugin>),
    External(Arc<External>),
}

impl Entry {
    pub fn id(&self) -> String {
        match self {
            Self::Builtin(p) => p.manifest().id,
            Self::External(e) => e.id().to_string(),
        }
    }
}

/// What lies in `registry.json`.
#[derive(Debug, Default, Serialize, Deserialize)]
struct Persisted {
    #[serde(default)]
    disabled: BTreeSet<String>,
    /// What was remembered when each external plugin was installed.
    #[serde(default)]
    installed: BTreeMap<String, Record>,
}

/// The record of an installation. Not there for decoration: from the hashes
/// the daemon learns before every start whether the files on disk were swapped,
/// from the publisher that an update was signed by whoever signed what is
/// installed, and from the permissions that an update does not ask for more
/// than a person allowed.
#[derive(Debug, Clone, Default, Serialize, Deserialize)]
pub struct Record {
    #[serde(default)]
    pub version: String,
    #[serde(default)]
    pub publisher: String,
    #[serde(default)]
    pub package_sha256: String,
    #[serde(default)]
    pub manifest_sha256: String,
    #[serde(default)]
    pub exec_sha256: String,
    #[serde(default)]
    pub permissions: Vec<String>,
    /// Installed past the showcase: there was no signature.
    #[serde(default)]
    pub unverified: bool,
}

struct Registry {
    builtin: Vec<Arc<dyn Plugin>>,
    /// External ones by identifier. A `BTreeMap` for a steady order in the
    /// list: the cards must not jump about from one start to the next.
    external: BTreeMap<String, Arc<External>>,
    disabled: BTreeSet<String>,
    installed: BTreeMap<String, Record>,
}

fn reg() -> &'static RwLock<Registry> {
    static REG: OnceLock<RwLock<Registry>> = OnceLock::new();
    REG.get_or_init(|| {
        // There are no built-in ones any more: ssh and HashiCorp arrive from
        // the showcase as ordinary packages and run as separate processes. The
        // kind "built-in" stays — the daemon has to be able to show one if it
        // ever builds a plugin into itself again.
        let builtin: Vec<Arc<dyn Plugin>> = Vec::new();
        let stored = load();
        let external = scan(&builtin, &BTreeMap::new());
        RwLock::new(Registry {
            builtin,
            external,
            disabled: stored.disabled,
            installed: stored.installed,
        })
    })
}

fn load() -> Persisted {
    let path = package::root().join(package::REGISTRY_FILE);
    let Ok(raw) = std::fs::read_to_string(&path) else { return Persisted::default() };
    match serde_json::from_str(&raw) {
        Ok(p) => p,
        Err(e) => {
            // A damaged file means "everything is on" rather than a panic:
            // the register keeps a convenience, not secrets.
            tracing::warn!(error = %e, path = %path.display(), "the plugin register did not parse");
            Persisted::default()
        }
    }
}

fn save(disabled: &BTreeSet<String>, installed: &BTreeMap<String, Record>) {
    let dir = package::root();
    if let Err(e) = std::fs::create_dir_all(&dir) {
        tracing::warn!(error = %e, "the plugins directory was not created");
        return;
    }
    let _ = crate::daemon::restrict(&dir);
    let path = dir.join(package::REGISTRY_FILE);
    let body = serde_json::to_string_pretty(&Persisted {
        disabled: disabled.clone(),
        installed: installed.clone(),
    })
    .unwrap_or_default();
    if let Err(e) = std::fs::write(&path, body) {
        tracing::warn!(error = %e, path = %path.display(), "the plugin register was not saved");
    }
}

/// Walking the directory of packages. The live processes of plugins already
/// found are kept: rebuilding the list is no reason to take down what works.
fn scan(
    builtin: &[Arc<dyn Plugin>],
    known: &BTreeMap<String, Arc<External>>,
) -> BTreeMap<String, Arc<External>> {
    let mut found = BTreeMap::new();
    let root = package::root();
    let Ok(dir) = std::fs::read_dir(&root) else { return found };
    for entry in dir.flatten() {
        if !entry.file_type().is_ok_and(|t| t.is_dir()) {
            continue;
        }
        let path = entry.path();
        if !path.join(package::MANIFEST).exists() {
            // A directory with no manifest is a built-in plugin's state
            // (`~/.keyward/plugins/ssh`) or the leftovers of an unpacking.
            continue;
        }
        let pkg = match package::read(&path) {
            Ok(pkg) => pkg,
            Err(e) => {
                tracing::warn!(path = %path.display(), error = %e, "a plugin package was skipped");
                continue;
            }
        };
        let id = pkg.manifest.id.clone();
        // The directory name and the identifier have to match: otherwise
        // `PluginRemove` would take the wrong thing down, and two packages
        // would fight over one settings file.
        if path.file_name().map(|n| n.to_string_lossy().into_owned()).as_deref() != Some(id.as_str()) {
            tracing::warn!(path = %path.display(), id = %id, "the directory is not named after the identifier; the package was skipped");
            continue;
        }
        if builtin.iter().any(|p| p.manifest().id == id) {
            tracing::warn!(id = %id, "an external package is pretending to be a built-in plugin and was skipped");
            continue;
        }
        match known.get(&id) {
            Some(live) => {
                found.insert(id, Arc::clone(live));
            }
            None => {
                found.insert(id, Arc::new(External::new(pkg, path)));
            }
        }
    }
    found
}

/// Rebuild the list of external plugins, after an installation or a removal.
/// Returns those that are gone: their processes have to be taken down.
pub fn rescan() -> Vec<Arc<External>> {
    let Ok(mut r) = reg().write() else { return Vec::new() };
    let fresh = scan(&r.builtin, &r.external);
    let mut gone = Vec::new();
    for (id, live) in &r.external {
        if !fresh.contains_key(id) {
            gone.push(Arc::clone(live));
        }
    }
    r.external = fresh;
    gone
}

/// The cards for the interface: built-in ones first, then external ones
/// alphabetically. One that is off is in the list too, or there would be
/// nothing to switch it back on with.
pub fn cards() -> Vec<Value> {
    let Ok(r) = reg().read() else { return Vec::new() };
    let mut out = Vec::new();
    for p in &r.builtin {
        let mut m = p.manifest();
        m.enabled = !r.disabled.contains(&m.id);
        out.push(serde_json::to_value(m).unwrap_or(Value::Null));
    }
    for (id, e) in &r.external {
        let mut m = e.manifest();
        m.enabled = !r.disabled.contains(id);
        out.push(serde_json::to_value(m).unwrap_or(Value::Null));
    }
    out
}

/// What is installed and at which version, for the showcase, so that it can
/// tell "install" from "update". Built-in ones are here too: their identifier
/// is taken, and the showcase is obliged to show that rather than offer to
/// install a second ssh.
pub fn installed_versions() -> BTreeMap<String, String> {
    let Ok(r) = reg().read() else { return BTreeMap::new() };
    let mut out = BTreeMap::new();
    for p in &r.builtin {
        let m = p.manifest();
        out.insert(m.id, m.version);
    }
    for (id, e) in &r.external {
        out.insert(id.clone(), e.manifest().version);
    }
    out
}

/// One plugin's card.
pub fn card(id: &str) -> Option<Value> {
    let r = reg().read().ok()?;
    let enabled = !r.disabled.contains(id);
    let manifest = r
        .builtin
        .iter()
        .map(|p| p.manifest())
        .find(|m| m.id == id)
        .or_else(|| r.external.get(id).map(|e| e.manifest()))?;
    let mut manifest = manifest;
    manifest.enabled = enabled;
    serde_json::to_value(manifest).ok()
}

pub fn find(id: &str) -> Option<Entry> {
    let r = reg().read().ok()?;
    if let Some(p) = r.builtin.iter().find(|p| p.manifest().id == id) {
        return Some(Entry::Builtin(Arc::clone(p)));
    }
    r.external.get(id).map(|e| Entry::External(Arc::clone(e)))
}

pub fn external(id: &str) -> Option<Arc<External>> {
    reg().read().ok()?.external.get(id).cloned()
}

pub fn is_builtin(id: &str) -> bool {
    reg().read().is_ok_and(|r| r.builtin.iter().any(|p| p.manifest().id == id))
}

/// The identifier is taken: nothing may be installed over it.
pub fn taken(id: &str) -> bool {
    reg().read().is_ok_and(|r| {
        r.builtin.iter().any(|p| p.manifest().id == id) || r.external.contains_key(id)
    })
}

pub fn is_enabled(id: &str) -> bool {
    reg().read().is_ok_and(|r| !r.disabled.contains(id))
}

/// Everything that is on: events go to these.
pub fn enabled_entries() -> Vec<Entry> {
    let Ok(r) = reg().read() else { return Vec::new() };
    let mut out: Vec<Entry> = Vec::new();
    for p in &r.builtin {
        if !r.disabled.contains(&p.manifest().id) {
            out.push(Entry::Builtin(Arc::clone(p)));
        }
    }
    for (id, e) in &r.external {
        if !r.disabled.contains(id) {
            out.push(Entry::External(Arc::clone(e)));
        }
    }
    out
}

/// Switch on or off. The state outlives a restart of the daemon.
pub fn set_enabled(id: &str, on: bool) {
    let Ok(mut r) = reg().write() else { return };
    if on {
        r.disabled.remove(id);
    } else {
        r.disabled.insert(id.to_string());
    }
    save(&r.disabled, &r.installed);
}

/// Switching off over crashes. A method of its own, because it is called from
/// a process's reading task rather than from a request handler.
pub fn disable_after_crash(id: &str) {
    tracing::warn!(plugin = id, "the plugin was switched off: it crashes too often");
    set_enabled(id, false);
}

/// Forget an external plugin's live instance, after its directory has been
/// rewritten by an update. Without this the register would keep the former
/// manifest: `rescan` spares live processes and does not re-read a package it
/// already knows. Returns the old instance: its process has to be taken
/// down.
pub fn drop_external(id: &str) -> Option<Arc<External>> {
    reg().write().ok()?.external.remove(id)
}

/// What was remembered at installation.
pub fn record(id: &str) -> Option<Record> {
    reg().read().ok()?.installed.get(id).cloned()
}

/// Remember an installation.
pub fn remember(id: &str, rec: Record) {
    let Ok(mut r) = reg().write() else { return };
    r.installed.insert(id.to_string(), rec);
    save(&r.disabled, &r.installed);
}

/// Forget a removed plugin: both its record in the register and its trace in
/// the list of the switched-off.
pub fn forget(id: &str) {
    let Ok(mut r) = reg().write() else { return };
    r.external.remove(id);
    r.disabled.remove(id);
    r.installed.remove(id);
    save(&r.disabled, &r.installed);
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn nothing_is_built_in_any_more() {
        // ssh and HashiCorp left for the showcase as ordinary packages. The
        // kind "built-in" stayed in the types, but there are no built-in
        // plugins, and no identifier is taken by the daemon itself any more.
        assert!(!is_builtin("ssh"), "ssh is built in again, and the showcase knows nothing of that");
        assert!(!is_builtin("hashicorp"), "hashicorp is built in again");
    }

    #[test]
    fn every_card_carries_what_the_window_draws() {
        // The list is sometimes empty: nothing is installed, so there is
        // nothing to draw. But everything in it has to be a whole card: the
        // interface draws a section and a switch from it.
        for card in cards() {
            assert!(card["id"].as_str().is_some_and(|id| !id.is_empty()), "a card with no name: {card}");
            assert!(card["enabled"].is_boolean(), "a card with no switch: {card}");
            assert!(
                matches!(card["origin"].as_str(), Some("builtin" | "external")),
                "a card of an unknown kind: {card}"
            );
        }
    }
}
