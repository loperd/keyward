//! The showcase: what can be installed at all.
//!
//! A showcase is one `index.json` per source with packages beside it. The
//! daemon walks the sources, keeps from each entry the version that suits this
//! machine, and puts the lot into one list for the window.
//!
//! Three rules this whole file grew out of:
//!
//! 1. **A crooked entry does not bring the showcase down.** Somebody else's
//!    json is written by people and by scripts; one entry with no `sha256` is
//!    no reason to show a person an empty screen. So parsing goes entry by
//!    entry and version by version, and what cannot be understood is dropped
//!    with a line in the log.
//! 2. **An unreachable source is not an error on the screen.** The network went
//!    away, so what is in the cache is given out and the entries are marked
//!    `stale`. Installed plugins do not suffer from an unreachable showcase,
//!    and the list must not either.
//! 3. **The network hides behind a trait.** Parsing and the choice of version
//!    are checked by tests rather than by luck: [`super::net::Fetch`] is
//!    replaced by a fake.

use std::cmp::Ordering;
use std::collections::BTreeMap;
use std::path::{Path, PathBuf};
use std::time::Duration;

use serde::{Deserialize, Serialize};
use serde_json::Value;

use super::net::{self, Fetch};
use super::package;

/// The showcase's cache lies next to the packages, so the name is taken.
pub const CACHE_FILE: &str = "catalog.json";

/// How long the cache counts as fresh. An hour is a compromise: plugins are
/// released less often than that, and a person who presses "refresh" gets the
/// network at once.
const TTL: u64 = 3600;

/// The ceiling on `index.json`. A showcase is a list of names; four megabytes
/// of text here mean something has gone wrong.
const INDEX_CAP: usize = 4 * 1024 * 1024;

const INDEX_TIMEOUT: Duration = Duration::from_secs(20);

/// One row of the showcase after parsing: the version already chosen, the
/// package address already complete.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Offer {
    pub id: String,
    pub title: String,
    pub description: String,
    pub icon: String,
    pub homepage: String,
    /// The showcase address it came from.
    pub source: String,
    pub version: String,
    pub permissions: Vec<String>,
    pub size: u64,
    pub url: String,
    pub sha256: String,
    /// Who signed the package. Empty means the showcase has no signature at
    /// all.
    pub publisher: String,
    /// The publisher's public key as the showcase declared it. That does not
    /// make it trusted: a person checks five words and decides for
    /// themselves.
    pub publisher_key: String,
    /// The package's detached signature, base64.
    pub signature: String,
    /// The version was revoked, with a reason. One like that is shown but not
    /// installed.
    pub revoked: Option<String>,
    /// The showcase did not answer and the entry came from the cache.
    pub stale: bool,
}

/// A revoked version: it must not be installed, and an installed one is
/// switched off.
#[derive(Debug, Clone, PartialEq, Eq, Deserialize)]
pub struct Revoked {
    pub id: String,
    pub version: String,
    #[serde(default)]
    pub reason: String,
}

/// This machine's target triple. `std` has no complete triple, and dragging in
/// a build script for one is pointless: each of the three systems has a single
/// vendor and abi.
pub fn target() -> String {
    let arch = std::env::consts::ARCH;
    let rest = if cfg!(target_os = "macos") {
        "apple-darwin"
    } else if cfg!(target_os = "windows") {
        "pc-windows-msvc"
    } else {
        "unknown-linux-gnu"
    };
    format!("{arch}-{rest}")
}

/// Does a version suit this machine? `any` is a script and does not care.
fn suitable(platform: &str, target: &str) -> bool {
    platform == "any" || platform == target
}

/// Comparing versions by their numeric parts: `1.10.0` is newer than `1.9.0`,
/// though alphabetically it is the other way round.
fn cmp_version(a: &str, b: &str) -> Ordering {
    let parts = |v: &str| -> Vec<u64> {
        v.split(['.', '-', '+'])
            .map(|p| {
                let digits: String = p.chars().take_while(char::is_ascii_digit).collect();
                digits.parse().unwrap_or(0)
            })
            .collect()
    };
    let (x, y) = (parts(a), parts(b));
    for i in 0..x.len().max(y.len()) {
        let ord = x.get(i).copied().unwrap_or(0).cmp(&y.get(i).copied().unwrap_or(0));
        if ord != Ordering::Equal {
            return ord;
        }
    }
    a.cmp(b)
}

/// Is `a` newer than `b`?
pub fn newer(a: &str, b: &str) -> bool {
    cmp_version(a, b) == Ordering::Greater
}

// -- Parsing index.json ----------------------------------------------------

#[derive(Deserialize)]
struct RawIndex {
    #[serde(default)]
    version: u64,
    #[serde(default)]
    plugins: Vec<Value>,
    #[serde(default)]
    revoked: Vec<Value>,
    /// The publisher keys of this showcase. The showcase declares them, a
    /// person trusts them: `PluginTrust` puts a key from here into
    /// `publishers.json`.
    #[serde(default)]
    publishers: Vec<Value>,
}

/// A publisher key declared by a showcase.
#[derive(Debug, Clone, Deserialize)]
struct IndexPublisher {
    id: String,
    #[serde(default)]
    key: String,
}

#[derive(Deserialize)]
struct RawPlugin {
    id: String,
    #[serde(default)]
    title: String,
    #[serde(default)]
    description: String,
    #[serde(default)]
    icon: String,
    #[serde(default)]
    homepage: String,
    #[serde(default)]
    versions: Vec<Value>,
}

#[derive(Clone, Deserialize)]
struct RawVersion {
    version: String,
    #[serde(default = "any")]
    platform: String,
    url: String,
    sha256: String,
    #[serde(default)]
    permissions: Vec<String>,
    #[serde(default)]
    size: u64,
    #[serde(default)]
    publisher: String,
    #[serde(default)]
    signature: String,
}

fn any() -> String {
    "any".to_string()
}

fn parse_publishers(raw: &[Value]) -> Vec<IndexPublisher> {
    raw.iter()
        .filter_map(|v| serde_json::from_value::<IndexPublisher>(v.clone()).ok())
        .filter(|p| !p.id.is_empty() && !p.key.is_empty())
        .collect()
}

/// A publisher key as declared by a showcase. `PluginTrust` needs it: the
/// interface sends only a name, and the daemon takes the key from the same
/// showcase the person saw the plugin in.
pub fn publisher_key(raw: &str, publisher: &str) -> Option<String> {
    let index: RawIndex = serde_json::from_str(raw).ok()?;
    if index.version != 1 {
        return None;
    }
    parse_publishers(&index.publishers).into_iter().find(|p| p.id == publisher).map(|p| p.key)
}

fn parse_revoked(raw: &[Value]) -> Vec<Revoked> {
    raw.iter()
        .filter_map(|v| serde_json::from_value::<Revoked>(v.clone()).ok())
        .filter(|r| !r.id.is_empty() && !r.version.is_empty())
        .collect()
}

/// The revoked versions from a source's showcase.
pub fn revocations(raw: &str) -> Vec<Revoked> {
    match serde_json::from_str::<RawIndex>(raw) {
        Ok(index) if index.version == 1 => parse_revoked(&index.revoked),
        _ => Vec::new(),
    }
}

fn hex64(s: &str) -> bool {
    s.len() == 64 && s.chars().all(|c| c.is_ascii_hexdigit())
}

/// Parse one source's showcase. Everything that cannot be understood is
/// dropped: a showcase is somebody else's file, and refusing the lot would mean
/// one badly published plugin hides the rest.
pub fn parse(source: &str, raw: &str, target: &str) -> Vec<Offer> {
    let index: RawIndex = match serde_json::from_str(raw) {
        Ok(i) => i,
        Err(e) => {
            tracing::warn!(source, error = %e, "the showcase did not parse");
            return Vec::new();
        }
    };
    if index.version != 1 {
        tracing::warn!(source, version = index.version, "a showcase in an unknown format");
        return Vec::new();
    }
    let revoked = parse_revoked(&index.revoked);
    let keys = parse_publishers(&index.publishers);
    let mut out = Vec::new();
    for entry in index.plugins {
        let plugin: RawPlugin = match serde_json::from_value(entry) {
            Ok(p) => p,
            Err(e) => {
                tracing::warn!(source, error = %e, "a showcase entry was skipped");
                continue;
            }
        };
        if let Err(e) = package::validate_id(&plugin.id) {
            tracing::warn!(source, error = %e, "a showcase entry was skipped");
            continue;
        }
        // The versions are sorted descending by us: the order in the file is
        // the showcase author's business, and "the first that suits" has to be
        // the newest that suits.
        let mut versions: Vec<RawVersion> = plugin
            .versions
            .into_iter()
            .filter_map(|v| match serde_json::from_value::<RawVersion>(v) {
                Ok(v) => Some(v),
                Err(e) => {
                    tracing::warn!(source, id = %plugin.id, error = %e, "a version was skipped");
                    None
                }
            })
            .collect();
        versions.sort_by(|a, b| cmp_version(&b.version, &a.version));

        // Whole, and suiting this machine.
        let fit: Vec<RawVersion> = versions
            .into_iter()
            .filter(|v| {
                if !suitable(&v.platform, target) {
                    return false;
                }
                if !hex64(&v.sha256) {
                    tracing::warn!(source, id = %plugin.id, version = %v.version, "a version with no usable sha256 was skipped");
                    return false;
                }
                !v.version.trim().is_empty()
            })
            .collect();
        let reason_of = |v: &RawVersion| {
            revoked
                .iter()
                .find(|r| r.id == plugin.id && r.version == v.version)
                .map(|r| if r.reason.is_empty() { keyward_core::text::t("plugin.revoked.noReason", &[]) } else { r.reason.clone() })
        };
        // A revoked one is taken only when there is no other: it must not be
        // installed, but hiding it would not be fair — a person is owed the
        // reason the plugin will not be there.
        let picked = fit
            .iter()
            .find(|v| reason_of(v).is_none())
            .or_else(|| fit.first())
            .cloned();
        let Some(picked) = picked else { continue };
        let reason = reason_of(&picked);
        let url = match net::resolve(source, &picked.url) {
            Ok(url) => url,
            Err(e) => {
                tracing::warn!(source, id = %plugin.id, error = %e, "a version with an unusable address was skipped");
                continue;
            }
        };
        let title = if plugin.title.trim().is_empty() { plugin.id.clone() } else { plugin.title };
        out.push(Offer {
            id: plugin.id,
            title,
            description: plugin.description,
            icon: plugin.icon,
            homepage: plugin.homepage,
            source: source.to_string(),
            version: picked.version,
            permissions: picked.permissions,
            size: picked.size,
            url,
            sha256: picked.sha256.to_ascii_lowercase(),
            publisher_key: keys
                .iter()
                .find(|k| k.id == picked.publisher)
                .map(|k| k.key.clone())
                .unwrap_or_default(),
            publisher: picked.publisher,
            signature: picked.signature,
            revoked: reason,
            stale: false,
        });
    }
    out
}

/// What the showcase holds at a package address, revoked entries included. A
/// showcase does not offer a revoked version, but an installation has to tell
/// "there is no such address in the showcase" from "this package was
/// revoked".
#[derive(Debug, Clone)]
pub struct Found {
    pub offer: Offer,
    pub revoked: Option<String>,
}

/// Find a version by a package address in one showcase. The platform does not
/// matter here: the question is about a particular file, not "what would suit
/// me".
pub fn lookup(source: &str, raw: &str, url: &str) -> Option<Found> {
    let index: RawIndex = serde_json::from_str(raw).ok()?;
    if index.version != 1 {
        return None;
    }
    let revoked = parse_revoked(&index.revoked);
    let keys = parse_publishers(&index.publishers);
    for entry in index.plugins {
        let Ok(plugin) = serde_json::from_value::<RawPlugin>(entry) else { continue };
        if package::validate_id(&plugin.id).is_err() {
            continue;
        }
        for v in plugin.versions {
            let Ok(v) = serde_json::from_value::<RawVersion>(v) else { continue };
            let Ok(full) = net::resolve(source, &v.url) else { continue };
            if full != url {
                continue;
            }
            let reason = revoked
                .iter()
                .find(|r| r.id == plugin.id && r.version == v.version)
                .map(|r| if r.reason.is_empty() { keyward_core::text::t("plugin.revoked.noReason", &[]) } else { r.reason.clone() });
            return Some(Found {
                offer: Offer {
                    id: plugin.id,
                    title: if plugin.title.trim().is_empty() { String::new() } else { plugin.title },
                    description: plugin.description,
                    icon: plugin.icon,
                    homepage: plugin.homepage,
                    source: source.to_string(),
                    version: v.version,
                    permissions: v.permissions,
                    size: v.size,
                    url: full,
                    sha256: v.sha256.to_ascii_lowercase(),
                    publisher_key: keys
                        .iter()
                        .find(|k| k.id == v.publisher)
                        .map(|k| k.key.clone())
                        .unwrap_or_default(),
                    publisher: v.publisher,
                    signature: v.signature,
                    revoked: reason.clone(),
                    stale: false,
                },
                revoked: reason,
            });
        }
    }
    None
}

/// Fold the showcases of several sources into one. One plugin from two
/// showcases is a choice of version, not two identical tiles in the window.
pub fn merge(all: Vec<Offer>) -> Vec<Offer> {
    let mut by_id: BTreeMap<String, Offer> = BTreeMap::new();
    for offer in all {
        match by_id.get(&offer.id) {
            // A fresh entry from the cache loses to a live one of the same
            // version: there is no reason for anyone to see "the source did not
            // answer" when another one did.
            Some(have) if newer(&have.version, &offer.version) => {}
            Some(have) if have.version == offer.version && !have.stale => {}
            _ => {
                by_id.insert(offer.id.clone(), offer);
            }
        }
    }
    by_id.into_values().collect()
}

// -- The cache --------------------------------------------------------------

#[derive(Default, Serialize, Deserialize)]
struct Cache {
    #[serde(default)]
    sources: BTreeMap<String, Cached>,
}

#[derive(Clone, Serialize, Deserialize)]
struct Cached {
    /// When it was fetched, in seconds since the epoch.
    fetched: u64,
    index: Value,
}

fn cache_path(dir: &Path) -> PathBuf {
    dir.join(CACHE_FILE)
}

fn load_cache(dir: &Path) -> Cache {
    let path = cache_path(dir);
    let Ok(raw) = std::fs::read_to_string(&path) else { return Cache::default() };
    serde_json::from_str(&raw).unwrap_or_else(|e| {
        tracing::warn!(error = %e, path = %path.display(), "the showcase cache did not parse");
        Cache::default()
    })
}

fn save_cache(dir: &Path, cache: &Cache) {
    if let Err(e) = std::fs::create_dir_all(dir) {
        tracing::warn!(error = %e, "the plugins directory was not created");
        return;
    }
    let _ = crate::daemon::restrict(dir);
    let body = serde_json::to_string_pretty(cache).unwrap_or_default();
    if let Err(e) = std::fs::write(cache_path(dir), body) {
        tracing::warn!(error = %e, "the showcase cache was not saved");
    }
}

pub fn now() -> u64 {
    std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map(|d| d.as_secs())
        .unwrap_or_default()
}

/// Is a source's cache fresh?
fn fresh(cached: &Cached, now: u64) -> bool {
    now.saturating_sub(cached.fetched) < TTL
}

// -- Gathering the showcase -------------------------------------------------

/// The whole showcase: what is offered and what was revoked.
#[derive(Debug, Default, Clone)]
pub struct Shelf {
    pub offers: Vec<Offer>,
    pub revoked: Vec<Revoked>,
}

/// Walk the sources and gather the offers. The network goes through `fetcher`
/// and the time comes from outside: both are replaced in tests.
pub async fn collect(
    dir: &Path,
    fetcher: &dyn Fetch,
    sources: &[String],
    refresh: bool,
    target: &str,
    now: u64,
) -> Shelf {
    let mut cache = load_cache(dir);
    let mut changed = false;
    let mut all = Vec::new();
    let mut revoked: Vec<Revoked> = Vec::new();

    for source in sources {
        let cached = cache.sources.get(source).cloned();
        // A fresh cache is not "no network" but an ordinary answer: a showcase
        // is not re-read every time a tab is opened.
        if !refresh {
            if let Some(c) = cached.as_ref().filter(|c| fresh(c, now)) {
                let raw = c.index.to_string();
                revoked.extend(revocations(&raw));
                all.extend(parse(source, &raw, target));
                continue;
            }
        }
        match fetcher.get(source, INDEX_CAP, INDEX_TIMEOUT).await {
            Ok(bytes) => {
                let raw = String::from_utf8_lossy(&bytes).into_owned();
                revoked.extend(revocations(&raw));
                let offers = parse(source, &raw, target);
                match serde_json::from_str::<Value>(&raw) {
                    Ok(index) => {
                        cache.sources.insert(source.clone(), Cached { fetched: now, index });
                        changed = true;
                    }
                    Err(e) => tracing::warn!(source, error = %e, "the showcase did not parse; it does not go into the cache"),
                }
                all.extend(offers);
            }
            Err(e) if e.to_string().contains(super::net::GONE) => {
                // There is nothing at the address: the showcase was taken down
                // or the address is wrong. Showing from the cache what is no
                // longer there would be a lie; we clear it and show nothing.
                tracing::warn!(source, error = %e, "there is no showcase at the address; the cache was thrown away");
                if cache.sources.remove(source).is_some() {
                    changed = true;
                }
            }
            Err(e) => {
                // The showcase is unreachable: the cache is given out however
                // old it is, and said so in the entry rather than as an error
                // across the whole screen.
                tracing::warn!(source, error = %e, "the showcase is unreachable");
                if let Some(c) = cached {
                    let raw = c.index.to_string();
                    revoked.extend(revocations(&raw));
                    all.extend(parse(source, &raw, target).into_iter().map(|mut o| {
                        o.stale = true;
                        o
                    }));
                }
            }
        }
    }

    if changed {
        save_cache(dir, &cache);
    }
    Shelf { offers: merge(all), revoked }
}

/// The five words of a publisher key. For a trusted publisher, from our own
/// file; for an unfamiliar one, from the key the showcase declared: that is the
/// one a person checks with the author before pressing "trust".
fn fingerprint_of(offer: &Offer, publishers: &[super::publishers::Publisher]) -> Vec<String> {
    if offer.publisher.is_empty() {
        return Vec::new();
    }
    if let Some(known) = publishers.iter().find(|p| p.id == offer.publisher) {
        return known.words();
    }
    if offer.publisher_key.is_empty() {
        return Vec::new();
    }
    let declared = super::publishers::Publisher {
        id: offer.publisher.clone(),
        key: offer.publisher_key.clone(),
        added: String::new(),
        builtin: false,
    };
    declared.words()
}

/// The reason an installed version was revoked, from the showcase's cache,
/// with no trip over the network.
pub fn revoked_reason(dir: &Path, sources: &[String], id: &str, version: &str) -> Option<String> {
    let cache = load_cache(dir);
    for source in sources {
        let c = cache.sources.get(source)?;
        let found = revocations(&c.index.to_string())
            .into_iter()
            .find(|r| r.id == id && r.version == version);
        if let Some(r) = found {
            return Some(if r.reason.is_empty() { keyward_core::text::t("plugin.revoked.noReason", &[]) } else { r.reason });
        }
    }
    None
}

/// A publisher key declared by any of the showcases. For `PluginTrust`.
pub fn declared_key(dir: &Path, sources: &[String], publisher: &str) -> Option<String> {
    let cache = load_cache(dir);
    for source in sources {
        if let Some(c) = cache.sources.get(source) {
            if let Some(key) = publisher_key(&c.index.to_string(), publisher) {
                return Some(key);
            }
        }
    }
    None
}

/// The showcase in the shape the window expects.
pub fn cards(
    offers: &[Offer],
    installed: &BTreeMap<String, String>,
    publishers: &[super::publishers::Publisher],
) -> Vec<Value> {
    offers
        .iter()
        .map(|o| {
            let have = installed.get(&o.id);
            let trusted = publishers.iter().any(|p| p.id == o.publisher);
            let fingerprint = fingerprint_of(o, publishers);
            let mut card = serde_json::json!({
                "id": o.id,
                "title": o.title,
                "description": o.description,
                "icon": o.icon,
                "homepage": o.homepage,
                "source": o.source,
                "url": o.url,
                "version": o.version,
                "permissions": o.permissions,
                "size": o.size,
                "publisher": o.publisher,
                "fingerprint": fingerprint,
                "trusted": trusted,
                "signed": !o.signature.is_empty(),
                "installed": have.is_some(),
                "installed_version": have.cloned().unwrap_or_default(),
                "update": have.is_some_and(|v| newer(&o.version, v)),
            });
            if o.stale {
                card["stale"] = Value::Bool(true);
            }
            if let Some(reason) = &o.revoked {
                card["revoked"] = Value::Bool(true);
                card["reason"] = Value::String(reason.clone());
            }
            card
        })
        .collect()
}

/// Find a showcase entry by a package address, for the fingerprint and the
/// signature before installing. The cache first: the list a person has just
/// pressed "install" on lies exactly there. Not found means one trip over the
/// network, and only then "the address is not in the showcase".
pub async fn found_for_url(
    dir: &Path,
    fetcher: &dyn Fetch,
    sources: &[String],
    url: &str,
    now: u64,
) -> Option<Found> {
    let cache = load_cache(dir);
    for source in sources {
        if let Some(c) = cache.sources.get(source) {
            if let Some(found) = lookup(source, &c.index.to_string(), url) {
                return Some(found);
            }
        }
    }
    // The cache may have fallen behind: a person could have taken a new
    // version out of the author's letter. One trip over the network, and only
    // then "installing it unverified".
    for source in sources {
        let Ok(bytes) = fetcher.get(source, INDEX_CAP, INDEX_TIMEOUT).await else { continue };
        let raw = String::from_utf8_lossy(&bytes).into_owned();
        if let Ok(index) = serde_json::from_str::<Value>(&raw) {
            let mut cache = load_cache(dir);
            cache.sources.insert(source.clone(), Cached { fetched: now, index });
            save_cache(dir, &cache);
        }
        if let Some(found) = lookup(source, &raw, url) {
            return Some(found);
        }
    }
    None
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::sync::Mutex;

    /// A showcase with no network: it gives back what was put in.
    struct Canned {
        answers: BTreeMap<String, anyhow::Result<String>>,
        calls: Mutex<Vec<String>>,
    }

    impl Canned {
        fn ok(source: &str, body: &str) -> Self {
            let mut answers = BTreeMap::new();
            answers.insert(source.to_string(), Ok(body.to_string()));
            Self { answers, calls: Mutex::new(Vec::new()) }
        }

        fn dead() -> Self {
            Self { answers: BTreeMap::new(), calls: Mutex::new(Vec::new()) }
        }

        fn calls(&self) -> usize {
            self.calls.lock().unwrap().len()
        }
    }

    #[async_trait::async_trait]
    impl Fetch for Canned {
        async fn get(&self, url: &str, _cap: usize, _t: Duration) -> anyhow::Result<Vec<u8>> {
            self.calls.lock().unwrap().push(url.to_string());
            match self.answers.get(url) {
                Some(Ok(body)) => Ok(body.clone().into_bytes()),
                _ => anyhow::bail!("the showcase does not answer"),
            }
        }
    }

    const SOURCE: &str = "https://pkg.example.net/index.json";

    const INDEX: &str = r#"{
      "version": 1,
      "plugins": [
        {
          "id": "hello", "title": "Hello", "description": "a check", "icon": "note",
          "homepage": "https://git.example.net/hello",
          "versions": [
            {"version": "1.0.0", "platform": "any", "url": "hello/1.0.0/hello-1.0.0.tar.gz",
             "sha256": "aa00000000000000000000000000000000000000000000000000000000000011",
             "permissions": ["entries", "notices"], "size": 4096},
            {"version": "1.2.0", "platform": "sparc-sun-solaris",
             "url": "https://pkg.example.net/hello/1.2.0/p.tar.gz",
             "sha256": "bb00000000000000000000000000000000000000000000000000000000000022"}
          ]
        },
        {
          "id": "native", "title": "Native",
          "versions": [
            {"version": "2.0.0", "platform": "aarch64-apple-darwin",
             "url": "https://pkg.example.net/native/2.0.0/p.tar.gz",
             "sha256": "cc00000000000000000000000000000000000000000000000000000000000033",
             "size": 10}
          ]
        },
        {"title": "no identifier", "versions": []},
        {"id": "UPPERCASE", "versions": []},
        {
          "id": "broken", "title": "Broken",
          "versions": [
            {"version": "1.0.0", "url": "broken/p.tar.gz"},
            {"version": "0.9.0", "url": "broken/p.tar.gz", "sha256": "short"}
          ]
        }
      ]
    }"#;

    fn temp(name: &str) -> PathBuf {
        let dir = std::env::temp_dir().join(format!("kw-cat-{}-{name}", std::process::id()));
        let _ = std::fs::remove_dir_all(&dir);
        std::fs::create_dir_all(&dir).unwrap();
        dir
    }

    #[test]
    fn the_index_parses_and_the_broken_bits_fall_out() {
        let offers = parse(SOURCE, INDEX, "aarch64-apple-darwin");
        let ids: Vec<&str> = offers.iter().map(|o| o.id.as_str()).collect();
        assert_eq!(ids, vec!["hello", "native"], "the showcase came out wrong: {ids:?}");

        let hello = &offers[0];
        assert_eq!(hello.version, "1.0.0", "a version for another platform must not win");
        // A relative address unfolds next to the showcase.
        assert_eq!(hello.url, "https://pkg.example.net/hello/1.0.0/hello-1.0.0.tar.gz");
        assert_eq!(hello.permissions, vec!["entries", "notices"]);
        assert_eq!(hello.size, 4096);
        assert!(!hello.stale);

        // An entry with no identifier, one with capitals in it, and a version
        // with no usable fingerprint all go past, and none of them brought the
        // showcase down.
        assert!(!ids.contains(&"broken"), "a version with no sha256 has no right to be installed");
    }

    #[test]
    fn an_unknown_platform_leaves_nothing_to_offer() {
        let offers = parse(SOURCE, INDEX, "sparc-sun-solaris");
        let ids: Vec<&str> = offers.iter().map(|o| o.id.as_str()).collect();
        // `any` suits everyone; a version for another triple suits only its
        // own.
        assert_eq!(ids, vec!["hello"]);
        assert_eq!(offers[0].version, "1.2.0", "for our own triple, our own version is taken");
    }

    #[test]
    fn a_broken_file_is_an_empty_showcase_not_a_panic() {
        assert!(parse(SOURCE, "{ not json", "any-target").is_empty());
        assert!(parse(SOURCE, r#"{"version": 7, "plugins": []}"#, "any-target").is_empty());
        assert!(parse(SOURCE, "[]", "any-target").is_empty());
    }

    #[test]
    fn versions_are_compared_by_numbers_not_letters() {
        assert!(newer("1.10.0", "1.9.0"));
        assert!(newer("2.0.0", "1.999.999"));
        assert!(!newer("1.0.0", "1.0.0"));
        assert!(!newer("0.9.0", "1.0.0"));
    }

    #[test]
    fn cards_say_what_is_installed_and_what_is_older() {
        let offers = parse(SOURCE, INDEX, "aarch64-apple-darwin");
        let mut installed = BTreeMap::new();
        installed.insert("hello".to_string(), "0.9.0".to_string());
        let cards = cards(&offers, &installed, &[]);
        assert_eq!(cards[0]["installed"], true);
        assert_eq!(cards[0]["installed_version"], "0.9.0");
        assert_eq!(cards[0]["update"], true);
        assert_eq!(cards[1]["installed"], false);
        assert_eq!(cards[1]["installed_version"], "");
        assert_eq!(cards[1]["update"], false);
        assert!(cards[0].get("stale").is_none(), "a live entry is not marked as cached");
    }

    #[tokio::test]
    async fn a_fresh_cache_saves_a_trip_and_a_stale_one_does_not() {
        let dir = temp("ttl");
        let net = Canned::ok(SOURCE, INDEX);
        let sources = vec![SOURCE.to_string()];

        let first = collect(&dir, &net, &sources, false, "aarch64-apple-darwin", 1000).await.offers;
        assert_eq!(first.len(), 2);
        assert_eq!(net.calls(), 1);

        // Within the hour we do not go to the network.
        let again = collect(&dir, &net, &sources, false, "aarch64-apple-darwin", 1000 + TTL - 1).await.offers;
        assert_eq!(again.len(), 2);
        assert_eq!(net.calls(), 1, "went to the network on a fresh cache");

        // The hour is up, so we go.
        collect(&dir, &net, &sources, false, "aarch64-apple-darwin", 1000 + TTL + 1).await;
        assert_eq!(net.calls(), 2);

        // "Refresh" always goes to the network.
        collect(&dir, &net, &sources, true, "aarch64-apple-darwin", 1000 + TTL + 1).await;
        assert_eq!(net.calls(), 3);

        let _ = std::fs::remove_dir_all(&dir);
    }

    #[tokio::test]
    async fn an_unreachable_source_falls_back_to_the_cache() {
        let dir = temp("stale");
        let sources = vec![SOURCE.to_string()];
        let live = Canned::ok(SOURCE, INDEX);
        collect(&dir, &live, &sources, false, "aarch64-apple-darwin", 1000).await;

        // The network went away and the cache is stale: the list has to stay
        // and the entries have to get their mark.
        let dead = Canned::dead();
        let offers = collect(&dir, &dead, &sources, false, "aarch64-apple-darwin", 1000 + TTL * 10).await.offers;
        assert_eq!(offers.len(), 2, "the showcase vanished along with the network");
        assert!(offers.iter().all(|o| o.stale), "entries from the cache are not marked");
        let cards = cards(&offers, &BTreeMap::new(), &[]);
        assert_eq!(cards[0]["stale"], true);

        let _ = std::fs::remove_dir_all(&dir);
    }

    #[tokio::test]
    async fn with_no_cache_and_no_network_the_list_is_simply_empty() {
        let dir = temp("nothing");
        let dead = Canned::dead();
        let offers = collect(&dir, &dead, &[SOURCE.to_string()], false, "aarch64-apple-darwin", 1).await.offers;
        assert!(offers.is_empty());
        let _ = std::fs::remove_dir_all(&dir);
    }

    #[test]
    fn a_revoked_version_is_not_offered_and_says_why() {
        let index = r#"{
          "version": 1,
          "revoked": [{"id": "hello", "version": "1.1.0", "reason": "the publisher key leaked"}],
          "plugins": [{"id": "hello", "title": "Hello", "versions": [
            {"version": "1.1.0", "platform": "any", "url": "h/1.1.0/p.tar.gz",
             "sha256": "aa00000000000000000000000000000000000000000000000000000000000011"},
            {"version": "1.0.0", "platform": "any", "url": "h/1.0.0/p.tar.gz",
             "sha256": "bb00000000000000000000000000000000000000000000000000000000000022"}]}]
        }"#;
        let offers = parse(SOURCE, index, "aarch64-apple-darwin");
        assert_eq!(offers.len(), 1);
        assert_eq!(offers[0].version, "1.0.0", "a revoked version must not be offered");
        let revoked = revocations(index);
        assert_eq!(revoked.len(), 1);
        assert_eq!(revoked[0].reason, "the publisher key leaked");
    }

    #[test]
    fn the_publisher_reaches_the_card() {
        let index = r#"{"version":1,"plugins":[{"id":"hello","title":"Hello","versions":[
          {"version":"1.0.0","platform":"any","url":"h/p.tar.gz",
           "sha256":"aa00000000000000000000000000000000000000000000000000000000000011",
           "publisher":"keyward","signature":"AAAA"}]}]}"#;
        let offers = parse(SOURCE, index, "any-target");
        assert_eq!(offers[0].publisher, "keyward");
        assert_eq!(offers[0].signature, "AAAA");
        let publishers = super::super::publishers::load_from(std::path::Path::new("/no-such-directory"));
        let card = &cards(&offers, &BTreeMap::new(), &publishers)[0];
        assert_eq!(card["publisher"], "keyward");
        assert_eq!(card["signed"], true);
        assert_eq!(card["trusted"], true, "a built-in publisher is trusted out of the box");
        assert_eq!(card["fingerprint"].as_array().map(Vec::len), Some(5), "five words to check the key by");

        // An unfamiliar publisher: no trust, but five words are there, out of
        // the key the showcase declared. Those are what a person checks with
        // the author.
        let stranger = r#"{"version":1,"publishers":[{"id":"neighbour","key":"AQEBAQEBAQEBAQEBAQEBAQEBAQEBAQEBAQEBAQEBAQE="}],
          "plugins":[{"id":"hello","title":"Hello","versions":[
          {"version":"1.0.0","platform":"any","url":"h/p.tar.gz",
           "sha256":"aa00000000000000000000000000000000000000000000000000000000000011",
           "publisher":"neighbour","signature":"AAAA"}]}]}"#;
        let offers = parse(SOURCE, stranger, "any-target");
        let card = &cards(&offers, &BTreeMap::new(), &publishers)[0];
        assert_eq!(card["trusted"], false);
        assert_eq!(card["fingerprint"].as_array().map(Vec::len), Some(5));
        assert_eq!(
            publisher_key(stranger, "neighbour").as_deref(),
            Some("AQEBAQEBAQEBAQEBAQEBAQEBAQEBAQEBAQEBAQEBAQE="),
            "a publisher key has to come out of the showcase: it is what trust is given to"
        );
    }


    #[test]
    fn two_sources_with_one_plugin_leave_the_newer_version() {
        let old = Offer {
            id: "hello".into(), title: "Hello".into(), description: String::new(), icon: String::new(),
            homepage: String::new(), source: "https://a/index.json".into(), version: "1.0.0".into(),
            permissions: vec![], size: 0, url: "https://a/p.tar.gz".into(), sha256: "0".repeat(64),
            publisher: "keyward".into(), publisher_key: String::new(), signature: "AA==".into(),
            revoked: None, stale: false,
        };
        let new = Offer { version: "1.1.0".into(), source: "https://b/index.json".into(), ..old.clone() };
        let merged = merge(vec![old.clone(), new.clone()]);
        assert_eq!(merged.len(), 1);
        assert_eq!(merged[0].version, "1.1.0");
        // The order of sources does not change the outcome.
        assert_eq!(merge(vec![new, old])[0].version, "1.1.0");
    }
}
