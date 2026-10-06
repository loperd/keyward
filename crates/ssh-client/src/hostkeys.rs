//! Which host keys are trusted.
//!
//! Four places, in this order:
//!
//! 1. The item's `kw-hostkey`: a pin is the last word. A key that does not match
//!    it is refused, whatever anything else says.
//! 2. The item's `kw-knownhosts`: the keys a person confirmed while logging in
//!    with this item, one known_hosts line each. This is where a confirmation
//!    is written: it lives in the vault, so every plugin that goes to a server
//!    with the item trusts what the person trusted in any of them, and it
//!    travels with the vault to the next machine.
//! 3. The person's `~/.ssh/known_hosts`, read and never written: an ssh
//!    configuration is too dear to be edited behind somebody's back, and the
//!    same host already trusted by `ssh` should not be asked about twice.
//! 4. The plugin's own `known_hosts` in its directory, where confirmations
//!    were written before they moved into the items. Read so that nobody is
//!    asked twice; a key found only there is copied into the item it was used
//!    with. Written only by a store that has no item — a test's. Host names in
//!    it are hashed the way OpenSSH's `HashKnownHosts` does.
//!
//! A key of the same kind that differs from a recorded one is a changed key and
//! is refused outright — that is exactly what a man in the middle looks like.
//! A host with nothing recorded is unknown, and the terminal asks.

use std::io::Write as _;
use std::path::{Path, PathBuf};
use std::sync::Arc;

use base64::Engine as _;
use hmac::{Hmac, Mac as _};
use keyward_plugin::Host;
use russh::keys::{HashAlg, PublicKey};

use crate::table::KNOWN_HOSTS;

/// Where a recorded key came from, for the words a person reads.
#[derive(Debug, Clone, Copy, PartialEq, Eq, serde::Serialize)]
#[serde(rename_all = "snake_case")]
pub enum Source {
    /// The item's `kw-hostkey`.
    Pin,
    /// The item's `kw-knownhosts`.
    Item,
    /// `~/.ssh/known_hosts`.
    User,
    /// The plugin's own file.
    Keyward,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Verdict {
    /// The key matches the item's pin.
    Pinned,
    /// The key is recorded for this host.
    Known(Source),
    /// Nothing is recorded for this host. `others` means keys of other kinds
    /// are, so the server offered a kind it was not known by.
    Unknown { others: bool },
    /// A different key of the same kind is recorded, or the key is revoked.
    Changed(Source),
}

impl Verdict {
    pub fn trusted(&self) -> bool {
        matches!(self, Self::Pinned | Self::Known(_))
    }
}

/// The host's key as a person compares it: `SHA256:…`.
pub fn fingerprint(key: &PublicKey) -> String {
    key.fingerprint(HashAlg::Sha256).to_string()
}

/// How known_hosts names a host: bare on port 22, `[host]:port` elsewhere.
fn host_port(host: &str, port: u16) -> String {
    if port == 22 {
        host.to_string()
    } else {
        format!("[{host}]:{port}")
    }
}

fn b64() -> base64::engine::GeneralPurpose {
    base64::engine::general_purpose::STANDARD
}

/// Does one pattern of a known_hosts line name this host? Hashed entries,
/// globs and plain names; a negated pattern that matches takes the whole line
/// out.
fn line_names(patterns: &str, name: &str) -> bool {
    let mut hit = false;
    for p in patterns.split(',') {
        if let Some(hashed) = p.strip_prefix("|1|") {
            let mut parts = hashed.split('|');
            let (Some(salt), Some(hash)) = (parts.next(), parts.next()) else { continue };
            let (Ok(salt), Ok(hash)) = (b64().decode(salt), b64().decode(hash)) else { continue };
            let Ok(mut mac) = Hmac::<sha1::Sha1>::new_from_slice(&salt) else { continue };
            mac.update(name.as_bytes());
            if mac.verify_slice(&hash).is_ok() {
                hit = true;
            }
        } else if let Some(negated) = p.strip_prefix('!') {
            if crate::glob::matches(negated, name) {
                return false;
            }
        } else if crate::glob::matches(p, name) {
            hit = true;
        }
    }
    hit
}

/// One recorded key.
struct Recorded {
    key: PublicKey,
    revoked: bool,
}

/// The keys a file records for a host. A missing file records nothing; a file
/// that cannot be read is an error, not "nothing" — that would turn a known
/// host into an unknown one and invite a person to trust a stranger. A line
/// that does not parse is skipped with a warning, as ssh itself does.
fn recorded(path: &Path, name: &str) -> anyhow::Result<Vec<Recorded>> {
    let text = match std::fs::read_to_string(path) {
        Ok(t) => t,
        Err(e) if e.kind() == std::io::ErrorKind::NotFound => return Ok(Vec::new()),
        Err(e) => {
            tracing::error!(path = %path.display(), error = %e, "a known_hosts file will not read");
            return Err(keyward_core::fault!("err.sshKnownHostsUnreadable", "path" => path.display().to_string()));
        }
    };
    Ok(recorded_in(&text, name, &path.display().to_string()))
}

/// The keys known_hosts text records for a host; `origin` names it in the log.
fn recorded_in(text: &str, name: &str, origin: &str) -> Vec<Recorded> {
    let mut out = Vec::new();
    for (n, line) in text.lines().enumerate() {
        let line = line.trim();
        if line.is_empty() || line.starts_with('#') {
            continue;
        }
        let mut fields = line.split_whitespace();
        let mut first = fields.next().unwrap_or_default();
        let mut revoked = false;
        if first.starts_with('@') {
            match first {
                "@revoked" => revoked = true,
                // A certificate authority vouches for host certificates; the
                // terminal compares plain keys and leaves those lines alone.
                _ => continue,
            }
            first = fields.next().unwrap_or_default();
        }
        if !line_names(first, name) {
            continue;
        }
        let (Some(_kind), Some(blob)) = (fields.next(), fields.next()) else {
            tracing::warn!(origin, line = n + 1, "a known_hosts line without a key was skipped");
            continue;
        };
        match russh::keys::parse_public_key_base64(blob) {
            Ok(key) => out.push(Recorded { key, revoked }),
            Err(e) => tracing::warn!(origin, line = n + 1, error = %e, "a known_hosts key that does not parse was skipped"),
        }
    }
    out
}

/// Takes a host's lines out of known_hosts text; how many went.
fn without(text: &str, name: &str) -> (String, usize) {
    let mut kept = String::with_capacity(text.len());
    let mut dropped = 0;
    for line in text.lines() {
        let first = line.split_whitespace().next().unwrap_or_default();
        if !line.trim_start().starts_with('#') && line_names(first, name) {
            dropped += 1;
        } else {
            kept.push_str(line);
            kept.push('\n');
        }
    }
    (kept, dropped)
}

/// Forgets what every item's `kw-knownhosts` records for a host: the way out
/// of a changed key a person has checked, together with `Store::forget`.
pub async fn forget_in_items(core: &dyn Host, host: &str, port: u16) -> anyhow::Result<usize> {
    let name = host_port(host, port);
    let mut dropped = 0;
    for e in core.entries() {
        let Some(text) = e.field(KNOWN_HOSTS) else { continue };
        let (kept, n) = without(text, &name);
        if n > 0 {
            core.set_fields(&e.id, vec![(KNOWN_HOSTS.to_string(), kept.trim_end().to_string())]).await?;
            dropped += n;
        }
    }
    Ok(dropped)
}

/// Are two host key fingerprints the same?
///
/// In the item's field a person may write the full `SHA256:...` fingerprint,
/// or what `ssh-keyscan` gives (`ssh-ed25519 AAAA...`), or plain base64. A
/// comparison that ignores case and trailing equals signs covers all three
/// forms without making anyone rewrite the field to our taste.
pub fn same_key(pinned: &str, seen: &str) -> bool {
    let tidy = |v: &str| -> String {
        v.trim()
            .rsplit(' ')
            .next()
            .unwrap_or("")
            .trim_start_matches("SHA256:")
            .trim_end_matches('=')
            .to_ascii_lowercase()
    };
    let seen = tidy(seen);
    pinned
        .split(|c: char| c == ',' || c.is_whitespace() && false)
        .map(tidy)
        .any(|p| !p.is_empty() && p == seen)
}

/// Does the item's `kw-hostkey` name this key? A person may write the
/// fingerprint, what `ssh-keyscan` prints or the bare base64 of the key.
pub fn pin_matches(pin: &str, key: &PublicKey) -> bool {
    if same_key(pin, &fingerprint(key)) {
        return true;
    }
    key.to_openssh().is_ok_and(|line| same_key(pin, &line))
}

/// The person's own known_hosts, where ssh keeps it.
pub fn user_file() -> Option<PathBuf> {
    std::env::home_dir().map(|h| h.join(".ssh").join("known_hosts"))
}

/// The item a login goes with: its `kw-knownhosts` is read and written
/// through the core.
#[derive(Clone)]
pub struct Item {
    pub entry_id: String,
    pub core: Arc<dyn Host>,
}

impl Item {
    /// The item's `kw-knownhosts` as it is now. An item that has left the
    /// vault is an error rather than "nothing recorded".
    async fn known(&self) -> anyhow::Result<String> {
        let entry = crate::core::entries(&self.core)
            .await?
            .into_iter()
            .find(|e| e.id == self.entry_id)
            .ok_or_else(|| keyward_core::fault!("err.sshKeyGone"))?;
        Ok(entry.field(KNOWN_HOSTS).unwrap_or_default().to_string())
    }
}

/// Where trust is recorded: the item, the person's file and the plugin's own.
#[derive(Clone)]
pub struct Store {
    pub user: Option<PathBuf>,
    pub own: PathBuf,
    pub item: Option<Item>,
}

impl std::fmt::Debug for Store {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("Store")
            .field("user", &self.user)
            .field("own", &self.own)
            .field("item", &self.item.as_ref().map(|i| &i.entry_id))
            .finish()
    }
}

impl Store {
    pub fn new(plugin_dir: &Path) -> Self {
        Self { user: user_file(), own: plugin_dir.join("known_hosts"), item: None }
    }

    /// The same store for a login with this item.
    pub fn for_item(self, entry_id: &str, core: Arc<dyn Host>) -> Self {
        Self { item: Some(Item { entry_id: entry_id.to_string(), core }), ..self }
    }

    /// What to make of the key a server presented.
    pub async fn verify(&self, host: &str, port: u16, key: &PublicKey, pin: Option<&str>) -> anyhow::Result<Verdict> {
        if let Some(pin) = pin.map(str::trim).filter(|p| !p.is_empty()) {
            return Ok(if pin_matches(pin, key) { Verdict::Pinned } else { Verdict::Changed(Source::Pin) });
        }
        let name = host_port(host, port);
        let mut sources = Vec::new();
        if let Some(item) = &self.item {
            sources.push((Source::Item, recorded_in(&item.known().await?, &name, KNOWN_HOSTS)));
        }
        if let Some(user) = &self.user {
            sources.push((Source::User, recorded(user, &name)?));
        }
        sources.push((Source::Keyward, recorded(&self.own, &name)?));

        // A revoked key is refused wherever it was revoked.
        for (source, keys) in &sources {
            if keys.iter().any(|r| r.revoked && r.key.key_data() == key.key_data()) {
                return Ok(Verdict::Changed(*source));
            }
        }
        for (source, keys) in &sources {
            if keys.iter().any(|r| !r.revoked && r.key.key_data() == key.key_data()) {
                return Ok(Verdict::Known(*source));
            }
        }
        for (source, keys) in &sources {
            if keys.iter().any(|r| !r.revoked && r.key.algorithm() == key.algorithm()) {
                return Ok(Verdict::Changed(*source));
            }
        }
        let others = sources.iter().any(|(_, keys)| keys.iter().any(|r| !r.revoked));
        Ok(Verdict::Unknown { others })
    }

    /// Records a key a person confirmed: in the item's `kw-knownhosts` under
    /// the plain name (the vault is sealed, and a person reading the item
    /// should see what is trusted), or, for a store with no item, in the
    /// plugin's own file under a hashed one.
    pub async fn learn(&self, host: &str, port: u16, key: &PublicKey) -> anyhow::Result<()> {
        let name = host_port(host, port);
        let openssh = key.to_openssh().map_err(|e| anyhow::anyhow!("the host key will not encode: {e}"))?;
        if let Some(item) = &self.item {
            let mut text = item.known().await?;
            if recorded_in(&text, &name, KNOWN_HOSTS).iter().any(|r| !r.revoked && r.key.key_data() == key.key_data()) {
                return Ok(());
            }
            if !text.is_empty() && !text.ends_with('\n') {
                text.push('\n');
            }
            text.push_str(&format!("{name} {}", openssh.trim()));
            return item.core.set_fields(&item.entry_id, vec![(KNOWN_HOSTS.to_string(), text)]).await;
        }
        let mut salt = [0u8; 20];
        rand_core::RngCore::fill_bytes(&mut rand_core::OsRng, &mut salt);
        let mut mac = Hmac::<sha1::Sha1>::new_from_slice(&salt).map_err(|e| anyhow::anyhow!("hmac: {e}"))?;
        mac.update(name.as_bytes());
        let hash = mac.finalize().into_bytes();
        let line = format!("|1|{}|{} {}\n", b64().encode(salt), b64().encode(hash), openssh.trim());

        let mut text = self.own_text()?;
        if !text.is_empty() && !text.ends_with('\n') {
            text.push('\n');
        }
        text.push_str(&line);
        self.write_own(&text)
    }

    /// Forgets what the plugin's own file records for a host: the way out of a
    /// changed key a person has checked, together with `forget_in_items`. The
    /// person's `~/.ssh/known_hosts` is never touched — that one they edit
    /// themselves.
    pub fn forget(&self, host: &str, port: u16) -> anyhow::Result<usize> {
        let (kept, dropped) = without(&self.own_text()?, &host_port(host, port));
        if dropped > 0 {
            self.write_own(&kept)?;
        }
        Ok(dropped)
    }

    fn own_text(&self) -> anyhow::Result<String> {
        match std::fs::read_to_string(&self.own) {
            Ok(t) => Ok(t),
            Err(e) if e.kind() == std::io::ErrorKind::NotFound => Ok(String::new()),
            Err(e) => {
                tracing::error!(path = %self.own.display(), error = %e, "the plugin's known_hosts will not read");
                Err(keyward_core::fault!("err.sshKnownHostsUnreadable", "path" => self.own.display().to_string()))
            }
        }
    }

    /// Written whole under a temporary name, private from the first byte, and
    /// moved into place: no half-written file and no window of wider
    /// permissions.
    fn write_own(&self, text: &str) -> anyhow::Result<()> {
        let tmp = self.own.with_extension("tmp");
        let result = (|| -> std::io::Result<()> {
            let mut opts = std::fs::OpenOptions::new();
            opts.write(true).create(true).truncate(true);
            #[cfg(unix)]
            {
                use std::os::unix::fs::OpenOptionsExt as _;
                opts.mode(0o600);
            }
            let mut f = opts.open(&tmp)?;
            f.write_all(text.as_bytes())?;
            f.sync_all()?;
            std::fs::rename(&tmp, &self.own)
        })();
        result.map_err(|e| {
            tracing::error!(path = %self.own.display(), error = %e, "the plugin's known_hosts was not written");
            if let Err(e) = std::fs::remove_file(&tmp) {
                if e.kind() != std::io::ErrorKind::NotFound {
                    tracing::warn!(path = %tmp.display(), error = %e, "a temporary known_hosts was left behind");
                }
            }
            keyward_core::fault!("err.sshKnownHostsUnwritable", "path" => self.own.display().to_string())
        })
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    const ED_A: &str = "AAAAC3NzaC1lZDI1NTE5AAAAIJdD7y3aLq454yWBdwLWbieU1ebz9/cu7/QEXn9OIeZJ";
    const ED_B: &str = "AAAAC3NzaC1lZDI1NTE5AAAAIA6rWI3G2sz07DnfFlrouTcysQlj2P+jpNSOEWD9OJ3X";

    fn key(b: &str) -> PublicKey {
        russh::keys::parse_public_key_base64(b).unwrap()
    }

    fn dir(name: &str) -> PathBuf {
        let d = std::env::temp_dir().join(format!("kw-hostkeys-{name}-{}", std::process::id()));
        let _ = std::fs::remove_dir_all(&d);
        std::fs::create_dir_all(&d).unwrap();
        d
    }

    fn store(d: &Path, user: &str) -> Store {
        let user_path = d.join("user_known_hosts");
        std::fs::write(&user_path, user).unwrap();
        Store { user: Some(user_path), own: d.join("known_hosts"), item: None }
    }

    /// A vault with one key, bound to `host`, for a store that writes into it.
    fn vault(known: &str) -> Arc<keyward_plugin::testing::StrictHost> {
        let fields: Vec<(&str, &str, bool)> =
            if known.is_empty() { vec![("kw-host", "*.example.com", false)] } else { vec![("kw-host", "*.example.com", false), (KNOWN_HOSTS, known, false)] };
        Arc::new(keyward_plugin::testing::StrictHost::new().item("k1", "Deploy", &fields))
    }

    #[tokio::test]
    async fn a_confirmation_goes_into_the_item_and_not_into_a_file() {
        let d = dir("item");
        let core = vault("");
        let s = store(&d, "").for_item("k1", core.clone());
        assert_eq!(s.verify("db.example.com", 2222, &key(ED_A), None).await.unwrap(), Verdict::Unknown { others: false });
        s.learn("db.example.com", 2222, &key(ED_A)).await.unwrap();
        s.learn("db.example.com", 2222, &key(ED_A)).await.unwrap();
        let known = core.field("k1", KNOWN_HOSTS).unwrap();
        assert_eq!(known, format!("[db.example.com]:2222 ssh-ed25519 {ED_A}"), "one line, however often it is confirmed");
        assert!(!s.own.exists(), "the plugin's own file is not written for an item");
        assert_eq!(s.verify("db.example.com", 2222, &key(ED_A), None).await.unwrap(), Verdict::Known(Source::Item));
        assert_eq!(s.verify("db.example.com", 2222, &key(ED_B), None).await.unwrap(), Verdict::Changed(Source::Item));

        // Another plugin with the same item trusts it too: nothing but the
        // vault is shared between them.
        let other = store(&dir("item-other"), "").for_item("k1", core.clone());
        assert_eq!(other.verify("db.example.com", 2222, &key(ED_A), None).await.unwrap(), Verdict::Known(Source::Item));
        assert!(core.refused().is_empty());
    }

    #[tokio::test]
    async fn forgetting_a_host_clears_it_from_every_item() {
        let core = vault(&format!("git.example.com ssh-ed25519 {ED_A}\n[db.example.com]:2222 ssh-ed25519 {ED_B}"));
        assert_eq!(forget_in_items(core.as_ref(), "git.example.com", 22).await.unwrap(), 1);
        assert_eq!(core.field("k1", KNOWN_HOSTS).unwrap(), format!("[db.example.com]:2222 ssh-ed25519 {ED_B}"));
        assert_eq!(forget_in_items(core.as_ref(), "db.example.com", 2222).await.unwrap(), 1);
        assert_eq!(core.field("k1", KNOWN_HOSTS), None, "an empty field is removed");
    }

    #[tokio::test]
    async fn an_item_that_left_the_vault_is_an_error_not_an_unknown_host() {
        let s = store(&dir("gone"), "").for_item("nope", vault(""));
        assert!(s.verify("db.example.com", 22, &key(ED_A), None).await.is_err());
    }

    #[tokio::test]
    async fn a_learned_key_is_trusted_and_its_host_is_not_written_in_the_clear() {
        let d = dir("learn");
        let s = store(&d, "");
        assert_eq!(s.verify("db.example.com", 2222, &key(ED_A), None).await.unwrap(), Verdict::Unknown { others: false });
        s.learn("db.example.com", 2222, &key(ED_A)).await.unwrap();
        let text = std::fs::read_to_string(&s.own).unwrap();
        assert!(!text.contains("example"), "the host name must be hashed: {text}");
        assert_eq!(s.verify("db.example.com", 2222, &key(ED_A), None).await.unwrap(), Verdict::Known(Source::Keyward));
        // Another port is another host.
        assert_eq!(s.verify("db.example.com", 22, &key(ED_A), None).await.unwrap(), Verdict::Unknown { others: false });
        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt as _;
            assert_eq!(std::fs::metadata(&s.own).unwrap().permissions().mode() & 0o777, 0o600);
        }
    }

    #[tokio::test]
    async fn a_changed_key_is_refused_and_forgetting_clears_only_our_file() {
        let d = dir("changed");
        let s = store(&d, &format!("git.example.com ssh-ed25519 {ED_A}\n"));
        assert_eq!(s.verify("git.example.com", 22, &key(ED_A), None).await.unwrap(), Verdict::Known(Source::User));
        assert_eq!(s.verify("git.example.com", 22, &key(ED_B), None).await.unwrap(), Verdict::Changed(Source::User));

        s.learn("box.example.com", 22, &key(ED_A)).await.unwrap();
        assert_eq!(s.verify("box.example.com", 22, &key(ED_B), None).await.unwrap(), Verdict::Changed(Source::Keyward));
        assert_eq!(s.forget("box.example.com", 22).unwrap(), 1);
        assert_eq!(s.verify("box.example.com", 22, &key(ED_B), None).await.unwrap(), Verdict::Unknown { others: false });
        // The person's own file is theirs.
        assert!(std::fs::read_to_string(s.user.as_ref().unwrap()).unwrap().contains("git.example.com"));
    }

    #[tokio::test]
    async fn a_pin_is_the_last_word() {
        let d = dir("pin");
        let s = store(&d, &format!("pinned.example.com ssh-ed25519 {ED_B}\n"));
        let fp = fingerprint(&key(ED_A));
        assert_eq!(s.verify("pinned.example.com", 22, &key(ED_A), Some(&fp)).await.unwrap(), Verdict::Pinned);
        assert_eq!(s.verify("pinned.example.com", 22, &key(ED_B), Some(&fp)).await.unwrap(), Verdict::Changed(Source::Pin));
        let keyscan = format!("ssh-ed25519 {ED_A}");
        assert_eq!(s.verify("pinned.example.com", 22, &key(ED_A), Some(&keyscan)).await.unwrap(), Verdict::Pinned);
    }

    #[tokio::test]
    async fn globs_negations_revocations_and_junk_lines() {
        let d = dir("globs");
        let s = store(
            &d,
            &format!(
                "# a comment\n*.example.com,!bad.example.com ssh-ed25519 {ED_A}\ngarbage\nx.example.com ssh-ed25519 not-base64\n@revoked * ssh-ed25519 {ED_B}\n@cert-authority *.example.com ssh-ed25519 {ED_B}\n"
            ),
        );
        assert_eq!(s.verify("a.example.com", 22, &key(ED_A), None).await.unwrap(), Verdict::Known(Source::User));
        assert_eq!(s.verify("bad.example.com", 22, &key(ED_A), None).await.unwrap(), Verdict::Unknown { others: false });
        assert_eq!(s.verify("anything", 22, &key(ED_B), None).await.unwrap(), Verdict::Changed(Source::User));
    }

    #[tokio::test]
    async fn openssh_hashed_entries_are_read() {
        // The line from russh's own tests: a hashed entry OpenSSH wrote.
        let d = dir("hashed");
        let s = store(
            &d,
            "|1|O33ESRMWPVkMYIwJ1Uw+n877jTo=|nuuC5vEqXlEZ/8BXQR7m619W6Ak= ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAAILIG2T/B0l0gaqj3puu510tu9N1OkQ4znY3LYuEm5zCF\n",
        );
        let k = key("AAAAC3NzaC1lZDI1NTE5AAAAILIG2T/B0l0gaqj3puu510tu9N1OkQ4znY3LYuEm5zCF");
        assert_eq!(s.verify("example.com", 22, &k, None).await.unwrap(), Verdict::Known(Source::User));
    }
}
