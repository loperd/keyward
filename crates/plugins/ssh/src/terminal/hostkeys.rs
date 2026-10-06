//! Which host keys the terminal trusts.
//!
//! Three places, in this order:
//!
//! 1. The item's `kw-hostkey`: a pin is the last word. A key that does not match
//!    it is refused, whatever any file says.
//! 2. The person's `~/.ssh/known_hosts`, read and never written: an ssh
//!    configuration is too dear to be edited behind somebody's back, and the
//!    same host already trusted by `ssh` should not be asked about twice.
//! 3. The plugin's own `known_hosts` in its directory, where the terminal
//!    writes what a person confirmed. Host names in it are hashed the way
//!    OpenSSH's `HashKnownHosts` does, so the file does not list where a person
//!    goes; the keys themselves are public.
//!
//! A key of the same kind that differs from a recorded one is a changed key and
//! is refused outright — that is exactly what a man in the middle looks like.
//! A host with nothing recorded is unknown, and the terminal asks.

use std::io::Write as _;
use std::path::{Path, PathBuf};

use base64::Engine as _;
use hmac::{Hmac, Mac as _};
use russh::keys::{HashAlg, PublicKey};

/// Where a recorded key came from, for the words a person reads.
#[derive(Debug, Clone, Copy, PartialEq, Eq, serde::Serialize)]
#[serde(rename_all = "snake_case")]
pub enum Source {
    /// The item's `kw-hostkey`.
    Pin,
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
            tracing::warn!(path = %path.display(), line = n + 1, "a known_hosts line without a key was skipped");
            continue;
        };
        match russh::keys::parse_public_key_base64(blob) {
            Ok(key) => out.push(Recorded { key, revoked }),
            Err(e) => tracing::warn!(path = %path.display(), line = n + 1, error = %e, "a known_hosts key that does not parse was skipped"),
        }
    }
    Ok(out)
}

/// Does the item's `kw-hostkey` name this key? A person may write the
/// fingerprint, what `ssh-keyscan` prints or the bare base64 of the key.
pub fn pin_matches(pin: &str, key: &PublicKey) -> bool {
    if crate::agent::same_key(pin, &fingerprint(key)) {
        return true;
    }
    key.to_openssh().is_ok_and(|line| crate::agent::same_key(pin, &line))
}

/// The person's own known_hosts, where ssh keeps it.
pub fn user_file() -> Option<PathBuf> {
    std::env::home_dir().map(|h| h.join(".ssh").join("known_hosts"))
}

/// The trust store's files: the person's and the plugin's own.
#[derive(Debug, Clone)]
pub struct Store {
    pub user: Option<PathBuf>,
    pub own: PathBuf,
}

impl Store {
    pub fn new(plugin_dir: &Path) -> Self {
        Self { user: user_file(), own: plugin_dir.join("known_hosts") }
    }

    /// What to make of the key a server presented.
    pub fn verify(&self, host: &str, port: u16, key: &PublicKey, pin: Option<&str>) -> anyhow::Result<Verdict> {
        if let Some(pin) = pin.map(str::trim).filter(|p| !p.is_empty()) {
            return Ok(if pin_matches(pin, key) { Verdict::Pinned } else { Verdict::Changed(Source::Pin) });
        }
        let name = host_port(host, port);
        let mut sources = Vec::new();
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

    /// Records a key a person confirmed, under a hashed name.
    pub fn learn(&self, host: &str, port: u16, key: &PublicKey) -> anyhow::Result<()> {
        let name = host_port(host, port);
        let mut salt = [0u8; 20];
        rand_core::RngCore::fill_bytes(&mut rand_core::OsRng, &mut salt);
        let mut mac = Hmac::<sha1::Sha1>::new_from_slice(&salt).map_err(|e| anyhow::anyhow!("hmac: {e}"))?;
        mac.update(name.as_bytes());
        let hash = mac.finalize().into_bytes();
        let openssh = key.to_openssh().map_err(|e| anyhow::anyhow!("the host key will not encode: {e}"))?;
        let line = format!("|1|{}|{} {}\n", b64().encode(salt), b64().encode(hash), openssh.trim());

        let mut text = self.own_text()?;
        if !text.is_empty() && !text.ends_with('\n') {
            text.push('\n');
        }
        text.push_str(&line);
        self.write_own(&text)
    }

    /// Forgets what the plugin's own file records for a host: the way out of a
    /// changed key a person has checked. The person's `~/.ssh/known_hosts` is
    /// never touched — that one they edit themselves.
    pub fn forget(&self, host: &str, port: u16) -> anyhow::Result<usize> {
        let name = host_port(host, port);
        let text = self.own_text()?;
        let mut kept = String::with_capacity(text.len());
        let mut dropped = 0;
        for line in text.lines() {
            let first = line.split_whitespace().next().unwrap_or_default();
            if !line.trim_start().starts_with('#') && line_names(first, &name) {
                dropped += 1;
            } else {
                kept.push_str(line);
                kept.push('\n');
            }
        }
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
        Store { user: Some(user_path), own: d.join("known_hosts") }
    }

    #[test]
    fn a_learned_key_is_trusted_and_its_host_is_not_written_in_the_clear() {
        let d = dir("learn");
        let s = store(&d, "");
        assert_eq!(s.verify("db.example.com", 2222, &key(ED_A), None).unwrap(), Verdict::Unknown { others: false });
        s.learn("db.example.com", 2222, &key(ED_A)).unwrap();
        let text = std::fs::read_to_string(&s.own).unwrap();
        assert!(!text.contains("example"), "the host name must be hashed: {text}");
        assert_eq!(s.verify("db.example.com", 2222, &key(ED_A), None).unwrap(), Verdict::Known(Source::Keyward));
        // Another port is another host.
        assert_eq!(s.verify("db.example.com", 22, &key(ED_A), None).unwrap(), Verdict::Unknown { others: false });
        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt as _;
            assert_eq!(std::fs::metadata(&s.own).unwrap().permissions().mode() & 0o777, 0o600);
        }
    }

    #[test]
    fn a_changed_key_is_refused_and_forgetting_clears_only_our_file() {
        let d = dir("changed");
        let s = store(&d, &format!("git.example.com ssh-ed25519 {ED_A}\n"));
        assert_eq!(s.verify("git.example.com", 22, &key(ED_A), None).unwrap(), Verdict::Known(Source::User));
        assert_eq!(s.verify("git.example.com", 22, &key(ED_B), None).unwrap(), Verdict::Changed(Source::User));

        s.learn("box.example.com", 22, &key(ED_A)).unwrap();
        assert_eq!(s.verify("box.example.com", 22, &key(ED_B), None).unwrap(), Verdict::Changed(Source::Keyward));
        assert_eq!(s.forget("box.example.com", 22).unwrap(), 1);
        assert_eq!(s.verify("box.example.com", 22, &key(ED_B), None).unwrap(), Verdict::Unknown { others: false });
        // The person's own file is theirs.
        assert!(std::fs::read_to_string(s.user.as_ref().unwrap()).unwrap().contains("git.example.com"));
    }

    #[test]
    fn a_pin_is_the_last_word() {
        let d = dir("pin");
        let s = store(&d, &format!("pinned.example.com ssh-ed25519 {ED_B}\n"));
        let fp = fingerprint(&key(ED_A));
        assert_eq!(s.verify("pinned.example.com", 22, &key(ED_A), Some(&fp)).unwrap(), Verdict::Pinned);
        assert_eq!(s.verify("pinned.example.com", 22, &key(ED_B), Some(&fp)).unwrap(), Verdict::Changed(Source::Pin));
        let keyscan = format!("ssh-ed25519 {ED_A}");
        assert_eq!(s.verify("pinned.example.com", 22, &key(ED_A), Some(&keyscan)).unwrap(), Verdict::Pinned);
    }

    #[test]
    fn globs_negations_revocations_and_junk_lines() {
        let d = dir("globs");
        let s = store(
            &d,
            &format!(
                "# a comment\n*.example.com,!bad.example.com ssh-ed25519 {ED_A}\ngarbage\nx.example.com ssh-ed25519 not-base64\n@revoked * ssh-ed25519 {ED_B}\n@cert-authority *.example.com ssh-ed25519 {ED_B}\n"
            ),
        );
        assert_eq!(s.verify("a.example.com", 22, &key(ED_A), None).unwrap(), Verdict::Known(Source::User));
        assert_eq!(s.verify("bad.example.com", 22, &key(ED_A), None).unwrap(), Verdict::Unknown { others: false });
        assert_eq!(s.verify("anything", 22, &key(ED_B), None).unwrap(), Verdict::Changed(Source::User));
    }

    #[test]
    fn openssh_hashed_entries_are_read() {
        // The line from russh's own tests: a hashed entry OpenSSH wrote.
        let d = dir("hashed");
        let s = store(
            &d,
            "|1|O33ESRMWPVkMYIwJ1Uw+n877jTo=|nuuC5vEqXlEZ/8BXQR7m619W6Ak= ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAAILIG2T/B0l0gaqj3puu510tu9N1OkQ4znY3LYuEm5zCF\n",
        );
        let k = key("AAAAC3NzaC1lZDI1NTE5AAAAILIG2T/B0l0gaqj3puu510tu9N1OkQ4znY3LYuEm5zCF");
        assert_eq!(s.verify("example.com", 22, &k, None).unwrap(), Verdict::Known(Source::User));
    }
}
