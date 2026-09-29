//! Who released a package.
//!
//! A `sha256` fingerprint answers the question "is this byte for byte the file
//! the showcase promised". It says nothing about who wrote that showcase:
//! swapping `index.json` swaps the fingerprint with it. So a package is signed
//! with a detached Ed25519 signature, and publishers' keys lie apart from the
//! showcase — in `~/.keyward/plugins/publishers.json` and in the code.
//!
//! A person adds a key deliberately and checks it by **five words**, the same
//! fingerprint Bitwarden shows for an account. Sixty-four hexadecimal
//! characters cannot be checked: a person looks at the first four and says
//! "looks right".

use std::path::{Path, PathBuf};

use anyhow::{bail, Context as _};
use base64::Engine as _;
use serde::{Deserialize, Serialize};

/// Publishers live in a file next to the packages, so the name is taken.
pub const PUBLISHERS_FILE: &str = "publishers.json";

/// The publisher built into the code: the project's key.
///
/// The private half lies only with the project's owner
/// (`~/.keyward/publisher.key`, mode 0600) and does not reach the repository —
/// otherwise the signature would mean nothing. This key's fingerprint in five
/// words:
/// «chimp agreeable mace definite amulet».
const BUILTIN: &[(&str, &str)] = &[("keyward", "iU6Fq/9Nlsnuvnkt8ErlMEW6g1tJ+/m6zzGvFD15v8g=")];

/// A trusted key.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Publisher {
    pub id: String,
    /// The Ed25519 public key, 32 bytes in base64.
    pub key: String,
    #[serde(default)]
    pub added: String,
    /// Built into the code: one like this cannot be removed or swapped by a
    /// file.
    #[serde(default)]
    pub builtin: bool,
}

impl Publisher {
    /// The key as bytes.
    pub fn bytes(&self) -> anyhow::Result<[u8; 32]> {
        let raw = base64::engine::general_purpose::STANDARD
            .decode(self.key.trim())
            .with_context(|| format!("the publisher key of \"{}\" is not base64", self.id))?;
        raw.try_into()
            .map_err(|_| anyhow::anyhow!("the publisher key of \"{}\" is not 32 bytes", self.id))
    }

    /// The five words a person checks the key by.
    pub fn words(&self) -> Vec<String> {
        match self.bytes() {
            Ok(key) => phrase(&self.id, &key),
            Err(_) => Vec::new(),
        }
    }
}

/// A publisher key's fingerprint: the same five words as an account's. The
/// publisher's identifier stands in for "whose it is": what is trusted is not
/// the key by itself but the pair of a name and a key.
pub fn phrase(id: &str, key: &[u8]) -> Vec<String> {
    keyward_vault::fingerprint::phrase(id, key).unwrap_or_default()
}

fn file(dir: &Path) -> PathBuf {
    dir.join(PUBLISHERS_FILE)
}

fn builtins() -> Vec<Publisher> {
    BUILTIN
        .iter()
        .map(|(id, key)| Publisher {
            id: (*id).to_string(),
            key: (*key).to_string(),
            added: String::new(),
            builtin: true,
        })
        .collect()
}

/// Every trusted key: the built-in ones first, then those a person added. A
/// file is not entitled to override a built-in key — otherwise "we trust our
/// own publisher" would stop meaning anything after one line of json.
pub fn load_from(dir: &Path) -> Vec<Publisher> {
    let mut out = builtins();
    let Ok(raw) = std::fs::read_to_string(file(dir)) else { return out };
    let parsed: Vec<Publisher> = match serde_json::from_str(&raw) {
        Ok(list) => list,
        Err(e) => {
            tracing::warn!(error = %e, "the list of publishers did not parse");
            return out;
        }
    };
    for mut p in parsed {
        if p.id.trim().is_empty() || out.iter().any(|k| k.id == p.id) {
            continue;
        }
        if p.bytes().is_err() {
            tracing::warn!(publisher = %p.id, "the publisher key will not do and was skipped");
            continue;
        }
        p.builtin = false;
        out.push(p);
    }
    out
}

/// Do we trust such a publisher?
pub fn trusted(dir: &Path, id: &str) -> Option<Publisher> {
    load_from(dir).into_iter().find(|p| p.id == id)
}

/// Add a publisher. The key is checked at once: a key that will not do, left
/// in the file, becomes a refusal to install a plugin a month later, when the
/// reason is no longer remembered.
pub fn add(dir: &Path, id: &str, key: &str) -> anyhow::Result<Publisher> {
    let id = id.trim();
    if id.is_empty() || id.len() > 64 || !id.chars().all(|c| c.is_ascii_alphanumeric() || matches!(c, '-' | '_' | '.')) {
        bail!("the publisher name \"{id}\" will not do: latin letters, digits, hyphen, underscore, dot");
    }
    let p = Publisher { id: id.to_string(), key: key.trim().to_string(), added: stamp(), builtin: false };
    p.bytes()?;
    let mut list: Vec<Publisher> = load_from(dir).into_iter().filter(|k| !k.builtin).collect();
    if let Some(have) = load_from(dir).into_iter().find(|k| k.id == id) {
        if have.key == p.key {
            return Ok(have);
        }
        // Swapping the key of a known name is exactly what all this is
        // written for. Rewriting it silently is not allowed.
        bail!(
            "the publisher \"{id}\" is already known with another key ({}). \
             If the key really has changed, remove it from {} by hand",
            have.words().join(" "),
            PUBLISHERS_FILE
        );
    }
    list.push(p.clone());
    std::fs::create_dir_all(dir)?;
    let _ = crate::daemon::restrict(dir);
    std::fs::write(file(dir), serde_json::to_string_pretty(&list)?)?;
    tracing::info!(publisher = id, "a publisher was added");
    Ok(p)
}

/// Strip a publisher of trust. A built-in one cannot be stripped: its trust is
/// part of the build, and rewriting it with a file would mean trust costs
/// nothing.
pub fn remove(dir: &Path, id: &str) -> anyhow::Result<()> {
    if BUILTIN.iter().any(|(k, _)| *k == id) {
        bail!("the publisher \"{id}\" is built into keyward; its trust comes off only with a rebuild");
    }
    let left: Vec<Publisher> =
        load_from(dir).into_iter().filter(|k| !k.builtin && k.id != id).collect();
    std::fs::create_dir_all(dir)?;
    let _ = crate::daemon::restrict(dir);
    std::fs::write(file(dir), serde_json::to_string_pretty(&left)?)?;
    tracing::info!(publisher = id, "a publisher was stripped of trust");
    Ok(())
}

fn stamp() -> String {
    let secs = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map(|d| d.as_secs())
        .unwrap_or_default();
    // No date crate: what is wanted is order and legibility, not a calendar.
    format!("{secs}")
}

/// Check a package's detached signature.
pub fn verify(key: &[u8; 32], bytes: &[u8], signature: &str) -> anyhow::Result<()> {
    use ed25519_dalek::{Signature, Verifier as _, VerifyingKey};

    let raw = base64::engine::general_purpose::STANDARD
        .decode(signature.trim())
        .context("the package signature is not base64")?;
    let raw: [u8; 64] = raw.try_into().map_err(|_| anyhow::anyhow!("the package signature is not 64 bytes"))?;
    let key = VerifyingKey::from_bytes(key).context("the publisher key will not do for a check")?;
    key.verify(bytes, &Signature::from_bytes(&raw))
        .map_err(|_| anyhow::anyhow!("the package signature does not check out against the publisher key"))
}

#[cfg(test)]
mod tests {
    use super::*;

    fn temp(name: &str) -> PathBuf {
        let dir = std::env::temp_dir().join(format!("kw-pub-{}-{name}", std::process::id()));
        let _ = std::fs::remove_dir_all(&dir);
        std::fs::create_dir_all(&dir).unwrap();
        dir
    }

    /// A key for the tests: our own, from a fixed seed. The project's key has
    /// nothing to do with it — its private half does not lie in the tree and
    /// must not.
    fn signer() -> ed25519_dalek::SigningKey {
        ed25519_dalek::SigningKey::from_bytes(&[42u8; 32])
    }

    #[test]
    fn a_signature_holds_only_for_its_own_bytes() {
        use ed25519_dalek::Signer as _;
        let key = signer().verifying_key();
        let sig = signer().sign(b"package bytes");
        let sig = base64::engine::general_purpose::STANDARD.encode(sig.to_bytes());
        verify(&key.to_bytes(), b"package bytes", &sig).unwrap();
        // One byte changed and the signature is gone.
        assert!(verify(&key.to_bytes(), b"package byteS", &sig).is_err());
        assert!(verify(&key.to_bytes(), b"package bytes", "not base64!!").is_err());
    }

    #[test]
    fn the_builtin_publisher_cannot_be_replaced_by_a_file() {
        let dir = temp("builtin");
        let evil = r#"[{"id":"keyward","key":"AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA="}]"#;
        std::fs::write(file(&dir), evil).unwrap();
        let known = trusted(&dir, "keyward").unwrap();
        assert_eq!(known.key, BUILTIN[0].1, "a file rewrote a built-in key");
        assert!(known.builtin);
        let _ = std::fs::remove_dir_all(&dir);
    }

    #[test]
    fn an_added_publisher_survives_and_shows_five_words() {
        let dir = temp("add");
        let key = base64::engine::general_purpose::STANDARD.encode([7u8; 32]);
        let p = add(&dir, "\u{441}\u{43e}\u{441}\u{435}\u{434}", &key).unwrap_err().to_string();
        assert!(p.contains("will not do"), "a name outside latin has to be a refusal: {p}");

        let p = add(&dir, "neighbour", &key).unwrap();
        assert_eq!(p.words().len(), 5, "five words are what a person checks a key by");
        assert!(trusted(&dir, "neighbour").is_some());
        // The same key a second time is not an error.
        add(&dir, "neighbour", &key).unwrap();
        // Another key under the same name is exactly what we are catching.
        let e = add(&dir, "neighbour", &base64::engine::general_purpose::STANDARD.encode([8u8; 32]))
            .unwrap_err()
            .to_string();
        assert!(e.contains("already known"), "got: {e}");
        assert!(add(&dir, "short", "AAAA").is_err(), "a key that is not 32 bytes has to be a refusal");
        let _ = std::fs::remove_dir_all(&dir);
    }

    #[test]
    fn a_publisher_can_be_dismissed_but_the_builtin_one_cannot() {
        let dir = temp("remove");
        let key = base64::engine::general_purpose::STANDARD.encode([9u8; 32]);
        add(&dir, "neighbour", &key).unwrap();
        remove(&dir, "neighbour").unwrap();
        assert!(trusted(&dir, "neighbour").is_none(), "one stripped of trust stayed trusted");
        let e = remove(&dir, BUILTIN[0].0).unwrap_err().to_string();
        assert!(e.contains("built into keyward"), "got: {e}");
        let _ = std::fs::remove_dir_all(&dir);
    }

    #[test]
    fn five_words_are_stable_and_bound_to_the_name() {
        let key = [1u8; 32];
        let a = phrase("keyward-dev", &key);
        assert_eq!(a.len(), 5);
        assert_eq!(a, phrase("keyward-dev", &key), "the fingerprint has to be the same");
        assert_ne!(a, phrase("someone-else", &key), "the fingerprint has to depend on the name");
    }
}
