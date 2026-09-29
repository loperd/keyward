//! Installing from an address: download, check, install.
//!
//! A package arrives over the network and is given the right to run as a
//! separate program with access to whatever a person agrees to. So there are
//! four lines here, all before anything at all reaches the disk:
//!
//! 1. **Revocation.** A version the showcase marks as revoked is not installed
//!    at all.
//! 2. **Signature.** A package from the showcase has to be signed with a
//!    trusted publisher's key. No signature, somebody else's key, an unknown
//!    publisher — a refusal that says what to do.
//! 3. **The publisher does not change.** An update is signed by whoever signed
//!    what is installed. Swapping the publisher of an installed plugin is no
//!    different from stealing a name.
//! 4. **Fingerprint.** The `sha256` from the showcase is required and is
//!    checked before unpacking.
//!
//! An address that is not in the showcase (typed in by hand) does install, but
//! its card travels with `unverified: true`: there was nothing to check
//! against, and the consent dialogue is obliged to say so plainly.

use std::path::{Path, PathBuf};
use std::time::Duration;

use anyhow::{bail, Context as _};
use sha2::{Digest, Sha256};

use super::catalog;
use super::net::Fetch;
use super::package::{self, Temp};
use super::publishers;
use super::registry::Record;

/// The ceiling on a package. A plugin is a script or a small binary; 64 MiB is
/// plenty, and without a ceiling the network could pour as much as it liked
/// into `~/.keyward`.
pub const CAP: usize = 64 * 1024 * 1024;

/// How long a whole package is waited for.
pub const TIMEOUT: Duration = Duration::from_secs(60);

/// An address rather than a path on disk.
pub fn is_url(path: &str) -> bool {
    path.starts_with("https://") || path.starts_with("file://")
}

/// A downloaded package: the file lives as long as `_tmp` does.
#[derive(Debug)]
pub struct Fetched {
    _tmp: Temp,
    pub file: PathBuf,
    /// The publisher's signature checked out.
    pub verified: bool,
    /// Who signed it. Empty means the package is not from the showcase.
    pub publisher: String,
    /// The fingerprint of what was downloaded.
    pub sha256: String,
    /// The version according to the showcase. Empty means the address is not
    /// from it.
    pub version: String,
    /// The permissions according to the showcase: the interface shows them
    /// before installing.
    pub permissions: Vec<String>,
}

/// The archive's name out of the address. The unpacking format is decided by
/// the extension, and we do not undertake to guess it from the contents: a
/// package has to be named the way it was built.
fn archive_name(url: &str) -> anyhow::Result<String> {
    let tail = url.split(['?', '#']).next().unwrap_or(url);
    let name = tail.rsplit('/').next().unwrap_or_default();
    let lower = name.to_ascii_lowercase();
    if !(lower.ends_with(".tar.gz") || lower.ends_with(".tgz") || lower.ends_with(".zip")) {
        return Err(keyward_core::fault!("err.notAPluginPackage", "url" => url));
    }
    // The name arrives from somebody else's file and becomes a file name on
    // our disk.
    let safe: String = name
        .chars()
        .map(|c| if c.is_ascii_alphanumeric() || matches!(c, '.' | '-' | '_') { c } else { '_' })
        .collect();
    Ok(safe)
}

pub fn digest(bytes: &[u8]) -> String {
    let mut h = Sha256::new();
    h.update(bytes);
    format!("{:x}", h.finalize())
}

/// Download a package into a temporary file and check everything that can be
/// checked before unpacking. `installed` says what is installed under this
/// identifier now: the record is what proves an update was signed by the same
/// publisher.
pub async fn fetch(
    dir: &Path,
    fetcher: &dyn Fetch,
    sources: &[String],
    url: &str,
    now: u64,
    installed: &(dyn Fn(&str) -> Option<Record> + Send + Sync),
) -> anyhow::Result<Fetched> {
    if !is_url(url) {
        return Err(keyward_core::fault!("err.sourceScheme", "url" => url));
    }
    let name = archive_name(url)?;
    let known = catalog::found_for_url(dir, fetcher, sources, url, now).await;

    // Revocation is the first line: there is no point downloading something
    // that was revoked.
    if let Some(found) = &known {
        if let Some(reason) = &found.revoked {
            return Err(keyward_core::fault!(
                "err.pluginVersionRevoked",
                "version" => &found.offer.version,
                "plugin" => &found.offer.id,
                "reason" => reason,
            ));
        }
    }

    // The signature and the publisher come before the download: with no key
    // there is nothing to download.
    let signer = match &known {
        Some(found) => Some(check_publisher(dir, &found.offer, installed)?),
        None => None,
    };

    let bytes = fetcher
        .get(url, CAP, TIMEOUT)
        .await
        .with_context(|| format!("the package {url} did not download"))?;
    if bytes.is_empty() {
        return Err(keyward_core::fault!("err.packageEmpty", "url" => url));
    }
    let sha256 = digest(&bytes);

    let (verified, publisher, version, permissions) = match (&known, signer) {
        (Some(found), Some(key)) => {
            let offer = &found.offer;
            if sha256 != offer.sha256 {
                // The fingerprint did not match: what lies at the address is
                // not what the showcase promised. There is nowhere to go on
                // from here.
                return Err(keyward_core::fault!(
                    "err.packageDigestMismatch",
                    "promised" => &offer.sha256,
                    "got" => sha256,
                ));
            }
            publishers::verify(&key, &bytes, &offer.signature).map_err(|_| {
                keyward_core::fault!(
                    "err.packageSignatureMismatch",
                    "plugin" => &offer.id,
                    "publisher" => &offer.publisher,
                )
            })?;
            (true, offer.publisher.clone(), offer.version.clone(), offer.permissions.clone())
        }
        _ => {
            tracing::warn!(url, "the address is not in the showcase; there is nothing to check against");
            (false, String::new(), String::new(), Vec::new())
        }
    };

    let tmp = package::scratch(dir, "dl")?;
    let file = tmp.path().join(name);
    std::fs::write(&file, &bytes).with_context(|| format!("cannot write {}", file.display()))?;
    Ok(Fetched { _tmp: tmp, file, verified, publisher, sha256, version, permissions })
}

/// The publisher of a showcase entry: whether they are trusted and whether
/// they are the one who signed what is installed. Returns their key.
fn check_publisher(
    dir: &Path,
    offer: &catalog::Offer,
    installed: &(dyn Fn(&str) -> Option<Record> + Send + Sync),
) -> anyhow::Result<[u8; 32]> {
    if offer.publisher.trim().is_empty() || offer.signature.trim().is_empty() {
        return Err(keyward_core::fault!("err.packageUnsigned", "plugin" => &offer.id));
    }
    // Swapping the publisher of an installed plugin is a theft of a name, and
    // the new key being trusted changes nothing about that.
    if let Some(rec) = installed(&offer.id) {
        if !rec.publisher.is_empty() && rec.publisher != offer.publisher {
            return Err(keyward_core::fault!(
                "err.publisherChanged",
                "installed" => &rec.publisher,
                "update" => &offer.publisher,
            ));
        }
    }
    let Some(known) = publishers::trusted(dir, &offer.publisher) else {
        // A refusal has to end in what a person should do: check five words
        // with the author and press "trust". That is a decision of its own, and
        // we are not entitled to make it for them.
        return Err(keyward_core::fault!(
            "err.publisherUnknown",
            "publisher" => &offer.publisher,
            "file" => publishers::PUBLISHERS_FILE,
        ));
    };
    known.bytes()
}

#[cfg(test)]
mod tests {
    use super::*;
    use base64::Engine as _;
    use std::collections::BTreeMap;
    use std::sync::Mutex;

    struct Canned {
        answers: BTreeMap<String, Vec<u8>>,
        calls: Mutex<Vec<String>>,
    }

    #[async_trait::async_trait]
    impl Fetch for Canned {
        async fn get(&self, url: &str, _cap: usize, _t: Duration) -> anyhow::Result<Vec<u8>> {
            self.calls.lock().unwrap().push(url.to_string());
            match self.answers.get(url) {
                Some(body) => Ok(body.clone()),
                None => anyhow::bail!("no answer for {url}"),
            }
        }
    }

    const SOURCE: &str = "https://pkg.example.net/index.json";
    const URL: &str = "https://pkg.example.net/hello/1.0.0/hello-1.0.0.tar.gz";
    /// A publisher key for the tests. The project's key has nothing to do with
    /// it: its private half does not lie in the tree, and no test can sign with
    /// it.
    const TEST_SEED: [u8; 32] = [42u8; 32];

    fn test_key() -> ed25519_dalek::SigningKey {
        ed25519_dalek::SigningKey::from_bytes(&TEST_SEED)
    }

    /// The tests' publisher, trusted inside this temporary directory.
    fn trust_test_publisher(dir: &std::path::Path) {
        let key = b64(&test_key().verifying_key().to_bytes());
        let _ = super::super::publishers::add(dir, "test-pub", &key);
    }

    fn b64(bytes: &[u8]) -> String {
        base64::engine::general_purpose::STANDARD.encode(bytes)
    }

    fn sign(body: &[u8]) -> String {
        use ed25519_dalek::Signer as _;
        b64(&test_key().sign(body).to_bytes())
    }

    /// A showcase with one version. Everything the tests vary is a
    /// parameter.
    struct Shelf {
        sha: String,
        signature: String,
        publisher: String,
        revoked: bool,
    }

    impl Shelf {
        fn of(body: &[u8]) -> Self {
            Self {
                sha: digest(body),
                signature: sign(body),
                publisher: "test-pub".to_string(),
                revoked: false,
            }
        }

        fn index(&self) -> String {
            let revoked = if self.revoked {
                r#""revoked":[{"id":"hello","version":"1.0.0","reason":"the publisher key leaked"}],"#
            } else {
                ""
            };
            format!(
                r#"{{"version":1,{revoked}"plugins":[{{"id":"hello","title":"Hello","versions":[
                   {{"version":"1.0.0","platform":"any","url":"{URL}","sha256":"{}",
                     "publisher":"{}","signature":"{}","permissions":["entries"],"size":7}}]}}]}}"#,
                self.sha, self.publisher, self.signature
            )
        }
    }

    fn temp(name: &str) -> PathBuf {
        let dir = std::env::temp_dir().join(format!("kw-rem-{}-{name}", std::process::id()));
        let _ = std::fs::remove_dir_all(&dir);
        std::fs::create_dir_all(&dir).unwrap();
        dir
    }

    fn canned(shelf: &Shelf, body: &[u8]) -> Canned {
        let mut answers = BTreeMap::new();
        answers.insert(SOURCE.to_string(), shelf.index().into_bytes());
        answers.insert(URL.to_string(), body.to_vec());
        Canned { answers, calls: Mutex::new(Vec::new()) }
    }

    async fn try_fetch(dir: &Path, net: &Canned, installed: Option<Record>) -> anyhow::Result<Fetched> {
        // Each case has a directory of its own: the showcase's cache lives in
        // it, and somebody else's cache would swap the entry under test.
        fetch(dir, net, &[SOURCE.to_string()], URL, 1, &|_| installed.clone()).await
    }

    #[test]
    fn only_archives_have_names() {
        assert_eq!(archive_name("https://a/b/hello-1.0.0.tar.gz").unwrap(), "hello-1.0.0.tar.gz");
        assert_eq!(archive_name("https://a/b/hello.zip?v=2").unwrap(), "hello.zip");
        // Neither `..` nor a slash from somebody else's name reaches the disk.
        assert_eq!(archive_name("https://a/b/..%2Fevil.tar.gz").unwrap(), ".._2Fevil.tar.gz");
        assert!(archive_name("https://a/b/hello").is_err());
        assert!(archive_name("https://a/b/hello.tar").is_err());
    }

    #[tokio::test]
    async fn a_signed_package_with_a_matching_fingerprint_goes_through() {
        let dir = temp("ok");
        trust_test_publisher(&dir);
        let body = "a package".as_bytes().to_vec();
        let net = canned(&Shelf::of(&body), &body);
        let got = try_fetch(&dir, &net, None).await.unwrap();
        assert!(got.verified, "a signed package from the showcase has to come back verified");
        assert_eq!(got.publisher, "test-pub");
        assert_eq!(got.version, "1.0.0");
        assert_eq!(got.permissions, vec!["entries"]);
        assert_eq!(std::fs::read(&got.file).unwrap(), body);
        let file = got.file.clone();
        drop(got);
        assert!(!file.exists(), "the temporary file stayed on disk");
        let _ = std::fs::remove_dir_all(&dir);
    }

    #[tokio::test]
    async fn a_wrong_fingerprint_is_a_refusal_and_nothing_else() {
        let dir = temp("mismatch");
        trust_test_publisher(&dir);
        let body = "a package".as_bytes().to_vec();
        // The showcase promises one thing and the address holds another: that
        // is a swap.
        let mut shelf = Shelf::of(&body);
        shelf.sha = "ab".repeat(32);
        let net = canned(&shelf, &body);
        let e = try_fetch(&dir, &net, None).await.unwrap_err().to_string();
        assert!(e.starts_with("err.packageDigestMismatch"), "got: {e}");
        assert!(e.contains("promised"), "got: {e}");
        let _ = std::fs::remove_dir_all(&dir);
    }

    #[tokio::test]
    async fn a_broken_signature_is_a_refusal() {
        let dir = temp("badsig");
        trust_test_publisher(&dir);
        let body = "a package".as_bytes().to_vec();
        // The fingerprint matches and the signature is of other bytes:
        // exactly what catches a swap that took the showcase with it.
        let mut shelf = Shelf::of(&body);
        shelf.signature = sign(b"other bytes");
        let net = canned(&shelf, &body);
        let e = try_fetch(&dir, &net, None).await.unwrap_err().to_string();
        assert!(e.starts_with("err.packageSignatureMismatch"), "got: {e}");
        let _ = std::fs::remove_dir_all(&dir);
    }

    #[tokio::test]
    async fn an_unsigned_or_unknown_publisher_is_a_refusal_with_advice() {
        let body = "a package".as_bytes().to_vec();

        let dir = temp("unknown");
        let mut shelf = Shelf::of(&body);
        shelf.publisher = "somebody-else".to_string();
        let e = try_fetch(&dir, &canned(&shelf, &body), None).await.unwrap_err().to_string();
        assert!(e.starts_with("err.publisherUnknown"), "got: {e}");
        assert!(e.contains("publisher"), "the refusal has to say what to do: {e}");
        let _ = std::fs::remove_dir_all(&dir);

        let dir = temp("unsigned");
        let mut shelf = Shelf::of(&body);
        shelf.signature = String::new();
        let e = try_fetch(&dir, &canned(&shelf, &body), None).await.unwrap_err().to_string();
        assert!(e.starts_with("err.packageUnsigned"), "got: {e}");
        let _ = std::fs::remove_dir_all(&dir);
    }

    #[tokio::test]
    async fn an_update_signed_by_someone_else_is_a_refusal() {
        let dir = temp("swap");
        let body = "a package".as_bytes().to_vec();
        let net = canned(&Shelf::of(&body), &body);
        // A version of the same plugin is installed, signed by another
        // publisher.
        let installed = Record { publisher: "neighbour".to_string(), ..Record::default() };
        let e = try_fetch(&dir, &net, Some(installed)).await.unwrap_err().to_string();
        assert!(e.starts_with("err.publisherChanged"), "got: {e}");
        let _ = std::fs::remove_dir_all(&dir);
    }

    #[tokio::test]
    async fn a_revoked_version_is_never_downloaded() {
        let dir = temp("revoked");
        trust_test_publisher(&dir);
        let body = "a package".as_bytes().to_vec();
        let mut shelf = Shelf::of(&body);
        shelf.revoked = true;
        let net = canned(&shelf, &body);
        let e = try_fetch(&dir, &net, None).await.unwrap_err().to_string();
        assert!(e.starts_with("err.pluginVersionRevoked"), "got: {e}");
        assert!(e.contains("the publisher key leaked"), "the reason has to arrive: {e}");
        // Nobody even went for the package.
        assert!(!net.calls.lock().unwrap().contains(&URL.to_string()), "there is no point downloading what was revoked");
        let _ = std::fs::remove_dir_all(&dir);
    }

    #[tokio::test]
    async fn an_address_outside_the_showcase_installs_unverified() {
        let dir = temp("hand");
        let mut answers = BTreeMap::new();
        let body = "a package".as_bytes().to_vec();
        let hand = "https://somebody.example.net/plugin.tar.gz";
        answers.insert(hand.to_string(), body.clone());
        let net = Canned { answers, calls: Mutex::new(Vec::new()) };
        let got = fetch(&dir, &net, &[SOURCE.to_string()], hand, 1, &|_| None).await.unwrap();
        assert!(!got.verified, "there was nothing to check against, and the card has to say so");
        assert!(got.publisher.is_empty());
        let _ = std::fs::remove_dir_all(&dir);
    }
}
