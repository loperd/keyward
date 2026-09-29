//! Fetching a file from a showcase address.
//!
//! The trait exists for the tests: a showcase and installing from an address
//! are the parsing of somebody else's json and a check of a fingerprint, and
//! there is no reason to bring a network up to test them. The live [`Net`]
//! knows two schemes — `https://` and `file://`, exactly those the list of
//! sources allows.

use std::path::PathBuf;
use std::time::Duration;

use anyhow::{bail, Context as _};

/// A marker in the error text: there is no showcase at the address. There is
/// no reason to sort out status codes higher up the stack; one thing matters —
/// this source's cache is due to be thrown away.
pub const GONE: &str = "no showcase there";

/// Whoever can fetch the contents at an address.
#[async_trait::async_trait]
pub trait Fetch: Send + Sync {
    /// Fetch a whole file. `cap` is the ceiling in bytes: more than that is
    /// not read at all, rather than read and thrown away.
    async fn get(&self, url: &str, cap: usize, timeout: Duration) -> anyhow::Result<Vec<u8>>;
}

/// A real network and a real disk.
pub struct Net;

#[async_trait::async_trait]
impl Fetch for Net {
    async fn get(&self, url: &str, cap: usize, timeout: Duration) -> anyhow::Result<Vec<u8>> {
        if let Some(path) = local_path(url) {
            return read_file(&path, cap);
        }
        if !url.starts_with("https://") {
            bail!("the address \"{url}\" is neither https:// nor file://");
        }
        // An outer timeout over the client's: the client's counts the
        // request, this one counts the lot, a byte-a-second trickle
        // included.
        tokio::time::timeout(timeout + Duration::from_secs(5), http(url, cap, timeout))
            .await
            .map_err(|_| anyhow::anyhow!("{url} did not answer within {}s", timeout.as_secs()))?
    }
}

async fn http(url: &str, cap: usize, timeout: Duration) -> anyhow::Result<Vec<u8>> {
    let client = reqwest::Client::builder()
        .timeout(timeout)
        .user_agent(concat!("keyward/", env!("CARGO_PKG_VERSION")))
        .build()
        .context("the http client would not build")?;
    let res = client.get(url).send().await.with_context(|| format!("cannot reach {url}"))?;
    if !res.status().is_success() {
        // "No such file" is not a broken connection but an answer: there is
        // no showcase at this address any more. The cache must not outlive it,
        // or a plugin taken off the shelf will be offered for ever.
        if matches!(res.status().as_u16(), 404 | 410) {
            bail!("{GONE}: {url} answered {}", res.status());
        }
        bail!("{url} answered {}", res.status());
    }
    // The promised size is checked before reading: if the server is honest,
    // there is no need to spend network and disk on a file known to be too
    // big.
    if let Some(len) = res.content_length() {
        if len > cap as u64 {
            bail!("{url} promises {len} bytes, over the ceiling of {cap}");
        }
    }
    let mut res = res;
    let mut body = Vec::new();
    // Chunk by chunk rather than whole: a server is free to lie in
    // Content-Length, and the only real limit is the one we count ourselves.
    while let Some(chunk) = res.chunk().await.with_context(|| format!("the connection to {url} broke"))? {
        if body.len() + chunk.len() > cap {
            bail!("{url} is over the ceiling of {cap} bytes");
        }
        body.extend_from_slice(&chunk);
    }
    Ok(body)
}

fn read_file(path: &std::path::Path, cap: usize) -> anyhow::Result<Vec<u8>> {
    let meta = std::fs::metadata(path)
        .with_context(|| format!("cannot find {}", path.display()))?;
    if meta.len() > cap as u64 {
        bail!("{} is over the ceiling of {cap} bytes", path.display());
    }
    std::fs::read(path).with_context(|| format!("cannot read {}", path.display()))
}

/// The path out of a `file://` address, or `None` if it is not one.
pub fn local_path(url: &str) -> Option<PathBuf> {
    let rest = url.strip_prefix("file://")?;
    // `file://localhost/path` is the same machine as `file:///path`.
    let rest = rest.strip_prefix("localhost").unwrap_or(rest);
    if !rest.starts_with('/') {
        return None;
    }
    Some(PathBuf::from(unescape(rest)))
}

/// Decoding `%20` and other percents. A person puts a showcase on disk
/// wherever they like, including a directory with a space in its name.
fn unescape(s: &str) -> String {
    let bytes = s.as_bytes();
    let mut out: Vec<u8> = Vec::with_capacity(bytes.len());
    let mut i = 0;
    while i < bytes.len() {
        if bytes[i] == b'%' && i + 2 < bytes.len() {
            let hex = std::str::from_utf8(&bytes[i + 1..i + 3]).ok();
            if let Some(b) = hex.and_then(|h| u8::from_str_radix(h, 16).ok()) {
                out.push(b);
                i += 3;
                continue;
            }
        }
        out.push(bytes[i]);
        i += 1;
    }
    String::from_utf8_lossy(&out).into_owned()
}

/// A package's address relative to the showcase's. `index.json` allows both a
/// full address and a relative one: a showcase laid out by `--dry-run` into
/// `dist/registry` has to travel with its directory rather than remember where
/// it was built.
pub fn resolve(source: &str, url: &str) -> anyhow::Result<String> {
    if url.starts_with("https://") || url.starts_with("file://") {
        return Ok(url.to_string());
    }
    if url.is_empty() {
        bail!("the version has no package address");
    }
    if url.contains("://") {
        bail!("the address \"{url}\" is neither https:// nor file://");
    }
    // A `..` in a relative address would take the download out of the showcase
    // somewhere else; a showcase is entitled to serve only what lies beside
    // it.
    if url.split('/').any(|p| p == "..") {
        bail!("the address \"{url}\" leads above the showcase");
    }
    let base = source.rsplit_once('/').map(|(b, _)| b).unwrap_or(source);
    Ok(format!("{base}/{}", url.trim_start_matches('/')))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn file_urls_become_paths() {
        assert_eq!(local_path("file:///tmp/registry/index.json"), Some(PathBuf::from("/tmp/registry/index.json")));
        assert_eq!(local_path("file://localhost/tmp/i.json"), Some(PathBuf::from("/tmp/i.json")));
        assert_eq!(local_path("file:///tmp/my%20showcase/i.json"), Some(PathBuf::from("/tmp/my showcase/i.json")));
        assert_eq!(local_path("https://example.net/i.json"), None);
    }

    #[test]
    fn relative_package_urls_hang_off_the_index() {
        let src = "file:///tmp/registry/index.json";
        assert_eq!(resolve(src, "hello/1.0.0/hello-1.0.0.tar.gz").unwrap(), "file:///tmp/registry/hello/1.0.0/hello-1.0.0.tar.gz");
        assert_eq!(resolve(src, "https://cdn.example.net/p.tar.gz").unwrap(), "https://cdn.example.net/p.tar.gz");
        assert!(resolve(src, "../../etc/passwd").is_err());
        assert!(resolve(src, "http://evil.net/p.tar.gz").is_err());
        assert!(resolve(src, "").is_err());
    }
}
