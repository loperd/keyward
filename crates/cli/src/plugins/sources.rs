//! Where the daemon takes its showcase from.
//!
//! The list of addresses lies in `~/.keyward/plugins/sources.json`, an ordinary
//! array of strings. On the first call the default address is written there: a
//! person is not obliged to know where the project's bucket lives in order to
//! see a list of plugins.
//!
//! There are exactly two schemes. `https://` because a showcase arrives over
//! the network and nobody should be able to swap it on the way; `file://` for
//! development, so that a `--dry-run` of a release can be fed to the daemon
//! without leaving the house. Everything else (`http://`, `ftp://`, a bare
//! path) is a refusal at the door rather than a surprise at download time.

use std::path::{Path, PathBuf};

use anyhow::bail;

/// The project's showcase: a public R2 bucket. A constant rather than a
/// setting: a person who touched nothing still has to see what can be
/// installed. An address of one's own goes alongside — that is what a list of
/// sources is for.
pub const DEFAULT_SOURCE: &str = "https://pub-1033618a705b4df7873bf6ec267b5ad4.r2.dev/index.json";

/// The name of the file holding the list of addresses.
pub const SOURCES_FILE: &str = "sources.json";

/// The ceiling on the number of sources. Each one is a trip over the network
/// on every refresh of the showcase; a hundred addresses would turn opening a
/// tab into a minute's wait.
const MAX: usize = 32;

/// Checking an address. Returns it back with trailing spaces taken off: a
/// person writes the list by hand, and a space at the end is no reason to
/// silently not find the showcase.
pub fn validate(url: &str) -> anyhow::Result<String> {
    let url = url.trim();
    if url.is_empty() {
        bail!("an empty source address");
    }
    if url.len() > 2048 {
        bail!("a source address longer than 2048 characters");
    }
    if !(url.starts_with("https://") || url.starts_with("file://")) {
        bail!("the address \"{url}\" is neither https:// nor file://; a showcase has no other sources");
    }
    // Control characters in an address are either a typo or an attempt to
    // slip a line break into a request header.
    if url.chars().any(|c| c.is_control()) {
        bail!("the address \"{url}\" has control characters in it");
    }
    Ok(url.to_string())
}

fn file(dir: &Path) -> PathBuf {
    dir.join(SOURCES_FILE)
}

/// Read the list out of a directory. No file, or a damaged one, gives the
/// default list: a showcase is not a setting, and there is no reason to lose it
/// over one crooked bracket.
pub fn load_from(dir: &Path) -> Vec<String> {
    let path = file(dir);
    let raw = match std::fs::read_to_string(&path) {
        Ok(raw) => raw,
        Err(_) => {
            let list = vec![DEFAULT_SOURCE.to_string()];
            // Written at once: it is easier to edit a file that already
            // exists than to guess at its format.
            let _ = write(dir, &list);
            return list;
        }
    };
    let parsed: Vec<String> = match serde_json::from_str(&raw) {
        Ok(list) => list,
        Err(e) => {
            tracing::warn!(error = %e, path = %path.display(), "the list of sources did not parse");
            return vec![DEFAULT_SOURCE.to_string()];
        }
    };
    let mut out = Vec::new();
    for url in parsed {
        match validate(&url) {
            Ok(url) if !out.contains(&url) => out.push(url),
            Ok(_) => {}
            Err(e) => tracing::warn!(error = %e, "a source was skipped"),
        }
    }
    if out.is_empty() {
        // An empty list means "no showcase at all", and nobody asked for
        // that: they asked to erase their own addresses.
        out.push(DEFAULT_SOURCE.to_string());
    }
    out
}

fn write(dir: &Path, list: &[String]) -> anyhow::Result<()> {
    std::fs::create_dir_all(dir)?;
    let _ = crate::daemon::restrict(dir);
    let body = serde_json::to_string_pretty(list)?;
    std::fs::write(file(dir), body)?;
    Ok(())
}

/// Replace the list. One address that will not do refuses the lot: silently
/// dropping a line a person has just typed in is worse than saying why.
pub fn save_to(dir: &Path, list: &[String]) -> anyhow::Result<Vec<String>> {
    if list.len() > MAX {
        bail!("more than {MAX} sources; nobody walks that many showcases");
    }
    let mut out: Vec<String> = Vec::new();
    for url in list {
        let url = validate(url)?;
        if !out.contains(&url) {
            out.push(url);
        }
    }
    if out.is_empty() {
        out.push(DEFAULT_SOURCE.to_string());
    }
    write(dir, &out)?;
    Ok(out)
}

/// The current list.
pub fn list() -> Vec<String> {
    load_from(&super::package::root())
}

/// Replace the list and return what went to disk.
pub fn set(list: &[String]) -> anyhow::Result<Vec<String>> {
    save_to(&super::package::root(), list)
}

#[cfg(test)]
mod tests {
    use super::*;

    fn temp(name: &str) -> PathBuf {
        let dir = std::env::temp_dir().join(format!("kw-src-{}-{name}", std::process::id()));
        let _ = std::fs::remove_dir_all(&dir);
        std::fs::create_dir_all(&dir).unwrap();
        dir
    }

    #[test]
    fn only_https_and_file_are_addresses() {
        for good in ["https://example.net/index.json", "file:///tmp/registry/index.json"] {
            validate(good).unwrap_or_else(|e| panic!("{good}: {e}"));
        }
        for bad in [
            "",
            "   ",
            "http://example.net/index.json",
            "ftp://example.net/index.json",
            "/tmp/registry/index.json",
            "example.net/index.json",
            "https://example.net/index.json\nHost: evil",
        ] {
            assert!(validate(bad).is_err(), "an address that will not do got through: {bad:?}");
        }
        // Spaces at the edges do not spoil an address; they simply do not
        // reach the list.
        assert_eq!(validate("  https://example.net/i.json ").unwrap(), "https://example.net/i.json");
    }

    #[test]
    fn the_file_is_seeded_on_first_read() {
        let dir = temp("seed");
        let list = load_from(&dir);
        assert_eq!(list, vec![DEFAULT_SOURCE.to_string()]);
        assert!(dir.join(SOURCES_FILE).exists(), "the sources file was not created");
        let _ = std::fs::remove_dir_all(&dir);
    }

    #[test]
    fn a_list_survives_a_round_trip() {
        let dir = temp("round");
        let saved = save_to(
            &dir,
            &[
                "file:///tmp/registry/index.json".to_string(),
                "https://example.net/index.json".to_string(),
                // A duplicate goes unnoticed; an extra trip over the network
                // does not.
                "https://example.net/index.json".to_string(),
            ],
        )
        .unwrap();
        assert_eq!(saved.len(), 2, "the duplicate stayed: {saved:?}");
        assert_eq!(load_from(&dir), saved, "what was read is not what was written");
        let _ = std::fs::remove_dir_all(&dir);
    }

    #[test]
    fn one_bad_address_refuses_the_whole_list() {
        let dir = temp("bad");
        save_to(&dir, &["https://example.net/index.json".to_string()]).unwrap();
        let e = save_to(&dir, &["https://ok.net/i.json".into(), "http://evil.net/i.json".into()])
            .unwrap_err()
            .to_string();
        assert!(e.contains("neither https://"), "got: {e}");
        // The old list is in place: the refusal rewrote nothing.
        assert_eq!(load_from(&dir), vec!["https://example.net/index.json".to_string()]);
        let _ = std::fs::remove_dir_all(&dir);
    }

    #[test]
    fn an_empty_list_means_the_default_one() {
        let dir = temp("empty");
        assert_eq!(save_to(&dir, &[]).unwrap(), vec![DEFAULT_SOURCE.to_string()]);
        let _ = std::fs::remove_dir_all(&dir);
    }

    #[test]
    fn a_broken_file_does_not_lose_the_showcase() {
        let dir = temp("broken");
        std::fs::write(dir.join(SOURCES_FILE), "{ this is not an array").unwrap();
        assert_eq!(load_from(&dir), vec![DEFAULT_SOURCE.to_string()]);
        let _ = std::fs::remove_dir_all(&dir);
    }
}
