//! What `~/.ssh/config` says about a host, read the way ssh reads it.
//!
//! A person's ssh configuration often knows more than the vault does: the real
//! address behind an alias, the login, the port. The terminal and the health
//! checks read it — never write it: an ssh configuration is too dear to be
//! edited behind somebody's back.
//!
//! What is read: `Host` blocks with their patterns and negations, `Include`,
//! and in them `HostName`, `User`, `Port`, `ProxyJump`. The first value
//! obtained wins, as in ssh. `Match` blocks are skipped whole — keyward's own
//! `Match exec` is one of them, and the rest need a running ssh to decide.

use std::path::{Path, PathBuf};

use serde::Serialize;

/// How deep `Include` may nest before it is a loop.
const MAX_DEPTH: usize = 8;

/// One `Host` block: its patterns and its options, in order.
#[derive(Debug, Clone, PartialEq, Eq)]
struct Block {
    /// `None` is the top of the file, before any `Host`: it applies to every
    /// host. A `Match` block is not kept at all.
    patterns: Option<Vec<String>>,
    options: Vec<(String, String)>,
}

/// What the configuration gives one host.
#[derive(Debug, Clone, Default, PartialEq, Eq, Serialize)]
pub struct Resolved {
    /// The real address, when the name is an alias.
    pub hostname: Option<String>,
    pub user: Option<String>,
    pub port: Option<u16>,
    /// The terminal does not go through jump hosts: when a host needs one, it
    /// says so rather than failing at the network.
    pub proxy_jump: Option<String>,
}

impl Resolved {
    pub fn is_empty(&self) -> bool {
        self.hostname.is_none() && self.user.is_none() && self.port.is_none() && self.proxy_jump.is_none()
    }
}

/// A host the configuration names outright — a pattern with no wildcard.
#[derive(Debug, Clone, Serialize)]
pub struct Named {
    pub alias: String,
    #[serde(flatten)]
    pub resolved: Resolved,
}

/// The whole configuration, read once.
#[derive(Debug, Clone, Default)]
pub struct Config {
    blocks: Vec<Block>,
}

/// `~/.ssh`.
fn ssh_dir() -> Option<PathBuf> {
    std::env::home_dir().map(|h| h.join(".ssh"))
}

/// A line's keyword and value: `Key value`, `Key=value`, `Key = "value"`.
fn split_line(line: &str) -> Option<(String, String)> {
    let line = line.trim();
    if line.is_empty() || line.starts_with('#') {
        return None;
    }
    let cut = line.find(|c: char| c.is_whitespace() || c == '=')?;
    let key = line[..cut].to_ascii_lowercase();
    let value = line[cut..].trim_start_matches(|c: char| c.is_whitespace() || c == '=').trim();
    Some((key, value.to_string()))
}

/// A value's words, quotes respected.
fn words(value: &str) -> Vec<String> {
    let mut out = Vec::new();
    let mut cur = String::new();
    let mut quoted = false;
    for c in value.chars() {
        match c {
            '"' => quoted = !quoted,
            c if c.is_whitespace() && !quoted => {
                if !cur.is_empty() {
                    out.push(std::mem::take(&mut cur));
                }
            }
            c => cur.push(c),
        }
    }
    if !cur.is_empty() {
        out.push(cur);
    }
    out
}

fn expand_home(path: &str) -> PathBuf {
    match (path.strip_prefix("~/"), std::env::home_dir()) {
        (Some(rest), Some(home)) => home.join(rest),
        _ => PathBuf::from(path),
    }
}

/// The files an `Include` names: globs relative to `~/.ssh`, in sorted order
/// as ssh takes them.
fn include_paths(pattern: &str, base: &Path) -> Vec<PathBuf> {
    let full = {
        let p = expand_home(pattern);
        if p.is_absolute() { p } else { base.join(p) }
    };
    let Some(name) = full.file_name().map(|n| n.to_string_lossy().into_owned()) else { return Vec::new() };
    if !name.contains(['*', '?']) {
        return vec![full];
    }
    let Some(dir) = full.parent() else { return Vec::new() };
    let Ok(read) = std::fs::read_dir(dir) else { return Vec::new() };
    let mut out: Vec<PathBuf> = read
        .flatten()
        .map(|e| e.path())
        .filter(|p| p.file_name().is_some_and(|n| crate::glob::matches(&name, &n.to_string_lossy())))
        .collect();
    out.sort();
    out
}

impl Config {
    /// The person's `~/.ssh/config`. No file is an empty configuration; a
    /// file that is there and cannot be read is an error — its values may be
    /// written into the vault, and "nothing" is not the same as "unknown".
    pub fn load() -> anyhow::Result<Self> {
        let Some(dir) = ssh_dir() else { return Ok(Self::default()) };
        let path = dir.join("config");
        let mut cfg = Self::default();
        cfg.read_file(&path, &dir, 0, true)?;
        Ok(cfg)
    }

    /// A configuration out of text, for the tests.
    pub fn parse(text: &str) -> Self {
        let mut cfg = Self::default();
        cfg.read_text(text, Path::new("/nonexistent"), 0);
        cfg
    }

    fn read_file(&mut self, path: &Path, base: &Path, depth: usize, top: bool) -> anyhow::Result<()> {
        match std::fs::read_to_string(path) {
            Ok(text) => {
                self.read_text(&text, base, depth);
                Ok(())
            }
            Err(e) if e.kind() == std::io::ErrorKind::NotFound => Ok(()),
            Err(e) if top => {
                tracing::error!(path = %path.display(), error = %e, "~/.ssh/config will not read");
                Err(keyward_core::fault!("err.sshConfigUnreadable", "path" => path.display().to_string()))
            }
            // An included file that will not read is skipped, as ssh does,
            // but not quietly.
            Err(e) => {
                tracing::warn!(path = %path.display(), error = %e, "a file ~/.ssh/config includes will not read; skipped");
                Ok(())
            }
        }
    }

    fn read_text(&mut self, text: &str, base: &Path, depth: usize) {
        // Options before the first Host apply to every host.
        let mut current = Block { patterns: None, options: Vec::new() };
        let mut skipping = false;
        for line in text.lines() {
            let Some((key, value)) = split_line(line) else { continue };
            match key.as_str() {
                "host" => {
                    self.blocks.push(std::mem::replace(&mut current, Block { patterns: Some(words(&value)), options: Vec::new() }));
                    skipping = false;
                }
                "match" => {
                    self.blocks.push(std::mem::replace(&mut current, Block { patterns: None, options: Vec::new() }));
                    skipping = true;
                }
                "include" if !skipping => {
                    if depth >= MAX_DEPTH {
                        tracing::warn!("~/.ssh/config includes too deep; the rest is skipped");
                        continue;
                    }
                    // What the included file says lands where the Include
                    // stands: the block so far is closed first.
                    let resume = current.patterns.clone();
                    self.blocks.push(std::mem::replace(&mut current, Block { patterns: resume.clone(), options: Vec::new() }));
                    for w in words(&value) {
                        for path in include_paths(&w, base) {
                            let mut inner = Config::default();
                            if inner.read_file(&path, base, depth + 1, false).is_ok() {
                                for mut b in inner.blocks {
                                    // Inside a Host block, an included file's
                                    // top-level options belong to that block.
                                    if b.patterns.is_none() {
                                        b.patterns = resume.clone();
                                    }
                                    self.blocks.push(b);
                                }
                            }
                        }
                    }
                }
                _ if skipping => {}
                _ => current.options.push((key, value)),
            }
        }
        self.blocks.push(current);
    }

    /// Does a block's pattern list name this host? A matching negation takes
    /// the block out whatever else matches.
    fn names(patterns: &[String], host: &str) -> bool {
        let mut hit = false;
        for p in patterns {
            if let Some(neg) = p.strip_prefix('!') {
                if crate::glob::matches(neg, host) {
                    return false;
                }
            } else if crate::glob::matches(p, host) {
                hit = true;
            }
        }
        hit
    }

    /// What the configuration gives a host: the first value of each option,
    /// in the order the blocks come.
    pub fn resolve(&self, host: &str) -> Resolved {
        let mut out = Resolved::default();
        for b in &self.blocks {
            if let Some(p) = &b.patterns {
                if !Self::names(p, host) {
                    continue;
                }
            }
            for (k, v) in &b.options {
                let v = v.trim_matches('"');
                match k.as_str() {
                    "hostname" if out.hostname.is_none() => out.hostname = Some(v.replace("%h", host)),
                    "user" if out.user.is_none() => out.user = Some(v.to_string()),
                    "port" if out.port.is_none() => match v.parse::<u16>() {
                        Ok(p) if p > 0 => out.port = Some(p),
                        _ => tracing::warn!(host, port = v, "~/.ssh/config gives a port that is not a number; ignored"),
                    },
                    "proxyjump" if out.proxy_jump.is_none() && !v.eq_ignore_ascii_case("none") => out.proxy_jump = Some(v.to_string()),
                    _ => {}
                }
            }
        }
        if out.hostname.as_deref() == Some(host) {
            out.hostname = None;
        }
        out
    }

    /// Every host the configuration names outright, with what it gives each.
    pub fn named(&self) -> Vec<Named> {
        let mut seen = std::collections::BTreeSet::new();
        for b in &self.blocks {
            for p in b.patterns.iter().flatten() {
                if !p.starts_with('!') && !crate::glob::has_wildcard(p) {
                    seen.insert(p.clone());
                }
            }
        }
        seen.into_iter().map(|alias| Named { resolved: self.resolve(&alias), alias }).collect()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    const CONFIG: &str = r#"
# a comment
Match exec "/Users/x/.local/bin/keyward resolve %h %r %p"
    IdentityAgent /Users/x/.keyward/s/%h.sock
    User nobody-from-match

Host prod
    HostName 203.0.113.10
    User ubuntu
    Port 2222

Host *.lab.example !bad.lab.example
    User=admin

Host bastion
    HostName=%h.example.net
    ProxyJump none

Host behind
    ProxyJump bastion

Host *
    User root
    Port 22
"#;

    #[test]
    fn a_host_gets_the_first_value_of_each_option() {
        let c = Config::parse(CONFIG);
        let prod = c.resolve("prod");
        assert_eq!(prod.hostname.as_deref(), Some("203.0.113.10"));
        assert_eq!(prod.user.as_deref(), Some("ubuntu"), "the Match block must not give the login");
        assert_eq!(prod.port, Some(2222));

        let lab = c.resolve("db.lab.example");
        assert_eq!((lab.user.as_deref(), lab.port, lab.hostname), (Some("admin"), Some(22), None));

        // A negation takes the block out; the catch-all still applies.
        assert_eq!(c.resolve("bad.lab.example").user.as_deref(), Some("root"));

        let bastion = c.resolve("bastion");
        assert_eq!(bastion.hostname.as_deref(), Some("bastion.example.net"));
        assert_eq!(bastion.proxy_jump, None);
        assert_eq!(c.resolve("behind").proxy_jump.as_deref(), Some("bastion"));
    }

    #[test]
    fn named_hosts_are_the_ones_without_wildcards() {
        let c = Config::parse(CONFIG);
        let names: Vec<String> = c.named().into_iter().map(|n| n.alias).collect();
        assert_eq!(names, vec!["bastion", "behind", "prod"]);
    }

    #[test]
    fn includes_land_where_they_stand() {
        let dir = std::env::temp_dir().join(format!("kw-sshconfig-{}", std::process::id()));
        std::fs::create_dir_all(dir.join("conf.d")).unwrap();
        std::fs::write(dir.join("conf.d/10-work"), "Host work\n  HostName 198.51.100.7\n  User deploy\n").unwrap();
        let mut c = Config::default();
        c.read_text("Include conf.d/*\nHost *\n  User root\n", &dir, 0);
        let work = c.resolve("work");
        assert_eq!(work.hostname.as_deref(), Some("198.51.100.7"));
        assert_eq!(work.user.as_deref(), Some("deploy"));
        let _ = std::fs::remove_dir_all(&dir);
    }

    #[test]
    fn keys_and_values_come_in_every_spelling() {
        assert_eq!(split_line("  User = \"alex\"  "), Some(("user".into(), "\"alex\"".into())));
        assert_eq!(split_line("Port=2200"), Some(("port".into(), "2200".into())));
        assert_eq!(split_line("# no"), None);
        assert_eq!(Config::parse("Host a\n User \"al ex\"\n").resolve("a").user.as_deref(), Some("al ex"));
    }
}
