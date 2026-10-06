//! What `~/.ssh/config` says about a host, read the way ssh reads it.
//!
//! A person's ssh configuration often knows more than the vault does: the real
//! address behind an alias, the login, the port. The terminal and the health
//! checks read it — never write it: an ssh configuration is too dear to be
//! edited behind somebody's back.
//!
//! What is read: `Host` blocks with their patterns and negations, `Include`,
//! and in them `HostName`, `User`, `Port`, `ProxyJump`, `ProxyCommand`. The
//! first value obtained wins, as in ssh. `Match` blocks are skipped whole —
//! keyward's own `Match exec` is one of them, and the rest need a running ssh
//! to decide.
//!
//! The vault often names a host by its address while the configuration names
//! it by an alias: `51.83.4.43` in an item, `Host ds` with a `HostName` that
//! resolves there in the file. ssh itself would not connect the two, but a
//! person means the same machine; so a host no block names outright is
//! looked up by the address a block's `HostName` gives, as written or as DNS
//! resolves it.

use std::collections::HashMap;
use std::net::IpAddr;
use std::path::{Path, PathBuf};
use std::sync::Arc;
use std::time::{Duration, Instant, SystemTime};

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
    /// The terminal does not go through jump hosts or proxy commands: when a
    /// host needs one, it says so rather than failing at the network.
    pub proxy_jump: Option<String>,
    pub proxy_command: Option<String>,
    /// The block's alias, when the host was found by its address rather than
    /// by name.
    pub alias: Option<String>,
}

impl Resolved {
    pub fn is_empty(&self) -> bool {
        self.hostname.is_none() && self.user.is_none() && self.port.is_none() && self.proxy_jump.is_none() && self.proxy_command.is_none()
    }

    /// What the host needs that the terminal cannot do, for the words a
    /// person reads.
    pub fn proxy(&self) -> Option<&str> {
        self.proxy_jump.as_deref().or(self.proxy_command.as_deref())
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
    /// The addresses the named hosts' `HostName`s resolve to: address → alias.
    addresses: HashMap<IpAddr, String>,
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
                    "proxycommand" if out.proxy_command.is_none() && !v.eq_ignore_ascii_case("none") => out.proxy_command = Some(v.to_string()),
                    _ => {}
                }
            }
        }
        if out.hostname.as_deref() == Some(host) {
            out.hostname = None;
        }
        out
    }

    /// Is the host named outright by some block — not only by a wildcard?
    fn names_outright(&self, host: &str) -> bool {
        self.blocks
            .iter()
            .flat_map(|b| b.patterns.iter().flatten())
            .any(|p| !p.starts_with('!') && !crate::glob::has_wildcard(p) && p.eq_ignore_ascii_case(host))
    }

    /// What the configuration gives a host, the way a person means it: by
    /// name as ssh reads it, or — for a host no block names — by the block
    /// whose `HostName` is that host or resolves to its address.
    pub fn lookup(&self, host: &str) -> Resolved {
        if self.names_outright(host) {
            return self.resolve(host);
        }
        let by_name = self
            .named()
            .into_iter()
            .find(|n| n.resolved.hostname.as_deref().is_some_and(|h| h.eq_ignore_ascii_case(host)))
            .map(|n| n.alias);
        let by_address = || host.parse::<IpAddr>().ok().and_then(|ip| self.addresses.get(&ip).cloned());
        match by_name.or_else(by_address) {
            Some(alias) => {
                let mut r = self.resolve(&alias);
                // The host is already the address.
                r.hostname = None;
                r.alias = Some(alias);
                r
            }
            None => self.resolve(host),
        }
    }

    /// Resolves every named host's `HostName` once, so a host the vault names
    /// by its address can be found. A name that does not resolve in time is
    /// left out; the rest still work.
    pub async fn index(&mut self) {
        let mut tasks = tokio::task::JoinSet::new();
        for n in self.named() {
            let Some(name) = n.resolved.hostname.clone().or_else(|| Some(n.alias.clone())) else { continue };
            if n.resolved.proxy().is_some() {
                continue;
            }
            tasks.spawn(async move {
                let found = tokio::time::timeout(Duration::from_secs(2), tokio::net::lookup_host((name.as_str(), 22))).await;
                (n.alias, found.ok().and_then(Result::ok).map(|a| a.map(|s| s.ip()).collect::<Vec<_>>()).unwrap_or_default())
            });
        }
        while let Some(done) = tasks.join_next().await {
            if let Ok((alias, ips)) = done {
                for ip in ips {
                    self.addresses.entry(ip).or_insert_with(|| alias.clone());
                }
            }
        }
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

/// The configuration as last read, and what it was read from.
struct Cached {
    stamp: Option<SystemTime>,
    read: Instant,
    config: Arc<Config>,
}

/// How long a read configuration is trusted before DNS is asked again, even
/// when the file has not changed.
const FRESH: Duration = Duration::from_secs(5 * 60);

fn stamp() -> Option<SystemTime> {
    ssh_dir().and_then(|d| std::fs::metadata(d.join("config")).ok()).and_then(|m| m.modified().ok())
}

/// The configuration, read and indexed once and read again when the file
/// changes — not on every keystroke that passes through the plugin.
pub async fn shared() -> anyhow::Result<Arc<Config>> {
    static CACHE: tokio::sync::Mutex<Option<Cached>> = tokio::sync::Mutex::const_new(None);
    let mut cache = CACHE.lock().await;
    let now = stamp();
    if let Some(c) = cache.as_ref() {
        if c.stamp == now && c.read.elapsed() < FRESH {
            return Ok(Arc::clone(&c.config));
        }
    }
    let mut config = Config::load()?;
    config.index().await;
    let config = Arc::new(config);
    *cache = Some(Cached { stamp: now, read: Instant::now(), config: Arc::clone(&config) });
    Ok(config)
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
    fn a_host_the_vault_names_by_its_address_finds_its_block() {
        let c = Config::parse(CONFIG);
        // As written in HostName.
        let r = c.lookup("203.0.113.10");
        assert_eq!((r.user.as_deref(), r.port, r.alias.as_deref(), r.hostname), (Some("ubuntu"), Some(2222), Some("prod"), None));
        // Named outright, it stays as ssh reads it.
        assert_eq!(c.lookup("prod").hostname.as_deref(), Some("203.0.113.10"));
        // Through DNS: the index maps the address to the alias.
        let mut c = c;
        c.addresses.insert("198.51.100.99".parse().unwrap(), "bastion".into());
        let r = c.lookup("198.51.100.99");
        assert_eq!(r.alias.as_deref(), Some("bastion"));
        // Nothing matches: the catch-all still applies.
        assert_eq!(c.lookup("192.0.2.1").user.as_deref(), Some("root"));
    }

    #[test]
    fn a_proxy_command_is_said_so() {
        let c = Config::parse("host i-* mi-*\n    ProxyCommand sh -c \"aws ssm start-session --target %h\"\nHost i-05bd\n    User ec2-user\n");
        let r = c.lookup("i-05bd");
        assert_eq!(r.user.as_deref(), Some("ec2-user"));
        assert!(r.proxy().is_some_and(|p| p.contains("aws ssm")));
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
