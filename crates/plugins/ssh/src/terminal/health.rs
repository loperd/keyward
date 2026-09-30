//! Whether the vault's ssh keys still get in where they are bound.
//!
//! A check goes as far as a login would and stops one step short: it reaches
//! the host, verifies its key the way the terminal does, and offers the vault's
//! public key without a signature. A server that would take the key answers
//! `PK_OK`; that answer is the result. Nothing is signed, so a check needs no
//! finger and never touches the private key — it can run on a timer.
//!
//! An unknown host is reported rather than probed: offering a key to a server
//! nobody has vouched for tells a stranger which keys a person holds.

use std::collections::{HashMap, HashSet};
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::Mutex;
use std::time::{Duration, Instant, SystemTime, UNIX_EPOCH};

use russh::keys::PublicKey;
use serde::Serialize;

use super::connect::{self, Guard};
use super::hostkeys::{self, Store, Verdict};

/// How long one check may take in all.
const CHECK: Duration = Duration::from_secs(15);

/// How long a check waits for a host to answer at all. A host that is down
/// must not hold the round up for long.
const REACH: Duration = Duration::from_secs(6);

/// What one check found. The order is the order of badness: a key's state is
/// the worst of its hosts'.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum Status {
    /// The key is bound to no host: there is nowhere to check it.
    Unbound,
    /// Only wildcard routes: there is no host name to reach.
    Wildcard,
    /// Not checked yet.
    Pending,
    /// The server would take the key.
    Ok,
    /// The host answered and its key is trusted, but no login is known to
    /// offer the key for.
    Reachable,
    /// Nobody has vouched for the host key yet.
    HostUnknown,
    /// The check itself failed in some other way.
    Error,
    /// The host could not be reached.
    Unreachable,
    /// The server would not take the key.
    Rejected,
    /// The host key differs from the recorded one.
    HostChanged,
}

/// One host of one key, as checked.
#[derive(Debug, Clone, Serialize)]
pub struct Check {
    pub host: String,
    pub port: u16,
    pub user: Option<String>,
    pub status: Status,
    pub latency_ms: Option<u64>,
    /// The reason, as a key for the window to render.
    pub detail: Option<String>,
    /// The host key's fingerprint, when it is the reason.
    pub fingerprint: Option<String>,
    pub checked_at: Option<u64>,
    /// Being checked right now: the result shown is the last one.
    #[serde(default)]
    pub checking: bool,
    /// Something worth saying besides the status, as a key for the window:
    /// the login taken from `~/.ssh/config`, say.
    #[serde(default)]
    pub note: Option<String>,
}

/// A key's health: the worst of its hosts.
#[derive(Debug, Clone, Serialize)]
pub struct KeyHealth {
    pub entry_id: String,
    pub entry_name: String,
    pub status: Status,
    pub checks: Vec<Check>,
}

#[derive(Debug, Clone, Serialize)]
pub struct Report {
    pub keys: Vec<KeyHealth>,
    pub running: bool,
    pub checked_at: Option<u64>,
}

/// A host to check a key against.
#[derive(Debug, Clone)]
pub struct Target {
    pub entry_id: String,
    pub entry_name: String,
    pub key: Option<PublicKey>,
    pub host: String,
    /// Where to connect: the host, or the real address `~/.ssh/config` gives
    /// an alias.
    pub address: String,
    pub port: u16,
    pub user: Option<String>,
    pub pin: Option<String>,
    /// What `~/.ssh/config` says where it differs from the vault: tried when
    /// the vault's login or port does not get in.
    pub alt: Option<Alt>,
}

/// A login and a port out of `~/.ssh/config`.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Alt {
    pub user: Option<String>,
    pub port: u16,
}

/// Fields of a key's item to write: what `~/.ssh/config` had and the server
/// proved right.
pub type Update = (String, Vec<(String, String)>);

/// A key with the hosts to check it against, or the reason there are none.
#[derive(Debug, Clone)]
pub struct Plan {
    pub entry_id: String,
    pub entry_name: String,
    pub targets: Vec<Target>,
    /// What to say when `targets` is empty.
    pub idle: Status,
}

fn now() -> u64 {
    SystemTime::now().duration_since(UNIX_EPOCH).map(|d| d.as_secs()).unwrap_or(0)
}

fn worst(checks: &[Check], idle: Status) -> Status {
    checks.iter().map(|c| c.status).max().unwrap_or(idle)
}

/// Checks one key against one host — with what the vault says, and when that
/// does not get in, with what `~/.ssh/config` says. A config that the server
/// proves right comes back as an update for the item.
pub async fn check(target: &Target, store: Store) -> (Check, Option<Update>) {
    let first = check_as(target, target.user.clone(), target.port, store.clone()).await;
    let Some(alt) = &target.alt else { return (first, None) };
    if !matches!(first.status, Status::Rejected | Status::Unreachable | Status::Error | Status::Reachable) {
        return (first, None);
    }
    let mut second = check_as(target, alt.user.clone(), alt.port, store).await;
    if second.status != Status::Ok {
        return (first, None);
    }
    let mut fields = Vec::new();
    if alt.user.is_some() && alt.user != target.user {
        fields.push((crate::table::USER.to_string(), alt.user.clone().unwrap_or_default()));
    }
    if alt.port != target.port {
        fields.push((crate::table::PORT.to_string(), if alt.port == 22 { String::new() } else { alt.port.to_string() }));
    }
    let note = serde_json::json!({ "user": alt.user.clone().unwrap_or_default(), "port": alt.port });
    second.note = Some(format!("term.health.fromConfig {note}"));
    tracing::info!(host = %target.host, entry = %target.entry_name, "~/.ssh/config got in where the vault did not; the item is updated");
    (second, Some((target.entry_id.clone(), fields)))
}

/// Checks one key against one host as one login on one port.
async fn check_as(target: &Target, user: Option<String>, port: u16, store: Store) -> Check {
    let started = Instant::now();
    let mut out = Check {
        host: target.host.clone(),
        port,
        user: user.clone(),
        status: Status::Error,
        latency_ms: None,
        detail: None,
        fingerprint: None,
        checked_at: Some(now()),
        checking: false,
        note: None,
    };
    let Some(key) = &target.key else {
        out.detail = Some(keyward_core::fault!("err.sshNoPublicKey", "key" => target.entry_name.as_str()).to_string());
        return out;
    };
    let fallback_user = user.clone();
    let run = async move {
        let (guard, seen) = Guard::new(&target.address, port, target.pin.clone(), store, None);
        let mut handle = match connect::handshake(&target.address, port, REACH, guard, &seen).await {
            Ok(h) => h,
            Err((e, seen)) => {
                return match seen {
                    Some(s) => {
                        out.fingerprint = Some(hostkeys::fingerprint(&s.key));
                        out.status = match s.verdict {
                            Verdict::Changed(_) => Status::HostChanged,
                            Verdict::Unknown { .. } => Status::HostUnknown,
                            Verdict::Pinned | Verdict::Known(_) => Status::Error,
                        };
                        out.detail = Some(e.to_string());
                        out
                    }
                    None => {
                        out.status = Status::Unreachable;
                        out.detail = Some(e.to_string());
                        out
                    }
                };
            }
        };
        out.status = match &user {
            None => Status::Reachable,
            Some(user) => match connect::probe(&mut handle, user, key).await {
                Ok(true) => Status::Ok,
                Ok(false) => Status::Rejected,
                Err(e) => {
                    out.detail = Some(e.to_string());
                    Status::Error
                }
            },
        };
        out.latency_ms = Some(started.elapsed().as_millis() as u64);
        if let Err(e) = handle.disconnect(russh::Disconnect::ByApplication, "", "en").await {
            tracing::debug!(error = %e, "a checked connection was gone before it was closed");
        }
        out
    };
    let fallback = Check {
        host: target.host.clone(),
        port,
        user: fallback_user,
        status: Status::Unreachable,
        latency_ms: None,
        detail: Some(connect::reach_error(&target.host, "timed out").to_string()),
        fingerprint: None,
        checked_at: Some(now()),
        checking: false,
        note: None,
    };
    tokio::time::timeout(CHECK, run).await.unwrap_or(fallback)
}

/// The board the window reads: the last results, and whether a round is
/// running.
pub struct Board {
    results: Mutex<HashMap<String, KeyHealth>>,
    running: AtomicBool,
    last: Mutex<Option<(Instant, u64)>>,
    /// The hosts a round is checking just now: key, host, port.
    checking: Mutex<HashSet<(String, String, u16)>>,
}

impl Default for Board {
    fn default() -> Self {
        Self {
            results: Mutex::new(HashMap::new()),
            running: AtomicBool::new(false),
            last: Mutex::new(None),
            checking: Mutex::new(HashSet::new()),
        }
    }
}

impl Board {
    /// The report over the keys as they are now: a key checked before keeps
    /// its results, a new one shows as pending, a gone one is dropped.
    pub fn report(&self, plans: &[Plan]) -> Report {
        let results = self.results.lock().map(|r| r.clone()).unwrap_or_default();
        let checking = self.checking.lock().map(|c| c.clone()).unwrap_or_default();
        let mut keys: Vec<KeyHealth> = plans
            .iter()
            .map(|p| {
                let mut checks: Vec<Check> = p
                    .targets
                    .iter()
                    .map(|t| {
                        // By the host: a result checked with what
                        // ~/.ssh/config said is this host's result, even
                        // before the vault has taken the new login or port.
                        results
                            .get(&p.entry_id)
                            .and_then(|k| {
                                k.checks
                                    .iter()
                                    .find(|c| c.host == t.host && c.port == t.port)
                                    .or_else(|| k.checks.iter().find(|c| c.host == t.host))
                            })
                            .cloned()
                            .unwrap_or(Check {
                                host: t.host.clone(),
                                port: t.port,
                                user: t.user.clone(),
                                status: Status::Pending,
                                latency_ms: None,
                                detail: None,
                                fingerprint: None,
                                checked_at: None,
                                checking: false,
                                note: None,
                            })
                    })
                    .map(|mut c| {
                        c.checking = checking.contains(&(p.entry_id.clone(), c.host.clone(), c.port));
                        c
                    })
                    .collect();
                checks.sort_by(|a, b| b.status.cmp(&a.status).then_with(|| a.host.cmp(&b.host)));
                KeyHealth { entry_id: p.entry_id.clone(), entry_name: p.entry_name.clone(), status: worst(&checks, p.idle), checks }
            })
            .collect();
        keys.sort_by_key(|k| k.entry_name.to_lowercase());
        Report {
            keys,
            running: self.running.load(Ordering::Relaxed),
            checked_at: self.last.lock().ok().and_then(|l| l.map(|(_, at)| at)),
        }
    }

    /// Whether the last round is older than `every`. Never checked counts as
    /// due.
    pub fn due(&self, every: Duration) -> bool {
        self.last.lock().ok().and_then(|l| *l).is_none_or(|(at, _)| at.elapsed() >= every)
    }

    /// Runs a round over the plans given — all keys, or one. A round that is
    /// already running is not doubled: `false` says this one did not start.
    ///
    /// Each host's result lands on the board as soon as it is known, so the
    /// window shows the round filling in rather than a wait on the slowest
    /// host.
    pub async fn run(&self, plans: Vec<Plan>, store: Store) -> Vec<Update> {
        if self.running.swap(true, Ordering::AcqRel) {
            return Vec::new();
        }
        let mut updates = Vec::new();
        if let Ok(mut c) = self.checking.lock() {
            for plan in &plans {
                for t in &plan.targets {
                    c.insert((plan.entry_id.clone(), t.host.clone(), t.port));
                }
            }
        }
        // A key with no host to check still gets its state.
        if let Ok(mut results) = self.results.lock() {
            for plan in plans.iter().filter(|p| p.targets.is_empty()) {
                results.insert(
                    plan.entry_id.clone(),
                    KeyHealth { entry_id: plan.entry_id.clone(), entry_name: plan.entry_name.clone(), status: plan.idle, checks: Vec::new() },
                );
            }
        }
        let names: HashMap<String, (String, Status)> = plans.iter().map(|p| (p.entry_id.clone(), (p.entry_name.clone(), p.idle))).collect();
        let mut tasks = tokio::task::JoinSet::new();
        for plan in &plans {
            for target in &plan.targets {
                let target = target.clone();
                let store = store.clone();
                tasks.spawn(async move { (target.entry_id.clone(), check(&target, store).await) });
            }
        }
        while let Some(done) = tasks.join_next().await {
            let (entry, (c, update)) = match done {
                Ok(found) => found,
                Err(e) => {
                    tracing::error!(error = %e, "a health check fell over");
                    continue;
                }
            };
            if let Some(u) = update.filter(|(_, fields)| !fields.is_empty()) {
                updates.push(u);
            }
            if let Ok(mut checking) = self.checking.lock() {
                checking.retain(|(e, h, _)| !(e == &entry && h == &c.host));
            }
            let Some((name, idle)) = names.get(&entry) else { continue };
            if let Ok(mut results) = self.results.lock() {
                let key = results.entry(entry.clone()).or_insert_with(|| KeyHealth {
                    entry_id: entry.clone(),
                    entry_name: name.clone(),
                    status: *idle,
                    checks: Vec::new(),
                });
                key.checks.retain(|old| old.host != c.host);
                key.checks.push(c);
                key.status = worst(&key.checks, *idle);
            }
        }
        if let Ok(mut checking) = self.checking.lock() {
            checking.clear();
        }
        if let Ok(mut last) = self.last.lock() {
            *last = Some((Instant::now(), now()));
        }
        self.running.store(false, Ordering::Release);
        updates
    }

    pub fn running(&self) -> bool {
        self.running.load(Ordering::Relaxed)
    }

    /// Forgets everything: the vault is locked.
    pub fn clear(&self) {
        if let Ok(mut r) = self.results.lock() {
            r.clear();
        }
        if let Ok(mut l) = self.last.lock() {
            *l = None;
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn c(host: &str, status: Status) -> Check {
        Check { host: host.into(), port: 22, user: None, status, latency_ms: None, detail: None, fingerprint: None, checked_at: None, checking: false, note: None }
    }

    #[test]
    fn a_key_is_as_healthy_as_its_worst_host() {
        assert_eq!(worst(&[c("a", Status::Ok), c("b", Status::Rejected)], Status::Unbound), Status::Rejected);
        assert_eq!(worst(&[c("a", Status::Ok), c("b", Status::Reachable)], Status::Unbound), Status::Reachable);
        assert_eq!(worst(&[c("a", Status::HostChanged), c("b", Status::Unreachable)], Status::Unbound), Status::HostChanged);
        assert_eq!(worst(&[], Status::Wildcard), Status::Wildcard);
    }

    #[test]
    fn the_report_follows_the_keys_as_they_are_now() {
        let board = Board::default();
        let plan = Plan {
            entry_id: "1".into(),
            entry_name: "prod".into(),
            targets: vec![Target { entry_id: "1".into(), entry_name: "prod".into(), key: None, host: "a.example.com".into(), address: "a.example.com".into(), port: 22, user: None, pin: None, alt: None }],
            idle: Status::Unbound,
        };
        let r = board.report(std::slice::from_ref(&plan));
        assert_eq!(r.keys[0].status, Status::Pending);
        assert!(board.due(Duration::from_secs(60)));
        assert!(r.checked_at.is_none());
    }

    #[tokio::test]
    async fn an_unreachable_host_is_said_so() {
        // Port 1 on the loopback: nobody listens there, the refusal is
        // immediate.
        let d = std::env::temp_dir().join(format!("kw-health-{}", std::process::id()));
        std::fs::create_dir_all(&d).unwrap();
        let key = russh::keys::parse_public_key_base64("AAAAC3NzaC1lZDI1NTE5AAAAIJdD7y3aLq454yWBdwLWbieU1ebz9/cu7/QEXn9OIeZJ").unwrap();
        let target = Target { entry_id: "1".into(), entry_name: "k".into(), key: Some(key), host: "127.0.0.1".into(), address: "127.0.0.1".into(), port: 1, user: Some("u".into()), pin: None, alt: None };
        let (got, update) = check(&target, Store { user: None, own: d.join("known_hosts") }).await;
        assert!(update.is_none());
        assert_eq!(got.status, Status::Unreachable);
        assert!(got.detail.unwrap().starts_with("err.sshUnreachable"));
    }
}
