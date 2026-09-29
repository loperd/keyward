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

use std::collections::HashMap;
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::Mutex;
use std::time::{Duration, Instant, SystemTime, UNIX_EPOCH};

use russh::keys::PublicKey;
use serde::Serialize;

use super::connect::{self, Guard};
use super::hostkeys::{self, Store, Verdict};

/// How long one check may take in all.
const CHECK: Duration = Duration::from_secs(20);

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
    pub port: u16,
    pub user: Option<String>,
    pub pin: Option<String>,
}

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

/// Checks one key against one host.
pub async fn check(target: &Target, store: Store) -> Check {
    let started = Instant::now();
    let mut out = Check {
        host: target.host.clone(),
        port: target.port,
        user: target.user.clone(),
        status: Status::Error,
        latency_ms: None,
        detail: None,
        fingerprint: None,
        checked_at: Some(now()),
    };
    let Some(key) = &target.key else {
        out.detail = Some(keyward_core::fault!("err.sshNoPublicKey", "key" => target.entry_name.as_str()).to_string());
        return out;
    };
    let run = async move {
        let (guard, seen) = Guard::new(&target.host, target.port, target.pin.clone(), store, None);
        let mut handle = match connect::handshake(&target.host, target.port, guard, &seen).await {
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
        out.status = match &target.user {
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
        port: target.port,
        user: target.user.clone(),
        status: Status::Unreachable,
        latency_ms: None,
        detail: Some(connect::reach_error(&target.host, "timed out").to_string()),
        fingerprint: None,
        checked_at: Some(now()),
    };
    tokio::time::timeout(CHECK, run).await.unwrap_or(fallback)
}

/// The board the window reads: the last results, and whether a round is
/// running.
pub struct Board {
    results: Mutex<HashMap<String, KeyHealth>>,
    running: AtomicBool,
    last: Mutex<Option<(Instant, u64)>>,
}

impl Default for Board {
    fn default() -> Self {
        Self { results: Mutex::new(HashMap::new()), running: AtomicBool::new(false), last: Mutex::new(None) }
    }
}

impl Board {
    /// The report over the keys as they are now: a key checked before keeps
    /// its results, a new one shows as pending, a gone one is dropped.
    pub fn report(&self, plans: &[Plan]) -> Report {
        let results = self.results.lock().map(|r| r.clone()).unwrap_or_default();
        let mut keys: Vec<KeyHealth> = plans
            .iter()
            .map(|p| {
                let mut checks: Vec<Check> = p
                    .targets
                    .iter()
                    .map(|t| {
                        results
                            .get(&p.entry_id)
                            .and_then(|k| k.checks.iter().find(|c| c.host == t.host && c.port == t.port && c.user == t.user))
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
                            })
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
    pub async fn run(&self, plans: Vec<Plan>, store: Store) -> bool {
        if self.running.swap(true, Ordering::AcqRel) {
            return false;
        }
        let mut tasks = tokio::task::JoinSet::new();
        for plan in &plans {
            for target in &plan.targets {
                let target = target.clone();
                let store = store.clone();
                tasks.spawn(async move { (target.entry_id.clone(), check(&target, store).await) });
            }
        }
        let mut found: HashMap<String, Vec<Check>> = HashMap::new();
        while let Some(done) = tasks.join_next().await {
            match done {
                Ok((entry, c)) => found.entry(entry).or_default().push(c),
                Err(e) => tracing::error!(error = %e, "a health check fell over"),
            }
        }
        if let Ok(mut results) = self.results.lock() {
            for plan in &plans {
                let checks = found.remove(&plan.entry_id).unwrap_or_default();
                results.insert(
                    plan.entry_id.clone(),
                    KeyHealth { entry_id: plan.entry_id.clone(), entry_name: plan.entry_name.clone(), status: worst(&checks, plan.idle), checks },
                );
            }
        }
        if let Ok(mut last) = self.last.lock() {
            *last = Some((Instant::now(), now()));
        }
        self.running.store(false, Ordering::Release);
        true
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
        Check { host: host.into(), port: 22, user: None, status, latency_ms: None, detail: None, fingerprint: None, checked_at: None }
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
            targets: vec![Target { entry_id: "1".into(), entry_name: "prod".into(), key: None, host: "a.example.com".into(), port: 22, user: None, pin: None }],
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
        let target = Target { entry_id: "1".into(), entry_name: "k".into(), key: Some(key), host: "127.0.0.1".into(), port: 1, user: Some("u".into()), pin: None };
        let got = check(&target, Store { user: None, own: d.join("known_hosts") }).await;
        assert_eq!(got.status, Status::Unreachable);
        assert!(got.detail.unwrap().starts_with("err.sshUnreachable"));
    }
}
