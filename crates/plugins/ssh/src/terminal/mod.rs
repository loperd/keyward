//! The terminal: a shell on a server, reached with a key the vault holds, in a
//! section of the window.
//!
//! All of it lives in this plugin; the core routes calls and knows nothing of
//! terminals. The pieces:
//!
//! - `link` — the page and the plugin seal what a terminal carries end to end;
//!   the window and the daemon in between see ciphertext.
//! - `connect` — russh, the host key check and signing through the core.
//! - `hostkeys` — which host keys are trusted, and where that is written.
//! - `session` — one live shell, its task and its scrollback.
//! - `health` — whether each key still gets in where it is bound, checked
//!   without signing anything.
//!
//! The operations, all through the plugin's one `call`:
//!
//! | op | payload | sealed |
//! |---|---|---|
//! | `term_link` | the page's public key | — |
//! | `term` | a link, a lane and a sealed request (below) | yes |
//! | `term_sessions` | — | — |
//! | `term_targets` | — | — |
//! | `term_forget_host` | a host and a port | — |
//! | `health` | — | — |
//! | `health_run` | a key, or every key | — |
//!
//! Inside `term`, on the input lane: `open`, `attach`, `write`, `resize`,
//! `trust`, `close`; on the output lane: `read`.

pub mod connect;
pub mod health;
pub mod hostkeys;
pub mod link;
pub mod session;

use std::collections::HashMap;
use std::path::Path;
use std::sync::{Arc, Mutex};
use std::time::{Duration, Instant};

use base64::Engine as _;
use keyward_plugin::{arg, out, Host, Result, VaultEntry};
use serde::{Deserialize, Serialize};
use serde_json::Value;
use zeroize::Zeroizing;

use crate::mapping::MappingTable;
use link::{Lane, Link};
use session::{Info, Plan, Session};

/// How many pages may hold a link at once. A page makes one per tab; an old
/// link nobody used for longest makes room.
const MAX_LINKS: usize = 32;

/// A link nobody used for this long is dropped.
const LINK_IDLE: Duration = Duration::from_secs(60 * 60);

/// How many shells may be open at once.
const MAX_SESSIONS: usize = 12;

/// The longest a read waits for output: well inside the daemon's thirty
/// seconds for an answer.
const READ_WAIT_MAX: Duration = Duration::from_secs(20);

/// Hosts the terminal got into, remembered for this run only: a wildcard
/// route names no host, and a health check needs one.
const RECENT: usize = 20;

fn b64() -> base64::engine::GeneralPurpose {
    base64::engine::general_purpose::STANDARD
}

/// The vault as the terminal needs it: the items with keys and the routes.
pub struct View<'a> {
    pub entries: &'a [VaultEntry],
    pub table: &'a MappingTable,
}

/// One page's link and the session it is bound to.
struct Slot {
    link: Link,
    session: Option<String>,
    used: Instant,
}

/// Where the terminal got in.
#[derive(Debug, Clone, PartialEq, Eq)]
struct Recent {
    entry_id: String,
    host: String,
    port: u16,
    user: String,
}

/// A destination the window offers: a route with a host name, or a host the
/// terminal got into this run.
#[derive(Debug, Clone, Serialize)]
pub struct Target {
    pub entry_id: String,
    pub entry_name: String,
    pub host: String,
    pub port: Option<u16>,
    pub user: Option<String>,
    /// The route's pattern as the person wrote it; empty for a recent host.
    pub pattern: String,
    pub recent: bool,
}

#[derive(Default)]
pub struct Terminals {
    links: Mutex<HashMap<String, Slot>>,
    sessions: Mutex<HashMap<String, Arc<Session>>>,
    recent: Arc<Mutex<Vec<Recent>>>,
    pub board: Arc<health::Board>,
}

// -- The envelopes ------------------------------------------------------------

#[derive(Deserialize)]
struct LinkArgs {
    public: String,
}

#[derive(Serialize)]
struct Linked {
    link: String,
    public: String,
}

#[derive(Deserialize)]
struct Sealed {
    link: String,
    lane: Lane,
    sealed: String,
}

#[derive(Debug, Deserialize)]
struct Where {
    #[serde(default)]
    entry_id: Option<String>,
    host: String,
    #[serde(default)]
    port: Option<u16>,
    #[serde(default)]
    user: Option<String>,
}

/// A request on the input lane. Not `Debug`: `write` carries keystrokes.
#[derive(Deserialize)]
#[serde(tag = "op", rename_all = "snake_case")]
enum InputOp {
    Open { target: Where, cols: u32, rows: u32 },
    Attach { session: String },
    Write { data: String },
    Resize { cols: u32, rows: u32 },
    Trust { answer: bool },
    Close,
}

/// A request on the output lane.
#[derive(Deserialize)]
#[serde(tag = "op", rename_all = "snake_case")]
enum OutputOp {
    Read {
        cursor: u64,
        version: u64,
        #[serde(default)]
        wait_ms: u64,
    },
}

#[derive(Serialize)]
struct Attached {
    session: Info,
    state: session::State,
}

#[derive(Serialize)]
struct ReadOut {
    data: Zeroizing<String>,
    cursor: u64,
    dropped: bool,
    state: session::State,
    version: u64,
}

#[derive(Serialize)]
struct SessionRow {
    #[serde(flatten)]
    info: Info,
    state: session::State,
}

#[derive(Deserialize)]
struct ForgetArgs {
    host: String,
    #[serde(default)]
    port: Option<u16>,
}

#[derive(Deserialize, Default)]
struct HealthArgs {
    #[serde(default)]
    entry_id: Option<String>,
}

impl Terminals {
    /// The terminal's operations. `None` means the operation is not the
    /// terminal's.
    pub async fn call(
        &self,
        host: &dyn Host,
        core: Result<Arc<dyn Host>>,
        view: View<'_>,
        op: &str,
        payload: Value,
    ) -> Option<Result<Value>> {
        let store = hostkeys::Store::new(&host.state_dir());
        Some(match op {
            "term_link" => self.link(payload),
            "term" => self.sealed(core, &view, store, payload).await,
            "term_sessions" => self.sessions(),
            "term_targets" => out(self.targets(&view)),
            "term_forget_host" => (|| {
                let a: ForgetArgs = arg(payload)?;
                out(store.forget(a.host.trim(), a.port.unwrap_or(22))?)
            })(),
            "health" => out(self.board.report(&self.plans(&view, None))),
            "health_run" => {
                let a: HealthArgs = if payload.is_null() { HealthArgs::default() } else { match arg(payload) {
                    Ok(a) => a,
                    Err(e) => return Some(Err(e)),
                } };
                let plans = self.plans(&view, a.entry_id.as_deref());
                self.board.run(plans, store).await;
                out(self.board.report(&self.plans(&view, None)))
            }
            _ => return None,
        })
    }

    /// Everything that lived on the keys comes down: the shells close, the
    /// links are forgotten, the health board is wiped.
    pub fn lock(&self) {
        let sessions: Vec<Arc<Session>> = self.sessions.lock().map(|mut s| s.drain().map(|(_, v)| v).collect()).unwrap_or_default();
        for s in &sessions {
            s.close();
        }
        if let Ok(mut l) = self.links.lock() {
            l.clear();
        }
        if let Ok(mut r) = self.recent.lock() {
            r.clear();
        }
        self.board.clear();
    }

    /// A health round in the background if one is due. The minute tick calls
    /// it; `every` comes from the settings.
    pub fn tick(self: &Arc<Self>, view: View<'_>, every: Duration, plugin_dir: &Path) {
        if every.is_zero() || view.entries.is_empty() || !self.board.due(every) {
            return;
        }
        let plans = self.plans(&view, None);
        let store = hostkeys::Store::new(plugin_dir);
        let board = Arc::clone(&self.board);
        tokio::spawn(async move {
            board.run(plans, store).await;
        });
    }

    fn link(&self, payload: Value) -> Result<Value> {
        let a: LinkArgs = arg(payload)?;
        let (link, public) = Link::accept(&a.public)?;
        let id = session::new_id();
        let mut links = self.links.lock().map_err(|_| keyward_core::fault!("err.sshTerminalBroken"))?;
        links.retain(|_, s| s.used.elapsed() < LINK_IDLE);
        while links.len() >= MAX_LINKS {
            let Some(oldest) = links.iter().min_by_key(|(_, s)| s.used).map(|(k, _)| k.clone()) else { break };
            links.remove(&oldest);
        }
        links.insert(id.clone(), Slot { link, session: None, used: Instant::now() });
        out(Linked { link: id, public })
    }

    /// Opens a request with its link's key, and hands back the link's session.
    fn open_request(&self, a: &Sealed) -> Result<(Zeroizing<Vec<u8>>, Option<String>)> {
        let mut links = self.links.lock().map_err(|_| keyward_core::fault!("err.sshTerminalBroken"))?;
        let slot = links.get_mut(&a.link).ok_or_else(|| keyward_core::fault!("err.sshLinkGone"))?;
        let plain = slot.link.open(a.lane, &a.sealed)?;
        slot.used = Instant::now();
        Ok((plain, slot.session.clone()))
    }

    fn seal_answer(&self, a: &Sealed, value: &impl Serialize, bind: Option<&str>) -> Result<Value> {
        let plain = Zeroizing::new(serde_json::to_vec(value)?);
        let mut links = self.links.lock().map_err(|_| keyward_core::fault!("err.sshTerminalBroken"))?;
        let slot = links.get_mut(&a.link).ok_or_else(|| keyward_core::fault!("err.sshLinkGone"))?;
        if let Some(id) = bind {
            slot.session = Some(id.to_string());
        }
        let sealed = slot.link.seal(a.lane, &plain)?;
        Ok(serde_json::json!({ "sealed": sealed }))
    }

    /// The answer to a request that failed, sealed like any other so the lane
    /// stays in step: `{"error": key}`.
    fn seal_error(&self, a: &Sealed, e: &anyhow::Error) -> Result<Value> {
        self.seal_answer(a, &serde_json::json!({ "error": e.to_string() }), None)
    }

    fn session(&self, id: Option<&str>) -> Result<Arc<Session>> {
        let id = id.ok_or_else(|| keyward_core::fault!("err.sshNoSession"))?;
        self.sessions
            .lock()
            .map_err(|_| keyward_core::fault!("err.sshTerminalBroken"))?
            .get(id)
            .cloned()
            .ok_or_else(|| keyward_core::fault!("err.sshSessionClosed"))
    }

    async fn sealed(&self, core: Result<Arc<dyn Host>>, view: &View<'_>, store: hostkeys::Store, payload: Value) -> Result<Value> {
        let a: Sealed = arg(payload)?;
        // A request that does not open is refused in the clear: there is no
        // key to seal an answer with that the page could trust.
        let (plain, bound) = self.open_request(&a)?;
        match a.lane {
            Lane::Input => {
                let op: InputOp = serde_json::from_slice(&plain).map_err(|e| anyhow::anyhow!("the terminal got something other than what it expected: {e}"))?;
                drop(plain);
                match self.input(op, bound.as_deref(), core, view, store) {
                    Ok((value, bind)) => self.seal_answer(&a, &value, bind.as_deref()),
                    Err(e) => self.seal_error(&a, &e),
                }
            }
            Lane::Output => {
                let OutputOp::Read { cursor, version, wait_ms } =
                    serde_json::from_slice(&plain).map_err(|e| anyhow::anyhow!("the terminal got something other than what it expected: {e}"))?;
                let session = match self.session(bound.as_deref()) {
                    Ok(s) => s,
                    Err(e) => return self.seal_error(&a, &e),
                };
                let wait = Duration::from_millis(wait_ms).min(READ_WAIT_MAX);
                let chunk = session.read(cursor, version, wait).await;
                let answer = ReadOut {
                    data: Zeroizing::new(b64().encode(&chunk.data[..])),
                    cursor: chunk.cursor,
                    dropped: chunk.dropped,
                    state: chunk.state,
                    version: chunk.version,
                };
                self.seal_answer(&a, &answer, None)
            }
        }
    }

    /// An input request, opened. The answer, and the session to bind the link
    /// to when it named one.
    fn input(
        &self,
        op: InputOp,
        bound: Option<&str>,
        core: Result<Arc<dyn Host>>,
        view: &View<'_>,
        store: hostkeys::Store,
    ) -> Result<(Value, Option<String>)> {
        match op {
            InputOp::Open { target, cols, rows } => {
                let plan = self.plan(view, target, cols, rows)?;
                let core = core?;
                let live = self.sessions.lock().map_err(|_| keyward_core::fault!("err.sshTerminalBroken"))?.values().filter(|s| !s.state().closed()).count();
                if live >= MAX_SESSIONS {
                    anyhow::bail!(keyward_core::fault!("err.sshTooManySessions", "max" => MAX_SESSIONS));
                }
                let recent = Arc::clone(&self.recent);
                let on_open: session::OnOpen = Box::new(move |info: &Info| remember(&recent, info));
                let session = Session::start(plan, store, core, on_open);
                let id = session.info.id.clone();
                let answer = Attached { session: session.info.clone(), state: session.state() };
                let mut sessions = self.sessions.lock().map_err(|_| keyward_core::fault!("err.sshTerminalBroken"))?;
                // Closed sessions nobody looks at any more make room.
                sessions.retain(|_, s| !s.state().closed());
                sessions.insert(id.clone(), session);
                Ok((serde_json::to_value(answer)?, Some(id)))
            }
            InputOp::Attach { session } => {
                let s = self.session(Some(&session))?;
                let answer = Attached { session: s.info.clone(), state: s.state() };
                Ok((serde_json::to_value(answer)?, Some(session)))
            }
            InputOp::Write { data } => {
                let bytes = Zeroizing::new(b64().decode(data.as_bytes()).map_err(|_| anyhow::anyhow!("the keystrokes are not base64"))?);
                drop(Zeroizing::new(data));
                self.session(bound)?.write(bytes)?;
                Ok((Value::Null, None))
            }
            InputOp::Resize { cols, rows } => {
                self.session(bound)?.resize(cols, rows)?;
                Ok((Value::Null, None))
            }
            InputOp::Trust { answer } => {
                self.session(bound)?.answer_trust(answer)?;
                Ok((Value::Null, None))
            }
            InputOp::Close => {
                let id = bound.ok_or_else(|| keyward_core::fault!("err.sshNoSession"))?;
                let gone = self.sessions.lock().map_err(|_| keyward_core::fault!("err.sshTerminalBroken"))?.remove(id);
                if let Some(s) = gone {
                    s.close();
                }
                Ok((Value::Null, None))
            }
        }
    }

    fn sessions(&self) -> Result<Value> {
        let sessions = self.sessions.lock().map_err(|_| keyward_core::fault!("err.sshTerminalBroken"))?;
        let mut rows: Vec<SessionRow> = sessions.values().map(|s| SessionRow { info: s.info.clone(), state: s.state() }).collect();
        rows.sort_by_key(|r| r.info.opened_at);
        out(rows)
    }

    /// Where to go and with which key, out of what the page asked.
    ///
    /// The key is the one the routes give the host — exactly one, as for ssh
    /// — unless the page named a key itself. The signature always asks for
    /// the person: a shell opened from the window is a use of the key, and
    /// every use is confirmed.
    fn plan(&self, view: &View<'_>, target: Where, cols: u32, rows: u32) -> Result<Plan> {
        let host = target.host.trim().to_string();
        if host.is_empty() || host.contains(char::is_whitespace) || host.starts_with('-') {
            anyhow::bail!(keyward_core::fault!("err.sshBadHost"));
        }
        let route = route_for(view.table, &host, target.user.as_deref(), target.port);
        let entry_id = match (&target.entry_id, &route) {
            (Some(id), _) => id.clone(),
            (None, Some(m)) => m.entry_id.clone(),
            (None, None) => anyhow::bail!(keyward_core::fault!("err.sshNoKeyForHost", "host" => host.as_str())),
        };
        let entry = view
            .entries
            .iter()
            .find(|e| e.id == entry_id)
            .ok_or_else(|| keyward_core::fault!("err.sshKeyGone"))?;
        // The route counts only when it is this key's: a pin or a login of
        // another key's route says nothing about this one.
        let route = route.filter(|m| m.entry_id == entry.id);
        if route.as_ref().is_some_and(|m| m.cert_role.is_some()) {
            anyhow::bail!(keyward_core::fault!("err.sshTerminalCertUnsupported", "key" => entry.name.as_str()));
        }
        let user = target
            .user
            .map(|u| u.trim().to_string())
            .filter(|u| !u.is_empty())
            .or_else(|| route.as_ref().and_then(|m| m.user.clone()))
            .ok_or_else(|| keyward_core::fault!("err.sshLoginRequired", "host" => host.as_str()))?;
        if user.contains(char::is_whitespace) {
            anyhow::bail!(keyward_core::fault!("err.sshBadLogin"));
        }
        let port = target.port.or(route.as_ref().and_then(|m| m.port)).unwrap_or(22);
        let key = public_key(entry)?;
        let pin = route
            .as_ref()
            .and_then(|m| m.hostkey.clone())
            .or_else(|| entry.field(crate::table::HOSTKEY).map(str::to_string));
        Ok(Plan {
            info: Info {
                id: session::new_id(),
                entry_id: entry.id.clone(),
                entry_name: entry.name.clone(),
                host,
                port,
                user,
                opened_at: session::opened_now(),
            },
            key,
            pin,
            confirm: true,
            cols: cols.clamp(2, 1000),
            rows: rows.clamp(1, 1000),
        })
    }

    /// The destinations to offer: routes that name a host, then hosts the
    /// terminal got into.
    fn targets(&self, view: &View<'_>) -> Vec<Target> {
        let mut out: Vec<Target> = view
            .table
            .mappings
            .iter()
            .filter(|m| !crate::glob::has_wildcard(&m.host))
            .map(|m| Target {
                entry_id: m.entry_id.clone(),
                entry_name: m.entry_name.clone(),
                host: m.host.clone(),
                port: m.port,
                user: m.user.clone(),
                pattern: m.pattern.clone(),
                recent: false,
            })
            .collect();
        let recent = self.recent.lock().map(|r| r.clone()).unwrap_or_default();
        for r in recent {
            let named = out.iter().any(|t| t.entry_id == r.entry_id && t.host == r.host && t.port.unwrap_or(22) == r.port && t.user.as_deref().is_none_or(|u| u == r.user));
            if named {
                continue;
            }
            let Some(entry) = view.entries.iter().find(|e| e.id == r.entry_id) else { continue };
            out.push(Target {
                entry_id: r.entry_id,
                entry_name: entry.name.clone(),
                host: r.host,
                port: Some(r.port),
                user: Some(r.user),
                pattern: String::new(),
                recent: true,
            });
        }
        out
    }

    /// What a health round checks: each key with a public half against each
    /// host it names, with the login the route gives or the one the terminal
    /// last got in with.
    fn plans(&self, view: &View<'_>, only: Option<&str>) -> Vec<health::Plan> {
        let recent = self.recent.lock().map(|r| r.clone()).unwrap_or_default();
        let mut plans = Vec::new();
        for e in view.entries.iter().filter(|e| e.public_key.is_some() || e.field(crate::table::HOST).is_some()) {
            if only.is_some_and(|id| id != e.id) {
                continue;
            }
            let key = public_key(e).ok();
            let routes: Vec<_> = view.table.mappings.iter().filter(|m| m.entry_id == e.id).collect();
            let mut targets = Vec::new();
            for m in routes.iter().filter(|m| !crate::glob::has_wildcard(&m.host)) {
                let port = m.port.unwrap_or(22);
                let user = m.user.clone().or_else(|| {
                    recent.iter().rev().find(|r| r.entry_id == e.id && r.host.eq_ignore_ascii_case(&m.host) && r.port == port).map(|r| r.user.clone())
                });
                targets.push(health::Target {
                    entry_id: e.id.clone(),
                    entry_name: e.name.clone(),
                    key: key.clone(),
                    host: m.host.clone(),
                    port,
                    user,
                    pin: m.hostkey.clone(),
                });
            }
            // Hosts a wildcard route led the terminal to.
            for r in recent.iter().filter(|r| r.entry_id == e.id) {
                if targets.iter().any(|t| t.host.eq_ignore_ascii_case(&r.host) && t.port == r.port) {
                    continue;
                }
                targets.push(health::Target {
                    entry_id: e.id.clone(),
                    entry_name: e.name.clone(),
                    key: key.clone(),
                    host: r.host.clone(),
                    port: r.port,
                    user: Some(r.user.clone()),
                    pin: e.field(crate::table::HOSTKEY).map(str::to_string),
                });
            }
            let idle = if routes.is_empty() { health::Status::Unbound } else { health::Status::Wildcard };
            plans.push(health::Plan { entry_id: e.id.clone(), entry_name: e.name.clone(), targets, idle });
        }
        plans
    }
}

/// The route for a destination. A person who typed no login still means the
/// route that names one — `alex@db` for `db` — as long as every login the
/// routes name for that host leads to one and the same key; otherwise the
/// login decides and has to be typed.
fn route_for(table: &MappingTable, host: &str, user: Option<&str>, port: Option<u16>) -> Option<crate::Mapping> {
    if let Some(r) = table.resolve(host, user, port) {
        return Some(r.mapping);
    }
    if user.is_some() {
        return None;
    }
    let mut logins: Vec<&str> = table
        .mappings
        .iter()
        .filter(|m| crate::glob::matches(&m.host, host) && m.port.is_none_or(|p| Some(p) == port.or(Some(22))))
        .filter_map(|m| m.user.as_deref())
        .collect();
    logins.sort_unstable();
    logins.dedup();
    let found: Vec<crate::Mapping> = logins.iter().filter_map(|u| table.resolve(host, Some(u), port)).map(|r| r.mapping).collect();
    let first = found.first()?;
    found.iter().all(|m| m.entry_id == first.entry_id).then(|| first.clone())
}

fn remember(recent: &Mutex<Vec<Recent>>, info: &Info) {
    let Ok(mut r) = recent.lock() else { return };
    let item = Recent { entry_id: info.entry_id.clone(), host: info.host.clone(), port: info.port, user: info.user.clone() };
    r.retain(|x| x != &item);
    r.push(item);
    let over = r.len().saturating_sub(RECENT);
    r.drain(..over);
}

fn public_key(entry: &VaultEntry) -> Result<russh::keys::PublicKey> {
    let raw = entry
        .public_key
        .as_deref()
        .map(str::trim)
        .filter(|k| !k.is_empty())
        .ok_or_else(|| keyward_core::fault!("err.sshNoPublicKey", "key" => entry.name.as_str()))?;
    russh::keys::PublicKey::from_openssh(raw).map_err(|_| keyward_core::fault!("err.sshNoPublicKey", "key" => entry.name.as_str()))
}

#[cfg(test)]
mod tests;
