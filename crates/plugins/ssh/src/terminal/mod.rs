//! The terminal: a shell on a server, reached with a key the vault holds, in a
//! section of the window.
//!
//! All of it lives in this plugin; the core routes calls and knows nothing of
//! terminals. The pieces:
//!
//! - `link`, `connect`, `hostkeys`, `sshconfig`, `probe` — the way to a server
//!   and the sealed link to the page, from `keyward-ssh-client`, which every
//!   plugin that goes to a server over ssh shares.
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
//! | `term_probe` | a host and a port: what system answers there | — |
//! | `term_config_hosts` | the hosts `~/.ssh/config` names | — |
//! | `health` | — | — |
//! | `health_run` | a key, or every key | — |
//!
//! Inside `term`, on the input lane: `open`, `attach`, `write`, `resize`,
//! `trust`, `close`; on the output lane: `read`.

pub mod health;
pub mod session;

pub use keyward_ssh_client::{connect, hostkeys, link, probe, sshconfig};

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
    /// The person's `~/.ssh/config`: real addresses behind aliases, logins,
    /// ports.
    pub ssh: &'a sshconfig::Config,
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
    /// The other names the same server goes by.
    pub aliases: Vec<String>,
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
struct ProbeArgs {
    host: String,
    #[serde(default)]
    port: Option<u16>,
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
            "term_probe" => match arg::<ProbeArgs>(payload) {
                Ok(a) => probe::banner(a.host.trim(), a.port.unwrap_or(22)).await.and_then(out),
                Err(e) => Err(e),
            },
            "term_config_hosts" => out(view.ssh.named()),
            "term_forget_host" => match arg::<ForgetArgs>(payload) {
                Ok(a) => {
                    let (h, port) = (a.host.trim(), a.port.unwrap_or(22));
                    match (store.forget(h, port), hostkeys::forget_in_items(host, h, port).await) {
                        (Ok(own), Ok(items)) => out(own + items),
                        (Err(e), _) | (_, Err(e)) => Err(e),
                    }
                }
                Err(e) => Err(e),
            },
            "health" => out(self.board.report(&self.plans(&view, None))),
            "health_run" => {
                let a: HealthArgs = if payload.is_null() { HealthArgs::default() } else { match arg(payload) {
                    Ok(a) => a,
                    Err(e) => return Some(Err(e)),
                } };
                // The round goes on in the background; the window watches the
                // board fill in rather than waiting on the slowest host.
                let plans = self.plans(&view, a.entry_id.as_deref());
                let board = Arc::clone(&self.board);
                let core = core.ok();
                let (started_tx, started_rx) = tokio::sync::oneshot::channel();
                tokio::spawn(async move {
                    let run = board.run(plans, store, core.clone());
                    tokio::pin!(run);
                    // Polled once so the round has marked what it checks
                    // before the answer goes out.
                    let first = futures_poll_once(run.as_mut()).await;
                    let _ = started_tx.send(());
                    let updates = match first {
                        Some(u) => u,
                        None => run.await,
                    };
                    apply(core, updates).await;
                });
                let _ = started_rx.await;
                out(self.board.report(&self.plans(&view, None)))
            }
            _ => return None,
        })
    }

    /// The health board over the keys as they are now: what the window's
    /// path is built from.
    pub fn health(&self, view: &View<'_>) -> health::Report {
        self.board.report(&self.plans(view, None))
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
    pub fn tick(self: &Arc<Self>, view: View<'_>, every: Duration, plugin_dir: &Path, core: Option<Arc<dyn Host>>) {
        if every.is_zero() || view.entries.is_empty() || !self.board.due(every) {
            return;
        }
        let plans = self.plans(&view, None);
        let store = hostkeys::Store::new(plugin_dir);
        let board = Arc::clone(&self.board);
        tokio::spawn(async move {
            let updates = board.run(plans, store, core.clone()).await;
            apply(core, updates).await;
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
                let mut plan = self.plan(view, target, cols, rows)?;
                let core = core?;
                let live = self.sessions.lock().map_err(|_| keyward_core::fault!("err.sshTerminalBroken"))?.values().filter(|s| !s.state().closed()).count();
                if live >= MAX_SESSIONS {
                    anyhow::bail!(keyward_core::fault!("err.sshTooManySessions", "max" => MAX_SESSIONS));
                }
                let recent = Arc::clone(&self.recent);
                let save = std::mem::take(&mut plan.save);
                let writer = Arc::clone(&core);
                let on_open: session::OnOpen = Box::new(move |info: &Info| {
                    remember(&recent, info);
                    if save.is_empty() {
                        return;
                    }
                    let entry_id = info.entry_id.clone();
                    tokio::spawn(async move {
                        if let Err(e) = writer.set_fields(&entry_id, save).await {
                            tracing::error!(entry = %entry_id, error = %e, "the login and port that worked were not saved to the item");
                        }
                    });
                });
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
        let conf = view.ssh.lookup(&host);
        if conf.proxy().is_some() {
            let via = conf.proxy_jump.clone().unwrap_or_else(|| "ProxyCommand".to_string());
            anyhow::bail!(keyward_core::fault!("err.sshProxyJumpUnsupported", "host" => host.as_str(), "jump" => via.as_str()));
        }
        if route.as_ref().is_some_and(|m| m.cert_role.is_some()) {
            anyhow::bail!(keyward_core::fault!("err.sshTerminalCertUnsupported", "key" => entry.name.as_str()));
        }
        let user = target
            .user
            .map(|u| u.trim().to_string())
            .filter(|u| !u.is_empty())
            .or_else(|| route.as_ref().and_then(|m| m.user.clone()))
            .or_else(|| crate::table::user_field(entry))
            .or_else(|| conf.user.clone())
            .ok_or_else(|| keyward_core::fault!("err.sshLoginRequired", "host" => host.as_str()))?;
        if user.contains(char::is_whitespace) {
            anyhow::bail!(keyward_core::fault!("err.sshBadLogin"));
        }
        let port = match target.port.or(route.as_ref().and_then(|m| m.port)) {
            Some(p) => p,
            None => crate::table::port_field(entry)?.or(conf.port).unwrap_or(22),
        };
        let address = conf.hostname.clone().unwrap_or_else(|| host.clone());
        let key = public_key(entry)?;
        // What worked is kept in the item's own fields, so the next shell and
        // the health checks know it — only where neither the route nor the
        // item says anything yet.
        let mut save = Vec::new();
        if route.as_ref().is_none_or(|m| m.user.is_none()) && crate::table::user_field(entry).is_none() {
            save.push((crate::table::USER.to_string(), user.clone()));
        }
        if port != 22 && route.as_ref().is_none_or(|m| m.port.is_none()) && entry.field(crate::table::PORT).is_none() {
            save.push((crate::table::PORT.to_string(), port.to_string()));
        }
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
                address,
                port,
                user,
                opened_at: session::opened_now(),
            },
            key,
            pin,
            confirm: true,
            cols: cols.clamp(2, 1000),
            rows: rows.clamp(1, 1000),
            save,
        })
    }

    /// The destinations to offer: one row per server a key reaches.
    fn targets(&self, view: &View<'_>) -> Vec<Target> {
        let recent = self.recent.lock().map(|r| r.clone()).unwrap_or_default();
        let mut out: Vec<Target> = Vec::new();
        for e in view.entries.iter() {
            for h in hosts_of(view, e, &recent) {
                // A name a health check found on a server already listed for
                // this key joins that row.
                if let Some(server) = self.board.server(&e.id, &h.host) {
                    let same = out
                        .iter_mut()
                        .find(|t| t.entry_id == e.id && self.board.server(&e.id, &t.host).as_ref() == Some(&server));
                    if let Some(t) = same {
                        for n in std::iter::once(h.host.clone()).chain(h.aliases) {
                            if !t.aliases.iter().any(|a| a.eq_ignore_ascii_case(&n)) {
                                t.aliases.push(n);
                            }
                        }
                        continue;
                    }
                }
                out.push(Target {
                    entry_id: e.id.clone(),
                    entry_name: e.name.clone(),
                    host: h.host,
                    port: Some(h.port),
                    user: h.user,
                    pattern: h.pattern,
                    recent: h.recent_only,
                    aliases: h.aliases,
                });
            }
        }
        out
    }

    /// What a health round checks: each key with a public half against each
    /// server it reaches — once per server, however many names it goes by.
    fn plans(&self, view: &View<'_>, only: Option<&str>) -> Vec<health::Plan> {
        let recent = self.recent.lock().map(|r| r.clone()).unwrap_or_default();
        let mut plans = Vec::new();
        for e in view.entries.iter().filter(|e| e.public_key.is_some() || e.field(crate::table::HOST).is_some()) {
            if only.is_some_and(|id| id != e.id) {
                continue;
            }
            let key = public_key(e).ok();
            let has_routes = view.table.mappings.iter().any(|m| m.entry_id == e.id);
            let targets = hosts_of(view, e, &recent)
                .into_iter()
                // A host behind a jump host or a proxy command cannot be
                // reached by the check.
                .filter(|h| !h.proxied)
                .map(|h| health::Target {
                    entry_id: e.id.clone(),
                    entry_name: e.name.clone(),
                    key: key.clone(),
                    host: h.host,
                    address: h.address,
                    port: h.port,
                    user: h.user,
                    pin: h.pin,
                    alt: h.alt,
                    save: h.save,
                    aliases: h.aliases,
                })
                .collect();
            let idle = if has_routes { health::Status::Wildcard } else { health::Status::Unbound };
            plans.push(health::Plan { entry_id: e.id.clone(), entry_name: e.name.clone(), targets, idle });
        }
        plans
    }
}

/// One server a key reaches, however many names it goes by.
struct HostRow {
    /// The name shown and connected to: a route's, when there is one.
    host: String,
    /// The other names of the same server.
    aliases: Vec<String>,
    address: String,
    user: Option<String>,
    port: u16,
    pin: Option<String>,
    pattern: String,
    /// Known only because the terminal got in there this run.
    recent_only: bool,
    proxied: bool,
    alt: Option<health::Alt>,
    save: Vec<(String, String)>,
}

/// Which server a name means: the `~/.ssh/config` block it belongs to — by
/// alias, by `HostName` or by the address that resolves to — or the name
/// itself.
fn server_of(view: &View<'_>, host: &str) -> String {
    view.ssh.lookup(host).alias.unwrap_or_else(|| host.to_string()).to_ascii_lowercase()
}

/// The servers a key reaches: its routes that name a host and the hosts the
/// terminal got into this run, grouped by server. `vps`, its `HostName` and
/// the address behind it are one row; two names that are two machines are
/// two.
fn hosts_of(view: &View<'_>, e: &VaultEntry, recent: &[Recent]) -> Vec<HostRow> {
    struct Group {
        server: String,
        names: Vec<String>,
        route: Option<crate::Mapping>,
        recent: Option<Recent>,
    }
    let mut groups: Vec<Group> = Vec::new();
    let mut add = |name: &str, route: Option<&crate::Mapping>, rec: Option<&Recent>| {
        let server = server_of(view, name);
        let g = match groups.iter_mut().find(|g| g.server == server) {
            Some(g) => g,
            None => {
                groups.push(Group { server, names: Vec::new(), route: None, recent: None });
                groups.last_mut().expect("just pushed")
            }
        };
        if !g.names.iter().any(|n| n.eq_ignore_ascii_case(name)) {
            g.names.push(name.to_string());
        }
        if g.route.is_none() {
            g.route = route.cloned();
        }
        if let Some(r) = rec {
            g.recent = Some(r.clone());
        }
    };
    for m in view.table.mappings.iter().filter(|m| m.entry_id == e.id && !crate::glob::has_wildcard(&m.host)) {
        add(&m.host, Some(m), None);
    }
    for r in recent.iter().filter(|r| r.entry_id == e.id) {
        add(&r.host, None, Some(r));
    }

    let own_user = crate::table::user_field(e);
    // A broken kw-port shows as none here; opening the shell says what is
    // wrong with it.
    let own_port = crate::table::port_field(e).ok().flatten();
    groups
        .into_iter()
        .map(|g| {
            let host = g.names[0].clone();
            let conf = view.ssh.lookup(&host);
            let route_user = g.route.as_ref().and_then(|m| m.user.clone());
            let route_port = g.route.as_ref().and_then(|m| m.port);
            let recent_user = g.recent.as_ref().map(|r| r.user.clone());
            let recent_port = g.recent.as_ref().map(|r| r.port);
            let user = route_user.clone().or_else(|| own_user.clone()).or(recent_user).or_else(|| conf.user.clone());
            let port = route_port.or(own_port).or(recent_port).or(conf.port).unwrap_or(22);
            // What the config says where it differs from the vault — but never
            // against a route's own login@ or :port, which is a rule for the
            // agent, not a guess.
            let alt_user = if route_user.is_none() { conf.user.clone().or(user.clone()) } else { user.clone() };
            let alt_port = if route_port.is_none() { conf.port.unwrap_or(port) } else { port };
            let alt = (alt_user != user || alt_port != port).then(|| health::Alt { user: alt_user, port: alt_port });
            // What came from the config because the vault had nothing is kept
            // once the server takes it.
            let mut save = Vec::new();
            if route_user.is_none() && own_user.is_none() {
                if let Some(u) = conf.user.clone().filter(|u| user.as_ref() == Some(u)) {
                    save.push((crate::table::USER.to_string(), u));
                }
            }
            if route_port.is_none() && own_port.is_none() && conf.port == Some(port) && port != 22 {
                save.push((crate::table::PORT.to_string(), port.to_string()));
            }
            HostRow {
                aliases: g.names[1..].to_vec(),
                address: conf.hostname.clone().unwrap_or_else(|| host.clone()),
                pin: g.route.as_ref().and_then(|m| m.hostkey.clone()).or_else(|| e.field(crate::table::HOSTKEY).map(str::to_string)),
                pattern: g.route.as_ref().map(|m| m.pattern.clone()).unwrap_or_default(),
                recent_only: g.route.is_none(),
                proxied: conf.proxy().is_some(),
                host,
                user,
                port,
                alt,
                save,
            }
        })
        .collect()
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

/// Polls a future once: `Some` when it finished on the spot.
async fn futures_poll_once<F: std::future::Future + Unpin>(mut f: F) -> Option<F::Output> {
    std::future::poll_fn(move |cx| match std::pin::Pin::new(&mut f).poll(cx) {
        std::task::Poll::Ready(v) => std::task::Poll::Ready(Some(v)),
        std::task::Poll::Pending => std::task::Poll::Ready(None),
    })
    .await
}

/// Writes what a health round proved: `~/.ssh/config` got in where the vault's
/// login or port did not, so the vault takes it.
async fn apply(core: Option<Arc<dyn Host>>, updates: Vec<health::Update>) {
    if updates.is_empty() {
        return;
    }
    let Some(core) = core else {
        tracing::error!("~/.ssh/config was proved right but there is no core to write it with");
        return;
    };
    for (entry_id, fields) in updates {
        if let Err(e) = core.set_fields(&entry_id, fields).await {
            tracing::error!(entry = %entry_id, error = %e, "the item was not updated from ~/.ssh/config");
        }
    }
}

fn remember(recent: &Mutex<Vec<Recent>>, info: &Info) {
    let Ok(mut r) = recent.lock() else { return };
    let item = Recent { entry_id: info.entry_id.clone(), host: info.host.clone(), port: info.port, user: info.user.clone() };
    // One per key and name: the latest login and port that worked replace the
    // earlier ones rather than lining up beside them.
    r.retain(|x| !(x.entry_id == item.entry_id && x.host.eq_ignore_ascii_case(&item.host)));
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
