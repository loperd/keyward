//! The Kubernetes plugin. A cluster comes from one of its sources:
//!
//! - a kubeconfig kept in the vault: a note with the `kw-kubeconfig` field,
//!   pasted in or imported from `~/.kube/config` (its files put inline, so the
//!   note stands on its own);
//! - a server the vault's keys reach over ssh, found there without anyone
//!   looking for a kubeconfig — only a server whose login, host and port are
//!   set up and which lets the login in;
//! - clouds (EKS and the like) are next, as sources of the same rank.
//!
//! ssh is one source, not the base: the plugin goes to a server through the
//! same library the ssh plugin uses (`keyward-ssh-client`) and needs no other
//! plugin installed; what the two share at run time is the vault — the routes
//! in `kw-host` and the host keys a person confirmed in `kw-knownhosts`.
//!
//! - `detect` — which kubeconfigs a server holds, and the commands that read
//!   them.
//! - `kubeconfig` — the one context used, checked before anything is built.
//! - `tunnel` — the API reached through the ssh session.
//! - `resources` — what of a cluster is shown.
//!
//! Finding a cluster logs in, and a login is a signature the person makes
//! with their finger. So nothing is looked for in the background: a round
//! over every server starts at the person's word (`scan`), and one server is
//! looked at when the person opens it (`scan` with `only`). What was found —
//! where, which kind, whether sudo is needed; nothing secret — is kept in the
//! plugin's settings. The kubeconfig itself is read when a cluster is opened,
//! held in memory while it is open and never written anywhere.
//!
//! The operations:
//!
//! | op | payload | sealed |
//! |---|---|---|
//! | `overview` | — | — |
//! | `scan` | `{only?: {entry_id, host, port}, trust?: fingerprint}` | — |
//! | `forget` | `{place}` | — |
//! | `import_local` | `{context?, name?}`: `~/.kube/config` into a note | — |
//! | `ui_link` | the window's public key | — |
//! | `ui` | a sealed declared request: `nav`, `view`, `act` | yes |
//!
//! The screens are declared (`ui`): the window draws them with its own kit.
//! Their actions reach the engine — `open`, `state`, `close`, `list`,
//! `manifest`, `logs`; `apply` (a dry run first, then for real), `delete`,
//! `scale`, `restart`; the pods' shells; and `add` — a pasted kubeconfig,
//! which is a secret and travels sealed like everything on that road.

pub mod detect;
pub mod exec;
pub mod kubeconfig;
mod places;
pub mod resources;
pub mod templates;
pub mod tunnel;
mod ui;

use std::collections::HashMap;
use std::sync::{Arc, Mutex, RwLock};
use std::time::{Duration, SystemTime, UNIX_EPOCH};

use keyward_plugin::{arg, out, Host, HostEvent, Manifest, Origin, Permission, Plugin, Result, SecretField};
use keyward_ssh_client::connect::{AskTrust, Guard, HostPrompt};
use keyward_ssh_client::hostkeys::Store;
use keyward_ssh_client::remote;
use keyward_ssh_client::targets::{self, Machine};
use keyward_ssh_client::{sshconfig, table};
use russh::client::Handle;
use serde::{Deserialize, Serialize};
use serde_json::Value;
use zeroize::Zeroizing;

use detect::Found;
use kubeconfig::{Origin as From, Summary};
use resources::Kind as ResourceKind;

/// The field of a note that holds a kubeconfig.
pub const KUBECONFIG_FIELD: &str = "kw-kubeconfig";

/// A kubeconfig is small; one bigger than this is not one.
const KUBECONFIG_MAX: usize = 256 * 1024;

/// How long the detection script and a read may take.
const COMMAND: Duration = Duration::from_secs(20);

/// How long one API request may take: well inside the daemon's thirty seconds.
const REQUEST: Duration = Duration::from_secs(20);

fn now() -> u64 {
    SystemTime::now().duration_since(UNIX_EPOCH).map(|d| d.as_secs()).unwrap_or(0)
}

// -- What was found -----------------------------------------------------------

/// A server, by the key that reaches it.
#[derive(Debug, Clone, PartialEq, Eq, Hash, Serialize, Deserialize)]
pub struct Place {
    pub entry_id: String,
    pub host: String,
    pub port: u16,
}

impl Place {
    fn of(m: &Machine) -> Self {
        Self { entry_id: m.entry_id.clone(), host: m.host.clone(), port: m.port }
    }
}

/// How the last look at a server went.
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(tag = "status", rename_all = "snake_case")]
pub enum Look {
    /// Logged in and ran the script; `found` — the masters there — may be
    /// empty.
    Seen {
        found: Vec<Found>,
        at: u64,
        /// `/etc/machine-id`.
        #[serde(default)]
        machine: Option<String>,
        #[serde(default)]
        peer: Option<String>,
    },
    /// Let the login in but ran no script: a server that takes commands of
    /// its own only, a git host. It has no cluster to look for.
    CommandOnly {
        at: u64,
        #[serde(default)]
        peer: Option<String>,
    },
    /// The host key is not trusted yet: the person is shown the fingerprint
    /// and asked with `trust`.
    HostUnknown {
        fingerprint: String,
        algorithm: String,
        at: u64,
        #[serde(default)]
        peer: Option<String>,
    },
    Failed {
        error: String,
        at: u64,
        #[serde(default)]
        peer: Option<String>,
    },
}

impl Look {
    /// Where the name led, `ip:port`: two names that lead to one place are
    /// one server.
    fn peer(&self) -> Option<&str> {
        match self {
            Self::Seen { peer, .. } | Self::CommandOnly { peer, .. } | Self::HostUnknown { peer, .. } | Self::Failed { peer, .. } => peer.as_deref(),
        }
    }

    /// How much a look says, to pick the one a merged row shows.
    fn rank(&self) -> u8 {
        match self {
            Self::Seen { .. } => 4,
            Self::CommandOnly { .. } => 3,
            Self::HostUnknown { .. } => 2,
            Self::Failed { .. } => 1,
        }
    }
}

/// What the plugin keeps in its settings: where it looked and what it saw.
/// Nothing in it is secret.
#[derive(Debug, Default, Serialize, Deserialize)]
struct Remembered {
    /// The format: looks made before masters alone counted — when any
    /// kubeconfig lying on a server was one — are of an older one.
    #[serde(default)]
    version: u32,
    #[serde(default)]
    looks: Vec<(Place, Look)>,
}

/// The current format of what the plugin keeps.
const REMEMBERED: u32 = 2;

impl Remembered {
    fn from(v: Value) -> anyhow::Result<Self> {
        if v.is_null() {
            return Ok(Self { version: REMEMBERED, ..Self::default() });
        }
        // Looks of an older format are what a scan found, not anything a
        // person wrote: they are dropped, with a word in the log, and the
        // next scan finds them again the new way.
        if v.get("version").and_then(Value::as_u64) != Some(u64::from(REMEMBERED)) {
            tracing::info!("the scan results of an older format were dropped; look at the servers again");
            return Ok(Self { version: REMEMBERED, ..Self::default() });
        }
        serde_json::from_value(v).map_err(|e| anyhow::anyhow!("the plugin's settings will not read: {e}"))
    }

    fn read(host: &dyn Host) -> anyhow::Result<Self> {
        Self::from(host.settings())
    }

    fn write(&self, host: &dyn Host) -> anyhow::Result<()> {
        host.set_settings(serde_json::to_value(Self { version: REMEMBERED, looks: self.looks.clone() })?)
    }

    /// The same, from a task on the runtime: see `keyward_ssh_client::core`.
    async fn read_async(core: &Arc<dyn Host>) -> anyhow::Result<Self> {
        Self::from(keyward_ssh_client::core::settings(core).await?)
    }

    async fn write_async(&self, core: &Arc<dyn Host>) -> anyhow::Result<()> {
        keyward_ssh_client::core::set_settings(core, serde_json::to_value(Self { version: REMEMBERED, looks: self.looks.clone() })?).await
    }

    fn set(&mut self, place: Place, look: Look) {
        self.looks.retain(|(p, _)| p != &place);
        self.looks.push((place, look));
    }
}

// -- The overview -------------------------------------------------------------

#[derive(Serialize)]
pub(crate) struct ServerRow {
    #[serde(flatten)]
    pub(crate) machine: Machine,
    pub(crate) look: Option<Look>,
    /// Being looked at right now.
    pub(crate) looking: bool,
    /// The other names the same server goes by: one machine, one row.
    pub(crate) aliases: Vec<String>,
}

/// One machine under several names is one row: by its `/etc/machine-id`
/// once it was looked at, before that by the address its name led to.
fn merge(rows: Vec<ServerRow>) -> Vec<ServerRow> {
    let key = |r: &ServerRow| -> String {
        match &r.look {
            Some(Look::Seen { machine: Some(m), .. }) => format!("machine {m}"),
            Some(l) => l.peer().map(|p| format!("peer {p}")).unwrap_or_else(|| format!("name {}|{}|{}", r.machine.entry_id, r.machine.host, r.machine.port)),
            None => format!("name {}|{}|{}", r.machine.entry_id, r.machine.host, r.machine.port),
        }
    };
    let rank = |r: &ServerRow| r.look.as_ref().map(Look::rank).unwrap_or(0);
    let peer_of = |r: &ServerRow| r.look.as_ref().and_then(Look::peer).map(str::to_string);
    let mut out: Vec<(String, ServerRow)> = Vec::new();
    for row in rows {
        let k = key(&row);
        let peer = peer_of(&row);
        // The same address also joins a machine already known by its id.
        let at = out.iter().position(|(ok, o)| *ok == k || (peer.is_some() && peer_of(o) == peer));
        let Some(i) = at else {
            out.push((k, row));
            continue;
        };
        let (ok, into) = out.remove(i);
        // The row that says most stands for the machine; the others lend it
        // their names.
        let (mut keep, other) = if rank(&row) > rank(&into) { (row, into) } else { (into, row) };
        keep.looking |= other.looking;
        for a in std::iter::once(other.machine.host).chain(other.aliases) {
            if !a.eq_ignore_ascii_case(&keep.machine.host) && !keep.aliases.iter().any(|x| x.eq_ignore_ascii_case(&a)) {
                keep.aliases.push(a);
            }
        }
        out.insert(i, (ok, keep));
    }
    out.into_iter().map(|(_, r)| r).collect()
}

/// A kubeconfig kept in the vault.
#[derive(Serialize)]
pub(crate) struct NoteRow {
    pub(crate) id: String,
    pub(crate) entry_id: String,
    pub(crate) name: String,
}

#[derive(Serialize)]
pub(crate) struct Overview {
    pub(crate) servers: Vec<ServerRow>,
    pub(crate) notes: Vec<NoteRow>,
    /// The contexts of `~/.kube/config`, for importing one; names only.
    pub(crate) local_contexts: Vec<String>,
    /// Why `~/.kube/config` could not be read, when it could not.
    pub(crate) local_error: Option<String>,
    /// What in the vault could not be read.
    pub(crate) broken: Vec<String>,
    pub(crate) scanning: bool,
}

// -- Open clusters ------------------------------------------------------------

/// A cluster by name: `ssh|<entry>|<host>|<port>|<kind>` or `note|<entry>`.
#[derive(Debug, Clone, PartialEq, Eq)]
enum ClusterId {
    Remote { place: Place, kind: detect::Kind },
    Note { entry_id: String },
}

impl ClusterId {
    fn parse(id: &str) -> anyhow::Result<Self> {
        let parts: Vec<&str> = id.split('|').collect();
        let bad = || keyward_core::fault!("err.kubeNoCluster");
        match parts.as_slice() {
            ["ssh", entry, host, port, kind] => Ok(Self::Remote {
                place: Place { entry_id: (*entry).to_string(), host: (*host).to_string(), port: port.parse().map_err(|_| bad())? },
                kind: serde_json::from_value(Value::String((*kind).to_string())).map_err(|_| bad())?,
            }),
            ["note", entry] if !entry.is_empty() => Ok(Self::Note { entry_id: (*entry).to_string() }),
            _ => Err(bad()),
        }
    }
}

enum State {
    Opening,
    Open { client: kube::Client, summary: Summary, _session: Option<Arc<Handle<Guard>>> },
    Failed(String),
}

#[derive(Serialize)]
#[serde(tag = "state", rename_all = "snake_case")]
enum StateOut<'a> {
    Closed,
    Opening,
    Open { summary: &'a Summary },
    Failed { error: &'a str },
}

// -- The plugin ---------------------------------------------------------------

#[derive(Default)]
struct Inner {
    /// The declared screens' sealed road to the window.
    ui: keyward_ui::UiServer,
    clusters: Mutex<HashMap<String, State>>,
    looking: Mutex<Vec<Place>>,
    scanning: Mutex<bool>,
    /// The pods' shells, by the id the page holds.
    shells: Mutex<HashMap<String, Arc<exec::Shell>>>,
}

pub struct KubePlugin {
    core: RwLock<Option<Arc<dyn Host>>>,
    inner: Arc<Inner>,
}

impl Default for KubePlugin {
    fn default() -> Self {
        Self::new()
    }
}

fn broken() -> anyhow::Error {
    keyward_core::fault!("err.kubeBroken")
}

impl KubePlugin {
    pub fn new() -> Self {
        Self { core: RwLock::new(None), inner: Arc::new(Inner::default()) }
    }

    fn core(&self) -> Result<Arc<dyn Host>> {
        self.core
            .read()
            .ok()
            .and_then(|c| c.clone())
            .ok_or_else(|| anyhow::anyhow!("the plugin is not attached to a core: there is nobody to sign"))
    }

    fn overview(&self, host: &dyn Host) -> Result<Value> {
        out(self.gather(host)?)
    }

    /// Everything the servers' screen shows.
    pub(crate) fn gather(&self, host: &dyn Host) -> Result<Overview> {
        let entries = host.entries();
        let (routes, _) = table::build_table(&entries);
        let ssh = sshconfig::Config::load()?;
        let machines = targets::machines(&entries, &routes, &ssh);
        let remembered = Remembered::read(host)?;
        let looking = self.inner.looking.lock().map_err(|_| broken())?.clone();
        let servers = machines
            .list
            .into_iter()
            .map(|m| {
                let place = Place::of(&m);
                ServerRow {
                    look: remembered.looks.iter().find(|(p, _)| p == &place).map(|(_, l)| l.clone()),
                    looking: looking.contains(&place),
                    machine: m,
                    aliases: Vec::new(),
                }
            })
            .collect();
        let servers = merge(servers);
        let notes = host
            .tagged_items(KUBECONFIG_FIELD)
            .into_iter()
            .map(|i| NoteRow { id: format!("note|{}", i.id), entry_id: i.id, name: i.name })
            .collect();
        let (local_contexts, local_error) = match local_contexts() {
            Ok(names) => (names, None),
            Err(e) => (Vec::new(), Some(e.to_string())),
        };
        Ok(Overview {
            servers,
            notes,
            local_contexts,
            local_error,
            broken: machines.broken.iter().map(ToString::to_string).collect(),
            scanning: *self.inner.scanning.lock().map_err(|_| broken())?,
        })
    }

    /// Starts a look at every server, or at one. It goes on in the background,
    /// one server after another — each asks for the person's finger, and two
    /// at once would be two questions at once — and the window watches the
    /// overview fill in.
    fn scan(&self, host: &dyn Host, payload: Value) -> Result<Value> {
        #[derive(Deserialize, Default)]
        struct Args {
            #[serde(default)]
            only: Option<Place>,
            #[serde(default)]
            trust: Option<String>,
        }
        let a: Args = if payload.is_null() { Args::default() } else { arg(payload)? };
        let core = self.core()?;
        let entries = host.entries();
        let (routes, _) = table::build_table(&entries);
        let ssh = sshconfig::Config::load()?;
        let machines: Vec<Machine> = targets::machines(&entries, &routes, &ssh)
            .list
            .into_iter()
            // Only what is set up: a server without a login or a port is not a
            // place to look, whatever the person asks.
            .filter(|m| m.proxy.is_none() && m.missing.is_empty())
            .filter(|m| a.only.as_ref().is_none_or(|p| p == &Place::of(m)))
            .collect();
        if a.only.is_some() && machines.is_empty() {
            anyhow::bail!(keyward_core::fault!("err.kubeNoServer"));
        }
        {
            let mut scanning = self.inner.scanning.lock().map_err(|_| broken())?;
            if *scanning {
                anyhow::bail!(keyward_core::fault!("err.kubeScanRunning"));
            }
            *scanning = true;
        }
        let inner = Arc::clone(&self.inner);
        let store = Store::new(&host.state_dir());
        tokio::spawn(async move {
            for m in machines {
                let place = Place::of(&m);
                if let Ok(mut l) = inner.looking.lock() {
                    l.push(place.clone());
                }
                let look = look_at(&m, &entries, store.clone(), Arc::clone(&core), a.trust.clone()).await;
                let saved = match Remembered::read_async(&core).await {
                    Ok(mut r) => {
                        r.set(place.clone(), look);
                        r.write_async(&core).await
                    }
                    Err(e) => Err(e),
                };
                if let Err(e) = saved {
                    tracing::error!(error = %e, "what a look at a server found was not kept");
                }
                if let Ok(mut l) = inner.looking.lock() {
                    l.retain(|p| p != &place);
                }
            }
            if let Ok(mut s) = inner.scanning.lock() {
                *s = false;
            }
        });
        self.overview(host)
    }

    /// `~/.kube/config`'s context into a note of its own: the context alone,
    /// with every file it names read here and put inline, so the note needs
    /// nothing outside the vault.
    async fn import_local(&self, host: &dyn Host, payload: Value) -> Result<Value> {
        #[derive(Deserialize, Default)]
        struct Args {
            #[serde(default)]
            context: Option<String>,
            #[serde(default)]
            name: Option<String>,
        }
        let a: Args = if payload.is_null() { Args::default() } else { arg(payload)? };
        let text = Zeroizing::new(read_local()?);
        let mut chosen = kubeconfig::choose(kubeconfig::parse(&text)?, a.context.as_deref())?;
        for (slot, path) in kubeconfig::files(&chosen) {
            let path = expand_home(&path);
            let bytes = Zeroizing::new(std::fs::read(&path).map_err(|e| {
                tracing::error!(path = %path.display(), error = %e, "a file the local kubeconfig names will not read");
                keyward_core::fault!("err.kubeLocalFileUnreadable", "path" => path.display().to_string())
            })?);
            kubeconfig::inline(&mut chosen, &slot, bytes);
        }
        let name = a.name.filter(|n| !n.trim().is_empty()).unwrap_or_else(|| chosen.summary.context.clone());
        save_note(host, &name, chosen).await?;
        self.overview(host)
    }

    fn forget(&self, host: &dyn Host, payload: Value) -> Result<Value> {
        #[derive(Deserialize)]
        struct Args {
            place: Place,
        }
        let a: Args = arg(payload)?;
        let mut r = Remembered::read(host)?;
        r.looks.retain(|(p, _)| p != &a.place);
        r.write(host)?;
        self.overview(host)
    }

    async fn run(&self, host: &dyn Host, op: Op) -> Result<Value> {
        match op {
            Op::Open { cluster } => {
                ClusterId::parse(&cluster)?;
                {
                    let mut clusters = self.inner.clusters.lock().map_err(|_| broken())?;
                    if matches!(clusters.get(&cluster), Some(State::Opening | State::Open { .. })) {
                        return self.state(&cluster);
                    }
                    clusters.insert(cluster.clone(), State::Opening);
                }
                let core = self.core()?;
                let inner = Arc::clone(&self.inner);
                let store = Store::new(&host.state_dir());
                let id = cluster.clone();
                // Opening may wait on the person's finger: in the background,
                // and the page asks for the state.
                tokio::spawn(async move {
                    let state = match open(&id, core, store).await {
                        Ok((client, summary, session)) => State::Open { client, summary, _session: session },
                        Err(e) => {
                            // Which cluster and why, for the log; nothing secret is in either.
                            tracing::warn!(cluster = %id, error = %e, "a cluster did not open");
                            State::Failed(e.to_string())
                        }
                    };
                    if let Ok(mut c) = inner.clusters.lock() {
                        // Closed meanwhile: it stays closed.
                        if matches!(c.get(&id), Some(State::Opening)) {
                            c.insert(id, state);
                        }
                    }
                });
                self.state(&cluster)
            }
            Op::State { cluster } => self.state(&cluster),
            Op::Close { cluster } => {
                self.inner.clusters.lock().map_err(|_| broken())?.remove(&cluster);
                out(StateOut::Closed)
            }
            Op::List { cluster, kind, namespace } => {
                let client = self.client(&cluster)?;
                let rows = within(resources::list(&client, kind, namespace.as_deref())).await?;
                out(rows)
            }
            Op::Manifest { cluster, kind, namespace, name } => {
                let client = self.client(&cluster)?;
                let yaml = within(resources::manifest(&client, kind, namespace.as_deref(), &name)).await?;
                out(serde_json::json!({ "yaml": yaml }))
            }
            Op::Logs { cluster, namespace, pod, container, tail } => {
                let client = self.client(&cluster)?;
                let text = within(resources::logs(&client, &namespace, &pod, container, tail.unwrap_or(500))).await?;
                out(serde_json::json!({ "text": text }))
            }
            Op::Apply { cluster, yaml, namespace, dry_run } => {
                let client = self.client(&cluster)?;
                let yaml = Zeroizing::new(yaml);
                let applied = within(resources::apply(&client, &yaml, namespace.as_deref(), dry_run)).await?;
                if !dry_run {
                    tracing::info!(kind = ?applied.kind, name = %applied.name, "a manifest was applied");
                }
                out(applied)
            }
            Op::Delete { cluster, kind, namespace, name } => {
                let client = self.client(&cluster)?;
                within(resources::delete(&client, kind, namespace.as_deref(), &name)).await?;
                tracing::info!(?kind, name = %name, "an object was deleted");
                out(serde_json::json!({ "done": true }))
            }
            Op::Scale { cluster, kind, namespace, name, replicas } => {
                let client = self.client(&cluster)?;
                within(resources::scale(&client, kind, &namespace, &name, replicas)).await?;
                out(serde_json::json!({ "done": true }))
            }
            Op::Restart { cluster, kind, namespace, name } => {
                let client = self.client(&cluster)?;
                within(resources::restart(&client, kind, &namespace, &name)).await?;
                out(serde_json::json!({ "done": true }))
            }
            Op::ShellOpen { cluster, namespace, pod, container, cols, rows } => {
                let client = self.client(&cluster)?;
                let mut shells = self.inner.shells.lock().map_err(|_| broken())?;
                shells.retain(|_, s| !matches!(s.state(), exec::State::Closed { .. }));
                if shells.len() >= 16 {
                    anyhow::bail!(keyward_core::fault!("err.kubeTooManyShells"));
                }
                let id = shell_id();
                shells.insert(id.clone(), exec::Shell::start(client, &namespace, &pod, container, cols, rows));
                out(serde_json::json!({ "shell": id }))
            }
            Op::ShellWrite { shell, data } => {
                use base64::Engine as _;
                let bytes = Zeroizing::new(
                    base64::engine::general_purpose::STANDARD.decode(data.as_bytes()).map_err(|_| keyward_core::fault!("err.kubeShellBroken", "reason" => "bad input"))?,
                );
                self.shell(&shell)?.write(bytes)?;
                out(Value::Null)
            }
            Op::ShellResize { shell, cols, rows } => {
                self.shell(&shell)?.resize(cols, rows)?;
                out(Value::Null)
            }
            Op::ShellClose { shell } => {
                if let Some(s) = self.inner.shells.lock().map_err(|_| broken())?.remove(&shell) {
                    s.close();
                }
                out(Value::Null)
            }
            Op::ShellRead { shell, cursor, wait_ms } => {
                let s = self.shell(&shell)?;
                let wait = Duration::from_millis(wait_ms).min(exec::READ_WAIT_MAX);
                out(s.read(cursor, wait).await)
            }
            Op::Add { name, yaml } => {
                let yaml = Zeroizing::new(yaml);
                let chosen = kubeconfig::choose(kubeconfig::parse(&yaml)?, None)?;
                save_note(host, &name, chosen).await?;
                out(serde_json::json!({ "saved": true }))
            }
        }
    }

    fn state(&self, cluster: &str) -> Result<Value> {
        let clusters = self.inner.clusters.lock().map_err(|_| broken())?;
        out(match clusters.get(cluster) {
            None => StateOut::Closed,
            Some(State::Opening) => StateOut::Opening,
            Some(State::Open { summary, .. }) => StateOut::Open { summary },
            Some(State::Failed(e)) => StateOut::Failed { error: e },
        })
    }

    fn shell(&self, id: &str) -> Result<Arc<exec::Shell>> {
        self.inner
            .shells
            .lock()
            .map_err(|_| broken())?
            .get(id)
            .cloned()
            .ok_or_else(|| keyward_core::fault!("err.kubeShellClosed"))
    }

    fn client(&self, cluster: &str) -> Result<kube::Client> {
        match self.inner.clusters.lock().map_err(|_| broken())?.get(cluster) {
            Some(State::Open { client, .. }) => Ok(client.clone()),
            _ => anyhow::bail!(keyward_core::fault!("err.kubeNotOpen")),
        }
    }

    /// Everything that lived on the vault's keys comes down.
    fn lock(&self) {
        self.inner.ui.lock();
        if let Ok(mut c) = self.inner.clusters.lock() {
            c.clear();
        }
        if let Ok(mut s) = self.inner.shells.lock() {
            for (_, shell) in s.drain() {
                shell.close();
            }
        }
    }
}

/// A request inside `kube`. Not `Debug`: nothing in it is secret, but its
/// answers are, and the habit is kept.
#[derive(Deserialize)]
#[serde(tag = "op", rename_all = "snake_case")]
enum Op {
    Open { cluster: String },
    State { cluster: String },
    Close { cluster: String },
    List { cluster: String, kind: ResourceKind, #[serde(default)] namespace: Option<String> },
    Manifest { cluster: String, kind: ResourceKind, #[serde(default)] namespace: Option<String>, name: String },
    Logs { cluster: String, namespace: String, pod: String, #[serde(default)] container: Option<String>, #[serde(default)] tail: Option<i64> },
    /// A pasted kubeconfig, kept as a note.
    Add { name: String, yaml: String },
    /// A manifest applied server side; `dry_run` first, always, from the window.
    Apply { cluster: String, yaml: String, #[serde(default)] namespace: Option<String>, dry_run: bool },
    Delete { cluster: String, kind: ResourceKind, #[serde(default)] namespace: Option<String>, name: String },
    Scale { cluster: String, kind: ResourceKind, namespace: String, name: String, replicas: i32 },
    Restart { cluster: String, kind: ResourceKind, namespace: String, name: String },
    /// A shell in a pod's container; on the input lane.
    ShellOpen { cluster: String, namespace: String, pod: String, #[serde(default)] container: Option<String>, cols: u16, rows: u16 },
    /// Keystrokes, base64. Not `Debug`: they may be a password.
    ShellWrite { shell: String, data: String },
    ShellResize { shell: String, cols: u16, rows: u16 },
    ShellClose { shell: String },
    /// Output since the cursor; on the output lane, a long poll.
    ShellRead { shell: String, cursor: u64, #[serde(default)] wait_ms: u64 },
}

fn shell_id() -> String {
    let mut b = [0u8; 12];
    rand_core::RngCore::fill_bytes(&mut rand_core::OsRng, &mut b);
    b.iter().map(|x| format!("{x:02x}")).collect()
}

/// Keeps the chosen context as a note: checked first as any note is when it is
/// opened — it may name no file and run nothing — so that what is saved will
/// open.
async fn save_note(host: &dyn Host, name: &str, chosen: kubeconfig::Chosen) -> anyhow::Result<()> {
    kubeconfig::check(&chosen, From::Remote)?;
    let name = name.trim();
    if name.is_empty() {
        anyhow::bail!(keyward_core::fault!("err.kubeNoName"));
    }
    let yaml = Zeroizing::new(
        serde_saphyr::to_string(&chosen.config).map_err(|e| anyhow::anyhow!("the kubeconfig will not turn into YAML: {e}"))?,
    );
    host.create_note(name, vec![(KUBECONFIG_FIELD.to_string(), yaml.to_string())], false).await?;
    Ok(())
}

/// `~/…` as a kubeconfig writes a path.
fn expand_home(path: &str) -> std::path::PathBuf {
    match (path.strip_prefix("~/"), std::env::home_dir()) {
        (Some(rest), Some(home)) => home.join(rest),
        _ => std::path::PathBuf::from(path),
    }
}

async fn within<T>(work: impl std::future::Future<Output = anyhow::Result<T>>) -> anyhow::Result<T> {
    match tokio::time::timeout(REQUEST, work).await {
        Ok(done) => done,
        Err(_) => anyhow::bail!(keyward_core::fault!("err.kubeTimedOut", "seconds" => REQUEST.as_secs())),
    }
}

/// Logs in to one server and runs the detection script.
///
/// An unknown host is not asked about here: the look stops at its key, before
/// anything is signed, and says so with the fingerprint. The person sees it
/// and, on a yes, looks again with `trust` — which lets in exactly that key
/// and no other.
async fn look_at(m: &Machine, entries: &[keyward_plugin::VaultEntry], store: Store, core: Arc<dyn Host>, trust: Option<String>) -> Look {
    let at = now();
    // Where the name leads, before anything else: it tells two names of one
    // machine apart from two machines even when the login fails.
    let peer = match tokio::net::lookup_host((m.address.as_str(), m.port)).await {
        Ok(mut addrs) => addrs.next().map(|a| a.to_string()),
        Err(_) => None,
    };
    let failed = |e: anyhow::Error| Look::Failed { error: e.to_string(), at, peer: peer.clone() };
    let Some(entry) = entries.iter().find(|e| e.id == m.entry_id) else {
        return failed(keyward_core::fault!("err.sshKeyGone"));
    };
    let login = match m.login(entry) {
        Ok(l) => l,
        Err(e) => return failed(e),
    };
    let offered: Arc<Mutex<Option<HostPrompt>>> = Arc::new(Mutex::new(None));
    let slot = Arc::clone(&offered);
    let ask: AskTrust = Arc::new(move |prompt: HostPrompt| {
        let yes = trust.as_deref() == Some(prompt.fingerprint.as_str());
        if let Ok(mut s) = slot.lock() {
            *s = Some(prompt);
        }
        let (tx, rx) = tokio::sync::oneshot::channel();
        let _ = tx.send(yes);
        rx
    });
    let handle = match remote::login(&login, store, core, Some(ask)).await {
        Ok(h) => h,
        Err(e) => {
            return match offered.lock().ok().and_then(|p| p.clone()) {
                Some(p) if e.to_string().starts_with("err.sshHostKeyDeclined") => {
                    Look::HostUnknown { fingerprint: p.fingerprint, algorithm: p.algorithm, at, peer: peer.clone() }
                }
                _ => failed(e),
            }
        }
    };
    let found = match remote::exec(&handle, &login.host, detect::SCRIPT, 16 * 1024, COMMAND).await {
        Ok(o) => detect::parse(&String::from_utf8_lossy(&o.stdout)),
        Err(e) => Err(e),
    };
    match found {
        Ok(Some(d)) => Look::Seen { found: d.found, at, machine: d.machine, peer },
        Ok(None) => Look::CommandOnly { at, peer },
        Err(e) => failed(e),
    }
}

/// Opens a cluster: reads its kubeconfig, checks it, builds a client.
async fn open(id: &str, core: Arc<dyn Host>, store: Store) -> anyhow::Result<(kube::Client, Summary, Option<Arc<Handle<Guard>>>)> {
    match ClusterId::parse(id)? {
        ClusterId::Note { entry_id } => {
            let text = Zeroizing::new(core.secret(&entry_id, SecretField::Custom(KUBECONFIG_FIELD.to_string())).await?);
            let chosen = kubeconfig::choose(kubeconfig::parse(&text)?, None)?;
            // A note stands on its own: no file, nothing to run.
            kubeconfig::check(&chosen, From::Remote)?;
            let summary = chosen.summary.clone();
            let client = tunnel::client(chosen, None).await?;
            within(async { client.apiserver_version().await.map_err(|e| resources::api_error("version", e)) }).await?;
            Ok((client, summary, None))
        }
        ClusterId::Remote { place, kind } => {
            let remembered = Remembered::read_async(&core).await?;
            let access = remembered
                .looks
                .iter()
                .find(|(p, _)| p == &place)
                .and_then(|(_, l)| match l {
                    Look::Seen { found, .. } => found.iter().find(|f| f.kind == kind).map(|f| f.access),
                    _ => None,
                })
                .ok_or_else(|| keyward_core::fault!("err.kubeNoCluster"))?;
            let entries = keyward_ssh_client::core::entries(&core).await?;
            let (routes, _) = table::build_table(&entries);
            let ssh = sshconfig::Config::load()?;
            let machine = targets::machines(&entries, &routes, &ssh)
                .list
                .into_iter()
                .find(|m| Place::of(m) == place)
                .ok_or_else(|| keyward_core::fault!("err.kubeNoServer"))?;
            let entry = entries.iter().find(|e| e.id == place.entry_id).ok_or_else(|| keyward_core::fault!("err.sshKeyGone"))?;
            let login = machine.login(entry)?;
            let handle = Arc::new(remote::login(&login, store, core, None).await?);
            let config = read_remote(&handle, &login.host, &detect::read_command(kind, access)?).await?;
            let mut chosen = kubeconfig::choose(kubeconfig::parse(&String::from_utf8_lossy(&config))?, detect::context_of(kind))?;
            drop(config);
            for (slot, path) in kubeconfig::files(&chosen) {
                let bytes = read_remote(&handle, &login.host, &detect::read_file_command(&path, access)?).await?;
                kubeconfig::inline(&mut chosen, &slot, bytes);
            }
            kubeconfig::check(&chosen, From::Remote)?;
            let summary = chosen.summary.clone();
            let client = tunnel::client(chosen, Some(Arc::clone(&handle))).await?;
            // The first request proves the client, so a bad certificate says
            // so here rather than on the first list.
            within(async { client.apiserver_version().await.map_err(|e| resources::api_error("version", e)) }).await?;
            Ok((client, summary, Some(handle)))
        }
    }
}

async fn read_remote(handle: &Handle<Guard>, host: &str, command: &str) -> anyhow::Result<Zeroizing<Vec<u8>>> {
    let o = remote::exec(handle, host, command, KUBECONFIG_MAX, COMMAND).await?;
    if o.status != Some(0) {
        tracing::warn!(host, status = ?o.status, stderr = %o.stderr, "a kubeconfig read failed");
        anyhow::bail!(keyward_core::fault!("err.kubeReadFailed", "host" => host));
    }
    Ok(o.stdout)
}

fn local_path() -> Option<std::path::PathBuf> {
    std::env::home_dir().map(|h| h.join(".kube").join("config"))
}

/// The person's own kubeconfig. A missing one is no error — there is simply
/// nothing local — but one that will not read is.
fn read_local() -> anyhow::Result<String> {
    let path = local_path().ok_or_else(|| keyward_core::fault!("err.kubeLocalUnreadable"))?;
    std::fs::read_to_string(&path).map_err(|e| {
        tracing::error!(path = %path.display(), error = %e, "the local kubeconfig will not read");
        keyward_core::fault!("err.kubeLocalUnreadable")
    })
}

fn local_contexts() -> anyhow::Result<Vec<String>> {
    let Some(path) = local_path() else { return Ok(Vec::new()) };
    if !path.exists() {
        return Ok(Vec::new());
    }
    let text = Zeroizing::new(read_local()?);
    Ok(kubeconfig::parse(&text)?.contexts.into_iter().map(|c| c.name).collect())
}

#[async_trait::async_trait]
impl Plugin for KubePlugin {
    fn manifest(&self) -> Manifest {
        Manifest {
            id: "kube".into(),
            title: "Kubernetes".into(),
            icon: "cluster".into(),
            section: true,
            needs_unlocked: true,
            version: env!("CARGO_PKG_VERSION").into(),
            description: "plugin.kube.description".into(),
            origin: Origin::Builtin,
            enabled: true,
            // The items with keys and routes; the notes with a kubeconfig
            // (`tagged_items`, and `secret` for its own `kw-kubeconfig`);
            // `kw-knownhosts` written when a host is trusted and a note made
            // on an import; a login signed by the core; the network the
            // servers and the clusters are on.
            permissions: vec![
                Permission::Entries,
                Permission::Items,
                Permission::ItemsWrite,
                Permission::Secrets,
                Permission::Notices,
                Permission::SshSign,
                Permission::Network,
            ],
            probe: false,
            declared: true,
            places: true,
        }
    }

    fn attach(&self, host: Arc<dyn Host>) {
        if let Ok(mut c) = self.core.write() {
            *c = Some(host);
        }
    }

    async fn call(&self, host: &dyn Host, op: &str, payload: Value) -> Result<Value> {
        match op {
            "overview" => self.overview(host),
            "scan" => self.scan(host, payload),
            "forget" => self.forget(host, payload),
            "import_local" => self.import_local(host, payload).await,
            other => match self.inner.ui.call(self, host, other, payload).await {
                Some(r) => r,
                None => anyhow::bail!("the kube plugin does not know the operation \"{other}\""),
            },
        }
    }

    async fn on_event(&self, _host: &dyn Host, event: HostEvent) {
        if event == HostEvent::Locked {
            self.lock();
        }
    }
}

#[cfg(test)]
mod stand;
#[cfg(test)]
mod tests;
