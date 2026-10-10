//! The daemon: it holds the accounts, the keys in memory and the ssh agent's
//! sockets. The one place where secrets live.

use std::collections::HashMap;
use std::sync::Arc;

use anyhow::Context as _;
use keyward_core::accounts::{Account, Registry};
use keyward_core::items::Catalog;
use keyward_core::proto::{AccountView, Request, Response, Status};
use keyward_core::settings::{LockAction, Settings};
use keyward_plugin::HostEvent;
use keyward_core::source::{self, VaultEntry};
use keyward_core::vault_state::VaultState;
use keyward_vault::{LoginOutcome, Vault};
use tokio::io::{AsyncReadExt as _, AsyncWriteExt as _};
use tokio::net::{UnixListener, UnixStream};
use tokio::sync::Mutex;

use crate::clipboard;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Source {
    /// Local JSON: a bridge for debugging without a vault.
    File,
    /// The real Bitwarden.
    Vault,
}

impl Source {
    fn label(self) -> &'static str {
        match self {
            Self::File => "file",
            Self::Vault => "vault",
        }
    }
}

/// How many notifications are held when nobody takes them.
///
/// A queue with no limit is a leak: the daemon lives for weeks, and a great
/// many leases expire in that time.
const NOTICE_KEEP: usize = 32;

/// A mirror of the state with no async lock.
///
/// `Host` asks for items and for "is the vault open" from synchronous methods,
/// and the daemon's mutex cannot be taken from there: it is asynchronous, and
/// the attempt would end in a panic in the middle of the working loop. The
/// mirror is updated where the truth itself changes — in `reload` and when
/// locking.
#[derive(Default)]
pub struct Mirror {
    entries: std::sync::RwLock<Vec<VaultEntry>>,
    active: std::sync::RwLock<Option<Vault>>,
    unlocked: std::sync::atomic::AtomicBool,
}

impl Mirror {
    pub fn entries(&self) -> Vec<VaultEntry> {
        self.entries.read().map(|e| e.clone()).unwrap_or_default()
    }

    pub fn active(&self) -> Option<Vault> {
        self.active.read().ok().and_then(|v| v.clone())
    }

    pub fn unlocked(&self) -> bool {
        self.unlocked.load(std::sync::atomic::Ordering::Relaxed)
    }
}

pub struct State {
    pub source: Source,
    pub registry: Registry,
    /// The vaults of every account set up. Several can be unlocked at once: a
    /// work key and a personal one are needed at the same time, not in turn.
    pub vaults: HashMap<String, Vault>,
    /// Notifications nobody has shown yet. A daemon under launchd has no
    /// interface and so draws nothing itself: it gathers them, and whoever has
    /// a window and the system's permission shows them.
    pub notices: Vec<keyward_core::proto::Notice>,
    pub entries: Vec<VaultEntry>,
    /// The same again, but reachable by plugins with no async lock.
    mirror: Arc<Mirror>,
    pub settings: Settings,
    /// When the daemon was last disturbed: automatic locking is counted from
    /// this.
    pub last_activity: std::time::Instant,
    /// The vault's contents, parsed. Computed lazily and outliving the
    /// interface's polls: decrypting four hundred items in full costs
    /// noticeable time, and doing it under the shared mutex on every poll is a
    /// sure way to clog the accept queue and get "Resource temporarily
    /// unavailable" for nothing.
    cache: Cache,
}

/// What is kept between requests, each piece under the account it is of.
/// The catalogue was kept bare: after a switch of accounts the window got the
/// one it switched away from, and opening any of its items said "not found"
/// in the account now active. A piece of another account is never served.
#[derive(Default)]
struct Cache {
    catalog: Option<(Option<String>, Catalog)>,
}

impl Cache {
    fn clear(&mut self) {
        *self = Self::default();
    }

    /// The catalogue of `account`, built once and kept for it alone.
    fn catalog(&mut self, account: Option<String>, build: impl FnOnce() -> Catalog) -> Catalog {
        match &self.catalog {
            Some((of, catalog)) if *of == account => catalog.clone(),
            _ => {
                let catalog = build();
                self.catalog = Some((account, catalog.clone()));
                catalog
            }
        }
    }
}

impl State {
    fn new(source: Source) -> Self {
        // Before several accounts the settings lived in the rbw config: they
        // are carried over, or after an update the vault looks unconfigured.
        keyward_vault::migrate_single_account();
        let registry = Registry::load();
        let mut vaults = HashMap::new();
        for account in &registry.accounts {
            vaults.insert(account.id.clone(), Vault::for_account(account.clone()));
        }
        let settings = Settings::load();
        speak(&settings);
        Self {
            source,
            settings,
            last_activity: std::time::Instant::now(),
            registry,
            vaults,
            notices: Vec::new(),
            entries: Vec::new(),
            mirror: Arc::new(Mirror::default()),
            cache: Cache::default(),
        }
    }

    /// The mirror, for the plugins.
    pub fn mirror(&self) -> Arc<Mirror> {
        Arc::clone(&self.mirror)
    }

    /// Bring the mirror up to the current state.
    fn sync_mirror(&self) {
        if let Ok(mut e) = self.mirror.entries.write() {
            *e = self.entries.clone();
        }
        if let Ok(mut a) = self.mirror.active.write() {
            *a = self.active().cloned();
        }
        self.mirror
            .unlocked
            .store(self.vaults.values().any(|v| v.state().is_unlocked()), std::sync::atomic::Ordering::Relaxed);
    }

    /// The vault's contents changed: drop the cache and rebuild the items.
    pub fn invalidate(&mut self) {
        let _ = self.reload();
    }

    fn active_id(&self) -> Option<String> {
        self.registry.active.clone()
    }

    pub(crate) fn active(&self) -> Option<&Vault> {
        self.active_id().and_then(|id| self.vaults.get(&id))
    }

    fn active_mut(&mut self) -> Option<&mut Vault> {
        let id = self.active_id()?;
        self.vaults.get_mut(&id)
    }

    fn vault_state(&self) -> VaultState {
        match self.source {
            Source::File => VaultState::Disabled,
            Source::Vault => self.active().map_or(VaultState::NeedsSetup, Vault::state),
        }
    }

    fn account_views(&self) -> Vec<AccountView> {
        self.registry
            .accounts
            .iter()
            .map(|a| AccountView {
                account: a.clone(),
                state: self.vaults.get(&a.id).map_or(VaultState::NeedsSetup, Vault::state),
                biometric: keyward_vault::biometric::is_remembered(&a.email),
                pin: keyward_vault::pin::is_set(&a.email),
            })
            .collect()
    }

    /// The catalogue of the active account's items.
    fn catalog(&mut self) -> Catalog {
        let account = self.active_id();
        let vault = account.as_ref().and_then(|id| self.vaults.get(id));
        self.cache.catalog(account.clone(), || vault.map(Vault::catalog).unwrap_or_default())
    }

    /// Rebuilds the table of routes. In vault mode it takes keys from **every**
    /// unlocked account: ssh must not depend on which tab is open in the
    /// window.
    pub(crate) fn reload(&mut self) -> anyhow::Result<()> {
        // Everything that depends on the vault's contents is now stale.
        self.cache.clear();
        let entries = match self.source {
            Source::File => source::load_from_file(&keyward_core::paths::mappings_file())?,
            Source::Vault => {
                let mut all = Vec::new();
                for (id, vault) in &self.vaults {
                    if !vault.state().is_unlocked() {
                        continue;
                    }
                    for mut e in vault.plugin_entries() {
                        // Item identifiers are unique only within one account,
                        // and the table is now shared.
                        e.id = format!("{id}\u{1}{}", e.id);
                        all.push(e);
                    }
                }
                all
            }
        };

        tracing::info!(source = self.source.label(), entries = entries.len(), "the items were rebuilt");
        self.entries = entries;
        self.sync_mirror();
        Ok(())
    }

    /// Logging out of an account: the keys out of memory, the account out of
    /// the register. The tokens on disk are left alone, as they were in
    /// `Request::Logout`.
    fn logout(&mut self, id: &str) {
        if let Some(v) = self.vaults.get_mut(id) {
            v.lock();
            forget_window();
        }
        self.vaults.remove(id);
        self.registry.remove(id);
    }

    /// Logging out of every account at once, on a timeout with
    /// `lock_action = logout`.
    fn logout_all(&mut self) {
        let ids: Vec<String> = self.vaults.keys().cloned().collect();
        for id in &ids {
            self.logout(id);
        }
        if let Err(e) = self.registry.save() {
            tracing::warn!(error = %e, "the register of accounts was not saved");
        }
        let _ = self.reload();
    }

    fn status(&mut self) -> Status {
        Status {
            version: env!("CARGO_PKG_VERSION").to_string(),
            source: self.source.label().to_string(),
            vault: self.vault_state(),
            biometric: self
                .active()
                .is_some_and(|v| keyward_vault::biometric::is_remembered(&v.account().email)),
            pin: self.active().is_some_and(|v| keyward_vault::pin::is_set(&v.account().email)),
            pending_edits: keyward_vault::edits::waiting(),
        }
    }
}

pub type Shared = Arc<Mutex<State>>;

pub async fn run(source: Source) -> anyhow::Result<()> {
    let base = keyward_core::paths::base_dir();
    std::fs::create_dir_all(&base).with_context(|| format!("cannot create {}", base.display()))?;
    let sock_dir = keyward_core::paths::agent_socket_dir();
    std::fs::create_dir_all(&sock_dir)?;
    restrict(&base)?;
    restrict(&sock_dir)?;

    // The requirement on peers' signatures is built out of our own signature,
    // and right here at start-up: "the daemon is not signed" has to reach the
    // log where it is looked for rather than surface in the middle of the
    // work.
    crate::peer::init();

    let mut state = State::new(source);
    if let Err(e) = state.reload() {
        tracing::warn!(error = %e, "the source of routes is unreachable");
        tracing::warn!(error = %e, "the source of items is unreachable");
    }
    let shared: Shared = Arc::new(Mutex::new(state));

    // The ssh agent's and HashiCorp's settings lived in the shared file: they
    // are taken before the interface manages to rewrite it without those
    // keys.
    crate::plugins::migrate_settings();
    // The first event: without it the table of routes would stay empty until
    // the vault was first opened, and with an open vault ssh would stop working
    // until the first sync.
    crate::plugins::notify(&shared, HostEvent::EntriesChanged).await;

    // The channel's key for this run: the private half stays in this
    // process, the public half is published before the socket appears, so
    // that no client ever finds the socket without it.
    let key = Arc::new(keyward_core::channel::DaemonKey::generate()?);
    key.publish().context("cannot publish the daemon's public key")?;

    let control = keyward_core::paths::control_socket();
    let _ = std::fs::remove_file(&control);
    let listener = UnixListener::bind(&control)
        .with_context(|| format!("cannot take the control socket {}", control.display()))?;
    restrict(&control)?;
    tracing::info!(socket = %control.display(), "the daemon is listening");

    // The minute tick: plugins decide for themselves what to do with it —
    // expired leases, sweeping up policies, rebuilding sockets.
    {
        let shared = shared.clone();
        tokio::spawn(async move {
            loop {
                tokio::time::sleep(std::time::Duration::from_secs(60)).await;
                crate::plugins::notify(&shared, keyward_plugin::HostEvent::Tick).await;
            }
        });
    }

    // Automatic locking: a task of its own, so that it does not depend on
    // whether anybody is calling the daemon.
    {
        let shared = shared.clone();
        tokio::spawn(async move {
            loop {
                tokio::time::sleep(std::time::Duration::from_secs(20)).await;
                let mut st = shared.lock().await;
                let Some(minutes) = st.settings.lock_timeout.as_minutes() else { continue };
                if st.last_activity.elapsed() < std::time::Duration::from_secs(u64::from(minutes) * 60) {
                    continue;
                }
                let was_open = st.vaults.values().any(|v| v.state().is_unlocked());
                if !was_open {
                    continue;
                }
                match st.settings.lock_action {
                    LockAction::Lock => {
                        for vault in st.vaults.values_mut() {
                            vault.lock();
                        }
                        forget_window();
                        let _ = st.reload();
                        tracing::info!(minutes, "the vault was locked after idling");
                    }
                    // The same as `Request::Logout` but for every account: the
                    // keys out of memory, the account out of the register, the
                    // sockets away. Touch ID and the PIN are left alone: they
                    // are about the password, not about the account.
                    LockAction::Logout => {
                        st.logout_all();
                        tracing::info!(minutes, "logged out of every account after idling");
                    }
                }
                // The mutex is let go before the event goes round: plugins
                // will set about taking their sockets down and will reach back
                // for the state.
                drop(st);
                crate::plugins::notify(&shared, HostEvent::Locked).await;
            }
        });
    }

    loop {
        let (stream, _) = listener.accept().await?;

        // Who is at the other end. Mode 0600 keeps strangers out as it is, but
        // the check here is a second line: if the directory ever ends up with
        // its permissions flung open, the daemon still will not talk to another
        // uid.
        match crate::peer::uid(&stream) {
            Ok(uid) if uid == unsafe { libc::getuid() } => {}
            Ok(uid) => {
                tracing::warn!(uid, "a connection from another user was refused");
                continue;
            }
            Err(e) => {
                tracing::warn!(error = %e, "the connection's owner could not be determined");
                continue;
            }
        }

        // A peer's signature is worked out once per connection rather than per
        // request: it does not change while the connection lives, and going to
        // Security.framework for every line is a noticeable price for
        // nothing.
        let peer = crate::peer::Peer::inspect(&stream);
        tracing::debug!(
            pid = peer.pid(),
            binary = peer.path(),
            verdict = peer.verdict(),
            "connection accepted"
        );

        let shared = shared.clone();
        let key = Arc::clone(&key);
        tokio::spawn(async move {
            if let Err(e) = serve(stream, shared, peer, key).await {
                let broken = e
                    .downcast_ref::<std::io::Error>()
                    .is_some_and(|io| io.kind() == std::io::ErrorKind::BrokenPipe);
                if broken {
                    tracing::debug!("the client closed the connection");
                } else {
                    tracing::warn!(error = %e, "the connection broke off");
                }
            }
        });
    }
}

/// Mode 0700 on the directories and 0600 on the socket.
pub(crate) fn restrict(path: &std::path::Path) -> anyhow::Result<()> {
    use std::os::unix::fs::PermissionsExt as _;
    let meta = std::fs::metadata(path)?;
    let mode = if meta.is_dir() { 0o700 } else { 0o600 };
    std::fs::set_permissions(path, std::fs::Permissions::from_mode(mode))?;
    Ok(())
}

/// An operation on an organisation: take a copy of the vault, let the lock go,
/// go to the network, rebuild the state. The same wrapper for seven
/// endpoints.
async fn org_op<F, Fut>(shared: &Shared, work: F) -> Response
where
    F: FnOnce(Vault) -> Fut,
    Fut: std::future::Future<Output = anyhow::Result<()>>,
{
    let Some(vault) = shared.lock().await.active().cloned() else {
        return Response::error(keyward_core::fault!("err.noAccount"));
    };
    match work(vault).await {
        Ok(()) => refreshed(&mut *shared.lock().await).await,
        Err(e) => Response::error(e),
    }
}

/// The same for an operation that makes something: the answer names it,
/// once the routes are rebuilt.
async fn created_op<F, Fut>(shared: &Shared, work: F) -> Response
where
    F: FnOnce(Vault) -> Fut,
    Fut: std::future::Future<Output = anyhow::Result<String>>,
{
    let Some(vault) = shared.lock().await.active().cloned() else {
        return Response::error(keyward_core::fault!("err.noAccount"));
    };
    match work(vault).await {
        Ok(id) => match refreshed(&mut *shared.lock().await).await {
            Response::Vault { .. } => Response::Created { id },
            other => other,
        },
        Err(e) => Response::error(e),
    }
}

/// An operation on an account whose answer is no more than "done": a copy of
/// the vault, the network without the lock, `Done`.
async fn account_op<F, Fut>(shared: &Shared, work: F) -> Response
where
    F: FnOnce(Vault) -> Fut,
    Fut: std::future::Future<Output = anyhow::Result<()>>,
{
    let Some(vault) = shared.lock().await.active().cloned() else {
        return Response::error(keyward_core::fault!("err.noAccount"));
    };
    match work(vault).await {
        Ok(()) => Response::Done,
        Err(e) => Response::error(e),
    }
}

/// An operation after which the daemon logs in again: a change of password, of
/// email, of KDF, a reset of the security stamp.
///
/// It works on a copy of the vault so as not to hold the lock across the
/// network, and then puts the copy in the original's place: the copy has both
/// the new keys and the login in progress if the server asked for a second
/// factor. The email may have changed, and then the account has a new
/// identifier and the register is rewritten.
async fn account_relogin<F, Fut>(shared: &Shared, work: F) -> Response
where
    F: FnOnce(Vault) -> Fut,
    Fut: std::future::Future<Output = (Vault, anyhow::Result<LoginOutcome>)>,
{
    let (old_id, vault) = {
        let st = shared.lock().await;
        match st.active() {
            Some(v) => (v.account().id.clone(), v.clone()),
            None => return Response::error(keyward_core::fault!("err.noAccount")),
        }
    };
    let (vault, outcome) = work(vault).await;

    let mut st = shared.lock().await;
    let new_id = vault.account().id.clone();
    if new_id != old_id {
        st.vaults.remove(&old_id);
        st.registry.remove(&old_id);
        st.registry.upsert(vault.account().clone());
        if let Err(e) = st.registry.save() {
            return Response::error(e);
        }
    }
    // If logging in again did not go through, the copy is locked and whatever
    // lives on its keys has to go, as with an ordinary `Lock`. A typo in the
    // password never reached the network, the vault stayed open as it was, and
    // the plugins are left alone.
    let locked = !vault.state().is_unlocked();
    st.vaults.insert(new_id, vault);
    let answer = match outcome {
        Ok(LoginOutcome::Done) => {
            ensure_snapshot(&mut st).await;
            refreshed(&mut st).await
        }
        Ok(LoginOutcome::TwoFactorRequired(providers)) => {
            let _ = st.reload();
            Response::TwoFactorRequired { providers }
        }
        Err(e) => {
            let _ = st.reload();
            Response::error(e)
        }
    };
    drop(st);
    crate::plugins::notify(shared, if locked { HostEvent::Locked } else { HostEvent::Unlocked }).await;
    answer
}

// -- The lock on passwords ---------------------------------------------------

/// A refusal to an outsider process. The sentence behind the key explains not
/// "no" but what exactly is wrong: the caller is not signed with our identity,
/// and that is mended by a signature, not by trying again.
pub(crate) const REFUSED_ALIEN: &str = "err.peerNotKeyward";
/// The passkey bridge asked for something other than passkeys.
pub(crate) const REFUSED_BRIDGE: &str = "err.peerBridgePasskeysOnly";
/// The CLI asked for what only the window may.
pub(crate) const REFUSED_CLI: &str = "err.peerCliNotAllowed";

/// A refusal to an external plugin that reached for a secret of its own
/// accord. Its own `kw-` fields are all it is allowed.
pub(crate) const REFUSED_PLUGIN: &str = "err.pluginForeignField";

/// A refusal to an external plugin on an item whose owner marked it "ask the
/// password again". Asking for a finger here would be a prompt with nobody at
/// the machine: a plugin works on the daemon's timer, not because a person
/// pressed something.
pub(crate) const REFUSED_REPROMPT: &str = "err.pluginReprompt";

/// Which language the daemon speaks when the system, not a window, draws what
/// it says: the reason under a Touch ID prompt, the body of a notification.
/// Everything that goes over the socket travels as a key instead, and the
/// window phrases it in whatever language it is running in.
fn speak(settings: &Settings) {
    use keyward_core::settings::Language;
    keyward_core::text::set_lang(match settings.language {
        Language::Ru => keyward_core::text::Lang::Ru,
        Language::En => keyward_core::text::Lang::En,
        Language::Auto => keyward_core::text::Lang::system(),
    });
    // A plugin's words travel inside its package, so they are read from disk
    // rather than compiled in. Re-read on every change of language as well: a
    // plugin may have been installed since the last time.
    keyward_core::text::load_dictionaries(&keyward_core::paths::plugins_dir());
}

/// What to do with a request for a password.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum Step {
    /// Hand it over silently.
    Give,
    /// Ask the sensor and hand it over.
    Ask,
    /// Refuse with this text.
    Deny(&'static str),
}

/// The table of decisions: who is asking, crossed with what is known about
/// their signature, gives what to do.
///
/// A function of its own, so that a test checks it rather than a finger at the
/// sensor.
///
/// * a verified peer gets the sensor, and after it a window of trust: without
///   one, autofill would turn into torture by touching;
/// * an unverified one is refused: exactly the hole all this was started for
///   (`nc -U` read a password on the same terms as the application);
/// * nothing to check with (the daemon is not signed itself, a `cargo run`
///   build) gets the sensor without a signature: there is nothing to compare
///   against, but turning a debug daemon into a brick is not allowed either;
/// * a built-in plugin on an event of the daemon's gets it silently: the secret
///   stays in the same process's memory, there is nobody at the sensor at that
///   moment, and a prompt on a minute timer would be a mockery;
/// * an external plugin on an event gets only its own `kw-` field, and only
///   one not marked "ask again": behind it is somebody else's process and no
///   request from a person.
///
/// `own_field` means the plugin is asking for a custom field in keyward's own
/// namespace — one it wrote itself, such as `kw-vault-addr`. A password, a
/// login, a one-time code and a private key are separate variants of
/// `SecretField` and can never be spelled that way, so this cannot turn into a
/// way around "passwords go to the window only".
pub(crate) fn decide(
    peer: &crate::peer::Peer,
    strict: bool,
    fresh: bool,
    always_ask: bool,
    own_field: bool,
) -> Step {
    use crate::peer::{Peer, Trust};
    match peer {
        Peer::Socket { trust: Trust::Alien, .. } => Step::Deny(REFUSED_ALIEN),
        // The bridge reaches a secret only through a passkey, and a passkey
        // always asks. It never gets anything silently.
        Peer::Socket { trust: Trust::Bridge, .. } => Step::Ask,
        // A plugin keeps its own service records in the vault — the address of
        // its server, the identifier of its role — and it is the one that put
        // them there. Refusing it those was refusing it its own handwriting:
        // the Vault plugin could not find out which server an item points at,
        // and every one of its screens read "this item has no connection to
        // Vault".
        Peer::External if own_field => {
            if strict {
                Step::Deny(REFUSED_REPROMPT)
            } else {
                Step::Give
            }
        }
        Peer::External => Step::Deny(REFUSED_PLUGIN),
        Peer::Builtin => Step::Give,
        // A verified peer does not always need the sensor. The lock on the
        // socket already cuts other processes off, and a person asks for a
        // password in the application themselves, looking at the screen:
        // demanding a finger for that too is the kind of nagging that gets
        // switched off along with the whole protection. The sensor is required
        // where the person decided so: the "ask for the password again" mark on
        // an item, a private ssh key, and the "always ask" setting.
        // The CLI never gets a value: whatever the person runs can run it.
        Peer::Socket { trust: Trust::Cli, .. } => Step::Deny(REFUSED_CLI),
        Peer::Socket { trust: Trust::App, .. } => {
            if strict || (always_ask && !fresh) {
                Step::Ask
            } else {
                Step::Give
            }
        }
        // Nothing to check with: an unsigned build. There is nothing to
        // compare against, so the sensor is asked: it is the only thing left
        // here that tells a person from another process.
        Peer::Socket { trust: Trust::Unknown, .. } => {
            if fresh && !strict {
                Step::Give
            } else {
                Step::Ask
            }
        }
    }
}

/// The requests on which a password leaves the daemon.
///
/// Everything not here stays open to any process of the same user: `keyward
/// resolve` is called by ssh on every connection, and a lock on that path would
/// mean the sensor on every `git push`.
/// Whether a peer may send a request at all, before anything else is looked
/// at. Every list here is closed: a request added later is refused to each of
/// them until somebody decides otherwise, rather than let through by default.
#[derive(Debug, PartialEq, Eq)]
pub(crate) enum Admit {
    Yes,
    /// Allowed once the person confirms at the sensor; the key is the
    /// prompt's text.
    Confirm(&'static str),
    No(&'static str),
}

pub(crate) fn admit(peer: &crate::peer::Peer, req: &Request) -> Admit {
    use crate::peer::{Peer, Trust};
    match peer {
        // The window a person works in; the secrets themselves are still
        // guarded request by request (`guard_secret`).
        Peer::Socket { trust: Trust::App, .. } => Admit::Yes,
        // An unsigned build has nothing to check with: the sensor decides at
        // every secret, as before.
        Peer::Socket { trust: Trust::Unknown, .. } => Admit::Yes,
        Peer::Socket { trust: Trust::Bridge, .. } => {
            if bridge_may(req) {
                Admit::Yes
            } else {
                Admit::No(REFUSED_BRIDGE)
            }
        }
        Peer::Socket { trust: Trust::Cli, .. } => cli_may(req),
        // An outsider may learn that a daemon is there, and nothing else: not
        // the vault's state, not a setting, not an item's note.
        Peer::Socket { trust: Trust::Alien, .. } => {
            if matches!(req, Request::Ping) {
                Admit::Yes
            } else {
                Admit::No(REFUSED_ALIEN)
            }
        }
        // Not over the socket at all.
        Peer::Builtin | Peer::External => Admit::Yes,
    }
}

/// What the CLI may ask for.
///
/// The CLI is ours, but whatever a person runs can run it — a script, a
/// package's install hook. So it gets what the install and ssh need and no
/// value out of the vault; and what would hand the vault to somebody else —
/// a plugin switched on is consent to its permissions, Touch ID's key is the
/// way in without the password — waits for the person's finger.
fn cli_may(req: &Request) -> Admit {
    match req {
        Request::Ping
        | Request::Status
        | Request::Vault
        | Request::Reload
        | Request::Lock
        | Request::Sync
        | Request::Unlock { .. }
        | Request::Login { .. }
        | Request::LoginTwoFactor { .. }
        | Request::SendTwoFactorEmail { .. }
        | Request::BiometricUnlock { .. }
        | Request::Setup { .. }
        | Request::Plugins
        | Request::PushNotice { .. }
        | Request::Extensions
        | Request::ExtensionUnpair { .. } => Admit::Yes,
        // The finger is asked by the pairing itself, with the key's words in
        // the prompt.
        Request::ExtensionPair { .. } => Admit::Yes,
        // ssh's `Match exec` and `keyward status`/`hosts`: routes, never a
        // key.
        Request::Plugin { plugin, action, .. } if plugin == "ssh" && matches!(action.as_str(), "resolve" | "status" | "hosts") => Admit::Yes,
        Request::PluginInstall { .. } | Request::PluginEnable { .. } | Request::PluginRemove { .. } => Admit::Confirm("touch.cliPlugins"),
        Request::BiometricRemember { .. } | Request::BiometricForget { .. } => Admit::Confirm("touch.cliTouchId"),
        // Writing an item: a script could overwrite what a person relies on,
        // so the finger; reading one back stays the window's.
        Request::CreateItem { .. } => Admit::Confirm("touch.cliWriteItem"),
        _ => Admit::No(REFUSED_CLI),
    }
}

/// How long one finger covers the CLI's changes: an install removes, installs
/// and switches on every plugin, and a dozen prompts in a row is how a person
/// learns to touch without reading.
const CLI_CONFIRM_HOLDS: std::time::Duration = std::time::Duration::from_secs(60);

static CLI_CONFIRMED: std::sync::Mutex<Option<std::time::Instant>> = std::sync::Mutex::new(None);

fn cli_confirmed_lately() -> bool {
    CLI_CONFIRMED
        .lock()
        .unwrap_or_else(std::sync::PoisonError::into_inner)
        .is_some_and(|t| t.elapsed() < CLI_CONFIRM_HOLDS)
}

fn remember_cli_confirmed() {
    *CLI_CONFIRMED.lock().unwrap_or_else(std::sync::PoisonError::into_inner) = Some(std::time::Instant::now());
}

/// What the passkey bridge may ask for.
pub(crate) fn bridge_may(req: &Request) -> bool {
    matches!(
        req,
        // Only what the extension signed: the bridge passes it on and has no
        // voice of its own.
        Request::Ping | Request::PasskeyBridge { .. }
    )
}

pub(crate) fn wants_secret(req: &Request) -> bool {
    matches!(
        req,
        Request::CopySecret { .. }
            | Request::RevealSecret { .. }
            | Request::ExportVault { .. }
            | Request::PluginWithFields { .. }
            | Request::PasskeyOffers { .. }
            | Request::PasskeyHomes { .. }
            | Request::PasskeySignIn { .. }
            | Request::PasskeyRegister { .. }
            | Request::PasskeyBridge { .. }
    )
}

/// The window of trust for handing out passwords.
///
/// Ours, not the one inside `biometric`: there the window deliberately does not
/// cover `confirm` — an ssh signature marked `kw-confirm` has to ask every time.
/// Here the matter is different: copy the login, then the password, then the
/// code — three touches in a row within ten seconds is not forgiven. It lives
/// for `biometric_grace_seconds` and goes out with the vault.
static TOUCHED: std::sync::Mutex<Option<std::time::Instant>> = std::sync::Mutex::new(None);

/// The vault was locked, and the window of trust closes with it, or "locked"
/// stops meaning anything.
pub(crate) fn forget_window() {
    *TOUCHED.lock().unwrap_or_else(std::sync::PoisonError::into_inner) = None;
}

/// The lock on everything that carries a password out of the daemon.
///
/// `strict` means "the window of trust does not count": private ssh keys and
/// items with the `reprompt` flag (the very one Bitwarden marks the most
/// sensitive things with) ask the sensor every time.
pub(crate) fn guard(
    peer: &crate::peer::Peer,
    why: &str,
    strict: bool,
    grace: u32,
    always_ask: bool,
    own_field: bool,
) -> anyhow::Result<()> {
    let mut window = TOUCHED.lock().unwrap_or_else(std::sync::PoisonError::into_inner);
    guard_with(
        peer,
        why,
        strict,
        grace,
        always_ask,
        own_field,
        std::time::Instant::now(),
        &mut window,
        keyward_vault::biometric::confirm,
    )
}

/// The same again, but with the window and the sensor from outside: that is how
/// a test checks it without a live finger.
fn guard_with(
    peer: &crate::peer::Peer,
    why: &str,
    strict: bool,
    grace: u32,
    always_ask: bool,
    own_field: bool,
    now: std::time::Instant,
    window: &mut Option<std::time::Instant>,
    confirm: fn(&str) -> anyhow::Result<()>,
) -> anyhow::Result<()> {
    let fresh = grace > 0
        && window.is_some_and(|t| now.duration_since(t) < std::time::Duration::from_secs(u64::from(grace)));
    match decide(peer, strict, fresh, always_ask, own_field) {
        Step::Deny(text) => anyhow::bail!("{text}"),
        Step::Give => Ok(()),
        Step::Ask => {
            // The sensor's prompt is drawn by the system, not by our window,
            // so here the daemon does say the sentence itself -- out of the
            // same dictionary the window reads.
            confirm(&keyward_core::text::t(why, &[]))
                .map_err(|e| anyhow::anyhow!("{}", keyward_core::text::t("err.notConfirmed", &[("reason", &e.to_string())])))?;
            // A strict confirmation opens no window: that is what strict
            // means.
            if !strict {
                *window = Some(now);
            }
            Ok(())
        }
    }
}

/// The lock on one particular field of an item.
///
/// Private ssh keys and fields under `reprompt` ask the sensor every time: the
/// whole point of the agent is that a key does not leave the daemon, and
/// quietly weakening somebody else's "ask again" mark is worse than not
/// supporting it at all.
pub(crate) fn guard_secret(
    peer: &crate::peer::Peer,
    vault: &Vault,
    entry_id: &str,
    field: &keyward_core::detail::SecretField,
    grace: u32,
    always_ask: bool,
) -> anyhow::Result<()> {
    let private_key = matches!(field, keyward_core::detail::SecretField::PrivateKey);
    let reprompt = vault.item_detail(entry_id).is_some_and(|d| d.reprompt);
    // A custom field in keyward's own namespace: what a plugin writes into an
    // item and reads back. `kw-` is that namespace everywhere — `kw-host`,
    // `kw-cert`, `kw-vault-addr` — and a field a person named themselves does
    // not fall into it.
    // The same rule the plugins' own tests run against (`StrictHost`).
    let own_field = keyward_plugin::external_may_read(field);
    let why = if private_key {
        "touch.privateKey"
    } else if reprompt {
        "touch.protectedField"
    } else {
        "touch.passwordToApp"
    };
    guard(peer, why, private_key || reprompt, grace, always_ask, own_field)
}

/// The vault as it is now, after a wait at the sensor.
///
/// A copy taken before Touch ID keeps its keys for as long as it lives: if
/// the vault was locked, or another account chosen, while the finger was on
/// its way, that copy would still hand the secret out. So whatever is read
/// after the sensor is read from the vault taken afresh — the same account,
/// with the keys it has now. A locked vault has none, and the read fails.
pub(crate) async fn vault_after_touch(shared: &Shared, account_id: &str) -> anyhow::Result<Vault> {
    let st = shared.lock().await;
    match st.active() {
        Some(v) if v.account().id == account_id => Ok(v.clone()),
        _ => Err(keyward_core::fault!("err.vaultLocked")),
    }
}

/// Put a notification into the queue. Whoever has a window shows it.
pub(crate) async fn push_notice(shared: &Shared, notice: keyward_core::proto::Notice) {
    let mut st = shared.lock().await;
    st.notices.push(notice);
    if st.notices.len() > NOTICE_KEEP {
        let extra = st.notices.len() - NOTICE_KEEP;
        st.notices.drain(0..extra);
    }
}

/// One frame of the channel from the socket; `None` at the end of the
/// connection.
async fn read_frame(read: &mut tokio::net::unix::OwnedReadHalf) -> anyhow::Result<Option<Vec<u8>>> {
    let mut len = [0u8; 2];
    match read.read_exact(&mut len).await {
        Ok(_) => {}
        Err(e) if e.kind() == std::io::ErrorKind::UnexpectedEof => return Ok(None),
        Err(e) => return Err(e.into()),
    }
    let mut frame = vec![0u8; u16::from_be_bytes(len) as usize];
    read.read_exact(&mut frame).await?;
    Ok(Some(frame))
}

async fn write_frames(write: &mut tokio::net::unix::OwnedWriteHalf, frames: Vec<Vec<u8>>) -> anyhow::Result<()> {
    for frame in frames {
        let len = u16::try_from(frame.len()).context("a frame over the limit")?;
        write.write_all(&len.to_be_bytes()).await?;
        write.write_all(&frame).await?;
    }
    write.flush().await?;
    Ok(())
}

/// One connection: the handshake, then encrypted requests and answers until
/// the client goes. Nothing is read or written in the clear after the first
/// two bytes — and those only tell a plaintext client of the old protocol
/// that it is not served.
async fn serve(
    stream: UnixStream,
    shared: Shared,
    peer: crate::peer::Peer,
    key: Arc<keyward_core::channel::DaemonKey>,
) -> anyhow::Result<()> {
    use keyward_core::channel;
    use zeroize::Zeroizing;
    let (mut read_half, mut write_half) = stream.into_split();

    let mut len = [0u8; 2];
    match read_half.read_exact(&mut len).await {
        Ok(_) => {}
        Err(e) if e.kind() == std::io::ErrorKind::UnexpectedEof => return Ok(()),
        Err(e) => return Err(e.into()),
    }
    if len[0] == channel::PLAINTEXT_FIRST_BYTE {
        tracing::warn!(pid = peer.pid(), binary = peer.path(), "a plaintext request was refused: the channel is required");
        let mut out = serde_json::to_vec(&Response::error(keyward_core::fault!("err.channelRequired")))?;
        out.push(b'\n');
        write_half.write_all(&out).await?;
        write_half.flush().await?;
        return Ok(());
    }
    let mut first = vec![0u8; u16::from_be_bytes(len) as usize];
    read_half.read_exact(&mut first).await?;
    let (reply, mut ch) = match channel::respond(&key, &first) {
        Ok(done) => done,
        Err(e) => {
            tracing::warn!(pid = peer.pid(), binary = peer.path(), "a handshake failed");
            return Err(e);
        }
    };
    write_frames(&mut write_half, vec![reply]).await?;

    loop {
        // One message: frames until it is whole. A frame that does not open
        // ends the connection — the channel cannot go on after it.
        let message: Zeroizing<Vec<u8>> = loop {
            let Some(frame) = read_frame(&mut read_half).await? else { return Ok(()) };
            match ch.open(&frame, channel::MAX_REQUEST) {
                Ok(Some(message)) => break message,
                Ok(None) => continue,
                Err(e) => {
                    tracing::warn!(pid = peer.pid(), error = %e, "a frame did not open; the connection is closed");
                    let refusal = Zeroizing::new(serde_json::to_vec(&Response::error(e))?);
                    if let Err(e) = write_frames(&mut write_half, ch.seal(&refusal)?).await {
                        tracing::debug!(error = %e, "the refusal did not reach the client");
                    }
                    return Ok(());
                }
            }
        };
        let response = match serde_json::from_slice::<Request>(&message) {
            Ok(req) => {
                // What this request changes for the plugins is decided before
                // it is handled: after that nothing of the request is left.
                let event = plugin_event(&req);
                // The log of actions: what was asked and how it ended, never
                // a value — a request's Debug hides every secret it carries,
                // and of an answer only its kind is written.
                let what = format!("{req:?}");
                let routine = req.is_routine();
                let started = std::time::Instant::now();
                let answer = handle(req, &shared, &peer).await;
                let ms = started.elapsed().as_millis();
                if routine {
                    tracing::debug!(target: "keyward::action", request = %what, result = %answer.kind(), ms, "done");
                } else {
                    tracing::info!(target: "keyward::action", request = %what, result = %answer.kind(), ms, "done");
                }
                if let Some(event) = event {
                    if !matches!(answer, Response::Error { .. }) {
                        if matches!(event, HostEvent::Unlocked) {
                            // Edits written before they were sealed get
                            // sealed now that the key is at hand.
                            if let Some(vault) = shared.lock().await.active() {
                                let n = vault.seal_old_edits();
                                if n > 0 {
                                    tracing::info!(edits = n, "old edits were sealed");
                                }
                            }
                        }
                        crate::plugins::notify(&shared, event).await;
                    }
                }
                answer
            }
            Err(e) => Response::error(keyward_core::fault!("err.unrecognisedRequest", "reason" => e)),
        };
        drop(message);
        let out = Zeroizing::new(serde_json::to_vec(&response)?);
        drop(response);
        write_frames(&mut write_half, ch.seal(&out)?).await?;
    }
}

/// Which event for the plugins this request gives rise to.
///
/// Plugins keep live things on the vault's items: the ssh agent's sockets, the
/// ledger of leases. Exactly three turns matter to them — the vault opened, the
/// vault locked, the items changed.
fn plugin_event(req: &Request) -> Option<HostEvent> {
    match req {
        Request::Unlock { .. }
        | Request::BiometricUnlock
        | Request::PinUnlock { .. }
        | Request::Login { .. }
        | Request::LoginTwoFactor { .. }
        | Request::SwitchAccount { .. } => Some(HostEvent::Unlocked),
        Request::Lock | Request::Logout { .. } => Some(HostEvent::Locked),
        Request::Sync
        | Request::Reload
        | Request::CreateItem { .. }
        | Request::NewItem { .. }
        | Request::SetItemCollections { .. }
        | Request::UpdateItem { .. }
        | Request::MergeItems { .. }
        | Request::TrashItem { .. }
        | Request::RestoreItem { .. }
        | Request::PurgeItems { .. }
        | Request::RetryEdit { .. }
        | Request::RollbackEdit { .. }
        | Request::RestoreTotp { .. }
        | Request::RegeneratePassword { .. }
        | Request::SetSettings { .. }
        | Request::PasskeyRegister { .. } => Some(HostEvent::EntriesChanged),
        _ => None,
    }
}

/// Pulls the vault's snapshot down if there is none yet.
///
/// A snapshot appears only after a sync, and the keys only after unlocking.
/// Without this step, right after the first unlock the list of items and the
/// routes would look empty though the vault is open.
async fn ensure_snapshot(st: &mut State) {
    let Some(vault) = st.active() else { return };
    if !vault.catalog().items.is_empty() {
        return;
    }
    tracing::info!("there is no vault snapshot; syncing");
    if let Err(e) = vault.sync().await {
        tracing::warn!(error = %e, "the first sync failed");
    }
    st.cache.clear();
}

/// After an operation that changed the vault's contents, rebuild the routes.
async fn refreshed(st: &mut State) -> Response {
    match st.reload() {
        Ok(()) => Response::Vault { state: st.vault_state() },
        Err(e) => Response::error(e),
    }
}

/// Handling a request. `peer` is the connection's peer: it decides whether
/// passwords are handed over. Everything else — the state, the items, the ssh
/// routes, calls into plugins — is open to any process of the same user:
/// `keyward resolve` is called by ssh on every connection, and the sensor has
/// no place there.
async fn handle(req: Request, shared: &Shared, peer: &crate::peer::Peer) -> Response {
    // Any call pushes automatic locking back: working with the vault is itself
    // the sign that a person is at the machine.
    shared.lock().await.last_activity = std::time::Instant::now();

    // A refusal to an outsider comes before everything else. The answer must
    // not depend on whether an account is set up or the vault is open:
    // otherwise, from the single text "add an account first", another process
    // learns more about the vault's state than it should, and the refusal
    // itself sounds different on different days.
    // Who may ask for what, before anything else: the lists are closed, so a
    // request added later is refused by default rather than let through.
    match admit(peer, &req) {
        Admit::Yes => {}
        Admit::No(text) => {
            tracing::warn!(pid = peer.pid(), binary = peer.path(), verdict = peer.verdict(), request = ?req, "a request was refused to this peer");
            return Response::error(text);
        }
        Admit::Confirm(why) if cli_confirmed_lately() => {
            tracing::debug!(why, "the CLI's confirmation still holds");
        }
        Admit::Confirm(why) => {
            let prompt = keyward_core::text::t(why, &[]);
            let answer = tokio::task::spawn_blocking(move || keyward_vault::biometric::confirm(&prompt)).await;
            match answer {
                Ok(Ok(())) => remember_cli_confirmed(),
                Ok(Err(e)) => return Response::error(anyhow::anyhow!("{}", keyward_core::text::t("err.notConfirmed", &[("reason", &e.to_string())]))),
                Err(e) => return Response::error(anyhow::anyhow!("the sensor's prompt fell over: {e}")),
            }
        }
    }

    if wants_secret(&req) {
        // A request over the socket is never a plugin reading back its own
        // field: those never come this way.
        if let Step::Deny(text) = decide(peer, false, false, false, false) {
            tracing::warn!(
                pid = peer.pid(),
                binary = peer.path(),
                "an outsider process asked for a password and was refused"
            );
            return Response::error(text);
        }
    }

    match req {
        Request::Ping => Response::Pong,
        Request::Status => Response::Status(shared.lock().await.status()),
        Request::Vault => Response::Vault { state: shared.lock().await.vault_state() },

        Request::Shutdown => {
            {
                let mut st = shared.lock().await;
                // The order matters: the keys first, then the sockets, then
                // the table. Otherwise a gap is left between the locking and
                // the taking down of sockets, and a signature slips through
                // it.
                for vault in st.vaults.values_mut() {
                    vault.lock();
                }
                forget_window();
                    st.entries.clear();
                st.entries.shrink_to_fit();
                st.cache.clear();
                tracing::info!("shutting down: the vaults are locked, the sockets are down, the state is forgotten");
            }
            // The answer goes out and a moment later the process dies:
            // launchd brings it back at the next login or on a kickstart.
            tokio::spawn(async {
                tokio::time::sleep(std::time::Duration::from_millis(120)).await;
                std::process::exit(0);
            });
            Response::Pong
        }

        Request::Reload => {
            let mut st = shared.lock().await;
            refreshed(&mut st).await
        }

        // -- Accounts -------------------------------------------------------
        Request::Accounts => {
            let st = shared.lock().await;
            Response::Accounts { accounts: st.account_views(), active: st.active_id() }
        }

        Request::Config => {
            let st = shared.lock().await;
            match st.registry.active() {
                Some(a) => Response::Config {
                    base_url: a.base_url.clone(),
                    email: a.email.clone(),
                    identity_url: a.identity_url.clone(),
                },
                None => Response::Config {
                    base_url: String::new(),
                    email: String::new(),
                    identity_url: None,
                },
            }
        }

        Request::Setup { base_url, email, identity_url } => {
            let account = Account::new(&base_url, &email, identity_url.as_deref());
            if account.base_url.is_empty() || account.email.is_empty() {
                return Response::error(keyward_core::fault!("err.setupNeedsUrlAndLogin"));
            }
            if !account.base_url.starts_with("http") {
                return Response::error(keyward_core::fault!("err.serverUrlScheme"));
            }

            let mut st = shared.lock().await;
            st.vaults
                .entry(account.id.clone())
                .or_insert_with(|| Vault::for_account(account.clone()));
            st.registry.upsert(account);
            if let Err(e) = st.registry.save() {
                return Response::error(e);
            }
            refreshed(&mut st).await
        }

        Request::SwitchAccount { id } => {
            let mut st = shared.lock().await;
            if st.registry.get(&id).is_none() {
                return Response::error(keyward_core::fault!("err.noSuchAccount"));
            }
            st.registry.active = Some(id);
            if let Err(e) = st.registry.save() {
                return Response::error(e);
            }
            st.cache.clear();
            // The sockets are left alone: the keys of other unlocked accounts
            // go on working, and switching is about the window, not about
            // ssh.
            Response::Vault { state: st.vault_state() }
        }

        Request::Logout { id } => {
            let mut st = shared.lock().await;
            st.logout(&id);
            if let Err(e) = st.registry.save() {
                return Response::error(e);
            }
            refreshed(&mut st).await
        }

        // -- Logging in, and the keys ---------------------------------------
        Request::Login { password } => {
            let mut st = shared.lock().await;
            let Some(vault) = st.active_mut() else {
                return Response::error(keyward_core::fault!("err.noAccount"));
            };
            match vault.login(&password).await {
                Ok(LoginOutcome::Done) => refreshed(&mut st).await,
                Ok(LoginOutcome::TwoFactorRequired(providers)) => {
                    Response::TwoFactorRequired { providers }
                }
                Err(e) => Response::error(e),
            }
        }

        Request::LoginTwoFactor { provider, token, remember } => {
            let mut st = shared.lock().await;
            let Some(vault) = st.active_mut() else {
                return Response::error(keyward_core::fault!("err.noAccount"));
            };
            match vault.login_two_factor(provider, &token, remember).await {
                Ok(()) => refreshed(&mut st).await,
                Err(e) => Response::error(e),
            }
        }

        Request::ResetSession => {
            let mut st = shared.lock().await;
            let Some(vault) = st.active_mut() else {
                return Response::error(keyward_core::fault!("err.noAccount"));
            };
            if let Err(e) = vault.forget_damaged_session() {
                return Response::error(e);
            }
            refreshed(&mut st).await
        }

        Request::SendTwoFactorEmail => {
            let st = shared.lock().await;
            let Some(vault) = st.active() else {
                return Response::error(keyward_core::fault!("err.noAccount"));
            };
            match vault.send_two_factor_email().await {
                Ok(()) => Response::TwoFactorEmailSent,
                Err(e) => Response::error(e),
            }
        }

        Request::Unlock { password } => {
            let mut st = shared.lock().await;
            let Some(vault) = st.active_mut() else {
                return Response::error(keyward_core::fault!("err.noAccount"));
            };
            match vault.unlock(&password) {
                Ok(()) => {
                    ensure_snapshot(&mut st).await;
                    refreshed(&mut st).await
                }
                Err(e) => Response::error(e),
            }
        }

        Request::Lock => {
            let mut st = shared.lock().await;
            if let Some(vault) = st.active_mut() {
                vault.lock();
            }
            // The window of trust does not outlive the lock: otherwise
            // "locked" stops meaning anything.
            forget_window();
            refreshed(&mut st).await
        }

        Request::Sync => {
            let mut st = shared.lock().await;
            let Some(vault) = st.active() else {
                return Response::error(keyward_core::fault!("err.noAccount"));
            };
            match vault.sync().await {
                Ok(_) => refreshed(&mut st).await,
                Err(e) => Response::error(e),
            }
        }

        // -- The vault's contents -------------------------------------------
        Request::Items => {
            let mut st = shared.lock().await;
            Response::Items { catalog: st.catalog() }
        }

        Request::ItemDetail { entry_id } => {
            let st = shared.lock().await;
            match st.active().and_then(|v| v.item_detail(&entry_id)) {
                Some(detail) => Response::Detail { detail },
                None => Response::error(keyward_core::fault!("err.itemNotFound")),
            }
        }

        Request::CreateFolder { name } => {
            org_op(shared, |v| async move { v.create_folder(&name).await.map(drop) }).await
        }

        Request::RenameFolder { folder_id, name } => {
            org_op(shared, |v| async move { v.rename_folder(&folder_id, &name).await }).await
        }

        Request::DeleteFolder { folder_id } => {
            org_op(shared, |v| async move { v.delete_folder(&folder_id).await }).await
        }

        Request::CreateCollection { org_id, name } => {
            org_op(shared, |v| async move { v.create_collection(&org_id, &name).await.map(drop) }).await
        }

        Request::NewFolder { name } => {
            created_op(shared, |v| async move { v.create_folder(&name).await }).await
        }

        Request::NewCollection { org_id, name } => {
            created_op(shared, |v| async move { v.create_collection(&org_id, &name).await }).await
        }

        Request::NewItem { kind, folder_id, org_id, collection_ids, edit } => {
            created_op(shared, |v| async move { v.create_item(kind, folder_id, org_id, collection_ids, edit).await })
                .await
        }

        Request::SetItemCollections { entry_id, collection_ids } => {
            org_op(shared, |v| async move { v.set_item_collections(&entry_id, collection_ids).await }).await
        }

        Request::InviteMembers { org_id, emails, role, access_all, access } => {
            org_op(shared, |v| async move { v.invite_members(&org_id, &emails, role, access_all, &access).await })
                .await
        }

        Request::SetMember { org_id, member_id, role, access_all, access } => {
            org_op(shared, |v| async move { v.set_member(&org_id, &member_id, role, access_all, &access).await })
                .await
        }

        Request::VerifyPassword { password } => {
            let Some(vault) = shared.lock().await.active().cloned() else {
                return Response::error(keyward_core::fault!("err.noAccount"));
            };
            // The key derivation takes its second off the runtime and without
            // the daemon's lock: nothing else waits on a re-prompt.
            match tokio::task::spawn_blocking(move || vault.verify_password(&password)).await {
                Ok(Ok(ok)) => Response::PasswordChecked { ok },
                Ok(Err(e)) => Response::error(e),
                Err(e) => Response::error(anyhow::anyhow!("the password check fell over: {e}")),
            }
        }

        Request::GeneratePassphrase { spec } => {
            let list = match keyward_vault::fingerprint::wordlist() {
                Ok(list) => list,
                Err(e) => return Response::error(e),
            };
            match keyward_core::generator::passphrase(&spec, list) {
                Ok(value) => {
                    // Into the history, as a generated password goes: the
                    // window does not send it back to be remembered.
                    if let Some(vault) = shared.lock().await.active().cloned() {
                        if let Err(e) = vault.remember_generated(false, &value) {
                            tracing::warn!(error = %e, "the passphrase did not go into the history");
                        }
                    }
                    Response::Secret { value }
                }
                Err(e) => Response::error(e),
            }
        }

        Request::RenameCollection { org_id, collection_id, name } => {
            org_op(shared, |v| async move {
                v.rename_collection(&org_id, &collection_id, &name).await
            })
            .await
        }

        Request::DeleteCollection { org_id, collection_id } => {
            org_op(shared, |v| async move { v.delete_collection(&org_id, &collection_id).await })
                .await
        }

        Request::InviteMember { org_id, email, role } => {
            org_op(shared, |v| async move { v.invite_member(&org_id, &email, role).await }).await
        }

        Request::SetMemberRole { org_id, member_id, role } => {
            org_op(shared, |v| async move { v.set_member_role(&org_id, &member_id, role).await })
                .await
        }

        Request::RemoveMember { org_id, member_id } => {
            org_op(shared, |v| async move { v.remove_member(&org_id, &member_id).await }).await
        }

        Request::ConfirmMember { org_id, member_id, user_id, fingerprint } => {
            org_op(shared, |v| async move {
                v.confirm_member(&org_id, &member_id, &user_id, &fingerprint).await
            })
            .await
        }

        Request::MemberFingerprint { org_id, member_id, user_id } => {
            let Some(vault) = shared.lock().await.active().cloned() else {
                return Response::error(keyward_core::fault!("err.noActiveAccount"));
            };
            tracing::debug!(%org_id, %member_id, "a member's fingerprint");
            match vault.member_fingerprint(&user_id).await {
                Ok(words) => Response::MemberFingerprint { words },
                Err(e) => Response::error(e),
            }
        }

        Request::CreateOrg { name, billing_email } => {
            let Some(vault) = shared.lock().await.active().cloned() else {
                return Response::error(keyward_core::fault!("err.noAccount"));
            };
            match vault.create_org(&name, &billing_email).await {
                Ok(_) => refreshed(&mut *shared.lock().await).await,
                Err(e) => Response::error(e),
            }
        }

        Request::UpdateOrg { org_id, name, billing_email } => {
            let Some(vault) = shared.lock().await.active().cloned() else {
                return Response::error(keyward_core::fault!("err.noAccount"));
            };
            match vault.update_org(&org_id, &name, &billing_email).await {
                Ok(()) => refreshed(&mut *shared.lock().await).await,
                Err(e) => Response::error(e),
            }
        }

        Request::DeleteOrg { org_id, master_password } => {
            let Some(vault) = shared.lock().await.active().cloned() else {
                return Response::error(keyward_core::fault!("err.noAccount"));
            };
            match vault.delete_org(&org_id, &master_password).await {
                Ok(()) => refreshed(&mut *shared.lock().await).await,
                Err(e) => Response::error(e),
            }
        }

        Request::SiteIcon { domain } => {
            let base = shared.lock().await.active().map(|v| v.account().base_url.clone());
            match base {
                Some(base) => Response::SiteIcon { data_url: crate::icons::site_icon(&base, &domain).await },
                None => Response::SiteIcon { data_url: None },
            }
        }

        Request::PushNotice { body } => {
            let mut st = shared.lock().await;
            st.notices.push(keyward_core::proto::Notice { title: "keyward".into(), body });
            Response::Pong
        }

        Request::TakeNotices => {
            let mut st = shared.lock().await;
            let notices = std::mem::take(&mut st.notices);
            Response::Notices { notices }
        }

        Request::OrgMembers { org_id } => {
            let st = shared.lock().await;
            let Some(vault) = st.active() else {
                return Response::error(keyward_core::fault!("err.noActiveAccount"));
            };
            match vault.org_members(&org_id).await {
                Ok(members) => Response::OrgMembers { members },
                Err(e) => Response::error(e),
            }
        }

        Request::RevealSecret { entry_id, field } => {
            let (vault, grace, always_ask) = {
                let st = shared.lock().await;
                match st.active() {
                    Some(v) => (v.clone(), st.settings.biometric_grace_seconds, st.settings.touch_id_for_secrets),
                    None => return Response::error(keyward_core::fault!("err.noAccount")),
                }
            };
            if let Err(e) = guard_secret(peer, &vault, &entry_id, &field, grace, always_ask) {
                return Response::error(e);
            }
            let vault = match vault_after_touch(shared, &vault.account().id).await {
                Ok(v) => v,
                Err(e) => return Response::error(e),
            };
            match vault.secret(&entry_id, &field) {
                Ok(value) => Response::Secret { value },
                Err(e) => Response::error(e),
            }
        }

        Request::CopySecret { entry_id, field } => {
            // The lock is let go before the sensor: a Touch ID prompt holds a
            // thread for a minute, and all that time the daemon would answer
            // nobody.
            let (vault, settings) = {
                let st = shared.lock().await;
                match st.active() {
                    Some(v) => (v.clone(), st.settings.clone()),
                    None => return Response::error(keyward_core::fault!("err.noAccount")),
                }
            };
            if let Err(e) = guard_secret(
                peer,
                &vault,
                &entry_id,
                &field,
                settings.biometric_grace_seconds,
                settings.touch_id_for_secrets,
            ) {
                return Response::error(e);
            }
            let vault = match vault_after_touch(shared, &vault.account().id).await {
                Ok(v) => v,
                Err(e) => return Response::error(e),
            };
            match vault.secret(&entry_id, &field) {
                Ok(value) => match clipboard::put(&value) {
                    Ok(count) => match (field.is_sensitive(), clipboard::clear_after(&settings)) {
                        (true, Some(after)) => {
                            clipboard::clear_later(count, after);
                            Response::Copied { clears_in: after.as_secs() }
                        }
                        _ => Response::Copied { clears_in: 0 },
                    },
                    Err(e) => Response::error(e),
                },
                Err(e) => Response::error(e),
            }
        }

        Request::CreateItem { kind, folder_id, edit } => {
            let Some(vault) = shared.lock().await.active().cloned() else {
                return Response::error(keyward_core::fault!("err.noAccount"));
            };
            match vault.create_item(kind, folder_id, None, Vec::new(), edit).await {
                Ok(_id) => refreshed(&mut *shared.lock().await).await,
                Err(e) => Response::error(e),
            }
        }

        Request::TrashItem { entry_id } => {
            let Some(vault) = shared.lock().await.active().cloned() else {
                return Response::error(keyward_core::fault!("err.noAccount"));
            };
            match vault.trash_item(&entry_id).await {
                Ok(()) => refreshed(&mut *shared.lock().await).await,
                Err(e) => Response::error(e),
            }
        }

        Request::RestoreItem { entry_id } => {
            let Some(vault) = shared.lock().await.active().cloned() else {
                return Response::error(keyward_core::fault!("err.noAccount"));
            };
            match vault.restore_item(&entry_id).await {
                Ok(()) => refreshed(&mut *shared.lock().await).await,
                Err(e) => Response::error(e),
            }
        }

        Request::PurgeItems { entry_ids } => {
            let Some(vault) = shared.lock().await.active().cloned() else {
                return Response::error(keyward_core::fault!("err.noAccount"));
            };
            // An empty list means "the whole trash": it is emptied whole more
            // often than one item at a time.
            let ids = if entry_ids.is_empty() { vault.trashed_ids() } else { entry_ids };
            match vault.purge_items(&ids).await {
                Ok(_) => refreshed(&mut *shared.lock().await).await,
                Err(e) => Response::error(e),
            }
        }

        Request::RecentItems => {
            let st = shared.lock().await;
            let Some(vault) = st.active() else { return Response::error(keyward_core::fault!("err.noActiveAccount")) };
            match vault.history() {
                Ok(history) => Response::Recent { ids: history.recent.clone() },
                Err(e) => Response::error(e),
            }
        }

        Request::GeneratorHistory => {
            let Some(vault) = shared.lock().await.active().cloned() else {
                return Response::error(keyward_core::fault!("err.noActiveAccount"));
            };
            match vault.history() {
                Ok(history) => Response::History { history: history.view() },
                Err(e) => Response::error(e),
            }
        }

        Request::CopyGenerated { taken, index } => {
            let st = shared.lock().await;
            let Some(vault) = st.active().cloned() else {
                return Response::error(keyward_core::fault!("err.noActiveAccount"));
            };
            let settings = st.settings.clone();
            drop(st);
            let history = match vault.history() {
                Ok(h) => h,
                Err(e) => return Response::error(e),
            };
            let list = if taken { &history.taken } else { &history.made };
            let Some(value) = list.get(index).map(|v| keyward_core::proto::Secret::new(v.clone())) else {
                return Response::error(keyward_core::fault!("err.generatedGone"));
            };
            drop(history);
            match clipboard::put(&value) {
                Ok(count) => {
                    // A copied password was almost certainly pasted somewhere,
                    // and is worth remembering apart from the merely shown.
                    let _ = vault.remember_generated(true, &value);
                    match clipboard::clear_after(&settings) {
                        Some(after) => {
                            clipboard::clear_later(count, after);
                            Response::Copied { clears_in: after.as_secs() }
                        }
                        None => Response::Copied { clears_in: 0 },
                    }
                }
                Err(e) => Response::error(e),
            }
        }

        Request::RevealGenerated { taken, index } => {
            let Some(vault) = shared.lock().await.active().cloned() else {
                return Response::error(keyward_core::fault!("err.noActiveAccount"));
            };
            match vault.history() {
                Ok(history) => {
                    let list = if taken { &history.taken } else { &history.made };
                    match list.get(index) {
                        Some(v) => Response::Secret { value: v.clone().into() },
                        None => Response::error(keyward_core::fault!("err.generatedGone")),
                    }
                }
                Err(e) => Response::error(e),
            }
        }

        Request::SshKeyDraft { source } => {
            use keyward_core::edits::{SshDraftSource, SshDraftView};
            let stored = match &source {
                SshDraftSource::Stored { entry_id } => match shared.lock().await.active().cloned() {
                    Some(vault) => Some(vault.secret(entry_id, &keyward_core::detail::SecretField::PrivateKey)),
                    None => Some(Err(keyward_core::fault!("err.noActiveAccount"))),
                },
                _ => None,
            };
            let made = match &source {
                SshDraftSource::Stored { .. } => match stored.expect("read above for a stored key") {
                    Ok(private_key) => keyward_sshkey::import(private_key.as_str(), None),
                    Err(e) => Err(e),
                },
                SshDraftSource::Generate { algorithm } => keyward_sshkey::generate(*algorithm, ""),
                SshDraftSource::Clipboard { passphrase } => match clipboard::read_text() {
                    Some(text) => keyward_sshkey::import(&text, passphrase.as_ref().map(|p| p.as_str())),
                    None => Err(keyward_core::fault!("err.sshKeyEmpty")),
                },
                SshDraftSource::Paste { private_key, passphrase } => {
                    keyward_sshkey::import(private_key, passphrase.as_ref().map(|p| p.as_str()))
                }
            };
            drop(source);
            match made {
                Ok(material) => {
                    let s = material.summary();
                    let id = keyward_vault::sshdraft::put(material);
                    Response::SshDraft {
                        draft: SshDraftView { id, public_key: s.public_key, fingerprint: s.fingerprint, algorithm: s.algorithm },
                    }
                }
                Err(e) => Response::error(e),
            }
        }

        Request::CopySshDraft { id } => {
            let settings = shared.lock().await.settings.clone();
            match keyward_vault::sshdraft::with(&id, |m| clipboard::put(&m.private_key)) {
                Some(Ok(count)) => match clipboard::clear_after(&settings) {
                    Some(after) => {
                        clipboard::clear_later(count, after);
                        Response::Copied { clears_in: after.as_secs() }
                    }
                    None => Response::Copied { clears_in: 0 },
                },
                Some(Err(e)) => Response::error(e),
                None => Response::error(keyward_core::fault!("err.sshDraftGone")),
            }
        }

        Request::RememberGenerated { taken, value } => {
            let Some(vault) = shared.lock().await.active().cloned() else {
                return Response::error(keyward_core::fault!("err.noActiveAccount"));
            };
            match vault.remember_generated(taken, &value) {
                Ok(history) => Response::History { history: history.view() },
                Err(e) => Response::error(e),
            }
        }

        Request::ForgetGenerated { taken } => {
            let Some(vault) = shared.lock().await.active().cloned() else {
                return Response::error(keyward_core::fault!("err.noActiveAccount"));
            };
            match vault.forget_generated(taken) {
                Ok(history) => Response::History { history: history.view() },
                Err(e) => Response::error(e),
            }
        }

        Request::RememberOpened { entry_id } => {
            let Some(vault) = shared.lock().await.active().cloned() else {
                return Response::error(keyward_core::fault!("err.noActiveAccount"));
            };
            match vault.remember_opened(&entry_id) {
                Ok(()) => Response::Pong,
                Err(e) => Response::error(e),
            }
        }

        Request::GeneratePassword { spec } => match keyward_core::generator::password(&spec) {
            Ok(value) => {
                let value: keyward_core::proto::Secret = value.into();
                // The history is kept here, by the daemon: the window no
                // longer sends a password back to have it remembered. With the
                // vault locked there is no history, and rightly so.
                if let Some(vault) = shared.lock().await.active().cloned() {
                    let _ = vault.remember_generated(false, &value);
                }
                Response::Secret { value }
            }
            Err(e) => Response::error(e),
        },

        Request::CopyText { value } => {
            let st = shared.lock().await;
            match clipboard::put(&value) {
                Ok(count) => match clipboard::clear_after(&st.settings) {
                    Some(after) => {
                        clipboard::clear_later(count, after);
                        Response::Copied { clears_in: after.as_secs() }
                    }
                    None => Response::Copied { clears_in: 0 },
                },
                Err(e) => Response::error(e),
            }
        }

        Request::UpdateItem { entry_id, edit } => {
            let mut st = shared.lock().await;
            let Some(vault) = st.active() else {
                return Response::error(keyward_core::fault!("err.noAccount"));
            };
            match vault.update_item(&entry_id, edit).await {
                Ok(e) => {
                    let _ = st.reload();
                    Response::Edit { edit: e }
                }
                Err(e) => Response::error(e),
            }
        }

        Request::MergeCompare { entry_ids } => {
            let st = shared.lock().await;
            let Some(vault) = st.active() else {
                return Response::error(keyward_core::fault!("err.noAccount"));
            };
            match vault.compare_for_merge(&entry_ids) {
                Ok(comparison) => Response::MergeComparison { comparison },
                Err(e) => Response::error(e),
            }
        }

        Request::MergeItems { plan } => {
            let Some(vault) = shared.lock().await.active().cloned() else {
                return Response::error(keyward_core::fault!("err.noAccount"));
            };
            match vault.merge_items(&plan).await {
                Ok(()) => refreshed(&mut *shared.lock().await).await,
                Err(e) => Response::error(e),
            }
        }

        Request::Edits => Response::Edits { edits: keyward_vault::edits_of(shared.lock().await.vaults.values()) },

        Request::RegeneratePassword { entry_id, spec } => {
            let mut st = shared.lock().await;
            let Some(vault) = st.active() else {
                return Response::error(keyward_core::fault!("err.noAccount"));
            };
            match vault.regenerate_password(&entry_id, &spec).await {
                Ok(e) => {
                    let _ = st.reload();
                    Response::Edit { edit: e }
                }
                Err(e) => Response::error(e),
            }
        }

        Request::RestoreTotp { entry_id } => {
            let mut st = shared.lock().await;
            let Some(vault) = st.active() else {
                return Response::error(keyward_core::fault!("err.noAccount"));
            };
            match vault.restore_totp(&entry_id).await {
                Ok(e) => {
                    let _ = st.reload();
                    Response::Edit { edit: e }
                }
                Err(e) => Response::error(e),
            }
        }

        Request::RetryEdit { id } => {
            let mut st = shared.lock().await;
            let Some(vault) = st.active() else {
                return Response::error(keyward_core::fault!("err.noAccount"));
            };
            match vault.retry_edit(&id).await {
                Ok(e) => {
                    let _ = st.reload();
                    Response::Edit { edit: e }
                }
                Err(e) => Response::error(e),
            }
        }

        Request::RollbackEdit { id } => {
            let mut st = shared.lock().await;
            let Some(vault) = st.active() else {
                return Response::error(keyward_core::fault!("err.noAccount"));
            };
            match vault.rollback_edit(&id).await {
                Ok(e) => {
                    let _ = st.reload();
                    Response::Edit { edit: e }
                }
                Err(e) => Response::error(e),
            }
        }

        Request::DiscardEdit { id } => match keyward_vault::edits::remove(&id) {
            Ok(()) => Response::Edits { edits: keyward_vault::edits_of(shared.lock().await.vaults.values()) },
            Err(e) => Response::error(e),
        },

        Request::GetSettings => {
            let st = shared.lock().await;
            Response::Settings { settings: st.settings.clone() }
        }

        Request::SetSettings { settings } => {
            if let Err(e) = settings.validate() {
                return Response::error(e);
            }
            let mut st = shared.lock().await;
            if let Err(e) = settings.save() {
                return Response::error(e);
            }
            if settings.start_on_login != st.settings.start_on_login {
                if let Err(e) = crate::autostart::set(settings.start_on_login) {
                    tracing::warn!(error = %e, "start-at-login was not changed");
                }
            }
            speak(&settings);
            st.settings = settings;
            Response::Settings { settings: st.settings.clone() }
        }

        Request::Plugins => Response::Plugins { plugins: crate::plugins::manifests() },

        // A plugin's envelope: the mutex is not held here — a plugin goes out
        // to the network and to sockets, and the daemon has to stay alive
        // meanwhile.
        Request::Plugin { plugin, action, payload } => {
            crate::plugins::call(shared, &plugin, &action, payload, peer).await
        }

        Request::PluginWithFields { plugin, action, mut payload, entry_id, fields, into } => {
            let (vault, grace, always_ask) = {
                let st = shared.lock().await;
                match st.active() {
                    Some(v) => (v.clone(), st.settings.biometric_grace_seconds, st.settings.touch_id_for_secrets),
                    None => return Response::error(keyward_core::fault!("err.noAccount")),
                }
            };
            let mut values = Vec::with_capacity(fields.len());
            for name in &fields {
                let field = keyward_core::detail::SecretField::Custom(name.clone());
                if let Err(e) = guard_secret(peer, &vault, &entry_id, &field, grace, always_ask) {
                    return Response::error(e);
                }
                let now = match vault_after_touch(shared, &vault.account().id).await {
                    Ok(v) => v,
                    Err(e) => return Response::error(e),
                };
                match now.secret(&entry_id, &field) {
                    Ok(v) if !v.trim().is_empty() => values.push(serde_json::Value::String(String::clone(&v))),
                    Ok(_) => {}
                    Err(e) => return Response::error(e),
                }
            }
            match payload.as_object_mut() {
                Some(map) => {
                    map.insert(into, serde_json::Value::Array(values));
                }
                None => return Response::error(keyward_core::fault!("err.pluginPayloadNotObject")),
            }
            crate::plugins::call(shared, &plugin, &action, payload, peer).await
        }

        // An installation puts a plugin in switched off and returns its card:
        // consent to the permissions is given separately, after seeing the
        // list.
        Request::PluginInstall { path } => crate::plugins::install(&path).await,
        // The showcase and its sources: the network, the cache and somebody
        // else's json are all inside `plugins`, and the daemon only passes the
        // question along.
        Request::PluginCatalog { refresh } => crate::plugins::catalog(shared, refresh).await,
        Request::PluginSources { set } => crate::plugins::source_list(set),
        Request::PluginTrust { publisher, trust } => {
            crate::plugins::trust(shared, &publisher, trust).await
        }
        Request::PluginRemove { id } => crate::plugins::remove(&id).await,
        Request::PluginEnable { id, on } => crate::plugins::enable(shared, &id, on).await,

        // ── Passkeys ────────────────────────────────────────────────────
        Request::PasskeyOffers { sign_in } => crate::passkeys::offers(shared, peer, sign_in).await,
        Request::PasskeyHomes { sign_in } => crate::passkeys::homes(shared, peer, sign_in).await,
        Request::PasskeySignIn { request } => crate::passkeys::sign_in(shared, peer, request).await,
        Request::PasskeyRegister { request } => crate::passkeys::register(shared, peer, request).await,
        Request::PasskeyBridge { key, signed, sig } => crate::passkeys::bridge(shared, peer, &key, &signed, &sig).await,

        Request::Extensions => {
            let Some(vault) = shared.lock().await.active().cloned() else {
                return Response::error(keyward_core::fault!("err.noAccount"));
            };
            match crate::extensions::paired(&vault) {
                Ok(paired) => Response::Extensions { paired, pending: crate::extensions::pending() },
                Err(e) => Response::error(e),
            }
        }
        Request::ExtensionPair { key } => {
            let Some(vault) = shared.lock().await.active().cloned() else {
                return Response::error(keyward_core::fault!("err.noAccount"));
            };
            // The words are in the prompt itself: the person compares them
            // with the extension's screen where they confirm.
            let Some(words) = crate::extensions::pairing_words(&key).map(|w| w.join(" ")) else {
                return Response::error(keyward_core::fault!("err.extensionNotAsking"));
            };
            let prompt = keyward_core::text::t("touch.pairExtension", &[("words", &words)]);
            match tokio::task::spawn_blocking(move || keyward_vault::biometric::confirm(&prompt)).await {
                Ok(Ok(())) => {}
                Ok(Err(e)) => return Response::error(anyhow::anyhow!("{}", keyward_core::text::t("err.notConfirmed", &[("reason", &e.to_string())]))),
                Err(e) => return Response::error(anyhow::anyhow!("the sensor's prompt fell over: {e}")),
            }
            if let Err(e) = crate::extensions::pair(&vault, &key).await {
                return Response::error(e);
            }
            tracing::info!(words, "a browser extension was paired");
            let mut st = shared.lock().await;
            if let Err(e) = st.reload() {
                tracing::error!(error = %e, "the items were not re-read after a pairing changed");
            }
            match st.active().map(crate::extensions::paired) {
                Some(Ok(paired)) => Response::Extensions { paired, pending: crate::extensions::pending() },
                Some(Err(e)) => Response::error(e),
                None => Response::error(keyward_core::fault!("err.noAccount")),
            }
        }
        Request::ExtensionUnpair { key } => {
            let Some(vault) = shared.lock().await.active().cloned() else {
                return Response::error(keyward_core::fault!("err.noAccount"));
            };
            if let Err(e) = crate::extensions::unpair(&vault, &key).await {
                return Response::error(e);
            }
            let mut st = shared.lock().await;
            if let Err(e) = st.reload() {
                tracing::error!(error = %e, "the items were not re-read after a pairing changed");
            }
            match st.active().map(crate::extensions::paired) {
                Some(Ok(paired)) => Response::Extensions { paired, pending: crate::extensions::pending() },
                Some(Err(e)) => Response::error(e),
                None => Response::error(keyward_core::fault!("err.noAccount")),
            }
        }

        Request::NoteFields { entry_id } => {
            let st = shared.lock().await;
            let names = st.active().map(|v| v.note_field_names(&entry_id)).unwrap_or_default();
            Response::Fields { names }
        }

        // ── Touch ID ────────────────────────────────────────────────────
        Request::BiometricUnlock => {
            // The lock is let go before the sensor: waiting for a finger took
            // up to a minute, and all that while the daemon answered nobody —
            // the window saw "the daemon is not answering".
            let Some(email) = shared.lock().await.active().map(|v| v.account().email.clone()) else {
                return Response::error(keyward_core::fault!("err.noAccount"));
            };
            let asked = email.clone();
            let password = match tokio::task::spawn_blocking(move || keyward_vault::biometric::recall(&asked)).await {
                Ok(Ok(p)) => zeroize::Zeroizing::new(p),
                Ok(Err(e)) => return Response::error(e),
                Err(e) => return Response::error(anyhow::anyhow!("the Touch ID task fell over: {e}")),
            };
            let mut st = shared.lock().await;
            // Another account may have been chosen while the finger was on its
            // way: the password is only for the one it was asked for.
            if st.active().map(|v| v.account().email.as_str()) != Some(email.as_str()) {
                return Response::error(keyward_core::fault!("err.noAccount"));
            }
            let Some(vault) = st.active_mut() else {
                return Response::error(keyward_core::fault!("err.noAccount"));
            };
            match vault.unlock(&password) {
                Ok(()) => {
                    ensure_snapshot(&mut st).await;
                    refreshed(&mut st).await
                }
                Err(e) => Response::error(keyward_core::fault!(
                    "err.keychainPasswordStale",
                    "reason" => e,
                )),
            }
        }

        Request::BiometricRemember { password } => {
            let mut st = shared.lock().await;
            let Some(email) = st.active().map(|v| v.account().email.clone()) else {
                return Response::error(keyward_core::fault!("err.noAccount"));
            };
            // The password is checked before saving: remembering a wrong one
            // means getting a Touch ID that always refuses.
            if let Some(vault) = st.active_mut() {
                if let Err(e) = vault.unlock(&password) {
                    return Response::error(e);
                }
            }
            match keyward_vault::biometric::remember(&email, &password) {
                Ok(()) => refreshed(&mut st).await,
                Err(e) => Response::error(e),
            }
        }

        Request::BiometricForget => {
            let st = shared.lock().await;
            let Some(email) = st.active().map(|v| v.account().email.clone()) else {
                return Response::error(keyward_core::fault!("err.noAccount"));
            };
            match keyward_vault::biometric::forget(&email) {
                Ok(()) => Response::Vault { state: st.vault_state() },
                Err(e) => Response::error(e),
            }
        }

        // -- The Bitwarden account -------------------------------------------
        Request::AccountProfile => {
            let Some(vault) = shared.lock().await.active().cloned() else {
                return Response::error(keyward_core::fault!("err.noAccount"));
            };
            match vault.account_profile().await {
                Ok(profile) => Response::AccountProfile { profile },
                Err(e) => Response::error(e),
            }
        }

        Request::AccountSetProfile { name, hint } => {
            account_op(shared, |v| async move { v.set_profile(&name, hint.as_deref()).await }).await
        }

        Request::AccountSetAvatar { color } => {
            account_op(shared, |v| async move { v.set_avatar(color.as_deref()).await }).await
        }

        Request::AccountChangePassword { current, new, hint } => {
            account_relogin(shared, |mut v| async move {
                let r = v.change_password(&current, &new, hint.as_deref()).await;
                (v, r)
            })
            .await
        }

        Request::AccountEmailToken { master_password, new_email } => {
            account_op(shared, |v| async move { v.request_email_token(&master_password, &new_email).await }).await
        }

        Request::AccountChangeEmail { master_password, new_email, token } => {
            account_relogin(shared, |mut v| async move {
                let r = v.change_email(&master_password, &new_email, &token).await;
                (v, r)
            })
            .await
        }

        Request::AccountChangeKdf { master_password, kdf } => {
            account_relogin(shared, |mut v| async move {
                let r = v.change_kdf(&master_password, &kdf).await;
                (v, r)
            })
            .await
        }

        Request::AccountDeauthorize { master_password } => {
            account_relogin(shared, |mut v| async move {
                let r = v.deauthorize(&master_password).await;
                (v, r)
            })
            .await
        }

        Request::AccountDelete { master_password } => {
            let (id, vault) = {
                let st = shared.lock().await;
                match st.active() {
                    Some(v) => (v.account().id.clone(), v.clone()),
                    None => return Response::error(keyward_core::fault!("err.noAccount")),
                }
            };
            if let Err(e) = vault.delete_account(&master_password).await {
                return Response::error(e);
            }
            // The server has forgotten the account already; the vault itself
            // erased the local traces, and the daemon's register is what is
            // left.
            let mut st = shared.lock().await;
            st.logout(&id);
            if let Err(e) = st.registry.save() {
                return Response::error(e);
            }
            refreshed(&mut st).await
        }

        Request::AccountPurge { master_password } => {
            org_op(shared, |v| async move { v.purge(&master_password).await }).await
        }

        // -- The second factor ------------------------------------------------
        Request::TwoFactorStatus => {
            let Some(vault) = shared.lock().await.active().cloned() else {
                return Response::error(keyward_core::fault!("err.noAccount"));
            };
            match vault.two_factor_status().await {
                Ok(status) => Response::TwoFactorStatus { status },
                Err(e) => Response::error(e),
            }
        }

        Request::TwoFactorAuthenticatorSetup { master_password } => {
            let Some(vault) = shared.lock().await.active().cloned() else {
                return Response::error(keyward_core::fault!("err.noAccount"));
            };
            match vault.authenticator_setup(&master_password).await {
                Ok(setup) => Response::AuthenticatorSetup { setup },
                Err(e) => Response::error(e),
            }
        }

        Request::TwoFactorAuthenticatorEnable { master_password, key, token } => {
            let Some(vault) = shared.lock().await.active().cloned() else {
                return Response::error(keyward_core::fault!("err.noAccount"));
            };
            match vault.authenticator_enable(&master_password, &key, &token).await {
                Ok(status) => Response::TwoFactorStatus { status },
                Err(e) => Response::error(e),
            }
        }

        Request::TwoFactorEmailSetup { master_password } => {
            let Some(vault) = shared.lock().await.active().cloned() else {
                return Response::error(keyward_core::fault!("err.noAccount"));
            };
            match vault.email_two_factor_setup(&master_password).await {
                Ok(setup) => Response::EmailTwoFactorSetup { setup },
                Err(e) => Response::error(e),
            }
        }

        Request::TwoFactorEmailSend { master_password, email } => {
            account_op(shared, |v| async move { v.email_two_factor_send(&master_password, &email).await }).await
        }

        Request::TwoFactorEmailEnable { master_password, email, token } => {
            let Some(vault) = shared.lock().await.active().cloned() else {
                return Response::error(keyward_core::fault!("err.noAccount"));
            };
            match vault.email_two_factor_enable(&master_password, &email, &token).await {
                Ok(status) => Response::TwoFactorStatus { status },
                Err(e) => Response::error(e),
            }
        }

        Request::TwoFactorDisable { master_password, provider } => {
            let Some(vault) = shared.lock().await.active().cloned() else {
                return Response::error(keyward_core::fault!("err.noAccount"));
            };
            match vault.two_factor_disable(&master_password, provider).await {
                Ok(status) => Response::TwoFactorStatus { status },
                Err(e) => Response::error(e),
            }
        }

        Request::TwoFactorRecoveryCode { master_password } => {
            let Some(vault) = shared.lock().await.active().cloned() else {
                return Response::error(keyward_core::fault!("err.noAccount"));
            };
            match vault.recovery_code(&master_password).await {
                Ok(code) => Response::RecoveryCode { code },
                Err(e) => Response::error(e),
            }
        }

        // -- Devices and export -----------------------------------------------
        Request::Devices => {
            let Some(vault) = shared.lock().await.active().cloned() else {
                return Response::error(keyward_core::fault!("err.noAccount"));
            };
            match vault.devices().await {
                Ok(devices) => Response::Devices { devices },
                Err(e) => Response::error(e),
            }
        }

        Request::ExportVault { master_password, format } => {
            // Decrypting the whole vault is noticeable work and the lock is
            // not held for it: a copy of the vault manages on its own.
            let (vault, grace, always_ask) = {
                let st = shared.lock().await;
                match st.active() {
                    Some(v) => (v.clone(), st.settings.biometric_grace_seconds, st.settings.touch_id_for_secrets),
                    None => return Response::error(keyward_core::fault!("err.noAccount")),
                }
            };
            // An export carries every password out at once, under the same
            // lock as one of them. The window of trust counts here: a person
            // types the master password by hand in this very request
            // anyway.
            if let Err(e) = guard(peer, "touch.exportVault", false, grace, always_ask, false) {
                return Response::error(e);
            }
            let vault = match vault_after_touch(shared, &vault.account().id).await {
                Ok(v) => v,
                Err(e) => return Response::error(e),
            };
            match vault.export(&master_password, format) {
                Ok((filename, content)) => Response::Export { filename, content },
                Err(e) => Response::error(e),
            }
        }

        // ── PIN ─────────────────────────────────────────────────────────
        Request::PinSet { pin, master_password } => {
            let mut st = shared.lock().await;
            let Some(email) = st.active().map(|v| v.account().email.clone()) else {
                return Response::error(keyward_core::fault!("err.noAccount"));
            };
            // The password is checked by unlocking, as with Touch ID:
            // remembering a wrong password under a PIN means getting a PIN that
            // does not open anything.
            if let Some(vault) = st.active_mut() {
                if let Err(e) = vault.unlock(&master_password) {
                    return Response::error(e);
                }
            }
            match keyward_vault::pin::set(&email, &pin, &master_password) {
                Ok(()) => {
                    ensure_snapshot(&mut st).await;
                    refreshed(&mut st).await
                }
                Err(e) => Response::error(e),
            }
        }

        Request::PinClear => {
            let st = shared.lock().await;
            let Some(email) = st.active().map(|v| v.account().email.clone()) else {
                return Response::error(keyward_core::fault!("err.noAccount"));
            };
            match keyward_vault::pin::forget(&email) {
                Ok(()) => Response::Vault { state: st.vault_state() },
                Err(e) => Response::error(e),
            }
        }

        Request::PinUnlock { pin } => {
            let mut st = shared.lock().await;
            let Some(email) = st.active().map(|v| v.account().email.clone()) else {
                return Response::error(keyward_core::fault!("err.noAccount"));
            };
            let password = match keyward_vault::pin::recall(&email, &pin) {
                Ok(p) => p,
                Err(e) => return Response::error(e),
            };
            let Some(vault) = st.active_mut() else {
                return Response::error(keyward_core::fault!("err.noAccount"));
            };
            match vault.unlock(&password) {
                Ok(()) => {
                    ensure_snapshot(&mut st).await;
                    refreshed(&mut st).await
                }
                // The password under the PIN is stale, so the PIN itself is of
                // no further use.
                Err(e) => {
                    let _ = keyward_vault::pin::forget(&email);
                    Response::error(keyward_core::fault!("err.pinPasswordStale", "reason" => e))
                }
            }
        }
    }
}


#[cfg(test)]
mod cache_tests {
    /// After a switch of accounts the window got the catalogue of the one it
    /// left, and every item it opened was "not found" in the one now active.
    #[test]
    fn a_catalogue_is_served_only_to_its_own_account() {
        let mut cache = super::Cache::default();
        let a = || keyward_core::items::Catalog { trash: 1, ..Default::default() };
        let b = || keyward_core::items::Catalog { trash: 2, ..Default::default() };
        assert_eq!(cache.catalog(Some("a".into()), a).trash, 1);
        assert_eq!(cache.catalog(Some("a".into()), b).trash, 1, "kept for its own account");
        assert_eq!(cache.catalog(Some("b".into()), b).trash, 2, "another account's is never served");
        assert_eq!(cache.catalog(None, a).trash, 1, "nor a catalogue to no account at all");
    }
}

#[cfg(test)]
mod tests {

    //! The lock's table of decisions. The sensor is replaced with a function
    //! pointer: the test has to run in CI, where there is no finger.

    // The "ask the sensor for every password" setting is off in the tests, as
    // it is by default: what is checked is the behaviour a person sees.
    const ASK_NEVER: bool = false;
    // The setting is on: only then is the sensor asked for an ordinary
    // password, and only then does the window of trust mean anything at all.
    const ASK_ALWAYS: bool = true;

    use std::sync::atomic::{AtomicUsize, Ordering};
    use std::sync::Mutex;
    use std::time::{Duration, Instant};

    use super::*;
    use crate::peer::{Peer, Trust};

    /// How many times the sensor was asked. There is one counter per process,
    /// so the tests that read it run in turn.
    static ASKED: AtomicUsize = AtomicUsize::new(0);
    static SERIAL: Mutex<()> = Mutex::new(());

    fn touched(_why: &str) -> anyhow::Result<()> {
        ASKED.fetch_add(1, Ordering::Relaxed);
        Ok(())
    }

    fn declined(_why: &str) -> anyhow::Result<()> {
        ASKED.fetch_add(1, Ordering::Relaxed);
        anyhow::bail!("the wrong finger")
    }

    fn ours() -> Peer {
        Peer::Socket { pid: 42, path: Some("/Applications/keyward.app".into()), trust: Trust::App }
    }

    fn alien() -> Peer {
        Peer::Socket { pid: 43, path: Some("/usr/bin/nc".into()), trust: Trust::Alien }
    }

    fn unsigned_daemon() -> Peer {
        Peer::Socket { pid: 44, path: None, trust: Trust::Unknown }
    }

    fn cli() -> Peer {
        Peer::Socket { pid: 45, path: Some("/Users/u/.local/bin/keyward".into()), trust: Trust::Cli }
    }

    fn bridge() -> Peer {
        Peer::Socket { pid: 46, path: None, trust: Trust::Bridge }
    }

    #[test]
    fn an_outsider_may_ping_and_nothing_else() {
        assert_eq!(admit(&alien(), &Request::Ping), Admit::Yes);
        for req in [
            Request::Status,
            Request::Vault,
            Request::Items,
            Request::ItemDetail { entry_id: "x".into() },
            Request::GetSettings,
            Request::BiometricUnlock,
            Request::Lock,
        ] {
            assert_eq!(admit(&alien(), &req), Admit::No(REFUSED_ALIEN), "{req:?}");
        }
    }

    #[test]
    fn the_cli_gets_what_the_install_and_ssh_need_and_no_value() {
        for req in [
            Request::Status,
            Request::Lock,
            Request::Plugins,
            Request::Plugin { plugin: "ssh".into(), action: "resolve".into(), payload: serde_json::Value::Null },
        ] {
            assert_eq!(admit(&cli(), &req), Admit::Yes, "{req:?}");
        }
        for req in [
            Request::Items,
            Request::ItemDetail { entry_id: "x".into() },
            Request::GetSettings,
            Request::Shutdown,
            Request::Plugin { plugin: "hashicorp".into(), action: "status".into(), payload: serde_json::Value::Null },
            Request::Plugin { plugin: "ssh".into(), action: "keys".into(), payload: serde_json::Value::Null },
        ] {
            assert_eq!(admit(&cli(), &req), Admit::No(REFUSED_CLI), "{req:?}");
        }
        // Switching a plugin on is consent to its permissions: the finger.
        assert_eq!(admit(&cli(), &Request::PluginEnable { id: "kube".into(), on: true }), Admit::Confirm("touch.cliPlugins"));
        assert_eq!(
            admit(&cli(), &Request::CreateItem { kind: 1, folder_id: None, edit: Default::default() }),
            Admit::Confirm("touch.cliWriteItem")
        );
    }

    #[test]
    fn the_window_is_admitted_and_the_bridge_keeps_to_passkeys() {
        assert_eq!(admit(&ours(), &Request::Items), Admit::Yes);
        assert_eq!(admit(&bridge(), &Request::Ping), Admit::Yes);
        assert_eq!(admit(&bridge(), &Request::Items), Admit::No(REFUSED_BRIDGE));
    }

    /// A field of somebody else's: a password, a login, a private key, or a
    /// custom field a person named themselves.
    const FOREIGN: bool = false;
    /// A field of the plugin's own: `kw-host`, `kw-vault-addr`.
    const OWN: bool = true;

    #[test]
    fn the_table_of_decisions() {
        // A verified peer is the application, and it asks for a password at a
        // person's request: silently. The lock on the socket has done its work
        // already.
        assert_eq!(decide(&ours(), false, false, false, FOREIGN), Step::Give);
        assert_eq!(decide(&ours(), false, true, false, FOREIGN), Step::Give);
        // A strict field — a private key, a `reprompt` — always gets the
        // sensor.
        assert_eq!(decide(&ours(), true, true, false, FOREIGN), Step::Ask);
        // The person asked to be asked always, so we ask — but the window of
        // trust works: three touches in a row is not forgiven.
        assert_eq!(decide(&ours(), false, false, true, FOREIGN), Step::Ask);
        assert_eq!(decide(&ours(), false, true, true, FOREIGN), Step::Give);

        // An unverified peer is refused under any circumstances.
        assert_eq!(decide(&alien(), false, true, false, FOREIGN), Step::Deny(REFUSED_ALIEN));
        assert_eq!(decide(&alien(), true, false, true, FOREIGN), Step::Deny(REFUSED_ALIEN));
        // An outsider process is not touched by "its own field": `kw-` is no
        // pass.
        assert_eq!(decide(&alien(), false, false, false, OWN), Step::Deny(REFUSED_ALIEN));

        // The daemon is not signed, so there is nothing to compare against and
        // the sensor decides.
        assert_eq!(decide(&unsigned_daemon(), false, false, false, FOREIGN), Step::Ask);
        assert_eq!(decide(&unsigned_daemon(), false, true, false, FOREIGN), Step::Give);

        // Plugins: our own silently; somebody else's only its own fields.
        assert_eq!(decide(&Peer::Builtin, true, false, true, FOREIGN), Step::Give);
        assert_eq!(decide(&Peer::External, false, true, false, FOREIGN), Step::Deny(REFUSED_PLUGIN));
        assert_eq!(decide(&Peer::External, false, false, false, OWN), Step::Give);
        // Even its own field is withheld when the item is marked "ask again":
        // there is nobody to ask at the sensor — no person is at the
        // machine.
        assert_eq!(decide(&Peer::External, true, false, false, OWN), Step::Deny(REFUSED_REPROMPT));
    }

    #[test]
    fn the_lock_covers_passwords_only() {
        use keyward_core::detail::SecretField;

        let field = SecretField::Password;
        assert!(wants_secret(&Request::RevealSecret { entry_id: "a".into(), field: field.clone() }));
        assert!(wants_secret(&Request::CopySecret { entry_id: "a".into(), field }));
        assert!(wants_secret(&Request::ExportVault {
            master_password: "x".to_string().into(),
            format: keyward_core::account::ExportFormat::Json,
        }));

        // Everything ssh and the window live on: no lock and no sensor.
        assert!(!wants_secret(&Request::Status));
        assert!(!wants_secret(&Request::Items));
        assert!(!wants_secret(&Request::ItemDetail { entry_id: "a".into() }));
        assert!(!wants_secret(&Request::Plugin {
            plugin: "ssh".into(),
            action: "resolve".into(),
            payload: serde_json::Value::Null,
        }));
    }

    #[test]
    fn an_outsider_is_refused_without_the_sensor() {
        let _serial = SERIAL.lock().unwrap_or_else(std::sync::PoisonError::into_inner);
        ASKED.store(0, Ordering::Relaxed);
        let mut window = None;

        let e = guard_with(&alien(), "touch.passwordToApp", false, 300, ASK_NEVER, FOREIGN, Instant::now(), &mut window, touched)
            .unwrap_err();
        assert_eq!(e.to_string(), REFUSED_ALIEN);
        // The sensor was not disturbed: a person has nothing to do with this,
        // it is another program.
        assert_eq!(ASKED.load(Ordering::Relaxed), 0);
        assert!(window.is_none());
    }

    #[test]
    fn the_window_of_trust_spares_the_finger() {
        let _serial = SERIAL.lock().unwrap_or_else(std::sync::PoisonError::into_inner);
        ASKED.store(0, Ordering::Relaxed);
        let mut window = None;
        let start = Instant::now();

        guard_with(&ours(), "touch.passwordToApp", false, 300, ASK_ALWAYS, FOREIGN, start, &mut window, touched).unwrap();
        assert_eq!(ASKED.load(Ordering::Relaxed), 1);

        // A neighbouring copy goes silently.
        guard_with(&ours(), "touch.passwordToApp", false, 300, ASK_ALWAYS, FOREIGN, start + Duration::from_secs(10), &mut window, touched)
            .unwrap();
        assert_eq!(ASKED.load(Ordering::Relaxed), 1);

        // The window is over, so the sensor again.
        guard_with(&ours(), "touch.passwordToApp", false, 300, ASK_ALWAYS, FOREIGN, start + Duration::from_secs(301), &mut window, touched)
            .unwrap();
        assert_eq!(ASKED.load(Ordering::Relaxed), 2);
    }

    #[test]
    fn a_verified_peer_gets_it_without_the_sensor() {
        // This is now the default: the lock on the socket has already cut
        // other processes off, and a person asks for a password in the window
        // themselves, looking at the screen.
        let _serial = SERIAL.lock().unwrap_or_else(std::sync::PoisonError::into_inner);
        ASKED.store(0, Ordering::Relaxed);
        let mut window = None;

        guard_with(&ours(), "touch.passwordToApp", false, 300, ASK_NEVER, FOREIGN, Instant::now(), &mut window, touched).unwrap();
        assert_eq!(ASKED.load(Ordering::Relaxed), 0, "there was no call to disturb the sensor");
    }

    #[test]
    fn a_strict_field_does_not_open_the_window() {
        let _serial = SERIAL.lock().unwrap_or_else(std::sync::PoisonError::into_inner);
        ASKED.store(0, Ordering::Relaxed);
        let mut window = None;
        let start = Instant::now();

        // A private key: the sensor every time, and no window is started after
        // it — otherwise one touch would turn into five minutes of any
        // passwords.
        guard_with(&ours(), "touch.privateKey", true, 300, ASK_NEVER, FOREIGN, start, &mut window, touched).unwrap();
        assert!(window.is_none());
        guard_with(&ours(), "touch.privateKey", true, 300, ASK_NEVER, FOREIGN, start + Duration::from_secs(1), &mut window, touched)
            .unwrap();
        assert_eq!(ASKED.load(Ordering::Relaxed), 2);
    }

    #[test]
    fn a_zero_window_asks_every_time() {
        let _serial = SERIAL.lock().unwrap_or_else(std::sync::PoisonError::into_inner);
        ASKED.store(0, Ordering::Relaxed);
        let mut window = None;
        let start = Instant::now();

        guard_with(&ours(), "touch.passwordToApp", false, 0, ASK_ALWAYS, FOREIGN, start, &mut window, touched).unwrap();
        guard_with(&ours(), "touch.passwordToApp", false, 0, ASK_ALWAYS, FOREIGN, start, &mut window, touched).unwrap();
        assert_eq!(ASKED.load(Ordering::Relaxed), 2);
    }

    #[test]
    fn a_refusal_from_the_sensor_does_not_open_the_window() {
        let _serial = SERIAL.lock().unwrap_or_else(std::sync::PoisonError::into_inner);
        ASKED.store(0, Ordering::Relaxed);
        let mut window = None;

        let e = guard_with(&ours(), "touch.passwordToApp", false, 300, ASK_ALWAYS, FOREIGN, Instant::now(), &mut window, declined)
            .unwrap_err();
        // What the sensor said travels on in whatever language the daemon
        // speaks: the wording is the dictionary's business, the reason is not.
        assert!(e.to_string().contains("the wrong finger"), "{e}");
        assert!(window.is_none());
    }

    #[test]
    fn a_builtin_plugin_works_without_the_sensor() {
        let _serial = SERIAL.lock().unwrap_or_else(std::sync::PoisonError::into_inner);
        ASKED.store(0, Ordering::Relaxed);
        let mut window = None;

        guard_with(&Peer::Builtin, "touch.passwordToApp", false, 300, ASK_NEVER, FOREIGN, Instant::now(), &mut window, touched).unwrap();
        assert_eq!(ASKED.load(Ordering::Relaxed), 0);

        let e = guard_with(&Peer::External, "touch.passwordToApp", false, 300, ASK_NEVER, FOREIGN, Instant::now(), &mut window, touched)
            .unwrap_err();
        assert_eq!(e.to_string(), REFUSED_PLUGIN);
    }
}
