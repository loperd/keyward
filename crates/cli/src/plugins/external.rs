//! An external plugin: a separate process and a conversation with it in lines
//! of JSON.
//!
//! Why a process and not a library: the vault's keys lie in the daemon's
//! address space. Somebody else's code next to them would read them directly,
//! and no signature check changes that. A separate process gets exactly what it
//! was allowed, and that is the only way to give a person "install a plugin"
//! without handing over the vault along with it.
//!
//! The conversation is simple and symmetric: one line of JSON per message,
//! `stdin` from the daemon, `stdout` to the daemon, `stderr` into the log. The
//! daemon sends calls and events, the plugin answers with results and asks the
//! core for things of its own (`host`); every request is checked against the
//! package's permissions.

use std::collections::HashMap;
use std::path::PathBuf;
use std::process::Stdio;
use std::sync::atomic::{AtomicBool, AtomicU64, Ordering};
use std::sync::Arc;
use std::time::{Duration, Instant};

use anyhow::{bail, Context as _};
use keyward_plugin::{Host, HostEvent, Manifest, Permission};
use serde::Deserialize;
use serde_json::{json, Value};
use tokio::io::{AsyncBufReadExt as _, BufReader};
use tokio::process::{ChildStdin, Command};
use tokio::sync::{oneshot, Mutex};

use super::package::Package;

/// How long an answer to a `call` is waited for. The count runs from the
/// plugin's last line rather than from the start of the call: while a plugin is
/// asking the core for things of its own it is busy, and the core itself may
/// hold it as long as it likes — Touch ID is asked of a person, and people walk
/// away from their machines.
const CALL_TIMEOUT: Duration = Duration::from_secs(30);


/// How many crashes a minute count as a fault. Once happens; three times in a
/// row means the plugin does not work, and pulling at it further means burning
/// processes.
const CRASH_LIMIT: usize = 3;
const CRASH_WINDOW: Duration = Duration::from_secs(60);

type Pending = Arc<std::sync::Mutex<HashMap<u64, oneshot::Sender<anyhow::Result<Value>>>>>;

/// The counter of crashes, shared by the plugin and the reading task. A type
/// of its own so that the task does not hold a reference to the plugin itself:
/// the plugin holds the task's handle, and that would make a cycle.
#[derive(Default)]
struct Crashes(std::sync::Mutex<Vec<Instant>>);

impl Crashes {
    /// Record a crash. `true` means it is time to switch off.
    fn note(&self) -> bool {
        let Ok(mut all) = self.0.lock() else { return false };
        let now = Instant::now();
        all.retain(|t| now.duration_since(*t) < CRASH_WINDOW);
        all.push(now);
        if all.len() >= CRASH_LIMIT {
            all.clear();
            return true;
        }
        false
    }
}

/// The way into a plugin: its pipe and the sealed channel over it.
struct Outbox {
    pipe: Mutex<ChildStdin>,
    channel: keyward_plugin_stdio::sealed::Sealed,
}

/// How long a plugin has to come to terms after it starts.
const HANDSHAKE: Duration = Duration::from_secs(10);

/// A plugin's live process.
struct Proc {
    /// The handle is there so that the process dies with `Proc`:
    /// `kill_on_drop` takes it down and reaps it when the plugin is switched off
    /// or removed.
    _child: tokio::process::Child,
    stdin: Arc<Outbox>,
    pending: Pending,
    /// When the plugin last said anything, in milliseconds since the process
    /// started. "Silent longer than the timeout" is counted from this.
    activity: Arc<AtomicU64>,
    started: Instant,
    alive: Arc<AtomicBool>,
    /// We take the process down ourselves: the plugin was switched off or
    /// removed altogether. The reading task has to tell that from a crash, or
    /// three flicks of the switch in a row would look like a fault.
    stopping: Arc<AtomicBool>,
    next_id: AtomicU64,
}

impl Proc {
    fn alive(&self) -> bool {
        self.alive.load(Ordering::Relaxed)
    }

    fn touch(&self) {
        touch(&self.activity, self.started);
    }
}

fn touch(activity: &AtomicU64, started: Instant) {
    activity.store(started.elapsed().as_millis() as u64, Ordering::Relaxed);
}

/// An external plugin as the register sees it.
pub struct External {
    pub pkg: Package,
    pub dir: PathBuf,
    proc: Mutex<Option<Proc>>,
    crashes: Arc<Crashes>,
}

impl External {
    pub fn new(pkg: Package, dir: PathBuf) -> Self {
        Self { pkg, dir, proc: Mutex::new(None), crashes: Arc::new(Crashes::default()) }
    }

    pub fn id(&self) -> &str {
        &self.pkg.manifest.id
    }

    pub fn manifest(&self) -> Manifest {
        self.pkg.manifest.clone()
    }

    /// A request from the interface. The process comes up at the first call
    /// and lives while the plugin is on.
    pub async fn call(&self, host: Arc<dyn Host>, action: &str, payload: Value) -> anyhow::Result<Value> {
        let (rx, activity, started, pending, stdin, alive, id) = {
            let mut slot = self.proc.lock().await;
            self.ensure(&mut slot, &host).await?;
            let proc = slot.as_ref().expect("the process has just come up");
            let id = proc.next_id.fetch_add(1, Ordering::Relaxed);
            let (tx, rx) = oneshot::channel();
            if let Ok(mut map) = proc.pending.lock() {
                map.insert(id, tx);
            }
            proc.touch();
            (
                rx,
                Arc::clone(&proc.activity),
                proc.started,
                Arc::clone(&proc.pending),
                Arc::clone(&proc.stdin),
                Arc::clone(&proc.alive),
                id,
            )
        };

        // From here on without the process's lock: the write is short, but
        // waiting for the answer under a shared lock is not allowed. The plugin
        // meanwhile asks the core for things of its own, and the reading task
        // has to be able to reach it.
        let line = json!({"kind": "call", "id": id, "action": action, "payload": payload});
        if let Err(e) = write_line(&stdin, &line).await {
            // The pipe broke: the process is gone, and the next call has to
            // bring it back up rather than write into the same pipe.
            alive.store(false, Ordering::Relaxed);
            return Err(e);
        }
        self.await_result(rx, &activity, started, &pending, id).await
    }

    /// An event from the core. No answer is waited for: an event is a notice,
    /// not a question.
    pub async fn event(&self, host: Arc<dyn Host>, event: HostEvent) {
        let name = match event {
            HostEvent::Unlocked => "unlocked",
            HostEvent::Locked => "locked",
            HostEvent::EntriesChanged => "entries_changed",
            HostEvent::Tick => "tick",
        };
        let mut slot = self.proc.lock().await;
        if let Err(e) = self.ensure(&mut slot, &host).await {
            tracing::warn!(plugin = self.id(), error = %e, "the plugin did not come up for an event");
            return;
        }
        let stdin = {
            let proc = slot.as_ref().expect("the process has just come up");
            Arc::clone(&proc.stdin)
        };
        drop(slot);
        if let Err(e) = write_line(&stdin, &json!({"kind": "event", "event": name})).await {
            tracing::warn!(plugin = self.id(), error = %e, "the event did not reach the plugin");
        }
    }

    /// Take the process down. Silently: switching off and removing are not
    /// failures.
    pub async fn stop(&self) {
        let taken = self.proc.lock().await.take();
        if let Some(proc) = taken {
            // The mark first, the death after: the reading task sees it
            // before the pipe closes and does not record a crash against us.
            proc.stopping.store(true, Ordering::Relaxed);
            drop(proc);
            tracing::info!(plugin = self.id(), "the plugin's process was taken down");
        }
    }

    /// Bring the process up if there is none or it has died.
    async fn ensure(&self, slot: &mut Option<Proc>, host: &Arc<dyn Host>) -> anyhow::Result<()> {
        if slot.as_ref().is_some_and(Proc::alive) {
            return Ok(());
        }
        *slot = None;
        *slot = Some(self.spawn(host).await?);
        Ok(())
    }

    async fn spawn(&self, host: &Arc<dyn Host>) -> anyhow::Result<Proc> {
        // The publisher's signature and the package's fingerprint were checked
        // at installation, and there their work ended: files on disk can be
        // swapped afterwards. So before every start the hashes of the manifest
        // and the program are recomputed. If they differ we do not start it and
        // switch it off with a notification: "the same plugin as yesterday" has
        // to mean something.
        if let Some(rec) = super::registry::record(self.id()) {
            if !rec.manifest_sha256.is_empty() {
                if let Err(e) = super::package::unchanged(
                    &self.dir,
                    &self.pkg.exec,
                    &rec.manifest_sha256,
                    &rec.exec_sha256,
                ) {
                    super::registry::set_enabled(self.id(), false);
                    host.notice(
                        &keyward_core::text::message("notice.pluginOff.title", &[]),
                        &keyward_core::text::message("notice.pluginFilesChanged.body", &[("plugin", self.id())]),
                    );
                    tracing::warn!(plugin = self.id(), error = %e, "the plugin was switched off: its files were swapped");
                    anyhow::bail!("{e}; the plugin was switched off — install it again");
                }
            }
        }

        let exe = self.pkg.exec_path(&self.dir);
        let mut cmd = Command::new(&exe);
        // A clean environment: a plugin has no business knowing about tokens
        // in neighbouring programs' variables, nor about what the daemon was
        // started from. `PATH` so that an interpreter from a shebang is found,
        // `HOME` so that python does not trip over a nameless user.
        cmd.current_dir(&self.dir)
            .env_clear()
            .env("PATH", std::env::var("PATH").unwrap_or_else(|_| "/usr/bin:/bin:/usr/sbin:/sbin".into()))
            .env("HOME", std::env::var("HOME").unwrap_or_default())
            .env("KEYWARD_PLUGIN_DIR", &self.dir)
            .stdin(Stdio::piped())
            .stdout(Stdio::piped())
            .stderr(Stdio::piped())
            // The process has to die with the record of it: an orphaned plugin
            // would go on holding sockets and pipes for no reason at all.
            .kill_on_drop(true);

        self.pkg.check_protocol()?;
        let mut child = cmd
            .spawn()
            .with_context(|| format!("the plugin \"{}\" would not start ({})", self.id(), exe.display()))?;
        let mut stdin = child.stdin.take().context("the plugin has no stdin")?;
        let mut stdout = child.stdout.take().context("the plugin has no stdout")?;
        // Not a message before the channel is up. A plugin that does not
        // come to terms in time is taken down with its record.
        let channel = match tokio::time::timeout(HANDSHAKE, keyward_plugin_stdio::sealed::initiate(&mut stdout, &mut stdin)).await {
            Ok(Ok(channel)) => channel,
            // A plugin that closed its pipe before answering has fallen over;
            // one that answered with something else speaks another protocol.
            Ok(Err(e)) if e.to_string().contains("err.pluginStoppedAnswering") => {
                tracing::warn!(plugin = self.id(), "the plugin closed its pipe before the handshake");
                return Err(keyward_core::fault!("err.pluginStoppedAnswering", "plugin" => self.id()));
            }
            Ok(Err(e)) => {
                tracing::warn!(plugin = self.id(), error = %e, "the plugin did not come to terms");
                return Err(keyward_core::fault!("err.pluginProtocolOld", "plugin" => self.id()));
            }
            Err(_) => {
                tracing::warn!(plugin = self.id(), "the plugin kept silent through the handshake");
                return Err(keyward_core::fault!("err.pluginStoppedAnswering", "plugin" => self.id()));
            }
        };
        let stderr = child.stderr.take().context("the plugin has no stderr")?;

        let started = Instant::now();
        let activity = Arc::new(AtomicU64::new(0));
        let alive = Arc::new(AtomicBool::new(true));
        let stopping = Arc::new(AtomicBool::new(false));
        let pending: Pending = Arc::new(std::sync::Mutex::new(HashMap::new()));
        let stdin = Arc::new(Outbox { pipe: Mutex::new(stdin), channel: channel.clone() });

        // stderr goes into the daemon's log marked with the plugin. It is the
        // one channel by which a plugin's author can say anything about
        // themselves, and losing it is not allowed.
        {
            let id = self.id().to_string();
            tokio::spawn(async move {
                let mut lines = BufReader::new(stderr).lines();
                while let Ok(Some(line)) = lines.next_line().await {
                    tracing::warn!(plugin = %id, "{line}");
                }
            });
        }

        let reader = Reader {
            id: self.id().to_string(),
            pid: child.id(),
            permissions: self.pkg.manifest.permissions.clone(),
            host: Arc::clone(host),
            stdin: Arc::clone(&stdin),
            pending: Arc::clone(&pending),
            activity: Arc::clone(&activity),
            alive: Arc::clone(&alive),
            stopping: Arc::clone(&stopping),
            crashes: Arc::clone(&self.crashes),
            started,
            channel,
        };
        tokio::spawn(reader.run(stdout));

        tracing::info!(plugin = self.id(), exec = %exe.display(), "the plugin was started");
        Ok(Proc {
            _child: child,
            stdin,
            pending,
            activity,
            started,
            alive,
            stopping,
            next_id: AtomicU64::new(1),
        })
    }

    /// Waiting for an answer to a call. The count of silence is reset by every
    /// line from the plugin: while it asks the core for things of its own it is
    /// not silent.
    async fn await_result(
        &self,
        mut rx: oneshot::Receiver<anyhow::Result<Value>>,
        activity: &AtomicU64,
        started: Instant,
        pending: &Pending,
        id: u64,
    ) -> anyhow::Result<Value> {
        loop {
            let idle = started.elapsed().saturating_sub(Duration::from_millis(activity.load(Ordering::Relaxed)));
            let left = CALL_TIMEOUT.saturating_sub(idle);
            if left.is_zero() {
                if let Ok(mut map) = pending.lock() {
                    map.remove(&id);
                }
                // The process is left alive: silence on one call is no reason
                // to lose everything else it holds.
                return Err(keyward_core::fault!("err.pluginSilent", "plugin" => self.id(), "seconds" => CALL_TIMEOUT.as_secs()));
            }
            match tokio::time::timeout(left, &mut rx).await {
                Ok(Ok(result)) => return result,
                Ok(Err(_)) => return Err(keyward_core::fault!("err.pluginGone", "plugin" => self.id())),
                Err(_) => continue,
            }
        }
    }
}

/// One message into a plugin's pipe, sealed.
async fn write_line(outbox: &Arc<Outbox>, value: &Value) -> anyhow::Result<()> {
    let message = zeroize::Zeroizing::new(serde_json::to_vec(value)?);
    let mut pipe = outbox.pipe.lock().await;
    keyward_plugin_stdio::sealed::send(&outbox.channel, &mut *pipe, &message).await
}

/// What the plugin sent.
#[derive(Debug, Deserialize)]
#[serde(tag = "kind", rename_all = "snake_case")]
enum FromPlugin {
    /// An answer to a call: exactly one of `ok` and `error`.
    Result {
        id: u64,
        #[serde(default)]
        ok: Value,
        #[serde(default)]
        error: Option<String>,
    },
    /// A request to the core.
    Host {
        id: u64,
        method: String,
        #[serde(default)]
        args: Value,
    },
}

/// The reading task: it alone parses the plugin's `stdout`, and it is also the
/// one that notices the plugin is gone.
struct Reader {
    id: String,
    /// The process id, so that we can take it down ourselves if the
    /// conversation stops being one.
    pid: Option<u32>,
    permissions: Vec<Permission>,
    host: Arc<dyn Host>,
    stdin: Arc<Outbox>,
    pending: Pending,
    activity: Arc<AtomicU64>,
    alive: Arc<AtomicBool>,
    stopping: Arc<AtomicBool>,
    crashes: Arc<Crashes>,
    started: Instant,
    channel: keyward_plugin_stdio::sealed::Sealed,
}

impl Reader {
    async fn run(self, stdout: tokio::process::ChildStdout) {
        let mut source = stdout;
        loop {
            // A message over the ceiling is refused by its sealed header —
            // not a conversation but an attempt at the daemon's memory — and
            // so is a frame that does not open: either way the process is
            // taken down without waiting for anybody to call it again.
            let message = match keyward_plugin_stdio::sealed::recv(&self.channel, &mut source).await {
                Ok(Some(message)) => message,
                Ok(None) => break,
                Err(e) => {
                    tracing::warn!(plugin = %self.id, error = %e, "the conversation with the plugin broke off; taking it down");
                    if let Some(pid) = self.pid {
                        // SAFETY: our own child, its number taken at start-up.
                        unsafe { libc::kill(pid as libc::pid_t, libc::SIGKILL) };
                    }
                    break;
                }
            };
            let Ok(line) = std::str::from_utf8(&message) else {
                tracing::warn!(plugin = %self.id, "the plugin sent something that is not text");
                continue;
            };
            touch(&self.activity, self.started);
            match serde_json::from_str::<FromPlugin>(line.trim()) {
                Ok(FromPlugin::Result { id, ok, error }) => {
                    let answer = match error {
                        Some(text) => Err(anyhow::anyhow!(text)),
                        None => Ok(ok),
                    };
                    let waiting = self.pending.lock().ok().and_then(|mut m| m.remove(&id));
                    match waiting {
                        Some(tx) => {
                            let _ = tx.send(answer);
                        }
                        // An answer to a call nobody waits for: either the
                        // timeout has already happened or the plugin is muddling
                        // numbers.
                        None => tracing::debug!(plugin = %self.id, id, "a stray answer from the plugin"),
                    }
                }
                Ok(FromPlugin::Host { id, method, args }) => {
                    // Every request is a task of its own: `secret` may come to
                    // rest on Touch ID, and the plugin has to be read
                    // meanwhile.
                    let host = Arc::clone(&self.host);
                    let stdin = Arc::clone(&self.stdin);
                    let permissions = self.permissions.clone();
                    let plugin = self.id.clone();
                    let activity = Arc::clone(&self.activity);
                    let started = self.started;
                    tokio::spawn(async move {
                        let answer = host_call(host.as_ref(), &permissions, &method, args).await;
                        let line = match answer {
                            Ok(value) => json!({"kind": "host_result", "id": id, "ok": value}),
                            Err(e) => {
                                tracing::info!(plugin = %plugin, method = %method, error = %e, "the plugin's request was refused");
                                json!({"kind": "host_result", "id": id, "error": e.to_string()})
                            }
                        };
                        // The core's answer is a sign of life too: while we
                        // were off fetching a secret the plugin was waiting for
                        // us rather than keeping silent.
                        touch(&activity, started);
                        if let Err(e) = write_line(&stdin, &line).await {
                            tracing::warn!(plugin = %plugin, error = %e, "the core's answer did not reach the plugin");
                        }
                    });
                }
                Err(e) => {
                    tracing::warn!(plugin = %self.id, error = %e, "the plugin sent something unintelligible");
                }
            }
        }

        self.alive.store(false, Ordering::Relaxed);
        let deliberate = self.stopping.load(Ordering::Relaxed);
        // Everyone who was waiting for an answer is woken with an error:
        // otherwise the interface would hang to the timeout on every call.
        if let Ok(mut map) = self.pending.lock() {
            for (_, tx) in map.drain() {
                let _ = tx.send(Err(keyward_core::fault!("err.pluginStoppedAnswering", "plugin" => &self.id)));
            }
        }

        if deliberate {
            // We took it down ourselves: this counts as no crash and there is
            // nothing to complain about; those waiting still had to be woken,
            // which is done above.
            tracing::debug!(plugin = %self.id, "the plugin's process closed at our command");
            return;
        }
        tracing::warn!(plugin = %self.id, "the plugin's process ended of its own accord");
        if self.crashes.note() {
            super::registry::disable_after_crash(&self.id);
            self.host.notice(
                &keyward_core::text::message("notice.pluginOff.title", &[]),
                &keyward_core::text::message("notice.pluginCrashed.body", &[("plugin", &self.id)]),
            );
        }
    }
}

/// A plugin's request to the core. Here and only here does external code reach
/// `Host`, and even then through the package's permissions.
async fn host_call(
    host: &dyn Host,
    permissions: &[Permission],
    method: &str,
    args: Value,
) -> anyhow::Result<Value> {
    // The permission first, the arguments after: a refusal must not depend on
    // whether the plugin assembled its request correctly.
    if let Some(need) = Permission::required_for(method)? {
        if !permissions.contains(&need) {
            // The name of the permission travels as a key too: the window has
            // the wording for `plugin.perm.*` in both languages already.
            return Err(keyward_core::fault!(
                "err.pluginNoPermission",
                "permission" => format!("plugin.perm.{}", need.name()),
            ));
        }
    }

    match method {
        "unlocked" => Ok(json!(host.unlocked())),

        // Where the account is; no secret, so no permission.
        "server" => Ok(json!(host.server())),

        "keychain_has" => {
            let a: NameArg = arg(args)?;
            Ok(json!(host.keychain_has(&a.name).await))
        }
        "keychain_get" => {
            let a: NameArg = arg(args)?;
            Ok(Value::String(host.keychain_get(&a.name).await?))
        }
        "keychain_set" => {
            let a: KeychainSetArg = arg(args)?;
            host.keychain_set(&a.name, &a.value).await?;
            Ok(Value::Null)
        }
        "keychain_forget" => {
            let a: NameArg = arg(args)?;
            host.keychain_forget(&a.name).await?;
            Ok(Value::Null)
        }
        "copy_text" => {
            let a: CopyArg = arg(args)?;
            Ok(Value::from(host.copy_text(&a.value).await?))
        }

        "entries" => {
            let mut entries = host.entries();
            // Private keys never leave, not even under the `entries`
            // permission. The whole point of the ssh agent is that a key does
            // not leave the daemon; an external process does not need one
            // either: the agent signs.
            for e in &mut entries {
                e.private_key = None;
            }
            Ok(serde_json::to_value(entries)?)
        }

        "item_detail" => {
            let a: EntryArg = arg(args)?;
            Ok(serde_json::to_value(host.item_detail(&a.entry_id).await)?)
        }

        "secret" => {
            let a: SecretArg = arg(args)?;
            Ok(Value::String(host.secret(&a.entry_id, a.field).await?))
        }

        "note_fields" => {
            let a: EntryArg = arg(args)?;
            Ok(serde_json::to_value(host.note_fields(&a.entry_id).await?)?)
        }

        "tagged_items" => {
            let a: TagArg = arg(args)?;
            Ok(serde_json::to_value(host.tagged_items(&a.field))?)
        }

        "create_note" => {
            let a: NoteArg = arg(args)?;
            Ok(Value::String(host.create_note(&a.name, a.fields, a.hidden).await?))
        }

        "trash_item" => {
            let a: EntryArg = arg(args)?;
            host.trash_item(&a.entry_id).await?;
            Ok(Value::Null)
        }

        "set_fields" => {
            let a: FieldsArg = arg(args)?;
            host.set_fields(&a.entry_id, a.fields).await?;
            Ok(Value::Null)
        }

        "notice" => {
            let a: NoticeArg = arg(args)?;
            host.notice(&a.title, &a.body);
            Ok(Value::Null)
        }

        // Signing is the only way for an external plugin to make use of the
        // vault's ssh key: the key itself is given to it under no permission at
        // all. Binary travels as base64: the conversation is lines.
        "sign_ssh" => {
            use base64::Engine as _;
            let a: SignArg = arg(args)?;
            let data = base64::engine::general_purpose::STANDARD
                .decode(&a.data)
                .map_err(|e| anyhow::anyhow!("the data to sign is not base64: {e}"))?;
            let signature = host.sign_ssh(&a.entry_id, &data, a.flags, a.confirm).await?;
            Ok(Value::String(base64::engine::general_purpose::STANDARD.encode(signature)))
        }

        "settings" => Ok(host.settings()),

        "set_settings" => {
            let a: SettingsArg = arg(args)?;
            host.set_settings(a.value)?;
            Ok(Value::Null)
        }

        // Unreachable: `required_for` has already refused an unfamiliar name.
        other => bail!("the core does not know the method \"{other}\""),
    }
}

fn arg<T: serde::de::DeserializeOwned>(args: Value) -> anyhow::Result<T> {
    serde_json::from_value(args).map_err(|e| anyhow::anyhow!("the core got the wrong arguments: {e}"))
}

#[derive(Deserialize)]
struct EntryArg {
    entry_id: String,
}

#[derive(Deserialize)]
struct SecretArg {
    entry_id: String,
    field: keyward_plugin::SecretField,
}

#[derive(Deserialize)]
struct TagArg {
    field: String,
}

#[derive(Deserialize)]
struct NoteArg {
    name: String,
    #[serde(default)]
    fields: Vec<(String, String)>,
    #[serde(default)]
    hidden: bool,
}

#[derive(Deserialize)]
struct NameArg {
    name: String,
}

/// Not `Debug`: it holds the value copied.
#[derive(Deserialize)]
struct CopyArg {
    value: keyward_core::proto::Secret,
}

/// Not `Debug`: it holds the secret.
#[derive(Deserialize)]
struct KeychainSetArg {
    name: String,
    value: String,
}

#[derive(Deserialize)]
struct FieldsArg {
    entry_id: String,
    #[serde(default)]
    fields: Vec<(String, String)>,
}

#[derive(Deserialize)]
struct SignArg {
    entry_id: String,
    /// What to sign, base64.
    data: String,
    /// The ssh agent request's flags: which RSA variant the client asks for.
    #[serde(default)]
    flags: u32,
    /// The plugin asks for the person to be asked. The core checks the
    /// `kw-confirm` mark on the item itself; no argument from here takes it
    /// off.
    #[serde(default)]
    confirm: bool,
}

#[derive(Deserialize)]
struct NoticeArg {
    title: String,
    #[serde(default)]
    body: String,
}

#[derive(Deserialize)]
struct SettingsArg {
    value: Value,
}

#[cfg(test)]
mod tests {
    use super::*;
    use keyward_plugin::{ItemDetail, Manifest, Origin, SecretField, TaggedItem, VaultEntry};
    use std::path::Path;

    /// A stub core: it answers out of memory and remembers what it was asked.
    #[derive(Default)]
    struct Stub {
        entries: Vec<VaultEntry>,
        notices: std::sync::Mutex<Vec<(String, String)>>,
    }

    #[async_trait::async_trait]
    impl Host for Stub {
        fn unlocked(&self) -> bool {
            true
        }
        fn entries(&self) -> Vec<VaultEntry> {
            self.entries.clone()
        }
        async fn item_detail(&self, _entry_id: &str) -> Option<ItemDetail> {
            None
        }
        async fn secret(&self, _entry_id: &str, _field: SecretField) -> keyward_plugin::Result<String> {
            Ok("a secret".into())
        }
        async fn note_fields(&self, _entry_id: &str) -> keyward_plugin::Result<Vec<String>> {
            Ok(Vec::new())
        }
        fn tagged_items(&self, _field: &str) -> Vec<TaggedItem> {
            Vec::new()
        }
        async fn create_note(
            &self,
            _name: &str,
            _fields: Vec<(String, String)>,
            _hidden: bool,
        ) -> keyward_plugin::Result<String> {
            Ok("id".into())
        }
        async fn trash_item(&self, _entry_id: &str) -> keyward_plugin::Result<()> {
            Ok(())
        }
        async fn set_fields(
            &self,
            _entry_id: &str,
            _fields: Vec<(String, String)>,
        ) -> keyward_plugin::Result<()> {
            Ok(())
        }
        fn notice(&self, title: &str, body: &str) {
            if let Ok(mut all) = self.notices.lock() {
                all.push((title.to_string(), body.to_string()));
            }
        }
        fn state_dir(&self) -> PathBuf {
            std::env::temp_dir()
        }
        fn settings(&self) -> Value {
            json!({"was": true})
        }
        fn set_settings(&self, _value: Value) -> keyward_plugin::Result<()> {
            Ok(())
        }
    }

    fn key(id: &str, name: &str) -> VaultEntry {
        // Field by field rather than `..Default::default()`: `VaultEntry`
        // wipes itself when dropped and so cannot be taken apart.
        let mut e = VaultEntry::default();
        e.id = id.into();
        e.name = name.into();
        e.set_field("kw-host", "*.example.com");
        e.public_key = Some("ssh-ed25519 AAAA".into());
        e.private_key = Some("A SECRET KEY".into());
        e
    }

    fn stub_with_keys() -> Arc<dyn Host> {
        Arc::new(Stub {
            entries: vec![key("1", "a work key"), key("2", "a personal key")],
            notices: Default::default(),
        })
    }

    /// The example package, the very one a person installs from the
    /// interface.
    fn example() -> PathBuf {
        Path::new(env!("CARGO_MANIFEST_DIR")).join("tests/fixtures/probe")
    }

    fn have_python() -> bool {
        std::path::Path::new("/usr/bin/python3").exists()
            || std::env::var("PATH").is_ok_and(|p| {
                p.split(':').any(|d| std::path::Path::new(d).join("python3").exists())
            })
    }

    fn package(permissions: Vec<Permission>) -> Package {
        let mut pkg = super::super::package::read(&example()).expect("the example parsed");
        pkg.manifest.permissions = permissions;
        pkg
    }

    #[tokio::test]
    async fn example_plugin_answers_through_the_runtime() {
        if !have_python() {
            eprintln!("python3 was not found; the example plugin cannot be checked");
            return;
        }
        let plugin = External::new(package(vec![Permission::Entries, Permission::Notices]), example());
        let answer = plugin.call(stub_with_keys(), "status", Value::Null).await.unwrap();
        assert_eq!(answer["count"], 2, "the plugin's answer: {answer}");
        assert_eq!(answer["unlocked"], true);
        assert_eq!(answer["keys"][0]["name"], "a work key");
        assert_eq!(answer["keys"][1]["hosts"], "*.example.com");

        // The process lives between calls, and an unfamiliar operation is the
        // plugin's error rather than the daemon's.
        let e = plugin.call(stub_with_keys(), "a flight to Mars", Value::Null).await.unwrap_err();
        assert!(e.to_string().contains("do not know the operation"), "got: {e}");
    }

    #[tokio::test]
    async fn a_refusal_is_an_answer_and_the_process_lives_on() {
        if !have_python() {
            eprintln!("python3 was not found; the example plugin cannot be checked");
            return;
        }
        // The same package, but with no permissions given: this is what a
        // plugin whose permissions nobody agreed to looks like.
        let plugin = External::new(package(Vec::new()), example());
        let e = plugin.call(stub_with_keys(), "status", Value::Null).await.unwrap_err();
        assert!(e.to_string().starts_with("err.pluginNoPermission "), "got: {e}");

        // A refusal is an answer rather than a break: the next call reaches
        // the same process and gets its own error rather than "the plugin is
        // gone".
        let e = plugin.call(stub_with_keys(), "a flight to Mars", Value::Null).await.unwrap_err();
        assert!(e.to_string().contains("do not know the operation"), "got: {e}");
    }

    #[tokio::test]
    async fn a_dead_plugin_is_started_again_on_the_next_call() {
        if !have_python() {
            eprintln!("python3 was not found; the example plugin cannot be checked");
            return;
        }
        use std::os::unix::fs::PermissionsExt as _;
        let dir = std::env::temp_dir().join(format!("kw-crash-{}", std::process::id()));
        let _ = std::fs::remove_dir_all(&dir);
        std::fs::create_dir_all(&dir).unwrap();
        let script = dir.join("crash.py");
        // A plugin that marks a file and dies at once: the number of marks
        // shows whether it was brought back up.
        std::fs::write(
            &script,
            "#!/usr/bin/env python3\nimport os\nopen(os.path.join(os.environ['KEYWARD_PLUGIN_DIR'], 'starts'), 'a').write('x')\n",
        )
        .unwrap();
        std::fs::set_permissions(&script, std::fs::Permissions::from_mode(0o755)).unwrap();
        std::fs::write(
            dir.join("plugin.json"),
            r#"{"id":"crashy","title":"Crashy","icon":"note","section":false,
                "needs_unlocked":false,"version":"1.0.0","exec":"crash.py","protocol":2}"#,
        )
        .unwrap();

        let pkg = super::super::package::read(&dir).unwrap();
        let plugin = External::new(pkg, dir.clone());
        for _ in 0..2 {
            let e = plugin.call(stub_with_keys(), "status", Value::Null).await.unwrap_err();
            let text = e.to_string();
            assert!(
                text.contains("err.pluginStoppedAnswering") || text.contains("Broken pipe"),
                "got: {text}"
            );
        }
        let starts = std::fs::read_to_string(dir.join("starts")).unwrap_or_default();
        assert_eq!(starts.len(), 2, "the process has to come back up at every call");
        let _ = std::fs::remove_dir_all(&dir);
    }

    #[tokio::test]
    async fn the_example_greets_the_human_when_the_vault_opens() {
        if !have_python() {
            eprintln!("python3 was not found; the example plugin cannot be checked");
            return;
        }
        let host = Arc::new(Stub {
            entries: vec![key("1", "a key")],
            notices: Default::default(),
        });
        let plugin = External::new(package(vec![Permission::Entries, Permission::Notices]), example());
        plugin.event(Arc::clone(&host) as Arc<dyn Host>, HostEvent::Unlocked).await;

        // An event is a notice and no answer is waited for, so we wait for its
        // consequence: the notification arrives in due course.
        let mut seen = Vec::new();
        for _ in 0..100 {
            tokio::time::sleep(Duration::from_millis(20)).await;
            seen = host.notices.lock().unwrap().clone();
            if !seen.is_empty() {
                break;
            }
        }
        assert_eq!(seen.len(), 1, "the plugin did not say hello");
        assert_eq!(seen[0].0, "Hello");
        assert!(seen[0].1.contains("1"), "the notification carries the number of keys: {:?}", seen[0].1);
    }

    #[tokio::test]
    async fn stopping_a_plugin_is_not_a_crash() {
        if !have_python() {
            eprintln!("python3 was not found; the example plugin cannot be checked");
            return;
        }
        // A switch flicked back and forth must not look like a fault:
        // otherwise three flicks a minute would switch a plugin off "for
        // crashing".
        let plugin = External::new(package(vec![Permission::Entries]), example());
        for _ in 0..3 {
            plugin.call(stub_with_keys(), "status", Value::Null).await.unwrap();
            plugin.stop().await;
        }
        assert!(
            plugin.call(stub_with_keys(), "status", Value::Null).await.is_ok(),
            "the plugin switched itself off, though we were the ones who took it down"
        );
    }

    #[tokio::test]
    async fn a_line_too_long_ends_the_conversation() {
        if !have_python() {
            eprintln!("python3 was not found; the example plugin cannot be checked");
            return;
        }
        use std::os::unix::fs::PermissionsExt as _;
        let dir = std::env::temp_dir().join(format!("kw-flood-{}", std::process::id()));
        let _ = std::fs::remove_dir_all(&dir);
        std::fs::create_dir_all(&dir).unwrap();
        let script = dir.join("flood.py");
        // Five megabytes with not one line break: the daemon has to stop
        // reading at that point rather than grow its buffer further.
        std::fs::write(
            &script,
            "#!/usr/bin/env python3\nimport sys, time\nsys.stdout.write('a' * (5 * 1024 * 1024))\nsys.stdout.flush()\ntime.sleep(60)\n",
        )
        .unwrap();
        std::fs::set_permissions(&script, std::fs::Permissions::from_mode(0o755)).unwrap();
        std::fs::write(
            dir.join("plugin.json"),
            r#"{"id":"flood","title":"Flood","icon":"note","section":false,
                "needs_unlocked":false,"version":"1.0.0","exec":"flood.py","protocol":2}"#,
        )
        .unwrap();

        let pkg = super::super::package::read(&dir).unwrap();
        let plugin = External::new(pkg, dir.clone());
        // Its garbage is not a handshake: it is refused as another protocol,
        // and nothing of it is taken in as a message.
        let e = plugin.call(stub_with_keys(), "status", Value::Null).await.unwrap_err();
        assert!(e.to_string().contains("err.pluginProtocolOld"), "got: {e}");
        let _ = std::fs::remove_dir_all(&dir);
    }

    #[test]
    fn three_crashes_a_minute_are_enough_to_turn_it_off() {
        let crashes = Crashes::default();
        assert!(!crashes.note(), "one crash is not yet a fault");
        assert!(!crashes.note());
        assert!(crashes.note(), "the third crash in a minute switches it off");
        // The counter resets: a plugin switched back on starts clean.
        assert!(!crashes.note());
    }

    #[tokio::test]
    async fn permissions_are_checked_on_every_host_call() {
        let host = Stub { entries: vec![key("1", "a key")], notices: Default::default() };

        // With no permission, a refusal that names what was wanted, not a
        // bare "no".
        let e = host_call(&host, &[], "entries", json!({})).await.unwrap_err();
        assert!(e.to_string().starts_with("err.pluginNoPermission "), "got: {e}");
        let e = host_call(&host, &[Permission::Entries], "secret", json!({"entry_id":"1","field":"password"}))
            .await
            .unwrap_err();
        assert!(e.to_string().contains("plugin.perm.secrets"), "got: {e}");

        // "Is the vault open" and one's own settings need no permission.
        assert_eq!(host_call(&host, &[], "unlocked", json!({})).await.unwrap(), json!(true));
        assert_eq!(host_call(&host, &[], "settings", json!({})).await.unwrap(), json!({"was": true}));

        // An unfamiliar method is a refusal, not an "allowed".
        assert!(host_call(&host, &[], "state_dir", json!({})).await.is_err());
    }

    #[tokio::test]
    async fn private_keys_never_leave_the_daemon() {
        // Even under the `entries` permission: the ssh agent inside the daemon
        // signs, and an external process needs a private key for nothing.
        let host = Stub { entries: vec![key("1", "a key")], notices: Default::default() };
        let got = host_call(&host, &[Permission::Entries], "entries", json!({})).await.unwrap();
        assert_eq!(got[0]["name"], "a key");
        assert_eq!(got[0]["public_key"], "ssh-ed25519 AAAA");
        assert!(got[0]["private_key"].is_null(), "a private key travelled outwards: {got}");
    }

    #[tokio::test]
    async fn bad_arguments_are_a_refusal_not_a_panic() {
        let host = Stub::default();
        let e = host_call(&host, &[Permission::Items], "item_detail", json!({})).await.unwrap_err();
        assert!(e.to_string().contains("wrong arguments"), "got: {e}");
    }

    #[test]
    fn the_manifest_of_the_example_is_what_the_card_shows() {
        let pkg = super::super::package::read(&example()).expect("the example parsed");
        let m: Manifest = pkg.manifest.clone();
        assert_eq!(m.id, "probe");
        assert_eq!(m.origin, Origin::External);
        assert!(!m.enabled, "a new plugin installs switched off");
        assert_eq!(m.permissions, vec![Permission::Entries, Permission::Notices]);
        assert_eq!(pkg.exec, "probe.py");
    }
}
