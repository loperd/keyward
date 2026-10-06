//! The bridge: the same `impl Plugin`, but as a separate program.
//!
//! A built-in plugin lives inside the daemon and calls the core straight
//! through the [`Host`] trait. An external one is a separate process, and all
//! the same travels as JSON messages over `stdin`/`stdout` — each one sealed
//! with Noise (`sealed`), none of them in the clear. That must be the
//! only difference: one and the same plugin type builds into the daemon and
//! into a showcase package, and behaves the same either way.
//!
//! There are two halves of the bridge here:
//!
//! - [`RemoteHost`] — the core as an external plugin sees it. Every method
//!   goes out as a `{"kind":"host",...}` line and waits for a `host_result`
//!   with its own number. A refusal over permissions arrives in an `error`
//!   field: that is an **answer**, not a break — the `Host` method returns
//!   `Err` and the plugin lives on.
//! - [`serve`] and [`run`] — the loop of the conversation: a `call` into the
//!   plugin, an `event` into the plugin, a `host_result` to whoever waits for
//!   it.
//!
//! The order of answers promises nothing. While a plugin waits on the core the
//! daemon may send a second call, and it has to go to work rather than queue
//! behind the first; that is what the numbers are for.
//!
//! The protocol is described in `docs/plugin-protocol.md` and implemented in
//! the daemon (`crates/cli/src/plugins/external.rs`). Departing from it is not
//! allowed.

pub mod sealed;

use std::collections::HashMap;
use std::path::PathBuf;
use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::{Arc, Mutex};

use keyward_plugin::{Host, HostEvent, ItemDetail, Plugin, Result, SecretField, TaggedItem, VaultEntry};
use serde::Deserialize;
use serde_json::{json, Value};
use tokio::io::{AsyncRead, AsyncWrite};
use tokio::sync::mpsc::{self, UnboundedSender};
use tokio::sync::oneshot;


/// The core's answer: a value or the text of a refusal. The text is shown to a
/// person, so it travels as it is rather than turning into a code.
type Answer = std::result::Result<Value, String>;

/// Who is waiting for the core's answer.
///
/// Half the [`Host`] methods are synchronous (`entries`, `unlocked`,
/// `settings`), and the answer to them still arrives as a line. A synchronous
/// method needs a channel a **thread can block on**; an asynchronous one needs
/// a task's waker. Hence two kinds of waiting rather than one.
enum Reply {
    Async(oneshot::Sender<Answer>),
    Blocking(std::sync::mpsc::Sender<Answer>),
}

impl Reply {
    fn wake(self, answer: Answer) {
        match self {
            Self::Async(tx) => {
                let _ = tx.send(answer);
            }
            Self::Blocking(tx) => {
                let _ = tx.send(answer);
            }
        }
    }
}

/// The core as an external plugin sees it.
///
/// Every method of the trait goes the same way: a number, a `host` line into
/// `stdout`, a wait for a `host_result` with that number. The wait can be as
/// long as it likes — the daemon on the other side is asking a person for Touch
/// ID, and people walk away from their machines.
pub struct RemoteHost {
    out: UnboundedSender<String>,
    pending: Mutex<HashMap<u64, Reply>>,
    next: AtomicU64,
    dir: PathBuf,
}

impl RemoteHost {
    fn new(out: UnboundedSender<String>, dir: PathBuf) -> Self {
        Self { out, pending: Mutex::new(HashMap::new()), next: AtomicU64::new(1), dir }
    }

    /// Write the request down and start waiting. An error here means the
    /// conversation is over: the pipe is closed or the queue of answers is
    /// lost.
    fn send(&self, method: &str, args: Value, reply: Reply) -> Result<()> {
        let id = self.next.fetch_add(1, Ordering::Relaxed);
        {
            let mut map = self
                .pending
                .lock()
                .map_err(|_| anyhow::anyhow!("the queue of requests to the core is damaged"))?;
            map.insert(id, reply);
        }
        let line = json!({"kind": "host", "id": id, "method": method, "args": args});
        if self.out.send(format!("{line}\n")).is_err() {
            if let Ok(mut map) = self.pending.lock() {
                map.remove(&id);
            }
            anyhow::bail!("the core is no longer listening: the request \"{method}\" did not go out");
        }
        Ok(())
    }

    /// Ask the core from an asynchronous method.
    async fn ask(&self, method: &str, args: Value) -> Result<Value> {
        let (tx, rx) = oneshot::channel();
        self.send(method, args, Reply::Async(tx))?;
        match rx.await {
            Ok(answer) => answer.map_err(|text| anyhow::anyhow!(text)),
            Err(_) => anyhow::bail!("the core did not answer \"{method}\""),
        }
    }

    /// Ask the core from a synchronous method: the thread stands until the
    /// answer.
    ///
    /// Standing here is possible only because a plugin's call runs on a
    /// thread of its own (see [`serve`]) rather than as a task of the runtime:
    /// otherwise reading `stdin` would stop too, and that is the very answer
    /// being waited for.
    fn ask_blocking(&self, method: &str, args: Value) -> Result<Value> {
        let (tx, rx) = std::sync::mpsc::channel();
        self.send(method, args, Reply::Blocking(tx))?;
        match rx.recv() {
            Ok(answer) => answer.map_err(|text| anyhow::anyhow!(text)),
            Err(_) => anyhow::bail!("the core did not answer \"{method}\""),
        }
    }

    /// The core's answer, to whoever waits for it.
    fn deliver(&self, id: u64, answer: Answer) {
        let waiting = self.pending.lock().ok().and_then(|mut m| m.remove(&id));
        match waiting {
            Some(reply) => reply.wake(answer),
            // An answer nobody waits for: the core is muddling numbers. Not
            // a reason to fall over, a reason to say so in the daemon's log.
            None => eprintln!("a stray answer from the core under number {id}"),
        }
    }

    /// The conversation is over: wake everyone who was waiting. Otherwise a
    /// synchronous method would stand on its channel for ever.
    fn fail_all(&self, why: &str) {
        let Ok(mut map) = self.pending.lock() else { return };
        for (_, reply) in map.drain() {
            reply.wake(Err(why.to_string()));
        }
    }

    /// Parsing the core's answer into one's own type.
    fn parse<T: serde::de::DeserializeOwned>(method: &str, value: Value) -> Result<T> {
        serde_json::from_value(value)
            .map_err(|e| anyhow::anyhow!("the core answered \"{method}\" with something unexpected: {e}"))
    }

    /// A synchronous method with no way to return a refusal: the complaint
    /// goes to `stderr` (which goes into the daemon's log) and an empty answer
    /// goes out.
    fn quiet<T: serde::de::DeserializeOwned + Default>(&self, method: &str, args: Value) -> T {
        match self.ask_blocking(method, args).and_then(|v| Self::parse(method, v)) {
            Ok(value) => value,
            Err(e) => {
                eprintln!("{method}: {e}");
                T::default()
            }
        }
    }
}

#[async_trait::async_trait]
impl Host for RemoteHost {
    fn unlocked(&self) -> bool {
        // No answer means locked: "I do not know" has to be "no", not "go
        // ahead and read secrets".
        self.quiet("unlocked", json!({}))
    }

    fn entries(&self) -> Vec<VaultEntry> {
        self.quiet("entries", json!({}))
    }

    async fn item_detail(&self, entry_id: &str) -> Option<ItemDetail> {
        match self.ask("item_detail", json!({ "entry_id": entry_id })).await {
            Ok(value) => Self::parse("item_detail", value).unwrap_or(None),
            Err(e) => {
                eprintln!("item_detail: {e}");
                None
            }
        }
    }

    async fn secret(&self, entry_id: &str, field: SecretField) -> Result<String> {
        let args = json!({ "entry_id": entry_id, "field": field });
        Self::parse("secret", self.ask("secret", args).await?)
    }

    async fn note_fields(&self, entry_id: &str) -> Result<Vec<String>> {
        let args = json!({ "entry_id": entry_id });
        Self::parse("note_fields", self.ask("note_fields", args).await?)
    }

    fn tagged_items(&self, field: &str) -> Vec<TaggedItem> {
        self.quiet("tagged_items", json!({ "field": field }))
    }

    fn server(&self) -> Option<String> {
        self.quiet("server", json!({}))
    }

    async fn keychain_has(&self, name: &str) -> bool {
        match self.ask("keychain_has", json!({ "name": name })).await {
            Ok(v) => v.as_bool().unwrap_or(false),
            Err(_) => false,
        }
    }

    async fn keychain_get(&self, name: &str) -> Result<String> {
        Self::parse("keychain_get", self.ask("keychain_get", json!({ "name": name })).await?)
    }

    async fn keychain_set(&self, name: &str, value: &str) -> Result<()> {
        self.ask("keychain_set", json!({ "name": name, "value": value })).await?;
        Ok(())
    }

    async fn keychain_forget(&self, name: &str) -> Result<()> {
        self.ask("keychain_forget", json!({ "name": name })).await?;
        Ok(())
    }

    async fn copy_text(&self, value: &str) -> Result<u64> {
        let v = self.ask("copy_text", json!({ "value": value })).await?;
        Ok(v.as_u64().unwrap_or(0))
    }

    async fn create_note(&self, name: &str, fields: Vec<(String, String)>, hidden: bool) -> Result<String> {
        let args = json!({ "name": name, "fields": fields, "hidden": hidden });
        Self::parse("create_note", self.ask("create_note", args).await?)
    }

    async fn trash_item(&self, entry_id: &str) -> Result<()> {
        self.ask("trash_item", json!({ "entry_id": entry_id })).await?;
        Ok(())
    }

    async fn set_fields(&self, entry_id: &str, fields: Vec<(String, String)>) -> Result<()> {
        self.ask("set_fields", json!({ "entry_id": entry_id, "fields": fields })).await?;
        Ok(())
    }

    async fn sign_ssh(&self, entry_id: &str, data: &[u8], flags: u32, confirm: bool) -> Result<Vec<u8>> {
        // What is signed and the signature are binary, and the conversation
        // is lines: base64.
        let args = json!({
            "entry_id": entry_id,
            "data": b64(data),
            "flags": flags,
            "confirm": confirm,
        });
        let answer: String = Self::parse("sign_ssh", self.ask("sign_ssh", args).await?)?;
        unb64(&answer).ok_or_else(|| anyhow::anyhow!("the core sent a signature that is not base64"))
    }

    fn notice(&self, title: &str, body: &str) {
        if let Err(e) = self.ask_blocking("notice", json!({ "title": title, "body": body })) {
            eprintln!("notice: {e}");
        }
    }

    fn state_dir(&self) -> PathBuf {
        // There is no directory of one's own in the protocol and no need for
        // one: an external plugin's directory is its package's directory, and
        // the daemon names it at start-up (`KEYWARD_PLUGIN_DIR`).
        self.dir.clone()
    }

    fn settings(&self) -> Value {
        match self.ask_blocking("settings", json!({})) {
            Ok(value) => value,
            Err(e) => {
                eprintln!("settings: {e}");
                Value::Null
            }
        }
    }

    fn set_settings(&self, value: Value) -> Result<()> {
        self.ask_blocking("set_settings", json!({ "value": value }))?;
        Ok(())
    }
}

/// Binary into a string and back: a conversation of lines has no room for
/// bytes.
fn b64(data: &[u8]) -> String {
    use base64::Engine as _;
    base64::engine::general_purpose::STANDARD.encode(data)
}

fn unb64(text: &str) -> Option<Vec<u8>> {
    use base64::Engine as _;
    base64::engine::general_purpose::STANDARD.decode(text).ok()
}

/// What the daemon sent.
#[derive(Debug, Deserialize)]
#[serde(tag = "kind", rename_all = "snake_case")]
enum FromHost {
    /// A request from the interface.
    Call {
        id: u64,
        action: String,
        #[serde(default)]
        payload: Value,
    },
    /// An event from the core.
    Event { event: String },
    /// An answer to the plugin's request: exactly one of `ok` and `error`.
    HostResult {
        id: u64,
        #[serde(default)]
        ok: Value,
        #[serde(default)]
        error: Option<String>,
    },
}

fn event_of(name: &str) -> Option<HostEvent> {
    Some(match name {
        "unlocked" => HostEvent::Unlocked,
        "locked" => HostEvent::Locked,
        "entries_changed" => HostEvent::EntriesChanged,
        "tick" => HostEvent::Tick,
        _ => return None,
    })
}

/// The package's directory: the daemon names it at start-up. No variable means
/// the plugin was started by hand, and the current directory is as good as
/// any.
fn plugin_dir() -> PathBuf {
    std::env::var_os("KEYWARD_PLUGIN_DIR")
        .map(PathBuf::from)
        .or_else(|| std::env::current_dir().ok())
        .unwrap_or_else(|| PathBuf::from("."))
}

/// Adopt the same keyward base directory the daemon has.
///
/// The daemon starts a plugin with a clean environment — `PATH`, `HOME`,
/// `KEYWARD_PLUGIN_DIR`, and nothing else: a plugin has no business knowing
/// about tokens in the variables of neighbouring programs. But the keyward base
/// has to be the same for both, or the plugin will raise its sockets next to
/// somebody else's vault. There is nowhere to take it from but the package's
/// directory: it is `<base>/plugins/<id>`.
///
/// Called on the first line of `main`, before the plugin is built: a plugin
/// may create its directories in its constructor, and it has to create them
/// where the vault is.
pub fn adopt_home() {
    if std::env::var_os("KEYWARD_HOME").is_some() {
        return;
    }
    let Some(dir) = std::env::var_os("KEYWARD_PLUGIN_DIR").map(PathBuf::from) else { return };
    let Some(plugins) = dir.parent() else { return };
    // Only if the directory really is that one: we will not guess about
    // somebody else's paths.
    if plugins.file_name().is_some_and(|n| n == "plugins") {
        if let Some(base) = plugins.parent() {
            std::env::set_var("KEYWARD_HOME", base);
        }
    }
}

/// Run a call or an event on a thread of its own.
///
/// Not as a task of the runtime but as a thread, and this is the whole
/// bridge's main decision. The synchronous [`Host`] methods stop a thread until
/// the core answers; were they to stop a runtime thread, reading `stdin` would
/// stop too — that is, delivery of the very answer. A thread of its own is
/// entitled to stand: while it waits, the runtime reads lines and hands out
/// answers.
fn on_own_thread<F>(work: F)
where
    F: std::future::Future<Output = ()> + Send + 'static,
{
    let handle = tokio::runtime::Handle::current();
    tokio::task::spawn_blocking(move || handle.block_on(work));
}

/// The loop of the conversation over a pair of channels. `run` is the same
/// thing over `stdin` and `stdout`; it is separate so that it can be tested in
/// memory.
pub async fn serve<R, W>(plugin: Arc<dyn Plugin>, input: R, output: W) -> anyhow::Result<()>
where
    R: AsyncRead + Unpin + Send + 'static,
    W: AsyncWrite + Unpin + Send + 'static,
{
    let (mut input, mut output) = (input, output);
    // Nothing is said before the channel is up: the daemon opens it, the
    // plugin answers, and a daemon that does not is not talked to at all.
    let channel = sealed::respond(&mut input, &mut output).await?;

    // One task writes: messages go out from different places — answers to
    // calls, requests to the core — and they must not be interleaved halfway.
    let (out, mut queue) = mpsc::unbounded_channel::<String>();
    let writer_channel = channel.clone();
    let writer = tokio::spawn(async move {
        let mut output = output;
        while let Some(line) = queue.recv().await {
            let message = zeroize::Zeroizing::new(line.into_bytes());
            if let Err(e) = sealed::send(&writer_channel, &mut output, &message).await {
                eprintln!("the conversation with the core broke off: {e}");
                break;
            }
        }
    });

    let host = Arc::new(RemoteHost::new(out.clone(), plugin_dir()));
    // A core that outlives a call: an ssh agent's socket asks for a signature
    // when ssh asks it, not when the daemon asks the plugin.
    plugin.attach(Arc::clone(&host) as Arc<dyn Host>);
    loop {
        let message = match sealed::recv(&channel, &mut input).await {
            Ok(Some(message)) => message,
            Ok(None) => break,
            Err(e) => {
                eprintln!("the conversation with the core broke off: {e}");
                break;
            }
        };
        let Ok(line) = std::str::from_utf8(&message) else {
            eprintln!("something that is not text came from the core");
            continue;
        };
        match serde_json::from_str::<FromHost>(line.trim()) {
            Ok(FromHost::Call { id, action, payload }) => {
                let plugin = Arc::clone(&plugin);
                let host = Arc::clone(&host);
                let out = out.clone();
                on_own_thread(async move {
                    let answer = plugin.call(host.as_ref(), &action, payload).await;
                    let line = match answer {
                        Ok(value) => json!({"kind": "result", "id": id, "ok": value}),
                        Err(e) => json!({"kind": "result", "id": id, "error": e.to_string()}),
                    };
                    let _ = out.send(format!("{line}\n"));
                });
            }
            Ok(FromHost::Event { event }) => match event_of(&event) {
                Some(event) => {
                    let plugin = Arc::clone(&plugin);
                    let host = Arc::clone(&host);
                    on_own_thread(async move {
                        plugin.on_event(host.as_ref(), event).await;
                    });
                }
                // An unfamiliar event means the core is newer than the
                // plugin. It has to be survived: an old plugin must work with
                // a new daemon.
                None => eprintln!("an unfamiliar event \"{event}\" was skipped"),
            },
            Ok(FromHost::HostResult { id, ok, error }) => {
                host.deliver(id, error.map_or(Ok(ok), Err));
            }
            // An unintelligible line goes to `stderr` (which goes into the
            // daemon's log) and the conversation goes on: losing a process that
            // holds the ssh agent over one line would not be fair.
            Err(e) => eprintln!("something unintelligible came from the core: {e}"),
        }
    }

    // Those waiting are owed the news that there is nothing left to wait for.
    host.fail_all("the conversation with the core has ended");
    drop(out);
    let _ = writer.await;
    Ok(())
}

/// A plugin as a program: the conversation on `stdin`/`stdout`, and exit
/// together with it.
///
/// The runtime is multi-threaded on purpose: calls run on threads of their own
/// (see [`on_own_thread`]) and reading lines has to go on all the while.
pub fn run<P: Plugin>(plugin: P) -> ! {
    // A plugin holds tokens and the secrets it is given: no core dump, no
    // debugger.
    keyward_core::harden::process();
    // Before the runtime and before any threads: after this the environment
    // is only read.
    adopt_home();
    let code = match start(Arc::new(plugin)) {
        Ok(()) => 0,
        Err(e) => {
            eprintln!("the plugin stopped: {e}");
            1
        }
    };
    std::process::exit(code)
}

fn start(plugin: Arc<dyn Plugin>) -> anyhow::Result<()> {
    let rt = tokio::runtime::Builder::new_multi_thread().enable_all().build()?;
    rt.block_on(serve(plugin, tokio::io::stdin(), tokio::io::stdout()))
}

#[cfg(test)]
mod tests {
    use super::*;
    use keyward_plugin::{Manifest, Origin};

    /// A plugin under test: every operation makes a request of its own to the
    /// core, so that the full round of `call` -> `host` -> `result` is visible
    /// in a test.
    struct Probe;

    #[async_trait::async_trait]
    impl Plugin for Probe {
        fn manifest(&self) -> Manifest {
            Manifest {
                id: "probe".into(),
                title: "Probe".into(),
                icon: "note".into(),
                section: false,
                needs_unlocked: false,
                version: "1.0.0".into(),
                description: String::new(),
                origin: Origin::External,
                enabled: true,
                permissions: Vec::new(),
                probe: false,
                declared: false,
                places: false,
            }
        }

        async fn call(&self, host: &dyn Host, op: &str, payload: Value) -> Result<Value> {
            match op {
                // A synchronous method of the core: the call's thread stands
                // on it.
                "count" => Ok(json!(host.entries().len())),
                // Asynchronous.
                "secret" => Ok(json!(host.secret("a", SecretField::Password).await?)),
                // Two in a row: the second must go out only after the first.
                "both" => {
                    let n = host.entries().len();
                    let s = host.secret("a", SecretField::Password).await?;
                    Ok(json!(format!("{n}:{s}")))
                }
                // A signature: the plugin has no key, so it asks the core.
                "sign" => {
                    let signature = host.sign_ssh("a", "to be signed".as_bytes(), 4, true).await?;
                    Ok(json!(String::from_utf8_lossy(&signature)))
                }
                "echo" => Ok(payload),
                other => anyhow::bail!("I do not know the operation \"{other}\""),
            }
        }

        async fn on_event(&self, host: &dyn Host, event: HostEvent) {
            if event == HostEvent::Unlocked {
                host.notice("an event", "the vault is open");
            }
        }
    }

    /// A pair of channels in memory instead of `stdin`/`stdout`, spoken to as
    /// the daemon speaks: the handshake first, then sealed messages.
    struct Wire {
        write: tokio::io::WriteHalf<tokio::io::DuplexStream>,
        read: tokio::io::ReadHalf<tokio::io::DuplexStream>,
        channel: sealed::Sealed,
    }

    impl Wire {
        async fn up() -> Self {
            let (mine, theirs) = tokio::io::duplex(64 * 1024);
            let (plugin_in, plugin_out) = tokio::io::split(theirs);
            tokio::spawn(serve(Arc::new(Probe), plugin_in, plugin_out));
            let (mut read, mut write) = tokio::io::split(mine);
            let channel = sealed::initiate(&mut read, &mut write).await.expect("the plugin came to terms");
            Self { write, read, channel }
        }

        async fn say(&mut self, value: Value) {
            sealed::send(&self.channel, &mut self.write, value.to_string().as_bytes()).await.unwrap();
        }

        async fn hear(&mut self) -> Value {
            let message = sealed::recv(&self.channel, &mut self.read).await.unwrap().expect("the plugin fell silent");
            serde_json::from_slice(&message).expect("the plugin sent something that is not json")
        }
    }

    #[tokio::test(flavor = "multi_thread", worker_threads = 2)]
    async fn a_call_goes_through_the_core_and_comes_back() {
        let mut wire = Wire::up().await;
        wire.say(json!({"kind": "call", "id": 1, "action": "count", "payload": null})).await;

        // The plugin asks the core for items.
        let ask = wire.hear().await;
        assert_eq!(ask["kind"], "host");
        assert_eq!(ask["method"], "entries");
        let id = ask["id"].as_u64().unwrap();
        wire.say(json!({"kind": "host_result", "id": id, "ok": [{"id": "a", "name": "first"}, {"id": "b", "name": "second"}]})).await;

        let answer = wire.hear().await;
        assert_eq!(answer, json!({"kind": "result", "id": 1, "ok": 2}));
    }

    #[tokio::test(flavor = "multi_thread", worker_threads = 2)]
    async fn a_refusal_is_an_answer_not_a_break() {
        let mut wire = Wire::up().await;
        wire.say(json!({"kind": "call", "id": 7, "action": "secret", "payload": null})).await;

        let ask = wire.hear().await;
        assert_eq!(ask["method"], "secret");
        let id = ask["id"].as_u64().unwrap();
        wire.say(json!({"kind": "host_result", "id": id, "error": "no permission to read passwords"})).await;

        let answer = wire.hear().await;
        assert_eq!(answer["kind"], "result");
        assert_eq!(answer["id"], 7);
        assert_eq!(answer["error"], "no permission to read passwords");

        // And the plugin is alive: a refusal is an answer.
        wire.say(json!({"kind": "call", "id": 8, "action": "echo", "payload": {"alive": true}})).await;
        assert_eq!(wire.hear().await, json!({"kind": "result", "id": 8, "ok": {"alive": true}}));
    }

    #[tokio::test(flavor = "multi_thread", worker_threads = 4)]
    async fn a_second_call_does_not_wait_for_the_first() {
        let mut wire = Wire::up().await;
        // The first call stands on the core...
        wire.say(json!({"kind": "call", "id": 1, "action": "count", "payload": null})).await;
        let first = wire.hear().await;
        assert_eq!(first["method"], "entries");

        // ...and the second must go to work in the meantime, not into a
        // queue.
        wire.say(json!({"kind": "call", "id": 2, "action": "secret", "payload": null})).await;
        let second = wire.hear().await;
        assert_eq!(second["method"], "secret");

        // The core's answers come back in reverse: the order of numbers
        // promises nothing.
        let (a, b) = (first["id"].as_u64().unwrap(), second["id"].as_u64().unwrap());
        wire.say(json!({"kind": "host_result", "id": b, "ok": "a password"})).await;
        wire.say(json!({"kind": "host_result", "id": a, "ok": []})).await;

        let mut seen = std::collections::BTreeMap::new();
        for _ in 0..2 {
            let answer = wire.hear().await;
            seen.insert(answer["id"].as_u64().unwrap(), answer["ok"].clone());
        }
        assert_eq!(seen.get(&1), Some(&json!(0)));
        assert_eq!(seen.get(&2), Some(&json!("a password")));
    }

    #[tokio::test(flavor = "multi_thread", worker_threads = 2)]
    async fn two_requests_in_one_call_keep_their_order() {
        let mut wire = Wire::up().await;
        wire.say(json!({"kind": "call", "id": 3, "action": "both", "payload": null})).await;

        let first = wire.hear().await;
        assert_eq!(first["method"], "entries");
        wire.say(json!({"kind": "host_result", "id": first["id"], "ok": [{"id": "a", "name": "first"}]})).await;

        let second = wire.hear().await;
        assert_eq!(second["method"], "secret");
        wire.say(json!({"kind": "host_result", "id": second["id"], "ok": "a password"})).await;

        assert_eq!(wire.hear().await["ok"], json!("1:a password"));
    }

    #[tokio::test(flavor = "multi_thread", worker_threads = 2)]
    async fn nonsense_does_not_end_the_conversation() {
        let mut wire = Wire::up().await;
        // Sealed, but not json: the conversation survives what it cannot read.
        sealed::send(&wire.channel, &mut wire.write, b"this is not json").await.unwrap();
        wire.say(json!({"kind": "arrived from the future", "id": 1})).await;
        wire.say(json!({"kind": "event", "event": "somersault"})).await;
        // An answer to a call nobody waits for is no reason to fall over
        // either.
        wire.say(json!({"kind": "host_result", "id": 999, "ok": null})).await;

        wire.say(json!({"kind": "call", "id": 5, "action": "echo", "payload": "alive"})).await;
        assert_eq!(wire.hear().await, json!({"kind": "result", "id": 5, "ok": "alive"}));
    }

    #[tokio::test(flavor = "multi_thread", worker_threads = 2)]
    async fn an_event_reaches_the_plugin() {
        let mut wire = Wire::up().await;
        wire.say(json!({"kind": "event", "event": "unlocked"})).await;
        let ask = wire.hear().await;
        assert_eq!(ask["method"], "notice");
        assert_eq!(ask["args"]["title"], "an event");
        wire.say(json!({"kind": "host_result", "id": ask["id"], "ok": null})).await;

        // The event was carried through: the next call answers, which means
        // the core's answer arrived and the thread that stood on `notice` was
        // let go.
        wire.say(json!({"kind": "call", "id": 1, "action": "echo", "payload": "still here"})).await;
        assert_eq!(wire.hear().await["ok"], json!("still here"));
    }

    #[tokio::test(flavor = "multi_thread", worker_threads = 2)]
    async fn a_signature_rides_the_wire_in_base64() {
        // The vault's key is handed to a plugin under no permission at all: it
        // brings the data and the core returns the signature. Binary travels as
        // base64.
        let mut wire = Wire::up().await;
        wire.say(json!({"kind": "call", "id": 4, "action": "sign", "payload": null})).await;

        let ask = wire.hear().await;
        assert_eq!(ask["method"], "sign_ssh");
        assert_eq!(ask["args"]["entry_id"], "a");
        assert_eq!(ask["args"]["flags"], 4);
        assert_eq!(ask["args"]["confirm"], true);
        assert_eq!(unb64(ask["args"]["data"].as_str().unwrap()).unwrap(), "to be signed".as_bytes());

        wire.say(json!({"kind": "host_result", "id": ask["id"], "ok": b64("a signature".as_bytes())})).await;
        assert_eq!(wire.hear().await["ok"], json!("a signature"));
    }

    #[tokio::test(flavor = "multi_thread", worker_threads = 2)]
    async fn an_unknown_op_is_an_error_of_the_plugin() {
        let mut wire = Wire::up().await;
        wire.say(json!({"kind": "call", "id": 9, "action": "fly", "payload": null})).await;
        let answer = wire.hear().await;
        assert_eq!(answer["id"], 9);
        assert!(answer["error"].as_str().unwrap().contains("I do not know the operation"), "{answer}");
    }
}
