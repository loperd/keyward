//! The terminal end to end: a real ssh server on the loopback (russh's own), a
//! page speaking the sealed protocol, and a core that signs the way the daemon
//! does — with the key only it holds, counting every signature.

use std::path::PathBuf;
use std::sync::atomic::{AtomicUsize, Ordering};
use std::sync::{Arc, Mutex};
use std::time::Duration;

use base64::Engine as _;
use keyward_plugin::{Host, HostEvent, ItemDetail, Plugin, SecretField, TaggedItem, VaultEntry};
use russh::server::{self, Auth, Msg, Session as ServerSession};
use russh::{Channel, ChannelId};
use serde_json::{json, Value};

use super::hostkeys;
use super::link::testing::{Page, PageLane};
use crate::SshPlugin;

const USER_KEY: &str = include_str!("../../../../sshkey/tests/fixtures/ssh/ed25519");
const HOST_KEY: &str = include_str!("testdata/host_ed25519");

fn b64(text: &str) -> String {
    base64::engine::general_purpose::STANDARD.encode(text)
}

// -- The server ---------------------------------------------------------------

#[derive(Clone)]
struct Server {
    allowed: russh::keys::PublicKey,
}

impl server::Handler for Server {
    type Error = russh::Error;

    async fn auth_publickey_offered(&mut self, user: &str, key: &russh::keys::PublicKey) -> Result<Auth, Self::Error> {
        Ok(if user == "alex" && key.key_data() == self.allowed.key_data() { Auth::Accept } else { Auth::reject() })
    }

    async fn auth_publickey(&mut self, user: &str, key: &russh::keys::PublicKey) -> Result<Auth, Self::Error> {
        self.auth_publickey_offered(user, key).await
    }

    async fn channel_open_session(&mut self, _channel: Channel<Msg>, reply: server::ChannelOpenHandle, _session: &mut ServerSession) -> Result<(), Self::Error> {
        reply.accept().await;
        Ok(())
    }

    async fn shell_request(&mut self, channel: ChannelId, session: &mut ServerSession) -> Result<(), Self::Error> {
        session.data(channel, b"welcome\r\n".to_vec())?;
        Ok(())
    }

    async fn window_change_request(&mut self, channel: ChannelId, cols: u32, rows: u32, _: u32, _: u32, session: &mut ServerSession) -> Result<(), Self::Error> {
        session.data(channel, format!("resized {cols}x{rows}\r\n").into_bytes())?;
        Ok(())
    }

    async fn data(&mut self, channel: ChannelId, data: &[u8], session: &mut ServerSession) -> Result<(), Self::Error> {
        if data == b"exit\r" {
            session.exit_status_request(channel, 7)?;
            session.close(channel)?;
        } else {
            session.data(channel, data.to_vec())?;
        }
        Ok(())
    }
}

/// A server on a free loopback port, serving every connection.
async fn serve(allowed: russh::keys::PublicKey) -> u16 {
    let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
    let port = listener.local_addr().unwrap().port();
    let config = Arc::new(server::Config {
        keys: vec![russh::keys::PrivateKey::from_openssh(HOST_KEY).unwrap()],
        auth_rejection_time: Duration::from_millis(0),
        auth_rejection_time_initial: Some(Duration::from_millis(0)),
        ..Default::default()
    });
    tokio::spawn(async move {
        loop {
            let Ok((stream, _)) = listener.accept().await else { return };
            let config = Arc::clone(&config);
            let handler = Server { allowed: allowed.clone() };
            tokio::spawn(async move {
                if let Ok(running) = server::run_stream(config, stream, handler).await {
                    let _ = running.await;
                }
            });
        }
    });
    port
}

// -- The core -------------------------------------------------------------------

struct Core {
    /// Changed by `set_fields`, as the vault would be.
    entries: Mutex<Vec<VaultEntry>>,
    dir: PathBuf,
    signed: AtomicUsize,
    confirmed: Mutex<Vec<bool>>,
    settings: Mutex<Value>,
    written: Mutex<Vec<(String, Vec<(String, String)>)>>,
}

#[async_trait::async_trait]
impl Host for Core {
    fn unlocked(&self) -> bool {
        true
    }
    fn entries(&self) -> Vec<VaultEntry> {
        self.entries.lock().unwrap().clone()
    }
    async fn item_detail(&self, _: &str) -> Option<ItemDetail> {
        None
    }
    async fn secret(&self, _: &str, _: SecretField) -> keyward_plugin::Result<String> {
        anyhow::bail!("no secrets here")
    }
    async fn note_fields(&self, _: &str) -> keyward_plugin::Result<Vec<String>> {
        Ok(Vec::new())
    }
    fn tagged_items(&self, _: &str) -> Vec<TaggedItem> {
        Vec::new()
    }
    async fn create_note(&self, _: &str, _: Vec<(String, String)>, _: bool) -> keyward_plugin::Result<String> {
        anyhow::bail!("no")
    }
    async fn trash_item(&self, _: &str) -> keyward_plugin::Result<()> {
        Ok(())
    }
    async fn set_fields(&self, entry_id: &str, fields: Vec<(String, String)>) -> keyward_plugin::Result<()> {
        let mut entries = self.entries.lock().unwrap();
        let entry = entries.iter_mut().find(|e| e.id == entry_id).expect("set_fields on an item that is not in the vault");
        for (name, value) in &fields {
            entry.set_field(name, value.clone());
        }
        drop(entries);
        self.written.lock().unwrap().push((entry_id.to_string(), fields));
        Ok(())
    }
    /// Signs as the daemon does: the key lives here and nowhere else.
    async fn sign_ssh(&self, entry_id: &str, data: &[u8], flags: u32, confirm: bool) -> keyward_plugin::Result<Vec<u8>> {
        use ssh_encoding::Encode as _;
        assert_eq!(entry_id, "key-1");
        assert_eq!(flags, 0, "an ed25519 key has no hash to choose");
        self.signed.fetch_add(1, Ordering::SeqCst);
        self.confirmed.lock().unwrap().push(confirm);
        let key = ssh_key::PrivateKey::from_openssh(USER_KEY).unwrap();
        let sig: ssh_key::Signature = signature::Signer::try_sign(&key, data).unwrap();
        let mut wire = Vec::new();
        sig.encode(&mut wire).unwrap();
        Ok(wire)
    }
    fn notice(&self, _: &str, _: &str) {}
    fn state_dir(&self) -> PathBuf {
        self.dir.clone()
    }
    fn settings(&self) -> Value {
        self.settings.lock().unwrap().clone()
    }
    fn set_settings(&self, value: Value) -> keyward_plugin::Result<()> {
        *self.settings.lock().unwrap() = value;
        Ok(())
    }
}

fn user_public() -> russh::keys::PublicKey {
    russh::keys::PrivateKey::from_openssh(USER_KEY).unwrap().public_key().clone()
}

fn host_public() -> russh::keys::PublicKey {
    russh::keys::PrivateKey::from_openssh(HOST_KEY).unwrap().public_key().clone()
}

fn fingerprint(key: &russh::keys::PublicKey) -> String {
    key.fingerprint(russh::keys::HashAlg::Sha256).to_string()
}

/// A plugin over a vault with one key bound to `alex@127.0.0.1:<port>`.
async fn plugin(name: &str, port: u16, pin: Option<&str>) -> (SshPlugin, Arc<Core>) {
    plugin_with_route(name, &format!("alex@127.0.0.1:{port}"), pin).await
}

async fn plugin_with_route(name: &str, route: &str, pin: Option<&str>) -> (SshPlugin, Arc<Core>) {
    // Every keyward path is read out of KEYWARD_HOME, and `~/.ssh` out of
    // HOME: both lead into the sandbox, never into a person's home.
    let sandbox = crate::tests::sandbox();
    let dir = sandbox.join(format!("term-{name}"));
    let _ = std::fs::remove_dir_all(&dir);
    std::fs::create_dir_all(&dir).unwrap();

    let mut e = VaultEntry::default();
    e.id = "key-1".into();
    e.name = "Lab".into();
    e.set_field("kw-host", route);
    if let Some(pin) = pin {
        e.set_field("kw-hostkey", pin);
    }
    e.public_key = Some(user_public().to_openssh().unwrap());
    let core = Arc::new(Core {
        entries: Mutex::new(vec![e]),
        dir,
        signed: AtomicUsize::new(0),
        confirmed: Mutex::new(Vec::new()),
        settings: Mutex::new(json!({"agent_enabled": false, "ask": "never", "shared_socket": false, "health_minutes": 0})),
        written: Mutex::new(Vec::new()),
    });
    let p = SshPlugin::new();
    p.attach(Arc::clone(&core) as Arc<dyn Host>);
    p.on_event(core.as_ref(), HostEvent::Unlocked).await;
    (p, core)
}

/// A page with its link.
struct Tab {
    link: String,
    input: PageLane,
    output: PageLane,
    cursor: u64,
    version: u64,
    seen: String,
}

async fn tab(p: &SshPlugin, core: &Core) -> Tab {
    let page = Page::new();
    let linked = p.call(core, "term_link", json!({ "public": page.hello })).await.unwrap();
    let (input, output) = page.finish(linked["public"].as_str().unwrap());
    Tab { link: linked["link"].as_str().unwrap().to_string(), input, output, cursor: 0, version: u64::MAX, seen: String::new() }
}

impl Tab {
    async fn input(&mut self, p: &SshPlugin, core: &Core, req: Value) -> Value {
        let sealed = self.input.seal(req.to_string().as_bytes());
        let answer = p.call(core, "term", json!({ "link": self.link, "lane": "input", "sealed": sealed })).await.unwrap();
        let text = answer.to_string();
        assert!(!text.contains("alex") && !text.contains("Lab"), "an answer must travel sealed: {text}");
        serde_json::from_slice(&self.input.open(answer["sealed"].as_str().unwrap())).unwrap()
    }

    /// Reads until `done` says so, gathering the output.
    async fn until(&mut self, p: &SshPlugin, core: &Core, done: impl Fn(&Value, &str) -> bool) -> Value {
        for _ in 0..100 {
            let req = json!({ "op": "read", "cursor": self.cursor, "version": self.version, "wait_ms": 2000 });
            let sealed = self.output.seal(req.to_string().as_bytes());
            let answer = p.call(core, "term", json!({ "link": self.link, "lane": "output", "sealed": sealed })).await.unwrap();
            assert!(!answer.to_string().contains("welcome"), "output must travel sealed");
            let got: Value = serde_json::from_slice(&self.output.open(answer["sealed"].as_str().unwrap())).unwrap();
            assert!(got.get("error").is_none(), "a read failed: {got}");
            let data = base64::engine::general_purpose::STANDARD.decode(got["data"].as_str().unwrap()).unwrap();
            self.seen.push_str(&String::from_utf8_lossy(&data));
            self.cursor = got["cursor"].as_u64().unwrap();
            self.version = got["version"].as_u64().unwrap();
            if done(&got["state"], &self.seen) {
                return got["state"].clone();
            }
        }
        panic!("the terminal never got there; seen so far: {:?}", self.seen);
    }
}

/// Starts a health round and waits for it to finish: the answer comes at
/// once, with the hosts marked as being checked, and the board fills in.
async fn health(p: &SshPlugin, core: &Core) -> Value {
    let started = p.call(core, "health_run", Value::Null).await.unwrap();
    assert_eq!(started["running"], true, "{started}");
    assert!(started["keys"][0]["checks"].as_array().unwrap().iter().all(|c| c["checking"] == true), "{started}");
    for _ in 0..500 {
        let report = p.call(core, "health", Value::Null).await.unwrap();
        if report["running"] == false {
            return report;
        }
        tokio::time::sleep(Duration::from_millis(20)).await;
    }
    panic!("the health round never finished");
}

fn kind(state: &Value) -> &str {
    state["kind"].as_str().unwrap_or_default()
}

fn open_req(port: u16) -> Value {
    json!({ "op": "open", "target": { "host": "127.0.0.1", "port": port }, "cols": 80, "rows": 24 })
}

#[tokio::test(flavor = "multi_thread")]
async fn a_shell_opens_trusts_the_host_once_and_signs_through_the_core() {
    let port = serve(user_public()).await;
    let (p, core) = plugin("shell", port, None).await;

    // Nobody has vouched for the host yet: the check stops at its key and
    // does not offer ours.
    let report = health(&p, &core).await;
    assert_eq!(report["keys"][0]["status"], "host_unknown", "{report}");
    assert_eq!(report["keys"][0]["checks"][0]["fingerprint"], fingerprint(&host_public()));
    assert_eq!(core.signed.load(Ordering::SeqCst), 0);

    let mut t = tab(&p, &core).await;
    let opened = t.input(&p, &core, open_req(port)).await;
    assert_eq!(opened["session"]["user"], "alex", "the login comes from the route: {opened}");
    assert_eq!(opened["session"]["entry_name"], "Lab");

    // The host is unknown: the page is asked, with the fingerprint.
    let state = t.until(&p, &core, |s, _| kind(s) == "verify").await;
    assert_eq!(state["prompt"]["fingerprint"], fingerprint(&host_public()));
    assert_eq!(t.input(&p, &core, json!({ "op": "trust", "answer": true })).await, Value::Null);

    t.until(&p, &core, |s, seen| kind(s) == "open" && seen.contains("welcome")).await;
    assert_eq!(core.signed.load(Ordering::SeqCst), 1, "one login, one signature");
    assert_eq!(*core.confirmed.lock().unwrap(), vec![true], "a shell from the window always asks for the person");

    t.input(&p, &core, json!({ "op": "write", "data": b64("echo me") })).await;
    t.until(&p, &core, |_, seen| seen.contains("echo me")).await;

    t.input(&p, &core, json!({ "op": "resize", "cols": 100, "rows": 30 })).await;
    t.until(&p, &core, |_, seen| seen.contains("resized 100x30")).await;

    // Another page re-attaches to the same shell and replays its scrollback.
    let id = opened["session"]["id"].as_str().unwrap().to_string();
    let mut again = tab(&p, &core).await;
    let attached = again.input(&p, &core, json!({ "op": "attach", "session": id })).await;
    assert_eq!(attached["state"]["kind"], "open");
    again.until(&p, &core, |_, seen| seen.contains("welcome") && seen.contains("echo me")).await;

    let sessions = p.call(core.as_ref(), "term_sessions", Value::Null).await.unwrap();
    assert_eq!(sessions.as_array().unwrap().len(), 1);

    // The confirmation lives in the item, where every plugin with the key
    // finds it, and not in a file of this plugin's.
    let known = core.entries()[0].field("kw-knownhosts").map(str::to_string);
    let line = host_public().to_openssh().unwrap();
    let without_comment = line.split_whitespace().take(2).collect::<Vec<_>>().join(" ");
    assert_eq!(known, Some(format!("[127.0.0.1]:{port} {without_comment}")));
    assert!(!core.dir.join("known_hosts").exists());

    // Now the host is trusted, the key checks healthy — and nothing more is
    // signed for it.
    let report = health(&p, &core).await;
    assert_eq!(report["keys"][0]["status"], "ok", "{report}");
    assert!(report["keys"][0]["checks"][0]["latency_ms"].is_u64());
    assert_eq!(core.signed.load(Ordering::SeqCst), 1, "a health check must not sign");

    // A second shell to the same host is not asked about it again.
    let mut second = tab(&p, &core).await;
    second.input(&p, &core, open_req(port)).await;
    second.until(&p, &core, |s, seen| kind(s) == "open" && seen.contains("welcome")).await;
    second.input(&p, &core, json!({ "op": "close" })).await;

    t.input(&p, &core, json!({ "op": "write", "data": b64("exit\r") })).await;
    let end = t.until(&p, &core, |s, _| kind(s) == "closed").await;
    assert_eq!(end["exit"], 7);
    assert_eq!(end["error"], Value::Null);

    // Writing into a closed shell is refused, sealed like any answer.
    let refused = t.input(&p, &core, json!({ "op": "write", "data": b64("x") })).await;
    assert!(refused["error"].as_str().unwrap().starts_with("err.sshSessionClosed"), "{refused}");
}

#[tokio::test(flavor = "multi_thread")]
async fn declining_an_unknown_host_ends_the_shell_without_signing() {
    let port = serve(user_public()).await;
    let (p, core) = plugin("declined", port, None).await;
    let mut t = tab(&p, &core).await;
    t.input(&p, &core, open_req(port)).await;
    t.until(&p, &core, |s, _| kind(s) == "verify").await;
    t.input(&p, &core, json!({ "op": "trust", "answer": false })).await;
    let end = t.until(&p, &core, |s, _| kind(s) == "closed").await;
    assert!(end["error"].as_str().unwrap().starts_with("err.sshHostKeyDeclined"), "{end}");
    assert_eq!(core.signed.load(Ordering::SeqCst), 0);
}

#[tokio::test(flavor = "multi_thread")]
async fn a_changed_host_key_is_refused_by_the_shell_and_by_the_check() {
    let port = serve(user_public()).await;
    // The item pins another key than the server's.
    let (p, core) = plugin("changed", port, Some(&fingerprint(&user_public()))).await;

    let report = health(&p, &core).await;
    assert_eq!(report["keys"][0]["status"], "host_changed", "{report}");

    let mut t = tab(&p, &core).await;
    t.input(&p, &core, open_req(port)).await;
    let end = t.until(&p, &core, |s, _| kind(s) == "closed").await;
    assert!(end["error"].as_str().unwrap().starts_with("err.sshHostKeyNotPinned"), "{end}");
    assert_eq!(core.signed.load(Ordering::SeqCst), 0, "nothing is signed for a host that is not the right one");
}

#[tokio::test(flavor = "multi_thread")]
async fn a_host_trusted_before_items_kept_trust_moves_into_the_item_without_asking() {
    let port = serve(user_public()).await;
    let (p, core) = plugin("legacy", port, None).await;
    // Confirmed by an older build: a hashed line in the plugin's own file.
    hostkeys::Store::new(&core.dir).learn("127.0.0.1", port, &host_public()).await.unwrap();

    let mut t = tab(&p, &core).await;
    t.input(&p, &core, open_req(port)).await;
    t.until(&p, &core, |s, seen| kind(s) == "open" && seen.contains("welcome")).await;
    let known = core.entries()[0].field("kw-knownhosts").map(str::to_string).unwrap_or_default();
    assert!(known.starts_with(&format!("[127.0.0.1]:{port} ssh-ed25519 ")), "copied into the item: {known:?}");
}

#[tokio::test(flavor = "multi_thread")]
async fn a_rejected_key_bad_targets_and_a_lock() {
    // The server lets in some other key, not ours.
    let port = serve(host_public()).await;
    let (p, core) = plugin("rejected", port, Some(&fingerprint(&host_public()))).await;

    let report = health(&p, &core).await;
    assert_eq!(report["keys"][0]["status"], "rejected", "{report}");
    assert_eq!(core.signed.load(Ordering::SeqCst), 0);

    let mut t = tab(&p, &core).await;
    t.input(&p, &core, open_req(port)).await;
    let end = t.until(&p, &core, |s, _| kind(s) == "closed").await;
    assert!(end["error"].as_str().unwrap().starts_with("err.sshKeyRejected"), "{end}");
    // The server said no to the offer before anything was signed.
    assert_eq!(core.signed.load(Ordering::SeqCst), 0);

    // A host no route names, and a host that is an option in disguise, are
    // refused before the network.
    let mut u = tab(&p, &core).await;
    let refused = u.input(&p, &core, json!({ "op": "open", "target": { "host": "nowhere.example.com" }, "cols": 80, "rows": 24 })).await;
    assert!(refused["error"].as_str().unwrap().starts_with("err.sshNoKeyForHost"), "{refused}");
    let refused = u
        .input(&p, &core, json!({ "op": "open", "target": { "host": "-oProxyCommand=x", "entry_id": "key-1", "user": "a" }, "cols": 80, "rows": 24 }))
        .await;
    assert!(refused["error"].as_str().unwrap().starts_with("err.sshBadHost"), "{refused}");

    // Locking forgets the links: the page's next request has nothing to open
    // with.
    p.on_event(core.as_ref(), HostEvent::Locked).await;
    let sealed = u.input.seal(b"{\"op\":\"close\"}");
    let err = p.call(core.as_ref(), "term", json!({ "link": u.link, "lane": "input", "sealed": sealed })).await.unwrap_err();
    assert!(err.to_string().starts_with("err.sshLinkGone"), "{err}");
    assert_eq!(p.call(core.as_ref(), "term_sessions", Value::Null).await.unwrap(), json!([]));
}

#[tokio::test(flavor = "multi_thread")]
async fn a_forged_request_is_refused_in_the_clear_and_does_not_break_the_lane() {
    let port = serve(user_public()).await;
    let (p, core) = plugin("forged", port, None).await;
    let mut t = tab(&p, &core).await;
    let err = p
        .call(core.as_ref(), "term", json!({ "link": t.link, "lane": "input", "sealed": b64("not sealed at all") }))
        .await
        .unwrap_err();
    assert!(err.to_string().starts_with("err.channelFailed"), "{err}");
    // The real page goes on as if nothing happened.
    let refused = t.input(&p, &core, json!({ "op": "resize", "cols": 1, "rows": 1 })).await;
    assert!(refused["error"].as_str().unwrap().starts_with("err.sshNoSession"), "{refused}");
}

#[tokio::test(flavor = "multi_thread")]
async fn the_login_and_port_that_worked_are_kept_in_fields_of_their_own() {
    let port = serve(user_public()).await;
    // The route names the host alone: no login, no port.
    let (p, core) = plugin_with_route("remember", "127.0.0.1", Some(&fingerprint(&host_public()))).await;
    let mut t = tab(&p, &core).await;
    t.input(&p, &core, json!({ "op": "open", "target": { "host": "127.0.0.1", "port": port, "user": "alex" }, "cols": 80, "rows": 24 }))
        .await;
    t.until(&p, &core, |s, seen| kind(s) == "open" && seen.contains("welcome")).await;
    for _ in 0..50 {
        if !core.written.lock().unwrap().is_empty() {
            break;
        }
        tokio::time::sleep(Duration::from_millis(20)).await;
    }
    let written = core.written.lock().unwrap().clone();
    assert_eq!(
        written,
        vec![("key-1".to_string(), vec![("kw-user".to_string(), "alex".to_string()), ("kw-port".to_string(), port.to_string())])]
    );
}

#[tokio::test(flavor = "multi_thread")]
async fn a_stale_vault_is_set_right_by_ssh_config_once_the_server_agrees() {
    let port = serve(user_public()).await;
    // The person's ~/.ssh/config knows the alias, the login and the port; the
    // vault has an old login. HOME leads into the sandbox.
    let ssh = crate::tests::sandbox().join(".ssh");
    std::fs::create_dir_all(&ssh).unwrap();
    let alias = format!("lab-{port}");
    let block = format!("\nHost {alias}\n    HostName 127.0.0.1\n    User alex\n    Port {port}\n");
    use std::io::Write as _;
    std::fs::OpenOptions::new().create(true).append(true).open(ssh.join("config")).unwrap().write_all(block.as_bytes()).unwrap();

    let (p, core) = plugin_with_route("stale", &alias, Some(&fingerprint(&host_public()))).await;
    // The item still says `root` from long ago.
    let mut stale = VaultEntry::default();
    stale.id = "key-1".into();
    stale.name = "Lab".into();
    stale.set_field("kw-host", &alias);
    stale.set_field("kw-user", "root");
    stale.set_field("kw-hostkey", &fingerprint(&host_public()));
    stale.public_key = Some(user_public().to_openssh().unwrap());
    let core = Arc::new(Core {
        entries: Mutex::new(vec![stale]),
        dir: core.dir.clone(),
        signed: AtomicUsize::new(0),
        confirmed: Mutex::new(Vec::new()),
        settings: Mutex::new(json!({"agent_enabled": false, "ask": "never", "shared_socket": false, "health_minutes": 0})),
        written: Mutex::new(Vec::new()),
    });
    p.attach(Arc::clone(&core) as Arc<dyn Host>);
    p.on_event(core.as_ref(), HostEvent::EntriesChanged).await;

    let report = health(&p, &core).await;
    let check = &report["keys"][0]["checks"][0];
    assert_eq!(report["keys"][0]["status"], "ok", "{report}");
    assert!(check["note"].as_str().unwrap().starts_with("term.health.fromConfig"), "{report}");
    for _ in 0..50 {
        if !core.written.lock().unwrap().is_empty() {
            break;
        }
        tokio::time::sleep(Duration::from_millis(20)).await;
    }
    assert_eq!(*core.written.lock().unwrap(), vec![("key-1".to_string(), vec![("kw-user".to_string(), "alex".to_string())])]);
    assert_eq!(core.signed.load(Ordering::SeqCst), 0, "setting the vault right signs nothing");

    // The terminal reaches the alias through its real address.
    let mut t = tab(&p, &core).await;
    let opened = t.input(&p, &core, json!({ "op": "open", "target": { "host": alias, "user": "alex" }, "cols": 80, "rows": 24 })).await;
    assert_eq!(opened["session"]["address"], "127.0.0.1", "{opened}");
    assert_eq!(opened["session"]["port"], port);
    t.until(&p, &core, |s, seen| kind(s) == "open" && seen.contains("welcome")).await;
}

#[tokio::test(flavor = "multi_thread")]
async fn a_vault_with_no_login_takes_the_configs_once_the_server_agrees() {
    let port = serve(user_public()).await;
    // The item names the address; the config names it by an alias whose
    // HostName is that address.
    let ssh = crate::tests::sandbox().join(".ssh");
    std::fs::create_dir_all(&ssh).unwrap();
    let alias = format!("byaddr-{port}");
    let block = format!("\nHost {alias}\n    HostName localhost\n    User alex\n    Port {port}\n");
    use std::io::Write as _;
    std::fs::OpenOptions::new().create(true).append(true).open(ssh.join("config")).unwrap().write_all(block.as_bytes()).unwrap();

    let (p, core) = plugin_with_route("byaddr", "localhost", Some(&fingerprint(&host_public()))).await;
    let report = health(&p, &core).await;
    assert_eq!(report["keys"][0]["status"], "ok", "{report}");
    for _ in 0..50 {
        if !core.written.lock().unwrap().is_empty() {
            break;
        }
        tokio::time::sleep(Duration::from_millis(20)).await;
    }
    assert_eq!(
        *core.written.lock().unwrap(),
        vec![("key-1".to_string(), vec![("kw-user".to_string(), "alex".to_string()), ("kw-port".to_string(), port.to_string())])]
    );
}

#[tokio::test(flavor = "multi_thread")]
async fn two_names_of_one_server_are_one_host_and_repeat_visits_add_nothing() {
    let port = serve(user_public()).await;
    // Two names for the same machine in the route, both with the same port.
    let route = format!("alex@127.0.0.1:{port}, alex@localhost:{port}");
    let (p, core) = plugin_with_route("onehost", &route, Some(&fingerprint(&host_public()))).await;

    let report = health(&p, &core).await;
    let checks = report["keys"][0]["checks"].as_array().unwrap();
    assert_eq!(checks.len(), 1, "one server, one row: {report}");
    assert_eq!(checks[0]["status"], "ok");
    assert_eq!(checks[0]["aliases"].as_array().unwrap().len(), 1, "{report}");

    let targets = p.call(core.as_ref(), "term_targets", Value::Null).await.unwrap();
    assert_eq!(targets.as_array().unwrap().len(), 1, "{targets}");

    // Getting in again and again, with the login and port given each time,
    // adds no rows.
    for _ in 0..3 {
        let mut t = tab(&p, &core).await;
        t.input(&p, &core, json!({ "op": "open", "target": { "host": "127.0.0.1", "port": port, "user": "alex" }, "cols": 80, "rows": 24 })).await;
        t.until(&p, &core, |s, seen| kind(s) == "open" && seen.contains("welcome")).await;
        t.input(&p, &core, json!({ "op": "close" })).await;
    }
    let targets = p.call(core.as_ref(), "term_targets", Value::Null).await.unwrap();
    assert_eq!(targets.as_array().unwrap().len(), 1, "{targets}");
    let report = health(&p, &core).await;
    assert_eq!(report["keys"][0]["checks"].as_array().unwrap().len(), 1, "{report}");
}
