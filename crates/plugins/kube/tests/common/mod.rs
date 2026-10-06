//! What the end-to-end tests share: an ssh server on loopback, and a core that
//! signs as the daemon would.
#![allow(dead_code)]

use std::path::PathBuf;
use std::sync::atomic::{AtomicUsize, Ordering};
use std::sync::{Arc, Mutex};
use std::time::Duration;

use keyward_plugin::{Host, ItemDetail, Plugin, SecretField, TaggedItem, VaultEntry};
use keyward_plugin_kube::KubePlugin;
use russh::server::{self, Auth, Msg, Session as ServerSession};
use russh::{Channel, ChannelId};
use serde_json::Value;

pub const USER_KEY: &str = include_str!("../../../../sshkey/tests/fixtures/ssh/ed25519");
const HOST_KEY: &str = include_str!("../testdata/host_ed25519");

// -- The server ---------------------------------------------------------------

/// What the server answers a command with: stdout and the exit status.
pub type Answers = Arc<dyn Fn(&str) -> (Vec<u8>, u32) + Send + Sync>;

#[derive(Clone)]
struct Server {
    allowed: russh::keys::PublicKey,
    ran: Arc<Mutex<Vec<String>>>,
    answers: Answers,
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

    async fn exec_request(&mut self, channel: ChannelId, data: &[u8], session: &mut ServerSession) -> Result<(), Self::Error> {
        let command = String::from_utf8_lossy(data).into_owned();
        self.ran.lock().unwrap().push(command.clone());
        session.channel_success(channel)?;
        let (out, status) = (self.answers)(&command);
        if status == 0 {
            session.data(channel, out)?;
        } else {
            session.extended_data(channel, 1, out)?;
        }
        session.exit_status_request(channel, status)?;
        session.eof(channel)?;
        session.close(channel)?;
        Ok(())
    }

    /// A way from the server to an address it reaches: what the API is
    /// tunnelled through.
    async fn channel_open_direct_tcpip(
        &mut self,
        channel: Channel<Msg>,
        host: &str,
        port: u32,
        _from: &str,
        _from_port: u32,
        reply: server::ChannelOpenHandle,
        _session: &mut ServerSession,
    ) -> Result<(), Self::Error> {
        let target = format!("{host}:{port}");
        self.ran.lock().unwrap().push(format!("tunnel {target}"));
        reply.accept().await;
        tokio::spawn(async move {
            let Ok(mut tcp) = tokio::net::TcpStream::connect(&target).await else { return };
            let mut stream = channel.into_stream();
            let _ = tokio::io::copy_bidirectional(&mut stream, &mut tcp).await;
        });
        Ok(())
    }
}

pub async fn serve(allowed: russh::keys::PublicKey, ran: Arc<Mutex<Vec<String>>>, answers: Answers) -> u16 {
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
            let handler = Server { allowed: allowed.clone(), ran: Arc::clone(&ran), answers: Arc::clone(&answers) };
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

pub struct Core {
    pub entries: Mutex<Vec<VaultEntry>>,
    pub dir: PathBuf,
    pub signed: AtomicUsize,
    pub settings: Mutex<Value>,
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
        for (name, value) in fields {
            entry.set_field(&name, value);
        }
        Ok(())
    }
    async fn sign_ssh(&self, entry_id: &str, data: &[u8], _flags: u32, confirm: bool) -> keyward_plugin::Result<Vec<u8>> {
        use ssh_encoding::Encode as _;
        assert_eq!(entry_id, "key-1");
        assert!(confirm, "a look signs in with the person's finger");
        self.signed.fetch_add(1, Ordering::SeqCst);
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

pub async fn settle(p: &KubePlugin, core: &Core) -> Value {
    for _ in 0..400 {
        let o = p.call(core, "overview", Value::Null).await.unwrap();
        if o["scanning"] == false {
            return o;
        }
        tokio::time::sleep(Duration::from_millis(20)).await;
    }
    panic!("the look never finished");
}

/// A home of the test's own: ~/.ssh and ~/.kube are read, and a test must not
/// read a person's.
pub fn sandbox(name: &str) -> PathBuf {
    let home = std::env::temp_dir().join(format!("kw-kube-{name}-{}", std::process::id()));
    let _ = std::fs::remove_dir_all(&home);
    std::fs::create_dir_all(&home).unwrap();
    std::env::set_var("HOME", &home);
    home
}

pub fn user_public() -> russh::keys::PublicKey {
    let user = ssh_key::PrivateKey::from_openssh(USER_KEY).unwrap();
    russh::keys::PublicKey::from_openssh(&user.public_key().to_openssh().unwrap()).unwrap()
}

/// A core with one key bound to the server.
pub fn core(home: &std::path::Path, port: u16) -> Arc<Core> {
    let mut e = VaultEntry::default();
    e.id = "key-1".into();
    e.name = "Lab".into();
    e.public_key = Some(user_public().to_openssh().unwrap());
    e.set_field("kw-host", format!("alex@127.0.0.1:{port}"));
    Arc::new(Core { entries: Mutex::new(vec![e]), dir: home.to_path_buf(), signed: AtomicUsize::new(0), settings: Mutex::new(Value::Null) })
}
