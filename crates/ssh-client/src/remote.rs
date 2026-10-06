//! A login to a server with an item's key, and commands run over it.
//!
//! What a plugin that works on a server needs besides a shell: log in the way
//! the terminal does — the host key checked against the item and the files,
//! the signature made by the core with the person's finger — and run a fixed
//! command without a pty, its output collected in memory that is wiped.

use std::sync::Arc;
use std::time::Duration;

use keyward_plugin::Host;
use russh::client::Handle;
use russh::keys::PublicKey;
use russh::ChannelMsg;
use zeroize::Zeroizing;

use crate::connect::{self, AskTrust, CoreSigner, Guard};
use crate::hostkeys::Store;

/// Where to log in and with what.
#[derive(Clone)]
pub struct Login {
    pub entry_id: String,
    pub entry_name: String,
    /// The name a person reads.
    pub host: String,
    /// Where it connects: the host, or the address `~/.ssh/config` gives an
    /// alias.
    pub address: String,
    pub port: u16,
    pub user: String,
    pub key: PublicKey,
    /// The item's `kw-hostkey`.
    pub pin: Option<String>,
}

/// Logs in. Nothing is signed for a host whose key is not trusted: the
/// handshake stops first. `ask` is how an unknown host is put to the person;
/// without it an unknown host is refused.
pub async fn login(login: &Login, store: Store, core: Arc<dyn Host>, ask: Option<AskTrust>) -> anyhow::Result<Handle<Guard>> {
    let clock = connect::Clock::default();
    let setup = async {
        let store = store.for_item(&login.entry_id, Arc::clone(&core));
        let (guard, seen) = Guard::timed(&login.address, login.port, login.pin.clone(), store, ask, clock.clone());
        let (mut handle, _) = connect::handshake(&login.address, login.port, connect::REACH, guard, &seen).await.map_err(|(e, _)| e)?;
        let mut signer = CoreSigner { core, entry_id: login.entry_id.clone(), confirm: true, clock: clock.clone() };
        if !connect::login(&mut handle, &login.user, &login.key, &mut signer).await? {
            anyhow::bail!(keyward_core::fault!(
                "err.sshKeyRejected",
                "user" => login.user.as_str(),
                "host" => login.host.as_str(),
                "key" => login.entry_name.as_str()
            ));
        }
        anyhow::Ok(handle)
    };
    match clock.within(connect::SETUP, setup).await {
        Some(done) => done,
        None => anyhow::bail!(keyward_core::fault!("err.sshTimedOutLogin", "host" => login.host.as_str(), "seconds" => connect::SETUP.as_secs())),
    }
}

/// What a command left behind.
pub struct Output {
    /// `None` when the server closed the channel without saying.
    pub status: Option<u32>,
    /// Wiped when dropped: it may be a kubeconfig.
    pub stdout: Zeroizing<Vec<u8>>,
    /// For the log and for telling "not allowed" from "not there"; kept short.
    pub stderr: String,
}

/// How much of stderr is kept.
const STDERR_MAX: usize = 4096;

/// Runs one command with no pty. Output longer than `limit` is an error
/// rather than cut: half a kubeconfig is not a kubeconfig.
pub async fn exec(handle: &Handle<Guard>, host: &str, command: &str, limit: usize, budget: Duration) -> anyhow::Result<Output> {
    let run = async {
        let mut channel = handle.channel_open_session().await.map_err(|e| connect::reach_error(host, e))?;
        channel.exec(true, command).await.map_err(|e| connect::reach_error(host, e))?;
        // Nothing goes in: a server that reads stdin (a git host's shell does)
        // is told so at once rather than left waiting.
        channel.eof().await.map_err(|e| connect::reach_error(host, e))?;
        let mut stdout = Zeroizing::new(Vec::new());
        let mut stderr = Vec::new();
        let mut status = None;
        while let Some(msg) = channel.wait().await {
            match msg {
                ChannelMsg::Data { data } => {
                    if stdout.len() + data.len() > limit {
                        anyhow::bail!(keyward_core::fault!("err.sshOutputTooLong", "host" => host, "max" => limit));
                    }
                    stdout.extend_from_slice(&data);
                }
                ChannelMsg::ExtendedData { data, .. } => {
                    let room = STDERR_MAX.saturating_sub(stderr.len());
                    stderr.extend_from_slice(&data[..data.len().min(room)]);
                }
                ChannelMsg::ExitStatus { exit_status } => status = Some(exit_status),
                // OpenSSH sends the end of data before the exit status: only
                // the close ends it.
                ChannelMsg::Close => break,
                _ => {}
            }
        }
        anyhow::Ok(Output { status, stdout, stderr: String::from_utf8_lossy(&stderr).into_owned() })
    };
    match tokio::time::timeout(budget, run).await {
        Ok(done) => done,
        Err(_) => anyhow::bail!(keyward_core::fault!("err.sshTimedOutCommand", "host" => host, "seconds" => budget.as_secs())),
    }
}
