//! One live terminal: an ssh session with a pty and a shell, driven by a task
//! of its own.
//!
//! The session outlives the page that opened it: leaving the section and
//! coming back re-attaches to the same shell, and the page replays what it
//! missed out of the scrollback kept here. What the server printed is kept in
//! a buffer that is wiped when it is trimmed and when the session goes; it
//! is never logged.

use std::sync::{Arc, Mutex};
use std::time::{Duration, SystemTime, UNIX_EPOCH};

use keyward_plugin::Host;
use russh::keys::PublicKey;
use russh::ChannelMsg;
use serde::Serialize;
use tokio::sync::{mpsc, oneshot, Notify};
use zeroize::{Zeroize as _, Zeroizing};

use super::connect::{self, CoreSigner, Guard, HostPrompt};
use super::hostkeys::Store;

/// How much of what the server printed is kept for a page that re-attaches.
const SCROLLBACK: usize = 2 * 1024 * 1024;

/// The most one read hands the page: well under the protocol's 4 MiB once it
/// is base64 and sealed.
pub const READ_MAX: usize = 256 * 1024;

/// Where a session is.
#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
#[serde(tag = "kind", rename_all = "snake_case")]
pub enum State {
    Connecting,
    /// An unknown host: the page shows the fingerprint and answers.
    Verify { prompt: HostPrompt },
    /// Waiting for the core's signature — and the person's finger.
    Authenticating,
    Open,
    /// Over. `error` is a key for the page to render; `exit` the shell's status.
    Closed { error: Option<String>, exit: Option<u32> },
}

impl State {
    pub fn closed(&self) -> bool {
        matches!(self, Self::Closed { .. })
    }
}

/// What the page knows a session by. Nothing secret: where it goes, as whom
/// and with which key.
#[derive(Debug, Clone, Serialize)]
pub struct Info {
    pub id: String,
    pub entry_id: String,
    pub entry_name: String,
    pub host: String,
    /// Where it connects: the host, or the real address `~/.ssh/config` gives
    /// an alias.
    pub address: String,
    pub port: u16,
    pub user: String,
    /// Seconds since the epoch.
    pub opened_at: u64,
}

/// Where to go and with what.
pub struct Plan {
    pub info: Info,
    pub key: PublicKey,
    pub pin: Option<String>,
    pub confirm: bool,
    pub cols: u32,
    pub rows: u32,
    /// The item's fields to fill in once the shell is up: the login and the
    /// port it worked with, where the item named none.
    pub save: Vec<(String, String)>,
}

/// What the page sends into a session.
enum Input {
    Data(Zeroizing<Vec<u8>>),
    Resize(u32, u32),
    Close,
}

/// The scrollback: the tail of what the server printed, with the absolute
/// offset of its first byte so a page can say where it stopped.
///
/// The buffer is allocated once with room to spare and trimmed before it
/// would grow, so it never reallocates and leaves no unwiped copy behind.
struct Ring {
    tail: Vec<u8>,
    base: u64,
}

impl Ring {
    fn new() -> Self {
        Self { tail: Vec::with_capacity(SCROLLBACK + READ_MAX), base: 0 }
    }

    fn end(&self) -> u64 {
        self.base + self.tail.len() as u64
    }

    fn push(&mut self, bytes: &[u8]) {
        let mut bytes = bytes;
        // A chunk bigger than the whole scrollback keeps only its end.
        if bytes.len() > SCROLLBACK {
            let skip = bytes.len() - SCROLLBACK;
            self.base += (self.tail.len() + skip) as u64;
            self.tail.zeroize();
            self.tail.clear();
            bytes = &bytes[skip..];
        }
        let over = (self.tail.len() + bytes.len()).saturating_sub(SCROLLBACK);
        if over > 0 {
            self.tail[..over].zeroize();
            self.tail.drain(..over);
            self.base += over as u64;
        }
        self.tail.extend_from_slice(bytes);
    }

    /// The bytes from `cursor` on, at most `max`. `dropped` means the page
    /// fell behind the scrollback and what it missed is gone.
    fn read(&self, cursor: u64, max: usize) -> (Zeroizing<Vec<u8>>, u64, bool) {
        let dropped = cursor < self.base;
        let from = cursor.clamp(self.base, self.end());
        let start = (from - self.base) as usize;
        let stop = (start + max).min(self.tail.len());
        (Zeroizing::new(self.tail[start..stop].to_vec()), self.base + stop as u64, dropped)
    }
}

impl Drop for Ring {
    fn drop(&mut self) {
        self.tail.zeroize();
    }
}

struct Shared {
    state: Mutex<(State, u64)>,
    out: Mutex<Ring>,
    notify: Notify,
    /// The answer to an unknown host's question, while one is asked.
    trust: Mutex<Option<oneshot::Sender<bool>>>,
}

impl Shared {
    fn set(&self, state: State) {
        if let Ok(mut s) = self.state.lock() {
            if s.0.closed() {
                return;
            }
            s.0 = state;
            s.1 += 1;
        }
        self.notify.notify_waiters();
    }

    fn state(&self) -> (State, u64) {
        self.state.lock().map(|s| s.clone()).unwrap_or((State::Closed { error: Some("err.sshTerminalBroken".into()), exit: None }, u64::MAX))
    }
}

/// What a read hands the page.
#[derive(Serialize)]
pub struct Chunk {
    #[serde(skip)]
    pub data: Zeroizing<Vec<u8>>,
    pub cursor: u64,
    pub dropped: bool,
    pub state: State,
    pub version: u64,
}

pub struct Session {
    pub info: Info,
    shared: Arc<Shared>,
    input: mpsc::UnboundedSender<Input>,
}

fn now() -> u64 {
    SystemTime::now().duration_since(UNIX_EPOCH).map(|d| d.as_secs()).unwrap_or(0)
}

pub fn new_id() -> String {
    let mut raw = [0u8; 12];
    rand_core::RngCore::fill_bytes(&mut rand_core::OsRng, &mut raw);
    raw.iter().map(|b| format!("{b:02x}")).collect()
}

pub fn opened_now() -> u64 {
    now()
}

/// Called once the shell is up: the terminal remembers where it got in, so a
/// health check can look at a host a wildcard route never named.
pub type OnOpen = Box<dyn FnOnce(&Info) + Send>;

impl Session {
    /// Starts the session's task and returns at once: connecting, a host
    /// question and the finger on the sensor are all states the page watches.
    pub fn start(plan: Plan, store: Store, core: Arc<dyn Host>, on_open: OnOpen) -> Arc<Self> {
        let shared = Arc::new(Shared {
            state: Mutex::new((State::Connecting, 0)),
            out: Mutex::new(Ring::new()),
            notify: Notify::new(),
            trust: Mutex::new(None),
        });
        let (tx, rx) = mpsc::unbounded_channel();
        let session = Arc::new(Self { info: plan.info.clone(), shared: Arc::clone(&shared), input: tx });
        tokio::spawn(async move {
            let host = plan.info.host.clone();
            let outcome = drive(plan, store, core, Arc::clone(&shared), rx, on_open).await;
            let closed = match outcome {
                Ok(exit) => State::Closed { error: None, exit },
                Err(e) => {
                    tracing::warn!(host = %host, error = %e, "a terminal session ended with an error");
                    State::Closed { error: Some(e.to_string()), exit: None }
                }
            };
            shared.set(closed);
            // Whoever is still asked about the host is answered no.
            if let Ok(mut t) = shared.trust.lock() {
                t.take();
            }
        });
        session
    }

    pub fn state(&self) -> State {
        self.shared.state().0
    }

    pub fn write(&self, data: Zeroizing<Vec<u8>>) -> anyhow::Result<()> {
        self.send(Input::Data(data))
    }

    pub fn resize(&self, cols: u32, rows: u32) -> anyhow::Result<()> {
        self.send(Input::Resize(cols.clamp(2, 1000), rows.clamp(1, 1000)))
    }

    pub fn close(&self) {
        // The task may be gone already: then there is nothing left to close.
        if self.input.send(Input::Close).is_err() {
            tracing::debug!(session = %self.info.id, "closing a session whose task has ended");
        }
    }

    fn send(&self, input: Input) -> anyhow::Result<()> {
        if self.state().closed() {
            anyhow::bail!(keyward_core::fault!("err.sshSessionClosed"));
        }
        self.input.send(input).map_err(|_| keyward_core::fault!("err.sshSessionClosed"))
    }

    /// The person's answer about an unknown host.
    pub fn answer_trust(&self, yes: bool) -> anyhow::Result<()> {
        let sender = self.shared.trust.lock().ok().and_then(|mut t| t.take());
        let Some(sender) = sender else {
            anyhow::bail!(keyward_core::fault!("err.sshNothingToTrust"));
        };
        if sender.send(yes).is_err() {
            anyhow::bail!(keyward_core::fault!("err.sshSessionClosed"));
        }
        Ok(())
    }

    /// Waits up to `wait` for output past `cursor` or a state past `version`,
    /// and hands over what there is.
    pub async fn read(&self, cursor: u64, version: u64, wait: Duration) -> Chunk {
        let deadline = tokio::time::Instant::now() + wait;
        loop {
            // Registered before looking, so a wake-up between the look and the
            // wait is not lost.
            let notified = self.shared.notify.notified();
            tokio::pin!(notified);
            notified.as_mut().enable();

            let (state, v) = self.shared.state();
            let (data, next, dropped) = match self.shared.out.lock() {
                Ok(ring) => ring.read(cursor, READ_MAX),
                Err(_) => (Zeroizing::new(Vec::new()), cursor, false),
            };
            if !data.is_empty() || dropped || v != version || state.closed() {
                return Chunk { data, cursor: next, dropped, state, version: v };
            }
            if tokio::time::timeout_at(deadline, notified).await.is_err() {
                return Chunk { data, cursor: next, dropped, state, version: v };
            }
        }
    }
}

impl Drop for Session {
    fn drop(&mut self) {
        self.close();
    }
}

/// The session's life: reach, verify, log in, open a shell, then pass bytes
/// both ways until either side stops.
async fn drive(
    plan: Plan,
    store: Store,
    core: Arc<dyn Host>,
    shared: Arc<Shared>,
    mut input: mpsc::UnboundedReceiver<Input>,
    on_open: OnOpen,
) -> anyhow::Result<Option<u32>> {
    let Plan { info, key, pin, confirm, cols, rows, save: _ } = plan;

    let asker = Arc::clone(&shared);
    let ask: connect::AskTrust = Arc::new(move |prompt: HostPrompt| {
        let (tx, rx) = oneshot::channel();
        if let Ok(mut t) = asker.trust.lock() {
            *t = Some(tx);
        }
        asker.set(State::Verify { prompt });
        rx
    });
    let (guard, seen) = Guard::new(&info.address, info.port, pin, store, Some(ask));
    let (mut handle, _) = connect::handshake(&info.address, info.port, connect::REACH, guard, &seen).await.map_err(|(e, _)| e)?;

    shared.set(State::Authenticating);
    let mut signer = CoreSigner { core, entry_id: info.entry_id.clone(), confirm };
    if !connect::login(&mut handle, &info.user, &key, &mut signer).await? {
        anyhow::bail!(keyward_core::fault!("err.sshKeyRejected", "user" => info.user.as_str(), "host" => info.host.as_str(), "key" => info.entry_name.as_str()));
    }

    let channel = handle.channel_open_session().await.map_err(|e| connect::reach_error(&info.host, e))?;
    channel
        .request_pty(false, "xterm-256color", cols, rows, 0, 0, &[])
        .await
        .map_err(|e| connect::reach_error(&info.host, e))?;
    channel.request_shell(false).await.map_err(|e| connect::reach_error(&info.host, e))?;
    shared.set(State::Open);
    on_open(&info);

    let (mut reader, writer) = channel.split();
    let mut exit = None;
    loop {
        tokio::select! {
            msg = reader.wait() => match msg {
                Some(ChannelMsg::Data { data }) | Some(ChannelMsg::ExtendedData { data, .. }) => {
                    if let Ok(mut out) = shared.out.lock() {
                        out.push(&data);
                    }
                    shared.notify.notify_waiters();
                }
                Some(ChannelMsg::ExitStatus { exit_status }) => exit = Some(exit_status),
                Some(ChannelMsg::Close) | None => break,
                Some(_) => {}
            },
            cmd = input.recv() => match cmd {
                Some(Input::Data(bytes)) => {
                    writer.data(&bytes[..]).await.map_err(|e| connect::reach_error(&info.host, e))?;
                }
                Some(Input::Resize(c, r)) => {
                    if let Err(e) = writer.window_change(c, r, 0, 0).await {
                        tracing::warn!(error = %e, "the terminal's new size did not reach the server");
                    }
                }
                Some(Input::Close) | None => {
                    if let Err(e) = writer.close().await {
                        tracing::debug!(error = %e, "the channel was gone before it was closed");
                    }
                    break;
                }
            },
        }
    }
    if let Err(e) = handle.disconnect(russh::Disconnect::ByApplication, "", "en").await {
        tracing::debug!(error = %e, "the connection was gone before it was closed");
    }
    Ok(exit)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn the_scrollback_keeps_the_tail_and_says_what_was_dropped() {
        let mut ring = Ring::new();
        ring.push(b"hello ");
        ring.push(b"world");
        let (data, cursor, dropped) = ring.read(0, 1024);
        assert_eq!(&data[..], b"hello world");
        assert_eq!(cursor, 11);
        assert!(!dropped);

        let (data, cursor, _) = ring.read(6, 3);
        assert_eq!(&data[..], b"wor");
        assert_eq!(cursor, 9);

        // Past the scrollback: the page that stopped at zero is told it missed
        // something and gets what is left.
        let big = vec![b'x'; SCROLLBACK];
        ring.push(&big);
        let (data, cursor, dropped) = ring.read(0, READ_MAX);
        assert!(dropped);
        assert_eq!(data.len(), READ_MAX);
        assert_eq!(cursor, ring.base + READ_MAX as u64);
        assert_eq!(ring.end(), 11 + SCROLLBACK as u64);
        assert_eq!(ring.tail.len(), SCROLLBACK);
        assert!(ring.tail.capacity() <= SCROLLBACK + READ_MAX, "the buffer must not have grown");

        // A cursor from the future is the end.
        let (data, cursor, dropped) = ring.read(u64::MAX, 10);
        assert!(data.is_empty() && !dropped);
        assert_eq!(cursor, ring.end());
    }

    #[test]
    fn a_chunk_bigger_than_the_scrollback_keeps_its_end() {
        let mut ring = Ring::new();
        ring.push(b"abc");
        let mut huge = vec![b'a'; SCROLLBACK + 10];
        *huge.last_mut().unwrap() = b'z';
        ring.push(&huge);
        assert_eq!(ring.tail.len(), SCROLLBACK);
        assert_eq!(ring.end(), 3 + SCROLLBACK as u64 + 10);
        assert_eq!(*ring.tail.last().unwrap(), b'z');
    }
}
