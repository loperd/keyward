//! A shell inside a pod's container: `kubectl exec -it`, through the cluster's
//! API — and so through the same ssh tunnel when the cluster came that way.
//!
//! Each shell is a session of the plugin's with its scrollback, the way the ssh
//! plugin keeps a terminal: the page writes keystrokes on the input lane of
//! its sealed link and waits for output on the other. The daemon and the
//! window carry ciphertext only.

use std::sync::{Arc, Mutex};
use std::time::Duration;

use futures::SinkExt as _;
use k8s_openapi::api::core::v1::Pod;
use kube::api::{Api, AttachParams, TerminalSize};
use serde::Serialize;
use tokio::io::{AsyncReadExt as _, AsyncWriteExt as _};
use tokio::sync::{mpsc, Notify};
use zeroize::Zeroizing;

/// How much of a shell's output is kept for a page that comes back.
const SCROLLBACK: usize = 512 * 1024;

/// The longest a read waits for output: inside the daemon's thirty seconds.
pub const READ_WAIT_MAX: Duration = Duration::from_secs(20);

/// The shell is started the way Lens starts one: bash where there is one,
/// sh otherwise.
const COMMAND: [&str; 3] = ["sh", "-c", "command -v bash >/dev/null 2>&1 && exec bash || exec sh"];

#[derive(Debug, Clone, Serialize, PartialEq, Eq)]
#[serde(tag = "state", rename_all = "snake_case")]
pub enum State {
    Connecting,
    Open,
    Closed { error: Option<String> },
}

enum Input {
    Data(Zeroizing<Vec<u8>>),
    Resize(u16, u16),
    Close,
}

/// The output kept: the tail of it, and how much was ever written.
struct Ring {
    buf: Zeroizing<Vec<u8>>,
    /// The position of `buf[0]` in everything the shell ever printed.
    start: u64,
}

impl Ring {
    fn end(&self) -> u64 {
        self.start + self.buf.len() as u64
    }

    fn push(&mut self, bytes: &[u8]) {
        self.buf.extend_from_slice(bytes);
        if self.buf.len() > SCROLLBACK {
            let cut = self.buf.len() - SCROLLBACK;
            self.buf.drain(..cut);
            self.start += cut as u64;
        }
    }
}

/// What a read gives the page.
#[derive(Serialize)]
pub struct Chunk {
    /// Base64 of the bytes since the cursor.
    pub data: Zeroizing<String>,
    pub cursor: u64,
    /// The page's cursor was older than the scrollback: some output is lost.
    pub dropped: bool,
    #[serde(flatten)]
    pub state: State,
}

pub struct Shell {
    input: mpsc::UnboundedSender<Input>,
    out: Mutex<Ring>,
    state: Mutex<State>,
    notify: Notify,
}

fn b64(bytes: &[u8]) -> Zeroizing<String> {
    use base64::Engine as _;
    Zeroizing::new(base64::engine::general_purpose::STANDARD.encode(bytes))
}

impl Shell {
    /// Starts a shell; it connects in the background.
    pub fn start(client: kube::Client, namespace: &str, pod: &str, container: Option<String>, cols: u16, rows: u16) -> Arc<Self> {
        let (tx, rx) = mpsc::unbounded_channel();
        let shell = Arc::new(Self {
            input: tx,
            out: Mutex::new(Ring { buf: Zeroizing::new(Vec::new()), start: 0 }),
            state: Mutex::new(State::Connecting),
            notify: Notify::new(),
        });
        let me = Arc::clone(&shell);
        let (namespace, pod) = (namespace.to_string(), pod.to_string());
        tokio::spawn(async move {
            let end = me.drive(client, &namespace, &pod, container, cols, rows, rx).await;
            me.set(State::Closed { error: end.err().map(|e| e.to_string()) });
        });
        shell
    }

    fn set(&self, state: State) {
        if let Ok(mut s) = self.state.lock() {
            if matches!(*s, State::Closed { .. }) {
                return;
            }
            *s = state;
        }
        self.notify.notify_waiters();
    }

    fn print(&self, bytes: &[u8]) {
        if let Ok(mut out) = self.out.lock() {
            out.push(bytes);
        }
        self.notify.notify_waiters();
    }

    #[allow(clippy::too_many_arguments)]
    async fn drive(
        &self,
        client: kube::Client,
        namespace: &str,
        pod: &str,
        container: Option<String>,
        cols: u16,
        rows: u16,
        mut input: mpsc::UnboundedReceiver<Input>,
    ) -> anyhow::Result<()> {
        let api: Api<Pod> = Api::namespaced(client, namespace);
        let mut params = AttachParams::interactive_tty();
        if let Some(c) = container {
            params = params.container(c);
        }
        let mut process = api.exec(pod, COMMAND, &params).await.map_err(|e| crate::resources::api_error("pods", e))?;
        let mut stdin = process.stdin().ok_or_else(|| anyhow::anyhow!("the shell has no input"))?;
        let mut stdout = process.stdout().ok_or_else(|| anyhow::anyhow!("the shell has no output"))?;
        let mut size = process.terminal_size();
        if let Some(size) = size.as_mut() {
            // The first size: the page's, not the default.
            let _ = size.send(TerminalSize { width: cols, height: rows }).await;
        }
        self.set(State::Open);
        let mut buf = Zeroizing::new(vec![0u8; 16 * 1024]);
        loop {
            tokio::select! {
                n = stdout.read(&mut buf[..]) => match n {
                    Ok(0) => break,
                    Ok(n) => self.print(&buf[..n]),
                    Err(e) => anyhow::bail!(keyward_core::fault!("err.kubeShellBroken", "reason" => e.to_string())),
                },
                msg = input.recv() => match msg {
                    Some(Input::Data(bytes)) => stdin.write_all(&bytes).await.map_err(|e| keyward_core::fault!("err.kubeShellBroken", "reason" => e.to_string()))?,
                    Some(Input::Resize(c, r)) => {
                        if let Some(size) = size.as_mut() {
                            if let Err(e) = size.send(TerminalSize { width: c, height: r }).await {
                                tracing::warn!(error = %e, "the shell's new size did not reach the pod");
                            }
                        }
                    }
                    Some(Input::Close) | None => break,
                },
            }
        }
        drop(stdin);
        drop(stdout);
        Ok(())
    }

    fn send(&self, input: Input) -> anyhow::Result<()> {
        self.input.send(input).map_err(|_| keyward_core::fault!("err.kubeShellClosed"))
    }

    pub fn write(&self, data: Zeroizing<Vec<u8>>) -> anyhow::Result<()> {
        self.send(Input::Data(data))
    }

    pub fn resize(&self, cols: u16, rows: u16) -> anyhow::Result<()> {
        self.send(Input::Resize(cols.clamp(10, 1000), rows.clamp(2, 1000)))
    }

    pub fn close(&self) {
        let _ = self.input.send(Input::Close);
    }

    pub fn state(&self) -> State {
        self.state.lock().map(|s| s.clone()).unwrap_or(State::Closed { error: None })
    }

    /// The output since `cursor`, waiting up to `wait` for some to come.
    pub async fn read(&self, cursor: u64, wait: Duration) -> Chunk {
        let ready = |me: &Self| {
            let end = me.out.lock().map(|o| o.end()).unwrap_or(0);
            end > cursor || matches!(me.state(), State::Closed { .. })
        };
        if !ready(self) {
            let notified = self.notify.notified();
            if !ready(self) {
                let _ = tokio::time::timeout(wait, notified).await;
            }
        }
        let (data, cursor, dropped) = match self.out.lock() {
            Ok(out) => {
                let from = cursor.max(out.start);
                let at = (from - out.start) as usize;
                (b64(&out.buf[at..]), out.end(), cursor < out.start)
            }
            Err(_) => (b64(&[]), cursor, false),
        };
        Chunk { data, cursor, dropped, state: self.state() }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn the_scrollback_keeps_the_tail_and_counts_what_went() {
        let mut r = Ring { buf: Zeroizing::new(Vec::new()), start: 0 };
        r.push(&vec![b'a'; SCROLLBACK]);
        r.push(b"tail");
        assert_eq!(r.end(), SCROLLBACK as u64 + 4);
        assert_eq!(r.buf.len(), SCROLLBACK);
        assert_eq!(&r.buf[SCROLLBACK - 4..], b"tail");
        assert_eq!(r.start, 4);
    }
}
