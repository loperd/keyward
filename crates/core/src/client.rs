//! A blocking client for the control socket. Synchronous on purpose: the CLI
//! uses it, so do the Tauri commands and the `resolve` helper that ssh calls on
//! every connection — dragging a runtime in there would buy nothing.

use std::os::unix::net::UnixStream;
use std::time::Duration;

use crate::proto::{Request, Response};

/// For a caller that is itself being waited on. `keyward resolve` stands in the
/// way of every ssh connection, and a stalled daemon must not become a stalled
/// ssh; the caller says so with [`call_with_timeout`], because the core has no
/// business knowing which plugin is in a hurry.
pub const IMPATIENT: Duration = Duration::from_secs(5);

/// The rest are in no hurry: sync, login and edits go over the network, and
/// the first request after a start warms the cache as well. Five seconds gave
/// them "Resource temporarily unavailable" where waiting was all that was
/// needed.
const TIMEOUT: Duration = Duration::from_secs(30);

/// Requests on which the daemon waits for a finger. The sensor gives a person
/// a minute, and giving up sooner means showing "the daemon is not answering"
/// to someone who simply had not got their finger there yet.
const BIOMETRIC_TIMEOUT: Duration = Duration::from_secs(90);

fn timeout_for(req: &Request) -> Duration {
    match req {
        Request::RevealSecret { .. }
        | Request::CopySecret { .. }
        | Request::ExportVault { .. }
        | Request::BiometricUnlock
        | Request::BiometricRemember { .. }
        | Request::PluginWithFields { .. }
        | Request::PasskeySignIn { .. }
        | Request::PasskeyRegister { .. } => BIOMETRIC_TIMEOUT,
        _ => TIMEOUT,
    }
}

pub fn call(req: &Request) -> anyhow::Result<Response> {
    call_with_timeout(req, timeout_for(req))
}

/// The same, with the wait chosen by the caller: whoever is being waited on
/// themselves knows how long they can afford, and a plugin's name says nothing
/// about it.
///
/// Before a byte of the request leaves, the client makes sure it is talking
/// to our daemon: the process at the other end of the socket must carry our
/// signature, and the handshake must complete with the key the daemon
/// published. The request and the answer then travel sealed; their plaintext
/// lives only in buffers wiped on drop.
pub fn call_with_timeout(req: &Request, timeout: Duration) -> anyhow::Result<Response> {
    use zeroize::Zeroizing;
    let path = crate::paths::control_socket();
    let mut stream = UnixStream::connect(&path).map_err(|e| {
        anyhow::anyhow!("the daemon is not answering on {}: {e}. Run `keyward daemon`", path.display())
    })?;
    stream.set_read_timeout(Some(timeout))?;
    stream.set_write_timeout(Some(timeout))?;

    check_daemon(&stream)?;
    let key = crate::channel::daemon_public_key()?;
    let mut ch = crate::channel::connect(&mut stream, &key)?;

    let body = Zeroizing::new(serde_json::to_vec(req)?);
    ch.send(&mut stream, &body)?;
    drop(body);
    let answer = ch.recv(&mut stream, crate::channel::MAX_RESPONSE)?;
    Ok(serde_json::from_slice(&answer)?)
}

/// Whether the process holding the socket is our daemon. An unsigned client
/// (a build run from the tree) has nothing to compare with and goes on; the
/// handshake still has to pass.
fn check_daemon(stream: &UnixStream) -> anyhow::Result<()> {
    let pid = crate::peer::pid(stream)?;
    match crate::peer::trust(pid) {
        crate::peer::Trust::Alien => Err(crate::fault!("err.daemonNotOurs")),
        _ => Ok(()),
    }
}

/// Is the daemon alive?
pub fn is_running() -> bool {
    matches!(call(&Request::Ping), Ok(Response::Pong))
}
