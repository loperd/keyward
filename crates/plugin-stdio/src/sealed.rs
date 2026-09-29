//! The plugin protocol's transport: the same messages as before, each one
//! sealed with Noise and carried in length-prefixed frames — nothing on the
//! pipe between the daemon and a plugin is in the clear.
//!
//! The daemon opens the conversation (`initiate`), the plugin answers
//! (`respond`); after that either side reads and writes messages. Reading and
//! writing happen on different tasks, so the channel sits behind a mutex that
//! is held for the encryption only, never across a wait on the pipe.

use std::sync::{Arc, Mutex};

use keyward_core::channel::{self, Channel};
use tokio::io::{AsyncRead, AsyncReadExt as _, AsyncWrite, AsyncWriteExt as _};
use zeroize::Zeroizing;

/// The largest message either side takes: the same ceiling a line had.
pub const MAX_MESSAGE: usize = 4 * 1024 * 1024;

/// An open channel, shared by the reading and the writing side.
#[derive(Clone, Debug)]
pub struct Sealed(Arc<Mutex<Channel>>);

impl Sealed {
    fn new(ch: Channel) -> Self {
        Self(Arc::new(Mutex::new(ch)))
    }

    fn with<T>(&self, f: impl FnOnce(&mut Channel) -> anyhow::Result<T>) -> anyhow::Result<T> {
        let mut guard = self.0.lock().map_err(|_| anyhow::anyhow!("the channel's lock was poisoned"))?;
        f(&mut guard)
    }
}

async fn read_frame(input: &mut (impl AsyncRead + Unpin)) -> anyhow::Result<Option<Vec<u8>>> {
    let mut len = [0u8; 2];
    match input.read_exact(&mut len).await {
        Ok(_) => {}
        Err(e) if e.kind() == std::io::ErrorKind::UnexpectedEof => return Ok(None),
        Err(e) => return Err(e.into()),
    }
    let mut frame = vec![0u8; u16::from_be_bytes(len) as usize];
    input.read_exact(&mut frame).await?;
    Ok(Some(frame))
}

async fn write_frames(output: &mut (impl AsyncWrite + Unpin), frames: Vec<Vec<u8>>) -> anyhow::Result<()> {
    for frame in frames {
        let len = u16::try_from(frame.len()).map_err(|_| anyhow::anyhow!("a frame over the limit"))?;
        output.write_all(&len.to_be_bytes()).await?;
        output.write_all(&frame).await?;
    }
    output.flush().await?;
    Ok(())
}

/// The first frame of a handshake. A side of the old protocol sends a line
/// of JSON instead: its `{` would read as the length of a frame, and the wait
/// for that many bytes would never end — so it is refused at the first byte.
async fn read_handshake(input: &mut (impl AsyncRead + Unpin)) -> anyhow::Result<Option<Vec<u8>>> {
    let mut len = [0u8; 2];
    match input.read_exact(&mut len).await {
        Ok(_) => {}
        Err(e) if e.kind() == std::io::ErrorKind::UnexpectedEof => return Ok(None),
        Err(e) => return Err(e.into()),
    }
    if len[0] == channel::PLAINTEXT_FIRST_BYTE {
        return Err(keyward_core::fault!("err.pluginProtocolOld"));
    }
    let mut frame = vec![0u8; u16::from_be_bytes(len) as usize];
    input.read_exact(&mut frame).await?;
    Ok(Some(frame))
}

/// The daemon's side of the handshake.
pub async fn initiate(
    input: &mut (impl AsyncRead + Unpin),
    output: &mut (impl AsyncWrite + Unpin),
) -> anyhow::Result<Sealed> {
    let (hs, first) = channel::plugin_initiate()?;
    write_frames(output, vec![first]).await?;
    let reply = read_handshake(input).await?.ok_or_else(|| keyward_core::fault!("err.pluginStoppedAnswering"))?;
    Ok(Sealed::new(channel::plugin_complete(hs, &reply)?))
}

/// The plugin's side of the handshake.
pub async fn respond(
    input: &mut (impl AsyncRead + Unpin),
    output: &mut (impl AsyncWrite + Unpin),
) -> anyhow::Result<Sealed> {
    let first = read_handshake(input).await?.ok_or_else(|| anyhow::anyhow!("the core closed the pipe before the handshake"))?;
    let (reply, ch) = channel::plugin_respond(&first)?;
    write_frames(output, vec![reply]).await?;
    Ok(Sealed::new(ch))
}

/// Sends one message.
pub async fn send(sealed: &Sealed, output: &mut (impl AsyncWrite + Unpin), message: &[u8]) -> anyhow::Result<()> {
    let frames = sealed.with(|ch| ch.seal(message))?;
    write_frames(output, frames).await
}

/// Receives one message; `None` when the other side has closed the pipe. A
/// frame that does not open is an error: the conversation cannot go on
/// after it.
pub async fn recv(sealed: &Sealed, input: &mut (impl AsyncRead + Unpin)) -> anyhow::Result<Option<Zeroizing<Vec<u8>>>> {
    loop {
        let Some(frame) = read_frame(input).await? else { return Ok(None) };
        if let Some(message) = sealed.with(|ch| ch.open(&frame, MAX_MESSAGE))? {
            return Ok(Some(message));
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[tokio::test]
    async fn both_sides_come_to_terms_and_talk() {
        let (daemon_end, plugin_end) = tokio::io::duplex(1 << 16);
        let (mut d_read, mut d_write) = tokio::io::split(daemon_end);
        let (mut p_read, mut p_write) = tokio::io::split(plugin_end);
        let plugin = tokio::spawn(async move {
            let sealed = respond(&mut p_read, &mut p_write).await.unwrap();
            let msg = recv(&sealed, &mut p_read).await.unwrap().unwrap();
            send(&sealed, &mut p_write, &msg).await.unwrap();
        });
        let sealed = initiate(&mut d_read, &mut d_write).await.unwrap();
        let big = vec![7u8; 200_000];
        send(&sealed, &mut d_write, &big).await.unwrap();
        let back = recv(&sealed, &mut d_read).await.unwrap().unwrap();
        assert_eq!(back.as_slice(), big.as_slice());
        plugin.await.unwrap();
    }

    #[tokio::test]
    async fn a_plugin_that_speaks_plain_lines_is_refused() {
        let (daemon_end, plugin_end) = tokio::io::duplex(1 << 16);
        let (mut d_read, mut d_write) = tokio::io::split(daemon_end);
        let (_p_read, mut p_write) = tokio::io::split(plugin_end);
        tokio::spawn(async move {
            // An old plugin: it answers with a line of JSON.
            p_write.write_all(b"{\"kind\":\"result\",\"id\":1,\"ok\":null}\n").await.unwrap();
        });
        let e = initiate(&mut d_read, &mut d_write).await.unwrap_err();
        assert!(e.to_string().contains("err.pluginProtocolOld"), "{e}");
    }
}
