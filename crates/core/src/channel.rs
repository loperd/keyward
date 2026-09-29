//! The encrypted channel over the control socket.
//!
//! Nothing crosses `~/.keyward/d.sock` in the clear: not a master password,
//! not a revealed secret, not the name of an item. Every connection opens with
//! a Noise handshake, `Noise_NK_25519_ChaChaPoly_BLAKE2s`:
//!
//! - **N** — the client has no static key of its own. Who the client is, the
//!   daemon learns from the kernel: the peer's pid and its code signature
//!   (`peer`).
//! - **K** — the client knows the daemon's static public key in advance. The
//!   daemon makes a fresh pair at every start; the private half lives in its
//!   memory only and is never written anywhere, the public half is published
//!   in `~/.keyward/daemon.pub`. The client checks, besides, that the process
//!   at the other end of the socket carries our signature — replacing both
//!   the socket and the key file is not enough to sit in the middle.
//!
//! The prologue carries the protocol's name and version: a client of another
//! version does not come to terms with the daemon at all, rather than half
//! understanding it.
//!
//! On the wire everything is frames: two bytes of length, big-endian, then a
//! Noise message of at most 65535 bytes. A message of the protocol is a header
//! frame (its length, sealed) followed by as many sealed chunks as it takes.

use std::io::{Read, Write};

use zeroize::Zeroizing;

pub const PATTERN: &str = "Noise_NK_25519_ChaChaPoly_BLAKE2s";
/// Bound into the handshake: another protocol or version fails it.
const PROLOGUE: &[u8] = b"keyward control v1";
const MAX_NOISE: usize = 65535;
const TAG: usize = 16;
const CHUNK: usize = MAX_NOISE - TAG;
/// The largest request taken: an edit with a long note fits many times over.
pub const MAX_REQUEST: usize = 4 << 20;
/// The largest answer taken: a whole vault's export.
pub const MAX_RESPONSE: usize = 64 << 20;
/// What a client of the old, plaintext protocol sends first: `{`. The daemon
/// tells it plainly that the channel is required and serves it nothing.
pub const PLAINTEXT_FIRST_BYTE: u8 = b'{';

fn failed() -> anyhow::Error {
    crate::fault!("err.channelFailed")
}

fn params() -> snow::params::NoiseParams {
    PATTERN.parse().expect("the pattern is a valid Noise name")
}

/// The daemon's static key for this run.
pub struct DaemonKey {
    public: [u8; 32],
    private: Zeroizing<Vec<u8>>,
}

impl DaemonKey {
    pub fn generate() -> anyhow::Result<Self> {
        let mut pair = snow::Builder::new(params()).generate_keypair().map_err(|_| failed())?;
        let private = Zeroizing::new(std::mem::take(&mut pair.private));
        let public: [u8; 32] = pair.public.as_slice().try_into().map_err(|_| failed())?;
        Ok(Self { public, private })
    }

    pub fn public(&self) -> &[u8; 32] {
        &self.public
    }

    /// Writes the public half where clients find it.
    pub fn publish(&self) -> anyhow::Result<()> {
        let hex: String = self.public.iter().map(|b| format!("{b:02x}")).collect();
        crate::paths::write_private(&crate::paths::daemon_public_key(), hex.as_bytes())?;
        Ok(())
    }
}

/// The daemon's public key, as it published it.
pub fn daemon_public_key() -> anyhow::Result<[u8; 32]> {
    let text = std::fs::read_to_string(crate::paths::daemon_public_key())
        .map_err(|_| crate::fault!("err.daemonKeyMissing"))?;
    parse_key(text.trim()).ok_or_else(|| crate::fault!("err.daemonKeyMissing"))
}

fn parse_key(hex: &str) -> Option<[u8; 32]> {
    if hex.len() != 64 {
        return None;
    }
    let mut out = [0u8; 32];
    for (i, b) in out.iter_mut().enumerate() {
        *b = u8::from_str_radix(hex.get(2 * i..2 * i + 2)?, 16).ok()?;
    }
    Some(out)
}

/// The daemon's side of a handshake.
pub fn respond(key: &DaemonKey, first: &[u8]) -> anyhow::Result<(Vec<u8>, Channel)> {
    let mut hs = snow::Builder::new(params())
        .prologue(PROLOGUE)
        .map_err(|_| failed())?
        .local_private_key(&key.private)
        .map_err(|_| failed())?
        .build_responder()
        .map_err(|_| failed())?;
    let mut scratch = Zeroizing::new(vec![0u8; MAX_NOISE]);
    // The handshake carries no payload: anything in it is another protocol.
    if hs.read_message(first, &mut scratch).map_err(|_| failed())? != 0 {
        return Err(failed());
    }
    let mut reply = vec![0u8; MAX_NOISE];
    let n = hs.write_message(&[], &mut reply).map_err(|_| failed())?;
    reply.truncate(n);
    let transport = hs.into_transport_mode().map_err(|_| failed())?;
    Ok((reply, Channel { transport, header: None, received: Zeroizing::new(Vec::new()) }))
}

/// The client's side of a handshake: the first message.
pub fn initiate(daemon: &[u8; 32]) -> anyhow::Result<(snow::HandshakeState, Vec<u8>)> {
    let mut hs = snow::Builder::new(params())
        .prologue(PROLOGUE)
        .map_err(|_| failed())?
        .remote_public_key(daemon)
        .map_err(|_| failed())?
        .build_initiator()
        .map_err(|_| failed())?;
    let mut first = vec![0u8; MAX_NOISE];
    let n = hs.write_message(&[], &mut first).map_err(|_| failed())?;
    first.truncate(n);
    Ok((hs, first))
}

/// The client's side: the daemon's answer finishes the handshake. A daemon
/// without the private half of the published key cannot make an answer that
/// passes here.
pub fn complete(mut hs: snow::HandshakeState, reply: &[u8]) -> anyhow::Result<Channel> {
    let mut scratch = Zeroizing::new(vec![0u8; MAX_NOISE]);
    if hs.read_message(reply, &mut scratch).map_err(|_| crate::fault!("err.daemonNotOurs"))? != 0 {
        return Err(crate::fault!("err.daemonNotOurs"));
    }
    let transport = hs.into_transport_mode().map_err(|_| failed())?;
    Ok(Channel { transport, header: None, received: Zeroizing::new(Vec::new()) })
}

/// The channel between the daemon and a plugin it started:
/// `Noise_NN_25519_ChaChaPoly_BLAKE2s`. Neither side has a static key: the
/// daemon made the process and holds both ends of its pipes, and that is the
/// plugin's authentication; Noise gives the conversation secrecy and
/// integrity, message by message. The prologue names the plugin protocol's
/// version — a plugin of another one does not come to terms at all.
pub const PLUGIN_PATTERN: &str = "Noise_NN_25519_ChaChaPoly_BLAKE2s";
const PLUGIN_PROLOGUE: &[u8] = b"keyward plugin v2";

fn plugin_builder() -> anyhow::Result<snow::Builder<'static>> {
    snow::Builder::new(PLUGIN_PATTERN.parse().expect("the pattern is a valid Noise name"))
        .prologue(PLUGIN_PROLOGUE)
        .map_err(|_| failed())
}

/// The daemon's side: the first message to a plugin.
pub fn plugin_initiate() -> anyhow::Result<(snow::HandshakeState, Vec<u8>)> {
    let mut hs = plugin_builder()?.build_initiator().map_err(|_| failed())?;
    let mut first = vec![0u8; MAX_NOISE];
    let n = hs.write_message(&[], &mut first).map_err(|_| failed())?;
    first.truncate(n);
    Ok((hs, first))
}

/// The plugin's side: the daemon's first message, the answer to it.
pub fn plugin_respond(first: &[u8]) -> anyhow::Result<(Vec<u8>, Channel)> {
    let mut hs = plugin_builder()?.build_responder().map_err(|_| failed())?;
    let mut scratch = Zeroizing::new(vec![0u8; MAX_NOISE]);
    // The handshake carries no payload: anything in it is another protocol.
    if hs.read_message(first, &mut scratch).map_err(|_| failed())? != 0 {
        return Err(failed());
    }
    let mut reply = vec![0u8; MAX_NOISE];
    let n = hs.write_message(&[], &mut reply).map_err(|_| failed())?;
    reply.truncate(n);
    let transport = hs.into_transport_mode().map_err(|_| failed())?;
    Ok((reply, Channel { transport, header: None, received: Zeroizing::new(Vec::new()) }))
}

/// The daemon's side: the plugin's answer finishes the handshake.
pub fn plugin_complete(mut hs: snow::HandshakeState, reply: &[u8]) -> anyhow::Result<Channel> {
    let mut scratch = Zeroizing::new(vec![0u8; MAX_NOISE]);
    if hs.read_message(reply, &mut scratch).map_err(|_| crate::fault!("err.pluginProtocolOld"))? != 0 {
        return Err(crate::fault!("err.pluginProtocolOld"));
    }
    let transport = hs.into_transport_mode().map_err(|_| failed())?;
    Ok(Channel { transport, header: None, received: Zeroizing::new(Vec::new()) })
}

/// An open channel: messages are sealed into frames and opened from them.
pub struct Channel {
    transport: snow::TransportState,
    /// The length of the message being received, once its header is in.
    header: Option<usize>,
    received: Zeroizing<Vec<u8>>,
}

/// Only that it is a channel: its keys are nobody's business, a log's least of all.
impl std::fmt::Debug for Channel {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str("Channel")
    }
}

impl Channel {
    /// A message as frames: its sealed length, then its sealed chunks.
    pub fn seal(&mut self, plain: &[u8]) -> anyhow::Result<Vec<Vec<u8>>> {
        let total = u32::try_from(plain.len()).map_err(|_| crate::fault!("err.channelTooLong"))?;
        let mut frames = Vec::with_capacity(1 + plain.len().div_ceil(CHUNK));
        frames.push(self.seal_one(&total.to_be_bytes())?);
        for chunk in plain.chunks(CHUNK) {
            frames.push(self.seal_one(chunk)?);
        }
        Ok(frames)
    }

    fn seal_one(&mut self, plain: &[u8]) -> anyhow::Result<Vec<u8>> {
        let mut out = vec![0u8; plain.len() + TAG];
        let n = self.transport.write_message(plain, &mut out).map_err(|_| failed())?;
        out.truncate(n);
        Ok(out)
    }

    /// Takes one frame. `Some` once a whole message is in. Anything that does
    /// not open — tampered, replayed, out of order — ends the channel.
    pub fn open(&mut self, frame: &[u8], max: usize) -> anyhow::Result<Option<Zeroizing<Vec<u8>>>> {
        let mut plain = Zeroizing::new(vec![0u8; frame.len()]);
        let n = self.transport.read_message(frame, &mut plain).map_err(|_| failed())?;
        plain.truncate(n);
        let total = match self.header {
            None => {
                let len: [u8; 4] = plain.as_slice().try_into().map_err(|_| failed())?;
                let total = u32::from_be_bytes(len) as usize;
                if total > max {
                    return Err(crate::fault!("err.channelTooLong"));
                }
                self.header = Some(total);
                self.received = Zeroizing::new(Vec::with_capacity(total));
                total
            }
            Some(total) => {
                if self.received.len() + plain.len() > total {
                    return Err(failed());
                }
                self.received.extend_from_slice(&plain);
                total
            }
        };
        if self.received.len() == total {
            self.header = None;
            return Ok(Some(std::mem::replace(&mut self.received, Zeroizing::new(Vec::new()))));
        }
        Ok(None)
    }

    /// Sends a message over a blocking stream.
    pub fn send(&mut self, stream: &mut impl Write, plain: &[u8]) -> anyhow::Result<()> {
        for frame in self.seal(plain)? {
            write_frame(stream, &frame)?;
        }
        stream.flush()?;
        Ok(())
    }

    /// Receives a message over a blocking stream.
    pub fn recv(&mut self, stream: &mut impl Read, max: usize) -> anyhow::Result<Zeroizing<Vec<u8>>> {
        loop {
            let frame = read_frame(stream)?;
            if let Some(message) = self.open(&frame, max)? {
                return Ok(message);
            }
        }
    }
}

pub fn write_frame(stream: &mut impl Write, frame: &[u8]) -> anyhow::Result<()> {
    let len = u16::try_from(frame.len()).map_err(|_| failed())?;
    stream.write_all(&len.to_be_bytes())?;
    stream.write_all(frame)?;
    Ok(())
}

pub fn read_frame(stream: &mut impl Read) -> anyhow::Result<Vec<u8>> {
    let mut len = [0u8; 2];
    stream.read_exact(&mut len).map_err(|_| crate::fault!("err.channelClosed"))?;
    let mut frame = vec![0u8; u16::from_be_bytes(len) as usize];
    stream.read_exact(&mut frame).map_err(|_| crate::fault!("err.channelClosed"))?;
    Ok(frame)
}

/// Opens a channel over a blocking stream to the daemon.
pub fn connect(stream: &mut (impl Read + Write), daemon: &[u8; 32]) -> anyhow::Result<Channel> {
    let (hs, first) = initiate(daemon)?;
    write_frame(stream, &first)?;
    stream.flush()?;
    let reply = read_frame(stream)?;
    complete(hs, &reply)
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::os::unix::net::UnixStream;

    /// A daemon on one end of a socket pair: it answers every message with
    /// the same bytes reversed.
    fn echo_daemon(key: DaemonKey, mut s: UnixStream) -> std::thread::JoinHandle<anyhow::Result<()>> {
        std::thread::spawn(move || {
            let first = read_frame(&mut s)?;
            let (reply, mut ch) = respond(&key, &first)?;
            write_frame(&mut s, &reply)?;
            loop {
                let Ok(msg) = ch.recv(&mut s, MAX_REQUEST) else { return Ok(()) };
                let back: Vec<u8> = msg.iter().rev().copied().collect();
                ch.send(&mut s, &back)?;
            }
        })
    }

    #[test]
    fn messages_of_any_size_go_there_and_back() {
        let key = DaemonKey::generate().unwrap();
        let public = *key.public();
        let (mut client, server) = UnixStream::pair().unwrap();
        let daemon = echo_daemon(key, server);
        let mut ch = connect(&mut client, &public).unwrap();
        for size in [0usize, 1, 100, CHUNK - 1, CHUNK, CHUNK + 1, 3 * CHUNK + 17, 300_000] {
            let msg: Vec<u8> = (0..size).map(|i| (i * 7 % 251) as u8).collect();
            ch.send(&mut client, &msg).unwrap();
            let back = ch.recv(&mut client, MAX_RESPONSE).unwrap();
            assert_eq!(back.len(), size);
            assert!(back.iter().rev().eq(msg.iter()), "size {size}");
        }
        drop(client);
        daemon.join().unwrap().unwrap();
    }

    #[test]
    fn nothing_on_the_wire_is_in_the_clear() {
        let key = DaemonKey::generate().unwrap();
        let (hs, first) = initiate(key.public()).unwrap();
        let (reply, mut server) = respond(&key, &first).unwrap();
        let mut client = complete(hs, &reply).unwrap();
        let secret = br#"{"op":"unlock","password":"correct horse battery staple"}"#;
        let frames = client.seal(secret).unwrap();
        let wire: Vec<u8> = frames.concat();
        assert!(!wire.windows(5).any(|w| w == b"horse"), "the password is not on the wire");
        assert!(!wire.windows(6).any(|w| w == b"unlock"), "neither is the operation");
        let mut got = None;
        for f in &frames {
            got = server.open(f, MAX_REQUEST).unwrap();
        }
        assert_eq!(got.unwrap().as_slice(), secret);
    }

    #[test]
    fn a_daemon_without_the_published_key_is_refused() {
        let real = DaemonKey::generate().unwrap();
        let impostor = DaemonKey::generate().unwrap();
        let (hs, first) = initiate(real.public()).unwrap();
        // The impostor cannot even read the first message meant for the real
        // key; and if it answers anyway, the client does not accept it.
        assert!(respond(&impostor, &first).is_err());
        let (_hs2, first2) = initiate(impostor.public()).unwrap();
        let (reply, _) = respond(&impostor, &first2).unwrap();
        let err = complete(hs, &reply).unwrap_err();
        assert!(err.to_string().contains("err.daemonNotOurs"));
    }

    #[test]
    fn a_tampered_or_replayed_frame_ends_the_channel() {
        let key = DaemonKey::generate().unwrap();
        let (hs, first) = initiate(key.public()).unwrap();
        let (reply, mut server) = respond(&key, &first).unwrap();
        let mut client = complete(hs, &reply).unwrap();

        let mut frames = client.seal(b"hello").unwrap();
        frames[1][0] ^= 1;
        assert!(server.open(&frames[0], MAX_REQUEST).unwrap().is_none());
        assert!(server.open(&frames[1], MAX_REQUEST).is_err(), "a flipped bit");

        let (hs, first) = initiate(key.public()).unwrap();
        let (reply, mut server) = respond(&key, &first).unwrap();
        let mut client = complete(hs, &reply).unwrap();
        let frames = client.seal(b"hello").unwrap();
        server.open(&frames[0], MAX_REQUEST).unwrap();
        server.open(&frames[1], MAX_REQUEST).unwrap();
        assert!(server.open(&frames[0], MAX_REQUEST).is_err(), "a replayed header");
    }

    #[test]
    fn an_oversized_message_is_refused_by_its_header() {
        let key = DaemonKey::generate().unwrap();
        let (hs, first) = initiate(key.public()).unwrap();
        let (reply, mut server) = respond(&key, &first).unwrap();
        let mut client = complete(hs, &reply).unwrap();
        let frames = client.seal(&vec![0u8; 1000]).unwrap();
        let err = server.open(&frames[0], 999).unwrap_err();
        assert!(err.to_string().contains("err.channelTooLong"));
    }

    #[test]
    fn a_plaintext_request_is_recognised_by_its_first_byte() {
        let key = DaemonKey::generate().unwrap();
        let (_, first) = initiate(key.public()).unwrap();
        // The handshake's first frame starts with its length, never with `{`.
        let mut wire = Vec::new();
        write_frame(&mut wire, &first).unwrap();
        assert_ne!(wire[0], PLAINTEXT_FIRST_BYTE);
        assert_eq!(br#"{"op":"ping"}"#[0], PLAINTEXT_FIRST_BYTE);
    }

    #[test]
    fn the_plugin_channel_seals_both_ways() {
        let (hs, first) = plugin_initiate().unwrap();
        let (reply, mut plugin) = plugin_respond(&first).unwrap();
        let mut daemon = plugin_complete(hs, &reply).unwrap();
        let secret = br#"{"kind":"host_result","id":3,"ok":"hvs.a-vault-token"}"#;
        let frames = daemon.seal(secret).unwrap();
        assert!(!frames.concat().windows(9).any(|w| w == b"hvs.a-vau"), "the token is not on the pipe");
        let mut got = None;
        for f in &frames {
            got = plugin.open(f, MAX_REQUEST).unwrap();
        }
        assert_eq!(got.unwrap().as_slice(), secret);
        let back = plugin.seal(b"{\"kind\":\"result\"}").unwrap();
        let mut got = None;
        for f in &back {
            got = daemon.open(f, MAX_REQUEST).unwrap();
        }
        assert_eq!(got.unwrap().as_slice(), b"{\"kind\":\"result\"}");
        // The control channel's handshake is not the plugin's: a plugin that
        // speaks another version does not come to terms.
        let key = DaemonKey::generate().unwrap();
        let (_, control_first) = initiate(key.public()).unwrap();
        assert!(plugin_respond(&control_first).is_err());
    }

    #[test]
    fn a_key_file_is_read_back_exactly() {
        let key = DaemonKey::generate().unwrap();
        let hex: String = key.public().iter().map(|b| format!("{b:02x}")).collect();
        assert_eq!(parse_key(&hex).as_ref(), Some(key.public()));
        assert!(parse_key("zz").is_none());
        assert!(parse_key(&hex[..62]).is_none());
    }
}
