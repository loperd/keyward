//! keyward's native messaging host: the one road from the browser extension
//! to the daemon, and only for passkeys.
//!
//! Chrome (and Arc, Brave, Edge — any Chromium) starts this binary when the
//! extension sends a message, with the extension's origin as the first
//! argument, and speaks to it over stdin/stdout: each message is a 32-bit
//! length in native byte order followed by that much JSON.
//!
//! What it is not: a proxy. It understands exactly four requests — the
//! passkeys a sign-in may use, the logins a new one may go into, a sign-in,
//! a registration — and turns each into the daemon's own request; anything
//! else is refused here, before the socket. The daemon trusts this binary as its own (it is signed with the
//! same identity), so a hole here would be a hole in the vault: an extension
//! compromised, or a page that got hold of its port, must not be able to ask
//! for a password through it.
//!
//! Nothing secret passes through: a request carries a challenge and a site,
//! an answer a signature and public data. The private key stays in the daemon.
//! And even that travels sealed on both legs: to the daemon over its
//! encrypted channel, to the browser in a session of its own (`bridge`).

mod bridge;

use std::io::{Read, Write};
use std::time::Duration;

use keyward_core::passkey::{Register, SignIn, SignInWith};
use keyward_core::proto::{Request, Response};
use serde::Deserialize;

/// The extensions allowed to start the host. Chrome checks the manifest's
/// `allowed_origins` itself; this is the second lock on the same door, for a
/// manifest someone edited.
///
/// The unpacked extension (its id comes from the `key` in its manifest) and
/// the Chrome Web Store's.
const ALLOWED: &[&str] = &[
    "chrome-extension://cblgcmdaededmmnlihjkalbkhdeegehl/",
    "chrome-extension://codlckblccbcnadacdnoieimkmdieajg/",
];

/// The largest message taken from the browser. An honest one is well under
/// two kilobytes; the ceiling stops a runaway length from allocating
/// gigabytes.
const MAX_MESSAGE: usize = 64 * 1024;

/// A sign-in waits for Touch ID, which the daemon gives a minute.
const WAIT: Duration = Duration::from_secs(90);

/// What the extension may ask.
#[derive(Debug, Deserialize)]
#[serde(tag = "op", rename_all = "snake_case")]
enum Ask {
    Offers { sign_in: SignIn },
    Homes { sign_in: SignIn },
    SignIn { request: SignInWith },
    Register { request: Register },
}

#[derive(Debug, Deserialize)]
struct Envelope {
    /// The extension's own number for the request, sent back as it came.
    #[serde(default)]
    id: u64,
    #[serde(flatten)]
    ask: Ask,
}

impl Ask {
    fn into_request(self) -> Request {
        match self {
            Self::Offers { sign_in } => Request::PasskeyOffers { sign_in },
            Self::Homes { sign_in } => Request::PasskeyHomes { sign_in },
            Self::SignIn { request } => Request::PasskeySignIn { request },
            Self::Register { request } => Request::PasskeyRegister { request },
        }
    }
}

/// The daemon's answer, as the extension gets it. Only the passkey
/// answers and an error pass; anything else the daemon might say is not
/// forwarded.
fn answer(id: u64, response: anyhow::Result<Response>) -> serde_json::Value {
    let fail = |message: &str| {
        let code = message.split_whitespace().next().filter(|w| w.starts_with("err.")).unwrap_or("err.passkeyHost");
        serde_json::json!({ "id": id, "ok": false, "code": code, "error": keyward_core::text::render(message) })
    };
    match response {
        Ok(Response::PasskeyOffers { offers }) => serde_json::json!({ "id": id, "ok": true, "offers": offers }),
        Ok(Response::PasskeyHomes { homes }) => serde_json::json!({ "id": id, "ok": true, "homes": homes }),
        Ok(Response::PasskeySignedIn { signed }) => serde_json::json!({ "id": id, "ok": true, "signed": signed }),
        Ok(Response::PasskeyRegistered { registered }) => {
            serde_json::json!({ "id": id, "ok": true, "registered": registered })
        }
        Ok(Response::Error { message }) => fail(&message),
        Ok(_) => fail("err.passkeyHost"),
        Err(e) => {
            eprintln!("keyward-passkey-host: {e}");
            fail("err.daemonNotRunning")
        }
    }
}

/// One message from the browser, or `None` at the end of input.
fn read_message(input: &mut impl Read) -> anyhow::Result<Option<Vec<u8>>> {
    let mut len = [0u8; 4];
    match input.read_exact(&mut len) {
        Ok(()) => {}
        Err(e) if e.kind() == std::io::ErrorKind::UnexpectedEof => return Ok(None),
        Err(e) => return Err(e.into()),
    }
    let len = u32::from_ne_bytes(len) as usize;
    if len > MAX_MESSAGE {
        anyhow::bail!("a message of {len} bytes is over the limit");
    }
    let mut body = vec![0u8; len];
    input.read_exact(&mut body)?;
    Ok(Some(body))
}

fn write_message(output: &mut impl Write, value: &serde_json::Value) -> anyhow::Result<()> {
    let body = serde_json::to_vec(value)?;
    output.write_all(&(body.len() as u32).to_ne_bytes())?;
    output.write_all(&body)?;
    output.flush()?;
    Ok(())
}

/// One request of the extension, opened: the daemon's answer, as JSON.
fn handle(message: &[u8], call: &dyn Fn(&Request) -> anyhow::Result<Response>) -> serde_json::Value {
    match serde_json::from_slice::<Envelope>(message) {
        Ok(Envelope { id, ask }) => answer(id, call(&ask.into_request())),
        // An unknown operation or a malformed one: refused here, never passed
        // on.
        Err(_) => {
            let id = serde_json::from_slice::<serde_json::Value>(message)
                .ok()
                .and_then(|v| v.get("id").and_then(serde_json::Value::as_u64))
                .unwrap_or(0);
            answer(id, Ok(Response::error("err.passkeyBadRequest")))
        }
    }
}

/// Said in the clear, and only this: the extension did not open the sealed
/// session, so it is told so and the connection ends.
fn refusal() -> serde_json::Value {
    serde_json::json!({ "ok": false, "code": "err.channelRequired", "error": keyward_core::text::render("err.channelRequired") })
}

/// Serves one connection: the key exchange, then sealed messages until the
/// browser closes the pipe. A message that is not sealed, or that does not
/// open, ends the connection.
fn serve(
    input: &mut impl Read,
    output: &mut impl Write,
    call: &dyn Fn(&Request) -> anyhow::Result<Response>,
) -> anyhow::Result<()> {
    let mut session: Option<bridge::Session> = None;
    while let Some(body) = read_message(input)? {
        let body: serde_json::Value = serde_json::from_slice(&body).unwrap_or(serde_json::Value::Null);
        match session.as_mut() {
            None => {
                let accepted = body.get("hello").and_then(serde_json::Value::as_str).map(bridge::Session::accept);
                match accepted {
                    Some(Ok((s, mine))) => {
                        write_message(output, &serde_json::json!({ "hello": mine }))?;
                        session = Some(s);
                    }
                    _ => {
                        eprintln!("keyward-passkey-host: a message before the key exchange was refused");
                        write_message(output, &refusal())?;
                        return Ok(());
                    }
                }
            }
            Some(s) => {
                let Some(sealed) = body.get("sealed").and_then(serde_json::Value::as_str) else {
                    eprintln!("keyward-passkey-host: an unsealed message was refused");
                    write_message(output, &refusal())?;
                    return Ok(());
                };
                let Ok(message) = s.open(sealed) else {
                    eprintln!("keyward-passkey-host: a message did not open; the connection is closed");
                    return Ok(());
                };
                let reply = zeroize::Zeroizing::new(serde_json::to_vec(&handle(&message, call))?);
                write_message(output, &serde_json::json!({ "sealed": s.seal(&reply)? }))?;
            }
        }
    }
    Ok(())
}

fn main() -> anyhow::Result<()> {
    keyward_core::harden::process();
    let caller = std::env::args().nth(1).unwrap_or_default();
    if !ALLOWED.contains(&caller.as_str()) {
        eprintln!("keyward-passkey-host: started by {caller:?}, which is not keyward's extension");
        std::process::exit(2);
    }
    let call = |req: &Request| keyward_core::client::call_with_timeout(req, WAIT);
    serve(&mut std::io::stdin().lock(), &mut std::io::stdout().lock(), &call)
}

#[cfg(test)]
mod tests {
    use super::*;
    use aes_gcm::aead::Aead as _;
    use aes_gcm::Nonce;
    use base64::Engine as _;

    fn framed(value: &serde_json::Value) -> Vec<u8> {
        let body = serde_json::to_vec(value).unwrap();
        let mut out = (body.len() as u32).to_ne_bytes().to_vec();
        out.extend_from_slice(&body);
        out
    }

    fn replies(mut output: &[u8]) -> Vec<serde_json::Value> {
        let mut out = Vec::new();
        while let Some(body) = read_message(&mut output).unwrap() {
            out.push(serde_json::from_slice(&body).unwrap());
        }
        out
    }

    fn nonce(n: u64) -> [u8; 12] {
        let mut out = [0u8; 12];
        out[4..].copy_from_slice(&n.to_be_bytes());
        out
    }

    fn b64() -> base64::engine::GeneralPurpose {
        base64::engine::general_purpose::STANDARD
    }

    fn roundtrip(messages: &[serde_json::Value], call: &(dyn Fn(&Request) -> anyhow::Result<Response> + Sync)) -> Vec<serde_json::Value> {
        // The host's key is fresh for each run, so the exchange is replayed
        // step by step against a live host thread over a socket pair.
        let ext = bridge::tests::Extension::new();
        let (mut ours, theirs) = std::os::unix::net::UnixStream::pair().unwrap();
        std::thread::scope(|scope| {
            scope.spawn(move || {
                let mut theirs = theirs;
                let mut writer = theirs.try_clone().unwrap();
                serve(&mut theirs, &mut writer, call).unwrap();
            });
            ours.write_all(&framed(&serde_json::json!({ "hello": ext.hello.clone() }))).unwrap();
            let host_hello: serde_json::Value = serde_json::from_slice(&read_message(&mut ours).unwrap().unwrap()).unwrap();
            let (to_host, to_ext) = ext.finish(host_hello["hello"].as_str().unwrap());
            let mut out = Vec::new();
            for (n, m) in messages.iter().enumerate() {
                let sealed = to_host.encrypt(Nonce::from_slice(&nonce(n as u64)), serde_json::to_vec(m).unwrap().as_slice()).unwrap();
                ours.write_all(&framed(&serde_json::json!({ "sealed": b64().encode(sealed) }))).unwrap();
                let reply: serde_json::Value = serde_json::from_slice(&read_message(&mut ours).unwrap().unwrap()).unwrap();
                let opened = to_ext
                    .decrypt(Nonce::from_slice(&nonce(n as u64)), b64().decode(reply["sealed"].as_str().unwrap()).unwrap().as_slice())
                    .unwrap();
                out.push(serde_json::from_slice(&opened).unwrap());
            }
            ours.shutdown(std::net::Shutdown::Write).unwrap();
            out
        })
    }

    fn offers() -> serde_json::Value {
        serde_json::json!({"id":7,"op":"offers","sign_in":{"origin":"https://example.com","challenge":"AAAAAAAAAAAAAAAAAAAAAA"}})
    }

    #[test]
    fn only_passkey_requests_pass() {
        let seen = std::sync::Mutex::new(Vec::new());
        let call = |req: &Request| {
            seen.lock().unwrap().push(format!("{req:?}"));
            Ok(Response::PasskeyOffers { offers: Vec::new() })
        };
        let out = roundtrip(
            &[
                offers(),
                serde_json::json!({"id":8,"op":"copy_secret","entry_id":"e","field":"password"}),
                serde_json::json!({"id":9,"op":"reveal_secret","entry_id":"e","field":"password"}),
            ],
            &call,
        );
        assert_eq!(seen.lock().unwrap().len(), 1, "only the passkey request reached the daemon");
        assert_eq!(out[0]["id"], 7);
        assert_eq!(out[0]["ok"], true);
        for (reply, id) in out[1..].iter().zip([8, 9]) {
            assert_eq!(reply["ok"], false);
            assert_eq!(reply["id"], id);
            assert_eq!(reply["code"], "err.passkeyBadRequest");
        }
    }

    #[test]
    fn a_daemon_answer_of_another_kind_is_not_forwarded() {
        let call = |_: &Request| Ok(Response::Secret { value: zeroize::Zeroizing::new("hunter2".into()) });
        let out = roundtrip(&[offers()], &call);
        assert!(!out[0].to_string().contains("hunter2"), "a secret never reaches the browser");
        assert_eq!(out[0]["code"], "err.passkeyHost");
    }

    #[test]
    fn an_error_keeps_its_key_for_the_extension() {
        let call = |_: &Request| Ok(Response::error("err.vaultLocked"));
        let out = roundtrip(&[offers()], &call);
        assert_eq!(out[0]["code"], "err.vaultLocked");
        assert_ne!(out[0]["error"], "err.vaultLocked", "rendered for a person");
    }

    #[test]
    fn a_plaintext_request_is_refused_and_nothing_reaches_the_daemon() {
        let call = |_: &Request| -> anyhow::Result<Response> { unreachable!("nothing reaches the daemon") };
        let mut output = Vec::new();
        serve(&mut framed(&offers()).as_slice(), &mut output, &call).unwrap();
        let out = replies(&output);
        assert_eq!(out.len(), 1);
        assert_eq!(out[0]["code"], "err.channelRequired");
    }

    #[test]
    fn nothing_on_the_browser_leg_is_in_the_clear() {
        let call = |_: &Request| Ok(Response::error("err.vaultLocked"));
        // The same conversation, but watched from the pipe: the host's
        // output must not carry the answer's words.
        let ext = bridge::tests::Extension::new();
        let (mut ours, theirs) = std::os::unix::net::UnixStream::pair().unwrap();
        let wire = std::thread::scope(|scope| {
            let host = scope.spawn(move || {
                let mut theirs = theirs;
                let mut out = Vec::new();
                let mut reader = theirs.try_clone().unwrap();
                // A tee: what the host writes is kept and passed on.
                struct Tee<'a>(&'a mut std::os::unix::net::UnixStream, &'a mut Vec<u8>);
                impl Write for Tee<'_> {
                    fn write(&mut self, b: &[u8]) -> std::io::Result<usize> {
                        self.1.extend_from_slice(b);
                        self.0.write(b)
                    }
                    fn flush(&mut self) -> std::io::Result<()> {
                        self.0.flush()
                    }
                }
                serve(&mut reader, &mut Tee(&mut theirs, &mut out), &call).unwrap();
                out
            });
            ours.write_all(&framed(&serde_json::json!({ "hello": ext.hello.clone() }))).unwrap();
            let host_hello: serde_json::Value = serde_json::from_slice(&read_message(&mut ours).unwrap().unwrap()).unwrap();
            let (to_host, _) = ext.finish(host_hello["hello"].as_str().unwrap());
            let sealed = to_host.encrypt(Nonce::from_slice(&nonce(0)), serde_json::to_vec(&offers()).unwrap().as_slice()).unwrap();
            ours.write_all(&framed(&serde_json::json!({ "sealed": b64().encode(sealed) }))).unwrap();
            read_message(&mut ours).unwrap().unwrap();
            ours.shutdown(std::net::Shutdown::Write).unwrap();
            host.join().unwrap()
        });
        let text = String::from_utf8_lossy(&wire);
        assert!(!text.contains("vaultLocked") && !text.contains("example.com"), "the browser leg carries only seals: {text}");
    }

    #[test]
    fn an_oversized_length_is_refused_before_allocating() {
        let mut input = ((MAX_MESSAGE + 1) as u32).to_ne_bytes().to_vec();
        input.extend([0u8; 16]);
        let call = |_: &Request| unreachable!("nothing reaches the daemon");
        let err = serve(&mut input.as_slice(), &mut Vec::new(), &call).unwrap_err();
        assert!(err.to_string().contains("over the limit"));
    }

    #[test]
    fn an_empty_input_ends_quietly() {
        let call = |_: &Request| unreachable!();
        serve(&mut [].as_slice(), &mut Vec::new(), &call).unwrap();
    }
}
