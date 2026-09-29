//! The terminal's page and the plugin talk sealed end to end.
//!
//! What a terminal carries is whatever a person types and whatever a server
//! prints: a `sudo` password, a token pasted into a prompt, the contents of an
//! `.env`. It crosses the window's Rust half and the daemon on its way here, and
//! neither of them has any business reading it. So the page and the plugin make
//! a key of their own and everything in between carries ciphertext:
//!
//! 1. The page sends its ephemeral P-256 key (`term_link`), the plugin answers
//!    with its own.
//! 2. Both derive four AES-256-GCM keys with HKDF-SHA256 over the shared
//!    secret — salt `keyward terminal v1`, the direction, the lane and both
//!    public keys in the info, so the keys belong to this exchange and no
//!    other.
//! 3. A link has two lanes, input and output, because a long-poll for output
//!    and a keystroke travel at the same time over separate connections and
//!    would overtake each other. Within a lane the page sends the next request
//!    only after the answer to the last one, and the nonce is the exchange's
//!    number: a request replayed, dropped or reordered does not open, and
//!    neither does an answer.
//!
//! The same construction as the browser bridge (`crates/passkey-host`), with
//! lanes added; WebCrypto does the page's half.

use aes_gcm::aead::{Aead as _, KeyInit as _, Payload};
use aes_gcm::{Aes256Gcm, Nonce};
use base64::Engine as _;
use p256::ecdh::EphemeralSecret;
use p256::elliptic_curve::sec1::ToEncodedPoint as _;
use serde::Deserialize;
use zeroize::Zeroizing;

const SALT: &[u8] = b"keyward terminal v1";
const TO_PLUGIN: &[u8] = b"page to plugin";
const TO_PAGE: &[u8] = b"plugin to page";

fn b64() -> base64::engine::GeneralPurpose {
    base64::engine::general_purpose::STANDARD
}

fn refused() -> anyhow::Error {
    keyward_core::fault!("err.channelFailed")
}

/// Which of a link's two lanes a message travels on.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum Lane {
    /// Opening, keystrokes, resizing, closing.
    Input,
    /// Waiting for what the server printed.
    Output,
}

impl Lane {
    fn label(self) -> &'static [u8] {
        match self {
            Self::Input => b"input",
            Self::Output => b"output",
        }
    }
}

/// One direction of one lane: its key and the number of the next exchange.
struct Half {
    key: Aes256Gcm,
    counter: u64,
}

/// One lane: a request opens with `from_page` under the exchange's number, and
/// its answer is sealed with `to_page` under the same number.
struct LaneKeys {
    from_page: Half,
    to_page: Half,
}

/// One page's keys. Not `Debug`: it holds them.
pub struct Link {
    input: LaneKeys,
    output: LaneKeys,
}

fn nonce(counter: u64) -> [u8; 12] {
    let mut n = [0u8; 12];
    n[4..].copy_from_slice(&counter.to_be_bytes());
    n
}

fn key(shared: &[u8], direction: &[u8], lane: Lane, page: &[u8], plugin: &[u8]) -> anyhow::Result<Aes256Gcm> {
    let hk = hkdf::Hkdf::<sha2::Sha256>::new(Some(SALT), shared);
    let label = lane.label();
    let mut info = Vec::with_capacity(direction.len() + 1 + label.len() + page.len() + plugin.len());
    info.extend_from_slice(direction);
    info.push(b' ');
    info.extend_from_slice(label);
    info.extend_from_slice(page);
    info.extend_from_slice(plugin);
    let mut out = Zeroizing::new([0u8; 32]);
    hk.expand(&info, out.as_mut()).map_err(|_| refused())?;
    Aes256Gcm::new_from_slice(out.as_ref()).map_err(|_| refused())
}

fn lane_keys(shared: &[u8], lane: Lane, page: &[u8], plugin: &[u8]) -> anyhow::Result<LaneKeys> {
    Ok(LaneKeys {
        from_page: Half { key: key(shared, TO_PLUGIN, lane, page, plugin)?, counter: 0 },
        to_page: Half { key: key(shared, TO_PAGE, lane, page, plugin)?, counter: 0 },
    })
}

impl Link {
    /// The plugin's answer to the page's key: the link, and the plugin's
    /// public key to send back.
    pub fn accept(page_public: &str) -> anyhow::Result<(Self, String)> {
        let page = b64().decode(page_public.trim()).map_err(|_| refused())?;
        let theirs = p256::PublicKey::from_sec1_bytes(&page).map_err(|_| refused())?;
        let mine = EphemeralSecret::random(&mut rand_core::OsRng);
        let plugin = mine.public_key().to_encoded_point(false).as_bytes().to_vec();
        let shared = mine.diffie_hellman(&theirs);
        let secret = shared.raw_secret_bytes();
        let link = Self {
            input: lane_keys(secret, Lane::Input, &page, &plugin)?,
            output: lane_keys(secret, Lane::Output, &page, &plugin)?,
        };
        Ok((link, b64().encode(&plugin)))
    }

    fn lane(&mut self, lane: Lane) -> &mut LaneKeys {
        match lane {
            Lane::Input => &mut self.input,
            Lane::Output => &mut self.output,
        }
    }

    /// Opens the page's request. The counter moves only when it opens: a
    /// forgery does not knock the lane out of step.
    pub fn open(&mut self, lane: Lane, sealed: &str) -> anyhow::Result<Zeroizing<Vec<u8>>> {
        let bytes = b64().decode(sealed.trim()).map_err(|_| refused())?;
        let half = &mut self.lane(lane).from_page;
        let n = nonce(half.counter);
        let plain = half
            .key
            .decrypt(Nonce::from_slice(&n), Payload { msg: &bytes, aad: lane.label() })
            .map_err(|_| refused())?;
        half.counter += 1;
        Ok(Zeroizing::new(plain))
    }

    /// Seals the answer to the request just opened on this lane.
    pub fn seal(&mut self, lane: Lane, plain: &[u8]) -> anyhow::Result<String> {
        let half = &mut self.lane(lane).to_page;
        let n = nonce(half.counter);
        let sealed = half
            .key
            .encrypt(Nonce::from_slice(&n), Payload { msg: plain, aad: lane.label() })
            .map_err(|_| refused())?;
        half.counter += 1;
        Ok(b64().encode(sealed))
    }
}

#[cfg(test)]
pub mod tests {
    use super::*;

    /// The page's half, as WebCrypto does it, for the tests.
    pub struct Page {
        pub hello: String,
        secret: EphemeralSecret,
        public: Vec<u8>,
    }

    /// The page's keys for one lane: sealing requests, opening answers.
    pub struct PageLane {
        to_plugin: Aes256Gcm,
        to_page: Aes256Gcm,
        sent: u64,
        received: u64,
        lane: Lane,
    }

    impl PageLane {
        pub fn seal(&mut self, plain: &[u8]) -> String {
            let n = nonce(self.sent);
            self.sent += 1;
            b64().encode(
                self.to_plugin
                    .encrypt(Nonce::from_slice(&n), Payload { msg: plain, aad: self.lane.label() })
                    .unwrap(),
            )
        }

        pub fn open(&mut self, sealed: &str) -> Vec<u8> {
            let n = nonce(self.received);
            self.received += 1;
            self.to_page
                .decrypt(Nonce::from_slice(&n), Payload { msg: &b64().decode(sealed).unwrap(), aad: self.lane.label() })
                .unwrap()
        }
    }

    impl Page {
        pub fn new() -> Self {
            let secret = EphemeralSecret::random(&mut rand_core::OsRng);
            let public = secret.public_key().to_encoded_point(false).as_bytes().to_vec();
            Self { hello: b64().encode(&public), secret, public }
        }

        pub fn finish(self, plugin_hello: &str) -> (PageLane, PageLane) {
            let plugin = b64().decode(plugin_hello).unwrap();
            let shared = self.secret.diffie_hellman(&p256::PublicKey::from_sec1_bytes(&plugin).unwrap());
            let s = shared.raw_secret_bytes();
            let make = |lane| PageLane {
                to_plugin: key(s, TO_PLUGIN, lane, &self.public, &plugin).unwrap(),
                to_page: key(s, TO_PAGE, lane, &self.public, &plugin).unwrap(),
                sent: 0,
                received: 0,
                lane,
            };
            (make(Lane::Input), make(Lane::Output))
        }
    }

    #[test]
    fn a_link_seals_both_ways_on_both_lanes() {
        let page = Page::new();
        let (mut link, hello) = Link::accept(&page.hello).unwrap();
        let (mut input, mut output) = page.finish(&hello);

        let req = input.seal(b"sudo password");
        assert!(!String::from_utf8_lossy(&b64().decode(&req).unwrap()).contains("password"));
        assert_eq!(&link.open(Lane::Input, &req).unwrap()[..], b"sudo password");
        let back = link.seal(Lane::Input, b"ok").unwrap();
        assert_eq!(input.open(&back), b"ok");

        // The lanes keep their own count: output's first exchange is number
        // zero whatever input has done.
        let poll = output.seal(b"read");
        assert_eq!(&link.open(Lane::Output, &poll).unwrap()[..], b"read");
    }

    #[test]
    fn a_replayed_reordered_or_crossed_message_does_not_open() {
        let page = Page::new();
        let (mut link, hello) = Link::accept(&page.hello).unwrap();
        let (mut input, mut output) = page.finish(&hello);

        let first = input.seal(b"first");
        let second = input.seal(b"second");
        assert!(link.open(Lane::Input, &second).is_err(), "out of order");
        assert!(link.open(Lane::Input, &first).is_ok());
        assert!(link.open(Lane::Input, &first).is_err(), "replayed");
        assert!(link.open(Lane::Input, &second).is_ok(), "a refusal must not knock the lane out of step");

        // A message of one lane does not open on the other.
        let poll = output.seal(b"read");
        assert!(link.open(Lane::Input, &poll).is_err());
    }

    #[test]
    fn a_link_is_bound_to_its_own_exchange() {
        let one = Page::new();
        let other = Page::new();
        let (mut link, _) = Link::accept(&one.hello).unwrap();
        let (_, hello) = Link::accept(&other.hello).unwrap();
        let (mut input, _) = other.finish(&hello);
        assert!(link.open(Lane::Input, &input.seal(b"x")).is_err());
        assert!(Link::accept("not a key").is_err());
    }
}
