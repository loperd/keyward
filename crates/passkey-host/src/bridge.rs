//! The browser's side of the road, sealed.
//!
//! Chrome's native messaging is JSON on a pipe, and the host is started afresh
//! for every connection; the format is Chrome's, the contents are ours. So a
//! connection opens with a key exchange and every message after it is sealed:
//!
//! 1. The extension sends `{"hello": <its ephemeral P-256 key>}`, the host
//!    answers `{"hello": <its own>}`.
//! 2. Both derive two keys with HKDF-SHA256 over the shared secret — salt
//!    `keyward bridge v1`, the direction and both public keys in the info, so
//!    the keys belong to this exchange and no other.
//! 3. Every message is `{"sealed": <AES-256-GCM>}`; the nonce is a counter of
//!    its direction, so a message replayed, dropped or reordered does not
//!    open.
//!
//! Who is at the other end is Chrome's to say: the host starts only for the
//! extension in `allowed_origins`, and checks that origin itself too.
//! WebCrypto has all of this built in; nothing is added to the extension.

use aes_gcm::aead::{Aead as _, KeyInit as _};
use aes_gcm::{Aes256Gcm, Nonce};
use base64::Engine as _;
use p256::ecdh::EphemeralSecret;
use p256::elliptic_curve::sec1::ToEncodedPoint as _;
use zeroize::Zeroizing;

const SALT: &[u8] = b"keyward bridge v1";
const TO_HOST: &[u8] = b"extension to host";
const TO_EXTENSION: &[u8] = b"host to extension";

fn b64() -> base64::engine::GeneralPurpose {
    base64::engine::general_purpose::STANDARD
}

fn refused() -> anyhow::Error {
    keyward_core::fault!("err.channelFailed")
}

/// One connection's keys and counters.
pub struct Session {
    from_extension: Aes256Gcm,
    to_extension: Aes256Gcm,
    received: u64,
    sent: u64,
}

fn nonce(counter: u64) -> [u8; 12] {
    let mut n = [0u8; 12];
    n[4..].copy_from_slice(&counter.to_be_bytes());
    n
}

fn key(shared: &[u8], label: &[u8], extension: &[u8], host: &[u8]) -> anyhow::Result<Aes256Gcm> {
    let hk = hkdf::Hkdf::<sha2::Sha256>::new(Some(SALT), shared);
    let mut info = Vec::with_capacity(label.len() + extension.len() + host.len());
    info.extend_from_slice(label);
    info.extend_from_slice(extension);
    info.extend_from_slice(host);
    let mut out = Zeroizing::new([0u8; 32]);
    hk.expand(&info, out.as_mut()).map_err(|_| refused())?;
    Aes256Gcm::new_from_slice(out.as_ref()).map_err(|_| refused())
}

impl Session {
    /// The host's answer to the extension's hello: the session, and the
    /// host's public key to send back.
    pub fn accept(extension_hello: &str) -> anyhow::Result<(Self, String)> {
        let extension = b64().decode(extension_hello.trim()).map_err(|_| refused())?;
        let theirs = p256::PublicKey::from_sec1_bytes(&extension).map_err(|_| refused())?;
        let mine = EphemeralSecret::random(&mut rand_core::OsRng);
        let host = mine.public_key().to_encoded_point(false).as_bytes().to_vec();
        let shared = mine.diffie_hellman(&theirs);
        let secret = shared.raw_secret_bytes();
        let session = Self {
            from_extension: key(secret, TO_HOST, &extension, &host)?,
            to_extension: key(secret, TO_EXTENSION, &extension, &host)?,
            received: 0,
            sent: 0,
        };
        Ok((session, b64().encode(&host)))
    }

    pub fn open(&mut self, sealed: &str) -> anyhow::Result<Zeroizing<Vec<u8>>> {
        let bytes = b64().decode(sealed.trim()).map_err(|_| refused())?;
        let n = nonce(self.received);
        let plain = self.from_extension.decrypt(Nonce::from_slice(&n), bytes.as_slice()).map_err(|_| refused())?;
        self.received += 1;
        Ok(Zeroizing::new(plain))
    }

    pub fn seal(&mut self, plain: &[u8]) -> anyhow::Result<String> {
        let n = nonce(self.sent);
        let sealed = self.to_extension.encrypt(Nonce::from_slice(&n), plain).map_err(|_| refused())?;
        self.sent += 1;
        Ok(b64().encode(sealed))
    }
}

#[cfg(test)]
pub mod tests {
    use super::*;

    /// The extension's half, as WebCrypto does it, for the tests.
    pub struct Extension {
        pub hello: String,
        secret: EphemeralSecret,
        public: Vec<u8>,
    }

    impl Extension {
        pub fn new() -> Self {
            let secret = EphemeralSecret::random(&mut rand_core::OsRng);
            let public = secret.public_key().to_encoded_point(false).as_bytes().to_vec();
            Self { hello: b64().encode(&public), secret, public }
        }

        /// Both directions' keys once the host has answered.
        pub fn finish(self, host_hello: &str) -> (Aes256Gcm, Aes256Gcm) {
            let host = b64().decode(host_hello).unwrap();
            let shared = self.secret.diffie_hellman(&p256::PublicKey::from_sec1_bytes(&host).unwrap());
            let s = shared.raw_secret_bytes();
            (key(s, TO_HOST, &self.public, &host).unwrap(), key(s, TO_EXTENSION, &self.public, &host).unwrap())
        }
    }

    #[test]
    fn a_session_seals_both_ways() {
        let ext = Extension::new();
        let (mut host, host_hello) = Session::accept(&ext.hello).unwrap();
        let (to_host, to_ext) = ext.finish(&host_hello);
        let one = to_host.encrypt(Nonce::from_slice(&nonce(0)), b"one".as_slice()).unwrap();
        assert_eq!(host.open(&b64().encode(&one)).unwrap().as_slice(), b"one");
        let back = host.seal(b"answer").unwrap();
        let plain = to_ext.decrypt(Nonce::from_slice(&nonce(0)), b64().decode(back).unwrap().as_slice()).unwrap();
        assert_eq!(plain, b"answer");
    }

    #[test]
    fn a_replayed_or_reordered_message_does_not_open() {
        let ext = Extension::new();
        let (mut host, host_hello) = Session::accept(&ext.hello).unwrap();
        let (to_host, _) = ext.finish(&host_hello);
        let second = to_host.encrypt(Nonce::from_slice(&nonce(1)), b"second".as_slice()).unwrap();
        assert!(host.open(&b64().encode(&second)).is_err(), "out of order");
        let first = to_host.encrypt(Nonce::from_slice(&nonce(0)), b"first".as_slice()).unwrap();
        host.open(&b64().encode(&first)).unwrap();
        assert!(host.open(&b64().encode(&first)).is_err(), "a replay");
    }

    #[test]
    fn a_session_is_bound_to_its_own_exchange() {
        let ext = Extension::new();
        let (mut host, _) = Session::accept(&ext.hello).unwrap();
        // Keys from another exchange do not open this one.
        let other = Extension::new();
        let (_, other_hello) = Session::accept(&other.hello).unwrap();
        let (to_host, _) = other.finish(&other_hello);
        let sealed = to_host.encrypt(Nonce::from_slice(&nonce(0)), b"x".as_slice()).unwrap();
        assert!(host.open(&b64().encode(&sealed)).is_err());
        assert!(Session::accept("not a key").is_err());
    }
}
