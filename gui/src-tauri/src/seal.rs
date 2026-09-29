//! What the window's Rust half hands its webview is sealed, not plain.
//!
//! A value a person asked to see — a password, a code, a generated one — has
//! to reach the page to be drawn, and it travels there sealed: every webview
//! opens a session at start (an ephemeral ECDH P-256 exchange, AES-256-GCM
//! from HKDF-SHA256 over both public keys) and opens the value with a key it
//! cannot even export, right before it is shown. A webview that has not opened
//! a session gets nothing.

use std::collections::HashMap;
use std::sync::{Mutex, OnceLock};

use aes_gcm::aead::{Aead as _, KeyInit as _};
use aes_gcm::{Aes256Gcm, Nonce};
use base64::Engine as _;
use p256::ecdh::EphemeralSecret;
use p256::elliptic_curve::sec1::ToEncodedPoint as _;
use rand_core::RngCore as _;
use zeroize::Zeroizing;

const SALT: &[u8] = b"keyward window v1";
const INFO: &[u8] = b"window to webview";

fn sessions() -> &'static Mutex<HashMap<String, Aes256Gcm>> {
    static SESSIONS: OnceLock<Mutex<HashMap<String, Aes256Gcm>>> = OnceLock::new();
    SESSIONS.get_or_init(|| Mutex::new(HashMap::new()))
}

fn b64() -> base64::engine::GeneralPurpose {
    base64::engine::general_purpose::STANDARD
}

/// A value on its way to the webview.
#[derive(serde::Serialize)]
pub struct Sealed {
    sealed: String,
}

fn key(secret: &[u8], webview: &[u8], window: &[u8]) -> Result<Aes256Gcm, String> {
    let hk = hkdf::Hkdf::<sha2::Sha256>::new(Some(SALT), secret);
    let mut info = Vec::with_capacity(INFO.len() + webview.len() + window.len());
    info.extend_from_slice(INFO);
    info.extend_from_slice(webview);
    info.extend_from_slice(window);
    let mut out = Zeroizing::new([0u8; 32]);
    hk.expand(&info, out.as_mut()).map_err(|_| "err.channelFailed".to_string())?;
    Aes256Gcm::new_from_slice(out.as_ref()).map_err(|_| "err.channelFailed".to_string())
}

/// Opens (or reopens, after a reload) a webview's session. Takes its public
/// key, gives back ours.
pub fn open(label: &str, public: &str) -> Result<String, String> {
    let theirs_raw = b64().decode(public.trim()).map_err(|_| "err.channelFailed".to_string())?;
    let theirs = p256::PublicKey::from_sec1_bytes(&theirs_raw).map_err(|_| "err.channelFailed".to_string())?;
    let mine = EphemeralSecret::random(&mut rand_core::OsRng);
    let ours = mine.public_key().to_encoded_point(false).as_bytes().to_vec();
    let shared = mine.diffie_hellman(&theirs);
    let cipher = key(shared.raw_secret_bytes(), &theirs_raw, &ours)?;
    sessions().lock().map_err(|_| "err.channelFailed".to_string())?.insert(label.to_string(), cipher);
    Ok(b64().encode(ours))
}

/// Seals a value for one webview. A random nonce: answers go out of order and
/// from several tasks at once.
pub fn seal(label: &str, value: &str) -> Result<Sealed, String> {
    let guard = sessions().lock().map_err(|_| "err.channelFailed".to_string())?;
    let cipher = guard.get(label).ok_or_else(|| "err.channelRequired".to_string())?;
    let mut nonce = [0u8; 12];
    rand_core::OsRng.fill_bytes(&mut nonce);
    let sealed = cipher
        .encrypt(Nonce::from_slice(&nonce), value.as_bytes())
        .map_err(|_| "err.channelFailed".to_string())?;
    let mut out = nonce.to_vec();
    out.extend_from_slice(&sealed);
    Ok(Sealed { sealed: b64().encode(out) })
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn a_value_reaches_the_webview_sealed_and_only_through_its_session() {
        // The webview's half, as WebCrypto does it.
        let page = EphemeralSecret::random(&mut rand_core::OsRng);
        let page_pub = page.public_key().to_encoded_point(false).as_bytes().to_vec();
        let ours = open("main", &b64().encode(&page_pub)).unwrap();
        let ours_raw = b64().decode(ours).unwrap();
        let shared = page.diffie_hellman(&p256::PublicKey::from_sec1_bytes(&ours_raw).unwrap());
        let page_key = key(shared.raw_secret_bytes(), &page_pub, &ours_raw).unwrap();

        let sealed = seal("main", "correct horse").unwrap();
        let raw = b64().decode(&sealed.sealed).unwrap();
        assert!(!String::from_utf8_lossy(&raw).contains("horse"));
        let plain = page_key.decrypt(Nonce::from_slice(&raw[..12]), &raw[12..]).unwrap();
        assert_eq!(plain, b"correct horse");

        assert_eq!(seal("never-opened", "x").err().as_deref(), Some("err.channelRequired"));
        assert!(open("main", "not a key").is_err());
    }
}
