//! Using passkeys, not only showing them: what a site asks of an
//! authenticator and what it gets back.
//!
//! keyward is a WebAuthn authenticator here. The private key never leaves the
//! daemon: a request carries the hash of the client data, an answer carries a
//! signature and the authenticator's data, and both are what any hardware key
//! would give out.
//!
//! Byte strings travel as unpadded base64url, the encoding WebAuthn itself
//! uses in JSON, so a browser bridge passes them on as they are.

use serde::{Deserialize, Serialize};

/// A passkey that fits a sign-in: the site may be offered it.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct PasskeyOffer {
    /// The item the passkey lies in.
    pub entry_id: String,
    pub entry_name: String,
    /// The identifier as the vault stores it (a GUID, or `b64.` plus
    /// base64url) — the one a passkey is deleted by.
    pub credential_id: String,
    pub rp_id: String,
    pub user_name: Option<String>,
    pub user_display_name: Option<String>,
    pub discoverable: bool,
}

/// What a site asks for at a sign-in, after the client has done its part:
/// the client data is already hashed.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct AssertionRequest {
    pub rp_id: String,
    #[serde(with = "b64url")]
    pub client_data_hash: Vec<u8>,
    /// The raw identifiers the site allows. Empty means "any passkey of this
    /// site", and then only a discoverable one fits.
    #[serde(default, with = "b64url_list")]
    pub allow_credentials: Vec<Vec<u8>>,
}

/// A signed sign-in.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct Assertion {
    #[serde(with = "b64url")]
    pub credential_id: Vec<u8>,
    #[serde(with = "b64url")]
    pub authenticator_data: Vec<u8>,
    /// ECDSA over `authenticator_data || client_data_hash`, DER.
    #[serde(with = "b64url")]
    pub signature: Vec<u8>,
    /// The user's identifier at the site. Absent only for a passkey imported
    /// without one.
    #[serde(default, with = "b64url_opt")]
    pub user_handle: Option<Vec<u8>>,
}

/// What a site asks for when it registers a new passkey.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct CreationRequest {
    pub rp_id: String,
    pub rp_name: Option<String>,
    #[serde(with = "b64url")]
    pub user_id: Vec<u8>,
    pub user_name: Option<String>,
    pub user_display_name: Option<String>,
    #[serde(with = "b64url")]
    pub client_data_hash: Vec<u8>,
    /// The COSE algorithms the site accepts, in its order of preference.
    /// Only ES256 (-7) is made; a site that does not take it gets a refusal.
    #[serde(default)]
    pub algorithms: Vec<i64>,
    /// Raw identifiers the site already knows for this user: if one of them is
    /// here, a second passkey is not made.
    #[serde(default, with = "b64url_list")]
    pub exclude_credentials: Vec<Vec<u8>>,
    /// The site wants a discoverable passkey. keyward makes only those, and
    /// the flag is recorded as asked.
    #[serde(default = "yes")]
    pub discoverable: bool,
}

fn yes() -> bool {
    true
}

/// Where a new passkey goes.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(tag = "kind", rename_all = "snake_case")]
pub enum PasskeyTarget {
    /// Into an existing login. A passkey of the same site and user already
    /// there is replaced, as Bitwarden's clients do: a login holds one.
    Existing { entry_id: String },
    /// Into a new login with this name and address.
    New { name: String, uri: Option<String> },
}

/// A sign-in as it comes to the daemon from a browser: the raw parts of
/// `navigator.credentials.get`, plus the origin the bridge saw. The daemon
/// checks the origin against the site, builds the client data itself and
/// hashes it — a page does not get to write what is signed.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct SignIn {
    pub origin: String,
    /// Absent means the origin's host, as WebAuthn says.
    #[serde(default)]
    pub rp_id: Option<String>,
    #[serde(with = "b64url")]
    pub challenge: Vec<u8>,
    #[serde(default, with = "b64url_list")]
    pub allow_credentials: Vec<Vec<u8>>,
}

/// A sign-in with the passkey the person picked.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct SignInWith {
    #[serde(flatten)]
    pub sign_in: SignIn,
    pub entry_id: String,
    /// As in [`PasskeyOffer::credential_id`].
    pub credential_id: String,
}

/// A registration as it comes from a browser: `navigator.credentials.create`.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct Register {
    pub origin: String,
    #[serde(default)]
    pub rp_id: Option<String>,
    #[serde(default)]
    pub rp_name: Option<String>,
    #[serde(with = "b64url")]
    pub user_id: Vec<u8>,
    #[serde(default)]
    pub user_name: Option<String>,
    #[serde(default)]
    pub user_display_name: Option<String>,
    #[serde(with = "b64url")]
    pub challenge: Vec<u8>,
    #[serde(default)]
    pub algorithms: Vec<i64>,
    #[serde(default, with = "b64url_list")]
    pub exclude_credentials: Vec<Vec<u8>>,
    #[serde(default = "yes")]
    pub discoverable: bool,
    pub target: PasskeyTarget,
}

/// A finished sign-in: the assertion plus the client data it was made over,
/// which the page hands to the site as `clientDataJSON`.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct SignedIn {
    pub assertion: Assertion,
    #[serde(with = "b64url")]
    pub client_data_json: Vec<u8>,
}

/// A finished registration.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct Registered {
    pub attestation: Attestation,
    #[serde(with = "b64url")]
    pub client_data_json: Vec<u8>,
}

/// A login a new passkey may go into: one whose address is on the site.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct PasskeyHome {
    pub entry_id: String,
    pub entry_name: String,
    pub user_name: Option<String>,
    /// It already holds a passkey for this site: saving replaces it for the
    /// same user.
    pub has_passkey: bool,
}

/// The ES256 COSE identifier.
pub const ES256: i64 = -7;

/// A registered passkey, the way the site receives it.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct Attestation {
    #[serde(with = "b64url")]
    pub credential_id: Vec<u8>,
    /// CBOR `{fmt: "none", attStmt: {}, authData}`.
    #[serde(with = "b64url")]
    pub attestation_object: Vec<u8>,
    #[serde(with = "b64url")]
    pub authenticator_data: Vec<u8>,
    /// SubjectPublicKeyInfo, DER: `getPublicKey()` in the browser.
    #[serde(with = "b64url")]
    pub public_key: Vec<u8>,
    pub algorithm: i64,
    /// The item the passkey went into.
    pub entry_id: Option<String>,
}

const ALPHABET: &[u8; 64] = b"ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789-_";

/// Unpadded base64url.
pub fn encode(bytes: &[u8]) -> String {
    let mut out = String::with_capacity(bytes.len().div_ceil(3) * 4);
    encode_with(bytes, &mut |c| out.push(c as char));
    out
}

/// Unpadded base64url, a character at a time: a secret is encoded straight
/// into a buffer of the caller's (locked memory), with no string in between
/// to be copied and left behind.
pub fn encode_with(bytes: &[u8], push: &mut dyn FnMut(u8)) {
    for chunk in bytes.chunks(3) {
        let n = chunk.iter().enumerate().fold(0u32, |n, (i, b)| n | u32::from(*b) << (16 - 8 * i));
        for i in 0..=chunk.len() {
            push(ALPHABET[(n >> (18 - 6 * i) & 63) as usize]);
        }
    }
}

/// Base64, url-safe or standard, padded or not: passkeys imported from other
/// managers come in either, and the vault keeps whatever arrived.
pub fn decode(text: &str) -> Option<Vec<u8>> {
    let mut out = Vec::with_capacity(text.len() * 3 / 4);
    decode_with(text.as_bytes(), &mut |b| out.push(b)).then_some(out)
}

/// [`decode`] a byte at a time, for the same reason as [`encode_with`]. On a
/// character that is not base64 it stops and says so; what was pushed by
/// then is the caller's to wipe.
pub fn decode_with(text: &[u8], push: &mut dyn FnMut(u8)) -> bool {
    let end = text.iter().rposition(|c| *c != b'=').map_or(0, |i| i + 1);
    let (mut acc, mut bits) = (0u32, 0u32);
    for &c in &text[..end] {
        let v = match c {
            b'A'..=b'Z' => c - b'A',
            b'a'..=b'z' => c - b'a' + 26,
            b'0'..=b'9' => c - b'0' + 52,
            b'-' | b'+' => 62,
            b'_' | b'/' => 63,
            _ => return false,
        };
        acc = acc << 6 | u32::from(v);
        bits += 6;
        if bits >= 8 {
            bits -= 8;
            push((acc >> bits) as u8);
            acc &= (1 << bits) - 1;
        }
    }
    true
}

mod b64url {
    use serde::{Deserialize as _, Deserializer, Serializer};

    pub fn serialize<S: Serializer>(v: &[u8], s: S) -> Result<S::Ok, S::Error> {
        s.serialize_str(&super::encode(v))
    }

    pub fn deserialize<'de, D: Deserializer<'de>>(d: D) -> Result<Vec<u8>, D::Error> {
        let text = String::deserialize(d)?;
        super::decode(&text).ok_or_else(|| serde::de::Error::custom("not base64url"))
    }
}

mod b64url_opt {
    use serde::{Deserialize as _, Deserializer, Serializer};

    pub fn serialize<S: Serializer>(v: &Option<Vec<u8>>, s: S) -> Result<S::Ok, S::Error> {
        match v {
            Some(v) => s.serialize_some(&super::encode(v)),
            None => s.serialize_none(),
        }
    }

    pub fn deserialize<'de, D: Deserializer<'de>>(d: D) -> Result<Option<Vec<u8>>, D::Error> {
        Option::<String>::deserialize(d)?
            .map(|t| super::decode(&t).ok_or_else(|| serde::de::Error::custom("not base64url")))
            .transpose()
    }
}

mod b64url_list {
    use serde::{Deserialize as _, Deserializer, Serializer};

    pub fn serialize<S: Serializer>(v: &[Vec<u8>], s: S) -> Result<S::Ok, S::Error> {
        s.collect_seq(v.iter().map(|b| super::encode(b)))
    }

    pub fn deserialize<'de, D: Deserializer<'de>>(d: D) -> Result<Vec<Vec<u8>>, D::Error> {
        Vec::<String>::deserialize(d)?
            .iter()
            .map(|t| super::decode(t).ok_or_else(|| serde::de::Error::custom("not base64url")))
            .collect()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn base64url_goes_there_and_back() {
        for len in 0..40 {
            let bytes: Vec<u8> = (0..len).map(|i| (i * 37 + 11) as u8).collect();
            let text = encode(&bytes);
            assert!(!text.contains('='), "unpadded");
            assert_eq!(decode(&text).unwrap(), bytes);
        }
    }

    #[test]
    fn standard_padded_base64_is_read_too() {
        // "hello?>" in standard base64 with padding and a slash.
        assert_eq!(decode("aGVsbG8/Pg==").unwrap(), b"hello?>");
        assert_eq!(decode("aGVsbG8_Pg").unwrap(), b"hello?>");
        assert!(decode("not base64!").is_none());
    }

    #[test]
    fn a_request_travels_with_bytes_as_text() {
        let req = AssertionRequest {
            rp_id: "example.com".into(),
            client_data_hash: vec![1, 2, 3],
            allow_credentials: vec![vec![0xff]],
        };
        let json = serde_json::to_value(&req).unwrap();
        assert_eq!(json["client_data_hash"], "AQID");
        assert_eq!(json["allow_credentials"][0], "_w");
        assert_eq!(serde_json::from_value::<AssertionRequest>(json).unwrap(), req);
    }
}

/// What the extension asks, inside what it signs.
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(tag = "op", rename_all = "snake_case")]
pub enum BridgeAsk {
    Offers { sign_in: SignIn },
    Homes { sign_in: SignIn },
    SignIn { request: SignInWith },
    Register { request: Register },
}

/// The string the extension signs: when, and what. The time keeps a signed
/// request from being replayed later.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Signed {
    /// Milliseconds since the epoch, the extension's clock.
    pub ts: u64,
    pub ask: BridgeAsk,
}

/// A browser extension, for the list a person pairs from.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct ExtensionRow {
    /// Its public key, base64 SEC1.
    pub key: String,
    /// The five words a person compares with the extension's screen.
    pub words: Vec<String>,
    /// Seconds since the epoch: when it was paired, or last asked.
    pub at: u64,
    /// Seconds since the epoch when a pairing's words stop counting; zero
    /// for a paired key.
    #[serde(default)]
    pub expires: u64,
}
