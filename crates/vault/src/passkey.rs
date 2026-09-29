//! keyward as a WebAuthn authenticator: signing in with a vault's passkeys
//! and registering new ones.
//!
//! The format is Bitwarden's, to the letter, so that a passkey made here
//! works in the official clients and one made there works here. A login's
//! `fido2Credentials` is an array of records in which every value is an
//! encrypted string of its own — except `creationDate`:
//!
//! - `credentialId` — a GUID (`0f8e…-…`) whose sixteen bytes are the raw
//!   identifier, or `b64.` plus base64url for one imported with any other
//!   length;
//! - `keyValue` — the private key, PKCS#8 DER in base64url;
//! - `userHandle` — the site's user identifier, base64url;
//! - `keyType` `public-key`, `keyAlgorithm` `ECDSA`, `keyCurve` `P-256`,
//!   `counter` and `discoverable` as text.
//!
//! The private key never exists in the clear outside locked memory: it is
//! decrypted into an `mlock`ed buffer that is wiped on drop, decoded from
//! base64 a byte at a time into another such buffer, and lives as a
//! `SigningKey` (which wipes itself) for one signature. A new key goes the
//! same way in reverse. No string, no ordinary vector, no log line ever holds
//! it. Nothing here asks the person: presence and
//! verification are the daemon's business, and `verified` says whether it
//! was obtained.

use keyward_bw::model::{Cipher, Login};
use keyward_bw::Sync;
use keyward_core::passkey::{
    Assertion, AssertionRequest, Attestation, CreationRequest, PasskeyOffer, PasskeyTarget, ES256,
};
use p256::ecdsa::signature::Signer as _;
use p256::ecdsa::{Signature, SigningKey};
use p256::pkcs8::{DecodePrivateKey as _, EncodePrivateKey as _, EncodePublicKey as _};
use sha2::{Digest as _, Sha256};

use crate::read::Ring;

pub mod client;

/// A sign-in checked and turned into what the authenticator signs: the
/// origin may speak for the site, the challenge is sane, and the client data
/// is the daemon's own. Done before anybody is asked for a finger, so that a
/// request that could never succeed does not raise Touch ID.
pub fn prepare_sign_in(
    s: &keyward_core::passkey::SignIn,
) -> anyhow::Result<(AssertionRequest, Vec<u8>)> {
    let origin = client::origin(&s.origin)?;
    let rp_id = client::rp_id(&origin, s.rp_id.as_deref())?;
    client::check_challenge(&s.challenge)?;
    let data = client::client_data(client::Ceremony::Get, &s.challenge, &origin);
    let req = AssertionRequest {
        rp_id,
        client_data_hash: client::hash(&data),
        allow_credentials: s.allow_credentials.clone(),
    };
    Ok((req, data))
}

/// The same for a registration.
pub fn prepare_register(
    r: &keyward_core::passkey::Register,
) -> anyhow::Result<(CreationRequest, Vec<u8>)> {
    let origin = client::origin(&r.origin)?;
    let rp_id = client::rp_id(&origin, r.rp_id.as_deref())?;
    client::check_challenge(&r.challenge)?;
    client::check_user_id(&r.user_id)?;
    let data = client::client_data(client::Ceremony::Create, &r.challenge, &origin);
    let req = CreationRequest {
        rp_id,
        rp_name: r.rp_name.clone(),
        user_id: r.user_id.clone(),
        user_name: r.user_name.clone(),
        user_display_name: r.user_display_name.clone(),
        client_data_hash: client::hash(&data),
        algorithms: r.algorithms.clone(),
        exclude_credentials: r.exclude_credentials.clone(),
        discoverable: r.discoverable,
    };
    Ok((req, data))
}

/// User present.
const UP: u8 = 0x01;
/// User verified.
const UV: u8 = 0x04;
/// Backup eligible and backed up: a vault passkey is synced by nature, and a
/// site may treat it accordingly.
const BE: u8 = 0x08;
const BS: u8 = 0x10;
/// Attested credential data follows.
const AT: u8 = 0x40;

/// All zeros: with `none` attestation an authenticator is not obliged to name
/// itself, and a made-up identifier would claim a certification nobody gave.
const AAGUID: [u8; 16] = [0; 16];

/// The raw identifier behind the one the vault stores.
pub fn raw_id(stored: &str) -> Option<Vec<u8>> {
    if let Some(b64) = stored.strip_prefix("b64.") {
        return keyward_core::passkey::decode(b64);
    }
    let hex: String = stored.chars().filter(|c| *c != '-').collect();
    if hex.len() != 32 || !hex.chars().all(|c| c.is_ascii_hexdigit()) {
        return None;
    }
    (0..16).map(|i| u8::from_str_radix(&hex[2 * i..2 * i + 2], 16).ok()).collect()
}

/// The identifier the vault stores for a raw one.
pub fn stored_id(raw: &[u8]) -> String {
    if raw.len() != 16 {
        return format!("b64.{}", keyward_core::passkey::encode(raw));
    }
    let hex: String = raw.iter().map(|b| format!("{b:02x}")).collect();
    format!("{}-{}-{}-{}-{}", &hex[..8], &hex[8..12], &hex[12..16], &hex[16..20], &hex[20..])
}

/// A random version-4 GUID, the way Bitwarden's clients name a new passkey.
fn new_guid() -> [u8; 16] {
    use rand::RngCore as _;
    let mut id = [0u8; 16];
    rand::rngs::OsRng.fill_bytes(&mut id);
    id[6] = id[6] & 0x0f | 0x40;
    id[8] = id[8] & 0x3f | 0x80;
    id
}

/// `rpIdHash | flags | signCount`, plus the attested credential data when a
/// passkey is being registered.
fn authenticator_data(rp_id: &str, flags: u8, counter: u32, attested: Option<(&[u8], &[u8])>) -> Vec<u8> {
    let mut out = Sha256::digest(rp_id.as_bytes()).to_vec();
    out.push(flags | if attested.is_some() { AT } else { 0 });
    out.extend_from_slice(&counter.to_be_bytes());
    if let Some((id, cose)) = attested {
        out.extend_from_slice(&AAGUID);
        out.extend_from_slice(&(id.len() as u16).to_be_bytes());
        out.extend_from_slice(id);
        out.extend_from_slice(cose);
    }
    out
}

fn flags(verified: bool) -> u8 {
    UP | BE | BS | if verified { UV } else { 0 }
}

/// Just enough CBOR for a COSE key and an attestation object: definite
/// lengths, keys in canonical order written by hand.
mod cbor {
    fn head(out: &mut Vec<u8>, major: u8, n: u64) {
        let m = major << 5;
        match n {
            0..=23 => out.push(m | n as u8),
            24..=0xff => out.extend_from_slice(&[m | 24, n as u8]),
            0x100..=0xffff => {
                out.push(m | 25);
                out.extend_from_slice(&(n as u16).to_be_bytes());
            }
            _ => {
                out.push(m | 26);
                out.extend_from_slice(&(n as u32).to_be_bytes());
            }
        }
    }

    pub fn int(out: &mut Vec<u8>, v: i64) {
        if v >= 0 {
            head(out, 0, v as u64);
        } else {
            head(out, 1, (-1 - v) as u64);
        }
    }

    pub fn bytes(out: &mut Vec<u8>, v: &[u8]) {
        head(out, 2, v.len() as u64);
        out.extend_from_slice(v);
    }

    pub fn text(out: &mut Vec<u8>, v: &str) {
        head(out, 3, v.len() as u64);
        out.extend_from_slice(v.as_bytes());
    }

    pub fn map(out: &mut Vec<u8>, len: u64) {
        head(out, 5, len);
    }
}

/// The public key as COSE_Key: `{1: 2 (EC2), 3: -7 (ES256), -1: 1 (P-256),
/// -2: x, -3: y}`.
fn cose_key(key: &SigningKey) -> Vec<u8> {
    let point = key.verifying_key().to_encoded_point(false);
    let (x, y) = (point.x().expect("an uncompressed point"), point.y().expect("an uncompressed point"));
    let mut out = Vec::with_capacity(77);
    cbor::map(&mut out, 5);
    cbor::int(&mut out, 1);
    cbor::int(&mut out, 2);
    cbor::int(&mut out, 3);
    cbor::int(&mut out, ES256);
    cbor::int(&mut out, -1);
    cbor::int(&mut out, 1);
    cbor::int(&mut out, -2);
    cbor::bytes(&mut out, x);
    cbor::int(&mut out, -3);
    cbor::bytes(&mut out, y);
    out
}

fn attestation_object(auth_data: &[u8]) -> Vec<u8> {
    let mut out = Vec::with_capacity(auth_data.len() + 32);
    cbor::map(&mut out, 3);
    cbor::text(&mut out, "fmt");
    cbor::text(&mut out, "none");
    cbor::text(&mut out, "attStmt");
    cbor::map(&mut out, 0);
    cbor::text(&mut out, "authData");
    cbor::bytes(&mut out, auth_data);
    out
}

/// A passkey record's field, decrypted.
fn field(c: &serde_json::Value, name: &str, dec: &dyn Fn(&str) -> Option<String>) -> Option<String> {
    c.get(name).and_then(|v| v.as_str()).and_then(dec).filter(|v| !v.is_empty())
}

/// The passkeys of a login, each with its decrypted identifier and site.
fn records<'a>(
    login: &'a Login,
    dec: &'a dyn Fn(&str) -> Option<String>,
) -> impl Iterator<Item = (usize, &'a serde_json::Value, String, String)> + 'a {
    login
        .fido2_credentials
        .as_ref()
        .and_then(|v| v.as_array())
        .into_iter()
        .flatten()
        .enumerate()
        .filter_map(move |(i, c)| match (field(c, "credentialId", dec), field(c, "rpId", dec)) {
            (Some(id), Some(rp)) => Some((i, c, id, rp)),
            // A passkey that does not open is not quietly dropped from sight.
            _ => {
                tracing::warn!(index = i, "a passkey record does not decrypt and is left out");
                None
            }
        })
}

fn same_site(a: &str, b: &str) -> bool {
    a.eq_ignore_ascii_case(b)
}

/// Does a passkey fit a sign-in: the same site, and either named in the
/// site's list or, when there is no list, discoverable.
fn fits(req: &AssertionRequest, stored: &str, rp_id: &str, discoverable: bool) -> bool {
    if !same_site(rp_id, &req.rp_id) {
        return false;
    }
    if req.allow_credentials.is_empty() {
        return discoverable;
    }
    raw_id(stored).is_some_and(|raw| req.allow_credentials.contains(&raw))
}

/// Every passkey in the vault the site may be offered.
pub fn offers(snapshot: &Sync, ring: &Ring<'_>, req: &AssertionRequest) -> Vec<PasskeyOffer> {
    let mut out = Vec::new();
    for cipher in snapshot.ciphers.iter().filter(|c| !c.in_trash()) {
        let Some(login) = cipher.login.as_ref() else { continue };
        let Some(keys) = ring.base(cipher.organization_id.as_deref()) else { continue };
        let item = ring.item(cipher);
        let dec = |v: &str| crate::read::decrypt(v, keys, item.as_ref());
        for (_, c, stored, rp_id) in records(login, &dec) {
            let discoverable = field(c, "discoverable", &dec).is_some_and(|v| v == "true");
            if !fits(req, &stored, &rp_id, discoverable) {
                continue;
            }
            out.push(PasskeyOffer {
                entry_id: cipher.id.clone(),
                entry_name: dec(&cipher.name).unwrap_or_default(),
                credential_id: stored,
                rp_id,
                user_name: field(c, "userName", &dec),
                user_display_name: field(c, "userDisplayName", &dec),
                discoverable,
            });
        }
    }
    out
}

/// Does an address in a login belong to the site: its host is the `rpId` or
/// a name under it. An address saved without a scheme counts as https.
fn on_site(uri: &str, rp_id: &str) -> bool {
    let uri = uri.trim();
    let full = if uri.contains("://") { uri.to_string() } else { format!("https://{uri}") };
    let Ok(url) = reqwest::Url::parse(&full) else { return false };
    let Some(host) = url.host_str() else { return false };
    let host = host.trim_end_matches('.').to_ascii_lowercase();
    host == rp_id || host.ends_with(&format!(".{rp_id}"))
}

/// The live logins whose addresses are on the site: where a new passkey may
/// be saved.
pub fn homes(snapshot: &Sync, ring: &Ring<'_>, rp_id: &str) -> Vec<keyward_core::passkey::PasskeyHome> {
    let mut out = Vec::new();
    for cipher in snapshot.ciphers.iter().filter(|c| !c.in_trash()) {
        let Some(login) = cipher.login.as_ref() else { continue };
        let Some(keys) = ring.base(cipher.organization_id.as_deref()) else { continue };
        let item = ring.item(cipher);
        let dec = |v: &str| crate::read::decrypt(v, keys, item.as_ref());
        let fits = login.uris.iter().filter_map(|u| u.uri.as_deref()).filter_map(dec).any(|u| on_site(&u, rp_id));
        if !fits {
            continue;
        }
        out.push(keyward_core::passkey::PasskeyHome {
            entry_id: cipher.id.clone(),
            entry_name: dec(&cipher.name).unwrap_or_default(),
            user_name: login.username.as_deref().and_then(dec).filter(|u| !u.is_empty()),
            has_passkey: records(login, &dec).any(|(_, _, _, site)| same_site(&site, rp_id)),
        });
    }
    out
}

/// A sign-in with one particular passkey. When the passkey keeps a real
/// counter (imported from a hardware-bound manager), the next version of the
/// item with the counter moved on comes back too: it has to be saved before
/// the signature leaves, or the next sign-in repeats the number and the site
/// takes the key for a clone.
pub fn assert(
    cipher: &Cipher,
    ring: &Ring<'_>,
    credential_id: &str,
    req: &AssertionRequest,
    verified: bool,
) -> anyhow::Result<(Assertion, Option<Cipher>)> {
    if cipher.in_trash() {
        return Err(keyward_core::fault!("err.passkeyGone"));
    }
    let login = cipher.login.as_ref().ok_or_else(|| keyward_core::fault!("err.passkeyGone"))?;
    let keys = ring
        .base(cipher.organization_id.as_deref())
        .ok_or_else(|| keyward_core::fault!("err.noKeysForItem"))?;
    let item = ring.item(cipher);
    let dec = |v: &str| crate::read::decrypt(v, keys, item.as_ref());
    let (index, record, stored, rp_id) = records(login, &dec)
        .find(|(_, _, stored, _)| stored == credential_id)
        .ok_or_else(|| keyward_core::fault!("err.passkeyGone"))?;
    let discoverable = field(record, "discoverable", &dec).is_some_and(|v| v == "true");
    if !fits(req, &stored, &rp_id, discoverable || !req.allow_credentials.is_empty()) {
        return Err(keyward_core::fault!("err.passkeyWrongSite"));
    }

    let key = open_key(record, keys, item.as_ref())?;
    let counter: u32 = field(record, "counter", &dec).and_then(|v| v.parse().ok()).unwrap_or(0);
    // A counter of zero is a synced passkey's: it stays zero, and a sign-in
    // writes nothing to the server.
    let (counter, next) = if counter == 0 {
        (0, None)
    } else {
        let bumped = counter.saturating_add(1);
        let mut next = cipher.clone();
        let sealed = crate::read::encrypt_for(ring, cipher, &bumped.to_string())?;
        if let Some(list) = next
            .login
            .as_mut()
            .and_then(|l| l.fido2_credentials.as_mut())
            .and_then(|v| v.as_array_mut())
        {
            list[index]["counter"] = serde_json::Value::String(sealed);
        }
        (bumped, Some(next))
    };

    let auth_data = authenticator_data(&req.rp_id, flags(verified), counter, None);
    let mut signed = auth_data.clone();
    signed.extend_from_slice(&req.client_data_hash);
    let signature: Signature = key.sign(&signed);
    let assertion = Assertion {
        credential_id: raw_id(&stored).ok_or_else(|| keyward_core::fault!("err.passkeyDamaged"))?,
        authenticator_data: auth_data,
        signature: signature.to_der().as_bytes().to_vec(),
        user_handle: field(record, "userHandle", &dec).and_then(|h| keyward_core::passkey::decode(&h)),
    };
    Ok((assertion, next))
}

/// The most a locked buffer holds. A P-256 key is some 140 bytes of DER and
/// 190 of base64; anything near the limit is not a key we can use, and it is
/// refused before a byte of it is copied rather than overflowing the buffer.
const LOCKED_MAX: usize = 4096;

fn damaged() -> anyhow::Error {
    keyward_core::fault!("err.passkeyDamaged")
}

/// The passkey's private key, opened in locked memory only.
fn open_key(
    record: &serde_json::Value,
    keys: &rbw::locked::Keys,
    item: Option<&rbw::locked::Keys>,
) -> anyhow::Result<SigningKey> {
    let sealed = record.get("keyValue").and_then(|v| v.as_str()).ok_or_else(damaged)?;
    // No mac, no decryption: see `read::authenticated`.
    if !crate::read::authenticated(sealed) {
        return Err(damaged());
    }
    let cipher = rbw::cipherstring::CipherString::new(sealed).map_err(|_| damaged())?;
    let rbw::cipherstring::CipherString::Symmetric { ciphertext, .. } = &cipher else {
        return Err(damaged());
    };
    if ciphertext.len() > LOCKED_MAX {
        return Err(keyward_core::fault!("err.passkeyUnsupportedKey"));
    }
    let mut text = cipher.decrypt_locked_symmetric(item.unwrap_or(keys)).map_err(|_| damaged())?;
    // The buffer keeps the PKCS#7 padding: rbw has already checked it, and it
    // is cut off here.
    let len = text.data().len();
    let pad = usize::from(*text.data().last().ok_or_else(damaged)?);
    if pad == 0 || pad > 16 || pad > len {
        return Err(damaged());
    }
    text.truncate(len - pad);

    let mut der = rbw::locked::Vec::new();
    if !keyward_core::passkey::decode_with(text.data(), &mut |b| der.extend(std::iter::once(b))) {
        return Err(damaged());
    }
    drop(text);
    SigningKey::from_pkcs8_der(der.data()).map_err(|_| keyward_core::fault!("err.passkeyUnsupportedKey"))
}

/// A new key's PKCS#8 as base64url, in locked memory, ready to be sealed.
fn encoded_key(key: &SigningKey) -> anyhow::Result<rbw::locked::Vec> {
    // `SecretDocument` wipes itself when dropped, at the end of this function.
    let der = key.to_pkcs8_der().map_err(|_| keyward_core::fault!("err.passkeyUnsupportedKey"))?;
    if der.as_bytes().len().div_ceil(3) * 4 > LOCKED_MAX {
        return Err(keyward_core::fault!("err.passkeyUnsupportedKey"));
    }
    let mut out = rbw::locked::Vec::new();
    keyward_core::passkey::encode_with(der.as_bytes(), &mut |c| out.extend(std::iter::once(c)));
    Ok(out)
}

/// A new passkey: the sealed record for the vault and what the site gets.
pub fn make(
    req: &CreationRequest,
    verified: bool,
    seal: &dyn Fn(&[u8]) -> anyhow::Result<String>,
    now: &str,
) -> anyhow::Result<(serde_json::Value, Attestation)> {
    if !req.algorithms.is_empty() && !req.algorithms.contains(&ES256) {
        return Err(keyward_core::fault!("err.passkeyAlgorithm"));
    }
    let key = SigningKey::random(&mut rand::rngs::OsRng);
    let raw = new_guid();
    let encoded = encoded_key(&key)?;

    let mut record = serde_json::Map::new();
    record.insert("keyValue".into(), serde_json::Value::String(seal(encoded.data())?));
    drop(encoded);
    let mut put = |name: &str, value: &str| -> anyhow::Result<()> {
        record.insert(name.to_string(), serde_json::Value::String(seal(value.as_bytes())?));
        Ok(())
    };
    put("credentialId", &stored_id(&raw))?;
    put("keyType", "public-key")?;
    put("keyAlgorithm", "ECDSA")?;
    put("keyCurve", "P-256")?;
    put("rpId", &req.rp_id)?;
    put("userHandle", &keyward_core::passkey::encode(&req.user_id))?;
    put("counter", "0")?;
    put("discoverable", if req.discoverable { "true" } else { "false" })?;
    for (name, value) in [
        ("rpName", &req.rp_name),
        ("userName", &req.user_name),
        ("userDisplayName", &req.user_display_name),
    ] {
        if let Some(v) = value.as_deref().filter(|v| !v.is_empty()) {
            put(name, v)?;
        }
    }
    record.insert("creationDate".into(), serde_json::Value::String(now.to_string()));

    let auth_data = authenticator_data(&req.rp_id, flags(verified), 0, Some((&raw, &cose_key(&key))));
    let public_key = key
        .verifying_key()
        .to_public_key_der()
        .map_err(|e| keyward_core::fault!("err.encryptValue", "reason" => e))?;
    let attestation = Attestation {
        credential_id: raw.to_vec(),
        attestation_object: attestation_object(&auth_data),
        authenticator_data: auth_data,
        public_key: public_key.as_bytes().to_vec(),
        algorithm: ES256,
        entry_id: None,
    };
    Ok((serde_json::Value::Object(record), attestation))
}

/// Refuses a registration when the site already knows one of the vault's
/// passkeys for this user: WebAuthn's `excludeCredentials`.
pub fn check_excluded(snapshot: &Sync, ring: &Ring<'_>, req: &CreationRequest) -> anyhow::Result<()> {
    if req.exclude_credentials.is_empty() {
        return Ok(());
    }
    let probe = AssertionRequest {
        rp_id: req.rp_id.clone(),
        client_data_hash: Vec::new(),
        allow_credentials: req.exclude_credentials.clone(),
    };
    if offers(snapshot, ring, &probe).is_empty() {
        Ok(())
    } else {
        Err(keyward_core::fault!("err.passkeyExists"))
    }
}

/// An existing login with the new passkey in it. A passkey of the same site
/// and the same user is replaced: registering again means the old one is
/// dead on the site's side anyway.
pub fn put_into(
    previous: &Cipher,
    ring: &Ring<'_>,
    record: serde_json::Value,
    req: &CreationRequest,
) -> anyhow::Result<Cipher> {
    if previous.in_trash() {
        return Err(keyward_core::fault!("err.itemNotFound"));
    }
    let Some(login) = previous.login.as_ref() else {
        return Err(keyward_core::fault!("err.passkeyNeedsLogin"));
    };
    let keys = ring
        .base(previous.organization_id.as_deref())
        .ok_or_else(|| keyward_core::fault!("err.noKeysForItem"))?;
    let item = ring.item(previous);
    let dec = |v: &str| crate::read::decrypt(v, keys, item.as_ref());
    let replaced: Vec<usize> = records(login, &dec)
        .filter(|(_, c, _, rp_id)| {
            same_site(rp_id, &req.rp_id)
                && field(c, "userHandle", &dec)
                    .and_then(|h| keyward_core::passkey::decode(&h))
                    .is_some_and(|h| h == req.user_id)
        })
        .map(|(i, ..)| i)
        .collect();
    let username_missing = login.username.as_deref().and_then(&dec).is_none_or(|u| u.is_empty());

    let mut next = previous.clone();
    let login = next.login.as_mut().expect("checked above");
    let mut list = match login.fido2_credentials.take() {
        Some(serde_json::Value::Array(list)) => list,
        _ => Vec::new(),
    };
    let mut i = 0;
    list.retain(|_| {
        let keep = !replaced.contains(&i);
        i += 1;
        keep
    });
    list.push(record);
    login.fido2_credentials = Some(serde_json::Value::Array(list));
    // Bitwarden's clients fill in an empty login from the passkey: the item
    // then reads as whose it is.
    if username_missing {
        if let Some(name) = req.user_name.as_deref().filter(|n| !n.is_empty()) {
            login.username = Some(crate::read::encrypt_for(ring, previous, name)?);
        }
    }
    Ok(next)
}

/// How many passkeys' last use is remembered; beyond it the longest unused
/// fall out.
const USES_KEEP: usize = 1024;

/// The file of last uses: a single sealed blob, so the disk shows neither
/// which passkeys there are nor how many.
#[derive(Default, serde::Serialize, serde::Deserialize)]
struct StoredUses {
    #[serde(default)]
    sealed: Option<String>,
}

/// Last uses, by the stored credential id, in Unix seconds.
type Uses = std::collections::HashMap<String, i64>;

/// Opens the file of last uses. Damage — a file that does not parse or a
/// seal that does not open — is an error, never an empty journal: an empty
/// one would be written back over it and the damage would become a loss.
fn open_uses(ring: &Ring<'_>, text: &str) -> anyhow::Result<Uses> {
    let damaged = || keyward_core::fault!("err.passkeyUsesDamaged");
    let stored: StoredUses = serde_json::from_str(text).map_err(|_| damaged())?;
    let Some(sealed) = stored.sealed.as_deref() else { return Ok(Uses::new()) };
    let plain = zeroize::Zeroizing::new(crate::read::decrypt_blob(ring, sealed).ok_or_else(damaged)?);
    serde_json::from_str(&plain).map_err(|_| damaged())
}

fn seal_uses(ring: &Ring<'_>, uses: &Uses) -> anyhow::Result<String> {
    let plain = zeroize::Zeroizing::new(serde_json::to_string(uses)?);
    let sealed = crate::read::encrypt_blob(ring, &plain)?;
    Ok(serde_json::to_string(&StoredUses { sealed: Some(sealed) })?)
}

/// Remembers a use, dropping the longest unused beyond the limit.
fn noted(mut uses: Uses, credential_id: &str, at: i64) -> Uses {
    uses.insert(credential_id.to_string(), at);
    while uses.len() > USES_KEEP {
        let Some(oldest) = uses.iter().min_by_key(|(_, t)| **t).map(|(k, _)| k.clone()) else { break };
        uses.remove(&oldest);
    }
    uses
}

impl crate::Vault {
    /// When each passkey was last used here, by its stored credential id. No
    /// file yet is an empty journal; a file that cannot be read is an error.
    pub(crate) fn passkey_uses(&self) -> anyhow::Result<Uses> {
        let ring = self.ring().ok_or_else(|| keyward_core::fault!("err.vaultLocked"))?;
        let path = keyward_core::paths::passkey_uses_file(&self.account.id);
        match std::fs::read_to_string(path) {
            Ok(text) => open_uses(&ring, &text),
            Err(e) if e.kind() == std::io::ErrorKind::NotFound => Ok(Uses::new()),
            Err(e) => Err(keyward_core::fault!("err.passkeyUsesDamaged", "reason" => e)),
        }
    }

    fn note_passkey_use(&self, credential_id: &str) -> anyhow::Result<()> {
        let ring = self.ring().ok_or_else(|| keyward_core::fault!("err.vaultLocked"))?;
        let now = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .map(|d| d.as_secs() as i64)
            .unwrap_or(0);
        // A journal that cannot be read is not written over.
        let uses = noted(self.passkey_uses()?, credential_id, now);
        let path = keyward_core::paths::passkey_uses_file(&self.account.id);
        Ok(keyward_core::paths::write_private(&path, seal_uses(&ring, &uses)?.as_bytes())?)
    }

    /// The vault's passkeys that fit a sign-in.
    pub fn passkey_offers(&self, req: &AssertionRequest) -> Vec<PasskeyOffer> {
        let Some(ring) = self.ring() else { return Vec::new() };
        offers(&self.snapshot(), &ring, req)
    }

    /// The site's logins a new passkey may go into.
    pub fn passkey_homes(&self, rp_id: &str) -> Vec<keyward_core::passkey::PasskeyHome> {
        let Some(ring) = self.ring() else { return Vec::new() };
        homes(&self.snapshot(), &ring, rp_id)
    }

    /// Everything about a registration that can be refused without the
    /// sensor: a passkey the site already knows, a target that is not a live
    /// login.
    pub fn passkey_check(&self, req: &CreationRequest, target: &PasskeyTarget) -> anyhow::Result<()> {
        let snapshot = self.snapshot();
        let ring = self.ring().ok_or_else(|| keyward_core::fault!("err.vaultLocked"))?;
        check_excluded(&snapshot, &ring, req)?;
        match target {
            PasskeyTarget::Existing { entry_id } => {
                let cipher = snapshot
                    .ciphers
                    .iter()
                    .find(|c| &c.id == entry_id && !c.in_trash())
                    .ok_or_else(|| keyward_core::fault!("err.itemNotFoundSync"))?;
                if cipher.login.is_none() {
                    return Err(keyward_core::fault!("err.passkeyNeedsLogin"));
                }
            }
            PasskeyTarget::New { name, .. } => {
                if name.trim().is_empty() {
                    return Err(keyward_core::fault!("err.itemNeedsName"));
                }
            }
        }
        Ok(())
    }

    /// Signs a sign-in with a passkey. The caller has already asked the
    /// person; `verified` says whether that was Touch ID.
    pub async fn passkey_assert(
        &self,
        entry_id: &str,
        credential_id: &str,
        req: &AssertionRequest,
        verified: bool,
    ) -> anyhow::Result<Assertion> {
        let snapshot = self.snapshot();
        let cipher = snapshot
            .ciphers
            .iter()
            .find(|c| c.id == entry_id)
            .ok_or_else(|| keyward_core::fault!("err.passkeyGone"))?;
        let ring = self.ring().ok_or_else(|| keyward_core::fault!("err.vaultLocked"))?;
        let (assertion, next) = assert(cipher, &ring, credential_id, req, verified)?;
        if let Some(next) = next {
            // Saved into the queue before the signature leaves: a counter
            // handed out must never be handed out again.
            self.queue_edit(cipher.clone(), next, &["field.passkey".to_string()]).await?;
        }
        // The sign-in is done and signed; a date in a card is not worth
        // failing it over. The failure is loud all the same, and a damaged
        // journal is left as it is rather than overwritten.
        if let Err(e) = self.note_passkey_use(credential_id) {
            tracing::error!(error = %e, "the passkey's last use was not remembered");
        }
        Ok(assertion)
    }

    /// Registers a new passkey in the vault.
    pub async fn passkey_create(
        &self,
        req: &CreationRequest,
        target: &PasskeyTarget,
        verified: bool,
    ) -> anyhow::Result<Attestation> {
        let snapshot = self.snapshot();
        let ring = self.ring().ok_or_else(|| keyward_core::fault!("err.vaultLocked"))?;
        check_excluded(&snapshot, &ring, req)?;
        let now = crate::iso_now();
        match target {
            PasskeyTarget::Existing { entry_id } => {
                let previous = snapshot
                    .ciphers
                    .iter()
                    .find(|c| &c.id == entry_id)
                    .cloned()
                    .ok_or_else(|| keyward_core::fault!("err.itemNotFoundSync"))?;
                let seal = |v: &[u8]| crate::read::encrypt_bytes_for(&ring, &previous, v);
                let (record, mut attestation) = make(req, verified, &seal, &now)?;
                let next = put_into(&previous, &ring, record, req)?;
                self.queue_edit(previous, next, &["field.passkey".to_string()]).await?;
                attestation.entry_id = Some(entry_id.clone());
                Ok(attestation)
            }
            PasskeyTarget::New { name, uri } => {
                let name = name.trim();
                if name.is_empty() {
                    return Err(keyward_core::fault!("err.itemNeedsName"));
                }
                let blank = Cipher { kind: 1, ..Default::default() };
                let seal = |v: &str| crate::read::encrypt_for(&ring, &blank, v);
                let (record, mut attestation) =
                    make(req, verified, &|v| crate::read::encrypt_bytes_for(&ring, &blank, v), &now)?;
                let mut cipher = blank.clone();
                cipher.name = seal(name)?;
                cipher.login = Some(Login {
                    username: req.user_name.as_deref().filter(|n| !n.is_empty()).map(&seal).transpose()?,
                    uris: uri
                        .as_deref()
                        .map(str::trim)
                        .filter(|u| !u.is_empty())
                        .map(|u| Ok(keyward_bw::model::Uri { uri: Some(seal(u)?), match_type: None }))
                        .into_iter()
                        .collect::<anyhow::Result<Vec<_>>>()?,
                    fido2_credentials: Some(serde_json::Value::Array(vec![record])),
                    ..Default::default()
                });
                self.post_new_cipher(&cipher).await?;
                // The server names the item; after the sync it is found by
                // the passkey it carries.
                let stored = stored_id(&attestation.credential_id);
                let probe = AssertionRequest {
                    rp_id: req.rp_id.clone(),
                    client_data_hash: Vec::new(),
                    allow_credentials: vec![attestation.credential_id.clone()],
                };
                attestation.entry_id = self
                    .passkey_offers(&probe)
                    .into_iter()
                    .find(|o| o.credential_id == stored)
                    .map(|o| o.entry_id);
                Ok(attestation)
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use p256::ecdsa::signature::Verifier as _;
    use p256::ecdsa::VerifyingKey;
    use p256::pkcs8::DecodePublicKey as _;

    fn user_keys() -> rbw::locked::Keys {
        let mut raw = rbw::locked::Vec::new();
        raw.extend(std::iter::repeat_n(7u8, 64));
        rbw::locked::Keys::new(raw)
    }

    fn creation(rp_id: &str, user: &[u8]) -> CreationRequest {
        CreationRequest {
            rp_id: rp_id.into(),
            rp_name: Some("Example".into()),
            user_id: user.to_vec(),
            user_name: Some("me@example.com".into()),
            user_display_name: Some("Me".into()),
            client_data_hash: vec![9; 32],
            algorithms: vec![ES256, -257],
            exclude_credentials: Vec::new(),
            discoverable: true,
        }
    }

    fn sign_in(rp_id: &str) -> AssertionRequest {
        AssertionRequest { rp_id: rp_id.into(), client_data_hash: vec![5; 32], allow_credentials: Vec::new() }
    }

    /// A snapshot with one login holding the given passkey records.
    fn with_login(user: &rbw::locked::Keys, records: Vec<serde_json::Value>) -> Sync {
        let enc = |s: &str| {
            rbw::cipherstring::CipherString::encrypt_symmetric(user, s.as_bytes()).unwrap().to_string()
        };
        serde_json::from_value(serde_json::json!({
            "ciphers": [{"id": "e1", "type": 1, "name": enc("Example"),
                         "login": {"fido2Credentials": records}}]
        }))
        .unwrap()
    }

    fn verify(public_key: &[u8], assertion: &Assertion, client_data_hash: &[u8]) {
        let key = VerifyingKey::from_public_key_der(public_key).unwrap();
        let sig = Signature::from_der(&assertion.signature).unwrap();
        let mut signed = assertion.authenticator_data.clone();
        signed.extend_from_slice(client_data_hash);
        key.verify(&signed, &sig).expect("the signature holds");
    }

    #[test]
    fn identifiers_go_there_and_back() {
        let guid = "0f8e2d6a-1b3c-4d5e-8f70-a1b2c3d4e5f6";
        let raw = raw_id(guid).unwrap();
        assert_eq!(raw.len(), 16);
        assert_eq!(raw[0], 0x0f);
        assert_eq!(stored_id(&raw), guid);

        let odd = vec![1u8, 2, 3, 250];
        let stored = stored_id(&odd);
        assert!(stored.starts_with("b64."));
        assert_eq!(raw_id(&stored).unwrap(), odd);
        assert!(raw_id("not-an-id").is_none());
    }

    #[test]
    fn a_new_guid_is_version_four() {
        let id = new_guid();
        assert_eq!(id[6] >> 4, 4);
        assert_eq!(id[8] >> 6, 0b10);
    }

    #[test]
    fn authenticator_data_is_laid_out_as_webauthn_says() {
        let data = authenticator_data("example.com", flags(true), 7, None);
        assert_eq!(data.len(), 37);
        assert_eq!(&data[..32], Sha256::digest(b"example.com").as_slice());
        assert_eq!(data[32], UP | UV | BE | BS);
        assert_eq!(&data[33..37], &[0, 0, 0, 7]);

        let data = authenticator_data("example.com", flags(false), 0, Some((&[1, 2], &[0xa0])));
        assert_eq!(data[32], UP | BE | BS | AT, "no UV without verification");
        assert_eq!(&data[37..53], &AAGUID);
        assert_eq!(&data[53..55], &[0, 2]);
        assert_eq!(&data[55..], &[1, 2, 0xa0]);
    }

    #[test]
    fn the_cose_key_is_canonical_cbor() {
        let key = SigningKey::random(&mut rand::rngs::OsRng);
        let cose = cose_key(&key);
        assert_eq!(cose.len(), 77);
        // map(5), 1: 2, 3: -7, -1: 1, -2: bytes(32)
        assert_eq!(&cose[..9], &[0xa5, 0x01, 0x02, 0x03, 0x26, 0x20, 0x01, 0x21, 0x58]);
        assert_eq!(cose[9], 32);
        assert_eq!(&cose[42..45], &[0x22, 0x58, 32]);
    }

    #[test]
    fn a_site_that_takes_no_es256_is_refused() {
        let mut req = creation("example.com", b"u");
        req.algorithms = vec![-257];
        let err = make(&req, true, &|v| Ok(String::from_utf8_lossy(v).into_owned()), "now").unwrap_err();
        assert!(err.to_string().contains("err.passkeyAlgorithm"));
        req.algorithms.clear();
        assert!(make(&req, true, &|v| Ok(String::from_utf8_lossy(v).into_owned()), "now").is_ok(), "no list means the defaults");
    }

    #[test]
    fn a_made_passkey_is_in_bitwardens_shape() {
        let (record, attestation) =
            make(&creation("example.com", b"user-1"), true, &|v| Ok(format!("enc:{}", String::from_utf8_lossy(v))), "2026-09-29T00:00:00.000Z").unwrap();
        let get = |k: &str| record[k].as_str().unwrap().to_string();
        assert_eq!(get("keyType"), "enc:public-key");
        assert_eq!(get("keyAlgorithm"), "enc:ECDSA");
        assert_eq!(get("keyCurve"), "enc:P-256");
        assert_eq!(get("rpId"), "enc:example.com");
        assert_eq!(get("counter"), "enc:0");
        assert_eq!(get("discoverable"), "enc:true");
        assert_eq!(get("userHandle"), format!("enc:{}", keyward_core::passkey::encode(b"user-1")));
        assert_eq!(get("creationDate"), "2026-09-29T00:00:00.000Z", "the date alone is in the clear");
        assert_eq!(get("credentialId"), format!("enc:{}", stored_id(&attestation.credential_id)));
        assert!(get("keyValue").starts_with("enc:"));
        assert_eq!(attestation.algorithm, ES256);
        assert_eq!(attestation.attestation_object[..5], [0xa3, 0x63, b'f', b'm', b't']);
    }

    #[test]
    fn a_made_passkey_signs_in_with_real_encryption() {
        let user = user_keys();
        let orgs = std::collections::HashMap::new();
        let ring = Ring { user: &user, orgs: &orgs };
        let blank = Cipher::default();
        let seal = |v: &[u8]| crate::read::encrypt_bytes_for(&ring, &blank, v);
        let (record, attestation) = make(&creation("example.com", b"user-1"), true, &seal, "now").unwrap();

        let snapshot = with_login(&user, vec![record]);
        let req = sign_in("Example.COM");
        let found = offers(&snapshot, &ring, &req);
        assert_eq!(found.len(), 1, "the site is compared without case");
        assert_eq!(found[0].entry_name, "Example");
        assert_eq!(found[0].user_name.as_deref(), Some("me@example.com"));

        let (assertion, next) = assert(&snapshot.ciphers[0], &ring, &found[0].credential_id, &req, true).unwrap();
        assert!(next.is_none(), "a synced passkey's counter stays zero and writes nothing");
        assert_eq!(assertion.credential_id, attestation.credential_id);
        assert_eq!(assertion.user_handle.as_deref(), Some(&b"user-1"[..]));
        assert_eq!(&assertion.authenticator_data[33..37], &[0, 0, 0, 0]);
        verify(&attestation.public_key, &assertion, &req.client_data_hash);

        // The existing reader sees it as before.
        let shown = crate::read::passkeys(snapshot.ciphers[0].login.as_ref().unwrap(), &|v| {
            crate::read::decrypt_for(&ring, &snapshot.ciphers[0], v)
        });
        assert_eq!(shown[0].rp_id, "example.com");
        assert_eq!(shown[0].key_curve.as_deref(), Some("P-256"));
    }

    #[test]
    fn another_sites_passkey_is_neither_offered_nor_signed_with() {
        let user = user_keys();
        let orgs = std::collections::HashMap::new();
        let ring = Ring { user: &user, orgs: &orgs };
        let blank = Cipher::default();
        let seal = |v: &[u8]| crate::read::encrypt_bytes_for(&ring, &blank, v);
        let (record, _) = make(&creation("example.com", b"u"), true, &seal, "now").unwrap();
        let snapshot = with_login(&user, vec![record]);

        let evil = sign_in("evil.example");
        assert!(offers(&snapshot, &ring, &evil).is_empty());
        let id = offers(&snapshot, &ring, &sign_in("example.com"))[0].credential_id.clone();
        let err = assert(&snapshot.ciphers[0], &ring, &id, &evil, true).unwrap_err();
        assert!(err.to_string().contains("err.passkeyWrongSite"));
    }

    #[test]
    fn an_allow_list_narrows_and_a_non_discoverable_needs_one() {
        let user = user_keys();
        let orgs = std::collections::HashMap::new();
        let ring = Ring { user: &user, orgs: &orgs };
        let blank = Cipher::default();
        let seal = |v: &[u8]| crate::read::encrypt_bytes_for(&ring, &blank, v);
        let mut req = creation("example.com", b"u");
        req.discoverable = false;
        let (record, attestation) = make(&req, true, &seal, "now").unwrap();
        let snapshot = with_login(&user, vec![record]);

        assert!(offers(&snapshot, &ring, &sign_in("example.com")).is_empty(), "no list, not discoverable");
        let mut named = sign_in("example.com");
        named.allow_credentials = vec![attestation.credential_id.clone()];
        assert_eq!(offers(&snapshot, &ring, &named).len(), 1);
        named.allow_credentials = vec![vec![0; 16]];
        assert!(offers(&snapshot, &ring, &named).is_empty(), "somebody else's identifier");
    }

    #[test]
    fn a_real_counter_moves_on_and_is_sealed_again() {
        let user = user_keys();
        let orgs = std::collections::HashMap::new();
        let ring = Ring { user: &user, orgs: &orgs };
        let blank = Cipher::default();
        let seal = |v: &[u8]| crate::read::encrypt_bytes_for(&ring, &blank, v);
        let (mut record, attestation) = make(&creation("example.com", b"u"), true, &seal, "now").unwrap();
        record["counter"] = serde_json::Value::String(seal(b"41").unwrap());
        let snapshot = with_login(&user, vec![record]);
        let req = sign_in("example.com");
        let id = stored_id(&attestation.credential_id);

        let (assertion, next) = assert(&snapshot.ciphers[0], &ring, &id, &req, false).unwrap();
        assert_eq!(&assertion.authenticator_data[33..37], &[0, 0, 0, 42]);
        assert_eq!(assertion.authenticator_data[32] & UV, 0);
        verify(&attestation.public_key, &assertion, &req.client_data_hash);
        let next = next.expect("the counter is saved");
        let sealed = next.login.unwrap().fido2_credentials.unwrap()[0]["counter"].as_str().unwrap().to_string();
        assert_eq!(crate::read::decrypt_for(&ring, &Cipher::default(), &sealed).as_deref(), Some("42"));
    }

    #[test]
    fn a_passkey_the_site_already_knows_is_not_made_twice() {
        let user = user_keys();
        let orgs = std::collections::HashMap::new();
        let ring = Ring { user: &user, orgs: &orgs };
        let blank = Cipher::default();
        let seal = |v: &[u8]| crate::read::encrypt_bytes_for(&ring, &blank, v);
        let (record, attestation) = make(&creation("example.com", b"u"), true, &seal, "now").unwrap();
        let snapshot = with_login(&user, vec![record]);

        let mut again = creation("example.com", b"u");
        again.exclude_credentials = vec![attestation.credential_id];
        let err = check_excluded(&snapshot, &ring, &again).unwrap_err();
        assert!(err.to_string().contains("err.passkeyExists"));
        again.exclude_credentials = vec![vec![0; 16]];
        assert!(check_excluded(&snapshot, &ring, &again).is_ok());
    }

    #[test]
    fn registering_again_replaces_only_the_same_users_passkey() {
        let user = user_keys();
        let orgs = std::collections::HashMap::new();
        let ring = Ring { user: &user, orgs: &orgs };
        let blank = Cipher::default();
        let seal = |v: &[u8]| crate::read::encrypt_bytes_for(&ring, &blank, v);
        let (old, _) = make(&creation("example.com", b"u"), true, &seal, "now").unwrap();
        let (other_site, _) = make(&creation("other.example", b"u"), true, &seal, "now").unwrap();
        let snapshot = with_login(&user, vec![old, other_site]);

        let req = creation("example.com", b"u");
        let (fresh, attestation) = make(&req, true, &seal, "now").unwrap();
        let next = put_into(&snapshot.ciphers[0], &ring, fresh, &req).unwrap();
        let login = next.login.as_ref().unwrap();
        let shown = crate::read::passkeys(login, &|v| crate::read::decrypt_for(&ring, &next, v));
        let sites: Vec<&str> = shown.iter().map(|p| p.rp_id.as_str()).collect();
        assert_eq!(sites, ["other.example", "example.com"]);
        assert_eq!(shown[1].credential_id, stored_id(&attestation.credential_id));
        let name = login.username.as_deref().and_then(|u| crate::read::decrypt_for(&ring, &next, u));
        assert_eq!(name.as_deref(), Some("me@example.com"), "an empty login takes the passkey's user");
    }

    #[test]
    fn a_key_without_a_mac_or_too_long_is_never_opened() {
        let user = user_keys();
        let orgs = std::collections::HashMap::new();
        let ring = Ring { user: &user, orgs: &orgs };
        let blank = Cipher::default();
        let seal = |v: &[u8]| crate::read::encrypt_bytes_for(&ring, &blank, v);
        let (mut record, attestation) = make(&creation("example.com", b"u"), true, &seal, "now").unwrap();
        let id = stored_id(&attestation.credential_id);
        let req = sign_in("example.com");

        // The mac cut off: a padding oracle's way in, refused before
        // decryption.
        let sealed = record["keyValue"].as_str().unwrap().to_string();
        let stripped = sealed.rsplit_once('|').unwrap().0.to_string();
        record["keyValue"] = serde_json::Value::String(stripped);
        let snapshot = with_login(&user, vec![record.clone()]);
        let err = assert(&snapshot.ciphers[0], &ring, &id, &req, true).unwrap_err();
        assert!(err.to_string().contains("err.passkeyDamaged"));

        // Longer than locked memory holds: refused, not overflowed.
        record["keyValue"] = serde_json::Value::String(seal(&vec![b'A'; LOCKED_MAX + 1]).unwrap());
        let snapshot = with_login(&user, vec![record]);
        let err = assert(&snapshot.ciphers[0], &ring, &id, &req, true).unwrap_err();
        assert!(err.to_string().contains("err.passkeyUnsupportedKey"));
    }

    #[test]
    fn a_new_passkey_is_offered_the_sites_own_logins() {
        let user = user_keys();
        let orgs = std::collections::HashMap::new();
        let ring = Ring { user: &user, orgs: &orgs };
        let enc = |s: &str| rbw::cipherstring::CipherString::encrypt_symmetric(&user, s.as_bytes()).unwrap().to_string();
        let snapshot: Sync = serde_json::from_value(serde_json::json!({"ciphers": [
            {"id": "a", "type": 1, "name": enc("Example"), "login": {"username": enc("me"), "uris": [{"uri": enc("https://login.example.com/x")}]}},
            {"id": "b", "type": 1, "name": enc("Bare"), "login": {"uris": [{"uri": enc("example.com")}]}},
            {"id": "c", "type": 1, "name": enc("Lookalike"), "login": {"uris": [{"uri": enc("https://evil-example.com")}]}},
            {"id": "d", "type": 1, "name": enc("Gone"), "deletedDate": "2026-01-01T00:00:00Z", "login": {"uris": [{"uri": enc("https://example.com")}]}}
        ]})).unwrap();
        let found = homes(&snapshot, &ring, "example.com");
        let ids: Vec<&str> = found.iter().map(|h| h.entry_id.as_str()).collect();
        assert_eq!(ids, ["a", "b"], "the site and names under it; no lookalike, no trash");
        assert_eq!(found[0].user_name.as_deref(), Some("me"));
        assert!(!found[0].has_passkey);
    }

    /// The whole daemon-side road — origin checked, client data built, a
    /// passkey made, then a sign-in with it — written out for an independent
    /// WebAuthn server to verify (`KW_WEBAUTHN_OUT=<file> cargo test --
    /// --ignored for_an_outside_verifier`). Our own tests check our reading
    /// of the spec; this checks it against somebody else's.
    #[test]
    #[ignore]
    fn for_an_outside_verifier() {
        let out = std::env::var("KW_WEBAUTHN_OUT").expect("KW_WEBAUTHN_OUT");
        let user = user_keys();
        let orgs = std::collections::HashMap::new();
        let ring = Ring { user: &user, orgs: &orgs };
        let blank = Cipher::default();
        let seal = |v: &[u8]| crate::read::encrypt_bytes_for(&ring, &blank, v);

        let register = keyward_core::passkey::Register {
            origin: "https://login.example.com".into(),
            rp_id: Some("example.com".into()),
            rp_name: Some("Example".into()),
            user_id: b"user-1".to_vec(),
            user_name: Some("me@example.com".into()),
            user_display_name: Some("Me".into()),
            challenge: vec![0x11; 32],
            algorithms: vec![ES256],
            exclude_credentials: Vec::new(),
            discoverable: true,
            target: PasskeyTarget::New { name: "Example".into(), uri: None },
        };
        let (creation, create_data) = prepare_register(&register).unwrap();
        let (record, attestation) = make(&creation, true, &seal, "now").unwrap();
        let snapshot = with_login(&user, vec![record]);

        let sign_in = keyward_core::passkey::SignIn {
            origin: "https://login.example.com".into(),
            rp_id: Some("example.com".into()),
            challenge: vec![0x22; 32],
            allow_credentials: Vec::new(),
        };
        let (req, get_data) = prepare_sign_in(&sign_in).unwrap();
        let offer = &offers(&snapshot, &ring, &req)[0];
        let (assertion, _) = assert(&snapshot.ciphers[0], &ring, &offer.credential_id, &req, true).unwrap();

        let doc = serde_json::json!({
            "registered": keyward_core::passkey::Registered { attestation, client_data_json: create_data },
            "signed": keyward_core::passkey::SignedIn { assertion, client_data_json: get_data },
        });
        std::fs::write(out, serde_json::to_string_pretty(&doc).unwrap()).unwrap();
    }

    #[test]
    fn last_uses_are_one_sealed_blob() {
        let user = user_keys();
        let orgs = std::collections::HashMap::new();
        let ring = Ring { user: &user, orgs: &orgs };
        let uses = noted(Uses::new(), "0f8e2d6a-1b3c-4d5e-8f70-a1b2c3d4e5f6", 1_790_000_000);
        let text = seal_uses(&ring, &uses).unwrap();
        assert!(!text.contains("0f8e2d6a"), "no credential id in the clear");
        assert!(!text.contains("1790000000"), "no time in the clear");
        let doc: serde_json::Value = serde_json::from_str(&text).unwrap();
        assert!(doc["sealed"].as_str().unwrap().starts_with("2."));
        assert_eq!(open_uses(&ring, &text).unwrap(), uses);
        assert!(open_uses(&ring, r#"{"sealed":null}"#).unwrap().is_empty(), "no journal yet");
        // Damage is an error, never an empty journal to be written back.
        for bad in ["not json", r#"{"sealed":"2.bad"}"#] {
            let err = open_uses(&ring, bad).unwrap_err();
            assert!(err.to_string().contains("err.passkeyUsesDamaged"), "{bad}");
        }
    }

    #[test]
    fn the_longest_unused_fall_out_first() {
        let mut uses = Uses::new();
        for i in 0..USES_KEEP as i64 {
            uses = noted(uses, &format!("id-{i}"), 1_000 + i);
        }
        let uses = noted(uses, "fresh", 99_999);
        assert_eq!(uses.len(), USES_KEEP);
        assert!(!uses.contains_key("id-0"), "the oldest went");
        assert!(uses.contains_key("id-1") && uses.contains_key("fresh"));
    }

    #[test]
    fn a_passkey_is_not_put_into_something_that_is_not_a_login() {
        let user = user_keys();
        let orgs = std::collections::HashMap::new();
        let ring = Ring { user: &user, orgs: &orgs };
        let note = Cipher { kind: 2, ..Default::default() };
        let req = creation("example.com", b"u");
        let err = put_into(&note, &ring, serde_json::json!({}), &req).unwrap_err();
        assert!(err.to_string().contains("err.passkeyNeedsLogin"));
    }
}
