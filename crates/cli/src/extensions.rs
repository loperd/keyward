//! The browser extensions the daemon gives passkeys to.
//!
//! The bridge (`keyward-passkey-host`) is a signed program of ours, but it
//! proves nothing about who is behind it: anything can start it, and a copy of
//! the extension's manifest gives a stranger the very same extension id. So
//! the extension has a key of its own — ECDSA P-256, made once, never
//! exportable — and signs every request; the bridge passes the signed string
//! on untouched, and the daemon reads a request only when the signature holds
//! and the key is one a person paired.
//!
//! Pairing is the person's decision, with the finger: an extension that asks
//! unpaired is refused with the five words of its key, and it is paired from
//! the window or from `keyward extension pair`, comparing those words. The
//! paired keys live in a hidden item of the person's own — not a file beside
//! the daemon, which any process of the same user could add a key to, and not
//! an organisation's item, which somebody else could share in.

use std::collections::HashMap;
use std::sync::Mutex;
use std::time::{Duration, Instant, SystemTime, UNIX_EPOCH};

use base64::Engine as _;
use keyward_core::passkey::{ExtensionRow, Signed};
use keyward_vault::Vault;
use p256::ecdsa::signature::Verifier as _;

/// The field that holds the paired keys, one `key seconds` per line.
pub const FIELD: &str = "kw-extension-keys";
/// The field that says where each paired key was paired: one `key browser
/// mac` per line, the two names in base64. A field of its own, so that a
/// keyward that knows only `FIELD` reads the list as it always did.
pub const ABOUT: &str = "kw-extension-about";
/// The hidden item's name.
const ITEM: &str = "keyward browser extensions";
/// What the extension signs is this, then the string it sends.
const CONTEXT: &str = "keyward extension v1\n";

/// How far the extension's clock may be from ours.
const SKEW: Duration = Duration::from_secs(60);
/// How long an unpaired key that asked stays on the list to pair from.
const PENDING_FOR: Duration = Duration::from_secs(10 * 60);
const PENDING_MAX: usize = 8;

fn b64() -> base64::engine::GeneralPurpose {
    base64::engine::general_purpose::STANDARD
}

fn now_secs() -> u64 {
    SystemTime::now().duration_since(UNIX_EPOCH).map(|d| d.as_secs()).unwrap_or(0)
}

/// The five words of a key under a context: the key's own for a paired one,
/// a fresh salt for a pairing.
fn phrase(context: &str, key: &str) -> Vec<String> {
    match b64().decode(key.trim()) {
        Ok(bytes) => keyward_vault::fingerprint::phrase(context, &bytes).unwrap_or_default(),
        Err(_) => Vec::new(),
    }
}

/// A paired key's words: the same every time, to tell paired browsers apart.
pub fn words(key: &str) -> Vec<String> {
    phrase("browser extension", key)
}

fn fresh_salt() -> String {
    let mut b = [0u8; 16];
    rand_core::RngCore::fill_bytes(&mut rand_core::OsRng, &mut b);
    b.iter().map(|x| format!("{x:02x}")).collect()
}

/// Signatures seen lately: a signed request is good once.
static SEEN: Mutex<Vec<(String, Instant)>> = Mutex::new(Vec::new());

/// A key that asked without being paired: when, and the salt of this pairing's
/// words.
struct Asking {
    since: Instant,
    at: u64,
    salt: String,
    browser: String,
}

/// Keys that asked without being paired.
static PENDING: Mutex<Option<HashMap<String, Asking>>> = Mutex::new(None);

/// When each paired key last made a request, since the daemon started.
static USED: Mutex<Option<HashMap<String, u64>>> = Mutex::new(None);

/// Marks a paired key's request.
pub fn used(key: &str) {
    let mut u = USED.lock().unwrap_or_else(std::sync::PoisonError::into_inner);
    u.get_or_insert_with(HashMap::new).insert(key.to_string(), now_secs());
}

fn last_used(key: &str) -> u64 {
    let u = USED.lock().unwrap_or_else(std::sync::PoisonError::into_inner);
    u.as_ref().and_then(|m| m.get(key).copied()).unwrap_or(0)
}

/// This Mac's name, as the person called it in the system settings. Asked
/// once; a Mac that will not say is named nothing, and the window says only
/// the browser.
fn this_mac() -> String {
    static NAME: std::sync::OnceLock<String> = std::sync::OnceLock::new();
    NAME.get_or_init(|| {
        match std::process::Command::new("/usr/sbin/scutil").args(["--get", "ComputerName"]).output() {
            Ok(o) if o.status.success() => String::from_utf8_lossy(&o.stdout).trim().to_string(),
            Ok(o) => {
                tracing::warn!(status = %o.status, "scutil would not say this Mac's name");
                String::new()
            }
            Err(e) => {
                tracing::warn!(error = %e, "scutil would not run to say this Mac's name");
                String::new()
            }
        }
    })
    .clone()
}

/// Where each key was paired, from `ABOUT`'s lines. A line that does not
/// read is an error, as in `FIELD`.
fn about(text: &str) -> anyhow::Result<HashMap<String, (String, String)>> {
    let damaged = || keyward_core::fault!("err.extensionListDamaged");
    let name = |s: &str| -> anyhow::Result<String> {
        String::from_utf8(b64().decode(s).map_err(|_| damaged())?).map_err(|_| damaged())
    };
    let mut out = HashMap::new();
    for line in text.lines().map(str::trim).filter(|l| !l.is_empty()) {
        let mut parts = line.split(' ');
        let (Some(key), Some(browser), Some(mac), None) = (parts.next(), parts.next(), parts.next(), parts.next()) else {
            anyhow::bail!(damaged());
        };
        out.insert(key.to_string(), (name(browser)?, name(mac)?));
    }
    Ok(out)
}

fn render_about(rows: &[ExtensionRow]) -> String {
    rows.iter()
        .filter(|r| !r.browser.is_empty() || !r.device.is_empty())
        .map(|r| format!("{} {} {}", r.key, b64().encode(&r.browser), b64().encode(&r.device)))
        .collect::<Vec<_>>()
        .join("\n")
}

/// Checks a signed request: the signature by `key`, the time, and that it has
/// not been seen before. The key's pairing is checked separately.
pub fn verify(key: &str, signed: &str, sig: &str) -> anyhow::Result<Signed> {
    let bad = || keyward_core::fault!("err.extensionBadSignature");
    let key_bytes = b64().decode(key.trim()).map_err(|_| bad())?;
    let verifying = p256::ecdsa::VerifyingKey::from_sec1_bytes(&key_bytes).map_err(|_| bad())?;
    // WebCrypto signs in the IEEE P1363 form: r and s, 32 bytes each.
    let signature = p256::ecdsa::Signature::from_slice(&b64().decode(sig.trim()).map_err(|_| bad())?).map_err(|_| bad())?;
    let message = [CONTEXT.as_bytes(), signed.as_bytes()].concat();
    verifying.verify(&message, &signature).map_err(|_| bad())?;

    let request: Signed = serde_json::from_str(signed).map_err(|_| keyward_core::fault!("err.passkeyBadRequest"))?;
    let now_ms = SystemTime::now().duration_since(UNIX_EPOCH).map(|d| d.as_millis() as u64).unwrap_or(0);
    if request.ts.abs_diff(now_ms) > SKEW.as_millis() as u64 {
        anyhow::bail!(keyward_core::fault!("err.extensionStale"));
    }
    let mut seen = SEEN.lock().unwrap_or_else(std::sync::PoisonError::into_inner);
    seen.retain(|(_, at)| at.elapsed() < SKEW * 2);
    if seen.iter().any(|(s, _)| s == sig) {
        anyhow::bail!(keyward_core::fault!("err.extensionReplayed"));
    }
    seen.push((sig.to_string(), Instant::now()));
    Ok(request)
}

/// The paired keys, from the person's own hidden items. A line that does not
/// read is an error: a damaged list must not quietly shrink or grow.
pub fn paired(vault: &Vault) -> anyhow::Result<Vec<ExtensionRow>> {
    let mut out = Vec::new();
    for item in vault.items_tagged(FIELD).into_iter().filter(|i| i.owned && i.hidden) {
        // `items_tagged` leaves hidden fields' values out on purpose; the
        // value is read on its own.
        let Some(text) = vault.note_field_values(&item.id, &[FIELD.to_string()]).into_iter().next() else { continue };
        let about = match vault.note_field_values(&item.id, &[ABOUT.to_string()]).into_iter().next() {
            Some(t) => about(&t)?,
            None => HashMap::new(),
        };
        for line in text.lines().map(str::trim).filter(|l| !l.is_empty()) {
            let (key, at) = line.split_once(' ').unwrap_or((line, "0"));
            let at: u64 = at.parse().map_err(|_| keyward_core::fault!("err.extensionListDamaged"))?;
            if b64().decode(key).is_err() {
                anyhow::bail!(keyward_core::fault!("err.extensionListDamaged"));
            }
            let (browser, device) = about.get(key).cloned().unwrap_or_default();
            out.push(ExtensionRow { key: key.to_string(), words: words(key), at, expires: 0, browser, device, used: last_used(key) });
        }
    }
    Ok(out)
}

pub fn is_paired(vault: &Vault, key: &str) -> anyhow::Result<bool> {
    Ok(paired(vault)?.iter().any(|r| r.key == key))
}

/// Puts an unpaired key on the list to pair from, and gives this pairing's
/// words. They are drawn afresh for every pairing — a salt of its own, with
/// the key — and stay the same while it is open, so that the extension's
/// window and keyward's can be compared at leisure. `browser` is the one it
/// asks from, kept to be said in the window and saved with the pairing.
pub fn asked(key: &str, browser: &str) -> (Vec<String>, u64) {
    let mut p = PENDING.lock().unwrap_or_else(std::sync::PoisonError::into_inner);
    let map = p.get_or_insert_with(HashMap::new);
    map.retain(|_, a| a.since.elapsed() < PENDING_FOR);
    if map.len() >= PENDING_MAX && !map.contains_key(key) {
        if let Some(oldest) = map.iter().min_by_key(|(_, a)| a.since).map(|(k, _)| k.clone()) {
            map.remove(&oldest);
        }
    }
    let entry = map.entry(key.to_string()).or_insert_with(|| Asking { since: Instant::now(), at: now_secs(), salt: fresh_salt(), browser: browser.to_string() });
    (phrase(&entry.salt, key), entry.at + PENDING_FOR.as_secs())
}

pub fn pending() -> Vec<ExtensionRow> {
    let mut p = PENDING.lock().unwrap_or_else(std::sync::PoisonError::into_inner);
    let map = p.get_or_insert_with(HashMap::new);
    map.retain(|_, a| a.since.elapsed() < PENDING_FOR);
    map.iter()
        .map(|(k, a)| ExtensionRow {
            key: k.clone(),
            words: phrase(&a.salt, k),
            at: a.at,
            expires: a.at + PENDING_FOR.as_secs(),
            browser: a.browser.clone(),
            device: this_mac(),
            used: 0,
        })
        .collect()
}

/// This pairing's words for a key that is asking.
pub fn pairing_words(key: &str) -> Option<Vec<String>> {
    let mut p = PENDING.lock().unwrap_or_else(std::sync::PoisonError::into_inner);
    let map = p.get_or_insert_with(HashMap::new);
    map.retain(|_, a| a.since.elapsed() < PENDING_FOR);
    map.get(key).map(|a| phrase(&a.salt, key))
}

/// Takes a key off the list to pair from, with the browser it asked from.
fn take_pending(key: &str) -> Option<String> {
    let mut p = PENDING.lock().unwrap_or_else(std::sync::PoisonError::into_inner);
    let map = p.get_or_insert_with(HashMap::new);
    map.retain(|_, a| a.since.elapsed() < PENDING_FOR);
    map.remove(key).map(|a| a.browser)
}

fn render(rows: &[ExtensionRow]) -> String {
    rows.iter().map(|r| format!("{} {}", r.key, r.at)).collect::<Vec<_>>().join("\n")
}

fn own_item(vault: &Vault) -> Option<String> {
    vault.items_tagged(FIELD).into_iter().find(|i| i.owned && i.hidden).map(|i| i.id)
}

/// Pairs a key that asked lately. Only such a key: a pairing is the answer to
/// an extension a person has in front of them, not a key typed in from
/// anywhere.
pub async fn pair(vault: &Vault, key: &str) -> anyhow::Result<()> {
    let Some(browser) = take_pending(key) else {
        anyhow::bail!(keyward_core::fault!("err.extensionNotAsking"));
    };
    let mut rows = paired(vault)?;
    if rows.iter().any(|r| r.key == key) {
        return Ok(());
    }
    rows.push(ExtensionRow { key: key.to_string(), words: Vec::new(), at: now_secs(), expires: 0, browser, device: this_mac(), used: 0 });
    let fields = [(FIELD.to_string(), render(&rows)), (ABOUT.to_string(), render_about(&rows))];
    match own_item(vault) {
        Some(id) => vault.set_item_fields(&id, &fields).await,
        None => {
            let fields: Vec<_> = fields.into_iter().filter(|(_, v)| !v.is_empty()).collect();
            vault.create_plugin_note(ITEM, &fields, true).await.map(|_| ())
        }
    }
}

pub async fn unpair(vault: &Vault, key: &str) -> anyhow::Result<()> {
    let rows: Vec<ExtensionRow> = paired(vault)?.into_iter().filter(|r| r.key != key).collect();
    let Some(id) = own_item(vault) else { return Ok(()) };
    vault.set_item_fields(&id, &[(FIELD.to_string(), render(&rows)), (ABOUT.to_string(), render_about(&rows))]).await
}

#[cfg(test)]
mod tests {
    use super::*;
    use p256::ecdsa::signature::Signer as _;

    fn signer() -> (p256::ecdsa::SigningKey, String) {
        let k = p256::ecdsa::SigningKey::random(&mut rand_core::OsRng);
        let public = b64().encode(k.verifying_key().to_encoded_point(false).as_bytes());
        (k, public)
    }

    fn signed(ts: u64) -> String {
        serde_json::json!({ "ts": ts, "ask": { "op": "offers", "sign_in": { "origin": "https://example.com", "challenge": "AAAAAAAAAAAAAAAAAAAAAA" } } }).to_string()
    }

    fn sign(k: &p256::ecdsa::SigningKey, text: &str) -> String {
        let s: p256::ecdsa::Signature = k.sign(&[CONTEXT.as_bytes(), text.as_bytes()].concat());
        b64().encode(s.to_bytes())
    }

    fn now_ms() -> u64 {
        SystemTime::now().duration_since(UNIX_EPOCH).unwrap().as_millis() as u64
    }

    #[test]
    fn a_request_is_read_only_under_its_own_fresh_signature_and_only_once() {
        let (k, key) = signer();
        let text = signed(now_ms());
        let sig = sign(&k, &text);
        assert!(verify(&key, &text, &sig).is_ok());
        assert!(verify(&key, &text, &sig).unwrap_err().to_string().starts_with("err.extensionReplayed"));

        // Another key, the same words: no.
        let (_, other) = signer();
        let text = signed(now_ms() + 1);
        assert!(verify(&other, &text, &sign(&k, &text)).unwrap_err().to_string().starts_with("err.extensionBadSignature"));

        // A changed request under the old signature: no.
        let sig = sign(&k, &text);
        let changed = text.replace("example.com", "evil.example");
        assert!(verify(&key, &changed, &sig).is_err());

        // Signed long ago: no.
        let old = signed(now_ms() - 10 * 60 * 1000);
        assert!(verify(&key, &old, &sign(&k, &old)).unwrap_err().to_string().starts_with("err.extensionStale"));
    }

    #[test]
    fn only_a_key_that_asked_lately_is_on_the_list_to_pair_from() {
        let (_, key) = signer();
        assert!(!pending().iter().any(|r| r.key == key));
        let (first, expires) = asked(&key, "Arc");
        assert_eq!(first.len(), 5);
        assert!(expires > now_secs() && expires <= now_secs() + PENDING_FOR.as_secs());
        assert_eq!(asked(&key, "Arc").0, first, "the same words while the pairing is open");
        let row = pending().into_iter().find(|r| r.key == key).unwrap();
        assert_eq!(row.words, first);
        assert_eq!(row.browser, "Arc", "the browser it asks from is said");
        assert_ne!(first, words(&key), "a pairing's words are drawn afresh, not the key's own");
        assert_eq!(take_pending(&key).as_deref(), Some("Arc"));
        assert!(take_pending(&key).is_none(), "taken once");
        assert_ne!(asked(&key, "Arc").0, first, "the next pairing has words of its own");
    }

    #[test]
    fn where_a_key_was_paired_reads_back_and_a_damaged_line_is_refused() {
        let row = |key: &str, browser: &str, device: &str| ExtensionRow {
            key: key.into(),
            words: Vec::new(),
            at: 1,
            expires: 0,
            browser: browser.into(),
            device: device.into(),
            used: 0,
        };
        let rows = [row("a2V5", "Google Chrome", "Studio Mac"), row("b3Ro", "", "")];
        let text = render_about(&rows);
        assert_eq!(text.lines().count(), 1, "a key paired before keyward kept this has no line");
        let read = about(&text).unwrap();
        assert_eq!(read["a2V5"], ("Google Chrome".to_string(), "Studio Mac".to_string()));
        assert!(about("a2V5 QXJj").is_err());
        assert!(about("a2V5 !! QXJj").is_err());
        assert!(about("a2V5 QXJj QXJj QXJj").is_err());
    }
}
