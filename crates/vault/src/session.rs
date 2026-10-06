//! An account's session on disk — the tokens, the KDF, the protected keys and
//! the entries rbw decrypts — sealed.
//!
//! rbw wrote it to its cache directory with `File::create`: plain JSON, the
//! access and refresh tokens in it, mode 0644, not atomically. Here it is one
//! file per account under `~/.keyward`, mode 0600, written to a temporary file
//! and renamed over, and **sealed**: AES-256-GCM with a fresh 96-bit nonce on
//! every write, the account's id bound in as associated data so that one
//! account's file cannot stand in for another's. The key is the account's
//! own, 32 random bytes in the login keychain (`keyward-session`), read
//! without a finger — the daemon needs it on every start — through the same
//! `/usr/bin/security` path the rest of keyward's keychain goes through.
//!
//! What it guards: the file alone — in a backup, a synced folder, a cache a
//! cleaner sweeps — is no use. What it does not: a process under the person's
//! uid reaches the keychain item as it reaches `security` itself; that is the
//! same line as the rest of keyward's keychain (see `biometric`).
//!
//! The shape inside is still rbw's `Db` — the entries and the unlock still go
//! through rbw, which reads that shape.
//!
//! The rules:
//! - a sealed file whose key is gone is an error, loudly — never a sign-out;
//! - a file that does not open (tampered, another account's, another key's)
//!   is an error — never an empty session;
//! - a plain file (ours from before, or rbw's) is sealed on its first read,
//!   read back, and only then is the plain copy gone.

use keyward_core::accounts::Account;
use zeroize::Zeroizing;

pub(crate) type Session = rbw::db::Db;

/// The first bytes of a sealed session: a plain one is JSON and begins with
/// `{`.
const MAGIC: &[u8; 8] = b"kwsess1\n";
const NONCE: usize = 12;

/// Where the keys lie. The keychain in the daemon; memory in the tests, which
/// must not touch the person's keychain.
pub(crate) trait Keys {
    fn load(&self, name: &str) -> anyhow::Result<Option<Zeroizing<Vec<u8>>>>;
    fn store(&self, name: &str, key: &[u8]) -> anyhow::Result<()>;
    fn forget(&self, name: &str) -> anyhow::Result<()>;
}

pub(crate) struct Keychain;

impl Keys for Keychain {
    fn load(&self, name: &str) -> anyhow::Result<Option<Zeroizing<Vec<u8>>>> {
        crate::biometric::session_key_load(name)
    }
    fn store(&self, name: &str, key: &[u8]) -> anyhow::Result<()> {
        crate::biometric::session_key_store(name, key)
    }
    fn forget(&self, name: &str) -> anyhow::Result<()> {
        crate::biometric::session_key_forget(name)
    }
}

fn path(account: &Account) -> std::path::PathBuf {
    keyward_core::paths::session_file(&account.id)
}

/// rbw's file for the account, as rbw names it.
fn legacy_path(account: &Account) -> std::path::PathBuf {
    rbw::dirs::db_file(&account.base_url, &account.email)
}

/// The key's name in the keychain: the account's hashed name, no email.
fn key_name(account: &Account) -> String {
    keyward_core::paths::account_key(&account.id)
}

fn aad(account: &Account) -> Vec<u8> {
    let mut a = b"keyward session v1\n".to_vec();
    a.extend_from_slice(account.id.as_bytes());
    a
}

fn cipher(key: &[u8]) -> anyhow::Result<aes_gcm::Aes256Gcm> {
    use aes_gcm::KeyInit as _;
    aes_gcm::Aes256Gcm::new_from_slice(key).map_err(|_| keyward_core::fault!("err.sessionKeyDamaged"))
}

fn seal(account: &Account, key: &[u8], plain: &[u8]) -> anyhow::Result<Vec<u8>> {
    seal_bound(&aad(account), key, plain)
}

fn seal_bound(aad: &[u8], key: &[u8], plain: &[u8]) -> anyhow::Result<Vec<u8>> {
    use aes_gcm::aead::{Aead as _, Payload};
    let mut nonce = [0u8; NONCE];
    getrandom::fill(&mut nonce).map_err(|e| keyward_core::fault!("err.sessionNotSaved", "reason" => e))?;
    let body = cipher(key)?
        .encrypt(&aes_gcm::Nonce::from(nonce), Payload { msg: plain, aad })
        .map_err(|_| keyward_core::fault!("err.sessionNotSaved", "reason" => "the session would not seal"))?;
    let mut out = Vec::with_capacity(MAGIC.len() + NONCE + body.len());
    out.extend_from_slice(MAGIC);
    out.extend_from_slice(&nonce);
    out.extend_from_slice(&body);
    Ok(out)
}

fn open(account: &Account, key: &[u8], sealed: &[u8]) -> anyhow::Result<Zeroizing<Vec<u8>>> {
    open_bound(&aad(account), key, sealed)
}

fn open_bound(aad: &[u8], key: &[u8], sealed: &[u8]) -> anyhow::Result<Zeroizing<Vec<u8>>> {
    use aes_gcm::aead::{Aead as _, Payload};
    let rest = &sealed[MAGIC.len()..];
    if rest.len() < NONCE + 16 {
        return Err(keyward_core::fault!("err.sessionTampered"));
    }
    let (nonce, body) = rest.split_at(NONCE);
    let nonce: [u8; NONCE] = nonce.try_into().map_err(|_| keyward_core::fault!("err.sessionTampered"))?;
    cipher(key)?
        .decrypt(&aes_gcm::Nonce::from(nonce), Payload { msg: body, aad })
        .map(Zeroizing::new)
        // Changed bytes, another account's file, another key: none of them
        // opens, and none of them is a session to fall back on.
        .map_err(|_| keyward_core::fault!("err.sessionTampered"))
}

fn parse(bytes: &[u8], file: &std::path::Path) -> anyhow::Result<Session> {
    serde_json::from_slice(bytes).map_err(|e| {
        // The kind and the place of the fault, never the text: the file holds
        // the tokens.
        keyward_core::fault!(
            "err.sessionNotRead",
            "file" => file.display(),
            "reason" => format!("{:?} at line {} column {}", e.classify(), e.line(), e.column())
        )
    })
}

fn is_sealed(bytes: &[u8]) -> bool {
    bytes.starts_with(MAGIC)
}

/// The account's session; `None` when there is none — never logged in, or
/// signed out and forgotten.
pub(crate) fn load(account: &Account) -> anyhow::Result<Option<Session>> {
    load_with(&Keychain, account)
}

pub(crate) fn save(account: &Account, session: &Session) -> anyhow::Result<()> {
    save_with(&Keychain, account, session)
}

pub(crate) fn remove(account: &Account) {
    remove_with(&Keychain, account)
}

/// Moves a session to another account's name: the email changed.
pub(crate) fn rename(from: &Account, to: &Account, session: &Session) -> anyhow::Result<()> {
    save(to, session)?;
    remove(from);
    Ok(())
}

pub(crate) fn load_with(keys: &dyn Keys, account: &Account) -> anyhow::Result<Option<Session>> {
    let file = path(account);
    let bytes = match std::fs::read(&file) {
        Ok(b) => Zeroizing::new(b),
        Err(e) if e.kind() == std::io::ErrorKind::NotFound => return migrate_legacy(keys, account),
        Err(e) => return Err(keyward_core::fault!("err.sessionNotRead", "file" => file.display(), "reason" => e)),
    };
    if is_sealed(&bytes) {
        // A sealed file and no key is the one case a sign-out would hide: the
        // person is told, the file stays.
        let key = keys.load(&key_name(account))?.ok_or_else(|| keyward_core::fault!("err.sessionKeyMissing"))?;
        let plain = open(account, &key, &bytes)?;
        return parse(&plain, &file).map(Some);
    }
    // Ours, from before sealing: sealed now, over itself.
    let session = parse(&bytes, &file)?;
    seal_over(keys, account, &session, &bytes)?;
    tracing::info!("the session file was sealed");
    Ok(Some(session))
}

pub(crate) fn save_with(keys: &dyn Keys, account: &Account, session: &Session) -> anyhow::Result<()> {
    let file = path(account);
    let name = key_name(account);
    let key = match keys.load(&name)? {
        Some(key) => key,
        None => {
            // A sealed file there with its key gone: a new key would write
            // over it and the loss would never be said.
            if std::fs::read(&file).is_ok_and(|b| is_sealed(&b)) {
                return Err(keyward_core::fault!("err.sessionKeyMissing"));
            }
            let mut key = Zeroizing::new(vec![0u8; 32]);
            getrandom::fill(&mut key).map_err(|e| keyward_core::fault!("err.sessionNotSaved", "reason" => e))?;
            keys.store(&name, &key)?;
            key
        }
    };
    let plain = Zeroizing::new(serde_json::to_vec(session).map_err(|e| keyward_core::fault!("err.sessionNotSaved", "reason" => e))?);
    let sealed = seal(account, &key, &plain)?;
    if let Some(dir) = file.parent() {
        std::fs::create_dir_all(dir).map_err(|e| keyward_core::fault!("err.sessionNotSaved", "reason" => e))?;
    }
    keyward_core::paths::write_private(&file, &sealed).map_err(|e| keyward_core::fault!("err.sessionNotSaved", "reason" => e))
}

pub(crate) fn remove_with(keys: &dyn Keys, account: &Account) {
    for file in [path(account), legacy_path(account), remember_path(account)] {
        if let Err(e) = std::fs::remove_file(&file) {
            if e.kind() != std::io::ErrorKind::NotFound {
                tracing::error!(error = %e, file = %file.display(), "a session file was not removed");
            }
        }
    }
    if let Err(e) = keys.forget(&key_name(account)) {
        tracing::error!(error = %e, "the session's key was not removed from the keychain");
    }
}

// -- A remembered device ------------------------------------------------------
//
// The token a server hands out when a person ticks "remember this device" at
// the second factor stands in for that factor on the next login, so it is
// kept as the session is: sealed with the account's session key, its own
// associated data so that neither file can stand in for the other, mode
// 0600. Never plain on disk, never out of the daemon.

fn remember_path(account: &Account) -> std::path::PathBuf {
    keyward_core::paths::two_factor_remember_file(&account.id)
}

fn remember_aad(account: &Account) -> Vec<u8> {
    let mut a = b"keyward two-factor remember v1\n".to_vec();
    a.extend_from_slice(account.id.as_bytes());
    a
}

/// The remembered device's token; `None` when the device is not remembered.
pub(crate) fn load_remember(account: &Account) -> anyhow::Result<Option<Zeroizing<String>>> {
    load_remember_with(&Keychain, account)
}

pub(crate) fn save_remember(account: &Account, token: &str) -> anyhow::Result<()> {
    save_remember_with(&Keychain, account, token)
}

/// The server no longer takes the token, or the person signs out for good.
pub(crate) fn forget_remember(account: &Account) {
    let file = remember_path(account);
    if let Err(e) = std::fs::remove_file(&file) {
        if e.kind() != std::io::ErrorKind::NotFound {
            tracing::error!(error = %e, file = %file.display(), "the remembered device's token was not removed");
        }
    }
}

/// A file that does not open is said loudly (`err.rememberDamaged`) and is
/// removed with the saying: it only ever skips a check, so the way out is
/// the second factor asked again on the next try — never a quiet skip now.
pub(crate) fn load_remember_with(keys: &dyn Keys, account: &Account) -> anyhow::Result<Option<Zeroizing<String>>> {
    let file = remember_path(account);
    let bytes = match std::fs::read(&file) {
        Ok(b) => Zeroizing::new(b),
        Err(e) if e.kind() == std::io::ErrorKind::NotFound => return Ok(None),
        Err(e) => return Err(keyward_core::fault!("err.rememberDamaged", "reason" => e)),
    };
    let damaged = |why: &str| {
        tracing::error!(why, file = %file.display(), "the remembered device's token does not open; it is removed");
        forget_remember(account);
        keyward_core::fault!("err.rememberDamaged", "reason" => why)
    };
    if !is_sealed(&bytes) {
        return Err(damaged("the file is not sealed"));
    }
    let Some(key) = keys.load(&key_name(account))? else {
        return Err(damaged("the session's key is gone"));
    };
    let plain = open_bound(&remember_aad(account), &key, &bytes).map_err(|_| damaged("the file does not open"))?;
    let token = String::from_utf8(plain.to_vec()).map_err(|_| damaged("the token is not text"))?;
    if token.is_empty() {
        return Err(damaged("the token is empty"));
    }
    Ok(Some(Zeroizing::new(token)))
}

/// Seals the token with the session's key; the session is saved first, so the
/// key is there.
pub(crate) fn save_remember_with(keys: &dyn Keys, account: &Account, token: &str) -> anyhow::Result<()> {
    if token.is_empty() {
        anyhow::bail!(keyward_core::fault!("err.rememberNotSaved", "reason" => "the server sent an empty token"));
    }
    let key = keys.load(&key_name(account))?.ok_or_else(|| keyward_core::fault!("err.sessionKeyMissing"))?;
    let sealed = seal_bound(&remember_aad(account), &key, token.as_bytes())?;
    let file = remember_path(account);
    if let Some(dir) = file.parent() {
        std::fs::create_dir_all(dir).map_err(|e| keyward_core::fault!("err.rememberNotSaved", "reason" => e))?;
    }
    keyward_core::paths::write_private(&file, &sealed).map_err(|e| keyward_core::fault!("err.rememberNotSaved", "reason" => e))
}

/// Seals a session read from plain bytes and checks that what is on disk
/// now opens to the same.
fn seal_over(keys: &dyn Keys, account: &Account, session: &Session, plain: &[u8]) -> anyhow::Result<()> {
    save_with(keys, account, session)?;
    let file = path(account);
    let back = Zeroizing::new(std::fs::read(&file).map_err(|e| keyward_core::fault!("err.sessionNotSaved", "reason" => e))?);
    let key = keys.load(&key_name(account))?.ok_or_else(|| keyward_core::fault!("err.sessionKeyMissing"))?;
    let opened = open(account, &key, &back)?;
    let same = serde_json::from_slice::<serde_json::Value>(&opened).ok() == serde_json::from_slice::<serde_json::Value>(plain).ok();
    if !same {
        anyhow::bail!(keyward_core::fault!("err.sessionNotSaved", "reason" => "the sealed copy does not open to the same"));
    }
    Ok(())
}

/// Takes rbw's plain file over, if there is one: sealed here, then gone.
fn migrate_legacy(keys: &dyn Keys, account: &Account) -> anyhow::Result<Option<Session>> {
    let old = legacy_path(account);
    let bytes = match std::fs::read(&old) {
        Ok(b) => Zeroizing::new(b),
        Err(e) if e.kind() == std::io::ErrorKind::NotFound => return Ok(None),
        Err(e) => return Err(keyward_core::fault!("err.sessionNotRead", "file" => old.display(), "reason" => e)),
    };
    let session = parse(&bytes, &old)?;
    seal_over(keys, account, &session, &bytes)?;
    if let Err(e) = std::fs::remove_file(&old) {
        tracing::error!(error = %e, file = %old.display(), "rbw's session file, with its tokens, was not removed");
    }
    tracing::info!("the session was taken over from rbw's cache and sealed");
    Ok(Some(session))
}

#[cfg(test)]
pub(crate) mod tests {
    use super::*;
    use std::collections::HashMap;
    use std::os::unix::fs::PermissionsExt as _;
    use std::sync::Mutex;

    /// `KEYWARD_HOME` and rbw's cache are process-wide: the tests that move
    /// them take turns.
    pub(crate) static HOME: Mutex<()> = Mutex::new(());

    pub(crate) fn sandbox(name: &str) -> (std::sync::MutexGuard<'static, ()>, std::path::PathBuf) {
        let guard = HOME.lock().unwrap_or_else(|p| p.into_inner());
        let dir = std::env::temp_dir().join(format!("kw-session-{name}-{}", std::process::id()));
        let _ = std::fs::remove_dir_all(&dir);
        std::fs::create_dir_all(&dir).unwrap();
        // SAFETY: the tests that touch the environment hold `HOME`.
        unsafe {
            std::env::set_var("KEYWARD_HOME", dir.join("keyward"));
            std::env::set_var("HOME", &dir);
            std::env::set_var("XDG_CACHE_HOME", dir.join("cache"));
            std::env::set_var("RBW_PROFILE", crate::PROFILE);
        }
        (guard, dir)
    }

    /// A keychain in memory. `down` makes it answer as a locked or absent
    /// keychain does.
    #[derive(Default)]
    pub(crate) struct Memory {
        keys: Mutex<HashMap<String, Vec<u8>>>,
        down: Mutex<bool>,
    }

    impl Keys for Memory {
        fn load(&self, name: &str) -> anyhow::Result<Option<Zeroizing<Vec<u8>>>> {
            if *self.down.lock().unwrap() {
                anyhow::bail!(keyward_core::fault!("err.sessionKeyUnavailable", "reason" => "locked"));
            }
            Ok(self.keys.lock().unwrap().get(name).cloned().map(Zeroizing::new))
        }
        fn store(&self, name: &str, key: &[u8]) -> anyhow::Result<()> {
            if *self.down.lock().unwrap() {
                anyhow::bail!(keyward_core::fault!("err.sessionKeyUnavailable", "reason" => "locked"));
            }
            self.keys.lock().unwrap().insert(name.into(), key.to_vec());
            Ok(())
        }
        fn forget(&self, name: &str) -> anyhow::Result<()> {
            self.keys.lock().unwrap().remove(name);
            Ok(())
        }
    }

    fn account() -> Account {
        Account::new("https://vw.example.net", "me@example.net", None)
    }

    fn session(refresh: &str) -> Session {
        let mut db = Session::new();
        db.access_token = Some("access-secret".into());
        db.refresh_token = Some(refresh.into());
        db.iterations = Some(600_000);
        db
    }

    fn contains(hay: &[u8], needle: &str) -> bool {
        hay.windows(needle.len()).any(|w| w == needle.as_bytes())
    }

    #[test]
    fn a_session_is_sealed_on_disk_and_opens_again() {
        let (_g, _dir) = sandbox("roundtrip");
        let (keys, a) = (Memory::default(), account());
        assert!(load_with(&keys, &a).unwrap().is_none());
        save_with(&keys, &a, &session("refresh-secret")).unwrap();

        let raw = std::fs::read(path(&a)).unwrap();
        assert!(raw.starts_with(MAGIC));
        assert!(!contains(&raw, "refresh-secret") && !contains(&raw, "access-secret"), "no token in the clear");
        assert_eq!(std::fs::metadata(path(&a)).unwrap().permissions().mode() & 0o777, 0o600);
        assert_eq!(load_with(&keys, &a).unwrap().unwrap().refresh_token.as_deref(), Some("refresh-secret"));

        // A fresh nonce every write: the same session seals differently.
        save_with(&keys, &a, &session("refresh-secret")).unwrap();
        assert_ne!(std::fs::read(path(&a)).unwrap(), raw);

        remove_with(&keys, &a);
        assert!(load_with(&keys, &a).unwrap().is_none());
        assert!(keys.keys.lock().unwrap().is_empty(), "the key goes with the session");
    }

    #[test]
    fn a_tampered_or_borrowed_file_is_refused() {
        let (_g, _dir) = sandbox("tamper");
        let (keys, a) = (Memory::default(), account());
        save_with(&keys, &a, &session("r")).unwrap();
        let mut raw = std::fs::read(path(&a)).unwrap();
        let last = raw.len() - 1;
        raw[last] ^= 1;
        std::fs::write(path(&a), &raw).unwrap();
        assert_eq!(load_with(&keys, &a).err().unwrap().to_string(), "err.sessionTampered");

        // Another account's sealed file under this account's name: the
        // associated data does not match, with the same key even.
        let b = Account::new("https://vw.example.net", "other@example.net", None);
        save_with(&keys, &b, &session("theirs")).unwrap();
        let key = keys.load(&key_name(&b)).unwrap().unwrap();
        keys.store(&key_name(&a), &key).unwrap();
        std::fs::copy(path(&b), path(&a)).unwrap();
        assert_eq!(load_with(&keys, &a).err().unwrap().to_string(), "err.sessionTampered");
    }

    #[test]
    fn a_plain_file_is_sealed_and_rbw_s_disappears() {
        let (_g, _dir) = sandbox("migrate");
        let (keys, a) = (Memory::default(), account());

        // Ours from before sealing.
        std::fs::create_dir_all(path(&a).parent().unwrap()).unwrap();
        std::fs::write(path(&a), serde_json::to_vec(&session("ours-plain")).unwrap()).unwrap();
        assert_eq!(load_with(&keys, &a).unwrap().unwrap().refresh_token.as_deref(), Some("ours-plain"));
        let raw = std::fs::read(path(&a)).unwrap();
        assert!(raw.starts_with(MAGIC) && !contains(&raw, "ours-plain"), "sealed over itself");

        // rbw's, world-readable, in its cache.
        remove_with(&keys, &a);
        let old = legacy_path(&a);
        std::fs::create_dir_all(old.parent().unwrap()).unwrap();
        std::fs::write(&old, serde_json::to_vec(&session("rbw-plain")).unwrap()).unwrap();
        assert_eq!(load_with(&keys, &a).unwrap().unwrap().refresh_token.as_deref(), Some("rbw-plain"));
        assert!(!old.exists(), "the plain copy with the tokens is gone");
        assert!(!contains(&std::fs::read(path(&a)).unwrap(), "rbw-plain"));
    }

    #[test]
    fn a_sealed_file_without_its_key_is_a_loud_error_not_a_sign_out() {
        let (_g, _dir) = sandbox("nokey");
        let (keys, a) = (Memory::default(), account());
        save_with(&keys, &a, &session("r")).unwrap();
        keys.forget(&key_name(&a)).unwrap();
        assert_eq!(load_with(&keys, &a).err().unwrap().to_string(), "err.sessionKeyMissing");
        // Nor does a save make a new key and write over what cannot be read.
        assert_eq!(save_with(&keys, &a, &session("new")).err().unwrap().to_string(), "err.sessionKeyMissing");
        assert!(std::fs::read(path(&a)).unwrap().starts_with(MAGIC), "the file is left as it was");

        // A keychain that does not answer is said as such, not as "no key".
        let down = Memory::default();
        save_with(&down, &a, &session("r")).err();
        *down.down.lock().unwrap() = true;
        assert!(load_with(&down, &a).err().unwrap().to_string().starts_with("err.sessionKeyUnavailable"));
    }

    #[test]
    fn a_remembered_device_is_sealed_with_the_session_key_and_bound_to_its_account() {
        let (_g, _dir) = sandbox("remember");
        let (keys, a) = (Memory::default(), account());
        assert!(load_remember_with(&keys, &a).unwrap().is_none(), "not remembered yet");
        assert_eq!(save_remember_with(&keys, &a, "tok").err().unwrap().to_string(), "err.sessionKeyMissing", "no key, no plain fallback");
        save_with(&keys, &a, &session("r")).unwrap();
        save_remember_with(&keys, &a, "remember-secret").unwrap();

        let on_disk = std::fs::read(remember_path(&a)).unwrap();
        assert!(on_disk.starts_with(MAGIC), "sealed");
        assert!(!on_disk.windows(15).any(|w| w == b"remember-secret"), "never plain on disk");
        assert_eq!(std::fs::metadata(remember_path(&a)).unwrap().permissions().mode() & 0o777, 0o600);
        assert_eq!(load_remember_with(&keys, &a).unwrap().unwrap().as_str(), "remember-secret");

        // The session file cannot stand in for the token, nor the other way.
        std::fs::copy(path(&a), remember_path(&a)).unwrap();
        assert_eq!(load_remember_with(&keys, &a).err().unwrap().to_string().split(' ').next(), Some("err.rememberDamaged"));
        assert!(!remember_path(&a).exists(), "a token that does not open is removed with the error");
        assert!(load_remember_with(&keys, &a).unwrap().is_none(), "and the next try asks the second factor");
        assert!(load_with(&keys, &a).unwrap().is_some(), "the session itself is untouched");

        save_remember_with(&keys, &a, "again").unwrap();
        remove_with(&keys, &a);
        assert!(!remember_path(&a).exists(), "a session removed takes the remembered device with it");
    }

    #[test]
    fn a_plain_file_that_does_not_read_is_an_error_and_stays() {
        let (_g, _dir) = sandbox("corrupt");
        let (keys, a) = (Memory::default(), account());
        let old = legacy_path(&a);
        std::fs::create_dir_all(old.parent().unwrap()).unwrap();
        std::fs::write(&old, br#"{"access_token": "secret-tok"#).unwrap();
        let e = load_with(&keys, &a).err().expect("refused").to_string();
        assert!(e.starts_with("err.sessionNotRead"), "{e}");
        assert!(!e.contains("secret-tok"), "the file's text stays out of the error");
        assert!(old.exists(), "left for a person to look at");
    }
}
