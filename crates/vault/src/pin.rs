//! Unlocking with a PIN.
//!
//! The master password lies in `~/.keyward/pin-<account>.json` (0600),
//! encrypted with AES-256-GCM under a key derived from the PIN through
//! Argon2id with a random salt. Without the file the PIN is useless; without
//! the PIN the file is useless — as with Touch ID, only here a person carries
//! the second half in their head.
//!
//! The honest price: a PIN is short, and Argon2id only slows a search down, it
//! does not make one impossible. So five wrong tries in a row erase the file:
//! after that, the master password and nothing else. The counter lives in the
//! daemon's memory and a restart resets it — but a restart takes the rights of
//! the same user, who has access to the file anyway.
//!
//! Next to the password the file holds **the same PIN key wrapped in the
//! master password** (`wrap`). It exists for exactly one reason: when the
//! master password changes the daemon knows the old and new passwords but not
//! the PIN, and without the wrapper it would have to drop the PIN on every
//! password change. The wrapper adds no new secret: the master password opens
//! everything as it is.

use std::path::{Path, PathBuf};

use aes_gcm::aead::{Aead, KeyInit};
use aes_gcm::{Aes256Gcm, Nonce};
use base64::Engine as _;
use serde::{Deserialize, Serialize};

/// How many wrong tries in a row are tolerated.
pub const MAX_ATTEMPTS: u8 = 5;

const B64: base64::engine::general_purpose::GeneralPurpose = base64::engine::general_purpose::STANDARD;

/// Argon2id's parameters. Kept in the file, so a later version can tighten
/// them without breaking what is already written.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
struct Params {
    memory_kib: u32,
    iterations: u32,
    parallelism: u32,
}

impl Default for Params {
    fn default() -> Self {
        // 64 MiB and three passes: about a hundred milliseconds on a laptop,
        // unnoticeable while typing, but tens of thousands of guesses a second
        // are out of the question.
        Self { memory_kib: 64 * 1024, iterations: 3, parallelism: 4 }
    }
}

/// One encrypted block: the salt for deriving the key, the nonce and the
/// ciphertext.
#[derive(Debug, Clone, Serialize, Deserialize)]
struct Sealed {
    salt: String,
    nonce: String,
    ct: String,
    params: Params,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
struct File {
    /// The master password under the key derived from the PIN.
    #[serde(flatten)]
    body: Sealed,
    /// The PIN key under the key derived from the master password, for
    /// re-encrypting when the password changes. Files written without the
    /// wrapper do not have it, and then a password change drops the PIN.
    #[serde(default)]
    wrap: Option<Sealed>,
}

/// An AES-256 key, zeroed when dropped.
#[derive(zeroize::Zeroize, zeroize::ZeroizeOnDrop)]
struct Key([u8; 32]);

fn derive(secret: &[u8], salt: &[u8], params: Params) -> anyhow::Result<Key> {
    let p = argon2::Params::new(params.memory_kib, params.iterations, params.parallelism, Some(32))
        .map_err(|e| anyhow::anyhow!("the Argon2 parameters are wrong: {e}"))?;
    let mut out = [0u8; 32];
    argon2::Argon2::new(argon2::Algorithm::Argon2id, argon2::Version::V0x13, p)
        .hash_password_into(secret, salt, &mut out)
        .map_err(|e| anyhow::anyhow!("Argon2 did not finish: {e}"))?;
    Ok(Key(out))
}

fn random<const N: usize>() -> anyhow::Result<[u8; N]> {
    let mut buf = [0u8; N];
    getrandom::fill(&mut buf).map_err(|e| anyhow::anyhow!("no randomness: {e}"))?;
    Ok(buf)
}

fn nonce_of(sealed: &Sealed) -> anyhow::Result<[u8; 12]> {
    let raw = B64.decode(&sealed.nonce).map_err(|_| anyhow::anyhow!("the PIN file is damaged: the nonce"))?;
    <[u8; 12]>::try_from(raw.as_slice()).map_err(|_| anyhow::anyhow!("the PIN file is damaged: the nonce length"))
}

/// Encrypts `plain` under a key derived from `secret`. The salt and the nonce
/// are fresh on every write.
fn seal(secret: &[u8], plain: &[u8], params: Params) -> anyhow::Result<(Sealed, Key)> {
    let salt: [u8; 16] = random()?;
    let nonce: [u8; 12] = random()?;
    let key = derive(secret, &salt, params)?;
    let cipher = Aes256Gcm::new_from_slice(&key.0).map_err(|e| anyhow::anyhow!("the cipher could not be built: {e}"))?;
    let ct = cipher
        .encrypt(&Nonce::from(nonce), plain)
        .map_err(|_| anyhow::anyhow!("encryption failed"))?;
    Ok((Sealed { salt: B64.encode(salt), nonce: B64.encode(nonce), ct: B64.encode(ct), params }, key))
}

/// The key from `secret` and the block's salt, without decrypting anything.
fn key_of(secret: &[u8], sealed: &Sealed) -> anyhow::Result<Key> {
    let salt = B64.decode(&sealed.salt).map_err(|_| anyhow::anyhow!("the PIN file is damaged: the salt"))?;
    derive(secret, &salt, sealed.params)
}

fn open_with(key: &Key, sealed: &Sealed) -> anyhow::Result<Vec<u8>> {
    let nonce = nonce_of(sealed)?;
    let ct = B64.decode(&sealed.ct).map_err(|_| anyhow::anyhow!("the PIN file is damaged: the ciphertext"))?;
    let cipher = Aes256Gcm::new_from_slice(&key.0).map_err(|e| anyhow::anyhow!("the cipher could not be built: {e}"))?;
    cipher
        .decrypt(&Nonce::from(nonce), ct.as_slice())
        .map_err(|_| anyhow::anyhow!("the PIN did not fit"))
}

/// Builds the file: the password under the PIN, the PIN key under the
/// password.
fn build(pin: &str, password: &str) -> anyhow::Result<File> {
    let params = Params::default();
    let (body, pin_key) = seal(pin.as_bytes(), password.as_bytes(), params)?;
    let (wrap, _) = seal(password.as_bytes(), &pin_key.0, params)?;
    Ok(File { body, wrap: Some(wrap) })
}

/// The password out of the file, given the PIN.
fn open(file: &File, pin: &str) -> anyhow::Result<String> {
    let key = key_of(pin.as_bytes(), &file.body)?;
    let plain = open_with(&key, &file.body)?;
    String::from_utf8(plain).map_err(|_| anyhow::anyhow!("the decrypted password is not text"))
}

/// Moves the file over to a new master password without knowing the PIN: the
/// PIN key is taken out of the wrapper with the old password, and the new
/// password is encrypted under it.
fn rewrapped(file: &File, old_password: &str, new_password: &str) -> anyhow::Result<File> {
    let wrap = file.wrap.as_ref().ok_or_else(|| anyhow::anyhow!("the PIN file has no wrapper"))?;
    let wrap_key = key_of(old_password.as_bytes(), wrap)?;
    let raw = open_with(&wrap_key, wrap).map_err(|_| anyhow::anyhow!("the old password did not open the PIN wrapper"))?;
    if raw.len() != 32 {
        anyhow::bail!("the PIN wrapper is damaged");
    }
    let mut pin_key = Key([0u8; 32]);
    pin_key.0.copy_from_slice(&raw);

    // The same PIN key, a fresh nonce, the new password inside.
    let nonce: [u8; 12] = random()?;
    let cipher = Aes256Gcm::new_from_slice(&pin_key.0).map_err(|e| anyhow::anyhow!("the cipher could not be built: {e}"))?;
    let ct = cipher
        .encrypt(&Nonce::from(nonce), new_password.as_bytes())
        .map_err(|_| anyhow::anyhow!("encryption failed"))?;
    let body = Sealed {
        salt: file.body.salt.clone(),
        nonce: B64.encode(nonce),
        ct: B64.encode(ct),
        params: file.body.params,
    };
    let (wrap, _) = seal(new_password.as_bytes(), &pin_key.0, file.body.params)?;
    Ok(File { body, wrap: Some(wrap) })
}

fn safe_name(account: &str) -> String {
    account
        .chars()
        .map(|c| if c.is_ascii_alphanumeric() || matches!(c, '.' | '-' | '_') { c } else { '_' })
        .collect()
}

fn path_in(dir: &Path, account: &str) -> PathBuf {
    dir.join(format!("pin-{}.json", safe_name(account)))
}

fn write(path: &Path, file: &File) -> anyhow::Result<()> {
    if let Some(dir) = path.parent() {
        std::fs::create_dir_all(dir)?;
    }
    // Permissions before contents, as with the Touch ID key: there must be no
    // window between the write and the chmod where umask decides.
    let mut opts = std::fs::OpenOptions::new();
    opts.write(true).create(true).truncate(true);
    {
        use std::os::unix::fs::OpenOptionsExt as _;
        opts.mode(0o600);
    }
    use std::io::Write as _;
    let mut f = opts.open(path)?;
    f.write_all(serde_json::to_string(file)?.as_bytes())?;
    f.sync_all()?;
    Ok(())
}

fn read(path: &Path) -> anyhow::Result<File> {
    let text = std::fs::read_to_string(path).map_err(|_| anyhow::anyhow!("no PIN is set"))?;
    serde_json::from_str(&text).map_err(|_| anyhow::anyhow!("the PIN file is damaged — set the PIN again"))
}

// -- The counter of tries ------------------------------------------------

static ATTEMPTS: std::sync::Mutex<Option<std::collections::HashMap<String, u8>>> =
    std::sync::Mutex::new(None);

fn attempts() -> std::sync::MutexGuard<'static, Option<std::collections::HashMap<String, u8>>> {
    ATTEMPTS.lock().unwrap_or_else(std::sync::PoisonError::into_inner)
}

/// Records a miss; `true` means the limit is used up.
fn miss(account: &str) -> bool {
    let mut guard = attempts();
    let map = guard.get_or_insert_with(Default::default);
    let n = map.entry(account.to_string()).or_insert(0);
    *n = n.saturating_add(1);
    *n >= MAX_ATTEMPTS
}

fn reset_attempts(account: &str) {
    if let Some(map) = attempts().as_mut() {
        map.remove(account);
    }
}

// -- The logic over a directory, kept apart from `base_dir()` for tests ---

fn set_in(dir: &Path, account: &str, pin: &str, password: &str) -> anyhow::Result<()> {
    if pin.chars().count() < 4 {
        anyhow::bail!("the PIN is shorter than four characters");
    }
    write(&path_in(dir, account), &build(pin, password)?)?;
    reset_attempts(account);
    Ok(())
}

fn recall_in(dir: &Path, account: &str, pin: &str) -> anyhow::Result<String> {
    let path = path_in(dir, account);
    let file = read(&path)?;
    match open(&file, pin) {
        Ok(password) => {
            reset_attempts(account);
            Ok(password)
        }
        Err(_) => {
            if miss(account) {
                let _ = std::fs::remove_file(&path);
                reset_attempts(account);
                anyhow::bail!("err.pinReset");
            }
            anyhow::bail!("err.badPin")
        }
    }
}

fn rewrap_in(dir: &Path, account: &str, old_password: &str, new_password: &str) -> anyhow::Result<()> {
    let path = path_in(dir, account);
    if !path.exists() {
        return Ok(());
    }
    let file = read(&path)?;
    match rewrapped(&file, old_password, new_password) {
        Ok(next) => write(&path, &next),
        Err(e) => {
            // Better no PIN than a PIN that opens the wrong password now.
            let _ = std::fs::remove_file(&path);
            Err(e)
        }
    }
}

fn rename_in(dir: &Path, from: &str, to: &str) -> anyhow::Result<()> {
    let old = path_in(dir, from);
    if !old.exists() || from == to {
        return Ok(());
    }
    std::fs::rename(&old, path_in(dir, to))?;
    reset_attempts(from);
    Ok(())
}

// -- The public interface -------------------------------------------------

fn dir() -> PathBuf {
    keyward_core::paths::base_dir()
}

/// Is a PIN set for this account?
pub fn is_set(account: &str) -> bool {
    path_in(&dir(), account).exists()
}

/// Remembers the master password under a PIN. Checking the password is the
/// caller's business.
pub fn set(account: &str, pin: &str, password: &str) -> anyhow::Result<()> {
    set_in(&dir(), account, pin, password)
}

/// The password, given the PIN. After five misses in a row the file is erased
/// and `err.pinReset` comes back; before that, `err.badPin`.
pub fn recall(account: &str, pin: &str) -> anyhow::Result<String> {
    recall_in(&dir(), account, pin)
}

pub fn forget(account: &str) -> anyhow::Result<()> {
    let path = path_in(&dir(), account);
    reset_attempts(account);
    match std::fs::remove_file(&path) {
        Ok(()) => Ok(()),
        Err(e) if e.kind() == std::io::ErrorKind::NotFound => Ok(()),
        Err(e) => Err(anyhow::anyhow!("the PIN file cannot be removed: {e}")),
    }
}

/// Re-encrypts the file under a new master password. If there is no file it
/// does nothing; if re-encrypting is impossible it erases the file and returns
/// the error.
pub fn rewrap(account: &str, old_password: &str, new_password: &str) -> anyhow::Result<()> {
    rewrap_in(&dir(), account, old_password, new_password)
}

/// Moves the file to another login, when the email changes.
pub fn rename(from: &str, to: &str) -> anyhow::Result<()> {
    rename_in(&dir(), from, to)
}

#[cfg(test)]
mod tests {
    use super::*;

    fn tmp() -> PathBuf {
        let n = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .map(|d| d.as_nanos())
            .unwrap_or(0);
        let dir = std::env::temp_dir().join(format!("keyward-pin-{}-{n}", std::process::id()));
        std::fs::create_dir_all(&dir).unwrap();
        dir
    }

    /// Fast parameters for the tests: what they check is not the strength.
    fn quick(pin: &str, password: &str) -> File {
        let params = Params { memory_kib: 64, iterations: 1, parallelism: 1 };
        let (body, pin_key) = seal(pin.as_bytes(), password.as_bytes(), params).unwrap();
        let (wrap, _) = seal(password.as_bytes(), &pin_key.0, params).unwrap();
        File { body, wrap: Some(wrap) }
    }

    #[test]
    fn a_password_opens_only_with_its_own_pin() {
        let f = quick("1234", "the master password");
        assert_eq!(open(&f, "1234").unwrap(), "the master password");
        assert!(open(&f, "1235").is_err());
        assert!(open(&f, "").is_err());
    }

    #[test]
    fn re_encrypting_under_a_new_password_keeps_the_pin() {
        let f = quick("1234", "old");
        let next = rewrapped(&f, "old", "new").expect("re-encrypted");
        assert_eq!(open(&next, "1234").unwrap(), "new");
        assert!(open(&next, "0000").is_err());
        // The wrapper moves to the new password too, so the next change works.
        let again = rewrapped(&next, "new", "third").expect("re-encrypted twice");
        assert_eq!(open(&again, "1234").unwrap(), "third");
    }

    #[test]
    fn somebody_elses_old_password_does_not_re_encrypt() {
        let f = quick("1234", "old");
        assert!(rewrapped(&f, "wrong", "new").is_err());
    }

    #[test]
    fn a_file_with_no_wrapper_is_not_re_encrypted() {
        let mut f = quick("1234", "old");
        f.wrap = None;
        assert!(rewrapped(&f, "old", "new").is_err());
        // It must still read: an older format is not a damaged one.
        let text = serde_json::to_string(&f).unwrap();
        let back: File = serde_json::from_str(&text).unwrap();
        assert_eq!(open(&back, "1234").unwrap(), "old");
    }

    #[test]
    fn five_misses_erase_the_file() {
        let dir = tmp();
        let account = format!("acc-{}", dir.display());
        write(&path_in(&dir, &account), &quick("1234", "the password")).unwrap();

        for i in 1..MAX_ATTEMPTS {
            let err = recall_in(&dir, &account, "0000").unwrap_err().to_string();
            assert_eq!(err, "err.badPin", "try {i}");
            assert!(path_in(&dir, &account).exists());
        }
        let err = recall_in(&dir, &account, "0000").unwrap_err().to_string();
        assert_eq!(err, "err.pinReset");
        assert!(!path_in(&dir, &account).exists(), "the file must be gone");
        assert!(recall_in(&dir, &account, "1234").is_err(), "without the file the PIN is useless");
    }

    #[test]
    fn the_right_pin_resets_the_counter() {
        let dir = tmp();
        let account = format!("acc-{}", dir.display());
        write(&path_in(&dir, &account), &quick("1234", "the password")).unwrap();
        for _ in 0..(MAX_ATTEMPTS - 1) {
            let _ = recall_in(&dir, &account, "0000");
        }
        assert_eq!(recall_in(&dir, &account, "1234").unwrap(), "the password");
        // Four misses in a row again, and the file is still alive.
        for _ in 0..(MAX_ATTEMPTS - 1) {
            let _ = recall_in(&dir, &account, "0000");
        }
        assert!(path_in(&dir, &account).exists());
    }

    #[test]
    fn the_file_is_0600_and_moves_to_another_login() {
        use std::os::unix::fs::PermissionsExt as _;
        let dir = tmp();
        write(&path_in(&dir, "a@x"), &quick("1234", "the password")).unwrap();
        let mode = std::fs::metadata(path_in(&dir, "a@x")).unwrap().permissions().mode() & 0o777;
        assert_eq!(mode, 0o600);

        rename_in(&dir, "a@x", "b@x").unwrap();
        assert!(!path_in(&dir, "a@x").exists());
        assert_eq!(recall_in(&dir, "b@x", "1234").unwrap(), "the password");
    }

    #[test]
    fn a_short_pin_is_refused() {
        let dir = tmp();
        assert!(set_in(&dir, "a@x", "123", "the password").is_err());
        assert!(!path_in(&dir, "a@x").exists());
    }

    #[test]
    fn the_file_name_does_not_leave_the_directory() {
        let p = path_in(Path::new("/base"), "../../etc/passwd");
        assert_eq!(p.parent().unwrap(), Path::new("/base"));
        assert_eq!(p.file_name().unwrap(), "pin-.._.._etc_passwd.json");
    }
}
