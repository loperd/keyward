//! Unlocking with Touch ID.
//!
//! The secret is split in two halves that live in two different places.
//!
//! The keychain holds only the ciphertext of the master password; the key to
//! it is in `~/.keyward/touchid-<account>.key` with mode 0600. Neither half
//! gives anything on its own.
//!
//! Why: a keychain item is created with an open ACL (see below), so a single
//! `security find-generic-password -s keyward -w` handed the master password
//! in the clear to any process — and the same password went into the keychain
//! backup, where the account password is enough to decrypt it. Now both are
//! useless without the file, and the file is not in the keychain.
//!
//! What this does not give: a process under the same uid will read the file
//! too. That is cured completely by a Developer ID signature and a return to
//! an ACL that requires the user's presence. Until then there are two lines
//! here instead of one, and at least the master password is not lying in the
//! clear where it is looked for first.
//!
//! Why every call on the keychain goes through `/usr/bin/security` rather than
//! `security-framework` from our own process: besides an ACL, an item has a
//! partition list. Ours looks like this: `apple-tool:`, `cdhash:...`,
//! `cdhash:...`. A `cdhash` partition is the code hash of one particular
//! binary, and a local build is signed ad hoc, so the hash changes with every
//! rebuild. Pressing "Always Allow" appends the current hash, and the very
//! next build falls out of the list: the system asks for the keychain password
//! again. Proper applications have `teamid:` from a Developer ID written
//! there, so updates do not knock it out; we have no such signature.
//!
//! `/usr/bin/security` is signed by Apple and sits in the `apple-tool:`
//! partition, which never changes. So we read and write through it by hand:
//! the password is in the keychain, there is no dialogue, and none of it
//! depends on the signature of our own binaries any more.
//!
//! The first approach went through the keychain with an ACL of "the user must
//! be present": the system itself would show Touch ID on a read. In practice
//! it fails with `-34018 A required entitlement isn't present` — items with an
//! ACL live in the data-protection keychain, which requires a signature with
//! entitlements a local build does not have.
//!
//! So biometrics are invoked explicitly through LocalAuthentication. The
//! policy is strictly biometric: `DeviceOwnerAuthentication` lets the system
//! substitute the account password for a fingerprint, and that prompt looked
//! like "the password again" too. With `WithBiometrics` the system does not
//! offer a password at all, and when the sensor is unavailable we ask for the
//! master password ourselves, in our own window.
//!
//! The honest price of the whole construction: the password is protected by
//! process permissions and by our own Touch ID prompt, not tied to a
//! fingerprint cryptographically — a process under your own uid reads it
//! without the sensor. With a Developer ID signature and entitlements this is
//! mended by returning to an ACL that requires the user's presence.

const SERVICE: &str = "keyward";

#[cfg(target_os = "macos")]
mod imp {
    use std::sync::mpsc;
    use std::time::Duration;

    use objc2_local_authentication::{LAContext, LAPolicy};

    use super::SERVICE;

    /// The one program whose entry in the partition list never changes.
    const SECURITY: &str = "/usr/bin/security";

    /// How long a person at the sensor is waited for.
    const PROMPT_TIMEOUT: Duration = Duration::from_secs(60);

    /// Saves the password **with no restriction by program**.
    ///
    /// The command goes to `security -i` on stdin rather than in arguments:
    /// arguments are visible in `ps` to any process of the user, if only for
    /// an instant.
    ///
    /// `-A` opens the ACL to every program. The protection is the same as it
    /// was: process permissions and our own Touch ID prompt. That is said here
    /// plainly rather than hidden behind the word "keychain".
    pub fn remember(account: &str, password: &str) -> anyhow::Result<()> {
        tracing::info!("writing the password into the keychain through /usr/bin/security");
        let _ = forget(account);
        let sealed = seal(account, password)?;
        run_security(
            &format!(
                "add-generic-password -U -A -s {} -a {} -w {}",
                quote(SERVICE)?,
                quote(account)?,
                quote(&sealed)?
            ),
        )
        .map_err(|e| anyhow::anyhow!("the keychain did not take the password: {e}"))?;
        Ok(())
    }

    /// A wrapper over reading from the keychain: the complaint is remembered
    /// so that the settings do not say "set up" while the keychain refuses.
    pub fn recall(account: &str) -> anyhow::Result<String> {
        match recall_inner(account) {
            Ok(password) => {
                note_success();
                Ok(password)
            }
            Err(e) => {
                note_failure(&e.to_string());
                Err(e)
            }
        }
    }

    fn recall_inner(account: &str) -> anyhow::Result<String> {
        authenticate(&keyward_core::text::t("touch.unlockVault", &[]), true)?;
        tracing::info!("reading the password from the keychain through /usr/bin/security");
        let out = std::process::Command::new(SECURITY)
            .args(["find-generic-password", "-s", SERVICE, "-a", account, "-w"])
            .output()
            .map_err(|e| anyhow::anyhow!("security would not start: {e}"))?;
        if !out.status.success() {
            let err = String::from_utf8_lossy(&out.stderr);
            anyhow::bail!("the keychain would not give the password: {}", err.trim());
        }
        let text = String::from_utf8(out.stdout).map_err(|_| anyhow::anyhow!("what lies in the keychain is not text"))?;
        // `security` appends a line break to the value; only that is removed.
        let stored = text.strip_suffix('\n').unwrap_or(&text);

        // The old format: the keychain held the password itself. It is moved
        // to the new one in place, so that nobody has to type the master
        // password again because the way of storing it changed.
        if !key_path(account).exists() {
            tracing::info!("moving the saved password into the split form");
            if let Err(e) = remember_sealed(account, stored) {
                tracing::warn!(error = %e, "the move failed; the password stayed as it was");
            }
            return Ok(stored.to_string());
        }

        open_sealed(account, stored)
    }

    pub fn forget(account: &str) -> anyhow::Result<()> {
        let _ = std::fs::remove_file(key_path(account));
        run_security(&format!(
            "delete-generic-password -s {} -a {}",
            quote(SERVICE)?,
            quote(account)?
        ))
        .map_err(|e| anyhow::anyhow!("the keychain would not give the item: {e}"))?;
        Ok(())
    }

    /// Feeds one command to `security` in its interactive mode.
    fn run_security(command: &str) -> anyhow::Result<()> {
        use std::io::Write;

        let mut child = std::process::Command::new(SECURITY)
            .arg("-i")
            .stdin(std::process::Stdio::piped())
            .stdout(std::process::Stdio::null())
            .stderr(std::process::Stdio::piped())
            .spawn()
            .map_err(|e| anyhow::anyhow!("security would not start: {e}"))?;

        child
            .stdin
            .as_mut()
            .ok_or_else(|| anyhow::anyhow!("security has no stdin"))?
            .write_all(format!("{command}\n").as_bytes())
            .map_err(|e| anyhow::anyhow!("security did not take the command: {e}"))?;

        let out = child.wait_with_output().map_err(|e| anyhow::anyhow!("security did not finish: {e}"))?;
        if !out.status.success() {
            let err = String::from_utf8_lossy(&out.stderr);
            anyhow::bail!("{}", err.trim());
        }
        Ok(())
    }

    /// Quoting for `security -i`, which splits a line the way a shell does.
    fn quote(value: &str) -> anyhow::Result<String> {
        // There is nothing to escape a line break with: `security -i` reads
        // commands line by line and will read anything after a break as the
        // next command. Such a password is simply not taken.
        if value.contains('\n') || value.contains('\r') {
            anyhow::bail!("there is a line break in the password; the keychain will not take it");
        }
        let escaped = value.replace('\\', "\\\\").replace('"', "\\\"");
        Ok(format!("\"{escaped}\""))
    }

    /// Is there a saved password?
    ///
    /// **Attributes only**, never the value. Reading the value of an item
    /// with the old biometric ACL waits silently for a touch on the sensor,
    /// and the daemon, which calls this on every poll of its state, hangs
    /// entirely.
    pub fn is_remembered(account: &str) -> bool {
        use security_framework::item::{ItemClass, ItemSearchOptions};
        ItemSearchOptions::new()
            .class(ItemClass::generic_password())
            .service(SERVICE)
            .account(account)
            .load_attributes(true)
            .search()
            .map(|items| !items.is_empty())
            .unwrap_or(false)
    }

    /// Rewrites the keychain in the split form without asking for the
    /// password again.
    fn remember_sealed(account: &str, password: &str) -> anyhow::Result<()> {
        let sealed = seal(account, password)?;
        run_security(&format!(
            "add-generic-password -U -A -s {} -a {} -w {}",
            quote(SERVICE)?,
            quote(account)?,
            quote(&sealed)?
        ))
        .map_err(|e| anyhow::anyhow!("the keychain did not take the password: {e}"))
    }

    /// Where the second half lies.
    fn key_path(account: &str) -> std::path::PathBuf {
        let safe: String = account
            .chars()
            .map(|c| if c.is_ascii_alphanumeric() || matches!(c, '.' | '-' | '_') { c } else { '_' })
            .collect();
        keyward_core::paths::base_dir().join(format!("touchid-{safe}.key"))
    }

    /// Wraps the password: the key into the file, the ciphertext out.
    fn seal(account: &str, password: &str) -> anyhow::Result<String> {
        use aes_gcm::aead::{Aead, KeyInit};
        use aes_gcm::{Aes256Gcm, Nonce};
        use base64::Engine as _;

        let mut key = [0u8; 32];
        getrandom::fill(&mut key).map_err(|e| anyhow::anyhow!("no randomness: {e}"))?;
        let mut nonce = [0u8; 12];
        getrandom::fill(&mut nonce).map_err(|e| anyhow::anyhow!("no randomness: {e}"))?;

        let cipher = Aes256Gcm::new_from_slice(&key[..])
            .map_err(|e| anyhow::anyhow!("the cipher could not be built: {e}"))?;
        let sealed = cipher
            .encrypt(&Nonce::from(nonce), password.as_bytes())
            .map_err(|_| anyhow::anyhow!("the password would not encrypt"))?;

        let path = key_path(account);
        if let Some(dir) = path.parent() {
            std::fs::create_dir_all(dir)?;
        }
        // Permissions first, contents second: otherwise there is a window
        // between the write and the chmod where umask decides the mode.
        let mut opts = std::fs::OpenOptions::new();
        opts.write(true).create(true).truncate(true);
        {
            use std::os::unix::fs::OpenOptionsExt as _;
            opts.mode(0o600);
        }
        {
            use std::io::Write as _;
            let mut file = opts.open(&path)?;
            file.write_all(&key)?;
            file.sync_all()?;
        }

        let mut blob = nonce.to_vec();
        blob.extend_from_slice(&sealed);
        Ok(base64::engine::general_purpose::STANDARD.encode(blob))
    }

    /// Unwraps it again.
    fn open_sealed(account: &str, sealed: &str) -> anyhow::Result<String> {
        use aes_gcm::aead::{Aead, KeyInit};
        use aes_gcm::{Aes256Gcm, Nonce};
        use base64::Engine as _;

        let key = std::fs::read(key_path(account))
            .map_err(|_| anyhow::anyhow!("the second half is missing — turn Touch ID on again"))?;
        if key.len() != 32 {
            anyhow::bail!("the second half is damaged — turn Touch ID on again");
        }
        let blob = base64::engine::general_purpose::STANDARD
            .decode(sealed.trim())
            .map_err(|_| anyhow::anyhow!("what lies in the keychain is not a ciphertext — turn Touch ID on again"))?;
        if blob.len() < 13 {
            anyhow::bail!("the ciphertext in the keychain is cut short");
        }
        let (nonce, body) = blob.split_at(12);
        let cipher = Aes256Gcm::new_from_slice(&key[..])
            .map_err(|e| anyhow::anyhow!("the cipher could not be built: {e}"))?;
        let plain = cipher
            .decrypt(&Nonce::try_from(nonce).map_err(|_| anyhow::anyhow!("the nonce is not twelve bytes"))?, body)
            .map_err(|_| anyhow::anyhow!("the halves do not match — turn Touch ID on again"))?;
        String::from_utf8(plain).map_err(|_| anyhow::anyhow!("the decrypted password is not text"))
    }

    /// Are biometrics available at all: is there a sensor, and is a
    /// fingerprint enrolled?
    pub fn is_available() -> bool {
        diagnose().is_none()
    }

    /// What exactly is wrong with the sensor, if anything. `None` means all
    /// is well.
    ///
    /// The system phrases the reason more precisely than anything guessed
    /// from a code: no sensor, no fingerprints, too many failed attempts. That
    /// is what a person is shown — "set up" over a silently broken sensor is
    /// worse than an honest "not working, and here is why".
    pub fn diagnose() -> Option<String> {
        let context = unsafe { LAContext::new() };
        match unsafe { context.canEvaluatePolicy_error(LAPolicy::DeviceOwnerAuthenticationWithBiometrics) }
        {
            Ok(()) => None,
            Err(e) => Some(e.localizedDescription().to_string()),
        }
    }

    /// The sensor's or the keychain's last failure, shown in the settings. An
    /// empty string is not allowed: `None` means "there were no complaints".
    pub fn last_failure() -> Option<String> {
        FAILURE.lock().unwrap_or_else(std::sync::PoisonError::into_inner).clone()
    }

    pub(crate) fn note_failure(text: &str) {
        let text = text.trim();
        if text.is_empty() {
            return;
        }
        *FAILURE.lock().unwrap_or_else(std::sync::PoisonError::into_inner) = Some(text.to_string());
    }

    pub(crate) fn note_success() {
        *FAILURE.lock().unwrap_or_else(std::sync::PoisonError::into_inner) = None;
    }

    /// Confirming an action, through the same system prompt as unlocking. The
    /// agent uses it before signing, when a key is marked `kw-confirm` or the
    /// settings say "always ask".
    pub fn confirm(reason: &str) -> anyhow::Result<()> {
        // No window of trust: a confirmation is a confirmation.
        authenticate(reason, false)
    }

    /// Shows the system's Touch ID prompt and waits for an answer.
    ///
    /// A success is remembered for `biometric_grace_seconds`: actions that
    /// follow one another — unlock the vault, sign at once, copy at once — do
    /// get by on one touch. Zero in the settings means "ask every time".
    fn authenticate(reason: &str, reusable: bool) -> anyhow::Result<()> {
        let grace = Duration::from_secs(u64::from(
            keyward_core::settings::Settings::load().biometric_grace_seconds,
        ));
        // The window of trust covers unlocking and what is read with it —
        // a copied password, a plugin's secret.
        //
        // An ssh signature is not covered: a key marked `kw-confirm` promises
        // a touch for every signature, and a shared counter turned that
        // promise into "one touch for five minutes of any signatures". There
        // is one counter per process, and unlocking the vault wound it up too.
        if reusable && !grace.is_zero() && last_ok().is_some_and(|t| t.elapsed() < grace) {
            return Ok(());
        }

        let context = unsafe { LAContext::new() };
        // Fingerprint only. The system draws its "Enter Password..." button
        // from this title, and an empty string takes it away.
        //
        // The system's own reuse window is not switched on at all: it lives
        // in the system, is not cleared when the vault is locked, and devalues
        // a signature confirmation in just the same way.
        unsafe {
            context.setLocalizedFallbackTitle(Some(&objc2_foundation::NSString::from_str("")));
        }
        let policy = LAPolicy::DeviceOwnerAuthenticationWithBiometrics;

        unsafe { context.canEvaluatePolicy_error(policy) }.map_err(|e| {
            let why = e.localizedDescription().to_string();
            note_failure(&why);
            anyhow::anyhow!("{}", keyward_core::text::t("err.touchIdUnavailable", &[("reason", &why)]))
        })?;

        let (tx, rx) = mpsc::channel::<Result<(), String>>();
        let reason = objc2_foundation::NSString::from_str(reason);

        let block = block2::RcBlock::new(
            move |ok: objc2::runtime::Bool, error: *mut objc2_foundation::NSError| {
                let result = if ok.as_bool() {
                    Ok(())
                } else if error.is_null() {
                    Err(keyward_core::text::t("err.notConfirmedPlain", &[]))
                } else {
                    // The error text comes from the system: it phrases the
                    // reason for a refusal more precisely than anything guessed
                    // from a code.
                    let message = unsafe { (*error).localizedDescription() }.to_string();
                    Err(message)
                };
                let _ = tx.send(result);
            },
        );

        unsafe { context.evaluatePolicy_localizedReason_reply(policy, &reason, &block) };

        match rx.recv_timeout(PROMPT_TIMEOUT) {
            Ok(Ok(())) => {
                if reusable {
                    mark_ok();
                }
                note_success();
                Ok(())
            }
            Ok(Err(e)) => {
                note_failure(&e);
                anyhow::bail!("{e}")
            }
            Err(_) => {
                let text = keyward_core::text::t("err.touchIdTimeout", &[]);
                note_failure(&text);
                anyhow::bail!("{text}")
            }
        }
    }

    /// When a person last confirmed that it is them.
    fn last_ok() -> Option<std::time::Instant> {
        *LAST_OK.lock().unwrap_or_else(std::sync::PoisonError::into_inner)
    }

    fn mark_ok() {
        *LAST_OK.lock().unwrap_or_else(std::sync::PoisonError::into_inner) =
            Some(std::time::Instant::now());
    }

    /// Cleared when the vault is locked: a window of trust must not outlive
    /// the lock, or "locked" stops meaning anything.
    pub fn forget_grace() {
        *LAST_OK.lock().unwrap_or_else(std::sync::PoisonError::into_inner) = None;
    }

    /// The keychain's service for plugins' secrets.
    const PLUGIN_SERVICE: &str = "keyward-plugin";

    /// Keep a plugin's secret in the login keychain — as a ciphertext only.
    ///
    /// The key comes from the vault (`Vault::plugin_secret_key`) and lives
    /// in the daemon's memory while the vault is open; nothing of it is on
    /// disk. Whoever pulls the item out with `security` gets bytes that are no
    /// use without an unlocked vault. The value goes to `security -i` on
    /// stdin, never in arguments.
    pub fn plugin_secret_store(key: &[u8; 32], item: &str, value: &str) -> anyhow::Result<()> {
        use aes_gcm::aead::{Aead, KeyInit};
        use aes_gcm::{Aes256Gcm, Nonce};
        use base64::Engine as _;

        let mut nonce = [0u8; 12];
        getrandom::fill(&mut nonce).map_err(|e| anyhow::anyhow!("no randomness: {e}"))?;
        let cipher = Aes256Gcm::new_from_slice(&key[..]).map_err(|e| anyhow::anyhow!("the cipher could not be built: {e}"))?;
        let sealed = cipher
            .encrypt(&Nonce::from(nonce), value.as_bytes())
            .map_err(|_| anyhow::anyhow!("the secret would not encrypt"))?;
        let mut blob = nonce.to_vec();
        blob.extend_from_slice(&sealed);
        let text = base64::engine::general_purpose::STANDARD.encode(blob);
        run_security(&format!(
            "add-generic-password -U -A -s {} -a {} -w {}",
            quote(PLUGIN_SERVICE)?,
            quote(item)?,
            quote(&text)?
        ))
        .map_err(|e| keyward_core::fault!("err.keychainWrite", "reason" => e))
    }

    /// Read a plugin's secret back: the person's finger first, then the
    /// keychain, then the vault's key.
    pub fn plugin_secret_load(key: &[u8; 32], item: &str, reason: &str) -> anyhow::Result<String> {
        use aes_gcm::aead::{Aead, KeyInit};
        use aes_gcm::{Aes256Gcm, Nonce};
        use base64::Engine as _;

        // Within the window of trust, like copying a password right after
        // unlocking: a plugin's secret read the moment the vault was opened
        // must not ask for the finger a second time.
        authenticate(reason, true)?;
        let out = std::process::Command::new(SECURITY)
            .args(["find-generic-password", "-s", PLUGIN_SERVICE, "-a", item, "-w"])
            .output()
            .map_err(|e| anyhow::anyhow!("security would not start: {e}"))?;
        if !out.status.success() {
            return Err(keyward_core::fault!("err.keychainNoSecret"));
        }
        let text = String::from_utf8(out.stdout).map_err(|_| anyhow::anyhow!("what lies in the keychain is not text"))?;
        let blob = base64::engine::general_purpose::STANDARD
            .decode(text.trim())
            .map_err(|_| keyward_core::fault!("err.keychainDamaged"))?;
        if blob.len() < 13 {
            return Err(keyward_core::fault!("err.keychainDamaged"));
        }
        let (nonce, body) = blob.split_at(12);
        let cipher = Aes256Gcm::new_from_slice(&key[..]).map_err(|e| anyhow::anyhow!("the cipher could not be built: {e}"))?;
        let plain = cipher
            .decrypt(&Nonce::try_from(nonce).map_err(|_| anyhow::anyhow!("the nonce is not twelve bytes"))?, body)
            // Another vault's key, or a changed one: the secret is someone
            // else's now, and has to be given again.
            .map_err(|_| keyward_core::fault!("err.keychainNotOurs"))?;
        String::from_utf8(plain).map_err(|_| keyward_core::fault!("err.keychainDamaged"))
    }

    /// Is there such a secret? Attributes only — no finger, no value.
    pub fn plugin_secret_exists(item: &str) -> bool {
        use security_framework::item::{ItemClass, ItemSearchOptions};
        ItemSearchOptions::new()
            .class(ItemClass::generic_password())
            .service(PLUGIN_SERVICE)
            .account(item)
            .load_attributes(true)
            .search()
            .is_ok_and(|found| !found.is_empty())
    }

    pub fn plugin_secret_forget(item: &str) -> anyhow::Result<()> {
        run_security(&format!("delete-generic-password -s {} -a {}", quote(PLUGIN_SERVICE)?, quote(item)?))
            .map_err(|e| keyward_core::fault!("err.keychainWrite", "reason" => e))
    }

    static LAST_OK: std::sync::Mutex<Option<std::time::Instant>> = std::sync::Mutex::new(None);

    /// The sensor's or the keychain's last complaint. It lives until a
    /// success, and the settings show it instead of a breezy "set up".
    static FAILURE: std::sync::Mutex<Option<String>> = std::sync::Mutex::new(None);
}

#[cfg(not(target_os = "macos"))]
mod imp {
    pub fn plugin_secret_store(_key: &[u8; 32], _item: &str, _value: &str) -> anyhow::Result<()> {
        anyhow::bail!("err.keychainMacosOnly")
    }
    pub fn plugin_secret_load(_key: &[u8; 32], _item: &str, _reason: &str) -> anyhow::Result<String> {
        anyhow::bail!("err.keychainMacosOnly")
    }
    pub fn plugin_secret_exists(_item: &str) -> bool {
        false
    }
    pub fn plugin_secret_forget(_item: &str) -> anyhow::Result<()> {
        Ok(())
    }
    pub fn remember(_account: &str, _password: &str) -> anyhow::Result<()> {
        anyhow::bail!("biometrics are supported on macOS only")
    }
    pub fn recall(_account: &str) -> anyhow::Result<String> {
        anyhow::bail!("biometrics are supported on macOS only")
    }
    pub fn forget(_account: &str) -> anyhow::Result<()> {
        anyhow::bail!("biometrics are supported on macOS only")
    }
    pub fn is_remembered(_account: &str) -> bool {
        false
    }
    pub fn diagnose() -> Option<String> {
        Some("biometrics are supported on macOS only".into())
    }

    pub fn last_failure() -> Option<String> {
        None
    }

    pub fn is_available() -> bool {
        false
    }
    pub fn confirm(_reason: &str) -> anyhow::Result<()> {
        anyhow::bail!("confirmation is supported on macOS only")
    }
    pub fn forget_grace() {}
}

pub use imp::{
    confirm, diagnose, forget, forget_grace, is_available, is_remembered, last_failure, plugin_secret_exists,
    plugin_secret_forget, plugin_secret_load, plugin_secret_store, recall, remember,
};
