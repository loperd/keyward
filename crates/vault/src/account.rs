//! The account: profile, master password, email, KDF, second factor, devices,
//! export.
//!
//! Everything that needs the master password begins by checking it **here**
//! rather than on the server: the master key is derived by the KDF from the
//! database and must open the protected key. A typo in the password then never
//! reaches the network, and the hash for the server is computed from that same
//! key — the KDF is not run a second time.
//!
//! After a change of password, of email, of KDF, or a reset of the security
//! stamp, the server invalidates every token, ours included. So each of those
//! operations ends with a fresh login, with the same outcome as an ordinary
//! `Login`, second factor and all.

use keyward_bw::account as api;
use keyward_bw::crypto::{EncString, Kdf, MasterKey};
use keyward_core::account::{
    AccountProfile, AuthenticatorSetup, Device, EmailTwoFactorSetup, ExportFormat, KdfInfo, TwoFactorOther,
    TwoFactorStatus,
};
use keyward_core::accounts::Account;
use keyward_core::two_factor::TwoFactorProvider;
use rbw::locked::Keys;

use crate::{LoginOutcome, Vault};

/// The authenticator's identifier in Bitwarden's protocol.
const PROVIDER_AUTHENTICATOR: i32 = 0;
/// The identifier of the code-by-email provider.
const PROVIDER_EMAIL: i32 = 1;

/// The KDF in `keyward_bw`'s terms, out of the rbw database. The defaults are
/// what Bitwarden gives a new account, for a database with no parameters.
pub(crate) fn kdf_of(db: &rbw::db::Db) -> Kdf {
    match db.kdf {
        Some(rbw::api::KdfType::Argon2id) => Kdf::Argon2id {
            iterations: db.iterations.unwrap_or(3),
            memory_mib: db.memory.unwrap_or(64),
            parallelism: db.parallelism.unwrap_or(4),
        },
        _ => Kdf::Pbkdf2 { iterations: db.iterations.unwrap_or(600_000) },
    }
}

fn kdf_info(kdf: Kdf) -> KdfInfo {
    match kdf {
        Kdf::Pbkdf2 { iterations } => KdfInfo::Pbkdf2 { iterations },
        Kdf::Argon2id { iterations, memory_mib, parallelism } => {
            KdfInfo::Argon2id { iterations, memory_mib, parallelism }
        }
    }
}

fn kdf_from_info(info: &KdfInfo) -> Kdf {
    match *info {
        KdfInfo::Pbkdf2 { iterations } => Kdf::Pbkdf2 { iterations },
        KdfInfo::Argon2id { iterations, memory_mib, parallelism } => {
            Kdf::Argon2id { iterations, memory_mib, parallelism }
        }
    }
}

fn kdf_params(kdf: Kdf) -> api::KdfParams {
    match kdf {
        Kdf::Pbkdf2 { iterations } => api::KdfParams { kdf: 0, iterations, memory: None, parallelism: None },
        Kdf::Argon2id { iterations, memory_mib, parallelism } => api::KdfParams {
            kdf: 1,
            iterations,
            memory: Some(memory_mib),
            parallelism: Some(parallelism),
        },
    }
}

/// The same bounds Vaultwarden checks: a refusal here reads better than a 400
/// from the server after a key has already been computed.
fn validate_kdf(info: &KdfInfo) -> anyhow::Result<()> {
    match *info {
        KdfInfo::Pbkdf2 { iterations } => {
            if !(100_000..=2_000_000).contains(&iterations) {
                return Err(keyward_core::fault!("err.kdfPbkdf2Range"));
            }
        }
        KdfInfo::Argon2id { iterations, memory_mib, parallelism } => {
            if !(1..=10).contains(&iterations) {
                return Err(keyward_core::fault!("err.kdfArgon2Iterations"));
            }
            if !(15..=1024).contains(&memory_mib) {
                return Err(keyward_core::fault!("err.kdfArgon2Memory"));
            }
            if !(1..=16).contains(&parallelism) {
                return Err(keyward_core::fault!("err.kdfArgon2Parallelism"));
            }
        }
    }
    Ok(())
}

/// The user key in full: encryption key ++ mac key.
fn user_key_bytes(keys: &Keys) -> Vec<u8> {
    let mut raw = keys.enc_key().to_vec();
    raw.extend_from_slice(keys.mac_key());
    raw
}

/// The state of the second factor, out of the server's list of providers.
pub(crate) fn two_factor_status(list: &[api::TwoFactorProvider]) -> TwoFactorStatus {
    let mut status = TwoFactorStatus::default();
    for p in list.iter().filter(|p| p.enabled) {
        match p.kind {
            PROVIDER_AUTHENTICATOR => status.authenticator = true,
            PROVIDER_EMAIL => status.email = true,
            other => {
                let id = u8::try_from(other).unwrap_or(u8::MAX);
                status.others.push(TwoFactorOther { provider: id, name: TwoFactorProvider::from_id(id).name });
            }
        }
    }
    status
}

/// The `otpauth://` for the QR code: the same string Bitwarden's web client
/// builds.
pub(crate) fn otpauth_url(email: &str, key: &str) -> String {
    format!("otpauth://totp/Bitwarden:{}?secret={key}&issuer=Bitwarden", rfc3986(email))
}

/// Percent encoding per RFC 3986: everything but the unreserved characters.
fn rfc3986(s: &str) -> String {
    let mut out = String::with_capacity(s.len());
    for b in s.bytes() {
        if b.is_ascii_alphanumeric() || matches!(b, b'-' | b'.' | b'_' | b'~') {
            out.push(b as char);
        } else {
            out.push_str(&format!("%{b:02X}"));
        }
    }
    out
}

/// The device identifier rbw uses on the server. It is what marks "this
/// device" in the list of devices.
fn own_device_id() -> Option<String> {
    std::fs::read_to_string(rbw::dirs::device_id_file())
        .ok()
        .map(|s| s.trim().to_string())
        .filter(|s| !s.is_empty())
}

fn rename_if_exists(from: &std::path::Path, to: &std::path::Path) {
    if from.exists() && from != to {
        if let Err(e) = std::fs::rename(from, to) {
            tracing::warn!(error = %e, from = %from.display(), "the file was not renamed");
        }
    }
}

impl Vault {
    /// The account's KDF parameters.
    pub fn kdf_info(&self) -> anyhow::Result<KdfInfo> {
        Ok(kdf_info(kdf_of(&self.db()?)))
    }

    /// The master key from the password, with a check that the password is
    /// right.
    ///
    /// The check is local: the key must open the protected key from the
    /// database, and open it into exactly the user key already in memory. If
    /// the vault is locked, or the protected key is in the old format without
    /// a mac, the check is skipped and the server verifies the password.
    fn master_key_checked(&self, password: &str) -> anyhow::Result<MasterKey> {
        if password.is_empty() {
            anyhow::bail!("err.badPassword");
        }
        let db = self.db()?;
        let (_, email) = self.identity();
        let key = MasterKey::derive(password, &email, kdf_of(&db))?;
        if let (Some(keys), Some(protected)) = (self.keys.as_ref(), db.protected_key.as_deref()) {
            if let Ok(sealed) = EncString::parse(protected) {
                let opened = sealed.decrypt(&key.stretch()?).map_err(|_| anyhow::anyhow!("err.badPassword"))?;
                if opened != user_key_bytes(keys) {
                    anyhow::bail!("err.badPassword");
                }
            }
        }
        Ok(key)
    }

    /// The user key wrapped in the new master key: what the server will save
    /// as `key`.
    fn wrapped_user_key(&self, master: &MasterKey) -> anyhow::Result<String> {
        let keys = self.keys.as_ref().ok_or_else(|| keyward_core::fault!("err.vaultLocked"))?;
        let raw = user_key_bytes(keys);
        Ok(EncString::encrypt(&master.stretch()?, &raw)?.to_string())
    }

    /// A call with a token; on a stale token, one sync and one retry.
    async fn with_token<T, F, Fut>(&self, call: F) -> anyhow::Result<T>
    where
        F: Fn(String, String) -> Fut,
        Fut: std::future::Future<Output = anyhow::Result<T>>,
    {
        let (server, token) = self.server_and_token()?;
        match call(server.clone(), token).await {
            Err(e) if e.to_string() == "err.sessionExpired" => {
                self.sync().await?;
                let (_, token) = self.server_and_token()?;
                call(server, token).await
            }
            other => other,
        }
    }

    /// The email as the server knows it: it is also the salt of the master
    /// key, and the server compares it character by character.
    async fn server_email(&self) -> anyhow::Result<String> {
        let profile = self.with_token(|s, t| async move { api::profile(&s, &t).await }).await?;
        Ok(if profile.email.is_empty() { self.account.email.to_lowercase() } else { profile.email })
    }

    /// Logging in again after an operation that invalidated the tokens.
    async fn relogin(&mut self, password: &str) -> anyhow::Result<LoginOutcome> {
        self.lock();
        self.login(password)
            .await
            .map_err(|e| keyward_core::fault!("err.reloginFailed", "reason" => e))
    }

    // -- The profile --------------------------------------------------------

    pub async fn account_profile(&self) -> anyhow::Result<AccountProfile> {
        let raw = self.with_token(|s, t| async move { api::profile(&s, &t).await }).await?;
        let user_id = if raw.id.is_empty() { self.snapshot().profile.id } else { raw.id };
        let fingerprint = self.fingerprint_for(&user_id).unwrap_or_default();
        Ok(AccountProfile {
            email: if raw.email.is_empty() { self.account.email.clone() } else { raw.email },
            user_id,
            name: raw.name.filter(|n| !n.trim().is_empty()),
            avatar_color: raw.avatar_color.filter(|c| !c.trim().is_empty()),
            master_password_hint: raw.master_password_hint.filter(|h| !h.trim().is_empty()),
            email_verified: raw.email_verified,
            premium: raw.premium,
            creation_date: raw.creation_date,
            kdf: self.kdf_info()?,
            fingerprint,
            two_factor_enabled: raw.two_factor_enabled,
        })
    }

    /// The five fingerprint words, from the identifier in the snapshot.
    pub fn fingerprint(&self) -> anyhow::Result<Vec<String>> {
        let id = self.snapshot().profile.id;
        if id.is_empty() {
            return Err(keyward_core::fault!("err.noAccountId"));
        }
        self.fingerprint_for(&id)
    }

    fn fingerprint_for(&self, user_id: &str) -> anyhow::Result<Vec<String>> {
        use rsa::pkcs8::EncodePublicKey as _;
        let private = self.user_private_key()?;
        let public = rsa::RsaPublicKey::from(&private);
        let der = public
            .to_public_key_der()
            .map_err(|e| keyward_core::fault!("err.publicKeyEncode", "reason" => e))?;
        crate::fingerprint::phrase(user_id, der.as_bytes())
    }

    pub async fn set_profile(&self, name: &str, hint: Option<&str>) -> anyhow::Result<()> {
        let name = name.trim();
        if name.is_empty() {
            return Err(keyward_core::fault!("err.nameEmpty"));
        }
        if name.chars().count() > 50 {
            return Err(keyward_core::fault!("err.nameTooLong"));
        }
        let hint = hint.map(str::trim).filter(|h| !h.is_empty()).map(str::to_string);
        self.with_token(|s, t| {
            let (name, hint) = (name.to_string(), hint.clone());
            async move { api::set_profile(&s, &t, &name, hint.as_deref()).await }
        })
        .await
    }

    pub async fn set_avatar(&self, color: Option<&str>) -> anyhow::Result<()> {
        let color = color.map(str::trim).filter(|c| !c.is_empty()).map(str::to_string);
        if let Some(c) = &color {
            let ok = c.len() == 7 && c.starts_with('#') && c[1..].chars().all(|ch| ch.is_ascii_hexdigit());
            if !ok {
                return Err(keyward_core::fault!("err.colorFormat"));
            }
        }
        self.with_token(|s, t| {
            let color = color.clone();
            async move { api::set_avatar(&s, &t, color.as_deref()).await }
        })
        .await
    }

    // -- Master password, email, KDF, devices ---------------------------------

    /// Changing the master password, and logging in again after it.
    pub async fn change_password(
        &mut self,
        current: &str,
        new: &str,
        hint: Option<&str>,
    ) -> anyhow::Result<LoginOutcome> {
        if new.chars().count() < 12 {
            return Err(keyward_core::fault!("err.passwordTooShort"));
        }
        if new == current {
            return Err(keyward_core::fault!("err.passwordUnchanged"));
        }
        let master = self.master_key_checked(current)?;
        let current_hash = master.password_hash(current);
        let (server, email) = self.identity();
        let kdf = kdf_of(&self.db()?);
        let new_master = MasterKey::derive(new, &email, kdf)?;
        let new_hash = new_master.password_hash(new);
        let key = self.wrapped_user_key(&new_master)?;
        let salt = self.server_email().await?;
        let hint = hint.map(str::trim).filter(|h| !h.is_empty()).map(str::to_string);

        self.with_token(|s, t| {
            let (salt, current_hash, new_hash, key, hint) =
                (salt.clone(), current_hash.clone(), new_hash.clone(), key.clone(), hint.clone());
            async move {
                let change = api::KeyChange {
                    salt: &salt,
                    kdf: kdf_params(kdf),
                    current_hash: &current_hash,
                    new_hash: &new_hash,
                    key: &key,
                };
                api::change_password(&s, &t, &change, hint.as_deref()).await
            }
        })
        .await?;
        tracing::warn!(email = %email, "the master password was changed");

        // The new protected key goes into the database at once: even if the
        // login does not go through, unlocking with the new password must work.
        let mut db = self.db()?;
        db.protected_key = Some(key);
        db.save(&server, &email).map_err(|e| keyward_core::fault!("err.rbwDbNotSaved", "reason" => e))?;

        // Touch ID held the old password, which now opens the wrong thing.
        if crate::biometric::is_remembered(&email) {
            if let Err(e) = crate::biometric::remember(&email, new) {
                tracing::warn!(error = %e, "the password under Touch ID was not updated");
                let _ = crate::biometric::forget(&email);
            }
        }
        if let Err(e) = crate::pin::rewrap(&email, current, new) {
            tracing::warn!(error = %e, "the PIN was not re-encrypted and has been dropped");
        }

        self.relogin(new).await
    }

    /// The first step of changing the email: the server sends a code to the
    /// new address.
    pub async fn request_email_token(&self, password: &str, new_email: &str) -> anyhow::Result<()> {
        let new_email = new_email.trim().to_lowercase();
        if !new_email.contains('@') {
            return Err(keyward_core::fault!("err.emailRequired"));
        }
        if new_email == self.account.email.to_lowercase() {
            return Err(keyward_core::fault!("err.emailUnchanged"));
        }
        let hash = self.master_key_checked(password)?.password_hash(password);
        self.with_token(|s, t| {
            let (hash, new_email) = (hash.clone(), new_email.clone());
            async move { api::email_token(&s, &t, &hash, &new_email).await }
        })
        .await
    }

    /// The second step: the code from the new address. The email is the salt
    /// of the master key, so the key is derived again and the account moves
    /// locally to the new address.
    pub async fn change_email(
        &mut self,
        password: &str,
        new_email: &str,
        token: &str,
    ) -> anyhow::Result<LoginOutcome> {
        let new_email = new_email.trim().to_lowercase();
        let token = token.trim();
        if !new_email.contains('@') {
            return Err(keyward_core::fault!("err.emailRequired"));
        }
        if token.is_empty() {
            return Err(keyward_core::fault!("err.emailCodeRequired"));
        }
        let master = self.master_key_checked(password)?;
        let hash = master.password_hash(password);
        let (server, old_email) = self.identity();
        let kdf = kdf_of(&self.db()?);
        let new_master = MasterKey::derive(password, &new_email, kdf)?;
        let new_hash = new_master.password_hash(password);
        let key = self.wrapped_user_key(&new_master)?;

        self.with_token(|s, t| {
            let (hash, new_email, new_hash, token, key) =
                (hash.clone(), new_email.clone(), new_hash.clone(), token.to_string(), key.clone());
            async move { api::change_email(&s, &t, &hash, &new_email, &new_hash, &token, &key).await }
        })
        .await?;
        tracing::warn!(from = %old_email, to = %new_email, "the account email was changed");

        // The local move: the rbw database, the snapshot, the history, Touch
        // ID, the PIN — all of it is keyed by the email or the account id.
        let old = self.account.clone();
        let next = Account::new(&old.base_url, &new_email, old.identity_url.as_deref());
        let mut db = rbw::db::Db::load(&server, &old.email).unwrap_or_default();
        db.protected_key = Some(key);
        db.save(&server, &next.email).map_err(|e| keyward_core::fault!("err.rbwDbNotSaved", "reason" => e))?;
        let _ = std::fs::remove_file(rbw::dirs::db_file(&server, &old.email));
        rename_if_exists(
            &keyward_core::paths::snapshot_file(&old.id),
            &keyward_core::paths::snapshot_file(&next.id),
        );
        rename_if_exists(
            &keyward_core::paths::history_file(&old.id),
            &keyward_core::paths::history_file(&next.id),
        );
        rename_if_exists(
            &keyward_core::paths::passkey_uses_file(&old.id),
            &keyward_core::paths::passkey_uses_file(&next.id),
        );
        if crate::biometric::is_remembered(&old.email) {
            let _ = crate::biometric::forget(&old.email);
            if let Err(e) = crate::biometric::remember(&next.email, password) {
                tracing::warn!(error = %e, "the password under Touch ID did not move to the new email");
            }
        }
        if let Err(e) = crate::pin::rename(&old.email, &next.email) {
            tracing::warn!(error = %e, "the PIN did not move to the new email");
        }
        self.account = next;

        self.relogin(password).await
    }

    /// Changing the key derivation function. The hash and the key are
    /// recomputed with the new parameters, the server remembers them, and then
    /// a fresh login.
    pub async fn change_kdf(&mut self, password: &str, kdf: &KdfInfo) -> anyhow::Result<LoginOutcome> {
        validate_kdf(kdf)?;
        let master = self.master_key_checked(password)?;
        let hash = master.password_hash(password);
        let (server, email) = self.identity();
        let new_kdf = kdf_from_info(kdf);
        if new_kdf == kdf_of(&self.db()?) {
            return Err(keyward_core::fault!("err.kdfUnchanged"));
        }
        let new_master = MasterKey::derive(password, &email, new_kdf)?;
        let new_hash = new_master.password_hash(password);
        let key = self.wrapped_user_key(&new_master)?;
        let salt = self.server_email().await?;

        self.with_token(|s, t| {
            let (salt, hash, new_hash, key) = (salt.clone(), hash.clone(), new_hash.clone(), key.clone());
            async move {
                let change = api::KeyChange {
                    salt: &salt,
                    kdf: kdf_params(new_kdf),
                    current_hash: &hash,
                    new_hash: &new_hash,
                    key: &key,
                };
                api::change_kdf(&s, &t, &change).await
            }
        })
        .await?;
        tracing::warn!(email = %email, ?kdf, "the KDF was changed");

        let mut db = self.db()?;
        match new_kdf {
            Kdf::Pbkdf2 { iterations } => {
                db.kdf = Some(rbw::api::KdfType::Pbkdf2);
                db.iterations = Some(iterations);
                db.memory = None;
                db.parallelism = None;
            }
            Kdf::Argon2id { iterations, memory_mib, parallelism } => {
                db.kdf = Some(rbw::api::KdfType::Argon2id);
                db.iterations = Some(iterations);
                db.memory = Some(memory_mib);
                db.parallelism = Some(parallelism);
            }
        }
        db.protected_key = Some(key);
        db.save(&server, &email).map_err(|e| keyward_core::fault!("err.rbwDbNotSaved", "reason" => e))?;

        self.relogin(password).await
    }

    /// Logging every device out: resetting the security stamp invalidates
    /// every token, ours among them, so we log in again straight away.
    pub async fn deauthorize(&mut self, password: &str) -> anyhow::Result<LoginOutcome> {
        let hash = self.master_key_checked(password)?.password_hash(password);
        self.with_token(|s, t| {
            let hash = hash.clone();
            async move { api::deauthorize(&s, &t, &hash).await }
        })
        .await?;
        tracing::warn!(email = %self.account.email, "every device was logged out");
        self.relogin(password).await
    }

    /// Deleting the account on the server and every trace of it on disk. The
    /// caller is the one that removes it from the daemon's register.
    pub async fn delete_account(&self, password: &str) -> anyhow::Result<()> {
        let hash = self.master_key_checked(password)?.password_hash(password);
        self.with_token(|s, t| {
            let hash = hash.clone();
            async move { api::delete(&s, &t, &hash).await }
        })
        .await?;
        tracing::warn!(email = %self.account.email, "the account was deleted on the server");
        self.forget_local();
        Ok(())
    }

    /// Erases everything local: the rbw database with its tokens, the
    /// snapshot, the history, the passkeys' last uses, the password under
    /// Touch ID and the PIN.
    pub fn forget_local(&self) {
        let (server, email) = self.identity();
        let _ = std::fs::remove_file(rbw::dirs::db_file(&server, &email));
        let _ = std::fs::remove_file(keyward_core::paths::snapshot_file(&self.account.id));
        let _ = std::fs::remove_file(keyward_core::paths::history_file(&self.account.id));
        let _ = std::fs::remove_file(keyward_core::paths::passkey_uses_file(&self.account.id));
        if crate::biometric::is_remembered(&email) {
            let _ = crate::biometric::forget(&email);
        }
        let _ = crate::pin::forget(&email);
    }

    /// Deletes every item and folder of one's own. Organisations are left
    /// alone.
    pub async fn purge(&self, password: &str) -> anyhow::Result<()> {
        let hash = self.master_key_checked(password)?.password_hash(password);
        self.with_token(|s, t| {
            let hash = hash.clone();
            async move { api::purge(&s, &t, &hash).await }
        })
        .await?;
        tracing::warn!(email = %self.account.email, "the personal vault was purged");
        self.sync().await?;
        Ok(())
    }

    /// The devices that have logged in. `current` marks the one matching the
    /// rbw device identifier keyward itself uses.
    pub async fn devices(&self) -> anyhow::Result<Vec<Device>> {
        let list = self.with_token(|s, t| async move { api::devices(&s, &t).await }).await?;
        let own = own_device_id();
        let mut out: Vec<Device> = list
            .into_iter()
            .map(|d| Device {
                current: own.as_deref().is_some_and(|id| id.eq_ignore_ascii_case(&d.identifier)),
                kind: d.kind_name().to_string(),
                id: d.id,
                name: d.name.filter(|n| !n.trim().is_empty()).unwrap_or_else(|| keyward_core::text::t("device.unnamed", &[])),
                identifier: d.identifier,
                created: d.creation_date,
                last_active: d.revision_date,
            })
            .collect();
        // One's own device first, then by name.
        out.sort_by(|a, b| b.current.cmp(&a.current).then_with(|| a.name.to_lowercase().cmp(&b.name.to_lowercase())));
        Ok(out)
    }

    // -- The second factor ----------------------------------------------------

    pub async fn two_factor_status(&self) -> anyhow::Result<TwoFactorStatus> {
        let list = self.with_token(|s, t| async move { api::two_factor(&s, &t).await }).await?;
        Ok(two_factor_status(&list))
    }

    pub async fn authenticator_setup(&self, password: &str) -> anyhow::Result<AuthenticatorSetup> {
        let hash = self.master_key_checked(password)?.password_hash(password);
        let raw = self
            .with_token(|s, t| {
                let hash = hash.clone();
                async move { api::authenticator(&s, &t, &hash).await }
            })
            .await?;
        Ok(AuthenticatorSetup {
            otpauth: otpauth_url(&self.account.email, &raw.key),
            key: raw.key,
            enabled: raw.enabled,
        })
    }

    pub async fn authenticator_enable(
        &self,
        password: &str,
        key: &str,
        token: &str,
    ) -> anyhow::Result<TwoFactorStatus> {
        let token: String = token.chars().filter(|c| !c.is_whitespace()).collect();
        if token.is_empty() {
            return Err(keyward_core::fault!("err.authCodeRequired"));
        }
        let hash = self.master_key_checked(password)?.password_hash(password);
        self.with_token(|s, t| {
            let (hash, key, token) = (hash.clone(), key.to_string(), token.clone());
            async move { api::enable_authenticator(&s, &t, &hash, &key, &token).await }
        })
        .await?;
        tracing::info!("the authenticator was turned on");
        self.two_factor_status().await
    }

    pub async fn email_two_factor_setup(&self, password: &str) -> anyhow::Result<EmailTwoFactorSetup> {
        let hash = self.master_key_checked(password)?.password_hash(password);
        let raw = self
            .with_token(|s, t| {
                let hash = hash.clone();
                async move { api::email_two_factor(&s, &t, &hash).await }
            })
            .await?;
        Ok(EmailTwoFactorSetup {
            email: raw.email.filter(|e| !e.trim().is_empty()).unwrap_or_else(|| self.account.email.clone()),
            enabled: raw.enabled,
        })
    }

    pub async fn email_two_factor_send(&self, password: &str, email: &str) -> anyhow::Result<()> {
        let email = email.trim().to_string();
        if !email.contains('@') {
            return Err(keyward_core::fault!("err.emailRequired"));
        }
        let hash = self.master_key_checked(password)?.password_hash(password);
        self.with_token(|s, t| {
            let (hash, email) = (hash.clone(), email.clone());
            async move { api::send_email_two_factor(&s, &t, &hash, &email).await }
        })
        .await
    }

    pub async fn email_two_factor_enable(
        &self,
        password: &str,
        email: &str,
        token: &str,
    ) -> anyhow::Result<TwoFactorStatus> {
        let email = email.trim().to_string();
        let token = token.trim().to_string();
        if token.is_empty() {
            return Err(keyward_core::fault!("err.emailCodeRequired"));
        }
        let hash = self.master_key_checked(password)?.password_hash(password);
        self.with_token(|s, t| {
            let (hash, email, token) = (hash.clone(), email.clone(), token.clone());
            async move { api::enable_email_two_factor(&s, &t, &hash, &email, &token).await }
        })
        .await?;
        tracing::info!("the code by email was turned on");
        self.two_factor_status().await
    }

    pub async fn two_factor_disable(&self, password: &str, provider: u8) -> anyhow::Result<TwoFactorStatus> {
        let hash = self.master_key_checked(password)?.password_hash(password);
        self.with_token(|s, t| {
            let hash = hash.clone();
            async move { api::disable_two_factor(&s, &t, &hash, provider).await }
        })
        .await?;
        tracing::warn!(provider, "the second factor was turned off");
        self.two_factor_status().await
    }

    pub async fn recovery_code(&self, password: &str) -> anyhow::Result<String> {
        let hash = self.master_key_checked(password)?.password_hash(password);
        let code = self
            .with_token(|s, t| {
                let hash = hash.clone();
                async move { api::recovery_code(&s, &t, &hash).await }
            })
            .await?;
        code.ok_or_else(|| keyward_core::fault!("err.noRecoveryCode"))
    }

    // -- Export ---------------------------------------------------------------

    /// The export file: a name and its contents. The password is checked as
    /// Bitwarden checks it: an unlocked vault on the screen is not yet a reason
    /// to hand the whole of it over in one file.
    pub fn export(&self, password: &str, format: ExportFormat) -> anyhow::Result<(String, String)> {
        let _ = self.master_key_checked(password)?;
        let ring = self.ring().ok_or_else(|| keyward_core::fault!("err.vaultLocked"))?;
        let snapshot = self.snapshot();
        let (folders, items) = crate::export::decrypt_all(&snapshot, &ring);
        let content = match format {
            ExportFormat::Json => crate::export::to_json(&folders, &items),
            ExportFormat::Csv => crate::export::to_csv(&folders, &items),
        };
        let now = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .map(|d| d.as_secs())
            .unwrap_or(0);
        tracing::warn!(?format, items = items.len(), "the vault was exported in the clear");
        Ok((crate::export::filename(format, now), content))
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn provider(kind: i32, enabled: bool) -> api::TwoFactorProvider {
        serde_json::from_value(serde_json::json!({ "type": kind, "enabled": enabled })).unwrap()
    }

    #[test]
    fn the_second_factor_status_falls_apart_into_methods() {
        let s = two_factor_status(&[provider(0, true), provider(1, true), provider(7, true), provider(3, false)]);
        assert!(s.authenticator && s.email);
        assert_eq!(s.others.len(), 1, "a YubiKey that is off stays out of the list");
        assert_eq!(s.others[0].provider, 7);
        assert_eq!(s.others[0].name, "WebAuthn");
    }

    #[test]
    fn an_empty_list_means_the_second_factor_is_off() {
        let s = two_factor_status(&[]);
        assert!(!s.authenticator && !s.email && s.others.is_empty());
    }

    #[test]
    fn the_otpauth_matches_the_web_client() {
        assert_eq!(
            otpauth_url("k@example.com", "JBSWY3DPEHPK3PXP"),
            "otpauth://totp/Bitwarden:k%40example.com?secret=JBSWY3DPEHPK3PXP&issuer=Bitwarden"
        );
    }

    #[test]
    fn the_kdf_bounds() {
        assert!(validate_kdf(&KdfInfo::Pbkdf2 { iterations: 600_000 }).is_ok());
        assert!(validate_kdf(&KdfInfo::Pbkdf2 { iterations: 1000 }).is_err());
        assert!(validate_kdf(&KdfInfo::Argon2id { iterations: 3, memory_mib: 64, parallelism: 4 }).is_ok());
        assert!(validate_kdf(&KdfInfo::Argon2id { iterations: 3, memory_mib: 8, parallelism: 4 }).is_err());
        assert!(validate_kdf(&KdfInfo::Argon2id { iterations: 0, memory_mib: 64, parallelism: 4 }).is_err());
        assert!(validate_kdf(&KdfInfo::Argon2id { iterations: 3, memory_mib: 64, parallelism: 32 }).is_err());
    }

    #[test]
    fn the_kdf_parameters_for_the_server() {
        let p = kdf_params(Kdf::Argon2id { iterations: 3, memory_mib: 64, parallelism: 4 });
        assert_eq!((p.kdf, p.iterations, p.memory, p.parallelism), (1, 3, Some(64), Some(4)));
        let p = kdf_params(Kdf::Pbkdf2 { iterations: 600_000 });
        assert_eq!((p.kdf, p.iterations, p.memory, p.parallelism), (0, 600_000, None, None));
    }

    #[test]
    fn the_kdf_round_trips() {
        for info in [
            KdfInfo::Pbkdf2 { iterations: 600_000 },
            KdfInfo::Argon2id { iterations: 3, memory_mib: 64, parallelism: 4 },
        ] {
            assert_eq!(kdf_info(kdf_from_info(&info)), info);
        }
    }
}
