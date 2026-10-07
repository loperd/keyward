//! Real access to Bitwarden: logging in, unlocking with the master password,
//! syncing and decrypting items.
//!
//! We do not write the cryptography ourselves; we take `rbw`'s core (MIT): key
//! derivation from the master password (PBKDF2/Argon2), EncString, the
//! protected key, organisation keys. Ours here is only what keyward needs:
//! which items to take and which fields to get out of them.
//!
//! The store is kept apart from the user's own `rbw` by the `RBW_PROFILE`
//! variable: `dirs::profile()` puts it into the directory name, so keyward
//! lives in `rbw-keyward` and not in somebody else's `rbw`.

mod account;
mod session;
pub mod sshdraft;
pub mod biometric;
pub mod bwapi;
pub mod edits;
pub mod export;
pub mod fingerprint;
mod merge;
pub mod pin;
pub mod passkey;
pub mod read;

use std::collections::HashMap;

use keyward_core::accounts::Account;
use keyward_core::detail::{card_expiry, ItemDetail, SecretField};
use keyward_core::edits::{edit_id, EditState, ItemEdit, PendingEdit};
use keyward_core::generator::History;
use keyward_core::items::{Catalog, CollectionAccess, CollectionPermission, MemberStatus, OrgMember, OrgRights, OrgRole};
use keyward_core::source::VaultEntry;
use keyward_core::two_factor::TwoFactorProvider;
use keyward_core::vault_state::VaultState;
use rbw::locked::Keys;

/// The profile keyward keeps rbw's config and cache under.
const PROFILE: &str = "keyward";

/// Picks the account up out of the rbw config when keyward's register is
/// empty.
///
/// Needed exactly once, at the move to several accounts: before that the
/// settings lived in the rbw config, and without the migration a person would
/// have seen "the vault is not set up" after an update and decided everything
/// was gone.
pub fn migrate_single_account() -> Option<Account> {
    init_profile();
    let mut registry = keyward_core::accounts::Registry::load();
    if !registry.accounts.is_empty() {
        return None;
    }
    let cfg = rbw::config::Config::load().ok()?;
    let (base_url, email) = (cfg.base_url?, cfg.email?);
    if base_url.is_empty() || email.is_empty() {
        return None;
    }
    let account = Account::new(&base_url, &email, cfg.identity_url.as_deref());
    registry.upsert(account.clone());
    registry.save().ok()?;
    tracing::info!(email = %account.email, "the account was carried over from the rbw config");
    Some(account)
}

/// Turns the profile isolation on. It must be called before any call on rbw
/// and before the runtime starts.
///
/// Our own profile is set **unconditionally**. A foreign `RBW_PROFILE` from
/// the environment used to be left as it was, and keyward went off to write
/// its config and tokens into the real rbw's profile, wiping out a person's
/// working session. The isolation the whole thing exists for could be switched
/// off by one line in `.zshrc`.
///
/// Exactly one call, at the very start of the process: `setenv(3)` is not
/// thread-safe against `getenv(3)`, and the runtime's worker threads read the
/// environment themselves.
pub fn init_profile() {
    static ONCE: std::sync::Once = std::sync::Once::new();
    ONCE.call_once(|| {
        // SAFETY: the only call, before the runtime and its workers exist.
        unsafe { std::env::set_var("RBW_PROFILE", PROFILE) };
    });
}

/// A login in progress: the server asked for a second factor. The password
/// stays in the daemon's protected memory so that it need not travel through
/// the interface a second time.
#[derive(zeroize::ZeroizeOnDrop)]
struct PendingLogin {
    password: String,
    /// What the server took the password as: an email code is asked for with
    /// it.
    password_hash: String,
    sso_email_2fa_session_token: Option<String>,
    #[zeroize(skip)]
    providers: Vec<TwoFactorProvider>,
}

/// How an attempt to log in ended.
pub enum LoginOutcome {
    Done,
    /// A second factor is needed. Which one the server decides, not a guess
    /// made by a form.
    TwoFactorRequired(Vec<TwoFactorProvider>),
}

/// Every edit on disk, opened by whichever of the given vaults is its
/// account's and unlocked; the rest are shown as locked.
pub fn edits_of<'a>(vaults: impl Iterator<Item = &'a Vault>) -> Vec<PendingEdit> {
    let rings: Vec<(String, crate::read::Ring<'a>)> =
        vaults.filter_map(|v| Some((v.account.id.clone(), v.ring()?))).collect();
    crate::edits::list(&rings)
}

/// A vault item marked with a plugin's field.
#[derive(Debug, Clone)]
pub struct TaggedItem {
    pub id: String,
    pub name: String,
    pub hidden: bool,
    pub owned: bool,
    pub fields: Vec<(String, String)>,
}

pub struct Vault {
    account: Account,
    keys: Option<Keys>,
    org_keys: HashMap<String, Keys>,
    pending: Option<PendingLogin>,
}

/// A copy for one request.
///
/// It exists so that a network call does not hold the daemon's shared lock:
/// while one thread syncs, the others have to answer, or ssh runs into its own
/// timeout for no reason. The keys are copied — rbw's `Keys` wipe their memory
/// when dropped, so a copy lives for exactly one request.
///
/// A login in progress is deliberately not copied: it holds the master
/// password, and there is no reason to spread that across copies — finishing a
/// login goes through the original vault under the lock anyway.
impl Clone for Vault {
    fn clone(&self) -> Self {
        Self {
            account: self.account.clone(),
            keys: self.keys.clone(),
            org_keys: self.org_keys.clone(),
            pending: None,
        }
    }
}

impl Vault {
    pub fn for_account(account: Account) -> Self {
        debug_assert!(
            std::env::var("RBW_PROFILE").as_deref() == Ok(PROFILE),
            "the rbw profile must be set before the runtime starts"
        );
        keyward_core::paths::migrate_account_files(&account.id);
        Self { account, keys: None, org_keys: HashMap::new(), pending: None }
    }

    /// Rewrites this account's old, unsealed edits sealed with its key. Called
    /// once the vault is open.
    pub fn seal_old_edits(&self) -> usize {
        let Some(ring) = self.ring() else { return 0 };
        crate::edits::seal_legacy(&ring, &self.account.id)
    }

    pub fn account(&self) -> &Account {
        &self.account
    }

    /// `rbw`'s core takes the server address from its own config rather than
    /// from arguments. So before every network call the config is rewritten for
    /// the current account. That is the price of several accounts over somebody
    /// else's client; there is no race, because every operation goes through
    /// the daemon's single mutex. The proper cure is vendoring the api client
    /// with an explicit config.
    fn activate(&self) -> anyhow::Result<()> {
        let mut cfg = rbw::config::Config::load().unwrap_or_default();
        let already = cfg.base_url.as_deref() == Some(self.account.base_url.as_str())
            && cfg.email.as_deref() == Some(self.account.email.as_str())
            && cfg.identity_url.as_deref() == self.account.identity_url.as_deref();
        if already {
            return Ok(());
        }
        cfg.base_url = Some(self.account.base_url.clone());
        cfg.email = Some(self.account.email.clone());
        cfg.identity_url = self.account.identity_url.clone();
        cfg.save().map_err(|e| keyward_core::fault!("err.rbwConfigNotSaved", "reason" => e))
    }

    fn identity(&self) -> (String, String) {
        (self.account.base_url.clone(), self.account.email.clone())
    }

    /// The account's session. None at all is "not logged in"; one that does
    /// not read is its own error.
    fn db(&self) -> anyhow::Result<session::Session> {
        session::load(&self.account)?.ok_or_else(|| keyward_core::fault!("err.noTokens"))
    }

    fn save_db(&self, db: &session::Session) -> anyhow::Result<()> {
        session::save(&self.account, db)
    }

    pub fn state(&self) -> VaultState {
        let (server, email) = self.identity();
        let db = match self.db() {
            Ok(db) => db,
            Err(e) => {
                // Not logged in is a state; a session that does not read is
                // damage, said as such — the window shows it with its way
                // out rather than a login that would refuse.
                let reason = e.to_string();
                if reason == "err.noTokens" {
                    return VaultState::LoggedOut { email, server };
                }
                tracing::error!(error = %e, "the session does not read");
                return VaultState::Damaged { email, server, reason };
            }
        };
        if db.needs_login() {
            return VaultState::LoggedOut { email, server };
        }
        if self.keys.is_none() {
            return VaultState::Locked { email, server };
        }
        let tagged = self.plugin_entries().len();
        VaultState::Unlocked { email, server, entries: db.entries.len(), tagged }
    }

    /// The first attempt at logging in, without a second factor. If the server
    /// asks for one, the list of methods comes back and the password stays with
    /// the daemon until the second step.
    pub async fn login(&mut self, password: &str) -> anyhow::Result<LoginOutcome> {
        match self.try_login(password, None, None, false).await {
            Ok(()) => {
                self.pending = None;
                Ok(LoginOutcome::Done)
            }
            Err(LoginError::TwoFactor { providers, sso_email_2fa_session_token, password_hash }) => {
                let providers: Vec<TwoFactorProvider> =
                    providers.into_iter().map(TwoFactorProvider::from_id).collect();
                self.pending = Some(PendingLogin {
                    password: password.to_string(),
                    password_hash: password_hash.to_string(),
                    sso_email_2fa_session_token,
                    providers: providers.clone(),
                });
                Ok(LoginOutcome::TwoFactorRequired(providers))
            }
            Err(LoginError::Other(e)) => Err(e),
        }
    }

    /// The session does not read (`VaultState::Damaged`) and the person
    /// chose to sign in again: the damaged session and the remembered device
    /// go, the account stays. Refused for a session that reads — this is no
    /// sign-out by the back door.
    pub fn forget_damaged_session(&mut self) -> anyhow::Result<()> {
        if !matches!(self.state(), VaultState::Damaged { .. }) {
            anyhow::bail!(keyward_core::fault!("err.sessionNotDamaged"));
        }
        self.lock();
        session::remove(&self.account);
        tracing::warn!(email = %self.account.email, "the damaged session was removed at the person's word");
        Ok(())
    }

    /// The second step: the code from the chosen method. `remember` asks the
    /// server to remember this device, so the next login skips the second
    /// factor.
    pub async fn login_two_factor(&mut self, provider: u8, token: &str, remember: bool) -> anyhow::Result<()> {
        let password = self
            .pending
            .as_ref()
            .map(|p| p.password.clone())
            .ok_or_else(|| keyward_core::fault!("err.noPendingLogin"))?;

        match self.try_login(&password, Some(token), Some(provider), remember).await {
            Ok(()) => {
                self.pending = None;
                Ok(())
            }
            Err(LoginError::TwoFactor { .. }) => {
                return Err(keyward_core::fault!("err.badTwoFactor"))
            }
            Err(LoginError::Other(e)) => Err(e),
        }
    }

    /// Asks the server to send a code by email. Only the `Email` provider
    /// needs it.
    pub async fn send_two_factor_email(&self) -> anyhow::Result<()> {
        let (server, email) = self.identity();
        let pending = self.pending.as_ref().ok_or_else(|| keyward_core::fault!("err.noPendingLogin"))?;
        let device = device_id()?;
        let sent = if pending.providers.iter().any(|p| p.kind == keyward_core::two_factor::TwoFactorKind::NewDevice) {
            // The device check's letter, asked again.
            keyward_bw::login::resend_new_device_code(&server, &email, &pending.password_hash).await
        } else {
            keyward_bw::login::send_two_factor_email(&server, &email, &pending.password_hash, &device).await
        };
        sent
            .map_err(|e| if e.to_string().starts_with("err.") { e } else { keyward_core::fault!("err.codeNotSent", "reason" => e) })
    }

    /// The second-factor methods for a login in progress.
    pub fn pending_two_factor(&self) -> Vec<TwoFactorProvider> {
        self.pending.as_ref().map(|p| p.providers.clone()).unwrap_or_default()
    }

    async fn try_login(
        &mut self,
        password: &str,
        two_factor_token: Option<&str>,
        two_factor_provider: Option<u8>,
        remember: bool,
    ) -> Result<(), LoginError> {
        let (server, email) = self.identity();
        let identity = keyward_bw::identity::url(&server, self.account.identity_url.as_deref());
        // Our words for the server's: a refusal already says what it is.
        let ours = |e: anyhow::Error| if e.to_string().starts_with("err.") { e } else { keyward_core::fault!("err.loginFailed", "reason" => e) };

        let kdf = keyward_bw::login::prelogin(&identity, &email).await.map_err(|e| LoginError::Other(ours(e)))?;
        let master = keyward_bw::crypto::MasterKey::derive(password, &email, kdf).map_err(|e| LoginError::Other(ours(e)))?;
        let password_hash = zeroize::Zeroizing::new(master.password_hash(password));
        let device_id = device_id().map_err(LoginError::Other)?;
        let device = keyward_bw::login::Device { id: &device_id, name: keyward_bw::login::DEVICE_NAME, kind: keyward_bw::login::DEVICE_KIND };
        // The device check's code is not a second factor's: it goes as
        // `newDeviceOtp`, the rest as `twoFactorToken`.
        let new_device = two_factor_provider == Some(keyward_core::two_factor::NEW_DEVICE);
        let code = if new_device { None } else { two_factor_provider.zip(two_factor_token) };
        let device_code = if new_device { two_factor_token } else { None };
        // The first try of a login goes with the remembered device's token,
        // where there is one: the second factor is then not asked.
        let remembered = if code.is_none() && device_code.is_none() { session::load_remember(&self.account).map_err(LoginError::Other)? } else { None };
        let second = match (code, remembered.as_deref()) {
            (Some((provider, token)), _) => Some(keyward_bw::login::SecondFactor::Code { provider, token, remember }),
            (None, Some(token)) => Some(keyward_bw::login::SecondFactor::Remembered(token)),
            (None, None) => None,
        };

        let answer = keyward_bw::login::login(&identity, &email, &password_hash, &device, second, device_code).await.map_err(|e| LoginError::Other(ours(e)))?;
        let (access_token, refresh_token, protected_key, private_key, remember_token) = match answer {
            keyward_bw::login::Answer::Done { access_token, refresh_token, key, private_key, remember_token } => {
                (access_token, refresh_token, key, private_key, remember_token)
            }
            keyward_bw::login::Answer::TwoFactor { providers, session_token } => {
                if remembered.is_some() {
                    // The server no longer remembers this device (it was
                    // forgotten there, or the token ran out): it goes here too.
                    tracing::info!(email = %email, "the server no longer takes the remembered device");
                    session::forget_remember(&self.account);
                }
                return Err(LoginError::TwoFactor { providers, sso_email_2fa_session_token: session_token, password_hash });
            }
            // The server mailed a code for this device: the step that asks
            // for it is the second factor's, with one method.
            keyward_bw::login::Answer::NewDevice => {
                return Err(LoginError::TwoFactor { providers: vec![keyward_core::two_factor::NEW_DEVICE], sso_email_2fa_session_token: None, password_hash });
            }
        };

        // A session that is there and does not read stops the login: writing
        // over it would hide what broke it.
        let mut db = session::load(&self.account).map_err(LoginError::Other)?.unwrap_or_default();
        db.access_token = Some(access_token.to_string());
        db.refresh_token = Some(refresh_token.to_string());
        set_kdf(&mut db, kdf);
        db.protected_key = Some(protected_key);
        if private_key.is_some() {
            db.protected_private_key = private_key;
        }
        self.save_db(&db).map_err(LoginError::Other)?;
        if remember {
            match remember_token {
                Some(token) => session::save_remember(&self.account, &token).map_err(LoginError::Other)?,
                // A server may decline to remember (Bitwarden's policy can
                // turn it off): the login stands, the next one asks again.
                None => tracing::warn!(email = %email, "the server did not remember this device"),
            }
        }

        tracing::info!(email = %email, "logged in");
        self.sync().await.map_err(LoginError::Other)?;
        self.unlock(password).map_err(LoginError::Other)?;
        Ok(())
    }

    /// Unlocking: the keys are derived from the master password and the
    /// protected key is decrypted. The password is not kept afterwards.
    pub fn unlock(&mut self, password: &str) -> anyhow::Result<()> {
        let (_, email) = self.identity();
        let db = self.db()?;

        let (Some(kdf), Some(iterations), Some(protected_key), Some(protected_private_key)) = (
            db.kdf,
            db.iterations,
            db.protected_key.as_deref(),
            db.protected_private_key.as_deref(),
        ) else {
            return Err(keyward_core::fault!("err.nothingToUnlock"));
        };

        // rbw derives the key itself from the stored parameters: they go
        // through the same bounds as a prelogin answer first, so a session
        // file tampered with on disk can neither weaken nor hang the KDF.
        crate::account::kdf_of(&db)?;

        let pw = locked_password(password);
        let (keys, org_keys) = rbw::actions::unlock(
            &email,
            &pw,
            kdf,
            iterations,
            db.memory,
            db.parallelism,
            protected_key,
            protected_private_key,
            &db.protected_org_keys,
        )
        .map_err(|e| anyhow::anyhow!("{e}"))?;

        self.keys = Some(keys);
        self.org_keys = org_keys;
        tracing::info!(entries = db.entries.len(), "the vault was unlocked");
        Ok(())
    }

    /// Forgets the keys. The tokens stay: unlocking again takes only the
    /// password.
    pub fn lock(&mut self) {
        self.keys = None;
        self.org_keys.clear();
        // A login in progress holds the master password: abandon the second
        // factor and it stayed in the daemon's memory until the next login.
        if let Some(pending) = self.pending.take() {
            drop(pending);
        }
        // The fingerprint's window of trust must not outlive the lock.
        crate::biometric::forget_grace();
        // Nor may a key waiting in a half-filled form.
        crate::sshdraft::clear();
        tracing::info!("the vault was locked");
    }

    pub async fn sync(&self) -> anyhow::Result<usize> {
        // rbw's sync takes the server from its own config.
        self.activate()?;
        let (server, _) = self.identity();
        let mut db = self.db()?;
        let (Some(access_token), Some(refresh_token)) =
            (db.access_token.clone(), db.refresh_token.clone())
        else {
            return Err(keyward_core::fault!("err.noTokens"));
        };

        // The refresh is ours, not rbw's: rbw drops the refresh token the
        // server rotates in, and the session ended on the login's thirtieth
        // day. A spent access token is traded here, and the new refresh token
        // is on disk before anything else is asked.
        let now = std::time::SystemTime::now().duration_since(std::time::UNIX_EPOCH).map(|d| d.as_secs()).unwrap_or(0);
        let (access_token, refresh_token) = if keyward_bw::identity::spent(&access_token, now, 60) {
            let identity = keyward_bw::identity::url(&server, self.account.identity_url.as_deref());
            match keyward_bw::identity::refresh(&identity, &refresh_token).await {
                Ok(tokens) => {
                    rotate(&mut db, tokens);
                    self.save_db(&db)?;
                    (db.access_token.clone().unwrap_or_default(), db.refresh_token.clone().unwrap_or_default())
                }
                Err(e) if e.to_string() == "err.sessionEnded" => {
                    // The server has ended the session: its tokens are of no
                    // use, and keeping them only says "failed" on every sync.
                    // Without them the vault reads as signed out, and the
                    // window asks for the master password; the entries on
                    // disk stay.
                    db.access_token = None;
                    db.refresh_token = None;
                    self.save_db(&db)?;
                    tracing::warn!("the server ended the session; a new login is needed");
                    return Err(keyward_core::fault!("err.sessionEnded"));
                }
                Err(e) => return Err(keyward_core::fault!("err.syncFailed", "reason" => e)),
            }
        } else {
            (access_token, refresh_token)
        };

        let (new_access_token, (protected_key, protected_private_key, protected_org_keys, entries)) =
            rbw::actions::sync(&access_token, &refresh_token)
                .await
                .map_err(|e| keyward_core::fault!("err.syncFailed", "reason" => rbw_reason(&e)))?;

        if let Some(t) = new_access_token {
            db.access_token = Some(t);
        }
        db.protected_key = Some(protected_key);
        db.protected_private_key = Some(protected_private_key);
        db.protected_org_keys = protected_org_keys;
        let count = entries.len();
        db.entries = entries;
        self.save_db(&db)?;

        // Our own snapshot: it has the trash, favourites, organisation names
        // and collections — everything rbw's model loses.
        match keyward_bw::sync::fetch(&server, db.access_token.as_deref().unwrap_or_default()).await {
            Ok(snapshot) => {
                let path = keyward_core::paths::snapshot_file(&self.account.id);
                if let Some(dir) = path.parent() {
                    let _ = std::fs::create_dir_all(dir);
                }
                if let Ok(text) = serde_json::to_string(&snapshot) {
                    if let Err(e) = keyward_core::paths::write_private(&path, text.as_bytes()) {
                        tracing::warn!(error = %e, "our own snapshot was not saved");
                    }
                }
            }
            Err(e) => tracing::warn!(error = %e, "our own snapshot did not arrive"),
        }

        tracing::info!(entries = count, "synced");
        Ok(count)
    }

    /// The vault snapshot our own sync brought back.
    fn snapshot(&self) -> keyward_bw::Sync {
        let path = keyward_core::paths::snapshot_file(&self.account.id);
        std::fs::read_to_string(path)
            .ok()
            .and_then(|t| serde_json::from_str(&t).ok())
            .unwrap_or_default()
    }

    fn ring(&self) -> Option<crate::read::Ring<'_>> {
        Some(crate::read::Ring { user: self.keys.as_ref()?, orgs: &self.org_keys })
    }

    /// The catalogue of items: kinds, folders, organisations, collections,
    /// the trash.
    pub fn catalog(&self) -> Catalog {
        let Some(ring) = self.ring() else { return Catalog::default() };
        crate::read::catalog(&self.snapshot(), &ring)
    }

    /// The items a plugin may work with: the vault's ssh keys and everything
    /// carrying keyward's own fields.
    pub fn plugin_entries(&self) -> Vec<VaultEntry> {
        let Some(ring) = self.ring() else { return Vec::new() };
        crate::read::plugin_entries(&self.snapshot(), &ring)
    }

    /// An item's card.
    pub fn item_detail(&self, entry_id: &str) -> Option<ItemDetail> {
        let ring = self.ring()?;
        let mut detail = crate::read::detail(&self.snapshot(), &ring, entry_id)?;
        if !detail.passkeys.is_empty() {
            // The card opens without the dates rather than not at all; the
            // damage is loud in the log.
            match self.passkey_uses() {
                Ok(uses) => {
                    for p in &mut detail.passkeys {
                        p.last_used = uses.get(&p.credential_id).map(|t| iso_at(*t));
                    }
                }
                Err(e) => tracing::error!(error = %e, "the passkeys' last uses cannot be read"),
            }
        }
        Some(detail)
    }

    /// A secret's value. For TOTP the **finished code** comes back rather
    /// than the seed: nobody but the generator needs the seed.
    pub fn secret(&self, entry_id: &str, field: &SecretField) -> anyhow::Result<keyward_core::proto::Secret> {
        let snapshot = self.snapshot();
        let cipher = snapshot
            .ciphers
            .iter()
            .find(|c| c.id == entry_id)
            .ok_or_else(|| keyward_core::fault!("err.itemNotFound"))?;
        let ring = self.ring().ok_or_else(|| keyward_core::fault!("err.vaultLocked"))?;

        let missing = || anyhow::anyhow!("err.noSuchField");
        let undecryptable = || anyhow::anyhow!("err.undecryptable");
        let dec = |v: &str| crate::read::decrypt_for(&ring, cipher, v);
        let take = |raw: Option<&str>| -> anyhow::Result<String> {
            dec(raw.ok_or_else(missing)?).ok_or_else(undecryptable)
        };

        let login = cipher.login.as_ref();
        let card = cipher.card.as_ref();

        let value = match field {
            SecretField::Password => take(login.and_then(|l| l.password.as_deref()))?,
            SecretField::Username => take(login.and_then(|l| l.username.as_deref()))?,
            SecretField::Totp => totp_code(&take(login.and_then(|l| l.totp.as_deref()))?)?,
            SecretField::TotpSecret => take(login.and_then(|l| l.totp.as_deref()))?,
            SecretField::CardNumber => take(card.and_then(|c| c.number.as_deref()))?,
            SecretField::CardCode => take(card.and_then(|c| c.code.as_deref()))?,
            SecretField::CardHolder => take(card.and_then(|c| c.cardholder_name.as_deref()))?,
            SecretField::CardExpShort
            | SecretField::CardExpLong
            | SecretField::CardExpMonth
            | SecretField::CardExpYear => {
                let m = card.and_then(|c| c.exp_month.as_deref()).and_then(dec);
                let y = card.and_then(|c| c.exp_year.as_deref()).and_then(dec);
                let (mm, yyyy) = card_expiry(m.as_deref(), y.as_deref()).ok_or_else(missing)?;
                let yy = keyward_core::detail::year_short(&yyyy);
                match field {
                    SecretField::CardExpShort => format!("{mm}/{yy}"),
                    SecretField::CardExpLong => format!("{mm}/{yyyy}"),
                    SecretField::CardExpMonth => mm,
                    _ => yyyy,
                }
            }
            SecretField::PrivateKey => {
                take(cipher.ssh_key.as_ref().and_then(|k| k.private_key.as_deref()))?
            }
            SecretField::Notes => take(cipher.notes.as_deref())?,
            SecretField::Custom(name) => {
                crate::read::field_of(&ring, cipher, name).ok_or_else(missing)?
            }
            SecretField::PasswordHistory(index) => {
                let entry = cipher
                    .password_history
                    .as_ref()
                    .and_then(|h| h.as_array())
                    .and_then(|list| list.get(*index))
                    .ok_or_else(missing)?;
                take(entry.get("password").and_then(|p| p.as_str()))?
            }
        };

        Ok(zeroize::Zeroizing::new(value))
    }

    /// Writes a changed item to the server.
    ///
    /// On a 401 we sync once — a sync refreshes the token — and try again: an
    /// expired session must not look like a refusal from the server.
    async fn write_cipher(&self, cipher: &keyward_bw::model::Cipher) -> anyhow::Result<()> {
        let (server, _) = self.identity();
        let access = |db: &rbw::db::Db| db.access_token.clone();

        let token = access(&self.db()?).ok_or_else(|| keyward_core::fault!("err.noTokens"))?;
        match crate::bwapi::put_cipher(&server, &token, cipher).await {
            Ok(()) => Ok(()),
            Err(crate::bwapi::WriteError::Unauthorized) => {
                self.sync().await?;
                let token =
                    access(&self.db()?).ok_or_else(|| keyward_core::fault!("err.noTokens"))?;
                crate::bwapi::put_cipher(&server, &token, cipher)
                    .await
                    .map_err(|e| anyhow::anyhow!("{e}"))
            }
            Err(e) => Err(anyhow::anyhow!("{e}")),
        }
    }

    /// Encrypts a value with the item's key.
    /// An ssh key item's new key, made or read as the edit asks and sealed
    /// for `cipher`. The private key is dropped from memory as soon as it is
    /// sealed.
    fn sealed_ssh_key(
        &self,
        cipher: &keyward_bw::model::Cipher,
        key: &keyward_core::edits::SshKeyEdit,
        comment: &str,
    ) -> anyhow::Result<keyward_bw::model::SshKey> {
        use keyward_core::edits::SshKeyEdit;
        let material = match key {
            SshKeyEdit::Generate { algorithm } => keyward_sshkey::generate(*algorithm, comment)?,
            SshKeyEdit::Import { private_key, passphrase } => {
                keyward_sshkey::import(private_key.as_str(), passphrase.as_ref().map(|p| p.as_str()))?
            }
            // A key made or read in the daemon: the window only named it.
            SshKeyEdit::Draft { id } => {
                crate::sshdraft::take(id).ok_or_else(|| keyward_core::fault!("err.sshDraftGone"))?
            }
        };
        Ok(keyward_bw::model::SshKey {
            private_key: Some(self.encrypt_for(cipher, &material.private_key)?),
            public_key: Some(self.encrypt_for(cipher, &material.public_key)?),
            fingerprint: Some(self.encrypt_for(cipher, &material.fingerprint)?),
        })
    }

    fn encrypt_for(&self, cipher: &keyward_bw::model::Cipher, text: &str) -> anyhow::Result<String> {
        let ring = self.ring().ok_or_else(|| keyward_core::fault!("err.vaultLocked"))?;
        crate::read::encrypt_for(&ring, cipher, text)
    }

    /// Writes a set of custom fields, keeping the rest.
    async fn write_fields(&self, entry_id: &str, values: &[(&str, String)]) -> anyhow::Result<()> {
        let snapshot = self.snapshot();
        let mut cipher = snapshot
            .ciphers
            .iter()
            .find(|c| c.id == entry_id)
            .cloned()
            .ok_or_else(|| keyward_core::fault!("err.itemNotFoundSync"))?;
        let ring = self.ring().ok_or_else(|| keyward_core::fault!("err.vaultLocked"))?;
        let before = cipher.clone();

        cipher.fields.retain(|f| {
            let name = f.name.as_deref().and_then(|n| crate::read::decrypt_for(&ring, &before, n));
            !name.is_some_and(|n| values.iter().any(|(k, _)| n.trim().eq_ignore_ascii_case(k)))
        });
        for (key, value) in values {
            cipher.fields.push(keyward_bw::model::Field {
                kind: 1,
                name: Some(self.encrypt_for(&cipher, key)?),
                value: Some(self.encrypt_for(&cipher, value)?),
                linked_id: None,
            });
        }

        self.write_cipher(&cipher).await?;
        self.sync().await?;
        Ok(())
    }

    /// Writes the list of hosts into `kw-host`. An empty string unbinds.
    pub async fn set_hosts(&self, entry_id: &str, hosts: &str) -> anyhow::Result<()> {
        let hosts = hosts.trim();
        if hosts.is_empty() {
            let snapshot = self.snapshot();
            let mut cipher = snapshot
                .ciphers
                .iter()
                .find(|c| c.id == entry_id)
                .cloned()
                .ok_or_else(|| keyward_core::fault!("err.itemNotFoundSync"))?;
            let ring = self.ring().ok_or_else(|| keyward_core::fault!("err.vaultLocked"))?;
            let before = cipher.clone();
            cipher.fields.retain(|f| {
                !f.name
                    .as_deref()
                    .and_then(|n| crate::read::decrypt_for(&ring, &before, n))
                    .is_some_and(|n| n.trim().eq_ignore_ascii_case("kw-host"))
            });
            self.write_cipher(&cipher).await?;
            self.sync().await?;
            tracing::info!(entry = %entry_id, "kw-host was cleared");
            return Ok(());
        }

        self.write_fields(entry_id, &[("kw-host", hosts.to_string())]).await?;
        tracing::info!(entry = %entry_id, hosts = hosts, "kw-host was written");
        Ok(())
    }

    /// Applies an edit to an item: locally at once, to the server at once
    /// too — but if the server did not answer, the edit stays in the queue and
    /// is not lost.
    /// Moves an item into the trash.
    pub async fn trash_item(&self, entry_id: &str) -> anyhow::Result<()> {
        self.retry_write(|server, token| {
            let id = entry_id.to_string();
            async move { crate::bwapi::trash_cipher(&server, &token, &id).await }
        })
        .await?;
        tracing::info!(entry = %entry_id, "the item is in the trash");
        self.sync().await?;
        Ok(())
    }

    /// Brings an item back out of the trash.
    pub async fn restore_item(&self, entry_id: &str) -> anyhow::Result<()> {
        self.retry_write(|server, token| {
            let id = entry_id.to_string();
            async move { crate::bwapi::restore_cipher(&server, &token, &id).await }
        })
        .await?;
        tracing::info!(entry = %entry_id, "the item was restored");
        self.sync().await?;
        Ok(())
    }

    /// Deletes items for good.
    ///
    /// Only those already in the trash: deleting past it would mean losing an
    /// item to a single press, and the interface must have nothing of the
    /// kind.
    pub async fn purge_items(&self, entry_ids: &[String]) -> anyhow::Result<usize> {
        if entry_ids.is_empty() {
            return Ok(0);
        }
        let in_trash = only_trashed(&self.snapshot(), entry_ids)?;

        let (server, _) = self.identity();
        let token = self.db()?.access_token.ok_or_else(|| keyward_core::fault!("err.noTokens"))?;
        match crate::bwapi::purge_ciphers(&server, &token, &in_trash).await {
            Ok(()) => {}
            Err(crate::bwapi::WriteError::Unauthorized) => {
                self.sync().await?;
                let token =
                    self.db()?.access_token.ok_or_else(|| keyward_core::fault!("err.noTokens"))?;
                crate::bwapi::purge_ciphers(&server, &token, &in_trash)
                    .await
                    .map_err(|e| anyhow::anyhow!("{e}"))?;
            }
            Err(e) => return Err(anyhow::anyhow!("{e}")),
        }
        tracing::info!(count = in_trash.len(), "the items were deleted for good");
        self.sync().await?;
        Ok(in_trash.len())
    }

    /// Everything that lies in the trash.
    pub fn trashed_ids(&self) -> Vec<String> {
        self.snapshot().ciphers.iter().filter(|c| c.in_trash()).map(|c| c.id.clone()).collect()
    }

    /// Creates an item of the chosen kind and returns its identifier: in
    /// one's own vault, or in an organisation's collections — then every
    /// value is sealed with the organisation's key, and the collections must
    /// be ones one may write to.
    pub async fn create_item(
        &self,
        kind: u8,
        folder_id: Option<String>,
        org_id: Option<String>,
        collection_ids: Vec<String>,
        edit: ItemEdit,
    ) -> anyhow::Result<String> {
        self.activate()?;
        let name = edit.name.clone().unwrap_or_default();
        if name.trim().is_empty() {
            return Err(keyward_core::fault!("err.itemNeedsName"));
        }
        if let Some(org) = org_id.as_deref() {
            self.may_write_into(org, &collection_ids)?;
        } else if !collection_ids.is_empty() {
            return Err(keyward_core::fault!("err.collectionsNeedOrg"));
        }

        let mut cipher = keyward_bw::model::Cipher {
            id: String::new(),
            kind,
            folder_id,
            organization_id: org_id,
            ..Default::default()
        };
        // What the closures below seal with: the item's own organisation,
        // without borrowing the item they fill in.
        let keyed = keyward_bw::model::Cipher {
            organization_id: cipher.organization_id.clone(),
            ..Default::default()
        };
        match kind {
            1 => cipher.login = Some(keyward_bw::model::Login::default()),
            2 => cipher.secure_note = Some(serde_json::json!({ "type": 0 })),
            3 => cipher.card = Some(keyward_bw::model::Card::default()),
            4 => cipher.identity = Some(keyward_bw::model::Identity::default()),
            // An ssh key is made from a key, generated or pasted in: an empty
            // one is of no use to anybody.
            5 if edit.ssh_key.is_some() => {}
            5 => return Err(keyward_core::fault!("err.sshKeyRequired")),
            _ => return Err(keyward_core::fault!("err.itemKindNotCreatable")),
        }
        if let (5, Some(key)) = (kind, edit.ssh_key.as_ref()) {
            // Made before the name is sealed: the name goes into the new
            // key's comment, in the clear.
            cipher.ssh_key = Some(self.sealed_ssh_key(&cipher, key, name.trim())?);
        }

        cipher.name = self.encrypt_for(&cipher, name.trim())?;
        if let Some(notes) = edit.notes.as_deref().filter(|n| !n.is_empty()) {
            cipher.notes = Some(self.encrypt_for(&cipher, notes)?);
        }
        if let Some(login) = cipher.login.as_mut() {
            let ring = self.ring().ok_or_else(|| keyward_core::fault!("err.vaultLocked"))?;
            let enc = |v: &str| crate::read::encrypt_for(&ring, &keyed, v);
            if let Some(v) = edit.username.as_deref().filter(|v| !v.is_empty()) {
                login.username = Some(enc(v)?);
            }
            if let Some(v) = edit.password.as_deref().filter(|v| !v.is_empty()) {
                login.password = Some(enc(v)?);
            }
            if let Some(v) = edit.totp.as_deref().filter(|v| !v.is_empty()) {
                check_totp_secret(v)?;
                login.totp = Some(enc(v)?);
            }
            if let Some(uris) = &edit.uris {
                login.uris = uris
                    .iter()
                    .map(|u| u.trim())
                    .filter(|u| !u.is_empty())
                    .map(|u| Ok(keyward_bw::model::Uri { uri: Some(enc(u)?), match_type: None }))
                    .collect::<anyhow::Result<Vec<_>>>()?;
            }
        }
        if let Some(on) = edit.reprompt {
            cipher.reprompt = u8::from(on);
        }
        if let Some(on) = edit.favorite {
            cipher.favorite = on;
        }

        {
            let ring = self.ring().ok_or_else(|| keyward_core::fault!("err.vaultLocked"))?;
            let seal = |v: &str| crate::read::encrypt_for(&ring, &keyed, v);
            if let (Some(card), Some(edit)) = (cipher.card.as_mut(), edit.card.as_ref()) {
                if let Some(v) = edit.cardholder_name.as_deref().filter(|v| !v.trim().is_empty()) {
                    card.cardholder_name = Some(seal(v)?);
                }
                if let Some(v) = edit.number.as_deref().filter(|v| !v.trim().is_empty()) {
                    card.number = Some(seal(v)?);
                }
                if let Some(v) = edit.brand.as_deref().filter(|v| !v.trim().is_empty()) {
                    card.brand = Some(seal(v)?);
                }
                if let Some(v) = edit.exp_month.as_deref().filter(|v| !v.trim().is_empty()) {
                    card.exp_month = Some(seal(v)?);
                }
                if let Some(v) = edit.exp_year.as_deref().filter(|v| !v.trim().is_empty()) {
                    card.exp_year = Some(seal(v)?);
                }
                if let Some(v) = edit.code.as_deref().filter(|v| !v.trim().is_empty()) {
                    card.code = Some(seal(v)?);
                }
            }
            if let (Some(who), Some(edit)) = (cipher.identity.as_mut(), edit.identity.as_ref()) {
                if let Some(v) = edit.title.as_deref().filter(|v| !v.trim().is_empty()) {
                    who.title = Some(seal(v)?);
                }
                if let Some(v) = edit.first_name.as_deref().filter(|v| !v.trim().is_empty()) {
                    who.first_name = Some(seal(v)?);
                }
                if let Some(v) = edit.middle_name.as_deref().filter(|v| !v.trim().is_empty()) {
                    who.middle_name = Some(seal(v)?);
                }
                if let Some(v) = edit.last_name.as_deref().filter(|v| !v.trim().is_empty()) {
                    who.last_name = Some(seal(v)?);
                }
                if let Some(v) = edit.username.as_deref().filter(|v| !v.trim().is_empty()) {
                    who.username = Some(seal(v)?);
                }
                if let Some(v) = edit.company.as_deref().filter(|v| !v.trim().is_empty()) {
                    who.company = Some(seal(v)?);
                }
                if let Some(v) = edit.email.as_deref().filter(|v| !v.trim().is_empty()) {
                    who.email = Some(seal(v)?);
                }
                if let Some(v) = edit.phone.as_deref().filter(|v| !v.trim().is_empty()) {
                    who.phone = Some(seal(v)?);
                }
                if let Some(v) = edit.address1.as_deref().filter(|v| !v.trim().is_empty()) {
                    who.address1 = Some(seal(v)?);
                }
                if let Some(v) = edit.address2.as_deref().filter(|v| !v.trim().is_empty()) {
                    who.address2 = Some(seal(v)?);
                }
                if let Some(v) = edit.address3.as_deref().filter(|v| !v.trim().is_empty()) {
                    who.address3 = Some(seal(v)?);
                }
                if let Some(v) = edit.city.as_deref().filter(|v| !v.trim().is_empty()) {
                    who.city = Some(seal(v)?);
                }
                if let Some(v) = edit.state.as_deref().filter(|v| !v.trim().is_empty()) {
                    who.state = Some(seal(v)?);
                }
                if let Some(v) = edit.postal_code.as_deref().filter(|v| !v.trim().is_empty()) {
                    who.postal_code = Some(seal(v)?);
                }
                if let Some(v) = edit.country.as_deref().filter(|v| !v.trim().is_empty()) {
                    who.country = Some(seal(v)?);
                }
                if let Some(v) = edit.ssn.as_deref().filter(|v| !v.trim().is_empty()) {
                    who.ssn = Some(seal(v)?);
                }
                if let Some(v) = edit.passport_number.as_deref().filter(|v| !v.trim().is_empty()) {
                    who.passport_number = Some(seal(v)?);
                }
                if let Some(v) = edit.license_number.as_deref().filter(|v| !v.trim().is_empty()) {
                    who.license_number = Some(seal(v)?);
                }
            }
        }
        for field in &edit.custom {
            // A linked field has no value at all: the point is the reference
            // to a field of the item, which a client reads from linkedId.
            let linked = field.kind == 3;
            cipher.fields.push(keyward_bw::model::Field {
                kind: field.kind,
                name: Some(self.encrypt_for(&cipher, &field.name)?),
                value: if linked { None } else { Some(self.encrypt_for(&cipher, &field.value)?) },
                linked_id: linked.then_some(field.linked_id).flatten(),
            });
        }

        let id = self.post_new_cipher(&cipher, &collection_ids).await?;
        tracing::info!(%name, %id, "the item was created");
        Ok(id)
    }

    /// Refuses unless every collection is the organisation's, one may write
    /// to it, and there is at least one: the server keeps no organisation's
    /// item outside a collection.
    fn may_write_into(&self, org_id: &str, collection_ids: &[String]) -> anyhow::Result<()> {
        if self.org_rights(org_id).is_none() {
            return Err(keyward_core::fault!("err.orgNotFound"));
        }
        if collection_ids.is_empty() {
            return Err(keyward_core::fault!("err.collectionRequired"));
        }
        let snapshot = self.snapshot();
        for id in collection_ids {
            let c = snapshot
                .collections
                .iter()
                .find(|c| &c.id == id)
                .ok_or_else(|| keyward_core::fault!("err.collectionNotFound"))?;
            if c.organization_id.as_deref() != Some(org_id) {
                return Err(keyward_core::fault!("err.collectionNotInOrg"));
            }
            if c.read_only {
                return Err(keyward_core::fault!("err.collectionReadOnly"));
            }
        }
        Ok(())
    }

    /// Puts an organisation's item into exactly these collections.
    pub async fn set_item_collections(&self, entry_id: &str, collection_ids: Vec<String>) -> anyhow::Result<()> {
        let org = self
            .snapshot()
            .ciphers
            .iter()
            .find(|c| c.id == entry_id)
            .ok_or_else(|| keyward_core::fault!("err.itemNotFoundSync"))?
            .organization_id
            .clone()
            .ok_or_else(|| keyward_core::fault!("err.collectionsNeedOrg"))?;
        self.may_write_into(&org, &collection_ids)?;
        let ids = &collection_ids;
        self.retry_write(|server, token| async move {
            crate::bwapi::put_collections(&server, &token, entry_id, ids).await
        })
        .await?;
        tracing::info!(%entry_id, count = collection_ids.len(), "the item's collections were set");
        self.sync().await?;
        Ok(())
    }

    /// Sends a new item to the server and syncs, so that it is in the
    /// snapshot by the time the caller looks. The answer is its identifier.
    pub(crate) async fn post_new_cipher(
        &self,
        cipher: &keyward_bw::model::Cipher,
        collection_ids: &[String],
    ) -> anyhow::Result<String> {
        let id = self
            .retry_write(|server, token| async move {
                crate::bwapi::post_cipher(&server, &token, cipher, collection_ids).await
            })
            .await?;
        self.sync().await?;
        Ok(id)
    }

    /// The shared wrapper around writing to the server: a 401 means "the
    /// token has expired" and is cured by a sync, not by repeating the same
    /// request.
    async fn retry_write<T, F, Fut>(&self, call: F) -> anyhow::Result<T>
    where
        F: Fn(String, String) -> Fut,
        Fut: std::future::Future<Output = Result<T, crate::bwapi::WriteError>>,
    {
        let (server, _) = self.identity();
        let token = self.db()?.access_token.ok_or_else(|| keyward_core::fault!("err.noTokens"))?;
        match call(server.clone(), token).await {
            Ok(v) => Ok(v),
            Err(crate::bwapi::WriteError::Unauthorized) => {
                self.sync().await?;
                let token =
                    self.db()?.access_token.ok_or_else(|| keyward_core::fault!("err.noTokens"))?;
                call(server, token).await.map_err(|e| anyhow::anyhow!("{e}"))
            }
            Err(e) => Err(anyhow::anyhow!("{e}")),
        }
    }

    pub async fn update_item(&self, entry_id: &str, edit: ItemEdit) -> anyhow::Result<PendingEdit> {
        if edit.is_empty() {
            return Err(keyward_core::fault!("err.nothingToSave"));
        }
        let snapshot = self.snapshot();
        let previous = snapshot
            .ciphers
            .iter()
            .find(|c| c.id == entry_id)
            .cloned()
            .ok_or_else(|| keyward_core::fault!("err.itemNotFoundSync"))?;
        let ring = self.ring().ok_or_else(|| keyward_core::fault!("err.vaultLocked"))?;
        let mut next = previous.clone();

        if let Some(name) = &edit.name {
            next.name = self.encrypt_for(&previous, name)?;
        }
        if let Some(notes) = &edit.notes {
            next.notes = if notes.is_empty() { None } else { Some(self.encrypt_for(&previous, notes)?) };
        }
        // A replaced password goes into the item's history, as Bitwarden's own
        // clients do: a new password the site then refuses must not cost the
        // old one.
        if let Some(new) = &edit.password {
            let old = previous
                .login
                .as_ref()
                .and_then(|l| l.password.as_deref())
                .and_then(|p| crate::read::decrypt_for(&ring, &previous, p));
            if let Some(old) = old.filter(|o| !o.is_empty() && o.as_str() != new.as_str()) {
                let entry = serde_json::json!({
                    "password": self.encrypt_for(&previous, &old)?,
                    "lastUsedDate": iso_now(),
                });
                next.password_history = Some(push_history(next.password_history.take(), entry));
                if let Some(login) = next.login.as_mut() {
                    login.password_revision_date = Some(iso_now());
                }
            }
        }
        if let Some(login) = next.login.as_mut() {
            if let Some(v) = &edit.username {
                login.username = if v.is_empty() { None } else { Some(self.encrypt_for(&previous, v)?) };
            }
            if let Some(v) = &edit.password {
                login.password = if v.is_empty() { None } else { Some(self.encrypt_for(&previous, v)?) };
            }
            if let Some(v) = &edit.totp {
                if !v.is_empty() {
                    check_totp_secret(v)?;
                }
                login.totp = if v.is_empty() { None } else { Some(self.encrypt_for(&previous, v)?) };
            }
            if let Some(uris) = &edit.uris {
                // The list is replaced whole: a half-edit breeds duplicates
                // that get sorted out by hand later. The match type is left
                // unset — the server and other clients read its absence as "by
                // domain", which is what is expected nine times out of ten.
                login.uris = uris
                    .iter()
                    .map(|u| u.trim())
                    .filter(|u| !u.is_empty())
                    .map(|u| {
                        Ok(keyward_bw::model::Uri {
                            uri: Some(self.encrypt_for(&previous, u)?),
                            match_type: None,
                        })
                    })
                    .collect::<anyhow::Result<Vec<_>>>()?;
            }
        }

        if let Some(on) = edit.reprompt {
            next.reprompt = u8::from(on);
        }
        if let Some(on) = edit.favorite {
            next.favorite = on;
        }

        // Forgetting the old passwords: the history goes to the server empty,
        // not absent — an absent one is left as it was.
        if edit.clear_password_history {
            if previous.password_history.as_ref().and_then(|h| h.as_array()).is_none_or(|h| h.is_empty()) {
                return Err(keyward_core::fault!("err.passwordHistoryEmpty"));
            }
            next.password_history = Some(serde_json::Value::Array(Vec::new()));
        }

        // A new key for an ssh key item: all three parts are replaced at
        // once, the public key and the fingerprint derived from the private
        // one — a pasted public key that does not match its private key would
        // make the agent offer one key and sign with another.
        if let Some(key) = &edit.ssh_key {
            if previous.ssh_key.is_none() && previous.kind != 5 {
                return Err(keyward_core::fault!("err.sshKeyNotAKeyItem"));
            }
            let comment = match &edit.name {
                Some(n) => n.trim().to_string(),
                None => crate::read::decrypt_for(&ring, &previous, &previous.name).unwrap_or_default(),
            };
            next.ssh_key = Some(self.sealed_ssh_key(&previous, key, &comment)?);
        }

        // Removing a passkey: the array stays encrypted as it is, and the
        // element with that credentialId simply falls out of it. The key is
        // copied nowhere and decrypted never.
        if !edit.remove_passkeys.is_empty() {
            let keys = ring
                .base(previous.organization_id.as_deref())
                .ok_or_else(|| keyward_core::fault!("err.noKeysForItem"))?;
            let item_key = ring.item(&previous);
            let dec = |v: &str| crate::read::decrypt(v, keys, item_key.as_ref());
            if let Some(login) = next.login.as_mut() {
                if let Some(serde_json::Value::Array(list)) = login.fido2_credentials.as_mut() {
                    let before = list.len();
                    list.retain(|c| {
                        let id = c.get("credentialId").and_then(|v| v.as_str()).and_then(dec);
                        !id.is_some_and(|id| edit.remove_passkeys.contains(&id))
                    });
                    if list.len() == before {
                        return Err(keyward_core::fault!("err.passkeyGone"));
                    }
                }
            }
        }

        // Passkeys merged in from another record, sealed for this one by the
        // daemon already.
        if !edit.add_passkeys.is_empty() {
            let login = next.login.as_mut().ok_or_else(|| keyward_core::fault!("err.mergeOnlyLogins"))?;
            match login.fido2_credentials.get_or_insert_with(|| serde_json::Value::Array(Vec::new())) {
                serde_json::Value::Array(list) => list.extend(edit.add_passkeys.iter().cloned()),
                _ => return Err(keyward_core::fault!("err.passkeyDamaged")),
            }
        }

        // Cards and identities: each kind of item has its own set of fields,
        // and until now only the name, the note and the login could be edited —
        // the rest could be changed only in somebody else's client.
        if let Some(edit) = &edit.card {
            let card = next.card.get_or_insert_with(Default::default);
            let seal = |v: &str| crate::read::encrypt_for(&ring, &previous, v);
                if let Some(v) = &edit.cardholder_name {
                    card.cardholder_name = if v.trim().is_empty() { None } else { Some(seal(v)?) };
                }
                if let Some(v) = &edit.number {
                    card.number = if v.trim().is_empty() { None } else { Some(seal(v)?) };
                }
                if let Some(v) = &edit.brand {
                    card.brand = if v.trim().is_empty() { None } else { Some(seal(v)?) };
                }
                if let Some(v) = &edit.exp_month {
                    card.exp_month = if v.trim().is_empty() { None } else { Some(seal(v)?) };
                }
                if let Some(v) = &edit.exp_year {
                    card.exp_year = if v.trim().is_empty() { None } else { Some(seal(v)?) };
                }
                if let Some(v) = &edit.code {
                    card.code = if v.trim().is_empty() { None } else { Some(seal(v)?) };
                }
        }

        if let Some(edit) = &edit.identity {
            let who = next.identity.get_or_insert_with(Default::default);
            let seal = |v: &str| crate::read::encrypt_for(&ring, &previous, v);
                if let Some(v) = &edit.title {
                    who.title = if v.trim().is_empty() { None } else { Some(seal(v)?) };
                }
                if let Some(v) = &edit.first_name {
                    who.first_name = if v.trim().is_empty() { None } else { Some(seal(v)?) };
                }
                if let Some(v) = &edit.middle_name {
                    who.middle_name = if v.trim().is_empty() { None } else { Some(seal(v)?) };
                }
                if let Some(v) = &edit.last_name {
                    who.last_name = if v.trim().is_empty() { None } else { Some(seal(v)?) };
                }
                if let Some(v) = &edit.username {
                    who.username = if v.trim().is_empty() { None } else { Some(seal(v)?) };
                }
                if let Some(v) = &edit.company {
                    who.company = if v.trim().is_empty() { None } else { Some(seal(v)?) };
                }
                if let Some(v) = &edit.email {
                    who.email = if v.trim().is_empty() { None } else { Some(seal(v)?) };
                }
                if let Some(v) = &edit.phone {
                    who.phone = if v.trim().is_empty() { None } else { Some(seal(v)?) };
                }
                if let Some(v) = &edit.address1 {
                    who.address1 = if v.trim().is_empty() { None } else { Some(seal(v)?) };
                }
                if let Some(v) = &edit.address2 {
                    who.address2 = if v.trim().is_empty() { None } else { Some(seal(v)?) };
                }
                if let Some(v) = &edit.address3 {
                    who.address3 = if v.trim().is_empty() { None } else { Some(seal(v)?) };
                }
                if let Some(v) = &edit.city {
                    who.city = if v.trim().is_empty() { None } else { Some(seal(v)?) };
                }
                if let Some(v) = &edit.state {
                    who.state = if v.trim().is_empty() { None } else { Some(seal(v)?) };
                }
                if let Some(v) = &edit.postal_code {
                    who.postal_code = if v.trim().is_empty() { None } else { Some(seal(v)?) };
                }
                if let Some(v) = &edit.country {
                    who.country = if v.trim().is_empty() { None } else { Some(seal(v)?) };
                }
                if let Some(v) = &edit.ssn {
                    who.ssn = if v.trim().is_empty() { None } else { Some(seal(v)?) };
                }
                if let Some(v) = &edit.passport_number {
                    who.passport_number = if v.trim().is_empty() { None } else { Some(seal(v)?) };
                }
                if let Some(v) = &edit.license_number {
                    who.license_number = if v.trim().is_empty() { None } else { Some(seal(v)?) };
                }
        }

        if let Some(folder) = &edit.folder_id {
            next.folder_id = folder.clone();
        }

        if !edit.remove_custom.is_empty() {
            next.fields.retain(|f| {
                let name = f.name.as_deref().and_then(|n| crate::read::decrypt_for(&ring, &previous, n));
                !name.is_some_and(|n| {
                    edit.remove_custom.iter().any(|drop| drop.trim().eq_ignore_ascii_case(n.trim()))
                })
            });
        }
        for field in &edit.custom {
            let (name, value) = (&field.name, &field.value);
            let linked = field.kind == 3;
            // A linked field has nothing to encrypt: it points at a field of
            // the item.
            let encrypted =
                if linked { None } else { Some(self.encrypt_for(&previous, value)?) };
            let existing = next.fields.iter_mut().find(|f| {
                f.name
                    .as_deref()
                    .and_then(|n| crate::read::decrypt_for(&ring, &previous, n))
                    .is_some_and(|n| n.trim().eq_ignore_ascii_case(name))
            });
            match existing {
                Some(f) => {
                    f.value = encrypted;
                    f.kind = field.kind;
                    f.linked_id = linked.then_some(field.linked_id).flatten();
                }
                // The new field's type comes from the edit: a zero used to
                // stand here, and a hidden field was created in the clear.
                None => next.fields.push(keyward_bw::model::Field {
                    kind: field.kind,
                    name: Some(self.encrypt_for(&previous, name)?),
                    value: encrypted,
                    linked_id: linked.then_some(field.linked_id).flatten(),
                }),
            }
        }

        self.queue_edit(previous, next, &edit.labels()).await
    }

    /// Puts an item's new version into the queue of edits and sends it: the
    /// queue is what makes an edit survive a crash and lets it be rolled back.
    pub(crate) async fn queue_edit(
        &self,
        previous: keyward_bw::model::Cipher,
        next: keyward_bw::model::Cipher,
        labels: &[String],
    ) -> anyhow::Result<PendingEdit> {
        let ring = self.ring().ok_or_else(|| keyward_core::fault!("err.vaultLocked"))?;
        let entry_id = previous.id.as_str();
        let meta = PendingEdit {
            id: edit_id(),
            account_id: self.account.id.clone(),
            entry_id: entry_id.to_string(),
            entry_name: crate::read::decrypt_for(&ring, &previous, &previous.name)
                .unwrap_or_else(|| entry_id.to_string()),
            created_at: crate::edits::now_rfc3339(),
            changed: crate::edits::changed_fields(labels),
            state: crate::edits::pending_state(),
            locked: false,
            damaged: false,
        };

        let mut stored = crate::edits::StoredEdit { meta, next, previous };
        // Into the queue before trying to send: if the process dies right
        // now, the edit must not disappear.
        crate::edits::save(&ring, &stored)?;

        self.push_edit(&mut stored).await;
        crate::edits::save(&ring, &stored)?;
        if matches!(stored.meta.state, EditState::Pushed) {
            self.sync().await?;
        }
        Ok(stored.meta)
    }

    async fn push_edit(&self, stored: &mut crate::edits::StoredEdit) {
        match self.write_cipher(&stored.next).await {
            Ok(()) => stored.meta.state = EditState::Pushed,
            Err(e) => {
                stored.meta.state = EditState::Pending {
                    attempts: attempts_of(&stored.meta.state) + 1,
                    last_error: Some(e.to_string()),
                }
            }
        }
    }

    /// Sending a stuck edit again.
    pub async fn retry_edit(&self, id: &str) -> anyhow::Result<PendingEdit> {
        let ring = self.ring().ok_or_else(|| keyward_core::fault!("err.vaultLocked"))?;
        let mut stored = crate::edits::load(&ring, &self.account.id, id)?;
        self.push_edit(&mut stored).await;
        crate::edits::save(&ring, &stored)?;
        if matches!(stored.meta.state, EditState::Pushed) {
            self.sync().await?;
        }
        Ok(stored.meta)
    }

    /// Rolling back: the version of the item from before the edit goes to the
    /// server.
    pub async fn rollback_edit(&self, id: &str) -> anyhow::Result<PendingEdit> {
        let ring = self.ring().ok_or_else(|| keyward_core::fault!("err.vaultLocked"))?;
        let mut stored = crate::edits::load(&ring, &self.account.id, id)?;
        std::mem::swap(&mut stored.next, &mut stored.previous);
        self.push_edit(&mut stored).await;
        if matches!(stored.meta.state, EditState::Pushed) {
            stored.meta.state = EditState::RolledBack;
            crate::edits::save(&ring, &stored)?;
            self.sync().await?;
        } else {
            // The rollback did not go through: put it back as it was, so that
            // a retry sends the edit and not its undoing.
            std::mem::swap(&mut stored.next, &mut stored.previous);
            crate::edits::save(&ring, &stored)?;
        }
        Ok(stored.meta)
    }

    /// A new password for a login, made and saved here: it never passes
    /// through the window, so it is in no log and no answer. The old one goes
    /// into the item's history; the new one is then copied the usual way.
    pub async fn regenerate_password(
        &self,
        entry_id: &str,
        spec: &keyward_core::generator::Spec,
    ) -> anyhow::Result<PendingEdit> {
        let password = keyward_core::generator::password(spec).map_err(|e| anyhow::anyhow!(e))?;
        self.update_item(entry_id, ItemEdit { password: Some(password.into()), ..Default::default() }).await
    }

    /// Puts back the TOTP secret an item had before a one-time code was saved
    /// over it. The journal of edits keeps each edit's previous version; the
    /// newest of them whose TOTP field is a real secret is the one taken. Only
    /// the TOTP field changes: everything else edited since stays as it is.
    pub async fn restore_totp(&self, entry_id: &str) -> anyhow::Result<PendingEdit> {
        let secret = {
            let ring = self.ring().ok_or_else(|| keyward_core::fault!("err.vaultLocked"))?;
            crate::edits::of_entry(&ring, &self.account.id, entry_id)
                .into_iter()
                .find_map(|stored| {
                    let raw = stored.previous.login.as_ref()?.totp.as_deref()?;
                    let plain = crate::read::decrypt_for(&ring, &stored.previous, raw)?;
                    check_totp_secret(&plain).is_ok().then_some(plain)
                })
                .ok_or_else(|| keyward_core::fault!("err.totpNothingToRestore"))?
        };
        self.update_item(entry_id, ItemEdit { totp: Some(secret.into()), ..Default::default() }).await
    }

    /// Which of the records hold each field of a login and which of them
    /// agree on it, compared here: no value leaves the daemon.
    pub fn compare_for_merge(&self, entry_ids: &[String]) -> anyhow::Result<keyward_core::merge::MergeComparison> {
        if entry_ids.len() < 2 {
            return Err(keyward_core::fault!("err.mergeNothing"));
        }
        let snapshot = self.snapshot();
        let ring = self.ring().ok_or_else(|| keyward_core::fault!("err.vaultLocked"))?;
        let ciphers = entry_ids.iter().map(|id| live_cipher(&snapshot, id)).collect::<anyhow::Result<Vec<_>>>()?;
        crate::merge::compare(&ring, &ciphers)
    }

    /// Merges records into one: the kept record takes the plan's fields and
    /// every record's addresses, and only once it is saved on the server do
    /// the others go to the trash. An edit left waiting in the queue keeps
    /// them where they are, and says so.
    pub async fn merge_items(&self, plan: &keyward_core::merge::MergePlan) -> anyhow::Result<()> {
        plan.check().map_err(|code| keyward_core::fault!(code))?;
        let edit = {
            let snapshot = self.snapshot();
            let ring = self.ring().ok_or_else(|| keyward_core::fault!("err.vaultLocked"))?;
            let keeper = live_cipher(&snapshot, &plan.keeper)?;
            let others = plan.others.iter().map(|id| live_cipher(&snapshot, id)).collect::<anyhow::Result<Vec<_>>>()?;
            crate::merge::edit_for(&ring, keeper, &others, plan)?
        };
        // Nothing to take and no address to add: the kept record stays as it
        // is and the copies simply go.
        if !edit.is_empty() {
            let saved = self.update_item(&plan.keeper, edit).await?;
            if !matches!(saved.state, EditState::Pushed) {
                return Err(keyward_core::fault!("err.mergeKeeperWaiting"));
            }
        }
        for id in &plan.others {
            self.trash_item(id).await?;
        }
        Ok(())
    }

    // -- For plugins ----------------------------------------------------------
    //
    // Everything a plugin can do to the vault's items goes through these four
    // methods. There are no keys, tokens or ciphertexts here: a plugin asks for
    // a field of one item, and the vault decides whether to hand it over.

    /// Items marked with the plugin's own field. The values of hidden fields
    /// are not given out: it is visible that a field exists, and the value is
    /// fetched with `secret`.
    pub fn items_tagged(&self, field: &str) -> Vec<TaggedItem> {
        let Some(ring) = self.ring() else { return Vec::new() };
        let snapshot = self.snapshot();
        let mut out: Vec<TaggedItem> = snapshot
            .ciphers
            .iter()
            .filter(|c| !c.in_trash())
            .filter(|c| crate::read::field_of(&ring, c, field).is_some())
            .map(|c| TaggedItem {
                id: c.id.clone(),
                name: crate::read::decrypt_for(&ring, c, &c.name).unwrap_or_default(),
                hidden: crate::read::field_of(&ring, c, crate::read::HIDDEN_MARK).is_some(),
                owned: c.organization_id.is_none(),
                fields: c
                    .fields
                    .iter()
                    .filter_map(|f| {
                        let name = crate::read::decrypt_for(&ring, c, f.name.as_deref()?)?;
                        let value = if f.kind == 1 {
                            String::new()
                        } else {
                            f.value.as_deref().and_then(|v| crate::read::decrypt_for(&ring, c, v)).unwrap_or_default()
                        };
                        Some((name, value))
                    })
                    .collect(),
            })
            .collect();
        out.sort_by(|a, b| a.name.to_lowercase().cmp(&b.name.to_lowercase()));
        out
    }

    /// Create a note with fields of one's own. A hidden one is a plugin's
    /// service item and stays out of keyward's list.
    pub async fn create_plugin_note(
        &self,
        name: &str,
        fields: &[(String, String)],
        hidden: bool,
    ) -> anyhow::Result<String> {
        let mut values: Vec<(&str, String)> = fields.iter().map(|(k, v)| (k.as_str(), v.clone())).collect();
        if hidden {
            values.push((crate::read::HIDDEN_MARK, "plugin".to_string()));
        }
        self.create_hidden_note(name, &values).await?;
        // The identifier is known only after a sync: the server issues it.
        let mark = fields.first().map(|(k, _)| k.clone()).unwrap_or_default();
        self.items_tagged(&mark)
            .into_iter()
            .find(|i| i.name == name)
            .map(|i| i.id)
            .ok_or_else(|| keyward_core::fault!("err.itemCreatedButMissing"))
    }

    /// Write one's own fields. An empty value removes the field: "unbind"
    /// rests on that.
    pub async fn set_item_fields(&self, entry_id: &str, fields: &[(String, String)]) -> anyhow::Result<()> {
        let keep: Vec<(&str, String)> =
            fields.iter().filter(|(_, v)| !v.is_empty()).map(|(k, v)| (k.as_str(), v.clone())).collect();
        let drop: Vec<String> = fields.iter().filter(|(_, v)| v.is_empty()).map(|(k, _)| k.clone()).collect();
        if !keep.is_empty() {
            self.write_fields(entry_id, &keep).await?;
        }
        if drop.is_empty() {
            return Ok(());
        }
        let snapshot = self.snapshot();
        let mut cipher = snapshot
            .ciphers
            .iter()
            .find(|c| c.id == entry_id)
            .cloned()
            .ok_or_else(|| keyward_core::fault!("err.itemNotFoundSync"))?;
        let ring = self.ring().ok_or_else(|| keyward_core::fault!("err.vaultLocked"))?;
        let before = cipher.clone();
        cipher.fields.retain(|f| {
            !f.name
                .as_deref()
                .and_then(|n| crate::read::decrypt_for(&ring, &before, n))
                .is_some_and(|n| drop.iter().any(|d| n.trim().eq_ignore_ascii_case(d)))
        });
        self.write_cipher(&cipher).await?;
        self.sync().await?;
        Ok(())
    }

    /// The names of an item's custom fields: one picks from them where the
    /// unseal keys lie. The values are not given out — the interface needs the
    /// names alone.
    pub fn note_field_names(&self, entry_id: &str) -> Vec<String> {
        let Some(ring) = self.ring() else { return Vec::new() };
        let snapshot = self.snapshot();
        let Some(cipher) = snapshot.ciphers.iter().find(|c| c.id == entry_id) else {
            return Vec::new();
        };
        cipher
            .fields
            .iter()
            .filter_map(|f| f.name.as_deref())
            .filter_map(|n| crate::read::decrypt_for(&ring, cipher, n))
            .filter(|n| !n.trim().is_empty() && !n.trim().to_lowercase().starts_with("kw-"))
            .collect()
    }

    /// The values of the chosen fields of an item: the shares of the unseal
    /// key. Empty ones are skipped: feeding an empty share loses a step of the
    /// threshold.
    pub fn note_field_values(&self, entry_id: &str, names: &[String]) -> Vec<String> {
        let Some(ring) = self.ring() else { return Vec::new() };
        let snapshot = self.snapshot();
        let Some(cipher) = snapshot.ciphers.iter().find(|c| c.id == entry_id) else {
            return Vec::new();
        };
        names
            .iter()
            .filter_map(|n| crate::read::field_of(&ring, cipher, n))
            .filter(|v| !v.trim().is_empty())
            .collect()
    }

    /// The generator's history.
    ///
    /// It lies on disk encrypted with the vault's key, the same one that
    /// closes the items themselves. So it reads only while the vault is open,
    /// and the file without the master password is useless. Keeping such a
    /// thing in the clear in the webview's localStorage would mean holding a
    /// copy of secrets outside the vault.
    pub fn history(&self) -> anyhow::Result<History> {
        let Some(ring) = self.ring() else { return Err(keyward_core::fault!("err.vaultLocked")) };
        let raw = std::fs::read_to_string(keyward_core::paths::history_file(&self.account.id))
            .unwrap_or_else(|_| "{}".into());
        let stored: StoredHistory = serde_json::from_str(&raw).unwrap_or_default();
        let plain = |list: &[String]| -> Vec<String> {
            list.iter().filter_map(|v| crate::read::decrypt_blob(&ring, v)).collect()
        };
        Ok(History {
            made: plain(&stored.made),
            taken: plain(&stored.taken),
            recent: plain(&stored.recent),
        })
    }

    /// Appends a value to one of the history's lists.
    pub fn remember_generated(&self, taken: bool, value: &str) -> anyhow::Result<History> {
        let mut current = self.history()?;
        let list = if taken { &mut current.taken } else { &mut current.made };
        list.retain(|v| v != value);
        list.insert(0, value.to_string());
        list.truncate(HISTORY_KEEP);
        self.write_history(&current)?;
        Ok(current)
    }

    /// Remembers that an item was opened.
    ///
    /// Identifiers, not names: a name is already the vault's contents. But
    /// they are encrypted along with the rest too, so that the file cannot be
    /// made into a list of what a person uses.
    pub fn remember_opened(&self, entry_id: &str) -> anyhow::Result<()> {
        let mut current = self.history()?;
        current.recent.retain(|v| v != entry_id);
        current.recent.insert(0, entry_id.to_string());
        current.recent.truncate(RECENT_KEEP);
        self.write_history(&current)
    }

    /// Erases one of the lists.
    pub fn forget_generated(&self, taken: bool) -> anyhow::Result<History> {
        let mut current = self.history()?;
        if taken {
            current.taken.clear();
        } else {
            current.made.clear();
        }
        self.write_history(&current)?;
        Ok(current)
    }

    fn write_history(&self, history: &History) -> anyhow::Result<()> {
        let ring = self.ring().ok_or_else(|| keyward_core::fault!("err.vaultLocked"))?;
        let seal = |list: &[String]| -> anyhow::Result<Vec<String>> {
            list.iter().map(|v| crate::read::encrypt_blob(&ring, v)).collect()
        };
        let stored = StoredHistory {
            made: seal(&history.made)?,
            taken: seal(&history.taken)?,
            recent: seal(&history.recent)?,
        };
        let path = keyward_core::paths::history_file(&self.account.id);
        // The file is encrypted, but the permissions are ours all the same,
        // from the first byte: the fewer eyes the better.
        keyward_core::paths::write_private(&path, serde_json::to_string(&stored)?.as_bytes())?;
        Ok(())
    }

    /// Every hidden item holding a root token.
    ///
    /// There can be several, one per Vault. The token's value is not given
    /// out — only what it can be recognised and revoked by.
    pub fn root_notes(&self) -> Vec<(String, String, u64)> {
        let Some(ring) = self.ring() else { return Vec::new() };
        let snapshot = self.snapshot();
        snapshot
            .ciphers
            .iter()
            // One's own, not an organisation's: see `root_note_id`.
            .filter(|c| c.organization_id.is_none() && !c.in_trash())
            .filter(|c| crate::read::field_of(&ring, c, crate::read::HIDDEN_MARK).is_some())
            .filter_map(|c| {
                let addr = crate::read::field_of(&ring, c, crate::read::ROOT_ADDR)?;
                // An empty value is what stays after a revocation: the item
                // is kept for the trail, but the token is no longer in it.
                let token = crate::read::field_of(&ring, c, "kw-vault-token")?;
                if token.trim().is_empty() {
                    return None;
                }
                let issued = crate::read::field_of(&ring, c, "kw-root-issued")
                    .and_then(|v| v.trim().parse::<u64>().ok())
                    .unwrap_or(0);
                Some((c.id.clone(), addr, issued))
            })
            .collect()
    }

    /// Creates a secure note that keyward's list does not show.
    async fn create_hidden_note(&self, name: &str, values: &[(&str, String)]) -> anyhow::Result<()> {
        let mut cipher = keyward_bw::model::Cipher {
            id: String::new(),
            kind: 2,
            name: String::new(),
            secure_note: Some(serde_json::json!({ "type": 0 })),
            ..Default::default()
        };
        cipher.name = self.encrypt_for(&cipher, name)?;
        for (key, value) in values {
            cipher.fields.push(keyward_bw::model::Field {
                // Type 1 is hidden: the value is not shown until it is opened.
                kind: 1,
                name: Some(self.encrypt_for(&cipher, key)?),
                value: Some(self.encrypt_for(&cipher, value)?),
                linked_id: None,
            });
        }

        let (server, _) = self.identity();
        let token = self.db()?.access_token.ok_or_else(|| keyward_core::fault!("err.noTokens"))?;
        match crate::bwapi::post_cipher(&server, &token, &cipher, &[]).await {
            Ok(_id) => {}
            Err(crate::bwapi::WriteError::Unauthorized) => {
                self.sync().await?;
                let token =
                    self.db()?.access_token.ok_or_else(|| keyward_core::fault!("err.noTokens"))?;
                crate::bwapi::post_cipher(&server, &token, &cipher, &[])
                    .await
                    .map_err(|e| anyhow::anyhow!("{e}"))?;
            }
            Err(e) => return Err(anyhow::anyhow!("{e}")),
        }
        self.sync().await?;
        Ok(())
    }

    /// Creates an organisation.
    ///
    /// It is assembled out of four encrypted parts, and all of them are made
    /// here, because the server only stores them:
    ///
    /// * the organisation key — 64 random bytes, encrypted with the owner's
    ///   **public** key. That is exactly why the owner can later hand this key
    ///   to a new member without knowing their password;
    /// * the organisation's own RSA pair: the public half goes as it is, the
    ///   private one encrypted with the organisation key;
    /// * the name of the default collection — with the organisation key too.
    pub async fn create_org(&self, name: &str, billing_email: &str) -> anyhow::Result<String> {
        use keyward_bw::crypto::{EncString, SymmetricKey};
        use rsa::pkcs8::EncodePrivateKey as _;
        use rsa::traits::PublicKeyParts as _;

        let name = name.trim();
        if name.is_empty() {
            return Err(keyward_core::fault!("err.orgNeedsName"));
        }
        let billing_email = billing_email.trim();
        if !billing_email.contains('@') {
            return Err(keyward_core::fault!("err.billingEmailRequired"));
        }

        // The owner's public key is derived from their private one: the
        // snapshot holds only the private one, and only encrypted.
        let mine = self.user_private_key()?;
        let public = rsa::RsaPublicKey::from(&mine);
        let _ = public.size();

        let mut org_key = [0u8; 64];
        getrandom::fill(&mut org_key).map_err(|e| keyward_core::fault!("err.noRandomness", "reason" => e))?;
        let sealed_org_key = keyward_bw::crypto::encrypt_rsa(&public, &org_key)?;
        let org_sym = SymmetricKey::from_bytes(&org_key)?;

        // The organisation's own pair. Two thousand and forty-eight bits is
        // what the official clients issue; some implementations of the server
        // will not take more.
        let mut rng = rand::rngs::OsRng;
        let org_private = rsa::RsaPrivateKey::new(&mut rng, 2048)
            .map_err(|e| keyward_core::fault!("err.orgKeyNotGenerated", "reason" => e))?;
        let org_public = rsa::RsaPublicKey::from(&org_private);
        let public_der = {
            use rsa::pkcs8::EncodePublicKey as _;
            org_public
                .to_public_key_der()
                .map_err(|e| keyward_core::fault!("err.publicKeyEncode", "reason" => e))?
        };
        let private_der = org_private
            .to_pkcs8_der()
            .map_err(|e| keyward_core::fault!("err.privateKeyEncode", "reason" => e))?;

        use base64::Engine as _;
        let request = keyward_bw::orgs::NewOrg {
            name: name.to_string(),
            billing_email: billing_email.to_string(),
            key: sealed_org_key,
            public_key: base64::engine::general_purpose::STANDARD.encode(public_der.as_bytes()),
            encrypted_private_key: EncString::encrypt(&org_sym, private_der.as_bytes())?.to_string(),
            collection_name: EncString::encrypt(&org_sym, b"Default Collection")?.to_string(),
        };

        let (server, _) = self.identity();
        let token = self.db()?.access_token.ok_or_else(|| keyward_core::fault!("err.noTokens"))?;
        let id = keyward_bw::orgs::create(&server, &token, &request).await?;
        tracing::info!(%name, %id, "the organisation was created");
        self.sync().await?;
        Ok(id)
    }

    /// Renaming an organisation.
    pub async fn update_org(&self, id: &str, name: &str, billing_email: &str) -> anyhow::Result<()> {
        let name = name.trim();
        if name.is_empty() {
            return Err(keyward_core::fault!("err.orgNeedsName"));
        }
        let (server, _) = self.identity();
        let token = self.db()?.access_token.ok_or_else(|| keyward_core::fault!("err.noTokens"))?;
        keyward_bw::orgs::update(&server, &token, id, name, billing_email.trim()).await?;
        tracing::info!(%id, %name, "the organisation was renamed");
        self.sync().await?;
        Ok(())
    }

    /// Deleting an organisation.
    ///
    /// The server asks for the hash of the master password, and it is right
    /// to: deleting takes the organisation's items away from every member. The
    /// password comes from the interface and turns into a hash right here, the
    /// same way it is computed at login.
    pub async fn delete_org(&self, id: &str, master_password: &str) -> anyhow::Result<()> {
        let hash = self.password_hash(master_password)?;
        let (server, _) = self.identity();
        let token = self.db()?.access_token.ok_or_else(|| keyward_core::fault!("err.noTokens"))?;
        keyward_bw::orgs::delete(&server, &token, id, &hash).await?;
        tracing::warn!(%id, "the organisation was deleted");
        self.sync().await?;
        Ok(())
    }

    /// Creates a folder of one's own.
    pub async fn create_folder(&self, name: &str) -> anyhow::Result<String> {
        let sealed = self.user_text(name)?;
        let (server, token) = self.server_and_token()?;
        let id = keyward_bw::folders::create(&server, &token, &sealed).await?;
        tracing::info!(%id, "the folder was created");
        self.sync().await?;
        Ok(id)
    }

    pub async fn rename_folder(&self, folder_id: &str, name: &str) -> anyhow::Result<()> {
        let sealed = self.user_text(name)?;
        let (server, token) = self.server_and_token()?;
        keyward_bw::folders::rename(&server, &token, folder_id, &sealed).await?;
        self.sync().await?;
        Ok(())
    }

    /// Deletes a folder. Its items stay, without a folder.
    pub async fn delete_folder(&self, folder_id: &str) -> anyhow::Result<()> {
        let (server, token) = self.server_and_token()?;
        keyward_bw::folders::delete(&server, &token, folder_id).await?;
        tracing::warn!(%folder_id, "the folder was deleted");
        self.sync().await?;
        Ok(())
    }

    /// Creates a collection in an organisation.
    pub async fn create_collection(&self, org_id: &str, name: &str) -> anyhow::Result<String> {
        let sealed = self.org_text(org_id, name)?;
        let (server, token) = self.server_and_token()?;
        let id = keyward_bw::orgs::create_collection(&server, &token, org_id, &sealed).await?;
        tracing::info!(%org_id, %name, %id, "the collection was created");
        self.sync().await?;
        Ok(id)
    }

    pub async fn rename_collection(
        &self,
        org_id: &str,
        collection_id: &str,
        name: &str,
    ) -> anyhow::Result<()> {
        let sealed = self.org_text(org_id, name)?;
        let (server, token) = self.server_and_token()?;
        keyward_bw::orgs::rename_collection(&server, &token, org_id, collection_id, &sealed).await?;
        self.sync().await?;
        Ok(())
    }

    pub async fn delete_collection(&self, org_id: &str, collection_id: &str) -> anyhow::Result<()> {
        let (server, token) = self.server_and_token()?;
        keyward_bw::orgs::delete_collection(&server, &token, org_id, collection_id).await?;
        tracing::warn!(%org_id, %collection_id, "the collection was deleted");
        self.sync().await?;
        Ok(())
    }

    /// Invites a member.
    pub async fn invite_member(&self, org_id: &str, email: &str, role: OrgRole) -> anyhow::Result<()> {
        let role = self.may_grant(org_id, role)?;
        let email = email.trim();
        if !email.contains('@') {
            return Err(keyward_core::fault!("err.memberEmailRequired"));
        }
        let (server, token) = self.server_and_token()?;
        keyward_bw::orgs::invite(&server, &token, org_id, email, role).await?;
        tracing::info!(%org_id, %email, role, "the member was invited");
        self.sync().await?;
        Ok(())
    }

    /// Invites people with one role and the same access.
    pub async fn invite_members(
        &self,
        org_id: &str,
        emails: &[String],
        role: OrgRole,
        access_all: bool,
        access: &[CollectionAccess],
    ) -> anyhow::Result<()> {
        let role = self.may_grant(org_id, role)?;
        let emails: Vec<String> = emails.iter().map(|e| e.trim().to_string()).collect();
        if emails.is_empty() || emails.iter().any(|e| !e.contains('@')) {
            return Err(keyward_core::fault!("err.memberEmailRequired"));
        }
        let grants = grants(access_all, access)?;
        let (server, token) = self.server_and_token()?;
        keyward_bw::orgs::invite_with_access(&server, &token, org_id, &emails, role, access_all, &grants).await?;
        tracing::info!(%org_id, count = emails.len(), role, access_all, collections = grants.len(), "members were invited");
        self.sync().await?;
        Ok(())
    }

    /// Changes a member's role and access in one step.
    pub async fn set_member(
        &self,
        org_id: &str,
        member_id: &str,
        role: OrgRole,
        access_all: bool,
        access: &[CollectionAccess],
    ) -> anyhow::Result<()> {
        self.may_edit_member(org_id, member_id).await?;
        let code = self.may_grant(org_id, role)?;
        let grants = grants(access_all, access)?;
        let (server, token) = self.server_and_token()?;
        keyward_bw::orgs::set_member(&server, &token, org_id, member_id, code, access_all, &grants).await?;
        tracing::info!(%org_id, %member_id, code, access_all, collections = grants.len(), "the member was changed");
        self.sync().await?;
        Ok(())
    }

    pub async fn set_member_role(
        &self,
        org_id: &str,
        member_id: &str,
        role: OrgRole,
    ) -> anyhow::Result<()> {
        self.may_edit_member(org_id, member_id).await?;
        let code = self.may_grant(org_id, role)?;
        let (server, token) = self.server_and_token()?;
        keyward_bw::orgs::set_role(&server, &token, org_id, member_id, code).await?;
        self.sync().await?;
        Ok(())
    }

    pub async fn remove_member(&self, org_id: &str, member_id: &str) -> anyhow::Result<()> {
        self.may_edit_member(org_id, member_id).await?;
        let (server, token) = self.server_and_token()?;
        keyward_bw::orgs::remove_member(&server, &token, org_id, member_id).await?;
        tracing::warn!(%org_id, %member_id, "the member was removed");
        self.sync().await?;
        Ok(())
    }

    /// The member's fingerprint: five words from the public key the server
    /// gives for them now, salted with their user id. The owner compares them
    /// with the member out of band before confirming; the very same words come
    /// back with the confirm.
    pub async fn member_fingerprint(&self, user_id: &str) -> anyhow::Result<Vec<String>> {
        let (server, token) = self.server_and_token()?;
        let public_b64 = keyward_bw::orgs::user_public_key(&server, &token, user_id).await?;
        let (_, words) = crate::fingerprint::member_key(user_id, &public_b64)?;
        Ok(words)
    }

    /// Confirms a member by handing them the organisation key.
    ///
    /// The key is encrypted with the **member's public key**, which we take
    /// from the server. Only they will be able to decrypt it — the server still
    /// knows neither the organisation key nor what lies in the organisation.
    /// `fingerprint` is the words the person was shown and compared: the key
    /// fetched now must make the same ones, or nothing is sealed — a key the
    /// server swapped in between is refused.
    pub async fn confirm_member(
        &self,
        org_id: &str,
        member_id: &str,
        user_id: &str,
        fingerprint: &[String],
    ) -> anyhow::Result<()> {
        let ring = self.ring().ok_or_else(|| keyward_core::fault!("err.vaultLocked"))?;
        let org_key = crate::read::org_key_bytes(&ring, org_id)
            .ok_or_else(|| keyward_core::fault!("err.noOrgKeySync"))?;

        let (server, token) = self.server_and_token()?;
        let public_b64 = keyward_bw::orgs::user_public_key(&server, &token, user_id).await?;
        let (public, words) = crate::fingerprint::member_key(user_id, &public_b64)?;
        if let Err(e) = crate::fingerprint::ensure_shown(fingerprint, &words) {
            tracing::warn!(%org_id, %member_id, "the member's key is not the one whose fingerprint was shown");
            return Err(e);
        }
        let sealed = keyward_bw::crypto::encrypt_rsa(&public, &org_key)?;

        keyward_bw::orgs::confirm_member(&server, &token, org_id, member_id, &sealed).await?;
        tracing::info!(%org_id, %member_id, "the member was confirmed");
        self.sync().await?;
        Ok(())
    }

    /// The key plugins' secrets in the keychain are sealed with: derived from
    /// the vault's own key, so it exists only while the vault is open and
    /// only in memory. A secret sealed under one account opens under no other.
    pub fn plugin_secret_key(&self) -> anyhow::Result<[u8; 32]> {
        let ring = self.ring().ok_or_else(|| keyward_core::fault!("err.vaultLocked"))?;
        let mut ikm = ring.user.enc_key().to_vec();
        ikm.extend_from_slice(ring.user.mac_key());
        let hk = hkdf::Hkdf::<sha2::Sha256>::new(Some(b"keyward"), &ikm);
        let mut key = [0u8; 32];
        hk.expand(b"plugin secrets v1", &mut key).map_err(|_| anyhow::anyhow!("the key would not derive"))?;
        Ok(key)
    }

    /// One's rights in an organisation, from the last sync.
    fn org_rights(&self, org_id: &str) -> Option<OrgRights> {
        self.snapshot().profile.organizations.iter().find(|o| o.id == org_id).map(crate::read::org_rights)
    }

    /// The server's number for a role one may hand out here, or a refusal:
    /// the window offers only these, and the daemon holds to it as well.
    fn may_grant(&self, org_id: &str, role: OrgRole) -> anyhow::Result<i32> {
        let rights = self.org_rights(org_id).ok_or_else(|| keyward_core::fault!("err.orgNotFound"))?;
        if !rights.assignable().contains(&role) {
            return Err(keyward_core::fault!("err.orgRoleNotYours"));
        }
        role.code().ok_or_else(|| keyward_core::fault!("err.orgRoleNotYours"))
    }

    /// A refusal unless one may change or remove this member.
    async fn may_edit_member(&self, org_id: &str, member_id: &str) -> anyhow::Result<()> {
        let member = self
            .org_members(org_id)
            .await?
            .into_iter()
            .find(|m| m.id == member_id)
            .ok_or_else(|| keyward_core::fault!("err.memberNotFound"))?;
        if member.can_edit {
            Ok(())
        } else {
            Err(keyward_core::fault!("err.memberNotYours"))
        }
    }

    /// A name encrypted with the organisation key.
    fn org_text(&self, org_id: &str, text: &str) -> anyhow::Result<String> {
        let text = text.trim();
        if text.is_empty() {
            return Err(keyward_core::fault!("err.nameEmpty"));
        }
        let ring = self.ring().ok_or_else(|| keyward_core::fault!("err.vaultLocked"))?;
        crate::read::encrypt_with_org(&ring, org_id, text)
    }

    /// A name encrypted with the user's own key: what a folder is named with.
    fn user_text(&self, text: &str) -> anyhow::Result<String> {
        let text = text.trim();
        if text.is_empty() {
            return Err(keyward_core::fault!("err.nameEmpty"));
        }
        let ring = self.ring().ok_or_else(|| keyward_core::fault!("err.vaultLocked"))?;
        let key = ring.base(None).ok_or_else(|| keyward_core::fault!("err.vaultLocked"))?;
        Ok(rbw::cipherstring::CipherString::encrypt_symmetric(key, text.as_bytes())
            .map_err(|e| keyward_core::fault!("err.encryptValue", "reason" => e))?
            .to_string())
    }

    /// The server address and a live access token.
    fn server_and_token(&self) -> anyhow::Result<(String, String)> {
        let (server, _) = self.identity();
        let token = self.db()?.access_token.ok_or_else(|| keyward_core::fault!("err.noTokens"))?;
        Ok((server, token))
    }

    /// The user's private key, decrypted.
    fn user_private_key(&self) -> anyhow::Result<rsa::RsaPrivateKey> {
        let ring = self.ring().ok_or_else(|| keyward_core::fault!("err.vaultLocked"))?;
        let snapshot = self.snapshot();
        let sealed = snapshot
            .profile
            .private_key
            .as_deref()
            .ok_or_else(|| keyward_core::fault!("err.noPrivateKey"))?;
        let der = crate::read::decrypt_raw(&ring, sealed)
            .ok_or_else(|| keyward_core::fault!("err.privateKeyLocked"))?;
        keyward_bw::crypto::parse_private_key(&der)
    }

    /// The master password hash, the one the server checks at login.
    fn password_hash(&self, password: &str) -> anyhow::Result<String> {
        let db = self.db()?;
        let (_, email) = self.identity();
        let key = keyward_bw::crypto::MasterKey::derive(password, &email, crate::account::kdf_of(&db)?)?;
        Ok(key.password_hash(password))
    }

    /// An organisation's members.
    ///
    /// The one place where the data does not come from a snapshot: `/api/sync`
    /// brings no members at all. So we go to the server, and if the token has
    /// expired we sync once and try again, just as on a write.
    pub async fn org_members(&self, org_id: &str) -> anyhow::Result<Vec<OrgMember>> {
        let (server, my_email) = self.identity();
        let token =
            self.db()?.access_token.ok_or_else(|| keyward_core::fault!("err.noTokens"))?;

        let users = match keyward_bw::orgs::users(&server, &token, org_id).await {
            Ok(users) => users,
            Err(e) if e.to_string() == "err.sessionExpired" => {
                self.sync().await?;
                let token = self
                    .db()?
                    .access_token
                    .ok_or_else(|| keyward_core::fault!("err.noTokens"))?;
                keyward_bw::orgs::users(&server, &token, org_id).await?
            }
            Err(e) => return Err(e),
        };

        let rights = self.org_rights(org_id);
        Ok(users
            .into_iter()
            .map(|u| {
                let email = u.email.unwrap_or_default();
                let role = OrgRole::from_code(u.kind);
                let is_you = email.eq_ignore_ascii_case(&my_email);
                OrgMember {
                    user_id: u.user_id.clone(),
                    is_you,
                    can_edit: rights.is_some_and(|r| r.can_edit(role, is_you)),
                    can_confirm: rights.is_some_and(|r| r.can_manage_users())
                        && MemberStatus::from_code(u.status) == MemberStatus::Accepted,
                    // A name is often the same as the email; showing it twice
                    // is pointless.
                    name: u.name.filter(|n| !n.trim().is_empty() && !n.eq_ignore_ascii_case(&email)),
                    id: u.id,
                    email,
                    role,
                    status: MemberStatus::from_code(u.status),
                    two_factor: u.two_factor_enabled,
                    access_all: u.access_all,
                    collections: u.collections.len(),
                    access: member_access(&u.collections),
                }
            })
            .collect())
    }

}

/// A member's collections as levels.
fn member_access(collections: &[keyward_bw::orgs::OrgUserCollection]) -> Vec<CollectionAccess> {
    collections
        .iter()
        .map(|c| CollectionAccess {
            id: c.id.clone(),
            permission: CollectionPermission::from_flags(c.read_only, c.hide_passwords, c.manage),
        })
        .collect()
}

/// Levels as the server's flags. Access to everything with a list beside it
/// says two things at once and is refused, as is a collection named twice.
fn grants(access_all: bool, access: &[CollectionAccess]) -> anyhow::Result<Vec<keyward_bw::orgs::CollectionGrant>> {
    if access_all && !access.is_empty() {
        return Err(keyward_core::fault!("err.memberAccessAllWithCollections"));
    }
    let mut seen = std::collections::HashSet::new();
    access
        .iter()
        .map(|a| {
            if !seen.insert(a.id.as_str()) {
                return Err(keyward_core::fault!("err.memberCollectionTwice"));
            }
            let (read_only, hide_passwords, manage) = a.permission.flags();
            Ok(keyward_bw::orgs::CollectionGrant { id: a.id.clone(), read_only, hide_passwords, manage })
        })
        .collect()
}

/// How many passwords are kept in each list. Twenty is enough to find "that
/// one" and too few to become an archive of secrets.
const HISTORY_KEEP: usize = 20;

/// How many recent items are remembered. Ten is exactly the list an eye takes
/// in whole, without scrolling.
const RECENT_KEEP: usize = 10;

/// The history as it lies on disk: the values are encrypted.
#[derive(Debug, Default, serde::Serialize, serde::Deserialize)]
struct StoredHistory {
    #[serde(default)]
    made: Vec<String>,
    #[serde(default)]
    taken: Vec<String>,
    #[serde(default)]
    recent: Vec<String>,
}

/// The internal outcome of an attempt to log in: being asked for a second
/// factor is not an error but a branch of the ordinary path, and mixing it
/// with real failures is not allowed.
enum LoginError {
    TwoFactor {
        providers: Vec<u8>,
        sso_email_2fa_session_token: Option<String>,
        password_hash: zeroize::Zeroizing<String>,
    },
    Other(anyhow::Error),
}

/// Picks out of what was asked for the part that really is in the trash.
///
/// A refusal covers the whole list at once rather than item by item: "delete
/// for good" is pressed once over a selection, and a partial execution would
/// go unseen.
///
/// Three separate reasons to refuse, and all three happen on a live vault:
/// the item is not in the snapshot (the snapshot is older than the vault); the
/// item is there and is not in the trash; and — separately — the server sent
/// two items with one id, only one of which is in the trash. In that last case
/// "at least one matched" would mean finishing off the live item, so all of
/// them have to match.
fn only_trashed(
    snapshot: &keyward_bw::Sync,
    entry_ids: &[String],
) -> anyhow::Result<Vec<String>> {
    let refuse = || keyward_core::fault!("err.deleteOnlyFromTrash");
    let mut out: Vec<String> = Vec::with_capacity(entry_ids.len());
    for id in entry_ids {
        let mut found = false;
        for c in snapshot.ciphers.iter().filter(|c| &c.id == id) {
            found = true;
            if !c.in_trash() {
                return Err(refuse());
            }
        }
        if !found {
            return Err(refuse());
        }
        // The same id twice in the list is one request: there is nothing to
        // delete twice.
        if !out.iter().any(|kept| kept == id) {
            out.push(id.clone());
        }
    }
    Ok(out)
}

/// Puts a refresh's tokens in the session: the new access token, and the new
/// refresh token when the server rotated one in — the old one runs out on its
/// own date.
/// A record in the vault and not in the trash: one in the trash is not merged.
fn live_cipher<'a>(snapshot: &'a keyward_bw::Sync, id: &str) -> anyhow::Result<&'a keyward_bw::model::Cipher> {
    let c = snapshot.ciphers.iter().find(|c| c.id == id).ok_or_else(|| keyward_core::fault!("err.itemNotFoundSync"))?;
    if c.in_trash() {
        return Err(keyward_core::fault!("err.mergeInTrash"));
    }
    Ok(c)
}

fn rotate(db: &mut rbw::db::Db, tokens: keyward_bw::identity::Tokens) {
    db.access_token = Some(tokens.access_token.to_string());
    if let Some(r) = tokens.refresh_token {
        db.refresh_token = Some(r.to_string());
    }
}

/// An rbw error in words that say where it went wrong. A JSON one says which
/// field of the server's answer did not read and what kind of fault it was —
/// not the value: the answer is the vault, and its words stay out of errors
/// and logs.
fn rbw_reason(e: &rbw::error::Error) -> String {
    match e {
        rbw::error::Error::Json { source } => {
            let inner = source.inner();
            format!("{e} at {} ({:?}, line {} column {})", source.path(), inner.classify(), inner.line(), inner.column())
        }
        other => other.to_string(),
    }
}

/// The account's KDF in the session's terms.
fn set_kdf(db: &mut session::Session, kdf: keyward_bw::crypto::Kdf) {
    use keyward_bw::crypto::Kdf;
    match kdf {
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
}

/// This computer's identifier on the servers. The one rbw made is kept: a new
/// one is a new device to the server, with an email about a login from it.
fn device_id() -> anyhow::Result<String> {
    let ours = keyward_core::paths::device_id_file();
    let read = |p: &std::path::Path| std::fs::read_to_string(p).ok().map(|s| s.trim().to_string()).filter(|s| !s.is_empty());
    if let Some(id) = read(&ours) {
        return Ok(id);
    }
    let id = match read(&rbw::dirs::device_id_file()) {
        Some(id) => id,
        None => {
            use rand::RngCore as _;
            let mut b = [0u8; 16];
            rand::thread_rng().fill_bytes(&mut b);
            // A version-4 UUID, as the servers expect one.
            b[6] = (b[6] & 0x0f) | 0x40;
            b[8] = (b[8] & 0x3f) | 0x80;
            let h: String = b.iter().map(|x| format!("{x:02x}")).collect();
            format!("{}-{}-{}-{}-{}", &h[0..8], &h[8..12], &h[12..16], &h[16..20], &h[20..32])
        }
    };
    if let Some(dir) = ours.parent() {
        std::fs::create_dir_all(dir).map_err(|e| keyward_core::fault!("err.sessionNotSaved", "reason" => e))?;
    }
    keyward_core::paths::write_private(&ours, id.as_bytes()).map_err(|e| keyward_core::fault!("err.sessionNotSaved", "reason" => e))?;
    Ok(id)
}

fn attempts_of(state: &EditState) -> u32 {
    match state {
        EditState::Pending { attempts, .. } => *attempts,
        _ => 0,
    }
}

/// How many former passwords an item keeps — Bitwarden's own number.
const PASSWORD_HISTORY: usize = 5;

/// The history with a former password put first, cut to its length.
fn push_history(history: Option<serde_json::Value>, entry: serde_json::Value) -> serde_json::Value {
    let mut list = match history {
        Some(serde_json::Value::Array(items)) => items,
        _ => Vec::new(),
    };
    list.insert(0, entry);
    list.truncate(PASSWORD_HISTORY);
    serde_json::Value::Array(list)
}

/// Now, as the server writes dates: `2026-09-28T10:40:00.000Z`.
fn iso_now() -> String {
    let secs = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map(|d| d.as_secs() as i64)
        .unwrap_or(0);
    iso_at(secs)
}

/// A Unix time as an ISO 8601 date in UTC. The civil date is worked out from
/// the day count (Howard Hinnant's algorithm): no calendar crate for one line.
fn iso_at(secs: i64) -> String {
    let (days, rest) = (secs.div_euclid(86_400), secs.rem_euclid(86_400));
    let z = days + 719_468;
    let era = z.div_euclid(146_097);
    let doe = z - era * 146_097;
    let yoe = (doe - doe / 1460 + doe / 36_524 - doe / 146_096) / 365;
    let doy = doe - (365 * yoe + yoe / 4 - yoe / 100);
    let mp = (5 * doy + 2) / 153;
    let day = doy - (153 * mp + 2) / 5 + 1;
    let month = if mp < 10 { mp + 3 } else { mp - 9 };
    let year = yoe + era * 400 + i64::from(month <= 2);
    format!("{year:04}-{month:02}-{day:02}T{:02}:{:02}:{:02}.000Z", rest / 3600, rest % 3600 / 60, rest % 60)
}

/// What goes into the TOTP field must be a secret a code can be made of.
fn check_totp_secret(value: &str) -> anyhow::Result<()> {
    totp_code(value).map(|_| ())
}

/// One-time code from the seed stored in the vault.
///
/// Bitwarden keeps either a bare base32 seed in that field or a whole
/// `otpauth://` URL with its own parameters (Steam included). Parsing the URL
/// is not our job: `totp-rs` understands both.
fn totp_code(seed: &str) -> anyhow::Result<String> {
    let seed = seed.trim();
    // A bare run of digits is what a one-time code looks like, and a code
    // saved in place of the secret destroys the secret. The hex spelling would
    // take such digits as a seed and hand out nonsense codes; they are refused
    // here, so that an item damaged that way says so instead.
    if (6..=10).contains(&seed.len()) && seed.bytes().all(|b| b.is_ascii_digit()) {
        return Err(keyward_core::fault!("err.totpLooksLikeCode"));
    }
    let totp = if seed.starts_with("otpauth://") || seed.starts_with("steam://") {
        totp_rs::TOTP::from_url_unchecked(seed)
            .map_err(|e| keyward_core::fault!("err.totpLinkUnreadable", "reason" => e))?
    } else {
        // With the otpauth feature on, the constructor demands an issuer and
        // an account name. For a bare seed they mean nothing beyond a caption.
        totp_rs::TOTP::new_unchecked(
            totp_rs::Algorithm::SHA1,
            6,
            1,
            30,
            totp_seed(seed)?,
            None,
            "keyward".to_string(),
        )
    };
    totp.generate_current().map_err(|e| keyward_core::fault!("err.totpCodeFailed", "reason" => e))
}

/// Seed bytes out of whatever a human pasted into the field.
///
/// RFC 6238 says base32, and that is what almost every site hands out. But
/// the field collects other spellings too: grouped with spaces or dashes,
/// lowercased, padded with `=`, prefixed with `secret=` left over from a
/// half-copied link; some corporate portals give hex or base64 instead. All
/// of these are the same seed written differently, and refusing over the
/// spelling is refusing for no reason.
fn totp_seed(seed: &str) -> anyhow::Result<Vec<u8>> {
    use base64::Engine as _;

    // A whole link is handled above; what lands here is a scrap such as
    // `secret=JBSW...&issuer=...`, and the value is what we want out of it.
    let tail = match seed.to_ascii_lowercase().find("secret=") {
        Some(at) => &seed[at + "secret=".len()..],
        None => seed,
    };
    let tail = tail.split('&').next().unwrap_or(tail);
    let tight: String = tail.chars().filter(|c| !c.is_whitespace()).collect();
    if tight.is_empty() {
        return Err(keyward_core::fault!("err.totpSeedEmpty"));
    }

    // 1. base32 — what is meant nine times out of ten.
    let b32: String = tight.chars().filter(|c| *c != '-' && *c != '=').flat_map(char::to_uppercase).collect();
    if let Ok(bytes) = totp_rs::Secret::Encoded(b32.clone()).to_bytes() {
        if !bytes.is_empty() {
            return Ok(bytes);
        }
    }
    // 2. Hex, and only after base32: "ABCDEF" is lawful base32 as well, so
    // catching such strings here would mean computing a code from the wrong
    // seed and never saying so.
    if b32.len() % 2 == 0 && b32.len() >= 16 && b32.chars().all(|c| c.is_ascii_hexdigit()) {
        let bytes: Option<Vec<u8>> =
            (0..b32.len()).step_by(2).map(|i| u8::from_str_radix(&b32[i..i + 2], 16).ok()).collect();
        if let Some(bytes) = bytes {
            return Ok(bytes);
        }
    }
    // 3. base64 — both alphabets, padded or not.
    let b64: String = tight.chars().filter(|c| *c != '=').collect();
    for engine in [&base64::engine::general_purpose::STANDARD_NO_PAD, &base64::engine::general_purpose::URL_SAFE_NO_PAD] {
        if let Ok(bytes) = engine.decode(&b64) {
            if !bytes.is_empty() {
                return Ok(bytes);
            }
        }
    }

    // The seed itself never appears in the message: it goes to the screen and
    // to the log. Only its shape is described.
    let outside = b32.chars().filter(|c| !matches!(c, 'A'..='Z' | '2'..='7')).count();
    let total = b32.chars().count();
    if outside > 0 {
        return Err(keyward_core::fault!("err.totpSeedBadAlphabet", "total" => total, "outside" => outside));
    }
    Err(keyward_core::fault!("err.totpSeedTruncated", "total" => total))
}

/// The master password in rbw's protected memory: the page is locked and
/// zeroed when reset, so the password leaks into neither swap nor dumps.
fn locked_password(password: &str) -> rbw::locked::Password {
    let mut vec = rbw::locked::Vec::new();
    vec.extend(password.bytes());
    rbw::locked::Password::new(vec)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn a_members_collections_from_the_server_become_levels() {
        let raw = r#"{"data":[{"id":"m","collections":[
            {"id":"a","readOnly":false,"hidePasswords":false,"manage":true},
            {"id":"b","readOnly":false,"hidePasswords":false,"manage":false},
            {"id":"c","readOnly":false,"hidePasswords":true,"manage":false},
            {"id":"d","readOnly":true,"hidePasswords":false,"manage":false},
            {"id":"e","readOnly":true,"hidePasswords":true,"manage":false}
        ]}]}"#;
        #[derive(serde::Deserialize)]
        struct Envelope {
            data: Vec<keyward_bw::orgs::OrgUser>,
        }
        let users: Envelope = serde_json::from_str(raw).expect("parses");
        let access = member_access(&users.data[0].collections);
        use CollectionPermission as P;
        let levels: Vec<(&str, P)> = access.iter().map(|a| (a.id.as_str(), a.permission)).collect();
        assert_eq!(
            levels,
            [("a", P::Manage), ("b", P::Edit), ("c", P::EditHidden), ("d", P::Read), ("e", P::ReadHidden)]
        );
    }

    #[test]
    fn levels_go_back_to_the_server_as_its_flags_and_contradictions_are_refused() {
        use CollectionPermission as P;
        let access = |id: &str, permission| CollectionAccess { id: id.into(), permission };
        let sent = grants(false, &[access("a", P::Manage), access("b", P::ReadHidden), access("c", P::Edit)]).expect("builds");
        let flags: Vec<(bool, bool, bool)> = sent.iter().map(|g| (g.read_only, g.hide_passwords, g.manage)).collect();
        assert_eq!(flags, [(false, false, true), (true, true, false), (false, false, false)]);
        assert!(grants(true, &[]).expect("builds").is_empty());
        assert!(grants(true, &[access("a", P::Read)]).is_err(), "everything and a list at once");
        assert!(grants(false, &[access("a", P::Read), access("a", P::Edit)]).is_err(), "one collection twice");
    }

    fn tokens(access: &str, refresh: Option<&str>) -> keyward_bw::identity::Tokens {
        keyward_bw::identity::Tokens { access_token: zeroize::Zeroizing::new(access.into()), refresh_token: refresh.map(|r| zeroize::Zeroizing::new(r.into())) }
    }

    /// The thirtieth-day sign-out: the refresh token the server rotates in
    /// must replace the one the login gave, or the session ends on that one's
    /// date.
    #[test]
    fn a_rotated_refresh_token_replaces_the_old_one() {
        let mut db = rbw::db::Db::new();
        db.access_token = Some("a1".into());
        db.refresh_token = Some("r1".into());
        rotate(&mut db, tokens("a2", Some("r2")));
        assert_eq!((db.access_token.as_deref(), db.refresh_token.as_deref()), (Some("a2"), Some("r2")));
        // A server that does not rotate leaves the refresh token as it was.
        rotate(&mut db, tokens("a3", None));
        assert_eq!((db.access_token.as_deref(), db.refresh_token.as_deref()), (Some("a3"), Some("r2")));
    }

    fn snapshot(raw: &str) -> keyward_bw::Sync {
        serde_json::from_str(raw).expect("the snapshot parses")
    }

    fn ids(list: &[&str]) -> Vec<String> {
        list.iter().map(|s| (*s).to_string()).collect()
    }

    /// A snapshot with one live item and two in the trash.
    fn vault() -> keyward_bw::Sync {
        snapshot(
            r#"{"ciphers":[
                {"id":"alive","name":"n"},
                {"id":"trash-1","name":"n","deletedDate":"2026-01-01T00:00:00Z"},
                {"id":"trash-2","name":"n","deletedDate":"2026-01-01T00:00:00Z"}
            ]}"#,
        )
    }

    // --- "delete for good" --------------------------------------------------
    //
    // The client's one irreversible operation. A mistake here is mended by
    // nothing: not by a sync, not by the trash, not by another device.

    #[test]
    fn only_what_is_in_the_trash_is_deleted() {
        let out = only_trashed(&vault(), &ids(&["trash-1", "trash-2"])).expect("allowed");
        assert_eq!(out, ids(&["trash-1", "trash-2"]));
    }

    #[test]
    fn one_live_item_in_the_list_cancels_the_whole_list() {
        // Not "delete what we can" but refuse outright: a person pressed once
        // over a selection and will not see a partial execution.
        let err = only_trashed(&vault(), &ids(&["trash-1", "alive"])).expect_err("refused");
        assert_eq!(err.to_string(), "err.deleteOnlyFromTrash");
    }

    #[test]
    fn an_unknown_identifier_is_a_refusal_not_a_skip() {
        // A snapshot can be older than the vault. An item we know nothing
        // about may not have been in the trash at all, and sending it off to be
        // deleted silently is not allowed.
        assert!(only_trashed(&vault(), &ids(&["trash-1", "stranger"])).is_err());
        assert!(only_trashed(&vault(), &ids(&[""])).is_err());
        assert!(only_trashed(&vault(), &ids(&["../../api/accounts"])).is_err());
    }

    #[test]
    fn a_duplicate_identifier_with_a_live_item_does_not_pass() {
        // The server -- or a swapped snapshot -- sends two items with one id:
        // one in the trash, one alive. A check of "at least one matched" let
        // that finish off the live one.
        let twin = snapshot(
            r#"{"ciphers":[
                {"id":"x","name":"alive"},
                {"id":"x","name":"in the trash","deletedDate":"2026-01-01T00:00:00Z"}
            ]}"#,
        );
        assert!(only_trashed(&twin, &ids(&["x"])).is_err());
    }

    #[test]
    fn the_same_identifier_twice_is_one_request() {
        let out = only_trashed(&vault(), &ids(&["trash-1", "trash-1"])).expect("allowed");
        assert_eq!(out, ids(&["trash-1"]));
    }

    #[test]
    fn an_empty_list_does_not_empty_the_trash() {
        // `DELETE /api/ciphers` with an empty `ids` is a request to "empty
        // everything". An empty selection in the interface must not turn into
        // one.
        assert!(only_trashed(&vault(), &[]).expect("empty").is_empty());
    }

    #[test]
    fn an_empty_snapshot_forbids_everything() {
        // The snapshot did not read: we take it that we know nothing about
        // the vault, and delete nothing.
        let empty = keyward_bw::Sync::default();
        assert!(only_trashed(&empty, &ids(&["trash-1"])).is_err());
    }

    /// A seed as another client spelled it: space-separated groups,
    /// lowercase, padding. Same seed, and the code must still come out.
    #[test]
    fn a_replaced_password_goes_first_into_a_history_of_five() {
        let mut history = None;
        for i in 0..7 {
            history = Some(push_history(history, serde_json::json!({ "password": format!("p{i}") })));
        }
        let list = history.unwrap();
        let list = list.as_array().unwrap();
        assert_eq!(list.len(), 5);
        assert_eq!(list[0]["password"], "p6", "the newest first");
        assert_eq!(list[4]["password"], "p2");
    }

    #[test]
    fn dates_are_written_as_the_server_writes_them() {
        assert_eq!(iso_at(0), "1970-01-01T00:00:00.000Z");
        assert_eq!(iso_at(1_790_592_000), "2026-09-28T10:40:00.000Z");
        assert_eq!(iso_at(951_782_400), "2000-02-29T00:00:00.000Z");
    }

    #[test]
    fn totp_field_refuses_a_code_in_place_of_the_secret() {
        for code in ["482913", "123456", "00123456"] {
            let e = check_totp_secret(code).expect_err(code).to_string();
            assert!(e.starts_with("err.totpLooksLikeCode"), "{code}: {e}");
        }
        check_totp_secret("JBSWY3DPEHPK3PXP").expect("a base32 secret");
        check_totp_secret("otpauth://totp/Example:a@b.c?secret=JBSWY3DPEHPK3PXP&issuer=Example").expect("a link");
        assert!(check_totp_secret("paste me later?").is_err());
    }

    #[test]
    fn totp_seed_reads_any_spelling() {
        let canon = totp_seed("JBSWY3DPEHPK3PXP").expect("plain base32");
        for spelling in ["jbswy3dp ehpk3pxp", "JBSW-Y3DP-EHPK-3PXP", "JBSWY3DPEHPK3PXP===", " JBSWY3DPEHPK3PXP "] {
            assert_eq!(totp_seed(spelling).expect(spelling), canon, "spelling {spelling:?}");
        }
    }

    /// What landed in the field is a scrap of a link, not the key.
    #[test]
    fn totp_seed_takes_key_out_of_url_scrap() {
        assert_eq!(
            totp_seed("secret=JBSWY3DPEHPK3PXP&issuer=Example").expect("scrap of a link"),
            totp_seed("JBSWY3DPEHPK3PXP").expect("plain base32")
        );
    }

    /// A hex seed from a corporate portal: base32 has no such characters,
    /// and this used to end in a refusal.
    #[test]
    fn totp_seed_accepts_hex() {
        assert_eq!(totp_seed("00112233445566778899aabbccddeeff").expect("hex seed"), (0..16).map(|i| i * 17).collect::<Vec<u8>>());
    }

    /// A refusal talks about the shape and never carries the seed itself.
    #[test]
    fn totp_seed_error_never_shows_the_seed() {
        let e = totp_seed("paste me later?").expect_err("not a seed").to_string();
        assert!(!e.contains("paste") && !e.contains("later"), "the refusal must not carry the seed: {e}");
        assert!(e.starts_with("err.totpSeedBadAlphabet "), "the refusal must name itself: {e}");
        assert!(totp_seed("   ").is_err());
    }
}
