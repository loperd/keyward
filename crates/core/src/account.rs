//! A Bitwarden account as the interface sees it: profile, second factor,
//! devices, export. Types only: the network and the cryptography live in
//! `vault`.

use serde::{Deserialize, Serialize};

/// The function that derives a key from the master password, in Bitwarden's
/// own terms.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(tag = "kind", rename_all = "snake_case")]
pub enum KdfInfo {
    Pbkdf2 { iterations: u32 },
    Argon2id { iterations: u32, memory_mib: u32, parallelism: u32 },
}

/// The account profile: what the server knows about a person.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct AccountProfile {
    pub user_id: String,
    pub email: String,
    pub name: Option<String>,
    /// The avatar colour, `#rrggbb`.
    pub avatar_color: Option<String>,
    pub master_password_hint: Option<String>,
    pub email_verified: bool,
    pub premium: bool,
    /// The date of registration, ISO 8601, as the server gives it.
    pub creation_date: Option<String>,
    pub kdf: KdfInfo,
    /// The five-word fingerprint, from the identifier and the public key. It
    /// is computed locally and matches what Bitwarden shows.
    pub fingerprint: Vec<String>,
    pub two_factor_enabled: bool,
}

/// Which second-factor methods are on.
#[derive(Debug, Clone, Default, Serialize, Deserialize)]
pub struct TwoFactorStatus {
    pub authenticator: bool,
    pub email: bool,
    /// Methods that are on but that keyward cannot manage (YubiKey, WebAuthn,
    /// Duo): shown as they are, and they can be turned off.
    pub others: Vec<TwoFactorOther>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct TwoFactorOther {
    /// The Bitwarden provider identifier (3 YubiKey, 7 WebAuthn, 2 Duo...).
    pub provider: u8,
    pub name: String,
}

/// The secret for an authenticator app. `Debug` is written by hand: the key
/// will not travel into a log.
#[derive(Clone, Serialize, Deserialize)]
pub struct AuthenticatorSetup {
    /// The base32 secret as the server issued it.
    pub key: String,
    /// `otpauth://totp/...`, for the QR code.
    pub otpauth: String,
    pub enabled: bool,
}

impl std::fmt::Debug for AuthenticatorSetup {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "AuthenticatorSetup {{ key: <hidden>, enabled: {} }}", self.enabled)
    }
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct EmailTwoFactorSetup {
    pub email: String,
    pub enabled: bool,
}

/// A device the account has been logged in from.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Device {
    pub id: String,
    pub name: String,
    /// The kind of device in words: `desktop`, `browser`, `mobile`, `cli`...
    pub kind: String,
    pub identifier: String,
    pub created: Option<String>,
    pub last_active: Option<String>,
    /// This device is keyward itself.
    pub current: bool,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum ExportFormat {
    /// Unencrypted JSON in Bitwarden's format.
    Json,
    /// CSV in Bitwarden's format.
    Csv,
}
